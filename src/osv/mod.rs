//! OSV vulnerability intelligence: does OSV block (ecosystem, name, version)?
//!
//! `osv::evaluate` is the one place SPEC's C15 two-phase dance is written: resolve
//! `policy::evaluate` OSV-blind first, and only when *that alone* would allow the
//! candidate, ask OSV and resolve again with the real answer. This is what keeps OSV
//! an OR-only signal (C1) — it is never even asked about a candidate the producer's
//! own blocklist already denies, so it can never be the reason a producer-tier deny
//! is undone.
//!
//! [`OsvClient::check`] never fails closed (C3/C14): a cache miss that cannot be
//! resolved — a full queue, a batcher timeout, a malformed or mismatched response —
//! answers `false`, the same as a confirmed non-match, and is cached for a short
//! negative TTL so a struggling OSV endpoint is not re-hammered by repeat callers.

pub(crate) mod batcher;

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lru::LruCache;
use reqwest::Client;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::policy::{self, BlocklistSnapshot, Candidate, Decision, Ecosystem};

/// The production OSV endpoint. Fixed rather than configurable (D4): only the cache
/// TTL and the per-check timeout are operator-tunable.
const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// How many records one flush carries at most, mirroring `delivery/siem.rs`'s
/// `BATCH_RECORDS`.
pub(crate) const OSV_BATCH_RECORDS: usize = 256;

/// How long a partial batch waits for company before it flushes anyway. Short, so a
/// solitary lookup is answered well inside `osv_request_timeout_ms`, and long enough
/// to gather every check one metadata request enqueues at once (`npm::resolve` and
/// `pypi::resolve` judge all of a project's candidates together).
pub(crate) const OSV_BATCH_INTERVAL: Duration = Duration::from_millis(10);

/// How long a failure's answer stays cached (C14): short, so a struggling OSV
/// endpoint is not re-hammered by repeat requests during an outage, but far shorter
/// than a confirmed answer's TTL so the outage is not remembered past its own life.
pub(crate) const OSV_NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// The bounded queue's capacity (G2/C12a): 4x `OSV_BATCH_RECORDS`, mirroring
/// `delivery/siem.rs`'s `BATCH_RECORDS` headroom convention.
pub(crate) const OSV_CHANNEL_CAPACITY: usize = 1024;

/// How many answers the cache holds at most; past it the least recently used goes.
pub(crate) const OSV_CACHE_ENTRIES: usize = 65_536;

/// How long [`OsvClient::check`] waits to enqueue before failing open (C12a).
pub(crate) const OSV_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(50);

/// One queued lookup and its reply channel.
pub(crate) type OsvRequest = ((Ecosystem, String, String), oneshot::Sender<bool>);

/// How OSV enforcement behaves (C16-C18b, D5). Read only by [`evaluate`], set once at
/// construction and never mutated — there is no reload/hot-swap path.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OsvMode {
    /// A confirmed OSV match denies the candidate (today's behaviour).
    Enforce,
    /// OSV is still asked and cached, but a match never denies — only logged
    /// (`crate::http::logging::record_osv_diagnostic_match`).
    Diagnostic,
    /// OSV is never asked (`OsvClient::check` is not called).
    Off,
}

/// One cached answer and when it stops being trusted.
struct CacheEntry {
    matched: bool,
    expires_at: Instant,
}

/// The short-TTL result cache (C13), internally locked so every caller shares one
/// map without holding a lock of its own. Shared with the batcher, which writes
/// every answer it gets whether or not its waiter is still listening.
pub(crate) struct OsvCache {
    /// Bounded at `OSV_CACHE_ENTRIES`, least recently used out first; an expired
    /// entry is also dropped as soon as a lookup finds it.
    entries: Mutex<LruCache<(Ecosystem, String, String), CacheEntry>>,
    /// The TTL a match is cached for. A non-match — confirmed or a failure, which
    /// `false` alone cannot tell apart — always uses `OSV_NEGATIVE_TTL`, the
    /// conservative choice on that ambiguity.
    match_ttl: Duration,
}

impl OsvCache {
    fn new(match_ttl: Duration) -> OsvCache {
        let capacity = NonZeroUsize::new(OSV_CACHE_ENTRIES).expect("a non-zero bound");
        OsvCache {
            entries: Mutex::new(LruCache::new(capacity)),
            match_ttl,
        }
    }

    fn get(&self, key: &(Ecosystem, String, String)) -> Option<bool> {
        let mut entries = self.entries.lock().expect("the OSV cache");
        match entries.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => return Some(entry.matched),
            Some(_) => {}
            None => return None,
        }
        entries.pop(key);
        None
    }

    pub(crate) fn put(&self, key: (Ecosystem, String, String), matched: bool) {
        let ttl = if matched {
            self.match_ttl
        } else {
            OSV_NEGATIVE_TTL
        };
        let mut entries = self.entries.lock().expect("the OSV cache");
        entries.put(
            key,
            CacheEntry {
                matched,
                expires_at: Instant::now() + ttl,
            },
        );
    }
}

/// The client half: a cache of recent answers (C13) and the sending half of the
/// batcher's queue.
pub struct OsvClient {
    tx: mpsc::Sender<OsvRequest>,
    cache: Arc<OsvCache>,
    /// The bound a waiting `check` call is held to (C12c/C14):
    /// `OSV_BATCH_INTERVAL` plus the figure the batcher wraps its own outbound call
    /// in, so a waiter outlasts the flush it is in unless the batcher is still busy
    /// with an earlier one.
    request_timeout: Duration,
    /// D5: how OSV enforcement behaves for every `check` this client's `evaluate`
    /// caller might make. Set once here, never mutated.
    mode: OsvMode,
}

impl OsvClient {
    /// Spawns the batcher once and returns the client handle plus the batcher's
    /// `JoinHandle`. `App::start` calls this with its `drain` token and puts the
    /// handle in the task set `Running::shutdown` joins.
    pub fn new(
        client: Client,
        cache_ttl: Duration,
        request_timeout: Duration,
        mode: OsvMode,
        shutdown: CancellationToken,
    ) -> (OsvClient, JoinHandle<()>) {
        let url = Url::parse(OSV_QUERYBATCH_URL).expect("a fixed, valid URL");
        OsvClient::spawn_with(client, url, cache_ttl, request_timeout, mode, shutdown)
    }

    /// The constructor behind [`OsvClient::new`], parameterised over the endpoint —
    /// production always calls `new`, which pins it to the real OSV endpoint; tests
    /// call this directly to point the batcher at a local server instead.
    ///
    /// `pub(crate)` rather than private so `App::start` can also reach it when an
    /// `AppDeps::osv_base_url` override is present — the only other caller, besides
    /// this module's own unit tests, that needs a batcher pointed at anything but
    /// the fixed production endpoint.
    pub(crate) fn spawn_with(
        client: Client,
        url: Url,
        cache_ttl: Duration,
        request_timeout: Duration,
        mode: OsvMode,
        shutdown: CancellationToken,
    ) -> (OsvClient, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(OSV_CHANNEL_CAPACITY);
        let cache = Arc::new(OsvCache::new(cache_ttl));
        let handle = tokio::spawn(batcher::run(
            client,
            url,
            rx,
            request_timeout,
            Arc::clone(&cache),
            shutdown,
        ));
        (
            OsvClient {
                tx,
                cache,
                request_timeout: OSV_BATCH_INTERVAL + request_timeout,
                mode,
            },
            handle,
        )
    }

    /// `true` only on a confirmed OSV `MAL-*` match. Every failure path — a cache
    /// miss that cannot be resolved, a full or timed-out enqueue (C12a), a batch
    /// failure or length mismatch (C12b/C14), an outbound timeout (C12c) — answers
    /// `false` instead. The batcher caches whatever answer a flush produced (see
    /// `OsvCache::put` for the TTLs); this caches only a lookup that never reached
    /// it.
    pub async fn check(&self, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
        let key = (ecosystem, name.to_owned(), version.to_owned());
        if let Some(matched) = self.cache.get(&key) {
            return matched;
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        let enqueued =
            tokio::time::timeout(OSV_ENQUEUE_TIMEOUT, self.tx.send((key.clone(), reply_tx))).await;
        if !matches!(enqueued, Ok(Ok(()))) {
            self.cache.put(key, false);
            return false;
        }
        // Bounded even though the batcher always answers (see `batcher::run`): it
        // may still be busy with an earlier flush. A waiter that gives up here still
        // gets its answer cached by the batcher for the next caller.
        tokio::time::timeout(self.request_timeout, reply_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }
}

/// A `reqwest::Client` whose requests to the OSV endpoint — always
/// `https://api.osv.dev`, fixed inside `OsvClient::new` — are redirected at the
/// connection level to an address nothing listens on. `App::start` still spawns a
/// real batcher over this client; every one of its flushes still gets a real,
/// immediate connection refusal rather than reaching the internet, which is what
/// keeps the test suite hermetic without `OsvClient::new` needing a URL parameter of
/// its own. **Compiled only under `test-support`**, mirroring
/// `Limits::set_response_timeouts`: production never needs an inert OSV endpoint.
#[cfg(feature = "test-support")]
pub fn unreachable_client() -> Client {
    // Port 0 is never a listener's own port (the OS refuses to `connect` to it, the
    // same way it refuses to `bind` to it), so this needs no listener of its own and
    // cannot flake by colliding with one a test elsewhere in the process opened.
    let nothing_listens_here: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
    Client::builder()
        .resolve("api.osv.dev", nothing_listens_here)
        .build()
        .expect("a client with a DNS override is always buildable")
}

/// The shared C15 two-phase wrapper (D2) every production call site uses in place of
/// a direct `policy::evaluate` call.
///
/// `policy::evaluate` is called OSV-blind first; OSV is asked only when that alone
/// would `Allow` the candidate, which is what keeps OSV an OR-only signal (C1) and
/// keeps the OSV round trip off the hot path of a candidate a producer already
/// blocks.
pub async fn evaluate(
    osv: &OsvClient,
    snapshot: Option<&BlocklistSnapshot>,
    now_utc_micros: i64,
    cooldown_seconds: u64,
    candidate: &Candidate<'_>,
) -> Decision {
    let blind = policy::evaluate(snapshot, now_utc_micros, cooldown_seconds, candidate, false);
    if !matches!(blind, Decision::Allow) {
        return blind;
    }
    if osv.mode == OsvMode::Off {
        return blind;
    }

    let matched = osv
        .check(candidate.ecosystem, candidate.name, candidate.version)
        .await;

    if osv.mode == OsvMode::Diagnostic {
        if matched {
            crate::http::logging::record_osv_diagnostic_match();
        }
        return blind;
    }

    policy::evaluate(
        snapshot,
        now_utc_micros,
        cooldown_seconds,
        candidate,
        matched,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PublicationTime;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration as StdDuration;

    /// The shipped `osv_request_timeout_ms`.
    const SHIPPED_TIMEOUT: StdDuration = StdDuration::from_millis(500);

    fn candidate<'a>(name: &'a str, version: &'a str) -> Candidate<'a> {
        Candidate {
            ecosystem: Ecosystem::Npm,
            name,
            version,
            publication: PublicationTime::Upstream(0),
            advertised_digests: &[],
            pinned_digests: &[],
        }
    }

    #[tokio::test]
    async fn check_fails_open_on_full_channel() {
        // Capacity 1, and the one slot is held by a request nothing will ever drain:
        // `check`'s own enqueue must therefore time out rather than block. `_rx` is
        // kept alive (never read) for the whole test — dropping it would close the
        // channel instead of leaving it full.
        let (tx, _rx) = mpsc::channel(1);
        let client = OsvClient {
            tx,
            cache: Arc::new(OsvCache::new(StdDuration::from_secs(60))),
            request_timeout: SHIPPED_TIMEOUT,
            mode: OsvMode::Enforce,
        };
        let (holder_tx, _holder_rx) = oneshot::channel::<bool>();
        client
            .tx
            .try_send((
                (Ecosystem::Npm, "filler".to_owned(), "0.0.0".to_owned()),
                holder_tx,
            ))
            .expect("the one slot is free before this send");

        let started = Instant::now();
        let matched = client.check(Ecosystem::Npm, "left-pad", "1.0.0").await;
        let elapsed = started.elapsed();

        assert!(!matched, "a full channel fails open");
        assert!(
            elapsed < SHIPPED_TIMEOUT,
            "the enqueue must fail open at OSV_ENQUEUE_TIMEOUT, not block; took {elapsed:?}"
        );
    }

    /// A solitary lookup against a collector that would match but answers too late
    /// fails open within one batch interval plus `request_timeout` (C12c/C14).
    #[tokio::test]
    async fn check_fails_open_on_batcher_timeout() {
        let (url, _server, _count) = osv_server(200, true, StdDuration::from_secs(60)).await;
        let request_timeout = StdDuration::from_millis(50);
        let (client, handle, shutdown) = spawn(
            url,
            OsvMode::Enforce,
            StdDuration::from_secs(60),
            request_timeout,
        );

        let started = Instant::now();
        let matched = client.check(Ecosystem::Npm, "left-pad", "1.0.0").await;
        let elapsed = started.elapsed();
        assert!(!matched, "a hung collector fails the check open");
        assert!(
            elapsed < OSV_BATCH_INTERVAL + request_timeout + StdDuration::from_millis(200),
            "bounded by the batch interval plus request_timeout; took {elapsed:?}"
        );

        shutdown.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn osv_client_new_spawns_one_batcher_task() {
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::new(
            Client::new(),
            StdDuration::from_secs(60),
            StdDuration::from_millis(50),
            OsvMode::Enforce,
            shutdown.clone(),
        );
        assert!(!handle.is_finished(), "the batcher is running");
        // Without a shutdown signal: dropping the last client is enough to end it.
        drop(client);
        handle.await.expect("the one spawned batcher task joins");
        drop(shutdown);
    }

    // ---------------------------------------------------------------------------
    // The real `OsvClient` and `evaluate`, against a local OSV stand-in whose
    // request count is what each test asserts on.
    // ---------------------------------------------------------------------------

    /// A `wiremock` server answering every `POST /v1/querybatch` with `status` and,
    /// for a `200`, a fixed matched/unmatched verdict for every query in the batch,
    /// after `delay`. Counts how many requests it received.
    pub(super) async fn osv_server(
        status: u16,
        matched: bool,
        delay: StdDuration,
    ) -> (Url, wiremock::MockServer, Arc<AtomicUsize>) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(move |request: &wiremock::Request| {
                counted.fetch_add(1, Ordering::SeqCst);
                let body: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("a JSON batch body");
                let queries = body["queries"].as_array().expect("a queries array");
                let vulns = if matched {
                    serde_json::json!([{"id": "MAL-2026-0001"}])
                } else {
                    serde_json::json!([])
                };
                let results: Vec<serde_json::Value> = queries
                    .iter()
                    .map(|_| serde_json::json!({"vulns": vulns}))
                    .collect();
                ResponseTemplate::new(status)
                    .set_body_json(serde_json::json!({"results": results}))
                    .set_delay(delay)
            })
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/v1/querybatch", server.uri())).unwrap();
        (url, server, count)
    }

    /// [`osv_server`] answering `200` at once with `matched` for every query.
    async fn mode_server(matched: bool) -> (Url, wiremock::MockServer, Arc<AtomicUsize>) {
        osv_server(200, matched, StdDuration::ZERO).await
    }

    fn spawn(
        url: Url,
        mode: OsvMode,
        cache_ttl: StdDuration,
        request_timeout: StdDuration,
    ) -> (OsvClient, JoinHandle<()>, CancellationToken) {
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            cache_ttl,
            request_timeout,
            mode,
            shutdown.clone(),
        );
        (client, handle, shutdown)
    }

    fn clean_snapshot(now: i64) -> BlocklistSnapshot {
        crate::policy::BlocklistSnapshot::parse_and_validate(
            br#"{"schema_version":1,"revision":1,
                 "generated_at":"1970-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
                 "blocked_packages":[],"blocked_hashes":[]}"#,
            now,
        )
        .expect("a valid snapshot")
    }

    /// `evaluate` on a clean snapshot, against a matching OSV in `mode`: the decision
    /// and how many times OSV was asked.
    async fn evaluate_in(mode: OsvMode, snapshot: &BlocklistSnapshot) -> (Decision, usize) {
        let (url, _server, count) = mode_server(true).await;
        let (client, handle, shutdown) =
            spawn(url, mode, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
        let decision = evaluate(
            &client,
            Some(snapshot),
            10_000_000,
            0,
            &candidate("left-pad", "1.0.0"),
        )
        .await;
        shutdown.cancel();
        let _ = handle.await;
        (decision, count.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn evaluate_skips_osv_when_producer_already_denies() {
        let blocked = crate::policy::BlocklistSnapshot::parse_and_validate(
            br#"{"schema_version":1,"revision":1,
                 "generated_at":"1970-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
                 "blocked_packages":[{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}],
                 "blocked_hashes":[]}"#,
            10_000_000,
        )
        .expect("a valid snapshot");

        let (decision, asked) = evaluate_in(OsvMode::Enforce, &blocked).await;
        assert_eq!(
            decision,
            Decision::Deny(crate::policy::DenyReason::BlockedPackage)
        );
        assert_eq!(
            asked, 0,
            "OSV is not asked about an already-denied candidate"
        );
    }

    #[tokio::test]
    async fn evaluate_enforce_mode_denies_on_match() {
        let (decision, asked) = evaluate_in(OsvMode::Enforce, &clean_snapshot(10_000_000)).await;
        assert_eq!(
            decision,
            Decision::Deny(crate::policy::DenyReason::BlockedByOsv)
        );
        assert_eq!(asked, 1, "a clean candidate asks OSV exactly once");
    }

    #[tokio::test]
    async fn evaluate_off_mode_never_calls_check() {
        let (decision, asked) = evaluate_in(OsvMode::Off, &clean_snapshot(10_000_000)).await;
        assert_eq!(decision, Decision::Allow);
        assert_eq!(asked, 0, "off mode never asks OSV");
    }

    #[tokio::test]
    async fn evaluate_diagnostic_mode_asks_osv_and_allows_on_match() {
        let (decision, asked) = evaluate_in(OsvMode::Diagnostic, &clean_snapshot(10_000_000)).await;
        assert_eq!(decision, Decision::Allow, "diagnostic mode never denies");
        assert_eq!(asked, 1, "diagnostic mode still asks OSV");
    }

    #[tokio::test]
    async fn evaluate_diagnostic_mode_allows_without_match() {
        let (url, _server, count) = mode_server(false).await;
        let (client, handle, shutdown) = spawn(
            url,
            OsvMode::Diagnostic,
            StdDuration::from_secs(60),
            SHIPPED_TIMEOUT,
        );
        let now = 10_000_000;
        let decision = evaluate(
            &client,
            Some(&clean_snapshot(now)),
            now,
            0,
            &candidate("left-pad", "1.0.0"),
        )
        .await;

        assert_eq!(decision, Decision::Allow);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        shutdown.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn a_cached_answer_needs_no_second_round_trip() {
        let (url, _server, count) = mode_server(true).await;
        let (client, handle, shutdown) = spawn(
            url,
            OsvMode::Enforce,
            StdDuration::from_secs(60),
            SHIPPED_TIMEOUT,
        );

        assert!(client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert!(client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "the second answer is the cached one"
        );

        shutdown.cancel();
        let _ = handle.await;
    }

    /// A match is trusted for `cache_ttl` and no longer: past it OSV is asked again.
    #[tokio::test]
    async fn an_expired_answer_is_asked_again() {
        let (url, _server, count) = mode_server(true).await;
        let cache_ttl = StdDuration::from_millis(50);
        let (client, handle, shutdown) = spawn(url, OsvMode::Enforce, cache_ttl, SHIPPED_TIMEOUT);

        assert!(client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        tokio::time::sleep(cache_ttl * 2).await;
        assert!(client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert_eq!(count.load(Ordering::SeqCst), 2);

        shutdown.cancel();
        let _ = handle.await;
    }

    /// A failed batch fails open and is cached too, so a struggling OSV endpoint is
    /// not asked again by the next caller (C14).
    #[tokio::test]
    async fn a_failed_lookup_fails_open_and_is_not_retried_at_once() {
        let (url, _server, count) = osv_server(500, true, StdDuration::ZERO).await;
        let (client, handle, shutdown) = spawn(
            url,
            OsvMode::Enforce,
            StdDuration::from_secs(60),
            SHIPPED_TIMEOUT,
        );

        assert!(!client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert!(!client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert_eq!(count.load(Ordering::SeqCst), 1, "the failure was cached");

        shutdown.cancel();
        let _ = handle.await;
    }

    /// The cache is bounded: once `OSV_CACHE_ENTRIES` other lookups have been
    /// answered since, the oldest answer is gone and OSV is asked again.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_cache_forgets_its_oldest_answer_past_its_bound() {
        let (url, server, _count) = mode_server(true).await;
        let (client, handle, shutdown) = spawn(
            url,
            OsvMode::Enforce,
            StdDuration::from_secs(600),
            SHIPPED_TIMEOUT,
        );
        let versions: Vec<String> = (0..=OSV_CACHE_ENTRIES).map(|n| n.to_string()).collect();
        for chunk in versions.chunks(OSV_BATCH_RECORDS) {
            let answers = futures_util::future::join_all(
                chunk
                    .iter()
                    .map(|version| client.check(Ecosystem::Npm, "left-pad", version)),
            )
            .await;
            assert!(
                answers.into_iter().all(|matched| matched),
                "every lookup was answered"
            );
        }
        let asked = server.received_requests().await.expect("recorded").len();

        assert!(client.check(Ecosystem::Npm, "left-pad", "0").await);
        let asked_again = server.received_requests().await.expect("recorded").len();
        assert_eq!(asked_again, asked + 1, "the oldest answer was evicted");

        shutdown.cancel();
        let _ = handle.await;
    }

    /// A caller that stops waiting (its request was cancelled) does not lose the
    /// answer: the batcher caches it, so the next caller gets the match without a
    /// second round trip.
    #[tokio::test]
    async fn an_answer_nobody_waited_for_is_still_cached() {
        let (url, _server, count) = osv_server(200, true, StdDuration::from_millis(100)).await;
        let (client, handle, shutdown) = spawn(
            url,
            OsvMode::Enforce,
            StdDuration::from_secs(60),
            SHIPPED_TIMEOUT,
        );

        let abandoned = tokio::time::timeout(
            StdDuration::from_millis(30),
            client.check(Ecosystem::Npm, "left-pad", "1.0.0"),
        )
        .await;
        assert!(abandoned.is_err(), "the first caller gave up mid-flight");
        tokio::time::sleep(StdDuration::from_millis(300)).await;

        assert!(client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert_eq!(count.load(Ordering::SeqCst), 1, "answered from the cache");

        shutdown.cancel();
        let _ = handle.await;
    }

    // ---------------------------------------------------------------------------
    // `App::start`/`Running::shutdown` wiring (tests 17/18 of Slice 1's scope).
    //
    // `App::start` builds the `OsvClient` itself, from `AppDeps::osv_client` (and
    // `AppDeps::osv_base_url` when a test points it elsewhere), and hands the
    // batcher's `JoinHandle` to the `Tasks` set `Running::shutdown` joins. These two
    // tests check that wiring from outside: exactly one task beyond the baseline,
    // a client that still answers, and a shutdown that completes.
    // ---------------------------------------------------------------------------

    /// The minimum `Config` `App::start` needs to run at all, in a fresh temporary
    /// data directory. Written by hand against `Config::from_toml_str` rather than
    /// borrowed from `tests/common` (a different compilation unit this module
    /// cannot reach).
    fn minimal_config(data_dir: &std::path::Path) -> crate::config::Config {
        let toml = format!(
            "listen = \"127.0.0.1:0\"\n\
             public_url = \"https://packages.example.org\"\n\
             data_dir = \"{dir}\"\n\
             blocklist_file = \"{dir}/blocklist.json\"\n\
             cooldown_seconds = 0\n\
             metadata_ttl_seconds = 300\n\
             blocklist_poll_seconds = 5\n\
             cache_max_bytes = 1048576\n\
             memory_cache_max_bytes = 1048576\n\
             max_artifact_bytes = 1048576\n\
             max_metadata_bytes = 1048576\n\
             max_blocklist_bytes = 1048576\n\
             max_upstream_requests = 4\n\
             max_artifact_downloads = 4\n\
             max_active_requests = 4\n",
            dir = data_dir.display(),
        );
        crate::config::Config::from_toml_str(&toml).expect("a minimal valid config")
    }

    /// The `AppDeps` this pair of tests shares: a minimal, real `App::start` call,
    /// with the osv client's requests redirected to an address nothing listens on
    /// (see `unreachable_client`), so the real, live batcher `App::start` spawns
    /// never reaches a socket beyond the loopback refusal.
    async fn start_minimal_app(data_dir: &std::path::Path) -> crate::Running {
        crate::App::start(crate::AppDeps {
            config: minimal_config(data_dir),
            clock: std::sync::Arc::new(crate::clock::SystemClock),
            // These tests make no request, so the production transport never dials.
            transport: std::sync::Arc::new(crate::upstream::ReqwestTransport::production()),
            // `OriginSet::for_tests` is deliberately not used here:
            // `no_config_key_or_env_var_relaxes_origins` asserts it is named only in
            // its own defining file. Nothing dials out, so the real production
            // origins are exactly as inert here as a fake set would be.
            origins: crate::upstream::OriginSet::production(),
            osv_client: unreachable_client(),
            osv_base_url: None,
        })
        .await
        .expect("the app starts with a minimal config")
    }

    #[tokio::test]
    async fn app_start_constructs_one_osv_client_and_spawns_its_batcher() {
        let data_dir = tempfile::tempdir().expect("a temporary data directory");
        let running = start_minimal_app(data_dir.path()).await;

        // Two background loops (the blocklist poller and the maintenance pass) plus
        // zero delivery tasks (this config configures neither sink) is the baseline
        // `App::start` always spawns; the osv batcher is the one task beyond that
        // baseline — this is `Tasks`, the exact `Vec<JoinHandle<()>>`
        // `Running::shutdown` joins, so its count is direct evidence the batcher is
        // really in that set and not merely running unmanaged somewhere.
        assert_eq!(
            running.background_task_count(),
            3,
            "exactly one task beyond the poller and the maintenance pass"
        );

        // The client `App::start` built from `AppDeps::osv_client` is reachable and
        // still functioning through its own, still-running batcher.
        assert!(
            !running
                .app()
                .osv
                .check(Ecosystem::Npm, "left-pad", "1.0.0")
                .await,
            "the wired-in client still answers checks"
        );

        running.shutdown().await.expect("a clean shutdown");
    }

    #[tokio::test]
    async fn running_shutdown_joins_the_batcher_task() {
        let data_dir = tempfile::tempdir().expect("a temporary data directory");
        let running = start_minimal_app(data_dir.path()).await;

        // The osv batcher's `JoinHandle` is one of the three `Tasks::count()` just
        // confirmed above — `Running::shutdown` cancels `drain` and then awaits
        // every one of them (`self.tasks.join().await`) before returning, so a
        // bounded, successful `shutdown()` here is exactly what "the batcher task
        // is joined, not merely told to stop" looks like from outside `Running`,
        // without instrumenting `osv::batcher::run` itself to prove it.
        tokio::time::timeout(StdDuration::from_secs(5), running.shutdown())
            .await
            .expect("shutdown, and therefore the batcher's join, completes promptly")
            .expect("a clean shutdown");
    }
}
