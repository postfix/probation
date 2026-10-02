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

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

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

/// How long a partial batch waits for company before it flushes anyway, mirroring
/// `delivery/siem.rs`'s `BATCH_INTERVAL`.
pub(crate) const OSV_BATCH_INTERVAL: Duration = Duration::from_secs(2);

/// How long a failure's answer stays cached (C14): short, so a struggling OSV
/// endpoint is not re-hammered by repeat requests during an outage, but far shorter
/// than a confirmed answer's TTL so the outage is not remembered past its own life.
pub(crate) const OSV_NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// The bounded queue's capacity (G2/C12a): 4x `OSV_BATCH_RECORDS`, mirroring
/// `delivery/siem.rs`'s `BATCH_RECORDS` headroom convention.
pub(crate) const OSV_CHANNEL_CAPACITY: usize = 1024;

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
/// map without holding a lock of its own.
struct OsvCache {
    entries: Mutex<HashMap<(Ecosystem, String, String), CacheEntry>>,
}

impl OsvCache {
    fn new() -> OsvCache {
        OsvCache {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, key: &(Ecosystem, String, String)) -> Option<bool> {
        let entries = self.entries.lock().expect("the OSV cache");
        entries
            .get(key)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.matched)
    }

    fn put(&self, key: (Ecosystem, String, String), matched: bool, ttl: Duration) {
        let mut entries = self.entries.lock().expect("the OSV cache");
        entries.insert(
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
    cache: OsvCache,
    /// The TTL a confirmed answer (matched or not) is cached for. A failure path
    /// always uses `OSV_NEGATIVE_TTL` instead (see `check`).
    cache_ttl: Duration,
    /// The bound `resolve` holds a waiting `check` call to (C12c/C14): the same
    /// figure the batcher wraps its own outbound call in, so a solitary lookup
    /// waiting on a flush that has not hit its count-cap or interval yet is not left
    /// waiting on `OSV_BATCH_INTERVAL` instead.
    request_timeout: Duration,
    /// D5: how OSV enforcement behaves for every `check` this client's `evaluate`
    /// caller might make. Set once here, never mutated.
    mode: OsvMode,
}

impl OsvClient {
    /// Spawns the batcher once and returns the client handle plus the batcher's
    /// `JoinHandle`. `App::start` does not hold the `shutdown` token this needs
    /// until it is already deep inside constructing `App` (`AppDeps` is what
    /// carries the finished, already-spawned client in), so this is called by
    /// whoever builds an `AppDeps` — `main.rs::serve()` in production, a test
    /// helper otherwise — each with its own `CancellationToken` for the batcher's
    /// lifetime; see `AppDeps::osv`'s doc comment.
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
        let handle = tokio::spawn(batcher::run(client, url, rx, request_timeout, shutdown));
        (
            OsvClient {
                tx,
                cache: OsvCache::new(),
                cache_ttl,
                request_timeout,
                mode,
            },
            handle,
        )
    }

    /// `true` only on a confirmed OSV `MAL-*` match. Every failure path — a cache
    /// miss that cannot be resolved, a full or timed-out enqueue (C12a), a batch
    /// failure or length mismatch (C12b/C14), an outbound timeout (C12c) — answers
    /// `false` instead, and is cached for `OSV_NEGATIVE_TTL` rather than
    /// `cache_ttl`, since a `false` answer alone cannot distinguish "confirmed no
    /// match" from "could not be resolved"; caching it briefly rather than for the
    /// full TTL is the conservative choice on that ambiguity.
    pub async fn check(&self, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
        let key = (ecosystem, name.to_owned(), version.to_owned());
        if let Some(matched) = self.cache.get(&key) {
            return matched;
        }

        let matched = self.resolve(key.clone()).await;
        let ttl = if matched {
            self.cache_ttl
        } else {
            OSV_NEGATIVE_TTL
        };
        self.cache.put(key, matched, ttl);
        matched
    }

    /// The uncached round trip: enqueue, bounded by `OSV_ENQUEUE_TIMEOUT` (C12a), and
    /// await the batcher's reply, bounded by `request_timeout` (C12c/C14). The
    /// batcher's own contract (see `batcher::run`) is to always answer its waiters,
    /// even on its own failure — but only once it flushes, which can be up to
    /// `OSV_BATCH_INTERVAL` away for a solitary lookup that has not filled a batch.
    /// Without its own bound here, a caller would wait on the batcher's flush
    /// cadence rather than on `request_timeout`, so this wraps the reply wait
    /// exactly as the batcher wraps its own outbound call.
    async fn resolve(&self, key: (Ecosystem, String, String)) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        let enqueued =
            tokio::time::timeout(OSV_ENQUEUE_TIMEOUT, self.tx.send((key, reply_tx))).await;
        match enqueued {
            Ok(Ok(())) => tokio::time::timeout(self.request_timeout, reply_rx)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false),
            Ok(Err(_)) | Err(_) => false,
        }
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

    /// A client with no batcher behind it at all: every field is reachable directly
    /// because these tests live in this module.
    fn client_with_capacity(capacity: usize, cache_ttl: StdDuration) -> OsvClient {
        let (tx, _rx) = mpsc::channel(capacity);
        OsvClient {
            tx,
            cache: OsvCache::new(),
            cache_ttl,
            request_timeout: StdDuration::from_millis(500),
            mode: OsvMode::Enforce,
        }
    }

    /// A "fake OSV client" for use in tests of `evaluate` itself: it never runs a
    /// batcher, answers a fixed value, and panics if asked more than `allowed` times
    /// — the same shape `osv::evaluate`'s own tests need without paying for a real
    /// batcher round trip. This is the test-fake convention `tests/common/mod.rs`
    /// (Slice 1's `AppDeps` fake) also builds on.
    struct FixedOsv {
        answer: bool,
        calls: AtomicUsize,
        allowed: usize,
    }

    impl FixedOsv {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    /// `evaluate_skips_osv_when_producer_already_denies` and
    /// `evaluate_calls_osv_only_when_producer_would_allow` need to observe whether
    /// `OsvClient::check` ran without a real batcher; since `OsvClient` itself has no
    /// trait to fake, both tests drive `osv::evaluate`'s own logic directly against
    /// a `policy::evaluate`-shaped decision plus a counted stand-in for `check`.
    async fn evaluate_with_fake(
        fake: &FixedOsv,
        snapshot: Option<&BlocklistSnapshot>,
        now: i64,
        cooldown: u64,
        candidate: &Candidate<'_>,
    ) -> Decision {
        let blind = policy::evaluate(snapshot, now, cooldown, candidate, false);
        if !matches!(blind, Decision::Allow) {
            return blind;
        }
        let calls = fake.calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            calls < fake.allowed,
            "the fake OSV client was asked more than expected"
        );
        policy::evaluate(snapshot, now, cooldown, candidate, fake.answer)
    }

    #[tokio::test]
    async fn evaluate_skips_osv_when_producer_already_denies() {
        let now = 10_000_000;
        let blocked = crate::policy::BlocklistSnapshot::parse_and_validate(
            br#"{"schema_version":1,"revision":1,
                 "generated_at":"1970-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
                 "blocked_packages":[{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}],
                 "blocked_hashes":[]}"#,
            now,
        )
        .expect("a valid snapshot");

        let fake = FixedOsv {
            answer: true,
            calls: AtomicUsize::new(0),
            allowed: 0,
        };
        let decision = evaluate_with_fake(
            &fake,
            Some(&blocked),
            now,
            0,
            &candidate("left-pad", "1.0.0"),
        )
        .await;

        assert_eq!(
            decision,
            Decision::Deny(crate::policy::DenyReason::BlockedPackage)
        );
        assert_eq!(
            fake.calls(),
            0,
            "OSV must not be asked about an already-denied candidate"
        );
    }

    #[tokio::test]
    async fn evaluate_calls_osv_only_when_producer_would_allow() {
        let now = 10_000_000;
        let clear = crate::policy::BlocklistSnapshot::parse_and_validate(
            br#"{"schema_version":1,"revision":1,
                 "generated_at":"1970-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
                 "blocked_packages":[],"blocked_hashes":[]}"#,
            now,
        )
        .expect("a valid snapshot");

        let fake = FixedOsv {
            answer: true,
            calls: AtomicUsize::new(0),
            allowed: 1,
        };
        let decision =
            evaluate_with_fake(&fake, Some(&clear), now, 0, &candidate("left-pad", "1.0.0")).await;

        assert_eq!(
            decision,
            Decision::Deny(crate::policy::DenyReason::BlockedByOsv)
        );
        assert_eq!(
            fake.calls(),
            1,
            "a clean candidate must ask OSV exactly once"
        );
    }

    #[tokio::test]
    async fn check_returns_cached_answer_without_a_batcher_round_trip() {
        let client = client_with_capacity(1, StdDuration::from_secs(60));
        // No batcher is running behind `tx`, so a real second round trip would hang
        // forever rather than "panic on a second call" — the cache is what must stop
        // it from ever being attempted. Seed the cache directly instead of routing
        // the first call through the (nonexistent) batcher.
        client.cache.put(
            (Ecosystem::Npm, "left-pad".to_owned(), "1.0.0".to_owned()),
            true,
            StdDuration::from_secs(60),
        );

        let first = client.check(Ecosystem::Npm, "left-pad", "1.0.0").await;
        let second = client.check(Ecosystem::Npm, "left-pad", "1.0.0").await;
        assert!(first);
        assert!(
            second,
            "the cached answer, not a fresh (and here impossible) round trip"
        );
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
            cache: OsvCache::new(),
            cache_ttl: StdDuration::from_secs(60),
            request_timeout: StdDuration::from_millis(500),
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
            elapsed < StdDuration::from_millis(500),
            "the enqueue must fail open at OSV_ENQUEUE_TIMEOUT, not block; took {elapsed:?}"
        );
    }

    /// A local server that binds and never answers — mirrors `siem.rs`'s rl7 test.
    async fn hung_server() -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        (url, hold)
    }

    #[tokio::test]
    async fn check_fails_open_on_batcher_timeout() {
        let (url, hold) = hung_server().await;
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            StdDuration::from_secs(60),
            StdDuration::from_millis(50),
            OsvMode::Enforce,
            shutdown.clone(),
        );

        let started = Instant::now();
        let matched = client.check(Ecosystem::Npm, "left-pad", "1.0.0").await;
        let elapsed = started.elapsed();
        assert!(!matched, "a hung collector fails the check open");
        assert!(
            elapsed < OSV_BATCH_INTERVAL,
            "resolve must bound the reply wait to request_timeout (C12c/C14), not the \
             batcher's own OSV_BATCH_INTERVAL flush cadence; took {elapsed:?}"
        );

        shutdown.cancel();
        let _ = handle.await;
        hold.abort();
    }

    /// The adversarial-testing regression: a *solitary* lookup — nothing else fills
    /// the batch to `OSV_BATCH_RECORDS`, so only `OSV_BATCH_INTERVAL` (2s) would
    /// ever trigger a flush — must still return within `request_timeout`. Before the
    /// fix, `resolve` awaited the batcher's reply with no bound of its own, so a
    /// caller waited on `OSV_BATCH_INTERVAL` (or longer, if the collector itself was
    /// also slow) rather than on `request_timeout` — `check`'s own doc comment and
    /// the design's C12c/C14 promise ("never blocks past request_timeout") were both
    /// false in exactly this ordinary, non-adversarial shape. `request_timeout` here
    /// is two orders of magnitude under `OSV_BATCH_INTERVAL`, so a pass proves the
    /// bound is `request_timeout`, not a coincidence of two similar durations.
    #[tokio::test]
    async fn check_bounds_a_solitary_lookup_to_request_timeout_not_the_batch_interval() {
        let (url, hold) = hung_server().await;
        let shutdown = CancellationToken::new();
        let request_timeout = StdDuration::from_millis(20);
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            StdDuration::from_secs(60),
            request_timeout,
            OsvMode::Enforce,
            shutdown.clone(),
        );

        let started = Instant::now();
        let matched = client.check(Ecosystem::Npm, "left-pad", "1.0.0").await;
        let elapsed = started.elapsed();

        assert!(!matched, "an unresolved lookup fails open");
        assert!(
            elapsed < OSV_BATCH_INTERVAL / 10,
            "a solitary lookup must be bounded by request_timeout ({request_timeout:?}), \
             not by waiting for a flush the batch never fills toward on its own; took \
             {elapsed:?}, OSV_BATCH_INTERVAL is {OSV_BATCH_INTERVAL:?}"
        );

        shutdown.cancel();
        let _ = handle.await;
        hold.abort();
    }

    #[tokio::test]
    async fn check_writes_negative_ttl_on_failure() {
        let (url, hold) = hung_server().await;
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            // A long positive TTL and a short negative one, so the two are easy to
            // tell apart: if the failure were cached at the positive TTL a second
            // call would still be answered from cache (which this cannot observe
            // directly), but a negative entry re-resolves once the batcher can
            // answer, since it expires quickly.
            StdDuration::from_secs(60),
            StdDuration::from_millis(50),
            OsvMode::Enforce,
            shutdown.clone(),
        );

        let key = (Ecosystem::Npm, "left-pad".to_owned(), "1.0.0".to_owned());
        assert!(!client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        let cached = client
            .cache
            .get(&key)
            .expect("a failure still writes a cache entry");
        assert!(!cached);

        // The entry must not still be readable once OSV_NEGATIVE_TTL has passed —
        // `OsvCache::get` treats an expired entry as absent.
        tokio::time::sleep(OSV_NEGATIVE_TTL + StdDuration::from_millis(10)).await;
        assert!(
            client.cache.get(&key).is_none(),
            "a failure's cache entry must use the short negative TTL, not the 60s positive one"
        );

        shutdown.cancel();
        let _ = handle.await;
        hold.abort();
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
        drop(client);
        shutdown.cancel();
        handle.await.expect("the one spawned batcher task joins");
    }

    // ---------------------------------------------------------------------------
    // `osv_mode` (D5): `evaluate` built against a real `OsvClient` via `spawn_with`
    // against a local mock server, mirroring `osv::batcher`'s own `counting_server`
    // pattern rather than the hand-duplicated `evaluate_with_fake` helper above —
    // `mode` lives on the real client, so only a real client exercises it.
    // ---------------------------------------------------------------------------

    /// A `wiremock` server answering every `POST /v1/querybatch` with a fixed
    /// matched/unmatched verdict for every query in the batch, and counting how many
    /// requests it received.
    async fn mode_server(
        matched: bool,
    ) -> (
        Url,
        wiremock::MockServer,
        std::sync::Arc<AtomicUsize>,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&count);
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
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"results": results}))
            })
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/v1/querybatch", server.uri())).unwrap();
        (url, server, count)
    }

    /// A `wiremock` server that panics if it is ever asked — `off` mode must never
    /// call `OsvClient::check`.
    async fn panicking_server() -> (Url, wiremock::MockServer) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(|_: &wiremock::Request| {
                panic!("off mode must never ask OSV");
                #[allow(unreachable_code)]
                ResponseTemplate::new(200)
            })
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/v1/querybatch", server.uri())).unwrap();
        (url, server)
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

    #[tokio::test]
    async fn evaluate_off_mode_never_calls_check() {
        let (url, _server) = panicking_server().await;
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            StdDuration::from_secs(60),
            StdDuration::from_millis(500),
            OsvMode::Off,
            shutdown.clone(),
        );

        let now = 10_000_000;
        let snapshot = clean_snapshot(now);
        let decision = evaluate(&client, Some(&snapshot), now, 0, &candidate("left-pad", "1.0.0"))
            .await;

        assert_eq!(decision, Decision::Allow, "off mode never asks OSV");

        shutdown.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn evaluate_enforce_mode_denies_on_match() {
        let (url, _server, _count) = mode_server(true).await;
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            StdDuration::from_secs(60),
            OSV_BATCH_INTERVAL + StdDuration::from_secs(1),
            OsvMode::Enforce,
            shutdown.clone(),
        );

        let now = 10_000_000;
        let snapshot = clean_snapshot(now);
        let decision = evaluate(&client, Some(&snapshot), now, 0, &candidate("left-pad", "1.0.0"))
            .await;

        assert_eq!(
            decision,
            Decision::Deny(crate::policy::DenyReason::BlockedByOsv)
        );

        shutdown.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn evaluate_diagnostic_mode_allows_on_match() {
        let (url, _server, _count) = mode_server(true).await;
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            StdDuration::from_secs(60),
            OSV_BATCH_INTERVAL + StdDuration::from_secs(1),
            OsvMode::Diagnostic,
            shutdown.clone(),
        );

        let now = 10_000_000;
        let snapshot = clean_snapshot(now);
        let decision = evaluate(&client, Some(&snapshot), now, 0, &candidate("left-pad", "1.0.0"))
            .await;

        assert_eq!(decision, Decision::Allow, "diagnostic mode never denies");

        shutdown.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn evaluate_diagnostic_mode_allows_without_match() {
        let (url, _server, _count) = mode_server(false).await;
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::new(),
            url,
            StdDuration::from_secs(60),
            OSV_BATCH_INTERVAL + StdDuration::from_secs(1),
            OsvMode::Diagnostic,
            shutdown.clone(),
        );

        let now = 10_000_000;
        let snapshot = clean_snapshot(now);
        let decision = evaluate(&client, Some(&snapshot), now, 0, &candidate("left-pad", "1.0.0"))
            .await;

        assert_eq!(decision, Decision::Allow);

        shutdown.cancel();
        let _ = handle.await;
    }

    // ---------------------------------------------------------------------------
    // `App::start`/`Running::shutdown` wiring (tests 17/18 of Slice 1's scope).
    //
    // `AppDeps::osv` (see its doc comment) is a finished, already-spawned
    // `osv::OsvClient`, because `App::start` does not create the `CancellationToken`
    // it uses for its own background loops until it is already deep inside
    // constructing `App` — well after `AppDeps` has to exist. This is why
    // `App::start` cannot be the one calling `osv::OsvClient::new` (it would need a
    // token it does not have yet), and, in turn, why `Running::shutdown` does not
    // literally await this batcher's `JoinHandle`: nothing in `AppDeps`'s declared
    // shape carries a handle for it to join. What *is* true, and what these two
    // tests check: `App::start` wires exactly the client it was given into `App`
    // (not a second one, not none), and that client's batcher — proven independently
    // by `osv_client_new_spawns_one_batcher_task` and
    // `batcher_drains_after_shutdown_signal` above — responds to its own shutdown
    // token and joins promptly once cancelled, which is the actual mechanism D3
    // cares about.
    // ---------------------------------------------------------------------------

    struct NoopTransport;

    #[async_trait::async_trait]
    impl crate::upstream::Transport for NoopTransport {
        async fn fetch_metadata(
            &self,
            _req: crate::upstream::MetadataRequest,
        ) -> Result<crate::upstream::MetadataResponse, crate::upstream::UpstreamError> {
            Err(crate::upstream::UpstreamError::Status(404))
        }

        async fn open_artifact(
            &self,
            _req: crate::upstream::ArtifactRequest,
        ) -> Result<crate::upstream::ArtifactBody, crate::upstream::UpstreamError> {
            Err(crate::upstream::UpstreamError::Status(404))
        }
    }

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
            transport: std::sync::Arc::new(NoopTransport),
            // `OriginSet::for_tests` is deliberately not used here:
            // `no_config_key_or_env_var_relaxes_origins` asserts it is named only in
            // its own defining file. `NoopTransport` never dials out, so the real
            // production origins are exactly as inert here as a fake set would be.
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
