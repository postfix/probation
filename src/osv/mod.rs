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
//! answers `false`, the same as a confirmed non-match. Failures cache nothing
//! (C-S16-1); only a real non-match is cached, for a short negative TTL.

pub(crate) mod batcher;
pub mod matches;

pub use batcher::osv_ecosystem;

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lru::LruCache;
use reqwest::Client;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use probation_policy::OsvSetting;
use probation_policy::api::OsvScope;

use crate::managed::report::UpstreamHealth;
use crate::policy::{self, Candidate, CompiledPolicy, Decision, Ecosystem};

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

/// How long a confirmed non-match stays cached: far shorter than a match's TTL, so a
/// package OSV later flags is not remembered as clean for long. A failed lookup has
/// no answer and is never cached (C-S16-1).
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

/// How OSV enforcement behaves (C16-C18b, D5) in standalone: compiled into the
/// standalone policy's OSV setting (`CompiledPolicy::standalone`), which [`evaluate`]
/// reads.
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

/// A matched entry of a managed endpoint (C1031): refused on past its TTL, until
/// `stale_until`, while the server cannot be asked.
struct MatchedEntry {
    expires_at: Instant,
    stale_until: Instant,
}

type Key = (Ecosystem, String, String);

/// What `OsvCache` keeps only in managed mode: matched entries exempt from LRU eviction
/// and capped, the stale window, persistence and the counters.
struct Retained {
    stale_window: Duration,
    path: Option<PathBuf>,
    health: Arc<UpstreamHealth>,
}

struct Inner {
    /// Bounded at `OSV_CACHE_ENTRIES`, least recently used out first; an expired
    /// entry is also dropped as soon as a lookup finds it. In managed mode only
    /// confirmed no-matches live here.
    lru: LruCache<Key, CacheEntry>,
    /// Managed mode only.
    matched: HashMap<Key, MatchedEntry>,
    dirty: bool,
}

/// The cache as a `put` hook sees it: between the store and the generation bump.
pub struct PutView<'a> {
    inner: &'a Inner,
    now: Instant,
}

impl PutView<'_> {
    pub fn get(&self, ecosystem: Ecosystem, name: &str, version: &str) -> Option<bool> {
        let key = (ecosystem, name.to_owned(), version.to_owned());
        if let Some(entry) = self.inner.matched.get(&key) {
            return (entry.expires_at > self.now).then_some(true);
        }
        self.inner.lru.peek(&key).filter(|entry| entry.expires_at > self.now).map(|entry| entry.matched)
    }
}

#[cfg(any(test, feature = "test-support"))]
type PutHook = Box<dyn Fn(&PutView<'_>) + Send + Sync>;

/// The short-TTL result cache (C13), internally locked so every caller shares one
/// map without holding a lock of its own. Shared with the batcher, which writes
/// every answer it gets whether or not its waiter is still listening.
pub(crate) struct OsvCache {
    entries: Mutex<Inner>,
    /// The TTL a match is cached for. Only a confirmed non-match is cached, for
    /// `OSV_NEGATIVE_TTL`; a failed lookup has no answer and is never cached.
    match_ttl: Duration,
    /// C1029 `osv_generation`: advances when a stored answer is a match for a key with
    /// no live match before it, the only change that can turn an allow into a deny.
    generation: Arc<AtomicU64>,
    retained: Option<Retained>,
    /// Serialises `persist` (snapshot and write together), so an older snapshot can never be
    /// renamed over a newer file.
    persist_lock: Mutex<()>,
    /// Test clock: milliseconds added to the real clock.
    skew_ms: AtomicU64,
    #[cfg(any(test, feature = "test-support"))]
    put_hook: Mutex<Option<PutHook>>,
}

/// How many matched entries a managed endpoint keeps in memory and on disk.
pub(crate) const OSV_MATCHED_CAP: usize = matches::MAX_ENTRIES;

impl OsvCache {
    fn new(match_ttl: Duration) -> OsvCache {
        OsvCache::build(match_ttl, None)
    }

    fn build(match_ttl: Duration, retained: Option<Retained>) -> OsvCache {
        let capacity = NonZeroUsize::new(OSV_CACHE_ENTRIES).expect("a non-zero bound");
        OsvCache {
            entries: Mutex::new(Inner { lru: LruCache::new(capacity), matched: HashMap::new(), dirty: false }),
            match_ttl,
            generation: Arc::default(),
            retained,
            persist_lock: Mutex::new(()),
            skew_ms: AtomicU64::new(0),
            #[cfg(any(test, feature = "test-support"))]
            put_hook: Mutex::new(None),
        }
    }

    /// A managed endpoint's cache: stale-if-error matches, exempt from eviction, loaded
    /// from and persisted to `path`. An unreadable file loads empty and never blocks.
    fn managed(match_ttl: Duration, stale_window: Duration, path: Option<PathBuf>, health: Arc<UpstreamHealth>) -> OsvCache {
        let cache = OsvCache::build(match_ttl, Some(Retained { stale_window, path: path.clone(), health: Arc::clone(&health) }));
        if let Some(path) = path
            && path.exists()
        {
            let now = cache.now();
            let wall = cache.wall();
            match matches::read_bounded(&path) {
                None => health.add_osv_matches_file_degraded(1),
                Some(bytes) => {
                    let loaded = matches::load_matches(&bytes, wall, stale_window);
                    if !loaded.header_ok {
                        health.add_osv_matches_file_degraded(1);
                    }
                    health.add_osv_matches_records_skipped(loaded.skipped);
                    let wall_unix = wall.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
                    let mut inner = cache.entries.lock().expect("the OSV cache");
                    for entry in loaded.entries {
                        let remaining = Duration::from_secs(entry.expiry_unix.saturating_sub(wall_unix));
                        // Past its TTL by construction: asked again as soon as the server is.
                        inner.matched.insert(
                            (entry.ecosystem, entry.name, entry.version),
                            MatchedEntry { expires_at: now, stale_until: now + remaining },
                        );
                    }
                }
            }
        }
        cache
    }

    /// Shared handle to the C1029 counter, for a response to compare before handoff.
    pub(crate) fn generation(&self) -> &Arc<AtomicU64> {
        &self.generation
    }

    fn now(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.skew_ms.load(Ordering::Relaxed))
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now() + Duration::from_millis(self.skew_ms.load(Ordering::Relaxed))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn advance(&self, by: Duration) {
        self.skew_ms.fetch_add(by.as_millis() as u64, Ordering::Relaxed);
    }

    /// A live answer only: an expired or absent one is `None`, and so is a matched entry
    /// past its TTL (it is asked again, and kept for [`OsvCache::stale_match`]).
    fn get(&self, key: &Key) -> Option<bool> {
        let now = self.now();
        let mut inner = self.entries.lock().expect("the OSV cache");
        if let Some(entry) = inner.matched.get(key) {
            if entry.expires_at > now {
                return Some(true);
            }
            if entry.stale_until <= now {
                inner.matched.remove(key);
                inner.dirty = true;
                if let Some(retained) = &self.retained {
                    retained.health.add_osv_stale_matches_expired(1);
                }
            }
            return None;
        }
        match inner.lru.get(key) {
            Some(entry) if entry.expires_at > now => return Some(entry.matched),
            Some(_) => {}
            None => return None,
        }
        inner.lru.pop(key);
        None
    }

    /// Whether a matched entry past its TTL is still inside its stale window: the answer
    /// of a failed or degraded lookup (C1031). Never extends a no-match.
    fn stale_match(&self, key: &Key) -> bool {
        if self.retained.is_none() {
            return false;
        }
        let now = self.now();
        let mut inner = self.entries.lock().expect("the OSV cache");
        match inner.matched.get(key) {
            Some(entry) if entry.stale_until > now => true,
            Some(_) => {
                inner.matched.remove(key);
                inner.dirty = true;
                if let Some(retained) = &self.retained {
                    retained.health.add_osv_stale_matches_expired(1);
                }
                false
            }
            None => false,
        }
    }

    pub(crate) fn put(&self, key: Key, matched: bool) {
        let now = self.now();
        let mut inner = self.entries.lock().expect("the OSV cache");
        let was_live_match = match inner.matched.get(&key) {
            Some(entry) => entry.expires_at > now,
            None => inner.lru.peek(&key).is_some_and(|entry| entry.matched && entry.expires_at > now),
        };
        match &self.retained {
            Some(retained) if matched => {
                inner.lru.pop(&key);
                inner.matched.insert(
                    key,
                    MatchedEntry { expires_at: now + self.match_ttl, stale_until: now + self.match_ttl + retained.stale_window },
                );
                // The memory cap: nearest expiry out, counted as a health warning.
                while inner.matched.len() > OSV_MATCHED_CAP {
                    let nearest = inner.matched.iter().min_by_key(|(_, e)| e.stale_until).map(|(k, _)| k.clone());
                    match nearest {
                        Some(k) => inner.matched.remove(&k),
                        None => break,
                    };
                    retained.health.add_osv_matches_file_degraded(1);
                }
                inner.dirty = true;
            }
            retained => {
                if retained.is_some() && inner.matched.remove(&key).is_some() {
                    inner.dirty = true;
                }
                let ttl = if matched { self.match_ttl } else { OSV_NEGATIVE_TTL };
                inner.lru.put(key, CacheEntry { matched, expires_at: now + ttl });
            }
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(hook) = self.put_hook.lock().expect("the put hook").as_ref() {
            hook(&PutView { inner: &inner, now });
        }
        if matched && !was_live_match {
            self.generation.fetch_add(1, Ordering::Release);
        }
    }

    /// Writes the matched entries when they changed since the last write. Blocking file
    /// I/O: the batcher calls it from `spawn_blocking`.
    fn persist(&self) {
        let Some(retained) = &self.retained else { return };
        let Some(path) = &retained.path else { return };
        let _serial = self.persist_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = self.now();
        let wall_unix = self.wall().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let entries: Vec<(Ecosystem, String, String, u64)> = {
            let mut inner = self.entries.lock().expect("the OSV cache");
            if !inner.dirty {
                return;
            }
            inner.dirty = false;
            inner
                .matched
                .iter()
                .filter(|(_, e)| e.stale_until > now)
                .map(|((eco, name, version), e)| (*eco, name.clone(), version.clone(), wall_unix + e.stale_until.saturating_duration_since(now).as_secs()))
                .collect()
        };
        let rendered = matches::render_matches(&entries);
        if rendered.dropped > 0 {
            retained.health.add_osv_matches_file_degraded(1);
        }
        if let Err(err) = matches::write_atomic(path, &rendered.bytes) {
            tracing::warn!(error = %err, "the persisted OSV matches could not be written");
            retained.health.add_osv_matches_file_degraded(1);
            self.entries.lock().expect("the OSV cache").dirty = true;
        }
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
}

/// Where a managed endpoint's OSV lookups go: the policy server's `<origin>/osv` and the
/// credential the endpoint already uses for that server. The credential is attached
/// only to requests whose origin equals `base`'s, decided when the target is built.
pub struct CentralTarget {
    pub base: Url,
    pub credential: String,
}

/// Managed-mode OSV settings (C1030, C1031).
pub struct CentralOptions {
    /// Test seam: allow an http server URL. Production never sets it; the credential still
    /// goes only to the configured origin and redirects are never followed.
    pub allow_http: bool,
    pub cache_ttl: Duration,
    pub request_timeout: Duration,
    /// `osv_stale_match_seconds`.
    pub stale_window: Duration,
    /// `<data_dir>/osv-matches`; `None` keeps matches in memory only.
    pub matches_path: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CentralBaseError;

/// The OSV base URL of a policy server: `<server origin>/osv`, built by path segment.
/// https is required unless `allow_http` (the test seam only); userinfo, query and
/// fragment are refused.
pub fn central_base(server: &Url, allow_http: bool) -> Result<Url, CentralBaseError> {
    let scheme_ok = server.scheme() == "https" || (allow_http && server.scheme() == "http");
    if !scheme_ok
        || server.host().is_none()
        || !server.username().is_empty()
        || server.password().is_some()
        || server.query().is_some()
        || server.fragment().is_some()
    {
        return Err(CentralBaseError);
    }
    let mut base = server.clone();
    base.path_segments_mut().map_err(|()| CentralBaseError)?.pop_if_empty().push("osv");
    Ok(base)
}

/// The dedicated OSV client of a managed endpoint: redirects disabled, https required
/// unless `allow_http` (the test seam).
fn central_http_client(allow_http: bool) -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!allow_http)
        .build()
        .expect("a client with no custom TLS is always buildable")
}

/// The effective OSV scope of a registry (LS-F12): a registry on its family's fixed
/// public source is `Public`; for any other target the explicit field wins, and an absent
/// field is `Public` (no protection is removed; the operator may set `Private`).
pub fn effective_scope(ecosystem: Ecosystem, target_url: Option<&str>, explicit: Option<OsvScope>) -> OsvScope {
    let Some(target_url) = target_url else {
        // No custom target: the family's own public registry.
        return OsvScope::Public;
    };
    let target_url = Some(target_url);
    let fixed: &[&str] = match ecosystem {
        Ecosystem::Npm => &["registry.npmjs.org"],
        Ecosystem::PyPi => &["pypi.org", "files.pythonhosted.org"],
        Ecosystem::RubyGems => &["rubygems.org", "index.rubygems.org"],
        Ecosystem::Cargo => &["index.crates.io", "static.crates.io"],
        Ecosystem::Go => &["proxy.golang.org", "sum.golang.org"],
    };
    let public_source = target_url
        .and_then(|text| Url::parse(text).ok())
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|host| fixed.contains(&host.as_str()));
    if public_source { OsvScope::Public } else { explicit.unwrap_or(OsvScope::Public) }
}

impl OsvClient {
    /// Spawns the batcher once and returns the client handle plus the batcher's
    /// `JoinHandle`. `App::start` calls this with its `drain` token and puts the
    /// handle in the task set `Running::shutdown` joins. Every batch's outcome is
    /// recorded in `upstreams` (C69).
    pub fn new(
        client: Client,
        cache_ttl: Duration,
        request_timeout: Duration,
        shutdown: CancellationToken,
        upstreams: Arc<UpstreamHealth>,
    ) -> (OsvClient, JoinHandle<()>) {
        let url = Url::parse(OSV_QUERYBATCH_URL).expect("a fixed, valid URL");
        OsvClient::spawn_with(client, url, cache_ttl, request_timeout, shutdown, upstreams)
    }

    /// The constructor behind [`OsvClient::new`], parameterised over the endpoint —
    /// production always calls `new`, which pins it to the real OSV endpoint; tests
    /// call this directly to point the batcher at a local server instead.
    ///
    /// `pub(crate)` rather than private so `App::start` can also reach it when an
    /// `AppDeps::osv_base_url` override is present — the only other caller, besides
    /// this module's own unit tests, that needs a batcher pointed at anything but
    /// the fixed production endpoint.
    pub fn spawn_with(
        client: Client,
        url: Url,
        cache_ttl: Duration,
        request_timeout: Duration,
        shutdown: CancellationToken,
        upstreams: Arc<UpstreamHealth>,
    ) -> (OsvClient, JoinHandle<()>) {
        let cache = Arc::new(OsvCache::new(cache_ttl));
        OsvClient::spawn_on(client, batcher::Target::direct(url), cache, request_timeout, shutdown, upstreams)
    }

    /// A managed endpoint's client (C1030): the same cache, batcher and fail-open rules,
    /// pointed at the policy server. It holds no reference to the policy refusal store, so
    /// nothing it sees can create or clear an authority refusal (LS-F1).
    pub fn spawn_central(
        target: CentralTarget,
        options: CentralOptions,
        shutdown: CancellationToken,
        upstreams: Arc<UpstreamHealth>,
    ) -> (OsvClient, JoinHandle<()>) {
        let cache = Arc::new(OsvCache::managed(
            options.cache_ttl,
            options.stale_window,
            options.matches_path,
            Arc::clone(&upstreams),
        ));
        // Built here, never handed in: redirects off and https only, so no caller can send the
        // credential across an origin by passing a more permissive client (SEC-8).
        let client = central_http_client(options.allow_http);
        OsvClient::spawn_on(client, batcher::Target::central(target), cache, options.request_timeout, shutdown, upstreams)
    }

    fn spawn_on(
        client: Client,
        target: batcher::Target,
        cache: Arc<OsvCache>,
        request_timeout: Duration,
        shutdown: CancellationToken,
        upstreams: Arc<UpstreamHealth>,
    ) -> (OsvClient, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(OSV_CHANNEL_CAPACITY);
        let handle = tokio::spawn(batcher::run(
            client,
            target,
            rx,
            request_timeout,
            Arc::clone(&cache),
            shutdown,
            upstreams,
        ));
        (
            OsvClient {
                tx,
                cache,
                request_timeout: OSV_BATCH_INTERVAL + request_timeout,
            },
            handle,
        )
    }

    /// The C1029 generation counter; read it before an evaluation starts.
    pub fn generation(&self) -> Arc<AtomicU64> {
        Arc::clone(self.cache.generation())
    }

    /// [`OsvClient::cached`], also answering a matched entry past its TTL but inside the stale
    /// window (managed mode): what a log-only "would have blocked" record must see.
    pub fn cached_or_stale(&self, ecosystem: Ecosystem, name: &str, version: &str) -> Option<bool> {
        let key = (ecosystem, name.to_owned(), version.to_owned());
        self.cache.get(&key).or_else(|| self.cache.stale_match(&key).then_some(true))
    }

    /// **Test seam, `test-support` only.** `threads` threads each store one match and persist.
    #[cfg(feature = "test-support")]
    pub fn store_and_persist_concurrently_for_test(&self, threads: usize, round: usize) {
        std::thread::scope(|scope| {
            for i in 0..threads {
                let cache = Arc::clone(&self.cache);
                scope.spawn(move || {
                    cache.put((Ecosystem::Npm, format!("p{round}-{i}"), "1.0.0".to_owned()), true);
                    cache.persist();
                });
            }
        });
    }

    /// The cached answer, if any, without ever querying OSV: `None` after a failure.
    pub fn cached(&self, ecosystem: Ecosystem, name: &str, version: &str) -> Option<bool> {
        self.cache
            .get(&(ecosystem, name.to_owned(), version.to_owned()))
    }

    /// **Test seams, compiled only under `test-support`.** The cache clock, the LS-F14
    /// hook between store and bump, and bulk fills for the eviction and cap cases.
    #[cfg(feature = "test-support")]
    pub fn advance_clock(&self, by: Duration) {
        self.cache.advance(by);
    }

    #[cfg(feature = "test-support")]
    pub fn set_put_hook(&self, hook: PutHook) {
        *self.cache.put_hook.lock().expect("the put hook") = Some(hook);
    }

    #[cfg(feature = "test-support")]
    pub fn fill_unmatched_for_test(&self, count: usize) {
        for i in 0..count {
            self.cache.put((Ecosystem::Npm, format!("fill-{i}"), "1.0.0".to_owned()), false);
        }
    }

    #[cfg(feature = "test-support")]
    pub fn fill_matched_for_test(&self, count: usize) {
        for i in 0..count {
            self.cache.put((Ecosystem::Npm, format!("fill-{i}"), "1.0.0".to_owned()), true);
        }
    }

    #[cfg(feature = "test-support")]
    pub fn matched_len(&self) -> usize {
        self.cache.entries.lock().expect("the OSV cache").matched.len()
    }

    /// `true` only on a confirmed OSV `MAL-*` match. Every failure path — a cache
    /// miss that cannot be resolved, a full or timed-out enqueue (C12a), a batch
    /// failure or length mismatch (C12b/C14), an outbound timeout (C12c) — answers
    /// `false` instead, and none of them is cached: only a real OSV answer reaches
    /// the cache, and only the batcher writes it (see `OsvCache::put` for the TTLs).
    ///
    /// In managed mode a failure keeps answering `true` for a key whose matched entry is
    /// still inside its stale window (C1031).
    pub async fn check(&self, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
        let key = (ecosystem, name.to_owned(), version.to_owned());
        if let Some(matched) = self.cache.get(&key) {
            return matched;
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        let enqueued =
            tokio::time::timeout(OSV_ENQUEUE_TIMEOUT, self.tx.send((key.clone(), reply_tx))).await;
        if !matches!(enqueued, Ok(Ok(()))) {
            return self.cache.stale_match(&key);
        }
        // Bounded even though the batcher always answers (see `batcher::run`): it
        // may still be busy with an earlier flush. A waiter that gives up here still
        // gets its answer cached by the batcher for the next caller.
        match tokio::time::timeout(self.request_timeout, reply_rx).await {
            Ok(Ok(matched)) => matched,
            _ => self.cache.stale_match(&key),
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

/// The OSV address nothing listens on, for tests that are not about OSV and run a
/// managed or shared-service endpoint (the plain test seam: no credential, http). **Compiled
/// only under `test-support`.**
#[cfg(feature = "test-support")]
pub fn unreachable_base_url() -> Url {
    Url::parse("http://127.0.0.1:0/v1/querybatch").expect("a fixed, valid URL")
}

/// The shared C15 two-phase wrapper (D2) every production call site uses in place of
/// a direct `policy::decide` call.
///
/// `policy::decide` is called OSV-blind first; OSV is asked only when that alone would
/// `Allow` the candidate and its rules do not turn OSV off (C110), which is what keeps
/// OSV an OR-only signal (C1) and keeps the OSV round trip off the hot path of a
/// candidate a producer already blocks. A log-only match allows and is recorded the
/// way standalone's `osv_mode = "diagnostic"` always has been (D7).
pub async fn evaluate(
    osv: &OsvClient,
    policy: &CompiledPolicy,
    now_utc_micros: i64,
    candidate: &Candidate<'_>,
) -> Decision {
    evaluate_scoped(osv, policy, now_utc_micros, candidate, OsvScope::Public).await
}

/// [`evaluate`] for a candidate that resolved from a registry of the given OSV scope
/// (LS-F12). A `Private` registry's names are never sent anywhere: the lookup is skipped
/// and the answer is the OSV-blind one (Allow without OSV).
pub async fn evaluate_scoped(
    osv: &OsvClient,
    policy: &CompiledPolicy,
    now_utc_micros: i64,
    candidate: &Candidate<'_>,
    scope: OsvScope,
) -> Decision {
    let blind = policy::decide(policy, candidate, now_utc_micros, false);
    if !matches!(blind.decision, Decision::Allow) {
        return blind.decision;
    }
    let rules = policy
        .policy
        .rules_for(candidate.ecosystem, candidate.name, candidate.version);
    if rules.osv == OsvSetting::Off || scope == OsvScope::Private {
        return blind.decision;
    }

    let matched = osv
        .check(candidate.ecosystem, candidate.name, candidate.version)
        .await;

    let verdict = policy::decide(policy, candidate, now_utc_micros, matched);
    if verdict.would_block {
        crate::http::logging::record_osv_diagnostic_match();
    }
    verdict.decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BlocklistSnapshot, PublicationTime};
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
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), request_timeout);

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

    /// A failed lookup caches nothing, so `cached` stays `None` and costs no query.
    #[tokio::test]
    async fn cached_is_none_after_a_failed_lookup() {
        let (url, _server, count) = osv_server(500, true, StdDuration::ZERO).await;
        let (client, _handle, _shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
        assert!(!client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        let seen = count.load(Ordering::SeqCst);
        assert_eq!(client.cached(Ecosystem::Npm, "left-pad", "1.0.0"), None);
        assert_eq!(count.load(Ordering::SeqCst), seen, "cached never queries");
    }

    #[tokio::test]
    async fn osv_client_new_spawns_one_batcher_task() {
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::new(
            Client::builder().no_proxy().build().expect("a client"),
            StdDuration::from_secs(60),
            StdDuration::from_millis(50),
            shutdown.clone(),
            Arc::default(),
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

        // A server of its own, not one from wiremock's shared pool: a pooled server
        // passes from test to test, and a request one test left half-sent is counted
        // by the next.
        let server = MockServer::builder().start().await;
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

    /// Rework 3: a test's OSV stand-in counts only that test's requests. A request
    /// another test left half-sent, finished after that test's stand-in is gone and
    /// this one has started, is not counted here (`evaluate_enforce_mode_denies_on_match`
    /// once read 2 for 1 this way under load).
    #[tokio::test]
    async fn a_request_another_test_left_half_sent_is_not_counted_here() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (url, earlier, _) = mode_server(true).await;
        let addr = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
        let mut late = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let body =
            br#"{"queries":[{"package":{"name":"left-pad","ecosystem":"npm"},"version":"1.0.0"}]}"#;
        let head = format!(
            "POST /v1/querybatch HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        late.write_all(head.as_bytes()).await.unwrap();
        drop(earlier);

        let (_url, _server, count) = mode_server(true).await;
        let _ = late.write_all(body).await;
        // Whatever answer the rest of the request gets, it has had it once this returns.
        let mut answer = Vec::new();
        let _ = late.read_to_end(&mut answer).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "the left-over request reached this test's stand-in: {}",
            String::from_utf8_lossy(&answer)
        );
    }

    /// [`osv_server`] answering `200` at once with `matched` for every query.
    async fn mode_server(matched: bool) -> (Url, wiremock::MockServer, Arc<AtomicUsize>) {
        osv_server(200, matched, StdDuration::ZERO).await
    }

    fn spawn(
        url: Url,
        cache_ttl: StdDuration,
        request_timeout: StdDuration,
    ) -> (OsvClient, JoinHandle<()>, CancellationToken) {
        let shutdown = CancellationToken::new();
        let (client, handle) = OsvClient::spawn_with(
            Client::builder().no_proxy().build().expect("a client"),
            url,
            cache_ttl,
            request_timeout,
            shutdown.clone(),
            Arc::default(),
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

    /// The standalone policy `App` compiles for `mode`, zero cooldown and `snapshot`.
    fn standalone(mode: OsvMode, snapshot: BlocklistSnapshot) -> CompiledPolicy {
        CompiledPolicy::standalone(0, mode, Arc::new(snapshot))
    }

    /// `evaluate` on a clean snapshot, against a matching OSV in `mode`: the decision
    /// and how many times OSV was asked.
    async fn evaluate_in(mode: OsvMode, snapshot: BlocklistSnapshot) -> (Decision, usize) {
        let (url, _server, count) = mode_server(true).await;
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
        let decision = evaluate(
            &client,
            &standalone(mode, snapshot),
            10_000_000,
            &candidate("left-pad", "1.0.0"),
        )
        .await;
        shutdown.cancel();
        let _ = handle.await;
        (decision, count.load(Ordering::SeqCst))
    }

    /// LS-F12: the OSV lookup runs only for a Public registry; a Private one is
    /// Allow-without-OSV and its names reach nothing.
    #[tokio::test]
    async fn osv_skipped_for_private_registry() {
        for (scope, asked) in [(OsvScope::Private, 0), (OsvScope::Public, 1)] {
            let (url, _server, count) = mode_server(true).await;
            let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
            let decision = evaluate_scoped(
                &client,
                &standalone(OsvMode::Enforce, clean_snapshot(10_000_000)),
                10_000_000,
                &candidate("left-pad", "1.0.0"),
                scope,
            )
            .await;
            shutdown.cancel();
            let _ = handle.await;
            assert_eq!(count.load(Ordering::SeqCst), asked, "{scope:?}");
            assert_eq!(matches!(decision, Decision::Allow), scope == OsvScope::Private, "{scope:?}: {decision:?}");
        }
    }

    fn gem_candidate<'a>(name: &'a str, version: &'a str) -> Candidate<'a> {
        Candidate { ecosystem: Ecosystem::RubyGems, ..candidate(name, version) }
    }

    /// Row 17, LS-F12: a RubyGems registry the operator sets Private is never asked about
    /// (its gem names reach nothing), and the effective scope is what decides.
    #[tokio::test]
    async fn osv_skipped_for_private_registry_in_rubygems() {
        let mirror = "https://gems.corp.example/";
        let scope = effective_scope(Ecosystem::RubyGems, Some(mirror), Some(OsvScope::Private));
        assert_eq!(scope, OsvScope::Private);
        let (url, _server, count) = mode_server(true).await;
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
        let decision = evaluate_scoped(&client, &standalone(OsvMode::Enforce, clean_snapshot(10_000_000)), 10_000_000, &gem_candidate("internal-gem", "1.0.0"), scope).await;
        shutdown.cancel();
        let _ = handle.await;
        assert_eq!(count.load(Ordering::SeqCst), 0, "a Private registry's gem name reaches no OSV server");
        assert!(matches!(decision, Decision::Allow), "{decision:?}");
        // The fixed public source ignores the field: rubygems.org is always Public.
        assert_eq!(effective_scope(Ecosystem::RubyGems, Some("https://rubygems.org/"), Some(OsvScope::Private)), OsvScope::Public);
        assert_eq!(effective_scope(Ecosystem::RubyGems, Some("https://index.rubygems.org/"), Some(OsvScope::Private)), OsvScope::Public);
    }

    /// Row 17, LS-F12: a public mirror whose operator says Public (and a custom mirror
    /// with no field, the user decision of 2026-11-18) is queried, and a MAL match denies.
    #[tokio::test]
    async fn osv_public_mirror_with_explicit_scope_is_queried() {
        let mirror = "https://mirror.example/rubygems/";
        for explicit in [Some(OsvScope::Public), None] {
            let scope = effective_scope(Ecosystem::RubyGems, Some(mirror), explicit);
            assert_eq!(scope, OsvScope::Public, "{explicit:?}");
            let (url, _server, count) = mode_server(true).await;
            let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
            let decision = evaluate_scoped(&client, &standalone(OsvMode::Enforce, clean_snapshot(10_000_000)), 10_000_000, &gem_candidate("rack", "9.9.9"), scope).await;
            shutdown.cancel();
            let _ = handle.await;
            assert_eq!(count.load(Ordering::SeqCst), 1, "{explicit:?}: the public mirror is queried");
            assert!(!matches!(decision, Decision::Allow), "{explicit:?}: a MAL match denies: {decision:?}");
        }
    }

    fn cargo_candidate<'a>(name: &'a str, version: &'a str) -> Candidate<'a> {
        Candidate { ecosystem: Ecosystem::Cargo, ..candidate(name, version) }
    }

    /// Row 18, LS-F12: a Cargo registry the operator sets Private is never asked about (its
    /// crate names reach nothing); the fixed public source ignores the field.
    #[tokio::test]
    async fn osv_skipped_for_private_registry_in_cargo() {
        let mirror = "https://crates.corp.example/index/";
        let scope = effective_scope(Ecosystem::Cargo, Some(mirror), Some(OsvScope::Private));
        assert_eq!(scope, OsvScope::Private);
        let (url, _server, count) = mode_server(true).await;
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
        let decision = evaluate_scoped(&client, &standalone(OsvMode::Enforce, clean_snapshot(10_000_000)), 10_000_000, &cargo_candidate("internal-crate", "1.0.0"), scope).await;
        shutdown.cancel();
        let _ = handle.await;
        assert_eq!(count.load(Ordering::SeqCst), 0, "a Private registry's crate name reaches no OSV server");
        assert!(matches!(decision, Decision::Allow), "{decision:?}");
        for public in ["https://index.crates.io/", "https://static.crates.io/crates"] {
            assert_eq!(effective_scope(Ecosystem::Cargo, Some(public), Some(OsvScope::Private)), OsvScope::Public, "{public}");
        }
    }

    /// Row 18, LS-F12: a mirror whose operator says Public, and one with no field (the user
    /// decision of 2026-11-18), is queried, and a MAL match denies.
    #[tokio::test]
    async fn osv_public_mirror_with_explicit_scope_is_queried_in_cargo() {
        let mirror = "https://mirror.example/cargo/";
        for explicit in [Some(OsvScope::Public), None] {
            let scope = effective_scope(Ecosystem::Cargo, Some(mirror), explicit);
            assert_eq!(scope, OsvScope::Public, "{explicit:?}");
            let (url, _server, count) = mode_server(true).await;
            let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
            let decision = evaluate_scoped(&client, &standalone(OsvMode::Enforce, clean_snapshot(10_000_000)), 10_000_000, &cargo_candidate("serde-json", "9.9.9"), scope).await;
            shutdown.cancel();
            let _ = handle.await;
            assert_eq!(count.load(Ordering::SeqCst), 1, "{explicit:?}: the public mirror is queried");
            assert!(!matches!(decision, Decision::Allow), "{explicit:?}: a MAL match denies: {decision:?}");
        }
    }

    fn go_candidate<'a>(name: &'a str, version: &'a str) -> Candidate<'a> {
        Candidate { ecosystem: Ecosystem::Go, ..candidate(name, version) }
    }

    /// Row 19, LS-F12 (`osv_skipped_for_private_registry_in_go`): a Go registry the operator sets
    /// Private is never asked about (its module paths reach nothing); the fixed public sources ignore
    /// the field.
    #[tokio::test]
    async fn osv_skipped_for_private_registry_in_go() {
        let mirror = "https://goproxy.corp.example/artifactory/api/go/repo/";
        let scope = effective_scope(Ecosystem::Go, Some(mirror), Some(OsvScope::Private));
        assert_eq!(scope, OsvScope::Private);
        let (url, _server, count) = mode_server(true).await;
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
        let decision = evaluate_scoped(&client, &standalone(OsvMode::Enforce, clean_snapshot(10_000_000)), 10_000_000, &go_candidate("corp.example/internal", "1.0.0"), scope).await;
        shutdown.cancel();
        let _ = handle.await;
        assert_eq!(count.load(Ordering::SeqCst), 0, "a Private registry's module path reaches no OSV server");
        assert!(matches!(decision, Decision::Allow), "{decision:?}");
        for public in ["https://proxy.golang.org/", "https://sum.golang.org/"] {
            assert_eq!(effective_scope(Ecosystem::Go, Some(public), Some(OsvScope::Private)), OsvScope::Public, "{public}");
        }
    }

    /// Row 19, LS-F12 (`osv_public_mirror_with_explicit_scope_is_queried`): a mirror whose operator
    /// says Public, and one with no field (the user decision of 2026-11-18), is queried, and a MAL
    /// match denies.
    #[tokio::test]
    async fn osv_public_mirror_with_explicit_scope_is_queried_in_go() {
        let mirror = "https://goproxy.mirror.example/";
        for explicit in [Some(OsvScope::Public), None] {
            let scope = effective_scope(Ecosystem::Go, Some(mirror), explicit);
            assert_eq!(scope, OsvScope::Public, "{explicit:?}");
            let (url, _server, count) = mode_server(true).await;
            let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
            let decision = evaluate_scoped(&client, &standalone(OsvMode::Enforce, clean_snapshot(10_000_000)), 10_000_000, &go_candidate("github.com/Azure/x", "9.9.9"), scope).await;
            shutdown.cancel();
            let _ = handle.await;
            assert_eq!(count.load(Ordering::SeqCst), 1, "{explicit:?}: the public mirror is queried");
            assert!(!matches!(decision, Decision::Allow), "{explicit:?}: a MAL match denies: {decision:?}");
        }
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

        let (decision, asked) = evaluate_in(OsvMode::Enforce, blocked).await;
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
        let (decision, asked) = evaluate_in(OsvMode::Enforce, clean_snapshot(10_000_000)).await;
        assert_eq!(
            decision,
            Decision::Deny(crate::policy::DenyReason::BlockedByOsv)
        );
        assert_eq!(asked, 1, "a clean candidate asks OSV exactly once");
    }

    #[tokio::test]
    async fn evaluate_off_mode_never_calls_check() {
        let (decision, asked) = evaluate_in(OsvMode::Off, clean_snapshot(10_000_000)).await;
        assert_eq!(decision, Decision::Allow);
        assert_eq!(asked, 0, "off mode never asks OSV");
    }

    #[tokio::test]
    async fn evaluate_diagnostic_mode_asks_osv_and_allows_on_match() {
        let (decision, asked) = evaluate_in(OsvMode::Diagnostic, clean_snapshot(10_000_000)).await;
        assert_eq!(decision, Decision::Allow, "diagnostic mode never denies");
        assert_eq!(asked, 1, "diagnostic mode still asks OSV");
    }

    #[tokio::test]
    async fn evaluate_diagnostic_mode_allows_without_match() {
        let (url, _server, count) = mode_server(false).await;
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);
        let now = 10_000_000;
        let decision = evaluate(
            &client,
            &standalone(OsvMode::Diagnostic, clean_snapshot(now)),
            now,
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
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);

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

    /// C1029: the generation advances only when a stored answer can turn an allow into
    /// a deny: a match for a key with no live match before it.
    #[test]
    fn generation_advances_only_on_a_new_match() {
        let cache = OsvCache::new(StdDuration::from_secs(60));
        let key = |v: &str| (Ecosystem::Npm, "left-pad".to_owned(), v.to_owned());
        let seen = || cache.generation().load(Ordering::SeqCst);
        cache.put(key("1"), false);
        assert_eq!(seen(), 0, "a non-match changes no verdict toward deny");
        cache.put(key("1"), true);
        assert_eq!(seen(), 1, "absent or non-match then match is a new deny");
        cache.put(key("1"), true);
        assert_eq!(seen(), 1, "re-storing a live match changes nothing");
        cache.put(key("2"), true);
        assert_eq!(seen(), 2, "a match for an absent key is new");
    }

    /// A match is trusted for `cache_ttl` and no longer: past it OSV is asked again.
    #[tokio::test]
    async fn an_expired_answer_is_asked_again() {
        let (url, _server, count) = mode_server(true).await;
        let cache_ttl = StdDuration::from_millis(50);
        let (client, handle, shutdown) = spawn(url, cache_ttl, SHIPPED_TIMEOUT);

        assert!(client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        tokio::time::sleep(cache_ttl * 2).await;
        assert!(client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert_eq!(count.load(Ordering::SeqCst), 2);

        shutdown.cancel();
        let _ = handle.await;
    }

    /// A failed batch fails open but caches nothing: a failure is not an answer, so the
    /// next caller asks OSV again (and a stored match can never be overwritten by one).
    #[tokio::test]
    async fn a_failed_lookup_fails_open_and_caches_nothing() {
        let (url, _server, count) = osv_server(500, true, StdDuration::ZERO).await;
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);

        assert!(!client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert!(!client.check(Ecosystem::Npm, "left-pad", "1.0.0").await);
        assert_eq!(count.load(Ordering::SeqCst), 2, "a failure is not cached, so OSV is asked again");

        shutdown.cancel();
        let _ = handle.await;
    }

    /// The cache is bounded: once `OSV_CACHE_ENTRIES` other lookups have been
    /// answered since, the oldest answer is gone and OSV is asked again.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_cache_forgets_its_oldest_answer_past_its_bound() {
        let (url, server, _count) = mode_server(true).await;
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(600), SHIPPED_TIMEOUT);
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
        let (client, handle, shutdown) = spawn(url, StdDuration::from_secs(60), SHIPPED_TIMEOUT);

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
            osv_server_origin_override: None,
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
