//! Central OSV lookup (C1030, row 30): an osv.dev-compatible `POST /osv/v1/querybatch`
//! answered from one upstream client and one shared cache.
//!
//! The route accepts a closed set of credentials (a live firewall token or a live
//! service key) and nothing else; it has its own rate budget, concurrency and
//! circuit breaker so it can never starve `/sync`. Upstream trouble is never a 5xx:
//! the affected queries carry `probation_degraded` and the envelope says
//! `upstream_ok: false` (fail-open, C3/C14). The server holds no reference to the
//! policy refusal store: a 401 here is never a policy authority refusal (LS-F1).
//!
//! Only `MAL-*` vulnerability refs are relayed: the endpoint's verdict is a `MAL-*`
//! match and nothing else, so the server stores and returns exactly that.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use lru::LruCache;
use probation_policy::Ecosystem;
use probation_policy::osv_key::{OsvKey, osv_key};
use probation_policy::osv_wire::{EnvelopeError, RenderedResult, parse_request, render_answer};
use serde::Deserialize;
use tokio::sync::{Semaphore, watch};

use crate::sync::{OsvCaller, SyncError, SyncState, Tenant};

pub const UPSTREAM_URL: &str = "https://api.osv.dev/v1/querybatch";

/// LS-F7 numeric bounds, all in one place. `Default` is the shipped value.
#[derive(Clone, Debug)]
pub struct OsvLimits {
    /// Request body cap, checked before parse.
    pub body_cap: usize,
    /// Queries per batch; never below the client's 256.
    pub batch_max: usize,
    /// Cache-missing keys per credential per minute (`osv_key_rate_per_minute`).
    pub key_rate_per_minute: u32,
    pub key_burst: u32,
    /// Global concurrent upstream calls.
    pub upstream_concurrency: usize,
    /// The coalescing wait and the upstream timeout: strictly below the client's
    /// `osv_request_timeout_ms` (floor 400 ms).
    pub deadline: Duration,
    /// How long a leader's upstream call may take. It outlives `deadline`: a slow but
    /// successful answer still lands in the cache, so a retry converges.
    pub upstream_timeout: Duration,
    /// Keys one upstream call carries at most (the client's batch).
    pub leader_chunk: usize,
    /// Requests per second one credential may send, cache hits included, and its burst.
    pub request_rate_per_second: u32,
    pub request_burst: u32,
    /// Request bodies parsed at once.
    pub parse_concurrency: usize,
    /// One shared egress: cache-missing keys per minute across every credential.
    pub global_key_rate_per_minute: u32,
    pub global_key_burst: u32,
    /// Pre-auth failure table size (LRU).
    pub preauth_table: usize,
    /// Pages followed for one query before it is degraded.
    pub max_pages: usize,
    /// How long a request body may take to arrive (a dripping body holds nothing meanwhile).
    pub body_read_timeout: Duration,
    /// The most of the shared key budget (burst and refill) one tenant, the place a credential
    /// belongs to, may use, in percent.
    pub tenant_share_percent: u32,
    /// Part of the shared burst kept for tenants that have barely used theirs, in percent.
    pub global_reserve_percent: u32,
    /// Each tenant's own floor, not shared: keys it may ask for even when the shared budget is
    /// down to its reserve (burst, and refill per minute).
    pub tenant_floor_burst: u32,
    pub tenant_floor_per_minute: u32,
    /// Upstream permits kept for rescue calls, so slow chunks cannot starve them.
    pub rescue_permits: usize,
    pub match_ttl: Duration,
    pub nomatch_ttl: Duration,
    pub cache_entries: usize,
    pub cache_bytes: usize,
    pub upstream_read_cap: usize,
    pub preauth_failures_per_minute: usize,
    /// Credential lookups that may use the database at once. OSV auth shares the app pool
    /// with `/sync`, so it is bounded separately and never takes the whole pool.
    pub auth_concurrency: usize,
}

impl Default for OsvLimits {
    fn default() -> Self {
        OsvLimits {
            body_cap: 1 << 20,
            batch_max: 1000,
            key_rate_per_minute: 600,
            key_burst: 1000,
            upstream_concurrency: 8,
            // User decision: server 1500 ms, client default 2000 ms, client floor 1600 ms.
            deadline: Duration::from_millis(1500),
            upstream_timeout: Duration::from_secs(10),
            leader_chunk: 256,
            request_rate_per_second: 100,
            request_burst: 500,
            parse_concurrency: 64,
            global_key_rate_per_minute: 12_000,
            global_key_burst: 3_000,
            preauth_table: 10_000,
            max_pages: 10,
            body_read_timeout: Duration::from_secs(2),
            tenant_share_percent: 25,
            global_reserve_percent: 20,
            tenant_floor_burst: 30,
            tenant_floor_per_minute: 60,
            rescue_permits: 2,
            match_ttl: Duration::from_secs(3600),
            nomatch_ttl: Duration::from_secs(30),
            cache_entries: 200_000,
            cache_bytes: 64 << 20,
            upstream_read_cap: 4 << 20,
            preauth_failures_per_minute: 10,
            auth_concurrency: 4,
        }
    }
}

/// Aggregate counters only; no per-key data is ever logged or counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OsvHealth {
    pub results_total: u64,
    pub results_degraded: u64,
    pub upstream_failures: u64,
    /// Times the upstream breaker opened on a 429 (an alert input).
    pub breaker_openings: u64,
    /// Credential lookups that reached the database.
    pub auth_lookups: u64,
}

#[derive(Clone, Debug)]
enum Answer {
    Matched(Arc<Vec<(String, Option<String>)>>),
    NoMatch,
    Failed,
}

struct Held {
    answer: Answer,
    expires: Instant,
    size: usize,
}

#[derive(Default)]
struct Cache {
    matched: Option<LruCache<OsvKey, Held>>,
    clean: Option<LruCache<OsvKey, Held>>,
    bytes: usize,
}

impl Cache {
    fn lrus(&mut self) -> (&mut LruCache<OsvKey, Held>, &mut LruCache<OsvKey, Held>) {
        let matched = self.matched.get_or_insert_with(LruCache::unbounded);
        let clean = self.clean.get_or_insert_with(LruCache::unbounded);
        (matched, clean)
    }

    fn get(&mut self, key: &OsvKey, now: Instant) -> Option<Answer> {
        let mut dropped = 0;
        let mut found = None;
        {
            let (matched, clean) = self.lrus();
            for lru in [matched, clean] {
                if let Some(held) = lru.get(key) {
                    if held.expires > now {
                        found = Some(held.answer.clone());
                    } else {
                        dropped = held.size;
                        lru.pop(key);
                    }
                    break;
                }
            }
        }
        self.bytes -= dropped;
        found
    }

    fn put(&mut self, key: OsvKey, answer: Answer, expires: Instant, limits: &OsvLimits) {
        let refs = match &answer {
            Answer::Matched(refs) => refs.iter().map(|(a, b)| a.len() + b.as_ref().map_or(0, String::len)).sum(),
            _ => 0,
        };
        let size = key.name.len() + key.version.len() + refs + 96;
        let is_match = matches!(answer, Answer::Matched(_));
        let (matched, clean) = self.lrus();
        let mut freed = 0;
        for lru in [&mut *matched, &mut *clean] {
            if let Some(old) = lru.pop(&key) {
                freed += old.size;
            }
        }
        let target = if is_match { matched } else { clean };
        target.put(key, Held { answer, expires, size });
        self.bytes = self.bytes - freed + size;
        // Entries first leave the clean list; a match goes last (garbage cannot evict one).
        while {
            let (m, c) = (self.matched.as_ref().map_or(0, LruCache::len), self.clean.as_ref().map_or(0, LruCache::len));
            m + c > limits.cache_entries || self.bytes > limits.cache_bytes
        } {
            let (matched, clean) = self.lrus();
            let evicted = clean.pop_lru().or_else(|| matched.pop_lru());
            match evicted {
                Some((_, held)) => self.bytes -= held.size,
                None => break,
            }
        }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

pub struct OsvState {
    sync: Arc<SyncState>,
    http: reqwest::Client,
    upstream: url::Url,
    limits: OsvLimits,
    clock: Clock,
    cache: Mutex<Cache>,
    inflight: Mutex<HashMap<OsvKey, watch::Receiver<Option<Answer>>>>,
    /// Cache-missing keys per credential.
    buckets: Mutex<HashMap<OsvCaller, Bucket>>,
    /// Requests per credential, cache hits included (SEC-4).
    request_buckets: Mutex<HashMap<OsvCaller, Bucket>>,
    /// Keys across every credential (SEC-5), and each tenant's share of them.
    global: Mutex<Option<Bucket>>,
    tenants: Mutex<HashMap<Tenant, Bucket>>,
    /// Each tenant's floor (see `OsvLimits::tenant_floor_burst`).
    floors: Mutex<HashMap<Tenant, Bucket>>,
    /// One rescue call per key: followers of a hot key share it.
    rescue: Mutex<HashMap<OsvKey, watch::Receiver<Option<Answer>>>>,
    rescue_permits: Arc<Semaphore>,
    /// Lookups per credential tag, before the auth gate.
    lookup_buckets: Mutex<LruCache<u64, Bucket>>,
    /// Tags that just failed to authenticate: answered 401 without a lookup for a few seconds.
    failed_tags: Mutex<LruCache<u64, Instant>>,
    auth_lookups: AtomicU64,
    /// Credentials that authenticated recently (hash prefix only): a blocked source may still
    /// use one, every other request from it is turned away without a lookup.
    known_good: Mutex<LruCache<u64, ()>>,
    preauth: Mutex<LruCache<IpAddr, VecDeque<Instant>>>,
    breaker: Mutex<Option<Instant>>,
    permits: Arc<Semaphore>,
    auth_permits: Semaphore,
    parse_permits: Semaphore,
    results_total: AtomicU64,
    results_degraded: AtomicU64,
    upstream_failures: AtomicU64,
    breaker_openings: AtomicU64,
}

impl OsvState {
    /// `upstream` is the full querybatch URL: the fixed api.osv.dev in production and a
    /// fake in tests. The request body never selects it.
    pub fn new(sync: Arc<SyncState>, upstream: url::Url) -> OsvState {
        OsvState::build(sync, upstream, OsvLimits::default())
    }

    fn build(sync: Arc<SyncState>, upstream: url::Url, limits: OsvLimits) -> OsvState {
        OsvState {
            sync,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .build()
                .expect("a client with no custom TLS is always buildable"),
            upstream,
            permits: Arc::new(Semaphore::new(limits.upstream_concurrency)),
            auth_permits: Semaphore::new(limits.auth_concurrency),
            parse_permits: Semaphore::new(limits.parse_concurrency),
            preauth: Mutex::new(LruCache::new(NonZeroUsize::new(limits.preauth_table.max(1)).expect("non-zero"))),
            rescue_permits: Arc::new(Semaphore::new(limits.rescue_permits.max(1))),
            limits,
            clock: Arc::new(Instant::now),
            cache: Mutex::default(),
            inflight: Mutex::default(),
            buckets: Mutex::default(),
            request_buckets: Mutex::default(),
            global: Mutex::new(None),
            tenants: Mutex::default(),
            floors: Mutex::default(),
            rescue: Mutex::default(),
            lookup_buckets: Mutex::new(LruCache::new(NonZeroUsize::new(10_000).expect("non-zero"))),
            failed_tags: Mutex::new(LruCache::new(NonZeroUsize::new(10_000).expect("non-zero"))),
            auth_lookups: AtomicU64::new(0),
            known_good: Mutex::new(LruCache::new(NonZeroUsize::new(10_000).expect("non-zero"))),
            breaker: Mutex::new(None),
            results_total: AtomicU64::new(0),
            results_degraded: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            breaker_openings: AtomicU64::new(0),
        }
    }

    /// The shipped server: the fixed upstream and `key_rate_per_minute` from config.
    pub fn production(sync: Arc<SyncState>, key_rate_per_minute: u32) -> OsvState {
        let url = url::Url::parse(UPSTREAM_URL).expect("a fixed, valid URL");
        OsvState::new(sync, url).with_limits(OsvLimits { key_rate_per_minute, ..OsvLimits::default() })
    }

    pub fn with_limits(mut self, limits: OsvLimits) -> OsvState {
        let clock = Arc::clone(&self.clock);
        self = OsvState::build(self.sync, self.upstream, limits);
        self.clock = clock;
        self
    }

    /// Clock seam for the caches, the rate buckets and the breaker.
    pub fn with_clock(mut self, clock: Clock) -> OsvState {
        self.clock = clock;
        self
    }

    pub fn health(&self) -> OsvHealth {
        OsvHealth {
            results_total: self.results_total.load(Ordering::Relaxed),
            results_degraded: self.results_degraded.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            breaker_openings: self.breaker_openings.load(Ordering::Relaxed),
            auth_lookups: self.auth_lookups.load(Ordering::Relaxed),
        }
    }

    /// How much longer the upstream breaker stays open.
    pub fn breaker_open_for(&self) -> Duration {
        let now = self.now();
        self.breaker
            .lock()
            .expect("the breaker")
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    /// The OSV ecosystem spellings the route accepts: exactly the families for which
    /// the shared mapping is `Some`.
    pub fn allowlist() -> Vec<&'static str> {
        Ecosystem::ALL.into_iter().filter_map(probation::osv::osv_ecosystem).collect()
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    fn ecosystem(spelling: &str) -> Option<Ecosystem> {
        Ecosystem::ALL
            .into_iter()
            .find(|eco| probation::osv::osv_ecosystem(*eco) == Some(spelling))
    }

    fn preauth_blocked(&self, source: IpAddr, now: Instant) -> bool {
        let mut table = self.preauth.lock().expect("the throttle");
        let Some(window) = table.get_mut(&source) else { return false };
        while window.front().is_some_and(|at| now.saturating_duration_since(*at) >= Duration::from_secs(60)) {
            window.pop_front();
        }
        window.len() >= self.limits.preauth_failures_per_minute
    }

    fn preauth_failed(&self, source: IpAddr, now: Instant) {
        // Bounded by the LRU: the oldest source falls out, never a full scan under the lock.
        let mut table = self.preauth.lock().expect("the throttle");
        // A window never holds more than twice the limit, so its memory does not follow the
        // attacker's request rate.
        let cap = self.limits.preauth_failures_per_minute * 2;
        match table.get_mut(&source) {
            Some(window) => {
                if window.len() < cap {
                    window.push_back(now);
                }
            }
            None => {
                table.put(source, VecDeque::from([now]));
            }
        }
    }

    /// Takes `cost` tokens when at least `cost` are there (a `cost` of 0 asks whether one
    /// is). `rate_per_sec` and `burst` shape the refill.
    fn take(bucket: &mut Bucket, now: Instant, rate_per_sec: f64, burst: f64, cost: f64) -> bool {
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate_per_sec).min(burst);
        bucket.last = now;
        let need = cost.max(1.0);
        let ok = bucket.tokens >= need;
        if ok {
            bucket.tokens -= cost;
        }
        ok
    }

    fn take_from(&self, map: &Mutex<HashMap<OsvCaller, Bucket>>, caller: OsvCaller, now: Instant, rate_per_sec: f64, burst: f64, cost: f64) -> bool {
        let mut table = map.lock().expect("the budgets");
        if table.len() > 10_000 {
            table.retain(|_, b| b.tokens < burst);
        }
        let bucket = table.entry(caller).or_insert(Bucket { tokens: burst, last: now });
        OsvState::take(bucket, now, rate_per_sec, burst, cost)
    }

    fn key_rate(&self) -> f64 {
        f64::from(self.limits.key_rate_per_minute) / 60.0
    }

    fn admit(&self, caller: OsvCaller, now: Instant) -> bool {
        self.take_from(&self.buckets, caller, now, self.key_rate(), f64::from(self.limits.key_burst), 0.0)
    }

    fn admit_request(&self, caller: OsvCaller, now: Instant) -> bool {
        self.take_from(
            &self.request_buckets,
            caller,
            now,
            f64::from(self.limits.request_rate_per_second),
            f64::from(self.limits.request_burst),
            1.0,
        )
    }

    /// One cache-missing key: the credential's own budget, its tenant's (organisation's) share,
    /// and the shared budget, which keeps a reserve. Below the reserve a tenant still has its
    /// own floor, so a few busy tenants cannot leave another with nothing.
    fn charge(&self, caller: OsvCaller, now: Instant) -> bool {
        if !self.take_from(&self.buckets, caller, now, self.key_rate(), f64::from(self.limits.key_burst), 1.0) {
            return false;
        }
        let tenant = caller.tenant();
        let give_back = |tenants: bool| {
            if let Some(own) = self.buckets.lock().expect("the budgets").get_mut(&caller) {
                own.tokens += 1.0;
            }
            if tenants && let Some(t) = self.tenants.lock().expect("the tenant budgets").get_mut(&tenant) {
                t.tokens += 1.0;
            }
        };
        let share = f64::from(self.limits.tenant_share_percent) / 100.0;
        let global_burst = f64::from(self.limits.global_key_burst);
        let global_rate = f64::from(self.limits.global_key_rate_per_minute) / 60.0;
        let tenant_burst = (global_burst * share).max(1.0);
        {
            let mut tenants = self.tenants.lock().expect("the tenant budgets");
            if tenants.len() > 10_000 {
                tenants.retain(|_, b| b.tokens < tenant_burst);
            }
            let bucket = tenants.entry(tenant).or_insert(Bucket { tokens: tenant_burst, last: now });
            if !OsvState::take(bucket, now, global_rate * share, tenant_burst, 1.0) {
                drop(tenants);
                give_back(false);
                return false;
            }
        }
        let reserve = global_burst * f64::from(self.limits.global_reserve_percent) / 100.0;
        {
            let mut global = self.global.lock().expect("the global budget");
            let bucket = global.get_or_insert(Bucket { tokens: global_burst, last: now });
            let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * global_rate).min(global_burst);
            bucket.last = now;
            if bucket.tokens - 1.0 >= reserve {
                bucket.tokens -= 1.0;
                return true;
            }
        }
        // The shared budget is down to its reserve: this tenant's own floor.
        let floor_burst = f64::from(self.limits.tenant_floor_burst);
        let mut floors = self.floors.lock().expect("the tenant floors");
        if floors.len() > 10_000 {
            floors.retain(|_, b| b.tokens < floor_burst);
        }
        let bucket = floors.entry(tenant).or_insert(Bucket { tokens: floor_burst, last: now });
        if OsvState::take(bucket, now, f64::from(self.limits.tenant_floor_per_minute) / 60.0, floor_burst, 1.0) {
            return true;
        }
        drop(floors);
        give_back(true);
        false
    }

    fn open_breaker(&self, retry_after: Option<&str>) {
        let secs = retry_after.and_then(|v| v.trim().parse::<u64>().ok()).map_or(30, |s| s.min(30));
        let mut jitter = [0u8; 2];
        let _ = getrandom::fill(&mut jitter);
        let extra = (secs * 1000 / 10) * u64::from(u16::from_le_bytes(jitter)) / u64::from(u16::MAX);
        let open = Duration::from_millis(secs * 1000 + extra).min(Duration::from_secs(60));
        *self.breaker.lock().expect("the breaker") = Some(self.now() + open);
        self.breaker_openings.fetch_add(1, Ordering::Relaxed);
    }

    fn breaker_open(&self) -> bool {
        self.breaker.lock().expect("the breaker").is_some_and(|until| until > self.now())
    }
}

pub fn router(state: Arc<OsvState>) -> Router {
    Router::new().route("/osv/v1/querybatch", post(querybatch)).with_state(state)
}

/// A short, non-reversible tag of a bearer string: enough to recognise a credential that
/// authenticated before, never the credential.
fn bearer_tag(headers: &HeaderMap) -> Option<u64> {
    use sha2::{Digest, Sha256};
    let bearer = headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    let digest = Sha256::digest(bearer.as_bytes());
    Some(u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")))
}

fn plain(status: StatusCode) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")]).into_response()
}

async fn querybatch(
    State(state): State<Arc<OsvState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let peer = peer.ip().to_canonical();
    // The same address derivation as `/sync`: behind a trusted proxy it is the client.
    let source = state.sync.source_of(peer, &headers);
    let now = state.now();
    // A source that keeps failing is turned away before any lookup, unless the request
    // carries a credential that authenticated before: a bad-token flood then cannot occupy
    // the auth gate (NEW-1).
    let tag = bearer_tag(&headers);
    let known = tag.is_some_and(|t| state.known_good.lock().expect("the known credentials").get(&t).is_some());
    // A blocked source is turned away without a lookup unless the credential authenticated
    // before. The rejection is not counted again: a block ends 60 s after the last real
    // failure, and while it lasts a first-time credential from that source (every client
    // behind a proxy missing from `trusted_proxies` shares one source) is turned away.
    if state.preauth_blocked(source, now) && !known {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    }
    if let Some(tag) = tag {
        // A credential that just failed is answered without another lookup.
        let recently_failed = state
            .failed_tags
            .lock()
            .expect("the failed credentials")
            .get(&tag)
            .is_some_and(|at| now.saturating_duration_since(*at) < Duration::from_secs(10));
        if recently_failed {
            // Still a failure from this source (counted, within the window's cap).
            state.preauth_failed(source, now);
            return plain(StatusCode::UNAUTHORIZED);
        }
    }
    // Lookups per credential are limited before the gate, so even a valid or once-valid
    // credential cannot keep it busy.
    if let Some(tag) = tag {
        let mut table = state.lookup_buckets.lock().expect("the lookup limits");
        let burst = f64::from(state.limits.request_burst);
        if table.get(&tag).is_none() {
            table.put(tag, Bucket { tokens: burst, last: now });
        }
        let bucket = table.get_mut(&tag).expect("just inserted");
        if !OsvState::take(bucket, now, f64::from(state.limits.request_rate_per_second), burst, 1.0) {
            return plain(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    // Credential first: nothing is read, cached or sent upstream for a stranger. The lookup
    // uses the database through a bounded gate of its own, so a flood of OSV requests
    // cannot take the pool `/sync` needs.
    let Ok(Ok(gate)) = tokio::time::timeout(Duration::from_secs(1), state.auth_permits.acquire()).await else {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    };
    state.auth_lookups.fetch_add(1, Ordering::Relaxed);
    let looked_up = state.sync.osv_caller(&headers, peer).await;
    drop(gate);
    let caller = match looked_up {
        Ok(caller) => {
            if let Some(tag) = tag {
                state.known_good.lock().expect("the known credentials").put(tag, ());
                state.failed_tags.lock().expect("the failed credentials").pop(&tag);
            }
            caller
        }
        Err(SyncError::Unauthenticated | SyncError::SourceRefused) => {
            // No longer exempt, and not looked up again for a moment.
            if let Some(tag) = tag {
                state.known_good.lock().expect("the known credentials").pop(&tag);
                state.failed_tags.lock().expect("the failed credentials").put(tag, now);
            }
            state.preauth_failed(source, now);
            return plain(StatusCode::UNAUTHORIZED);
        }
        Err(_) => return plain(StatusCode::SERVICE_UNAVAILABLE),
    };
    if !state.admit_request(caller, now) || !state.admit(caller, now) {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    }
    // The body first, with a time limit and no permit held: a dripping body costs a socket,
    // not a turn of anyone else's (NEW-2). The cap is bytes; the batch cap below is a count,
    // and the byte cap wins when keys are large.
    let read = match tokio::time::timeout(state.limits.body_read_timeout, axum::body::to_bytes(body, state.limits.body_cap)).await {
        Ok(read) => read,
        Err(_) => return plain(StatusCode::REQUEST_TIMEOUT),
    };
    let Ok(body) = read else {
        return plain(StatusCode::PAYLOAD_TOO_LARGE);
    };
    // Parsing a 1 MiB body is the one CPU cost cache hits still pay: bounded in flight.
    let Ok(parse_permit) = state.parse_permits.try_acquire() else {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    };
    let parsed = parse_request(&body);
    drop(parse_permit);
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(EnvelopeError::NotJson | EnvelopeError::NotAnObject | EnvelopeError::QueriesMissing | EnvelopeError::DuplicateKey | EnvelopeError::TooDeep) => {
            return plain(StatusCode::BAD_REQUEST);
        }
    };
    if parsed.len() > state.limits.batch_max {
        return plain(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let started = tokio::time::Instant::now();
    let answer = state.answer(caller, parsed, started).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")],
        answer,
    )
        .into_response()
}

enum Slot {
    Degraded,
    Key(usize),
}

enum Pending {
    Done(Answer),
    /// Waiting on a leader: ours (`led`) or another request's.
    Wait { rx: watch::Receiver<Option<Answer>>, led: bool, key: OsvKey },
    /// Over a remaining budget: degraded, not an upstream failure.
    Budget,
}

type Leader = (OsvKey, watch::Sender<Option<Answer>>);

impl OsvState {
    /// For each key: a held answer, a wait on someone's upstream call, or a call of our own.
    /// Our own are spawned (in chunks) independently of this request, so a cancelled
    /// request cannot fail a follower.
    fn register(self: &Arc<Self>, caller: OsvCaller, keys: &[OsvKey]) -> Vec<Pending> {
        let now = self.now();
        let mut pending = Vec::with_capacity(keys.len());
        let mut leaders: Vec<Leader> = Vec::new();
        for key in keys {
            let mut inflight = self.inflight.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(rx) = inflight.get(key) {
                pending.push(Pending::Wait { rx: rx.clone(), led: false, key: key.clone() });
                continue;
            }
            if let Some(hit) = self.cache.lock().expect("the answer cache").get(key, now) {
                pending.push(Pending::Done(hit));
                continue;
            }
            if !self.charge(caller, now) {
                pending.push(Pending::Budget);
                continue;
            }
            let (tx, rx) = watch::channel(None);
            inflight.insert(key.clone(), rx.clone());
            leaders.push((key.clone(), tx));
            pending.push(Pending::Wait { rx, led: true, key: key.clone() });
        }
        while !leaders.is_empty() {
            let rest = leaders.split_off(leaders.len().min(self.limits.leader_chunk));
            tokio::spawn(Arc::clone(self).fetch(std::mem::replace(&mut leaders, rest)));
        }
        pending
    }

    async fn answer(
        self: &Arc<Self>,
        caller: OsvCaller,
        parsed: Vec<probation_policy::osv_wire::ParsedQuery>,
        started: tokio::time::Instant,
    ) -> Vec<u8> {
        let deadline_at = started + self.limits.deadline;
        let mut distinct: Vec<OsvKey> = Vec::new();
        let mut index: HashMap<OsvKey, usize> = HashMap::new();
        let mut slots = Vec::with_capacity(parsed.len());
        for query in parsed {
            let key = query.ok().and_then(|(eco, name, version)| {
                let ecosystem = OsvState::ecosystem(&eco)?;
                osv_key(ecosystem, &name, &version).ok()
            });
            slots.push(match key {
                None => Slot::Degraded,
                Some(key) => Slot::Key(*index.entry(key.clone()).or_insert_with(|| {
                    distinct.push(key);
                    distinct.len() - 1
                })),
            });
        }

        let pending = self.register(caller, &distinct);
        let led: Vec<bool> = pending.iter().map(|p| matches!(p, Pending::Wait { led: true, .. })).collect();
        let mut resolved = self.settle(caller, pending, started, deadline_at).await;
        // A follower that was handed a foreign leader's failure asks for itself, once, while
        // its own deadline still allows it (SEC-2).
        let retry: Vec<usize> = (0..distinct.len())
            .filter(|i| matches!(resolved[*i], Some(Answer::Failed)) && !led[*i] && tokio::time::Instant::now() < deadline_at)
            .collect();
        if !retry.is_empty() {
            let keys: Vec<OsvKey> = retry.iter().map(|i| distinct[*i].clone()).collect();
            let again = self.settle(caller, self.register(caller, &keys), started, deadline_at).await;
            for (i, answer) in retry.into_iter().zip(again) {
                resolved[i] = answer;
            }
        }
        let upstream_ok = !resolved.iter().any(|r| matches!(r, Some(Answer::Failed)));
        let results: Vec<RenderedResult> = slots
            .iter()
            .map(|slot| match slot {
                Slot::Degraded => RenderedResult::Degraded,
                Slot::Key(i) => match &resolved[*i] {
                    Some(Answer::Matched(refs)) => RenderedResult::Matched(refs.as_ref().clone()),
                    Some(Answer::NoMatch) => RenderedResult::NoMatch,
                    Some(Answer::Failed) | None => RenderedResult::Degraded,
                },
            })
            .collect();
        let degraded = results.iter().filter(|r| **r == RenderedResult::Degraded).count() as u64;
        self.results_total.fetch_add(results.len() as u64, Ordering::Relaxed);
        self.results_degraded.fetch_add(degraded, Ordering::Relaxed);
        render_answer(&results, upstream_ok)
    }

    /// Waits for each key. A follower of someone else's call that has waited half its
    /// deadline asks for itself (its own budget, bypassing the in-flight table), so a slow
    /// chunk it cannot influence does not decide its answer (SEC-2).
    async fn settle(
        self: &Arc<Self>,
        caller: OsvCaller,
        pending: Vec<Pending>,
        started: tokio::time::Instant,
        deadline_at: tokio::time::Instant,
    ) -> Vec<Option<Answer>> {
        let half = started + self.limits.deadline / 2;
        let mut resolved = Vec::with_capacity(pending.len());
        for item in pending {
            resolved.push(match item {
                Pending::Done(answer) => Some(answer),
                Pending::Budget => None,
                Pending::Wait { mut rx, led, key } => {
                    let first: Option<Answer> = if led {
                        None
                    } else {
                        match tokio::time::timeout_at(half, rx.wait_for(Option::is_some)).await {
                            Ok(Ok(value)) => Some(value.clone().unwrap_or(Answer::Failed)),
                            Ok(Err(_)) => Some(Answer::Failed),
                            Err(_) => None,
                        }
                    };
                    let answer = match first {
                        Some(answer) => answer,
                        None if !led => {
                            // One rescue call per key: the first follower to get here starts it,
                            // the rest wait on it.
                            let mut rescue_rx = self.rescue_for(caller, &key);
                            let raced = tokio::time::timeout_at(deadline_at, async {
                                match rescue_rx.as_mut() {
                                    Some(rescue_rx) => tokio::select! {
                                        waited = rx.wait_for(Option::is_some) => match waited {
                                            Ok(value) => value.clone().unwrap_or(Answer::Failed),
                                            Err(_) => Answer::Failed,
                                        },
                                        waited = rescue_rx.wait_for(Option::is_some) => match waited {
                                            Ok(value) => value.clone().unwrap_or(Answer::Failed),
                                            Err(_) => Answer::Failed,
                                        },
                                    },
                                    None => match rx.wait_for(Option::is_some).await {
                                        Ok(value) => value.clone().unwrap_or(Answer::Failed),
                                        Err(_) => Answer::Failed,
                                    },
                                }
                            })
                            .await;
                            raced.unwrap_or(Answer::Failed)
                        }
                        None => match tokio::time::timeout_at(deadline_at, rx.wait_for(Option::is_some)).await {
                            Ok(Ok(value)) => value.clone().unwrap_or(Answer::Failed),
                            _ => Answer::Failed,
                        },
                    };
                    Some(answer)
                }
            });
        }
        resolved
    }

    /// The rescue slot of `key`: the receiver of the one call a follower fires for itself, started
    /// here when no other follower has (charged to the starter), or `None` when the budget is
    /// spent and the follower can only wait.
    fn rescue_for(self: &Arc<Self>, caller: OsvCaller, key: &OsvKey) -> Option<watch::Receiver<Option<Answer>>> {
        let mut rescue = self.rescue.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(rx) = rescue.get(key) {
            return Some(rx.clone());
        }
        if !self.charge(caller, self.now()) {
            return None;
        }
        let (tx, rx) = watch::channel(None);
        rescue.insert(key.clone(), rx.clone());
        let state = Arc::clone(self);
        let key = key.clone();
        tokio::spawn(async move {
            let answers = tokio::time::timeout(state.limits.upstream_timeout, state.call_upstream_with(&[&key], &state.rescue_permits)).await;
            let answer = answers.ok().and_then(|a| a.into_iter().next()).unwrap_or(Answer::Failed);
            let now = state.now();
            match &answer {
                Answer::Matched(_) => state.cache.lock().expect("the answer cache").put(key.clone(), answer.clone(), now + state.limits.match_ttl, &state.limits),
                Answer::NoMatch => state.cache.lock().expect("the answer cache").put(key.clone(), answer.clone(), now + state.limits.nomatch_ttl, &state.limits),
                Answer::Failed => {}
            }
            let _ = tx.send(Some(answer));
            state.rescue.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&key);
        });
        Some(rx)
    }

    /// The upstream half of one chunk of cache-missing keys: stores what is confirmed,
    /// publishes to every waiter, then leaves the in-flight table. It is not bound by any
    /// request's deadline, so a slow answer still reaches the cache.
    async fn fetch(self: Arc<Self>, leaders: Vec<Leader>) {
        let keys: Vec<&OsvKey> = leaders.iter().map(|(k, _)| k).collect();
        // However this task ends, its keys leave the in-flight table (a panic must not leave
        // followers waiting on a dead leader).
        let _guard = InflightGuard { state: Arc::clone(&self), keys: keys.iter().map(|k| (*k).clone()).collect() };
        let answers = match tokio::time::timeout(self.limits.upstream_timeout, self.call_upstream(&keys)).await {
            Ok(answers) => answers,
            Err(_) => vec![Answer::Failed; keys.len()],
        };
        if answers.iter().any(|a| matches!(a, Answer::Failed)) {
            self.upstream_failures.fetch_add(1, Ordering::Relaxed);
        }
        let now = self.now();
        for ((key, tx), answer) in leaders.into_iter().zip(answers) {
            // Store before publishing, publish before leaving the table, so no request
            // sees neither the entry nor the in-flight marker.
            match &answer {
                Answer::Matched(_) => self.cache.lock().expect("the answer cache").put(key.clone(), answer.clone(), now + self.limits.match_ttl, &self.limits),
                Answer::NoMatch => self.cache.lock().expect("the answer cache").put(key.clone(), answer.clone(), now + self.limits.nomatch_ttl, &self.limits),
                Answer::Failed => {}
            }
            let _ = tx.send(Some(answer));
            self.inflight.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&key);
        }
    }

    async fn call_upstream(&self, keys: &[&OsvKey]) -> Vec<Answer> {
        self.call_upstream_with(keys, &self.permits).await
    }

    async fn call_upstream_with(&self, keys: &[&OsvKey], permits: &Semaphore) -> Vec<Answer> {
        if self.breaker_open() {
            return vec![Answer::Failed; keys.len()];
        }
        let Ok(_permit) = permits.acquire().await else {
            return vec![Answer::Failed; keys.len()];
        };
        match self.post_batch(keys).await {
            Ok(answers) => answers,
            // A 4xx for a combined batch: one tenant's bad key must not fail the rest.
            Err(UpstreamError::Rejected) if keys.len() > 1 => {
                let mut out = Vec::with_capacity(keys.len());
                for key in keys {
                    out.push(match self.post_batch(&[key]).await {
                        Ok(mut one) => one.pop().unwrap_or(Answer::Failed),
                        Err(_) => Answer::Failed,
                    });
                }
                out
            }
            Err(_) => vec![Answer::Failed; keys.len()],
        }
    }

    /// One upstream call for already-built `queries`, with the size cap and strict shape.
    async fn send_queries(&self, queries: Vec<serde_json::Value>) -> Result<Vec<UpResult>, UpstreamError> {
        let body = serde_json::to_vec(&serde_json::json!({"queries": queries})).expect("a JSON value serializes");
        let mut response = self
            .http
            .post(self.upstream.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| UpstreamError::Failed)?;
        let status = response.status();
        if status.as_u16() == 429 {
            let retry = response.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).map(str::to_owned);
            self.open_breaker(retry.as_deref());
            return Err(UpstreamError::Failed);
        }
        if status.is_client_error() {
            return Err(UpstreamError::Rejected);
        }
        if !status.is_success() {
            return Err(UpstreamError::Failed);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| UpstreamError::Failed)? {
            if bytes.len() + chunk.len() > self.limits.upstream_read_cap {
                return Err(UpstreamError::Failed);
            }
            bytes.extend_from_slice(&chunk);
        }
        let up: Up = serde_json::from_slice(&bytes).map_err(|_| UpstreamError::Failed)?;
        // Stored only when the answer lines up with the question.
        if up.results.len() != queries.len() {
            return Err(UpstreamError::Failed);
        }
        Ok(up.results)
    }

    async fn post_batch(&self, keys: &[&OsvKey]) -> Result<Vec<Answer>, UpstreamError> {
        let queries: Vec<serde_json::Value> = keys.iter().map(|k| query_for(k, None)).collect();
        let results = self.send_queries(queries).await?;
        let mut answers = Vec::with_capacity(keys.len());
        for (key, result) in keys.iter().zip(results) {
            // One key's page error degrades that key only.
            answers.push(self.answer_for(key, result).await.unwrap_or(Answer::Failed));
        }
        Ok(answers)
    }

    /// One key's verdict from its first page, following page tokens (SEC-9): a MAL entry on
    /// a later page must not read as no-match. Past `max_pages` the key is degraded.
    async fn answer_for(&self, key: &OsvKey, first: UpResult) -> Result<Answer, UpstreamError> {
        let mut refs = mal_refs(first.vulns);
        let mut token = first.next_page_token;
        let mut pages = 1;
        while let Some(next) = token.take() {
            if pages >= self.limits.max_pages {
                return Ok(Answer::Failed);
            }
            pages += 1;
            let page = self.send_queries(vec![query_for(key, Some(&next))]).await?.pop().ok_or(UpstreamError::Failed)?;
            refs.extend(mal_refs(page.vulns));
            token = page.next_page_token;
        }
        refs.truncate(probation_policy::osv_wire::MAX_VULN_REFS);
        Ok(if refs.is_empty() { Answer::NoMatch } else { Answer::Matched(Arc::new(refs)) })
    }
}

#[derive(Deserialize)]
struct Up {
    results: Vec<UpResult>,
}

#[derive(Deserialize)]
struct UpResult {
    #[serde(default)]
    vulns: Vec<UpVuln>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct UpVuln {
    id: String,
    #[serde(default)]
    modified: Option<String>,
}

fn mal_refs(vulns: Vec<UpVuln>) -> Vec<(String, Option<String>)> {
    vulns.into_iter().filter(|v| v.id.starts_with("MAL-")).map(|v| (v.id, v.modified)).collect()
}

fn query_for(key: &OsvKey, page_token: Option<&str>) -> serde_json::Value {
    let mut query = serde_json::json!({
        "package": {"name": key.name, "ecosystem": probation::osv::osv_ecosystem(key.ecosystem).unwrap_or("")},
        "version": key.version,
    });
    if let Some(token) = page_token {
        query["page_token"] = serde_json::Value::from(token);
    }
    query
}

struct InflightGuard {
    state: Arc<OsvState>,
    keys: Vec<OsvKey>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // A poisoned table is still cleaned: the guard exists for the failure paths.
        let mut inflight = self.state.inflight.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in &self.keys {
            inflight.remove(key);
        }
    }
}

enum UpstreamError {
    Failed,
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state that never connects to a database (the pool is lazy).
    fn state() -> Arc<OsvState> {
        let pool = sqlx::PgPool::connect_lazy("postgres://u:p@127.0.0.1:1/none").expect("a lazy pool");
        let sync = Arc::new(SyncState::new(pool, Vec::new(), None));
        Arc::new(OsvState::new(sync, url::Url::parse("http://127.0.0.1:1/v1/querybatch").unwrap()))
    }

    /// A panicking fetch task, or any panic while the in-flight table is held, must not leave a
    /// key stuck: the guard cleans even a poisoned table.
    #[tokio::test]
    async fn inflight_guard_cleans_a_poisoned_table() {
        let state = state();
        let key = osv_key(Ecosystem::Npm, "left-pad", "1.0.0").unwrap();
        let (_tx, rx) = watch::channel(None);
        state.inflight.lock().unwrap().insert(key.clone(), rx);
        let poisoner = Arc::clone(&state);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.inflight.lock().unwrap();
            panic!("a panic while the table is held");
        })
        .join();
        assert!(state.inflight.is_poisoned());
        drop(InflightGuard { state: Arc::clone(&state), keys: vec![key.clone()] });
        let table = state.inflight.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!table.contains_key(&key), "the guard removed the key from the poisoned table");
    }
}
