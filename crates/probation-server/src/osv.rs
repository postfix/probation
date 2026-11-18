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

use crate::sync::{OsvCaller, SyncState, SyncError};

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
    /// Keys across every credential (SEC-5).
    global: Mutex<Option<Bucket>>,
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
            limits,
            clock: Arc::new(Instant::now),
            cache: Mutex::default(),
            inflight: Mutex::default(),
            buckets: Mutex::default(),
            request_buckets: Mutex::default(),
            global: Mutex::new(None),
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
        match table.get_mut(&source) {
            Some(window) => window.push_back(now),
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

    /// One cache-missing key: the credential's own budget and the shared one.
    fn charge(&self, caller: OsvCaller, now: Instant) -> bool {
        if !self.take_from(&self.buckets, caller, now, self.key_rate(), f64::from(self.limits.key_burst), 1.0) {
            return false;
        }
        let burst = f64::from(self.limits.global_key_burst);
        let mut global = self.global.lock().expect("the global budget");
        let bucket = global.get_or_insert(Bucket { tokens: burst, last: now });
        if OsvState::take(bucket, now, f64::from(self.limits.global_key_rate_per_minute) / 60.0, burst, 1.0) {
            return true;
        }
        drop(global);
        // Over the shared budget: give the credential its token back.
        if let Some(own) = self.buckets.lock().expect("the budgets").get_mut(&caller) {
            own.tokens += 1.0;
        }
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
    // Credential first: nothing is read, cached or sent upstream for a stranger. The lookup
    // uses the database through a bounded gate of its own, so a flood of OSV requests
    // cannot take the pool `/sync` needs.
    let Ok(Ok(gate)) = tokio::time::timeout(Duration::from_secs(1), state.auth_permits.acquire()).await else {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    };
    let looked_up = state.sync.osv_caller(&headers, peer).await;
    drop(gate);
    let caller = match looked_up {
        Ok(caller) => caller,
        Err(SyncError::Unauthenticated | SyncError::SourceRefused) => {
            // A request that authenticates is never throttled; repeated failures from one
            // source are.
            let blocked = state.preauth_blocked(source, now);
            state.preauth_failed(source, now);
            return plain(if blocked { StatusCode::TOO_MANY_REQUESTS } else { StatusCode::UNAUTHORIZED });
        }
        Err(_) => return plain(StatusCode::SERVICE_UNAVAILABLE),
    };
    if !state.admit_request(caller, now) || !state.admit(caller, now) {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    }
    // Parsing a 1 MiB body is the one CPU cost cache hits still pay: bounded in flight.
    let Ok(parse_permit) = state.parse_permits.try_acquire() else {
        return plain(StatusCode::TOO_MANY_REQUESTS);
    };
    let Ok(body) = axum::body::to_bytes(body, state.limits.body_cap).await else {
        return plain(StatusCode::PAYLOAD_TOO_LARGE);
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
    Wait { rx: watch::Receiver<Option<Answer>>, led: bool },
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
            let mut inflight = self.inflight.lock().expect("the in-flight table");
            if let Some(rx) = inflight.get(key) {
                pending.push(Pending::Wait { rx: rx.clone(), led: false });
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
            pending.push(Pending::Wait { rx, led: true });
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
        let mut resolved = Self::settle(pending, deadline_at).await;
        // A follower that was handed a foreign leader's failure asks for itself, once, while
        // its own deadline still allows it (SEC-2).
        let retry: Vec<usize> = (0..distinct.len())
            .filter(|i| matches!(resolved[*i], Some(Answer::Failed)) && !led[*i] && tokio::time::Instant::now() < deadline_at)
            .collect();
        if !retry.is_empty() {
            let keys: Vec<OsvKey> = retry.iter().map(|i| distinct[*i].clone()).collect();
            let again = Self::settle(self.register(caller, &keys), deadline_at).await;
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

    async fn settle(pending: Vec<Pending>, deadline_at: tokio::time::Instant) -> Vec<Option<Answer>> {
        let mut resolved = Vec::with_capacity(pending.len());
        for item in pending {
            resolved.push(match item {
                Pending::Done(answer) => Some(answer),
                Pending::Budget => None,
                Pending::Wait { mut rx, .. } => {
                    let waited = tokio::time::timeout_at(deadline_at, rx.wait_for(Option::is_some)).await;
                    Some(match waited {
                        Ok(Ok(value)) => value.clone().unwrap_or(Answer::Failed),
                        _ => Answer::Failed,
                    })
                }
            });
        }
        resolved
    }

    /// The upstream half of one chunk of cache-missing keys: stores what is confirmed,
    /// publishes to every waiter, then leaves the in-flight table. It is not bound by any
    /// request's deadline, so a slow answer still reaches the cache.
    async fn fetch(self: Arc<Self>, leaders: Vec<Leader>) {
        let keys: Vec<&OsvKey> = leaders.iter().map(|(k, _)| k).collect();
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
            self.inflight.lock().expect("the in-flight table").remove(&key);
        }
    }

    async fn call_upstream(&self, keys: &[&OsvKey]) -> Vec<Answer> {
        if self.breaker_open() {
            return vec![Answer::Failed; keys.len()];
        }
        let Ok(_permit) = self.permits.acquire().await else {
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
            answers.push(self.answer_for(key, result).await?);
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

enum UpstreamError {
    Failed,
    Rejected,
}
