//! The management server's `sync lookup` and `sync layers` calls (02-architecture.md
//! § Endpoints). Bodies are encoded with `serde_json`: this crate's reqwest has no
//! `json` feature.

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use probation_policy::PlaceRef;
use probation_policy::api::{
    CertificateAdmission, CertificateAdmissionRequest, KeyHash, KeyLookup, KeyLookupRequest,
    LayersRequest, LayersResponse,
};
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::config::{FirewallToken, ManagementConfig};

/// Why a call has no answer to use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallError {
    /// Connect error, timeout, 5xx, an unexpected status, or a body cut short or too
    /// big.
    Unreachable,
    /// A `200` whose body does not decode (F3): most likely a server newer than this
    /// firewall.
    Unreadable,
    /// The server answered `429`.
    Busy,
    /// The server refused this firewall's token (`401`).
    TokenRefused,
}

/// The most calls this firewall sends the management server in any one second, and the
/// most it has in flight. The server answers `429` to a token's 201st arrival in a
/// second (T31, `FIREWALL_TOKEN_RATE_PER_SECOND` in probation-server's sync.rs). The
/// lookup budget meters only key lookups: certificate admissions, layer fetches and the
/// calls one lookup fans out into were unmetered, so a burst of them came back as
/// `429`, which is `Busy`, and reached the package client as `503 LOOKUP_BUSY`.
///
/// Every call of this client goes through its pacer. A request arriving in any one second
/// was either sent in that second (at most `MAX_CALLS_PER_SECOND`) or sent earlier and still
/// in flight at its start (at most `MAX_IN_FLIGHT`), so the server sees at most 182 of its
/// 200. The remaining 18 per second are reserved, by decision, for the `changes` poll: it
/// is built by `KeySync` in `sync.rs` with its own HTTP client, is NOT paced, and sends one
/// call per sync period. Keep the sum below the server's rate.
const MAX_CALLS_PER_SECOND: usize = 150;
const MAX_IN_FLIGHT: usize = 32;
/// The server's per-token rate (`FIREWALL_TOKEN_RATE_PER_SECOND` in probation-server's
/// sync.rs); a test reads that source to keep the two equal.
const SERVER_RATE_PER_SECOND: usize = 200;
const _: () = assert!(MAX_CALLS_PER_SECOND + MAX_IN_FLIGHT < SERVER_RATE_PER_SECOND);

/// The biggest answer read: a layer with many blocks, well under the server's own caps.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;

pub struct SyncClient {
    http: reqwest::Client,
    base: Url,
    token: FirewallToken,
    timeout: Duration,
    /// Shared by every sender of this token in the process (see `pacer_for`).
    pacer: Arc<Pacer>,
}

impl SyncClient {
    pub fn new(config: &ManagementConfig) -> SyncClient {
        SyncClient {
            // No redirects and no proxy from the environment: the token and the key
            // hashes are for this URL only.
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("an HTTP client with the default TLS backend"),
            base: base_of(&config.url),
            token: config.token.clone(),
            timeout: Duration::from_secs(config.request_timeout_seconds.get()),
            pacer: pacer_for(&config.token),
        }
    }

    pub async fn lookup(&self, key_hash: KeyHash) -> Result<KeyLookup, CallError> {
        self.call("api/v1/sync/lookup", &KeyLookupRequest { key_hash })
            .await
    }

    pub async fn layers(&self, places: Vec<PlaceRef>) -> Result<LayersResponse, CallError> {
        self.call("api/v1/sync/layers", &LayersRequest { places })
            .await
    }

    pub async fn certificate(
        &self,
        asked: CertificateAdmissionRequest,
    ) -> Result<CertificateAdmission, CallError> {
        self.call("api/v1/sync/certificate", &asked).await
    }

    /// One `POST`: waiting for a pacer slot, sending and reading the answer all within one
    /// `request_timeout_seconds`.
    async fn call<B: Serialize, A: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<A, CallError> {
        // One deadline for the whole call, taken first: the wait for a slot, the send and the
        // body together take at most `request_timeout_seconds`.
        let deadline = tokio::time::Instant::now() + self.timeout;
        let url = self.base.join(path).map_err(|_| CallError::Unreachable)?;
        let body = serde_json::to_vec(body).map_err(|_| CallError::Unreachable)?;
        // Held until the answer is read: the call counts as in flight until then.
        let _in_flight = self.pacer.acquire(deadline).await?;
        let sent = self
            .http
            .post(url)
            .bearer_auth(self.token.expose())
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send();
        let response = tokio::time::timeout_at(deadline, sent)
            .await
            .map_err(|_| CallError::Unreachable)?
            .map_err(|_| CallError::Unreachable)?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => return Err(CallError::Busy),
            StatusCode::UNAUTHORIZED => return Err(CallError::TokenRefused),
            _ => return Err(CallError::Unreachable),
        }
        let answer = tokio::time::timeout_at(deadline, read_bounded(response))
            .await
            .map_err(|_| CallError::Unreachable)??;
        serde_json::from_slice(&answer).map_err(|_| CallError::Unreadable)
    }
}

/// Paces the calls of one token: a sliding window of sends and a bound on calls in
/// flight, served first come, first served. `acquire` waits no longer than the caller's
/// deadline; a wait that cannot end before it (or exactly at it, leaving nothing to
/// send with) is `Busy` without a send. Dropping the future gives back whatever it
/// took, so an aborted call leaves neither a permit nor a window entry behind.
pub(super) struct Pacer {
    max_calls: usize,
    window: Duration,
    sent: tokio::sync::Mutex<VecDeque<tokio::time::Instant>>,
    in_flight: Arc<tokio::sync::Semaphore>,
    /// When a send was last granted, for `pacer_for` to keep a pacer one quiet window.
    last_grant: Mutex<Option<tokio::time::Instant>>,
    #[cfg(test)]
    max_in_flight: usize,
    /// Test evidence: the most calls ever in flight at a grant, and when each was granted.
    #[cfg(test)]
    peak_in_flight: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    grants: Mutex<Vec<tokio::time::Instant>>,
}

impl Pacer {
    pub(super) fn new(max_calls: usize, max_in_flight: usize, window: Duration) -> Pacer {
        Pacer {
            max_calls,
            window,
            sent: tokio::sync::Mutex::new(VecDeque::new()),
            in_flight: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
            last_grant: Mutex::new(None),
            #[cfg(test)]
            max_in_flight,
            #[cfg(test)]
            peak_in_flight: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            grants: Mutex::new(Vec::new()),
        }
    }

    pub(super) async fn acquire(
        &self,
        give_up: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, CallError> {
        let permit = tokio::time::timeout_at(give_up, Arc::clone(&self.in_flight).acquire_owned())
            .await
            .map_err(|_| CallError::Busy)?
            .map_err(|_| CallError::Unreachable)?;
        // The lock queues waiters first come, first served; its holder is the one
        // sleeping for the oldest send to leave the window.
        let mut sent = tokio::time::timeout_at(give_up, self.sent.lock())
            .await
            .map_err(|_| CallError::Busy)?;
        loop {
            let now = tokio::time::Instant::now();
            while sent.front().is_some_and(|at| now.duration_since(*at) >= self.window) {
                sent.pop_front();
            }
            if sent.len() < self.max_calls {
                sent.push_back(now);
                *self.last_grant.lock().expect("never poisoned") = Some(now);
                #[cfg(test)]
                {
                    let busy = self.max_in_flight - self.in_flight.available_permits();
                    self.peak_in_flight.fetch_max(busy, std::sync::atomic::Ordering::SeqCst);
                    self.grants.lock().unwrap().push(now);
                }
                return Ok(permit);
            }
            let ready_at = sent.front().map(|at| *at + self.window).unwrap_or(now);
            if ready_at >= give_up {
                return Err(CallError::Busy);
            }
            tokio::time::sleep_until(ready_at).await;
        }
    }

    #[cfg(test)]
    pub(super) async fn window_len(&self) -> usize {
        self.sent.lock().await.len()
    }

    #[cfg(test)]
    pub(super) async fn window_front(&self) -> Option<tokio::time::Instant> {
        self.sent.lock().await.front().copied()
    }

    #[cfg(test)]
    pub(super) fn available_flight(&self) -> usize {
        self.in_flight.available_permits()
    }

    #[cfg(test)]
    async fn fill_window(&self) {
        let mut sent = self.sent.lock().await;
        let now = tokio::time::Instant::now();
        *self.last_grant.lock().unwrap() = Some(now);
        while sent.len() < self.max_calls {
            sent.push_back(now);
        }
    }
}

/// The pacer of `token` in this process. The server's limit is per token, so every
/// `SyncClient` built for one token takes slots from one pacer; the entry outlives its
/// last client. It does not cover the `changes` poll (see `MAX_CALLS_PER_SECOND`), and two
/// firewall replicas that share one token each have their own pacer and process, so
/// together they can exceed the server's rate: give each replica its own token.
pub(super) fn pacer_for(token: &FirewallToken) -> Arc<Pacer> {
    static PACERS: OnceLock<Mutex<HashMap<u64, Arc<Pacer>>>> = OnceLock::new();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    token.expose().hash(&mut hasher);
    let key = hasher.finish();
    let mut pacers = PACERS.get_or_init(Default::default).lock().expect("the pacer table is never poisoned");
    // An entry nobody holds goes only after a quiet window: a client created just after the last
    // one was dropped must not get a fresh window and burst past the server's rate.
    let now = tokio::time::Instant::now();
    pacers.retain(|_, pacer| {
        Arc::strong_count(pacer) > 1
            || pacer.last_grant.lock().expect("never poisoned").is_some_and(|at| now.duration_since(at) < pacer.window)
    });
    Arc::clone(pacers.entry(key).or_insert_with(|| Arc::new(Pacer::new(MAX_CALLS_PER_SECOND, MAX_IN_FLIGHT, Duration::from_secs(1)))))
}

/// The body, refused past `MAX_ANSWER_BYTES` however it is framed.
async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, CallError> {
    let mut answer = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| CallError::Unreachable)? {
        if answer.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(CallError::Unreachable);
        }
        answer.extend_from_slice(&chunk);
    }
    Ok(answer)
}

/// `url` as a base `join` keeps the whole path of: a `/prefix` without its trailing
/// slash would otherwise lose `prefix`.
fn base_of(url: &Url) -> Url {
    let mut base = url.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use probation_policy::api::{CertificateAdmission, CertificateAdmissionRequest, RegistryId};
    use probation_policy::Ecosystem;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The management server's rule for one firewall token (T31,
    /// `FIREWALL_TOKEN_RATE_PER_SECOND` in probation-server's sync.rs): the 201st call
    /// inside one second is answered `429`.
    const SERVER_RATE: usize = 200;

    async fn counting_server() -> (MockServer, Arc<Mutex<(usize, usize)>>) {
        let server = MockServer::start().await;
        let seen = Arc::new(Mutex::new((0usize, 0usize))); // (received, answered 429)
        let window = Arc::new(Mutex::new(VecDeque::<Instant>::new()));
        let record = Arc::clone(&seen);
        Mock::given(method("POST"))
            .and(path("/api/v1/sync/certificate"))
            .respond_with(move |_: &wiremock::Request| {
                let now = Instant::now();
                let mut window = window.lock().unwrap();
                while window.front().is_some_and(|at| now.duration_since(*at).as_secs_f64() >= 1.0) {
                    window.pop_front();
                }
                let mut seen = record.lock().unwrap();
                seen.0 += 1;
                if window.len() >= SERVER_RATE {
                    seen.1 += 1;
                    return ResponseTemplate::new(429);
                }
                window.push_back(now);
                ResponseTemplate::new(200).set_body_json(CertificateAdmission::Refused)
            })
            .mount(&server)
            .await;
        (server, seen)
    }

    /// A client with a token of its own, so tests running side by side do not share a pacer.
    fn client(server: &MockServer, timeout_seconds: u64) -> Arc<SyncClient> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let token = format!("test-{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        client_on(server, timeout_seconds, &token)
    }

    fn client_on(server: &MockServer, timeout_seconds: u64, token: &str) -> Arc<SyncClient> {
        Arc::new(SyncClient::new(&ManagementConfig {
            url: server.uri().parse().unwrap(),
            token: FirewallToken::new(token.into()),
            token_file: "/test/token".into(),
            key_cache_ttl_seconds: 300.try_into().unwrap(),
            key_cache_max_entries: 64.try_into().unwrap(),
            lookup_budget_per_second: 200.try_into().unwrap(),
            client_lookup_allowance_per_second: 100.try_into().unwrap(),
            request_timeout_seconds: timeout_seconds.try_into().unwrap(),
            sync_margin_seconds: 1.try_into().unwrap(),
            trusted_proxies: vec![],
        }))
    }

    async fn burst(client: &Arc<SyncClient>, calls: usize) -> Vec<Result<CertificateAdmission, CallError>> {
        let tasks: Vec<_> = (0..calls)
            .map(|_| {
                let client = Arc::clone(client);
                tokio::spawn(async move {
                    client
                        .certificate(CertificateAdmissionRequest {
                            registry: RegistryId(1),
                            ecosystem: Ecosystem::Npm,
                            chain: vec![vec![1]],
                        })
                        .await
                })
            })
            .collect();
        let mut answers = Vec::new();
        for task in tasks {
            answers.push(task.await.unwrap());
        }
        answers
    }

    /// Certificate admissions are not metered by the lookup budget, so a burst of
    /// them (the 10,000-identity scale scenario runs 32 workers) made the firewall
    /// exceed the server's per-token rate and answer its own clients `503 LOOKUP_BUSY`.
    /// A burst the timeout can absorb is paced, not refused, and never trips the server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_the_timeout_can_absorb_is_paced_below_the_servers_rate() {
        let (server, seen) = counting_server().await;
        let answers = burst(&client(&server, 20), 500).await;
        let (received, limited) = *seen.lock().unwrap();
        assert_eq!(limited, 0, "the server answered 429 to {limited} of {received} calls");
        assert!(answers.iter().all(|answer| matches!(answer, Ok(CertificateAdmission::Refused))), "every call is answered");
        assert_eq!(received, 500);
    }


    // ---- Pacer without a network (P3). tokio's `test-util` (paused time) is not enabled
    // for this crate, so these run on a short real window.
    use tokio::time::Instant as Tick;
    const W: Duration = Duration::from_millis(300);

    #[tokio::test]
    async fn a_cancelled_wait_gives_back_its_permit_and_takes_no_slot() {
        let pacer = Arc::new(Pacer::new(2, 2, W));
        drop(pacer.acquire(Tick::now() + Duration::from_secs(5)).await.unwrap());
        drop(pacer.acquire(Tick::now() + Duration::from_secs(5)).await.unwrap());
        assert_eq!(pacer.window_len().await, 2);
        let waiting = {
            let pacer = Arc::clone(&pacer);
            tokio::spawn(async move { pacer.acquire(Tick::now() + Duration::from_secs(5)).await.map(drop) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert_eq!(pacer.available_flight(), 2, "the aborted wait returned its in-flight place");
        assert_eq!(pacer.window_len().await, 2, "and recorded no send");
        tokio::time::sleep(W).await;
        assert!(pacer.acquire(Tick::now() + Duration::from_millis(50)).await.is_ok(), "the window is usable again at once");
    }

    #[tokio::test]
    async fn waiters_are_served_in_arrival_order_within_a_bounded_time() {
        let pacer = Arc::new(Pacer::new(3, 100, W));
        let start = Tick::now();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        for index in 0..10usize {
            let (pacer, tx) = (Arc::clone(&pacer), tx.clone());
            tokio::spawn(async move {
                pacer.acquire(Tick::now() + Duration::from_secs(60)).await.map(drop).unwrap();
                tx.send((index, Tick::now() - start)).unwrap();
            });
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        drop(tx);
        let mut served = Vec::new();
        while let Some(row) = rx.recv().await {
            served.push(row);
        }
        assert_eq!(served.iter().map(|(index, _)| *index).collect::<Vec<_>>(), (0..10).collect::<Vec<_>>(), "first come, first served");
        for (index, at) in &served {
            let due = W * (*index as u32 / 3);
            // Never early; late only by scheduling noise, well under one more window.
            assert!(*at + Duration::from_millis(5) >= due && *at <= due + W * 2,
                "waiter {index} is served in its own window ({due:?}), got {at:?}");
        }
    }

    #[tokio::test]
    async fn a_slot_that_frees_exactly_at_the_deadline_is_refused_busy() {
        let pacer = Arc::new(Pacer::new(1, 10, W));
        let t0 = Tick::now();
        drop(pacer.acquire(t0 + Duration::from_secs(5)).await.unwrap());
        let freed = pacer.window_front().await.unwrap() + W;
        assert_eq!(pacer.acquire(freed).await.unwrap_err(), CallError::Busy, "nothing would be left to send");
        assert!(pacer.acquire(freed + Duration::from_millis(5)).await.is_ok(), "one tick later it is served");
        assert!(Tick::now() >= freed, "served when the slot freed");
    }

    #[tokio::test]
    async fn the_in_flight_bound_holds_until_a_call_ends() {
        let pacer = Arc::new(Pacer::new(1000, 2, W));
        let first = pacer.acquire(Tick::now() + Duration::from_secs(5)).await.unwrap();
        let _second = pacer.acquire(Tick::now() + Duration::from_secs(5)).await.unwrap();
        assert_eq!(pacer.acquire(Tick::now() + Duration::from_millis(100)).await.unwrap_err(), CallError::Busy);
        drop(first);
        assert!(pacer.acquire(Tick::now() + Duration::from_millis(100)).await.is_ok());
    }

    /// P1: the wait for a slot is part of the request's one deadline, so a call never
    /// takes longer than `request_timeout_seconds` in total.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn waiting_for_a_slot_spends_the_same_deadline_as_the_exchange() {
        let (server, _seen) = counting_server().await;
        let slow = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/sync/certificate"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(2500)).set_body_json(CertificateAdmission::Refused))
            .mount(&slow)
            .await;
        drop(server);
        let client = client(&slow, 3);
        // Fill the last second's window, then ask once more: it must wait for ~1 s, leaving
        // ~2 s of the 3 s deadline for an exchange that takes 2.5 s. Two deadlines (a fresh 3 s
        // after the wait) would let it succeed at ~3.5 s; one deadline ends it at 3 s.
        client.pacer.fill_window().await;
        let started = Instant::now();
        let answer = burst(&client, 1).await.pop().unwrap();
        let took = started.elapsed();
        assert!(matches!(answer, Err(CallError::Unreachable)), "the exchange ran out of the one deadline: {answer:?}");
        assert!(took < Duration::from_millis(3400), "total {took:?} exceeds request_timeout_seconds");
    }

    /// P2: two clients on one token share one limiter, so together they stay under the
    /// server's rate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clients_on_one_token_share_the_limit() {
        let (server, seen) = counting_server().await;
        let (a, b) = (client_on(&server, 20, "one-token"), client_on(&server, 20, "one-token"));
        let (left, right) = tokio::join!(burst(&a, 250), burst(&b, 250));
        let (received, limited) = *seen.lock().unwrap();
        assert_eq!(limited, 0, "the server answered 429 to {limited} of {received} calls");
        assert!(left.iter().chain(right.iter()).all(|answer| matches!(answer, Ok(CertificateAdmission::Refused))));
    }

    /// Real overload is still refused, with no dependence on the scheduler: every wait
    /// that would end at or after the shared deadline is `Busy`, so exactly one window's
    /// worth of sends is granted and the rest are refused.
    #[tokio::test]
    async fn a_burst_beyond_the_deadline_is_refused_busy_exactly() {
        let pacer = Pacer::new(MAX_CALLS_PER_SECOND, 10_000, Duration::from_secs(1));
        let give_up = tokio::time::Instant::now() + Duration::from_secs(1);
        let (mut granted, mut busy) = (0, 0);
        for _ in 0..600 {
            match pacer.acquire(give_up).await {
                Ok(permit) => { drop(permit); granted += 1 }
                Err(CallError::Busy) => busy += 1,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!((granted, busy), (MAX_CALLS_PER_SECOND, 600 - MAX_CALLS_PER_SECOND));
    }

    /// A raw HTTP server (the response headers go out at once, the body after `delay`) that
    /// applies the management server's rule (the 201st arrival in a second is a `429`) and
    /// records, per call, how many were open between arrival and the end of the body.
    struct SlowServer {
        url: String,
        state: Arc<Mutex<SlowState>>,
    }

    #[derive(Default)]
    struct SlowState {
        arrivals: Vec<Instant>,
        limited: usize,
        open: usize,
        peak_open: usize,
    }

    async fn slow_body_server(delay: Duration) -> SlowServer {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(SlowState::default()));
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let state = Arc::clone(&shared);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    loop {
                        // One request: headers, then Content-Length bytes of body.
                        let (head_end, length) = loop {
                            if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&buffer[..end]).to_lowercase();
                                let length = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
                                break (end + 4, length);
                            }
                            let mut chunk = [0u8; 4096];
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                            }
                        };
                        while buffer.len() < head_end + length {
                            let mut chunk = [0u8; 4096];
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let request_line = String::from_utf8_lossy(&buffer[..head_end]).lines().next().unwrap_or("").to_owned();
                        buffer.drain(..head_end + length);
                        let now = Instant::now();
                        let limited = {
                            let mut state = state.lock().unwrap();
                            let recent = state.arrivals.iter().filter(|at| now.duration_since(**at).as_secs_f64() < 1.0).count();
                            state.arrivals.push(now);
                            if recent >= SERVER_RATE_PER_SECOND {
                                state.limited += 1;
                                true
                            } else {
                                state.open += 1;
                                let open = state.open;
                                state.peak_open = state.peak_open.max(open);
                                false
                            }
                        };
                        if limited {
                            if socket.write_all(b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\n\r\n").await.is_err() { return }
                            continue;
                        }
                        let body = if request_line.contains("/lookup") {
                            serde_json::to_vec(&probation_policy::api::KeyLookup::Unknown { revision: 1 })
                        } else if request_line.contains("/layers") {
                            serde_json::to_vec(&probation_policy::api::LayersResponse { layers: vec![], revision: 1 })
                        } else {
                            serde_json::to_vec(&CertificateAdmission::Refused)
                        }
                        .unwrap();
                        let head = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", body.len());
                        let wrote = async {
                            socket.write_all(head.as_bytes()).await?;
                            socket.flush().await?;
                            tokio::time::sleep(delay).await;
                            socket.write_all(&body).await
                        }
                        .await;
                        state.lock().unwrap().open -= 1;
                        if wrote.is_err() { return }
                    }
                });
            }
        });
        SlowServer { url, state }
    }

    fn client_for(url: &str, timeout_seconds: u64) -> Arc<SyncClient> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let token = format!("slow-{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        Arc::new(SyncClient::new(&ManagementConfig {
            url: url.parse().unwrap(),
            token: FirewallToken::new(token),
            token_file: "/test/token".into(),
            key_cache_ttl_seconds: 300.try_into().unwrap(),
            key_cache_max_entries: 64.try_into().unwrap(),
            lookup_budget_per_second: 200.try_into().unwrap(),
            client_lookup_allowance_per_second: 100.try_into().unwrap(),
            request_timeout_seconds: timeout_seconds.try_into().unwrap(),
            sync_margin_seconds: 1.try_into().unwrap(),
            trusted_proxies: vec![],
        }))
    }

    /// Lookups, layer fetches and certificate admissions, `per_kind` of each at once.
    async fn mixed_burst(client: &Arc<SyncClient>, per_kind: usize) {
        use probation_policy::api::KeyHash;
        let mut tasks = Vec::new();
        for _ in 0..per_kind {
            let (a, b, c) = (Arc::clone(client), Arc::clone(client), Arc::clone(client));
            tasks.push(tokio::spawn(async move { a.lookup(KeyHash([7; 32])).await.map(drop) }));
            tasks.push(tokio::spawn(async move { b.layers(vec![]).await.map(drop) }));
            tasks.push(tokio::spawn(async move {
                c.certificate(CertificateAdmissionRequest { registry: RegistryId(1), ecosystem: Ecosystem::Npm, chain: vec![vec![1]] }).await.map(drop)
            }));
        }
        for task in tasks {
            task.await.unwrap().expect("every call is answered");
        }
    }

    fn busiest_second(arrivals: &[Instant]) -> usize {
        arrivals.iter().map(|a| arrivals.iter().filter(|b| **b >= *a && b.duration_since(*a).as_secs_f64() < 1.0).count()).max().unwrap_or(0)
    }

    /// C3/G6: the answer's headers arrive at once and its body 300 ms later. The permit is
    /// held until the body is read, so the server never has more than 32 calls open (arrival
    /// to end of body), and the client never sends more than 150 in a second. Releasing the
    /// permit before `read_bounded`, or deleting the semaphore, makes this fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mixed_calls_with_a_slow_body_stay_within_the_in_flight_cap_and_the_send_rate() {
        let server = slow_body_server(Duration::from_millis(300)).await;
        let client = client_for(&server.url, 60);
        mixed_burst(&client, 160).await;
        let state = server.state.lock().unwrap();
        assert_eq!(state.limited, 0, "the server answered 429 {} times", state.limited);
        assert!(state.peak_open <= 32, "the server had {} calls open together", state.peak_open);
        let peak = client.pacer.peak_in_flight.load(std::sync::atomic::Ordering::SeqCst);
        assert!(peak <= 32, "peak in flight {peak} exceeds 32");
        let grants: Vec<Instant> = client.pacer.grants.lock().unwrap().iter().map(|t| t.into_std()).collect();
        assert_eq!(grants.len(), 480);
        assert!(busiest_second(&grants) <= 150, "{} sends in one second", busiest_second(&grants));
    }

    /// G6: worst case for bunching — slow answers (900 ms) from a burst of 400 calls. No
    /// 1 s window sees more than 182 arrivals (150 sent + 32 in flight) and none is a 429.
    /// This is an empirical check only: with answers this slow the 32 in-flight places cycle
    /// about 35 times a second, far below the bound. The bound itself holds by construction
    /// (`MAX_CALLS_PER_SECOND + MAX_IN_FLIGHT < SERVER_RATE_PER_SECOND`, a compile-time assert,
    /// and the grant-side checks in `mixed_calls_with_a_slow_body...`); a delayed-TCP-proxy
    /// variant could not reach the bound either, because every delayed request keeps its
    /// in-flight place, so no dependency-free version was added.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_answers_never_push_arrivals_past_the_servers_rate() {
        let server = slow_body_server(Duration::from_millis(900)).await;
        let client = client_for(&server.url, 120);
        mixed_burst(&client, 134).await; // 402 calls
        let state = server.state.lock().unwrap();
        assert_eq!(state.limited, 0);
        assert!(busiest_second(&state.arrivals) <= 182, "{} arrivals in one second", busiest_second(&state.arrivals));
    }

    /// G6 sensitivity of the send-rate cap: instant answers, so only the window limits the
    /// rate. With `MAX_CALLS_PER_SECOND` raised to 190 the arrivals pass 200 and the server refuses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn instant_answers_are_held_to_the_send_rate() {
        let server = slow_body_server(Duration::from_millis(0)).await;
        let client = client_for(&server.url, 60);
        mixed_burst(&client, 300).await; // 900 calls
        let state = server.state.lock().unwrap();
        assert_eq!(state.limited, 0, "the server answered 429 {} times", state.limited);
        assert!(busiest_second(&state.arrivals) <= 182, "{} arrivals in one second", busiest_second(&state.arrivals));
    }

    /// D5: the constant the budget is written against is the server's.
    #[test]
    fn the_server_rate_constant_is_the_servers() {
        let server = include_str!("../../crates/probation-server/src/sync.rs");
        let line = server.lines().find(|l| l.contains("pub const FIREWALL_TOKEN_RATE_PER_SECOND")).expect("the server constant exists");
        let value: usize = line.split('=').nth(1).unwrap().trim().trim_end_matches(';').trim().parse().unwrap();
        assert_eq!(value, SERVER_RATE_PER_SECOND, "update SERVER_RATE_PER_SECOND and re-check the pacer budget");
    }

    /// G7/C8: one pacer per token, shared by every client of it. When the last client is dropped
    /// the pacer is kept for one more window, so a client created at once cannot burst past the
    /// server's rate on a fresh window; after a quiet window the entry goes and the next client
    /// starts fresh.
    #[tokio::test]
    async fn pacers_are_per_token_and_outlive_their_last_client_by_one_window() {
        let (a1, a2, b) = (FirewallToken::new("g7-a".into()), FirewallToken::new("g7-a".into()), FirewallToken::new("g7-b".into()));
        let first = pacer_for(&a1);
        assert!(Arc::ptr_eq(&first, &pacer_for(&a2)), "the same token shares one pacer");
        assert!(!Arc::ptr_eq(&first, &pacer_for(&b)), "another token has its own");
        first.fill_window().await;
        assert!(first.window_len().await >= MAX_CALLS_PER_SECOND);
        drop(first);
        let again = pacer_for(&a1);
        assert!(again.window_len().await >= MAX_CALLS_PER_SECOND, "a client created at once inherits the busy window");
        again.fill_window().await; // refreshed: the last grant is now
        drop(again);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(pacer_for(&a1).window_len().await, 0, "after a quiet window a new client starts with a fresh window");
        assert!(Arc::strong_count(&pacer_for(&b)) >= 1);
    }

    /// G8: a waiter aborted while queued behind the lock does not stop the ones behind it,
    /// and gives back its in-flight place.
    #[tokio::test]
    async fn an_aborted_middle_waiter_does_not_block_the_queue_behind_it() {
        let pacer = Arc::new(Pacer::new(1, 10, W));
        drop(pacer.acquire(Tick::now() + Duration::from_secs(30)).await.unwrap());
        let start = Tick::now();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut handles = Vec::new();
        for index in 0..3usize {
            let (pacer, tx) = (Arc::clone(&pacer), tx.clone());
            handles.push(tokio::spawn(async move {
                pacer.acquire(Tick::now() + Duration::from_secs(30)).await.map(drop).unwrap();
                tx.send((index, Tick::now() - start)).unwrap();
            }));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handles[1].abort();
        drop(tx);
        let mut served = Vec::new();
        while let Some(row) = rx.recv().await {
            served.push(row);
        }
        assert_eq!(served.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 2], "the waiters around the aborted one are served in order");
        assert!(served[1].1 >= served[0].1 + W - Duration::from_millis(10), "each still waits for its own window");
        assert_eq!(pacer.available_flight(), 10, "every place is back");
    }

    /// G8: with only two places, ten waiters contend on the semaphore itself and are still
    /// served in arrival order.
    #[tokio::test]
    async fn contended_in_flight_places_are_handed_out_in_arrival_order() {
        let pacer = Arc::new(Pacer::new(1000, 2, W));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        for index in 0..10usize {
            let (pacer, tx) = (Arc::clone(&pacer), tx.clone());
            tokio::spawn(async move {
                let permit = pacer.acquire(Tick::now() + Duration::from_secs(60)).await.unwrap();
                tx.send(index).unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await; // the call is in flight
                drop(permit);
            });
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        drop(tx);
        let mut order = Vec::new();
        while let Some(index) = rx.recv().await {
            order.push(index);
        }
        assert_eq!(order, (0..10).collect::<Vec<_>>());
    }

    /// P5: the wait on the FIFO lock honours the request's deadline. A holds the window, a
    /// head waiter sleeps toward it with a long deadline, and B queued behind the lock with
    /// half a window left must be refused at about half a window, not when the head wakes.
    #[tokio::test]
    async fn a_waiter_queued_on_the_lock_gives_up_at_its_own_deadline() {
        let pacer = Arc::new(Pacer::new(1, 10, W));
        drop(pacer.acquire(Tick::now() + Duration::from_secs(5)).await.unwrap());
        let head = {
            let pacer = Arc::clone(&pacer);
            tokio::spawn(async move { pacer.acquire(Tick::now() + Duration::from_secs(5)).await.map(drop) })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = Tick::now();
        assert_eq!(pacer.acquire(started + W / 2).await.unwrap_err(), CallError::Busy);
        assert!(started.elapsed() < W * 3 / 4, "B overshot its deadline: {:?}", started.elapsed());
        head.await.unwrap().unwrap();
    }

    /// P16: the production `acquire` (not the test helper) records the grant, so a pacer
    /// whose clients are all gone is kept for one quiet window.
    #[tokio::test]
    async fn a_real_acquire_keeps_the_pacer_for_a_quiet_window() {
        let token = FirewallToken::new("p16-token".into());
        let first = pacer_for(&token);
        drop(first.acquire(Tick::now() + Duration::from_secs(5)).await.unwrap());
        drop(first);
        let again = pacer_for(&token);
        assert_eq!(again.window_len().await, 1, "the window survived its last client");
    }

    /// P18: a full window frees when its oldest send ages out (front + window), not a
    /// window after the later caller arrived.
    #[tokio::test]
    async fn an_aged_window_wakes_at_the_front_plus_the_window() {
        let pacer = Pacer::new(2, 10, W);
        let t0 = Tick::now();
        drop(pacer.acquire(t0 + Duration::from_secs(5)).await.unwrap());
        tokio::time::sleep(W / 3).await;
        drop(pacer.acquire(t0 + Duration::from_secs(5)).await.unwrap());
        let front = pacer.window_front().await.unwrap();
        drop(pacer.acquire(t0 + Duration::from_secs(5)).await.unwrap());
        let late = Tick::now() - (front + W);
        assert!(late < W / 6, "woke {late:?} after front + window");
    }

    /// P13/P14: the token goes to the configured URL only: a redirect is not followed and
    /// the environment proxy is not used.
    #[tokio::test]
    async fn redirects_are_not_followed_and_the_environment_proxy_is_ignored() {
        let elsewhere = MockServer::start().await;
        let origin = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", format!("{}/api/v1/sync/certificate", elsewhere.uri())))
            .mount(&origin)
            .await;
        let answer = burst(&client(&origin, 5), 1).await.pop().unwrap();
        assert_eq!(answer, Err(CallError::Unreachable));
        assert!(elsewhere.received_requests().await.unwrap().is_empty(), "the redirect was followed");

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        // SAFETY: only this test sets proxy variables; every client here builds with no_proxy.
        unsafe {
            std::env::set_var("HTTP_PROXY", format!("http://{}", proxy.local_addr().unwrap()));
            std::env::set_var("http_proxy", format!("http://{}", proxy.local_addr().unwrap()));
        }
        let (server, _seen) = counting_server().await;
        let answer = burst(&client(&server, 5), 1).await.pop().unwrap();
        assert!(matches!(answer, Ok(CertificateAdmission::Refused)), "{answer:?}");
        assert!(tokio::time::timeout(Duration::from_millis(100), proxy.accept()).await.is_err(), "the call went through the proxy");
    }
}
