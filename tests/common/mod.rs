//! The integration-test harness.
//!
//! Test-only code lives here and not behind a cargo feature, so the release binary
//! cannot contain a bypass. Nothing in `src/` refers to this file.
//!
//! Each test binary compiles its own copy of this module and uses only part of it,
//! so unused items here are expected rather than a sign of dead code.
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use probation::clock::{Clock, SystemClock};
use probation::config::Config;
use probation::upstream::{
    ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, OriginSet, ReqwestTransport,
    Transport, UpstreamError, UpstreamValidators,
};
use probation::{App, AppDeps, Running};
use tempfile::TempDir;
use url::Url;

/// The shipped `config.sample.toml` exactly as an operator would use it, with only
/// `listen` replaced by port 0 so tests can run in parallel.
///
/// `data_dir` is left as the sample's production path on purpose: `TestServer`
/// replaces it with a directory the test owns, so no test can accidentally take the
/// lock on, or write to, a real deployment's state.
pub fn sample_config() -> Config {
    let mut config = Config::load(Path::new("config.sample.toml"))
        .expect("config.sample.toml is valid configuration");
    config.listen = SocketAddr::from(([127, 0, 0, 1], 0));
    config
}

/// A clock the test moves by hand.
///
/// The monotonic reading ordinarily advances with the wall clock, which is enough for
/// the slices that only have deadlines. [`TestClock::rewind_wall_clock_seconds`] is
/// what tells the two apart: it moves the wall clock backwards while leaving the
/// monotonic reading where it was, which is the only shape a real backward jump has.
pub struct TestClock {
    start_utc_micros: i64,
    utc_micros: AtomicI64,
    monotonic_base: Instant,
    /// Monotonic time the wall clock has been rewound past. A real monotonic clock
    /// never runs backwards, so every rewind is added here and the reading stands
    /// still instead of following the wall clock down.
    monotonic_carry_micros: AtomicI64,
}

impl TestClock {
    pub fn at(utc_micros: i64) -> Arc<TestClock> {
        Arc::new(TestClock {
            start_utc_micros: utc_micros,
            utc_micros: AtomicI64::new(utc_micros),
            monotonic_base: Instant::now(),
            monotonic_carry_micros: AtomicI64::new(0),
        })
    }

    /// The RFC 3339 spelling is what the fixtures use, so tests can name the same
    /// instant the blocklist window does.
    pub fn at_rfc3339(text: &str) -> Arc<TestClock> {
        TestClock::at(parse_rfc3339(text))
    }

    pub fn set_rfc3339(&self, text: &str) {
        self.utc_micros.store(parse_rfc3339(text), Ordering::SeqCst);
    }

    pub fn advance_seconds(&self, seconds: i64) {
        self.utc_micros
            .fetch_add(seconds * 1_000_000, Ordering::SeqCst);
    }

    /// Moves the wall clock `seconds` into the past while the monotonic reading
    /// stays exactly where it is — an NTP step, not a time machine.
    pub fn rewind_wall_clock_seconds(&self, seconds: i64) {
        self.monotonic_carry_micros
            .fetch_add(seconds * 1_000_000, Ordering::SeqCst);
        self.utc_micros
            .fetch_sub(seconds * 1_000_000, Ordering::SeqCst);
    }

    /// The same clock as the injectable trait object, for a test that keeps its own
    /// handle to move the clock with after the server has taken one.
    pub fn shared(self: &Arc<Self>) -> Arc<dyn Clock> {
        let clock: Arc<TestClock> = Arc::clone(self);
        clock
    }
}

impl Clock for TestClock {
    fn now_utc_micros(&self) -> i64 {
        self.utc_micros.load(Ordering::SeqCst)
    }

    fn now_monotonic(&self) -> Instant {
        let elapsed = self
            .now_utc_micros()
            .saturating_sub(self.start_utc_micros)
            .max(0)
            .saturating_add(self.monotonic_carry_micros.load(Ordering::SeqCst));
        self.monotonic_base + Duration::from_micros(elapsed as u64)
    }
}

pub fn parse_rfc3339(text: &str) -> i64 {
    text.parse::<jiff::Timestamp>()
        .expect("a test timestamp")
        .as_microsecond()
}

/// A real server started through `App::start`, bound to an ephemeral loopback port
/// so tests can run in parallel.
pub struct TestServer {
    running: Running,
    client: reqwest::Client,
    /// Held so the directory survives as long as the server that is using it. `None`
    /// when the test supplied a directory of its own, which is what a restart needs.
    _data_dir: Option<TempDir>,
}

impl TestServer {
    /// The shipped sample configuration and the real clock, in a data directory of
    /// its own.
    pub async fn start() -> TestServer {
        TestServer::start_with(sample_config(), Arc::new(SystemClock)).await
    }

    /// The same startup path, with a configuration and a clock the test chose, in a
    /// fresh data directory this server owns. This is the only way a test influences
    /// the application: there is no bypass.
    ///
    /// The upstream is a [`FakeRegistry`] that knows nothing, so a test that says
    /// nothing about upstream reaches no socket at all — the default is offline
    /// rather than "the real registry, if this machine happens to have a network".
    pub async fn start_with(config: Config, clock: Arc<dyn Clock>) -> TestServer {
        let (transport, origins) = fake_upstream();
        TestServer::start_with_upstream(config, clock, transport, origins).await
    }

    /// The full seam: configuration, clock, transport and origin set, all four
    /// injected. Nothing else reaches `App::start`.
    pub async fn start_with_upstream(
        mut config: Config,
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        origins: OriginSet,
    ) -> TestServer {
        let data_dir = tempfile::tempdir().expect("a temporary data directory");
        config.data_dir = data_dir.path().to_path_buf();

        let running = start(
            config,
            clock,
            transport,
            origins,
            probation::osv::unreachable_client(),
            None,
        )
        .await;
        TestServer {
            running,
            client: downstream_client(),
            _data_dir: Some(data_dir),
        }
    }

    /// The same seam, for a test that needs OSV to actually answer something — a
    /// match, not just `start_with_upstream`'s fail-open refusal. `osv_client` and
    /// `osv_base_url` replace the offline default, typically a plain
    /// `reqwest::Client::new()` and a local `wiremock` server's URL.
    pub async fn start_with_upstream_and_osv(
        mut config: Config,
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        origins: OriginSet,
        osv_client: reqwest::Client,
        osv_base_url: Url,
    ) -> TestServer {
        let data_dir = tempfile::tempdir().expect("a temporary data directory");
        config.data_dir = data_dir.path().to_path_buf();

        let running = start(
            config,
            clock,
            transport,
            origins,
            osv_client,
            Some(osv_base_url),
        )
        .await;
        TestServer {
            running,
            client: downstream_client(),
            _data_dir: Some(data_dir),
        }
    }

    /// Starts in a directory the test owns, so a later start can find what this one
    /// persisted. `config.data_dir` is overwritten with `data_dir`.
    pub async fn start_in(
        data_dir: &Path,
        mut config: Config,
        clock: Arc<dyn Clock>,
    ) -> TestServer {
        config.data_dir = data_dir.to_path_buf();

        let (transport, origins) = fake_upstream();
        let running = start(
            config,
            clock,
            transport,
            origins,
            probation::osv::unreachable_client(),
            None,
        )
        .await;
        TestServer {
            running,
            client: downstream_client(),
            _data_dir: None,
        }
    }

    /// The same, with a registry the test keeps a handle on so it can read back the
    /// URLs the server asked for.
    pub async fn start_in_with_registry(
        data_dir: &Path,
        mut config: Config,
        clock: Arc<dyn Clock>,
        registry: Arc<FakeRegistry>,
    ) -> TestServer {
        config.data_dir = data_dir.to_path_buf();

        let running = start(
            config,
            clock,
            registry,
            fake_origins(),
            probation::osv::unreachable_client(),
            None,
        )
        .await;
        TestServer {
            running,
            client: downstream_client(),
            _data_dir: None,
        }
    }

    /// The running application, for a test that has to read state the HTTP surface
    /// does not expose — a persisted reference row, say.
    pub fn running(&self) -> &Running {
        &self.running
    }

    /// How many storage commands every request so far has put on a queue.
    ///
    /// SPEC §10: "On a fully warm request, policy and response lookup require no
    /// database query". This is what a test reads that off.
    pub fn store_commands(&self) -> u64 {
        self.running.app().store().commands_issued()
    }

    pub async fn json(&self, path: &str) -> serde_json::Value {
        let response = self.get(path).await;
        let status = response.status();
        let body = response.text().await.expect("a body");
        assert!(
            status.is_success(),
            "{path} answered {status}, not a document: {body}"
        );
        serde_json::from_str(&body)
            .unwrap_or_else(|err| panic!("{path} is not JSON: {err}: {body}"))
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.running.local_addr)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.running.local_addr
    }

    /// The application, for a test that drives a library entry point directly rather
    /// than through a socket — which is how a concurrency test gets a future it can
    /// drop at an instant of its own choosing.
    pub fn app(&self) -> Arc<probation::App> {
        Arc::clone(self.running.app())
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("the request completes")
    }

    /// The same request with headers of the test's choosing. Used to prove that
    /// what a client sends this proxy is not what this proxy sends upstream.
    pub async fn get_with_headers(
        &self,
        path: &str,
        headers: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut request = self.client.get(self.url(path));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.send().await.expect("the request completes")
    }

    /// A request with a method this server does not support on that route, for the
    /// SPEC §11 `405` row.
    pub async fn post(&self, path: &str) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .send()
            .await
            .expect("the request completes")
    }

    pub async fn head(&self, path: &str) -> reqwest::Response {
        self.client
            .head(self.url(path))
            .send()
            .await
            .expect("the request completes")
    }

    pub async fn status(&self, path: &str) -> u16 {
        self.get(path).await.status().as_u16()
    }

    /// A request whose target reaches the server byte for byte.
    ///
    /// `reqwest` parses what it is given into a `Url`, which decodes `%2E` and then
    /// removes dot segments — so `/npm/%2E%2E` never leaves the client as anything
    /// but `/`. An attacker does not use `reqwest`. This writes the request line
    /// itself, so a path the URL crate would rewrite can actually be delivered.
    ///
    /// Slice 4 learned this the hard way: its first test for a `..` package name
    /// passed against broken code, because the attack never left the client. Every
    /// assertion about a hostile path goes through here.
    pub async fn raw_get(&self, raw_path: &str, headers: &[(&str, &str)]) -> String {
        let addr = self.running.local_addr;
        let mut request =
            format!("GET {raw_path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        self.raw_send(&request).await
    }

    /// The whole request, byte for byte, including its request line.
    ///
    /// The same reason as [`TestServer::raw_get`] and two more: `reqwest` will not
    /// send every method a client could put on the wire, and it will not send a
    /// malformed request line at all. Both are things this server has to answer.
    pub async fn raw_send(&self, raw_request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = self.running.local_addr;
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the server accepts a connection");
        stream
            .write_all(raw_request.as_bytes())
            .await
            .expect("the request is written");

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("the response is read");
        String::from_utf8_lossy(&response).into_owned()
    }

    pub async fn raw_get_status(&self, raw_path: &str) -> u16 {
        let response = self.raw_get(raw_path, &[]).await;
        let status = response
            .split_whitespace()
            .nth(1)
            .unwrap_or_else(|| panic!("a status line, got {response:?}"));
        status.parse().expect("a numeric status")
    }

    /// Waits for `path` to answer `expected`, panicking with what it saw instead when
    /// `within` runs out. Used where a background loop, not the request, is what makes
    /// the answer change.
    pub async fn wait_for_status(&self, path: &str, expected: u16, within: Duration) {
        let deadline = Instant::now() + within;
        let mut last = self.status(path).await;
        while last != expected {
            if Instant::now() >= deadline {
                panic!("{path} answered {last}, not {expected}, within {within:?}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            last = self.status(path).await;
        }
    }

    pub async fn shutdown(self) {
        self.running.shutdown().await.expect("a clean shutdown");
    }
}

/// The client a test talks to its own server with.
///
/// `.no_proxy()` is not decoration. `reqwest` reads `HTTP_PROXY`/`ALL_PROXY` at
/// build time, and `origin_guard::no_config_key_or_env_var_relaxes_origins` sets
/// both for real, process-wide, while it runs — so a default client built anywhere
/// in that window tries to reach the loopback test server through a proxy that
/// refuses every connection. A test client has no business using a proxy in any
/// case.
pub fn downstream_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("a test HTTP client")
}

/// Waits until `condition` holds, or panics saying it never did.
///
/// This is a wait for something to *become* true, never a wait to create timing: every
/// test below forces the interleaving it is about with a [`Gate`] or by dropping a
/// future itself, and then uses this only to observe the consequence.
pub async fn wait_until(what: &str, within: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "{what} did not happen within {within:?}"
        );
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// A client that sends a request and then does not read the answer.
///
/// `reqwest` reads a response as fast as it arrives, which is the opposite of what a
/// slow-consumer test needs. This writes the request line itself and leaves the socket
/// alone, so the kernel's receive buffer fills, the server's send blocks, and the
/// SPEC §9 deadlines are what end the response.
pub struct SlowReader {
    stream: tokio::net::TcpStream,
}

impl SlowReader {
    pub async fn get(server: &TestServer, path: &str) -> SlowReader {
        use tokio::io::AsyncWriteExt;

        let addr = server.local_addr();
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the server accepts a connection");
        let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("the request is written");
        SlowReader { stream }
    }

    /// Reads everything the server managed to send, once it has stopped sending.
    /// Returns the whole response, headers included.
    pub async fn read_what_arrived(mut self) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

        let mut response = Vec::new();
        let _ = self.stream.read_to_end(&mut response).await;
        response
    }
}

/// The status code of a response read off a raw socket.
pub fn raw_status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("a status line, got {response:?}"))
        .parse()
        .expect("a numeric status")
}

/// One header value of a response read off a raw socket, matched case-insensitively
/// as HTTP requires.
pub fn raw_header(response: &str, name: &str) -> Option<String> {
    response
        .split("\r\n\r\n")
        .next()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}

/// The body of an HTTP/1.1 response read off a raw socket: everything after the
/// blank line.
pub fn body_bytes(response: &[u8]) -> &[u8] {
    match response.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(at) => &response[at + 4..],
        None => &[],
    }
}

async fn start(
    config: Config,
    clock: Arc<dyn Clock>,
    transport: Arc<dyn Transport>,
    origins: OriginSet,
    osv_client: reqwest::Client,
    osv_base_url: Option<Url>,
) -> Running {
    App::start(AppDeps {
        config,
        clock,
        transport,
        origins,
        osv_client,
        osv_base_url,
    })
    .await
    .expect("the server binds and starts")
}

/// What an in-process [`FakeRegistry`] answers with for one URL path.
#[derive(Clone, Debug)]
pub enum FakeAnswer {
    /// A `200` with this body.
    Body(String),
    /// Upstream `404`/`410`.
    Missing,
    Fail(UpstreamError),
    /// Metadata only: a registry that validates. It answers `200` with `body` and an
    /// `ETag` of `etag`, and `304` to any request whose `If-None-Match` carries that
    /// same `etag` — which is exactly the pair SPEC §10's revalidation needs, and the
    /// only way a test can tell a conditional request from a refetch.
    Validated {
        etag: String,
        body: String,
    },
    /// Metadata only: answers `304` whatever the request carried — including a
    /// request that carried no validator at all, which no conforming registry would
    /// ever do.
    ///
    /// [`FakeAnswer::Validated`] cannot produce that state by construction, and it
    /// should not be bent into producing it: a registry that only ever answers `304`
    /// to a matching validator is the right default. This is the hostile-registry
    /// shape, and it is the only way to witness the firewall's fail-closed branches
    /// for a `304` it never asked a conditional question to get.
    AlwaysNotModified {
        etag: Option<String>,
        last_modified: Option<String>,
    },
    /// Artifacts only: declares `declared_length` bytes and then stops early. This
    /// is the truncating transport — the body is complete as far as the stream is
    /// concerned, and only the declared length says otherwise.
    Truncated {
        declared_length: u64,
        body: String,
    },
    /// Artifacts only: sends `head`, waits at `gate`, then sends `tail`. A request
    /// parked here has a download genuinely in flight, which is what lets a test
    /// assert on what the client has received *during* verification.
    Gated {
        head: String,
        tail: String,
        gate: Arc<Gate>,
    },
    /// Artifacts only: sends `head`, then panics when the stream is next polled. This
    /// stands in for any bug that could panic inside a transfer — an unwrap, an index,
    /// a dependency — and it is how a test reaches the transfer task's unwind path
    /// without putting a panic in the product code to reach it.
    PanicsMidStream {
        head: String,
    },
    /// Metadata only: waits at `gate`, then answers with `body`. A refresh parked here
    /// is genuinely in flight, which is what lets a test be certain the requests that
    /// join it are concurrent with it rather than served one after another.
    GatedMetadata {
        body: String,
        gate: Arc<Gate>,
    },
    /// Metadata only: waits at `gate`, then answers `304` carrying `etag`.
    ///
    /// The revalidation counterpart of [`FakeAnswer::GatedMetadata`], which can only
    /// park a *full fetch*. Parking a conditional refresh is the only way to hold one
    /// genuinely in flight while the test walks the wall clock across the maximum-age
    /// ceiling, so this is what a coalescing-boundary test needs and nothing else
    /// here provides. It answers `304` whatever the request carried, like
    /// [`FakeAnswer::AlwaysNotModified`]; a test registers it only after a seeding
    /// `200` has stored the validators the refresh will send.
    GatedNotModified {
        etag: String,
        gate: Arc<Gate>,
    },
    /// Metadata only: waits at `gate`, then panics. The metadata counterpart of
    /// [`FakeAnswer::PanicsMidStream`], and the same reason: it reaches the refresh's
    /// unwind path without putting a panic in the product code to reach it.
    PanicsMidRefresh {
        gate: Arc<Gate>,
    },
}

/// A rendezvous between a test and a download in flight.
#[derive(Debug)]
pub struct Gate {
    reached: tokio::sync::Semaphore,
    released: tokio::sync::Semaphore,
}

impl Gate {
    pub fn new() -> Arc<Gate> {
        Arc::new(Gate {
            reached: tokio::sync::Semaphore::new(0),
            released: tokio::sync::Semaphore::new(0),
        })
    }

    /// Returns once the transport has delivered its first chunk and is waiting.
    pub async fn wait_until_reached(&self) {
        let _ = self.reached.acquire().await.expect("the gate is open");
    }

    /// Lets the download finish.
    pub fn release(&self) {
        self.released.add_permits(1);
    }

    async fn arrive(&self) {
        self.reached.add_permits(1);
        let _ = self.released.acquire().await.expect("the gate is open");
    }
}

/// An in-process [`Transport`]: no socket, no DNS, no TLS.
///
/// It records every URL it is asked for, so a test can assert that a locally
/// conclusive denial never reached upstream, and it answers `Missing` for anything
/// it was not told about, so a server a test never configured serves nothing.
#[derive(Default)]
pub struct FakeRegistry {
    answers: Mutex<HashMap<String, FakeAnswer>>,
    calls: Mutex<Vec<Url>>,
    /// The validators every *conditional* metadata request carried, with the path it
    /// was for. A request that carried none is absent, so a test can say "this
    /// revalidation was conditional" rather than only "upstream was asked again".
    conditional: Mutex<Vec<(String, UpstreamValidators)>>,
    /// How many requests this registry answered `304`.
    not_modified: std::sync::atomic::AtomicUsize,
    /// Every call fails once this is set, while still being recorded — so a test can
    /// assert both that upstream was unreachable and that nothing tried to reach it.
    offline: std::sync::atomic::AtomicBool,
}

impl FakeRegistry {
    pub fn new() -> Arc<FakeRegistry> {
        Arc::new(FakeRegistry::default())
    }

    /// `path` is the URL path, as `Url::path` spells it — percent-encoded exactly
    /// the way `OriginSet::url_for` built it.
    pub fn answer(self: &Arc<Self>, path: &str, answer: FakeAnswer) -> Arc<FakeRegistry> {
        self.answers
            .lock()
            .expect("the fake registry's answers")
            .insert(path.to_owned(), answer);
        Arc::clone(self)
    }

    pub fn calls(&self) -> Vec<Url> {
        self.calls
            .lock()
            .expect("the fake registry's calls")
            .clone()
    }

    /// The validators each conditional request for `path` carried, in order.
    pub fn conditional_calls(&self, path: &str) -> Vec<UpstreamValidators> {
        self.conditional
            .lock()
            .expect("the fake registry's conditional requests")
            .iter()
            .filter(|(asked, _)| asked == path)
            .map(|(_, validators)| validators.clone())
            .collect()
    }

    /// How many requests this registry has answered `304` rather than with a body.
    pub fn not_modified_answers(&self) -> usize {
        self.not_modified.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Makes every later call fail, as an unreachable upstream does. PERF-01's test
    /// uses this: with upstream unreachable, a locally conclusive block must still
    /// answer.
    pub fn go_offline(&self) {
        self.offline
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn record(&self, url: &Url) -> FakeAnswer {
        self.calls
            .lock()
            .expect("the fake registry's calls")
            .push(url.clone());
        if self.offline.load(std::sync::atomic::Ordering::SeqCst) {
            return FakeAnswer::Fail(UpstreamError::Transport(
                "the upstream registry is unreachable".to_owned(),
            ));
        }
        self.answers
            .lock()
            .expect("the fake registry's answers")
            .get(url.path())
            .cloned()
            .unwrap_or(FakeAnswer::Missing)
    }
}

#[async_trait]
impl Transport for FakeRegistry {
    async fn fetch_metadata(
        &self,
        req: MetadataRequest,
    ) -> Result<MetadataResponse, UpstreamError> {
        if let Some(validators) = req.validators.as_ref().filter(|v| !v.is_empty()) {
            self.conditional
                .lock()
                .expect("the fake registry's conditional requests")
                .push((req.url.path().to_owned(), validators.clone()));
        }

        match self.record(&req.url) {
            FakeAnswer::Body(body) => {
                if body.len() as u64 > req.max_bytes {
                    return Err(UpstreamError::TooLarge {
                        limit: req.max_bytes,
                    });
                }
                Ok(MetadataResponse::Fresh {
                    body: body.into(),
                    validators: UpstreamValidators::default(),
                })
            }
            FakeAnswer::Validated { etag, body } => {
                let validators = UpstreamValidators {
                    etag: Some(etag.clone()),
                    last_modified: None,
                };
                if req.validators.and_then(|sent| sent.etag).as_deref() == Some(etag.as_str()) {
                    self.not_modified
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    return Ok(MetadataResponse::NotModified { validators });
                }
                if body.len() as u64 > req.max_bytes {
                    return Err(UpstreamError::TooLarge {
                        limit: req.max_bytes,
                    });
                }
                Ok(MetadataResponse::Fresh {
                    body: body.into(),
                    validators,
                })
            }
            FakeAnswer::AlwaysNotModified {
                etag,
                last_modified,
            } => {
                self.not_modified
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(MetadataResponse::NotModified {
                    validators: UpstreamValidators {
                        etag,
                        last_modified,
                    },
                })
            }
            FakeAnswer::Missing => Ok(MetadataResponse::Missing),
            FakeAnswer::Fail(err) => Err(err),
            // Neither shape describes a metadata document; a test registers them for
            // artifact paths only.
            FakeAnswer::Truncated { body, .. } | FakeAnswer::Gated { head: body, .. } => {
                Ok(MetadataResponse::Fresh {
                    body: body.into(),
                    validators: UpstreamValidators::default(),
                })
            }
            // Artifact-only, and a metadata document is not what it describes.
            FakeAnswer::PanicsMidStream { .. } => Ok(MetadataResponse::Missing),
            FakeAnswer::GatedMetadata { body, gate } => {
                // The refresh is now genuinely in flight and has not answered.
                gate.arrive().await;
                Ok(MetadataResponse::Fresh {
                    body: body.into(),
                    validators: UpstreamValidators::default(),
                })
            }
            FakeAnswer::GatedNotModified { etag, gate } => {
                // The revalidation is now genuinely in flight and has not answered.
                gate.arrive().await;
                self.not_modified
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(MetadataResponse::NotModified {
                    validators: UpstreamValidators {
                        etag: Some(etag),
                        last_modified: None,
                    },
                })
            }
            FakeAnswer::PanicsMidRefresh { gate } => {
                gate.arrive().await;
                panic!("the upstream metadata refresh panicked mid-flight");
            }
        }
    }

    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        let capped = |body: String, declared: Option<u64>| ArtifactBody {
            declared_length: declared,
            stream: probation::upstream::capped(
                Box::pin(futures_util::stream::once(async move {
                    Ok(bytes::Bytes::from(body))
                })),
                req.max_bytes,
            ),
        };

        match self.record(&req.url) {
            FakeAnswer::Body(body) => {
                let declared = body.len() as u64;
                Ok(capped(body, Some(declared)))
            }
            FakeAnswer::Truncated {
                declared_length,
                body,
            } => Ok(capped(body, Some(declared_length))),
            FakeAnswer::Gated { head, tail, gate } => {
                let declared = (head.len() + tail.len()) as u64;
                let stream = futures_util::stream::unfold(
                    (Some(head), Some(tail), gate),
                    |(head, tail, gate)| async move {
                        if let Some(head) = head {
                            return Some((Ok(bytes::Bytes::from(head)), (None, tail, gate)));
                        }
                        let tail = tail?;
                        // The download is now genuinely in flight and half arrived.
                        gate.arrive().await;
                        Some((Ok(bytes::Bytes::from(tail)), (None, None, gate)))
                    },
                );
                Ok(ArtifactBody {
                    declared_length: Some(declared),
                    stream: probation::upstream::capped(Box::pin(stream), req.max_bytes),
                })
            }
            FakeAnswer::PanicsMidStream { head } => {
                let declared = (head.len() + 1) as u64;
                let stream = futures_util::stream::unfold(Some(head), |head| async move {
                    match head {
                        Some(head) => Some((Ok(bytes::Bytes::from(head)), None)),
                        None => panic!("the upstream transfer panicked mid-body"),
                    }
                });
                Ok(ArtifactBody {
                    declared_length: Some(declared),
                    stream: probation::upstream::capped(Box::pin(stream), req.max_bytes),
                })
            }
            FakeAnswer::Missing => Err(UpstreamError::Status(404)),
            FakeAnswer::Fail(err) => Err(err),
            // Metadata-only, and an artifact body is not what they describe.
            FakeAnswer::Validated { .. }
            | FakeAnswer::AlwaysNotModified { .. }
            | FakeAnswer::GatedMetadata { .. }
            | FakeAnswer::GatedNotModified { .. }
            | FakeAnswer::PanicsMidRefresh { .. } => Err(UpstreamError::Status(404)),
        }
    }
}

/// Origins for a transport that never connects. They are still `https` on default
/// ports, so nothing here quietly depends on the relaxation `for_tests` grants.
pub fn fake_origins() -> OriginSet {
    OriginSet::for_tests(
        Url::parse("https://npm.invalid").expect("a fake npm origin"),
        Url::parse("https://pypi.invalid").expect("a fake pypi origin"),
        Url::parse("https://files.invalid").expect("a fake artifact origin"),
    )
}

pub fn fake_upstream() -> (Arc<dyn Transport>, OriginSet) {
    (FakeRegistry::new(), fake_origins())
}

/// The URL path `OriginSet::url_for` builds for one npm package name, which is the
/// key a [`FakeRegistry`] answer has to be registered under.
///
/// Computed rather than written out, because a scoped name's `/` becomes `%2F` and a
/// test that spelled that by hand would be asserting on its own guess.
pub fn npm_upstream_path(name: &str) -> String {
    fake_origins()
        .url_for(probation::upstream::OriginKind::NpmMetadata, &[name])
        .expect("the fake origin builds a URL for this name")
        .path()
        .to_owned()
}

/// The URL path `OriginSet::url_for` builds for one *normalised* PyPI project name.
/// The trailing empty segment is the canonical `/simple/{project}/` form, which is
/// what a [`FakeRegistry`] answer has to be registered under.
pub fn pypi_upstream_path(name: &str) -> String {
    fake_origins()
        .url_for(
            probation::upstream::OriginKind::PypiMetadata,
            &["simple", name, ""],
        )
        .expect("the fake origin builds a URL for this project")
        .path()
        .to_owned()
}

/// The `error` token of a SPEC §11 error body, which is the part a client matches
/// on.
pub async fn body_error(response: reqwest::Response) -> String {
    let body = response.text().await.expect("a body");
    let value: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("the body is not JSON: {err}: {body}"));
    value["error"]
        .as_str()
        .unwrap_or_else(|| panic!("the error body names an error: {body}"))
        .to_owned()
}

/// A checked-in fixture under `tests/fixtures/`.
pub fn fixture(relative: &str) -> String {
    let path = Path::new("tests/fixtures").join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("the fixture {} is readable: {err}", path.display()))
}

/// A `wiremock` socket standing in for a registry, with the *production*
/// [`ReqwestTransport`] pointed at it.
///
/// This is the only way the real client, the real redirect policy and the real
/// admission check are exercised without a public network: everything below
/// `ReqwestTransport::for_origins` is exactly what ships.
pub struct WiremockUpstream {
    pub server: wiremock::MockServer,
    pub origins: OriginSet,
    pub transport: Arc<dyn Transport>,
}

impl WiremockUpstream {
    /// One socket standing in for all three origins.
    pub async fn start() -> WiremockUpstream {
        let server = wiremock::MockServer::start().await;
        let origin = Url::parse(&server.uri()).expect("the wiremock origin is a URL");
        let origins = OriginSet::for_tests(origin.clone(), origin.clone(), origin);
        let transport = Arc::new(ReqwestTransport::for_origins(origins.clone()));
        WiremockUpstream {
            server,
            origins,
            transport,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.uri())
    }
}

/// A configuration whose blocklist file is a valid snapshot that blocks nothing, so
/// `policy::evaluate` answers something other than `Unavailable` and a request can
/// reach the outbound boundary at all.
///
/// The window is wide enough that the real clock is inside it, because the tests
/// that use this one are about the network and not about time.
pub fn config_with_open_blocklist(dir: &Path) -> Config {
    let blocklist_file = dir.join("blocklist.json");
    std::fs::write(
        &blocklist_file,
        snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", ""),
    )
    .expect("the blocklist is written");

    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config
}

/// Runs `body` on a runtime of its own and then destroys that runtime without
/// letting any task finish.
///
/// **This is not a process kill.** No signal is delivered and no separate process is
/// involved: `shutdown_timeout(Duration::ZERO)` drops every task in this process
/// where it stands — the storage task mid-loop, the poller mid-poll, the listener
/// mid-accept — and the connection and lock file close by `Drop`. No shutdown path
/// runs and nothing is checkpointed, which is the state a restart has to recover
/// from. Gate 3 fixes that tests use the library and never a spawned binary, so a
/// real signal is not available here.
///
/// What it therefore does **not** cover: a kill in the middle of a write the kernel
/// has not yet taken, a partially written write-ahead-log frame, or anything
/// `SIGKILL` does that dropping a handle does not. Real-`SIGKILL` coverage was done
/// separately, by adversarial testing against spawned processes.
pub fn run_and_kill<F>(body: impl FnOnce() -> F)
where
    F: Future<Output = ()>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    runtime.block_on(body());
    runtime.shutdown_timeout(Duration::ZERO);
}

/// Runs `body` on a runtime of its own and shuts that runtime down in the ordinary
/// way. Used by the tests that are not `#[tokio::test]` because they also need
/// [`run_and_kill`].
pub fn run<T>(body: impl Future<Output = T>) -> T {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    runtime.block_on(body)
}

/// Captures the crate's `ERROR` log lines so a test can assert that a background
/// loop kept trying rather than giving up quietly.
///
/// One global subscriber for the whole test binary, because `set_global_default` may
/// be called only once per process and a thread-local subscriber would miss the
/// poller, which runs on other runtime threads. Tests therefore share one buffer and
/// select their own lines by the temp path they were given, which is unique per test.
pub mod logs {
    use std::io;
    use std::sync::{Arc, Mutex, OnceLock};

    #[derive(Clone, Default)]
    pub struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("the capture buffer")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;

        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }

    /// Installs the capturing subscriber the first time it is called and hands back
    /// the shared buffer. Safe to call from every test in a binary.
    pub fn capture() -> Captured {
        install(tracing::Level::ERROR)
    }

    /// The same buffer, installed at `WARN`, for the exclusions SPEC §7 and §11 ask
    /// to be logged — an excluded file is not an error.
    ///
    /// The level is decided by whichever of the two runs first *in this binary*, and
    /// cargo gives every test file its own process, so a file that wants `WARN` gets
    /// it without widening what any other file captures.
    pub fn capture_warn() -> Captured {
        install(tracing::Level::WARN)
    }

    /// The same buffer at `INFO`, which is where SPEC §11's per-request decision line
    /// and the periodic counter summary are written.
    pub fn capture_info() -> Captured {
        install(tracing::Level::INFO)
    }

    fn install(level: tracing::Level) -> Captured {
        static CAPTURED: OnceLock<Captured> = OnceLock::new();
        CAPTURED
            .get_or_init(|| {
                let captured = Captured::default();
                let subscriber = tracing_subscriber::fmt()
                    .with_writer(captured.clone())
                    // Without this the buffer holds ANSI escapes between every field
                    // name and its value, so an assertion about a structured field
                    // would be matching on terminal colours.
                    .with_ansi(false)
                    .with_max_level(level)
                    .finish();
                // A second install would mean two test binaries in one process, which
                // cargo does not do; ignoring the failure keeps the helper infallible.
                let _ = tracing::subscriber::set_global_default(subscriber);
                captured
            })
            .clone()
    }

    impl Captured {
        /// How many captured lines mention `needle`. Tests pass their own temp path,
        /// which no other test in the binary can produce.
        pub fn lines_mentioning(&self, needle: &str) -> usize {
            self.lines_containing_all(&[needle])
        }

        /// How many captured lines mention every one of `needles`.
        ///
        /// Tests in one binary share this buffer and run in parallel, so an assertion
        /// about "one line per request" has to select that request's line rather than
        /// count everything. A request ID plus the decision line's own message is a
        /// selector no other test in the binary can produce.
        pub fn lines_containing_all(&self, needles: &[&str]) -> usize {
            String::from_utf8_lossy(&self.0.lock().expect("the capture buffer"))
                .lines()
                .filter(|line| needles.iter().all(|needle| line.contains(needle)))
                .count()
        }

        /// Everything captured so far, for an assertion that has to read a line rather
        /// than count it.
        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("the capture buffer")).into_owned()
        }
    }
}

/// A valid blocklist document. `blocked` is the raw contents of `blocked_packages`,
/// so a test can write exactly the records it wants to reason about.
pub fn snapshot(revision: u64, generated_at: &str, expires_at: &str, blocked: &str) -> String {
    format!(
        r#"{{"schema_version":1,"revision":{revision},"generated_at":"{generated_at}","expires_at":"{expires_at}","blocked_packages":[{blocked}],"blocked_hashes":[]}}"#
    )
}

/// A valid blocklist document with both record kinds, so a test can block a digest
/// as well as a package. `blocked` and `hashes` are the raw contents of
/// `blocked_packages` and `blocked_hashes`.
pub fn snapshot_with(
    revision: u64,
    generated_at: &str,
    expires_at: &str,
    blocked: &str,
    hashes: &str,
) -> String {
    format!(
        r#"{{"schema_version":1,"revision":{revision},"generated_at":"{generated_at}","expires_at":"{expires_at}","blocked_packages":[{blocked}],"blocked_hashes":[{hashes}]}}"#
    )
}

/// Puts `document` in force immediately, as `PolicyHandle::publish` does at the end
/// of the poller's pass.
///
/// This is the publication point and nothing else: the poller's own commit-then-
/// publish ordering is slice 3's subject and is tested there. What these tests need
/// is a new snapshot in force at an instant they choose, without waiting a polling
/// interval for it.
pub fn publish_blocklist(server: &TestServer, document: &str, now_micros: i64) {
    let snapshot = probation::policy::BlocklistSnapshot::parse_and_validate(
        document.as_bytes(),
        now_micros,
    )
    .expect("the test blocklist is valid");
    server
        .running()
        .app()
        .publish_blocklist(std::sync::Arc::new(snapshot));
}

/// A clock that publishes a blocklist the first time it is read after being armed.
///
/// This is how a test lands a blocklist update *inside* one request, deterministically
/// and without a sleep. `artifacts::serve_artifact` loads the policy snapshot before
/// it reads the clock, so arming this before a request means: the request's first
/// check runs against the old snapshot, the update is published, and the final check —
/// which loads the snapshot again — must see it. That is exactly the revocation
/// boundary window.
pub struct TriggerClock {
    inner: Arc<TestClock>,
    armed: std::sync::atomic::AtomicBool,
    /// **Weak**, and that is load-bearing: the application holds this clock, so an
    /// `Arc` here would be a cycle, and `Running::shutdown` — which closes the store
    /// queues by dropping the last `App` — would wait for a storage task that never
    /// stops.
    app: Mutex<Option<std::sync::Weak<probation::App>>>,
    document: Mutex<Option<String>>,
}

impl TriggerClock {
    pub fn at_rfc3339(text: &str) -> Arc<TriggerClock> {
        Arc::new(TriggerClock {
            inner: TestClock::at_rfc3339(text),
            armed: std::sync::atomic::AtomicBool::new(false),
            app: Mutex::new(None),
            document: Mutex::new(None),
        })
    }

    pub fn shared(self: &Arc<Self>) -> Arc<dyn Clock> {
        let clock: Arc<TriggerClock> = Arc::clone(self);
        clock
    }

    /// Publishes `document` on the next clock reading, once.
    pub fn arm(&self, server: &TestServer, document: &str) {
        *self.app.lock().expect("the trigger's app") = Some(Arc::downgrade(server.running().app()));
        *self.document.lock().expect("the trigger's document") = Some(document.to_owned());
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn fired(&self) -> bool {
        !self.armed.load(std::sync::atomic::Ordering::SeqCst)
            && self
                .document
                .lock()
                .expect("the trigger's document")
                .is_some()
    }
}

impl Clock for TriggerClock {
    fn now_utc_micros(&self) -> i64 {
        let now = self.inner.now_utc_micros();
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            && let (Some(app), Some(document)) = (
                self.app
                    .lock()
                    .expect("the trigger's app")
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade),
                self.document
                    .lock()
                    .expect("the trigger's document")
                    .clone(),
            )
        {
            let snapshot = probation::policy::BlocklistSnapshot::parse_and_validate(
                document.as_bytes(),
                now,
            )
            .expect("the test blocklist is valid");
            app.publish_blocklist(std::sync::Arc::new(snapshot));
        }
        now
    }

    fn now_monotonic(&self) -> Instant {
        self.inner.now_monotonic()
    }
}

/// The URL path an npm tarball sits at on the fake registry origin, which is the key
/// a [`FakeRegistry`] answer for the artifact has to be registered under.
pub fn npm_artifact_upstream_path(name: &str, filename: &str) -> String {
    format!("/{name}/-/{filename}")
}

/// `{name}/-/{filename}` on the fake npm origin, as a `dist.tarball` value.
pub fn npm_tarball_url(name: &str, filename: &str) -> String {
    format!("https://npm.invalid/{name}/-/{filename}")
}

/// The firewall's own artifact path out of a rendered document's `dist.tarball`.
pub fn artifact_path(document: &serde_json::Value, version: &str) -> String {
    let tarball = document["versions"][version]["dist"]["tarball"]
        .as_str()
        .unwrap_or_else(|| panic!("version {version} has a rewritten tarball URL: {document}"));
    let url = Url::parse(tarball).expect("the rewritten tarball URL parses");
    url.path().to_owned()
}

/// Replaces `path` the way SPEC §8 requires a producer to: write a sibling and
/// rename over it, so a reader never sees a half-written file and the replacement
/// always lands on a new inode.
pub fn replace_atomically(path: &Path, contents: &str) {
    let temp = path.with_extension("next");
    std::fs::write(&temp, contents).expect("the replacement is written");
    std::fs::rename(&temp, path).expect("the replacement is renamed into place");
}

/// The same atomic replacement, with the modification time of the file it replaces
/// carried over to the replacement *before* the rename.
///
/// This is TM-5's case: two different contents of exactly the same length, appearing
/// to have been written at exactly the same instant. Setting the time on the sibling
/// rather than after the rename means the file that appears is already
/// indistinguishable by time and length — a reader cannot catch it in between.
pub fn replace_atomically_preserving_mtime(path: &Path, contents: &str) {
    let modified = modified_of(path);
    let temp = path.with_extension("next");
    std::fs::write(&temp, contents).expect("the replacement is written");
    set_modified(&temp, modified);
    std::fs::rename(&temp, path).expect("the replacement is renamed into place");
}

/// Rewrites `path` in place, keeping its inode. This is the out-of-contract producer
/// the 60-second backstop re-read exists for.
pub fn rewrite_in_place(path: &Path, contents: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("the existing file is opened");
    file.write_all(contents.as_bytes())
        .expect("the rewrite is written");
    file.sync_all().expect("the rewrite reaches the filesystem");
}

/// Forces `path`'s modification time, so a test can make two writes look like one
/// instant to anything that compares timestamps.
pub fn set_modified(path: &Path, modified: SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("the file is opened to set its times");
    file.set_modified(modified)
        .expect("the modification time is set");
}

pub fn modified_of(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .expect("the file exists")
        .modified()
        .expect("the filesystem records modification times")
}

/// Where the database lives inside a data directory, for the tests that assert
/// something about the bytes on disk.
pub fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join("firewall.db")
}

pub fn wal_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join("firewall.db-wal")
}

// ---------------------------------------------------------------------------
// The rated-load driver
// ---------------------------------------------------------------------------

/// Three independent measurements of one rated-load run, plus the achieved rate.
#[derive(Debug)]
pub struct RatedLoadResult {
    /// Requests issued and answered.
    pub offered: u64,
    /// Distinct decided `request_id`s plus summary records, read from the destination.
    pub delivered: u64,
    /// The application's monotonic loss total, read after shutdown.
    pub dropped: u64,
    /// Requests in the timed window (`offered` less the one warm-up request per worker) over its seconds.
    pub achieved: f64,
}

/// Offers `GET /health/live` at `target_rate` per second for `duration` against the
/// file sink alone, then reconciles. `target_rate` above what the build can sustain
/// runs unpaced, so `achieved` is then the build's ceiling.
///
/// `log_file_max_bytes` is sized for the whole run unless the caller changed it from
/// the sample's value. A rotation destroys the previous generation, so a rotated run
/// is void and panics rather than reporting a low `delivered`.
pub async fn drive_rated_load(
    mut config: Config,
    target_rate: u32,
    duration: Duration,
) -> RatedLoadResult {
    const WORKERS: u32 = 32;
    assert!(config.siem_url.is_none(), "exactly one sink: the file sink");
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");
    config.log_file_path = Some(path.clone());
    if config.log_file_max_bytes == sample_config().log_file_max_bytes {
        let records = u64::from(target_rate).saturating_mul(duration.as_secs() + 1) + 1;
        let bytes = records.saturating_mul(4096).max(1 << 20);
        config.log_file_max_bytes = std::num::NonZeroU64::new(bytes).unwrap();
    }
    // Longer than any run: the only summary is the one shutdown flushes (C65).
    probation::http::logging::set_summary_window(Duration::from_secs(3600));

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    let app = server.app(); // cloned before shutdown drops the server's handle
    let url = server.url("/health/live");
    let offered = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let interval = Duration::from_secs_f64(f64::from(WORKERS) / f64::from(target_rate));

    // Each worker opens its connection with one request that is counted in `offered`
    // but sits outside the timed window: 32 simultaneous connects take over a second
    // to accept in a debug build, and that is not the request rate being measured.
    let barrier = Arc::new(tokio::sync::Barrier::new(WORKERS as usize + 1));
    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let (client, url, offered) = (downstream_client(), url.clone(), Arc::clone(&offered));
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                let get = || async {
                    let status = client.get(&url).send().await.expect("a response").status();
                    assert!(status.is_success(), "/health/live answered {status}");
                    offered.fetch_add(1, Ordering::Relaxed);
                };
                get().await;
                barrier.wait().await;
                let started = Instant::now();
                let mut next = started;
                while started.elapsed() < duration {
                    get().await;
                    next += interval;
                    tokio::time::sleep_until(next.into()).await;
                }
            })
        })
        .collect();
    barrier.wait().await;
    let started = Instant::now();
    for worker in workers {
        worker.await.expect("a load worker");
    }
    let elapsed = started.elapsed();
    // `Running::shutdown` awaits the store task, which ends only when every `App`
    // handle is gone, so this clone must be dropped before shutdown can return. The
    // tally is therefore read while shutdown runs, once the shutdown summary — the
    // last record offered, queued behind everything else — is in the file: by then
    // the drain has finished and no loss site can fire again.
    let shutdown = tokio::spawn(server.shutdown());
    let drain_limit = Instant::now() + Duration::from_secs(6);
    let mut seen_summary = false;
    while !seen_summary && Instant::now() < drain_limit {
        tokio::time::sleep(Duration::from_millis(20)).await;
        seen_summary = std::fs::read_to_string(&path)
            .is_ok_and(|text| text.contains("\"event\":\"request_summary\""));
    }
    let dropped = app.delivery_lost_total();
    // The summary may itself have been dropped by a small queue, and that is counted;
    // absent and uncounted means the file sink's 5 s drain deadline cut the tail off,
    // and the reconciliation is then not exact.
    assert!(
        seen_summary || dropped > 0,
        "the drain deadline was hit, so the reconciliation is not exact"
    );
    drop(app);
    shutdown.await.expect("the shutdown task");

    let mut rolled = path.clone().into_os_string();
    rolled.push(".1");
    assert!(
        !Path::new(&rolled).exists(),
        "the file sink rotated: the run is void, delivered would be under-counted"
    );
    let text = std::fs::read_to_string(&path).expect("the delivery file is readable");
    let mut ids = std::collections::HashSet::new();
    let mut summaries = 0;
    for line in text.lines() {
        let record: serde_json::Value = serde_json::from_str(line).expect("one JSON object a line");
        match record["event"].as_str() {
            Some("request_decided") => {
                ids.insert(
                    record["request_id"]
                        .as_str()
                        .expect("a request_id")
                        .to_owned(),
                );
            }
            Some("request_summary") => summaries += 1,
            other => panic!("unexpected record kind {other:?}"),
        }
    }
    let offered = offered.load(Ordering::Relaxed);
    RatedLoadResult {
        offered,
        delivered: ids.len() as u64 + summaries,
        dropped,
        achieved: (offered - u64::from(WORKERS)) as f64 / elapsed.as_secs_f64(),
    }
}
