//! Slice 3 of the management server: a managed firewall syncs with the server, enforces
//! the network lock and readiness, keeps its cache fresh, serves stale entries while
//! the server is down, ships activity and applies settings pushes
//! (03-program-design.md § Test plan).
//!
//! The firewall syncs every second here (`sync_interval_seconds = 2`, margin 1). Client
//! addresses outside loopback reach it through a listed proxy (`X-Forwarded-For`), the
//! way they do in production behind one.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use common::sync::{FakeSyncServer, PLATFORM, key, org, personal};
use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins,
    npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
};
use probation::config::{Cidr, Config, SettingsState};
use probation::managed::activity::{
    ACTIVITY_ACCOUNT_CAP, ACTIVITY_BATCH_MAX, ACTIVITY_QUEUE_CAP, ActivityQueue,
};
use probation::upstream::{OriginKind, OriginSet, Transport};
use probation_policy::api::{
    AccountKind, ActivityEvent, ActivityLayer, ActivityResult, ChangesRequest, KeyId, LimitChange,
    LimitSource, Reachability,
};
use probation_policy::{Block, Ecosystem, Layer, LayerKind, OsvSetting, PlaceRef, Switches};
use serde_json::{Map, Value, json};

const NOW: &str = "2026-04-06T12:00:00Z";
const PUBLISHED: &str = "2026-01-01T00:00:00Z";
/// Twelve hours before `NOW`: inside the platform's one-day freeze.
const FRESH: &str = "2026-04-06T00:00:00Z";
const LEFT_PAD: &str = "left-pad";
const OLD: &str = "1.0.0";
const NEW: &str = "2.0.0";

const ACME: u32 = 10;
const GLOBEX: u32 = 20;

fn acme_key() -> String {
    key(1)
}

fn globex_key() -> String {
    key(2)
}

fn platform_layer() -> Layer {
    Layer {
        freeze_seconds: Some(86_400),
        osv: Some(OsvSetting::Off),
        allow: Switches::ALL,
        ..Layer::empty(LayerKind::Platform)
    }
}

fn org_layer(blocks: Vec<Block>) -> Layer {
    Layer {
        blocks,
        allow: Switches::ALL,
        ..Layer::empty(LayerKind::Org)
    }
}

fn left_pad_block() -> Block {
    Block::Package {
        ecosystem: Ecosystem::Npm,
        name: LEFT_PAD.to_owned(),
        reason: None,
    }
}

fn tarball(version: &str) -> String {
    format!("{LEFT_PAD}-{version}.tgz")
}

/// The firewall's own path for a tarball, as a lockfile names it.
fn tarball_route(version: &str) -> String {
    format!("/npm/{LEFT_PAD}/-/{}", tarball(version))
}

fn npm_document() -> String {
    let mut versions = Map::new();
    let mut time = Map::new();
    for (version, published) in [(OLD, PUBLISHED), (NEW, FRESH)] {
        versions.insert(
            version.to_owned(),
            json!({
                "name": LEFT_PAD,
                "version": version,
                "dist": {"tarball": npm_tarball_url(LEFT_PAD, &tarball(version))},
            }),
        );
        time.insert(version.to_owned(), json!(published));
    }
    json!({
        "name": LEFT_PAD,
        "dist-tags": {"latest": OLD},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

fn registry() -> Arc<FakeRegistry> {
    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(LEFT_PAD),
        FakeAnswer::Body(npm_document()),
    );
    for version in [OLD, NEW] {
        registry.answer(
            &npm_artifact_upstream_path(LEFT_PAD, &tarball(version)),
            FakeAnswer::Body(format!("tarball {version}\n")),
        );
    }
    registry
}

/// Syncs every second; a call to the server may take a second.
fn fast(config: &mut Config) {
    config.sync_interval_seconds = NonZeroU64::new(2).unwrap();
    let management = config.management.as_mut().expect("managed");
    management.sync_margin_seconds = NonZeroU64::new(1).unwrap();
    management.request_timeout_seconds = NonZeroU64::new(1).unwrap();
}

/// The decision log a test configured with [`log_to_file`].
fn decision_log(data_dir: &Path) -> String {
    std::fs::read_to_string(data_dir.join("../decisions.ndjson")).expect("the log")
}

/// Decision records to a file beside the data directory.
fn log_to_file(config: &mut Config) {
    config.log_file_path = Some(config.data_dir.join("../decisions.ndjson"));
}

fn cidr(text: &str) -> Cidr {
    Cidr::parse(text).expect("a range")
}

fn loopback(a: u8, b: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, a, b))
}

struct Harness {
    server: TestServer,
    sync: FakeSyncServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    config: Config,
    data_dir: PathBuf,
    _dir: tempfile::TempDir,
}

/// Acme blocks nothing and Globex blocks nothing until a test says so; `acme_key` and
/// `globex_key` are theirs. `adjust` sees the fake server before the firewall starts.
async fn harness(adjust: impl FnOnce(&FakeSyncServer, &mut Config)) -> Harness {
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), org_layer(Vec::new()));
    sync.layer(org(GLOBEX), org_layer(Vec::new()));
    sync.known_key(&acme_key(), &[PLATFORM, org(ACME)]);
    sync.known_key(&globex_key(), &[PLATFORM, org(GLOBEX)]);

    let dir = tempfile::tempdir().expect("a directory");
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    fast(&mut config);
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    config.data_dir = data_dir.clone();
    adjust(&sync, &mut config);
    let clock = TestClock::at_rfc3339(NOW);
    let registry = registry();
    let server = TestServer::start_in_with_registry(
        &data_dir,
        config.clone(),
        clock.shared(),
        Arc::clone(&registry),
    )
    .await;
    Harness {
        server,
        sync,
        registry,
        clock,
        config,
        data_dir,
        _dir: dir,
    }
}

impl Harness {
    async fn get(&self, path: &str, key: &str) -> reqwest::Response {
        self.server
            .get_with_headers(path, &[("authorization", &format!("Bearer {key}"))])
            .await
    }

    /// A request from loopback address `from`, through a listed proxy when `forwarded`
    /// names the client.
    async fn get_from(
        &self,
        from: IpAddr,
        path: &str,
        key: &str,
        forwarded: Option<&str>,
    ) -> reqwest::Response {
        let mut request = reqwest::Client::builder()
            .no_proxy()
            .local_address(from)
            .build()
            .expect("a client")
            .get(self.server.url(path))
            .header("authorization", format!("Bearer {key}"));
        if let Some(forwarded) = forwarded {
            request = request.header("x-forwarded-for", forwarded);
        }
        request.send().await.expect("the request completes")
    }

    fn managed(&self) -> Arc<probation::App> {
        self.server.app()
    }

    /// A request in a task of its own, for one a test holds at the server.
    fn spawn_get(&self, path: &str, key: &str) -> tokio::task::JoinHandle<u16> {
        let request = common::sync::client_with_key(key)
            .get(self.server.url(path))
            .send();
        tokio::spawn(async move { request.await.expect("a response").status().as_u16() })
    }

    /// The same firewall started again on its data directory, the server as it is.
    async fn restart(self) -> Harness {
        self.server.shutdown().await;
        let server = TestServer::start_in_with_registry(
            &self.data_dir,
            self.config.clone(),
            self.clock.shared(),
            Arc::clone(&self.registry),
        )
        .await;
        Harness { server, ..self }
    }
}

async fn status_of(response: reqwest::Response) -> (u16, String) {
    let status = response.status().as_u16();
    (status, response.text().await.expect("a body"))
}

async fn assert_status(response: reqwest::Response, expected: u16, error: &str, what: &str) {
    let (status, body) = status_of(response).await;
    assert_eq!(status, expected, "{what}: {body}");
    let value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    assert_eq!(value["error"], error, "{what}: {body}");
}

/// Every activity event delivered to the server, in order.
fn activity(sync: &FakeSyncServer) -> Vec<ActivityEvent> {
    sync.delivered()
        .into_iter()
        .flat_map(|request| request.activity)
        .collect()
}

async fn wait_for(what: &str, within: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "{what} did not happen within {within:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Waits until the server has been sent an activity event matching `found`.
async fn wait_for_activity(
    sync: &FakeSyncServer,
    found: impl Fn(&ActivityEvent) -> bool,
) -> ActivityEvent {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(event) = activity(sync).into_iter().find(|event| found(event)) {
            return event;
        }
        assert!(
            Instant::now() < deadline,
            "no such activity: {:#?}",
            activity(sync)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// T-auth-not-ready-503 (T1, C109): with no snapshot and the first `changes` answer
/// held, every request answers 503 `NOT_READY`; so does one whose peer address is
/// missing; then 200 once the first sync is applied.
#[tokio::test]
async fn t_auth_not_ready_503() {
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), org_layer(Vec::new()));
    sync.known_key(&acme_key(), &[PLATFORM, org(ACME)]);
    let gate = sync.hold_changes();
    let dir = tempfile::tempdir().expect("a directory");
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    config.data_dir = dir.path().join("data");
    let clock = TestClock::at_rfc3339(NOW);
    let running = common::start_unready(
        config,
        clock.shared(),
        registry(),
        fake_origins(),
        probation::osv::unreachable_client(),
        None,
    )
    .await;
    let server = TestServer::from_running(running);
    gate.wait_until_reached().await;

    let bearer = format!("Bearer {}", acme_key());
    let response = server
        .get_with_headers("/npm/left-pad", &[("authorization", &bearer)])
        .await;
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().unwrap().to_owned()),
        Some("1".to_owned())
    );
    assert_status(response, 503, "NOT_READY", "before the first sync").await;
    assert_eq!(server.status("/health/ready").await, 503);
    assert_eq!(
        sync.lookups(),
        0,
        "nothing is looked up before the first sync"
    );

    sync.release_holds();
    server
        .wait_for_status("/health/ready", 200, Duration::from_secs(5))
        .await;
    let response = server
        .get_with_headers("/npm/left-pad", &[("authorization", &bearer)])
        .await;
    assert_eq!(
        response.status(),
        200,
        "served once the first sync is applied"
    );

    // The router served without connect-info, as a fault would leave it: no peer
    // address, so no request is judged.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener");
    let addr = listener.local_addr().expect("its address");
    let without_peer =
        tokio::spawn(axum::serve(listener, probation::http::router(server.app())).into_future());
    let response = common::downstream_client()
        .get(format!("http://{addr}/npm/left-pad"))
        .header("authorization", &bearer)
        .send()
        .await
        .expect("the request completes");
    assert_status(response, 503, "NOT_READY", "no peer address").await;
    // It holds the app, which must go before the store can close.
    without_peer.abort();
    let _ = without_peer.await;
    server.shutdown().await;
}

/// T-sync-late-answer-dropped (H6): a lookup and a `layers` call held across a delta
/// that revokes the key and edits the layer are dropped when they arrive, and so are
/// a lookup and a `layers` answer held across a reset.
#[tokio::test]
async fn t_sync_late_answer_dropped() {
    let h = harness(|sync, config| {
        sync.layer(org(30), org_layer(Vec::new()));
        sync.known_key(&key(31), &[PLATFORM, org(30)]);
        sync.known_key(&key(32), &[PLATFORM, org(ACME)]);
        sync.known_key(&key(41), &[PLATFORM, org(40)]);
        sync.layer(org(40), org_layer(Vec::new()));
        sync.known_key(&key(42), &[PLATFORM, org(ACME)]);
        for n in 60..63 {
            sync.layer(org(n), org_layer(Vec::new()));
            sync.known_key(&key(n + 1), &[PLATFORM, org(n)]);
        }
        sync.layer(org(90), org_layer(Vec::new()));
        sync.known_key(&key(91), &[PLATFORM, org(90)]);
        let management = config.management.as_mut().unwrap();
        management.request_timeout_seconds = NonZeroU64::new(5).unwrap();
        management.sync_margin_seconds = NonZeroU64::new(5).unwrap();
        config.sync_interval_seconds = NonZeroU64::new(6).unwrap();
    })
    .await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);

    // A lookup for key 32 held while it is revoked.
    let lookups = h.sync.hold_lookups();
    let held = h.spawn_get("/npm/left-pad", &key(32));
    lookups.wait_until_reached().await;
    let revoked = h.sync.revoke(&key(32));
    h.sync.applied(revoked).await;
    lookups.release();
    lookups.release();
    assert_eq!(held.await.unwrap(), 401, "the late Known answer is dropped");

    // A `layers` call for org 30, held while its layer is edited to block left-pad.
    h.sync.release_holds();
    let layers = h.sync.hold_layers();
    let held = h.spawn_get("/npm/left-pad", &key(31));
    layers.wait_until_reached().await;
    let edited = h
        .sync
        .edit_layer(org(30), org_layer(vec![left_pad_block()]));
    h.sync.applied(edited).await;
    h.sync.release_holds();
    assert_eq!(held.await.unwrap(), 403, "decided under the edited layer");

    // The same across a reset whose skipped rows revoked key 42 and edited org 40: a
    // `layers` call for org 40 and a lookup for key 42, both held.
    let layers = h.sync.hold_layers();
    let held_layers = h.spawn_get("/npm/left-pad", &key(41));
    layers.wait_until_reached().await;
    let lookups = h.sync.hold_lookups();
    let held_lookup = h.spawn_get("/npm/left-pad", &key(42));
    lookups.wait_until_reached().await;
    let gate = h.sync.hold_changes();
    gate.wait_until_reached().await;
    h.sync.revoke(&key(42));
    h.sync
        .edit_layer(org(40), org_layer(vec![left_pad_block()]));
    h.sync.prune();
    let floor = h.sync.revision();
    gate.release();
    h.sync.applied(floor).await;
    h.sync.release_holds();
    assert_eq!(
        held_lookup.await.unwrap(),
        401,
        "a lookup older than the reset floor"
    );
    assert_eq!(
        held_layers.await.unwrap(),
        503,
        "a lookup older than the reset floor is not cached when its layers arrive"
    );
    h.clock.advance_seconds(1);
    assert_eq!(
        h.get("/npm/left-pad", &key(41)).await.status(),
        403,
        "the new layer"
    );

    // B1: a lookup is answered, then its `layers` call is held while a `key` row, a
    // `place` row and a reset are applied. None of the three is cached.
    let cases: [(u32, &str); 3] = [(61, "a key row"), (62, "a place row"), (63, "a reset")];
    for (n, what) in cases {
        h.clock.advance_seconds(1);
        let layers = h.sync.hold_layers();
        let held = h.spawn_get("/npm/left-pad", &key(n));
        layers.wait_until_reached().await;
        let applied = match n {
            61 => h.sync.revoke(&key(n)),
            62 => h.sync.suspend(org(n - 1)),
            _ => {
                let gate = h.sync.hold_changes();
                gate.wait_until_reached().await;
                h.sync.revoke(&key(n));
                h.sync.prune();
                let floor = h.sync.revision();
                gate.release();
                floor
            }
        };
        h.sync.applied(applied).await;
        h.sync.release_holds();
        assert_ne!(held.await.unwrap(), 200, "{what}: not served");
        h.clock.advance_seconds(1);
        let lookups = h.sync.lookups();
        let response = h.get("/npm/left-pad", &key(n)).await;
        assert_status(response, 401, "AUTHENTICATION_REQUIRED", what).await;
        assert_eq!(h.sync.lookups() - lookups, 1, "{what}: it was not cached");
    }

    // X2: a TTL-expired entry is looked up again; its layers are fetched; a `place` row
    // (a suspension) lands meanwhile. The late answer is busy, and the entry, now
    // place-expired, is never served stale for it.
    h.clock.advance_seconds(1);
    assert_eq!(h.get("/npm/left-pad", &key(91)).await.status(), 200);
    h.clock.advance_seconds(200);
    assert_eq!(h.get("/npm/left-pad", &key(91)).await.status(), 200);
    h.clock.advance_seconds(101);
    let changes = h.sync.hold_changes();
    changes.wait_until_reached().await;
    h.sync.edit_layer(org(90), org_layer(Vec::new()));
    let layers = h.sync.hold_layers();
    let held = h.spawn_get("/npm/left-pad", &key(91));
    layers.wait_until_reached().await;
    let suspended = h.sync.suspend(org(90));
    for _ in 0..8 {
        changes.release();
    }
    h.sync.applied(suspended).await;
    h.sync.release_holds();
    assert_eq!(held.await.unwrap(), 503, "busy, never the stale entry");
    h.server.shutdown().await;
}

/// T-upstream-configured (C35, TEST-01 as amended): an `npm_upstream_url` is where npm
/// metadata is fetched from; a bad one is refused at startup; nothing else relaxes the
/// origins.
#[tokio::test]
async fn t_upstream_configured() {
    let sample = std::fs::read_to_string("config.sample.toml").expect("the shipped sample");
    let with = |line: &str| Config::from_toml_str(&format!("{sample}\n{line}\n"));

    let config = with("npm_upstream_url = \"https://registry.example\"").expect("an https origin");
    let origins = OriginSet::configured(&config);
    assert_eq!(
        origins.origin(OriginKind::NpmMetadata).as_str(),
        "https://registry.example/"
    );
    assert_eq!(
        origins.origin(OriginKind::PypiMetadata).as_str(),
        "https://pypi.org/",
        "an origin not configured stays SPEC §11's"
    );
    assert!(!origins.allows_private_addresses());

    // Fetched from the configured origin, through the injected test transport.
    let dir = tempfile::tempdir().expect("a directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.npm_upstream_url = Some("https://registry.example".parse().unwrap());
    let origins = OriginSet::configured(&config);
    let registry = FakeRegistry::new();
    registry.answer(&format!("/{LEFT_PAD}"), FakeAnswer::Body(npm_document()));
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        origins,
    )
    .await;
    assert_eq!(server.status("/npm/left-pad").await, 200);
    assert!(
        registry
            .calls()
            .iter()
            .any(|url| url.as_str() == "https://registry.example/left-pad"),
        "{:?}",
        registry.calls()
    );
    server.shutdown().await;

    for (line, what) in [
        ("npm_upstream_url = \"http://registry.example\"", "http"),
        (
            "pypi_upstream_url = \"https://user:pw@registry.example\"",
            "credentials",
        ),
        (
            "pypi_artifacts_url = \"https://10.0.0.1\"",
            "a private address",
        ),
        ("npm_upstream_url = \"https://[::1]\"", "loopback"),
        (
            "npm_upstream_url = \"https://registry.example/prefix\"",
            "a path prefix",
        ),
        (
            "npm_upstream_url = \"https://registry.example/?q=1\"",
            "a query",
        ),
        (
            "npm_registry_url = \"https://registry.example\"",
            "another key",
        ),
    ] {
        let refused = with(line).expect_err(what);
        assert!(
            refused
                .to_string()
                .contains(line.split(' ').next().unwrap()),
            "{what}: {refused}"
        );
    }
}

/// T-auth-network-403 (C30, C77, C92, T1): inside Acme's approved range a Globex key and
/// a personal key are refused with 403 showing only the client address; Acme's key works
/// from inside and outside, also as an IPv4-mapped address; no record names the client.
#[tokio::test]
async fn t_auth_network_403() {
    let h = harness(|sync, config| {
        sync.set_ranges(&[
            ("192.0.2.0/24", ACME),
            ("127.0.3.0/24", ACME),
            // An IPv4 range written in its IPv4-mapped IPv6 form (M1).
            ("::ffff:198.51.100.0/120", ACME),
        ]);
        sync.layer(personal(5), Layer::empty(LayerKind::Personal));
        sync.known_key(&key(3), &[PLATFORM, personal(5)]);
        // The only way an address outside loopback reaches a test: a listed proxy, here
        // also written in the mapped form.
        config.management.as_mut().unwrap().trusted_proxies = vec![cidr("::ffff:127.0.9.0/120")];
        log_to_file(config);
        assert!(!config.log_consumer_identification);
    })
    .await;
    let proxy = loopback(9, 1);

    for (key, what) in [(globex_key(), "Globex"), (key(3), "personal")] {
        let response = h
            .get_from(proxy, "/npm/left-pad", &key, Some("192.0.2.7"))
            .await;
        let (status, body) = status_of(response).await;
        assert_eq!(status, 403, "{what}: {body}");
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["error"], "NETWORK_NOT_ALLOWED");
        assert!(
            value["reason"].as_str().unwrap().contains("192.0.2.7"),
            "{body}"
        );
        for name in ["Acme", "acme", "Globex", "globex", "10"] {
            assert!(!value["reason"].as_str().unwrap().contains(name), "{body}");
        }
    }
    // The peer itself inside a range, with no proxy.
    let response = h
        .get_from(loopback(3, 9), "/npm/left-pad", &globex_key(), None)
        .await;
    assert_status(
        response,
        403,
        "NETWORK_NOT_ALLOWED",
        "a peer inside the range",
    )
    .await;

    // Every address of the mapped-form range, not only its first.
    let response = h
        .get_from(proxy, "/npm/left-pad", &globex_key(), Some("198.51.100.77"))
        .await;
    assert_status(
        response,
        403,
        "NETWORK_NOT_ALLOWED",
        "inside a range written in mapped form",
    )
    .await;

    for forwarded in ["203.0.113.1", "::ffff:192.0.2.7", "192.0.2.7"] {
        let response = h
            .get_from(proxy, "/npm/left-pad", &acme_key(), Some(forwarded))
            .await;
        assert_eq!(response.status(), 200, "Acme from {forwarded}");
    }
    let response = h
        .get_from(
            proxy,
            "/npm/left-pad",
            &globex_key(),
            Some("::ffff:192.0.2.7"),
        )
        .await;
    let (status, body) = status_of(response).await;
    assert_eq!(status, 403, "a mapped address is its IPv4 address: {body}");
    assert!(
        body.contains("192.0.2.7") && !body.contains("::ffff"),
        "{body}"
    );

    h.server.shutdown().await;
    let log = decision_log(&h.data_dir);
    assert!(log.contains("NETWORK_NOT_ALLOWED"), "{log}");
    assert!(
        !log.contains("consumer"),
        "no record names the client: {log}"
    );
    assert!(
        !log.contains("192.0.2.7"),
        "the refused address is not logged: {log}"
    );
}

/// T-auth-trusted-proxy (C113, C120, T23, S2-2): only a listed proxy's
/// `X-Forwarded-For` is read, every line of it, and its rightmost untrusted entry is
/// the client; the decision record keeps the peer; the lookup allowance is per derived
/// client, an IPv6 one by its /64 and a mapped one as IPv4.
#[tokio::test]
async fn t_auth_trusted_proxy() {
    let h = harness(|sync, config| {
        sync.set_ranges(&[("192.0.2.0/24", ACME)]);
        config.management.as_mut().unwrap().trusted_proxies =
            vec![cidr("127.0.0.1/32"), cidr("127.0.10.0/24")];
        log_to_file(config);
        config.log_consumer_identification = true;
    })
    .await;
    let proxy = loopback(10, 5);
    let untrusted = loopback(20, 1);

    let response = h
        .get_from(proxy, "/npm/left-pad", &globex_key(), Some("192.0.2.7"))
        .await;
    let (status, body) = status_of(response).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("192.0.2.7"), "{body}");

    let response = h
        .get_from(untrusted, "/npm/left-pad", &globex_key(), Some("192.0.2.7"))
        .await;
    assert_eq!(
        response.status(),
        200,
        "an unlisted peer's header is ignored"
    );

    let response = h
        .get_from(
            proxy,
            "/npm/left-pad",
            &globex_key(),
            Some("198.51.100.9, 192.0.2.7"),
        )
        .await;
    let (status, body) = status_of(response).await;
    assert_eq!(status, 403, "the rightmost untrusted entry wins: {body}");
    assert!(
        body.contains("192.0.2.7") && !body.contains("198.51.100.9"),
        "{body}"
    );

    // Two header lines through a listed proxy (the raw socket leaves from 127.0.0.1).
    let raw = h
        .server
        .raw_get(
            "/npm/left-pad",
            &[
                ("authorization", &format!("Bearer {}", globex_key())),
                ("x-forwarded-for", "198.51.100.9"),
                ("x-forwarded-for", "192.0.2.7"),
            ],
        )
        .await;
    assert_eq!(common::raw_status(&raw), 403, "{raw}");
    assert!(raw.contains("192.0.2.7"), "{raw}");
    let raw = h
        .server
        .raw_get(
            "/npm/left-pad",
            &[
                ("authorization", &format!("Bearer {}", acme_key())),
                ("x-forwarded-for", "192.0.2.7, not-an-address"),
            ],
        )
        .await;
    assert_ne!(
        common::raw_status(&raw),
        200,
        "an unparsable entry is refused: {raw}"
    );

    // A flood of unknown keys from one forwarded client, and a new Acme key from
    // another behind the same proxy.
    h.clock.advance_seconds(1);
    let before = h.sync.lookups();
    let mut busy = 0;
    for n in 0..20 {
        let response = h
            .get_from(proxy, "/npm/left-pad", &key(1_000 + n), Some("192.0.2.7"))
            .await;
        match response.status().as_u16() {
            401 => {}
            503 => busy += 1,
            other => panic!("the flood answered {other}"),
        }
    }
    assert!(
        h.sync.lookups() - before <= 5,
        "{} lookups",
        h.sync.lookups() - before
    );
    assert!(busy >= 15);
    h.sync.known_key(&key(2_000), &[PLATFORM, org(ACME)]);
    let response = h
        .get_from(proxy, "/npm/left-pad", &key(2_000), Some("192.0.2.8"))
        .await;
    assert_eq!(
        response.status(),
        200,
        "the other client's new key, first request"
    );

    // S2-2: one IPv6 /64 is one client, and so is an address with its mapped form.
    for clients in [
        ["2001:db8::1", "2001:db8::2:1", "2001:db8::ffff:3"],
        ["192.0.2.9", "::ffff:192.0.2.9", "192.0.2.9"],
    ] {
        h.clock.advance_seconds(1);
        let before = h.sync.lookups();
        for n in 0..12u32 {
            let client = clients[n as usize % 3];
            let unknown = key(3_000 + n + 100 * u32::from(client.contains("db8")));
            let _ = h
                .get_from(proxy, "/npm/left-pad", &unknown, Some(client))
                .await;
        }
        assert!(
            h.sync.lookups() - before <= 5,
            "{clients:?}: {} lookups",
            h.sync.lookups() - before
        );
    }

    h.server.shutdown().await;
    let log = decision_log(&h.data_dir);
    let refused: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["result"] == "REFUSED" || record["status"] == 403)
        .collect();
    assert!(!refused.is_empty(), "{log}");
    for record in &refused {
        assert_ne!(
            record["consumer"], "192.0.2.7",
            "never the forwarded address: {record}"
        );
    }
    assert!(
        log.lines()
            .any(|line| line.contains("\"consumer\":\"127.0.10.5\"")),
        "the record keeps the peer: {log}"
    );
}

/// T-managed-ignores-blocklist (C80, C109): with no blocklist file, and with an expired
/// one, a managed firewall is ready after its first sync and serves; its records name
/// no blocklist revision.
#[tokio::test]
async fn t_managed_ignores_blocklist() {
    let sample = std::fs::read_to_string("config.sample.toml").expect("the shipped sample");
    let dir = tempfile::tempdir().expect("a directory");
    let token = dir.path().join("firewall.token");
    std::fs::write(&token, "fwt_test-firewall-token").unwrap();
    let without: String = sample
        .lines()
        .filter(|line| {
            !line.starts_with("blocklist_file") && !line.starts_with("blocklist_poll_seconds")
        })
        .map(|line| format!("{line}\n"))
        .collect();
    let managed = format!(
        "{without}\n[management]\nurl = \"https://probation.example\"\ntoken_file = \"{}\"\n",
        token.display()
    );
    let config = Config::from_toml_str(&managed).expect("a managed file needs no blocklist");
    assert_eq!(config.blocklist_file, PathBuf::new());
    assert!(
        Config::from_toml_str(&without).is_err(),
        "standalone still needs one"
    );

    let expired = dir.path().join("expired.json");
    std::fs::write(
        &expired,
        common::snapshot(7, "2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z", ""),
    )
    .unwrap();
    for (blocklist, what) in [(PathBuf::new(), "no file"), (expired, "an expired file")] {
        let h = harness(|_, config| {
            config.blocklist_file = blocklist.clone();
            log_to_file(config);
        })
        .await;
        assert_eq!(h.server.status("/health/ready").await, 200, "{what}");
        assert_eq!(
            h.get("/npm/left-pad", &acme_key()).await.status(),
            200,
            "{what}"
        );
        h.server.shutdown().await;
        let log = decision_log(&h.data_dir);
        assert!(log.contains("\"blocklist_revision\":0"), "{what}: {log}");
        assert!(!log.contains("\"blocklist_revision\":7"), "{what}: {log}");
    }
}

/// T-auth-revoked-401-after-sync (C13, C20): a key revoked at t answers 401 by t plus
/// one interval (2 s here).
#[tokio::test]
async fn t_auth_revoked_401_after_sync() {
    let h = harness(|_, _| {}).await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    let revoked_at = Instant::now();
    h.sync.revoke(&acme_key());
    loop {
        let status = h.get("/npm/left-pad", &acme_key()).await.status();
        if status == 401 {
            break;
        }
        assert_eq!(status, 200);
        assert!(
            revoked_at.elapsed() < Duration::from_secs(2),
            "still served after one interval"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(revoked_at.elapsed() <= Duration::from_secs(2));
    h.server.shutdown().await;
}

/// T-auth-stale-served (C19, C96): an expired entry is served under its last policy
/// while the server is down, and after it returns the next request asks once; a lookup
/// that never answers is served stale within the request timeout, and later ones with
/// no wait; a 429 serves an expired entry stale; a place-expired entry is never served
/// stale while the server is busy.
#[tokio::test]
async fn t_auth_stale_served() {
    let h = harness(|sync, config| {
        config.management.as_mut().unwrap().key_cache_ttl_seconds = NonZeroU64::new(1).unwrap();
        sync.known_key(&key(5), &[PLATFORM, org(ACME)]);
        sync.known_key(&key(6), &[PLATFORM, org(GLOBEX)]);
    })
    .await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);

    h.sync.go_down(true);
    h.clock.advance_seconds(2);
    assert_eq!(
        h.get("/npm/left-pad", &acme_key()).await.status(),
        200,
        "served stale"
    );

    h.sync.go_down(false);
    let revoked = h.sync.revoke(&acme_key());
    h.sync.applied(revoked).await;
    let before = h.sync.lookups();
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 401);
    assert_eq!(
        h.sync.lookups() - before,
        1,
        "one lookup after the server returns"
    );

    // A lookup the server accepts and never answers.
    assert_eq!(h.get("/npm/left-pad", &key(5)).await.status(), 200);
    let _never = (h.sync.hold_lookups(), h.sync.hold_changes());
    h.clock.advance_seconds(2);
    let started = Instant::now();
    assert_eq!(h.get("/npm/left-pad", &key(5)).await.status(), 200);
    assert!(
        started.elapsed() < Duration::from_millis(1_200),
        "{:?}",
        started.elapsed()
    );
    let started = Instant::now();
    assert_eq!(h.get("/npm/left-pad", &key(5)).await.status(), 200);
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "no wait while marked down"
    );

    // The server answers syncs again, and 429 to a lookup: the expired entry is served.
    h.sync.release_holds();
    h.sync.sync_rounds(1).await;
    h.sync
        .answer_lookups_with(Some(StatusCode::TOO_MANY_REQUESTS));
    h.clock.advance_seconds(2);
    let before = h.sync.lookups();
    assert_eq!(
        h.get("/npm/left-pad", &key(5)).await.status(),
        200,
        "a 429 serves stale"
    );
    assert_eq!(h.sync.lookups() - before, 1);

    // A place row expires key 6's entry while lookups are refused as busy.
    assert_eq!(
        h.get("/npm/left-pad", &key(6)).await.status(),
        503,
        "busy, with no entry"
    );
    h.sync.answer_lookups_with(None);
    assert_eq!(h.get("/npm/left-pad", &key(6)).await.status(), 200);
    h.sync
        .answer_lookups_with(Some(StatusCode::TOO_MANY_REQUESTS));
    let expired = h.sync.touch_place(org(GLOBEX));
    h.sync.applied(expired).await;
    let response = h.get("/npm/left-pad", &key(6)).await;
    assert_status(response, 503, "LOOKUP_BUSY", "a place-expired entry").await;
    h.server.shutdown().await;
}

/// T-auth-miss-server-down-401 (C19): a key never seen, while the server is down.
#[tokio::test]
async fn t_auth_miss_server_down_401() {
    let h = harness(|sync, _| {
        sync.known_key(&key(7), &[PLATFORM, org(ACME)]);
    })
    .await;
    h.sync.go_down(true);
    let response = h.get("/npm/left-pad", &key(7)).await;
    assert_status(response, 401, "AUTHENTICATION_REQUIRED", "a new key").await;
    h.server.shutdown().await;
}

/// T-sync-reset: a layer edit and a range approval the firewall's cursor fell behind
/// arrive as a reset; afterwards both apply, and the caches refill lazily.
#[tokio::test]
async fn t_sync_reset() {
    let h = harness(|_, _| {}).await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    assert_eq!(h.get("/npm/left-pad", &globex_key()).await.status(), 200);

    let gate = h.sync.hold_changes();
    gate.wait_until_reached().await;
    h.sync
        .edit_layer(org(ACME), org_layer(vec![left_pad_block()]));
    h.sync.set_ranges(&[("127.0.0.0/8", ACME)]);
    h.sync.prune();
    let reset = h.sync.revision();
    h.sync.release_holds();
    h.sync.applied(reset).await;
    let reset_answered = h.sync.changes_requests().len();

    let (lookups, layers) = (h.sync.lookups(), h.sync.layer_calls());
    let response = h.get("/npm/left-pad", &acme_key()).await;
    assert_status(response, 403, "BLOCKED", "the edited layer").await;
    assert_eq!(h.sync.lookups() - lookups, 1, "the key cache was emptied");
    assert!(h.sync.layer_calls() > layers, "the layer cache was emptied");
    let response = h.get("/npm/left-pad", &globex_key()).await;
    assert_status(response, 403, "NETWORK_NOT_ALLOWED", "the new range").await;
    assert!(reset_answered >= 1);
    h.server.shutdown().await;
}

/// T-sync-unreachable-keeps-cache (C19, C96, W3): a server that is down, or refuses this
/// firewall's address, or answers 429, leaves the cache and the queued activity alone.
#[tokio::test]
async fn t_sync_unreachable_keeps_cache() {
    let h = harness(|sync, _| {
        sync.revoked_key(&key(9), &[PLATFORM, org(ACME)]);
    })
    .await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    let revoked = || {
        activity(&h.sync)
            .into_iter()
            .filter(|event| event.result == ActivityResult::RefusedRevoked)
            .count()
    };
    // Known as revoked, so a refusal while the server is down is still a row.
    assert_eq!(h.get("/npm/left-pad", &key(9)).await.status(), 401);
    wait_for("the first row", Duration::from_secs(5), || revoked() == 1).await;

    for (round, (outage, what)) in [
        (None, "down"),
        (
            Some((StatusCode::FORBIDDEN, Some("FIREWALL_SOURCE_REFUSED"))),
            "source refused",
        ),
        (Some((StatusCode::TOO_MANY_REQUESTS, None)), "429"),
    ]
    .into_iter()
    .enumerate()
    {
        match outage {
            None => h.sync.go_down(true),
            Some(answer) => h.sync.answer_changes_with(Some(answer)),
        }
        h.sync.sync_rounds(1).await;
        // M3: the row keeps the time it was made at, however long the outage.
        h.clock.advance_seconds(10);
        let made_at = jiff::Timestamp::from_microsecond(probation::clock::Clock::now_utc_micros(
            h.clock.as_ref(),
        ))
        .map(|at| format!("{at:.6}"))
        .unwrap();
        assert_eq!(h.get("/npm/left-pad", &key(9)).await.status(), 401);
        h.clock.advance_seconds(20);
        h.sync.sync_rounds(2).await;
        let lookups = h.sync.lookups();
        assert_eq!(
            h.get("/npm/left-pad", &acme_key()).await.status(),
            200,
            "{what}"
        );
        assert_eq!(h.sync.lookups(), lookups, "{what}: served from the cache");
        assert_eq!(revoked(), round + 1, "{what}: the row waits in the queue");
        h.sync.go_down(false);
        h.sync.answer_changes_with(None);
        wait_for(
            &format!("{what}: the re-queued row"),
            Duration::from_secs(5),
            || revoked() == round + 2,
        )
        .await;
        let delivered = activity(&h.sync);
        let row = delivered
            .iter()
            .rev()
            .find(|event| event.result == ActivityResult::RefusedRevoked)
            .unwrap();
        assert_eq!(row.at.as_deref(), Some(made_at.as_str()), "{what}");
    }
    let ids: Vec<String> = activity(&h.sync)
        .into_iter()
        .map(|event| event.event_id)
        .collect();
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(
        (ids.len(), unique.len()),
        (4, 4),
        "each row is delivered once: {ids:?}"
    );
    h.server.shutdown().await;
}

/// T-sync-rejected-batch-dropped (F13): a refused batch is dropped and counted, the next
/// call is empty, and a refused empty call is treated as unreachable and reported; a 429
/// is re-queued; no call carries more than `ACTIVITY_BATCH_MAX` events.
#[tokio::test]
async fn t_sync_rejected_batch_dropped() {
    let h = harness(|sync, _| {
        sync.revoked_key(&key(9), &[PLATFORM, org(ACME)]);
    })
    .await;
    // Three rows queued while a call is held; it is answered, and the next call, which
    // carries them, is refused.
    let gate = h.sync.hold_changes();
    gate.wait_until_reached().await;
    for _ in 0..3 {
        assert_eq!(h.get("/npm/left-pad", &key(9)).await.status(), 401);
    }
    let answered = h.sync.delivered().len();
    h.sync.release_holds();
    wait_for("the held call's answer", Duration::from_secs(5), || {
        h.sync.delivered().len() > answered
    })
    .await;
    h.sync
        .answer_changes_with(Some((StatusCode::PAYLOAD_TOO_LARGE, None)));
    wait_for("the batch of three", Duration::from_secs(5), || {
        h.sync
            .changes_requests()
            .iter()
            .any(|request| request.activity.len() == 3)
    })
    .await;
    h.sync.sync_rounds(1).await;
    let requests = h.sync.changes_requests();
    let refused_batch = requests
        .iter()
        .position(|request| request.activity.len() == 3)
        .expect("the batch was sent");
    let empty = &requests[refused_batch + 1];
    assert!(empty.activity.is_empty() && empty.activity_dropped.is_empty());
    assert_eq!(
        h.server.status("/health/ready").await,
        503,
        "reported on readiness"
    );

    h.sync.answer_changes_with(None);
    h.sync.sync_rounds(3).await;
    let requests = h.sync.changes_requests();
    assert!(
        requests[refused_batch + 2..].iter().any(|request| request
            .report
            .last_apply_error
            .as_deref()
            .is_some_and(|error| error.contains("refused"))),
        "the next report carries it"
    );
    let dropped: u64 = requests
        .iter()
        .flat_map(|request| &request.activity_dropped)
        .filter(|count| count.account == org(ACME))
        .map(|count| count.count)
        .sum();
    assert_eq!(dropped, 3, "the refused batch is counted, not re-sent");
    assert!(activity(&h.sync).is_empty(), "none of them was delivered");
    let sent: usize = requests.iter().map(|request| request.activity.len()).sum();
    assert_eq!(sent, 3, "the events went out once");
    assert_eq!(h.server.status("/health/ready").await, 200);

    // A 429 is re-queued like a 5xx, never dropped.
    h.sync
        .answer_changes_with(Some((StatusCode::TOO_MANY_REQUESTS, None)));
    h.sync.sync_rounds(1).await;
    assert_eq!(h.get("/npm/left-pad", &key(9)).await.status(), 401);
    h.sync.sync_rounds(1).await;
    h.sync.answer_changes_with(None);
    wait_for("the 429's row", Duration::from_secs(5), || {
        activity(&h.sync).len() == 1
    })
    .await;

    // Many events: every call carries at most the batch cap.
    let app = h.managed();
    let queue = app.managed().unwrap().activity();
    for n in 0..(ACTIVITY_BATCH_MAX + 500) {
        queue.record_activity(
            org(ACME + (n % 7) as u32),
            event(KeyId(n as u64), ActivityResult::Blocked),
        );
    }
    wait_for("all of them", Duration::from_secs(10), || {
        activity(&h.sync).len() == 1 + ACTIVITY_BATCH_MAX + 500
    })
    .await;
    for request in h.sync.changes_requests() {
        assert!(request.activity.len() <= ACTIVITY_BATCH_MAX);
        assert!(request.activity_dropped.len() <= ACTIVITY_BATCH_MAX);
    }
    // The app must go before the store can close.
    drop(app);
    h.server.shutdown().await;
}

/// T-sync-idle-prune-after-answer (C96, W3): an entry unused for a TTL is kept through
/// an outage and pruned after the first sync the server answers.
#[tokio::test]
async fn t_sync_idle_prune_after_answer() {
    let h = harness(|_, config| {
        config.management.as_mut().unwrap().key_cache_ttl_seconds = NonZeroU64::new(1).unwrap();
    })
    .await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    h.sync.go_down(true);
    h.clock.advance_seconds(3);
    h.sync.sync_rounds(3).await;
    assert_eq!(
        h.get("/npm/left-pad", &acme_key()).await.status(),
        200,
        "kept through the outage, served stale"
    );
    h.clock.advance_seconds(3);
    h.sync.go_down(false);
    h.sync.sync_rounds(2).await;
    h.sync.go_down(true);
    assert_eq!(
        h.get("/npm/left-pad", &acme_key()).await.status(),
        401,
        "pruned after the answered sync, so nothing is left to serve"
    );
    h.server.shutdown().await;
}

/// T-sync-retired-stops (C72): a `retired` answer, a 401 to `changes`, and a 401 to a
/// lookup or a `layers` call each stop all serving, stale entries included.
#[tokio::test]
async fn t_sync_retired_stops() {
    for how in ["retired", "changes 401", "lookup 401", "layers 401"] {
        let h = harness(|sync, _| {
            sync.layer(org(30), org_layer(Vec::new()));
            sync.known_key(&key(31), &[PLATFORM, org(30)]);
            sync.known_key(&key(32), &[PLATFORM, org(ACME)]);
        })
        .await;
        assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
        match how {
            "retired" => h.sync.retire(),
            "changes 401" => h
                .sync
                .answer_changes_with(Some((StatusCode::UNAUTHORIZED, None))),
            "lookup 401" => {
                h.sync.answer_lookups_with(Some(StatusCode::UNAUTHORIZED));
                assert_eq!(
                    h.get("/npm/left-pad", &key(32)).await.status(),
                    401,
                    "{how}"
                );
            }
            _ => {
                h.sync.answer_layers_with(Some(StatusCode::UNAUTHORIZED));
                assert_eq!(
                    h.get("/npm/left-pad", &key(31)).await.status(),
                    401,
                    "{how}"
                );
            }
        }
        if how.starts_with("retired") || how.starts_with("changes") {
            h.sync.sync_rounds(2).await;
        }
        h.sync.answer_lookups_with(None);
        h.sync.answer_layers_with(None);
        for key in [acme_key(), key(31), key(32)] {
            let response = h.get("/npm/left-pad", &key).await;
            assert_status(response, 401, "AUTHENTICATION_REQUIRED", how).await;
        }
        if how == "retired" {
            // P: retirement empties the cache, so its snapshot holds no key either, before
            // any entry could have aged out.
            h.sync.sync_rounds(1).await;
            let snapshot = std::fs::read_to_string(h.data_dir.join("managed-cache.json")).unwrap();
            let snapshot: Value = serde_json::from_str(&snapshot).unwrap();
            assert_eq!(snapshot["keys"], json!([]), "{how}: {snapshot}");
        }
        h.clock.advance_seconds(400);
        let response = h.get("/npm/left-pad", &acme_key()).await;
        assert_eq!(response.status(), 401, "{how}: not served stale");
        assert_eq!(h.server.status("/health/ready").await, 503, "{how}");
        h.server.shutdown().await;
    }
}

/// T-sync-ancestor-invalidation (C111, T7): an edit of a layer above a cached key's
/// place reaches it within an interval with one `layers` call and no lookup; a platform
/// edit costs one fetch however many keys share it, and so do 100 requests right after.
#[tokio::test]
async fn t_sync_ancestor_invalidation() {
    let group = PlaceRef {
        kind: LayerKind::Group,
        id: 11,
    };
    let user = PlaceRef {
        kind: LayerKind::User,
        id: 12,
    };
    let h = harness(|sync, _| {
        sync.layer(
            group,
            Layer {
                allow: Switches::ALL,
                ..Layer::empty(LayerKind::Group)
            },
        );
        sync.layer(user, Layer::empty(LayerKind::User));
        sync.known_key(&key(5), &[PLATFORM, org(ACME), group, user]);
        sync.known_key(&key(6), &[PLATFORM, org(GLOBEX)]);
    })
    .await;
    for key in [key(5), acme_key(), globex_key(), key(6)] {
        assert_eq!(h.get("/npm/left-pad", &key).await.status(), 200);
    }

    let (lookups, layers) = (h.sync.lookups(), h.sync.layer_calls());
    let edited = h
        .sync
        .edit_layer(org(ACME), org_layer(vec![left_pad_block()]));
    h.sync.applied(edited).await;
    let response = h.get("/npm/left-pad", &key(5)).await;
    assert_status(response, 403, "BLOCKED", "a user under the edited org").await;
    assert_eq!(h.sync.layer_calls() - layers, 1);
    assert_eq!(h.sync.lookups(), lookups, "no lookup");

    let layers = h.sync.layer_calls();
    let edited = h.sync.edit_layer(
        PLATFORM,
        Layer {
            blocks: vec![left_pad_block()],
            ..platform_layer()
        },
    );
    h.sync.applied(edited).await;
    for key in [globex_key(), key(6), acme_key()] {
        let response = h.get("/npm/left-pad", &key).await;
        assert_status(response, 403, "BLOCKED", "under the edited platform").await;
    }
    assert_eq!(
        h.sync.layer_calls() - layers,
        1,
        "one fetch for the platform"
    );
    assert_eq!(h.sync.lookups(), lookups);

    // 100 requests right after an edit: the sync task fetches; none of them does.
    let layers = h.sync.layer_calls();
    let edited = h.sync.edit_layer(PLATFORM, platform_layer());
    let client = common::sync::client_with_key(&globex_key());
    let url = h.server.url("/npm/left-pad");
    let burst: Vec<_> = (0..100)
        .map(|_| tokio::spawn(client.get(&url).send()))
        .collect();
    for request in burst {
        let status = request
            .await
            .unwrap()
            .expect("a response")
            .status()
            .as_u16();
        assert!(status == 200 || status == 403, "{status}");
    }
    h.sync.applied(edited).await;
    assert_eq!(h.get("/npm/left-pad", &globex_key()).await.status(), 200);
    assert_eq!(h.sync.layer_calls() - layers, 1, "exactly one layers call");
    assert_eq!(h.sync.lookups(), lookups);
    h.server.shutdown().await;
}

/// T-sync-stale-layer-server-down (C19): a layer row applied whose refetch fails keeps
/// the last known layer in use; the stale marker survives a restart, and the layer is
/// refetched on the first answered sync.
#[tokio::test]
async fn t_sync_stale_layer_server_down() {
    let h = harness(|_, _| {}).await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    h.sync
        .answer_layers_with(Some(StatusCode::SERVICE_UNAVAILABLE));
    let edited = h
        .sync
        .edit_layer(org(ACME), org_layer(vec![left_pad_block()]));
    h.sync.applied(edited).await;
    h.sync.sync_rounds(1).await;
    assert_eq!(
        h.get("/npm/left-pad", &acme_key()).await.status(),
        200,
        "the last known layer"
    );

    h.sync.go_down(true);
    let h = h.restart().await;
    assert_eq!(
        h.server.status("/health/ready").await,
        200,
        "from the snapshot"
    );
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);

    let layers = h.sync.layer_calls();
    h.sync.answer_layers_with(None);
    h.sync.go_down(false);
    h.sync.sync_rounds(2).await;
    assert_eq!(h.sync.layer_calls() - layers, 1, "refetched by the sync");
    let response = h.get("/npm/left-pad", &acme_key()).await;
    assert_status(response, 403, "BLOCKED", "the refetched layer").await;
    h.server.shutdown().await;
}

fn event(key_id: KeyId, result: ActivityResult) -> ActivityEvent {
    ActivityEvent {
        event_id: String::new(),
        key_id,
        place: org(ACME),
        ecosystem: Some(Ecosystem::Npm),
        package: Some(LEFT_PAD.to_owned()),
        version: Some(OLD.to_owned()),
        result,
        rule: "blocked_package".to_owned(),
        layer: ActivityLayer::Layer(LayerKind::Org),
        client_ip: None,
        eligible_at: None,
        at: None,
    }
}

type Drained = (Vec<(PlaceRef, ActivityEvent)>, Vec<(PlaceRef, u64)>);

/// Everything the queue holds, batch by batch, and the drop counts.
fn drain(queue: &ActivityQueue) -> Drained {
    let mut events = Vec::new();
    let mut dropped = Vec::new();
    loop {
        let batch = queue.take_batch();
        if batch.events.is_empty() && batch.dropped.is_empty() {
            return (events, dropped);
        }
        events.extend(
            batch
                .events
                .into_iter()
                .map(|queued| (queued.account, queued.event)),
        );
        dropped.extend(
            batch
                .dropped
                .into_iter()
                .map(|count| (count.account, count.count)),
        );
    }
}

/// T-activity-queued (C23): a blocked download is queued with its key id, place,
/// package, rule and layer, and reaches the server in the next sync; the key and its
/// hash do not.
#[tokio::test]
async fn t_activity_queued() {
    let h = harness(|sync, _| {
        sync.layer(
            org(GLOBEX),
            org_layer(vec![
                left_pad_block(),
                Block::Package {
                    ecosystem: Ecosystem::PyPi,
                    name: "alpha".to_owned(),
                    reason: None,
                },
            ]),
        );
    })
    .await;
    let response = h.get(&tarball_route(OLD), &globex_key()).await;
    assert_status(response, 403, "BLOCKED", "a blocked tarball").await;
    let event = wait_for_activity(&h.sync, |event| event.result == ActivityResult::Blocked).await;
    assert_eq!(event.key_id, KeyId(2));
    assert_eq!(event.place, org(GLOBEX));
    assert_eq!(event.ecosystem, Some(Ecosystem::Npm));
    assert_eq!(event.package.as_deref(), Some(LEFT_PAD));
    assert_eq!(event.version.as_deref(), Some(OLD));
    assert_eq!(event.rule, "blocked_package");
    assert_eq!(event.layer, ActivityLayer::Layer(LayerKind::Org));
    assert_eq!(event.client_ip, None);
    assert!(!event.event_id.is_empty());
    let hash = probation_policy::api::KeyHash::of(&globex_key());
    let hash = serde_json::to_string(&hash).unwrap();
    for (at, body) in h.sync.bodies() {
        if at.ends_with("/changes") {
            assert!(!body.contains(&globex_key()) && !body.contains(hash.trim_matches('"')));
        }
    }

    // V1 (S3-8): a refused metadata or version request is one row, with its package,
    // and its version when the route names one; versions merely hidden inside a
    // listing that is served are none.
    let fresh = "fresh-pkg";
    h.registry.answer(
        &npm_upstream_path(fresh),
        FakeAnswer::Body(
            json!({
                "name": fresh,
                "dist-tags": {"latest": NEW},
                "versions": {NEW: {
                    "name": fresh,
                    "version": NEW,
                    "dist": {"tarball": npm_tarball_url(fresh, &format!("{fresh}-{NEW}.tgz"))},
                }},
                "time": {NEW: FRESH},
            })
            .to_string(),
        ),
    );
    h.registry.answer(
        &common::pypi_upstream_path("alpha"),
        FakeAnswer::Body(
            json!({
                "meta": {"api-version": "1.1"},
                "name": "alpha",
                "versions": [],
                "files": [{
                    "filename": "alpha-1.0-py3-none-any.whl",
                    "url": "https://files.invalid/packages/ab/cd/alpha-1.0-py3-none-any.whl",
                    "hashes": {"sha256": "aa".repeat(32)},
                    "upload-time": PUBLISHED,
                }],
            })
            .to_string(),
        ),
    );
    let before = activity(&h.sync).len();
    let response = h.get("/npm/left-pad", &globex_key()).await;
    assert_status(response, 403, "BLOCKED", "the blocked listing").await;
    let response = h.get(&format!("/npm/left-pad/{OLD}"), &globex_key()).await;
    assert_status(response, 403, "BLOCKED", "a blocked version").await;
    let response = h.get(&format!("/npm/left-pad/{NEW}"), &acme_key()).await;
    assert_status(response, 403, "HELD", "a held version").await;
    let response = h.get(&format!("/npm/{fresh}"), &acme_key()).await;
    assert_status(response, 403, "HELD", "a listing held whole").await;
    // PyPI answers a refusal with an empty listing (SPEC §7). Each request is a row,
    // the second one served from the rendered cache.
    for _ in 0..2 {
        let response = h.get("/pypi/simple/alpha/", &globex_key()).await;
        assert_eq!(response.status(), 200, "PyPI answers an empty listing");
    }
    // Served, with 2.0.0 hidden while it is held: no row.
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    wait_for("six refusal rows", Duration::from_secs(10), || {
        activity(&h.sync).len() >= before + 6
    })
    .await;
    h.sync.sync_rounds(2).await;
    let rows = activity(&h.sync)[before..].to_vec();
    let summary: Vec<_> = rows
        .iter()
        .map(|row| {
            (
                row.result,
                row.package.clone(),
                row.version.clone(),
                row.eligible_at.clone(),
            )
        })
        .collect();
    let eligible = Some("2026-04-07T00:00:00Z".to_owned());
    assert_eq!(
        summary,
        vec![
            (
                ActivityResult::Blocked,
                Some(LEFT_PAD.to_owned()),
                None,
                None
            ),
            (
                ActivityResult::Blocked,
                Some(LEFT_PAD.to_owned()),
                Some(OLD.to_owned()),
                None
            ),
            (
                ActivityResult::Held,
                Some(LEFT_PAD.to_owned()),
                Some(NEW.to_owned()),
                eligible.clone()
            ),
            (ActivityResult::Held, Some(fresh.to_owned()), None, eligible),
            (
                ActivityResult::Blocked,
                Some("alpha".to_owned()),
                None,
                None
            ),
            (
                ActivityResult::Blocked,
                Some("alpha".to_owned()),
                None,
                None
            ),
        ],
        "one row a refused request, none for the served listing"
    );
    assert_eq!(rows[0].layer, ActivityLayer::Layer(LayerKind::Org));
    assert_eq!(rows[0].rule, "blocked_package");
    assert_eq!(rows[2].layer, ActivityLayer::Layer(LayerKind::Platform));
    assert_eq!(rows[4].ecosystem, Some(Ecosystem::PyPi));
    assert_eq!(rows[5].layer, ActivityLayer::Layer(LayerKind::Org));
    assert_eq!(rows[5].rule, "blocked_package");
    h.server.shutdown().await;
}

/// T-activity-bounded (T18): `ACTIVITY_QUEUE_CAP + 10` events over 11 accounts, none
/// above its share: the oldest 10 go, and no account counts a drop.
#[test]
fn t_activity_bounded() {
    let queue = ActivityQueue::new(1);
    let total = ACTIVITY_QUEUE_CAP + 10;
    for n in 0..total {
        queue.record_activity(
            org(n as u32 % 11),
            event(KeyId(n as u64), ActivityResult::Blocked),
        );
    }
    let (events, dropped) = drain(&queue);
    assert_eq!(events.len(), ACTIVITY_QUEUE_CAP);
    assert_eq!(events[0].1.key_id, KeyId(10), "the oldest 10 dropped");
    assert_eq!(events.last().unwrap().1.key_id, KeyId(total as u64 - 1));
    assert!(dropped.is_empty(), "{dropped:?}");
    let ids: std::collections::HashSet<_> =
        events.iter().map(|(_, event)| &event.event_id).collect();
    assert_eq!(ids.len(), events.len(), "every event id is unique");
}

/// T-activity-fair-share (T18): an account flooding the queue keeps its share and
/// counts the rest as dropped, and another account's event is still queued; an account
/// spread over many places is still one account.
#[test]
fn t_activity_fair_share() {
    let queue = ActivityQueue::new(1);
    for n in 0..2 * ACTIVITY_ACCOUNT_CAP {
        queue.record_activity(org(1), event(KeyId(n as u64), ActivityResult::Blocked));
    }
    queue.record_activity(org(2), event(KeyId(99_999), ActivityResult::Blocked));
    let (events, dropped) = drain(&queue);
    let of = |account| {
        events
            .iter()
            .filter(|(owner, _)| *owner == org(account))
            .count()
    };
    assert_eq!(of(1), ACTIVITY_ACCOUNT_CAP);
    assert_eq!(of(2), 1, "B's event is kept");
    assert_eq!(dropped, vec![(org(1), ACTIVITY_ACCOUNT_CAP as u64)]);

    let queue = ActivityQueue::new(1);
    for place in 0..11u32 {
        for n in 0..1_000u64 {
            let mut row = event(KeyId(n), ActivityResult::Held);
            row.place = PlaceRef {
                kind: LayerKind::Group,
                id: 100 + place,
            };
            queue.record_activity(org(1), row);
        }
    }
    queue.record_activity(org(2), event(KeyId(1), ActivityResult::Blocked));
    let (events, dropped) = drain(&queue);
    assert_eq!(of_account(&events, 1), ACTIVITY_ACCOUNT_CAP);
    assert_eq!(of_account(&events, 2), 1);
    assert_eq!(
        dropped,
        vec![(org(1), 11 * 1_000 - ACTIVITY_ACCOUNT_CAP as u64)]
    );
}

fn of_account(events: &[(PlaceRef, ActivityEvent)], account: u32) -> usize {
    events
        .iter()
        .filter(|(owner, _)| *owner == org(account))
        .count()
}

/// T-activity-layer (C23, C56): an org-layer block names `org`; a platform freeze hold
/// names `platform`, with `eligible_at` its publication time plus the freeze.
#[tokio::test]
async fn t_activity_layer() {
    let h = harness(|sync, _| {
        sync.layer(org(GLOBEX), org_layer(vec![left_pad_block()]));
    })
    .await;
    assert_eq!(
        h.get(&tarball_route(OLD), &globex_key()).await.status(),
        403
    );
    let response = h.get(&tarball_route(NEW), &acme_key()).await;
    assert_status(response, 403, "HELD", "frozen for a day").await;
    let blocked = wait_for_activity(&h.sync, |event| event.result == ActivityResult::Blocked).await;
    assert_eq!(blocked.layer, ActivityLayer::Layer(LayerKind::Org));
    let held = wait_for_activity(&h.sync, |event| event.result == ActivityResult::Held).await;
    assert_eq!(held.layer, ActivityLayer::Layer(LayerKind::Platform));
    assert_eq!(held.rule, "freeze");
    assert_eq!(held.version.as_deref(), Some(NEW));
    assert_eq!(held.eligible_at.as_deref(), Some("2026-04-07T00:00:00Z"));
    h.server.shutdown().await;
}

/// T-activity-would-block (C81): a group's OSV log-only setting serves an OSV match and
/// records "would have blocked".
#[tokio::test]
async fn t_activity_would_block() {
    let group = PlaceRef {
        kind: LayerKind::Group,
        id: 11,
    };
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), org_layer(Vec::new()));
    sync.layer(
        group,
        Layer {
            osv: Some(OsvSetting::LogOnly),
            ..Layer::empty(LayerKind::Group)
        },
    );
    sync.known_key(&key(5), &[PLATFORM, org(ACME), group]);
    let (osv_url, _osv) = common::osv_flagging(&[(LEFT_PAD, OLD)]).await;
    let dir = tempfile::tempdir().expect("a directory");
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    fast(&mut config);
    let server = TestServer::start_with_upstream_and_osv(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        registry(),
        fake_origins(),
        reqwest::Client::new(),
        osv_url,
    )
    .await;
    let response = server
        .get_with_headers(
            &tarball_route(OLD),
            &[("authorization", &format!("Bearer {}", key(5)))],
        )
        .await;
    assert_eq!(response.status(), 200, "log-only serves the match");
    let event = wait_for_activity(&sync, |event| event.result == ActivityResult::WouldBlock).await;
    assert_eq!(event.layer, ActivityLayer::Layer(LayerKind::Group));
    assert_eq!(event.rule, "osv");
    assert_eq!(event.version.as_deref(), Some(OLD));
    server.shutdown().await;
}

/// T-activity-refusals (C55, C92): a revoked key, a suspended organisation's key and a
/// foreign key inside a locked range each leave a row with the key id.
#[tokio::test]
async fn t_activity_refusals() {
    let h = harness(|sync, config| {
        sync.revoked_key(&key(9), &[PLATFORM, org(ACME)]);
        sync.layer(org(30), org_layer(Vec::new()));
        sync.known_key(&key(31), &[PLATFORM, org(30)]);
        sync.set_ranges(&[("192.0.2.0/24", ACME)]);
        config.management.as_mut().unwrap().trusted_proxies = vec![cidr("127.0.9.0/24")];
    })
    .await;
    assert_eq!(h.get("/npm/left-pad", &key(9)).await.status(), 401);
    let suspended = h.sync.suspend(org(30));
    h.sync.applied(suspended).await;
    assert_eq!(h.get("/npm/left-pad", &key(31)).await.status(), 401);
    // C: re-activating the organisation (a `place` row) clears its keys' refusal.
    h.sync.known_key(&key(31), &[PLATFORM, org(30)]);
    let reactivated = h.sync.touch_place(org(30));
    h.sync.applied(reactivated).await;
    h.clock.advance_seconds(1);
    assert_eq!(
        h.get("/npm/left-pad", &key(31)).await.status(),
        200,
        "re-activated"
    );
    let response = h
        .get_from(
            loopback(9, 1),
            "/npm/left-pad",
            &globex_key(),
            Some("192.0.2.7"),
        )
        .await;
    assert_eq!(response.status(), 403);

    let revoked = wait_for_activity(&h.sync, |e| e.result == ActivityResult::RefusedRevoked).await;
    assert_eq!(
        (revoked.key_id, revoked.layer),
        (KeyId(3), ActivityLayer::None)
    );
    let suspended =
        wait_for_activity(&h.sync, |e| e.result == ActivityResult::RefusedSuspended).await;
    assert_eq!(suspended.layer, ActivityLayer::None);
    assert_eq!(suspended.place, org(30));
    let network = wait_for_activity(&h.sync, |e| e.result == ActivityResult::RefusedNetwork).await;
    assert_eq!(network.key_id, KeyId(2));
    assert_eq!(network.layer, ActivityLayer::Network);
    assert_eq!(network.client_ip, Some("192.0.2.7".parse().unwrap()));
    assert!(network.package.is_none());
    for event in activity(&h.sync) {
        assert!(!event.rule.contains("Acme") && !event.rule.contains(&ACME.to_string()));
    }
    h.server.shutdown().await;
}

/// T-rate-limit-per-account (C28, C66, C114): two keys of one personal account share its
/// 10 a minute; the 11th and 12th requests get 429; another account is untouched.
#[tokio::test]
async fn t_rate_limit_per_account() {
    let h = harness(|sync, _| {
        sync.layer(personal(5), Layer::empty(LayerKind::Personal));
        sync.known_key_limited(&key(3), &[PLATFORM, personal(5)], Some(10));
        sync.known_key_limited(&key(4), &[PLATFORM, personal(5)], Some(10));
        sync.layer(personal(6), Layer::empty(LayerKind::Personal));
        sync.known_key_limited(&key(5), &[PLATFORM, personal(6)], Some(10));
    })
    .await;
    let mut statuses = Vec::new();
    for _ in 0..6 {
        for key in [key(3), key(4)] {
            statuses.push(h.get("/npm/left-pad", &key).await.status().as_u16());
        }
    }
    assert_eq!(statuses[..10], [200; 10]);
    assert_eq!(statuses[10..], [429, 429]);
    let response = h.get("/npm/left-pad", &key(3)).await;
    assert_status(response, 429, "TOO_MANY_REQUESTS", "over the limit").await;
    assert_eq!(
        h.get("/npm/left-pad", &key(5)).await.status(),
        200,
        "another account"
    );
    h.clock.advance_seconds(6);
    assert_eq!(
        h.get("/npm/left-pad", &key(4)).await.status(),
        200,
        "one more after 6 s"
    );
    h.server.shutdown().await;
}

/// T-settings-push (C22, C105): a valid push is written to the overlay and the firewall
/// asks to restart, delivering the queued activity in a last call; an invalid one
/// leaves every file alone and is reported.
#[tokio::test]
async fn t_settings_push() {
    let h = harness(|sync, _| {
        sync.revoked_key(&key(9), &[PLATFORM, org(ACME)]);
    })
    .await;
    let overlay = h.data_dir.join("managed-settings.toml");

    h.sync.push_settings(1, "max_active_requests = 0\n");
    h.sync.sync_rounds(2).await;
    assert!(!overlay.exists(), "an invalid push writes nothing");
    let report = h.sync.changes_requests().last().unwrap().report.clone();
    assert!(
        report
            .last_apply_error
            .as_deref()
            .is_some_and(|error| error.contains("max_active_requests")),
        "{report:?}"
    );
    assert_eq!(report.settings_revision, 0);
    let restart = tokio::time::timeout(
        Duration::from_millis(100),
        h.server.running().restart_requested(),
    )
    .await;
    assert!(restart.is_err(), "no restart for an invalid push");

    // B2: a log file start-up could not open is refused at push time. And a failed push
    // is never applied again, even once it would pass (L).
    let missing = h.data_dir.join("missing");
    let log = missing.join("decisions.ndjson");
    h.sync.push_settings(
        5,
        &format!(
            "log_file_path = \"{}\"\nlog_consumer_identification = true\n",
            log.display()
        ),
    );
    h.sync.sync_rounds(2).await;
    assert!(!overlay.exists(), "an unopenable log file writes nothing");
    let report = h.sync.changes_requests().last().unwrap().report.clone();
    assert!(
        report
            .last_apply_error
            .as_deref()
            .is_some_and(|error| error.contains("log_file_path")),
        "{report:?}"
    );
    std::fs::create_dir(&missing).unwrap();
    h.sync.sync_rounds(2).await;
    assert!(!overlay.exists(), "a failed push is not tried again");
    let restart = tokio::time::timeout(
        Duration::from_millis(100),
        h.server.running().restart_requested(),
    )
    .await;
    assert!(restart.is_err(), "no restart for a push that failed once");

    let gate = h.sync.hold_changes();
    gate.wait_until_reached().await;
    for _ in 0..2 {
        assert_eq!(h.get("/npm/left-pad", &key(9)).await.status(), 401);
    }
    h.sync.push_settings(
        2,
        "max_active_requests = 64\nnpm_upstream_url = \"https://registry.example\"\n",
    );
    h.sync.release_holds();
    tokio::time::timeout(
        Duration::from_secs(5),
        h.server.running().restart_requested(),
    )
    .await
    .expect("a restart is asked for");
    assert_eq!(
        std::fs::read_to_string(&overlay).unwrap(),
        "max_active_requests = 64\nnpm_upstream_url = \"https://registry.example\"\n"
    );
    assert_eq!(SettingsState::load(&h.data_dir).settings_revision, 2);
    assert!(h.get("/npm/left-pad", &key(9)).await.status() == 401);
    let before = h.sync.changes_requests().len();
    h.server.shutdown().await;
    let requests = h.sync.changes_requests();
    assert!(requests.len() > before, "a last call before exit");
    let delivered = requests
        .iter()
        .flat_map(|request| &request.activity)
        .filter(|event| event.result == ActivityResult::RefusedRevoked)
        .count();
    assert_eq!(
        delivered, 3,
        "every queued event went out before the restart"
    );

    // X3: a local log file start-up cannot open does not stop a push that leaves it
    // alone, with consumer identification off: start-up only warns about it then.
    let h = harness(|_, config| {
        let local = format!(
            "{}\nlog_file_path = \"/nonexistent-probation-dir/decisions.ndjson\"\n",
            config.local.0
        );
        config.local = probation::config::LocalText(local.into());
    })
    .await;
    h.sync.push_settings(6, "max_active_requests = 64\n");
    tokio::time::timeout(
        Duration::from_secs(5),
        h.server.running().restart_requested(),
    )
    .await
    .expect("the push is applied");
    h.server.shutdown().await;
}

/// T-settings-push-allowlist (T5, C35, C118): local-only keys, paths outside the data
/// directory or onto the firewall's own files, and `http` upstreams are refused, and a
/// refused push leaves the overlay alone.
#[tokio::test]
async fn t_settings_push_allowlist() {
    let dir = tempfile::tempdir().expect("a directory");
    let mut config = config_with_open_blocklist(dir.path());
    let data_dir = std::fs::canonicalize(dir.path()).unwrap();
    config.data_dir = data_dir.clone();
    let mut management = FakeSyncServer::start().await.management();
    management.token_file = data_dir.join("firewall.token");
    std::fs::write(&management.token_file, "fwt_x").unwrap();
    config.management = Some(management);
    let at = |name: &str| data_dir.join(name).display().to_string();

    // Every key of the one list the server checks a push against is refused here too
    // (C35, C118).
    for key in probation_policy::LOCAL_ONLY_SETTINGS {
        assert!(
            config.with_overlay(&format!("{key} = \"x\"\n")).is_err(),
            "{key} must be refused"
        );
    }
    for (push, what) in [
        (
            "[management]\nurl = \"https://evil.example\"\n".to_owned(),
            "management",
        ),
        ("listen = \"0.0.0.0:1\"\n".to_owned(), "listen"),
        (
            "public_url = \"https://evil.example\"\n".to_owned(),
            "public_url",
        ),
        (
            "siem_url = \"https://evil.example\"\n".to_owned(),
            "siem_url",
        ),
        (
            "siem_auth_header = \"x-key\"\n".to_owned(),
            "siem_auth_header",
        ),
        ("data_dir = \"/tmp\"\n".to_owned(), "data_dir"),
        (
            "tls_cert_path = \"/tmp/cert.pem\"\n".to_owned(),
            "tls_cert_path",
        ),
        (
            "tls_key_path = \"/tmp/key.pem\"\n".to_owned(),
            "tls_key_path",
        ),
        (
            "log_file_path = \"/tmp/decisions.ndjson\"\n".to_owned(),
            "a path outside data_dir",
        ),
        (
            format!("log_file_path = \"{}/../x.ndjson\"\n", data_dir.display()),
            "a walk out",
        ),
        (
            "npm_upstream_url = \"http://registry.example\"\n".to_owned(),
            "an http upstream",
        ),
        (
            format!("log_file_path = \"{}\"\n", at("firewall.db")),
            "the database",
        ),
        (
            format!("log_file_path = \"{}\"\n", at("firewall.db-wal")),
            "its log",
        ),
        (
            format!("log_file_path = \"{}\"\n", at("managed-cache.json")),
            "a managed file",
        ),
        (
            format!("log_file_path = \"{}\"\n", at("firewall.token")),
            "the token file",
        ),
    ] {
        assert!(
            config.with_overlay(&push).is_err(),
            "{what} must be refused"
        );
    }
    // V2: nothing the firewall keeps under data_dir itself, and no symlink, may be a
    // pushed path. Each target exists, so only the confinement rule can refuse it.
    for dir in ["state", "content/objects", "content/tmp"] {
        std::fs::create_dir_all(data_dir.join(dir)).unwrap();
    }
    for file in [
        "lock",
        "state/firewall.db",
        "managed-settings.toml",
        "managed-settings.state",
    ] {
        std::fs::write(data_dir.join(file), "").unwrap();
    }
    let elsewhere = tempfile::tempdir().expect("a directory");
    let outside = elsewhere.path().join("decisions.ndjson");
    std::fs::write(&outside, "").unwrap();
    std::os::unix::fs::symlink(&outside, data_dir.join("link.ndjson")).unwrap();
    for (path, what) in [
        ("lock", "the data-directory lock"),
        ("state/firewall.db", "the store"),
        ("state/decisions.ndjson", "a file in the store's directory"),
        ("content/objects/decisions.ndjson", "the content store"),
        ("content/tmp/x.part", "a temporary download"),
        ("managed-cache.prev.json", "the previous cache snapshot"),
        ("managed-settings.toml", "the settings overlay"),
        ("managed-settings.prev.toml", "the previous overlay"),
        ("managed-settings.state", "the settings state"),
        (".tmpAbCdEf", "a file being written atomically"),
        ("link.ndjson", "a symlink out of data_dir"),
    ] {
        let push = format!("log_file_path = \"{}\"\n", at(path));
        let refused = config.with_overlay(&push).expect_err(what);
        assert!(
            refused.contains("must name a file of its own"),
            "{what}: {refused}"
        );
    }

    let accepted = config
        .with_overlay(&format!(
            "log_file_path = \"{}\"\npypi_upstream_url = \"https://pypi.example\"\n",
            at("decisions.ndjson")
        ))
        .expect("a file of its own and an https origin");
    assert_eq!(
        accepted.listen, config.listen,
        "local-only keys are this file's"
    );
    assert_eq!(accepted.data_dir, config.data_dir);
    assert_eq!(accepted.public_url, config.public_url);

    // Through the firewall: refused, reported, and nothing written.
    let h = harness(|_, _| {}).await;
    h.sync.push_settings(3, "listen = \"0.0.0.0:1\"\n");
    h.sync.sync_rounds(2).await;
    assert!(!h.data_dir.join("managed-settings.toml").exists());
    let report = h.sync.changes_requests().last().unwrap().report.clone();
    assert!(report.last_apply_error.unwrap().contains("listen"));
    assert_eq!(
        report.failed_revision,
        Some(3),
        "the refused push's revision (S7-14)"
    );

    // E: however long the reason, the report carries at most 2 KiB of it.
    h.sync
        .push_settings(4, &format!("{} = 1\n", "x".repeat(5_000)));
    h.sync.sync_rounds(2).await;
    let report = h.sync.changes_requests().last().unwrap().report.clone();
    let error = report.last_apply_error.expect("an error");
    assert!(error.contains("xxxx"), "{error}");
    assert!(error.len() <= 2_048, "{} bytes", error.len());
    h.server.shutdown().await;
}

/// T-settings-rollback (C71): an overlay that fails at start is swapped for the previous
/// one, the firewall starts on it, and the error is reported.
#[tokio::test]
async fn t_settings_rollback() {
    let h = harness(|_, _| {}).await;
    h.server.shutdown().await;
    std::fs::write(
        h.data_dir.join("managed-settings.toml"),
        "max_active_requests = 0\n",
    )
    .unwrap();
    std::fs::write(
        h.data_dir.join("managed-settings.prev.toml"),
        "max_active_requests = 7\n",
    )
    .unwrap();
    SettingsState {
        settings_revision: 2,
        previous_revision: 1,
        failed_revision: None,
        last_apply_error: None,
    }
    .save(&h.data_dir)
    .unwrap();

    let config = probation::with_settings_overlay(h.config.clone()).await;
    assert_eq!(config.max_active_requests.get(), 7, "the previous overlay");
    assert_eq!(
        std::fs::read_to_string(h.data_dir.join("managed-settings.toml")).unwrap(),
        "max_active_requests = 7\n"
    );
    let state = SettingsState::load(&h.data_dir);
    assert_eq!(state.settings_revision, 1);
    assert_eq!(state.failed_revision, Some(2));
    assert!(
        state
            .last_apply_error
            .unwrap()
            .contains("max_active_requests")
    );

    let server = TestServer::start_in_with_registry(
        &h.data_dir,
        config,
        h.clock.shared(),
        Arc::clone(&h.registry),
    )
    .await;
    h.sync.sync_rounds(1).await;
    let report = h.sync.changes_requests().last().unwrap().report.clone();
    assert_eq!(report.settings_revision, 1);
    assert!(
        report
            .last_apply_error
            .unwrap()
            .contains("max_active_requests")
    );
    server.shutdown().await;

    // B2: an overlay that passes every check and still fails `App::start` is rolled
    // back and the start tried again once. Here the failure is staged: the overlay's
    // start is given a log file it cannot open with consumer identification on, a
    // delivery failure, which is the kind a push can cause.
    std::fs::write(
        h.data_dir.join("managed-settings.toml"),
        "max_active_requests = 64\n",
    )
    .unwrap();
    SettingsState {
        settings_revision: 3,
        previous_revision: 1,
        failed_revision: None,
        last_apply_error: None,
    }
    .save(&h.data_dir)
    .unwrap();
    std::fs::write(
        h.data_dir.join("managed-settings.prev.toml"),
        "max_active_requests = 7\n",
    )
    .unwrap();
    let clock = h.clock.shared();
    let registry = Arc::clone(&h.registry);
    let running = probation::start_with_settings(h.config.clone(), move |mut config| {
        if config.max_active_requests.get() == 64 {
            config.log_file_path = Some(PathBuf::from("/nonexistent-probation-dir/x.ndjson"));
            config.log_consumer_identification = true;
        }
        probation::AppDeps {
            config,
            clock: Arc::clone(&clock),
            transport: Arc::clone(&registry) as Arc<dyn Transport>,
            origins: fake_origins(),
            osv_client: probation::osv::unreachable_client(),
            osv_base_url: None,
        }
    })
    .await
    .expect("started again on the previous overlay");
    assert_eq!(running.app().config.max_active_requests.get(), 7);
    let state = SettingsState::load(&h.data_dir);
    assert_eq!(
        (state.settings_revision, state.failed_revision),
        (1, Some(3))
    );
    assert!(state.last_apply_error.unwrap().contains("log_file_path"));

    // X1: a second instance on the data directory this one holds fails to start, and
    // changes neither the overlay nor the state: only a failure the overlay can cause
    // rolls it back, and never before this process holds the directory.
    std::fs::write(
        h.data_dir.join("managed-settings.toml"),
        "max_active_requests = 64\n",
    )
    .unwrap();
    let held_state = SettingsState::load(&h.data_dir);
    let second = probation::start_with_settings(h.config.clone(), |config| probation::AppDeps {
        config,
        clock: h.clock.shared(),
        transport: Arc::clone(&h.registry) as Arc<dyn Transport>,
        origins: fake_origins(),
        osv_client: probation::osv::unreachable_client(),
        osv_base_url: None,
    })
    .await;
    assert!(
        matches!(second, Err(probation::StartupError::DataDir(_))),
        "{:?}",
        second.err()
    );
    assert_eq!(SettingsState::load(&h.data_dir), held_state);
    assert_eq!(
        std::fs::read_to_string(h.data_dir.join("managed-settings.toml")).unwrap(),
        "max_active_requests = 64\n"
    );
    TestServer::from_running(running).shutdown().await;
}

/// T-settings-revision-no-loop (C105, C115): after the restart a push asked for, the
/// firewall reports the applied revision and its cursor, so the server sends no
/// settings again and there is exactly one restart.
#[tokio::test]
async fn t_settings_revision_no_loop() {
    let h = harness(|_, _| {}).await;
    h.sync.edit_layer(org(GLOBEX), org_layer(Vec::new()));
    h.sync.push_settings(4, "max_active_requests = 64\n");
    tokio::time::timeout(
        Duration::from_secs(5),
        h.server.running().restart_requested(),
    )
    .await
    .expect("a restart");
    h.server.shutdown().await;
    let cursor = h.sync.changes_requests().last().unwrap().since;

    let mut config = probation::with_settings_overlay(h.config.clone()).await;
    assert_eq!(config.max_active_requests.get(), 64);
    // The overlay is merged over the file as written, and this test's file is the
    // shipped sample: its one-minute interval is put back to this test's.
    config.sync_interval_seconds = h.config.sync_interval_seconds;
    let server = TestServer::start_in_with_registry(
        &h.data_dir,
        config,
        h.clock.shared(),
        Arc::clone(&h.registry),
    )
    .await;
    let calls = h.sync.changes_requests().len();
    h.sync.sync_rounds(3).await;
    let after: Vec<ChangesRequest> = h.sync.changes_requests().split_off(calls);
    assert!(
        after
            .iter()
            .all(|request| request.report.settings_revision == 4)
    );
    assert!(
        after[0].since >= cursor && after[0].since > 0,
        "the cursor was restored"
    );
    let restart = tokio::time::timeout(
        Duration::from_millis(200),
        server.running().restart_requested(),
    )
    .await;
    assert!(restart.is_err(), "no second restart");
    server.shutdown().await;
}

/// T-cache-snapshot-restart (C19, C115): a restart while the server is down keeps
/// serving cached keys and keeps the network lock; the snapshot holds no key; a
/// truncated snapshot falls back to the previous one; readiness holds.
#[tokio::test]
async fn t_cache_snapshot_restart() {
    let h = harness(|sync, _| {
        sync.set_ranges(&[("127.0.5.0/24", ACME)]);
    })
    .await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    assert_eq!(h.get("/npm/left-pad", &globex_key()).await.status(), 200);
    h.sync.sync_rounds(2).await;
    h.sync.go_down(true);

    let h = h.restart().await;
    assert_eq!(
        h.server.status("/health/ready").await,
        200,
        "ready from the snapshot"
    );
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    let response = h
        .get_from(loopback(5, 9), "/npm/left-pad", &globex_key(), None)
        .await;
    assert_status(response, 403, "NETWORK_NOT_ALLOWED", "the lock survives").await;
    let snapshot = std::fs::read_to_string(h.data_dir.join("managed-cache.json")).unwrap();
    assert!(!snapshot.contains("prb_"), "{snapshot}");

    h.server.shutdown().await;
    assert!(h.data_dir.join("managed-cache.prev.json").exists());
    let current = h.data_dir.join("managed-cache.json");
    let text = std::fs::read_to_string(&current).unwrap();
    std::fs::write(&current, &text[..text.len() / 2]).unwrap();
    let server = TestServer::start_in_with_registry(
        &h.data_dir,
        h.config.clone(),
        h.clock.shared(),
        Arc::clone(&h.registry),
    )
    .await;
    assert_eq!(
        server.status("/health/ready").await,
        200,
        "from the previous snapshot"
    );
    let response = server
        .get_with_headers(
            "/npm/left-pad",
            &[("authorization", &format!("Bearer {}", acme_key()))],
        )
        .await;
    assert_eq!(response.status(), 200, "served from the previous snapshot");
    server.shutdown().await;
}

/// T-sync-limits-in-place (C28, C67, K2): a default change updates the cached entries
/// whose rate is the default and spares an override, with no lookup; deleting the
/// override gives the default; a lookup read before the change is dropped and asked
/// once more.
#[tokio::test]
async fn t_sync_limits_in_place() {
    let h = harness(|sync, _| {
        sync.known_key_limited(&key(3), &[PLATFORM, org(ACME)], Some(6_000));
        sync.known_key_limited(&key(4), &[PLATFORM, org(GLOBEX)], Some(6_000));
        sync.layer(org(50), org_layer(Vec::new()));
        sync.known_key_limited(&key(5), &[PLATFORM, org(50)], Some(6_000));
    })
    .await;
    let globex_override = LimitChange {
        scope_kind: AccountKind::Org,
        scope_id: Some(GLOBEX),
        rate_per_min: NonZeroU32::new(100),
        source: LimitSource::Override,
    };
    let applied = h.sync.set_limit(globex_override);
    h.sync.applied(applied).await;
    for key in [key(3), key(4)] {
        assert_eq!(h.get("/npm/left-pad", &key).await.status(), 200);
    }
    let lookups = h.sync.lookups();

    let default = |rate| LimitChange {
        scope_kind: AccountKind::Org,
        scope_id: None,
        rate_per_min: NonZeroU32::new(rate),
        source: LimitSource::Default,
    };
    let applied = h.sync.set_limit(default(3));
    h.sync.applied(applied).await;
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(h.get("/npm/left-pad", &key(3)).await.status().as_u16());
    }
    assert_eq!(statuses, [200, 200, 200, 429, 429], "the new default of 3");
    for _ in 0..5 {
        assert_eq!(
            h.get("/npm/left-pad", &key(4)).await.status(),
            200,
            "the override stays"
        );
    }
    assert_eq!(h.sync.lookups(), lookups, "no lookup for cached entries");

    let applied = h.sync.set_limit(LimitChange {
        rate_per_min: NonZeroU32::new(3),
        source: LimitSource::Default,
        ..globex_override
    });
    h.sync.applied(applied).await;
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(h.get("/npm/left-pad", &key(4)).await.status().as_u16());
    }
    assert_eq!(statuses, [200, 200, 200, 429], "the default now");

    // A lookup for key 5 read before a default change arrives after it.
    let gate = h.sync.hold_lookups();
    let held = h.spawn_get("/npm/left-pad", &key(5));
    gate.wait_until_reached().await;
    let applied = h.sync.set_limit(default(1));
    h.sync.applied(applied).await;
    let before = h.sync.lookups();
    h.sync.release_holds();
    assert_eq!(held.await.unwrap(), 200);
    assert_eq!(h.sync.lookups() - before, 1, "asked once more");
    let response = h.get("/npm/left-pad", &key(5)).await;
    assert_status(response, 429, "TOO_MANY_REQUESTS", "the new default of 1").await;
    h.server.shutdown().await;
}

/// T-report-upstream-unreachable (C69): each report says whether npm, PyPI (metadata or
/// files) and OSV answered in the last period, through the production transport.
#[tokio::test]
async fn t_report_upstream_unreachable() {
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let npm = MockServer::start().await;
    let pypi = MockServer::start().await;
    let files = MockServer::start().await;
    let osv = MockServer::start().await;
    let origin = |server: &MockServer| url::Url::parse(&server.uri()).unwrap();
    let origins = OriginSet::for_tests(origin(&npm), origin(&pypi), origin(&files));
    let transport: Arc<dyn Transport> = Arc::new(
        probation::upstream::ReqwestTransport::for_origins(origins.clone()),
    );
    let wheel = "alpha-1.0-py3-none-any.whl";
    let project = json!({
        "meta": {"api-version": "1.1"},
        "name": "alpha",
        "versions": [],
        "files": [{
            "filename": wheel,
            "url": format!("{}/packages/{wheel}", files.uri()),
            "hashes": {"sha256": "ab".repeat(32)},
            "upload-time": PUBLISHED,
        }],
    });
    Mock::given(method("GET"))
        .and(path("/simple/alpha/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.pypi.simple.v1+json")
                .set_body_string(project.to_string()),
        )
        .mount(&pypi)
        .await;
    for server in [&npm, &files, &osv] {
        Mock::given(path_regex(".*"))
            .respond_with(ResponseTemplate::new(503))
            .mount(server)
            .await;
    }

    let sync = FakeSyncServer::start().await;
    sync.layer(
        PLATFORM,
        Layer {
            freeze_seconds: Some(0),
            osv: Some(OsvSetting::On),
            ..platform_layer()
        },
    );
    sync.layer(org(ACME), org_layer(Vec::new()));
    sync.known_key(&acme_key(), &[PLATFORM, org(ACME)]);
    let dir = tempfile::tempdir().expect("a directory");
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    fast(&mut config);
    let server = TestServer::start_with_upstream_and_osv(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        transport,
        origins,
        reqwest::Client::new(),
        url::Url::parse(&format!("{}/v1/querybatch", osv.uri())).unwrap(),
    )
    .await;
    let first = sync.changes_requests()[0].report.status.upstreams;
    assert_eq!(
        (first.npm, first.pypi, first.osv),
        (Reachability::Ok, Reachability::Ok, Reachability::Ok),
        "no calls yet"
    );
    let bearer = format!("Bearer {}", acme_key());
    let get = async |route: &str| {
        server
            .get_with_headers(
                route,
                &[
                    ("authorization", bearer.as_str()),
                    ("accept", "application/vnd.pypi.simple.v1+json"),
                ],
            )
            .await
    };
    let latest = |sync: &FakeSyncServer| {
        sync.changes_requests()
            .last()
            .unwrap()
            .report
            .status
            .upstreams
    };

    // npm refused, PyPI metadata answered, files refused, OSV refused (asked for the
    // PyPI file's version, since the policy's OSV is on).
    assert_eq!(get("/npm/left-pad").await.status(), 502);
    let listing: Value =
        serde_json::from_str(&get("/pypi/simple/alpha/").await.text().await.unwrap()).unwrap();
    let file = url::Url::parse(listing["files"][0]["url"].as_str().expect("a file")).unwrap();
    assert_ne!(get(file.path()).await.status(), 200);
    sync.sync_rounds(2).await;
    let status = latest(&sync);
    assert_eq!(status.npm, Reachability::Unreachable);
    assert_eq!(
        status.pypi,
        Reachability::Unreachable,
        "files fail while metadata answers"
    );
    assert_eq!(status.osv, Reachability::Unreachable);

    // A period with no calls changes nothing.
    sync.sync_rounds(1).await;
    assert_eq!(latest(&sync), status);

    // Each recovers.
    for server in [&npm, &files, &osv] {
        server.reset().await;
    }
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_document()))
        .mount(&npm)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("wheel bytes"))
        .mount(&files)
        .await;
    Mock::given(method("POST"))
        .respond_with(|request: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&request.body).expect("a batch");
            let results: Vec<Value> = body["queries"]
                .as_array()
                .expect("queries")
                .iter()
                .map(|_| json!({"vulns": []}))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({"results": results}))
        })
        .mount(&osv)
        .await;
    assert_eq!(get("/npm/left-pad").await.status(), 200);
    let _ = get(file.path()).await;
    sync.sync_rounds(2).await;
    let status = latest(&sync);
    assert_eq!(
        (status.npm, status.pypi, status.osv),
        (Reachability::Ok, Reachability::Ok, Reachability::Ok)
    );
    server.shutdown().await;
}

/// S2-8 (M2): a `layers` call on the request path is made once per place however many
/// new keys need it at once, and is charged to the lookup budget.
#[tokio::test]
async fn t_layer_fetch_single_flight_and_budget() {
    let h = harness(|sync, _| {
        sync.layer(org(70), org_layer(Vec::new()));
        for n in 0..20 {
            sync.known_key(&key(700 + n), &[PLATFORM, org(70)]);
        }
    })
    .await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    let layers = h.sync.layer_calls();
    let gate = h.sync.hold_layers();
    let burst: Vec<_> = (0..20u8)
        .map(|n| {
            let request = reqwest::Client::builder()
                .no_proxy()
                .local_address(loopback(40, n + 1))
                .build()
                .unwrap()
                .get(h.server.url("/npm/left-pad"))
                .header(
                    "authorization",
                    format!("Bearer {}", key(700 + u32::from(n))),
                )
                .send();
            tokio::spawn(async move { request.await.expect("a response").status().as_u16() })
        })
        .collect();
    gate.wait_until_reached().await;
    let app = h.server.app();
    let managed = app.managed().expect("managed");
    wait_for(
        "20 requests on one layers call",
        Duration::from_secs(5),
        || managed.waiting_on_layer(org(70)) == 20,
    )
    .await;
    h.sync.release_holds();
    for request in burst {
        assert_eq!(request.await.unwrap(), 200);
    }
    assert_eq!(
        h.sync.layer_calls() - layers,
        1,
        "one layers call for the burst"
    );
    drop(app);
    h.server.shutdown().await;

    // A budget of one a second: the new key's lookup takes it, so its layers call is
    // past the budget and the key is told to retry.
    let h = harness(|sync, config| {
        config.management.as_mut().unwrap().lookup_budget_per_second = NonZeroU32::new(1).unwrap();
        sync.layer(org(71), org_layer(Vec::new()));
        sync.known_key(&key(800), &[PLATFORM, org(71)]);
    })
    .await;
    let response = h.get("/npm/left-pad", &key(800)).await;
    assert_status(
        response,
        503,
        "LOOKUP_BUSY",
        "a layers call past the budget",
    )
    .await;
    h.server.shutdown().await;
}

/// X4 (H6): an invalidation is remembered as long as an ask can be in flight, not one
/// TTL: a lookup held past the TTL and answered after the key's revocation is not
/// cached.
#[tokio::test]
async fn t_sync_record_outlives_a_held_ask() {
    let h = harness(|sync, config| {
        sync.known_key(&key(95), &[PLATFORM, org(ACME)]);
        let management = config.management.as_mut().unwrap();
        management.key_cache_ttl_seconds = NonZeroU64::new(1).unwrap();
        management.request_timeout_seconds = NonZeroU64::new(5).unwrap();
        management.sync_margin_seconds = NonZeroU64::new(5).unwrap();
        config.sync_interval_seconds = NonZeroU64::new(6).unwrap();
    })
    .await;
    let lookups = h.sync.hold_lookups();
    let held = h.spawn_get("/npm/left-pad", &key(95));
    lookups.wait_until_reached().await;
    let revoked = h.sync.revoke(&key(95));
    h.sync.applied(revoked).await;
    // Past the TTL, and a sync answered since, which is when records are pruned.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    h.sync.sync_rounds(1).await;
    h.sync.release_holds();
    assert_eq!(held.await.unwrap(), 401, "the late Known answer is dropped");
    h.server.shutdown().await;
}

/// C126: after a database restore the server answers a firewall that is ahead with a
/// reset at its own, lower revision. The firewall empties its cache and adopts that
/// revision as cursor and floor; a lookup from before the reset, carrying a revision
/// above the new floor, is not cached; a fresh one is; nothing is locked out.
#[tokio::test]
async fn t_sync_reset_to_a_lower_revision() {
    let h = harness(|sync, config| {
        sync.known_key(&key(96), &[PLATFORM, org(ACME)]);
        sync.known_key(&key(97), &[PLATFORM, org(ACME)]);
        sync.layer(org(80), org_layer(Vec::new()));
        sync.known_key(&key(98), &[PLATFORM, org(80)]);
        sync.known_key(&key(99), &[PLATFORM, org(80)]);
        let management = config.management.as_mut().unwrap();
        management.request_timeout_seconds = NonZeroU64::new(5).unwrap();
        management.sync_margin_seconds = NonZeroU64::new(5).unwrap();
        config.sync_interval_seconds = NonZeroU64::new(6).unwrap();
    })
    .await;
    h.sync.set_revision(1_000);
    h.sync.applied(1_000).await;
    // A first reset, at 1000 (the log pruned past the cursor), puts the floor there: a
    // floor kept at the highest ever seen would lock out every answer from the restored
    // database.
    h.sync.set_revision(1_001);
    h.sync.prune();
    h.sync.set_revision(1_000);
    wait_for("a reset at 1000", Duration::from_secs(5), || {
        h.sync.resets() == 1
    })
    .await;
    h.sync.restore_to(1_000);
    h.sync.sync_rounds(1).await;
    assert_eq!(h.sync.changes_requests().last().unwrap().since, 1_000);
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);

    // A lookup read at 1000, held while the database is restored to 900.
    let lookups = h.sync.hold_lookups();
    let held = h.spawn_get("/npm/left-pad", &key(96));
    lookups.wait_until_reached().await;
    h.sync.restore_to(900);
    // The restored database predates key 96.
    h.sync.answer(
        &key(96),
        probation_policy::api::KeyLookup::Unknown { revision: 0 },
    );
    wait_for("a reset at 900", Duration::from_secs(5), || {
        h.sync.resets() == 2
    })
    .await;
    h.sync.sync_rounds(1).await;
    h.sync.release_holds();
    assert_eq!(
        held.await.unwrap(),
        401,
        "the answer read at 1000 is dropped; the one asked again says unknown"
    );
    let sinces: Vec<u64> = h
        .sync
        .changes_requests()
        .iter()
        .map(|request| request.since)
        .collect();
    assert_eq!(
        sinces.last(),
        Some(&900),
        "the cursor is the reset's revision: {sinces:?}"
    );

    // Nothing from before the reset is cached, and nothing is locked out.
    h.clock.advance_seconds(1);
    for key in [acme_key(), key(97)] {
        let lookups = h.sync.lookups();
        assert_eq!(h.get("/npm/left-pad", &key).await.status(), 200);
        assert_eq!(h.sync.lookups() - lookups, 1, "looked up afresh");
        assert_eq!(h.get("/npm/left-pad", &key).await.status(), 200);
        assert_eq!(h.sync.lookups() - lookups, 1, "then cached");
    }
    assert_eq!(h.sync.resets(), 2, "then ordinary deltas");

    // V3: a `layers` call held across a reset to a lower revision. Its answer, read
    // before the restore at a higher layer revision, is not stored; it is asked again,
    // and a request waiting on it is served under the restored layer.
    h.sync.set_revision(1_999);
    let edited = h.sync.edit_layer(org(80), org_layer(Vec::new()));
    h.sync.applied(edited).await;
    h.clock.advance_seconds(1);
    let held_layers = h.sync.hold_layers();
    let first = h.spawn_get("/npm/left-pad", &key(98));
    held_layers.wait_until_reached().await;
    h.sync.restore_to(1_500);
    h.sync.layer(org(80), org_layer(vec![left_pad_block()]));
    wait_for("a reset at 1500", Duration::from_secs(5), || {
        h.sync.resets() == 3
    })
    .await;
    h.sync.sync_rounds(1).await;
    let second = h.spawn_get("/npm/left-pad", &key(99));
    let app = h.server.app();
    let managed = app.managed().expect("managed");
    wait_for(
        "both requests on the held layers call",
        Duration::from_secs(5),
        || managed.waiting_on_layer(org(80)) == 2,
    )
    .await;
    h.sync.release_holds();
    assert_eq!(
        second.await.unwrap(),
        403,
        "decided under the restored layer"
    );
    assert_ne!(first.await.unwrap(), 200, "an ask from before the reset");
    drop(app);
    h.server.shutdown().await;
}

/// F2: the activity queued since the last round goes out on every graceful stop, not
/// only before a restart for a settings push.
#[tokio::test]
async fn t_activity_flushed_on_stop() {
    let h = harness(|_, config| {
        // One round at start and no other before the stop.
        config.sync_interval_seconds = NonZeroU64::new(3600).unwrap();
    })
    .await;
    wait_for("the first round", Duration::from_secs(5), || {
        !h.sync.changes_requests().is_empty()
    })
    .await;
    let app = h.managed();
    app.managed()
        .unwrap()
        .activity()
        .record_activity(org(ACME), event(KeyId(77), ActivityResult::Blocked));
    drop(app);
    let restart = tokio::time::timeout(
        Duration::from_millis(100),
        h.server.running().restart_requested(),
    )
    .await;
    assert!(restart.is_err(), "no settings push, so no restart");
    h.server.shutdown().await;
    let delivered = activity(&h.sync);
    assert!(
        delivered.iter().any(|event| event.key_id == KeyId(77)),
        "the queued event went out before the stop: {delivered:#?}"
    );
}

/// The report the last `changes` call carried.
fn last_report(sync: &FakeSyncServer) -> probation_policy::api::FirewallReport {
    sync.changes_requests().last().unwrap().report.clone()
}

/// The version-skew error a report carries after an unreadable answer: the firewall's
/// version, and a revision no settings rollout has, so it never fails a rollout step.
fn assert_skew_reported(report: &probation_policy::api::FirewallReport, what: &str) {
    let error = report.last_apply_error.as_deref().unwrap_or_default();
    assert!(
        error.contains("could not be read")
            && error.contains(&format!("(v{})", env!("CARGO_PKG_VERSION"))),
        "{what}: {report:?}"
    );
    assert_eq!(report.failed_revision, Some(0), "{what}: {report:?}");
}

/// F3 (decision 2026-10-23): a `200` this firewall cannot read is not an outage and
/// does not fail readiness. It keeps serving its cache, and the next report says why,
/// until the server answers in a form it reads again.
#[tokio::test]
async fn t_sync_unreadable_answer() {
    let h = harness(|_, _| {}).await;
    h.server
        .wait_for_status("/health/ready", 200, Duration::from_secs(5))
        .await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    // A layer kind this firewall does not know, as a newer server might send.
    h.sync.answer_raw(
        "/api/v1/sync/changes",
        Some(
            r#"{"revision":1,"changed_keys":[],"changed_layers":[{"kind":"Galaxy","id":1}],"changed_places":[],"changed_limits":[],"network_lock":null,"settings":null,"reset":false,"retired":false}"#,
        ),
    );
    h.sync.sync_rounds(2).await;
    assert_eq!(h.server.status("/health/ready").await, 200, "still ready");
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    assert_skew_reported(&last_report(&h.sync), "changes");
    h.sync.answer_raw("/api/v1/sync/changes", None);
    h.sync.sync_rounds(2).await;
    assert_eq!(last_report(&h.sync).last_apply_error, None, "cleared");
    h.server.shutdown().await;
}

/// F3: an unreadable `layers` answer after a block edit is reported, and the stale
/// layer stays in use until one can be read (C19).
#[tokio::test]
async fn t_sync_unreadable_layers() {
    let h = harness(|_, _| {}).await;
    assert_eq!(h.get("/npm/left-pad", &acme_key()).await.status(), 200);
    // A block kind this firewall does not know.
    h.sync.answer_raw(
        "/api/v1/sync/layers",
        Some(
            r#"{"layers":[{"place":{"kind":"Org","id":10},"layer":{"kind":"Org","freeze_seconds":null,"osv":null,"blocks":[{"Quarantine":{"name":"left-pad"}}],"exceptions":[],"allow":{"exceptions":true,"osv_off":true,"shorter_freeze":true}},"revision":99}],"revision":99}"#,
        ),
    );
    let edited = h
        .sync
        .edit_layer(org(ACME), org_layer(vec![left_pad_block()]));
    h.sync.applied(edited).await;
    h.sync.sync_rounds(1).await;
    assert_skew_reported(&last_report(&h.sync), "layers");
    assert_eq!(h.server.status("/health/ready").await, 200, "still ready");
    assert_eq!(
        h.get("/npm/left-pad", &acme_key()).await.status(),
        200,
        "the stale layer is still the one in use"
    );
    h.sync.answer_raw("/api/v1/sync/layers", None);
    h.sync.sync_rounds(2).await;
    let response = h.get("/npm/left-pad", &acme_key()).await;
    assert_status(response, 403, "BLOCKED", "the edited layer, once readable").await;
    assert_eq!(last_report(&h.sync).last_apply_error, None, "cleared");
    h.server.shutdown().await;
}

/// F3: an unreadable `lookup` answer is reported like an unreachable server's: a key
/// never seen gets `401`, and readiness holds.
#[tokio::test]
async fn t_sync_unreadable_lookup() {
    let h = harness(|_, _| {}).await;
    h.sync.answer_raw(
        "/api/v1/sync/lookup",
        Some(r#"{"status":"quarantined","revision":1}"#),
    );
    assert_eq!(h.get("/npm/left-pad", &globex_key()).await.status(), 401);
    h.sync.sync_rounds(1).await;
    assert_skew_reported(&last_report(&h.sync), "lookup");
    assert_eq!(h.server.status("/health/ready").await, 200, "still ready");
    h.sync.answer_raw("/api/v1/sync/lookup", None);
    h.sync.sync_rounds(1).await;
    assert_eq!(h.get("/npm/left-pad", &globex_key()).await.status(), 200);
    h.server.shutdown().await;
}

/// F2: a last batch the server refuses on a stop is warned about and counted as
/// dropped, as a failed one is. Seven events, so the line is this test's alone.
#[tokio::test]
async fn t_activity_flush_refused_on_stop() {
    let logs = common::logs::capture_warn();
    let h = harness(|_, config| {
        config.sync_interval_seconds = NonZeroU64::new(3600).unwrap();
    })
    .await;
    wait_for("the first round", Duration::from_secs(5), || {
        !h.sync.changes_requests().is_empty()
    })
    .await;
    let app = h.managed();
    for n in 0..7 {
        app.managed()
            .unwrap()
            .activity()
            .record_activity(org(ACME), event(KeyId(70 + n), ActivityResult::Blocked));
    }
    drop(app);
    h.sync
        .answer_changes_with(Some((StatusCode::PAYLOAD_TOO_LARGE, None)));
    h.server.shutdown().await;
    assert!(
        h.sync
            .changes_requests()
            .iter()
            .any(|request| request.activity.len() == 7),
        "the last batch was sent"
    );
    assert_eq!(
        logs.lines_containing_all(&["could not be delivered", "events=7"]),
        1,
        "{}",
        logs.text()
    );
}
