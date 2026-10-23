//! Slice 2 of the management server: a managed firewall serves each request under its
//! own key's policy, fetched from a fake management server, and refuses a missing or
//! unknown key with `401` (03-program-design.md § Test plan).

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::sync::{FakeSyncServer, PLATFORM, base64, key, org};
use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, artifact_path, body_error,
    config_with_open_blocklist, fake_origins, npm_artifact_upstream_path, npm_tarball_url,
    npm_upstream_path, pypi_upstream_path, wait_until,
};
use probation::config::{Config, FirewallToken};
use probation::store::rows::ReferenceId;
use probation::upstream::Transport;
use probation_policy::api::{ChainLink, KeyId, KeyLookup, LimitSource, OrgId};
use probation_policy::{Block, DigestAlgorithm, Ecosystem, Layer, LayerKind, OsvSetting, Switches};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

const NOW: &str = "2026-04-06T12:00:00Z";
const PUBLISHED: &str = "2026-01-01T00:00:00Z";
const LEFT_PAD: &str = "left-pad";
const OLD: &str = "1.0.0";
const NEW: &str = "1.3.0";
const FILENAME: &str = "left-pad-1.0.0.tgz";
const ALPHA: &str = "alpha";

/// Acme blocks nothing; Globex blocks `left-pad`.
const ACME: u32 = 10;
const GLOBEX: u32 = 20;

/// Globex's key and Acme's key.
fn key_a() -> String {
    key(1)
}
fn key_b() -> String {
    key(2)
}

fn bearer(key: &str) -> String {
    format!("Bearer {key}")
}

fn platform_layer() -> Layer {
    Layer {
        freeze_seconds: Some(86_400),
        osv: Some(OsvSetting::Off),
        allow: Switches::ALL,
        ..Layer::empty(LayerKind::Platform)
    }
}

fn org_blocking(blocks: Vec<Block>) -> Layer {
    Layer {
        blocks,
        ..Layer::empty(LayerKind::Org)
    }
}

fn package_block() -> Block {
    Block::Package {
        ecosystem: Ecosystem::Npm,
        name: LEFT_PAD.to_owned(),
        reason: None,
    }
}

fn npm_document() -> String {
    npm_document_of(LEFT_PAD)
}

fn npm_document_of(name: &str) -> String {
    let mut versions = Map::new();
    let mut time = Map::new();
    for version in [OLD, NEW] {
        versions.insert(
            version.to_owned(),
            json!({
                "name": name,
                "version": version,
                "dist": {"tarball": npm_tarball_url(name, &format!("{name}-{version}.tgz"))},
            }),
        );
        time.insert(version.to_owned(), json!(PUBLISHED));
    }
    json!({
        "name": name,
        "dist-tags": {"latest": NEW},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

fn pypi_document() -> String {
    let file = "alpha-1.0-py3-none-any.whl";
    json!({
        "meta": {"api-version": "1.1"},
        "name": ALPHA,
        "versions": [],
        "files": [{
            "filename": file,
            "url": format!("https://files.invalid/packages/ab/cd/{file}"),
            "hashes": {"sha256": "aa".repeat(32)},
            "upload-time": PUBLISHED,
        }],
    })
    .to_string()
}

struct Harness {
    server: TestServer,
    sync: FakeSyncServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    dir: tempfile::TempDir,
}

impl Harness {
    async fn get(&self, path: &str, key: &str) -> reqwest::Response {
        self.server
            .get_with_headers(path, &[("authorization", &bearer(key))])
            .await
    }

    async fn get_from(&self, from: IpAddr, path: &str, key: &str) -> reqwest::Response {
        client_from(from)
            .get(self.server.url(path))
            .header("authorization", bearer(key))
            .send()
            .await
            .expect("the request completes")
    }
}

/// A client whose connections leave from `from`, a loopback address of its own, so the
/// firewall sees a distinct peer.
fn client_from(from: IpAddr) -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .local_address(from)
        .build()
        .expect("a client")
}

fn loopback(a: u8, b: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, a, b))
}

/// A managed firewall with Acme and Globex on the fake server, `left-pad` and `alpha`
/// upstream.
async fn harness(globex: Vec<Block>, adjust: impl FnOnce(&mut Config)) -> Harness {
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), org_blocking(Vec::new()));
    sync.layer(org(GLOBEX), org_blocking(globex));
    sync.known_key(&key_a(), &[PLATFORM, org(GLOBEX)]);
    sync.known_key(&key_b(), &[PLATFORM, org(ACME)]);

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(LEFT_PAD),
        FakeAnswer::Body(npm_document()),
    );
    registry.answer(
        &pypi_upstream_path(ALPHA),
        FakeAnswer::Body(pypi_document()),
    );

    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    adjust(&mut config);
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;
    Harness {
        server,
        sync,
        registry,
        clock,
        dir,
    }
}

async fn assert_unauthenticated(response: reqwest::Response, what: &str) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{what}");
    let body = response.text().await.expect("a body");
    let value: Value = serde_json::from_str(&body).expect("a JSON body");
    assert_eq!(value["error"], "AUTHENTICATION_REQUIRED", "{what}: {body}");
    for name in ["Acme", "Globex", "acme", "globex"] {
        assert!(!body.contains(name), "{what}: no account is named: {body}");
    }
}

async fn assert_busy(response: reqwest::Response, what: &str) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{what}");
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("1"),
        "{what}"
    );
    assert_eq!(body_error(response).await, "LOOKUP_BUSY", "{what}");
}

async fn json_of(response: reqwest::Response) -> Value {
    let status = response.status();
    let text = response.text().await.expect("a body");
    assert!(status.is_success(), "answered {status}: {text}");
    serde_json::from_str(&text).expect("a JSON body")
}

fn versions_of(document: &Value) -> Vec<String> {
    let mut versions: Vec<String> = document["versions"]
        .as_object()
        .expect("a versions object")
        .keys()
        .cloned()
        .collect();
    versions.sort();
    versions
}

/// T-auth-missing-401 (C13): no header, an unparsable one, or a key without `prb_` is
/// refused with one fixed `401` and never looked up; routes that touch no package data
/// stay open.
#[tokio::test]
async fn t_auth_missing_401() {
    let h = harness(Vec::new(), |_| {}).await;

    assert_unauthenticated(h.server.get("/npm/left-pad").await, "no header").await;
    assert_unauthenticated(h.server.get("/pypi/simple/").await, "no header, index").await;
    assert_unauthenticated(
        h.server.get("/npm/left-pad/-/left-pad-1.0.0.tgz").await,
        "no header, tarball",
    )
    .await;
    for value in [
        "Token prb_00000000000000000000000000000001",
        "Bearer",
        "Bearer not-a-key",
        "Basic !!!not-base64",
    ] {
        let response = h
            .server
            .get_with_headers("/npm/left-pad", &[("authorization", value)])
            .await;
        assert_unauthenticated(response, value).await;
    }
    assert_eq!(h.sync.lookups(), 0, "nothing malformed is looked up");

    assert_eq!(h.server.status("/npm/-/ping").await, 200);
    assert_eq!(h.server.raw_get_status("/pypi/simple/left-pad").await, 301);
    assert_eq!(h.server.status("/health/live").await, 200);
    assert_eq!(
        h.server.status("/health/ready").await,
        200,
        "ready once the first sync is applied (C109)"
    );
}

/// T-auth-unknown-401 (C13): a well-formed key the server does not know, and a revoked
/// one, get the same `401` as a missing key.
#[tokio::test]
async fn t_auth_unknown_401() {
    let h = harness(Vec::new(), |_| {}).await;
    h.sync.revoked_key(&key(3), &[PLATFORM, org(ACME)]);

    h.sync.answer(
        &key(5),
        KeyLookup::Suspended {
            key_id: KeyId(5),
            place: org(ACME),
            place_chain: Vec::new(),
            revision: 1,
        },
    );

    // Each refusal is cached: the second try within the TTL asks nobody.
    for _ in 0..2 {
        assert_unauthenticated(h.get("/npm/left-pad", &key(99)).await, "unknown").await;
        assert_unauthenticated(h.get("/npm/left-pad", &key(3)).await, "revoked").await;
        assert_unauthenticated(h.get("/npm/left-pad", &key(5)).await, "suspended").await;
    }
    assert_eq!(h.sync.lookups(), 3, "one lookup each");

    // A chain whose layer is not the kind of its place cannot be resolved, so the key
    // is not served under some other policy.
    h.sync.layer(org(40), Layer::empty(LayerKind::Group));
    h.sync.known_key(&key(4), &[PLATFORM, org(40)]);
    assert_unauthenticated(h.get("/npm/left-pad", &key(4)).await, "inconsistent").await;

    // No answer from the server, and a server that refuses this firewall's token: a
    // key with no entry is refused.
    let mut unreachable = h.sync.management();
    unreachable.url = "http://127.0.0.1:1/".parse().unwrap();
    let mut wrong_token = h.sync.management();
    wrong_token.token = FirewallToken::new("fwt_not-this-firewall".to_owned());
    for (management, what) in [(unreachable, "unreachable"), (wrong_token, "token refused")] {
        let dir = tempfile::tempdir().expect("a directory");
        let mut config = config_with_open_blocklist(dir.path());
        config.management = Some(management);
        let clock = TestClock::at_rfc3339(NOW);
        let server = TestServer::start_with_upstream(
            config,
            clock.shared(),
            Arc::clone(&h.registry) as Arc<dyn Transport>,
            fake_origins(),
        )
        .await;
        let response = server
            .get_with_headers("/npm/left-pad", &[("authorization", &bearer(&key_b()))])
            .await;
        if what == "unreachable" {
            // It never applied a first sync, so it serves nothing (T1, C109).
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{what}");
            assert_eq!(body_error(response).await, "NOT_READY", "{what}");
        } else {
            assert_unauthenticated(response, what).await;
        }
    }
}

/// T-auth-basic (C34, T19): pip and uv send the key as a Basic password under any
/// username; an oversized header is refused before decoding, and a password that is not
/// a key is never looked up.
#[tokio::test]
async fn t_auth_basic() {
    let h = harness(vec![package_block()], |_| {}).await;
    for user in ["key", "__token__", ""] {
        let header = format!("Basic {}", base64(format!("{user}:{}", key_b())));
        let response = h
            .server
            .get_with_headers("/npm/left-pad", &[("authorization", &header)])
            .await;
        assert_eq!(response.status(), 200, "username {user:?}");
    }
    let header = format!("Basic {}", base64(format!("__token__:{}", key_a())));
    let response = h
        .server
        .get_with_headers("/npm/left-pad", &[("authorization", &header)])
        .await;
    assert_eq!(response.status(), 403, "decided under Globex's policy");
    assert_eq!(h.sync.lookups(), 2, "each key looked up once");

    let oversized = format!(
        "Basic {}",
        base64(format!("__token__:{}{}", key_b(), "x".repeat(1024)))
    );
    let response = h
        .server
        .get_with_headers("/npm/left-pad", &[("authorization", &oversized)])
        .await;
    assert_unauthenticated(response, "a header over 1 KiB").await;

    let header = format!("Basic {}", base64("__token__:hunter2"));
    let response = h
        .server
        .get_with_headers("/npm/left-pad", &[("authorization", &header)])
        .await;
    assert_unauthenticated(response, "a password that is not a key").await;
    assert_eq!(h.sync.lookups(), 2, "neither reached the server");

    // Two `Authorization` headers: the first is the one read.
    for (first, second, status) in [
        (
            bearer(&key_b()),
            "Bearer prb_not-a-known-key".to_owned(),
            200,
        ),
        (
            "Bearer prb_not-a-known-key".to_owned(),
            bearer(&key_b()),
            401,
        ),
    ] {
        let response = h
            .server
            .get_with_headers(
                "/npm/left-pad",
                &[("authorization", &first), ("authorization", &second)],
            )
            .await;
        assert_eq!(response.status(), status, "first {first:?}");
    }
}

/// T-auth-negative-cache (T10, C2, C120): unknown keys are cached for 30 s; lookups are
/// held to the firewall-wide budget with a share reserved for keys that have an entry,
/// and to each client's allowance; a valid key is told to retry (`503`), never `401`.
#[tokio::test]
async fn t_auth_negative_cache() {
    let h = harness(Vec::new(), |_| {}).await;

    // Five tries of one unknown key in 30 s: one lookup.
    for _ in 0..5 {
        assert_unauthenticated(h.get("/npm/left-pad", &key(500)).await, "unknown").await;
        h.clock.advance_seconds(5);
    }
    assert_eq!(h.sync.lookups(), 1);
    h.clock.advance_seconds(10);
    assert_unauthenticated(h.get("/npm/left-pad", &key(500)).await, "unknown").await;
    assert_eq!(h.sync.lookups(), 2, "asked again once the 30 s are up");

    // 200 distinct unknown keys in one second from 40 clients, then a new valid key.
    h.clock.advance_seconds(1);
    h.sync.known_key(&key(7), &[PLATFORM, org(ACME)]);
    let before = h.sync.lookups();
    let (unauthenticated, busy) = flood(&h, 1_000, 40, 5).await;
    let reached = h.sync.lookups() - before;
    assert!(reached <= 50, "{reached} lookups reached the server");
    assert_eq!(unauthenticated, reached, "only a looked-up key is refused");
    assert_eq!(busy, 200 - reached);
    let first = h.get_from(loopback(2, 1), "/npm/left-pad", &key(7)).await;
    assert_ne!(first.status(), 401, "a valid key is never told it is wrong");
    if first.status() != 200 {
        assert_busy(first, "the valid key during the flood").await;
        h.clock.advance_seconds(1);
        let retry = h.get_from(loopback(2, 1), "/npm/left-pad", &key(7)).await;
        assert_eq!(retry.status(), 200, "the retry a second later is served");
    }

    // The server's own 429, for a key with no entry: busy, not refused.
    h.clock.advance_seconds(1);
    h.sync
        .answer_lookups_with(Some(StatusCode::TOO_MANY_REQUESTS));
    assert_busy(h.get("/npm/left-pad", &key(8)).await, "lookup 429").await;
    h.sync.answer_lookups_with(None);

    // A 429 on `layers` for a place with no cached layer.
    h.sync.layer(org(30), org_blocking(Vec::new()));
    h.sync.known_key(&key(9), &[PLATFORM, org(30)]);
    h.sync
        .answer_layers_with(Some(StatusCode::TOO_MANY_REQUESTS));
    assert_busy(h.get("/npm/left-pad", &key(9)).await, "layers 429").await;
    h.sync.answer_layers_with(None);

    // A chain naming a newer layer than the server's answer holds: the key cannot be
    // checked yet, which is busy, never refused.
    h.sync.layer(org(31), org_blocking(Vec::new()));
    h.sync.answer(
        &key(11),
        KeyLookup::Known {
            key_id: KeyId(11),
            org: Some(OrgId(31)),
            account: org(31),
            place_chain: vec![
                ChainLink {
                    place: PLATFORM,
                    layer_revision: 1,
                },
                ChainLink {
                    place: org(31),
                    layer_revision: 5,
                },
            ],
            rate_limit: None,
            rate_limit_source: LimitSource::Default,
            revision: 5,
        },
    );
    assert_busy(h.get("/npm/left-pad", &key(11)).await, "an older layer").await;

    // A 10 s flood of distinct unknown keys while a known key's entry expires: its
    // re-lookup uses the reserved share.
    assert_eq!(h.get("/npm/left-pad", &key_b()).await.status(), 200);
    h.clock.advance_seconds(301);
    for second in 0..10u32 {
        h.clock.advance_seconds(1);
        let before = h.sync.lookups();
        flood(&h, 10_000 + second * 1_000, 40, 5).await;
        assert!(h.sync.lookups() - before <= 50);
        if second == 5 {
            let response = h.get("/npm/left-pad", &key_b()).await;
            assert_eq!(
                response.status(),
                200,
                "the expired entry is looked up again"
            );
        }
    }

    // A 10 s flood from one client while another client's new key arrives.
    for second in 0..10u32 {
        h.clock.advance_seconds(1);
        let before = h.sync.lookups();
        let (unauthenticated, busy) = flood(&h, 50_000 + second * 1_000, 1, 20).await;
        assert!(
            h.sync.lookups() - before <= 5,
            "the flooding client gets at most 5 lookups a second"
        );
        assert_eq!(
            (unauthenticated, busy),
            (h.sync.lookups() - before, 20 - unauthenticated)
        );
        let fresh = key(90_000 + second);
        h.sync.known_key(&fresh, &[PLATFORM, org(ACME)]);
        let response = h.get_from(loopback(3, 1), "/npm/left-pad", &fresh).await;
        assert_eq!(
            response.status(),
            200,
            "the other client's key, first request"
        );
    }
}

/// `clients` loopback clients each send `per_client` distinct unknown keys starting at
/// `from`. Returns the `401` and `503 LOOKUP_BUSY` counts; anything else fails.
async fn flood(h: &Harness, from: u32, clients: u8, per_client: u32) -> (usize, usize) {
    let mut unauthenticated = 0;
    let mut busy = 0;
    for client in 0..clients {
        let http = client_from(loopback(1, client + 1));
        for n in 0..per_client {
            let unknown = key(from + u32::from(client) * per_client + n);
            let response = http
                .get(h.server.url("/npm/left-pad"))
                .header("authorization", bearer(&unknown))
                .send()
                .await
                .expect("the request completes");
            match response.status().as_u16() {
                401 => unauthenticated += 1,
                503 => {
                    assert_busy(response, "a flooded lookup").await;
                    busy += 1;
                }
                other => panic!("an unknown key answered {other}"),
            }
        }
    }
    (unauthenticated, busy)
}

/// T-auth-single-flight (T10): a burst of 100 requests with one new key makes one
/// lookup, and every request is served.
#[tokio::test]
async fn t_auth_single_flight() {
    let h = harness(Vec::new(), |_| {}).await;
    // The listing is warm under Acme's policy, so the burst measures the lookup and not
    // a cold metadata fetch.
    assert_eq!(h.get("/npm/left-pad", &key_b()).await.status(), 200);
    let gate = h.sync.hold_lookups();
    let fresh = key(42);
    h.sync.known_key(&fresh, &[PLATFORM, org(ACME)]);

    let url = h.server.url("/npm/left-pad");
    let client = common::downstream_client();
    let requests: Vec<_> = (0..100)
        .map(|_| {
            let request = client
                .get(&url)
                .header("authorization", bearer(&fresh))
                .send();
            tokio::spawn(request)
        })
        .collect();
    gate.wait_until_reached().await;
    joined(&h, &fresh, 100).await;
    gate.release();
    for request in requests {
        let response = request
            .await
            .expect("joined")
            .expect("the request completes");
        let status = response.status();
        assert_eq!(status, 200, "{}", response.text().await.unwrap_or_default());
    }
    assert_eq!(
        h.sync.lookups(),
        2,
        "one for the warm-up key, one for the burst"
    );

    // The burst shares a refusal too: one lookup, every request told the same. An
    // unknown key is refused; the server's 429 is busy, never refused.
    for (status, answer) in [(401, None), (503, Some(StatusCode::TOO_MANY_REQUESTS))] {
        h.clock.advance_seconds(1);
        h.sync.answer_lookups_with(answer);
        let gate = h.sync.hold_lookups();
        let before = h.sync.lookups();
        let unknown = key(43 + status);
        let requests: Vec<_> = (0..50)
            .map(|_| {
                let request = client
                    .get(&url)
                    .header("authorization", bearer(&unknown))
                    .send();
                tokio::spawn(request)
            })
            .collect();
        gate.wait_until_reached().await;
        joined(&h, &unknown, 50).await;
        gate.release();
        for request in requests {
            let response = request
                .await
                .expect("joined")
                .expect("the request completes");
            assert_eq!(u32::from(response.status().as_u16()), status);
        }
        assert_eq!(h.sync.lookups() - before, 1, "one lookup for {status}");
    }
}

/// Waits until `count` requests share the lookup in flight for `key`.
async fn joined(h: &Harness, key: &str, count: usize) {
    let app = h.server.app();
    let hash = probation_policy::api::KeyHash::of(key);
    wait_until(
        &format!("{count} requests on one lookup"),
        Duration::from_secs(5),
        || app.managed().expect("managed").waiting_on(&hash) == count,
    )
    .await;
}

/// T-decide-per-key-policy (C8, W1): two keys on one firewall, one of whose policies
/// blocks `left-pad`. The decision record names the place and never the key.
#[tokio::test]
async fn t_decide_per_key_policy() {
    let log = tempfile::tempdir().expect("a log directory");
    let log_file = log.path().join("decisions.ndjson");
    let h = harness(vec![package_block()], |config| {
        config.log_file_path = Some(log_file.clone());
    })
    .await;

    let response = h.get("/npm/left-pad", &key_a()).await;
    assert_eq!(response.status(), 403);
    assert_eq!(body_error(response).await, "BLOCKED");
    assert_eq!(h.get("/npm/left-pad", &key_b()).await.status(), 200);
    let response = h.get("/npm/left-pad", &key_a()).await;
    assert_eq!(response.status(), 403, "and again, warm");

    wait_until("three decision records", Duration::from_secs(5), || {
        std::fs::read_to_string(&log_file).is_ok_and(|text| text.lines().count() >= 3)
    })
    .await;
    let text = std::fs::read_to_string(&log_file).expect("the decision log");
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("NDJSON"))
        .collect();
    assert_eq!(records[0]["place"], GLOBEX);
    assert_eq!(records[1]["place"], ACME);
    for secret in [key_a(), key_b()] {
        let hash: String = Sha256::digest(secret.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(!text.contains(&secret), "the key never reaches a record");
        assert!(!text.contains(&hash), "nor does its hash");
    }
}

/// T-cache-no-cross-policy-leak (C103, T8): two keys alternating on one listing each see
/// their own filtered document, cold and warm.
#[tokio::test]
async fn t_cache_no_cross_policy_leak() {
    let version_block = Block::Version {
        ecosystem: Ecosystem::Npm,
        name: LEFT_PAD.to_owned(),
        version: NEW.to_owned(),
        reason: None,
    };
    let h = harness(vec![version_block], |_| {}).await;
    for _ in 0..3 {
        let globex = json_of(h.get("/npm/left-pad", &key_a()).await).await;
        assert_eq!(versions_of(&globex), [OLD]);
        let acme = json_of(h.get("/npm/left-pad", &key_b()).await).await;
        assert_eq!(versions_of(&acme), [OLD, NEW]);
    }
}

/// T-download-per-waiter-decision (C104): A and B wait on one transfer of a tarball
/// whose computed SHA-256 A's policy blocks. Upstream is asked once; A is refused and
/// B is served.
#[tokio::test]
async fn t_download_per_waiter_decision() {
    let (head, tail) = ("first half of the tarball\n", "second half\n");
    let digest: String = Sha256::digest(format!("{head}{tail}").as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let file_block = Block::File {
        algorithm: DigestAlgorithm::Sha256,
        digest,
        reason: None,
    };
    let h = harness(vec![file_block], |_| {}).await;
    let gate = Gate::new();
    let tarball = npm_artifact_upstream_path(LEFT_PAD, FILENAME);
    h.registry.answer(
        &tarball,
        FakeAnswer::Gated {
            head: head.to_owned(),
            tail: tail.to_owned(),
            gate: Arc::clone(&gate),
        },
    );

    let listing = json_of(h.get("/npm/left-pad", &key_a()).await).await;
    let path = artifact_path(&listing, OLD);
    let id = path.split('/').nth(3).expect("a reference id");
    let id = ReferenceId::parse_hex(id).expect("a reference id");

    let client = common::downstream_client();
    let url = h.server.url(&path);
    let globex = tokio::spawn(
        client
            .get(&url)
            .header("authorization", bearer(&key_a()))
            .send(),
    );
    gate.wait_until_reached().await;
    let acme = tokio::spawn(
        client
            .get(&url)
            .header("authorization", bearer(&key_b()))
            .send(),
    );
    let app = h.server.app();
    wait_until(
        "both waiters on one transfer",
        Duration::from_secs(5),
        || app.downloads.waiting_on(&id) == 2,
    )
    .await;
    gate.release();

    let globex = globex.await.unwrap().expect("A's request completes");
    assert_eq!(globex.status(), 403);
    assert_eq!(body_error(globex).await, "BLOCKED");
    let acme = acme.await.unwrap().expect("B's request completes");
    assert_eq!(acme.status(), 200);
    assert_eq!(acme.text().await.unwrap(), format!("{head}{tail}"));
    let fetched = h
        .registry
        .calls()
        .iter()
        .filter(|url| url.path() == tarball)
        .count();
    assert_eq!(fetched, 1, "one upstream fetch");

    // SPEC §9: the digest A's policy blocks now hides the version from A's listing,
    // at once (no clock advance), while B still sees it.
    let globex = json_of(h.get("/npm/left-pad", &key_a()).await).await;
    assert_eq!(versions_of(&globex), [NEW], "the downloader's listing");
    let acme = json_of(h.get("/npm/left-pad", &key_b()).await).await;
    assert_eq!(versions_of(&acme), [OLD, NEW]);

    // The same when B downloads first and A is refused from disk afterwards.
    let file_block = Block::File {
        algorithm: DigestAlgorithm::Sha256,
        digest: hex(&Sha256::digest(format!("{head}{tail}").as_bytes())),
        reason: None,
    };
    let h = harness(vec![file_block], |_| {}).await;
    h.registry
        .answer(&tarball, FakeAnswer::Body(format!("{head}{tail}")));
    let globex = json_of(h.get("/npm/left-pad", &key_a()).await).await;
    assert_eq!(versions_of(&globex), [OLD, NEW], "no digest is known yet");
    let path = artifact_path(&globex, OLD);
    assert_eq!(h.get(&path, &key_b()).await.status(), 200);
    assert_eq!(
        h.get(&path, &key_a()).await.status(),
        403,
        "refused from disk"
    );
    let globex = json_of(h.get("/npm/left-pad", &key_a()).await).await;
    assert_eq!(versions_of(&globex), [NEW], "a later key's listing");

    refresh_never_carries_pins_older_than_its_generation().await;
}

/// D1: a metadata refresh whose snapshot reads its pins before another request's pin,
/// digest-generation bump and cache drop land, and commits after them, would carry the
/// new generation with the old pins, and A's listing would show what A's policy blocks
/// until the metadata TTL. The refresh is held just before its commit while B's
/// transfer steps (pin, bump, drop, as `artifacts::download::transfer` takes them in
/// managed mode) land; a real download would join the held refresh instead. Pins read
/// after the commit are never older than its generation, so A's listing hides it.
async fn refresh_never_carries_pins_older_than_its_generation() {
    use probation::store::cache::ProjectKey;
    use sha2::Sha512;

    let tarball = "racy tarball bytes\n";
    let wheel = "racy wheel bytes\n";
    let globex = vec![
        Block::File {
            algorithm: DigestAlgorithm::Sha256,
            digest: hex(&Sha256::digest(tarball.as_bytes())),
            reason: None,
        },
        // PyPI advertises the SHA-256, so the computed one is the SHA-512.
        Block::File {
            algorithm: DigestAlgorithm::Sha512,
            digest: hex(&Sha512::digest(wheel.as_bytes())),
            reason: None,
        },
    ];
    let h = harness(globex, |_| {}).await;
    let pypi_files = |name: &str| {
        let files: Vec<Value> = [OLD, NEW]
            .iter()
            .map(|version| {
                let file = format!("racy_alpha-{version}-py3-none-any.whl");
                json!({
                    "filename": file,
                    "url": format!("https://files.invalid/packages/ab/cd/{file}"),
                    "hashes": {"sha256": "aa".repeat(32)},
                    "upload-time": PUBLISHED,
                })
            })
            .collect();
        json!({
            "meta": {"api-version": "1.1"},
            "name": name,
            "versions": [],
            "files": files,
        })
        .to_string()
    };
    h.registry.answer(
        &npm_upstream_path("racy-widget"),
        FakeAnswer::Body(npm_document_of("racy-widget")),
    );
    h.registry.answer(
        &pypi_upstream_path("racy-alpha"),
        FakeAnswer::Body(pypi_files("racy-alpha")),
    );
    let json = ("accept", "application/vnd.pypi.simple.v1+json");
    let pypi = async |key: &str| {
        let auth = bearer(key);
        let response = h
            .server
            .get_with_headers(
                "/pypi/simple/racy-alpha/",
                &[json, ("authorization", &auth)],
            )
            .await;
        json_of(response).await
    };
    let listed = |listing: &Value| -> Vec<String> {
        listing["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|file| file["filename"].as_str().expect("a filename").to_owned())
            .collect()
    };

    let npm = json_of(h.get("/npm/racy-widget", &key_a()).await).await;
    let npm_id = artifact_path(&npm, OLD);
    let npm_id = ReferenceId::parse_hex(npm_id.split('/').nth(3).unwrap()).unwrap();
    let pypi_listing = pypi(&key_a()).await;
    assert_eq!(listed(&pypi_listing).len(), 2);
    let wheel_url = pypi_listing["files"][0]["url"].as_str().expect("a URL");
    let pypi_id = ReferenceId::parse_hex(wheel_url.split('/').nth_back(1).unwrap()).unwrap();

    for (ecosystem, name, id, bytes) in [
        (Ecosystem::Npm, "racy-widget", npm_id, tarball),
        (Ecosystem::PyPi, "racy-alpha", pypi_id, wheel),
    ] {
        // The metadata TTL ends, so A's next listing refreshes the project.
        h.clock.advance_seconds(301);
        let pause = probation::pause::arm("before refresh commit", name);
        let listing = tokio::spawn({
            let client = common::downstream_client();
            let auth = bearer(&key_a());
            let url = match ecosystem {
                Ecosystem::Npm => h.server.url("/npm/racy-widget"),
                Ecosystem::PyPi => h.server.url("/pypi/simple/racy-alpha/"),
            };
            client
                .get(url)
                .header("authorization", auth)
                .header(json.0, json.1)
                .send()
        });
        tokio::time::timeout(Duration::from_secs(5), pause.reached())
            .await
            .expect("A's refresh reaches the point before its commit");

        let app = h.server.app();
        let store = app.store();
        let sha256: [u8; 32] = Sha256::digest(bytes.as_bytes()).into();
        let sha512: [u8; 64] = Sha512::digest(bytes.as_bytes()).into();
        store
            .pin_computed_digests(id, sha256, sha512, bytes.len() as u64)
            .await
            .expect("B's pin");
        store
            .bump_digest_generation(ecosystem, name)
            .await
            .expect("B's bump");
        store
            .caches()
            .projects
            .remove(&ProjectKey::new(ecosystem, name));
        pause.release();

        let listing = json_of(listing.await.unwrap().expect("A's listing")).await;
        let again = match ecosystem {
            Ecosystem::Npm => {
                assert_eq!(versions_of(&listing), [NEW], "the refreshed npm listing");
                json_of(h.get("/npm/racy-widget", &key_a()).await).await
            }
            Ecosystem::PyPi => {
                assert_eq!(listed(&listing).len(), 1, "the refreshed PyPI listing");
                pypi(&key_a()).await
            }
        };
        match ecosystem {
            Ecosystem::Npm => assert_eq!(versions_of(&again), [NEW], "and the next one"),
            Ecosystem::PyPi => assert_eq!(listed(&again).len(), 1, "and the next one"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// T-config-management-required (T20): a broken `[management]` section is a
/// configuration error naming the key, so the firewall never starts standalone.
#[test]
fn t_config_management_required() {
    let sample = std::fs::read_to_string("config.sample.toml").expect("the sample");
    let dir = tempfile::tempdir().expect("a directory");
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "fwt_secret\n").expect("the token file");

    let with = |section: &str| Config::from_toml_str(&format!("{sample}\n[management]\n{section}"));
    let error = |section: &str| with(section).expect_err(section).to_string();

    assert!(
        error("url = \"https://sync.example\"").contains("management.token_file"),
        "a missing token_file is named"
    );
    let missing = dir.path().join("absent");
    assert!(
        error(&format!(
            "url = \"https://sync.example\"\ntoken_file = {missing:?}"
        ))
        .contains("management.token_file"),
        "an unreadable token file is named"
    );
    assert!(
        error(&format!(
            "url = \"http://sync.example\"\ntoken_file = {token_file:?}"
        ))
        .contains("management.url"),
        "an http url is named"
    );
    assert!(
        error(&format!("token_file = {token_file:?}")).contains("management.url"),
        "a missing url is named"
    );
    // A token goes into an HTTP header: only visible ASCII, once trimmed.
    for (n, token) in ["a\nb", "a\rb", "a\x7f", "a b"].iter().enumerate() {
        let file = dir.path().join(format!("bad-token-{n}"));
        std::fs::write(&file, token).expect("a token file");
        assert!(
            error(&format!(
                "url = \"https://sync.example\"\ntoken_file = {file:?}"
            ))
            .contains("management.token_file"),
            "the token {token:?} is refused"
        );
    }
    let interval = Config::from_toml_str(&format!(
        "sync_interval_seconds = 9223372036854775807\n{sample}\n[management]\nurl = \"https://sync.example\"\ntoken_file = {token_file:?}"
    ))
    .expect_err("an interval no clock can hold")
    .to_string();
    assert!(interval.contains("sync_interval_seconds"), "{interval}");

    let empty = dir.path().join("empty");
    std::fs::write(&empty, "\n").expect("an empty token file");
    let whole = format!("url = \"https://sync.example/base\"\ntoken_file = {token_file:?}");
    for (section, key) in [
        (
            format!("url = \"https://sync.example\"\ntoken_file = {empty:?}"),
            "management.token_file",
        ),
        (
            format!("url = \"not a url\"\ntoken_file = {token_file:?}"),
            "management.url",
        ),
        (
            format!("url = \"https://u:p@sync.example\"\ntoken_file = {token_file:?}"),
            "management.url",
        ),
        (
            format!("{whole}\nkey_cache_ttl_seconds = 0"),
            "management.key_cache_ttl_seconds",
        ),
        (
            format!("{whole}\nkey_cache_max_entries = 0"),
            "management.key_cache_max_entries",
        ),
        (
            format!("{whole}\nlookup_budget_per_second = 0"),
            "management.lookup_budget_per_second",
        ),
        (
            format!("{whole}\nsync_margin_seconds = 31"),
            "management.sync_margin_seconds",
        ),
        (
            format!("{whole}\nrequest_timeout_seconds = 6"),
            "management.request_timeout_seconds",
        ),
        (
            format!("{whole}\ntrusted_proxies = [\"10.0.0.0/33\"]"),
            "management.trusted_proxies",
        ),
        (
            format!("{whole}\ntrusted_proxies = [\"10.0.0.0\"]"),
            "management.trusted_proxies",
        ),
        // C34: https only, loopback included.
        (
            format!("url = \"http://localhost:1\"\ntoken_file = {token_file:?}"),
            "management.url",
        ),
        (
            format!("url = \"http://127.0.0.1:1\"\ntoken_file = {token_file:?}"),
            "management.url",
        ),
        // A duration that cannot be added to a clock reading is refused, not a panic.
        (
            format!("{whole}\nkey_cache_ttl_seconds = 9223372036854775807"),
            "management.key_cache_ttl_seconds",
        ),
    ] {
        assert!(
            error(&section).contains(key),
            "{key} is named for {section}"
        );
    }
    assert!(
        error(&format!("{whole}\nunknown_key = 1")).contains("unknown_key"),
        "an unknown key in the section is refused"
    );
    let proxies = with(&format!(
        "{whole}\ntrusted_proxies = [\"10.0.0.0/8\", \"2001:db8::/32\"]"
    ))
    .expect("two ranges");
    assert_eq!(
        proxies.management.expect("managed").trusted_proxies.len(),
        2
    );

    let config = with(&format!(
        "url = \"https://sync.example\"\ntoken_file = {token_file:?}"
    ))
    .expect("a whole section");
    let management = config.management.expect("managed mode");
    assert_eq!(management.key_cache_ttl_seconds.get(), 300);
    assert_eq!(management.lookup_budget_per_second.get(), 50);
    assert_eq!(management.client_lookup_allowance_per_second.get(), 5);
    assert_eq!(management.request_timeout_seconds.get(), 2);
    assert_eq!(config.sync_interval_seconds.get(), 60);
    assert!(
        !format!("{management:?}").contains("fwt_secret"),
        "the token never reaches a printed configuration"
    );
}

/// T-pypi-root-index-empty (T8, C1): in managed mode the root index lists no project,
/// whoever fetched what; standalone still lists what was fetched.
#[tokio::test]
async fn t_pypi_root_index_empty() {
    let h = harness(Vec::new(), |_| {}).await;
    let json = [("accept", "application/vnd.pypi.simple.v1+json")];
    for key in [key_a(), key_b()] {
        let auth = bearer(&key);
        let headers = [json[0], ("authorization", auth.as_str())];
        let response = h
            .server
            .get_with_headers("/pypi/simple/alpha/", &headers)
            .await;
        assert_eq!(response.status(), 200);
        let index = json_of(h.server.get_with_headers("/pypi/simple/", &headers).await).await;
        assert_eq!(index["projects"], json!([]), "{index}");
        let html = h
            .server
            .get_with_headers("/pypi/simple/", &[("authorization", auth.as_str())])
            .await;
        assert_eq!(html.status(), 200);
        let html = html.text().await.expect("an HTML index");
        assert!(html.contains("<html") && !html.contains(ALPHA), "{html}");
    }

    let standalone = TestServer::start_with_upstream(
        config_with_open_blocklist(h.dir.path()),
        h.clock.shared(),
        Arc::clone(&h.registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;
    let response = standalone
        .get_with_headers("/pypi/simple/alpha/", &json)
        .await;
    assert_eq!(response.status(), 200);
    let index = json_of(standalone.get_with_headers("/pypi/simple/", &json).await).await;
    assert_eq!(index["projects"], json!([{"name": ALPHA}]));
}
