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
                Ecosystem::RubyGems => unreachable!("this race loops npm and PyPI only"),
                Ecosystem::Cargo => unreachable!(
                    "this matrix loops npm and PyPI only; Cargo is covered in tests/cargo_registry.rs"
                ),
                Ecosystem::Go => unreachable!(
                    "this matrix loops npm and PyPI only; Go is covered in tests/go_modules.rs"
                ),
                Ecosystem::NuGet => unreachable!(
                    "this matrix loops npm and PyPI only; NuGet is covered in tests/nuget_registry.rs"
                ),
                Ecosystem::Maven => unreachable!(
                    "this matrix loops npm and PyPI only; Maven is covered in tests/maven_registry.rs"
                ),
                Ecosystem::Conan => unreachable!(
                    "this matrix loops npm and PyPI only; Conan is covered in tests/conan_registry.rs"
                ),
                Ecosystem::Oci => unreachable!(
                    "this matrix loops npm and PyPI only; OCI is covered in tests/oci_registry.rs"
                ),
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
            Ecosystem::RubyGems => unreachable!("this race loops npm and PyPI only"),
            Ecosystem::Cargo => unreachable!(
                "this matrix loops npm and PyPI only; Cargo is covered in tests/cargo_registry.rs"
            ),
            Ecosystem::Go => unreachable!(
                "this matrix loops npm and PyPI only; Go is covered in tests/go_modules.rs"
            ),
            Ecosystem::NuGet => unreachable!(
                "this matrix loops npm and PyPI only; NuGet is covered in tests/nuget_registry.rs"
            ),
            Ecosystem::Maven => unreachable!(
                "this matrix loops npm and PyPI only; Maven is covered in tests/maven_registry.rs"
            ),
            Ecosystem::Conan => unreachable!(
                "this matrix loops npm and PyPI only; Conan is covered in tests/conan_registry.rs"
            ),
            Ecosystem::Oci => unreachable!(
                "this matrix loops npm and PyPI only; OCI is covered in tests/oci_registry.rs"
            ),
        };
        match ecosystem {
            Ecosystem::Npm => assert_eq!(versions_of(&again), [NEW], "and the next one"),
            Ecosystem::PyPi => assert_eq!(listed(&again).len(), 1, "and the next one"),
            Ecosystem::RubyGems => unreachable!("this race loops npm and PyPI only"),
            Ecosystem::Cargo => unreachable!(
                "this matrix loops npm and PyPI only; Cargo is covered in tests/cargo_registry.rs"
            ),
            Ecosystem::Go => unreachable!(
                "this matrix loops npm and PyPI only; Go is covered in tests/go_modules.rs"
            ),
            Ecosystem::NuGet => unreachable!(
                "this matrix loops npm and PyPI only; NuGet is covered in tests/nuget_registry.rs"
            ),
            Ecosystem::Maven => unreachable!(
                "this matrix loops npm and PyPI only; Maven is covered in tests/maven_registry.rs"
            ),
            Ecosystem::Conan => unreachable!(
                "this matrix loops npm and PyPI only; Conan is covered in tests/conan_registry.rs"
            ),
            Ecosystem::Oci => unreachable!(
                "this matrix loops npm and PyPI only; OCI is covered in tests/oci_registry.rs"
            ),
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

    // The sample's commented-out `[management]` section, uncommented, is a whole
    // managed configuration with the documented defaults (S2-8).
    let (_, commented) = sample
        .split_once("\n# [management]\n")
        .expect("the sample carries a commented [management] section");
    let mut uncommented = String::from("[management]\n");
    for line in commented.lines() {
        match line.strip_prefix("# ") {
            Some(setting) if setting.contains(" = ") => {
                let setting = if setting.starts_with("token_file") {
                    format!("token_file = {token_file:?}")
                } else {
                    setting.to_owned()
                };
                uncommented.push_str(&setting);
                uncommented.push('\n');
            }
            _ => {}
        }
    }
    let sample_managed = Config::from_toml_str(&format!("{sample}\n{uncommented}"))
        .unwrap_or_else(|err| panic!("{uncommented}: {err}"));
    let management = sample_managed.management.expect("managed mode");
    assert_eq!(management.url.as_str(), "https://manage.example.org/");
    assert_eq!(management.key_cache_ttl_seconds.get(), 300);
    assert_eq!(management.client_lookup_allowance_per_second.get(), 5);
    assert!(management.trusted_proxies.is_empty());
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

/// Row 17 (CR F4): in managed mode a RubyGems `/info` listing with nothing left is the family's
/// refusal and leaves one decision record with no version, as a refused PyPI listing does; a key
/// whose policy keeps a line is served it and leaves none; and the refused key sees an empty index.
#[tokio::test]
async fn rubygems_fully_refused_listing_records_one_decision() {
    let gem = "gemx";
    let h = harness(
        vec![Block::Package {
            ecosystem: Ecosystem::RubyGems,
            name: gem.to_owned(),
            reason: None,
        }],
        |_| {},
    )
    .await;
    let path = fake_origins()
        .url_for(
            probation::upstream::OriginKind::RubygemsMetadata,
            &["info", gem],
        )
        .unwrap()
        .path()
        .to_owned();
    h.registry.answer(
        &path,
        FakeAnswer::Body(format!(
            "---\n1.0.0 |checksum:{},created_at:2025-01-01T00:00:00Z\n",
            "ab".repeat(32)
        )),
    );
    let refused = h.get(&format!("/rubygems/info/{gem}"), &key_a()).await;
    assert_eq!(refused.status(), StatusCode::OK);
    assert_eq!(
        refused.text().await.unwrap(),
        "---\n",
        "Globex blocks the gem"
    );
    let served = h.get(&format!("/rubygems/info/{gem}"), &key_b()).await;
    assert!(
        served.text().await.unwrap().contains("1.0.0"),
        "Acme's policy keeps the line"
    );
    // The queue is read directly: no sync round is needed to see what the request recorded.
    let batch = h.server.app().managed().unwrap().activity().take_batch();
    let events: Vec<_> = batch
        .events
        .iter()
        .map(|q| &q.event)
        .filter(|e| e.ecosystem == Some(Ecosystem::RubyGems))
        .collect();
    assert_eq!(events.len(), 1, "{events:#?}");
    assert_eq!(
        (events[0].package.as_deref(), events[0].version.as_deref()),
        (Some(gem), None)
    );
    h.server.shutdown().await;
}

/// Row 18: a managed firewall authenticates every Cargo read, so it tells Cargo to send its token
/// (`auth-required` in the rewritten `config.json`) and answers an unauthenticated read with the
/// `Cargo login_url` challenge besides Basic, which is what makes `cargo` fetch its token and retry.
#[tokio::test]
async fn cargo_key_route_challenges_and_advertises_auth_required() {
    let h = harness(vec![], |_| {}).await;
    let path = |segments: &[&str]| {
        fake_origins()
            .url_for(probation::upstream::OriginKind::CargoIndex, segments)
            .unwrap()
            .path()
            .to_owned()
    };
    h.registry.answer(
        &path(&["config.json"]),
        FakeAnswer::Body(r#"{"dl":"https://static.crates.io/crates"}"#.to_owned()),
    );
    let anonymous = h.server.get("/cargo/config.json").await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let challenges: Vec<String> = anonymous
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(
        challenges.iter().any(|c| c.starts_with("Basic "))
            && challenges
                .iter()
                .any(|c| c.starts_with("Cargo login_url=\"")),
        "{challenges:?}"
    );
    let download = h.server.get("/cargo/crates/demo/1.0.0/download").await;
    assert_eq!(download.status(), StatusCode::UNAUTHORIZED);
    assert!(
        download
            .headers()
            .get_all("www-authenticate")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("Cargo "))
    );
    let served = h.get("/cargo/config.json", &key_a()).await;
    assert_eq!(served.status(), StatusCode::OK);
    let config: Value = serde_json::from_slice(&served.bytes().await.unwrap()).unwrap();
    assert_eq!(
        config["auth-required"], true,
        "cargo sends its token only to a registry that says so"
    );
    assert_eq!(
        h.get("/cargo/config.json", "prb_not_a_known_key_0123456789ab")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    h.server.shutdown().await;
}

/// Row 18 (the family's version of slice 17's F4): a Cargo index with nothing left for a key is the
/// family's refusal and leaves one decision record with no version; a key that keeps a line is served
/// it and leaves none.
#[tokio::test]
async fn cargo_fully_refused_listing_records_one_decision() {
    let krate = "cratex";
    let h = harness(
        vec![Block::Package {
            ecosystem: Ecosystem::Cargo,
            name: krate.to_owned(),
            reason: None,
        }],
        |_| {},
    )
    .await;
    let path = |segments: &[&str]| {
        fake_origins()
            .url_for(probation::upstream::OriginKind::CargoIndex, segments)
            .unwrap()
            .path()
            .to_owned()
    };
    h.registry.answer(
        &path(&["config.json"]),
        FakeAnswer::Body(r#"{"dl":"https://static.crates.io/crates"}"#.to_owned()),
    );
    let line = format!(
        r#"{{"name":"{krate}","vers":"1.0.0","deps":[],"cksum":"{}","features":{{}},"yanked":false,"pubtime":"2025-01-01T00:00:00Z"}}"#,
        "ab".repeat(32)
    );
    h.registry.answer(
        &path(&["cr", "at", krate]),
        FakeAnswer::Body(format!("{line}\n")),
    );
    let refused = h.get(&format!("/cargo/cr/at/{krate}"), &key_a()).await;
    assert_eq!(refused.status(), StatusCode::OK);
    assert_eq!(refused.text().await.unwrap(), "", "Globex blocks the crate");
    let served = h.get(&format!("/cargo/cr/at/{krate}"), &key_b()).await;
    assert_eq!(
        served.text().await.unwrap(),
        format!("{line}\n"),
        "Acme's policy keeps the line"
    );
    let batch = h.server.app().managed().unwrap().activity().take_batch();
    let events: Vec<_> = batch
        .events
        .iter()
        .map(|q| &q.event)
        .filter(|e| e.ecosystem == Some(Ecosystem::Cargo))
        .collect();
    assert_eq!(events.len(), 1, "{events:#?}");
    assert_eq!(
        (events[0].package.as_deref(), events[0].version.as_deref()),
        (Some(krate), None)
    );
    h.server.shutdown().await;
}

/// Row 19: a managed firewall authenticates every Go read with the key (Basic from the GOPROXY URL's
/// userinfo or `.netrc`), refuses an unknown key with the same 401, and the key's policy decides: one
/// organisation's block refuses the module for its keys and leaves another's served. The refusal is
/// local (no upstream call) and leaves one decision record.
#[tokio::test]
async fn go_key_route_authenticates_every_read_and_refuses_a_blocked_module_locally() {
    let module = "example.com/gox";
    let h = harness(
        vec![Block::Package {
            ecosystem: Ecosystem::Go,
            name: module.to_owned(),
            reason: None,
        }],
        |_| {},
    )
    .await;
    let path = |tail: &str| {
        let mut segments: Vec<&str> = module.split('/').collect();
        segments.extend(tail.split('/'));
        fake_origins()
            .url_for(probation::upstream::OriginKind::GoProxy, &segments)
            .unwrap()
            .path()
            .to_owned()
    };
    h.registry
        .answer(&path("@v/list"), FakeAnswer::Body("v1.0.0\n".to_owned()));
    h.registry.answer(
        &path("@v/v1.0.0.info"),
        FakeAnswer::Body(r#"{"Version":"v1.0.0","Time":"2025-01-01T00:00:00Z"}"#.to_owned()),
    );
    for tail in ["@v/list", "@latest", "@v/v1.0.0.info", "@v/v1.0.0.zip"] {
        let anonymous = h.server.get(&format!("/go/{module}/{tail}")).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED, "{tail}");
    }
    assert_eq!(
        h.get(
            &format!("/go/{module}/@v/list"),
            "prb_not_a_known_key_0123456789ab"
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        h.registry.calls().is_empty(),
        "no upstream call before authentication"
    );
    let refused = h.get(&format!("/go/{module}/@v/list"), &key_a()).await;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "Globex blocks the module"
    );
    assert!(
        h.registry.calls().is_empty(),
        "a blocked module reaches no upstream call"
    );
    let served = h.get(&format!("/go/{module}/@v/list"), &key_b()).await;
    assert_eq!(
        served.text().await.unwrap(),
        "v1.0.0\n",
        "Acme's policy keeps the version"
    );
    let batch = h.server.app().managed().unwrap().activity().take_batch();
    let events: Vec<_> = batch
        .events
        .iter()
        .map(|q| &q.event)
        .filter(|e| e.ecosystem == Some(Ecosystem::Go))
        .collect();
    assert_eq!(events.len(), 1, "{events:#?}");
    assert_eq!(
        (events[0].package.as_deref(), events[0].version.as_deref()),
        (Some(module), None)
    );
    h.server.shutdown().await;
}

/// Row 20: a managed firewall authenticates every NuGet read with the key (Basic from `packageSourceCredentials`),
/// refuses an unknown key with the same 401, and the key's policy decides: one organisation's block (written in
/// mixed case, as an operator types it) refuses the id for its keys and leaves another's served. The refusal is
/// local (no upstream call) and leaves one decision record.
#[tokio::test]
async fn nuget_key_route_authenticates_every_read_and_refuses_a_blocked_package_locally() {
    let h = harness(
        vec![Block::Package {
            ecosystem: Ecosystem::NuGet,
            name: "Evil.Pkg".to_owned(),
            reason: None,
        }],
        |_| {},
    )
    .await;
    let index = serde_json::json!({"version": "3.0.0", "resources": [
        {"@id": "https://api.nuget.org/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"},
        {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/", "@type": "RegistrationsBaseUrl/Versioned"},
    ]});
    h.registry
        .answer("/v3/index.json", FakeAnswer::Body(index.to_string()));
    h.registry.answer(
        "/v3-flatcontainer/evil.pkg/index.json",
        FakeAnswer::Body(r#"{"versions":["1.0.0"]}"#.to_owned()),
    );
    let (registration, _) = common::nuget::registration(
        "evil.pkg",
        &[vec![common::nuget::leaf(
            "evil.pkg",
            "1.0.0",
            Some("2025-01-01T00:00:00.000+00:00"),
            true,
        )]],
        &[],
    );
    h.registry.answer(
        "/v3/registration5-gz-semver2/evil.pkg/index.json",
        FakeAnswer::Body(registration),
    );
    for path in [
        "/nuget/v3/index.json",
        "/nuget/v3-flatcontainer/evil.pkg/index.json",
        "/nuget/v3/registration/evil.pkg/index.json",
        "/nuget/v3-flatcontainer/evil.pkg/1.0.0/evil.pkg.1.0.0.nupkg",
        "/nuget/v3/query?q=x",
    ] {
        assert_eq!(
            h.server.get(path).await.status(),
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(
        h.get(
            "/nuget/v3-flatcontainer/evil.pkg/index.json",
            "prb_not_a_known_key_0123456789ab"
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        h.registry.calls().is_empty(),
        "no upstream call before authentication"
    );
    for path in [
        "/nuget/v3-flatcontainer/evil.pkg/index.json",
        "/nuget/v3/registration/evil.pkg/index.json",
        "/nuget/v3-flatcontainer/evil.pkg/1.0.0/evil.pkg.1.0.0.nupkg",
    ] {
        assert_eq!(
            h.get(path, &key_a()).await.status(),
            StatusCode::FORBIDDEN,
            "Globex blocks the id: {path}"
        );
    }
    assert!(
        h.registry.calls().is_empty(),
        "a blocked id reaches no upstream call"
    );
    assert_eq!(
        h.get("/nuget/v3-flatcontainer/evil.pkg/index.json", &key_b())
            .await
            .text()
            .await
            .unwrap(),
        r#"{"versions":["1.0.0"]}"#,
        "Acme's policy keeps the version"
    );
    // The key route serves no publish endpoint: a managed firewall forwards no writes.
    let put = reqwest::Client::new()
        .put(h.server.url("/nuget/api/v2/package"))
        .header("x-nuget-apikey", "k")
        .body("x")
        .send()
        .await
        .unwrap();
    assert!(
        matches!(put.status().as_u16(), 404 | 405),
        "{}",
        put.status()
    );
    let batch = h.server.app().managed().unwrap().activity().take_batch();
    let events: Vec<_> = batch
        .events
        .iter()
        .map(|q| &q.event)
        .filter(|e| e.ecosystem == Some(Ecosystem::NuGet))
        .collect();
    assert_eq!(
        events.len(),
        3,
        "one decision record per refusal: {events:#?}"
    );
    assert!(
        events
            .iter()
            .all(|e| e.package.as_deref() == Some("evil.pkg")),
        "{events:#?}"
    );
    h.server.shutdown().await;
}

/// Row 21: a managed firewall authenticates every Maven read with the key (the Basic password of `settings.xml`, or a
/// Bearer), refuses an unknown key with the same 401, and the key's policy decides: one organisation's block refuses the
/// coordinate for its keys (case-exact) and leaves another's served. The refusal is local (no upstream call) and leaves one
/// decision record per refusal; the key route serves no deploy endpoint.
#[tokio::test]
async fn maven_key_route_authenticates_every_read_and_refuses_a_blocked_coordinate_locally() {
    let h = harness(
        vec![Block::Package {
            ecosystem: Ecosystem::Maven,
            name: "org.evil:Bad".to_owned(),
            reason: None,
        }],
        |_| {},
    )
    .await;
    h.registry.answer(
        "/maven2/org/evil/Bad/maven-metadata.xml",
        FakeAnswer::Body(common::maven::metadata(
            "org.evil",
            "Bad",
            "1.0",
            "1.0",
            &["1.0"],
        )),
    );
    h.registry.answer(
        "/maven2/org/evil/Bad/1.0/Bad-1.0.pom",
        FakeAnswer::Dated {
            body: common::maven::pom("org.evil", "Bad", "1.0").into_bytes(),
            last_modified: common::maven::http_date("2025-01-01T00:00:00Z"),
        },
    );
    h.registry.answer(
        "/maven2/org/evil/Bad/1.0/Bad-1.0.jar",
        FakeAnswer::Dated {
            body: common::maven::jar("Bad", "1.0"),
            last_modified: common::maven::http_date("2025-01-01T00:00:00Z"),
        },
    );
    let paths = [
        "/maven/org/evil/Bad/maven-metadata.xml",
        "/maven/org/evil/Bad/maven-metadata.xml.sha1",
        "/maven/org/evil/Bad/1.0/Bad-1.0.jar",
        "/maven/org/evil/Bad/1.0/Bad-1.0.pom.sha1",
    ];
    for path in paths {
        assert_eq!(
            h.server.get(path).await.status(),
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(
        h.get(paths[0], "prb_not_a_known_key_0123456789ab")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        h.registry.calls().is_empty(),
        "no upstream call before authentication"
    );
    for path in paths {
        assert_eq!(
            h.get(path, &key_a()).await.status(),
            StatusCode::FORBIDDEN,
            "Globex blocks the coordinate: {path}"
        );
    }
    assert!(
        h.registry.calls().is_empty(),
        "a blocked coordinate reaches no upstream call"
    );
    let served = h
        .get("/maven/org/evil/Bad/maven-metadata.xml", &key_b())
        .await;
    assert_eq!(
        served.status(),
        StatusCode::OK,
        "Acme's policy keeps the version"
    );
    assert!(
        served
            .text()
            .await
            .unwrap()
            .contains("<version>1.0</version>")
    );
    assert_eq!(
        h.get("/maven/org/evil/Bad/1.0/Bad-1.0.jar", &key_b())
            .await
            .status(),
        StatusCode::OK
    );
    let put = reqwest::Client::new()
        .put(h.server.url("/maven/org/evil/Bad/1.0/Bad-1.0.jar"))
        .header("authorization", "Basic dTpw")
        .body("x")
        .send()
        .await
        .unwrap();
    assert!(
        matches!(put.status().as_u16(), 404 | 405),
        "{}",
        put.status()
    );
    let batch = h.server.app().managed().unwrap().activity().take_batch();
    let events: Vec<_> = batch
        .events
        .iter()
        .map(|q| &q.event)
        .filter(|e| e.ecosystem == Some(Ecosystem::Maven))
        .collect();
    assert_eq!(
        events.len(),
        4,
        "one decision record per refusal: {events:#?}"
    );
    assert!(
        events
            .iter()
            .all(|e| e.package.as_deref() == Some("org.evil:Bad")),
        "{events:#?}"
    );
    h.server.shutdown().await;
}

/// Row 19 fix round: a policy publication (any sync that changed anything, even an unrelated key) between a request's
/// authorisation and its release refuses the finished response (SPEC §9). A Go client does not retry a 503 and a
/// `go get` is many tiny requests, so the Go route admits the request again instead: the new policy then decides it
/// (served when it still allows it) and a change that keeps landing is reported after three admissions.
#[tokio::test]
async fn go_request_released_across_a_policy_publication_is_admitted_again() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for (publications, expected) in [
        (0usize, StatusCode::OK),
        (1, StatusCode::OK),
        (2, StatusCode::OK),
        (3, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let h = harness(vec![], |_| {}).await;
        let path = |tail: &str| {
            let mut segments: Vec<&str> = "example.com/rt".split('/').collect();
            segments.extend(tail.split('/'));
            fake_origins()
                .url_for(probation::upstream::OriginKind::GoProxy, &segments)
                .unwrap()
                .path()
                .to_owned()
        };
        h.registry.answer(
            &path("@v/v1.0.0.info"),
            FakeAnswer::Body(r#"{"Version":"v1.0.0","Time":"2025-01-01T00:00:00Z"}"#.to_owned()),
        );
        h.registry.answer(
            &path("@v/v1.0.0.mod"),
            FakeAnswer::Body("module example.com/rt\n".to_owned()),
        );
        let gate = Arc::clone(h.server.app().managed().unwrap().publication_gate());
        let left = Arc::new(AtomicUsize::new(publications));
        let (writer, counter) = (Arc::clone(&gate), Arc::clone(&left));
        gate.set_barrier(Arc::new(move || {
            if counter
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                let writer = Arc::clone(&writer);
                std::thread::spawn(move || writer.publish(|| ()).unwrap())
                    .join()
                    .unwrap();
            }
        }));
        let answer = h.get("/go/example.com/rt/@v/v1.0.0.mod", &key_b()).await;
        assert_eq!(
            answer.status(),
            expected,
            "{publications} publications landing between authorisation and release"
        );
        if expected == StatusCode::OK {
            assert_eq!(answer.text().await.unwrap(), "module example.com/rt\n");
        }
        h.server.shutdown().await;
    }
}

/// Recheck N1: the revision-query bound is per key. One key's junk tokens (for one module, or for a thousand module
/// names) never make another key's `go get mod@main` a 429.
#[tokio::test]
async fn go_revision_queries_are_bounded_per_key_and_junk_cannot_block_another_key() {
    let h = harness(vec![], |_| {}).await;
    let status = |path: String, key: String| {
        let h = &h;
        async move { h.get(&path, &key).await.status() }
    };
    for n in 0..32 {
        assert_ne!(
            status(format!("/go/example.com/rv/@v/junk{n}.info"), key_a()).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{n}"
        );
    }
    assert_eq!(
        status("/go/example.com/rv/@v/junk32.info".to_owned(), key_a()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the 33rd distinct token of one key"
    );
    assert_ne!(
        status("/go/example.com/rv/@v/main.info".to_owned(), key_b()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "another key still resolves"
    );
    // A thousand junk module names from one key fill no table another key needs.
    for n in 0..1100 {
        let _ = status(format!("/go/junk{n}.example.com/m/@v/a.info"), key_a()).await;
    }
    assert_ne!(
        status("/go/example.com/other/@v/main.info".to_owned(), key_b()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the table is not full for everyone"
    );
    h.server.shutdown().await;
}

/// Recheck N3 (Go, managed key route): a block published while the request is in flight wins: the response admitted
/// under the old policy is refused at release, the request is admitted again, and the new policy answers 403.
#[tokio::test]
async fn go_block_published_while_the_request_is_in_flight_wins() {
    struct Held {
        inner: Arc<FakeRegistry>,
        arrived: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl Transport for Held {
        async fn fetch_metadata(
            &self,
            request: probation::upstream::MetadataRequest,
        ) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError>
        {
            if request.url.path().contains("/mid.example/") && request.url.path().ends_with(".info")
            {
                self.arrived.notify_one();
                self.release.notified().await;
            }
            self.inner.fetch_metadata(request).await
        }
        async fn open_artifact(
            &self,
            request: probation::upstream::ArtifactRequest,
        ) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
            self.inner.open_artifact(request).await
        }
    }
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), org_blocking(Vec::new()));
    sync.known_key(&key_b(), &[PLATFORM, org(ACME)]);
    let registry = FakeRegistry::new();
    let path_of = |tail: &str| {
        fake_origins()
            .url_for(
                probation::upstream::OriginKind::GoProxy,
                &["mid.example", "m", "@v", tail],
            )
            .unwrap()
            .path()
            .to_owned()
    };
    registry.answer(
        &path_of("v1.0.0.info"),
        FakeAnswer::Body(r#"{"Version":"v1.0.0","Time":"2025-01-01T00:00:00Z"}"#.to_owned()),
    );
    registry.answer(
        &path_of("v1.0.0.mod"),
        FakeAnswer::Body("module mid.example/m // before the block\n".to_owned()),
    );
    let held = Arc::new(Held {
        inner: registry,
        arrived: Default::default(),
        release: Default::default(),
    });
    let dir = tempfile::tempdir().unwrap();
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    config.sync_interval_seconds = std::num::NonZeroU64::new(1).unwrap();
    let clock = TestClock::at_rfc3339(NOW);
    let server = Arc::new(
        TestServer::start_with_upstream(
            config,
            clock.shared(),
            Arc::clone(&held) as Arc<dyn Transport>,
            fake_origins(),
        )
        .await,
    );
    let fetch = {
        let (server, key) = (Arc::clone(&server), key_b());
        tokio::spawn(async move {
            let response = reqwest::Client::new()
                .get(server.url("/go/mid.example/m/@v/v1.0.0.mod"))
                .header("authorization", bearer(&key))
                .send()
                .await
                .unwrap();
            (response.status().as_u16(), response.text().await.unwrap())
        })
    };
    held.arrived.notified().await;
    let revision = sync.edit_layer(
        org(ACME),
        org_blocking(vec![Block::Package {
            ecosystem: Ecosystem::Go,
            name: "mid.example/m".to_owned(),
            reason: None,
        }]),
    );
    clock.advance_seconds(70);
    sync.applied(revision).await;
    // Wait until the new policy is the one the firewall serves (a second request of the same key is refused locally),
    // while the first is still in flight; only then let it go on.
    let mut applied = false;
    for _ in 0..200 {
        let probe = reqwest::Client::new()
            .get(server.url("/go/mid.example/m/@v/list"))
            .header("authorization", bearer(&key_b()))
            .send()
            .await
            .unwrap();
        if probe.status() == StatusCode::FORBIDDEN {
            applied = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(applied, "the block reached the firewall");
    held.release.notify_one();
    let (status, body) = fetch.await.unwrap();
    assert_eq!(status, 403, "{body}");
    assert!(!body.contains("before the block"));
}

/// Recheck-4 L2 (Conan search, managed key route): a stricter layer published while a search judges is never applied late to a listing made
/// under the old one. The reference is a day old: listed under the old layer (no freeze), held under the new one (a 7-day freeze). The
/// answer (re-admitted under the new layer, or refused by the end-of-search fingerprint check) does not list it.
#[tokio::test]
async fn a_conan_search_does_not_list_what_a_layer_published_mid_search_holds() {
    struct Held {
        inner: Arc<FakeRegistry>,
        arrived: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl Transport for Held {
        async fn fetch_metadata(
            &self,
            request: probation::upstream::MetadataRequest,
        ) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError>
        {
            if request.url.path().contains("/slowmid/")
                && request.url.path().ends_with("/revisions")
            {
                self.arrived.notify_one();
                self.release.notified().await;
            }
            self.inner.fetch_metadata(request).await
        }
        async fn open_artifact(
            &self,
            request: probation::upstream::ArtifactRequest,
        ) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
            self.inner.open_artifact(request).await
        }
    }
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), org_blocking(Vec::new()));
    sync.known_key(&key_b(), &[PLATFORM, org(ACME)]);
    let registry = FakeRegistry::new();
    let day_old = "2026-04-05T12:00:00Z";
    for name in ["slowmid", "fastmid"] {
        registry.answer(
            &common::conan::at(&format!("{}/revisions", common::conan::base(name, "1.0"))),
            FakeAnswer::Body(common::conan::revisions_doc(
                ("reference", &format!("{name}/1.0@_/_")),
                &[("aaaa0000000000000000000000000001", Some(day_old))],
            )),
        );
    }
    registry.answer(
        &common::conan::at("v2/conans/search"),
        FakeAnswer::Body(common::conan::search_doc(&[
            "slowmid/1.0@_/_",
            "fastmid/1.0@_/_",
        ])),
    );
    let held = Arc::new(Held {
        inner: registry,
        arrived: Default::default(),
        release: Default::default(),
    });
    let dir = tempfile::tempdir().unwrap();
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    config.sync_interval_seconds = std::num::NonZeroU64::new(1).unwrap();
    let clock = TestClock::at_rfc3339(NOW);
    let origins = fake_origins().with_conan(
        url::Url::parse(common::conan::REMOTE).unwrap(),
        url::Url::parse(common::conan::PUBLISH).unwrap(),
    );
    let server = Arc::new(
        TestServer::start_with_upstream(
            config,
            clock.shared(),
            Arc::clone(&held) as Arc<dyn Transport>,
            origins,
        )
        .await,
    );
    let search = {
        let (server, key) = (Arc::clone(&server), key_b());
        tokio::spawn(async move {
            let response = reqwest::Client::new()
                .get(server.url("/conan/v2/conans/search?q=*"))
                .header("authorization", bearer(&key))
                .send()
                .await
                .unwrap();
            (response.status().as_u16(), response.text().await.unwrap())
        })
    };
    held.arrived.notified().await;
    let revision = sync.edit_layer(
        org(ACME),
        Layer {
            freeze_seconds: Some(7 * 86_400),
            ..org_blocking(Vec::new())
        },
    );
    clock.advance_seconds(70);
    sync.applied(revision).await;
    // The new layer is the one the firewall serves once a fresh read of the day-old reference is held.
    let mut applied = false;
    for _ in 0..200 {
        let probe = reqwest::Client::new()
            .get(server.url("/conan/v2/conans/fastmid/1.0/_/_/latest"))
            .header("authorization", bearer(&key_b()))
            .send()
            .await
            .unwrap();
        if probe.status() == StatusCode::FORBIDDEN {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(applied, "the layer reached the firewall");
    held.release.notify_one();
    let (status, body) = search.await.unwrap();
    assert!(
        !body.contains("fastmid") && !body.contains("slowmid"),
        "nothing judged under the old layer is listed under the new one: {status} {body}"
    );
}

/// Recheck-5 R5-1: a Conan search re-reads the key's policy when it is done, and that costs the account no second token of its rate limit.
#[tokio::test]
async fn a_conan_search_costs_one_rate_token() {
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), org_blocking(Vec::new()));
    sync.known_key_limited(&key_b(), &[PLATFORM, org(ACME)], Some(2));
    let registry = FakeRegistry::new();
    registry.answer(
        &common::conan::at("v2/conans/search"),
        FakeAnswer::Body(common::conan::search_doc(&["tok/1.0@_/_"])),
    );
    registry.answer(
        &common::conan::at(&format!("{}/revisions", common::conan::base("tok", "1.0"))),
        FakeAnswer::Body(common::conan::revisions_doc(
            ("reference", "tok/1.0@_/_"),
            &[(
                "aaaa0000000000000000000000000001",
                Some("2025-01-01T00:00:00Z"),
            )],
        )),
    );
    let dir = tempfile::tempdir().unwrap();
    let config = sync.managed(config_with_open_blocklist(dir.path()));
    let origins = fake_origins().with_conan(
        url::Url::parse(common::conan::REMOTE).unwrap(),
        url::Url::parse(common::conan::PUBLISH).unwrap(),
    );
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        registry as Arc<dyn Transport>,
        origins,
    )
    .await;
    let get = |path: &'static str| {
        let (url, key) = (server.url(path), key_b());
        async move {
            reqwest::Client::new()
                .get(url)
                .header("authorization", bearer(&key))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(
        get("/conan/v2/conans/search?q=*").await,
        200,
        "the first token"
    );
    assert_eq!(
        get("/conan/v2/users/check_credentials").await,
        200,
        "the second token: the search did not take two"
    );
    assert_eq!(
        get("/conan/v2/users/check_credentials").await,
        429,
        "the bucket of two is empty"
    );
}

/// Row 23: a managed firewall authenticates every Conan read with the key (the password of `conan remote login`, which this firewall
/// answers with the key itself as the token the client then sends as a Bearer), refuses an unknown key with the same 401, and the key's
/// policy decides: one organisation's block refuses the package for its keys and leaves another's served. The refusal is local (no
/// upstream call) and leaves one decision record per refusal; the key route serves no upload endpoint.
#[tokio::test]
async fn conan_key_route_authenticates_every_read_and_refuses_a_blocked_package_locally() {
    let h = harness(
        vec![Block::Package {
            ecosystem: Ecosystem::Conan,
            name: "evil".to_owned(),
            reason: None,
        }],
        |_| {},
    )
    .await;
    let rev = "aaaa0000000000000000000000000001";
    h.registry.answer(
        "/v2/conans/evil/1.0/_/_/revisions",
        FakeAnswer::Body(common::conan::revisions_doc(
            ("reference", "evil/1.0@_/_"),
            &[(rev, Some("2025-01-01T00:00:00Z"))],
        )),
    );
    h.registry.answer(
        &format!("/v2/conans/evil/1.0/_/_/revisions/{rev}/files/conanmanifest.txt"),
        FakeAnswer::Body(common::conan::manifest(rev)),
    );
    let paths = [
        "/conan/v2/conans/evil/1.0/_/_/revisions",
        "/conan/v2/conans/evil/1.0/_/_/latest",
        "/conan/v2/users/authenticate",
        &format!("/conan/v2/conans/evil/1.0/_/_/revisions/{rev}/files/conanmanifest.txt"),
    ];
    for path in paths {
        assert_eq!(
            h.server.get(path).await.status(),
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(
        h.get(paths[0], "prb_not_a_known_key_0123456789ab")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        h.registry.calls().is_empty(),
        "no upstream call before authentication"
    );
    // The login: the key as the Basic password comes back as the token (and a check of it is its admission).
    let basic = format!("Basic {}", base64(format!("user:{}", key_b())));
    let login = h
        .server
        .get_with_headers("/conan/v2/users/authenticate", &[("authorization", &basic)])
        .await;
    assert_eq!(
        (login.status(), login.text().await.unwrap()),
        (StatusCode::OK, key_b())
    );
    assert_eq!(
        h.get("/conan/v2/users/check_credentials", &key_b())
            .await
            .status(),
        StatusCode::OK
    );
    for path in &paths[..2] {
        assert_eq!(
            h.get(path, &key_a()).await.status(),
            StatusCode::FORBIDDEN,
            "Globex blocks the package: {path}"
        );
    }
    assert_eq!(
        h.get(paths[3], &key_a()).await.status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        h.registry.calls().is_empty(),
        "a blocked package reaches no upstream call"
    );
    let served = h.get(paths[0], &key_b()).await;
    assert_eq!(
        served.status(),
        StatusCode::OK,
        "Acme's policy keeps the package"
    );
    assert!(served.text().await.unwrap().contains(rev));
    assert_eq!(h.get(paths[3], &key_b()).await.status(), StatusCode::OK);
    let put = reqwest::Client::new()
        .put(h.server.url(&format!(
            "/conan/v2/conans/evil/1.0/_/_/revisions/{rev}/files/conanfile.py"
        )))
        .header("authorization", "Basic dTpw")
        .body("x")
        .send()
        .await
        .unwrap();
    assert!(
        matches!(put.status().as_u16(), 404 | 405),
        "{}",
        put.status()
    );
    let batch = h.server.app().managed().unwrap().activity().take_batch();
    let events: Vec<_> = batch
        .events
        .iter()
        .map(|q| &q.event)
        .filter(|e| e.ecosystem == Some(Ecosystem::Conan))
        .collect();
    assert_eq!(
        events.len(),
        3,
        "one decision record per refusal: {events:#?}"
    );
    assert!(
        events.iter().all(|e| e.package.as_deref() == Some("evil")),
        "{events:#?}"
    );
    h.server.shutdown().await;
}

// ---------------------------------------------------------------- row 24: OCI on the certificate-managed key route

/// An organisation layer that releases an image as soon as it is first seen (the age of an image starts then): so these tests are about
/// who decides, not about the cooldown.
fn oci_org(blocks: Vec<Block>) -> Layer {
    Layer {
        freeze_seconds: Some(0),
        ..org_blocking(blocks)
    }
}

fn oci_origins() -> probation::upstream::OriginSet {
    fake_origins().with_oci(
        url::Url::parse(common::oci::REGISTRY).unwrap(),
        url::Url::parse(common::oci::CDN).unwrap(),
    )
}

/// Row 24: a managed firewall admits every OCI read by the key a client's own `docker login` carries (the password of the token request,
/// which this firewall answers with the key itself as the token a client then sends as a Bearer), answers an unknown key with the
/// registry's own challenge (a Bearer realm that is this firewall's `/v2/token`), and the key's policy decides: a blocked repository is
/// refused locally, with no registry call; a write has no route on this firewall.
#[tokio::test]
async fn oci_key_route_runs_the_registrys_token_flow_with_the_key_and_refuses_a_blocked_repository_locally()
 {
    let h = harness(
        vec![Block::Package {
            ecosystem: Ecosystem::Oci,
            name: "evil/app".to_owned(),
            reason: None,
        }],
        |_| {},
    )
    .await;
    let oci = common::oci::FakeOci::new();
    let app = common::oci::image("a", &[b"layer"]);
    oci.put_image("evil/app", Some("v1"), &app);
    oci.put_image("good/app", Some("v1"), &app);
    h.server.shutdown().await;
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), oci_org(Vec::new()));
    sync.layer(
        org(GLOBEX),
        oci_org(vec![Block::Package {
            ecosystem: Ecosystem::Oci,
            name: "evil/app".to_owned(),
            reason: None,
        }]),
    );
    sync.known_key(&key_a(), &[PLATFORM, org(GLOBEX)]);
    sync.known_key(&key_b(), &[PLATFORM, org(ACME)]);
    let dir = tempfile::tempdir().unwrap();
    let config = sync.managed(config_with_open_blocklist(dir.path()));
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&oci) as Arc<dyn Transport>,
        oci_origins(),
    )
    .await;
    let get = |path: &str, key: Option<&str>| {
        let url = server.url(path);
        let key = key.map(bearer);
        async move {
            let mut request = reqwest::Client::new().get(url);
            if let Some(key) = key {
                request = request.header("authorization", key);
            }
            request.send().await.unwrap()
        }
    };
    // No key: the challenge names this firewall's token endpoint, and nothing was asked of the registry.
    let challenge = get("/v2/", None).await;
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenge
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("Bearer realm=\""),
        "{:?}",
        challenge.headers()
    );
    assert_eq!(
        get(
            "/v2/good/app/manifests/v1",
            Some("prb_not_a_known_key_0123456789ab")
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        oci.seen().is_empty(),
        "no registry call before authentication"
    );
    // The token request: the key as the Basic password comes back as the token (docker login's own flow), and the token is admitted.
    let basic = format!("Basic {}", base64(format!("user:{}", key_b())));
    let token = reqwest::Client::new()
        .get(server.url("/v2/token?service=probation&scope=repository:good/app:pull"))
        .header("authorization", &basic)
        .send()
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_str(&token.text().await.unwrap()).unwrap();
    assert_eq!(doc["token"], key_b(), "{doc}");
    assert_eq!(get("/v2/", Some(&key_b())).await.status(), StatusCode::OK);
    // The key's policy decides.
    assert_eq!(
        get("/v2/evil/app/manifests/v1", Some(&key_a()))
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "Globex blocks the repository"
    );
    assert!(
        oci.seen().is_empty(),
        "a blocked repository reaches no registry call: {:?}",
        oci.seen()
    );
    let served = get("/v2/evil/app/manifests/v1", Some(&key_b())).await;
    assert_eq!(served.status(), StatusCode::OK, "Acme's policy keeps it");
    assert_eq!(served.bytes().await.unwrap().to_vec(), app.manifest);
    let blob = get(
        &format!("/v2/evil/app/blobs/{}", app.layer_digests[0]),
        Some(&key_b()),
    )
    .await;
    assert_eq!(blob.status(), StatusCode::OK);
    // The registry never saw a firewall key.
    assert!(
        oci.seen().iter().all(|call| call
            .authorization
            .as_deref()
            .is_none_or(|auth| !auth.contains("prb_"))),
        "{:?}",
        oci.seen()
    );
    // A write has no route on a key route.
    let post = reqwest::Client::new()
        .post(server.url("/v2/good/app/blobs/uploads/"))
        .header("authorization", bearer(&key_b()))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    server.shutdown().await;
}

/// R2: a registry that challenges with a token service on another host works on the key route when `oci_token_url` names that host.
#[tokio::test]
async fn oci_key_route_follows_a_token_service_on_another_host_only_when_named() {
    for (named, expected) in [
        (None, StatusCode::BAD_GATEWAY),
        (Some("https://gitlab.example"), StatusCode::OK),
    ] {
        let oci = common::oci::FakeOci::new();
        oci.require_token();
        oci.foreign_realm("https://gitlab.example/jwt/auth");
        oci.put_image(
            "good/app",
            Some("v1"),
            &common::oci::image("a", &[b"layer"]),
        );
        let sync = FakeSyncServer::start().await;
        sync.layer(PLATFORM, platform_layer());
        sync.layer(org(ACME), oci_org(Vec::new()));
        sync.known_key(&key_b(), &[PLATFORM, org(ACME)]);
        let dir = tempfile::tempdir().unwrap();
        let mut config = sync.managed(config_with_open_blocklist(dir.path()));
        config.oci_token_url = named.map(|text| url::Url::parse(text).unwrap());
        let server = TestServer::start_with_upstream(
            config,
            TestClock::at_rfc3339(NOW).shared(),
            Arc::clone(&oci) as Arc<dyn Transport>,
            oci_origins(),
        )
        .await;
        let response = reqwest::Client::new()
            .get(server.url("/v2/good/app/manifests/v1"))
            .header("authorization", bearer(&key_b()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "named {named:?}");
        server.shutdown().await;
    }
}

/// Row 24 (the lesson of slice 23's R5-1): the policy re-read after a document costs the account no second token of its rate limit.
#[tokio::test]
async fn an_oci_read_costs_one_rate_token() {
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), oci_org(Vec::new()));
    sync.known_key_limited(&key_b(), &[PLATFORM, org(ACME)], Some(2));
    let oci = common::oci::FakeOci::new();
    oci.put_image("app", Some("v1"), &common::oci::image("a", &[b"layer"]));
    let dir = tempfile::tempdir().unwrap();
    let config = sync.managed(config_with_open_blocklist(dir.path()));
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        oci as Arc<dyn Transport>,
        oci_origins(),
    )
    .await;
    let get = |path: &'static str| {
        let (url, key) = (server.url(path), key_b());
        async move {
            reqwest::Client::new()
                .get(url)
                .header("authorization", bearer(&key))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(get("/v2/app/manifests/v1").await, 200, "the first token");
    assert_eq!(
        get("/v2/app/tags/list").await,
        404,
        "the second token: the manifest did not take two (the registry has no tag list: its 404)"
    );
    assert_eq!(
        get("/v2/app/manifests/v1").await,
        429,
        "the bucket of two is empty"
    );
    server.shutdown().await;
}

/// Row 24 (FIX-16-A on the key route): a stricter layer published while a manifest is being fetched is never applied late to an answer
/// made under the old one: the manifest is a day old, served under the old layer, held under the new (a 7-day freeze); the answer that
/// leaves is the re-admitted one.
#[tokio::test]
async fn an_oci_manifest_is_not_served_under_a_layer_that_a_publication_replaced_mid_request() {
    struct Held {
        inner: Arc<common::oci::FakeOci>,
        arrived: tokio::sync::Notify,
        release: tokio::sync::Notify,
        once: std::sync::atomic::AtomicBool,
    }
    #[async_trait::async_trait]
    impl Transport for Held {
        async fn fetch_metadata(
            &self,
            request: probation::upstream::MetadataRequest,
        ) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError>
        {
            self.inner.fetch_metadata(request).await
        }
        async fn fetch_oci(
            &self,
            request: probation::upstream::OciRequest,
        ) -> Result<probation::upstream::OciResponse, probation::upstream::UpstreamError> {
            // Only the first fetch of the slow manifest is held: the re-admitted request must not wait for a second release.
            let gated = request.url.path().contains("/slow/manifests/")
                && !self.once.swap(true, std::sync::atomic::Ordering::SeqCst);
            let answer = self.inner.fetch_oci(request).await;
            if gated {
                self.arrived.notify_one();
                self.release.notified().await;
            }
            answer
        }
        async fn open_artifact(
            &self,
            request: probation::upstream::ArtifactRequest,
        ) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
            self.inner.open_artifact(request).await
        }
    }
    let sync = FakeSyncServer::start().await;
    sync.layer(PLATFORM, platform_layer());
    sync.layer(org(ACME), oci_org(Vec::new()));
    sync.known_key(&key_b(), &[PLATFORM, org(ACME)]);
    let oci = common::oci::FakeOci::new();
    let app = common::oci::image("a", &[b"layer"]);
    oci.put_image("slow", Some("v1"), &app);
    oci.put_image("fast", Some("v1"), &app);
    let held = Arc::new(Held {
        inner: oci,
        arrived: Default::default(),
        release: Default::default(),
        once: Default::default(),
    });
    let dir = tempfile::tempdir().unwrap();
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    config.sync_interval_seconds = std::num::NonZeroU64::new(1).unwrap();
    let clock = TestClock::at_rfc3339(NOW);
    let server = Arc::new(
        TestServer::start_with_upstream(
            config,
            clock.shared(),
            Arc::clone(&held) as Arc<dyn Transport>,
            oci_origins(),
        )
        .await,
    );
    let read = {
        let (server, key) = (Arc::clone(&server), key_b());
        tokio::spawn(async move {
            let response = reqwest::Client::new()
                .get(server.url("/v2/slow/manifests/v1"))
                .header("authorization", bearer(&key))
                .send()
                .await
                .unwrap();
            (
                response.status().as_u16(),
                response.bytes().await.unwrap().to_vec(),
            )
        })
    };
    held.arrived.notified().await;
    let revision = sync.edit_layer(
        org(ACME),
        Layer {
            freeze_seconds: Some(7 * 86_400),
            ..org_blocking(Vec::new())
        },
    );
    clock.advance_seconds(70);
    sync.applied(revision).await;
    let mut applied = false;
    for _ in 0..200 {
        let probe = reqwest::Client::new()
            .get(server.url("/v2/fast/manifests/v1"))
            .header("authorization", bearer(&key_b()))
            .send()
            .await
            .unwrap();
        if probe.status() == StatusCode::FORBIDDEN {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(applied, "the layer reached the firewall");
    held.release.notify_one();
    let (status, body) = read.await.unwrap();
    assert!(
        body != app.manifest,
        "nothing decided under the old layer is served under the new one: {status}"
    );
    assert_eq!(
        status, 403,
        "the request is admitted again under the new layer, which holds it"
    );
}
