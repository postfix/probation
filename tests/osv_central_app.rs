//! Row 30: a shared-service endpoint started through `App::start` asks the policy server
//! for OSV answers (production derivation and credential attachment run against a
//! loopback fake through `AppDeps::osv_server_origin_override`) and never api.osv.dev.
//! Config rules for managed OSV live here too.

mod common;

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins, npm_upstream_path};
use probation::config::{Config, FirewallToken, ServicePolicyConfig};
use probation::upstream::Transport;
use probation_policy::api::*;
use probation_policy::osv_wire::{RenderedResult, render_answer};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef};
use reqwest::StatusCode;
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::{method, path}};

const KEY: &str = "prb_01234567890123456789012345678901";

fn snapshot(osv: OsvSetting) -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    ServicePolicySnapshot {
        version: 1,
        key_id: KeyId(7),
        org: OrgId(10),
        account: places[1],
        revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places
            .iter()
            .map(|place| PlaceLayer {
                place: *place,
                layer: Layer {
                    freeze_seconds: Some(0),
                    osv: (place.kind == LayerKind::Platform).then_some(osv),
                    ..Layer::empty(place.kind)
                },
                revision: 1,
            })
            .collect(),
        rate_limit: None,
        rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor {
            registry: RegistryId(3),
            ecosystem: probation_policy::Ecosystem::Npm,
            target_url: None,
            trusted: false,
            registry_private_cidrs: vec![],
            deletion_scopes: vec![],
            osv_scope: None, archive_origin: None,
        }],
    }
}

struct Seen {
    auth: Option<String>,
    path: String,
}

/// A policy server that also answers `/osv/v1/querybatch`: names starting `evil-` match.
async fn policy_server(osv: OsvSetting, osv_status: u16) -> (MockServer, Arc<Mutex<Vec<Seen>>>) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot(osv)))
        .mount(&server)
        .await;
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let recorded = Arc::clone(&seen);
    Mock::given(method("POST"))
        .and(path("/osv/v1/querybatch"))
        .respond_with(move |request: &Request| {
            recorded.lock().unwrap().push(Seen {
                auth: request.headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned),
                path: request.url.path().to_owned(),
            });
            if osv_status != 200 {
                return ResponseTemplate::new(osv_status);
            }
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let results: Vec<RenderedResult> = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    if q["package"]["name"].as_str().unwrap().starts_with("evil-") {
                        RenderedResult::Matched(vec![("MAL-2026-9".into(), None)])
                    } else {
                        RenderedResult::NoMatch
                    }
                })
                .collect();
            ResponseTemplate::new(200).set_body_bytes(render_answer(&results, true))
        })
        .mount(&server)
        .await;
    (server, seen)
}

fn registry_with(names: &[&str]) -> Arc<FakeRegistry> {
    let registry = FakeRegistry::new();
    for name in names {
        registry.answer(
            &npm_upstream_path(name),
            FakeAnswer::Body(
                serde_json::json!({
                    "name": name,
                    "dist-tags": {"latest": "1.0.0"},
                    "versions": {"1.0.0": {"name": name, "version": "1.0.0", "dist": {"tarball": common::npm_tarball_url(name, &format!("{name}-1.0.0.tgz"))}}},
                    "time": {"1.0.0": "2020-01-01T00:00:00Z"}
                })
                .to_string(),
            ),
        );
    }
    registry
}

/// A TCP listener that counts connections: used as a forward proxy for a client, so every
/// request that client makes, to any host, is a visible connection here.
struct Recorder {
    connections: Arc<std::sync::atomic::AtomicUsize>,
    client: reqwest::Client,
}

impl Recorder {
    async fn start() -> Recorder {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections: Arc<std::sync::atomic::AtomicUsize> = Arc::default();
        let counted = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Ok((_stream, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let client = reqwest::Client::builder().proxy(reqwest::Proxy::all(format!("http://{addr}")).unwrap()).build().unwrap();
        Recorder { connections, client }
    }

    fn count(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }
}

async fn endpoint(policy: &MockServer, registry: Arc<FakeRegistry>) -> (TestServer, std::path::PathBuf) {
    endpoint_with(policy, registry, probation::osv::unreachable_client()).await
}

async fn endpoint_with(policy: &MockServer, registry: Arc<FakeRegistry>, osv_client: reqwest::Client) -> (TestServer, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: "https://policy.invalid".parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new(KEY.into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
    });
    // The configured server cannot be reached; the override stands in for it and the
    // snapshot comes from the same fake.
    config.service_policy.as_mut().unwrap().server_url = policy.uri().parse().unwrap();
    let server = TestServer::start_with_osv_server_origin(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        registry as Arc<dyn Transport>,
        fake_origins(),
        osv_client,
        policy.uri().parse().unwrap(),
    )
    .await;
    let data_dir = server.app().config.data_dir.clone();
    std::mem::forget(dir);
    (server, data_dir)
}

#[tokio::test]
async fn managed_endpoint_sends_no_request_to_osv_dev_and_asks_the_server_with_its_credential() {
    let (policy, seen) = policy_server(OsvSetting::On, 200).await;
    let (server, _data) = endpoint(&policy, registry_with(&["evil-pkg", "clean-pkg"])).await;
    let clean = server.get("/registry/npm/3/clean-pkg").await;
    assert_eq!(clean.status(), StatusCode::OK);
    let clean: serde_json::Value = serde_json::from_slice(&clean.bytes().await.unwrap()).unwrap();
    assert!(clean["versions"]["1.0.0"].is_object(), "an unmatched version is served");
    let evil = server.get("/registry/npm/3/evil-pkg").await;
    let evil: serde_json::Value = serde_json::from_slice(&evil.bytes().await.unwrap()).unwrap_or_default();
    assert!(evil["versions"]["1.0.0"].is_null(), "the server's MAL match removes the version: {evil}");
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    for hit in seen.iter() {
        assert_eq!(hit.path, "/osv/v1/querybatch");
        assert_eq!(hit.auth.as_deref(), Some(&*format!("Bearer {KEY}")), "the endpoint's existing credential");
    }
}

#[tokio::test]
async fn osv_modes_work_through_the_server_path() {
    // off: never asked; log-only: asked, match allows; enforce: match denies.
    let (policy, seen) = policy_server(OsvSetting::Off, 200).await;
    let (server, _d) = endpoint(&policy, registry_with(&["evil-pkg"])).await;
    let doc = server.get("/registry/npm/3/evil-pkg").await;
    let doc: serde_json::Value = serde_json::from_slice(&doc.bytes().await.unwrap()).unwrap();
    assert!(doc["versions"]["1.0.0"].is_object());
    assert!(seen.lock().unwrap().is_empty(), "off: OSV is never asked");

    let (policy, seen) = policy_server(OsvSetting::LogOnly, 200).await;
    let (server, _d) = endpoint(&policy, registry_with(&["evil-pkg"])).await;
    let doc = server.get("/registry/npm/3/evil-pkg").await;
    let doc: serde_json::Value = serde_json::from_slice(&doc.bytes().await.unwrap()).unwrap();
    assert!(doc["versions"]["1.0.0"].is_object(), "log-only: a match is recorded, not enforced");
    assert!(!seen.lock().unwrap().is_empty(), "log-only still asks");
}

#[tokio::test]
async fn osv_server_401_leaves_policy_serving_and_no_refusal() {
    for status in [401u16, 403, 429, 500] {
        let (policy, seen) = policy_server(OsvSetting::On, status).await;
        let (server, data) = endpoint(&policy, registry_with(&["evil-pkg"])).await;
        let doc = server.get("/registry/npm/3/evil-pkg").await;
        assert_eq!(doc.status(), StatusCode::OK, "fail open on {status}");
        assert!(!seen.lock().unwrap().is_empty());
        assert!(!data.join("service-policy.refused").exists(), "an OSV {status} is never a policy refusal");
        assert_eq!(server.get("/health/ready").await.status(), StatusCode::OK, "readiness is unchanged");
    }
}

/// LS-F1: only a 401/403 on the snapshot route is a refusal, and a 2xx on the OSV route
/// never clears one.
#[tokio::test]
async fn snapshot_refusal_not_cleared_by_osv_2xx() {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(401)).mount(&policy).await;
    Mock::given(method("POST"))
        .and(path("/osv/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(render_answer(&[RenderedResult::NoMatch], true)))
        .mount(&policy)
        .await;
    let (server, data) = endpoint(&policy, registry_with(&["clean-pkg"])).await;
    assert!(data.join("service-policy.refused").exists(), "a snapshot 401 persists the refusal");
    let response = server.get("/registry/npm/3/clean-pkg").await;
    assert_ne!(response.status(), StatusCode::OK, "no policy while refused");
    assert!(data.join("service-policy.refused").exists(), "still refused after traffic");
    assert!(
        !policy.received_requests().await.unwrap().iter().any(|r| r.url.path() == "/osv/v1/querybatch"),
        "nothing was served, so OSV was never asked and nothing could clear it"
    );
}

// ---- configuration --------------------------------------------------------------

/// `sample` without the lines whose key `top` sets again.
fn override_keys(sample: &str, top: &str) -> String {
    let keys: Vec<&str> = top.lines().filter_map(|line| line.split_once('=')).map(|(key, _)| key.trim()).collect();
    sample
        .lines()
        .filter(|line| !keys.iter().any(|key| line.trim_start().starts_with(&format!("{key} ")) || line.trim_start().starts_with(&format!("{key}="))))
        .collect::<Vec<_>>()
        .join("\n")
}

fn managed(top: &str) -> Result<Config, probation::config::ConfigError> {
    let sample = override_keys(&std::fs::read_to_string("config.sample.toml").expect("the sample"), top);
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "fwt_secret\n").unwrap();
    let text = format!("{top}\n{sample}\n[management]\nurl = \"https://sync.example\"\ntoken_file = {token:?}\n");
    let config = Config::from_toml_str(&text);
    drop(dir);
    config
}

#[test]
fn managed_config_has_no_direct_osv_key() {
    let config = managed("").expect("a managed sample");
    let (server, credential) = config.osv_central_server().expect("managed mode asks its server");
    assert_eq!(server.as_str(), "https://sync.example/");
    assert_eq!(credential.expose_for_test_support(), "fwt_secret");
    for key in ["osv_url", "osv_base_url", "osv_direct", "osv_upstream_url", "osv_endpoint"] {
        let error = managed(&format!("{key} = \"https://api.osv.dev\"")).expect_err(key).to_string();
        assert!(error.contains(key), "{key}: {error}");
    }
}

#[test]
fn standalone_still_queries_osv_dev_directly() {
    let standalone = Config::load(std::path::Path::new("config.sample.toml")).unwrap();
    assert!(standalone.osv_central_server().is_none());
    let source = std::fs::read_to_string("src/lib.rs").unwrap();
    assert!(
        source.contains("(None, None) => osv::OsvClient::new("),
        "the standalone arm still builds the fixed api.osv.dev client"
    );
}

/// Structural: the fixed-host constructor has no managed caller.
#[test]
fn osv_managed_arm_cannot_call_fixed_constructor() {
    let source = std::fs::read_to_string("src/lib.rs").unwrap();
    let start = source.find("let (osv, osv_task) = match (central").expect("the OSV construction");
    let block = &source[start..start + source[start..].find("delivery_tasks.push(osv_task)").unwrap()];
    let central_arm = &block[..block.find("(None, Some(url))").unwrap()];
    assert!(central_arm.contains("spawn_central") && !central_arm.contains("OsvClient::new("));
    assert_eq!(source.matches("OsvClient::new(").count(), 1, "one construction of the fixed-host client");
    // The managed arm is chosen whenever a server is configured and no plain seam is given.
    assert!(source.contains("osv_central_server(), &deps.osv_base_url"));
}

#[test]
fn managed_config_rejects_osv_timeout_below_server_deadline() {
    let error = managed("osv_request_timeout_ms = 1599").unwrap_err().to_string();
    assert!(error.contains("osv_request_timeout_ms"), "{error}");
    assert!(managed("osv_request_timeout_ms = 1600").is_ok());
    assert!(managed("").is_ok(), "the shipped 2000 ms default");
    let top = "osv_request_timeout_ms = 50";
    let standalone = override_keys(&std::fs::read_to_string("config.sample.toml").unwrap(), top);
    assert!(Config::from_toml_str(&format!("{top}\n{standalone}")).is_ok(), "standalone is unchanged");
}

#[test]
fn osv_stale_window_config_bounds() {
    for ok in [3600, 86_400, 604_800] {
        assert_eq!(managed(&format!("osv_stale_match_seconds = {ok}")).unwrap().osv_stale_match_seconds, ok);
    }
    for bad in [0, 3599, 604_801] {
        let error = managed(&format!("osv_stale_match_seconds = {bad}")).unwrap_err().to_string();
        assert!(error.contains("osv_stale_match_seconds"), "{bad}: {error}");
    }
    assert_eq!(managed("").unwrap().osv_stale_match_seconds, 86_400, "the default");
    let standalone = std::fs::read_to_string("config.sample.toml").unwrap();
    let error = Config::from_toml_str(&format!("osv_stale_match_seconds = 7200\n{standalone}")).unwrap_err().to_string();
    assert!(error.contains("osv_stale_match_seconds"), "managed only: {error}");
}

// ---- scope (LS-F12) ---------------------------------------------------------------

#[test]
fn osv_scope_default_rules() {
    use probation::osv::effective_scope;
    use probation_policy::Ecosystem;
    // No target and the fixed public sources are Public whatever the field says.
    assert_eq!(effective_scope(Ecosystem::Npm, None, Some(OsvScope::Private)), OsvScope::Public);
    assert_eq!(effective_scope(Ecosystem::Npm, Some("https://registry.npmjs.org/"), Some(OsvScope::Private)), OsvScope::Public);
    assert_eq!(effective_scope(Ecosystem::PyPi, Some("https://pypi.org/simple/"), Some(OsvScope::Private)), OsvScope::Public);
    assert_eq!(effective_scope(Ecosystem::PyPi, Some("https://files.pythonhosted.org/"), None), OsvScope::Public);
    // A custom target defaults to Public (user decision 2026-11-18); the explicit field wins.
    assert_eq!(effective_scope(Ecosystem::Npm, Some("https://93.184.216.34/"), None), OsvScope::Public);
    assert_eq!(effective_scope(Ecosystem::PyPi, Some("https://pypi.corp.example/"), None), OsvScope::Public);
    assert_eq!(effective_scope(Ecosystem::Npm, Some("https://93.184.216.34/"), Some(OsvScope::Private)), OsvScope::Private);
    assert_eq!(effective_scope(Ecosystem::Npm, Some("https://93.184.216.34/"), Some(OsvScope::Public)), OsvScope::Public);
}

/// The registry descriptor's scope reaches the decision: a Private custom registry is
/// not OSV-applicable, a default or Public one is queried (the skip itself is
/// `osv_skipped_for_private_registry` in src/osv).
#[tokio::test]
async fn osv_scope_follows_the_active_snapshot() {
    for (target, scope, want) in [
        (Some("https://93.184.216.34/"), Some(OsvScope::Private), OsvScope::Private),
        (Some("https://93.184.216.34/"), None, OsvScope::Public),
        (Some("https://93.184.216.34/"), Some(OsvScope::Public), OsvScope::Public),
        (None, Some(OsvScope::Private), OsvScope::Public),
    ] {
        let policy = MockServer::start().await;
        let mut snap = snapshot(OsvSetting::On);
        snap.registries[0].target_url = target.map(str::to_owned);
        snap.registries[0].osv_scope = scope;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(snap)).mount(&policy).await;
        let (server, _d) = endpoint(&policy, registry_with(&[])).await;
        assert_eq!(server.app().osv_scope(3), want, "{target:?} {scope:?}");
        assert_eq!(server.app().osv_scope(99), OsvScope::Public, "an unknown registry is queried");
    }
}

// ---- code review F2: the Private skip through every adapter path ------------------------

/// Drives npm metadata, the npm artifact and PyPI metadata through a
/// shared-service endpoint whose registries carry `scope`, with a recorder as the policy
/// server's OSV route. Returns the OSV hits after each of the three steps.
async fn drive_all_paths(scope: Option<OsvScope>) -> Vec<usize> {
    use sha2::{Digest, Sha256};
    let bytes = "private registry bytes";
    let policy = MockServer::start().await;
    let mut snap = snapshot(OsvSetting::On);
    snap.registries[0].target_url = Some("https://93.184.216.34/".into());
    snap.registries[0].osv_scope = scope;
    snap.registries.push(RegistryDescriptor {
        registry: RegistryId(4),
        ecosystem: probation_policy::Ecosystem::PyPi,
        target_url: Some("https://93.184.216.35/".into()),
        trusted: false,
        registry_private_cidrs: vec![],
        deletion_scopes: vec![],
        osv_scope: scope,
        archive_origin: None,
    });
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(snap)).mount(&policy).await;
    let hits: Arc<Mutex<usize>> = Arc::default();
    let counter = Arc::clone(&hits);
    Mock::given(method("POST"))
        .and(path("/osv/v1/querybatch"))
        .respond_with(move |request: &Request| {
            *counter.lock().unwrap() += 1;
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let n = body["queries"].as_array().unwrap().len();
            ResponseTemplate::new(200).set_body_bytes(render_answer(&vec![RenderedResult::NoMatch; n], true))
        })
        .mount(&policy)
        .await;
    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path("internal-pkg"),
        FakeAnswer::Body(
            serde_json::json!({"name":"internal-pkg","versions":{"1.0.0":{"name":"internal-pkg","version":"1.0.0","dist":{
                "tarball": "https://93.184.216.34/internal-pkg/-/internal-pkg-1.0.0.tgz",
                "integrity": format!("sha256-{}", common::sync::base64(Sha256::digest(bytes.as_bytes())))}}},
                "time":{"1.0.0":"2026-01-01T00:00:00Z"}})
            .to_string(),
        ),
    );
    registry.answer(&common::npm_artifact_upstream_path("internal-pkg", "internal-pkg-1.0.0.tgz"), FakeAnswer::Body(bytes.into()));
    registry.answer(
        &common::pypi_upstream_path("internal-pkg"),
        FakeAnswer::Body(
            serde_json::json!({"meta":{"api-version":"1.1"},"name":"internal-pkg","files":[{"filename":"internal_pkg-1.0.0-py3-none-any.whl",
                "url":"https://93.184.216.35/packages/internal_pkg-1.0.0-py3-none-any.whl",
                "hashes":{"sha256": hex::encode(Sha256::digest(bytes.as_bytes()))},"upload-time":"2026-01-01T00:00:00Z"}]})
            .to_string(),
        ),
    );
    registry.answer("/packages/internal_pkg-1.0.0-py3-none-any.whl", FakeAnswer::Body(bytes.into()));
    let (server, _data) = endpoint(&policy, registry).await;
    let mut seen = Vec::new();

    let npm = server.get("/registry/npm/3/internal-pkg").await;
    assert_eq!(npm.status(), StatusCode::OK, "npm metadata");
    let npm: serde_json::Value = serde_json::from_slice(&npm.bytes().await.unwrap()).unwrap();
    assert!(npm["versions"]["1.0.0"].is_object());
    seen.push(*hits.lock().unwrap());
    let tarball: reqwest::Url = npm["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap().parse().unwrap();
    let artifact = server.get(tarball.path()).await;
    assert_eq!(artifact.status(), StatusCode::OK, "npm artifact");
    seen.push(*hits.lock().unwrap());

    let pypi = server.get_with_headers("/registry/pypi/4/simple/internal-pkg/", &[("accept", "application/vnd.pypi.simple.v1+json")]).await;
    assert_eq!(pypi.status(), StatusCode::OK, "pypi metadata");
    seen.push(*hits.lock().unwrap());
    // The PyPI artifact path is `artifacts::evaluate`, the function the npm artifact step above
    // already drove; a custom PyPI file origin cannot be served by this fake transport.
    seen
}

/// LS-F12: a Private registry's names reach neither the shared server nor api.osv.dev, on any
/// adapter path; the Public control is asked on each path (so the zero is not a dead recorder).
#[tokio::test]
async fn osv_private_names_never_reach_server_or_upstream() {
    let private = drive_all_paths(Some(OsvScope::Private)).await;
    assert_eq!(private, vec![0, 0, 0], "a Private registry is never asked about: {private:?}");
    let public = drive_all_paths(None).await;
    assert!(public[0] >= 1 && public[2] > public[1] && public[1] >= public[0], "the default (Public) is asked on npm and PyPI metadata: {public:?}");
}

/// Code review F6: a recorder stands in for api.osv.dev (every request of the client handed in
/// as `AppDeps::osv_client` is a connection to it). A managed endpoint never uses that client.
#[tokio::test]
async fn managed_endpoint_makes_no_connection_to_osv_dev() {
    let recorder = Recorder::start().await;
    let (policy, seen) = policy_server(OsvSetting::On, 200).await;
    let (server, _data) = endpoint_with(&policy, registry_with(&["evil-pkg", "clean-pkg"]), recorder.client.clone()).await;
    let _ = server.get("/registry/npm/3/clean-pkg").await;
    let _ = server.get("/registry/npm/3/evil-pkg").await;
    assert!(!seen.lock().unwrap().is_empty(), "the lookups went to the policy server");
    assert_eq!(recorder.count(), 0, "and none to api.osv.dev");
}

/// The control that makes the zero above mean something, and the behavioural standalone case:
/// a standalone server asks api.osv.dev directly through the client it is given.
#[tokio::test]
async fn standalone_still_queries_osv_dev_directly_behaviour() {
    let recorder = Recorder::start().await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_open_blocklist(dir.path());
    let server = TestServer::start_with_osv_client(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        registry_with(&["clean-pkg"]) as Arc<dyn Transport>,
        fake_origins(),
        recorder.client.clone(),
    )
    .await;
    let _ = server.get("/npm/clean-pkg").await;
    assert!(recorder.count() >= 1, "standalone connected for api.osv.dev");
}
