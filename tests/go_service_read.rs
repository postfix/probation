//! Row 19: the Go READ path through the shared service for a selected registry with a real
//! `target_url` (an Artifactory-style layout under a path prefix), what a credential-bearing read
//! shares (nothing: C1028), the upstream 401/403 codes, the absent checksum route of a private
//! registry, and the read-only rule (GOPROXY has no write protocol).
mod common;

use common::go::{info, mod_text, module_zip};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{Transport, UpstreamError};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{num::NonZeroU64, sync::Arc};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

const PREFIX: &str = "/artifactory/api/go/repo";
const OLD: &str = "2025-01-01T00:00:00Z";

fn snapshot(freeze: u64, target: Option<&str>, archive: Option<&str>) -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer { freeze_seconds: Some(freeze), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor {
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Go, target_url: target.map(str::to_owned),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive.map(str::to_owned), resource_path_prefix: None,
        }],
    }
}

/// A transport that answers like the fake registry and records what each artifact request carried.
struct Recording(Arc<FakeRegistry>, std::sync::Mutex<Vec<(String, Option<url::Url>, bool)>>);

#[async_trait::async_trait]
impl Transport for Recording {
    async fn fetch_metadata(&self, request: probation::upstream::MetadataRequest) -> Result<probation::upstream::MetadataResponse, UpstreamError> {
        self.0.fetch_metadata(request).await
    }
    async fn open_artifact(&self, request: probation::upstream::ArtifactRequest) -> Result<probation::upstream::ArtifactBody, UpstreamError> {
        self.1.lock().unwrap().push((request.url.path().to_owned(), request.archive_origin.clone(), request.allow_archive_redirect));
        self.0.open_artifact(request).await
    }
}

struct Fixture {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    recording: Option<Arc<Recording>>,
    _clock: Arc<TestClock>,
    _policy: MockServer,
}

async fn start(freeze: u64, target: Option<&str>) -> Fixture {
    start_with(freeze, target, None, false).await
}

/// `recording`: the transport records the archive origin each artifact request carries.
async fn start_with(freeze: u64, target: Option<&str>, archive: Option<&str>, record: bool) -> Fixture {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot(freeze, target, archive))).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let registry = FakeRegistry::new();
    let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
    let recording = record.then(|| Arc::new(Recording(Arc::clone(&registry), std::sync::Mutex::new(Vec::new()))));
    let transport: Arc<dyn Transport> = match &recording {
        Some(recording) => Arc::clone(recording) as Arc<dyn Transport>,
        None => Arc::clone(&registry) as Arc<dyn Transport>,
    };
    let server = TestServer::start_with_upstream(config, clock.shared(), transport, fake_origins()).await;
    Fixture { server, registry, recording, _clock: clock, _policy: policy }
}

fn private(prefix: &str, f: &Fixture, module: &str, version: &str, time: &str) {
    f.registry.answer(&format!("{prefix}/{module}/@v/list"), FakeAnswer::Body(format!("{version}\n")));
    f.registry.answer(&format!("{prefix}/{module}/@v/{version}.info"), FakeAnswer::Body(info(version, Some(time))));
    f.registry.answer(&format!("{prefix}/{module}/@v/{version}.mod"), FakeAnswer::Body(mod_text(module)));
    f.registry.answer(&format!("{prefix}/{module}/@v/{version}.zip"), FakeAnswer::Bytes(module_zip(module, version, "package p\n")));
}

fn calls(f: &Fixture, needle: &str) -> usize {
    f.registry.calls().iter().filter(|url| url.path().ends_with(needle)).count()
}

#[tokio::test]
async fn a_selected_registry_is_read_from_its_own_prefix_through_both_roots() {
    let f = start(0, Some(&format!("https://reg.invalid{PREFIX}/"))).await;
    private(PREFIX, &f, "corp.example/lib", "v1.2.3", OLD);
    for root in ["/go", "/registry/go/7"] {
        assert_eq!(f.server.get(&format!("{root}/corp.example/lib/@v/list")).await.text().await.unwrap(), "v1.2.3\n", "{root}");
        let zip = f.server.get(&format!("{root}/corp.example/lib/@v/v1.2.3.zip")).await;
        assert_eq!((zip.status().as_u16(), zip.bytes().await.unwrap().to_vec()), (200, module_zip("corp.example/lib", "v1.2.3", "package p\n")), "{root}");
    }
    // Every upstream call stayed under the registry's own prefix.
    assert!(f.registry.calls().iter().all(|url| url.path().starts_with(PREFIX)), "{:?}", f.registry.calls());
    // A registry that is not this family's, or an unknown id, is no route.
    assert_eq!(f.server.get("/registry/go/8/corp.example/lib/@v/list").await.status(), 404);
    assert_eq!(f.server.get("/registry/cargo/7/config.json").await.status(), 404);
    f.server.shutdown().await;
}

/// C1028 for the Go version tables: a credential-bearing read never reads or fills the shared
/// version memory (each such read confirms the version itself), and a plain read does share it.
#[tokio::test]
async fn credential_bearing_reads_share_no_version_memory() {
    let f = start(0, None).await;
    let base = "/go/open.example/mod/@v";
    // The public registry (no target): upstream paths are the plain proxy paths.
    f.registry.answer("/open.example/mod/@v/v1.0.0.info", FakeAnswer::Body(info("v1.0.0", Some(OLD))));
    f.registry.answer("/open.example/mod/@v/v1.0.0.mod", FakeAnswer::Body(mod_text("open.example/mod")));
    let plain = |headers: &'static [(&'static str, &'static str)]| {
        let (server, path) = (&f.server, format!("{base}/v1.0.0.mod"));
        async move { server.get_with_headers(&path, headers).await.status().as_u16() }
    };
    assert_eq!(plain(&[("accept", "*/*")]).await, 200);
    let after_first = calls(&f, "v1.0.0.info");
    assert_eq!(plain(&[("accept", "*/*")]).await, 200);
    assert_eq!(calls(&f, "v1.0.0.info"), after_first, "a plain read shares the version memory");
    for carrier in [[("authorization", "Basic dXNlcjpwdw==")], [("authorization", "Bearer abc")], [("cookie", "s=1")], [("x-probe-unknown", "1")]] {
        let before = calls(&f, "v1.0.0.info");
        let carrier: &'static [(&'static str, &'static str)] = Box::leak(Box::new(carrier));
        assert_eq!(plain(carrier).await, 200, "{carrier:?}");
        assert!(calls(&f, "v1.0.0.info") > before, "{carrier:?}: a credential-bearing read confirms the version itself and fills nothing");
    }
    f.server.shutdown().await;
}

#[tokio::test]
async fn upstream_401_and_403_have_their_own_codes_and_a_missing_version_is_404() {
    let f = start(0, None).await;
    f.registry.answer("/login.example/m/@v/v1.0.0.info", FakeAnswer::Fail(UpstreamError::Status(401)));
    f.registry.answer("/deny.example/m/@v/v1.0.0.info", FakeAnswer::Fail(UpstreamError::Status(403)));
    f.registry.answer("/down.example/m/@v/v1.0.0.info", FakeAnswer::Fail(UpstreamError::Status(503)));
    f.registry.answer("/gone.example/m/@v/v1.0.0.info", FakeAnswer::Missing);
    let code = |answer: reqwest::Response| async move {
        let status = answer.status().as_u16();
        let body: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap_or_default();
        (status, body["error"].as_str().unwrap_or_default().to_owned())
    };
    assert_eq!(code(f.server.get("/go/login.example/m/@v/v1.0.0.zip").await).await, (401, "UPSTREAM_AUTHENTICATION_REQUIRED".to_owned()));
    assert_eq!(code(f.server.get("/go/deny.example/m/@v/v1.0.0.info").await).await, (403, "UPSTREAM_DENIED".to_owned()));
    assert_eq!(code(f.server.get("/go/down.example/m/@v/v1.0.0.mod").await).await.0, 502);
    assert_eq!(code(f.server.get("/go/gone.example/m/@v/v1.0.0.mod").await).await.0, 404);
    f.server.shutdown().await;
}

#[tokio::test]
async fn a_private_registry_has_no_checksum_database_route_and_the_public_one_forwards_without_the_callers_credential() {
    let private = start(0, Some(&format!("https://reg.invalid{PREFIX}/"))).await;
    let before = private.registry.calls().len();
    assert_eq!(private.server.get("/go/sumdb/sum.golang.org/latest").await.status(), 404);
    assert_eq!(private.registry.calls().len(), before, "no upstream call for a private registry's checksum route");
    private.server.shutdown().await;
    let public = start(0, None).await;
    public.registry.answer("/latest", FakeAnswer::Body("go.sum database tree\n".to_owned()));
    let answer = public.server.get_with_headers("/go/sumdb/sum.golang.org/latest", &[("authorization", "Bearer secret")]).await;
    assert_eq!(answer.status(), 200);
    public.server.shutdown().await;
}

#[tokio::test]
async fn go_is_read_only_through_the_shared_service() {
    let f = start(0, None).await;
    let calls_before = f.registry.calls().len();
    let client = reqwest::Client::new();
    for (verb, path) in [
        ("PUT", "/go/open.example/mod/@v/v1.0.0.zip"),
        ("POST", "/go/open.example/mod/@v/v1.0.0.info"),
        ("DELETE", "/registry/go/7/open.example/mod/@v/v1.0.0.mod"),
        ("PATCH", "/go/open.example/mod/@v/list"),
        ("POST", "/go/sumdb/sum.golang.org/latest"),
    ] {
        let response = client.request(verb.parse().unwrap(), f.server.url(path)).body("x").send().await.unwrap();
        assert!(matches!(response.status().as_u16(), 404 | 405), "{verb} {path}: {}", response.status());
    }
    assert_eq!(f.server.get("/go/open.example/mod/@v/list?token=abc").await.status(), 404, "a query string is no route");
    assert_eq!(f.registry.calls().len(), calls_before, "nothing reached upstream");
    f.server.shutdown().await;
}

/// The archive origin a Go registry declares reaches the transport with its zip (so a redirect may land
/// there), only for a Go registry that declared one, and with every file of the version.
#[tokio::test]
async fn a_declared_go_archive_origin_travels_with_the_zip_request_only() {
    for (archive, expected) in [(Some("https://zips.invalid/bucket"), Some("https://zips.invalid/bucket")), (None, None)] {
        let f = start_with(0, Some(&format!("https://reg.invalid{PREFIX}/")), archive, true).await;
        private(PREFIX, &f, "corp.example/lib", "v1.2.3", OLD);
        for ext in ["zip", "mod", "info"] {
            assert_eq!(f.server.get(&format!("/go/corp.example/lib/@v/v1.2.3.{ext}")).await.status(), 200, "{ext}");
        }
        let seen = f.recording.as_ref().unwrap().1.lock().unwrap().clone();
        assert!(seen.len() >= 3, "{seen:?}");
        assert!(seen.iter().all(|(_, origin, _)| origin.as_ref().map(url::Url::as_str) == expected), "{archive:?}: {seen:?}");
        // Only the zip transfer may follow the redirect to it.
        assert!(seen.iter().all(|(path, _, allow)| *allow == path.ends_with(".zip")), "{seen:?}");
        f.server.shutdown().await;
    }
}

/// A credential-bearing read has a throwaway version table, and a restart or an eviction forgets the shared
/// one, so the only memory of an earlier date left is the reference row: a proxy that re-dates a held
/// version to the past cannot make it eligible through a request-scoped read either (the date only gets later).
#[tokio::test]
async fn a_request_scoped_read_cannot_make_a_held_version_older() {
    use probation::artifacts::ArtifactReference;
    use probation::store::rows::ReferenceId;
    let f = start(7 * 86_400, None).await;
    let info_path = "/dated.example/m/@v/v1.0.0.info";
    f.registry.answer(info_path, FakeAnswer::Body(info("v1.0.0", Some("2026-04-05T12:00:00Z"))));
    f.registry.answer("/dated.example/m/@v/v1.0.0.mod", FakeAnswer::Body(mod_text("dated.example/m")));
    let carrier = [("authorization", "Bearer caller")];
    assert_eq!(f.server.get_with_headers("/go/dated.example/m/@v/v1.0.0.mod", &carrier).await.status(), 403, "young: held");
    // The process forgets everything it knew in memory: the reference rows of the version leave the shared cache.
    for ext in ["info", "mod", "zip"] {
        let reference = ArtifactReference {
            ecosystem: probation_policy::Ecosystem::Go,
            name: "dated.example/m".to_owned(),
            version: "1.0.0".to_owned(),
            filename: format!("v1.0.0.{ext}"),
            upstream_url: format!("https://proxy.golang.org/dated.example/m/@v/v1.0.0.{ext}").parse().unwrap(),
            expected: Vec::new(),
        };
        f.server.app().store().caches().references.remove(&ReferenceId::compute_in_registry(7, &reference));
    }
    f.registry.answer(info_path, FakeAnswer::Body(info("v1.0.0", Some(OLD))));
    for headers in [&carrier[..], &[("accept", "*/*")][..]] {
        assert_eq!(f.server.get_with_headers("/go/dated.example/m/@v/v1.0.0.mod", headers).await.status(), 403, "re-dated to the past: still held ({headers:?})");
    }
    f.server.shutdown().await;
}

/// Recheck N7: a request-scoped list starts with an empty table, but the store holds every date it recorded: the table is
/// seeded from it, so a long list completes over the requests it needs (64 new dates each) and is not re-dated from nothing.
#[tokio::test]
async fn a_long_list_is_not_dated_again_from_nothing_by_a_request_with_an_empty_table() {
    let f = start(7 * 86_400, None).await;
    let versions: Vec<String> = (0..130).map(|n| format!("v1.0.{n}")).collect();
    f.registry.answer("/big.example/m/@v/list", FakeAnswer::Body(versions.iter().map(|v| format!("{v}\n")).collect()));
    for v in &versions {
        f.registry.answer(&format!("/big.example/m/@v/{v}.info"), FakeAnswer::Body(info(v, Some(OLD))));
    }
    let carrier = [("authorization", "Bearer caller")];
    let mut sizes = Vec::new();
    for _ in 0..3 {
        let body = f.server.get_with_headers("/go/big.example/m/@v/list", &carrier).await.text().await.unwrap();
        sizes.push(body.lines().count());
    }
    assert_eq!(sizes, vec![64, 128, 130], "each request-scoped list adds the next 64 dates instead of starting over");
    f.server.shutdown().await;
}

/// A transport whose `.mod` download waits for the test, so a snapshot can change while it is in flight.
struct HeldMod {
    inner: Arc<FakeRegistry>,
    arrived: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Transport for HeldMod {
    async fn fetch_metadata(&self, request: probation::upstream::MetadataRequest) -> Result<probation::upstream::MetadataResponse, UpstreamError> {
        self.inner.fetch_metadata(request).await
    }
    async fn open_artifact(&self, request: probation::upstream::ArtifactRequest) -> Result<probation::upstream::ArtifactBody, UpstreamError> {
        if request.url.path().ends_with(".mod") {
            self.arrived.notify_one();
            self.release.notified().await;
        }
        self.inner.open_artifact(request).await
    }
}

/// Recheck N3 (Go, shared service): a block published while a `.mod` is in flight wins (403), and the bytes fetched under
/// the old snapshot are not delivered.
#[tokio::test]
async fn a_block_published_while_a_go_file_is_in_flight_wins() {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot(0, None, None))).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(3600).unwrap(),
        trusted_proxies: vec![],
    });
    let registry = FakeRegistry::new();
    registry.answer("/mid.example/m/@v/v1.0.0.info", FakeAnswer::Body(info("v1.0.0", Some(OLD))));
    registry.answer("/mid.example/m/@v/v1.0.0.mod", FakeAnswer::Body("module mid.example/m // old snapshot\n".to_owned()));
    let held = Arc::new(HeldMod { inner: registry, arrived: Default::default(), release: Default::default() });
    let server = Arc::new(TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), Arc::clone(&held) as Arc<dyn Transport>, fake_origins()).await);
    let fetch = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let response = server.get("/go/mid.example/m/@v/v1.0.0.mod").await;
            (response.status().as_u16(), response.text().await.unwrap())
        })
    };
    held.arrived.notified().await;
    let mut blocked = snapshot(0, None, None);
    blocked.revision = 2;
    for link in &mut blocked.place_chain {
        link.layer_revision = 2;
    }
    for layer in &mut blocked.layers {
        layer.revision = 2;
        if layer.place.kind == LayerKind::Org {
            layer.layer.blocks.push(probation_policy::Block::Package { ecosystem: probation_policy::Ecosystem::Go, name: "mid.example/m".to_owned(), reason: None });
        }
    }
    policy.reset().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(blocked)).mount(&policy).await;
    server.app().service_policy().expect("service mode").sync_once().await.expect("the new snapshot activates");
    held.release.notify_one();
    let (status, body) = fetch.await.unwrap();
    assert_eq!(status, 403, "{body}");
    assert!(!body.contains("old snapshot"));
}
