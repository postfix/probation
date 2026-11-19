//! Row 18 review follow-ups (F1, F5, F6, L2): the Cargo READ path through the shared service for a
//! selected registry with a real `target_url` (an Artifactory-style layout), its first-seen rule, the
//! spelling cap, the upstream call count, and the `Cargo login_url` challenge on a 401.
mod common;

use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::Transport;
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU64, sync::Arc};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

const PREFIX: &str = "/api/cargo/repo/index";
const OLD: &str = "2025-01-01T00:00:00Z";

fn snapshot(freeze: u64, archive_origin: Option<&str>) -> ServicePolicySnapshot {
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
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Cargo, target_url: Some(format!("https://reg.invalid{PREFIX}/")),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive_origin.map(str::to_owned), resource_path_prefix: None,
        }],
    }
}

struct Fixture {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    _policy: MockServer,
}

async fn start(freeze: u64, dl: &str) -> Fixture {
    start_with(freeze, dl, None).await
}

async fn start_with(freeze: u64, dl: &str, archive_origin: Option<&str>) -> Fixture {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot(freeze, archive_origin))).mount(&policy).await;
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
    registry.answer(&format!("{PREFIX}/config.json"), FakeAnswer::Body(format!(r#"{{"dl":"{dl}"}}"#)));
    let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, fake_origins()).await;
    Fixture { server, registry, clock, _policy: policy }
}

fn line(name: &str, vers: &str, bytes: &[u8], pubtime: Option<&str>) -> String {
    let pubtime = pubtime.map(|at| format!(r#","pubtime":"{at}""#)).unwrap_or_default();
    format!(r#"{{"name":"{name}","vers":"{vers}","deps":[],"cksum":"{}","features":{{}},"yanked":false{pubtime}}}"#, hex::encode(Sha256::digest(bytes)))
}

fn calls(f: &Fixture, path: &str) -> usize {
    f.registry.calls().iter().filter(|url| url.path() == path).count()
}

/// F1: a selected registry with a real `target_url`: config, index filter and download all go through
/// `/registry/cargo/{id}/`, from the registry's own prefix, and an archive outside that prefix is refused.
#[tokio::test]
async fn selected_registry_reads_index_and_downloads_under_its_own_prefix() {
    let f = start(0, &format!("https://reg.invalid{PREFIX}/crates")).await;
    let bytes = b"selected crate bytes".to_vec();
    f.registry.answer(&format!("{PREFIX}/de/mo/demo"), FakeAnswer::Body(format!("{}\n", line("demo", "1.0.0", &bytes, Some(OLD)))));
    f.registry.answer(&format!("{PREFIX}/crates/demo/1.0.0/download"), FakeAnswer::Bytes(bytes.clone()));
    let index = f.server.get("/registry/cargo/7/de/mo/demo").await;
    assert_eq!(index.status(), 200);
    assert!(index.text().await.unwrap().contains(r#""vers":"1.0.0""#));
    let config = f.server.get("/registry/cargo/7/config.json").await;
    assert_eq!(config.status(), 200);
    assert!(config.text().await.unwrap().contains("/registry/cargo/7/crates"), "dl names the selected endpoint");
    let archive = f.server.get("/registry/cargo/7/crates/demo/1.0.0/download").await;
    assert_eq!((archive.status().as_u16(), archive.bytes().await.unwrap().to_vec()), (200, bytes));
    // The unqualified root reaches the same registry.
    assert_eq!(f.server.get("/cargo/de/mo/demo").await.status(), 200);
    f.server.shutdown().await;
}

#[tokio::test]
async fn selected_registry_with_a_dl_outside_its_prefix_is_refused_with_502() {
    for dl in ["https://reg.invalid/api/cargo/repo/crates", "https://static.invalid/crates", "https://reg.invalid:8443/api/cargo/repo/index/crates"] {
        let f = start(0, dl).await;
        let bytes = b"x".to_vec();
        f.registry.answer(&format!("{PREFIX}/de/mo/demo"), FakeAnswer::Body(format!("{}\n", line("demo", "1.0.0", &bytes, Some(OLD)))));
        assert_eq!(f.server.get("/registry/cargo/7/de/mo/demo").await.status(), 502, "{dl}");
        assert_eq!(f.server.get("/registry/cargo/7/crates/demo/1.0.0/download").await.status(), 502, "{dl}");
        assert!(f.registry.calls().iter().all(|url| url.host_str() != Some("static.invalid") && !url.path().ends_with("/download")), "{dl}: nothing fetched from outside the prefix");
        f.server.shutdown().await;
    }
}

/// F5: the service-mode first-seen rule for an undated version (the commit path is the same as standalone's).
#[tokio::test]
async fn service_mode_undated_version_waits_on_first_seen() {
    let f = start(7 * 86_400, &format!("https://reg.invalid{PREFIX}/crates")).await;
    let bytes = b"u".to_vec();
    let undated = line("undated", "1.0.0", &bytes, None);
    f.registry.answer(&format!("{PREFIX}/un/da/undated"), FakeAnswer::Body(format!("{undated}\n")));
    assert_eq!(f.server.get("/cargo/un/da/undated").await.text().await.unwrap(), "", "held from the moment it was first seen");
    f.clock.advance_seconds(6 * 86_400);
    assert_eq!(f.server.get("/cargo/un/da/undated").await.text().await.unwrap(), "", "six days");
    f.clock.advance_seconds(2 * 86_400);
    assert_eq!(f.server.get("/cargo/un/da/undated").await.text().await.unwrap(), format!("{undated}\n"), "eight days since first seen");
    f.server.shutdown().await;
}

/// F5: the 4-spelling cap and its "costs upstream nothing" rule hold in service mode too.
#[tokio::test]
async fn service_mode_commits_at_most_four_spellings_of_a_crate() {
    let f = start(0, &format!("https://reg.invalid{PREFIX}/crates")).await;
    let bytes = b"s".to_vec();
    let variants = ["a-b-c-d", "a_b-c-d", "a-b_c-d", "a-b-c_d", "a_b_c_d"];
    let url = |variant: &str| format!("/cargo/{}", probation::cargo_registry::index::index_segments(variant).join("/"));
    for variant in variants {
        f.registry.answer(&format!("{PREFIX}/{}", probation::cargo_registry::index::index_segments(variant).join("/")), FakeAnswer::Body(format!("{}\n", line(variant, "1.0.0", &bytes, Some(OLD)))));
    }
    for variant in &variants[..4] {
        assert_eq!(f.server.get(&url(variant)).await.status(), 200, "{variant}");
    }
    let before = f.registry.calls().len();
    assert_eq!(f.server.get(&url(variants[4])).await.status(), 404);
    assert_eq!(f.registry.calls().len(), before, "a fifth spelling costs upstream nothing");
    f.server.shutdown().await;
}

/// F6/L3: shareable reads in service mode share one index and one config fetch for a few seconds;
/// a credential-bearing read neither reads nor fills that.
#[tokio::test]
async fn service_mode_index_fetches_are_shared_for_plain_reads_and_never_for_credentialed_ones() {
    let f = start(0, &format!("https://reg.invalid{PREFIX}/crates")).await;
    let bytes = b"memo".to_vec();
    let index = format!("{PREFIX}/de/mo/demo");
    f.registry.answer(&index, FakeAnswer::Body(format!("{}\n", line("demo", "1.0.0", &bytes, Some(OLD)))));
    f.registry.answer(&format!("{PREFIX}/crates/demo/1.0.0/download"), FakeAnswer::Bytes(bytes));
    let plain = [("accept", "*/*")];
    for _ in 0..3 {
        assert_eq!(f.server.get_with_headers("/cargo/de/mo/demo", &plain).await.status(), 200);
    }
    assert_eq!(f.server.get_with_headers("/cargo/crates/demo/1.0.0/download", &plain).await.status(), 200);
    assert_eq!(calls(&f, &index), 1, "four plain reads cost one index fetch");
    assert_eq!(calls(&f, &format!("{PREFIX}/config.json")), 1);
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get_with_headers("/cargo/de/mo/demo", &plain).await.status(), 200);
    assert_eq!(calls(&f, &index), 2, "the share is short");
    let before = calls(&f, &index);
    for _ in 0..3 {
        assert_eq!(f.server.get_with_headers("/cargo/de/mo/demo", &[("authorization", "tok")]).await.status(), 200);
    }
    assert_eq!(calls(&f, &index), before + 3, "a credential-bearing read never reads the share");
    assert_eq!(f.server.get_with_headers("/cargo/de/mo/demo", &plain).await.status(), 200);
    assert_eq!(calls(&f, &index), before + 3, "and none of them filled the share: the plain read reused the earlier plain fetch and fetched nothing");
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get_with_headers("/cargo/de/mo/demo", &plain).await.status(), 200);
    assert_eq!(calls(&f, &index), before + 4);
    f.server.shutdown().await;
}

/// L2: in service mode a registry that refuses the (absent) token is answered with the Cargo challenge,
/// so cargo runs its credential provider; a registry's 403 is not a login request.
#[tokio::test]
async fn service_mode_upstream_401_carries_the_cargo_login_challenge() {
    let f = start(0, &format!("https://reg.invalid{PREFIX}/crates")).await;
    f.registry.answer(&format!("{PREFIX}/lo/gi/login"), FakeAnswer::Fail(probation::upstream::UpstreamError::Status(401)));
    f.registry.answer(&format!("{PREFIX}/de/ny/deny"), FakeAnswer::Fail(probation::upstream::UpstreamError::Status(403)));
    for path in ["/cargo/lo/gi/login", "/registry/cargo/7/lo/gi/login"] {
        let response = f.server.get(path).await;
        assert_eq!(response.status(), 401, "{path}");
        let challenge: Vec<String> = response.headers().get_all("www-authenticate").iter().map(|v| v.to_str().unwrap().to_owned()).collect();
        assert!(challenge.iter().any(|c| c.starts_with("Cargo login_url=\"") && c.contains("/registry/cargo/7/")), "{path}: {challenge:?}");
    }
    let denied = f.server.get("/cargo/de/ny/deny").await;
    assert_eq!(denied.status(), 403);
    assert!(denied.headers().get_all("www-authenticate").iter().next().is_none());
    f.server.shutdown().await;
}

/// The user's decision of 2026-11-19: a registry whose archives are not under its index URL declares an
/// archive origin; its archives are fetched from there only, and the index host's credential does not follow.
#[tokio::test]
async fn a_declared_archive_origin_admits_archives_outside_the_index_prefix() {
    for (dl, archive) in [
        ("https://reg.invalid/api/cargo/repo/crates", "https://reg.invalid/api/cargo/repo/crates"),
        ("https://files.invalid/crates", "https://files.invalid/crates"),
        ("https://files.invalid/crates", "https://files.invalid/"),
    ] {
        let f = start_with(0, dl, Some(archive)).await;
        let bytes = b"archived crate".to_vec();
        f.registry.answer(&format!("{PREFIX}/de/mo/demo"), FakeAnswer::Body(format!("{}\n", line("demo", "1.0.0", &bytes, Some(OLD)))));
        let archive_path = format!("{}/demo/1.0.0/download", dl.split_once("invalid").unwrap().1);
        f.registry.answer(&archive_path, FakeAnswer::Bytes(bytes.clone()));
        assert_eq!(f.server.get("/registry/cargo/7/de/mo/demo").await.status(), 200, "{dl}");
        let archive_fetch = f.server.get("/registry/cargo/7/crates/demo/1.0.0/download").await;
        assert_eq!((archive_fetch.status().as_u16(), archive_fetch.bytes().await.unwrap().to_vec()), (200, bytes), "{dl}");
        let fetched = f.registry.calls().into_iter().find(|url| url.path() == archive_path).expect("the archive was fetched");
        assert_eq!(fetched.host_str(), Some(dl.split("//").nth(1).unwrap().split('/').next().unwrap()));
        f.server.shutdown().await;
    }
}

#[tokio::test]
async fn a_dl_outside_the_declared_archive_origin_is_still_refused() {
    for dl in ["https://evil.invalid/crates", "https://files.invalid/other", "https://files.invalid:8443/crates", "https://reg.invalid/api/cargo/repo/index/crates"] {
        let f = start_with(0, dl, Some("https://files.invalid/crates")).await;
        let bytes = b"x".to_vec();
        f.registry.answer(&format!("{PREFIX}/de/mo/demo"), FakeAnswer::Body(format!("{}\n", line("demo", "1.0.0", &bytes, Some(OLD)))));
        assert_eq!(f.server.get("/registry/cargo/7/de/mo/demo").await.status(), 502, "{dl}: the index target's own prefix no longer admits archives once an archive origin is declared");
        assert_eq!(f.server.get("/registry/cargo/7/crates/demo/1.0.0/download").await.status(), 502, "{dl}");
        assert!(f.registry.calls().iter().all(|url| !url.path().ends_with("/download")), "{dl}: nothing fetched");
        f.server.shutdown().await;
    }
}

/// A transport whose archive download waits for the test, so a snapshot can change in flight.
struct Gated {
    inner: Arc<FakeRegistry>,
    arrived: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Transport for Gated {
    async fn fetch_metadata(&self, request: probation::upstream::MetadataRequest) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError> {
        self.inner.fetch_metadata(request).await
    }
    async fn open_artifact(&self, request: probation::upstream::ArtifactRequest) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
        self.arrived.notify_one();
        self.release.notified().await;
        self.inner.open_artifact(request).await
    }
}

/// N3: a download admitted under one archive origin is not delivered when the registry's descriptor has
/// lost or changed it by the time the bytes are verified (the stale reference fails closed). The shared
/// service's publication gate refuses the in-flight response too; the recheck is the second guard.
#[tokio::test]
async fn a_download_in_flight_when_the_archive_origin_changes_is_not_delivered() {
    let policy = MockServer::start().await;
    let archive = "https://files.invalid/crates";
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot(0, Some(archive)))).mount(&policy).await;
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
    registry.answer(&format!("{PREFIX}/config.json"), FakeAnswer::Body(format!(r#"{{"dl":"{archive}"}}"#)));
    let bytes = b"in flight".to_vec();
    registry.answer(&format!("{PREFIX}/de/mo/demo"), FakeAnswer::Body(format!("{}\n", line("demo", "1.0.0", &bytes, Some(OLD)))));
    registry.answer("/crates/demo/1.0.0/download", FakeAnswer::Bytes(bytes));
    let gated = Arc::new(Gated { inner: registry, arrived: Default::default(), release: Default::default() });
    let server = Arc::new(TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), Arc::clone(&gated) as Arc<dyn Transport>, fake_origins()).await);
    let fetch = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.get("/registry/cargo/7/crates/demo/1.0.0/download").await.status() })
    };
    gated.arrived.notified().await;
    // The registry's descriptor loses its archive origin while the archive is in flight.
    policy.reset().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot(0, None))).mount(&policy).await;
    server.app().service_policy().expect("service mode").sync_once().await.expect("the new snapshot activates");
    gated.release.notify_one();
    let status = fetch.await.unwrap();
    // The publication refuses the finished response; it is admitted again under the new snapshot, whose descriptor has no
    // archive origin any more, so the archive is outside the registry's prefix: refused, never delivered.
    assert!(matches!(status.as_u16(), 404 | 502), "the stale download is refused under the new snapshot, not delivered: {status}");
}

/// Recheck N3 (generic, shared service): a block published while a download is in flight must win. The finished response
/// is refused by the publication gate, the request is admitted again under the new snapshot and is 403 there; the bytes
/// admitted under the old snapshot are never delivered.
#[tokio::test]
async fn a_block_published_while_a_download_is_in_flight_wins() {
    let policy = MockServer::start().await;
    let archive = format!("https://reg.invalid{PREFIX}/crates");
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot(0, None))).mount(&policy).await;
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
    registry.answer(&format!("{PREFIX}/config.json"), FakeAnswer::Body(format!(r#"{{"dl":"{archive}"}}"#)));
    let bytes = b"admitted under the old snapshot".to_vec();
    registry.answer(&format!("{PREFIX}/de/mo/demo"), FakeAnswer::Body(format!("{}\n", line("demo", "1.0.0", &bytes, Some(OLD)))));
    registry.answer(&format!("{PREFIX}/crates/demo/1.0.0/download"), FakeAnswer::Bytes(bytes));
    let gated = Arc::new(Gated { inner: registry, arrived: Default::default(), release: Default::default() });
    let server = Arc::new(TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), Arc::clone(&gated) as Arc<dyn Transport>, fake_origins()).await);
    let fetch = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let response = server.get("/registry/cargo/7/crates/demo/1.0.0/download").await;
            (response.status(), response.text().await.unwrap())
        })
    };
    gated.arrived.notified().await;
    let mut blocked = snapshot(0, None);
    blocked.revision = 2;
    for layer in &mut blocked.place_chain {
        layer.layer_revision = 2;
    }
    for layer in &mut blocked.layers {
        layer.revision = 2;
        if layer.place.kind == LayerKind::Org {
            layer.layer.blocks.push(probation_policy::Block::Package { ecosystem: probation_policy::Ecosystem::Cargo, name: "demo".to_owned(), reason: None });
        }
    }
    policy.reset().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(blocked)).mount(&policy).await;
    server.app().service_policy().expect("service mode").sync_once().await.expect("the new snapshot activates");
    gated.release.notify_one();
    let (status, body) = fetch.await.unwrap();
    assert_eq!(status, 403, "the block wins over the response admitted before it: {body}");
    assert!(!body.contains("admitted under the old snapshot"));
}
