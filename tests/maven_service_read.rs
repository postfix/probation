//! Row 21: the Maven READ path through the shared service for a selected registry with a real `target_url` (an Artifactory-style
//! layout under a path prefix), what a credential-bearing read forwards and shares (C1028), the upstream 401/403 codes, the
//! declared archive origin, the bounded process tables and the verbs the read routes refuse.
mod common;

use common::maven::{self, jar, metadata, pom, http_date};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{Transport, UpstreamError};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{num::{NonZeroU32, NonZeroU64}, sync::Arc};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

const HOST: &str = "https://reg.invalid";
const PREFIX: &str = "/artifactory/libs-release";
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn snapshot_with(freeze: u64, target: Option<&str>, archive: Option<&str>, count: u64) -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    let mut snapshot = ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer { freeze_seconds: Some(freeze), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor {
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Maven, target_url: target.map(str::to_owned),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive.map(str::to_owned), resource_path_prefix: None,
        }],
    };
    for n in 1..count {
        snapshot.registries.push(RegistryDescriptor {
            registry: RegistryId(7 + n), ecosystem: probation_policy::Ecosystem::Maven, target_url: Some(format!("https://reg{n}.invalid/repo/")),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        });
    }
    snapshot
}

/// (path, read authorization, archive origin, whether a redirect to it may be followed) of one artifact request.
type Artifact = (String, Option<String>, Option<url::Url>, bool);

struct Recording {
    inner: Arc<FakeRegistry>,
    metadata_auth: std::sync::Mutex<Vec<(String, Option<String>)>>,
    artifacts: std::sync::Mutex<Vec<Artifact>>,
}

#[async_trait::async_trait]
impl Transport for Recording {
    async fn fetch_metadata(&self, request: probation::upstream::MetadataRequest) -> Result<probation::upstream::MetadataResponse, UpstreamError> {
        self.metadata_auth.lock().unwrap().push((request.url.path().to_owned(), request.read_authorization.clone()));
        self.inner.fetch_metadata(request).await
    }
    async fn open_artifact(&self, request: probation::upstream::ArtifactRequest) -> Result<probation::upstream::ArtifactBody, UpstreamError> {
        self.artifacts.lock().unwrap().push((request.url.path().to_owned(), request.read_authorization.clone(), request.archive_origin.clone(), request.allow_archive_redirect));
        self.inner.open_artifact(request).await
    }
}

struct Fixture {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    recording: Arc<Recording>,
    clock: Arc<TestClock>,
    _policy: MockServer,
}

async fn start(freeze: u64, target: Option<&str>, archive: Option<&str>) -> Fixture {
    start_n(freeze, target, archive, 1).await
}

async fn start_n(freeze: u64, target: Option<&str>, archive: Option<&str>, count: u64) -> Fixture {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot_with(freeze, target, archive, count))).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.max_references_per_project = NonZeroU32::new(40).unwrap();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let registry = FakeRegistry::new();
    let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
    let recording = Arc::new(Recording { inner: Arc::clone(&registry), metadata_auth: Default::default(), artifacts: Default::default() });
    let origins = fake_origins().with_maven(url::Url::parse(maven::REPO).unwrap(), url::Url::parse(maven::PUBLISH).unwrap());
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&recording) as Arc<dyn Transport>, origins).await;
    Fixture { server, registry, recording, clock, _policy: policy }
}

fn target() -> String {
    format!("{HOST}{PREFIX}/")
}

/// A private registry: `corp:lib` with 1.0 old and 2.0 young, laid out under `PREFIX` on its own host.
fn private_registry(f: &Fixture) {
    f.registry.answer(&format!("{PREFIX}/corp/lib/maven-metadata.xml"), FakeAnswer::Body(metadata("corp", "lib", "2.0", "2.0", &["1.0", "2.0"])));
    for (version, date) in [("1.0", OLD), ("2.0", YOUNG)] {
        let dir = format!("{PREFIX}/corp/lib/{version}");
        f.registry.answer(&format!("{dir}/lib-{version}.pom"), FakeAnswer::Dated { body: pom("corp", "lib", version).into_bytes(), last_modified: http_date(date) });
        f.registry.answer(&format!("{dir}/lib-{version}.jar"), FakeAnswer::Dated { body: jar("lib", version), last_modified: http_date(date) });
    }
}

fn calls(f: &Fixture, needle: &str) -> usize {
    f.registry.calls().iter().filter(|u| u.path().contains(needle)).count()
}

#[tokio::test]
async fn a_selected_registry_is_read_from_its_own_layout_through_both_roots() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f);
    for root in ["/maven", "/registry/maven/7"] {
        let metadata = f.server.get(&format!("{root}/corp/lib/maven-metadata.xml")).await;
        let (status, body) = (metadata.status().as_u16(), metadata.text().await.unwrap());
        assert_eq!(status, 200, "{root}");
        assert!(body.contains("<version>1.0</version>") && !body.contains("<version>2.0</version>") && body.contains("<release>1.0</release>"), "{root}: {body}");
        let jar = f.server.get(&format!("{root}/corp/lib/1.0/lib-1.0.jar")).await;
        assert_eq!((jar.status().as_u16(), jar.bytes().await.unwrap().to_vec()), (200, maven::jar("lib", "1.0")), "{root}");
        assert_eq!(f.server.get(&format!("{root}/corp/lib/2.0/lib-2.0.jar")).await.status().as_u16(), 403, "{root}");
    }
    // Every upstream call stayed on the registry's own host and under its own layout.
    assert!(f.registry.calls().iter().all(|url| url.host_str() == Some("reg.invalid") && url.path().starts_with(PREFIX)), "{:?}", f.registry.calls());
    assert_eq!(calls(&f, "lib-2.0.jar"), 0);
    // A registry that is not this family's, or an unknown id, is no route.
    assert_eq!(f.server.get("/registry/maven/8/corp/lib/maven-metadata.xml").await.status(), 404);
    assert_eq!(f.server.get("/registry/go/7/example.com/m/@v/list").await.status(), 404);
    f.server.shutdown().await;
}

/// The caller's own registry credential goes to the registry's origin with every read, never anywhere else, and the
/// service key never leaves.
#[tokio::test]
async fn the_callers_credential_travels_to_the_registry_only() {
    let f = start(0, Some(&target()), None).await;
    private_registry(&f);
    let carrier = [("authorization", "Basic dXNlcjpwdw==")];
    assert_eq!(f.server.get_with_headers("/maven/corp/lib/maven-metadata.xml", &carrier).await.status().as_u16(), 200);
    assert_eq!(f.server.get_with_headers("/maven/corp/lib/1.0/lib-1.0.jar", &carrier).await.status().as_u16(), 200);
    let metadata = f.recording.metadata_auth.lock().unwrap().clone();
    assert!(metadata.len() >= 3 && metadata.iter().all(|(_, auth)| auth.as_deref() == Some("Basic dXNlcjpwdw==")), "{metadata:?}");
    let artifacts = f.recording.artifacts.lock().unwrap().clone();
    assert!(!artifacts.is_empty() && artifacts.iter().all(|(_, auth, ..)| auth.as_deref() == Some("Basic dXNlcjpwdw==")), "{artifacts:?}");
    assert!(metadata.iter().all(|(_, auth)| auth.as_deref() != Some("prb_01234567890123456789012345678901")));
    // A header that is not a Basic or Bearer credential is refused as one.
    assert_eq!(f.server.get_with_headers("/maven/corp/lib/maven-metadata.xml", &[("authorization", "prb_x")]).await.status().as_u16(), 401);
    f.server.shutdown().await;
}

/// C1028 and the share: credential-free reads of one artifact's metadata within a few seconds cost one fetch; a read that
/// carries the caller's credential fetches for itself, every time, and fills nothing a credential-free read can find.
#[tokio::test]
async fn a_credentialed_read_shares_nothing_and_a_credential_free_one_shares_for_a_moment() {
    let f = start(0, Some(&target()), None).await;
    private_registry(&f);
    for _ in 0..3 {
        assert_eq!(f.server.get("/maven/corp/lib/maven-metadata.xml").await.status().as_u16(), 200);
    }
    assert_eq!(calls(&f, "/corp/lib/maven-metadata.xml"), 1, "credential-free reads share the fetched document");
    let carrier = [("authorization", "Basic dXNlcjpwdw==")];
    for _ in 0..3 {
        assert_eq!(f.server.get_with_headers("/maven/corp/lib/maven-metadata.xml", &carrier).await.status().as_u16(), 200);
    }
    assert_eq!(calls(&f, "/corp/lib/maven-metadata.xml"), 4, "each credentialed read fetched for itself and read the share of none");
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get("/maven/corp/lib/maven-metadata.xml").await.status().as_u16(), 200);
    assert_eq!(calls(&f, "/corp/lib/maven-metadata.xml"), 5, "the credentialed reads left nothing for this one, and the share expires");
    // Bytes fetched under a credential are never served without it.
    assert_eq!(f.server.get_with_headers("/maven/corp/lib/1.0/lib-1.0.jar", &carrier).await.status().as_u16(), 200);
    f.registry.answer(&format!("{PREFIX}/corp/lib/1.0/lib-1.0.jar"), FakeAnswer::Fail(UpstreamError::Status(401)));
    assert_eq!(f.server.get("/maven/corp/lib/1.0/lib-1.0.jar").await.status().as_u16(), 401, "the credential-free read does not find the credentialed bytes");
    f.server.shutdown().await;
}

#[tokio::test]
async fn upstream_401_and_403_have_their_own_codes_and_a_missing_artifact_is_404() {
    let f = start(0, None, None).await;
    f.registry.answer("/maven2/corp/login/maven-metadata.xml", FakeAnswer::Fail(UpstreamError::Status(401)));
    f.registry.answer("/maven2/corp/deny/maven-metadata.xml", FakeAnswer::Fail(UpstreamError::Status(403)));
    f.registry.answer("/maven2/corp/down/maven-metadata.xml", FakeAnswer::Fail(UpstreamError::Status(503)));
    f.registry.answer("/maven2/corp/gone/maven-metadata.xml", FakeAnswer::Missing);
    let code = |answer: reqwest::Response| async move {
        let status = answer.status().as_u16();
        let challenge = answer.headers().get("www-authenticate").map(|v| v.to_str().unwrap().to_owned());
        let body: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap_or_default();
        (status, body["error"].as_str().unwrap_or_default().to_owned(), challenge)
    };
    let (status, error, challenge) = code(f.server.get("/maven/corp/login/maven-metadata.xml").await).await;
    assert_eq!((status, error.as_str()), (401, "UPSTREAM_AUTHENTICATION_REQUIRED"));
    assert!(challenge.is_some_and(|c| c.starts_with("Basic")), "a registry's own 401 carries the challenge Maven needs to send its credential");
    assert_eq!(code(f.server.get("/maven/corp/deny/maven-metadata.xml").await).await.0, 403);
    assert_eq!(code(f.server.get("/maven/corp/down/maven-metadata.xml").await).await.0, 502);
    assert_eq!(code(f.server.get("/maven/corp/gone/maven-metadata.xml").await).await.0, 404);
    f.server.shutdown().await;
}

/// The archive origin a Maven registry declares reaches the transport with its jar (so a redirect may land there), only for a
/// registry that declared one, and only a large file's transfer may follow it (a POM or a checksum never does).
#[tokio::test]
async fn a_declared_maven_archive_origin_travels_with_the_jar_request_only() {
    for (archive, expected) in [(Some("https://blobs.invalid/store"), Some("https://blobs.invalid/store")), (None, None)] {
        let f = start(0, Some(&target()), archive).await;
        private_registry(&f);
        f.registry.answer(&format!("{PREFIX}/corp/lib/1.0/lib-1.0.jar.sha1"), FakeAnswer::Body("00".into()));
        for file in ["lib-1.0.jar", "lib-1.0.pom", "lib-1.0.jar.sha1"] {
            assert_eq!(f.server.get(&format!("/maven/corp/lib/1.0/{file}")).await.status().as_u16(), 200, "{file}");
        }
        let seen = f.recording.artifacts.lock().unwrap().clone();
        assert!(seen.len() >= 3, "{seen:?}");
        assert!(seen.iter().all(|(_, _, origin, _)| origin.as_ref().map(url::Url::as_str) == expected), "{archive:?}: {seen:?}");
        assert!(seen.iter().all(|(path, _, _, allow)| *allow == path.ends_with(".jar")), "{seen:?}");
        f.server.shutdown().await;
    }
}

/// Every route is a read here (the deploy verbs are class W, tests/maven_service_write.rs): another verb or a query reaches nothing.
#[tokio::test]
async fn reads_are_read_only_and_a_query_is_no_route() {
    let f = start(0, None, None).await;
    let before = f.registry.calls().len();
    let client = reqwest::Client::new();
    for (verb, path) in [("POST", "/maven/corp/lib/maven-metadata.xml"), ("PATCH", "/registry/maven/7/corp/lib/1.0/lib-1.0.jar"), ("POST", "/maven/archetype-catalog.xml")] {
        let response = client.request(verb.parse().unwrap(), f.server.url(path)).body("x").send().await.unwrap();
        assert!(matches!(response.status().as_u16(), 404 | 405), "{verb} {path}: {}", response.status());
    }
    assert_eq!(f.server.get("/maven/corp/lib/maven-metadata.xml?token=abc").await.status(), 404, "a query string is no route");
    assert_eq!(f.registry.calls().len(), before, "nothing reached upstream");
    f.server.shutdown().await;
}

/// The process tables stay bounded: one cell per artifact (128), eight shared documents, the gates.
#[tokio::test]
async fn the_process_tables_stay_bounded() {
    let f = start(0, None, None).await;
    for n in 0..200 {
        f.registry.answer(&format!("/maven2/corp/a{n}/maven-metadata.xml"), FakeAnswer::Body(metadata("corp", &format!("a{n}"), "1.0", "1.0", &["1.0"])));
        f.registry.answer(&format!("/maven2/corp/a{n}/1.0/a{n}-1.0.pom"), FakeAnswer::Dated { body: pom("corp", &format!("a{n}"), "1.0").into_bytes(), last_modified: http_date(OLD) });
        assert_eq!(f.server.get(&format!("/maven/corp/a{n}/maven-metadata.xml")).await.status().as_u16(), 200);
    }
    let [cells, raw, gates] = probation::maven::serve::table_sizes(&f.server.app());
    assert!(cells <= 128 && raw <= 8 && gates <= 256, "{cells} {raw} {gates}");
    f.server.shutdown().await;
}

/// F1 + C1028: credential-free reads share the fetched archetype catalog for a moment; a read that carries the caller's credential
/// fetches its own copy every time and leaves none behind.
#[tokio::test]
async fn the_archetype_catalog_is_shared_for_credential_free_reads_only() {
    let f = start(0, Some(&target()), None).await;
    f.registry.answer(&format!("{PREFIX}/archetype-catalog.xml"), FakeAnswer::Body("<archetype-catalog><archetypes></archetypes></archetype-catalog>".into()));
    for _ in 0..3 {
        assert_eq!(f.server.get("/maven/archetype-catalog.xml").await.status().as_u16(), 200);
    }
    assert_eq!(calls(&f, "/archetype-catalog.xml"), 1, "credential-free reads share one fetch");
    let carrier = [("authorization", "Basic dXNlcjpwdw==")];
    for _ in 0..3 {
        assert_eq!(f.server.get_with_headers("/maven/archetype-catalog.xml", &carrier).await.status().as_u16(), 200);
    }
    assert_eq!(calls(&f, "/archetype-catalog.xml"), 4, "each credentialed read fetched its own and none read the shared copy");
    assert!(f.recording.metadata_auth.lock().unwrap().iter().filter(|(p, a)| p.ends_with("archetype-catalog.xml") && a.is_some()).count() == 3);
    f.server.shutdown().await;
}

/// R4: a credentialed catalog read holds its own registry's slot, never the one the public registry's reads wait for.
#[tokio::test]
async fn a_slow_private_catalog_does_not_keep_another_registrys_catalog_waiting() {
    let f = start_n(0, Some(&target()), None, 2).await;
    let gate = common::Gate::new();
    let doc = "<archetype-catalog><archetypes></archetypes></archetype-catalog>".to_owned();
    f.registry.answer(&format!("{PREFIX}/archetype-catalog.xml"), FakeAnswer::GatedMetadata { body: doc.clone(), gate: Arc::clone(&gate) });
    f.registry.answer("/repo/archetype-catalog.xml", FakeAnswer::Body(doc));
    let slow = {
        let url = f.server.url("/registry/maven/7/archetype-catalog.xml");
        tokio::spawn(async move { reqwest::Client::new().get(url).header("authorization", "Basic dXNlcjpwdw==").send().await.unwrap().status().as_u16() })
    };
    gate.wait_until_reached().await;
    let started = std::time::Instant::now();
    let other = f.server.get_with_headers("/registry/maven/8/archetype-catalog.xml", &[("authorization", "Basic dXNlcjpwdw==")]).await;
    assert_eq!(other.status().as_u16(), 200, "another registry's catalog is answered while the slow one is held");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    gate.release();
    assert_eq!(slow.await.unwrap(), 200);
    f.server.shutdown().await;
}
