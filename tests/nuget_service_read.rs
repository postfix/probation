//! Row 20: the NuGet READ path through the shared service for a selected registry with a real `target_url`
//! (an Artifactory-style layout under a path prefix, resources anywhere on the registry's host), what a
//! credential-bearing read forwards and shares, the upstream 401/403 codes, the declared archive origin and the
//! read-only rule of every route but the four publish endpoints.
mod common;

use common::nuget::{self, flat_index, leaf, registration};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{Transport, UpstreamError};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{num::{NonZeroU32, NonZeroU64}, sync::Arc};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

const HOST: &str = "https://reg.invalid";
const PREFIX: &str = "/artifactory/api/nuget/repo";
const OLD: &str = "2025-01-01T00:00:00.000+00:00";
const YOUNG: &str = "2026-04-05T12:00:00.000+00:00";

/// `count` NuGet registries (ids 7, 8, ...) with `target` (the first) or hosts of their own, and the first with `prefix`.
fn snapshot_with(freeze: u64, target: Option<&str>, archive: Option<&str>, prefix: Option<&str>, count: u64) -> ServicePolicySnapshot {
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
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::NuGet, target_url: target.map(str::to_owned),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive.map(str::to_owned), resource_path_prefix: prefix.map(str::to_owned),
        }],
    };
    for n in 1..count {
        snapshot.registries.push(RegistryDescriptor {
            registry: RegistryId(7 + n), ecosystem: probation_policy::Ecosystem::NuGet, target_url: Some(format!("https://reg{n}.invalid/v3/index.json")),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        });
    }
    snapshot
}

/// (path, read authorization, archive origin, whether a redirect to it may be followed) of one artifact request.
type Artifact = (String, Option<String>, Option<url::Url>, bool);

/// A transport that answers like the fake registry and records what each request carried.
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
    _clock: Arc<TestClock>,
    _policy: MockServer,
}

async fn start(freeze: u64, target: Option<&str>, archive: Option<&str>) -> Fixture {
    start_full(freeze, target, archive, None, 1).await
}

async fn start_full(freeze: u64, target: Option<&str>, archive: Option<&str>, prefix: Option<&str>, count: u64) -> Fixture {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot_with(freeze, target, archive, prefix, count))).mount(&policy).await;
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
    let origins = fake_origins().with_nuget(
        url::Url::parse(nuget::INDEX_ORIGIN).unwrap(), url::Url::parse(nuget::SEARCH_ORIGIN).unwrap(), url::Url::parse(nuget::PUBLISH_ORIGIN).unwrap(),
    );
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&recording) as Arc<dyn Transport>, origins).await;
    Fixture { server, registry, recording, _clock: clock, _policy: policy }
}

/// A private registry: its service index names every resource under `PREFIX` on its own host (a layout that
/// differs from the index's own path, as Artifactory and Azure Artifacts do), plus search on another host.
fn private_registry(f: &Fixture, search_host: &str) {
    let index = serde_json::json!({"version": "3.0.0", "resources": [
        {"@id": format!("{HOST}{PREFIX}/flat/"), "@type": "PackageBaseAddress/3.0.0"},
        {"@id": format!("{HOST}{PREFIX}/registration/"), "@type": "RegistrationsBaseUrl/Versioned"},
        {"@id": format!("{search_host}/query"), "@type": "SearchQueryService"},
        {"@id": format!("{HOST}{PREFIX}/push"), "@type": "PackagePublish/2.0.0"},
    ]});
    f.registry.answer(&format!("{PREFIX}/v3/index.json"), FakeAnswer::Body(index.to_string()));
    let id = "corp.lib";
    f.registry.answer(&format!("{PREFIX}/flat/{id}/index.json"), FakeAnswer::Body(flat_index(&["1.0.0", "2.0.0"])));
    let mut leaves = vec![leaf(id, "1.0.0", Some(OLD), true), leaf(id, "2.0.0", Some(YOUNG), true)];
    for l in &mut leaves {
        // The leaves' own URLs name the registry's layout; this firewall rewrites them, so what they say does not matter.
        l["packageContent"] = serde_json::json!(format!("{HOST}{PREFIX}/flat/ignored"));
    }
    let (reg, _) = registration(id, &[leaves], &[]);
    f.registry.answer(&format!("{PREFIX}/registration/{id}/index.json"), FakeAnswer::Body(reg));
    for v in ["1.0.0", "2.0.0"] {
        f.registry.answer(&format!("{PREFIX}/flat/{id}/{v}/{id}.{v}.nupkg"), FakeAnswer::Bytes(nuget::nupkg(id, v)));
        f.registry.answer(&format!("{PREFIX}/flat/{id}/{v}/{id}.nuspec"), FakeAnswer::Body(nuget::nuspec(id, v)));
        f.registry.answer(&format!("{PREFIX}/flat/{id}/{v}/readme"), FakeAnswer::Body("# r".into()));
        f.registry.answer(&format!("{PREFIX}/flat/{id}/{v}/icon"), FakeAnswer::Bytes(vec![1, 2, 3]));
    }
}

fn calls(f: &Fixture, path: &str) -> usize {
    f.registry.calls().iter().filter(|u| u.path().ends_with(path)).count()
}

fn target() -> String {
    format!("{HOST}{PREFIX}/v3/index.json")
}

#[tokio::test]
async fn a_selected_registry_is_read_from_its_own_layout_through_both_roots() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f, HOST);
    for root in ["/nuget", "/registry/nuget/7"] {
        let (status, body) = (f.server.get(&format!("{root}/v3-flatcontainer/corp.lib/index.json")).await.status().as_u16(), f.server.get(&format!("{root}/v3-flatcontainer/corp.lib/index.json")).await.text().await.unwrap());
        assert_eq!((status, body.as_str()), (200, r#"{"versions":["1.0.0"]}"#), "{root}");
        let nupkg = f.server.get(&format!("{root}/v3-flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.nupkg")).await;
        assert_eq!((nupkg.status().as_u16(), nupkg.bytes().await.unwrap().to_vec()), (200, nuget::nupkg("corp.lib", "1.0.0")), "{root}");
        assert_eq!(f.server.get(&format!("{root}/v3-flatcontainer/corp.lib/2.0.0/corp.lib.nuspec")).await.status().as_u16(), 403, "{root}");
        let reg: serde_json::Value = f.server.get(&format!("{root}/v3/registration/corp.lib/index.json")).await.text().await.map(|t| serde_json::from_str(&t).unwrap()).unwrap();
        assert_eq!(reg["items"][0]["count"], 1, "{root}: {reg}");
    }
    let index: serde_json::Value = f.server.get("/nuget/v3/index.json").await.text().await.map(|t| serde_json::from_str(&t).unwrap()).unwrap();
    let kinds: Vec<&str> = index["resources"].as_array().unwrap().iter().map(|r| r["@type"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"PackagePublish/2.0.0") && kinds.contains(&"SearchQueryService"), "the shared service advertises what the registry offers: {kinds:?}");
    // Every upstream call stayed on the registry's own host and under its own layout.
    assert!(f.registry.calls().iter().all(|url| url.host_str() == Some("reg.invalid") && url.path().starts_with(PREFIX)), "{:?}", f.registry.calls());
    // A registry that is not this family's, or an unknown id, is no route.
    assert_eq!(f.server.get("/registry/nuget/8/v3/index.json").await.status(), 404);
    assert_eq!(f.server.get("/registry/go/7/example.com/m/@v/list").await.status(), 404);
    f.server.shutdown().await;
}

#[tokio::test]
async fn resources_on_another_host_than_the_selected_registrys_are_not_used() {
    let f = start(0, Some(&target()), None).await;
    private_registry(&f, "https://other.invalid");
    let index: serde_json::Value = f.server.get("/nuget/v3/index.json").await.text().await.map(|t| serde_json::from_str(&t).unwrap()).unwrap();
    let kinds: Vec<&str> = index["resources"].as_array().unwrap().iter().map(|r| r["@type"].as_str().unwrap()).collect();
    assert!(!kinds.contains(&"SearchQueryService"), "a search service on another host is skipped: {kinds:?}");
    assert_eq!(f.server.get("/nuget/v3/query?q=x").await.status(), 404);
    // A registry whose flat container is on another host cannot be served at all.
    let moved = serde_json::json!({"version": "3.0.0", "resources": [{"@id": "https://other.invalid/flat/", "@type": "PackageBaseAddress/3.0.0"}]});
    f.registry.answer(&format!("{PREFIX}/v3/index.json"), FakeAnswer::Body(moved.to_string()));
    f._clock.advance_seconds(120);
    assert_eq!(f.server.get("/nuget/v3-flatcontainer/corp.lib/index.json").await.status(), 502);
    assert!(f.registry.calls().iter().all(|url| url.host_str() == Some("reg.invalid")), "{:?}", f.registry.calls());
    f.server.shutdown().await;
}

/// The caller's own registry credential goes to the registry's origin with every read, never anywhere else,
/// and the service key never leaves.
#[tokio::test]
async fn the_callers_credential_travels_to_the_registry_only() {
    let f = start(0, Some(&target()), None).await;
    private_registry(&f, HOST);
    let carrier = [("authorization", "Basic dXNlcjpwdw==")];
    assert_eq!(f.server.get_with_headers("/nuget/v3-flatcontainer/corp.lib/index.json", &carrier).await.status().as_u16(), 200);
    assert_eq!(f.server.get_with_headers("/nuget/v3-flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.nupkg", &carrier).await.status().as_u16(), 200);
    let metadata = f.recording.metadata_auth.lock().unwrap().clone();
    assert!(metadata.len() >= 3 && metadata.iter().all(|(_, auth)| auth.as_deref() == Some("Basic dXNlcjpwdw==")), "{metadata:?}");
    let artifacts = f.recording.artifacts.lock().unwrap().clone();
    assert!(artifacts.iter().all(|(_, auth, ..)| auth.as_deref() == Some("Basic dXNlcjpwdw==")), "{artifacts:?}");
    assert!(metadata.iter().chain(artifacts.iter().map(|(p, a, ..)| (p.clone(), a.clone())).collect::<Vec<_>>().iter()).all(|(_, auth)| auth.as_deref() != Some("prb_01234567890123456789012345678901")));
    // A header that is not a Basic or Bearer credential is refused as one.
    assert_eq!(f.server.get_with_headers("/nuget/v3-flatcontainer/corp.lib/index.json", &[("authorization", "prb_x")]).await.status().as_u16(), 401);
    f.server.shutdown().await;
}

#[tokio::test]
async fn upstream_401_and_403_have_their_own_codes_and_a_missing_package_is_404() {
    let f = start(0, None, None).await;
    f.registry.answer("/v3/index.json", FakeAnswer::Body(nuget::service_index(&[])));
    f.registry.answer("/v3-flatcontainer/login.pkg/index.json", FakeAnswer::Fail(UpstreamError::Status(401)));
    f.registry.answer("/v3-flatcontainer/deny.pkg/index.json", FakeAnswer::Fail(UpstreamError::Status(403)));
    f.registry.answer("/v3-flatcontainer/down.pkg/index.json", FakeAnswer::Fail(UpstreamError::Status(503)));
    f.registry.answer("/v3-flatcontainer/gone.pkg/index.json", FakeAnswer::Missing);
    let code = |answer: reqwest::Response| async move {
        let status = answer.status().as_u16();
        let challenge = answer.headers().get("www-authenticate").map(|v| v.to_str().unwrap().to_owned());
        let body: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap_or_default();
        (status, body["error"].as_str().unwrap_or_default().to_owned(), challenge)
    };
    let (status, error, challenge) = code(f.server.get("/nuget/v3-flatcontainer/login.pkg/index.json").await).await;
    assert_eq!((status, error.as_str()), (401, "UPSTREAM_AUTHENTICATION_REQUIRED"));
    assert!(challenge.is_some_and(|c| c.starts_with("Basic")), "a registry's own 401 carries the challenge NuGet needs to send its credential");
    assert_eq!(code(f.server.get("/nuget/v3-flatcontainer/deny.pkg/index.json").await).await.0, 403);
    assert_eq!(code(f.server.get("/nuget/v3-flatcontainer/down.pkg/index.json").await).await.0, 502);
    assert_eq!(code(f.server.get("/nuget/v3-flatcontainer/gone.pkg/index.json").await).await.0, 404);
    f.server.shutdown().await;
}

/// The archive origin a NuGet registry declares reaches the transport with its package (so a redirect may land
/// there), only for a registry that declared one, and only the `.nupkg` transfer may follow it.
#[tokio::test]
async fn a_declared_nuget_archive_origin_travels_with_the_package_request_only() {
    for (archive, expected) in [(Some("https://blobs.invalid/store"), Some("https://blobs.invalid/store")), (None, None)] {
        let f = start(0, Some(&target()), archive).await;
        private_registry(&f, HOST);
        for file in ["corp.lib.1.0.0.nupkg", "corp.lib.nuspec", "readme", "icon"] {
            assert_eq!(f.server.get(&format!("/nuget/v3-flatcontainer/corp.lib/1.0.0/{file}")).await.status().as_u16(), 200, "{file}");
        }
        let seen = f.recording.artifacts.lock().unwrap().clone();
        assert!(seen.len() >= 4, "{seen:?}");
        assert!(seen.iter().all(|(_, _, origin, _)| origin.as_ref().map(url::Url::as_str) == expected), "{archive:?}: {seen:?}");
        assert!(seen.iter().all(|(path, _, _, allow)| *allow == path.ends_with(".nupkg")), "{seen:?}");
        f.server.shutdown().await;
    }
}

/// Every route but the four publish endpoints is a read: another verb or a query on it reaches nothing.
#[tokio::test]
async fn reads_are_read_only_and_a_query_is_only_for_search() {
    let f = start(0, None, None).await;
    let before = f.registry.calls().len();
    let client = reqwest::Client::new();
    for (verb, path) in [
        ("PUT", "/nuget/v3-flatcontainer/demo/1.0.0/demo.1.0.0.nupkg"),
        ("POST", "/nuget/v3/index.json"),
        ("DELETE", "/registry/nuget/7/v3/registration/demo/index.json"),
        ("PATCH", "/nuget/v3/query"),
        ("PUT", "/nuget/api/v2/other"),
    ] {
        let response = client.request(verb.parse().unwrap(), f.server.url(path)).body("x").send().await.unwrap();
        assert!(matches!(response.status().as_u16(), 404 | 405), "{verb} {path}: {}", response.status());
    }
    assert_eq!(f.server.get("/nuget/v3-flatcontainer/demo/index.json?token=abc").await.status(), 404, "a query string is no route");
    assert_eq!(f.server.get("/nuget/v3/index.json?x=1").await.status(), 404);
    assert_eq!(f.registry.calls().len(), before, "nothing reached upstream");
    f.server.shutdown().await;
}

/// Search and autocomplete through the shared service keep their query (the protocol's own keys, `take` bounded)
/// and are answered from the registry's own search host with only the allowed versions.
#[tokio::test]
async fn search_works_through_the_shared_service_with_its_query_keys() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f, HOST);
    f.registry.answer("/query", FakeAnswer::Body(serde_json::json!({"totalHits": 1, "data": [{
        "id": "Corp.Lib", "version": "2.0.0", "registration": format!("{HOST}{PREFIX}/registration/corp.lib/index.json"),
        "versions": [{"version": "1.0.0", "@id": "x"}, {"version": "2.0.0", "@id": "y"}],
    }]}).to_string()));
    for root in ["/nuget", "/registry/nuget/7"] {
        let answer = f.server.get(&format!("{root}/v3/query?q=corp&take=100&evil=1")).await;
        assert_eq!(answer.status().as_u16(), 200, "{root}");
        let doc: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap();
        assert_eq!((doc["data"][0]["version"].as_str(), doc["data"][0]["versions"].as_array().map(Vec::len)), (Some("1.0.0"), Some(1)), "{root}: {doc}");
    }
    let asked: Vec<url::Url> = f.registry.calls().into_iter().filter(|u| u.path() == "/query").collect();
    assert!(asked.len() == 2 && asked.iter().all(|u| u.host_str() == Some("reg.invalid") && u.query() == Some("q=corp&take=100")), "{asked:?}");
    f.server.shutdown().await;
}

/// F1 + C1028 through the shared service: credential-free reads share the registration documents and the vulnerability
/// documents for a few seconds; a read that carries the caller's credential fetches for itself and fills nothing.
#[tokio::test]
async fn a_credentialed_read_shares_neither_registration_nor_aux_documents() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f, HOST);
    let vuln_index = serde_json::json!({"version": "3.0.0", "resources": [
        {"@id": format!("{HOST}{PREFIX}/flat/"), "@type": "PackageBaseAddress/3.0.0"},
        {"@id": format!("{HOST}{PREFIX}/registration/"), "@type": "RegistrationsBaseUrl/Versioned"},
        {"@id": format!("{HOST}{PREFIX}/vuln/index.json"), "@type": "VulnerabilityInfo/6.7.0"},
    ]});
    f.registry.answer(&format!("{PREFIX}/v3/index.json"), FakeAnswer::Body(vuln_index.to_string()));
    f.registry.answer(&format!("{PREFIX}/vuln/index.json"), FakeAnswer::Body(serde_json::json!([{"@name": "base", "@id": format!("{HOST}{PREFIX}/vuln/base.json"), "@updated": "x"}]).to_string()));
    f.registry.answer(&format!("{PREFIX}/vuln/base.json"), FakeAnswer::Body("{}".to_owned()));
    let carrier = [("authorization", "Basic dXNlcjpwdw==")];
    let reg = format!("{PREFIX}/registration/corp.lib/index.json");
    for _ in 0..3 {
        assert_eq!(f.server.get_with_headers("/nuget/v3/registration/corp.lib/index.json", &[("accept", "*/*")]).await.status().as_u16(), 200);
        assert_eq!(f.server.get_with_headers("/nuget/v3/vulnerabilities/base.json", &[("accept", "*/*")]).await.status().as_u16(), 200);
    }
    assert_eq!((calls(&f, &reg), calls(&f, "/vuln/base.json")), (1, 1), "credential-free reads share both");
    for _ in 0..2 {
        assert_eq!(f.server.get_with_headers("/nuget/v3/registration/corp.lib/index.json", &carrier).await.status().as_u16(), 200);
        assert_eq!(f.server.get_with_headers("/nuget/v3/vulnerabilities/base.json", &carrier).await.status().as_u16(), 200);
    }
    assert_eq!((calls(&f, &reg), calls(&f, "/vuln/base.json")), (3, 3), "each credential-bearing read fetched for itself and filled nothing");
    f.server.shutdown().await;
}

/// F1: the tables the process keeps are bounded: 70 registries' service indexes stay within 64 entries and 300 projects
/// within the shared table's 256.
#[tokio::test]
async fn the_service_index_and_project_tables_stay_bounded() {
    let f = start_full(0, Some(&target()), None, None, 70).await;
    for n in 7..77 {
        let _ = f.server.get(&format!("/registry/nuget/{n}/v3/index.json")).await;
    }
    let sizes = probation::nuget::serve::table_sizes(&f.server.app());
    assert!(sizes[0] > 0 && sizes[0] <= 64, "service index table: {}", sizes[0]);
    private_registry(&f, HOST);
    for n in 0..300 {
        f.registry.answer(&format!("{PREFIX}/flat/t{n}/index.json"), FakeAnswer::Body(flat_index(&["1.0.0"])));
        assert_eq!(f.server.get(&format!("/registry/nuget/7/v3-flatcontainer/t{n}/index.json")).await.status().as_u16(), 200, "t{n}");
    }
    let sizes = probation::nuget::serve::table_sizes(&f.server.app());
    assert!(sizes[1] > 0 && sizes[1] <= 256, "shared project table: {}", sizes[1]);
    assert!(sizes[4] <= 256, "refresh gate table: {}", sizes[4]);
    f.server.shutdown().await;
}

/// F3: a registry's resource path prefix narrows the resources its service index names to a path of its host; absent, the
/// whole host is admitted (the layouts of Azure Artifacts, Artifactory and GitHub Packages keep working).
#[tokio::test]
async fn a_resource_path_prefix_confines_the_registrys_resources_to_it() {
    for (prefix, flat_ok, search_ok) in [(None, true, true), (Some("/artifactory/api/nuget"), true, true), (Some("/artifactory/api/nuget/repo"), true, true), (Some("/artifactory/api/nuget/rep"), false, false), (Some("/other/tenant"), false, false)] {
        let f = start_full(0, Some(&target()), None, prefix, 1).await;
        private_registry(&f, HOST);
        // The search service lies beside the flat container, outside `/artifactory/api/nuget/repo/flat`.
        let index = serde_json::json!({"version": "3.0.0", "resources": [
            {"@id": format!("{HOST}{PREFIX}/flat/"), "@type": "PackageBaseAddress/3.0.0"},
            {"@id": format!("{HOST}/artifactory/api/nuget/search/query"), "@type": "SearchQueryService"},
        ]});
        f.registry.answer(&format!("{PREFIX}/v3/index.json"), FakeAnswer::Body(index.to_string()));
        let flat = f.server.get("/nuget/v3-flatcontainer/corp.lib/index.json").await.status().as_u16();
        assert_eq!(flat == 200 || flat == 403, flat_ok, "{prefix:?}: flat container {flat}");
        if flat_ok {
            let served: serde_json::Value = serde_json::from_str(&f.server.get("/nuget/v3/index.json").await.text().await.unwrap()).unwrap();
            let search = served["resources"].as_array().unwrap().iter().any(|r| r["@type"] == "SearchQueryService");
            let expected = search_ok && prefix != Some("/artifactory/api/nuget/repo");
            assert_eq!(search, expected, "{prefix:?}: a search service outside the prefix is not used");
        } else {
            assert_eq!(flat, 502, "{prefix:?}");
            assert!(f.registry.calls().iter().all(|u| !u.path().contains("/flat/")), "nothing was asked outside the prefix");
        }
        f.server.shutdown().await;
    }
}

/// R5: the documents a registry's vulnerability and signature indexes name are fetched with its read credential, so they
/// too must lie under the registry's resource path prefix (a document of another tenant's path of the same host is not
/// fetched), and the service index cache is per prefix.
#[tokio::test]
async fn the_urls_a_vulnerability_or_signature_index_names_must_lie_under_the_prefix() {
    let f = start_full(0, Some(&target()), None, Some(PREFIX), 1).await;
    let index = serde_json::json!({"version": "3.0.0", "resources": [
        {"@id": format!("{HOST}{PREFIX}/flat/"), "@type": "PackageBaseAddress/3.0.0"},
        {"@id": format!("{HOST}{PREFIX}/vuln/index.json"), "@type": "VulnerabilityInfo/6.7.0"},
        {"@id": format!("{HOST}{PREFIX}/sig/index.json"), "@type": "RepositorySignatures/5.0.0"},
    ]});
    f.registry.answer(&format!("{PREFIX}/v3/index.json"), FakeAnswer::Body(index.to_string()));
    let inside = format!("{HOST}{PREFIX}/vuln/base.json");
    let outside = format!("{HOST}/artifactory/api/nuget/other-tenant/vuln/base.json");
    f.registry.answer(&format!("{PREFIX}/vuln/base.json"), FakeAnswer::Body("{}".into()));
    f.registry.answer("/artifactory/api/nuget/other-tenant/vuln/base.json", FakeAnswer::Body("{\"secret\":1}".into()));
    f.registry.answer(&format!("{PREFIX}/vuln/index.json"), FakeAnswer::Body(serde_json::json!([{"@name": "base", "@id": inside, "@updated": "x"}]).to_string()));
    assert_eq!(f.server.get("/nuget/v3/vulnerabilities/base.json").await.status().as_u16(), 200, "a file under the prefix is served");
    f.registry.answer(&format!("{PREFIX}/vuln/index.json"), FakeAnswer::Body(serde_json::json!([{"@name": "base", "@id": outside, "@updated": "x"}]).to_string()));
    f.server.get("/nuget/v3/vulnerabilities/index.json").await;
    // The documents are cached for a few seconds: let them expire.
    f._clock.advance_seconds(60);
    assert_eq!(f.server.get("/nuget/v3/vulnerabilities/base.json").await.status().as_u16(), 502, "a file outside the prefix is refused");
    assert_eq!(calls(&f, "other-tenant/vuln/base.json"), 0, "and never fetched");
    // A certificate outside the prefix likewise.
    let certificate = b"cert-bytes".to_vec();
    let fingerprint = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&certificate))
    };
    f.registry.answer(&format!("{PREFIX}/sig/index.json"), FakeAnswer::Body(serde_json::json!({"allRepositorySigned": true, "signingCertificates": [{"fingerprints": {"2.16.840.1.101.3.4.2.1": fingerprint}, "subject": "s", "issuer": "i", "notBefore": "a", "notAfter": "b", "contentUrl": format!("{HOST}/artifactory/api/nuget/other-tenant/cert.crt")}]}).to_string()));
    f.registry.answer("/artifactory/api/nuget/other-tenant/cert.crt", FakeAnswer::Bytes(certificate));
    assert_eq!(f.server.get(&format!("/nuget/v3/repository-signatures/certificates/{fingerprint}.crt")).await.status().as_u16(), 502);
    assert_eq!(calls(&f, "other-tenant/cert.crt"), 0, "the certificate outside the prefix is never fetched");
    f.server.shutdown().await;
}

/// R4: one registry cannot hold every refresh place: with registry 7 holding its four stalled refreshes, registry 8's read
/// still completes.
#[tokio::test]
async fn one_registry_holding_its_refresh_places_does_not_starve_another() {
    let f = start_full(0, Some(&target()), None, None, 2).await;
    private_registry(&f, HOST);
    // Registry 8 (the second selected one) lives on reg1.invalid.
    let second = serde_json::json!({"version": "3.0.0", "resources": [{"@id": "https://reg1.invalid/flat/", "@type": "PackageBaseAddress/3.0.0"}]});
    f.registry.answer("/v3/index.json", FakeAnswer::Body(second.to_string()));
    f.registry.answer("/flat/other.lib/index.json", FakeAnswer::Body(flat_index(&["1.0.0"])));
    let gate = common::Gate::new();
    for n in 0..8 {
        f.registry.answer(&format!("{PREFIX}/flat/stall{n}/index.json"), FakeAnswer::GatedMetadata { body: flat_index(&["1.0.0"]), gate: Arc::clone(&gate) });
    }
    let server = Arc::new(f.server);
    let stalled: Vec<_> = (0..8).map(|n| {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.get(&format!("/registry/nuget/7/v3-flatcontainer/stall{n}/index.json")).await.status().as_u16() })
    }).collect();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let held = f.registry.calls().iter().filter(|u| u.path().contains("/flat/stall") && u.path().ends_with("/index.json")).count();
    assert_eq!(held, 4, "registry 7 holds its four places, four more wait");
    let other = server.get("/registry/nuget/8/v3-flatcontainer/other.lib/index.json").await.status().as_u16();
    assert_eq!(other, 200, "registry 8 still has places");
    for _ in 0..100 {
        gate.release();
    }
    for read in stalled {
        assert_eq!(read.await.unwrap(), 200);
    }
}

/// Recheck-2 N2: in the shared service nothing of a project is stored, so a version with no date outside the newest ones is
/// not listed and not served until a file of it has been asked for once; its first-seen time then runs from that request, and
/// it is served only after the cooldown (never early).
#[tokio::test]
async fn an_undated_old_version_in_the_shared_service_waits_from_the_first_request_for_a_file() {
    let f = start(7 * 86_400, None, None).await;
    f.registry.answer("/v3/index.json", FakeAnswer::Body(nuget::service_index(&[])));
    let many: Vec<String> = (0..60).map(|n| format!("1.0.{n}")).collect();
    let names: Vec<&str> = many.iter().map(String::as_str).collect();
    f.registry.answer("/v3-flatcontainer/big.pkg/index.json", FakeAnswer::Body(flat_index(&names)));
    f.registry.answer("/v3/registration5-gz-semver2/big.pkg/index.json", FakeAnswer::Missing);
    for v in ["1.0.0", "1.0.5"] {
        f.registry.answer(&format!("/v3-flatcontainer/big.pkg/{v}/big.pkg.{v}.nupkg"), FakeAnswer::Bytes(nuget::nupkg("big.pkg", v)));
    }
    assert!(listed(&f).await.is_empty(), "every undated version waits a whole cooldown");
    assert_eq!(f.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.0/big.pkg.1.0.0.nupkg").await.status().as_u16(), 403, "never served early");
    f._clock.advance_seconds(8 * 86_400);
    let after: Vec<String> = listed(&f).await;
    let mut expected = vec!["1.0.0".to_owned()];
    expected.extend((50..60).map(|n| format!("1.0.{n}")));
    assert_eq!(after, expected, "the newest ten and the one asked for have their first-seen time, the rest start again");
    assert_eq!(f.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.0/big.pkg.1.0.0.nupkg").await.status().as_u16(), 200, "served after the cooldown");
    assert_eq!(f.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.5/big.pkg.1.0.5.nupkg").await.status().as_u16(), 403, "one asked for only now waits from now");
    f.server.shutdown().await;
}

async fn listed(f: &Fixture) -> Vec<String> {
    let body: serde_json::Value = serde_json::from_str(&f.server.get("/nuget/v3-flatcontainer/big.pkg/index.json").await.text().await.unwrap()).unwrap();
    body["versions"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect()
}
