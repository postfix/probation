//! Row 23: the Conan READ path through the shared service for a selected registry with a real `target_url` (an Artifactory-style
//! remote under a path prefix), what a credential-bearing read forwards and shares (C1028), the upstream 401/403 codes, the
//! declared archive origin, the bounded process tables and the verbs the read routes refuse.
mod common;

use common::conan;
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{Transport, UpstreamError};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{num::{NonZeroU32, NonZeroU64}, sync::Arc};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

const HOST: &str = "https://reg.invalid";
const PREFIX: &str = "/artifactory/api/conan/libs";
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
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Conan, target_url: target.map(str::to_owned),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive.map(str::to_owned), resource_path_prefix: None,
        }],
    };
    for n in 1..count {
        snapshot.registries.push(RegistryDescriptor {
            registry: RegistryId(7 + n), ecosystem: probation_policy::Ecosystem::Conan, target_url: Some(format!("https://reg{n}.invalid/repo/")),
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
    let origins = fake_origins().with_conan(url::Url::parse(conan::REMOTE).unwrap(), url::Url::parse(conan::PUBLISH).unwrap());
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&recording) as Arc<dyn Transport>, origins).await;
    Fixture { server, registry, recording, clock, _policy: policy }
}

fn target() -> String {
    format!("{HOST}{PREFIX}/")
}

const R1: &str = "aaaa0000000000000000000000000001";
const R2: &str = "bbbb0000000000000000000000000002";

/// A private registry: `lib/1.0` with an old revision and a young one, laid out under `PREFIX` on its own host.
fn private_registry(f: &Fixture) {
    let prefixed = |path: &str| format!("{PREFIX}/{path}");
    let base = conan::base("lib", "1.0");
    f.registry.answer(&prefixed(&format!("{base}/revisions")), FakeAnswer::Body(conan::revisions_doc(("reference", "lib/1.0@_/_"), &[(R2, Some(YOUNG)), (R1, Some(OLD))])));
    for rev in [R1, R2] {
        let dir = format!("{base}/revisions/{rev}");
        f.registry.answer(&prefixed(&format!("{dir}/files")), FakeAnswer::Body(conan::files_doc(&["conanfile.py", "conanmanifest.txt", "conan_export.tgz"])));
        f.registry.answer(&prefixed(&format!("{dir}/files/conanfile.py")), FakeAnswer::Body(conan::conanfile("lib", "1.0")));
        f.registry.answer(&prefixed(&format!("{dir}/files/conanmanifest.txt")), FakeAnswer::Body(conan::manifest(rev)));
        f.registry.answer(&prefixed(&format!("{dir}/files/conan_export.tgz")), FakeAnswer::Bytes(conan::tgz(rev)));
    }
}

fn calls(f: &Fixture, needle: &str) -> usize {
    f.registry.calls().iter().filter(|u| u.path().contains(needle)).count()
}

#[tokio::test]
async fn a_selected_registry_is_read_from_its_own_layout_through_both_roots() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f);
    for root in ["/conan", "/registry/conan/7"] {
        let revisions = f.server.get(&format!("{root}/v2/conans/lib/1.0/_/_/revisions")).await;
        let (status, body) = (revisions.status().as_u16(), revisions.text().await.unwrap());
        assert_eq!(status, 200, "{root}");
        assert!(body.contains(R1) && !body.contains(R2), "{root}: {body}");
        let file = f.server.get(&format!("{root}/v2/conans/lib/1.0/_/_/revisions/{R1}/files/conan_export.tgz")).await;
        assert_eq!((file.status().as_u16(), file.bytes().await.unwrap().to_vec()), (200, conan::tgz(R1)), "{root}");
        assert_eq!(f.server.get(&format!("{root}/v2/conans/lib/1.0/_/_/revisions/{R2}/files/conan_export.tgz")).await.status().as_u16(), 403, "{root}");
    }
    // Every upstream call stayed on the registry's own host and under its own prefix.
    assert!(f.registry.calls().iter().all(|url| url.host_str() == Some("reg.invalid") && url.path().starts_with(PREFIX)), "{:?}", f.registry.calls());
    assert_eq!(calls(&f, &format!("{R2}/files")), 0);
    // A registry that is not this family's, or an unknown id, is no route.
    assert_eq!(f.server.get("/registry/conan/8/v2/conans/lib/1.0/_/_/revisions").await.status(), 404);
    assert_eq!(f.server.get("/registry/go/7/example.com/m/@v/list").await.status(), 404);
    f.server.shutdown().await;
}

/// The caller's own registry credential goes to the registry's origin with every read, never anywhere else, and the
/// service key never leaves.
#[tokio::test]
async fn the_callers_credential_travels_to_the_registry_only() {
    let f = start(0, Some(&target()), None).await;
    private_registry(&f);
    let carrier = [("authorization", "Bearer callers-token")];
    assert_eq!(f.server.get_with_headers("/conan/v2/conans/lib/1.0/_/_/revisions", &carrier).await.status().as_u16(), 200);
    assert_eq!(f.server.get_with_headers(&format!("/conan/v2/conans/lib/1.0/_/_/revisions/{R1}/files/conan_export.tgz"), &carrier).await.status().as_u16(), 200);
    let metadata = f.recording.metadata_auth.lock().unwrap().clone();
    assert!(metadata.len() >= 2 && metadata.iter().all(|(_, auth)| auth.as_deref() == Some("Bearer callers-token")), "{metadata:?}");
    let artifacts = f.recording.artifacts.lock().unwrap().clone();
    assert!(!artifacts.is_empty() && artifacts.iter().all(|(_, auth, ..)| auth.as_deref() == Some("Bearer callers-token")), "{artifacts:?}");
    assert!(metadata.iter().all(|(_, auth)| auth.as_deref() != Some("prb_01234567890123456789012345678901")));
    // A header that is not a Basic or Bearer credential is refused as one.
    assert_eq!(f.server.get_with_headers("/conan/v2/conans/lib/1.0/_/_/revisions", &[("authorization", "prb_x")]).await.status().as_u16(), 401);
    f.server.shutdown().await;
}

/// The login is the remote's own: the Basic credential of `conan remote login` goes to the registry's `authenticate` and what it
/// answers (its token) comes back as text; the service key never leaves.
#[tokio::test]
async fn a_login_is_the_registrys_own_answer_to_the_callers_credential() {
    let f = start(0, Some(&target()), None).await;
    f.registry.answer(&format!("{PREFIX}/v2/users/authenticate"), FakeAnswer::Body("a.jwt.token".into()));
    f.registry.answer(&format!("{PREFIX}/v2/users/check_credentials"), FakeAnswer::Body(String::new()));
    let login = f.server.get_with_headers("/conan/v2/users/authenticate", &[("authorization", "Basic dXNlcjpwdw==")]).await;
    assert_eq!((login.status().as_u16(), login.text().await.unwrap()), (200, "a.jwt.token".to_owned()));
    assert_eq!(f.server.get_with_headers("/conan/v2/users/check_credentials", &[("authorization", "Bearer a.jwt.token")]).await.status().as_u16(), 200);
    let seen = f.recording.metadata_auth.lock().unwrap().clone();
    assert_eq!(seen, [(format!("{PREFIX}/v2/users/authenticate"), Some("Basic dXNlcjpwdw==".to_owned())), (format!("{PREFIX}/v2/users/check_credentials"), Some("Bearer a.jwt.token".to_owned()))]);
    f.server.shutdown().await;
}

/// C1028 and the share: credential-free reads of one list within a few seconds cost one fetch; a read that carries the caller's
/// credential fetches for itself, every time, and fills nothing a credential-free read can find.
#[tokio::test]
async fn a_credentialed_read_shares_nothing_and_a_credential_free_one_shares_for_a_moment() {
    let f = start(0, Some(&target()), None).await;
    private_registry(&f);
    for _ in 0..3 {
        assert_eq!(f.server.get("/conan/v2/conans/lib/1.0/_/_/revisions").await.status().as_u16(), 200);
    }
    assert_eq!(calls(&f, "/lib/1.0/_/_/revisions"), 1, "credential-free reads share the fetched list");
    let carrier = [("authorization", "Bearer callers-token")];
    for _ in 0..3 {
        assert_eq!(f.server.get_with_headers("/conan/v2/conans/lib/1.0/_/_/revisions", &carrier).await.status().as_u16(), 200);
    }
    assert_eq!(calls(&f, "/lib/1.0/_/_/revisions"), 4, "each credentialed read fetched for itself and read the share of none");
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get("/conan/v2/conans/lib/1.0/_/_/revisions").await.status().as_u16(), 200);
    assert_eq!(calls(&f, "/lib/1.0/_/_/revisions"), 5, "the credentialed reads left nothing for this one, and the share expires");
    // Bytes fetched under a credential are never served without it.
    let file = format!("/conan/v2/conans/lib/1.0/_/_/revisions/{R1}/files/conan_export.tgz");
    assert_eq!(f.server.get_with_headers(&file, &carrier).await.status().as_u16(), 200);
    f.registry.answer(&format!("{PREFIX}/v2/conans/lib/1.0/_/_/revisions/{R1}/files/conan_export.tgz"), FakeAnswer::Fail(UpstreamError::Status(401)));
    assert_eq!(f.server.get(&file).await.status().as_u16(), 401, "the credential-free read does not find the credentialed bytes");
    f.server.shutdown().await;
}

#[tokio::test]
async fn upstream_401_and_403_have_their_own_codes_and_a_missing_reference_is_404() {
    let f = start(0, None, None).await;
    f.registry.answer(&conan::at("v2/conans/login/1.0/_/_/revisions"), FakeAnswer::Fail(UpstreamError::Status(401)));
    f.registry.answer(&conan::at("v2/conans/deny/1.0/_/_/revisions"), FakeAnswer::Fail(UpstreamError::Status(403)));
    f.registry.answer(&conan::at("v2/conans/down/1.0/_/_/revisions"), FakeAnswer::Fail(UpstreamError::Status(503)));
    f.registry.answer(&conan::at("v2/conans/gone/1.0/_/_/revisions"), FakeAnswer::Missing);
    let code = |answer: reqwest::Response| async move {
        let status = answer.status().as_u16();
        let challenge = answer.headers().get("www-authenticate").map(|v| v.to_str().unwrap().to_owned());
        let body: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap_or_default();
        (status, body["error"].as_str().unwrap_or_default().to_owned(), challenge)
    };
    let (status, error, challenge) = code(f.server.get("/conan/v2/conans/login/1.0/_/_/revisions").await).await;
    assert_eq!((status, error.as_str()), (401, "UPSTREAM_AUTHENTICATION_REQUIRED"));
    assert!(challenge.is_some_and(|c| c.starts_with("Bearer")), "a registry's own 401 carries the challenge the client needs to log in");
    assert_eq!(code(f.server.get("/conan/v2/conans/deny/1.0/_/_/revisions").await).await.0, 403);
    assert_eq!(code(f.server.get("/conan/v2/conans/down/1.0/_/_/revisions").await).await.0, 502);
    assert_eq!(code(f.server.get("/conan/v2/conans/gone/1.0/_/_/revisions").await).await.0, 404);
    f.server.shutdown().await;
}

/// The archive origin a Conan registry declares reaches the transport with its archive (so a redirect may land there), only for a
/// registry that declared one, and only an archive's transfer may follow it (a manifest or a recipe file never does).
#[tokio::test]
async fn a_declared_conan_archive_origin_travels_with_the_archive_request_only() {
    for (archive, expected) in [(Some("https://blobs.invalid/store"), Some("https://blobs.invalid/store")), (None, None)] {
        let f = start(0, Some(&target()), archive).await;
        private_registry(&f);
        for file in ["conan_export.tgz", "conanfile.py", "conanmanifest.txt"] {
            assert_eq!(f.server.get(&format!("/conan/v2/conans/lib/1.0/_/_/revisions/{R1}/files/{file}")).await.status().as_u16(), 200, "{file}");
        }
        let seen = f.recording.artifacts.lock().unwrap().clone();
        assert!(seen.len() >= 3, "{seen:?}");
        assert!(seen.iter().all(|(_, _, origin, _)| origin.as_ref().map(url::Url::as_str) == expected), "{archive:?}: {seen:?}");
        assert!(seen.iter().all(|(path, _, _, allow)| *allow == path.ends_with(".tgz")), "{seen:?}");
        f.server.shutdown().await;
    }
}

/// Every route is a read here (the upload verbs are class W, tests/conan_service_write.rs): another verb or a stray query reaches nothing.
#[tokio::test]
async fn reads_are_read_only_and_a_stray_query_is_no_route() {
    let f = start(0, None, None).await;
    let before = f.registry.calls().len();
    let client = reqwest::Client::new();
    for (verb, path) in [("POST", "/conan/v2/conans/lib/1.0/_/_/revisions"), ("PATCH", "/registry/conan/7/v2/conans/lib/1.0/_/_/latest"), ("POST", "/conan/v2/conans/search?q=a")] {
        let response = client.request(verb.parse().unwrap(), f.server.url(path)).body("x").send().await.unwrap();
        assert!(matches!(response.status().as_u16(), 404 | 405), "{verb} {path}: {}", response.status());
    }
    assert_eq!(f.server.get("/conan/v2/conans/lib/1.0/_/_/revisions?token=abc").await.status(), 404, "a query string is no route");
    assert_eq!(f.server.get("/conan/v2/conans/search?q=a&token=abc").await.status(), 404, "only the search's own keys are a query");
    assert_eq!(f.registry.calls().len(), before, "nothing reached upstream");
    f.server.shutdown().await;
}

/// The process tables stay bounded: one cell per package (128), the shared lists, the places and gates.
#[tokio::test]
async fn the_process_tables_stay_bounded() {
    let f = start(0, None, None).await;
    for n in 0..200 {
        conan::serve_recipe(&f.registry, &format!("pkg{n}"), "1.0", &[(R1, OLD)]);
        assert_eq!(f.server.get(&format!("/conan/v2/conans/pkg{n}/1.0/_/_/revisions")).await.status().as_u16(), 200);
    }
    let [cells, places, gates, raw] = probation::conan::serve::table_sizes(&f.server.app());
    assert!(cells <= 128 && places <= 256 && gates <= 1024 && raw <= 1024, "{cells} {places} {gates} {raw}");
    f.server.shutdown().await;
}

// ------------------------------------------------------------------ fix round

/// C23-2: one expiry of the freshness window costs one list for the whole revision, not one per file.
#[tokio::test]
async fn files_of_one_revision_cost_one_list_per_freshness_window() {
    let f = start(0, Some(&target()), None).await;
    private_registry(&f);
    let file = |name: &str| format!("/conan/v2/conans/lib/1.0/_/_/revisions/{R1}/files/{name}");
    assert_eq!(f.server.get(&file("conanfile.py")).await.status().as_u16(), 200);
    assert_eq!(f.server.get(&file("conanmanifest.txt")).await.status().as_u16(), 200);
    let lists = |f: &Fixture| f.registry.calls().iter().filter(|url| url.path().ends_with("/lib/1.0/_/_/revisions")).count();
    assert_eq!(lists(&f), 1, "two files, one list");
    // What a request costs while everything is fresh (store commands), measured on a third file of the same revision.
    let before = f.server.store_commands();
    assert_eq!(f.server.get(&file("conan_export.tgz")).await.status().as_u16(), 200);
    let fresh_cost = f.server.store_commands() - before;
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get(&file("conanfile.py")).await.status().as_u16(), 200);
    assert_eq!(lists(&f), 2, "the expiry made one list read");
    // The expiry confirmed the revision again: the next request costs what a fresh one does (it does not re-judge the list).
    let before = f.server.store_commands();
    assert_eq!(f.server.get(&file("conanmanifest.txt")).await.status().as_u16(), 200);
    assert!(f.server.store_commands() - before <= fresh_cost, "a request after the expiry's own re-reading is a fresh one: {} against {fresh_cost}", f.server.store_commands() - before);
    f.server.shutdown().await;
}

/// F2: one credential holds two of a registry's four fetch places; another credential still gets one.
#[tokio::test]
async fn one_credential_cannot_hold_all_of_a_registrys_fetch_places() {
    let f = start(0, Some(&target()), None).await;
    let gate = common::Gate::new();
    for n in 0..3 {
        f.registry.answer(&format!("{PREFIX}/v2/conans/slow{n}/1.0/_/_/revisions"), FakeAnswer::GatedMetadata { body: conan::revisions_doc(("reference", "x"), &[(R1, Some(OLD))]), gate: Arc::clone(&gate) });
    }
    conan::serve_recipe(&f.registry, "fast", "1.0", &[(R1, OLD)]);
    f.registry.answer(&format!("{PREFIX}/v2/conans/fast/1.0/_/_/revisions"), FakeAnswer::Body(conan::revisions_doc(("reference", "fast/1.0@_/_"), &[(R1, Some(OLD))])));
    let holders: Vec<_> = (0..3)
        .map(|n| {
            let url = f.server.url(&format!("/conan/v2/conans/slow{n}/1.0/_/_/revisions"));
            tokio::spawn(async move { reqwest::Client::new().get(url).header("authorization", "Bearer junk").send().await.unwrap().status().as_u16() })
        })
        .collect();
    gate.wait_until_reached().await;
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(calls(&f, "/revisions"), 2, "a credential holds two places: the third request waits");
    let other = f.server.get_with_headers("/conan/v2/conans/fast/1.0/_/_/revisions", &[("authorization", "Bearer honest")]).await;
    assert_eq!(other.status().as_u16(), 200, "another credential is not kept out");
    gate.release();
    gate.release();
    gate.release();
    for holder in holders {
        let _ = holder.await;
    }
    f.server.shutdown().await;
}

/// C23-3: a credential's own upload keeps its existence checks working during the cooldown; another credential still sees the hold.
#[tokio::test]
async fn the_depositors_own_lists_are_not_held_by_the_cooldown_of_what_it_uploaded() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f);
    let revisions = "/conan/v2/conans/lib/1.0/_/_/revisions";
    let listed = |body: String| serde_json::from_str::<serde_json::Value>(&body).unwrap()["revisions"].as_array().unwrap().iter().map(|r| r["revision"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
    let mine = [("authorization", "Bearer depositor")];
    assert_eq!(listed(f.server.get_with_headers(revisions, &mine).await.text().await.unwrap()), [R1], "before: the young revision is held");
    {
    let app = f.server.app();
    probation::conan::serve::note_upload(&app, "Bearer depositor", 7, &probation::conan::serve::UnitRef::Recipe(probation::conan::coords::Recipe {
        rref: probation::conan::coords::Rref { name: "lib".into(), version: "1.0".into(), user: "_".into(), channel: "_".into() },
        rrev: R2.into(),
    }));
    }
    assert_eq!(listed(f.server.get_with_headers(revisions, &mine).await.text().await.unwrap()), [R2, R1], "the depositor sees its own upload");
    assert_eq!(listed(f.server.get_with_headers(revisions, &[("authorization", "Bearer other")]).await.text().await.unwrap()), [R1], "another credential still sees the cooldown");
    f.server.shutdown().await;
}

/// R8: a search in shared-service mode (the mode the product sells): credential-free it shares its verdicts, with the caller's own
/// credential it judges alone, and an unreadable list withholds only its reference.
#[tokio::test]
async fn a_search_in_shared_service_mode_lists_what_passes_and_shares_nothing_credentialed() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f);
    f.registry.answer(&format!("{PREFIX}/v2/conans/search"), FakeAnswer::Body(conan::search_doc(&["lib/1.0@_/_", "ghost/1.0@_/_"])));
    f.registry.answer(&format!("{PREFIX}/v2/conans/ghost/1.0/_/_/revisions"), FakeAnswer::Missing);
    for _ in 0..2 {
        let found = f.server.get("/conan/v2/conans/search?q=*").await;
        assert_eq!(found.status().as_u16(), 200);
        assert_eq!(found.headers()["x-probation-withheld"], "1");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&found.text().await.unwrap()).unwrap()["results"], serde_json::json!(["lib/1.0@_/_"]));
    }
    let before = calls(&f, "/lib/1.0/_/_/revisions");
    let mine = f.server.get_with_headers("/conan/v2/conans/search?q=*", &[("authorization", "Bearer callers-token")]).await;
    assert_eq!(mine.status().as_u16(), 200);
    assert!(calls(&f, "/lib/1.0/_/_/revisions") > before, "a credentialed search reads for itself and fills nothing shared");
    f.server.shutdown().await;
}

/// R6: the uploads a credential is remembered for are bounded per credential (the oldest goes first) and do not touch another credential's.
#[tokio::test]
async fn the_remembered_uploads_of_a_credential_are_bounded_and_do_not_touch_another_credentials() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    private_registry(&f);
    let unit = |rev: &str| probation::conan::serve::UnitRef::Recipe(probation::conan::coords::Recipe {
        rref: probation::conan::coords::Rref { name: "lib".into(), version: "1.0".into(), user: "_".into(), channel: "_".into() },
        rrev: rev.into(),
    });
    {
        let app = f.server.app();
        probation::conan::serve::note_upload(&app, "Bearer other", 7, &unit(R2));
        probation::conan::serve::note_upload(&app, "Bearer flood", 7, &unit(R2));
        for n in 0..4_200 {
            probation::conan::serve::note_upload(&app, "Bearer flood", 7, &unit(&format!("{n:032x}")));
        }
    }
    let revisions = "/conan/v2/conans/lib/1.0/_/_/revisions";
    let listed = |body: String| serde_json::from_str::<serde_json::Value>(&body).unwrap()["revisions"].as_array().unwrap().iter().map(|r| r["revision"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
    assert_eq!(listed(f.server.get_with_headers(revisions, &[("authorization", "Bearer other")]).await.text().await.unwrap()), [R2, R1], "another credential keeps its own");
    assert_eq!(listed(f.server.get_with_headers(revisions, &[("authorization", "Bearer flood")]).await.text().await.unwrap()), [R1], "the flooding credential lost its oldest");
    let (held, counted, ordered) = probation::conan::serve::own_sizes(&f.server.app());
    assert_eq!((held, counted, ordered), (4_097, 4_097, 4_097), "the count of each credential is derived from what is held: 4,096 of the flood and one of the other");
    f.server.shutdown().await;
}

/// N4: one owner (here: one client address) holds at most half of a registry's search slots; another owner still gets a search.
#[tokio::test]
async fn one_owner_cannot_take_all_of_a_registrys_search_slots() {
    let f = start(0, Some(&target()), None).await;
    let gate = common::Gate::new();
    f.registry.answer(&format!("{PREFIX}/v2/conans/search"), FakeAnswer::Body(conan::search_doc(&["slow/1.0@_/_"])));
    f.registry.answer(&format!("{PREFIX}/v2/conans/slow/1.0/_/_/revisions"), FakeAnswer::GatedMetadata { body: conan::revisions_doc(("reference", "slow/1.0@_/_"), &[(R1, Some(OLD))]), gate: Arc::clone(&gate) });
    let from = |address: &'static str| {
        let url = f.server.url("/conan/v2/conans/search?q=*");
        async move { reqwest::Client::builder().local_address(Some(address.parse().unwrap())).build().unwrap().get(url).header("authorization", "Bearer junk").send().await.unwrap().status().as_u16() }
    };
    let held: Vec<_> = (0..2).map(|_| tokio::spawn(from("127.0.0.1"))).collect();
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(from("127.0.0.1").await, 503, "the owner holds its half of the registry's search slots");
    let other = tokio::spawn(from("127.0.0.2"));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for _ in 0..4 {
        gate.release();
    }
    assert_eq!(other.await.unwrap(), 200, "another owner still gets a search");
    for held in held {
        assert_eq!(held.await.unwrap(), 200);
    }
    f.server.shutdown().await;
}

/// L2 (N6): a policy published while a search judges is never applied late to a listing made under the old one: the listing made under the
/// freeze-free policy (both references pass) is refused and the request is admitted again under the new snapshot (a 7-day freeze), which holds
/// both young references: the answer lists neither.
#[tokio::test]
async fn a_policy_published_mid_search_is_applied_to_the_listing() {
    let f = start(0, Some(&target()), None).await;
    let gate = common::Gate::new();
    f.registry.answer(&format!("{PREFIX}/v2/conans/search"), FakeAnswer::Body(conan::search_doc(&["slow/1.0@_/_", "fast/1.0@_/_"])));
    f.registry.answer(&format!("{PREFIX}/v2/conans/slow/1.0/_/_/revisions"), FakeAnswer::GatedMetadata { body: conan::revisions_doc(("reference", "slow/1.0@_/_"), &[(R1, Some(YOUNG))]), gate: Arc::clone(&gate) });
    f.registry.answer(&format!("{PREFIX}/v2/conans/fast/1.0/_/_/revisions"), FakeAnswer::Body(conan::revisions_doc(("reference", "fast/1.0@_/_"), &[(R1, Some(YOUNG))])));
    let judging = { let url = f.server.url("/conan/v2/conans/search?q=*"); tokio::spawn(async move { reqwest::get(url).await.unwrap().text().await.unwrap() }) };
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    f._policy.reset().await;
    let mut snapshot = snapshot_with(7 * 86_400, Some(&target()), None, 1);
    snapshot.revision = 2;
    snapshot.layers.iter_mut().for_each(|layer| layer.revision = 2);
    snapshot.place_chain.iter_mut().for_each(|link| link.layer_revision = 2);
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot)).mount(&f._policy).await;
    f.server.app().service_policy().unwrap().sync_once().await.unwrap();
    gate.release();
    gate.release();
    let answer: serde_json::Value = serde_json::from_str(&judging.await.unwrap()).unwrap();
    assert_eq!(answer["results"], serde_json::json!([]), "nothing judged under the old policy is listed under the new one");
    f.server.shutdown().await;
}

fn list_path(prefix: &str, name: &str) -> String {
    format!("{prefix}/v2/conans/{name}/1.0/_/_/revisions")
}

/// R4-3: one owner (one client address) that reads two registries holds at most 12 of the process's 16 judging lanes in all, not 12 on each.
#[tokio::test]
async fn one_owner_on_two_registries_cannot_hold_every_judging_lane() {
    let f = start_n(0, Some(&target()), None, 2).await;
    let gate = common::Gate::new();
    for (prefix, letter) in [(PREFIX, "a"), ("/repo", "b")] {
        let names: Vec<String> = (0..20).map(|n| format!("{letter}{n}/1.0@_/_")).collect();
        f.registry.answer(&format!("{prefix}/v2/conans/search"), FakeAnswer::Body(conan::search_doc(&names.iter().map(String::as_str).collect::<Vec<_>>())));
        for n in 0..20 {
            f.registry.answer(&list_path(prefix, &format!("{letter}{n}")), FakeAnswer::GatedMetadata { body: conan::revisions_doc(("reference", "x"), &[(R1, Some(OLD))]), gate: Arc::clone(&gate) });
        }
    }
    let searches: Vec<_> = ["/registry/conan/7", "/registry/conan/8"].into_iter().map(|root| { let url = f.server.url(&format!("{root}/v2/conans/search?q=*")); tokio::spawn(async move { reqwest::get(url).await.unwrap().status().as_u16() }) }).collect();
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    assert_eq!(calls(&f, "/revisions"), 12, "one owner judges 12 lists at once across both registries (not 24, and not 16)");
    for _ in 0..40 {
        gate.release();
    }
    for search in searches {
        assert_eq!(search.await.unwrap(), 200);
    }
    f.server.shutdown().await;
}

/// R4-2 as a check, in service mode (an owner, 12 lanes): a search too large for one attempt, the registry 100 ms away and the client giving
/// up after 1.5 s each time, is answered after a bounded run of retries.
#[tokio::test]
async fn in_service_mode_an_aborted_search_converges_over_retries_at_100_ms() {
    let f = start(0, Some(&target()), None).await;
    let names: Vec<String> = (0..600).map(|n| format!("s{n}/1.0@_/_")).collect();
    f.registry.answer(&format!("{PREFIX}/v2/conans/search"), FakeAnswer::Body(conan::search_doc(&names.iter().map(String::as_str).collect::<Vec<_>>())));
    for n in 0..600 {
        f.registry.answer(&list_path(PREFIX, &format!("s{n}")), FakeAnswer::Body(conan::revisions_doc(("reference", "x"), &[(R1, Some(OLD))])));
    }
    f.registry.set_delay_ms(100);
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_millis(1_500)).build().unwrap();
    let mut attempts = 0;
    let mut status = 0;
    while status != 200 && attempts < 12 {
        attempts += 1;
        status = client.get(f.server.url("/conan/v2/conans/search?q=*")).send().await.map_or(0, |r| r.status().as_u16());
        f.clock.advance_seconds(30);
    }
    assert_eq!(status, 200, "converged after {attempts} attempts");
    f.server.shutdown().await;
}

/// R4-2, the measurement in service mode (`--ignored --nocapture`): 9,000 references, 100 and 200 ms away, the production deadline, one line per attempt.
#[tokio::test]
#[ignore = "a measurement: cargo test --test conan_service_read service_mode_measurement -- --ignored --nocapture"]
async fn service_mode_measurement() {
    for delay in [100u64, 200] {
        let f = start(0, Some(&target()), None).await;
        let names: Vec<String> = (0..9_000).map(|n| format!("m{n}/1.0@_/_")).collect();
        f.registry.answer(&format!("{PREFIX}/v2/conans/search"), FakeAnswer::Body(conan::search_doc(&names.iter().map(String::as_str).collect::<Vec<_>>())));
        for n in 0..9_000 {
            f.registry.answer(&list_path(PREFIX, &format!("m{n}")), FakeAnswer::Body(conan::revisions_doc(("reference", "x"), &[(R1, Some(OLD))])));
        }
        f.registry.set_delay_ms(delay);
        let total = std::time::Instant::now();
        for attempt in 1..=6 {
            let started = std::time::Instant::now();
            let status = f.server.get("/conan/v2/conans/search?q=*").await.status().as_u16();
            eprintln!("SERVICE delay_ms={delay} attempt={attempt} status={status} seconds={:.1} total_seconds={:.1}", started.elapsed().as_secs_f64(), total.elapsed().as_secs_f64());
            if status == 200 {
                break;
            }
        }
        f.server.shutdown().await;
    }
}
