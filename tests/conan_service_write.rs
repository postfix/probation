//! Row 23: `conan upload` through the shared service (class W): the `PUT` of each file of a recipe or package revision and a
//! `DELETE`, forwarded with the caller's own `Authorization` (the token a Conan login returned) to the registry's own origin (or, for
//! the public registry, the configured upload URL), never the service key; the challenge the client waits for; the bounds.
mod common;

use common::{TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{ActionRequest, ActionResponse, ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, Transport, UpstreamError};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{num::NonZeroU64, sync::{Arc, Mutex}};
use tokio::io::AsyncReadExt;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

#[derive(Debug, PartialEq, Eq)]
struct Call {
    method: String,
    url: String,
    origin: String,
    authorization: Option<String>,
    api_key: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct Registry {
    calls: Mutex<Vec<Call>>,
    reads: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Transport for Registry {
    async fn fetch_metadata(&self, _: MetadataRequest) -> Result<MetadataResponse, UpstreamError> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(UpstreamError::Status(404))
    }
    async fn open_artifact(&self, _: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(UpstreamError::Status(404))
    }
    async fn send_action(&self, mut request: ActionRequest) -> Result<ActionResponse, UpstreamError> {
        let mut body = Vec::new();
        request.body.read_to_end(&mut body).await.unwrap();
        let status = match request.authorization.as_deref() {
            Some("Bearer denied") => 403,
            Some("Bearer odd") => 302,
            _ => 201,
        };
        self.calls.lock().unwrap().push(Call {
            method: request.method.to_string(),
            url: request.url.to_string(),
            origin: request.origin.to_string(),
            authorization: request.authorization.clone(),
            api_key: request.api_key.clone(),
            content_type: request.content_type.clone(),
            body,
        });
        Ok(ActionResponse { status, content_type: Some("text/html".into()), body: b"<script>alert(1)</script>".as_slice().into() })
    }
}

fn snapshot_at(target: Option<&str>) -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer { freeze_seconds: Some(0), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor {
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Conan, target_url: target.map(Into::into),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None, token_origin: None,
        }],
    }
}

async fn start(target: Option<&str>, public_deploy: Option<&str>) -> (TestServer, Arc<Registry>, MockServer) {
    start_behind(target, public_deploy, vec![]).await
}

async fn start_behind(target: Option<&str>, public_deploy: Option<&str>, trusted_proxies: Vec<probation::config::Cidr>) -> (TestServer, Arc<Registry>, MockServer) {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot_at(target))).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.max_artifact_bytes = NonZeroU64::new(100).unwrap();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
        trusted_proxies,
    });
    let registry = Arc::new(Registry { calls: Mutex::default(), reads: Default::default() });
    let mut origins = fake_origins();
    if let Some(deploy) = public_deploy {
        origins = origins.with_conan(url::Url::parse(common::conan::REMOTE).unwrap(), url::Url::parse(deploy).unwrap());
    }
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), registry.clone(), origins).await;
    (server, registry, policy)
}


const TARGET: &str = "https://art.invalid/artifactory/api/conan/local/";
const REV: &str = "aaaa0000000000000000000000000001";
const PKG: &str = "b647c43bfefae3f830561ca202b6cfd935b56205";
const PREV: &str = "fee20b6da94c4580b0c84ca5ce203fdc";

fn recipe_file(file: &str) -> String {
    format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{REV}/files/{file}")
}

fn package_file(file: &str) -> String {
    format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{REV}/packages/{PKG}/revisions/{PREV}/files/{file}")
}

#[tokio::test]
async fn an_upload_is_challenged_then_forwarded_with_the_callers_own_credential_only() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    let files = [
        recipe_file("conanfile.py"),
        recipe_file("conanmanifest.txt"),
        recipe_file("conan_export.tgz"),
        package_file("conaninfo.txt"),
        package_file("conan_package.tgz"),
        format!("/registry/conan/7/v2/conans/mylib/2.0/acme/stable/revisions/{REV}/files/conanfile.py"),
    ];
    // A client sends its token only when it has one: without, it gets the challenge, before anything is read or asked.
    for uri in &files {
        let response = client.put(server.url(uri)).body("x").send().await.unwrap();
        assert_eq!(response.status(), 401, "{uri}");
        assert!(response.headers()["www-authenticate"].to_str().unwrap().starts_with("Bearer"), "{uri}");
    }
    assert!(registry.calls.lock().unwrap().is_empty());
    assert_eq!(registry.reads.load(std::sync::atomic::Ordering::SeqCst), 0, "not even a lookup");
    for uri in &files {
        let response = client.put(server.url(uri)).header("authorization", "Bearer tok").header("content-type", "application/octet-stream").body("artifact bytes").send().await.unwrap();
        assert_eq!(response.status(), 201, "{uri}");
    }
    let seen = std::mem::take(&mut *registry.calls.lock().unwrap());
    let urls: Vec<&str> = seen.iter().map(|c| c.url.as_str()).collect();
    let root = "https://art.invalid/artifactory/api/conan/local/v2/conans";
    assert_eq!(urls, [
        format!("{root}/zlib/1.3.1/_/_/revisions/{REV}/files/conanfile.py"),
        format!("{root}/zlib/1.3.1/_/_/revisions/{REV}/files/conanmanifest.txt"),
        format!("{root}/zlib/1.3.1/_/_/revisions/{REV}/files/conan_export.tgz"),
        format!("{root}/zlib/1.3.1/_/_/revisions/{REV}/packages/{PKG}/revisions/{PREV}/files/conaninfo.txt"),
        format!("{root}/zlib/1.3.1/_/_/revisions/{REV}/packages/{PKG}/revisions/{PREV}/files/conan_package.tgz"),
        format!("{root}/mylib/2.0/acme/stable/revisions/{REV}/files/conanfile.py"),
    ]);
    assert!(seen.iter().all(|c| c.method == "PUT" && c.authorization.as_deref() == Some("Bearer tok") && c.body == b"artifact bytes" && c.origin == TARGET), "{seen:?}");
    assert!(seen.iter().all(|c| c.api_key.is_none() && c.authorization.as_deref() != Some("prb_01234567890123456789012345678901")), "the service key never leaves");
    // A clean-up is a DELETE with the same rules.
    let deleted = client.delete(server.url(&recipe_file("conan_export.tgz"))).header("authorization", "Bearer tok").send().await.unwrap();
    assert_eq!(deleted.status(), 201);
    assert_eq!(registry.calls.lock().unwrap()[0].method, "DELETE");
    server.shutdown().await;
}

#[tokio::test]
async fn the_registrys_refusal_is_the_answer_and_nothing_it_says_is_served_as_a_page() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    let denied = client.put(server.url(&recipe_file("conanfile.py"))).header("authorization", "Bearer denied").body("x").send().await.unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(denied.headers()["content-type"], "text/plain; charset=utf-8");
    assert_eq!(denied.headers()["x-content-type-options"], "nosniff");
    // An answer an upload endpoint does not give is a 502, never relayed.
    let odd = client.put(server.url(&recipe_file("conanfile.py"))).header("authorization", "Bearer odd").body("x").send().await.unwrap();
    assert_eq!(odd.status(), 502);
    assert_eq!(registry.calls.lock().unwrap().len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn paths_that_are_no_layout_path_and_oversize_bodies_reach_nothing() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    for uri in ["/conan/v2/conans/zlib/1.3.1/_/_/latest", "/conan/v2/conans/zlib/1.3.1/_/_/revisions", "/conan/v2/conans/zlib/1.3.1/_/_/revisions/a/files/", "/conan/v2/conans/zlib/1.3.1/acme/_/revisions/a/files/x", "/conan/v1/conans/zlib/1.3.1/_/_/upload_urls", "/conan/v2/conans/zlib/1.3.1/_/_/revisions/a/files/../x", "/conan/v2/users/authenticate", "/conan/v2/conans/search"] {
        let status = client.put(server.url(uri)).header("authorization", "Bearer tok").body("x").send().await.unwrap().status();
        assert_eq!(status, 404, "{uri}");
    }
    let big = client.put(server.url(&recipe_file("conan_export.tgz"))).header("authorization", "Bearer tok").body(vec![0u8; 500]).send().await.unwrap();
    assert_eq!(big.status(), 413, "over the cap: refused before the registry is asked anything");
    assert!(registry.calls.lock().unwrap().is_empty());
    for verb in ["POST", "PATCH"] {
        let status = client.request(verb.parse().unwrap(), server.url(&recipe_file("conanfile.py"))).header("authorization", "Bearer tok").body("x").send().await.unwrap().status();
        assert_eq!(status, 405, "{verb}");
    }
    server.shutdown().await;
}

/// The public registry has no upload endpoint unless the operator names one (ConanCenter takes no upload of its own).
#[tokio::test]
async fn the_public_registrys_upload_url_is_the_configured_one_and_otherwise_there_is_none() {
    let (server, registry, _policy) = start(None, None).await;
    let response = reqwest::Client::new().put(server.url(&recipe_file("conanfile.py"))).header("authorization", "Bearer tok").body("x").send().await.unwrap();
    assert_eq!(response.status(), 404, "no configured upload URL, no route");
    assert!(registry.calls.lock().unwrap().is_empty());
    server.shutdown().await;
    let (server, registry, _policy) = start(None, Some(common::conan::PUBLISH)).await;
    let response = reqwest::Client::new().put(server.url(&recipe_file("conanfile.py"))).header("authorization", "Bearer tok").body("x").send().await.unwrap();
    assert_eq!(response.status(), 201);
    {
        let seen = registry.calls.lock().unwrap();
        assert_eq!((seen[0].url.as_str(), seen[0].origin.as_str()), (format!("https://conan-upload.invalid/up/v2/conans/zlib/1.3.1/_/_/revisions/{REV}/files/conanfile.py").as_str(), "https://conan-upload.invalid/up"));
    }
    server.shutdown().await;
}

/// A standalone firewall has no upload route: a write is refused and reaches nothing.
#[tokio::test]
async fn a_standalone_firewall_has_no_upload_route() {
    let server = TestServer::start().await;
    for (verb, uri) in [("PUT", recipe_file("conanfile.py")), ("DELETE", recipe_file("conanfile.py")), ("PUT", format!("/registry/conan/7/v2/conans/zlib/1.3.1/_/_/revisions/{REV}/files/conanfile.py"))] {
        for credential in [None, Some("Bearer tok")] {
            let mut request = reqwest::Client::new().request(verb.parse().unwrap(), server.url(&uri)).body("x");
            if let Some(credential) = credential {
                request = request.header("authorization", credential);
            }
            let status = request.send().await.unwrap().status().as_u16();
            assert!(matches!(status, 401 | 404 | 405 | 503), "{verb} {uri}: {status}");
        }
    }
    server.shutdown().await;
}

/// A clean-up of a recipe, a revision or a package directory is forwarded to the registry's own directory URL.
#[tokio::test]
async fn a_delete_of_a_directory_is_forwarded() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    let directories = ["/conan/v2/conans/zlib/1.3.1/_/_".to_owned(), format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{REV}"), format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{REV}/packages/{PKG}/revisions/{PREV}")];
    for uri in &directories {
        let response = client.delete(server.url(uri)).header("authorization", "Bearer tok").send().await.unwrap();
        assert_eq!(response.status(), 201, "{uri}");
    }
    {
        let seen = registry.calls.lock().unwrap();
        let urls: Vec<&str> = seen.iter().map(|c| c.url.as_str()).collect();
        let root = "https://art.invalid/artifactory/api/conan/local/v2/conans/zlib/1.3.1/_/_";
        assert_eq!(urls, [root.to_owned(), format!("{root}/revisions/{REV}"), format!("{root}/revisions/{REV}/packages/{PKG}/revisions/{PREV}")], "{seen:?}");
    }
    // A PUT to a directory is a 404.
    assert_eq!(client.put(server.url("/conan/v2/conans/zlib/1.3.1/_/_")).header("authorization", "Bearer tok").body("x").send().await.unwrap().status(), 404);
    server.shutdown().await;
}

/// Holds one deploy open (its body never ends) from `from` with `credential` and the extra headers; returns the task.
fn hold(url: &str, from: &str, credential: String, extra: &'static [(&'static str, &'static str)]) -> tokio::task::JoinHandle<()> {
    let (url, from) = (url.to_owned(), from.to_owned());
    tokio::spawn(async move {
        let body = reqwest::Body::wrap_stream(futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>());
        let client = reqwest::Client::builder().local_address(Some(from.parse().unwrap())).build().unwrap();
        let mut request = client.put(url).header("authorization", credential);
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let _ = request.body(body).send().await;
    })
}

async fn until_held(server: &TestServer, places: usize) {
    for _ in 0..200 {
        if server.app().limits.spool_places_free() == probation::http::limits::SPOOLS - places {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("the {places} uploads never took their places");
}

async fn put_from(url: &str, from: &str, credential: &str, extra: &[(&str, &str)]) -> u16 {
    let client = reqwest::Client::builder().local_address(Some(from.parse().unwrap())).build().unwrap();
    let mut request = client.put(url).header("authorization", credential);
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    request.body("x").send().await.unwrap().status().as_u16()
}

/// N1 (service mode): the places are counted per client ADDRESS and per presented credential, never by the credential alone.
/// Junk credentials from one address take that address's half of the places and no more, and a different address still deploys.
#[tokio::test]
async fn junk_credentials_from_one_address_take_that_addresss_share_and_another_address_still_deploys() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let url = server.url("/conan/v2/conans/zlib/1.3.1/_/_/revisions/aaaa0000000000000000000000000001/files/conan_export.tgz");
    let held: Vec<_> = (0..probation::http::limits::SPOOLS_PER_OWNER).map(|n| hold(&url, "127.0.0.1", format!("Bearer junk{n}"), &[])).collect();
    until_held(&server, probation::http::limits::SPOOLS_PER_OWNER).await;
    assert_eq!(put_from(&url, "127.0.0.1", "Bearer junk-five", &[]).await, 503, "the address holds its share, with a fresh junk credential too");
    assert_eq!(put_from(&url, "127.0.0.2", "Bearer tok", &[]).await, 201, "a different address still deploys");
    assert_eq!(registry.calls.lock().unwrap().len(), 1, "only the second address reached the registry");
    held.iter().for_each(|task| task.abort());
    server.shutdown().await;
}


/// The firewall's own key is never an upload credential: it is refused here and reaches no registry.
#[tokio::test]
async fn a_firewall_key_is_refused_as_an_upload_credential() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    for credential in ["Bearer prb_0123456789012345678901234567890123", "Basic dXNlcjpwcmJfMDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw=="] {
        let response = client.put(server.url(&recipe_file("conanfile.py"))).header("authorization", credential).body("x").send().await.unwrap();
        assert_eq!(response.status(), 403, "{credential}");
    }
    assert!(registry.calls.lock().unwrap().is_empty());
    server.shutdown().await;
}
