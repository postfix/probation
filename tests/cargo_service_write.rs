//! Row 18 follow-up: Cargo's write API through the shared service, as `gem push` and PyPI's
//! upload (class W): `cargo publish`, `yank`, `unyank` and `owner`, with the caller's own token
//! going to the registry's own API origin, never the service key; the reads of the same API
//! (owner list, search) are forwarded as class R.
mod common;

use common::{TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{
    ActionRequest, ActionResponse, ArtifactBody, ArtifactRequest, MetadataRequest,
    MetadataResponse, Transport, UpstreamError,
};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{
    num::NonZeroU64,
    sync::{Arc, Mutex},
};
use tokio::io::AsyncReadExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[derive(Debug, PartialEq, Eq)]
struct Call {
    method: String,
    url: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// The registry: serves a `config.json` whose `api` is `api`, and records every write and read of its API.
struct Registry {
    api: String,
    calls: Mutex<Vec<Call>>,
    /// How many times `config.json` was asked for.
    configs: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Transport for Registry {
    async fn fetch_metadata(&self, request: MetadataRequest) -> Result<MetadataResponse, UpstreamError> {
        if request.url.path().ends_with("/config.json") {
            self.configs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(MetadataResponse::Fresh {
                body: format!(r#"{{"dl":"https://cargo-reg.invalid/dl","api":"{}"}}"#, self.api).into_bytes().into(),
                validators: Default::default(),
            });
        }
        Err(UpstreamError::Status(404))
    }
    async fn open_artifact(&self, _: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        Err(UpstreamError::Status(404))
    }
    async fn send_action(&self, mut request: ActionRequest) -> Result<ActionResponse, UpstreamError> {
        let mut body = Vec::new();
        request.body.read_to_end(&mut body).await.unwrap();
        let denied = request.authorization.as_deref() == Some("denied");
        self.calls.lock().unwrap().push(Call {
            method: request.method.to_string(),
            url: request.url.to_string(),
            authorization: request.authorization.clone(),
            content_type: request.content_type.clone(),
            body,
        });
        Ok(ActionResponse { status: if denied { 403 } else { 200 }, content_type: Some("application/json".into()), body: b"{\"ok\":true}".as_slice().into() })
    }
}

fn snapshot_at(target: &str) -> ServicePolicySnapshot {
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
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Cargo, target_url: Some(target.into()),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }],
    }
}

async fn start(api: &str) -> (TestServer, Arc<Registry>, MockServer) {
    start_at("https://cargo-reg.invalid/", api).await
}

async fn start_at(target: &str, api: &str) -> (TestServer, Arc<Registry>, MockServer) {
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
        trusted_proxies: vec![],
    });
    let registry = Arc::new(Registry { api: api.to_owned(), calls: Mutex::default(), configs: Default::default() });
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), registry.clone(), fake_origins()).await;
    (server, registry, policy)
}

#[tokio::test]
async fn shared_service_forwards_cargo_writes_with_the_callers_own_token_only() {
    let (server, registry, _policy) = start("https://cargo-reg.invalid").await;
    let client = reqwest::Client::new();
    let writes = [
        ("PUT", "/cargo/api/v1/crates/new"),
        ("DELETE", "/cargo/api/v1/crates/demo/1.0.0/yank"),
        ("PUT", "/cargo/api/v1/crates/demo/1.0.0/unyank"),
        ("PUT", "/cargo/api/v1/crates/demo/owners"),
        ("DELETE", "/cargo/api/v1/crates/demo/owners"),
    ];
    // No credential: refused locally with 401 before any upstream call (not even config.json).
    for (verb, uri) in writes {
        let response = client.request(verb.parse().unwrap(), server.url(uri)).body("x").send().await.unwrap();
        assert_eq!(response.status(), 401, "{verb} {uri}");
    }
    assert!(registry.calls.lock().unwrap().is_empty());
    // With the caller's bare token every write reaches the registry's own API path with it.
    let publish = client.put(server.url("/cargo/api/v1/crates/new")).header("authorization", "cio0123456789").header("content-type", "application/octet-stream").body("crate bytes").send().await.unwrap();
    assert_eq!((publish.status().as_u16(), publish.text().await.unwrap().as_str()), (200, "{\"ok\":true}"));
    for (verb, uri) in &writes[1..] {
        let response = client.request(verb.parse().unwrap(), server.url(uri)).header("authorization", "cio0123456789").header("content-type", "application/json").body("{\"users\":[\"u\"]}").send().await.unwrap();
        assert_eq!(response.status(), 200, "{verb} {uri}");
    }
    let denied = client.put(server.url("/cargo/api/v1/crates/new")).header("authorization", "denied").body("x").send().await.unwrap();
    assert_eq!(denied.status(), 403, "the registry's own refusal is the answer");
    // Over the size cap: 413, nothing forwarded. A name or version that is not a crate name or SemVer: 404.
    assert_eq!(client.put(server.url("/cargo/api/v1/crates/new")).header("authorization", "k").body(vec![0u8; 500]).send().await.unwrap().status(), 413);
    for uri in ["/cargo/api/v1/crates/a.b/1.0.0/yank", "/cargo/api/v1/crates/demo/1.0/yank", "/cargo/api/v1/crates/demo/owners/x"] {
        assert_eq!(client.delete(server.url(uri)).header("authorization", "k").send().await.unwrap().status(), 404, "{uri}");
    }
    // Other verbs on those paths are not routes of the API.
    assert_eq!(client.post(server.url("/cargo/api/v1/crates/new")).header("authorization", "k").body("x").send().await.unwrap().status(), 405);
    assert_eq!(client.delete(server.url("/cargo/api/v1/crates/new")).header("authorization", "k").send().await.unwrap().status(), 405);
    assert_eq!(client.put(server.url("/cargo/api/v1/crates/demo/1.0.0/yank")).header("authorization", "k").body("x").send().await.unwrap().status(), 405);
    let seen = std::mem::take(&mut *registry.calls.lock().unwrap());
    let got: Vec<(&str, &str, Option<&str>)> = seen.iter().map(|c| (c.method.as_str(), c.url.as_str(), c.authorization.as_deref())).collect();
    let token = Some("cio0123456789");
    assert_eq!(got, [
        ("PUT", "https://cargo-reg.invalid/api/v1/crates/new", token),
        ("DELETE", "https://cargo-reg.invalid/api/v1/crates/demo/1.0.0/yank", token),
        ("PUT", "https://cargo-reg.invalid/api/v1/crates/demo/1.0.0/unyank", token),
        ("PUT", "https://cargo-reg.invalid/api/v1/crates/demo/owners", token),
        ("DELETE", "https://cargo-reg.invalid/api/v1/crates/demo/owners", token),
        ("PUT", "https://cargo-reg.invalid/api/v1/crates/new", Some("denied")),
    ], "{seen:?}");
    assert_eq!((seen[0].content_type.as_deref(), seen[0].body.as_slice()), (Some("application/octet-stream"), b"crate bytes".as_slice()));
    assert_eq!(seen[3].body, b"{\"users\":[\"u\"]}", "the owner body arrives whole");
    assert!(seen.iter().all(|c| c.authorization.as_deref() != Some("prb_01234567890123456789012345678901")), "the service key never leaves");
    server.shutdown().await;
}

#[tokio::test]
async fn shared_service_forwards_the_owner_list_and_search_as_reads() {
    let (server, registry, _policy) = start("https://cargo-reg.invalid").await;
    let client = reqwest::Client::new();
    // A read needs no credential; the caller's own, when present, goes along. Unknown query keys are dropped.
    let owners = client.get(server.url("/cargo/api/v1/crates/demo/owners")).send().await.unwrap();
    assert_eq!(owners.status(), 200);
    let search = client.get(server.url("/cargo/api/v1/crates?q=serde%20json&per_page=5&evil=1&page=2")).header("authorization", "cio0123456789").send().await.unwrap();
    assert_eq!(search.status(), 200);
    let seen = std::mem::take(&mut *registry.calls.lock().unwrap());
    assert_eq!((seen[0].method.as_str(), seen[0].url.as_str(), seen[0].authorization.as_deref()), ("GET", "https://cargo-reg.invalid/api/v1/crates/demo/owners", None));
    assert_eq!((seen[1].method.as_str(), seen[1].url.as_str(), seen[1].authorization.as_deref()), ("GET", "https://cargo-reg.invalid/api/v1/crates?q=serde+json&per_page=5&page=2", Some("cio0123456789")));
    // Any other query on a read route is no route.
    assert_eq!(client.get(server.url("/cargo/config.json?x=1")).send().await.unwrap().status(), 404);
    assert_eq!(client.get(server.url("/cargo/api/v1/crates/demo/owners?x=1")).send().await.unwrap().status(), 404);
    server.shutdown().await;
}

#[tokio::test]
async fn an_api_root_outside_the_registrys_own_origin_is_never_written_to() {
    let (server, registry, _policy) = start("https://evil.invalid").await;
    let client = reqwest::Client::new();
    let response = client.put(server.url("/cargo/api/v1/crates/new")).header("authorization", "cio0123456789").body("x").send().await.unwrap();
    assert_eq!(response.status(), 502, "a config.json naming another host is refused");
    assert!(registry.calls.lock().unwrap().is_empty(), "the caller's token went nowhere");
    server.shutdown().await;
}

/// N1: a body the declared Content-Length already shows to be over the cap is refused with 413 before
/// anything is asked of the registry (not even its config.json).
#[tokio::test]
async fn an_oversize_write_is_refused_before_the_registry_is_asked_anything() {
    let (server, registry, _policy) = start("https://cargo-reg.invalid").await;
    let response = reqwest::Client::new().put(server.url("/cargo/api/v1/crates/new")).header("authorization", "tok").body(vec![0u8; 500]).send().await.unwrap();
    assert_eq!(response.status(), 413);
    assert_eq!(registry.configs.load(std::sync::atomic::Ordering::SeqCst), 0, "no config.json fetch for a body over the cap");
    assert!(registry.calls.lock().unwrap().is_empty());
    server.shutdown().await;
}

/// N4: the API root is pinned by path as well: it must be nested with the registry's own path (the same
/// prefix, below it, or above it as Artifactory's `.../repo` is above `.../repo/index`), so the token
/// cannot be steered to an unrelated path of the registry's host.
#[tokio::test]
async fn an_api_root_on_an_unrelated_path_of_the_registrys_host_is_never_written_to() {
    for (api, allowed) in [
        ("https://cargo-reg.invalid/other/place", false),
        ("https://cargo-reg.invalid/", true),
        ("https://cargo-reg.invalid", true),
    ] {
        let (server, registry, _policy) = start_at("https://cargo-reg.invalid/api/cargo/repo/index/", api).await;
        let response = reqwest::Client::new().put(server.url("/cargo/api/v1/crates/new")).header("authorization", "tok").body("x").send().await.unwrap();
        assert_eq!(response.status(), if allowed { 200 } else { 502 }, "{api}");
        assert_eq!(registry.calls.lock().unwrap().len(), usize::from(allowed), "{api}");
        server.shutdown().await;
    }
    for (api, allowed) in [("https://cargo-reg.invalid/api/cargo/repo", true), ("https://cargo-reg.invalid/api/cargo/repo/index/v2", true), ("https://cargo-reg.invalid/api/cargo/rep", false), ("https://cargo-reg.invalid/api/cargo/repo2", false)] {
        let (server, registry, _policy) = start_at("https://cargo-reg.invalid/api/cargo/repo/index/", api).await;
        let response = reqwest::Client::new().put(server.url("/cargo/api/v1/crates/new")).header("authorization", "tok").body("x").send().await.unwrap();
        assert_eq!(response.status(), if allowed { 200 } else { 502 }, "{api}");
        assert_eq!(registry.calls.lock().unwrap().len(), usize::from(allowed), "{api}");
        server.shutdown().await;
    }
}
