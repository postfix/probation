mod common;

use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{ActionRequest, ActionResponse, ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, Transport, UpstreamError};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{num::NonZeroU64, sync::{Arc, Mutex, Weak, atomic::{AtomicBool, Ordering}}};
use tokio::io::AsyncReadExt;
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Registry {
    inner: Arc<FakeRegistry>,
    mode: &'static str,
    wrote: AtomicBool,
    trace: Mutex<Vec<(String, String, String)>>,
    app: Mutex<Weak<probation::App>>,
}

impl Registry {
    fn new(inner: Arc<FakeRegistry>, mode: &'static str) -> Self {
        Self { inner, mode, wrote: AtomicBool::new(false), trace: Mutex::new(vec![]), app: Mutex::new(Weak::new()) }
    }
}

#[async_trait::async_trait]
impl Transport for Registry {
    async fn fetch_metadata(&self, request: MetadataRequest) -> Result<MetadataResponse, UpstreamError> {
        self.inner.fetch_metadata(request).await
    }
    async fn fetch_token_packument(&self, request: MetadataRequest, token: &str) -> Result<MetadataResponse, UpstreamError> {
        assert_eq!(token, "Bearer owner");
        assert_eq!(request.url.host_str(), Some("npm.invalid"));
        self.trace.lock().unwrap().push(("GET".into(), request.url.to_string(), token.into()));
        if self.wrote.load(Ordering::SeqCst) && self.mode == "unavailable" { return Err(UpstreamError::Timeout); }
        self.inner.fetch_metadata(request).await
    }
    async fn send_action(&self, mut request: ActionRequest) -> Result<ActionResponse, UpstreamError> {
        assert_eq!(request.url.host_str(), Some("npm.invalid"));
        assert_eq!(request.authorization.as_deref(), Some("Bearer owner"));
        self.trace.lock().unwrap().push((request.method.to_string(), request.url.to_string(), request.authorization.clone().unwrap()));
        if request.method == "DELETE" {
            return Ok(ActionResponse { status: 200, content_type: None, body: b"{\"ok\":true}".as_slice().into() });
        }
        let mut bytes = Vec::new();
        request.body.read_to_end(&mut bytes).await.unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if self.mode == "denied" {
            return Ok(ActionResponse { status: 403, content_type: None, body: b"{}".as_slice().into() });
        }
        self.wrote.store(true, Ordering::SeqCst);
        if self.mode != "retained" {
            value["_rev"] = "2".into();
            self.inner.answer("/example", FakeAnswer::Body(value.to_string()));
        }
        if self.mode == "marker_failure" {
            let app = self.app.lock().unwrap().upgrade().unwrap();
            app.store().commit_action_leases(3, 0, "example", vec![], app.clock.now_utc_micros()).await.unwrap();
        }
        let body = match self.mode {
            "fallback" | "unavailable" | "retained" => "{}",
            "bad_revision" => "{\"rev\":\"bad/revision\"}",
            "malformed" => "not json",
            _ => "{\"rev\":\"2\"}",
        };
        Ok(ActionResponse { status: 201, content_type: None, body: body.to_owned().into() })
    }
    async fn open_artifact(&self, request: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        self.inner.open_artifact(request).await
    }
}

fn snapshot() -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer { place: *place,
            layer: Layer { freeze_seconds: Some(0), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) }, revision: 1 }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor { registry: RegistryId(3), ecosystem: probation_policy::Ecosystem::Npm,
            target_url: None, trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![] }],
    }
}

async fn setup(mode: &'static str) -> (TestServer, Arc<Registry>, tempfile::TempDir, MockServer) {
    setup_named(mode, "example").await
}

async fn setup_named(mode: &'static str, name: &str) -> (TestServer, Arc<Registry>, tempfile::TempDir, MockServer) {
    let policy = MockServer::start().await;
    let mut configured = snapshot();
    if mode == "foreign" {
        configured.registries[0].deletion_scopes.push(RegistryDeletionScope {
            origin: "https://foreign.invalid".into(), path_prefix: "/example".into(), forward_bearer: true,
        });
    }
    Mock::given(wiremock::matchers::method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(configured)).mount(&policy).await;
    let registry = FakeRegistry::new();
    registry.answer(&common::npm_upstream_path(name), FakeAnswer::Body(serde_json::json!({
        "name":name, "_rev":"1", "versions":{"1.0.0":{"name":name, "version":"1.0.0",
        "dist":{"tarball":format!("https://npm.invalid/{name}/-/example-1.0.0.tgz"), "shasum":"0000000000000000000000000000000000000000"}}},
        "dist-tags":{"latest":"1.0.0"}, "time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig { server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(), service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap() });
    let registry = Arc::new(Registry::new(registry, mode));
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        registry.clone(), fake_origins()).await;
    *registry.app.lock().unwrap() = Arc::downgrade(&server.app());
    (server, registry, dir, policy)
}

#[tokio::test]
async fn scoped_action_routes_decode_once_and_preserve_selected_identity() {
    let (server, registry, _dir, _policy) = setup_named("revision", "@scope/example").await;
    let client = reqwest::Client::new();
    for encoded in ["@scope%2fexample", "@scope%2Fexample", "%40scope%2Fexample"] {
        let response = server.get_with_headers(&format!("/registry/npm/3/{encoded}?write=true"), &[("authorization", "Bearer owner")]).await;
        assert_eq!(response.status(), 200, "scoped write preflight: {encoded}");
        let response = client.delete(server.url(&format!("/registry/npm/3/{encoded}/-rev/1"))).bearer_auth("owner").send().await.unwrap();
        assert_eq!(response.status(), 200, "scoped whole-package DELETE: {encoded}");
    }
    let trace = registry.trace.lock().unwrap().clone();
    assert_eq!(trace.len(), 6);
    for pair in trace.chunks_exact(2) {
        assert_eq!(pair[0], ("GET".into(), "https://npm.invalid/@scope%2Fexample?write=true".into(), "Bearer owner".into()));
        assert_eq!(pair[1], ("DELETE".into(), "https://npm.invalid/@scope%2Fexample/-rev/1".into(), "Bearer owner".into()));
    }
    for malformed in ["@scope%252fexample", "@scope%2F..", "@scope%2Fexample%2Fextra", "@scope%ZZexample", "@scope%2F%FF", "@scope%2Fexample%00", "@scope%2Fexample%5Cextra"] {
        assert!(server.get_with_headers(&format!("/registry/npm/3/{malformed}?write=true"), &[("authorization", "Bearer owner")]).await.status().is_client_error());
        assert!(client.delete(server.url(&format!("/registry/npm/3/{malformed}/-rev/1"))).bearer_auth("owner").send().await.unwrap().status().is_client_error());
    }
    assert_eq!(registry.trace.lock().unwrap().len(), trace.len(), "malformed and double-encoded routes make zero upstream calls");
}

#[tokio::test]
async fn sealed_foreign_reference_with_valid_marker_refuses_before_send() {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead, Payload}};
    use probation::{artifacts::reference::{ArtifactReference, ReferenceId}, policy::{Digest, Ecosystem, HashAlgorithm}};
    let (server, registry, _dir, _policy) = setup("foreign").await;
    let response = server.get_with_headers("/registry/npm/3/example?write=true", &[("authorization", "Bearer owner")]).await;
    assert_eq!(response.status(), 200);
    let doc: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let local: url::Url = doc["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap().parse().unwrap();
    let original = ReferenceId::parse_hex(local.path().split('/').rev().nth(1).unwrap()).unwrap();
    let app = server.app();
    let now = app.clock.now_utc_micros();
    let mut lease = app.store().get_action_lease(3, 0, original, now).await.unwrap().unwrap();
    let foreign = ArtifactReference {
        ecosystem: Ecosystem::Npm, name: "example".into(), version: "1.0.0".into(), filename: "example-1.0.0.tgz".into(),
        upstream_url: "https://foreign.invalid/example/-/example-1.0.0.tgz".parse().unwrap(),
        expected: vec![Digest::parse_hex(HashAlgorithm::Sha1, "0000000000000000000000000000000000000000").unwrap()],
    };
    lease.reference_id = ReferenceId::compute_in_registry(3, &foreign);
    // A persisted-state attack fixture uses the real service seal, so lookup and decryption succeed.
    let key = std::fs::read(app.config.data_dir.join("npm-unpublish.key")).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = [7u8; 12];
    let aad = format!("npm-service-unpublish:3:{}", lease.reference_id.to_hex());
    let sealed = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: foreign.upstream_url.as_str().as_bytes(), aad: aad.as_bytes() }).unwrap();
    lease.sealed_url = [nonce.as_slice(), sealed.as_slice()].concat();
    app.store().commit_action_leases(3, 0, "example", vec![lease.clone()], now).await.unwrap();
    app.store().mark_removed_leases(3, 0, vec![lease.reference_id], "2".into()).await.unwrap();
    let before = registry.trace.lock().unwrap().len();
    let response = reqwest::Client::new().delete(server.url(&format!("/registry/npm/3/artifacts/{}/example-1.0.0.tgz/-rev/2", lease.reference_id.to_hex())))
        .bearer_auth("owner").send().await.unwrap();
    assert_eq!(response.status(), 400, "a stored, decryptable extra-origin reference must fail destination approval");
    assert!(response.text().await.unwrap().contains("service unpublish requires the selected registry origin"));
    assert_eq!(registry.trace.lock().unwrap().len(), before, "foreign reference sends no request or developer credential");
    assert!(app.store().consume_action_marker(3, 0, lease.reference_id, "2".into(), now).await.unwrap(), "the valid marker was not consumed before origin refusal");
}

#[tokio::test]
async fn write_preflight_commits_a_service_scoped_reference() {
    let (server, _, _dir, _policy) = setup("revision").await;
    let response = server.get_with_headers("/registry/npm/3/example?write=true", &[("authorization", "Bearer owner")]).await;
    assert_eq!(response.status(), 200, "write preflight must advertise a durable service reference");
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let local: url::Url = body["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap().parse().unwrap();
    let reference = probation::store::rows::ReferenceId::parse_hex(local.path().split('/').rev().nth(1).unwrap()).unwrap();
    let lease = server.app().store().get_action_lease(3, 0, reference, 0).await.unwrap();
    assert!(lease.is_some(), "service store namespace is independent of policy place 10");
    assert!(server.app().store().get_action_lease(3, 10, reference, 0).await.unwrap().is_none(), "policy place is not a member identity");
}

#[tokio::test]
async fn service_removal_verifies_revision_and_consumes_once_before_send() {
    for mode in ["revision", "fallback", "unavailable", "retained", "bad_revision", "malformed", "denied", "unchanged", "marker_failure"] {
        let (server, registry, _dir, _policy) = setup(mode).await;
        let response = server.get_with_headers("/registry/npm/3/example?write=true", &[("authorization", "Bearer owner")]).await;
        assert_eq!(response.status(), 200);
        let mut document: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let local: url::Url = document["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap().parse().unwrap();
        if mode != "unchanged" { document["versions"].as_object_mut().unwrap().remove("1.0.0"); }
        let client = reqwest::Client::new();
        let response = client.put(server.url("/registry/npm/3/example/-rev/1")).bearer_auth("owner")
            .header("content-type", "application/json").body(document.to_string()).send().await.unwrap();
        let success = matches!(mode, "revision" | "fallback");
        let expected = if success || mode == "unchanged" { 201 } else if mode == "denied" { 403 } else { 503 };
        assert_eq!(response.status(), expected, "{mode}: accepted removal must be verified before a durable service marker");
        if expected == 503 { assert!(response.text().await.unwrap().contains("PARTIAL_WRITE_UNCERTAIN"), "{mode}"); }
        let refused = if mode == "marker_failure" { 503 } else { 404 };
        let delete = |revision: &str| client.delete(server.url(&format!("{}/-rev/{revision}", local.path()))).bearer_auth("owner").send();
        assert_eq!(delete("wrong").await.unwrap().status(), refused, "wrong revision: {mode}");
        let (first, second) = tokio::join!(delete("2"), delete("2"));
        let mut statuses = [first.unwrap().status().as_u16(), second.unwrap().status().as_u16()];
        statuses.sort();
        assert_eq!(statuses, if success { [200, 404] } else { [refused, refused] }, "{mode}: only one accepted-removal marker may send");
        assert_eq!(delete("2").await.unwrap().status(), refused, "replay: {mode}");
        let trace = registry.trace.lock().unwrap();
        assert_eq!(trace.iter().filter(|(method, _, _)| method == "DELETE").count(), usize::from(success), "{mode}: outbound count");
        if matches!(mode, "fallback" | "unavailable" | "retained") {
            assert_eq!(trace.iter().filter(|(method, _, _)| method == "GET").count(), 2, "{mode}: immediate authenticated GET");
            assert_eq!(trace[2], ("GET".into(), "https://npm.invalid/example".into(), "Bearer owner".into()));
        }
    }
}
