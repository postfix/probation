//! Row 20: NuGet's publish endpoints through the shared service, as `gem push` and `cargo publish` (class W):
//! `dotnet nuget push` (and its symbol package form), `dotnet nuget delete` (unlist) and relist, with the
//! caller's own API key going to the endpoint the registry's own service index names, never the service key; a
//! registry's service index that names an endpoint on another origin is never written to.
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
    origin: String,
    authorization: Option<String>,
    api_key: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// The registry: serves a service index whose publish endpoints are `publish`, and records every write.
struct Registry {
    publish: String,
    flat: String,
    calls: Mutex<Vec<Call>>,
    indexes: std::sync::atomic::AtomicUsize,
    /// What the registry answers a write with when the key is `odd`: (status, content type, body).
    odd: Mutex<(u16, &'static str, &'static str)>,
}

#[async_trait::async_trait]
impl Transport for Registry {
    async fn fetch_metadata(&self, request: MetadataRequest) -> Result<MetadataResponse, UpstreamError> {
        if request.url.path().ends_with("/index.json") {
            self.indexes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = serde_json::json!({"version": "3.0.0", "resources": [
                {"@id": format!("{}/flat/", self.flat), "@type": "PackageBaseAddress/3.0.0"},
                {"@id": format!("{}/api/v2/package", self.publish), "@type": "PackagePublish/2.0.0"},
                {"@id": format!("{}/api/v2/symbolpackage", self.publish), "@type": "SymbolPackagePublish/4.9.0"},
            ]});
            return Ok(MetadataResponse::Fresh { body: body.to_string().into_bytes().into(), validators: Default::default() });
        }
        Err(UpstreamError::Status(404))
    }
    async fn open_artifact(&self, _: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        Err(UpstreamError::Status(404))
    }
    async fn send_action(&self, mut request: ActionRequest) -> Result<ActionResponse, UpstreamError> {
        let mut body = Vec::new();
        request.body.read_to_end(&mut body).await.unwrap();
        let denied = request.api_key.as_deref() == Some("denied");
        let odd = request.api_key.as_deref() == Some("odd");
        self.calls.lock().unwrap().push(Call {
            method: request.method.to_string(),
            url: request.url.to_string(),
            origin: request.origin.to_string(),
            authorization: request.authorization.clone(),
            api_key: request.api_key.clone(),
            content_type: request.content_type.clone(),
            body,
        });
        if odd {
            let (status, content_type, body) = *self.odd.lock().unwrap();
            return Ok(ActionResponse { status, content_type: Some(content_type.into()), body: body.as_bytes().to_vec().into() });
        }
        Ok(ActionResponse { status: if denied { 403 } else { 201 }, content_type: Some("text/plain".into()), body: b"created".as_slice().into() })
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
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::NuGet, target_url: target.map(Into::into),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }],
    }
}

async fn start(publish: &str) -> (TestServer, Arc<Registry>, MockServer) {
    start_at(Some("https://nuget-reg.invalid/v3/index.json"), publish).await
}

async fn start_at(target: Option<&str>, publish: &str) -> (TestServer, Arc<Registry>, MockServer) {
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
    let flat = if target.is_some_and(|t| t.contains("nuget-reg")) { "https://nuget-reg.invalid" } else { "https://nuget-pub.invalid" };
    let registry = Arc::new(Registry { publish: publish.to_owned(), flat: flat.to_owned(), calls: Mutex::default(), indexes: Default::default(), odd: Mutex::new((200, "text/plain", "")) });
    let origins = fake_origins().with_nuget(
        url::Url::parse("https://nuget-pub.invalid").unwrap(),
        url::Url::parse("https://nuget-search.invalid").unwrap(),
        url::Url::parse("https://nuget-push.invalid").unwrap(),
    );
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), registry.clone(), origins).await;
    (server, registry, policy)
}

#[tokio::test]
async fn shared_service_forwards_nuget_writes_with_the_callers_own_key_only() {
    let (server, registry, _policy) = start("https://nuget-reg.invalid").await;
    let client = reqwest::Client::new();
    let writes = [
        ("PUT", "/nuget/api/v2/package"),
        ("PUT", "/nuget/api/v2/symbolpackage"),
        ("PUT", "/nuget/api/v2/package/"),
        ("PUT", "/nuget/api/v2/symbolpackage/"),
        ("DELETE", "/nuget/api/v2/package/Demo.Pkg/1.0.0"),
        ("POST", "/nuget/api/v2/package/Demo.Pkg/1.0.0"),
    ];
    // No credential: refused locally with 401 before any upstream call (not even the service index).
    for (verb, uri) in writes {
        let response = client.request(verb.parse().unwrap(), server.url(uri)).body("x").send().await.unwrap();
        assert_eq!(response.status(), 401, "{verb} {uri}");
    }
    assert!(registry.calls.lock().unwrap().is_empty());
    assert_eq!(registry.indexes.load(std::sync::atomic::Ordering::SeqCst), 0);
    // With the caller's own API key (and a private feed's Authorization) every write reaches the registry's endpoint.
    let publish = client.put(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "key-123").header("content-type", "multipart/form-data; boundary=b").body("package bytes").send().await.unwrap();
    assert_eq!((publish.status().as_u16(), publish.text().await.unwrap().as_str()), (201, "created"));
    for (verb, uri) in &writes[1..] {
        let response = client.request(verb.parse().unwrap(), server.url(uri)).header("x-nuget-apikey", "key-123").header("authorization", "Basic dTpw").body("x").send().await.unwrap();
        assert_eq!(response.status(), 201, "{verb} {uri}");
    }
    let denied = client.put(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "denied").body("x").send().await.unwrap();
    assert_eq!(denied.status(), 403, "the registry's own refusal is the answer");
    // Over the size cap: 413, nothing forwarded. An id or version that is no NuGet id or version: 404.
    assert_eq!(client.put(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "k").body(vec![0u8; 500]).send().await.unwrap().status(), 413);
    for uri in ["/nuget/api/v2/package/a%20b/1.0.0", "/nuget/api/v2/package/demo/1.0.0.0.0", "/nuget/api/v2/package/demo/x"] {
        assert_eq!(client.delete(server.url(uri)).header("x-nuget-apikey", "k").send().await.unwrap().status(), 404, "{uri}");
    }
    // Other verbs on those paths are not routes of the publish API.
    assert_eq!(client.post(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "k").body("x").send().await.unwrap().status(), 405);
    assert_eq!(client.delete(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "k").send().await.unwrap().status(), 405);
    assert_eq!(client.put(server.url("/nuget/api/v2/package/demo/1.0.0")).header("x-nuget-apikey", "k").body("x").send().await.unwrap().status(), 405);
    let seen = std::mem::take(&mut *registry.calls.lock().unwrap());
    let got: Vec<(&str, &str)> = seen.iter().map(|c| (c.method.as_str(), c.url.as_str())).collect();
    assert_eq!(got, [
        ("PUT", "https://nuget-reg.invalid/api/v2/package"),
        ("PUT", "https://nuget-reg.invalid/api/v2/symbolpackage"),
        ("PUT", "https://nuget-reg.invalid/api/v2/package"),
        ("PUT", "https://nuget-reg.invalid/api/v2/symbolpackage"),
        ("DELETE", "https://nuget-reg.invalid/api/v2/package/Demo.Pkg/1.0.0"),
        ("POST", "https://nuget-reg.invalid/api/v2/package/Demo.Pkg/1.0.0"),
        ("PUT", "https://nuget-reg.invalid/api/v2/package"),
    ], "{seen:?}");
    assert_eq!((seen[0].api_key.as_deref(), seen[0].authorization.as_deref(), seen[0].content_type.as_deref(), seen[0].body.as_slice()), (Some("key-123"), None, Some("multipart/form-data; boundary=b"), b"package bytes".as_slice()));
    assert_eq!((seen[1].api_key.as_deref(), seen[1].authorization.as_deref()), (Some("key-123"), Some("Basic dTpw")));
    assert!(seen.iter().all(|c| c.origin == "https://nuget-reg.invalid/"), "admitted against the registry's own origin: {seen:?}");
    assert!(seen.iter().all(|c| c.api_key.as_deref() != Some("prb_01234567890123456789012345678901") && c.authorization.as_deref() != Some("prb_01234567890123456789012345678901")), "the service key never leaves");
    server.shutdown().await;
}

/// The key travels in `Authorization` alone when that is all a private feed's client sends (Bearer from a credential provider).
#[tokio::test]
async fn an_authorization_header_alone_is_a_credential_and_is_forwarded() {
    let (server, registry, _policy) = start("https://nuget-reg.invalid").await;
    let response = reqwest::Client::new().put(server.url("/nuget/api/v2/package")).header("authorization", "Bearer abc").body("x").send().await.unwrap();
    assert_eq!(response.status(), 201);
    {
        let seen = registry.calls.lock().unwrap();
        assert_eq!((seen[0].authorization.as_deref(), seen[0].api_key.as_deref()), (Some("Bearer abc"), None));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn a_publish_endpoint_outside_the_registrys_own_origin_is_never_written_to() {
    let (server, registry, _policy) = start("https://evil.invalid").await;
    let response = reqwest::Client::new().put(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "key-123").body("x").send().await.unwrap();
    assert_eq!(response.status(), 404, "a service index naming a publish endpoint on another host offers none");
    assert!(registry.calls.lock().unwrap().is_empty(), "the caller's key went nowhere");
    server.shutdown().await;
}

/// The public registry (no target of its own): its publish endpoint is the configured publish host, nothing else.
#[tokio::test]
async fn the_public_registrys_publish_endpoint_is_the_configured_publish_host() {
    let (server, registry, _policy) = start_at(None, "https://nuget-push.invalid").await;
    let response = reqwest::Client::new().put(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "key-123").body("x").send().await.unwrap();
    assert_eq!(response.status(), 201);
    {
        let seen = registry.calls.lock().unwrap();
        assert_eq!((seen[0].method.as_str(), seen[0].url.as_str(), seen[0].origin.as_str()), ("PUT", "https://nuget-push.invalid/api/v2/package", "https://nuget-push.invalid/"));
    }
    // A registry added by the public service index URL is the public registry (its resources are the three configured hosts).
    let (server3, registry3, _policy3) = start_at(Some("https://nuget-pub.invalid/v3/index.json"), "https://nuget-push.invalid").await;
    let response = reqwest::Client::new().put(server3.url("/nuget/api/v2/package")).header("x-nuget-apikey", "key-123").body("x").send().await.unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(registry3.calls.lock().unwrap()[0].url, "https://nuget-push.invalid/api/v2/package");
    server3.shutdown().await;
    let (server2, registry2, _policy2) = start_at(None, "https://evil.invalid").await;
    let response = reqwest::Client::new().put(server2.url("/nuget/api/v2/package")).header("x-nuget-apikey", "key-123").body("x").send().await.unwrap();
    assert_eq!(response.status(), 404);
    assert!(registry2.calls.lock().unwrap().is_empty());
    server.shutdown().await;
    server2.shutdown().await;
}

/// A body whose declared Content-Length is over the cap is refused with 413 before anything is asked of the registry.
#[tokio::test]
async fn an_oversize_write_is_refused_before_the_registry_is_asked_anything() {
    let (server, registry, _policy) = start("https://nuget-reg.invalid").await;
    let response = reqwest::Client::new().put(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "k").body(vec![0u8; 500]).send().await.unwrap();
    assert_eq!(response.status(), 413);
    assert_eq!(registry.indexes.load(std::sync::atomic::Ordering::SeqCst), 0, "no service index fetch for a body over the cap");
    assert!(registry.calls.lock().unwrap().is_empty());
    server.shutdown().await;
}

/// A standalone firewall has no publish route: a write is refused and reaches nothing.
#[tokio::test]
async fn a_standalone_firewall_has_no_publish_route() {
    let server = TestServer::start().await;
    for (verb, uri) in [("PUT", "/nuget/api/v2/package"), ("DELETE", "/nuget/api/v2/package/demo/1.0.0"), ("POST", "/nuget/api/v2/package/demo/1.0.0"), ("PUT", "/registry/nuget/7/api/v2/package")] {
        for key in [None, Some("key")] {
            let mut request = reqwest::Client::new().request(verb.parse().unwrap(), server.url(uri)).body("x");
            if let Some(key) = key {
                request = request.header("x-nuget-apikey", key);
            }
            let status = request.send().await.unwrap().status().as_u16();
            assert!(matches!(status, 401 | 404 | 405 | 503), "{verb} {uri}: {status}");
        }
    }
    server.shutdown().await;
}

/// F2 (shared spool bound): uploads that keep their body open hold a spool place each; past the places the next upload
/// is refused with 503 at once, whatever key it carries, and nothing reaches the registry. The same bound serves every
/// publish forwarder (src/http/spool.rs).
#[tokio::test]
async fn uploads_past_the_spool_places_are_refused_not_queued() {
    let (server, registry, _policy) = start("https://nuget-reg.invalid").await;
    let url = server.url("/nuget/api/v2/package");
    let mut held = Vec::new();
    for _ in 0..probation::http::limits::SPOOLS {
        let url = url.clone();
        held.push(tokio::spawn(async move {
            let body = reqwest::Body::wrap_stream(futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>());
            let _ = reqwest::Client::new().put(url).header("x-nuget-apikey", "junk").body(body).send().await;
        }));
    }
    for _ in 0..100 {
        if server.app().limits.spool_slot().is_none() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let refused = reqwest::Client::new().put(&url).header("x-nuget-apikey", "junk").body("x").send().await.unwrap();
    assert_eq!(refused.status(), 503, "the ninth upload is refused");
    assert!(registry.calls.lock().unwrap().is_empty(), "nothing was forwarded");
    for task in held {
        task.abort();
    }
    server.shutdown().await;
}

/// F5: only the answers a publish endpoint gives are relayed, as plain text or JSON nobody is asked to sniff: HTML from a
/// registry is served as text, a status that is no publish answer is a 502.
#[tokio::test]
async fn a_write_response_is_relayed_only_as_text_or_json_with_a_known_status() {
    let (server, registry, _policy) = start("https://nuget-reg.invalid").await;
    let client = reqwest::Client::new();
    for (status, content_type, body, expected_status, expected_type) in [
        (201, "text/html; charset=utf-8", "<script>alert(1)</script>", 201, "text/plain; charset=utf-8"),
        (409, "application/json; charset=utf-8", "{\"error\":\"exists\"}", 409, "application/json"),
        (400, "image/svg+xml", "<svg onload=x>", 400, "text/plain; charset=utf-8"),
        (302, "text/plain", "", 502, "application/json"),
        (500, "text/plain", "boom", 502, "application/json"),
    ] {
        *registry.odd.lock().unwrap() = (status, content_type, body);
        let response = client.put(server.url("/nuget/api/v2/package")).header("x-nuget-apikey", "odd").body("x").send().await.unwrap();
        assert_eq!(response.status().as_u16(), expected_status, "{status} {content_type}");
        assert_eq!(response.headers().get("content-type").unwrap().to_str().unwrap(), expected_type, "{status} {content_type}");
        if expected_status != 502 {
            assert_eq!(response.headers().get("x-content-type-options").unwrap(), "nosniff");
        }
    }
    server.shutdown().await;
}

// ---- Recheck-1 R3: the shared spool budget, progressive reservation, idle and total deadlines, empty bodies ----

fn chunks(count: usize, size: usize) -> axum::body::Body {
    let chunk = bytes::Bytes::from(vec![7u8; size]);
    axum::body::Body::from_stream(futures_util::stream::iter((0..count).map(move |_| Ok::<_, std::io::Error>(chunk.clone()))))
}

fn pending() -> axum::body::Body {
    axum::body::Body::from_stream(futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>())
}

fn secs(n: u64) -> std::time::Duration {
    std::time::Duration::from_secs(n)
}

/// A declared length above the whole budget, and a chunked body that outgrows its cap, are `TooLarge` (a 413), never
/// an overloaded 503 that no retry could fix; neither keeps a place or a byte.
#[tokio::test]
async fn a_declared_or_chunked_overflow_is_too_large_and_returns_its_place() {
    use probation::http::spool::{Spooled, spool_with};
    let (server, _registry, _policy) = start("https://nuget-reg.invalid").await;
    let app = server.app();
    let total = app.limits.spool_budget_total();
    let free = app.limits.spool_budget_free();
    assert!(total >= app.config.max_artifact_bytes.get() * 2, "the budget holds the largest accepted upload");
    let declared = spool_with(&app, 0, Some(total + 1), u64::MAX, axum::body::Body::empty(), secs(5), secs(5)).await.unwrap();
    assert!(matches!(declared, Spooled::TooLarge));
    let chunked = spool_with(&app, 0, None, 10, chunks(3, 6), secs(5), secs(5)).await.unwrap();
    assert!(matches!(chunked, Spooled::TooLarge));
    assert_eq!(app.limits.spool_budget_free(), free, "every byte is returned");
    for _ in 0..probation::http::limits::SPOOLS {
        assert!(app.limits.spool_slot().is_some());
    }
    drop(app);
    server.shutdown().await;
}

/// A stalled upload that declared the whole budget holds no bytes and one place: a second upload goes through, and
/// when the first stalls past the idle limit or the total deadline it is refused and its place comes back.
#[tokio::test]
async fn a_stalled_declaration_holds_little_and_times_out_giving_its_place_back() {
    use probation::http::spool::{Spooled, spool_with};
    let (server, _registry, _policy) = start("https://nuget-reg.invalid").await;
    let app = server.app();
    let total = app.limits.spool_budget_total() / 2; // one owner's half of the budget
    let began = std::time::Instant::now();
    let stalled = {
        let app = app.clone();
        tokio::spawn(async move { spool_with(&app, 0, Some(total), total, pending(), secs(1), secs(60)).await.map(|_| ()) })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let second = spool_with(&app, 0, Some(1 << 20), 1 << 20, chunks(1, 1 << 20), secs(5), secs(5)).await.unwrap();
    let Spooled::Body(second) = second else { panic!("the second upload is accepted") };
    assert_eq!(second.length, 1 << 20);
    drop(second);
    assert!(stalled.await.unwrap().is_err(), "the idle limit refuses it");
    assert!(began.elapsed() < secs(10), "after the idle limit, not the total deadline");
    assert_eq!(app.limits.spool_budget_free(), total * 2);
    // total deadline: chunks keep arriving but never finish
    let slow = axum::body::Body::from_stream(futures_util::stream::unfold((), |()| async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Some((Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x")), ()))
    }));
    assert!(spool_with(&app, 0, None, total, slow, secs(5), std::time::Duration::from_millis(400)).await.is_err());
    assert_eq!(app.limits.spool_budget_free(), total * 2, "the deadline returns the bytes");
    for _ in 0..probation::http::limits::SPOOLS {
        assert!(app.limits.spool_slot().is_some());
    }
    drop(app);
    server.shutdown().await;
}

/// An upload that is dropped mid-body (the client went away) frees its place; an empty body takes none.
#[tokio::test]
async fn an_aborted_upload_frees_its_place_and_an_empty_body_takes_none() {
    use probation::http::spool::{Spooled, spool_with};
    let (server, _registry, _policy) = start("https://nuget-reg.invalid").await;
    let app = server.app();
    let held = {
        let app = app.clone();
        tokio::spawn(async move { spool_with(&app, 0, None, 100, pending(), secs(60), secs(60)).await.map(|_| ()) })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let places: Vec<_> = std::iter::from_fn(|| app.limits.spool_slot()).collect();
    assert_eq!(places.len(), probation::http::limits::SPOOLS - 1, "the stalled upload holds one place");
    drop(places);
    held.abort();
    let _ = held.await;
    assert_eq!(std::iter::from_fn(|| app.limits.spool_slot()).collect::<Vec<_>>().len(), probation::http::limits::SPOOLS);
    // with every place taken, an empty body (unlist/relist) still passes
    let all: Vec<_> = std::iter::from_fn(|| app.limits.spool_slot()).collect();
    assert!(!all.is_empty());
    assert!(matches!(spool_with(&app, 0, Some(0), 100, axum::body::Body::empty(), secs(5), secs(5)).await.unwrap(), Spooled::Body(_)));
    drop(all);
    drop(app);
    server.shutdown().await;
}

/// Two large legitimate uploads at once both fit when the budget holds them: neither is turned into a 503.
#[tokio::test]
async fn two_large_uploads_in_parallel_are_not_serialised_into_a_503() {
    use probation::http::spool::{Spooled, spool_with};
    let (server, _registry, _policy) = start("https://nuget-reg.invalid").await;
    let app = server.app();
    let each = app.limits.spool_budget_total() / 2 - (1 << 20);
    let run = |app: Arc<probation::App>, owner: u64| async move {
        let n = (each >> 20) as usize;
        match spool_with(&app, owner, Some(n as u64 * (1 << 20)), u64::MAX, chunks(n, 1 << 20), secs(30), secs(60)).await {
            Ok(Spooled::Body(spool)) => { tokio::time::sleep(std::time::Duration::from_millis(200)).await; spool.length }
            _ => 0,
        }
    };
    let (a, b) = tokio::join!(run(app.clone(), 1), run(app.clone(), 2));
    assert!(a > 0 && b > 0, "both uploads fit: {a} {b}");
    drop(app);
    server.shutdown().await;
}

// ---- Recheck-2 N4: one key's share of the places, and uploads that together exceed the budget go one after the other ----

/// One valid key cannot hold every place: a fifth upload of the same key is refused while another key's still gets one.
#[tokio::test]
async fn one_key_cannot_hold_all_the_spool_places() {
    use probation::http::spool::spool_with;
    let (server, _registry, _policy) = start("https://nuget-reg.invalid").await;
    let app = server.app();
    let held: Vec<_> = (0..probation::http::limits::SPOOLS_PER_OWNER)
        .map(|_| {
            let app = app.clone();
            tokio::spawn(async move { spool_with(&app, 42, None, 100, pending(), secs(60), secs(60)).await.map(|_| ()) })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(matches!(spool_with(&app, 42, None, 100, chunks(1, 1), secs(5), secs(5)).await, Err(probation::http::error::ApiError::Overloaded)), "the same key is out of places");
    assert!(spool_with(&app, 43, None, 100, chunks(1, 1), secs(5), secs(5)).await.is_ok(), "another key still has one");
    for task in held {
        task.abort();
        let _ = task.await;
    }
    assert!(spool_with(&app, 42, None, 100, chunks(1, 1), secs(5), secs(5)).await.is_ok(), "the places came back");
    drop(app);
    server.shutdown().await;
}

/// Uploads that together are more than the budget are not a 503 for the second while places are free: it waits for another to
/// finish and then goes through (each owner holds at most half of the budget).
#[tokio::test]
async fn two_uploads_over_the_budget_together_go_one_after_the_other() {
    use probation::http::spool::{Spooled, spool_with};
    let (server, _registry, _policy) = start("https://nuget-reg.invalid").await;
    let app = server.app();
    let total = app.limits.spool_budget_total();
    let each = ((total * 45 / 100) >> 20) as usize;
    let small = ((total * 20 / 100) >> 20) as usize;
    let third = {
        let app = app.clone();
        tokio::spawn(async move {
            use futures_util::StreamExt;
            let body = futures_util::stream::iter((0..small).map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; 1 << 20])))).chain(futures_util::stream::pending());
            let _ = spool_with(&app, 3, None, u64::MAX, axum::body::Body::from_stream(body), secs(60), secs(60)).await;
        })
    };
    let first = {
        let app = app.clone();
        tokio::spawn(async move {
            let Ok(Spooled::Body(spool)) = spool_with(&app, 1, None, u64::MAX, chunks(each, 1 << 20), secs(30), secs(60)).await else { return 0 };
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            spool.length
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let second = match spool_with(&app, 2, None, u64::MAX, chunks(each, 1 << 20), secs(30), secs(60)).await {
        Ok(Spooled::Body(spool)) => spool.length,
        _ => 0,
    };
    assert!(first.await.unwrap() > 0 && second > 0, "both fit one after the other");
    third.abort();
    drop(app);
    server.shutdown().await;
}
