//! Row 21: `mvn deploy` through the shared service (class W): the `PUT` of each file, checksum, signature and
//! `maven-metadata.xml` and a `DELETE`, forwarded with the caller's own `Authorization` to the registry's own origin (or, for the
//! public registry, the configured deploy URL), never the service key; the `Basic` challenge Maven waits for; the bounds.
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
            Some("Basic denied") => 403,
            Some("Basic odd") => 302,
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
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Maven, target_url: target.map(Into::into),
            trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
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
        origins = origins.with_maven(url::Url::parse(common::maven::REPO).unwrap(), url::Url::parse(deploy).unwrap());
    }
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), registry.clone(), origins).await;
    (server, registry, policy)
}

const TARGET: &str = "https://nexus.invalid/repository/releases/";

#[tokio::test]
async fn a_deploy_is_challenged_then_forwarded_with_the_callers_own_credential_only() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    let files = [
        "/maven/org/demo/lib/1.0/lib-1.0.jar",
        "/maven/org/demo/lib/1.0/lib-1.0.jar.sha1",
        "/maven/org/demo/lib/1.0/lib-1.0.pom",
        "/maven/org/demo/lib/1.0/lib-1.0.jar.asc",
        "/maven/org/demo/lib/maven-metadata.xml",
        "/maven/org/demo/lib/maven-metadata.xml.md5",
        "/maven/org/demo/lib/1.0-SNAPSHOT/maven-metadata.xml",
        "/registry/maven/7/org/demo/lib/1.0/lib-1.0-sources.jar",
    ];
    // Maven sends no credential first: it gets the challenge, before anything is read or asked.
    for uri in files {
        let response = client.put(server.url(uri)).body("x").send().await.unwrap();
        assert_eq!(response.status(), 401, "{uri}");
        assert!(response.headers()["www-authenticate"].to_str().unwrap().starts_with("Basic"), "{uri}");
    }
    assert!(registry.calls.lock().unwrap().is_empty());
    assert_eq!(registry.reads.load(std::sync::atomic::Ordering::SeqCst), 0, "not even a lookup");
    for uri in files {
        let response = client.put(server.url(uri)).header("authorization", "Basic dTpw").header("content-type", "application/octet-stream").body("artifact bytes").send().await.unwrap();
        assert_eq!(response.status(), 201, "{uri}");
    }
    let seen = std::mem::take(&mut *registry.calls.lock().unwrap());
    let urls: Vec<&str> = seen.iter().map(|c| c.url.as_str()).collect();
    assert_eq!(urls, [
        "https://nexus.invalid/repository/releases/org/demo/lib/1.0/lib-1.0.jar",
        "https://nexus.invalid/repository/releases/org/demo/lib/1.0/lib-1.0.jar.sha1",
        "https://nexus.invalid/repository/releases/org/demo/lib/1.0/lib-1.0.pom",
        "https://nexus.invalid/repository/releases/org/demo/lib/1.0/lib-1.0.jar.asc",
        "https://nexus.invalid/repository/releases/org/demo/lib/maven-metadata.xml",
        "https://nexus.invalid/repository/releases/org/demo/lib/maven-metadata.xml.md5",
        "https://nexus.invalid/repository/releases/org/demo/lib/1.0-SNAPSHOT/maven-metadata.xml",
        "https://nexus.invalid/repository/releases/org/demo/lib/1.0/lib-1.0-sources.jar",
    ]);
    assert!(seen.iter().all(|c| c.method == "PUT" && c.authorization.as_deref() == Some("Basic dTpw") && c.body == b"artifact bytes" && c.origin == TARGET), "{seen:?}");
    assert!(seen.iter().all(|c| c.api_key.is_none() && c.authorization.as_deref() != Some("prb_01234567890123456789012345678901")), "the service key never leaves");
    // A clean-up is a DELETE with the same rules.
    let deleted = client.delete(server.url("/maven/org/demo/lib/1.0/lib-1.0.jar")).header("authorization", "Basic dTpw").send().await.unwrap();
    assert_eq!(deleted.status(), 201);
    assert_eq!(registry.calls.lock().unwrap()[0].method, "DELETE");
    server.shutdown().await;
}

#[tokio::test]
async fn the_registrys_refusal_is_the_answer_and_nothing_it_says_is_served_as_a_page() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    let denied = client.put(server.url("/maven/org/demo/lib/1.0/lib-1.0.jar")).header("authorization", "Basic denied").body("x").send().await.unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(denied.headers()["content-type"], "text/plain; charset=utf-8");
    assert_eq!(denied.headers()["x-content-type-options"], "nosniff");
    // An answer a deploy endpoint does not give is a 502, never relayed.
    let odd = client.put(server.url("/maven/org/demo/lib/1.0/lib-1.0.jar")).header("authorization", "Basic odd").body("x").send().await.unwrap();
    assert_eq!(odd.status(), 502);
    assert_eq!(registry.calls.lock().unwrap().len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn paths_that_are_no_layout_path_and_oversize_bodies_reach_nothing() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    for uri in ["/maven/org/demo/lib/1.0/other-1.0.jar", "/maven/lib/1.0/lib-1.0.jar", "/maven/archetype-catalog.xml", "/maven/org/demo/lib/1.0/lib-1.0.jar/..", "/maven/org/demo/lib/1.0/"] {
        let status = client.put(server.url(uri)).header("authorization", "Basic dTpw").body("x").send().await.unwrap().status();
        assert_eq!(status, 404, "{uri}");
    }
    let big = client.put(server.url("/maven/org/demo/lib/1.0/lib-1.0.jar")).header("authorization", "Basic dTpw").body(vec![0u8; 500]).send().await.unwrap();
    assert_eq!(big.status(), 413, "over the cap: refused before the registry is asked anything");
    assert!(registry.calls.lock().unwrap().is_empty());
    for verb in ["POST", "PATCH"] {
        let status = client.request(verb.parse().unwrap(), server.url("/maven/org/demo/lib/1.0/lib-1.0.jar")).header("authorization", "Basic dTpw").body("x").send().await.unwrap().status();
        assert_eq!(status, 405, "{verb}");
    }
    server.shutdown().await;
}

/// The public registry has no deploy endpoint unless the operator names one (Maven Central has none of its own).
#[tokio::test]
async fn the_public_registrys_deploy_url_is_the_configured_one_and_otherwise_there_is_none() {
    let (server, registry, _policy) = start(None, None).await;
    let response = reqwest::Client::new().put(server.url("/maven/org/demo/lib/1.0/lib-1.0.jar")).header("authorization", "Basic dTpw").body("x").send().await.unwrap();
    assert_eq!(response.status(), 404, "no configured deploy URL, no route");
    assert!(registry.calls.lock().unwrap().is_empty());
    server.shutdown().await;
    let (server, registry, _policy) = start(None, Some(common::maven::PUBLISH)).await;
    let response = reqwest::Client::new().put(server.url("/maven/org/demo/lib/1.0/lib-1.0.jar")).header("authorization", "Basic dTpw").body("x").send().await.unwrap();
    assert_eq!(response.status(), 201);
    {
        let seen = registry.calls.lock().unwrap();
        assert_eq!((seen[0].url.as_str(), seen[0].origin.as_str()), ("https://maven-deploy.invalid/repo/org/demo/lib/1.0/lib-1.0.jar", "https://maven-deploy.invalid/repo"));
    }
    server.shutdown().await;
}

/// A standalone firewall has no deploy route: a write is refused and reaches nothing.
#[tokio::test]
async fn a_standalone_firewall_has_no_deploy_route() {
    let server = TestServer::start().await;
    for (verb, uri) in [("PUT", "/maven/org/demo/lib/1.0/lib-1.0.jar"), ("DELETE", "/maven/org/demo/lib/1.0/lib-1.0.jar"), ("PUT", "/registry/maven/7/org/demo/lib/1.0/lib-1.0.jar")] {
        for credential in [None, Some("Basic dTpw")] {
            let mut request = reqwest::Client::new().request(verb.parse().unwrap(), server.url(uri)).body("x");
            if let Some(credential) = credential {
                request = request.header("authorization", credential);
            }
            let status = request.send().await.unwrap().status().as_u16();
            assert!(matches!(status, 401 | 404 | 405 | 503), "{verb} {uri}: {status}");
        }
    }
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
    let url = server.url("/maven/org/demo/lib/1.0/lib-1.0.jar");
    let held: Vec<_> = (0..probation::http::limits::SPOOLS_PER_OWNER).map(|n| hold(&url, "127.0.0.1", format!("Basic junk{n}"), &[])).collect();
    until_held(&server, probation::http::limits::SPOOLS_PER_OWNER).await;
    assert_eq!(put_from(&url, "127.0.0.1", "Basic junk-five", &[]).await, 503, "the address holds its share, with a fresh junk credential too");
    assert_eq!(put_from(&url, "127.0.0.2", "Basic dTpw", &[]).await, 201, "a different address still deploys");
    assert_eq!(registry.calls.lock().unwrap().len(), 1, "only the second address reached the registry");
    held.iter().for_each(|task| task.abort());
    server.shutdown().await;
}

/// One credential presented from many addresses is capped too (the second count), while other credentials are not kept out.
#[tokio::test]
async fn one_credential_from_many_addresses_holds_its_share_only() {
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let url = server.url("/maven/org/demo/lib/1.0/lib-1.0.jar");
    let held: Vec<_> = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"].iter().map(|from| hold(&url, from, "Basic same".into(), &[])).collect();
    until_held(&server, probation::http::limits::SPOOLS_PER_OWNER).await;
    assert_eq!(put_from(&url, "127.0.0.5", "Basic same", &[]).await, 503, "the credential holds its share");
    assert_eq!(put_from(&url, "127.0.0.5", "Basic other", &[]).await, 201, "another credential from a fresh address deploys");
    held.iter().for_each(|task| task.abort());
    server.shutdown().await;
}

/// `X-Forwarded-For` is believed only from a listed proxy: unlisted, a forged header buys no second share; listed, the client it
/// names is the address counted.
#[tokio::test]
async fn a_forwarded_for_header_names_the_client_only_from_a_listed_proxy() {
    const FROM_A: &[(&str, &str)] = &[("x-forwarded-for", "198.51.100.1")];
    const FROM_B: &[(&str, &str)] = &[("x-forwarded-for", "198.51.100.2")];
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let url = server.url("/maven/org/demo/lib/1.0/lib-1.0.jar");
    let held: Vec<_> = (0..probation::http::limits::SPOOLS_PER_OWNER).map(|n| hold(&url, "127.0.0.1", format!("Basic junk{n}"), FROM_A)).collect();
    until_held(&server, probation::http::limits::SPOOLS_PER_OWNER).await;
    assert_eq!(put_from(&url, "127.0.0.1", "Basic dTpw", FROM_B).await, 503, "a forged header from an unlisted peer is ignored: the peer's share is held");
    held.iter().for_each(|task| task.abort());
    server.shutdown().await;

    let (server, _registry, _policy) = start_behind(Some(TARGET), None, vec![probation::config::Cidr::parse("127.0.0.0/8").unwrap()]).await;
    let url = server.url("/maven/org/demo/lib/1.0/lib-1.0.jar");
    let held: Vec<_> = (0..probation::http::limits::SPOOLS_PER_OWNER).map(|n| hold(&url, "127.0.0.1", format!("Basic junk{n}"), FROM_A)).collect();
    until_held(&server, probation::http::limits::SPOOLS_PER_OWNER).await;
    assert_eq!(put_from(&url, "127.0.0.1", "Basic fresh", FROM_A).await, 503, "the named client holds its share");
    assert_eq!(put_from(&url, "127.0.0.1", "Basic dTpw", FROM_B).await, 201, "another client behind the same listed proxy still deploys");
    held.iter().for_each(|task| task.abort());
    server.shutdown().await;
}

/// S21-6: a clean-up of a whole version or artifact directory is forwarded to the registry's own directory URL.
#[tokio::test]
async fn a_delete_of_a_directory_is_forwarded() {
    let (server, registry, _policy) = start(Some(TARGET), None).await;
    let client = reqwest::Client::new();
    for uri in ["/maven/org/demo/lib/1.0/", "/maven/org/demo/lib/", "/maven/org/demo/lib/1.0"] {
        let response = client.delete(server.url(uri)).header("authorization", "Basic dTpw").send().await.unwrap();
        assert_eq!(response.status(), 201, "{uri}");
    }
    {
        let seen = registry.calls.lock().unwrap();
        let urls: Vec<&str> = seen.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(urls, ["https://nexus.invalid/repository/releases/org/demo/lib/1.0/", "https://nexus.invalid/repository/releases/org/demo/lib/", "https://nexus.invalid/repository/releases/org/demo/lib/1.0/"], "{seen:?}");
    }
    // A PUT to a directory, or a directory name that is no layout name, is still a 404.
    assert_eq!(client.put(server.url("/maven/org/demo/lib/1.0/")).header("authorization", "Basic dTpw").body("x").send().await.unwrap().status(), 404);
    assert_eq!(client.delete(server.url("/maven/org/de.mo/lib/1.0/")).header("authorization", "Basic dTpw").send().await.unwrap().status(), 404);
    server.shutdown().await;
}

#[tokio::test]
async fn a_trickle_below_the_minimum_rate_is_cut_after_the_grace_period() {
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let app = server.app();
    let slow = futures_util::stream::unfold(0u32, |n| async move {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        (n < 40).then(|| (Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x")), n + 1))
    });
    let result = probation::http::spool::spool_paced(&app, 1, None, 1 << 20, axum::body::Body::from_stream(slow), std::time::Duration::from_secs(5), std::time::Duration::from_secs(30), std::time::Duration::from_millis(400), std::time::Duration::from_secs(5)).await;
    assert!(matches!(result, Err(probation::http::error::ApiError::InvalidInput(_))), "one byte every 150 ms is below 1 KiB/s");
    let fast = futures_util::stream::iter((0..5).map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; 4096]))));
    let ok = probation::http::spool::spool_paced(&app, 2, None, 1 << 20, axum::body::Body::from_stream(fast), std::time::Duration::from_secs(5), std::time::Duration::from_secs(30), std::time::Duration::from_millis(0), std::time::Duration::from_secs(5)).await;
    assert!(ok.is_ok(), "a real upload is not cut");
    drop(app);
    server.shutdown().await;
}

// ------------------------------------------------------------------ recheck-1 round

/// R5: the first chunk may be slow to start; a stall in the middle of a body is cut by the shorter limit. R1: the body's total
/// deadline follows its declared length.
#[tokio::test]
async fn a_slow_start_is_allowed_a_mid_body_stall_is_not_and_the_deadline_follows_the_declared_length() {
    use probation::http::spool::{body_deadline, spool_paced, BODY_DEADLINE, UNDECLARED_DEADLINE};
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let app = server.app();
    let ms = std::time::Duration::from_millis;
    let late = futures_util::stream::once(async move { tokio::time::sleep(ms(400)).await; Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x")) });
    let started = spool_paced(&app, 1, None, 100, axum::body::Body::from_stream(late), ms(100), ms(5000), ms(10_000), ms(3000)).await;
    assert!(started.is_ok(), "the first chunk gets its own, longer wait");
    let stalled = futures_util::stream::unfold(0, |n| async move {
        if n == 0 { Some((Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x")), 1)) } else { tokio::time::sleep(std::time::Duration::from_millis(600)).await; Some((Ok(bytes::Bytes::from_static(b"y")), n + 1)) }
    });
    let cut = spool_paced(&app, 2, None, 100, axum::body::Body::from_stream(stalled), ms(100), ms(5000), ms(10_000), ms(3000)).await;
    assert!(matches!(cut, Err(probation::http::error::ApiError::InvalidInput(_))), "a stall after the first chunk is cut at the mid-body limit");
    drop(app);
    assert_eq!(body_deadline(None), UNDECLARED_DEADLINE);
    assert!(body_deadline(Some(1 << 20)) < std::time::Duration::from_secs(5 * 60), "a 1 MiB body may not hold a place for minutes");
    assert!(body_deadline(Some(1 << 20)) > std::time::Duration::from_secs(60), "but is given time to arrive at the floor rate");
    assert_eq!(body_deadline(Some(1 << 30)), BODY_DEADLINE, "a large declared upload keeps the whole deadline");
    server.shutdown().await;
}

/// R1: every publish forwarder counts its places the same way: through `spool::owner_of`, never by the service key alone.
#[test]
fn all_six_forwarders_count_their_spool_places_per_real_identity_and_credential() {
    for file in ["registry_action", "pypi_routes", "rubygems_routes", "cargo_routes", "nuget_routes", "maven_routes"] {
        let text = std::fs::read_to_string(format!("{}/src/http/{file}.rs", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let compact: String = text.split_whitespace().collect();
        assert!(compact.contains("spool::owner_of(&app,&principal,&") || compact.contains("spool::owner_of(app,&principal,&") || compact.contains("spool::owner_of(app,principal,&"), "{file} passes the real identity (account or address) and credential to the spool");
        assert!(!compact.contains("key_id.0,&headers)") && !compact.contains("key_id.0,&request.headers)"), "{file} must not count by the key id");
    }
}

// ------------------------------------------------------------------ recheck-2 round

/// N3: the rate clock starts at the FIRST chunk: a small first chunk that arrives after the grace period (inside the first-chunk
/// wait) is accepted, and a body that bursts early may not then trickle on that credit (the rate is also held over a window).
#[tokio::test]
async fn the_rate_clock_starts_at_the_first_chunk_and_a_burst_does_not_license_a_trickle() {
    use probation::http::spool::spool_paced;
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let app = server.app();
    let ms = std::time::Duration::from_millis;
    let late = futures_util::stream::once(async move { tokio::time::sleep(ms(2500)).await; Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x")) });
    let accepted = spool_paced(&app, 1, None, 100, axum::body::Body::from_stream(late), ms(100), ms(30_000), ms(1000), ms(5000)).await;
    assert!(accepted.is_ok(), "a first chunk at 2.5 s with a 1 s grace and a 5 s first-chunk wait is not 'too slow'");
    // A burst of 1 MiB, then one byte every 300 ms for 12 s: the average since the start stays far above the floor for a minute,
    // but the window sees a trickle.
    let burst_then_trickle = futures_util::stream::unfold(0u32, |n| async move {
        if n == 0 {
            return Some((Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; 1 << 20])), 1));
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        (n < 40).then(|| (Ok(bytes::Bytes::from_static(b"x")), n + 1))
    });
    let started = std::time::Instant::now();
    let cut = spool_paced(&app, 2, None, 4 << 20, axum::body::Body::from_stream(burst_then_trickle), ms(5000), ms(30_000), ms(1000), ms(5000)).await;
    assert!(matches!(cut, Err(probation::http::error::ApiError::InvalidInput(_))), "the trickle is cut");
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "the seat is held a window or two, not the body deadline");
    drop(app);
    server.shutdown().await;
}

/// N2: one owner holds at most half of the byte budget, however it bursts; another owner still reserves, at once.
#[tokio::test]
async fn one_owner_never_holds_more_than_half_of_the_spool_budget() {
    use futures_util::StreamExt;
    use probation::http::spool::{Spooled, spool_with};
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let app = server.app();
    let secs = std::time::Duration::from_secs;
    let half = app.limits.spool_budget_total() / 2;
    let mib = 1usize << 20;
    let chunks = (half as usize / mib) as u32;
    let burst = futures_util::stream::iter((0..chunks).map(move |_| Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; mib])))).chain(futures_util::stream::pending());
    let holder = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { spool_with(&app, 1, None, u64::MAX, axum::body::Body::from_stream(burst), secs(60), secs(60)).await.map(|_| ()) })
    };
    for _ in 0..200 {
        if app.limits.spool_budget_free() <= half {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(!app.limits.spool_reservation(1).grow(1), "the first owner holds its half");
    let other = spool_with(&app, 2, Some(1 << 20), 1 << 20, axum::body::Body::from(vec![0u8; mib]), secs(5), secs(5)).await.unwrap();
    assert!(matches!(other, Spooled::Body(_)), "another owner still reserves, at once");
    holder.abort();
    drop(other);
    drop(app);
    server.shutdown().await;
}

// ------------------------------------------------------------------ recheck-3 round

/// R3-4: one owner's two big uploads that together exceed its half take turns instead of both waiting for each other.
#[tokio::test]
async fn one_owners_two_big_uploads_take_turns_and_both_complete() {
    use probation::http::spool::{Spooled, spool_with};
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let app = server.app();
    let secs = std::time::Duration::from_secs;
    let mib = 1usize << 20;
    let body = move || axum::body::Body::from_stream(futures_util::stream::unfold(0usize, move |n| async move {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        (n < 20).then(|| (Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; mib])), n + 1))
    }));
    let one = |app: Arc<probation::App>, body: axum::body::Body| async move {
        match spool_with(&app, 1, Some(20 << 20), u64::MAX, body, secs(5), secs(60)).await {
            Ok(Spooled::Body(spool)) => Some(spool.length),
            _ => None,
        }
    };
    let started = std::time::Instant::now();
    let (a, b) = tokio::join!(one(app.clone(), body()), one(app.clone(), body()));
    assert_eq!((a, b), (Some(20 << 20), Some(20 << 20)), "both 20 MiB uploads of one owner complete");
    assert!(started.elapsed() < secs(20), "they queued, they did not wait out the 30 s budget wait");
    drop(app);
    server.shutdown().await;
}

/// R3-5: the time an upload waits for its own bytes (a contended budget) is not counted against the client's rate floor.
#[tokio::test]
async fn our_own_wait_for_budget_is_not_the_clients_slowness() {
    use probation::http::spool::spool_paced;
    let (server, _registry, _policy) = start(Some(TARGET), None).await;
    let app = server.app();
    let ms = std::time::Duration::from_millis;
    let half = app.limits.spool_budget_total() / 2;
    let (mut two, mut three) = (app.limits.spool_reservation(2), app.limits.spool_reservation(3));
    assert!(two.grow(half) && three.grow(half), "the budget is taken");
    let release = tokio::spawn(async move {
        tokio::time::sleep(ms(2000)).await;
        drop((two, three));
    });
    let small = futures_util::stream::iter((0..3).map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; 100]))));
    let result = spool_paced(&app, 1, None, 1 << 20, axum::body::Body::from_stream(small), ms(5000), ms(30_000), ms(1000), ms(5000)).await;
    assert!(result.is_ok(), "100-byte chunks that waited 2 s for the budget are not 'too slow'");
    release.await.unwrap();
    drop(app);
    server.shutdown().await;
}
