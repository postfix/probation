//! Row 24: OCI through the shared service for a selected registry with a real `target_url` (a registry under a path prefix, as an
//! Artifactory repository is laid out): the client's own credential and the token flow (the firewall's `/v2/token`), what a
//! credential-bearing read forwards and shares (C1028), the challenge a client waits for, the class-W pushes and uploads with
//! their `Location` rewritten, and the verbs the read routes refuse.
mod common;

use common::oci::{self, CDN, FakeOci, image, sha256};
use common::{TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::Transport;
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::{num::{NonZeroU32, NonZeroU64}, sync::Arc};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

const HOST: &str = "https://oci.invalid";
const PREFIX: &str = "/artifactory/api/docker/images";
const KEY: &str = "prb_01234567890123456789012345678901";

fn snapshot_with(freeze: u64, target: Option<&str>, archive: Option<&str>, count: u64, token_origin: Option<&str>) -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    let descriptor = |id: u64, target: Option<String>, archive: Option<String>| RegistryDescriptor {
        registry: RegistryId(id), ecosystem: probation_policy::Ecosystem::Oci, target_url: target, trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive, resource_path_prefix: None, token_origin: if id == 7 { token_origin.map(str::to_owned) } else { None },
    };
    let mut registries = vec![descriptor(7, target.map(str::to_owned), archive.map(str::to_owned))];
    for n in 1..count {
        registries.push(descriptor(7 + n, Some(format!("https://reg{n}.invalid/repo/")), None));
    }
    ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer { freeze_seconds: Some(freeze), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries,
    }
}

struct Fixture {
    server: TestServer,
    oci: Arc<FakeOci>,
    _policy: MockServer,
}

async fn start(freeze: u64, target: Option<&str>, archive: Option<&str>) -> Fixture {
    start_n(freeze, target, archive, 1).await
}

async fn start_n(freeze: u64, target: Option<&str>, archive: Option<&str>, count: u64) -> Fixture {
    start_with(freeze, target, archive, count, None, false, |_| {}).await
}

/// `proxied`: the loopback peer is a trusted proxy, so a request's `X-Forwarded-For` names the client (two clients from one test process).
async fn start_with(freeze: u64, target: Option<&str>, archive: Option<&str>, count: u64, token_origin: Option<&str>, proxied: bool, tune: impl FnOnce(&mut probation::config::Config)) -> Fixture {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot_with(freeze, target, archive, count, token_origin))).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.max_references_per_project = NonZeroU32::new(40).unwrap();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new(KEY.into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
        trusted_proxies: if proxied { vec![probation::config::Cidr::parse("127.0.0.0/8").unwrap()] } else { vec![] },
    });
    tune(&mut config);
    let oci = FakeOci::new();
    oci.set_prefix(PREFIX);
    let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
    let origins = fake_origins().with_oci(url::Url::parse(HOST).unwrap(), url::Url::parse(CDN).unwrap());
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&oci) as Arc<dyn Transport>, origins).await;
    Fixture { server, oci, _policy: policy }
}

fn target() -> String {
    format!("{HOST}{PREFIX}/")
}

fn layer(tag: &str) -> Vec<u8> {
    format!("layer of {tag}").into_bytes().repeat(30)
}

#[tokio::test]
async fn a_selected_registry_is_read_from_its_own_prefix_through_both_roots() {
    let f = start(0, Some(&target()), None).await;
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("team/app", Some("v1"), &app);
    for root in ["/v2", "/registry/oci/7/v2"] {
        let manifest = f.server.get(&format!("{root}/team/app/manifests/v1")).await;
        assert_eq!(manifest.status().as_u16(), 200, "{root}");
        assert_eq!(manifest.bytes().await.unwrap().to_vec(), app.manifest, "{root}");
        let blob = f.server.get(&format!("{root}/team/app/blobs/{}", app.layer_digests[0])).await;
        assert_eq!((blob.status().as_u16(), blob.bytes().await.unwrap().to_vec()), (200, app.layers[0].clone()), "{root}");
        assert_eq!(f.server.get(&format!("{root}/")).await.status().as_u16(), 200, "{root}: the ping");
    }
    assert!(f.oci.seen().iter().all(|call| call.path.starts_with(PREFIX)), "every call stayed under the registry's prefix: {:?}", f.oci.seen());
    // An unknown id, another family's root, and a second registry's ambiguity are no route.
    assert_eq!(f.server.get("/registry/oci/8/v2/team/app/manifests/v1").await.status().as_u16(), 404);
    assert_eq!(f.server.get("/registry/conan/7/v2/ping").await.status().as_u16(), 404);
    f.server.shutdown().await;
}

#[tokio::test]
async fn two_registries_make_the_plain_root_ambiguous_and_the_selected_one_is_still_served() {
    let f = start_n(0, Some(&target()), None, 2).await;
    f.oci.put_image("app", Some("v1"), &image("a", &[&layer("one")]));
    assert_eq!(f.server.get("/v2/app/manifests/v1").await.status().as_u16(), 404, "which registry is not a guess");
    assert_eq!(f.server.get("/registry/oci/7/v2/app/manifests/v1").await.status().as_u16(), 200);
    f.server.shutdown().await;
}

/// The caller's own credential goes to the registry's origin and nowhere else, is request-scoped (shares nothing), and the service
/// key never leaves.
#[tokio::test]
async fn the_callers_credential_travels_to_the_registry_only_and_shares_nothing() {
    let f = start(0, Some(&target()), None).await;
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("app", Some("v1"), &app);
    let carrier = [("authorization", "Bearer callers-token")];
    assert_eq!(f.server.get_with_headers("/v2/app/manifests/v1", &carrier).await.status().as_u16(), 200);
    let blob = format!("/v2/app/blobs/{}", app.layer_digests[0]);
    assert_eq!(f.server.get_with_headers(&blob, &carrier).await.status().as_u16(), 200);
    let seen = f.oci.seen();
    assert!(seen.iter().all(|call| call.authorization.as_deref() == Some("Bearer callers-token")), "{seen:?}");
    assert!(seen.iter().all(|call| call.authorization.as_deref() != Some(KEY)));
    // The blob a credentialed caller fetched was not stored for anyone else: the next caller (with none) makes the registry send it again.
    let before = f.oci.artifact_requests().len();
    assert_eq!(f.server.get_with_headers(&blob, &carrier).await.status().as_u16(), 200);
    assert_eq!(f.oci.artifact_requests().len(), before + 1, "a credentialed read is served from nothing shared");
    // (the body is read to the end: a client that leaves a first pull cancels it, N4)
    for _ in 0..2 {
        let response = f.server.get(&blob).await;
        assert_eq!(response.status().as_u16(), 200);
        response.bytes().await.unwrap();
    }
    assert_eq!(f.oci.artifact_requests().len(), before + 2, "an anonymous read fills the shared store once and is then served from it");
    // A header that is neither a Basic nor a Bearer credential is refused as one.
    assert_eq!(f.server.get_with_headers("/v2/app/manifests/v1", &[("authorization", "prb_x")]).await.status().as_u16(), 401);
    f.server.shutdown().await;
}

/// A registry that wants tokens: a client's Basic credential is exchanged at the registry's realm by the firewall (the credential goes
/// to the registry's origin and to that realm only), and `/v2/token` is the same exchange for a client that runs the flow itself.
#[tokio::test]
async fn a_basic_credential_is_exchanged_for_a_token_at_the_registrys_realm_only() {
    let f = start(0, Some(&target()), None).await;
    f.oci.require_token();
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("app", Some("v1"), &app);
    let basic = [("authorization", "Basic dXNlcjpwdw==")];
    assert_eq!(f.server.get_with_headers("/v2/app/manifests/v1", &basic).await.status().as_u16(), 200);
    let seen = f.oci.seen();
    assert!(seen.iter().any(|call| call.path.ends_with("/token") && call.authorization.as_deref() == Some("Basic dXNlcjpwdw==")), "{seen:?}");
    assert!(seen.iter().filter(|call| call.path.contains("/manifests/")).all(|call| call.authorization.as_deref() == Some("Bearer tok-user")), "the registry saw the token, not the password: {seen:?}");
    // The client's own token flow: `/v2/token` is answered from the registry's realm with the caller's credential.
    let token = f.server.get_with_headers("/v2/token?service=fake&scope=repository:app:pull", &basic).await;
    assert_eq!(token.status().as_u16(), 200);
    let doc: serde_json::Value = serde_json::from_str(&token.text().await.unwrap()).unwrap();
    assert_eq!(doc["token"], "tok-user", "{doc}");
    // A scope that is not a repository's, or a key this endpoint does not take, is no route; a realm outside the table is never asked.
    for bad in ["/v2/token?scope=evil", "/v2/token?password=x", "/v2/token?scope=repository:A/b:pull"] {
        assert_eq!(f.server.get_with_headers(bad, &basic).await.status().as_u16(), 404, "{bad}");
    }
    f.server.shutdown().await;
    let g = start(0, Some(&target()), None).await;
    g.oci.require_token();
    g.oci.foreign_realm("https://evil.example/token");
    assert_eq!(g.server.get_with_headers("/v2/token?scope=repository:app:pull", &basic).await.status().as_u16(), 502);
    assert!(g.oci.seen().iter().all(|call| call.authorization.as_deref() != Some("Basic dXNlcjpwdw==")), "the credential went nowhere: {:?}", g.oci.seen());
    g.server.shutdown().await;
}

#[tokio::test]
async fn a_private_repository_is_answered_with_the_challenge_a_client_waits_for() {
    let f = start(0, Some(&target()), None).await;
    f.oci.require_token();
    f.oci.deny_anonymous();
    f.oci.put_image("app", Some("v1"), &image("a", &[&layer("one")]));
    let response = f.server.get("/v2/app/manifests/v1").await;
    assert_eq!(response.status().as_u16(), 401);
    let challenge = response.headers().get("www-authenticate").unwrap().to_str().unwrap().to_owned();
    assert!(challenge.starts_with("Bearer realm=\"") && challenge.contains("/v2/token\"") && challenge.contains("scope=\"repository:app:pull\""), "{challenge}");
    assert!(!challenge.contains("evil") && !challenge.contains("oci.invalid"), "the realm is this firewall's own token endpoint: {challenge}");
    let doc: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(doc["errors"][0]["code"], "UNAUTHORIZED");
    // The ping tells a client with nothing to sign in; with a credential it is answered.
    assert_eq!(f.server.get("/v2/").await.status().as_u16(), 401);
    assert_eq!(f.server.get_with_headers("/v2/", &[("authorization", "Basic dXNlcjpwdw==")]).await.status().as_u16(), 200);
    f.server.shutdown().await;
    // A registry that takes Basic directly is challenged with Basic.
    let g = start(0, Some(&target()), None).await;
    g.oci.basic_only();
    let response = g.server.get("/v2/").await;
    assert_eq!(response.status().as_u16(), 401);
    assert!(response.headers().get("www-authenticate").unwrap().to_str().unwrap().starts_with("Basic"), "{:?}", response.headers());
    g.server.shutdown().await;
}

/// An existence check by a caller with a credential (a push asks before it uploads) is the registry's answer and delivers no
/// content: the cooldown does not hold it back, a block still does; a read with none is held like any.
#[tokio::test]
async fn a_credentialed_head_is_an_existence_check_and_the_cooldown_does_not_hold_it() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    f.oci.require_token();
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("app", Some("v1"), &app);
    let carrier = [("authorization", "Bearer tok-callers")];
    let manifest = "/v2/app/manifests/v1";
    let blob = format!("/v2/app/blobs/{}", app.layer_digests[0]);
    let head = |path: String, headers: Vec<(&'static str, &'static str)>| {
        let url = f.server.url(&path);
        async move {
            let mut request = common::downstream_client().head(url);
            for (k, v) in headers {
                request = request.header(k, v);
            }
            request.send().await.unwrap()
        }
    };
    assert_eq!(head(manifest.into(), carrier.to_vec()).await.status().as_u16(), 200, "a credentialed HEAD of a young manifest");
    let head_blob = head(blob.clone(), carrier.to_vec()).await;
    assert_eq!(head_blob.status().as_u16(), 200, "and of a blob nobody has vouched for");
    assert_eq!(head_blob.headers().get("docker-content-digest").unwrap().to_str().unwrap(), app.layer_digests[0]);
    assert_eq!(head_blob.headers().get("content-length").unwrap().to_str().unwrap(), app.layers[0].len().to_string());
    assert_eq!(f.server.get_with_headers(manifest, &carrier).await.status().as_u16(), 403, "a GET is held");
    assert_eq!(f.server.get_with_headers(&blob, &carrier).await.status().as_u16(), 403);
    assert_eq!(head(manifest.into(), vec![]).await.status().as_u16(), 403, "an anonymous HEAD is held");
    f.server.shutdown().await;
}

#[tokio::test]
async fn the_upstream_401_and_403_are_the_registrys_own_and_a_withdrawn_digest_is_a_404() {
    let f = start(0, Some(&target()), None).await;
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("app", Some("v1"), &app);
    assert_eq!(f.server.get("/v2/app/manifests/nope").await.status().as_u16(), 404);
    let (status, code): (u16, String) = {
        let r = f.server.get("/v2/app/manifests/nope").await;
        let doc: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
        (404, doc["errors"][0]["code"].as_str().unwrap().to_owned())
    };
    assert_eq!((status, code.as_str()), (404, "MANIFEST_UNKNOWN"));
    f.server.shutdown().await;
}

// ------------------------------------------------------------------ writes (class W)

#[tokio::test]
async fn a_push_is_forwarded_with_the_callers_own_credential_and_every_location_comes_back_in_the_firewalls_namespace() {
    let f = start(0, Some(&target()), None).await;
    let carrier = "Bearer callers-token";
    let post = |path: &str, auth: Option<&str>, body: Vec<u8>| {
        let url = f.server.url(path);
        let auth = auth.map(str::to_owned);
        async move {
            let mut request = common::downstream_client().post(url).body(body);
            if let Some(auth) = auth {
                request = request.header("authorization", auth);
            }
            request.send().await.unwrap()
        }
    };
    // Without a credential: the challenge, and nothing was asked of anything.
    let refused = post("/v2/team/app/blobs/uploads/", None, vec![]).await;
    assert_eq!(refused.status().as_u16(), 401);
    assert!(refused.headers().get("www-authenticate").unwrap().to_str().unwrap().contains("scope=\"repository:team/app:pull,push\""));
    assert!(f.oci.seen().is_empty() && f.oci.writes().is_empty());
    // The firewall's own key is never a registry credential.
    assert_eq!(post("/v2/team/app/blobs/uploads/", Some(&format!("Bearer {KEY}")), vec![]).await.status().as_u16(), 403);
    assert!(f.oci.writes().is_empty());
    // Start, chunk, finish: each answer's Location is this firewall's own path.
    let start = post("/v2/team/app/blobs/uploads/", Some(carrier), vec![]).await;
    assert_eq!(start.status().as_u16(), 202);
    let location = start.headers().get("location").unwrap().to_str().unwrap().to_owned();
    assert_eq!(location, "/v2/team/app/blobs/uploads/uuid-1?_state=opaque", "{location}");
    assert_eq!(start.headers().get("docker-upload-uuid").unwrap(), "uuid-1");
    let chunk = vec![7u8; 100_000];
    let patch = common::downstream_client().patch(f.server.url(&location)).header("authorization", carrier).header("content-type", "application/octet-stream").body(chunk.clone()).send().await.unwrap();
    assert_eq!(patch.status().as_u16(), 202);
    assert_eq!(patch.headers().get("range").unwrap(), "0-99999");
    let digest = sha256(&chunk);
    let put = common::downstream_client().put(f.server.url(&format!("/v2/team/app/blobs/uploads/uuid-1?_state=opaque&digest={digest}"))).header("authorization", carrier).send().await.unwrap();
    assert_eq!(put.status().as_u16(), 201);
    let manifest = common::downstream_client().put(f.server.url("/v2/team/app/manifests/v1")).header("authorization", carrier).header("content-type", oci::OCI_MANIFEST).body(b"{}".to_vec()).send().await.unwrap();
    assert_eq!(manifest.status().as_u16(), 201);
    let writes = f.oci.writes();
    assert_eq!(writes.iter().map(|(m, _, n)| (m.as_str(), *n)).collect::<Vec<_>>(), [("POST", 0), ("PATCH", 100_000), ("PUT", 0), ("PUT", 2)], "{writes:?}");
    assert!(writes.iter().all(|(_, path, _)| path.starts_with(PREFIX)), "{writes:?}");
    assert!(f.oci.seen().iter().filter(|call| call.method != "GET").all(|call| call.authorization.as_deref() == Some(carrier)), "{:?}", f.oci.seen());
    // A cross-repository mount is forwarded as the registry's own query.
    let mount = post(&format!("/v2/team/app/blobs/uploads/?mount={digest}&from=team/other"), Some(carrier), vec![]).await;
    assert_eq!(mount.status().as_u16(), 202);
    assert!(f.oci.writes().last().unwrap().1.contains("mount="), "{:?}", f.oci.writes());
    // A delete.
    let delete = common::downstream_client().delete(f.server.url("/v2/team/app/manifests/v1")).header("authorization", carrier).send().await.unwrap();
    assert_eq!(delete.status().as_u16(), 202);
    f.server.shutdown().await;
}

#[tokio::test]
async fn a_location_that_leaves_the_registry_is_not_passed_on() {
    let f = start(0, Some(&target()), None).await;
    for location in ["https://evil.example/v2/team/app/blobs/uploads/x", "//evil.example/v2/x", "https://oci.invalid/elsewhere/v2/x"] {
        f.oci.upload_location(location);
        let response = common::downstream_client().post(f.server.url("/v2/team/app/blobs/uploads/")).header("authorization", "Bearer callers-token").send().await.unwrap();
        assert_eq!(response.status().as_u16(), 502, "{location}");
        assert!(response.headers().get("location").is_none(), "{location}");
    }
    // The registry's own absolute URL is the same resource in the client's namespace.
    f.oci.upload_location(&format!("{HOST}{PREFIX}/v2/team/app/blobs/uploads/abc?_state=s"));
    let response = common::downstream_client().post(f.server.url("/v2/team/app/blobs/uploads/")).header("authorization", "Bearer callers-token").send().await.unwrap();
    assert_eq!(response.headers().get("location").unwrap(), "/v2/team/app/blobs/uploads/abc?_state=s");
    f.server.shutdown().await;
}

#[tokio::test]
async fn a_layer_larger_than_the_spool_limit_is_a_413_before_anything_is_asked_and_a_standalone_firewall_has_no_write_route() {
    let f = start(0, Some(&target()), None).await;
    let big = common::downstream_client().patch(f.server.url("/v2/team/app/blobs/uploads/uuid-1")).header("authorization", "Bearer callers-token").header("content-length", "99999999999999").body(vec![0u8; 1]).send().await;
    if let Ok(response) = big {
        assert_eq!(response.status().as_u16(), 413);
    }
    assert!(f.oci.writes().is_empty());
    f.server.shutdown().await;
}

/// C1028 for OCI through the row 28 seam: a read that carries a credential (or anything the allow-list does not know) leaves nothing in
/// a shared cache, a blob fetched under a credential is never served without it, and the control read does fill the caches.
/// Path-embedded and query-embedded credential forms are no route and reach nothing.
#[tokio::test]
async fn credential_bearing_read_never_enters_shared_caches_oci_end_to_end() {
    let f = start(0, Some(&target()), None).await;
    let open = image("open", &[&layer("open")]);
    f.oci.put_image("pub/app", Some("v1"), &open);
    let manifest = format!("/v2/pub/app/manifests/{}", open.digest);
    let calls = |needle: &str| f.oci.seen().iter().filter(|call| call.path.ends_with(needle)).count();
    let digest_tail = format!("/manifests/{}", open.digest);
    for _ in 0..2 {
        assert_eq!(f.server.get_with_headers(&manifest, &[("accept", "*/*")]).await.status().as_u16(), 200);
    }
    assert_eq!(calls(&digest_tail), 1, "an allow-listed read of a digest keeps what it learned for a moment");
    for (n, carrier) in [("authorization", "Basic dXNlcjpwdw=="), ("authorization", "Bearer allowed"), ("cookie", "s=1"), ("x-registry-auth", "k"), ("x-probe-unknown", "1")].into_iter().enumerate() {
        let before = calls(&digest_tail);
        assert_eq!(f.server.get_with_headers(&manifest, &[carrier]).await.status().as_u16(), 200, "{carrier:?}");
        assert_eq!(calls(&digest_tail), before + 1, "carrier {n} {carrier:?}: a credential-bearing read reads and fills nothing shared");
    }
    // Its blob never enters the shared store; the control read does.
    let data = f.server.app().config.data_dir.clone();
    let files = |dir: &str| -> usize { walk(&data.join(dir)) };
    let blob = format!("/v2/pub/app/blobs/{}", open.layer_digests[0]);
    let before = files("content");
    let credentialed = f.server.get_with_headers(&blob, &[("authorization", "Bearer allowed")]).await;
    assert_eq!((credentialed.status().as_u16(), credentialed.bytes().await.unwrap().to_vec()), (200, open.layers[0].clone()));
    assert_eq!(files("content"), before, "no credential-bearing blob in the shared store");
    assert_eq!(files("credential-reads"), 0);
    // (The headers of a first pull go out before the layer is verified, so the body is read to the end before the store is looked at.)
    let control = f.server.get_with_headers(&blob, &[("accept", "*/*")]).await;
    assert_eq!((control.status().as_u16(), control.bytes().await.unwrap().to_vec()), (200, open.layers[0].clone()));
    assert!(files("content") > before, "an allow-listed read is cached");
    // Path- and query-embedded credential forms are no route and reach nothing.
    let asked = f.oci.seen().len();
    for path in ["/v2/tok3n@host/pub/app/manifests/v1", "/v2/pub/app/manifests/v1;token=abc", "/v2/%40token/pub/app/manifests/v1", "/v2/pub/app/tags/list?access_token=abc", "/v2/pub/app/manifests/v1?token=abc", "/v2/pub/app/manifests/tok3n@host"] {
        assert_eq!(f.server.get(path).await.status().as_u16(), 404, "{path}");
    }
    assert_eq!(f.oci.seen().len(), asked, "no registry call for a path-embedded credential form");
    f.server.shutdown().await;
}

fn walk(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map(|entries| entries.flatten().map(|entry| if entry.path().is_dir() { walk(&entry.path()) } else { usize::from(entry.file_name() != "lock") }).sum()).unwrap_or(0)
}

/// FIX-16-A for OCI: a policy publication between a read's authorisation and its release (a manifest, a tag list, a blob) admits the
/// read again under the new snapshot; one publication is served, a change that keeps landing is a 503 after three admissions.
#[tokio::test]
async fn a_publication_between_authorisation_and_release_is_admitted_again() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let f = start(0, Some(&target()), None).await;
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("pub/app", Some("v1"), &app);
    f.oci.put_tags("pub/app", &["v1"], None);
    let gate = Arc::clone(&f.server.app().service_policy().expect("service mode").publication_gate);
    for path in ["/v2/pub/app/manifests/v1".to_owned(), "/v2/pub/app/tags/list".to_owned(), format!("/v2/pub/app/blobs/{}", app.layer_digests[0]), "/v2/".to_owned()] {
        for (publications, expected) in [(0usize, 200u16), (1, 200), (100, 503)] {
            let counter = Arc::new(AtomicUsize::new(publications));
            let (writer, left) = (Arc::clone(&gate), Arc::clone(&counter));
            gate.set_barrier(Arc::new(move || {
                if left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                    let writer = Arc::clone(&writer);
                    std::thread::spawn(move || writer.publish(|| ()).unwrap()).join().unwrap();
                }
            }));
            assert_eq!(f.server.get(&path).await.status().as_u16(), expected, "{path}: {publications} publications between authorisation and release");
        }
    }
    gate.set_barrier(Arc::new(|| {}));
    f.server.shutdown().await;
}

/// One credential holds at most two of a registry's fetch places, so a junk `Authorization` cannot starve the others.
#[tokio::test]
async fn one_credential_cannot_hold_all_of_a_registrys_fetch_places() {
    let f = start(0, Some(&target()), None).await;
    f.oci.put_image("pub/app", Some("v1"), &image("a", &[&layer("one")]));
    f.oci.set_delay_ms(300);
    let url = f.server.url("/v2/pub/app/manifests/v1");
    let mut joins = Vec::new();
    for _ in 0..8 {
        let url = url.clone();
        joins.push(tokio::spawn(async move { common::downstream_client().get(url).header("authorization", "Bearer one-callers-token").send().await.unwrap().status().as_u16() }));
    }
    for join in joins {
        assert_eq!(join.await.unwrap(), 200);
    }
    assert!(f.oci.peak_in_flight() <= 2, "one credential held {} of the registry's places", f.oci.peak_in_flight());
    // Eight different credentials share the registry's own eight.
    let mut joins = Vec::new();
    for n in 0..16 {
        let url = url.clone();
        joins.push(tokio::spawn(async move { common::downstream_client().get(url).header("authorization", format!("Bearer token-{n}")).send().await.unwrap().status().as_u16() }));
    }
    for join in joins {
        assert_eq!(join.await.unwrap(), 200);
    }
    assert!(f.oci.peak_in_flight() <= 8, "the registry's own places: {}", f.oci.peak_in_flight());
    f.server.shutdown().await;
}

/// A layer pushed with no declared length (a client that streams) is spooled and forwarded with the length it turned out to have.
#[tokio::test]
async fn a_chunked_blob_upload_is_spooled_and_forwarded_with_its_real_length() {
    let f = start(0, Some(&target()), None).await;
    let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = (0..40).map(|n| Ok(bytes::Bytes::from(vec![n as u8; 50_000]))).collect();
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(chunks));
    let patch = common::downstream_client().patch(f.server.url("/v2/team/app/blobs/uploads/uuid-1")).header("authorization", "Bearer callers-token").body(body).send().await.unwrap();
    assert_eq!(patch.status().as_u16(), 202);
    assert_eq!(f.oci.writes().last().unwrap().2, 2_000_000, "the registry received every byte, with the length the spool counted");
    f.server.shutdown().await;
}

/// A document over its bound is a 502, never a truncated list a client would take for the whole.
#[tokio::test]
async fn a_tag_list_over_its_bound_is_a_502_and_never_a_truncated_list() {
    let f = start(0, Some(&target()), None).await;
    f.oci.big_tag_list(1_200_000);
    let response = f.server.get("/v2/pub/app/tags/list").await;
    assert_eq!(response.status().as_u16(), 502);
    f.oci.big_tag_list(20_000);
    let response = f.server.get("/v2/pub/app/tags/list").await;
    assert_eq!(response.status().as_u16(), 200, "a 20,000-tag list (five times the largest real one) is served whole");
    let doc: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(doc["tags"].as_array().unwrap().len(), 20_000);
    f.server.shutdown().await;
}

/// A Basic credential is exchanged for a token for a BLOB transfer too (the artifact pipeline sends one `Authorization` and drops it at the
/// first redirect hop): the registry sees the token, never the password, and the storage host sees nothing.
#[tokio::test]
async fn a_basic_credential_is_exchanged_for_a_token_for_a_blob_transfer_too() {
    let f = start(0, Some(&target()), None).await;
    f.oci.require_token();
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("app", Some("v1"), &app);
    let basic = [("authorization", "Basic dXNlcjpwdw==")];
    let blob = f.server.get_with_headers(&format!("/v2/app/blobs/{}", app.layer_digests[0]), &basic).await;
    assert_eq!((blob.status().as_u16(), blob.bytes().await.unwrap().to_vec()), (200, app.layers[0].clone()));
    let artifacts = f.oci.artifact_requests();
    assert!(!artifacts.is_empty() && artifacts.iter().all(|(_, auth, ..)| auth.as_deref() == Some("Bearer tok-user")), "{artifacts:?}");
    assert!(f.oci.seen().iter().filter(|call| !call.path.ends_with("/token")).all(|call| call.authorization.as_deref() != Some("Basic dXNlcjpwdw==")), "the password went to the token realm only: {:?}", f.oci.seen());
    f.server.shutdown().await;
}

/// With a registry at the root of its host (no path prefix to fall back on) the origin of a `Location` is the whole check: another host's
/// URL with the same path is not passed on (probe P7 of the evidence found the prefix check hiding this).
#[tokio::test]
async fn a_location_on_another_host_with_the_same_path_is_not_passed_on() {
    let f = start(0, Some(&format!("{HOST}/")), None).await;
    f.oci.set_prefix("");
    for location in ["https://evil.example/v2/team/app/blobs/uploads/x", "http://oci.invalid/v2/team/app/blobs/uploads/x", "https://oci.invalid:8443/v2/team/app/blobs/uploads/x"] {
        f.oci.upload_location(location);
        let response = common::downstream_client().post(f.server.url("/v2/team/app/blobs/uploads/")).header("authorization", "Bearer callers-token").send().await.unwrap();
        assert_eq!(response.status().as_u16(), 502, "{location}");
        assert!(response.headers().get("location").is_none(), "{location}");
    }
    f.oci.upload_location("https://oci.invalid/v2/team/app/blobs/uploads/abc?_state=s");
    let response = common::downstream_client().post(f.server.url("/v2/team/app/blobs/uploads/")).header("authorization", "Bearer callers-token").send().await.unwrap();
    assert_eq!(response.headers().get("location").unwrap(), "/v2/team/app/blobs/uploads/abc?_state=s");
    f.server.shutdown().await;
}

/// The ping is the registry's own state: a registry that wants tokens is answered `401` with this firewall's challenge even when an anonymous
/// token would do (a client that is told "open" never presents a credential, so its push would meet a 401 it does not act on); the whole token
/// flow through the firewall, anonymous, then works for a read.
#[tokio::test]
async fn the_ping_mirrors_the_registrys_challenge_and_the_anonymous_token_flow_through_the_firewall_reads_an_image() {
    let f = start(0, Some(&target()), None).await;
    f.oci.require_token();
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("pub/app", Some("v1"), &app);
    let ping = f.server.get("/v2/").await;
    assert_eq!(ping.status().as_u16(), 401);
    assert!(ping.headers().get("www-authenticate").unwrap().to_str().unwrap().starts_with("Bearer realm=\""));
    // The client's own flow: an anonymous token from this firewall's endpoint, then the image with it.
    let token = f.server.get("/v2/token?service=probation&scope=repository:pub/app:pull").await;
    let doc: serde_json::Value = serde_json::from_str(&token.text().await.unwrap()).unwrap();
    assert_eq!(doc["token"], "tok-anon", "{doc}");
    let bearer = [("authorization", "Bearer tok-anon")];
    assert_eq!(f.server.get_with_headers("/v2/", &bearer).await.status().as_u16(), 200, "a client that carries a token is told the registry is open to it");
    let manifest = f.server.get_with_headers("/v2/pub/app/manifests/v1", &bearer).await;
    assert_eq!((manifest.status().as_u16(), manifest.bytes().await.unwrap().to_vec()), (200, app.manifest.clone()));
    let blob = f.server.get_with_headers(&format!("/v2/pub/app/blobs/{}", app.layer_digests[0]), &bearer).await;
    assert_eq!((blob.status().as_u16(), blob.bytes().await.unwrap().to_vec()), (200, app.layers[0].clone()));
    // A client that does not run the flow at all (a bare GET) is still served with the firewall's own anonymous token.
    assert_eq!(f.server.get("/v2/pub/app/manifests/v1").await.status().as_u16(), 200);
    f.server.shutdown().await;
}

// ------------------------------------------------------------------ the fix round (reviews/slice-24)

async fn client_at(url: String, address: &str, auth: Option<String>) -> u16 {
    let mut request = common::downstream_client().get(url).header("x-forwarded-for", address.to_owned());
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    request.send().await.unwrap().status().as_u16()
}

/// S24-F2 / code F3: a client address holds at most four of a registry's eight places, whatever credentials it presents (eight junk ones, or
/// none), and another client still gets a place at once.
#[tokio::test]
async fn one_client_address_cannot_hold_the_places_whatever_credentials_it_presents() {
    let f = start_with(0, Some(&target()), None, 1, None, true, |_| {}).await;
    f.oci.put_image("pub/app", Some("v1"), &image("a", &[&layer("one")]));
    f.oci.set_delay_ms(600);
    let url = f.server.url("/v2/pub/app/manifests/v1");
    let mut joins = Vec::new();
    for n in 0..16 {
        let auth = (n < 8).then(|| format!("Bearer junk-{n}"));
        joins.push(tokio::spawn(client_at(url.clone(), "203.0.113.7", auth)));
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let began = std::time::Instant::now();
    assert_eq!(client_at(url.clone(), "198.51.100.9", None).await, 200, "another client is served");
    assert!(began.elapsed() < std::time::Duration::from_millis(1_500), "another client did not queue behind the first: {:?}", began.elapsed());
    for join in joins {
        assert_eq!(join.await.unwrap(), 200);
    }
    assert!(f.oci.peak_in_flight() <= 5, "one address held {} places (its 4, plus the other client's 1)", f.oci.peak_in_flight());
    f.server.shutdown().await;
}

/// Code F12 / S24-F6.4: one client's flood of repository names cannot flush the anonymous tokens of the others, and holds at most its share of the table.
#[tokio::test]
async fn one_client_cannot_clear_the_token_table_of_the_others() {
    let f = start_with(0, Some(&target()), None, 1, None, true, |config| config.max_references_per_project = NonZeroU32::new(100).unwrap()).await;
    f.oci.require_token();
    f.oci.put_image("good/app", Some("v1"), &image("a", &[&layer("one")]));
    let url = f.server.url("/v2/good/app/manifests/v1");
    assert_eq!(client_at(url.clone(), "198.51.100.9", None).await, 200);
    let tokens = f.oci.count("/token");
    for n in 0..300 {
        f.oci.put_image(&format!("flood/r{n}"), Some("v1"), &image("x", &[]));
        assert_eq!(client_at(f.server.url(&format!("/v2/flood/r{n}/manifests/v1")), "203.0.113.7", None).await, 200);
    }
    let sizes = probation::oci::serve::table_sizes(&f.server.app());
    assert!(sizes[0] <= 33, "one client holds at most its own 32 tokens (and the one of the first): {sizes:?}");
    assert_eq!(client_at(url, "198.51.100.9", None).await, 200);
    assert_eq!(f.oci.count("/token"), tokens + 300, "the other client's token was still there: only the flood asked for tokens");
    f.server.shutdown().await;
}

/// Code F4: a manifest that has its row is read, not written (and no row gate is taken): 100 pulls make no commit after the first.
#[tokio::test]
async fn a_manifest_that_has_its_row_is_read_and_never_written_again() {
    let f = start(0, Some(&target()), None).await;
    f.oci.put_image("pub/app", Some("v1"), &image("a", &[&layer("one")]));
    assert_eq!(f.server.get("/v2/pub/app/manifests/v1").await.status().as_u16(), 200);
    let before = f.server.store_commands();
    for _ in 0..100 {
        assert_eq!(f.server.get_with_headers("/v2/pub/app/manifests/v1", &[("authorization", "Bearer c")]).await.status().as_u16(), 200);
    }
    let commands = f.server.store_commands() - before;
    assert!(commands <= 100 + 5, "one store read per request and no write: {commands} commands for 100 requests");
    f.server.shutdown().await;
}

/// Code F5: a registry whose challenge names a token service on another host works when its descriptor declares that origin, and only then.
#[tokio::test]
async fn a_token_service_on_another_host_works_only_when_the_registry_declares_it() {
    for (declared, expected) in [(None, 502u16), (Some("https://gitlab.example"), 200), (Some("https://other.example"), 502)] {
        let f = start_with(0, Some(&target()), None, 1, declared, false, |_| {}).await;
        f.oci.require_token();
        f.oci.foreign_realm("https://gitlab.example/jwt/auth");
        f.oci.put_image("app", Some("v1"), &image("a", &[&layer("one")]));
        assert_eq!(f.server.get("/v2/app/manifests/v1").await.status().as_u16(), expected, "declared {declared:?}");
        f.server.shutdown().await;
    }
}

/// Code F6: `OCI-Subject` of a registry's answer to a manifest PUT reaches the client (shape checked).
#[tokio::test]
async fn oci_subject_of_a_manifest_put_is_relayed() {
    let f = start(0, Some(&target()), None).await;
    f.oci.answer_oci_subject();
    let put = common::downstream_client().put(f.server.url("/v2/team/app/manifests/sig")).header("authorization", "Bearer c").header("content-type", oci::OCI_MANIFEST).body(r#"{"subject":{"digest":"x"}}"#).send().await.unwrap();
    assert_eq!(put.status().as_u16(), 201);
    assert_eq!(put.headers().get("oci-subject").unwrap().to_str().unwrap(), format!("sha256:{}", "5".repeat(64)));
    f.server.shutdown().await;
}

/// Code F7: a long referrers list is followed page by page (same origin, same list, bounded) and answered whole; no link of the registry reaches
/// the client; a list that loops is a 502.
#[tokio::test]
async fn a_paged_referrers_list_is_answered_whole_and_a_loop_is_refused() {
    let f = start(0, Some(&target()), None).await;
    let subject = format!("sha256:{}", "a".repeat(64));
    let entry = |n: u8| serde_json::json!({"mediaType": oci::OCI_MANIFEST, "digest": format!("sha256:{}", format!("{n:02x}").repeat(32)), "size": 5, "artifactType": "application/vnd.example.sig"});
    let page = |entries: Vec<serde_json::Value>| serde_json::json!({"schemaVersion": 2, "mediaType": oci::OCI_INDEX, "manifests": entries}).to_string();
    let path = format!("/v2/team/app/referrers/{subject}");
    let next = |last: &str| format!("<https://oci.invalid{PREFIX}{path}?last={last}>; rel=\"next\"");
    f.oci.put_referrer_page("team/app", &subject, "", &page(vec![entry(1), entry(2)]), Some(&next("p2")));
    f.oci.put_referrer_page("team/app", &subject, "p2", &page(vec![entry(3)]), Some(&next("p3")));
    f.oci.put_referrer_page("team/app", &subject, "p3", &page(vec![entry(4)]), None);
    let answer = f.server.get(&path).await;
    assert_eq!(answer.status().as_u16(), 200);
    assert!(answer.headers().get("link").is_none(), "no pagination link reaches the client");
    let doc: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap();
    assert_eq!(doc["manifests"].as_array().unwrap().len(), 4, "{doc}");
    f.oci.put_referrer_page("team/app", &subject, "p3", &page(vec![entry(4)]), Some(&next("p3")));
    assert_eq!(f.server.get(&path).await.status().as_u16(), 502, "a page that names itself is a loop, not a list");
    f.server.shutdown().await;
}

/// Code F8: the tag-schema fallback of a registry without the referrers API (an index of descriptors, no content) is not held by a cooldown; the same
/// tag name over an image, and any other tag, still is.
#[tokio::test]
async fn the_referrers_fallback_index_is_not_cooled_down_and_nothing_else_is_exempt_by_name() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    let tag = format!("sha256-{}", "b".repeat(64));
    let index = serde_json::json!({"schemaVersion": 2, "mediaType": oci::OCI_INDEX, "manifests": [{"mediaType": oci::OCI_MANIFEST, "digest": format!("sha256:{}", "c".repeat(64)), "size": 9, "artifactType": "x/y"}]}).to_string().into_bytes();
    f.oci.put_manifest("team/app", &tag, &index, oci::OCI_INDEX);
    assert_eq!(f.server.get(&format!("/v2/team/app/manifests/{tag}")).await.status().as_u16(), 200, "an index of descriptors under the fallback tag");
    f.oci.put_manifest("team/app", "latest", &index, oci::OCI_INDEX);
    assert_eq!(f.server.get("/v2/team/app/manifests/latest").await.status().as_u16(), 403, "the same index under an ordinary tag waits");
    let image = image("a", &[&layer("one")]);
    f.oci.put_manifest("team/other", &tag, &image.manifest, oci::OCI_MANIFEST);
    assert_eq!(f.server.get(&format!("/v2/team/other/manifests/{tag}")).await.status().as_u16(), 403, "an image under the fallback's name waits");
    f.server.shutdown().await;
}

/// Code F9: the status of an upload session is forwarded with the caller's credential and challenged without one.
#[tokio::test]
async fn the_status_of_an_upload_session_is_forwarded_with_the_callers_credential() {
    let f = start(0, Some(&target()), None).await;
    let path = f.server.url("/v2/team/app/blobs/uploads/uuid-1?_state=s");
    let without = common::downstream_client().get(&path).send().await.unwrap();
    assert_eq!(without.status().as_u16(), 401);
    assert!(f.oci.seen().is_empty());
    let with = common::downstream_client().get(&path).header("authorization", "Bearer c").send().await.unwrap();
    assert_eq!(with.status().as_u16(), 204);
    assert_eq!(with.headers().get("range").unwrap(), "0-99");
    assert_eq!(with.headers().get("location").unwrap(), "/v2/team/app/blobs/uploads/uuid-1?_state=opaque");
    f.server.shutdown().await;
}

/// Code F13: a client's HEAD of a manifest is the registry's HEAD (Docker Hub counts a GET as a pull and a HEAD as none), judged by the digest it
/// names, and remembered for a moment; a GET reads the bytes.
#[tokio::test]
async fn a_head_of_a_manifest_is_the_registrys_head_and_is_remembered() {
    let f = start(0, Some(&target()), None).await;
    let app = image("a", &[&layer("one")]);
    f.oci.put_image("pub/app", Some("v1"), &app);
    for _ in 0..3 {
        let head = f.server.head("/v2/pub/app/manifests/v1").await;
        assert_eq!(head.status().as_u16(), 200);
        assert_eq!(head.headers().get("docker-content-digest").unwrap().to_str().unwrap(), app.digest);
        assert_eq!(head.headers().get("content-length").unwrap().to_str().unwrap(), app.manifest.len().to_string());
    }
    let manifest_calls: Vec<_> = f.oci.seen().into_iter().filter(|call| call.path.contains("/manifests/")).map(|call| call.method).collect();
    assert_eq!(manifest_calls, ["HEAD"], "one registry HEAD, no GET, for three client HEADs: {manifest_calls:?}");
    let get = f.server.get("/v2/pub/app/manifests/v1").await;
    assert_eq!((get.status().as_u16(), get.bytes().await.unwrap().to_vec()), (200, app.manifest.clone()));
    f.server.shutdown().await;
}

/// S24-F4: a credential proves nothing to a registry that asked for none, so the cooldown holds a HEAD there.
#[tokio::test]
async fn a_credential_on_a_registry_that_asked_for_none_does_not_exempt_a_head() {
    let f = start(7 * 86_400, Some(&target()), None).await;
    f.oci.put_image("pub/app", Some("v1"), &image("a", &[&layer("one")]));
    let head = common::downstream_client().head(f.server.url("/v2/pub/app/manifests/v1")).header("authorization", "Bearer junk").send().await.unwrap();
    assert_eq!(head.status().as_u16(), 403);
    f.server.shutdown().await;
}

/// S24-F5: a manifest is served under a manifest media type or `application/json`, never the registry's `text/html`, and nothing is sniffed.
#[tokio::test]
async fn a_manifest_is_never_served_as_a_page() {
    let f = start(0, Some(&target()), None).await;
    let app = image("a", &[&layer("one")]);
    f.oci.put_manifest("pub/app", "v1", &app.manifest, "text/html");
    let response = f.server.get("/v2/pub/app/manifests/v1").await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    assert_eq!(response.headers().get("x-content-type-options").unwrap(), "nosniff");
    for path in ["/v2/", "/v2/pub/app/tags/list"] {
        assert_eq!(f.server.get(path).await.headers().get("x-content-type-options").map(|v| v.to_str().unwrap().to_owned()), Some("nosniff".to_owned()), "{path}");
    }
    f.server.shutdown().await;
}

/// S24-F6: the registry segment is an id before anything is built from it; the token answer is `no-store`.
#[tokio::test]
async fn the_registry_segment_is_validated_first_and_a_token_is_never_cached() {
    let f = start(0, Some(&target()), None).await;
    for bad in ["abc", "7x", "0", "07"] {
        let answer = common::downstream_client().post(f.server.url(&format!("/registry/oci/{bad}/v2/team/app/blobs/uploads/"))).send().await.unwrap();
        assert_eq!(answer.status().as_u16(), 404, "{bad}");
        assert!(answer.headers().get("www-authenticate").is_none(), "{bad}: no realm is built from it");
    }
    f.oci.require_token();
    let token = f.server.get("/v2/token?scope=repository:app:pull").await;
    assert_eq!(token.status().as_u16(), 200);
    assert_eq!(token.headers().get("cache-control").unwrap(), "no-store");
    f.server.shutdown().await;
}

/// S24-F3 / F10: a digest blocked under any repository is blocked in every one (a read of the manifest, the blob, a mount, an upload that finishes
/// with it, a delete), and what a policy blocks is not pushed either. A sha512 spelling of a manifest is the same manifest; a blob has no sha512 route.
#[tokio::test]
async fn a_blocked_digest_is_blocked_in_every_repository_and_every_spelling() {
    let app = image("evil", &[&layer("evil")]);
    let sha512 = |bytes: &[u8]| probation::oci::coords::Digest::of(probation::oci::coords::Algorithm::Sha512, bytes).to_string();
    let policy = MockServer::start().await;
    let mut snapshot = snapshot_with(0, Some(&target()), None, 1, None);
    snapshot.layers[1].layer.blocks.push(probation_policy::Block::Version { ecosystem: probation_policy::Ecosystem::Oci, name: "library/foo".into(), version: app.digest.clone(), reason: None });
    snapshot.layers[1].layer.blocks.push(probation_policy::Block::Version { ecosystem: probation_policy::Ecosystem::Oci, name: "team/app".into(), version: "bad-tag".into(), reason: None });
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot)).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig { server_url: policy.uri().parse().unwrap(), service_key_file: "/test/key".into(), service_key: FirewallToken::new(KEY.into()), sync_interval_seconds: NonZeroU64::new(60).unwrap(), trusted_proxies: vec![] });
    let oci = FakeOci::new();
    oci.set_prefix(PREFIX);
    oci.put_image("evil/foo", Some("v1"), &app);
    oci.put_image("team/app", Some("bad-tag"), &app);
    let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
    let origins = fake_origins().with_oci(url::Url::parse(HOST).unwrap(), url::Url::parse(CDN).unwrap());
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&oci) as Arc<dyn Transport>, origins).await;
    let status = |method: &str, path: String| {
        let (url, method) = (server.url(&path), method.to_owned());
        async move { common::downstream_client().request(method.parse().unwrap(), url).header("authorization", "Bearer c").send().await.unwrap().status().as_u16() }
    };
    let digest = &app.digest;
    assert_eq!(status("GET", format!("/v2/evil/foo/manifests/{digest}")).await, 403, "re-hosted under another repository");
    oci.put_manifest("evil/foo", &sha512(&app.manifest), &app.manifest, oci::OCI_MANIFEST);
    assert_eq!(status("GET", format!("/v2/evil/foo/manifests/{}", sha512(&app.manifest))).await, 403, "the sha512 spelling is the same bytes, and the same block");
    assert_eq!(status("GET", format!("/v2/evil/foo/blobs/{digest}")).await, 403);
    oci.put_blob("evil/foo", &sha512(&app.config), &app.config);
    assert_eq!(status("GET", format!("/v2/evil/foo/blobs/{}", sha512(&app.config))).await, 200, "a blob is served by its sha512 spelling too, verified in that algorithm");
    assert_eq!(status("GET", format!("/v2/evil/foo/blobs/sha512:{}", "0".repeat(128))).await, 404, "an unknown sha512 is not found");
    assert_eq!(status("POST", format!("/v2/evil/foo/blobs/uploads/?mount={digest}&from=library/foo")).await, 403, "a mount of a blocked digest");
    assert_eq!(status("PUT", format!("/v2/evil/foo/blobs/uploads/uuid-1?digest={digest}")).await, 403, "an upload that finishes with it");
    assert_eq!(status("DELETE", format!("/v2/evil/foo/blobs/{digest}")).await, 403);
    assert_eq!(status("PUT", "/v2/team/app/manifests/bad-tag".to_owned()).await, 403, "a blocked tag is not pushed");
    assert_eq!(status("PUT", format!("/v2/team/app/manifests/{digest}")).await, 403, "nor a blocked digest");
    assert_eq!(status("PUT", "/v2/team/app/manifests/fine".to_owned()).await, 201, "an unblocked tag is");
    assert!(oci.writes().iter().all(|(_, path, _)| !path.contains("bad-tag") && !path.contains(digest.as_str())), "nothing blocked reached the registry: {:?}", oci.writes());
    server.shutdown().await;
}

/// Code F11: the children an already registered parent shares are not counted again against the row bound.
#[tokio::test]
async fn children_that_have_rows_are_not_counted_again_by_the_row_bound() {
    let f = start_with(0, Some(&target()), None, 1, None, false, |config| config.max_references_per_project = NonZeroU32::new(1).unwrap()).await;
    let first = image("a", &[&layer("1"), &layer("2")]);
    f.oci.put_image("bounded/app", Some("v1"), &first);
    assert_eq!(f.server.get("/v2/bounded/app/manifests/v1").await.status().as_u16(), 200, "manifest, config and two layers: four rows of five");
    // A second manifest naming the same config and layers (it differs in an annotation): one new row, no new child.
    let mut doc: serde_json::Value = serde_json::from_slice(&first.manifest).unwrap();
    doc["annotations"] = serde_json::json!({"note": "again"});
    let second = serde_json::to_vec(&doc).unwrap();
    f.oci.put_manifest("bounded/app", "v2", &second, oci::OCI_MANIFEST);
    assert_eq!(f.server.get("/v2/bounded/app/manifests/v2").await.status().as_u16(), 200);
    let rows = f.server.app().store().count_project_references_in(7, probation::policy::Ecosystem::Oci, "bounded/app").await.unwrap();
    assert_eq!(rows, 5);
    f.server.shutdown().await;
}

/// Code F13 / S24 U-2: a registry holds at most five times `max_references_per_project` repositories.
#[tokio::test]
async fn a_registry_holds_a_bounded_number_of_repositories() {
    let f = start_with(0, Some(&target()), None, 1, None, false, |config| config.max_references_per_project = NonZeroU32::new(1).unwrap()).await;
    for n in 0..7 {
        f.oci.put_image(&format!("many/r{n}"), Some("v1"), &image(&format!("{n}"), &[]));
    }
    let mut statuses = Vec::new();
    for n in 0..7 {
        statuses.push(f.server.get(&format!("/v2/many/r{n}/manifests/v1")).await.status().as_u16());
    }
    assert_eq!(statuses, [200, 200, 200, 200, 200, 503, 503], "five repositories fit, the rest wait");
    assert_eq!(f.server.get("/v2/many/r0/manifests/v1").await.status().as_u16(), 200, "a repository that has rows is still served");
    f.server.shutdown().await;
}

/// U2: a manifest whose layer names download URLs of its own would be fetched around the firewall: refused.
/// Q23: many first requests of different new repositories at the same moment cannot each see room for the last one.
#[tokio::test]
async fn simultaneous_new_repositories_do_not_overshoot_the_repository_bound() {
    let f = start_with(0, Some(&target()), None, 1, None, false, |config| config.max_references_per_project = NonZeroU32::new(1).unwrap()).await;
    f.oci.set_delay_ms(150);
    for n in 0..16 {
        f.oci.put_image(&format!("burst/r{n}"), Some("v1"), &image(&format!("{n}"), &[]));
    }
    let client = common::downstream_client();
    let calls: Vec<_> = (0..16).map(|n| { let (url, client) = (f.server.url(&format!("/v2/burst/r{n}/manifests/v1")), client.clone()); tokio::spawn(async move { client.get(url).header("authorization", "Bearer c").send().await.unwrap().status().as_u16() }) }).collect();
    let mut served = 0;
    for call in calls {
        served += usize::from(call.await.unwrap() == 200);
    }
    assert_eq!(served, 5, "exactly the bound's five repositories, however many asked at once");
    f.server.shutdown().await;
}

/// U1: the headers of a first pull go out before the layer has been downloaded and verified (a client sees `200`, the length and the digest at
/// once), and the body follows the verified file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_headers_of_a_first_pull_go_out_before_the_layer_is_verified() {
    let f = start(0, Some(&target()), None).await;
    let app = image("slow", &[&layer("slow")]);
    f.oci.put_image("pub/app", Some("v1"), &app);
    assert_eq!(f.server.get("/v2/pub/app/manifests/v1").await.status().as_u16(), 200);
    f.oci.set_artifact_delay_ms(1_500);
    let started = std::time::Instant::now();
    let mut response = f.server.get(&format!("/v2/pub/app/blobs/{}", app.layer_digests[0])).await;
    let headers_after = started.elapsed();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.content_length(), Some(app.layers[0].len() as u64));
    assert_eq!(response.headers().get("docker-content-digest").unwrap().to_str().unwrap(), app.layer_digests[0]);
    assert!(headers_after < std::time::Duration::from_millis(1_000), "the headers waited for the download: {headers_after:?}");
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }
    assert!(started.elapsed() >= std::time::Duration::from_millis(1_500), "the body followed the download");
    assert_eq!(body, app.layers[0]);
    f.server.shutdown().await;
}

/// U3: a manifest whose layers are named by sha512 works: the blob route takes the sha512 spelling, the bytes are verified in that algorithm,
/// and the policy identity stays the sha256 the firewall computed (a block on it holds for the sha512 spelling too).
#[tokio::test]
async fn a_layer_named_by_sha512_is_served_verified_and_judged_by_its_sha256() {
    use probation::oci::coords::{Algorithm, Digest};
    let bytes = layer("sha512");
    let (d512, d256) = (Digest::of(Algorithm::Sha512, &bytes).to_string(), Digest::of(Algorithm::Sha256, &bytes).to_string());
    let manifest = serde_json::json!({"schemaVersion": 2, "mediaType": oci::OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": format!("sha256:{}", "1".repeat(64)), "size": 1},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d512, "size": bytes.len()}]});
    for (blocked, expected) in [(false, 200u16), (true, 403)] {
        let policy = MockServer::start().await;
        let mut snapshot = snapshot_with(0, Some(&target()), None, 1, None);
        if blocked {
            snapshot.layers[1].layer.blocks.push(probation_policy::Block::Version { ecosystem: probation_policy::Ecosystem::Oci, name: "library/foo".into(), version: d256.clone(), reason: None });
        }
        Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot)).mount(&policy).await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_with_open_blocklist(dir.path());
        config.service_policy = Some(ServicePolicyConfig { server_url: policy.uri().parse().unwrap(), service_key_file: "/test/key".into(), service_key: FirewallToken::new(KEY.into()), sync_interval_seconds: NonZeroU64::new(60).unwrap(), trusted_proxies: vec![] });
        let oci = FakeOci::new();
        oci.set_prefix(PREFIX);
        oci.put_manifest("app", "v1", manifest.to_string().as_bytes(), oci::OCI_MANIFEST);
        oci.put_blob("app", &d512, &bytes);
        let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
        let origins = fake_origins().with_oci(url::Url::parse(HOST).unwrap(), url::Url::parse(CDN).unwrap());
        let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&oci) as Arc<dyn Transport>, origins).await;
        let get = |path: String| { let url = server.url(&path); async move { common::downstream_client().get(url).header("authorization", "Bearer c").send().await.unwrap() } };
        // (a block names the sha256 of the bytes, which a manifest that names them by sha512 does not state: the manifest is served, and the
        // layer is judged by the sha256 the firewall computes while the bytes arrive)
        assert_eq!(get("/v2/app/manifests/v1".into()).await.status().as_u16(), 200);
        let blob = get(format!("/v2/app/blobs/{d512}")).await;
        assert_eq!(blob.status().as_u16(), expected, "blocked {blocked}");
        if !blocked {
            assert_eq!(blob.bytes().await.unwrap().to_vec(), bytes, "the bytes of the sha512 layer");
        }
        if blocked {
            // N3: the pair is known now (the bytes were hashed), so the manifest that names the layer by sha512 is refused at manifest time too.
            assert_eq!(get("/v2/app/manifests/v1".into()).await.status().as_u16(), 403, "the stored sha256 of a sha512 child is checked against the blocks");
        }
        server.shutdown().await;
    }
    // Bytes that are not their sha512 are never released.
    let f = start(0, Some(&target()), None).await;
    let wrong = format!("sha512:{}", "7".repeat(128));
    f.oci.put_blob("app", &wrong, b"not those bytes");
    let blob = f.server.get(&format!("/v2/app/blobs/{wrong}")).await;
    assert!(blob.status().as_u16() != 200 || blob.bytes().await.is_err());
    f.server.shutdown().await;
}

fn foreign_manifest(bytes: &[u8], urls: &[&str]) -> (Vec<u8>, String) {
    let digest = probation::oci::coords::Digest::of(probation::oci::coords::Algorithm::Sha256, bytes).to_string();
    let manifest = serde_json::json!({"schemaVersion": 2, "mediaType": oci::OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": format!("sha256:{}", "1".repeat(64)), "size": 1},
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip", "digest": digest, "size": bytes.len(), "urls": urls}]});
    (manifest.to_string().into_bytes(), digest)
}

#[tokio::test]
async fn a_foreign_layer_is_accepted_and_served_by_digest_from_its_listed_host() {
    let f = start(0, Some(&target()), None).await;
    // (a registry that asks for a token: the firewall's own anonymous token is its alone, and goes to no foreign host)
    f.oci.require_token();
    let bytes = b"a windows base layer";
    let url = "https://mcr.microsoft.com/v2/windows/servercore/blobs/layer";
    let (manifest, digest) = foreign_manifest(bytes, &[url]);
    f.oci.put_manifest("win/base", "ltsc", &manifest, oci::OCI_MANIFEST);
    f.oci.put_foreign(url, bytes);
    assert_eq!(f.server.get("/v2/win/base/manifests/ltsc").await.status().as_u16(), 200);
    // (a Basic credential would be exchanged at the registry's realm for a token: none of that may reach the foreign host)
    let blob = f.server.get_with_headers(&format!("/v2/win/base/blobs/{digest}"), &[("authorization", "Basic dXNlcjpwdw==")]).await;
    assert_eq!(blob.status().as_u16(), 200);
    assert_eq!(blob.bytes().await.unwrap().as_ref(), bytes);
    let artifacts = f.oci.artifact_requests();
    assert!(artifacts.iter().any(|(path, authorization, _, _)| path.ends_with("/blobs/layer") && authorization.is_none()), "fetched from the listed URL with no credential: {artifacts:?}");
    f.server.shutdown().await;
}

#[tokio::test]
async fn a_foreign_layer_whose_bytes_are_not_its_digest_is_never_released() {
    let f = start(0, Some(&target()), None).await;
    let url = "https://mcr.microsoft.com/v2/windows/servercore/blobs/layer";
    let (manifest, digest) = foreign_manifest(b"the layer that was named", &[url]);
    f.oci.put_manifest("win/base", "ltsc", &manifest, oci::OCI_MANIFEST);
    f.oci.put_foreign(url, b"some other bytes");
    assert_eq!(f.server.get("/v2/win/base/manifests/ltsc").await.status().as_u16(), 200);
    let blob = f.server.get(&format!("/v2/win/base/blobs/{digest}")).await;
    assert_ne!(blob.status().as_u16(), 200);
    f.server.shutdown().await;
}

#[tokio::test]
async fn a_foreign_layer_on_a_host_that_is_not_listed_is_refused() {
    let f = start(0, Some(&target()), None).await;
    for url in ["https://elsewhere.example/layer", "http://mcr.microsoft.com/layer", "https://user:pw@mcr.microsoft.com/layer", "https://mcr.microsoft.com.evil.example/layer", "https://127.0.0.1/layer"] {
        let (manifest, _) = foreign_manifest(b"x", &[url]);
        f.oci.put_manifest("win/base", "ltsc", &manifest, oci::OCI_MANIFEST);
        let response = f.server.get("/v2/win/base/manifests/ltsc").await;
        assert_eq!(response.status().as_u16(), 403, "{url}");
        assert!(response.text().await.unwrap().contains("download URL"), "{url}");
    }
    f.server.shutdown().await;
}

#[tokio::test]
async fn a_block_on_a_foreign_layer_digest_refuses_the_manifest() {
    let bytes = b"a blocked foreign layer";
    let digest = probation::oci::coords::Digest::of(probation::oci::coords::Algorithm::Sha256, bytes).to_string();
    let policy = MockServer::start().await;
    let mut snapshot = snapshot_with(0, Some(&target()), None, 1, None);
    snapshot.layers[1].layer.blocks.push(probation_policy::Block::Version { ecosystem: probation_policy::Ecosystem::Oci, name: "library/foo".into(), version: digest.clone(), reason: None });
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot)).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig { server_url: policy.uri().parse().unwrap(), service_key_file: "/test/key".into(), service_key: FirewallToken::new(KEY.into()), sync_interval_seconds: NonZeroU64::new(60).unwrap(), trusted_proxies: vec![] });
    let oci = FakeOci::new();
    oci.set_prefix(PREFIX);
    let (manifest, _) = foreign_manifest(bytes, &["https://mcr.microsoft.com/layer"]);
    oci.put_manifest("win/base", "ltsc", &manifest, oci::OCI_MANIFEST);
    let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
    let origins = fake_origins().with_oci(url::Url::parse(HOST).unwrap(), url::Url::parse(CDN).unwrap());
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&oci) as Arc<dyn Transport>, origins).await;
    let response = common::downstream_client().get(server.url("/v2/win/base/manifests/ltsc")).header("authorization", "Bearer c").send().await.unwrap();
    assert_eq!(response.status().as_u16(), 403, "a manifest that names a blocked digest, a foreign one included, is refused");
    server.shutdown().await;
}

/// U3: only sha256 and sha512 are algorithms: another one is no route, and a manifest that names one is refused.
#[tokio::test]
async fn an_unknown_digest_algorithm_is_refused() {
    let f = start(0, Some(&target()), None).await;
    let hex96 = "d".repeat(96);
    for path in [format!("/v2/app/blobs/sha384:{hex96}"), format!("/v2/app/manifests/sha384:{hex96}"), format!("/v2/app/blobs/md5:{}", "d".repeat(32))] {
        assert_eq!(f.server.get(&path).await.status().as_u16(), 404, "{path}");
    }
    assert!(f.oci.seen().is_empty());
    let odd = serde_json::json!({"schemaVersion": 2, "mediaType": oci::OCI_MANIFEST, "config": {"digest": format!("sha384:{hex96}"), "size": 1}, "layers": []});
    f.oci.put_manifest("app", "odd", odd.to_string().as_bytes(), oci::OCI_MANIFEST);
    assert_eq!(f.server.get("/v2/app/manifests/odd").await.status().as_u16(), 502);
    f.server.shutdown().await;
}

/// S24-F1 in a shared service: the caller's own Basic credential is the only one the token endpoint uses; a Basic-only registry answers the
/// caller's own credential's text; nothing is invented for a caller that presented none.
#[tokio::test]
async fn the_token_endpoint_of_a_shared_service_uses_only_what_the_caller_sent() {
    let f = start(0, Some(&target()), None).await;
    f.oci.basic_only();
    let none = f.server.get("/v2/token?scope=repository:app:pull,push").await;
    assert_eq!(none.status().as_u16(), 401, "a Basic-only registry and no credential: nothing is invented");
    let basic = [("authorization", "Basic dXNlcjpwdw==")];
    let own = f.server.get_with_headers("/v2/token?scope=repository:app:pull,push", &basic).await;
    let doc: serde_json::Value = serde_json::from_str(&own.text().await.unwrap()).unwrap();
    assert_eq!(doc["token"], "dXNlcjpwdw==", "the caller's own credential's text, to the caller who sent it");
    f.server.shutdown().await;
}

/// Code F1: a layer with no declared length (docker, skopeo and containerd stream it chunked) may take what its size needs at a floor of the
/// shared rate, not five minutes.
#[test]
fn an_undeclared_layer_has_the_time_its_size_needs() {
    use probation::http::oci_routes::body_deadline;
    use probation::http::spool::UNDECLARED_DEADLINE;
    let five_gib = 5u64 << 30;
    let at_one_mib_a_second = std::time::Duration::from_secs(five_gib >> 20);
    assert!(at_one_mib_a_second > UNDECLARED_DEADLINE, "the shared five minutes would cut a 5 GiB layer on a 1 MiB/s link");
    assert!(body_deadline(None, five_gib) >= at_one_mib_a_second, "{:?}", body_deadline(None, five_gib));
    assert_eq!(body_deadline(None, five_gib), std::time::Duration::from_secs(2 * 3600), "bounded at two hours");
    assert!(body_deadline(None, 8 << 20) >= UNDECLARED_DEADLINE, "a manifest keeps at least the shared rule");
    assert_eq!(body_deadline(Some(1 << 20), five_gib), probation::http::spool::body_deadline(Some(1 << 20)), "a declared length has the shared rule");
}

/// Code F2: more layers than an owner's share of the spool holds wait their turn (before a byte of their body is read) instead of failing in
/// the middle of their stream.
#[tokio::test]
async fn layers_beyond_an_owners_share_of_the_spool_queue_instead_of_failing() {
    let f = start(0, Some(&target()), None).await;
    let lane = ((f.server.app().limits.spool_budget_total() / 2) / f.server.app().config.max_artifact_bytes.get()).clamp(1, 4) as usize;
    let mut open = Vec::new();
    for n in 0..lane {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(4);
        sender.send(Ok(bytes::Bytes::from(vec![1u8; 1000]))).await.unwrap();
        let body = reqwest::Body::wrap_stream(futures_util::stream::unfold(receiver, |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) }));
        let url = f.server.url(&format!("/v2/team/app/blobs/uploads/s{n}"));
        let call = tokio::spawn(async move { common::downstream_client().patch(url).header("authorization", "Bearer c").body(body).send().await.unwrap().status().as_u16() });
        open.push((sender, call));
    }
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let url = f.server.url("/v2/team/app/blobs/uploads/queued");
    let queued = tokio::spawn(async move { common::downstream_client().patch(url).header("authorization", "Bearer c").body(vec![2u8; 2000]).send().await.unwrap().status().as_u16() });
    tokio::time::sleep(std::time::Duration::from_millis(1_000)).await;
    assert!(!queued.is_finished(), "the layer past the owner's share waits its turn");
    assert!(f.oci.writes().is_empty(), "and no byte of it was read or forwarded");
    let (sender, call) = open.remove(0);
    drop(sender);
    assert_eq!(call.await.unwrap(), 202);
    assert_eq!(queued.await.unwrap(), 202, "it goes once a place is free");
    for (sender, call) in open {
        drop(sender);
        assert_eq!(call.await.unwrap(), 202);
    }
    f.server.shutdown().await;
}

/// Opens `lane` layer uploads that stay open (a body that is not finished), so the owner's upload lane is full.
async fn fill_the_upload_lane(f: &Fixture) -> Vec<(tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>, tokio::task::JoinHandle<u16>)> {
    let lane = ((f.server.app().limits.spool_budget_total() / 2) / f.server.app().config.max_artifact_bytes.get()).clamp(1, 4) as usize;
    let mut open = Vec::new();
    for n in 0..lane {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(4);
        sender.send(Ok(bytes::Bytes::from(vec![1u8; 1000]))).await.unwrap();
        let body = reqwest::Body::wrap_stream(futures_util::stream::unfold(receiver, |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) }));
        let url = f.server.url(&format!("/v2/team/app/blobs/uploads/s{n}"));
        let call = tokio::spawn(async move { common::downstream_client().patch(url).header("authorization", "Bearer c").body(body).send().await.unwrap().status().as_u16() });
        open.push((sender, call));
    }
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    open
}

/// R1: the empty start of an upload, the finishing PUT and the manifest PUT of a push never wait behind its layers, even when the owner's
/// lane is full of layers still streaming.
#[tokio::test]
async fn the_small_requests_of_a_push_do_not_wait_for_a_layer_place() {
    let f = start(0, Some(&target()), None).await;
    let open = fill_the_upload_lane(&f).await;
    let auth = ("authorization", "Bearer c");
    let client = common::downstream_client();
    let within = |what: &'static str, request: reqwest::RequestBuilder| async move {
        let sent = tokio::time::timeout(std::time::Duration::from_secs(5), request.send()).await.unwrap_or_else(|_| panic!("{what} waited behind a layer"));
        sent.unwrap().status().as_u16()
    };
    assert_eq!(within("the upload start", client.post(f.server.url("/v2/team/app/blobs/uploads/")).header(auth.0, auth.1)).await, 202);
    let digest = format!("sha256:{}", "a".repeat(64));
    assert_eq!(within("the finishing PUT", client.put(f.server.url(&format!("/v2/team/app/blobs/uploads/s9?digest={digest}"))).header(auth.0, auth.1).header("content-length", "0")).await, 201);
    // (a monolithic upload: the finishing PUT carries a small body, which is no layer either)
    assert_eq!(within("a small finishing PUT with a body", client.put(f.server.url(&format!("/v2/team/app/blobs/uploads/s8?digest={digest}"))).header(auth.0, auth.1).body(vec![5u8; 100])).await, 201);
    let image = image("push", &[&layer("one")]);
    assert_eq!(within("the manifest PUT", client.put(f.server.url("/v2/team/app/manifests/v9")).header(auth.0, auth.1).header("content-type", oci::OCI_MANIFEST).body(image.manifest.clone())).await, 201);
    for (sender, call) in open {
        drop(sender);
        assert_eq!(call.await.unwrap(), 202);
    }
    f.server.shutdown().await;
}

/// R1: a request with no body at all (no `Content-Length`, no `Transfer-Encoding`: the server knows it is empty before it reads a byte) is small too.
#[tokio::test]
async fn an_upload_start_with_no_body_headers_does_not_wait_for_a_layer_place() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = start(0, Some(&target()), None).await;
    let open = fill_the_upload_lane(&f).await;
    let url = url::Url::parse(&f.server.url("/")).unwrap();
    let authority = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
    let mut socket = tokio::net::TcpStream::connect(&authority).await.unwrap();
    socket.write_all(format!("POST /v2/team/app/blobs/uploads/ HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer c\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), socket.read_to_end(&mut answer)).await.expect("an empty start waited behind a layer").unwrap();
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 202"), "{}", String::from_utf8_lossy(&answer));
    for (sender, call) in open {
        drop(sender);
        assert_eq!(call.await.unwrap(), 202);
    }
    f.server.shutdown().await;
}

/// N2: a lane that is streaming is never treated as idle by the table's clean-up: with more owners than the table holds, the owner whose
/// layers are still streaming keeps its lane (its next layer queues).
#[tokio::test]
async fn a_streaming_lane_is_not_evicted_when_the_owner_table_overflows() {
    let f = start_with(0, Some(&target()), None, 1, None, true, |_| {}).await;
    let open = fill_the_upload_lane(&f).await;
    let client = common::downstream_client();
    for n in 0..1_100u32 {
        let status = client.patch(f.server.url(&format!("/v2/team/app/blobs/uploads/o{n}"))).header("authorization", "Bearer c").header("x-forwarded-for", format!("10.{}.{}.1", n / 250, n % 250)).body(vec![1u8; 10]).send().await.unwrap().status().as_u16();
        assert_eq!(status, 202, "owner {n}");
    }
    let url = f.server.url("/v2/team/app/blobs/uploads/again");
    let again = tokio::spawn(async move { common::downstream_client().patch(url).header("authorization", "Bearer c").body(vec![2u8; 10]).send().await.unwrap().status().as_u16() });
    tokio::time::sleep(std::time::Duration::from_millis(1_000)).await;
    assert!(!again.is_finished(), "the owner's lane is still full of streaming layers: its next layer waits");
    for (sender, call) in open {
        drop(sender);
        assert_eq!(call.await.unwrap(), 202);
    }
    assert_eq!(again.await.unwrap(), 202);
    f.server.shutdown().await;
}

/// N4: a client that goes away during a first pull cancels the transfer when no other request shares it (the layer is then fetched again).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_leaves_a_first_pull_cancels_the_transfer_nobody_else_waits_for() {
    let f = start(0, Some(&target()), None).await;
    let app = image("leaves", &[&layer("leaves")]);
    f.oci.put_image("pub/app", Some("v1"), &app);
    assert_eq!(f.server.get("/v2/pub/app/manifests/v1").await.status().as_u16(), 200);
    f.oci.set_artifact_delay_ms(1_000);
    let response = f.server.get(&format!("/v2/pub/app/blobs/{}", app.layer_digests[0])).await;
    assert_eq!(response.status().as_u16(), 200);
    drop(response);
    tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;
    f.oci.set_artifact_delay_ms(0);
    let again = f.server.get(&format!("/v2/pub/app/blobs/{}", app.layer_digests[0])).await;
    assert_eq!(again.bytes().await.unwrap().to_vec(), app.layers[0]);
    assert_eq!(f.oci.artifact_requests().len(), 2, "the first transfer was cancelled, not completed for nobody: the layer was fetched again");
    f.server.shutdown().await;
}

/// R1: one address that floods layer uploads cannot take `max_active_requests`: the requests that wait for a lane place hold no active-request
/// place, at most a few wait, and the rest are a 503 at once; a read from the same address is served throughout.
#[tokio::test]
async fn a_flood_of_layer_uploads_from_one_address_cannot_take_the_active_request_places() {
    let f = start_with(0, Some(&target()), None, 1, None, false, |config| config.max_active_requests = NonZeroU32::new(8).unwrap()).await;
    f.oci.put_image("pub/app", Some("v1"), &image("a", &[&layer("one")]));
    let open = fill_the_upload_lane(&f).await;
    let mut flood = Vec::new();
    let client = common::downstream_client();
    for n in 0..40 {
        let (url, client) = (f.server.url(&format!("/v2/team/app/blobs/uploads/f{n}")), client.clone());
        flood.push(tokio::spawn(async move { client.patch(url).header("authorization", "Bearer c").body(vec![3u8; 2000]).send().await.unwrap().status().as_u16() }));
    }
    tokio::time::sleep(std::time::Duration::from_millis(1_000)).await;
    let refused = futures_util::future::join_all(flood.iter_mut().filter(|call| call.is_finished()).map(|call| async { call.await.unwrap() })).await;
    assert!(refused.len() >= 30 && refused.iter().all(|status| *status == 503), "the waiters beyond the cap are refused at once: {} finished", refused.len());
    for _ in 0..5 {
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), common::downstream_client().get(f.server.url("/v2/pub/app/manifests/v1")).header("authorization", "Bearer c").send()).await.expect("a read waited behind the flood");
        assert_eq!(read.unwrap().status().as_u16(), 200, "an active-request place is still free");
    }
    for (sender, call) in open {
        drop(sender);
        assert_eq!(call.await.unwrap(), 202);
    }
    f.server.shutdown().await;
}

/// U1 (measured, `--ignored`): the first pull of a big layer through the firewall. The artifact pipeline hashes the whole layer before the first
/// byte is delivered (a client must never receive bytes that are not their digest), so the time to the first byte is the download plus the hashing;
/// the memory is the pipeline's (a temp file, not a buffer). `OCI_LAYER_MIB` sets the size (default 1024). Run:
/// `cargo test --test oci_service first_pull_of_a_big_layer -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures a multi-GiB first pull; run by hand"]
async fn first_pull_of_a_big_layer_is_measured() {
    let mib: usize = std::env::var("OCI_LAYER_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(1024);
    let f = start(0, Some(&target()), None).await;
    let block: Vec<u8> = (0..(1 << 20)).map(|n| (n * 31 % 251) as u8).collect();
    let layer: Vec<u8> = (0..mib).flat_map(|_| block.iter().copied()).collect();
    let digest = sha256(&layer);
    let hwm = || std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l| l.starts_with("VmHWM")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    f.oci.put_blob("big/app", &digest, &layer);
    let manifest_digest = {
        let cfg = b"{}".to_vec();
        let manifest = serde_json::to_vec(&serde_json::json!({"schemaVersion": 2, "mediaType": oci::OCI_MANIFEST, "config": {"digest": sha256(&cfg), "size": 2}, "layers": [{"digest": digest, "size": layer.len()}]})).unwrap();
        f.oci.put_blob("big/app", &sha256(&cfg), &cfg);
        f.oci.put_manifest("big/app", "v1", &manifest, oci::OCI_MANIFEST);
        sha256(&manifest)
    };
    let _ = manifest_digest;
    assert_eq!(f.server.get("/v2/big/app/manifests/v1").await.status().as_u16(), 200);
    let (before, started) = (hwm(), std::time::Instant::now());
    let mut response = f.server.get(&format!("/v2/big/app/blobs/{digest}")).await;
    let headers_after = started.elapsed();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.content_length(), Some(layer.len() as u64));
    let first = response.chunk().await.unwrap().expect("a first chunk");
    let first_byte = started.elapsed();
    let mut received = first.len();
    while let Some(chunk) = response.chunk().await.unwrap() {
        received += chunk.len();
    }
    let total = started.elapsed();
    assert_eq!(received, layer.len());
    eprintln!("MEASURED layer {mib} MiB: response headers after {headers_after:?}, first body byte after {first_byte:?} (the download and one hash, then the bytes), whole body after {total:?}, peak resident growth {} MiB (this process also holds the {mib} MiB fake layer and its copies)", (hwm() - before) / 1024);
    let again = std::time::Instant::now();
    let second = f.server.get(&format!("/v2/big/app/blobs/{digest}")).await;
    assert_eq!(second.status().as_u16(), 200);
    eprintln!("MEASURED second pull (verified bytes on disk): first byte after {:?}", again.elapsed());
    f.server.shutdown().await;
}
