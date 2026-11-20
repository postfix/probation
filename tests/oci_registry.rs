//! Row 24: OCI distribution protection, end to end through the firewall against an in-process `FakeOci` registry and a clock the
//! test moves by hand. The real client witness is tests/oci_native.rs (podman and, where present, containerd's `ctr`), the shared
//! service forms are tests/oci_service.rs.

mod common;

use std::sync::Arc;

use common::oci::{self, FakeOci, REGISTRY, CDN, image, index_of, sha256};
use common::{TestClock, TestServer, fake_origins, sample_config};
use probation::config::Config;
use probation::upstream::{OriginSet, Transport};
use tempfile::TempDir;
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const DAY: u64 = 86_400;

struct Harness {
    server: TestServer,
    oci: Arc<FakeOci>,
    clock: Arc<TestClock>,
    _dir: TempDir,
}

fn origins() -> OriginSet {
    fake_origins().with_oci(Url::parse(REGISTRY).unwrap(), Url::parse(CDN).unwrap())
}

async fn harness_with(blocked: &str, cooldown: u64, tune: impl FnOnce(&mut Config)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let blocklist_file = dir.path().join("blocklist.json");
    std::fs::write(&blocklist_file, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked)).unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config.cooldown_seconds = cooldown;
    tune(&mut config);
    let oci = FakeOci::new();
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&oci) as Arc<dyn Transport>, origins()).await;
    Harness { server, oci, clock, _dir: dir }
}

async fn harness(blocked: &str, cooldown: u64) -> Harness {
    harness_with(blocked, cooldown, |_| {}).await
}

async fn body_of(h: &Harness, path: &str) -> (u16, Vec<u8>) {
    let response = h.server.get(path).await;
    (response.status().as_u16(), response.bytes().await.unwrap().to_vec())
}

async fn code_of(h: &Harness, path: &str) -> (u16, String) {
    let (status, body) = body_of(h, path).await;
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, doc["errors"][0]["code"].as_str().unwrap_or("").to_owned())
}

fn layer(tag: &str) -> Vec<u8> {
    format!("layer bytes of {tag}").into_bytes().repeat(40)
}

#[tokio::test]
async fn the_ping_is_the_firewalls_own_answer_and_a_path_that_is_no_route_asks_nothing() {
    let h = harness("", 7 * DAY).await;
    for path in ["/v2/", "/v2"] {
        let response = h.server.get(path).await;
        assert_eq!(response.status().as_u16(), 200, "{path}");
        assert_eq!(response.headers().get("docker-distribution-api-version").unwrap(), "registry/2.0");
    }
    for path in ["/v2/Alpine/manifests/latest", "/v2/app/manifests/-bad", "/v2/app/blobs/md5:aaaa", "/v2/app/unknown", "/v2/app/manifests/latest/x"] {
        assert_eq!(h.server.get(path).await.status().as_u16(), 404, "{path}");
    }
    assert!(h.oci.seen().is_empty(), "no registry was asked: {:?}", h.oci.seen());
    h.server.shutdown().await;
}

/// The age of an image is when this firewall first saw its digest. The config's `created` (2001) is the depositor's word and releases
/// nothing; the digest is held for a whole cooldown and then served exactly.
#[tokio::test]
async fn a_young_digest_is_held_whatever_its_config_says_and_is_served_exactly_once_it_has_aged() {
    let h = harness("", 7 * DAY).await;
    let app = image("a", &[&layer("one")]);
    h.oci.put_image("team/app", Some("latest"), &app);
    let held = h.server.get("/v2/team/app/manifests/latest").await;
    assert_eq!(held.status().as_u16(), 403);
    let doc: serde_json::Value = serde_json::from_str(&held.text().await.unwrap()).unwrap();
    assert_eq!(doc["errors"][0]["code"], "DENIED", "{doc}");
    assert!(h.oci.count("/blobs/") == 0, "no blob was asked for");
    h.clock.advance_seconds(6 * DAY as i64);
    assert_eq!(h.server.get("/v2/team/app/manifests/latest").await.status().as_u16(), 403, "still inside the cooldown");
    h.clock.advance_seconds(2 * DAY as i64);
    let served = h.server.get("/v2/team/app/manifests/latest").await;
    assert_eq!(served.status().as_u16(), 200);
    assert_eq!(served.headers().get("docker-content-digest").unwrap().to_str().unwrap(), app.digest);
    assert_eq!(served.headers().get("content-type").unwrap(), oci::OCI_MANIFEST);
    assert_eq!(served.bytes().await.unwrap().to_vec(), app.manifest, "the exact bytes the registry wrote");
    // HEAD runs the same checks and sends no body.
    let head = h.server.head("/v2/team/app/manifests/latest").await;
    assert_eq!(head.status().as_u16(), 200);
    assert_eq!(head.headers().get("content-length").unwrap().to_str().unwrap(), app.manifest.len().to_string());
    h.server.shutdown().await;
}

#[tokio::test]
async fn bytes_that_are_not_the_digest_are_never_served() {
    let h = harness("", 0).await;
    let app = image("a", &[&layer("one")]);
    // The registry answers a DIFFERENT manifest under the digest asked for.
    let other = image("other", &[&layer("two")]);
    h.oci.put_manifest("app", &app.digest, &other.manifest, oci::OCI_MANIFEST);
    assert_eq!(h.server.get(&format!("/v2/app/manifests/{}", app.digest)).await.status().as_u16(), 502);
    // A registry whose Docker-Content-Digest is not the digest of its own bytes is as refused.
    let h2 = harness("", 0).await;
    h2.oci.put_image("app", Some("latest"), &app);
    h2.oci.claim_digest(&sha256(b"something else"));
    assert_eq!(h2.server.get("/v2/app/manifests/latest").await.status().as_u16(), 502);
    h.server.shutdown().await;
    h2.server.shutdown().await;
}

#[tokio::test]
async fn a_blocked_repository_tag_or_digest_is_refused_before_any_registry_is_asked() {
    let app = image("a", &[&layer("one")]);
    let blocked = format!(
        r#"{{"ecosystem":"oci","name":"evil/app","version":null,"reason":"malware"}},{{"ecosystem":"oci","name":"app","version":"bad-tag","reason":"malware"}},{{"ecosystem":"oci","name":"app","version":"{}","reason":"malware"}}"#,
        app.digest
    );
    let h = harness(&blocked, 0).await;
    h.oci.put_image("evil/app", Some("latest"), &app);
    h.oci.put_image("app", Some("bad-tag"), &app);
    for path in ["/v2/evil/app/manifests/latest".to_owned(), "/v2/evil/app/tags/list".to_owned(), format!("/v2/evil/app/blobs/{}", app.config_digest), "/v2/app/manifests/bad-tag".to_owned(), format!("/v2/app/manifests/{}", app.digest), format!("/v2/app/blobs/{}", app.digest)] {
        let (status, code) = code_of(&h, &path).await;
        assert_eq!((status, code.as_str()), (403, "DENIED"), "{path}");
    }
    assert!(h.oci.seen().is_empty(), "nothing was asked: {:?}", h.oci.seen());
    h.server.shutdown().await;
}

#[tokio::test]
async fn an_allowed_image_delivers_its_config_and_layers_verified_and_a_layer_nobody_named_waits_its_own_cooldown() {
    let h = harness("", 7 * DAY).await;
    let app = image("a", &[&layer("one"), &layer("two")]);
    h.oci.put_image("app", Some("v1"), &app);
    assert_eq!(h.server.get("/v2/app/manifests/v1").await.status().as_u16(), 403);
    h.clock.advance_seconds(8 * DAY as i64);
    assert_eq!(h.server.get("/v2/app/manifests/v1").await.status().as_u16(), 200);
    // The children of an allowed manifest take its date: they need no cooldown of their own.
    for (digest, bytes) in std::iter::once((&app.config_digest, &app.config)).chain(app.layer_digests.iter().zip(&app.layers)) {
        let response = h.server.get(&format!("/v2/app/blobs/{digest}")).await;
        assert_eq!(response.status().as_u16(), 200, "{digest}");
        assert_eq!(response.headers().get("docker-content-digest").unwrap().to_str().unwrap(), digest);
        assert_eq!(response.bytes().await.unwrap().to_vec(), *bytes, "{digest}");
    }
    // A range of a verified layer.
    let ranged = h.server.get_with_headers(&format!("/v2/app/blobs/{}", app.layer_digests[0]), &[("range", "bytes=2-9")]).await;
    assert_eq!(ranged.status().as_u16(), 206);
    assert_eq!(ranged.bytes().await.unwrap().to_vec(), app.layers[0][2..10].to_vec());
    // A blob no allowed manifest named is a direct request: its own first-seen time starts its own cooldown.
    let stray = layer("stray");
    h.oci.put_blob("app", &sha256(&stray), &stray);
    assert_eq!(code_of(&h, &format!("/v2/app/blobs/{}", sha256(&stray))).await, (403, "DENIED".into()));
    h.clock.advance_seconds(8 * DAY as i64);
    assert_eq!(body_of(&h, &format!("/v2/app/blobs/{}", sha256(&stray))).await, (200, stray));
    // A digest that exists nowhere makes no row and is a 404.
    assert_eq!(code_of(&h, &format!("/v2/app/blobs/sha256:{}", "7".repeat(64))).await, (404, "BLOB_UNKNOWN".into()));
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_layer_whose_bytes_are_not_its_digest_is_refused() {
    let h = harness("", 0).await;
    let app = image("a", &[&layer("one")]);
    h.oci.put_image("app", Some("v1"), &app);
    h.oci.put_blob("app", &app.layer_digests[0], b"not the layer that was named");
    assert_eq!(h.server.get("/v2/app/manifests/v1").await.status().as_u16(), 200);
    let response = h.server.get(&format!("/v2/app/blobs/{}", app.layer_digests[0])).await;
    // The headers go out at once (U1), so a wrong layer is an aborted connection and never a clean body: no byte of it is released.
    let status = response.status().as_u16();
    let body = response.bytes().await;
    assert!(status != 200 || body.is_err(), "a layer that is not its digest is never a complete 200");
    if let Ok(body) = body {
        assert!(!String::from_utf8_lossy(&body).contains("not the layer"), "no byte of the wrong layer left");
    }
    h.server.shutdown().await;
}

#[tokio::test]
async fn an_index_names_its_children_and_a_tag_that_moves_is_a_new_digest_with_its_own_age() {
    let h = harness("", 7 * DAY).await;
    let amd = image("amd", &[&layer("amd")]);
    let arm = image("arm", &[&layer("arm")]);
    let (index, index_digest) = index_of(&[&amd, &arm]);
    h.oci.put_image("multi", None, &amd);
    h.oci.put_image("multi", None, &arm);
    h.oci.put_manifest("multi", "latest", &index, oci::OCI_INDEX);
    h.oci.put_manifest("multi", &index_digest, &index, oci::OCI_INDEX);
    assert_eq!(h.server.get("/v2/multi/manifests/latest").await.status().as_u16(), 403);
    h.clock.advance_seconds(8 * DAY as i64);
    assert_eq!(body_of(&h, "/v2/multi/manifests/latest").await, (200, index.clone()));
    // Each child is a manifest the index named: dated with it, so allowed now.
    assert_eq!(body_of(&h, &format!("/v2/multi/manifests/{}", amd.digest)).await, (200, amd.manifest.clone()));
    assert_eq!(body_of(&h, &format!("/v2/multi/manifests/{}", arm.digest)).await, (200, arm.manifest.clone()));
    // A manifest no index named is judged by its own first-seen time.
    let lone = image("lone", &[&layer("lone")]);
    h.oci.put_image("multi", None, &lone);
    assert_eq!(h.server.get(&format!("/v2/multi/manifests/{}", lone.digest)).await.status().as_u16(), 403);
    // The tag moves to a new digest: new first-seen, held; the old digest stays servable by name.
    let next = image("next", &[&layer("next")]);
    h.oci.put_image("multi", Some("latest"), &next);
    assert_eq!(h.server.get("/v2/multi/manifests/latest").await.status().as_u16(), 403, "a new digest waits its own cooldown");
    assert_eq!(body_of(&h, &format!("/v2/multi/manifests/{index_digest}")).await, (200, index));
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_tag_list_is_rebuilt_and_its_link_cannot_lead_a_client_off_the_registry_or_the_list() {
    let h = harness(r#"{"ecosystem":"oci","name":"app","version":"bad","reason":"malware"}"#, 0).await;
    h.oci.put_tags("app", &["v1", "v2", "bad", "-x"], Some("<https://oci.invalid/v2/app/tags/list?last=v2&n=2&token=SECRET>; rel=\"next\""));
    let page = h.server.get("/v2/app/tags/list?n=2").await;
    assert_eq!(page.status().as_u16(), 200);
    assert_eq!(page.headers().get("link").unwrap().to_str().unwrap(), "</v2/app/tags/list?last=v2&n=2>; rel=\"next\"", "relative, paging keys only");
    let doc: serde_json::Value = serde_json::from_str(&page.text().await.unwrap()).unwrap();
    assert_eq!(doc["tags"], serde_json::json!(["v1", "v2"]), "a blocked tag and an invalid one are not listed: {doc}");
    assert_eq!(doc["name"], "app");
    // A link to another host, or to another list, is no link.
    for link in ["<https://evil.example/v2/app/tags/list?n=2>; rel=\"next\"", "</v2/other/tags/list?n=2>; rel=\"next\""] {
        h.oci.put_tags("app", &["v1"], Some(link));
        let page = h.server.get("/v2/app/tags/list").await;
        assert!(page.headers().get("link").is_none(), "{link}");
    }
    // A query key the route does not take is no route.
    assert_eq!(h.server.get("/v2/app/tags/list?token=x").await.status().as_u16(), 404);
    h.server.shutdown().await;
}

#[tokio::test]
async fn referrers_and_the_catalog_are_rebuilt_from_what_is_well_formed() {
    let h = harness(r#"{"ecosystem":"oci","name":"secret/app","version":null,"reason":"malware"}"#, 0).await;
    let subject = format!("sha256:{}", "a".repeat(64));
    let good = format!("sha256:{}", "b".repeat(64));
    h.oci.put_referrers("app", &subject, &serde_json::json!({
        "schemaVersion": 2, "mediaType": oci::OCI_INDEX,
        "manifests": [
            {"mediaType": oci::OCI_MANIFEST, "digest": good, "size": 10, "artifactType": "application/vnd.example.sbom", "annotations": {"k": "v"}, "extra": "dropped"},
            {"mediaType": oci::OCI_MANIFEST, "digest": "md5:nope", "size": 1}
        ], "url": "https://evil.example/"}).to_string());
    let (status, body) = body_of(&h, &format!("/v2/app/referrers/{subject}")).await;
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status, 200, "{doc}");
    assert_eq!(doc["manifests"].as_array().unwrap().len(), 1, "{doc}");
    assert!(doc["manifests"][0].get("extra").is_none() && doc.get("url").is_none(), "only what a client reads: {doc}");
    assert_eq!(doc["manifests"][0]["artifactType"], "application/vnd.example.sbom");
    h.oci.put_catalog(r#"{"repositories":["app","secret/app","Bad Name"]}"#, Some("<https://evil.example/v2/_catalog?n=1>; rel=\"next\""));
    let page = h.server.get("/v2/_catalog").await;
    assert!(page.headers().get("link").is_none());
    let doc: serde_json::Value = serde_json::from_str(&page.text().await.unwrap()).unwrap();
    assert_eq!(doc["repositories"], serde_json::json!(["app"]));
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_registrys_token_flow_is_run_by_the_firewall_once_and_the_token_goes_where_it_belongs() {
    let h = harness("", 0).await;
    h.oci.require_token();
    let app = image("a", &[&layer("one")]);
    h.oci.put_image("app", Some("v1"), &app);
    assert_eq!(h.server.get("/v2/app/manifests/v1").await.status().as_u16(), 200, "the anonymous token is the firewall's own business");
    assert_eq!(h.server.get(&format!("/v2/app/blobs/{}", app.config_digest)).await.status().as_u16(), 200);
    assert_eq!(h.server.get("/v2/app/manifests/v1").await.status().as_u16(), 200);
    assert_eq!(h.oci.count("/token"), 1, "one token for the repository's scope, shared");
    let artifacts = h.oci.artifact_requests();
    assert!(artifacts.iter().all(|(_, auth, _, redirect)| auth.as_deref() == Some("Bearer tok-anon") && *redirect), "{artifacts:?}");
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_token_realm_on_another_host_is_never_asked() {
    let h = harness("", 0).await;
    h.oci.require_token();
    h.oci.foreign_realm("https://evil.example/token");
    h.oci.put_image("app", Some("v1"), &image("a", &[&layer("one")]));
    assert_eq!(h.server.get("/v2/app/manifests/v1").await.status().as_u16(), 502);
    assert_eq!(h.oci.count("/token"), 0, "the realm was not asked: {:?}", h.oci.seen());
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_row_bound_is_hard_and_atomic() {
    // A repository holds at most five times max_references_per_project rows: here 5.
    let h = harness_with("", 0, |config| config.max_references_per_project = std::num::NonZeroU32::new(1).unwrap()).await;
    let big = image("big", &[&layer("1"), &layer("2"), &layer("3"), &layer("4"), &layer("5")]);
    h.oci.put_image("bounded", Some("big"), &big);
    assert_eq!(h.server.get("/v2/bounded/manifests/big").await.status().as_u16(), 503, "the manifest and six children do not fit");
    let rows = || async { h.server.app().store().count_project_references_in(0, probation::policy::Ecosystem::Oci, "bounded").await.unwrap() };
    assert_eq!(rows().await, 1, "only the manifest's own row was committed; the children committed nothing");
    // A small image fits.
    let small = image("small", &[&layer("s")]);
    h.oci.put_image("bounded", Some("small"), &small);
    assert_eq!(h.server.get("/v2/bounded/manifests/small").await.status().as_u16(), 200, "three rows more is four");
    assert_eq!(rows().await, 4);
    let third = image("third", &[&layer("t")]);
    h.oci.put_image("bounded", Some("third"), &third);
    assert_eq!(h.server.get("/v2/bounded/manifests/third").await.status().as_u16(), 503, "three more is past five");
    assert_eq!(rows().await, 4 + 1, "the manifest's own row is the one thing committed (it carries the clock); its children committed nothing");
    // An upload session is no read.
    assert_eq!(h.server.get("/v2/app/blobs/uploads/abc").await.status().as_u16(), 405);
    h.server.shutdown().await;
}

fn h_delay(h: &Harness) {
    h.oci.set_delay_ms(100);
}

#[tokio::test]
async fn simultaneous_first_requests_never_overshoot_the_row_bound() {
    let h = harness_with("", 0, |config| config.max_references_per_project = std::num::NonZeroU32::new(2).unwrap()).await;
    let mut joins = Vec::new();
    h_delay(&h);
    for n in 0..24 {
        let app = image(&format!("n{n}"), &[&layer(&format!("n{n}"))]);
        h.oci.put_image("race", Some(&format!("t{n}")), &app);
        let url = h.server.url(&format!("/v2/race/manifests/t{n}"));
        joins.push(tokio::spawn(async move { common::downstream_client().get(url).send().await.unwrap().status().as_u16() }));
    }
    let mut statuses = Vec::new();
    for join in joins {
        statuses.push(join.await.unwrap());
    }
    let rows = h.server.app().store().count_project_references_in(0, probation::policy::Ecosystem::Oci, "race").await.unwrap();
    assert!(rows <= 10, "{rows} rows past the bound of 10: {statuses:?}");
    assert!(statuses.iter().all(|s| matches!(s, 200 | 503)), "{statuses:?}");
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_process_tables_stay_bounded() {
    let h = harness("", 0).await;
    for n in 0..300 {
        let app = image(&format!("t{n}"), &[]);
        h.oci.put_image(&format!("r{n}"), None, &app);
        assert_eq!(h.server.get(&format!("/v2/r{n}/manifests/{}", app.digest)).await.status().as_u16(), 200);
    }
    let sizes = probation::oci::serve::table_sizes(&h.server.app());
    assert!(sizes[5] <= 256, "the manifest memo: {sizes:?}");
    assert!(sizes.iter().all(|size| *size <= 4_096), "{sizes:?}");
    h.server.shutdown().await;
}

#[tokio::test]
async fn an_unreachable_registry_is_a_502_and_a_block_still_answers_locally() {
    let h = harness(r#"{"ecosystem":"oci","name":"evil","version":null,"reason":"malware"}"#, 0).await;
    h.oci.go_offline();
    assert_eq!(h.server.get("/v2/app/manifests/latest").await.status().as_u16(), 502);
    assert_eq!(h.server.get("/v2/evil/manifests/latest").await.status().as_u16(), 403);
    h.server.shutdown().await;
}

/// S24-F1: a firewall that admits by certificate (or has no admission at all) NEVER mints or echoes a registry token: its token endpoint answers its
/// own opaque pull-only token, whatever scopes are asked and whatever the registry is (a Bearer token service, or Basic only) and whatever credential
/// the registry has on file for the caller. Nothing is asked of the registry. (The route's own principal carries the stored credential; this
/// calls the endpoint with a credential in the caller's own header, which a firewall that is not a shared service must not use either.)
#[tokio::test]
async fn a_firewall_that_is_not_a_shared_service_never_mints_or_echoes_a_registry_token() {
    let h = harness(r#"{"ecosystem":"oci","name":"blocked/app","version":null,"reason":"malware"}"#, 0).await;
    for basic_only in [false, true] {
        if basic_only {
            h.oci.basic_only();
        } else {
            h.oci.require_token();
        }
        let app = h.server.app();
        let answer = probation::oci::serve::serve_token(&app, None, 0, "service=x&scope=repository:team/app:pull,push,delete&scope=repository:blocked/app:pull&scope=repository:other/app:*", Some("Basic c3RvcmVkOnNlY3JldA==")).await.unwrap();
        let text = String::from_utf8(answer.to_vec()).unwrap();
        assert!(!text.contains("c3RvcmVkOnNlY3JldA") && !text.contains("tok-"), "no stored credential, no registry token: {text}");
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(doc["token"].as_str().unwrap().starts_with(probation::oci::serve::LOCAL_TOKEN_PREFIX) && doc["token"] != probation::oci::serve::LOCAL_TOKEN_PREFIX, "{doc}");
        assert_eq!(doc["scope"], "repository:team/app:pull", "pull of a repository the policy lets through, nothing else: {doc}");
    }
    assert!(h.oci.seen().is_empty(), "the registry was asked nothing: {:?}", h.oci.seen());
    h.server.shutdown().await;
}

/// A registry whose HEAD says nothing usable (no digest, a zero length) does not make an empty manifest: the GET decides (found by containerd, which reads the
/// HEAD's `Content-Length` as the manifest's size).
#[tokio::test]
async fn a_head_with_no_usable_length_falls_back_to_the_bytes() {
    struct Mute(Arc<FakeOci>);
    #[async_trait::async_trait]
    impl Transport for Mute {
        async fn fetch_metadata(&self, request: probation::upstream::MetadataRequest) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError> {
            self.0.fetch_metadata(request).await
        }
        async fn fetch_oci(&self, request: probation::upstream::OciRequest) -> Result<probation::upstream::OciResponse, probation::upstream::UpstreamError> {
            let head = request.method == axum::http::Method::HEAD;
            let mut answer = self.0.fetch_oci(request).await?;
            if head {
                answer.headers.retain(|(name, _)| *name != "content-length");
                answer.headers.push(("content-length", "0".to_owned()));
            }
            Ok(answer)
        }
        async fn open_artifact(&self, request: probation::upstream::ArtifactRequest) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
            self.0.open_artifact(request).await
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let blocklist_file = dir.path().join("blocklist.json");
    std::fs::write(&blocklist_file, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "")).unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config.cooldown_seconds = 0;
    let oci = FakeOci::new();
    let app = image("a", &[&layer("one")]);
    oci.put_image("pub/app", Some("v1"), &app);
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339(NOW).shared(), Arc::new(Mute(Arc::clone(&oci))) as Arc<dyn Transport>, origins()).await;
    let head = server.head("/v2/pub/app/manifests/v1").await;
    assert_eq!(head.status().as_u16(), 200);
    assert_eq!(head.headers().get("content-length").unwrap().to_str().unwrap(), app.manifest.len().to_string(), "the size of the bytes, not the HEAD's zero");
    assert_eq!(oci.seen().iter().filter(|call| call.path.contains("/manifests/") && call.method == "GET").count(), 1);
    server.shutdown().await;
}

/// R2: a registry whose challenge names a token service on another host (GitLab's registry does) works in a standalone firewall when
/// `oci_token_url` names that host, and only then.
#[tokio::test]
async fn a_token_service_on_another_host_works_when_the_firewall_names_it() {
    for (named, expected) in [(None, 502u16), (Some("https://gitlab.example"), 200), (Some("https://other.example"), 502)] {
        let h = harness_with("", 0, |config| config.oci_token_url = named.map(|text| Url::parse(text).unwrap())).await;
        h.oci.require_token();
        h.oci.foreign_realm("https://gitlab.example/jwt/auth");
        h.oci.put_image("app", Some("v1"), &image("a", &[&layer("one")]));
        assert_eq!(h.server.get("/v2/app/manifests/v1").await.status().as_u16(), expected, "named {named:?}");
        h.server.shutdown().await;
    }
}
