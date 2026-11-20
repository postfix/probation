mod common;

use axum::{
    http::{HeaderMap, Method},
    response::IntoResponse,
};
use common::sync::{FakeSyncServer, PLATFORM, base64, key, org};
use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, config_with_open_blocklist,
    fake_origins, npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
};
use probation::upstream::Transport;
use probation_policy::{
    Block, Ecosystem, Layer, LayerKind, OsvSetting,
    api::{ChangesRequest, Reachability, Upstreams},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

async fn sync_now(server: &TestServer) {
    let app = server.app();
    let managed = app.managed().unwrap();
    let request = ChangesRequest {
        since: managed.sync().cursor(),
        report: managed.report(Upstreams {
            npm: Reachability::Ok,
            pypi: Reachability::Ok,
            osv: Reachability::Ok, rubygems: None, cargo: None, go: None, nuget: None, maven: None, conan: None, oci: None,
        }),
        activity: vec![],
        activity_dropped: vec![],
    };
    managed.sync().fetch_changes(&request).await.unwrap();
    managed.after_answer().await;
}

#[tokio::test]
async fn managed_cold_policy_change_refuses_before_release() {
    let management = FakeSyncServer::start().await;
    management.layer(
        PLATFORM,
        Layer {
            freeze_seconds: Some(0),
            osv: Some(OsvSetting::Off),
            ..Layer::empty(LayerKind::Platform)
        },
    );
    management.layer(org(10), Layer::empty(LayerKind::Org));
    let key = key(1);
    management.known_key(&key, &[PLATFORM, org(10)]);
    let registry = FakeRegistry::new();
    let bytes = "verified package bytes";
    registry.answer(
        &npm_upstream_path("authority-check"),
        FakeAnswer::Body(
            serde_json::json!({
                "name":"authority-check", "dist-tags":{"latest":"1.0.0"},
                "versions":{"1.0.0":{"name":"authority-check","version":"1.0.0","dist":{
                    "tarball":npm_tarball_url("authority-check", "authority-check-1.0.0.tgz"),
                    "integrity":format!("sha256-{}", base64(Sha256::digest(bytes.as_bytes())))
                }}}, "time":{"1.0.0":"2026-01-01T00:00:00Z"}
            })
            .to_string(),
        ),
    );
    let gate = Gate::new();
    registry.answer(
        &npm_artifact_upstream_path("authority-check", "authority-check-1.0.0.tgz"),
        FakeAnswer::Gated {
            head: "verified ".into(),
            tail: "package bytes".into(),
            gate: Arc::clone(&gate),
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let config = management.managed(config_with_open_blocklist(dir.path()));
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        registry as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;
    sync_now(&server).await;
    let url = server.url("/npm/authority-check/-/authority-check-1.0.0.tgz");
    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .get(url)
            .bearer_auth(key)
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.wait_until_reached())
        .await
        .unwrap();
    let revision = management.edit_layer(
        org(10),
        Layer {
            blocks: vec![Block::Package {
                ecosystem: Ecosystem::Npm,
                name: "authority-check".into(),
                reason: None,
            }],
            ..Layer::empty(LayerKind::Org)
        },
    );
    sync_now(&server).await;
    assert!(server.app().managed().unwrap().sync().cursor() >= revision);
    gate.release();
    let response = request.await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(
        !status.is_success(),
        "a deny published before artifact release must govern the request: {body}"
    );
    assert!(
        !body.contains(bytes),
        "zero artifact payload bytes may be released"
    );
}

/// Exercise the public prepare/handoff seam directly so publication happens at
/// precisely that boundary, for both downloaded and already verified files.
async fn prepared_boundary(
    ecosystem: Ecosystem,
    warm: bool,
    action: &str,
    method: Method,
    range: Option<&str>,
) {
    let management = FakeSyncServer::start().await;
    management.layer(
        PLATFORM,
        Layer {
            freeze_seconds: Some(0),
            osv: Some(OsvSetting::Off),
            ..Layer::empty(LayerKind::Platform)
        },
    );
    management.layer(org(10), Layer::empty(LayerKind::Org));
    let key = key(1);
    management.known_key(&key, &[PLATFORM, org(10)]);
    let registry = FakeRegistry::new();
    let bytes = "verified package bytes";
    let (metadata_path, filename) = match ecosystem {
        Ecosystem::Npm => {
            let filename = "authority-check-1.0.0.tgz";
            registry.answer(&npm_upstream_path("authority-check"), FakeAnswer::Body(serde_json::json!({
                "name":"authority-check", "versions":{"1.0.0":{"name":"authority-check","version":"1.0.0","dist":{
                    "tarball":npm_tarball_url("authority-check", filename), "integrity":format!("sha256-{}", base64(Sha256::digest(bytes.as_bytes())))
                }}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}
            }).to_string()));
            registry.answer(
                &npm_artifact_upstream_path("authority-check", filename),
                FakeAnswer::Body(bytes.into()),
            );
            ("/npm/authority-check", filename)
        }
        Ecosystem::PyPi => {
            let filename = "authority_check-1.0.0-py3-none-any.whl";
            registry.answer(&common::pypi_upstream_path("authority-check"), FakeAnswer::Body(serde_json::json!({
                "meta":{"api-version":"1.1"}, "name":"authority-check", "files":[{
                    "filename":filename, "url":format!("https://files.invalid/packages/{filename}"),
                    "hashes":{"sha256":hex::encode(Sha256::digest(bytes.as_bytes()))}, "upload-time":"2026-01-01T00:00:00Z"
                }]
            }).to_string()));
            registry.answer(
                &format!("/packages/{filename}"),
                FakeAnswer::Body(bytes.into()),
            );
            ("/pypi/simple/authority-check/", filename)
        }
        Ecosystem::RubyGems => unreachable!("this matrix loops npm and PyPI only; RubyGems is covered in tests/rubygems_registry.rs"),
        Ecosystem::Cargo => unreachable!("this matrix loops npm and PyPI only; Cargo is covered in tests/cargo_registry.rs"),
        Ecosystem::Go => unreachable!("this matrix loops npm and PyPI only; Go is covered in tests/go_modules.rs"),
        Ecosystem::NuGet => unreachable!("this matrix loops npm and PyPI only; NuGet is covered in tests/nuget_registry.rs"),
        Ecosystem::Maven => unreachable!("this matrix loops npm and PyPI only; Maven is covered in tests/maven_registry.rs"),
        Ecosystem::Conan => unreachable!("this matrix loops npm and PyPI only; Conan is covered in tests/conan_registry.rs"),
        Ecosystem::Oci => unreachable!("this matrix loops npm and PyPI only; OCI is covered in tests/oci_registry.rs"),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = management.managed(config_with_open_blocklist(dir.path()));
    config.metadata_ttl_seconds = 0;
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;
    sync_now(&server).await;
    let bearer = format!("Bearer {key}");
    let listing = server
        .get_with_headers(
            metadata_path,
            &[
                ("authorization", &bearer),
                ("accept", "application/vnd.pypi.simple.v1+json"),
            ],
        )
        .await;
    assert!(listing.status().is_success());
    let listing: serde_json::Value =
        serde_json::from_slice(&listing.bytes().await.unwrap()).unwrap();
    let url = match ecosystem {
        Ecosystem::Npm => &listing["versions"]["1.0.0"]["dist"]["tarball"],
        Ecosystem::PyPi => &listing["files"][0]["url"],
        Ecosystem::RubyGems => unreachable!("this matrix loops npm and PyPI only; RubyGems is covered in tests/rubygems_registry.rs"),
        Ecosystem::Cargo => unreachable!("this matrix loops npm and PyPI only; Cargo is covered in tests/cargo_registry.rs"),
        Ecosystem::Go => unreachable!("this matrix loops npm and PyPI only; Go is covered in tests/go_modules.rs"),
        Ecosystem::NuGet => unreachable!("this matrix loops npm and PyPI only; NuGet is covered in tests/nuget_registry.rs"),
        Ecosystem::Maven => unreachable!("this matrix loops npm and PyPI only; Maven is covered in tests/maven_registry.rs"),
        Ecosystem::Conan => unreachable!("this matrix loops npm and PyPI only; Conan is covered in tests/conan_registry.rs"),
        Ecosystem::Oci => unreachable!("this matrix loops npm and PyPI only; OCI is covered in tests/oci_registry.rs"),
    };
    let url: reqwest::Url = url.as_str().unwrap().parse().unwrap();
    let id =
        probation::store::rows::ReferenceId::parse_hex(url.path().split('/').rev().nth(1).unwrap())
            .unwrap();
    if warm {
        let response = server
            .get_with_headers(url.path(), &[("authorization", &bearer)])
            .await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.text().await.unwrap(), bytes);
    }
    if action.starts_with("http_") {
        // The real route has already selected its principal when metadata pauses.
        // A zero metadata TTL makes the same checkpoint reachable on verified hits.
        let upstream = match ecosystem {
            Ecosystem::Npm => npm_upstream_path("authority-check"),
            Ecosystem::PyPi => common::pypi_upstream_path("authority-check"),
            Ecosystem::RubyGems => unreachable!("this matrix loops npm and PyPI only; RubyGems is covered in tests/rubygems_registry.rs"),
            Ecosystem::Cargo => unreachable!("this matrix loops npm and PyPI only; Cargo is covered in tests/cargo_registry.rs"),
            Ecosystem::Go => unreachable!("this matrix loops npm and PyPI only; Go is covered in tests/go_modules.rs"),
            Ecosystem::NuGet => unreachable!("this matrix loops npm and PyPI only; NuGet is covered in tests/nuget_registry.rs"),
            Ecosystem::Maven => unreachable!("this matrix loops npm and PyPI only; Maven is covered in tests/maven_registry.rs"),
            Ecosystem::Conan => unreachable!("this matrix loops npm and PyPI only; Conan is covered in tests/conan_registry.rs"),
            Ecosystem::Oci => unreachable!("this matrix loops npm and PyPI only; OCI is covered in tests/oci_registry.rs"),
        };
        let raw = match ecosystem {
            Ecosystem::Npm => {
                serde_json::json!({"name":"authority-check","versions":{"1.0.0":{"name":"authority-check","version":"1.0.0","dist":{"tarball":npm_tarball_url("authority-check", filename),"integrity":format!("sha256-{}",base64(Sha256::digest(bytes.as_bytes())))}}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}})
            }
            Ecosystem::PyPi => {
                serde_json::json!({"meta":{"api-version":"1.1"},"name":"authority-check","files":[{"filename":filename,"url":format!("https://files.invalid/packages/{filename}"),"hashes":{"sha256":hex::encode(Sha256::digest(bytes.as_bytes()))},"upload-time":"2026-01-01T00:00:00Z"}]})
            }
            Ecosystem::RubyGems => unreachable!("this matrix loops npm and PyPI only; RubyGems is covered in tests/rubygems_registry.rs"),
            Ecosystem::Cargo => unreachable!("this matrix loops npm and PyPI only; Cargo is covered in tests/cargo_registry.rs"),
            Ecosystem::Go => unreachable!("this matrix loops npm and PyPI only; Go is covered in tests/go_modules.rs"),
            Ecosystem::NuGet => unreachable!("this matrix loops npm and PyPI only; NuGet is covered in tests/nuget_registry.rs"),
            Ecosystem::Maven => unreachable!("this matrix loops npm and PyPI only; Maven is covered in tests/maven_registry.rs"),
            Ecosystem::Conan => unreachable!("this matrix loops npm and PyPI only; Conan is covered in tests/conan_registry.rs"),
            Ecosystem::Oci => unreachable!("this matrix loops npm and PyPI only; OCI is covered in tests/oci_registry.rs"),
        };
        let gate = Gate::new();
        registry.answer(
            &upstream,
            FakeAnswer::GatedMetadata {
                body: raw.to_string(),
                gate: Arc::clone(&gate),
            },
        );
        let request_url = server.url(url.path());
        let request = tokio::spawn(async move {
            reqwest::Client::new()
                .get(request_url)
                .header("authorization", bearer)
                .send()
                .await
                .unwrap()
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), gate.wait_until_reached())
            .await
            .unwrap();
        if action == "http_refusal" {
            management.suspend(org(10));
        } else {
            management.edit_layer(
                org(10),
                Layer {
                    blocks: vec![Block::Package {
                        ecosystem,
                        name: "authority-check".into(),
                        reason: None,
                    }],
                    ..Layer::empty(LayerKind::Org)
                },
            );
        }
        sync_now(&server).await;
        gate.release();
        let response = request.await.unwrap();
        assert!(
            !response.status().is_success(),
            "HTTP {ecosystem:?} warm={warm} {action}"
        );
        assert!(!response.text().await.unwrap().contains(bytes));
        return;
    }
    let app = server.app();
    let mut headers = HeaderMap::new();
    headers.insert("authorization", bearer.parse().unwrap());
    let principal = app
        .managed()
        .unwrap()
        .authenticate(&headers, "127.0.0.1".parse().unwrap())
        .await
        .unwrap();
    assert!(
        probation::artifacts::serve_artifact_in(
            &app,
            Some(&principal),
            ecosystem,
            999,
            id,
            filename,
            &method,
            range
        )
        .await
        .is_err(),
        "registry is part of exact reference binding"
    );
    assert!(
        probation::artifacts::serve_artifact(
            &app,
            Some(&principal),
            ecosystem,
            id,
            "other-file.tgz",
            &method,
            range
        )
        .await
        .is_err(),
        "filename is part of exact reference binding"
    );
    let prepared = probation::artifacts::serve_artifact(
        &app,
        Some(&principal),
        ecosystem,
        id,
        filename,
        &method,
        range,
    )
    .await
    .unwrap();
    let response = if action == "accepted" {
        let response = prepared.into_response();
        management.suspend(org(10));
        sync_now(&server).await;
        response
    } else {
        match action {
            "refusal" => {
                management.suspend(org(10));
                sync_now(&server).await;
            }
            "deny" => {
                management.edit_layer(
                    org(10),
                    Layer {
                        blocks: vec![Block::Package {
                            ecosystem,
                            name: "authority-check".into(),
                            reason: None,
                        }],
                        ..Layer::empty(LayerKind::Org)
                    },
                );
                sync_now(&server).await;
            }
            "unchanged" => sync_now(&server).await,
            "same_revision" => {
                let revision = app.managed().unwrap().sync().cursor();
                management.touch_place(org(10));
                management.set_revision(revision);
                sync_now(&server).await;
            }
            _ => panic!("unknown action"),
        }
        prepared.into_response()
    };
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    if matches!(action, "deny" | "refusal" | "same_revision") {
        assert!(
            !status.is_success(),
            "{ecosystem:?} warm={warm} {action} {method} must govern final handoff"
        );
        assert!(
            !body
                .windows(bytes.len())
                .any(|part| part == bytes.as_bytes())
        );
    } else {
        assert!(
            status.is_success(),
            "{ecosystem:?} warm={warm} {action} {method}"
        );
        assert_eq!(
            body.as_ref(),
            if method == Method::HEAD {
                b"".as_slice()
            } else if range.is_some() {
                b"verified".as_slice()
            } else {
                bytes.as_bytes()
            }
        );
    }
}

#[tokio::test]
async fn managed_http_cold_and_warm_changes_refuse_for_both_ecosystems() {
    for ecosystem in [Ecosystem::Npm, Ecosystem::PyPi] {
        for warm in [false, true] {
            for action in ["http_deny", "http_refusal"] {
                prepared_boundary(ecosystem, warm, action, Method::GET, None).await;
            }
        }
    }
}

#[tokio::test]
async fn same_revision_authority_payload_invalidates_prepared_response() {
    prepared_boundary(Ecosystem::Npm, true, "same_revision", Method::GET, None).await;
}

#[tokio::test]
async fn cold_and_warm_current_authority_applies_to_head_range_and_get() {
    for ecosystem in [Ecosystem::Npm, Ecosystem::PyPi] {
        for warm in [false, true] {
            for action in ["deny", "refusal", "unchanged"] {
                for (method, range) in [
                    (Method::GET, None),
                    (Method::HEAD, None),
                    (Method::GET, Some("bytes=0-7")),
                ] {
                    prepared_boundary(ecosystem, warm, action, method, range).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn accepted_stream_survives_later_authority_refusal_for_both_ecosystems() {
    for ecosystem in [Ecosystem::Npm, Ecosystem::PyPi] {
        for warm in [false, true] {
            prepared_boundary(ecosystem, warm, "accepted", Method::GET, None).await;
        }
    }
}

// ---- Slice 28 row: FIX-16-A cases on the common (login-free) service route ----

/// A deny published and confirmed locally while a cold artifact request is still in flight
/// on the common route (`/npm/...`, no selected-registry prefix) governs that request: it
/// refuses, zero payload bytes. The unchanged control delivers the exact bytes.
#[tokio::test]
async fn common_route_policy_change_refuses_before_release() {
    use probation::config::{FirewallToken, ServicePolicyConfig};
    use probation_policy::api::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};
    for deny in [true, false] {
        let places = [probation_policy::PlaceRef { kind: LayerKind::Platform, id: 1 }, probation_policy::PlaceRef { kind: LayerKind::Org, id: 10 }];
        let snapshot = |revision: u64, blocked: bool| ServicePolicySnapshot {
            version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision,
            place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
            layers: places.iter().map(|place| PlaceLayer {
                place: *place,
                layer: Layer {
                    freeze_seconds: Some(0), osv: Some(OsvSetting::Off),
                    blocks: if blocked && place.kind == LayerKind::Org { vec![Block::Package { ecosystem: Ecosystem::Npm, name: "common-race".into(), reason: None }] } else { vec![] },
                    ..Layer::empty(place.kind)
                },
                revision: 1,
            }).collect(),
            rate_limit: None, rate_limit_source: LimitSource::Default,
            registries: vec![RegistryDescriptor {
                registry: RegistryId(3), ecosystem: Ecosystem::Npm, target_url: None, trusted: false,
                registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None, token_origin: None,
            }],
        };
        let policy_server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot(1, false))).mount(&policy_server).await;
        let bytes = "common route bytes";
        let registry = FakeRegistry::new();
        let raw = serde_json::json!({
            "name":"common-race", "dist-tags":{"latest":"1.0.0"},
            "versions":{"1.0.0":{"name":"common-race","version":"1.0.0","dist":{
                "tarball": npm_tarball_url("common-race", "common-race-1.0.0.tgz"),
                "integrity": format!("sha256-{}", base64(Sha256::digest(bytes.as_bytes())))}}},
            "time":{"1.0.0":"2026-01-01T00:00:00Z"}
        }).to_string();
        registry.answer(&npm_upstream_path("common-race"), FakeAnswer::Body(raw.clone()));
        registry.answer(&npm_artifact_upstream_path("common-race", "common-race-1.0.0.tgz"), FakeAnswer::Body(bytes.into()));
        let gate = Gate::new();
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_with_open_blocklist(dir.path());
        config.service_policy = Some(ServicePolicyConfig {
            server_url: policy_server.uri().parse().unwrap(),
            service_key_file: "/test/key".into(),
            service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
            sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
            trusted_proxies: vec![],
        });
        let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), Arc::clone(&registry) as Arc<dyn Transport>, fake_origins()).await;
        // The common route: `/npm/{package}` names the only npm registry; its tarball URL
        // carries the selected prefix, so address the artifact through the common root.
        let document: serde_json::Value = serde_json::from_str(&server.get("/npm/common-race").await.text().await.unwrap()).unwrap();
        let tarball = reqwest::Url::parse(document["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap()).unwrap().path().to_owned();
        // The artifact request revalidates its project upstream; hold that revalidation.
        registry.answer(&npm_upstream_path("common-race"), FakeAnswer::GatedMetadata { body: raw, gate: Arc::clone(&gate) });
        let url = server.url(&tarball);
        let request = tokio::spawn(async move { reqwest::get(url).await.unwrap() });
        tokio::time::timeout(std::time::Duration::from_secs(5), gate.wait_until_reached()).await.unwrap();
        policy_server.reset().await;
        let published = if deny { snapshot(2, true) } else { snapshot(1, false) };
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(published)).mount(&policy_server).await;
        server.app().service_policy().unwrap().sync_once().await.unwrap();
        gate.release();
        let response = request.await.unwrap();
        if deny {
            assert!(!response.status().is_success(), "the deny published before release governs the request");
            assert!(!response.text().await.unwrap().contains(bytes), "zero payload bytes");
        } else {
            assert_eq!(response.text().await.unwrap(), bytes, "an unchanged policy delivers the exact bytes");
        }
        server.shutdown().await;
    }
}
