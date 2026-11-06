mod common;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins,
    npm_upstream_path,
};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{
    ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, Transport, UpstreamError,
};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use std::{num::NonZeroU64, sync::Arc};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct ReadTrace {
    artifact: bool,
    url: reqwest::Url,
    authorization: Option<String>,
}

struct CredentialRegistry(Arc<FakeRegistry>, std::sync::Mutex<Vec<ReadTrace>>);

#[async_trait::async_trait]
impl Transport for CredentialRegistry {
    async fn fetch_token_packument(
        &self,
        mut request: MetadataRequest,
        authorization: &str,
    ) -> Result<MetadataResponse, UpstreamError> {
        request.read_authorization = Some(authorization.to_owned());
        self.fetch_metadata(request).await
    }

    async fn fetch_metadata(
        &self,
        request: MetadataRequest,
    ) -> Result<MetadataResponse, UpstreamError> {
        self.1.lock().unwrap().push(ReadTrace {
            artifact: false,
            url: request.url.clone(),
            authorization: request.read_authorization.clone(),
        });
        if request.read_authorization.as_deref() == Some("Bearer denied") {
            return Err(UpstreamError::Status(403));
        }
        if request.url.path().contains("private-only")
            && request.read_authorization.as_deref() != Some("Bearer allowed")
        {
            return Err(UpstreamError::Status(403));
        }
        self.0.fetch_metadata(request).await
    }
    async fn open_artifact(&self, request: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        self.1.lock().unwrap().push(ReadTrace {
            artifact: true,
            url: request.url.clone(),
            authorization: request.read_authorization.clone(),
        });
        self.0.open_artifact(request).await
    }
}

fn policy_snapshot() -> ServicePolicySnapshot {
    let places = [
        PlaceRef {
            kind: LayerKind::Platform,
            id: 1,
        },
        PlaceRef {
            kind: LayerKind::Org,
            id: 10,
        },
    ];
    ServicePolicySnapshot {
        version: 1,
        key_id: KeyId(7),
        org: OrgId(10),
        account: places[1],
        revision: 1,
        place_chain: places
            .iter()
            .map(|place| ChainLink {
                place: *place,
                layer_revision: 1,
            })
            .collect(),
        layers: places
            .iter()
            .map(|place| PlaceLayer {
                place: *place,
                layer: Layer {
                    freeze_seconds: Some(0),
                    osv: Some(OsvSetting::Off),
                    ..Layer::empty(place.kind)
                },
                revision: 1,
            })
            .collect(),
        rate_limit: None,
        rate_limit_source: LimitSource::Default,
        registries: vec![
            RegistryDescriptor {
                registry: RegistryId(3),
                ecosystem: probation_policy::Ecosystem::Npm,
                target_url: None,
                trusted: false,
                registry_private_cidrs: vec![],
                deletion_scopes: vec![],
            },
            RegistryDescriptor {
                registry: RegistryId(4),
                ecosystem: probation_policy::Ecosystem::PyPi,
                target_url: None,
                trusted: false,
                registry_private_cidrs: vec![],
                deletion_scopes: vec![],
            },
        ],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_service_final_handoff_orders_publication() {
    use axum::{http::Method, response::IntoResponse};
    use probation_policy::{Block, Ecosystem};
    for ecosystem in [Ecosystem::Npm, Ecosystem::PyPi] {
        for warm in [false, true] {
            for action in ["deny_get", "deny_head", "deny_range", "refusal", "accepted"] {
                let policy_server = MockServer::start().await;
                let mut snapshot = policy_snapshot();
                Mock::given(wiremock::matchers::method("GET"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(snapshot.clone()))
                    .mount(&policy_server)
                    .await;
                let registry = FakeRegistry::new();
                let bytes = "verified final service bytes";
                let (registry_id, listing_path, filename, raw, upstream, artifact_upstream) =
                    match ecosystem {
                        Ecosystem::Npm => (
                            3,
                            "/registry/npm/3/final-package",
                            "final-package-1.0.0.tgz",
                            serde_json::json!({"name":"final-package","versions":{"1.0.0":{"name":"final-package","version":"1.0.0","dist":{"tarball":common::npm_tarball_url("final-package","final-package-1.0.0.tgz"),"integrity":format!("sha256-{}",common::sync::base64(Sha256::digest(bytes.as_bytes())))}}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}}),
                            npm_upstream_path("final-package"),
                            common::npm_artifact_upstream_path(
                                "final-package",
                                "final-package-1.0.0.tgz",
                            ),
                        ),
                        Ecosystem::PyPi => (
                            4,
                            "/registry/pypi/4/simple/final-package/",
                            "final_package-1.0.0-py3-none-any.whl",
                            serde_json::json!({"meta":{"api-version":"1.1"},"name":"final-package","files":[{"filename":"final_package-1.0.0-py3-none-any.whl","url":"https://files.invalid/packages/final_package-1.0.0-py3-none-any.whl","hashes":{"sha256":hex::encode(Sha256::digest(bytes.as_bytes()))},"upload-time":"2026-01-01T00:00:00Z"}]}),
                            common::pypi_upstream_path("final-package"),
                            "/packages/final_package-1.0.0-py3-none-any.whl".into(),
                        ),
                    };
                registry.answer(&upstream, FakeAnswer::Body(raw.to_string()));
                registry.answer(&artifact_upstream, FakeAnswer::Body(bytes.into()));
                let dir = tempfile::tempdir().unwrap();
                let mut config = config_with_open_blocklist(dir.path());
                config.service_policy = Some(ServicePolicyConfig {
                    server_url: policy_server.uri().parse().unwrap(),
                    service_key_file: "/test/key".into(),
                    service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
                    sync_interval_seconds: NonZeroU64::new(60).unwrap(),
                });
                let server = TestServer::start_with_upstream(
                    config,
                    TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
                    registry as Arc<dyn Transport>,
                    fake_origins(),
                )
                .await;
                let listing = server
                    .get_with_headers(
                        listing_path,
                        &[("accept", "application/vnd.pypi.simple.v1+json")],
                    )
                    .await;
                assert!(listing.status().is_success());
                let listing: serde_json::Value =
                    serde_json::from_slice(&listing.bytes().await.unwrap()).unwrap();
                let url = if ecosystem == Ecosystem::Npm {
                    &listing["versions"]["1.0.0"]["dist"]["tarball"]
                } else {
                    &listing["files"][0]["url"]
                };
                let url: reqwest::Url = url.as_str().unwrap().parse().unwrap();
                let id = probation::store::rows::ReferenceId::parse_hex(
                    url.path().split('/').rev().nth(1).unwrap(),
                )
                .unwrap();
                if warm {
                    let response = server.get(url.path()).await;
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(response.text().await.unwrap(), bytes);
                }
                let method = if action == "deny_head" {
                    Method::HEAD
                } else {
                    Method::GET
                };
                let range = (action == "deny_range").then_some("bytes=0-7");
                let app = server.app();
                let principal = app
                    .service_policy()
                    .unwrap()
                    .principal(RegistryId(registry_id), ecosystem)
                    .unwrap();
                let mut prepared = Some(
                    probation::artifacts::serve_artifact_in(
                        &app,
                        Some(&principal),
                        ecosystem,
                        registry_id,
                        id,
                        filename,
                        &method,
                        range,
                    )
                    .await
                    .unwrap(),
                );
                let accepted =
                    (action == "accepted").then(|| prepared.take().unwrap().into_response());
                policy_server.reset().await;
                if action == "refusal" {
                    Mock::given(wiremock::matchers::method("GET"))
                        .respond_with(ResponseTemplate::new(401))
                        .mount(&policy_server)
                        .await;
                } else {
                    snapshot.revision += 1;
                    snapshot.place_chain[1].layer_revision += 1;
                    snapshot.layers[1].revision += 1;
                    snapshot.layers[1].layer.blocks.push(Block::Package {
                        ecosystem,
                        name: "final-package".into(),
                        reason: None,
                    });
                    Mock::given(wiremock::matchers::method("GET"))
                        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot))
                        .mount(&policy_server)
                        .await;
                }
                let publishing_app = Arc::clone(&app);
                let refused = action == "refusal";
                tokio::task::spawn_blocking(move || {
                    let result = tokio::runtime::Handle::current()
                        .block_on(publishing_app.service_policy().unwrap().sync_once());
                    assert_eq!(result.is_err(), refused);
                })
                .await
                .unwrap();
                let response = accepted.unwrap_or_else(|| prepared.take().unwrap().into_response());
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                if action == "accepted" {
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(
                        &body[..],
                        bytes.as_bytes(),
                        "accepted stream survives later publication"
                    );
                } else {
                    assert!(
                        !status.is_success(),
                        "{ecosystem:?} warm={warm} {action} must refuse final handoff"
                    );
                    assert!(
                        !String::from_utf8_lossy(&body).contains("verified"),
                        "no artifact bytes before authorization"
                    );
                }
                let next = server.get(url.path()).await;
                assert!(
                    !next.status().is_success(),
                    "next request observes publication after accepted stream"
                );
                assert!(!next.text().await.unwrap().contains(bytes));
            }
        }
    }
}

#[tokio::test]
async fn shared_raw_scoped_tarball_preserves_selected_registry() {
    let policy_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_snapshot()))
        .mount(&policy_server)
        .await;
    let registry = FakeRegistry::new();
    let bytes = "verified scoped package bytes";
    registry.answer(&npm_upstream_path("@scope/pkg"), FakeAnswer::Body(serde_json::json!({
        "name":"@scope/pkg", "versions":{"1.0.0":{"name":"@scope/pkg","version":"1.0.0","dist":{
            "tarball":common::npm_tarball_url("@scope/pkg", "pkg-1.0.0.tgz"),
            "integrity":format!("sha256-{}",common::sync::base64(Sha256::digest(bytes.as_bytes())))
        }}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    registry.answer(
        &common::npm_artifact_upstream_path("@scope/pkg", "pkg-1.0.0.tgz"),
        FakeAnswer::Body(bytes.into()),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy_server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
    });
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;
    for path in [
        "/npm/@scope/pkg/-/pkg-1.0.0.tgz",
        "/registry/npm/3/@scope/pkg/-/pkg-1.0.0.tgz",
    ] {
        let response = server.get(path).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "raw scoped lockfile tarball must be served: {path}"
        );
        assert_eq!(response.text().await.unwrap(), bytes);
        let response = reqwest::Client::new()
            .head(server.url(path))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.bytes().await.unwrap().is_empty());
    }
    let before = registry.calls().len();
    assert_eq!(
        server
            .get("/registry/npm/999/@scope/pkg/-/pkg-1.0.0.tgz")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        registry.calls().len(),
        before,
        "foreign registry cannot fall back to the configured alias"
    );
}

#[tokio::test]
async fn shared_http_cold_warm_selected_and_legacy_authority_changes() {
    use probation_policy::{Block, Ecosystem};
    for ecosystem in [Ecosystem::Npm, Ecosystem::PyPi] {
        for warm in [false, true] {
            for change in ["deny", "refusal", "rate", "unchanged"] {
                let refused = change == "refusal";
                for alias in [false, true] {
                    let policy_server = MockServer::start().await;
                    let snapshot = policy_snapshot();
                    Mock::given(method("GET"))
                        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot.clone()))
                        .mount(&policy_server)
                        .await;
                    let registry = FakeRegistry::new();
                    let bytes = "verified race bytes";
                    let (upstream, metadata_path, raw, artifact_upstream) = match ecosystem {
                        Ecosystem::Npm => (
                            common::npm_upstream_path("race-package"),
                            "/registry/npm/3/race-package",
                            serde_json::json!({
                                "name":"race-package", "versions":{"1.0.0":{"name":"race-package","version":"1.0.0","dist":{"tarball":common::npm_tarball_url("race-package", "race-package-1.0.0.tgz"),"integrity":format!("sha256-{}",common::sync::base64(Sha256::digest(bytes.as_bytes())))}}}, "time":{"1.0.0":"2026-01-01T00:00:00Z"}
                            }),
                            common::npm_artifact_upstream_path(
                                "race-package",
                                "race-package-1.0.0.tgz",
                            ),
                        ),
                        Ecosystem::PyPi => (
                            common::pypi_upstream_path("race-package"),
                            "/registry/pypi/4/simple/race-package/",
                            serde_json::json!({
                                "meta":{"api-version":"1.1"},"name":"race-package","files":[{"filename":"race_package-1.0.0-py3-none-any.whl","url":"https://files.invalid/packages/race_package-1.0.0-py3-none-any.whl","hashes":{"sha256":hex::encode(Sha256::digest(bytes.as_bytes()))},"upload-time":"2026-01-01T00:00:00Z"}]
                            }),
                            "/packages/race_package-1.0.0-py3-none-any.whl".into(),
                        ),
                    };
                    registry.answer(&upstream, FakeAnswer::Body(raw.to_string()));
                    registry.answer(&artifact_upstream, FakeAnswer::Body(bytes.into()));
                    let dir = tempfile::tempdir().unwrap();
                    let mut config = config_with_open_blocklist(dir.path());
                    config.service_policy = Some(ServicePolicyConfig {
                        server_url: policy_server.uri().parse().unwrap(),
                        service_key_file: "/test/key".into(),
                        service_key: FirewallToken::new(
                            "prb_01234567890123456789012345678901".into(),
                        ),
                        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
                    });
                    let server = TestServer::start_with_upstream(
                        config,
                        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
                        Arc::clone(&registry) as Arc<dyn Transport>,
                        fake_origins(),
                    )
                    .await;
                    let response = server
                        .get_with_headers(
                            metadata_path,
                            &[("accept", "application/vnd.pypi.simple.v1+json")],
                        )
                        .await;
                    assert!(response.status().is_success());
                    let listing: serde_json::Value =
                        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
                    let artifact = match ecosystem {
                        Ecosystem::Npm => &listing["versions"]["1.0.0"]["dist"]["tarball"],
                        Ecosystem::PyPi => &listing["files"][0]["url"],
                    };
                    let mut artifact_path = reqwest::Url::parse(artifact.as_str().unwrap())
                        .unwrap()
                        .path()
                        .to_owned();
                    if alias {
                        artifact_path = artifact_path
                            .replace("/registry/npm/3/", "/npm/")
                            .replace("/registry/pypi/4/", "/pypi/");
                    }
                    if warm {
                        assert_eq!(
                            server.get(&artifact_path).await.text().await.unwrap(),
                            bytes
                        );
                    }
                    let gate = common::Gate::new();
                    registry.answer(
                        &upstream,
                        FakeAnswer::GatedMetadata {
                            body: raw.to_string(),
                            gate: Arc::clone(&gate),
                        },
                    );
                    let url = server.url(&artifact_path);
                    let request = tokio::spawn(async move { reqwest::get(url).await.unwrap() });
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        gate.wait_until_reached(),
                    )
                    .await
                    .unwrap();
                    policy_server.reset().await;
                    if refused {
                        Mock::given(method("GET"))
                            .respond_with(ResponseTemplate::new(401))
                            .mount(&policy_server)
                            .await;
                    } else {
                        let mut denied = snapshot;
                        if change == "rate" {
                            denied.rate_limit = std::num::NonZeroU32::new(1);
                        } else if change == "deny" {
                            denied.layers[1].layer.blocks = vec![Block::Package {
                                ecosystem,
                                name: "race-package".into(),
                                reason: None,
                            }];
                        }
                        Mock::given(method("GET"))
                            .respond_with(ResponseTemplate::new(200).set_body_json(denied))
                            .mount(&policy_server)
                            .await;
                    }
                    let synchronized = server.app().service_policy().unwrap().sync_once().await;
                    assert_eq!(synchronized.is_err(), refused);
                    gate.release();
                    let response = request.await.unwrap();
                    if change == "rate" {
                        if !response.status().is_success() {
                            assert_eq!(
                                server.get(&artifact_path).await.status(),
                                StatusCode::OK,
                                "a refused old-generation request did not consume the new budget"
                            );
                        }
                        assert_eq!(
                            server.get(&artifact_path).await.status(),
                            StatusCode::TOO_MANY_REQUESTS,
                            "a request served under the new generation must consume its new account budget"
                        );
                    } else if change == "unchanged" {
                        assert_eq!(
                            response.status(),
                            StatusCode::OK,
                            "an identical full poll does not revoke in-flight authority"
                        );
                        assert_eq!(response.text().await.unwrap(), bytes);
                    } else {
                        assert!(
                            !response.status().is_success(),
                            "{ecosystem:?} warm={warm} refusal={refused} alias={alias}"
                        );
                        assert!(!response.text().await.unwrap().contains(bytes));
                    }
                    server.shutdown().await;
                }
            }
        }
    }
}

#[tokio::test]
async fn shared_service_applies_one_policy_without_downstream_login() {
    let policy_server = MockServer::start().await;
    let snapshot = policy_snapshot();
    Mock::given(method("GET"))
        .and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot.clone()))
        .mount(&policy_server)
        .await;
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path("left-pad"), FakeAnswer::Body(serde_json::json!({
        "name":"left-pad", "dist-tags":{"latest":"1.0.0"},
        "versions":{"1.0.0":{"name":"left-pad","version":"1.0.0","dist":{"tarball":"https://npm.invalid/left-pad/-/left-pad-1.0.0.tgz", "integrity":format!("sha256-{}", common::sync::base64(Sha256::digest(b"verified package bytes")))}}},
        "time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    registry.answer(
        &common::npm_artifact_upstream_path("left-pad", "left-pad-1.0.0.tgz"),
        FakeAnswer::Body("verified package bytes".into()),
    );
    registry.answer(&common::pypi_upstream_path("friendly-bard"), FakeAnswer::Body(serde_json::json!({
        "meta":{"api-version":"1.1"}, "name":"friendly-bard", "files":[{
            "filename":"friendly_bard-1.0.0-py3-none-any.whl", "url":"https://files.invalid/packages/friendly_bard-1.0.0-py3-none-any.whl",
            "hashes":{"sha256":hex::encode(Sha256::digest(b"verified wheel bytes"))}, "upload-time":"2026-01-01T00:00:00Z"
        }]
    }).to_string()));
    registry.answer(
        "/packages/friendly_bard-1.0.0-py3-none-any.whl",
        FakeAnswer::Body("verified wheel bytes".into()),
    );
    registry.answer(&common::npm_upstream_path("private-only"), FakeAnswer::Body(serde_json::json!({
        "name":"private-only", "versions":{"1.0.0":{"name":"private-only","version":"1.0.0","dist":{"tarball":common::npm_tarball_url("private-only", "private-only-1.0.0.tgz"),"integrity":format!("sha256-{}",common::sync::base64(Sha256::digest(b"private verified bytes")))}}}, "time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    registry.answer(
        &common::npm_artifact_upstream_path("private-only", "private-only-1.0.0.tgz"),
        FakeAnswer::Body("private verified bytes".into()),
    );
    registry.answer(&common::pypi_upstream_path("private-only"), FakeAnswer::Body(serde_json::json!({
        "meta":{"api-version":"1.1"},"name":"private-only","files":[{"filename":"private_only-1.0.0-py3-none-any.whl","url":"https://files.invalid/packages/private_only-1.0.0-py3-none-any.whl","hashes":{"sha256":hex::encode(Sha256::digest(b"private verified bytes"))},"upload-time":"2026-01-01T00:00:00Z"}]
    }).to_string()));
    registry.answer(
        "/packages/private_only-1.0.0-py3-none-any.whl",
        FakeAnswer::Body("private verified bytes".into()),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy_server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
    });
    let transport = Arc::new(CredentialRegistry(
        registry,
        std::sync::Mutex::new(Vec::new()),
    ));
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        Arc::clone(&transport) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;
    let response = server.get("/registry/npm/3/left-pad").await;
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "shared service reads do not require a member certificate: {body}; policy loaded: {}",
        server.app().service_policy().unwrap().snapshot().is_some()
    );
    assert!(body.contains("1.0.0"));
    let document: serde_json::Value = serde_json::from_str(&body).unwrap();
    let artifact = document["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    let artifact_path = reqwest::Url::parse(artifact).unwrap().path().to_owned();
    assert!(!body.contains("prb_"));
    assert_eq!(
        server.get("/registry/npm/999/left-pad").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        reqwest::Client::new()
            .put(server.url("/registry/npm/3/left-pad"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let before_delete = transport.0.calls().len();
    for (path, expected) in [
        ("/registry/npm/3/left-pad/-/left-pad-1.0.0.tgz".to_owned(), StatusCode::METHOD_NOT_ALLOWED),
        ("/registry/npm/3/left-pad/-rev/1-old".to_owned(), StatusCode::UNAUTHORIZED),
        (format!("{artifact_path}/-rev/1-old"), StatusCode::UNAUTHORIZED),
    ] {
        assert_eq!(
            reqwest::Client::new()
                .delete(server.url(&path))
                .send()
                .await
                .unwrap()
                .status(),
            expected,
            "direct tarball DELETE refuses and named DELETEs require developer authorization"
        );
    }
    assert_eq!(
        transport.0.calls().len(),
        before_delete,
        "refused and unauthenticated DELETE categories perform no upstream I/O"
    );
    assert_eq!(
        server
            .get_with_headers(
                "/registry/npm/3/left-pad",
                &[("authorization", "Bearer allowed")]
            )
            .await
            .status(),
        StatusCode::OK
    );
    let response = server
        .get_with_headers(&artifact_path, &[("authorization", "Bearer allowed")])
        .await;
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "allowed credential must fetch selected artifact: {body}"
    );
    assert_eq!(body, "verified package bytes");
    assert_eq!(
        server
            .get_with_headers(&artifact_path, &[("authorization", "Bearer denied")])
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "warm artifacts must reauthorize the caller upstream"
    );
    assert_eq!(
        server
            .get_with_headers(
                &artifact_path,
                &[("range", "bytes=0-7"), ("authorization", "Bearer allowed")]
            )
            .await
            .text()
            .await
            .unwrap(),
        "verified"
    );
    assert_eq!(server.head(&artifact_path).await.status(), StatusCode::OK);
    assert_eq!(
        server
            .get(&artifact_path.replacen("/npm/3/", "/npm/999/", 1))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(server.get("/npm/left-pad").await.status(), StatusCode::OK);
    let response = server
        .get_with_headers(
            "/registry/pypi/4/simple/friendly-bard/",
            &[
                ("accept", "application/vnd.pypi.simple.v1+json"),
                ("authorization", "Bearer allowed"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let document: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let wheel = reqwest::Url::parse(document["files"][0]["url"].as_str().unwrap())
        .unwrap()
        .path()
        .to_owned();
    assert_eq!(
        server
            .get_with_headers(&wheel, &[("authorization", "Bearer allowed")])
            .await
            .text()
            .await
            .unwrap(),
        "verified wheel bytes"
    );
    assert_eq!(
        server
            .get_with_headers(&wheel, &[("authorization", "Bearer denied")])
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .get_with_headers(&wheel, &[("range", "bytes=0-7")])
            .await
            .text()
            .await
            .unwrap(),
        "verified"
    );
    assert_eq!(server.head(&wheel).await.status(), StatusCode::OK);
    assert_eq!(
        server.get("/pypi/simple/friendly-bard/").await.status(),
        StatusCode::OK
    );
    for (path, npm) in [
        ("/registry/npm/3/private-only", true),
        ("/registry/pypi/4/simple/private-only/", false),
    ] {
        assert_eq!(
            server.get(path).await.status(),
            StatusCode::FORBIDDEN,
            "private metadata requires upstream credentials"
        );
        let response = server
            .get_with_headers(
                path,
                &[
                    ("authorization", "Bearer allowed"),
                    ("accept", "application/vnd.pypi.simple.v1+json"),
                ],
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let document: serde_json::Value =
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let url = if npm {
            &document["versions"]["1.0.0"]["dist"]["tarball"]
        } else {
            &document["files"][0]["url"]
        };
        let path = reqwest::Url::parse(url.as_str().unwrap())
            .unwrap()
            .path()
            .to_owned();
        assert_eq!(
            server
                .get_with_headers(&path, &[("authorization", "Bearer allowed")])
                .await
                .text()
                .await
                .unwrap(),
            "private verified bytes"
        );
        assert_eq!(
            server.get(&path).await.status(),
            StatusCode::FORBIDDEN,
            "anonymous request cannot reuse private verified bytes"
        );
        assert_eq!(
            server
                .get_with_headers(&path, &[("authorization", "Bearer other")])
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "a second credential cannot reuse private verified bytes"
        );
        let (registry, ecosystem) = if npm {
            (3, probation_policy::Ecosystem::Npm)
        } else {
            (4, probation_policy::Ecosystem::PyPi)
        };
        assert!(
            server
                .app()
                .store()
                .get_project_in(registry, ecosystem, "private-only")
                .await
                .unwrap()
                .is_none()
        );
        let project =
            probation::store::cache::ProjectKey::in_registry(registry, ecosystem, "private-only");
        assert!(
            server
                .app()
                .store()
                .caches()
                .projects
                .get(&project)
                .is_none()
        );
    }
    assert_eq!(
        server
            .get_with_headers(
                "/registry/npm/3/left-pad",
                &[("authorization", "Bearer denied")]
            )
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "a cached public/allowed read cannot authorize a denied upstream credential"
    );
    assert!(
        transport
            .1
            .lock()
            .unwrap()
            .iter()
            .any(|value| value.authorization.as_deref() == Some("Bearer allowed"))
    );
    assert!(
        !transport
            .1
            .lock()
            .unwrap()
            .iter()
            .filter_map(|value| value.authorization.as_ref())
            .any(|value| value.contains("prb_"))
    );
    transport.0.answer(&npm_upstream_path("extra-origin"), FakeAnswer::Body(serde_json::json!({
        "name":"extra-origin","versions":{"1.0.0":{"name":"extra-origin","version":"1.0.0","dist":{
            "tarball":"https://files.invalid/packages/npm-extra-origin.tgz",
            "integrity":format!("sha256-{}", common::sync::base64(Sha256::digest(b"extra origin")))
        }}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    assert!(
        !server
            .get_with_headers(
                "/registry/npm/3/extra-origin/-/npm-extra-origin.tgz",
                &[("authorization", "Bearer allowed")]
            )
            .await
            .status()
            .is_success()
    );
    {
        let traces = transport.1.lock().unwrap();
        assert!(
            !traces
                .iter()
                .any(|trace| trace.artifact && trace.url.path().ends_with("npm-extra-origin.tgz")),
            "npm extra-origin artifact is refused before any credential-bearing transfer"
        );
        for host in ["npm.invalid", "pypi.invalid"] {
            assert!(
                traces.iter().any(|trace| !trace.artifact
                    && trace.url.host_str() == Some(host)
                    && trace.authorization.as_deref() == Some("Bearer allowed")),
                "selected metadata origin receives its credential: {host}"
            );
        }
        assert!(
            traces.iter().any(|trace| trace.artifact
                && trace.url.host_str() == Some("npm.invalid")
                && trace.authorization.as_deref() == Some("Bearer allowed")),
            "selected npm artifact origin retains registry authentication"
        );
        let extra: Vec<_> = traces
            .iter()
            .filter(|trace| trace.artifact && trace.url.host_str() == Some("files.invalid"))
            .collect();
        assert!(
            !extra.is_empty(),
            "extra-origin artifact control must execute"
        );
        assert!(
            extra.iter().all(|trace| trace.authorization.is_none()),
            "PyPI files origin must never receive the selected metadata origin's credential"
        );
    }
    let stored = server
        .app()
        .store()
        .get_project_in(3, probation_policy::Ecosystem::Npm, "left-pad")
        .await
        .unwrap();
    assert!(
        stored.is_none(),
        "service metadata must remain request-local on disk"
    );
    let project = probation::store::cache::ProjectKey::in_registry(
        3,
        probation_policy::Ecosystem::Npm,
        "left-pad",
    );
    assert!(
        server
            .app()
            .store()
            .caches()
            .projects
            .get(&project)
            .is_none(),
        "service metadata must remain request-local in memory"
    );
    assert!(
        server
            .app()
            .store()
            .get_project_in(4, probation_policy::Ecosystem::PyPi, "friendly-bard")
            .await
            .unwrap()
            .is_none()
    );
    let mut limited = snapshot;
    limited.rate_limit = std::num::NonZeroU32::new(1);
    policy_server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(limited))
        .mount(&policy_server)
        .await;
    server
        .app()
        .service_policy()
        .unwrap()
        .sync_once()
        .await
        .unwrap();
    assert_eq!(server.get("/npm/left-pad").await.status(), StatusCode::OK);
    assert_eq!(
        server.get("/pypi/simple/friendly-bard/").await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "one service account rate applies across ecosystems"
    );
    server.shutdown().await;
    let restarted = TestServer::start_with_upstream(
        config_with_open_blocklist(dir.path()),
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        Arc::clone(&transport) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;
    assert!(
        restarted
            .app()
            .store()
            .get_project_in(3, probation_policy::Ecosystem::Npm, "left-pad")
            .await
            .unwrap()
            .is_none(),
        "mode switch and restart must not recover private metadata"
    );
    assert!(
        restarted
            .app()
            .store()
            .get_project_in(3, probation_policy::Ecosystem::Npm, "private-only")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restarted
            .app()
            .store()
            .get_project_in(4, probation_policy::Ecosystem::PyPi, "private-only")
            .await
            .unwrap()
            .is_none()
    );
    restarted.shutdown().await;
}
