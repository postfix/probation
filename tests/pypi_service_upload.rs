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
struct Upload {
    url: String,
    authorization: String,
    body: Vec<u8>,
}

#[derive(Default)]
struct Registry(Mutex<Vec<Upload>>);

#[async_trait::async_trait]
impl Transport for Registry {
    async fn fetch_metadata(&self, _: MetadataRequest) -> Result<MetadataResponse, UpstreamError> {
        Err(UpstreamError::Status(404))
    }
    async fn open_artifact(&self, _: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        Err(UpstreamError::Status(404))
    }
    async fn send_action(
        &self,
        mut request: ActionRequest,
    ) -> Result<ActionResponse, UpstreamError> {
        let mut body = Vec::new();
        request.body.read_to_end(&mut body).await.unwrap();
        let authorization = request.authorization.unwrap();
        self.0.lock().unwrap().push(Upload {
            url: request.url.to_string(),
            authorization: authorization.clone(),
            body,
        });
        Ok(ActionResponse {
            status: if authorization == "Basic dXNlcjpkZW5pZWQ=" || authorization == "Bearer denied"
            {
                403
            } else {
                200
            },
            content_type: None,
            body: b"upload result".as_slice().into(),
        })
    }
}

fn snapshot() -> ServicePolicySnapshot {
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
        registries: vec![RegistryDescriptor {
            registry: RegistryId(4),
            ecosystem: probation_policy::Ecosystem::PyPi,
            target_url: Some("https://pypi.invalid/legacy/".into()),
            trusted: false,
            registry_private_cidrs: vec![],
            deletion_scopes: vec![],
        }],
    }
}

#[tokio::test]
async fn local_service_forwards_selected_pypi_upload_and_upstream_denial() {
    let policy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&policy)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.max_artifact_bytes = NonZeroU64::new(100).unwrap();
    config.max_metadata_bytes = NonZeroU64::new(100).unwrap();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
    });
    let registry = Arc::new(Registry::default());
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        registry.clone(),
        fake_origins(),
    )
    .await;
    let client = reqwest::Client::new();
    let send = |path: &str, authorization: &str| {
        client
            .post(server.url(path))
            .header("authorization", authorization)
            .header("content-type", "multipart/form-data; boundary=probe")
            .body("--probe\r\ncontent\r\n--probe--\r\n")
    };
    for (authorization, expected) in [
        ("Basic dXNlcjpvd25lcg==", 200),
        ("Bearer owner", 200),
        ("Basic dXNlcjpkZW5pZWQ=", 403),
        ("Bearer denied", 403),
    ] {
        let response = send("/registry/pypi/4/", authorization)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            expected,
            "{authorization} selected upload"
        );
        assert_eq!(response.text().await.unwrap(), "upload result");
    }
    let basic = "Basic dXNlcjpvd25lcg==";
    for (method, route, expected) in [
        (reqwest::Method::POST, "/registry/pypi/99/", 404),
        (reqwest::Method::POST, "/registry/pypi/4/unknown", 405),
        (reqwest::Method::POST, "/registry/pypi/4", 404),
        (reqwest::Method::POST, "/registry/pypi/4/?x=1", 404),
        (reqwest::Method::POST, "/registry/pypi/04/", 404),
        (reqwest::Method::POST, "/pypi/", 405),
        (reqwest::Method::POST, "/registry/npm/4/", 404),
        (reqwest::Method::PUT, "/registry/pypi/4/", 405),
        (reqwest::Method::PATCH, "/registry/pypi/4/", 405),
        (reqwest::Method::DELETE, "/registry/pypi/4/", 405),
        (reqwest::Method::GET, "/registry/pypi/4/", 405),
    ] {
        let response = client
            .request(method.clone(), server.url(route))
            .header("authorization", basic)
            .header("content-type", "multipart/form-data; boundary=probe")
            .body("--probe\r\ncontent\r\n--probe--\r\n")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{method} {route}");
    }
    for (label, authorization, content_type, expected) in [
        ("no credential", None, Some("multipart/form-data; boundary=probe"), 401),
        ("unsupported scheme", Some("Token owner"), Some("multipart/form-data; boundary=probe"), 401),
        ("empty bearer", Some("Bearer "), Some("multipart/form-data; boundary=probe"), 401),
        ("non-multipart body", Some(basic), Some("text/plain"), 400),
        ("no content type", Some(basic), None, 400),
    ] {
        let mut request = client.post(server.url("/registry/pypi/4/")).body("x");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        if let Some(value) = content_type {
            request = request.header("content-type", value);
        }
        assert_eq!(request.send().await.unwrap().status().as_u16(), expected, "{label}");
    }
    assert_eq!(
        send("/registry/pypi/4/", "Basic dXNlcjpvd25lcg==")
            .body("x".repeat(301))
            .send()
            .await
            .unwrap()
            .status(),
        413,
        "declared B+1 upload is refused before upstream I/O"
    );
    let chunked = reqwest::Body::wrap_stream(futures_util::stream::once(async {
        Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b'x'; 301]))
    }));
    assert_eq!(
        send("/registry/pypi/4/", "Basic dXNlcjpvd25lcg==")
            .body(chunked)
            .send()
            .await
            .unwrap()
            .status(),
        413,
        "chunked B+1 upload is refused before a completed upstream write"
    );
    let trace = registry.0.lock().unwrap();
    assert_eq!(
        trace.len(),
        4,
        "only the selected upload route makes upstream calls"
    );
    for (row, authorization) in trace.iter().zip([
        "Basic dXNlcjpvd25lcg==",
        "Bearer owner",
        "Basic dXNlcjpkZW5pZWQ=",
        "Bearer denied",
    ]) {
        assert_eq!(row.url, "https://pypi.invalid/legacy/");
        assert_eq!(row.authorization, authorization);
        assert_eq!(row.body, b"--probe\r\ncontent\r\n--probe--\r\n");
    }
}
