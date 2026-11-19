//! Row 17: `gem push` and `gem yank` through the shared service, as PyPI's upload (class W).
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
    method: String,
    url: String,
    authorization: String,
    otp: Option<String>,
    content_type: Option<String>,
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
            method: request.method.to_string(),
            url: request.url.to_string(),
            authorization: authorization.clone(),
            otp: request.otp.clone(),
            content_type: request.content_type.clone(),
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
            registry: RegistryId(5),
            ecosystem: probation_policy::Ecosystem::RubyGems,
            target_url: Some("https://gems.invalid/".into()),
            trusted: false,
            registry_private_cidrs: vec![],
            deletion_scopes: vec![],
            osv_scope: None, archive_origin: None,
        }],
    }
}

#[tokio::test]
async fn shared_service_forwards_gem_push_and_yank_with_the_callers_own_key_only() {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot())).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.max_artifact_bytes = NonZeroU64::new(100).unwrap();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
    });
    let registry = Arc::new(Registry::default());
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), registry.clone(), fake_origins()).await;
    let client = reqwest::Client::new();
    // No credential: refused locally, nothing forwarded.
    let url = server.url("/rubygems/api/v1/gems");
    assert_eq!(client.post(&url).body("gem bytes").send().await.unwrap().status(), 401);
    assert_eq!(client.delete(server.url("/rubygems/api/v1/gems/yank")).body("gem_name=x").send().await.unwrap().status(), 401);
    assert!(registry.0.lock().unwrap().is_empty());
    // A push carries the caller's bare RubyGems API key to the registry's own origin.
    let pushed = client.post(&url).header("authorization", "rubygems_0123456789abcdef").header("OTP", "123456").header("content-type", "application/octet-stream").body("gem bytes").send().await.unwrap();
    assert_eq!((pushed.status().as_u16(), pushed.text().await.unwrap().as_str()), (200, "upload result"));
    let yanked = client.delete(server.url("/rubygems/api/v1/gems/yank")).header("authorization", "rubygems_0123456789abcdef").header("content-type", "application/x-www-form-urlencoded").body("gem_name=demo&version=1.0.0").send().await.unwrap();
    assert_eq!(yanked.status().as_u16(), 200);
    // Over the size cap: 413, nothing forwarded.
    assert_eq!(client.post(&url).header("authorization", "k").body(vec![0u8; 500]).send().await.unwrap().status(), 413);
    // Any other write path is not a RubyGems write route.
    assert_eq!(client.put(server.url("/rubygems/api/v1/gems")).header("authorization", "k").body("x").send().await.unwrap().status(), 405);
    {
    let seen = registry.0.lock().unwrap();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!((seen[0].method.as_str(), seen[0].url.as_str(), seen[0].authorization.as_str(), seen[0].body.as_slice()), ("POST", "https://gems.invalid/api/v1/gems", "rubygems_0123456789abcdef", b"gem bytes".as_slice()));
    assert_eq!((seen[0].otp.as_deref(), seen[0].content_type.as_deref()), (Some("123456"), Some("application/octet-stream")), "N8: the MFA code and content type reach the registry");
    assert_eq!(seen[1].otp, None, "no OTP sent, none invented");
    assert_eq!((seen[1].method.as_str(), seen[1].url.as_str(), seen[1].body.as_slice()), ("DELETE", "https://gems.invalid/api/v1/gems/yank", b"gem_name=demo&version=1.0.0".as_slice()));
    }
    server.shutdown().await;
}

/// R5: the OTP header is forwarded only when non-empty and at most 64 bytes.
#[tokio::test]
async fn otp_is_forwarded_only_within_its_bounds() {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot())).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
    });
    let registry = Arc::new(Registry::default());
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), registry.clone(), fake_origins()).await;
    let client = reqwest::Client::new();
    let (at_cap, over_cap) = ("1".repeat(64), "1".repeat(65));
    for otp in [at_cap.as_str(), over_cap.as_str(), ""] {
        let sent = client.post(server.url("/rubygems/api/v1/gems")).header("authorization", "k").header("OTP", otp).body("g").send().await.unwrap();
        assert_eq!(sent.status().as_u16(), 200);
    }
    let seen = registry.0.lock().unwrap();
    let otps: Vec<Option<&str>> = seen.iter().map(|upload| upload.otp.as_deref()).collect();
    assert_eq!(otps, [Some(at_cap.as_str()), None, None], "64 bytes pass; 65 bytes and an empty value are dropped, the push still goes");
}
