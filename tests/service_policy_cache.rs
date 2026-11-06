use probation::config::Config;
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::managed::service_policy::ServicePolicy;
use probation_policy::{Layer, LayerKind, PlaceRef, api::*};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

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
                layer: Layer::empty(place.kind),
                revision: 1,
            })
            .collect(),
        rate_limit: None,
        rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor {
            registry: RegistryId(3),
            ecosystem: probation_policy::Ecosystem::Npm,
            target_url: None,
            trusted: false,
            registry_private_cidrs: vec![],
            deletion_scopes: vec![],
        }],
    }
}

#[tokio::test]
#[cfg(unix)]
async fn refusal_remains_closed_when_storage_fails_during_the_request() {
    let server = MockServer::start().await;
    let config = ServicePolicyConfig {
        server_url: server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&server)
        .await;
    let policy = ServicePolicy::load(&config, dir.path());
    policy.sync_once().await.unwrap();
    policy.sync_once().await.unwrap();
    assert!(!dir.path().join("service-policy.refused").exists());
    server.reset().await;
    let data_dir = dir.path().to_owned();
    Mock::given(method("GET"))
        .respond_with(move |_: &wiremock::Request| {
            std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
            ResponseTemplate::new(401)
        })
        .mount(&server)
        .await;
    let result = policy.sync_once().await;
    let cannot_create = std::fs::write(dir.path().join("write-probe"), "probe").is_err();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        cannot_create,
        "test must actually deny writes for the current UID"
    );
    assert!(result.is_err());
    assert!(policy.snapshot().is_none());
    drop(policy);
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let restarted = ServicePolicy::load(&config, dir.path());
    assert!(
        restarted.snapshot().is_none(),
        "storage failure while receiving refusal must not resurrect a remembered grant after restart"
    );
    assert!(restarted.sync_once().await.is_err());
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_none(),
        "503 must never clear an existing refusal"
    );
}

#[tokio::test]
async fn service_policy_fetches_and_remembers_only_its_configured_binding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policy/snapshot"))
        .and(header(
            "authorization",
            "Bearer prb_01234567890123456789012345678901",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&server)
        .await;
    let config = ServicePolicyConfig {
        server_url: server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    let policy = ServicePolicy::load(&config, dir.path());
    assert!(policy.snapshot().is_none());
    assert!(
        policy.sync_once().await.is_ok(),
        "a valid service policy must activate"
    );
    assert_eq!(policy.snapshot().unwrap().org, OrgId(10));
    assert_eq!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .unwrap()
            .key_id,
        KeyId(7)
    );
    let mut rotated = config.clone();
    rotated.service_key = FirewallToken::new("prb_11111111111111111111111111111111".into());
    assert!(
        ServicePolicy::load(&rotated, dir.path())
            .snapshot()
            .is_none()
    );
}

#[tokio::test]
async fn explicit_refusal_survives_restart_and_previous_file_recovery() {
    let server = MockServer::start().await;
    let config = ServicePolicyConfig {
        server_url: server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&server)
        .await;
    let policy = ServicePolicy::load(&config, dir.path());
    policy.sync_once().await.unwrap();
    policy.sync_once().await.unwrap();
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    assert!(policy.sync_once().await.is_err());
    assert!(
        policy.snapshot().is_some(),
        "transient outage retains matching remembered policy"
    );
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_some(),
        "a completed transient check preserves remembered policy across restart"
    );
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    assert!(policy.sync_once().await.is_err());
    assert!(
        policy.snapshot().is_none(),
        "explicit refusal must close admission"
    );
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_none()
    );
    std::fs::write(dir.path().join("service-policy.json"), "damaged primary").unwrap();
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_none(),
        "previous grants cannot resurrect refused authority"
    );
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&server)
        .await;
    policy.sync_once().await.unwrap();
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_some(),
        "successful matching policy recovers durable refusal"
    );
    std::fs::create_dir(dir.path().join("service-policy.refused")).unwrap();
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    assert!(
        policy.sync_once().await.is_err(),
        "refusal tombstone cannot overwrite a directory"
    );
    assert!(
        policy.snapshot().is_none(),
        "persistence failure must keep in-memory admission closed"
    );
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_none()
    );
}

#[tokio::test]
async fn malformed_snapshots_cannot_replace_remembered_authority() {
    let server = MockServer::start().await;
    let config = ServicePolicyConfig {
        server_url: server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    let policy = ServicePolicy::load(&config, dir.path());
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&server)
        .await;
    policy.sync_once().await.unwrap();
    let generation = policy.publication_gate.generation();
    let mut invalid = Vec::new();
    let mut reply = snapshot();
    reply.version = 2;
    invalid.push(reply);
    let mut reply = snapshot();
    reply.account.id = 99;
    invalid.push(reply);
    let mut reply = snapshot();
    reply.place_chain[1].layer_revision = 99;
    invalid.push(reply);
    let mut reply = snapshot();
    reply.registries.push(reply.registries[0].clone());
    invalid.push(reply);
    let mut reply = snapshot();
    reply.registries[0].target_url = Some("http://127.0.0.1/private".into());
    invalid.push(reply);
    for reply in invalid {
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(reply))
            .mount(&server)
            .await;
        assert!(policy.sync_once().await.is_err());
        assert_eq!(policy.publication_gate.generation(), generation);
        assert_eq!(policy.snapshot().unwrap().org, OrgId(10));
    }
    let mut rotated = config.clone();
    rotated.server_url = "https://other.example.test".parse().unwrap();
    assert!(
        ServicePolicy::load(&rotated, dir.path())
            .snapshot()
            .is_none()
    );
}

#[tokio::test]
async fn rotation_cannot_resurrect_a_refused_key_from_previous_snapshot() {
    let server = MockServer::start().await;
    let config = ServicePolicyConfig {
        server_url: server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&server)
        .await;
    let first = ServicePolicy::load(&config, dir.path());
    first.sync_once().await.unwrap();
    first.sync_once().await.unwrap();
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    assert!(first.sync_once().await.is_err());
    let mut rotated = config.clone();
    rotated.service_key = FirewallToken::new("prb_11111111111111111111111111111111".into());
    let second = ServicePolicy::load(&rotated, dir.path());
    assert!(second.snapshot().is_none());
    let mut reply = snapshot();
    reply.key_id = KeyId(8);
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(reply))
        .mount(&server)
        .await;
    second.sync_once().await.unwrap();
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_none(),
        "successful key rotation must not resurrect refused previous authority"
    );
    std::fs::write(dir.path().join("service-policy.json"), "damaged primary").unwrap();
    assert!(
        ServicePolicy::load(&config, dir.path())
            .snapshot()
            .is_none(),
        "damaged replacement cannot reveal a refused previous key"
    );
}

#[test]
fn explicit_service_policy_config_accepts_private_key_and_refuses_unsafe_binding() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("service.key");
    std::fs::write(&key, "prb_01234567890123456789012345678901").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let text = format!(
        "{}\n[service_policy]\nserver_url = \"https://policy.example.test\"\nservice_key_file = {:?}\n",
        include_str!("../config.sample.toml"),
        key
    );
    assert!(
        Config::from_toml_str(&text).is_ok(),
        "private service-policy config must load"
    );
    assert!(
        Config::from_toml_str(
            &text.replace("https://policy.example.test", "http://policy.example.test")
        )
        .is_err()
    );
    assert!(Config::from_toml_str(&format!("{text}sync_interval_seconds = 0\n")).is_err());
    assert!(Config::from_toml_str(&text.replace("127.0.0.1:8080", "0.0.0.0:8080")).is_err());
    // Windows has no mode bits: the key file's ACL is the operator's to restrict.
    #[cfg(unix)]
    {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            Config::from_toml_str(&text).is_err(),
            "a shared-readable service key must refuse startup"
        );
    }
}
