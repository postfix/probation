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
            osv_scope: None,
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

// ---- Slice 28: LS-F8 monotonic revision floor, LS-F1 refusal route ----

fn config_for(server: &MockServer) -> ServicePolicyConfig {
    ServicePolicyConfig {
        server_url: server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
    }
}

async fn serve(server: &MockServer, snapshot: &ServicePolicySnapshot) {
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot))
        .mount(server)
        .await;
}

fn at_revision(revision: u64) -> ServicePolicySnapshot {
    let mut value = snapshot();
    value.revision = revision;
    value
}

async fn with_floor(revision: u64) -> (MockServer, ServicePolicyConfig, tempfile::TempDir, ServicePolicy) {
    let server = MockServer::start().await;
    let config = config_for(&server);
    let dir = tempfile::tempdir().unwrap();
    let policy = ServicePolicy::load(&config, dir.path());
    serve(&server, &at_revision(revision)).await;
    policy.sync_once().await.unwrap();
    (server, config, dir, policy)
}

#[tokio::test]
async fn activation_rejects_older_revision_same_binding() {
    let (server, config, dir, policy) = with_floor(5).await;
    serve(&server, &at_revision(4)).await;
    assert!(policy.sync_once().await.is_err(), "an older revision is a structural rejection");
    assert_eq!(policy.snapshot().unwrap().revision, 5, "last good retained");
    assert!(!dir.path().join("service-policy.refused").exists(), "no refusal change");
    assert_eq!(
        ServicePolicy::load(&config, dir.path()).snapshot().unwrap().revision,
        5,
        "the floor survives restart"
    );
}

#[tokio::test]
async fn activation_equal_revision_identical_digest_is_accepted() {
    let (server, _config, _dir, policy) = with_floor(5).await;
    serve(&server, &at_revision(5)).await;
    policy.sync_once().await.unwrap();
}

#[tokio::test]
async fn activation_equal_revision_different_policy_digest_is_rejected() {
    let (server, _config, _dir, policy) = with_floor(5).await;
    let mut other = at_revision(5);
    other.layers[1].revision = 2;
    other.place_chain[1].layer_revision = 2;
    serve(&server, &other).await;
    assert!(policy.sync_once().await.is_err());
    assert_eq!(policy.snapshot().unwrap().layers[1].revision, 1);
}

#[tokio::test]
async fn activation_equal_revision_registry_edit_is_accepted() {
    let (server, _config, _dir, policy) = with_floor(5).await;
    let mut edited = at_revision(5);
    edited.registries[0].trusted = true;
    serve(&server, &edited).await;
    policy.sync_once().await.unwrap();
    assert!(policy.snapshot().unwrap().registries[0].trusted, "registry edits are latest-wins");
}

#[tokio::test]
async fn activation_equal_revision_rate_change_is_accepted() {
    let (server, _config, _dir, policy) = with_floor(5).await;
    let mut edited = at_revision(5);
    edited.rate_limit = std::num::NonZeroU32::new(30);
    serve(&server, &edited).await;
    policy.sync_once().await.unwrap();
    assert_eq!(policy.snapshot().unwrap().rate_limit, std::num::NonZeroU32::new(30));
}

#[tokio::test]
async fn activation_after_key_rotation_starts_without_floor() {
    let (server, config, dir, _policy) = with_floor(5).await;
    let mut rotated = config.clone();
    rotated.service_key = FirewallToken::new("prb_11111111111111111111111111111111".into());
    let policy = ServicePolicy::load(&rotated, dir.path());
    serve(&server, &at_revision(1)).await;
    policy.sync_once().await.unwrap();
    assert_eq!(policy.snapshot().unwrap().revision, 1);
}

#[tokio::test]
async fn activation_floor_reset_by_operator_command() {
    let (server, config, dir, policy) = with_floor(5).await;
    drop(policy);
    ServicePolicy::reset_revision_floor(&config, dir.path()).unwrap();
    let policy = ServicePolicy::load(&config, dir.path());
    serve(&server, &at_revision(2)).await;
    policy.sync_once().await.unwrap();
    assert_eq!(policy.snapshot().unwrap().revision, 2, "the next valid snapshot sets the new floor");
    serve(&server, &at_revision(1)).await;
    assert!(policy.sync_once().await.is_err());
}

#[tokio::test]
async fn floor_reset_never_clears_a_refusal() {
    let (server, config, dir, policy) = with_floor(5).await;
    server.reset().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(401)).mount(&server).await;
    assert!(policy.sync_once().await.is_err());
    drop(policy);
    ServicePolicy::reset_revision_floor(&config, dir.path()).unwrap();
    assert!(dir.path().join("service-policy.refused").exists());
    assert!(ServicePolicy::load(&config, dir.path()).snapshot().is_none());
}

#[tokio::test]
async fn snapshot_404_is_not_an_authority_refusal() {
    let (server, config, dir, policy) = with_floor(5).await;
    server.reset().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
    assert!(policy.sync_once().await.is_err());
    assert!(policy.snapshot().is_some(), "only 401/403 on the snapshot route refuse");
    assert!(!dir.path().join("service-policy.refused").exists());
    assert!(ServicePolicy::load(&config, dir.path()).snapshot().is_some());
}

#[test]
#[cfg(unix)]
fn reset_revision_floor_command_leaves_the_marker_and_requires_service_policy() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("service.key");
    std::fs::write(&key, "prb_01234567890123456789012345678901").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let base = include_str!("../config.sample.toml")
        .lines()
        .filter(|line| !line.trim_start().starts_with("data_dir"))
        .collect::<Vec<_>>()
        .join("\n");
    let text = format!(
        "data_dir = {:?}\n{base}\n[service_policy]\nserver_url = \"https://policy.example.test\"\nservice_key_file = {:?}\n",
        data, key
    );
    let config = dir.path().join("probation.toml");
    std::fs::write(&config, &text).unwrap();
    let run = |path: &std::path::Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_probation"))
            .args(["reset-revision-floor", "--config"])
            .arg(path)
            .output()
            .unwrap()
    };
    let output = run(&config);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(data.join("revision-floor-reset").exists());
    let plain = dir.path().join("plain.toml");
    std::fs::write(&plain, include_str!("../config.sample.toml")).unwrap();
    assert!(!run(&plain).status.success(), "no service_policy section: nothing to reset");
}

// ---- LS-F7 bounds on the policy snapshot ----

/// Each case builds a snapshot just over one bound; at the limit it must activate.
async fn bound_case(over: bool, edit: impl Fn(&mut ServicePolicySnapshot, bool)) -> bool {
    let server = MockServer::start().await;
    let config = config_for(&server);
    let dir = tempfile::tempdir().unwrap();
    let policy = ServicePolicy::load(&config, dir.path());
    let mut value = snapshot();
    edit(&mut value, over);
    serve(&server, &value).await;
    let accepted = policy.sync_once().await.is_ok();
    assert!(!dir.path().join("service-policy.refused").exists(), "a bound violation is structural, never a refusal");
    accepted
}

fn descriptors(count: u64) -> Vec<RegistryDescriptor> {
    (1..=count)
        .map(|id| RegistryDescriptor {
            registry: RegistryId(id),
            ecosystem: probation_policy::Ecosystem::Npm,
            target_url: None,
            trusted: false,
            registry_private_cidrs: vec![],
            deletion_scopes: vec![],
            osv_scope: None,
        })
        .collect()
}

fn exception(name: String) -> probation_policy::Exception {
    probation_policy::Exception {
        ecosystem: probation_policy::Ecosystem::Npm,
        name,
        version: None,
        lifts: probation_policy::Lifts::default(),
    }
}

#[tokio::test]
async fn activation_rejects_snapshot_over_each_bound() {
    // registries: at most 256
    let registries = |value: &mut ServicePolicySnapshot, over: bool| value.registries = descriptors(if over { 257 } else { 256 });
    assert!(bound_case(false, registries).await, "256 registries");
    assert!(!bound_case(true, registries).await, "257 registries");
    // CIDR strings: at most 64 per descriptor
    let cidrs = |value: &mut ServicePolicySnapshot, over: bool| {
        value.registries[0].target_url = Some("https://10.0.0.7/".into());
        value.registries[0].registry_private_cidrs = (0..if over { 65 } else { 64 }).map(|n| format!("10.{n}.0.0/16")).collect();
    };
    assert!(bound_case(false, cidrs).await, "64 cidrs");
    assert!(!bound_case(true, cidrs).await, "65 cidrs");
    // rules per layer: at most 10,000
    let rules = |value: &mut ServicePolicySnapshot, over: bool| {
        value.layers[1].layer.exceptions = (0..if over { 10_001 } else { 10_000 }).map(|n| exception(format!("p{n}"))).collect();
    };
    assert!(bound_case(false, rules).await, "10000 rules in a layer");
    assert!(!bound_case(true, rules).await, "10001 rules in a layer");
    // any string field: at most 2048 bytes
    let strings = |value: &mut ServicePolicySnapshot, over: bool| {
        value.layers[1].layer.exceptions = vec![exception("a".repeat(if over { 2049 } else { 2048 }))];
    };
    assert!(bound_case(false, strings).await, "2048-byte string");
    assert!(!bound_case(true, strings).await, "2049-byte string");
}

// ---- LS-F3 an unknown ecosystem tag degrades only what it names ----

async fn sync_raw(raw: serde_json::Value) -> (Result<(), probation::managed::service_policy::ServicePolicyError>, ServicePolicy, tempfile::TempDir) {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let policy = ServicePolicy::load(&config_for(&server), dir.path());
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(raw))
        .mount(&server)
        .await;
    let result = policy.sync_once().await;
    (result, policy, dir)
}

fn mixed_snapshot() -> serde_json::Value {
    let mut raw = serde_json::to_value(snapshot()).unwrap();
    raw["layers"][1]["layer"]["blocks"] = serde_json::json!([
        {"Package": {"ecosystem": "Npm", "name": "left-pad"}},
        {"Package": {"ecosystem": "Maven2", "name": "org.example:lib"}}
    ]);
    raw["registries"].as_array_mut().unwrap().push(serde_json::json!({
        "registry": 4, "ecosystem": "Maven2", "target_url": null, "trusted": false,
        "registry_private_cidrs": [], "deletion_scopes": []
    }));
    raw
}

#[tokio::test]
async fn activation_unknown_ecosystem_degrades_only_that_registry() {
    let (result, policy, _dir) = sync_raw(mixed_snapshot()).await;
    result.expect("an unknown tag is not structural");
    let active = policy.snapshot().unwrap();
    assert_eq!(active.registries.len(), 1, "the known registry stays");
    assert_eq!(policy.unavailable_registries(), vec![RegistryId(4)], "readiness lists the unknown registry degraded");
    assert!(policy.principal(RegistryId(4), probation_policy::Ecosystem::Npm).is_none(), "requests to it refuse");
    assert!(policy.principal(RegistryId(3), probation_policy::Ecosystem::Npm).is_some());
}

#[tokio::test]
async fn activation_mixed_version_snapshot_keeps_known_denies() {
    let (result, policy, _dir) = sync_raw(mixed_snapshot()).await;
    result.unwrap();
    let active = policy.snapshot().unwrap();
    assert_eq!(active.layers[1].layer.blocks.len(), 1, "the npm block is active, the Maven2 rule is skipped");
    assert_eq!(policy.rules_skipped_unknown_ecosystem(), 1);
}

#[tokio::test]
async fn activation_structural_error_still_rejects_whole_snapshot() {
    let mut raw = mixed_snapshot();
    raw["version"] = serde_json::json!(2);
    let (result, policy, _dir) = sync_raw(raw).await;
    assert!(result.is_err());
    assert!(policy.snapshot().is_none());
}

// ---- LS-F9 / D5: a descriptor naming a denied address is rejected before activation ----

fn targeting(url: &str, cidr: &str) -> ServicePolicySnapshot {
    let mut value = snapshot();
    value.registries[0].target_url = Some(url.into());
    value.registries[0].registry_private_cidrs = vec![cidr.into()];
    value
}

#[tokio::test]
async fn descriptor_naming_loopback_or_link_local_is_rejected_before_activation() {
    // The registry's own private CIDR list cannot unlock a denied address.
    for (url, cidr) in [
        ("https://127.0.0.1/", "127.0.0.0/8"),
        ("https://[::1]/", "::1/128"),
        ("https://169.254.169.254/", "169.254.0.0/16"),
        ("https://[::ffff:127.0.0.1]/", "127.0.0.0/8"),
    ] {
        let (result, policy, _dir) = sync_raw(serde_json::to_value(targeting(url, cidr)).unwrap()).await;
        assert!(result.is_err(), "{url}");
        assert!(policy.snapshot().is_none(), "{url}");
    }
    let (result, _policy, _dir) = sync_raw(serde_json::to_value(targeting("https://10.0.0.5/", "10.0.0.0/8")).unwrap()).await;
    result.expect("an ordinary private registry named by its own CIDR stays allowed");
}

#[tokio::test]
async fn descriptor_naming_the_enforcers_own_listener_is_rejected() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let policy = ServicePolicy::load(&config_for(&server), dir.path()).with_listener("203.0.113.5:8080".parse().unwrap());
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(targeting("https://203.0.113.5:8080/", "203.0.113.0/24")))
        .mount(&server)
        .await;
    assert!(policy.sync_once().await.is_err());
    assert!(policy.snapshot().is_none());
}

// ---- LS-F15 config inputs ----

#[cfg(unix)]
fn service_config(url: &str, key_bytes: &[u8]) -> Result<Config, probation::config::ConfigError> {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("service.key");
    std::fs::write(&key, key_bytes).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    Config::from_toml_str(&format!(
        "{}\n[service_policy]\nserver_url = {url:?}\nservice_key_file = {:?}\n",
        include_str!("../config.sample.toml"),
        key
    ))
}

#[test]
#[cfg(unix)]
fn config_server_url_rejects_path_query_userinfo_fragment_and_http() {
    for ok in ["https://policy.example.test", "https://policy.example.test/", "https://policy.example.test:8443"] {
        assert!(service_config(ok, b"prb_01234567890123456789012345678901").is_ok(), "{ok}");
    }
    for bad in [
        "http://policy.example.test",
        "https://policy.example.test/api",
        "https://policy.example.test/?q=1",
        "https://user:pw@policy.example.test",
        "https://policy.example.test/#frag",
    ] {
        assert!(service_config(bad, b"prb_01234567890123456789012345678901").is_err(), "{bad}");
    }
}

#[test]
#[cfg(unix)]
fn config_service_key_rejects_control_non_ascii_and_overlong() {
    let url = "https://policy.example.test";
    for bad in [
        &b"prb_0123456789012345678901234567890\x01"[..],
        "prb_0123456789012345678901234567890\u{e9}".as_bytes(),
        b"prb_0123456789012345678901234567 890",
        &[b"prb_".as_slice(), &[b'a'; 600]].concat(),
    ] {
        let error = service_config(url, bad).expect_err("rejected").to_string();
        assert!(!error.contains("prb_0123"), "the message never echoes the key: {error}");
    }
}

#[test]
#[cfg(unix)]
fn config_service_key_trims_single_trailing_newline() {
    let url = "https://policy.example.test";
    assert!(service_config(url, b"prb_01234567890123456789012345678901\n").is_ok());
    assert!(service_config(url, b"prb_01234567890123456789012345678901\r\n").is_ok());
    assert!(service_config(url, b"prb_01234567890123456789012345678901\n\n").is_err(), "exactly one is trimmed");
    assert!(service_config(url, b"prb_01234567890123456789012345678901 ").is_err(), "trailing space is not trimmed");
    assert!(service_config(url, b" prb_01234567890123456789012345678901").is_err());
}

// ---- LS-F9 / LS-F16 optional config keys (written after the code: red not observed) ----

#[test]
fn config_control_plane_and_credential_temp_keys() {
    let sample = include_str!("../config.sample.toml");
    let with = |extra: &str| Config::from_toml_str(&format!("{extra}\n{sample}"));
    let ok = with("control_plane_cidrs = [\"10.96.0.0/12\"]\ncredential_temp_max_request_bytes = 4294967296\ncredential_temp_max_total_bytes = 1073741824").unwrap();
    assert_eq!(ok.control_plane_cidrs.len(), 1);
    assert_eq!(ok.credential_temp_max_request_bytes, Some(4294967296));
    assert!(with("control_plane_cidrs = [\"not-a-cidr\"]").is_err());
    assert!(with("credential_temp_max_total_bytes = 0").is_err(), "positive when set");
    let default = Config::from_toml_str(sample).unwrap();
    assert!(default.credential_temp_max_request_bytes.is_none() && default.credential_temp_max_total_bytes.is_none(), "no cap by default");
}

#[tokio::test]
async fn descriptor_hostname_resolving_to_a_denied_address_is_rejected_at_activation() {
    // `localhost` resolves to loopback; the registry's own private CIDRs cannot unlock it
    // (LS-F9: hostnames are checked as resolved, at activation and again at connect).
    let mut snapshot = targeting("https://localhost:9443/", "127.0.0.0/8");
    snapshot.registries[0].registry_private_cidrs.push("::1/128".into());
    let (result, policy, _dir) = sync_raw(serde_json::to_value(snapshot).unwrap()).await;
    assert!(result.is_err());
    assert!(policy.snapshot().is_none());
}

// ---- R28-7: the degraded state survives a restart ----

#[tokio::test]
async fn unknown_ecosystem_degraded_state_survives_restart() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&server);
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(mixed_snapshot())).mount(&server).await;
    ServicePolicy::load(&config, dir.path()).sync_once().await.unwrap();
    let restarted = ServicePolicy::load(&config, dir.path());
    assert!(restarted.snapshot().is_some());
    assert_eq!(restarted.unavailable_registries(), vec![RegistryId(4)], "readiness still lists the unknown registry");
    assert_eq!(restarted.rules_skipped_unknown_ecosystem(), 1);
}

// ---- S28-8: the denylist needs the configured port ----

#[test]
#[cfg(unix)]
fn listen_port_zero_is_refused_under_service_policy() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("service.key");
    std::fs::write(&key, "prb_01234567890123456789012345678901").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let text = |listen: &str| {
        format!(
            "{}\n[service_policy]\nserver_url = \"https://policy.example.test\"\nservice_key_file = {:?}\n",
            include_str!("../config.sample.toml").replace("127.0.0.1:8080", listen),
            key
        )
    };
    let refused = Config::from_toml_str(&text("127.0.0.1:0")).expect_err("port 0 cannot name the own listener").to_string();
    assert!(refused.contains("listen"), "{refused}");
    assert!(Config::from_toml_str(&text("127.0.0.1:8080")).is_ok());
    // Without [service_policy] a random port stays allowed (tests and local use).
    assert!(Config::from_toml_str(&include_str!("../config.sample.toml").replace("127.0.0.1:8080", "127.0.0.1:0")).is_ok());
}
