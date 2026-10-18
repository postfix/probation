//! Slice 1's witness: the whole wire — CLI configuration, router, error mapping and
//! a real policy call — against a server that is actually listening.

mod common;

use std::error::Error as _;
use std::path::Path;

use common::{
    TestClock, TestServer, config_with_open_blocklist, fake_upstream, logs, sample_config,
};
use probation::config::Config;
use probation::{App, AppDeps, StartupError};
use serde_json::Value;

#[tokio::test]
async fn health_live_answers_200() {
    let server = TestServer::start().await;

    let response = server.get("/health/live").await;

    assert_eq!(response.status().as_u16(), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn health_ready_answers_503_while_no_blocklist_is_loaded() {
    let server = TestServer::start().await;

    let response = server.get("/health/ready").await;

    assert_eq!(response.status().as_u16(), 503);
    server.shutdown().await;
}

#[tokio::test]
async fn npm_package_answers_503_policy_unavailable() {
    let server = TestServer::start().await;

    let response = server.get("/npm/left-pad").await;

    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let body = response.text().await.expect("a response body");
    let body: Value = serde_json::from_str(&body).expect("a JSON error body");
    assert_eq!(body["error"], Value::from("POLICY_UNAVAILABLE"));
    assert!(
        body["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "the error body carries a non-empty reason: {body}"
    );
    assert!(
        body["request_id"].as_str().is_some_and(|id| !id.is_empty()),
        "the error body carries a non-empty request_id: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn an_unknown_path_answers_404() {
    let server = TestServer::start().await;

    let response = server.get("/not-a-route").await;

    assert_eq!(response.status().as_u16(), 404);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Startup: what `App::start` refuses, and the TLS listener
// ---------------------------------------------------------------------------

fn deps(config: Config) -> AppDeps {
    let (transport, origins) = fake_upstream();
    AppDeps {
        config,
        clock: TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        transport,
        origins,
        osv_client: probation::osv::unreachable_client(),
        osv_base_url: None,
    }
}

async fn refused(config: Config) -> StartupError {
    match App::start(deps(config)).await {
        Ok(running) => {
            running.shutdown().await.expect("a clean shutdown");
            panic!("startup was expected to fail")
        }
        Err(err) => err,
    }
}

fn config_in(data_dir: &Path) -> Config {
    let mut config = sample_config();
    config.data_dir = data_dir.to_path_buf();
    config
}

/// Each refusal names its cause, and keeps the underlying error where there is one.
#[tokio::test]
async fn startup_refusals_name_their_cause() {
    let dir = tempfile::tempdir().expect("a data directory");

    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let mut config = config_in(&dir.path().join("bind"));
    config.listen = taken.local_addr().expect("an address");
    let err = refused(config).await;
    assert!(matches!(err, StartupError::Bind { .. }), "{err}");
    assert!(err.to_string().starts_with("cannot bind"), "{err}");
    assert!(err.source().is_some());

    let held = TestServer::start_in(
        &dir.path().join("held"),
        sample_config(),
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
    )
    .await;
    let err = refused(config_in(&dir.path().join("held"))).await;
    assert!(matches!(err, StartupError::DataDir(_)), "{err}");
    assert!(err.source().is_some());
    held.shutdown().await;

    let mut config = config_in(&dir.path().join("tls"));
    config.tls_cert_path = Some(dir.path().join("absent-cert.pem"));
    config.tls_key_path = Some(dir.path().join("absent-key.pem"));
    let err = refused(config).await;
    assert!(matches!(err, StartupError::Tls(_)), "{err}");
    assert!(err.source().is_some());

    let mut config = config_in(&dir.path().join("delivery"));
    config.log_file_path = Some(dir.path().join("no-such-directory").join("log.ndjson"));
    config.log_consumer_identification = true;
    let err = refused(config).await;
    assert!(matches!(err, StartupError::Delivery(_)), "{err}");
    assert!(err.to_string().contains("log_file_path"), "{err}");
    assert!(err.source().is_none());
}

/// SPEC §8: "Persist the last accepted snapshot so restart can use it while still
/// valid", and the restart says so.
#[tokio::test]
async fn a_restart_restores_the_persisted_blocklist() {
    let captured = logs::capture_info();
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let config = config_with_open_blocklist(blocklist_dir.path());
    let clock = || TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared();

    let first = TestServer::start_in(data_dir.path(), config.clone(), clock()).await;
    assert_eq!(first.status("/health/ready").await, 200);
    first.shutdown().await;

    let mut without_file = config;
    without_file.blocklist_file = blocklist_dir.path().join("gone.json");
    let restarted = TestServer::start_in(data_dir.path(), without_file, clock()).await;
    assert_eq!(
        restarted.status("/health/ready").await,
        200,
        "the persisted snapshot is back in force with no file to read"
    );
    assert!(
        captured.lines_containing_all(&["back in force", "entries=0"]) >= 1,
        "Captured:\n{}",
        captured.text()
    );
    restarted.shutdown().await;

    // A persisted snapshot that has since expired is not a policy: it stays out.
    let expiring_dir = tempfile::tempdir().expect("a data directory");
    let mut expiring = config_with_open_blocklist(blocklist_dir.path());
    std::fs::write(
        &expiring.blocklist_file,
        common::snapshot(1, "2020-01-01T00:00:00Z", "2026-04-07T00:00:00Z", ""),
    )
    .expect("the blocklist is written");
    let first = TestServer::start_in(expiring_dir.path(), expiring.clone(), clock()).await;
    assert_eq!(first.status("/health/ready").await, 200);
    first.shutdown().await;
    expiring.blocklist_file = blocklist_dir.path().join("gone.json");
    let later = TestServer::start_in(
        expiring_dir.path(),
        expiring,
        TestClock::at_rfc3339("2026-04-08T00:00:00Z").shared(),
    )
    .await;
    assert_eq!(later.status("/health/ready").await, 503);
    later.shutdown().await;
}

/// SPEC §10: a database that will not recover is a running, unready service — never
/// a refusal to start, and never a silently recreated database.
#[tokio::test]
async fn a_database_that_will_not_open_starts_unready() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let database = common::database_path(data_dir.path());
    std::fs::create_dir_all(database.parent().expect("a state directory"))
        .expect("the state directory is created");
    std::fs::write(&database, vec![0xABu8; 8192]).expect("the unreadable database is written");

    let server = TestServer::start_in(
        data_dir.path(),
        sample_config(),
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
    )
    .await;
    assert_eq!(server.status("/health/live").await, 200);
    assert_eq!(server.status("/health/ready").await, 503);
    server.shutdown().await;
}

/// A test that needs OSV to answer names its endpoint; startup accepts it the same
/// way it accepts the fixed production one.
#[tokio::test]
async fn startup_accepts_a_named_osv_endpoint() {
    let (transport, origins) = fake_upstream();
    let server = TestServer::start_with_upstream_and_osv(
        sample_config(),
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        transport,
        origins,
        common::downstream_client(),
        url::Url::parse("http://127.0.0.1:9/").expect("a URL"),
    )
    .await;
    assert_eq!(server.status("/health/live").await, 200);
    server.shutdown().await;
}

/// The plain listener with the peer address offered to the router, which only an
/// operator's opt-in turns on.
#[tokio::test]
async fn plain_http_is_served_with_consumer_identification_on() {
    let logs_dir = tempfile::tempdir().expect("a log directory");
    let mut config = sample_config();
    config.log_file_path = Some(logs_dir.path().join("decisions.ndjson"));
    config.log_consumer_identification = true;
    let server = TestServer::start_with(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
    )
    .await;
    assert_eq!(server.status("/health/live").await, 200);
    server.shutdown().await;
}

/// `serve` terminates TLS itself when both keys are set, with or without the peer
/// address being recorded. The fixture is a self-signed test certificate for
/// 127.0.0.1 and nothing else.
#[tokio::test]
async fn tls_is_served_when_both_keys_are_set() {
    let fixture = |name: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(name)
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("a TLS test client");
    let logs_dir = tempfile::tempdir().expect("a log directory");

    for identify in [false, true] {
        let mut config = sample_config();
        config.tls_cert_path = Some(fixture("cert.pem"));
        config.tls_key_path = Some(fixture("key.pem"));
        if identify {
            config.log_file_path = Some(logs_dir.path().join("decisions.ndjson"));
            config.log_consumer_identification = true;
        }
        let server = TestServer::start_with(
            config,
            TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        )
        .await;

        let url = format!("https://{}/health/live", server.local_addr());
        let response = client.get(&url).send().await.expect("a TLS response");
        assert_eq!(response.status().as_u16(), 200, "identify={identify}");
        server.shutdown().await;
    }
}
