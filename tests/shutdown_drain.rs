//! Shutdown waits for in-flight requests, but not forever: a request that never
//! finishes must not hold the process past the drain deadline.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, config_with_open_blocklist,
    fake_origins, npm_upstream_path,
};

#[tokio::test]
async fn shutdown_closes_a_request_that_outlives_the_drain_deadline() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let gate = Gate::new();
    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path("never-answers"),
        FakeAnswer::GatedMetadata {
            body: "{}".to_owned(),
            gate: Arc::clone(&gate),
        },
    );
    let server = TestServer::start_with_upstream(
        config_with_open_blocklist(dir.path()),
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        registry as Arc<dyn probation::upstream::Transport>,
        fake_origins(),
    )
    .await;

    let url = server.url("/npm/never-answers");
    let parked = tokio::spawn(async move { common::downstream_client().get(url).send().await });
    gate.wait_until_reached().await;

    // The gate is never released, so only the deadline can end this request.
    tokio::time::timeout(
        Duration::from_secs(10),
        server.shutdown_within(Duration::from_millis(200)),
    )
    .await
    .expect("shutdown finishes once the drain deadline has passed");

    assert!(
        parked.await.expect("the client task").is_err(),
        "the parked request's connection was closed rather than answered"
    );
}
