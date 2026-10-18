//! SPEC §10: "Storage write failures make readiness false and deny package responses
//! with `503` until storage is usable again." A warm response needs no storage
//! command at all, so it is exactly the response that would slip past an unhealthy
//! store if only readiness looked at it.

mod common;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, database_path,
    npm_upstream_path,
};
use serde_json::{Value, json};

const NOW: &str = "2026-04-06T12:00:00Z";
const NAME: &str = "storage-witness";

fn document() -> String {
    json!({
        "name": NAME,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "name": NAME,
            "version": "1.0.0",
            "dist": {"tarball": common::npm_tarball_url(NAME, "storage-witness-1.0.0.tgz")},
        }},
        "time": {"1.0.0": "2020-01-01T00:00:00Z"},
    })
    .to_string()
}

#[tokio::test]
async fn package_routes_answer_503_while_storage_is_unhealthy() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let config = config_with_open_blocklist(blocklist_dir.path());

    // A first run creates the schema; then one row is written that the PyPI index
    // cannot read back, which is a storage failure the test can cause on demand.
    TestServer::start_in(
        data_dir.path(),
        config.clone(),
        TestClock::at_rfc3339(NOW).shared(),
    )
    .await
    .shutdown()
    .await;
    {
        let database = turso::Builder::new_local(
            database_path(data_dir.path())
                .to_str()
                .expect("a UTF-8 path"),
        )
        .build()
        .await
        .expect("the database opens");
        let connection = database.connect().expect("a connection");
        connection
            .execute(
                "INSERT INTO projects (ecosystem, name, payload, validated_at_micros, \
                 fetched_at_micros, generation, digest_generation) \
                 VALUES ('pypi', X'FF', X'', 0, 0, 1, 0)",
                (),
            )
            .await
            .expect("the unreadable row is written");
    }

    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(NAME), FakeAnswer::Body(document()));
    let server = TestServer::start_in_with_registry(
        data_dir.path(),
        config,
        TestClock::at_rfc3339(NOW).shared(),
        registry,
    )
    .await;

    let path = format!("/npm/{NAME}");
    assert_eq!(server.status(&path).await, 200, "the cold request");
    let commands = server.store_commands();
    assert_eq!(server.status(&path).await, 200, "the warm request");
    assert_eq!(
        server.store_commands(),
        commands,
        "and it is genuinely warm"
    );

    assert_eq!(
        server.status("/pypi/simple/").await,
        503,
        "the unreadable row is a storage failure"
    );
    assert_eq!(server.status("/health/ready").await, 503);

    for path in [
        path.clone(),
        format!("/npm/{NAME}/1.0.0"),
        "/pypi/simple/".to_owned(),
        "/pypi/simple/anything/".to_owned(),
        format!("/npm/artifacts/{}/f.tgz", "a".repeat(64)),
        format!("/pypi/artifacts/{}/f.whl", "a".repeat(64)),
    ] {
        let response = server.get(&path).await;
        assert_eq!(response.status().as_u16(), 503, "{path}");
        let text = response.text().await.expect("a body");
        let body: Value = serde_json::from_str(&text).expect("a JSON error body");
        assert_eq!(body["error"], "STORAGE_UNUSABLE", "{path}: {body}");
    }
    assert_eq!(
        server.status("/health/live").await,
        200,
        "liveness is not storage"
    );

    server.shutdown().await;
}
