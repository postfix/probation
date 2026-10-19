//! A tarball requested at upstream's own path, `/npm/{name}/-/{filename}`.
//!
//! That is the path an existing lockfile names: npm rewrites only the host of a
//! `resolved` URL to the configured registry and keeps upstream's path, and a yarn 1
//! lockfile whose host is rewritten to this instance asks for the same thing. Such a
//! client never fetches metadata first, so the route has to find the reference
//! itself, and then decide exactly as the reference-id route does.

mod common;

use std::sync::Arc;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist,
    npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path, publish_blocklist,
    snapshot_with,
};
use serde_json::{Map, Value, json};
use tempfile::TempDir;

const VERSION: &str = "1.0.0";

/// Five days before [`NOW`], so the one-day cooldown is spent.
const PUBLISHED: &str = "2026-04-01T00:00:00Z";
const NOW: &str = "2026-04-06T12:00:00Z";

fn body() -> String {
    common::fixture("artifacts/harmless-widget-1.0.0.tgz")
}

/// The last segment of a package name, which is what npm names its tarball after.
fn filename(name: &str) -> String {
    let base = name.rsplit('/').next().expect("a name has a last segment");
    format!("{base}-{VERSION}.tgz")
}

/// One npm document advertising one version published at `published`.
fn document(name: &str, published: &str) -> String {
    let mut versions = Map::new();
    versions.insert(
        VERSION.to_owned(),
        json!({
            "name": name,
            "version": VERSION,
            "dist": {"tarball": npm_tarball_url(name, &filename(name))},
        }),
    );
    let mut time = Map::new();
    time.insert(VERSION.to_owned(), json!(published));

    json!({
        "name": name,
        "dist-tags": {"latest": VERSION},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    _dir: TempDir,
}

/// A server whose upstream advertises `name` at [`VERSION`], published at
/// `published`, and serves its tarball.
async fn harness(name: &str, published: &str) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = config_with_open_blocklist(dir.path());

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(name),
        FakeAnswer::Body(document(name, published)),
    );
    registry.answer(
        &npm_artifact_upstream_path(name, &filename(name)),
        FakeAnswer::Body(body()),
    );

    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_in_with_registry(
        &dir.path().join("data"),
        config,
        clock.shared(),
        Arc::clone(&registry),
    )
    .await;
    Harness {
        server,
        registry,
        clock,
        _dir: dir,
    }
}

/// A lockfile client asks for the tarball and nothing else.
#[tokio::test]
async fn an_upstream_shaped_path_serves_the_verified_tarball() {
    let name = "fixture-widget";
    let harness = harness(name, PUBLISHED).await;

    let response = harness
        .server
        .get(&format!("/npm/{name}/-/{}", filename(name)))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.expect("a body"), body());
    harness.server.shutdown().await;
}

/// npm keeps a scoped package's `@scope/name` path unencoded in a lockfile.
#[tokio::test]
async fn a_scoped_upstream_shaped_path_serves_the_tarball() {
    let name = "@fixture/widget";
    let harness = harness(name, PUBLISHED).await;

    let response = harness
        .server
        .get(&format!("/npm/{name}/-/{}", filename(name)))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.expect("a body"), body());
    harness.server.shutdown().await;
}

/// A lockfile can pin a version that is still inside its cooldown. It is refused
/// exactly as the reference-id route refuses it, not served and not hidden as missing.
#[tokio::test]
async fn a_held_version_is_refused_as_held() {
    let name = "fixture-widget";
    // An hour before [`NOW`]: well inside the one-day cooldown.
    let harness = harness(name, "2026-04-06T11:00:00Z").await;

    let response = harness
        .server
        .get(&format!("/npm/{name}/-/{}", filename(name)))
        .await;
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(common::body_error(response).await, "HELD");
    harness.server.shutdown().await;
}

/// A filename the snapshot does not advertise is not a reference, whatever its shape.
#[tokio::test]
async fn a_filename_upstream_does_not_advertise_is_not_found() {
    let name = "fixture-widget";
    let harness = harness(name, PUBLISHED).await;

    let response = harness
        .server
        .get(&format!("/npm/{name}/-/{name}-9.9.9.tgz"))
        .await;
    assert_eq!(response.status().as_u16(), 404);
    assert_eq!(common::body_error(response).await, "NOT_FOUND");
    harness.server.shutdown().await;
}

/// `/npm/artifacts/-/…` is also the shape of the reference-id route, with `-` where
/// the id goes. A package really named `artifacts` still gets its tarball.
#[tokio::test]
async fn a_package_named_artifacts_gets_its_tarball() {
    let name = "artifacts";
    let harness = harness(name, PUBLISHED).await;

    let response = harness
        .server
        .get(&format!("/npm/{name}/-/{}", filename(name)))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.expect("a body"), body());
    harness.server.shutdown().await;
}

/// Two versions whose tarball URLs end in the same filename: the path names neither
/// for certain, so it serves neither rather than picking one.
#[tokio::test]
async fn a_filename_two_versions_share_is_not_found() {
    let name = "fixture-widget";
    let shared = filename(name);
    let dir = tempfile::tempdir().expect("a temporary directory");
    let registry = FakeRegistry::new();
    let document = json!({
        "name": name,
        "dist-tags": {"latest": "1.0.1"},
        "versions": {
            "1.0.0": {"name": name, "version": "1.0.0",
                      "dist": {"tarball": npm_tarball_url(name, &shared)}},
            "1.0.1": {"name": name, "version": "1.0.1",
                      "dist": {"tarball": npm_tarball_url("elsewhere", &shared)}},
        },
        "time": {"1.0.0": PUBLISHED, "1.0.1": PUBLISHED},
    });
    registry.answer(
        &npm_upstream_path(name),
        FakeAnswer::Body(document.to_string()),
    );
    registry.answer(
        &npm_artifact_upstream_path(name, &shared),
        FakeAnswer::Body(body()),
    );
    let server = TestServer::start_in_with_registry(
        &dir.path().join("data"),
        config_with_open_blocklist(dir.path()),
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&registry),
    )
    .await;

    let response = server.get(&format!("/npm/{name}/-/{shared}")).await;
    assert_eq!(response.status().as_u16(), 404);
    server.shutdown().await;
}

/// A block decided from what this instance already holds does not wait on upstream,
/// exactly as on the reference-id route: the project's metadata has expired and the
/// registry is unreachable, and the block still answers.
#[tokio::test]
async fn a_local_block_answers_without_upstream_once_metadata_has_expired() {
    let name = "fixture-widget";
    let harness = harness(name, PUBLISHED).await;
    let path = format!("/npm/{name}/-/{}", filename(name));
    assert_eq!(harness.server.status(&path).await, 200);

    publish_blocklist(
        &harness.server,
        &snapshot_with(
            2,
            "2026-04-05T00:00:00Z",
            "2099-01-01T00:00:00Z",
            &format!(r#"{{"ecosystem":"npm","name":"{name}","version":null,"reason":"malware"}}"#),
            "",
        ),
        common::parse_rfc3339(NOW),
    );
    harness.clock.advance_seconds(86_400);
    harness.registry.go_offline();
    let calls_before = harness.registry.calls().len();

    let response = harness.server.get(&path).await;
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(common::body_error(response).await, "BLOCKED");
    assert_eq!(
        harness.registry.calls().len(),
        calls_before,
        "upstream was not asked"
    );
    harness.server.shutdown().await;
}

/// SPEC §9 artifact delivery answers `HEAD` after every check and sends no body; the
/// upstream-shaped path is that delivery too.
#[tokio::test]
async fn head_on_an_upstream_shaped_path_runs_the_checks_without_a_body() {
    let name = "fixture-widget";
    let harness = harness(name, PUBLISHED).await;

    let response = harness
        .server
        .head(&format!("/npm/{name}/-/{}", filename(name)))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some(body().len().to_string().as_str()),
        "the length of the verified bytes"
    );
    harness.server.shutdown().await;
}

/// npm 11 and later add the registry's path to a lockfile URL only when the URL does
/// not already start with it, so the package named `npm`, whose upstream path is
/// `/npm/-/npm-{version}.tgz`, arrives here without the prefix.
#[tokio::test]
async fn the_package_named_npm_gets_its_tarball_at_its_unprefixed_path() {
    let name = "npm";
    let harness = harness(name, PUBLISHED).await;

    let response = harness
        .server
        .get(&format!("/npm/-/{}", filename(name)))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().await.expect("a body"), body());
    assert_eq!(
        harness.server.status("/npm/-/whoami").await,
        404,
        "and the rest of npm's `-` namespace is still refused"
    );
    harness.server.shutdown().await;
}
