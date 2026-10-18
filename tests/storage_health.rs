//! SPEC §10: "Storage write failures make readiness false and deny package responses
//! with `503` until storage is usable again."
//!
//! "Usable again" is a statement about writes. A read that succeeds says nothing
//! about whether the next commit will, so readiness must stay false through any
//! number of successful reads and come back only when a write does.
//!
//! The write failure is a real one, injected through the store's own interface: a
//! reference with an empty filename violates the schema's `CHECK`, so the database
//! refuses the transaction exactly as it refuses one on a full disk.
//!
//! The "deny package responses" half is checked over HTTP: a warm response needs no
//! storage command at all, so it is exactly the response that would slip past an
//! unhealthy store if only readiness looked at it.

mod common;

use std::error::Error as _;
use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, database_path,
    npm_upstream_path,
};
use probation::policy::Ecosystem;
use probation::store::cache::MemoryCaches;
use probation::store::rows::{ArtifactReference, ProjectRefresh, ReferenceId, ReferenceUpsert};
use probation::store::startup::{RecoveryError, StartupError};
use probation::store::{StoreHandle, startup};
use probation::upstream::UpstreamValidators;
use serde_json::{Value, json};
use url::Url;

fn refresh(filename: &str) -> ProjectRefresh {
    let reference = ArtifactReference {
        ecosystem: Ecosystem::Npm,
        name: "health-widget".to_owned(),
        version: "1.0.0".to_owned(),
        filename: filename.to_owned(),
        upstream_url: Url::parse("https://npm.invalid/health-widget/-/health-widget-1.0.0.tgz")
            .expect("a test URL"),
        expected: Vec::new(),
    };
    ProjectRefresh {
        ecosystem: Ecosystem::Npm,
        name: "health-widget".to_owned(),
        payload: Arc::from(b"{}".as_slice()),
        validators: UpstreamValidators::default(),
        validated_at_micros: 1,
        fetched_at_micros: 1,
        references: vec![ReferenceUpsert {
            id: ReferenceId::compute(&reference),
            reference,
            publication_micros: Some(1),
            first_seen_micros: None,
        }],
    }
}

#[tokio::test]
async fn readiness_follows_writes_not_reads() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let server = TestServer::start_with(
        config_with_open_blocklist(dir.path()),
        Arc::new(probation::clock::SystemClock),
    )
    .await;
    let store = server.app().store().clone();
    assert_eq!(server.status("/health/ready").await, 200);

    let failed = store.commit_project_refresh(refresh("")).await;
    assert!(failed.is_err(), "the database refused the write");
    assert_eq!(
        server.status("/health/ready").await,
        503,
        "a failed write makes readiness false"
    );

    store
        .get_project(Ecosystem::Npm, "health-widget")
        .await
        .expect("reads still succeed");
    store
        .load_blocklist()
        .await
        .expect("and another kind of read");
    assert_eq!(
        server.status("/health/ready").await,
        503,
        "a successful read is not evidence that writes work again"
    );

    store
        .commit_project_refresh(refresh("health-widget-1.0.0.tgz"))
        .await
        .expect("the write succeeds now");
    assert_eq!(
        server.status("/health/ready").await,
        200,
        "and a successful write is"
    );

    drop(store);
    server.shutdown().await;
}

/// An instance a readiness probe has taken out of rotation receives no request whose
/// write could bring it back, so the maintenance pass has to be what finds out that
/// the database takes writes again.
#[tokio::test]
async fn a_maintenance_pass_restores_readiness_once_the_database_takes_writes() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let server = TestServer::start_with(
        config_with_open_blocklist(dir.path()),
        Arc::new(probation::clock::SystemClock),
    )
    .await;
    let app = server.app();

    assert!(
        app.store()
            .commit_project_refresh(refresh(""))
            .await
            .is_err()
    );
    assert_eq!(server.status("/health/ready").await, 503);

    probation::tasks::maintenance::run_once(&app).await;
    assert_eq!(
        server.status("/health/ready").await,
        200,
        "the pass wrote, the write succeeded, and readiness followed it"
    );

    drop(app);
    server.shutdown().await;
}

/// The engine's file I/O blocks inside `poll` (`synchronous=FULL` fsyncs on every
/// commit), so the store must not run on a worker of the runtime that serves
/// requests. Witnessed by not driving that runtime at all: the store is started on
/// one runtime, which is then left idle, and a command sent from a second runtime
/// still gets its answer.
#[test]
fn the_store_answers_without_the_runtime_that_started_it() {
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let starting = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let (store, _task): (StoreHandle, _) = starting.block_on(async {
        let opened = startup::open_and_recover(dir.path())
            .await
            .expect("the data directory opens");
        probation::store::spawn(
            opened.connection.expect("a fresh database recovers"),
            opened.lock,
            Arc::new(MemoryCaches::new(1 << 20)),
        )
    });

    let asking = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a second runtime");
    let answered = asking.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), store.load_blocklist()).await
    });
    assert!(
        matches!(answered, Ok(Ok(None))),
        "the store answered on its own thread: {answered:?}"
    );
}

// ---------------------------------------------------------------------------
// Startup refusals, and what each one says
// ---------------------------------------------------------------------------

/// A data directory that cannot be created, or whose lock file cannot be opened,
/// leaves nothing to run; the error names the path an operator has to fix.
#[tokio::test]
async fn an_unusable_data_directory_is_refused_with_its_path() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let file = dir.path().join("not-a-directory");
    std::fs::write(&file, b"").expect("a file where the data directory goes");
    let refused = startup::open_and_recover(&file)
        .await
        .err()
        .expect("no data directory");
    assert!(matches!(refused, StartupError::Directory { .. }));
    assert!(
        refused.to_string().starts_with("cannot create "),
        "{refused}"
    );
    assert!(refused.source().is_some());

    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(data_dir.join("lock")).expect("a directory where the lock goes");
    let refused = startup::open_and_recover(&data_dir)
        .await
        .err()
        .expect("no lock");
    assert!(matches!(refused, StartupError::Lock(_)));
    assert!(
        refused
            .to_string()
            .starts_with("cannot open the lock file "),
        "{refused}"
    );
    let lock_error = refused.source().expect("the lock error");
    assert!(lock_error.source().is_some(), "and the io error under it");
}

/// A database path that is not UTF-8 cannot be handed to the engine; the process
/// starts unready and says why.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_data_directory_whose_path_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let data_dir = dir.path().join(std::ffi::OsStr::from_bytes(b"data-\xff"));
    let opened = startup::open_and_recover(&data_dir)
        .await
        .expect("the directory and lock are fine");
    let refused = opened.connection.expect_err("the database is not opened");
    assert!(matches!(refused, RecoveryError::Path(_)));
    assert!(
        refused.to_string().contains("is not valid UTF-8"),
        "{refused}"
    );
    assert!(refused.source().is_none());
}

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
