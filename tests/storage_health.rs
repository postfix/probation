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

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{TestServer, config_with_open_blocklist};
use probation::policy::Ecosystem;
use probation::store::cache::MemoryCaches;
use probation::store::rows::{ArtifactReference, ProjectRefresh, ReferenceId, ReferenceUpsert};
use probation::store::{StoreHandle, startup};
use probation::upstream::UpstreamValidators;
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
