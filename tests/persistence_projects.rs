//! Slice 5's half of SPEC §13 item 13 and all of item 1's restart rule: a project
//! and its references commit together or not at all, and a first-seen time is on
//! disk before it makes anything eligible — and is still there after a restart.
//!
//! The lock, schema, WAL and recovery half of item 13 is slice 3's and lives in
//! `persistence_recovery.rs`. These five need `ProjectRefresh`, which slice 5 is the
//! first to build.

mod common;

use std::sync::Arc;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, npm_upstream_path, parse_rfc3339,
    sample_config,
};
use probation::policy::Ecosystem;
use probation::store::cache::MemoryCaches;
use probation::store::rows::{
    ArtifactReference, Generation, ProjectRefresh, ReferenceId, ReferenceUpsert,
};
use probation::store::{StoreHandle, startup};
use probation::upstream::UpstreamValidators;
use serde_json::Value;
use tempfile::TempDir;
use url::Url;

const NAME: &str = "fixture-untimed";
const T0: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// The transaction, exercised directly
// ---------------------------------------------------------------------------

async fn store(dir: &TempDir) -> (StoreHandle, tokio::task::JoinHandle<()>) {
    let opened = startup::open_and_recover(dir.path())
        .await
        .expect("the data directory opens");
    let connection = opened.connection.expect("a fresh database recovers");
    probation::store::spawn(
        connection,
        opened.lock,
        Arc::new(MemoryCaches::new(1 << 20)),
    )
}

fn reference(version: &str, filename: &str) -> ArtifactReference {
    ArtifactReference {
        ecosystem: Ecosystem::Npm,
        name: "widget".to_owned(),
        version: version.to_owned(),
        filename: filename.to_owned(),
        upstream_url: Url::parse(&format!(
            "https://npm.invalid/widget/-/widget-{version}.tgz"
        ))
        .expect("a test URL"),
        expected: Vec::new(),
    }
}

fn upsert(version: &str, filename: &str, first_seen: Option<i64>) -> ReferenceUpsert {
    let reference = reference(version, filename);
    ReferenceUpsert {
        id: ReferenceId::compute(&reference),
        reference,
        publication_micros: None,
        first_seen_micros: first_seen,
    }
}

fn refresh(validated_at: i64, references: Vec<ReferenceUpsert>) -> ProjectRefresh {
    ProjectRefresh {
        ecosystem: Ecosystem::Npm,
        name: "widget".to_owned(),
        payload: Arc::from(br#"{"name":"widget"}"#.as_slice()),
        validators: UpstreamValidators::default(),
        validated_at_micros: validated_at,
        fetched_at_micros: validated_at,
        references,
    }
}

/// SPEC §10: "Commit a project snapshot, its reference upserts, and new first-seen
/// values together before publishing the new in-memory generation."
#[tokio::test]
async fn project_and_references_commit_atomically() {
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let (store, task) = store(&dir).await;

    let references = vec![
        upsert("1.0.0", "widget-1.0.0.tgz", Some(1_000)),
        upsert("1.1.0", "widget-1.1.0.tgz", Some(2_000)),
        upsert("2.0.0", "widget-2.0.0.tgz", None),
    ];
    let committed = store
        .commit_project_refresh(refresh(5_000, references.clone()))
        .await
        .expect("the refresh commits");

    assert_eq!(committed.generation, Generation(1));
    let project = store
        .get_project(Ecosystem::Npm, "widget")
        .await
        .expect("a query")
        .expect("the project landed");
    assert_eq!(project.generation, Generation(1));
    assert_eq!(project.validated_at_micros, 5_000);

    for upsert in &references {
        let row = store
            .get_reference(upsert.id)
            .await
            .expect("a query")
            .unwrap_or_else(|| {
                panic!(
                    "{} landed in the same transaction as its project",
                    upsert.reference.version
                )
            });
        assert_eq!(row.reference, upsert.reference);
        assert_eq!(row.first_seen_micros, upsert.first_seen_micros);
    }
    assert_eq!(
        committed.first_seen.len(),
        2,
        "the commit reports the first-seen values in force, and only the two that have one"
    );

    // A second refresh publishes a new generation, which is what invalidates every
    // response rendered from the old one.
    let again = store
        .commit_project_refresh(refresh(6_000, references))
        .await
        .expect("the second refresh commits");
    assert_eq!(again.generation, Generation(2));

    drop(store);
    task.await.expect("the storage task stops");
}

/// REL-01: a failure part-way through must leave nothing behind. A half-written
/// project would advertise references that are not there.
#[tokio::test]
async fn transaction_rollback_leaves_no_partial_project() {
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let (store, task) = store(&dir).await;

    let good = upsert("1.0.0", "widget-1.0.0.tgz", Some(1_000));
    // A reference with no filename cannot be served, and the schema says so. It is
    // the second of the two, so the project row and the first reference are already
    // written inside the transaction when it fails.
    let bad = upsert("1.1.0", "", None);

    let outcome = store
        .commit_project_refresh(refresh(5_000, vec![good.clone(), bad]))
        .await;
    assert!(
        outcome.is_err(),
        "the commit must fail rather than write what it can"
    );

    assert!(
        store
            .get_project(Ecosystem::Npm, "widget")
            .await
            .expect("a query")
            .is_none(),
        "the project row was written before the failure and must not have survived it"
    );
    assert!(
        store
            .get_reference(good.id)
            .await
            .expect("a query")
            .is_none(),
        "nor the reference that was written before it"
    );

    // And the store is still usable afterwards: a rollback is not a wedged
    // connection.
    store
        .commit_project_refresh(refresh(6_000, vec![good.clone()]))
        .await
        .expect("a later refresh still commits");
    assert!(
        store
            .get_reference(good.id)
            .await
            .expect("a query")
            .is_some()
    );

    drop(store);
    task.await.expect("the storage task stops");
}

// ---------------------------------------------------------------------------
// First-seen times, through the whole server
// ---------------------------------------------------------------------------

/// A package document with no publication times at all, so every version's age has
/// to come from a persisted first-seen value.
fn untimed_document() -> String {
    format!(
        r#"{{
            "name": "{NAME}",
            "dist-tags": {{"latest": "1.0.0"}},
            "versions": {{
                "1.0.0": {{"name": "{NAME}", "version": "1.0.0",
                    "dist": {{"tarball": "https://npm.invalid/{NAME}/-/{NAME}-1.0.0.tgz"}}}}
            }},
            "time": {{}}
        }}"#
    )
}

/// The same document, now carrying an upstream timestamp from long before the
/// first-seen value this instance recorded.
fn timed_document() -> String {
    untimed_document().replace(
        r#""time": {}"#,
        r#""time": {"1.0.0": "2026-01-01T00:00:00.000Z"}"#,
    )
}

/// The reference the document above describes, computed exactly as the server does.
fn untimed_reference_id() -> ReferenceId {
    ReferenceId::compute(&ArtifactReference {
        ecosystem: Ecosystem::Npm,
        name: NAME.to_owned(),
        version: "1.0.0".to_owned(),
        filename: format!("{NAME}-1.0.0.tgz"),
        upstream_url: Url::parse(&format!("https://npm.invalid/{NAME}/-/{NAME}-1.0.0.tgz"))
            .expect("a test URL"),
        expected: Vec::new(),
    })
}

fn registry_answering(document: String) -> Arc<FakeRegistry> {
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(NAME), FakeAnswer::Body(document));
    registry
}

/// The data directory, the blocklist file, and the configuration a restart reuses.
fn config_in(dir: &TempDir, cooldown: u64) -> probation::config::Config {
    let blocklist_file = dir.path().join("blocklist.json");
    if !blocklist_file.exists() {
        std::fs::write(
            &blocklist_file,
            common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", ""),
        )
        .expect("the blocklist is written");
    }

    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config.cooldown_seconds = cooldown;
    config
}

/// SPEC §5: "When a timestamp is absent, use a persisted first-seen timestamp for
/// that exact artifact reference. Persist it before using it to make an artifact
/// eligible."
#[tokio::test]
async fn first_seen_persisted_before_it_grants_eligibility() {
    let t0 = parse_rfc3339(T0);

    // With no cooldown the very first request is the one that would make this
    // artifact eligible, which is exactly the moment the value has to be on disk.
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let server = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, 0),
        TestClock::at_rfc3339(T0).shared(),
        registry_answering(untimed_document()),
    )
    .await;

    let document: Value = server.json(&format!("/npm/{NAME}")).await;
    assert!(
        document["versions"].get("1.0.0").is_some(),
        "with a zero cooldown an untimed release is eligible as soon as its first-seen \
         time exists"
    );

    let row = server
        .running()
        .app()
        .store()
        .get_reference(untimed_reference_id())
        .await
        .expect("a query")
        .expect("the first-seen time is already committed when the response is produced");
    assert_eq!(row.first_seen_micros, Some(t0));
    assert_eq!(
        row.publication_micros, None,
        "upstream supplied no time, so none was invented"
    );
    server.shutdown().await;

    // And with a cooldown, the deadline the client is given is derived from that
    // persisted value rather than from a fresh reading of the clock.
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let server = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, ONE_DAY),
        TestClock::at_rfc3339(T0).shared(),
        registry_answering(untimed_document()),
    )
    .await;

    let response = server.get(&format!("/npm/{NAME}")).await;
    assert_eq!(response.status().as_u16(), 403);
    let body: Value = serde_json::from_str(&response.text().await.expect("a body"))
        .expect("the error body is JSON");
    assert_eq!(
        body["eligible_at"],
        Value::from("2026-04-07T12:00:00Z"),
        "the first-seen time plus the cooldown"
    );
    server.shutdown().await;

    // A store this instance cannot write is never a reason to serve anyway: the same
    // request that would otherwise have been allowed is refused instead.
    let dir = tempfile::tempdir().expect("a temporary data directory");
    std::fs::create_dir_all(dir.path().join("state")).expect("the state directory");
    std::fs::write(dir.path().join("state").join("firewall.db-wal"), [7u8; 64])
        .expect("an unrecoverable write-ahead log with no database beside it");
    let server = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, 0),
        TestClock::at_rfc3339(T0).shared(),
        registry_answering(untimed_document()),
    )
    .await;
    assert_eq!(
        server.status(&format!("/npm/{NAME}")).await,
        503,
        "nothing that could not be committed is served"
    );
    server.shutdown().await;
}

/// SPEC §5: "Restarting the service must not reset it." `01-product.md` says the
/// same thing as "a restart does not reset the clock".
#[tokio::test]
async fn first_seen_survives_restart() {
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let t0 = parse_rfc3339(T0);

    let server = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, ONE_DAY),
        TestClock::at_rfc3339(T0).shared(),
        registry_answering(untimed_document()),
    )
    .await;
    assert_eq!(
        server.status(&format!("/npm/{NAME}")).await,
        403,
        "the release is untimed, so its cooldown starts the moment it is first seen"
    );
    server.shutdown().await;

    // Two days later, in a new process against the same data directory.
    let restarted = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, ONE_DAY),
        TestClock::at_rfc3339("2026-04-08T12:00:00Z").shared(),
        registry_answering(untimed_document()),
    )
    .await;

    let document: Value = restarted.json(&format!("/npm/{NAME}")).await;
    assert!(
        document["versions"].get("1.0.0").is_some(),
        "a restart does not reset the clock: the cooldown is counted from the original \
         first-seen time, so the release is eligible by now"
    );
    assert_eq!(
        restarted
            .running()
            .app()
            .store()
            .get_reference(untimed_reference_id())
            .await
            .expect("a query")
            .expect("the reference survived")
            .first_seen_micros,
        Some(t0),
        "and the stored value is the original one, not a fresh one from this start"
    );

    restarted.shutdown().await;
}

/// SPEC §5: "If a valid upstream timestamp later appears, use it."
#[tokio::test]
async fn upstream_timestamp_supersedes_first_seen() {
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let t0 = parse_rfc3339(T0);

    let server = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, ONE_DAY),
        TestClock::at_rfc3339(T0).shared(),
        registry_answering(untimed_document()),
    )
    .await;
    assert_eq!(server.status(&format!("/npm/{NAME}")).await, 403);
    server.shutdown().await;

    // Upstream now publishes the timestamp it had been missing — a date months
    // before this instance ever saw the package. Nothing else about the reference
    // changed, so it is the same reference and the same stored row.
    //
    // Ten minutes later, not the same instant: the stored snapshot is only
    // revalidated once its metadata TTL is up (SPEC §10, "After metadata TTL,
    // revalidate upstream before responding"), so at T0 the new document would not
    // be read at all. Ten minutes is well past the five-minute TTL and nowhere near
    // the one-day cooldown, so a still-held release would still be held.
    let restarted = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, ONE_DAY),
        TestClock::at_rfc3339("2026-04-06T12:10:00Z").shared(),
        registry_answering(timed_document()),
    )
    .await;

    let document: Value = restarted.json(&format!("/npm/{NAME}")).await;
    assert!(
        document["versions"].get("1.0.0").is_some(),
        "the upstream time is three months old, so the release is eligible at once"
    );

    let row = restarted
        .running()
        .app()
        .store()
        .get_reference(untimed_reference_id())
        .await
        .expect("a query")
        .expect("the reference is still there");
    assert_eq!(
        row.publication_micros,
        Some(parse_rfc3339("2026-01-01T00:00:00Z"))
    );
    assert_eq!(
        row.first_seen_micros,
        Some(t0),
        "the first-seen time is kept rather than discarded; upstream supersedes it, \
         which is not the same as erasing it"
    );

    restarted.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 15: the last full fetch is persisted (SPEC rev 3 §10)
// ---------------------------------------------------------------------------

/// SPEC §5: the ceiling is measured from a persisted instant, so that instant has to
/// survive a restart — which is exactly why it is a wall-clock value in a column
/// rather than a monotonic reading in memory.
#[tokio::test]
async fn a_full_fetch_time_survives_a_restart() {
    let dir = tempfile::tempdir().expect("a temporary data directory");

    let (first, task) = store(&dir).await;
    first
        .commit_project_refresh(ProjectRefresh {
            ecosystem: Ecosystem::Npm,
            name: "widget".to_owned(),
            payload: Arc::from(br#"{"name":"widget"}"#.as_slice()),
            validators: UpstreamValidators::default(),
            // Four seconds of revalidation on top of the full fetch, so a column that
            // merely copied the other one would be visible.
            validated_at_micros: 9_000,
            fetched_at_micros: 5_000,
            references: Vec::new(),
        })
        .await
        .expect("the refresh commits");
    drop(first);
    task.await.expect("the storage task stops");

    let (restarted, task) = store(&dir).await;
    let row = restarted
        .get_project(Ecosystem::Npm, "widget")
        .await
        .expect("a query")
        .expect("the project survived the restart");
    assert_eq!(
        row.fetched_at_micros, 5_000,
        "the last FULL fetch is read back from disk, not re-derived from this start"
    );
    assert_eq!(
        row.validated_at_micros, 9_000,
        "and it is a column of its own rather than a second name for the validation time"
    );

    drop(restarted);
    task.await.expect("the storage task stops");
}

/// The trap this column exists to close, across a restart. A reloaded snapshot is
/// revalidated conditionally; the `304` that answers must carry the ORIGINAL
/// full-fetch time forward. A restart is not a fetch, and if it reset this column an
/// unlucky restart cadence would postpone the ceiling forever.
#[tokio::test]
async fn a_304_after_a_restart_still_reads_the_stored_full_fetch_time() {
    let dir = tempfile::tempdir().expect("a temporary data directory");
    let t0 = parse_rfc3339(T0);
    let path = format!("/npm/{NAME}");

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(NAME),
        FakeAnswer::Validated {
            etag: "\"v1\"".to_owned(),
            body: untimed_document(),
        },
    );

    let server = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, ONE_DAY),
        TestClock::at_rfc3339(T0).shared(),
        Arc::clone(&registry),
    )
    .await;
    // Untimed release under a one-day cooldown: held, which is answer enough — the
    // snapshot is what this test is about.
    assert_eq!(server.status(&path).await, 403);
    assert_eq!(
        stored_full_fetch(&server).await,
        t0,
        "the first fetch records itself as a full fetch"
    );
    server.shutdown().await;

    // A new process an hour later, against the same data directory. The metadata TTL
    // is five minutes, so the reloaded snapshot is revalidated at once.
    let later = "2026-04-06T13:00:00Z";
    let restarted = TestServer::start_in_with_registry(
        dir.path(),
        config_in(&dir, ONE_DAY),
        TestClock::at_rfc3339(later).shared(),
        Arc::clone(&registry),
    )
    .await;
    assert_eq!(restarted.status(&path).await, 403);
    assert_eq!(
        registry.not_modified_answers(),
        1,
        "the reloaded snapshot really was revalidated conditionally and answered 304"
    );

    let row = restarted
        .running()
        .app()
        .store()
        .get_project(Ecosystem::Npm, NAME)
        .await
        .expect("a query")
        .expect("the project survived the restart");
    assert_eq!(
        row.fetched_at_micros, t0,
        "the 304 carried the original full-fetch time forward across the restart"
    );
    assert_eq!(
        row.validated_at_micros,
        parse_rfc3339(later),
        "while the validation time is this process's, which is what a 304 renews"
    );

    restarted.shutdown().await;
}

async fn stored_full_fetch(server: &TestServer) -> i64 {
    server
        .running()
        .app()
        .store()
        .get_project(Ecosystem::Npm, NAME)
        .await
        .expect("a query")
        .expect("the project is stored")
        .fetched_at_micros
}
