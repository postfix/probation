//! Slice 7's third witness: durability (REL-01) and the storage-failure rule.
//!
//! SPEC §10: "Flush and synchronize the completed temporary file, atomically rename
//! within the same filesystem, synchronize the destination directory, and only then
//! commit its database mapping", and "A crash must never make a temporary file
//! downloadable", and "Storage write failures […] never relax policy to free space."
//!
//! The order is read off the publication itself, and each synchronisation is then
//! made to fail: a publication that skipped one would report success where
//! `file_sync_order_holds` requires it to fail.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, artifact_path, config_with_open_blocklist,
    npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path, publish_blocklist,
    snapshot_with, wait_until,
};
use probation::artifacts::content::{ContentKey, ContentStore, SyncStep};
use probation::config::Config;
use probation::store::rows::{ReferenceId, ReferenceRow};
use serde_json::{Map, Value, json};

const WIDGET: &str = "fixture-widget";
const FILENAME: &str = "fixture-widget-1.0.0.tgz";
const VERSION: &str = "1.0.0";
const PUBLISHED: &str = "2026-04-01T00:00:00Z";
const NOW: &str = "2026-04-06T12:00:00Z";
const BODY_SHA256: &str = "029830248baf17af5d9a9e23d3e7054a8860882d1cdc06bbbb1549056d347acb";
const BODY_SRI: &str = "sha512-cuZOnpQDIYuoiW0VpldsZLmUaQ/eZwGjVHeTZQoXRdTeBMh5mj1XyHMlEqTzPjYFW3AxzuKZi8cb4GZ2QP4G7g==";

fn body() -> String {
    common::fixture("artifacts/harmless-widget-1.0.0.tgz")
}

fn document() -> String {
    let mut versions = Map::new();
    versions.insert(
        VERSION.to_owned(),
        json!({
            "name": WIDGET,
            "version": VERSION,
            "dist": {"tarball": npm_tarball_url(WIDGET, FILENAME), "integrity": BODY_SRI},
        }),
    );
    let mut time = Map::new();
    time.insert(VERSION.to_owned(), json!(PUBLISHED));
    json!({
        "name": WIDGET,
        "dist-tags": {"latest": VERSION},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    data_dir: PathBuf,
}

impl Harness {
    async fn artifact_path(&self) -> String {
        let document = self.server.json(&format!("/npm/{WIDGET}")).await;
        artifact_path(&document, VERSION)
    }

    async fn reference(&self, path: &str) -> ReferenceRow {
        let hex = path.split('/').nth(3).expect("a reference id");
        self.server
            .running()
            .app()
            .store()
            .get_reference(ReferenceId::parse_hex(hex).expect("hexadecimal"))
            .await
            .expect("the reference query")
            .expect("the reference is committed")
    }

    fn objects_dir(&self) -> PathBuf {
        self.data_dir.join("content").join("objects")
    }

    fn temp_dir(&self) -> PathBuf {
        self.data_dir.join("content").join("tmp")
    }

    /// Where the verified body lives once it is cached: its own SHA-256, fanned out.
    fn body_object(&self) -> PathBuf {
        self.objects_dir().join(&BODY_SHA256[..2]).join(BODY_SHA256)
    }

    fn object_count(&self) -> usize {
        std::fs::read_dir(self.objects_dir())
            .map(|fan_out| {
                fan_out
                    .flatten()
                    .filter_map(|entry| std::fs::read_dir(entry.path()).ok())
                    .map(|entries| entries.count())
                    .sum()
            })
            .unwrap_or(0)
    }

    fn temp_count(&self) -> usize {
        std::fs::read_dir(self.temp_dir())
            .map(|entries| entries.count())
            .unwrap_or(0)
    }
}

/// A server over `data_dir`, with the registry serving the document and the artifact.
async fn start(data_dir: &Path, config: Config) -> Harness {
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(WIDGET), FakeAnswer::Body(document()));
    registry.answer(
        &npm_artifact_upstream_path(WIDGET, FILENAME),
        FakeAnswer::Body(body()),
    );

    let server = TestServer::start_in_with_registry(
        data_dir,
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&registry),
    )
    .await;

    Harness {
        server,
        registry,
        data_dir: data_dir.to_path_buf(),
    }
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = std::fs::metadata(path)
        .expect("the directory exists")
        .permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).expect("the mode is set");
}

// ---------------------------------------------------------------------------
// REL-01
// ---------------------------------------------------------------------------

/// Two halves of one ordering. The steps a real publication performed, in order; and
/// the database mapping, which does not exist when the publication did not finish —
/// so the commit is downstream of the file being durable, not beside it.
#[tokio::test]
async fn file_sync_order_holds() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 30);
    let key = ContentKey::from_sha256([9u8; 32]);

    let mut temp = store.create_temp(1024).await.expect("a temporary download");
    temp.write_all(body().as_bytes()).await.expect("the write");
    let published = store.publish(temp, &key).await.expect("the publication");

    assert_eq!(
        published.steps,
        vec![
            SyncStep::Flush,
            SyncStep::SyncFile,
            SyncStep::Rename,
            SyncStep::SyncDirectory,
        ],
        "SPEC §10: flush, synchronise the file, rename, synchronise the directory — \
         and only then may a mapping be committed"
    );
    assert_eq!(
        std::fs::read(store.path_for(&key)).expect("the published file"),
        body().as_bytes()
    );

    // The step list above is the publication describing itself. These two make the
    // synchronisations observable from outside: each one is made to fail, and the
    // publication has to fail with it. A publication that skipped either call would
    // report success here.
    assert_publication_fails_when_the_file_cannot_be_synchronised().await;
    assert_publication_fails_when_the_directory_cannot_be_synchronised().await;

    // The other half, end to end: when the publication cannot complete, no mapping
    // is committed — which is only true if the commit comes after it.
    let data = tempfile::tempdir().expect("a temporary data directory");
    let blocklist_dir = tempfile::tempdir().expect("a temporary directory");
    let harness = start(
        &data.path().join("data"),
        config_with_open_blocklist(blocklist_dir.path()),
    )
    .await;
    let path = harness.artifact_path().await;
    set_mode(&harness.objects_dir(), 0o500);

    assert_eq!(
        harness.server.status(&path).await,
        503,
        "a publication that cannot finish refuses the request"
    );
    let row = harness.reference(&path).await;
    assert_eq!(
        row.content_key, None,
        "and commits no mapping to bytes that never became durable"
    );
    assert_eq!(
        harness.temp_count(),
        0,
        "and a publication that failed part way leaves no temporary file behind"
    );

    set_mode(&harness.objects_dir(), 0o700);
    harness.server.shutdown().await;
}

fn entries(directory: &Path) -> usize {
    std::fs::read_dir(directory).map_or(0, |entries| entries.count())
}

/// `fsync` on a character device is `EINVAL`, so a download whose temporary name is a
/// link to `/dev/null` takes every write and then cannot be synchronised. The name is
/// the first one a fresh store hands out; the link is the fault, planted where the
/// download is about to be written.
#[cfg(target_os = "linux")]
async fn assert_publication_fails_when_the_file_cannot_be_synchronised() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 30);
    let first_temp = store
        .temp_dir()
        .join(format!("{}-0.part", std::process::id()));
    std::os::unix::fs::symlink("/dev/null", &first_temp).expect("the fault is planted");

    let key = ContentKey::from_sha256([7u8; 32]);
    let mut temp = store.create_temp(1024).await.expect("a temporary download");
    assert_eq!(
        temp.path(),
        first_temp,
        "the download is written through the fault"
    );
    temp.write_all(body().as_bytes()).await.expect("the write");

    assert!(
        store.publish(temp, &key).await.is_err(),
        "a file that cannot be synchronised is never published"
    );
    assert!(
        !store.path_for(&key).exists(),
        "and nothing was renamed into place"
    );
    assert_eq!(entries(&store.temp_dir()), 0, "and nothing is left in tmp/");
    assert_eq!(store.reserved_bytes(), 0);
}

#[cfg(not(target_os = "linux"))]
async fn assert_publication_fails_when_the_file_cannot_be_synchronised() {}

/// A fan-out directory that can be written and searched but not read: the rename
/// into it succeeds, and opening it to synchronise the new entry does not.
async fn assert_publication_fails_when_the_directory_cannot_be_synchronised() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 30);
    let key = ContentKey::from_sha256([8u8; 32]);
    let fan_out = store
        .path_for(&key)
        .parent()
        .expect("a fan-out directory")
        .to_path_buf();
    std::fs::create_dir_all(&fan_out).expect("the fan-out directory");
    set_mode(&fan_out, 0o300);

    let mut temp = store.create_temp(1024).await.expect("a temporary download");
    temp.write_all(body().as_bytes()).await.expect("the write");
    let published = store.publish(temp, &key).await;

    set_mode(&fan_out, 0o700);
    assert!(
        published.is_err(),
        "a rename whose directory entry cannot be made durable is not a publication"
    );
    assert_eq!(entries(&store.temp_dir()), 0, "and nothing is left in tmp/");
    assert_eq!(store.reserved_bytes(), 0);
}

/// The state a crash between the rename and the commit leaves behind: bytes in the
/// content directory that no mapping names, and whatever was still in flight sitting
/// in `tmp/`.
///
/// Neither may be served. The temporary file is removed at startup, and the request
/// re-downloads and re-verifies; the orphan sits at the very path the verified bytes
/// are published to, does not hash to that path's key, and is replaced rather than
/// reused — so the bytes the client receives are the verified ones and not the ones
/// the crash left.
#[tokio::test]
async fn crash_between_rename_and_commit_leaves_no_downloadable_temp_file() {
    let data = tempfile::tempdir().expect("a temporary data directory");
    let blocklist_dir = tempfile::tempdir().expect("a temporary directory");
    let data_dir = data.path().join("data");

    // A first run, which commits the reference and advertises its URL.
    let first = start(&data_dir, config_with_open_blocklist(blocklist_dir.path())).await;
    let path = first.artifact_path().await;
    let objects = first.objects_dir();
    let temp_dir = first.temp_dir();
    first.server.shutdown().await;

    // The crash state, written by hand: a half-finished download in `tmp/`, and an
    // object whose mapping was never committed — at the very path the verified body
    // will be published to, which is the only place it could ever be served from.
    let hostile = "hostile bytes a crash left behind\n";
    let stale_temp = temp_dir.join("1234-0.part");
    std::fs::write(&stale_temp, hostile).expect("the crashed download is left behind");
    let orphan = objects.join(&BODY_SHA256[..2]).join(BODY_SHA256);
    std::fs::create_dir_all(orphan.parent().expect("a fan-out directory")).expect("the directory");
    std::fs::write(&orphan, hostile).expect("the orphaned object is left behind");

    let second = start(&data_dir, config_with_open_blocklist(blocklist_dir.path())).await;
    assert!(
        !stale_temp.exists(),
        "SPEC §10: startup removes incomplete artifact temporary files"
    );
    assert_eq!(second.temp_count(), 0);

    let response = second.server.get(&path).await;
    assert_eq!(response.status().as_u16(), 200);
    let served = response.text().await.expect("a body");
    assert_eq!(
        served,
        body(),
        "the client receives verified bytes, never what the crash left in place"
    );
    assert_ne!(served, hostile);

    let row = second.reference(&path).await;
    assert_eq!(
        row.content_key.map(|key| key.to_hex()).as_deref(),
        Some(BODY_SHA256),
        "the mapping that exists now is the one this run verified and committed"
    );
    assert_eq!(
        second.temp_count(),
        0,
        "and it left no temporary file of its own"
    );
    second.server.shutdown().await;
}

/// SPEC §9: "Detect missing files and size mismatches and discard their cache
/// mappings." Discarding has to lead somewhere: the next request re-downloads,
/// re-verifies, and serves the verified bytes, rather than re-committing the mapping
/// to the same wrong file and refusing every request for the reference from then on.
#[tokio::test]
async fn a_cached_object_of_the_wrong_size_is_replaced_not_wedged() {
    let data = tempfile::tempdir().expect("a temporary data directory");
    let blocklist_dir = tempfile::tempdir().expect("a temporary directory");
    let harness = start(
        &data.path().join("data"),
        config_with_open_blocklist(blocklist_dir.path()),
    )
    .await;
    let path = harness.artifact_path().await;
    assert_eq!(harness.server.get(&path).await.status().as_u16(), 200);

    let mut object = std::fs::OpenOptions::new()
        .append(true)
        .open(harness.body_object())
        .expect("the cached object");
    std::io::Write::write_all(&mut object, b"!").expect("one byte appended");
    drop(object);

    for attempt in [
        "the request that finds the mismatch",
        "and the one after it",
    ] {
        let response = harness.server.get(&path).await;
        assert_eq!(response.status().as_u16(), 200, "{attempt}");
        assert_eq!(
            response.text().await.expect("a body"),
            body(),
            "{attempt} serves the verified bytes"
        );
    }
    harness.server.shutdown().await;
}

/// The wrong-sized file goes with its mapping, so nothing on disk still answers to
/// the key — even when the re-download that would replace it cannot happen.
#[tokio::test]
async fn a_cached_object_of_the_wrong_size_is_removed_with_its_mapping() {
    let data = tempfile::tempdir().expect("a temporary data directory");
    let blocklist_dir = tempfile::tempdir().expect("a temporary directory");
    let harness = start(
        &data.path().join("data"),
        config_with_open_blocklist(blocklist_dir.path()),
    )
    .await;
    let path = harness.artifact_path().await;
    assert_eq!(harness.server.get(&path).await.status().as_u16(), 200);
    // SPEC §10 never evicts an open file, and the response above can still hold this
    // one open after its status arrives.
    let key = harness
        .reference(&path)
        .await
        .content_key
        .expect("the body is cached");
    // No `App` handle outlives the wait: shutdown drops the last one to stop the store.
    wait_until(
        "the first response released the file",
        Duration::from_secs(5),
        || harness.server.app().content.open_count(&key) == 0,
    )
    .await;

    std::fs::write(harness.body_object(), "short").expect("the object is truncated");
    harness.registry.go_offline();

    assert_eq!(
        harness.server.status(&path).await,
        502,
        "upstream cannot supply the bytes again, and the wrong ones are not served"
    );
    assert!(
        !harness.body_object().exists(),
        "the file that no longer matched its mapping is gone"
    );
    assert_eq!(harness.reference(&path).await.content_key, None);
    harness.server.shutdown().await;
}

// ---------------------------------------------------------------------------
// OPS-01
// ---------------------------------------------------------------------------

/// SPEC §10: "Storage write failures make readiness false and deny package responses
/// with `503` until storage is usable again; never relax policy to free space."
///
/// The full filesystem is simulated by taking write permission off the content
/// directory, which is the closest an unprivileged test can get to `ENOSPC`: the
/// write fails, and the only question this test asks is what the firewall does when
/// it cannot store bytes. It must refuse — not serve them unverified, and not stop
/// enforcing anything else.
#[tokio::test]
async fn disk_full_is_a_503_not_a_policy_relaxation() {
    let data = tempfile::tempdir().expect("a temporary data directory");
    let blocklist_dir = tempfile::tempdir().expect("a temporary directory");
    let harness = start(
        &data.path().join("data"),
        config_with_open_blocklist(blocklist_dir.path()),
    )
    .await;
    let path = harness.artifact_path().await;

    // No room for a temporary download, and none for a published object either.
    set_mode(&harness.temp_dir(), 0o500);
    set_mode(&harness.objects_dir(), 0o500);

    let response = harness.server.get(&path).await;
    assert_eq!(
        response.status().as_u16(),
        503,
        "a cold request that cannot be stored is refused"
    );
    assert_eq!(common::body_error(response).await, "CAPACITY_EXHAUSTED");
    assert_eq!(
        harness.server.status("/health/ready").await,
        503,
        "SPEC §10: a storage write failure makes readiness false"
    );

    let row = harness.reference(&path).await;
    assert_eq!(row.content_key, None);
    assert_eq!(
        row.pinned_sha256, None,
        "nothing was verified, so nothing was pinned"
    );
    assert_eq!(harness.object_count(), 0);

    // And policy is exactly as strict as it was: a block is still a block, and a
    // request that cannot be stored is still refused rather than served.
    publish_blocklist(
        &harness.server,
        &snapshot_with(
            2,
            "2026-04-05T00:00:00Z",
            "2099-01-01T00:00:00Z",
            &format!(
                r#"{{"ecosystem":"npm","name":"{WIDGET}","version":null,"reason":"malware"}}"#
            ),
            "",
        ),
        common::parse_rfc3339(NOW),
    );
    // While storage is unusable every package response is SPEC §10's 503, the
    // blocked one included; nothing is served either way.
    let response = harness.server.get(&path).await;
    assert_eq!(
        response.status().as_u16(),
        503,
        "storage pressure is never a reason to serve"
    );
    assert_eq!(common::body_error(response).await, "STORAGE_UNUSABLE");

    probation::tasks::maintenance::run_once(&harness.server.app()).await;
    assert_eq!(
        harness.server.status("/health/ready").await,
        503,
        "and it stays false while the content directory still refuses writes, \
         maintenance pass or not"
    );

    // "Until storage is usable again": once it is, the next maintenance pass finds
    // out without waiting for a request — a readiness probe that has taken this
    // instance out of rotation would otherwise leave it out for good.
    set_mode(&harness.temp_dir(), 0o700);
    set_mode(&harness.objects_dir(), 0o700);
    probation::tasks::maintenance::run_once(&harness.server.app()).await;
    assert_eq!(harness.server.status("/health/ready").await, 200);
    assert_eq!(
        harness.server.status(&path).await,
        403,
        "and the block published under storage pressure is enforced once storage is back"
    );
    harness.server.shutdown().await;
}
