//! Slice 7's third witness: durability (REL-01) and the storage-failure rule.
//!
//! SPEC §10: "Flush and synchronize the completed temporary file, atomically rename
//! within the same filesystem, synchronize the destination directory, and only then
//! commit its database mapping", and "A crash must never make a temporary file
//! downloadable", and "Storage write failures […] never relax policy to free space."
//!
//! The order is read off the publication itself: `ContentStore::publish` records each
//! step as the syscall behind it returns, so `file_sync_order_holds` is asserting on
//! what happened rather than on what a comment says happens.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, artifact_path, config_with_open_blocklist,
    npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path, publish_blocklist,
    snapshot_with,
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

    set_mode(&harness.objects_dir(), 0o700);
    harness.server.shutdown().await;
}

/// The state a crash between the rename and the commit leaves behind: bytes in the
/// content directory that no mapping names, and whatever was still in flight sitting
/// in `tmp/`.
///
/// Neither may be served. The temporary file is removed at startup, and the request
/// re-downloads and re-verifies rather than finding anything to reuse — so the bytes
/// the client receives are the verified ones and not the ones the crash left.
///
/// Reclaiming the orphaned object itself belongs to slice 8's eviction pass; what
/// matters here is that it is unreachable.
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
    // object whose mapping was never committed.
    let hostile = "hostile bytes a crash left behind\n";
    let stale_temp = temp_dir.join("1234-0.part");
    std::fs::write(&stale_temp, hostile).expect("the crashed download is left behind");
    let orphan = objects.join("ab").join("ab".repeat(32));
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
    assert_eq!(
        harness.server.status(&path).await,
        403,
        "storage pressure is never a reason to stop enforcing a block"
    );

    set_mode(&harness.temp_dir(), 0o700);
    set_mode(&harness.objects_dir(), 0o700);
    harness.server.shutdown().await;
}
