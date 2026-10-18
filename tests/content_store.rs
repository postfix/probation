//! The content store's publish/open-verified seam, as properties.
//!
//! The cache is content-addressed, so the bytes at a key's path are either the bytes
//! that hash to that key or they are not the cache entry at all. Two promises follow,
//! and both are stated for *any* input rather than for the inputs a hand-written
//! example happens to pick:
//!
//! * whatever is already sitting at a key's path — a crash's leftovers, a truncated
//!   copy, bytes planted under the right name — publishing verified bytes under that
//!   key leaves the verified bytes there, and opening the key reads them back;
//! * however a publication ends — published, reused, refused by the filesystem, or
//!   abandoned — `tmp/` is empty and no reservation is held once it has.

use std::error::Error as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use probation::artifacts::content::{ContentError, ContentKey, ContentStore};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

fn key_of(bytes: &[u8]) -> ContentKey {
    ContentKey::from_sha256(Sha256::digest(bytes).into())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime")
}

fn temp_entries(store: &ContentStore) -> usize {
    std::fs::read_dir(store.temp_dir()).map_or(0, |entries| entries.count())
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("the mode is set");
}

async fn publish(store: &ContentStore, bytes: &[u8]) -> bool {
    let mut temp = store
        .create_temp(bytes.len() as u64 + 1)
        .await
        .expect("a temporary download");
    temp.write_all(bytes).await.expect("the write");
    store.publish(temp, &key_of(bytes)).await.is_ok()
}

async fn read_back(store: &ContentStore, bytes: &[u8]) -> Vec<u8> {
    let mut opened = store
        .open_verified(&key_of(bytes), bytes.len() as u64)
        .await
        .expect("the published key opens at its verified size");
    let mut read = Vec::new();
    opened
        .file_mut()
        .read_to_end(&mut read)
        .await
        .expect("the file reads");
    read
}

/// One way a publication can end.
#[derive(Clone, Debug)]
enum Outcome {
    /// Published, or reused when the same bytes were published before.
    Publish(Vec<u8>),
    /// The fan-out directory takes no new entry, so the rename fails after the file
    /// has been flushed and synchronised.
    RefusedByTheFilesystem(Vec<u8>),
    /// Written and then dropped without being published.
    Abandon(Vec<u8>),
}

fn outcome() -> impl Strategy<Value = Outcome> {
    // A small alphabet, so the same bytes recur and the reuse path is exercised.
    let bytes = prop::collection::vec(0u8..4, 1..6);
    prop_oneof![
        bytes.clone().prop_map(Outcome::Publish),
        bytes.clone().prop_map(Outcome::RefusedByTheFilesystem),
        bytes.prop_map(Outcome::Abandon),
    ]
}

proptest! {
    // `Direct`, because `SourceParallel` looks for a `lib.rs` beside the source file
    // and an integration test has none.
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "proptest-regressions/content_store.txt",
        ))),
        ..ProptestConfig::default()
    })]

    /// Whatever is at the key's path beforehand, the verified bytes are what the key
    /// serves afterwards.
    #[test]
    fn publishing_over_anything_at_the_path_leaves_the_verified_bytes(
        verified in prop::collection::vec(any::<u8>(), 1..64),
        planted in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = ContentStore::new(dir.path(), 1 << 20);
        let path = store.path_for(&key_of(&verified));
        std::fs::create_dir_all(path.parent().expect("a fan-out directory")).expect("the directory");
        std::fs::write(&path, &planted).expect("the planted file");

        let read = runtime().block_on(async {
            prop_assert!(publish(&store, &verified).await, "the publication succeeds");
            Ok(read_back(&store, &verified).await)
        })?;
        prop_assert_eq!(read, verified);
        prop_assert_eq!(temp_entries(&store), 0);
    }

    /// `tmp/` is empty, and the budget whole, after every publication however it ends.
    #[test]
    fn every_publication_outcome_leaves_tmp_empty(
        outcomes in prop::collection::vec(outcome(), 1..12),
    ) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = ContentStore::new(dir.path(), 1 << 20);
        let runtime = runtime();

        for outcome in outcomes {
            runtime.block_on(async {
                match &outcome {
                    Outcome::Publish(bytes) => {
                        prop_assert!(publish(&store, bytes).await, "{:?} publishes", outcome);
                    }
                    Outcome::RefusedByTheFilesystem(bytes) => {
                        let fan_out = store
                            .path_for(&key_of(bytes))
                            .parent()
                            .expect("a fan-out directory")
                            .to_path_buf();
                        std::fs::create_dir_all(&fan_out).expect("the fan-out directory");
                        set_mode(&fan_out, 0o500);
                        // Refused, or reused when these bytes were already published:
                        // either is an ending, and the property is about what is left.
                        let _ = publish(&store, bytes).await;
                        set_mode(&fan_out, 0o700);
                    }
                    Outcome::Abandon(bytes) => {
                        let mut temp = store.create_temp(64).await.expect("a temporary download");
                        temp.write_all(bytes).await.expect("the write");
                    }
                }
                Ok(())
            })?;
            prop_assert_eq!(temp_entries(&store), 0, "after {:?}", outcome);
            prop_assert_eq!(store.reserved_bytes(), 0, "after {:?}", outcome);
        }
    }
}

// ---------------------------------------------------------------------------
// The failure edges, one example each
// ---------------------------------------------------------------------------

async fn published(store: &ContentStore, bytes: &[u8]) -> ContentKey {
    assert!(publish(store, bytes).await, "the publication succeeds");
    key_of(bytes)
}

/// A content key prints as the hex of the digest it is, which is what every log
/// line naming one relies on.
#[test]
fn a_content_key_prints_as_its_digest() {
    let key = key_of(b"bytes");
    assert_eq!(key.to_string(), key.to_hex());
    assert_eq!(key.to_hex().len(), 64);
}

/// A data directory the store cannot create its directories in refuses every cold
/// download, and says which path it could not write.
#[tokio::test]
async fn an_unwritable_data_directory_refuses_downloads_with_the_path() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let not_a_directory = dir.path().join("file");
    std::fs::write(&not_a_directory, b"").expect("a file where the data directory goes");

    let store = ContentStore::new(&not_a_directory, 1 << 20);
    let refused = store
        .create_temp(1)
        .await
        .err()
        .expect("no temporary download");
    assert!(matches!(refused, ContentError::Write { .. }));
    assert!(
        refused.to_string().starts_with("cannot write "),
        "{refused}"
    );
    assert!(refused.source().is_some(), "the io error travels with it");
    assert_eq!(
        store.remove_temp_files(),
        0,
        "and there is no tmp/ to clean"
    );
    assert!(
        store.probe().await.is_err(),
        "and a probe finds it still broken"
    );
}

/// The probe writes into both directories, so a content directory that refuses new
/// objects fails it even while `tmp/` is fine.
#[tokio::test]
async fn the_probe_fails_while_objects_refuses_writes() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 20);
    assert!(store.probe().await.is_ok());

    let objects = dir.path().join("content").join("objects");
    set_mode(&objects, 0o500);
    let probed = store.probe().await;
    set_mode(&objects, 0o700);
    assert!(matches!(probed, Err(ContentError::Write { .. })));
    assert_eq!(temp_entries(&store), 0);
}

/// A write the filesystem refuses surfaces when the publication flushes it, and the
/// publication fails rather than renaming a short file into place.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_write_the_disk_refuses_fails_the_publication() {
    // A fresh store, whose first temporary name is linked to a device that refuses
    // every write with `ENOSPC`.
    async fn writing_to_a_full_disk(
        dir: &Path,
    ) -> (ContentStore, probation::artifacts::content::TempDownload) {
        let store = ContentStore::new(dir, 1 << 20);
        let first = store
            .temp_dir()
            .join(format!("{}-0.part", std::process::id()));
        std::os::unix::fs::symlink("/dev/full", &first).expect("the fault is planted");
        let temp = store.create_temp(64).await.expect("a temporary download");
        (store, temp)
    }

    // A write is buffered, so a lone refused write surfaces when the publication
    // flushes it; a second write surfaces it at once. Either way nothing is placed.
    for writes in [1, 2] {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (store, mut temp) = writing_to_a_full_disk(dir.path()).await;
        let mut outcome = Ok(());
        for _ in 0..writes {
            outcome = temp.write_all(b"bytes").await;
        }
        assert_eq!(outcome.is_err(), writes == 2, "after {writes} writes");
        let refused = store.publish(temp, &key_of(b"bytes")).await;
        assert!(
            matches!(refused, Err(ContentError::Write { .. })),
            "{refused:?}",
            refused = refused.err()
        );
        assert!(!store.path_for(&key_of(b"bytes")).exists());
        assert_eq!(temp_entries(&store), 0);
    }
}

/// An object whose size is right but which cannot be opened is not reused: it is
/// replaced with the verified bytes.
#[tokio::test]
async fn an_unreadable_object_at_the_path_is_replaced() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 20);
    let path = store.path_for(&key_of(b"verified"));
    std::fs::create_dir_all(path.parent().expect("a fan-out directory")).expect("the directory");
    std::fs::write(&path, b"verified").expect("the planted file");
    set_mode(&path, 0o000);

    published(&store, b"verified").await;
    assert_eq!(read_back(&store, b"verified").await, b"verified");
}

/// Eviction and an open race for the same key; whichever claims it first wins, and
/// the loser is told so rather than reading a file that is being removed.
#[tokio::test]
async fn an_open_during_eviction_is_refused_and_a_second_eviction_stands_aside() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 20);
    let key = published(&store, b"evicted").await;

    // `join!` polls in order: the first eviction claims the key and yields inside
    // the removal, and only then do the other two run.
    let (first, second, opened) = tokio::join!(
        store.evict(&key),
        store.evict(&key),
        store.open_verified(&key, 7)
    );
    assert!(first, "the first eviction removed the file");
    assert!(!second, "a second pass over the same key stands aside");
    let refused = opened.err().expect("the open is refused");
    assert!(matches!(refused, ContentError::Missing { .. }));
    assert!(refused.to_string().starts_with("cannot open "), "{refused}");
    assert!(refused.source().is_some());
    assert!(!store.path_for(&key).exists());
}

/// Two responses can hold one file; it stays pinned until the last lets go.
#[tokio::test]
async fn a_file_held_twice_stays_pinned_until_both_let_go() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 20);
    let key = published(&store, b"shared").await;

    let first = store.open_verified(&key, 6).await.expect("the first hold");
    let second = store.open_verified(&key, 6).await.expect("the second hold");
    assert_eq!(store.open_count(&key), 2);
    drop(first);
    assert_eq!(store.open_count(&key), 1);
    assert!(!store.evict(&key).await, "still held");
    drop(second);
    assert_eq!(store.open_count(&key), 0);
    assert!(store.evict(&key).await, "and evictable once both let go");
}

/// A file the filesystem will not let eviction remove is reported as still there,
/// so its mapping is kept.
#[tokio::test]
async fn an_eviction_the_filesystem_refuses_keeps_the_file() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 1 << 20);
    let key = published(&store, b"kept").await;
    let fan_out = store
        .path_for(&key)
        .parent()
        .expect("a fan-out directory")
        .to_path_buf();

    set_mode(&fan_out, 0o500);
    let evicted = store.evict(&key).await;
    set_mode(&fan_out, 0o700);
    assert!(!evicted);
    assert!(store.path_for(&key).exists());
}

/// The two refusals that carry no io error name what they refused.
#[tokio::test]
async fn a_wrong_size_and_a_full_budget_say_what_they_refused() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = ContentStore::new(dir.path(), 10);
    let key = published(&store, b"four").await;

    let mismatch = store
        .open_verified(&key, 5)
        .await
        .err()
        .expect("a size mismatch");
    assert!(
        mismatch.to_string().contains("holds 4 bytes, not the 5"),
        "{mismatch}"
    );
    assert!(mismatch.source().is_none());

    let full = store.create_temp(11).await.err().expect("over the budget");
    assert_eq!(
        full.to_string(),
        "cannot reserve 11 bytes against the 10-byte cache budget"
    );
    assert!(full.source().is_none());
}
