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

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use probation::artifacts::content::{ContentKey, ContentStore};
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
