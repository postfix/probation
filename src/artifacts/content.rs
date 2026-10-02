//! The content cache on disk: where verified bytes live, and the publication order
//! SPEC §10 and finding REL-01 require.
//!
//! > "Flush and synchronize the completed temporary file, atomically rename within
//! > the same filesystem, synchronize the destination directory, and only then commit
//! > its database mapping."
//!
//! [`ContentStore::publish`] performs exactly those four steps in that order and
//! reports the ones it actually performed, so the order is a value a test can read
//! rather than a claim in a comment. The fifth step — committing the mapping — is the
//! caller's, and it happens only after `publish` has returned `Ok`.
//!
//! A temporary download is never reachable from a URL: it lives under `tmp/` with a
//! name nothing derives from a reference, and [`TempDownload`] removes its file on
//! drop. Startup removes whatever a crash left there
//! ([`ContentStore::remove_temp_files`]), so "a crash must never make a temporary
//! file downloadable" holds both while running and across a restart.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;

/// The verified SHA-256 of the bytes. A content key, never a reference id: two
/// references that turn out to hold the same bytes share one file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ContentKey([u8; 32]);

impl ContentKey {
    pub fn from_sha256(sha256: [u8; 32]) -> ContentKey {
        ContentKey(sha256)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// One step of the publication order, recorded as it completes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncStep {
    Flush,
    SyncFile,
    Rename,
    SyncDirectory,
}

/// What a publication did. `reused` means another reference had already published
/// these exact bytes, so the existing file was kept and nothing was replaced
/// (SPEC §10: "reuse the verified file without replacing an open file").
#[derive(Clone, Debug)]
pub struct Published {
    pub steps: Vec<SyncStep>,
    pub reused: bool,
}

const OBJECTS_DIR: &str = "objects";
const TEMP_DIR: &str = "tmp";
const TEMP_SUFFIX: &str = ".part";

/// Which files a request currently has open, and which ones the evictor has claimed.
///
/// One lock covers both, because the only question either answers is asked about the
/// same instant: eviction may claim a key exactly when nothing holds it open, and an
/// open may proceed exactly when the evictor has not claimed it. Splitting them would
/// put a window between the two halves of that question.
#[derive(Default)]
struct OpenFiles {
    pins: HashMap<ContentKey, usize>,
    /// Keys the maintenance pass is removing. An open started while a key is in here
    /// is refused, which the caller already handles as a stale mapping.
    evicting: HashSet<ContentKey>,
}

pub struct ContentStore {
    root: PathBuf,
    /// Only to keep two concurrent downloads in one process from choosing the same
    /// temporary name. It is not an identifier of anything.
    counter: AtomicU64,
    /// SPEC §4's `cache_max_bytes`, as the ceiling on concurrently reserved
    /// in-flight downloads.
    capacity: u64,
    reserved: Arc<AtomicU64>,
    open: Arc<Mutex<OpenFiles>>,
    /// SPEC §10: "access updates batched off the request path". A hit records its key
    /// here and the maintenance pass writes them, so no request waits for a write.
    touched: Mutex<Vec<ContentKey>>,
}

impl ContentStore {
    /// `data_dir/content`. The directories are created here, at startup, rather than
    /// on the first download.
    pub fn new(data_dir: &Path, capacity: u64) -> ContentStore {
        let root = data_dir.join("content");
        for directory in [root.join(OBJECTS_DIR), root.join(TEMP_DIR)] {
            if let Err(err) = std::fs::create_dir_all(&directory) {
                tracing::error!(
                    path = %directory.display(),
                    error = %err,
                    "the content cache directory could not be created; cold artifact requests \
                     will be refused"
                );
            }
        }
        ContentStore {
            root,
            counter: AtomicU64::new(0),
            capacity,
            reserved: Arc::new(AtomicU64::new(0)),
            open: Arc::new(Mutex::new(OpenFiles::default())),
            touched: Mutex::new(Vec::new()),
        }
    }

    /// How many bytes in-flight downloads currently hold against the budget. Zero
    /// once every temporary download has been published or abandoned.
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved.load(Ordering::Relaxed)
    }

    /// How many responses currently hold this key's file open. The evictor refuses to
    /// touch a key this answers non-zero for (SPEC §10: "Never evict open files").
    pub fn open_count(&self, key: &ContentKey) -> usize {
        self.open
            .lock()
            .expect("the open-file table")
            .pins
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    /// The keys read since the last pass, for the maintenance loop to write access
    /// times for. Draining is what keeps the list bounded by traffic between passes
    /// rather than by uptime.
    pub fn drain_touched(&self) -> Vec<ContentKey> {
        std::mem::take(&mut *self.touched.lock().expect("the touched-key list"))
    }

    /// SPEC §10: "Reserve capacity for temporary downloads; count unknown-length
    /// downloads against `max_artifact_bytes` until their final size is known. If
    /// capacity cannot be reserved or reclaimed, refuse the cold request."
    ///
    /// The ceiling is `cache_max_bytes`, and what it bounds is the bytes downloads
    /// hold *in flight*; the bytes already published are bounded by the maintenance
    /// pass, which evicts down to the same budget. Holding one counter for both would
    /// mean the content store tracking every publication and eviction itself, and the
    /// database already records exactly that.
    fn reserve(&self, bytes: u64) -> Result<Reservation, ContentError> {
        let mut held = self.reserved.load(Ordering::Acquire);
        loop {
            let wanted = held.saturating_add(bytes);
            if wanted > self.capacity {
                return Err(ContentError::NoCapacity {
                    wanted: bytes,
                    capacity: self.capacity,
                });
            }
            match self.reserved.compare_exchange_weak(
                held,
                wanted,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Reservation {
                        reserved: Arc::clone(&self.reserved),
                        bytes,
                    });
                }
                Err(current) => held = current,
            }
        }
    }

    /// Removes one key's bytes, unless a response has it open.
    ///
    /// Returns whether the file is gone. The claim and the pin check happen under one
    /// lock, so a request cannot open the file between them; a request that arrives
    /// after the claim is refused and re-fetches, which is the same path a missing
    /// file already takes.
    pub async fn evict(&self, key: &ContentKey) -> bool {
        {
            let mut open = self.open.lock().expect("the open-file table");
            if open.pins.get(key).copied().unwrap_or(0) > 0 {
                return false;
            }
            if !open.evicting.insert(*key) {
                // Another pass already has it.
                return false;
            }
        }

        let removed = match tokio::fs::remove_file(self.path_for(key)).await {
            Ok(()) => true,
            // Already gone is the outcome eviction wanted.
            Err(err) => err.kind() == io::ErrorKind::NotFound,
        };

        self.open
            .lock()
            .expect("the open-file table")
            .evicting
            .remove(key);
        removed
    }

    pub fn temp_dir(&self) -> PathBuf {
        self.root.join(TEMP_DIR)
    }

    /// One fan-out level, so a large cache does not put every object in one
    /// directory.
    pub fn path_for(&self, key: &ContentKey) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(OBJECTS_DIR).join(&hex[..2]).join(&hex)
    }

    /// SPEC §10: "On startup […] remove incomplete artifact temporary files." Returns
    /// how many were removed, which is what makes a crash visible in the log.
    pub fn remove_temp_files(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(self.temp_dir()) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            if std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::warn!(
                removed,
                "removed incomplete artifact downloads left by a previous run"
            );
        }
        removed
    }

    /// A temporary download holding `reserve_bytes` against the budget until it is
    /// published or dropped. SPEC §10 counts an unknown-length download against
    /// `max_artifact_bytes`, so that is what the caller reserves.
    pub async fn create_temp(&self, reserve_bytes: u64) -> Result<TempDownload, ContentError> {
        let reservation = self.reserve(reserve_bytes)?;
        let name = format!(
            "{}-{}{TEMP_SUFFIX}",
            std::process::id(),
            self.counter.fetch_add(1, Ordering::Relaxed)
        );
        let path = self.temp_dir().join(name);
        let file = tokio::fs::File::create(&path)
            .await
            .map_err(|source| ContentError::Write {
                path: path.clone(),
                source,
            })?;
        Ok(TempDownload {
            path: Some(path),
            file: Some(file),
            _reservation: reservation,
        })
    }

    /// REL-01, in order: flush, fsync the file, rename it into place, fsync the
    /// destination directory. The caller commits the database mapping only after
    /// this returns `Ok`.
    pub async fn publish(
        &self,
        mut temp: TempDownload,
        key: &ContentKey,
    ) -> Result<Published, ContentError> {
        let mut steps = Vec::with_capacity(4);
        let (path, mut file) = temp.take();

        file.flush().await.map_err(|source| ContentError::Write {
            path: path.clone(),
            source,
        })?;
        steps.push(SyncStep::Flush);

        // The bytes, then the metadata: after this the file's contents survive a
        // power loss, which is what makes the rename meaningful.
        file.sync_all()
            .await
            .map_err(|source| ContentError::Write {
                path: path.clone(),
                source,
            })?;
        steps.push(SyncStep::SyncFile);
        drop(file);

        let destination = self.path_for(key);
        let directory = destination
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.root.join(OBJECTS_DIR));
        tokio::fs::create_dir_all(&directory)
            .await
            .map_err(|source| ContentError::Write {
                path: directory.clone(),
                source,
            })?;

        // Another reference already published these exact bytes. Renaming over it
        // would replace a file other responses may have open, and there is nothing
        // to gain: the content is addressed by its own digest.
        if tokio::fs::metadata(&destination).await.is_ok() {
            let _ = tokio::fs::remove_file(&path).await;
            return Ok(Published {
                steps,
                reused: true,
            });
        }

        tokio::fs::rename(&path, &destination)
            .await
            .map_err(|source| ContentError::Write {
                path: destination.clone(),
                source,
            })?;
        steps.push(SyncStep::Rename);

        // Renaming is atomic but the directory entry is not durable until the
        // directory itself is synchronised; without this a crash can leave the file
        // reachable from a committed mapping and gone from the filesystem.
        sync_directory(&directory).await?;
        steps.push(SyncStep::SyncDirectory);

        Ok(Published {
            steps,
            reused: false,
        })
    }

    /// Opens an already verified file. SPEC §9: verified cache hits are not rehashed,
    /// but a missing file or a size mismatch discards the mapping — which is the
    /// caller's job, on `Err`.
    pub async fn open_verified(
        &self,
        key: &ContentKey,
        expected_size: u64,
    ) -> Result<PinnedFile, ContentError> {
        let path = self.path_for(key);

        // The pin is taken *before* the file is opened, so there is no instant in
        // which this request is reading a file the evictor believes nobody holds.
        let pin = {
            let mut open = self.open.lock().expect("the open-file table");
            if open.evicting.contains(key) {
                return Err(ContentError::Missing {
                    path,
                    source: io::Error::other("the cached file is being evicted"),
                });
            }
            *open.pins.entry(*key).or_insert(0) += 1;
            OpenPin {
                open: Arc::clone(&self.open),
                key: *key,
            }
        };

        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|source| ContentError::Missing {
                path: path.clone(),
                source,
            })?;
        let size = file
            .metadata()
            .await
            .map_err(|source| ContentError::Missing {
                path: path.clone(),
                source,
            })?
            .len();
        if size != expected_size {
            return Err(ContentError::SizeMismatch {
                path,
                expected: expected_size,
                found: size,
            });
        }

        // Off the request path by construction: the write happens in the maintenance
        // pass that drains this (SPEC §10).
        self.touched
            .lock()
            .expect("the touched-key list")
            .push(*key);

        Ok(PinnedFile {
            file,
            size,
            _pin: pin,
        })
    }
}

/// Bytes held against `cache_max_bytes` while a download is in flight. Dropping it
/// gives them back, which is what "removes its temporary file and reservation" means
/// when a download is abandoned.
struct Reservation {
    reserved: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.reserved.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// One response's claim on one cached file. While any exist for a key, eviction
/// leaves that key alone; the last one to drop releases it.
struct OpenPin {
    open: Arc<Mutex<OpenFiles>>,
    key: ContentKey,
}

impl Drop for OpenPin {
    fn drop(&mut self) {
        let mut open = self.open.lock().expect("the open-file table");
        match open.pins.get_mut(&self.key) {
            Some(count) if *count > 1 => *count -= 1,
            // The last holder removes the entry rather than leaving a zero behind, so
            // the table is the size of what is open and not of what has ever been.
            Some(_) => {
                open.pins.remove(&self.key);
            }
            None => {}
        }
    }
}

/// `fsync` on a directory needs it opened for reading, which is what makes a rename
/// durable on Linux.
async fn sync_directory(directory: &Path) -> Result<(), ContentError> {
    let handle = tokio::fs::File::open(directory)
        .await
        .map_err(|source| ContentError::Write {
            path: directory.to_path_buf(),
            source,
        })?;
    handle
        .sync_all()
        .await
        .map_err(|source| ContentError::Write {
            path: directory.to_path_buf(),
            source,
        })
}

/// An in-progress download. Dropping it removes the file: a download that fails, is
/// refused by policy, or is abandoned leaves nothing behind.
pub struct TempDownload {
    path: Option<PathBuf>,
    file: Option<tokio::fs::File>,
    /// Released with the file, so an abandoned download gives its bytes back to the
    /// budget at the same instant it gives the disk space back.
    _reservation: Reservation,
}

impl TempDownload {
    pub fn path(&self) -> &Path {
        self.path.as_deref().unwrap_or(Path::new(""))
    }

    pub async fn write_all(&mut self, chunk: &[u8]) -> Result<(), ContentError> {
        let path = self.path.clone().unwrap_or_default();
        match &mut self.file {
            Some(file) => file
                .write_all(chunk)
                .await
                .map_err(|source| ContentError::Write { path, source }),
            None => Err(ContentError::Write {
                path,
                source: io::Error::other("the temporary download was already published"),
            }),
        }
    }

    /// Consumes the handle without letting `Drop` remove the file, because the file
    /// is about to become the published object.
    fn take(&mut self) -> (PathBuf, tokio::fs::File) {
        let path = self.path.take().unwrap_or_default();
        let file = self
            .file
            .take()
            .expect("a temporary download is published once");
        (path, file)
    }
}

impl Drop for TempDownload {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// An open, verified file. Eviction may not remove it while it is held: the `_pin`
/// below is a count [`ContentStore::evict`] consults under the same lock it claims a
/// key with, so there is no instant in which a request is reading a file the evictor
/// believes is free (SPEC §10: "Never evict open files").
pub struct PinnedFile {
    file: tokio::fs::File,
    size: u64,
    _pin: OpenPin,
}

impl PinnedFile {
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The open file itself. The pin travels with `self`, so the bytes stay where
    /// they are for exactly as long as the caller holds this value — which, for a
    /// response, is until the last body byte has left or a deadline has ended it.
    pub fn file_mut(&mut self) -> &mut tokio::fs::File {
        &mut self.file
    }
}

#[derive(Debug)]
pub enum ContentError {
    /// The file a mapping names is not there, or cannot be opened.
    Missing { path: PathBuf, source: io::Error },
    /// It is there and is the wrong size, so the mapping is stale (SPEC §9).
    SizeMismatch {
        path: PathBuf,
        expected: u64,
        found: u64,
    },
    /// The local filesystem refused a write: no space, no permission, no directory.
    /// SPEC §10 is explicit that this is a `503` and never a relaxation of policy.
    Write { path: PathBuf, source: io::Error },
    /// SPEC §10: "If capacity cannot be reserved or reclaimed, refuse the cold
    /// request without deleting in-use files." Also a `503`, and also never a
    /// relaxation of policy.
    NoCapacity { wanted: u64, capacity: u64 },
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentError::Missing { path, source } => {
                write!(f, "cannot open {}: {source}", path.display())
            }
            ContentError::SizeMismatch {
                path,
                expected,
                found,
            } => write!(
                f,
                "{} holds {found} bytes, not the {expected} its mapping records",
                path.display()
            ),
            ContentError::Write { path, source } => {
                write!(f, "cannot write {}: {source}", path.display())
            }
            ContentError::NoCapacity { wanted, capacity } => write!(
                f,
                "cannot reserve {wanted} bytes against the {capacity}-byte cache budget"
            ),
        }
    }
}

impl std::error::Error for ContentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ContentError::Missing { source, .. } | ContentError::Write { source, .. } => {
                Some(source)
            }
            ContentError::SizeMismatch { .. } | ContentError::NoCapacity { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> ContentKey {
        ContentKey::from_sha256([byte; 32])
    }

    /// The order REL-01 names, read off the steps the real publication performed.
    #[tokio::test]
    async fn publication_flushes_syncs_renames_then_syncs_the_directory() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let store = ContentStore::new(dir.path(), 1 << 30);

        let mut temp = store.create_temp(64).await.expect("a temporary download");
        temp.write_all(b"verified bytes").await.expect("the write");
        let temp_path = temp.path().to_path_buf();

        let published = store.publish(temp, &key(1)).await.expect("the publication");
        assert_eq!(
            published.steps,
            vec![
                SyncStep::Flush,
                SyncStep::SyncFile,
                SyncStep::Rename,
                SyncStep::SyncDirectory
            ]
        );
        assert!(!published.reused);
        assert!(!temp_path.exists(), "the temporary file is gone");
        assert_eq!(
            std::fs::read(store.path_for(&key(1))).expect("the published file"),
            b"verified bytes"
        );
    }

    /// Dropping an unpublished download removes its file, so a failure or a refusal
    /// leaves nothing a later request could find.
    #[tokio::test]
    async fn an_unpublished_download_removes_its_own_file() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let store = ContentStore::new(dir.path(), 1 << 30);

        let mut temp = store.create_temp(64).await.expect("a temporary download");
        temp.write_all(b"never verified").await.expect("the write");
        let path = temp.path().to_path_buf();
        assert!(path.exists());

        drop(temp);
        assert!(
            !path.exists(),
            "an abandoned download leaves no file behind"
        );
    }

    #[tokio::test]
    async fn a_second_reference_reuses_published_bytes_rather_than_replacing_them() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let store = ContentStore::new(dir.path(), 1 << 30);

        let mut first = store.create_temp(64).await.expect("a temporary download");
        first.write_all(b"shared bytes").await.expect("the write");
        store.publish(first, &key(2)).await.expect("the first");

        let mut second = store.create_temp(64).await.expect("a temporary download");
        second.write_all(b"shared bytes").await.expect("the write");
        let published = store.publish(second, &key(2)).await.expect("the second");

        assert!(published.reused, "the existing file is kept");
        assert!(!published.steps.contains(&SyncStep::Rename));
        assert_eq!(
            std::fs::read_dir(store.temp_dir())
                .expect("the temp directory")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn a_mapping_to_a_file_of_the_wrong_size_is_reported_rather_than_served() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let store = ContentStore::new(dir.path(), 1 << 30);

        let mut temp = store.create_temp(64).await.expect("a temporary download");
        temp.write_all(b"four").await.expect("the write");
        store.publish(temp, &key(3)).await.expect("the publication");

        assert!(store.open_verified(&key(3), 4).await.is_ok());
        assert!(matches!(
            store.open_verified(&key(3), 5).await,
            Err(ContentError::SizeMismatch { .. })
        ));
        assert!(matches!(
            store.open_verified(&key(4), 4).await,
            Err(ContentError::Missing { .. })
        ));
    }

    /// FLOW-01: an abandoned download leaves no reservation behind, or a service that
    /// only ever lost downloads would eventually refuse every cold request.
    #[tokio::test]
    async fn an_abandoned_download_gives_its_reservation_back() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let store = ContentStore::new(dir.path(), 100);

        let temp = store.create_temp(60).await.expect("a temporary download");
        assert_eq!(store.reserved_bytes(), 60);
        assert!(
            matches!(
                store.create_temp(60).await,
                Err(ContentError::NoCapacity { .. })
            ),
            "a second reservation over the budget is refused, not queued"
        );

        drop(temp);
        assert_eq!(store.reserved_bytes(), 0);
        assert!(
            store.create_temp(60).await.is_ok(),
            "and the budget is free again"
        );
    }

    /// SPEC §10: "Never evict open files."
    #[tokio::test]
    async fn eviction_refuses_a_key_a_response_holds_open() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let store = ContentStore::new(dir.path(), 1 << 30);

        let mut temp = store.create_temp(64).await.expect("a temporary download");
        temp.write_all(b"held").await.expect("the write");
        store.publish(temp, &key(5)).await.expect("the publication");

        let held = store
            .open_verified(&key(5), 4)
            .await
            .expect("the open file");
        assert_eq!(store.open_count(&key(5)), 1);
        assert!(!store.evict(&key(5)).await, "an open file is left alone");
        assert!(store.path_for(&key(5)).exists());

        drop(held);
        assert_eq!(store.open_count(&key(5)), 0);
        assert!(store.evict(&key(5)).await, "and is evictable once released");
        assert!(!store.path_for(&key(5)).exists());
    }
}
