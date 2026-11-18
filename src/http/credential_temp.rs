//! Request-owned temporary files for credential-bearing reads (LS-F16).
//!
//! Bodies are held in a file in a per-process subdirectory
//! `<data_dir>/credential-reads/<pid>-<nonce>/` (mode 0700, unlinked at creation where the
//! platform supports it) and verified complete before any byte is delivered, so every
//! refusal here happens before the response starts. There is no per-request cap by
//! default; `max_request_bytes` and `max_total_bytes` are optional. A process holds a lock
//! file in its subdirectory; the startup sweep removes only subdirectories whose lock it
//! can acquire.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, PartialEq, Eq)]
pub enum TempError {
    /// 413, no `Retry-After`: the refusal is deterministic.
    TooLarge,
    /// 503 with `Retry-After`: fits alone, not beside the bytes in use.
    Busy,
    /// 503 without `Retry-After`: the operator must free space.
    NoSpace,
    UnsafeParent,
    Io,
}

impl TempError {
    pub fn status(&self) -> u16 {
        match self {
            TempError::TooLarge => 413,
            _ => 503,
        }
    }

    pub fn retry_after(&self) -> bool {
        matches!(self, TempError::Busy)
    }

    pub fn from_io(error: &io::Error) -> TempError {
        if error.kind() == io::ErrorKind::StorageFull || error.raw_os_error() == Some(28) {
            TempError::NoSpace
        } else {
            TempError::Io
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    pub max_request_bytes: Option<u64>,
    pub max_total_bytes: Option<u64>,
}

struct Shared {
    limits: Limits,
    used: AtomicU64,
}

pub struct CredentialTemp {
    dir: PathBuf,
    shared: Arc<Shared>,
    _lock: File,
}

/// Releases `bytes` from the process-wide total when dropped.
struct Account {
    shared: Arc<Shared>,
    bytes: u64,
}

impl Drop for Account {
    fn drop(&mut self) {
        self.shared.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

pub struct TempFile {
    file: File,
    account: Account,
}

/// A fully written body, readable from `file`; its bytes stay counted until it is dropped.
pub struct CompletedTemp {
    pub file: File,
    _account: Account,
}

impl CredentialTemp {
    pub fn open(data_dir: &Path, limits: Limits) -> Result<CredentialTemp, TempError> {
        let parent = data_dir.join("credential-reads");
        match std::fs::symlink_metadata(&parent) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => return Err(TempError::UnsafeParent),
            Ok(meta) => {
                Self::check_owner(data_dir, &meta)?;
                // A pre-existing parent that others can write is tightened before use.
                Self::private(&parent)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&parent).map_err(|_| TempError::Io)?;
                Self::private(&parent)?;
            }
            Err(_) => return Err(TempError::Io),
        }
        Self::sweep(&parent);
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = parent.join(format!("{}-{nonce:08x}{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir(&dir).map_err(|_| TempError::Io)?;
        Self::private(&dir)?;
        let lock = File::create(dir.join("lock")).map_err(|_| TempError::Io)?;
        lock.try_lock().map_err(|_| TempError::Io)?;
        Ok(CredentialTemp { dir, shared: Arc::new(Shared { limits, used: AtomicU64::new(0) }), _lock: lock })
    }

    #[cfg(unix)]
    fn private(path: &Path) -> Result<(), TempError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|_| TempError::Io)
    }

    #[cfg(not(unix))]
    fn private(_path: &Path) -> Result<(), TempError> {
        Ok(())
    }

    /// The parent must belong to the service user: the owner of the data directory.
    #[cfg(unix)]
    fn check_owner(data_dir: &Path, parent: &std::fs::Metadata) -> Result<(), TempError> {
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::metadata(data_dir).map_err(|_| TempError::Io)?.uid();
        if parent.uid() == owner { Ok(()) } else { Err(TempError::UnsafeParent) }
    }

    #[cfg(not(unix))]
    fn check_owner(_data_dir: &Path, _parent: &std::fs::Metadata) -> Result<(), TempError> {
        Ok(())
    }

    /// Removes only subdirectories whose lock file can be acquired (no live owner). A lock
    /// that is a symlink is never opened (it could point anywhere); a directory with no lock
    /// at all is removed only once it is older than a minute, so one a starting process has
    /// just created is not taken from it.
    fn sweep(parent: &Path) {
        const GRACE: std::time::Duration = std::time::Duration::from_secs(60);
        for entry in std::fs::read_dir(parent).into_iter().flatten().flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if !meta.is_dir() {
                continue;
            }
            let lock_path = path.join("lock");
            match std::fs::symlink_metadata(&lock_path) {
                Ok(lock_meta) if lock_meta.file_type().is_file() => {
                    let Ok(lock) = File::options().read(true).write(true).open(&lock_path) else { continue };
                    if lock.try_lock().is_ok() {
                        let _ = std::fs::remove_dir_all(&path);
                    }
                }
                Ok(_) => continue,
                Err(_) => {
                    let old = meta.modified().ok().and_then(|at| at.elapsed().ok()).is_some_and(|age| age > GRACE);
                    if old {
                        let _ = std::fs::remove_dir_all(&path);
                    }
                }
            }
        }
    }

    /// Admission for one body. A refusal here is before the first body byte.
    pub fn begin(&self, content_length: Option<u64>) -> Result<TempFile, TempError> {
        let limits = self.shared.limits;
        if let Some(length) = content_length {
            if limits.max_request_bytes.is_some_and(|max| length > max) || limits.max_total_bytes.is_some_and(|max| length > max) {
                return Err(TempError::TooLarge);
            }
            if limits.max_total_bytes.is_some_and(|max| self.shared.used.load(Ordering::SeqCst) + length > max) {
                return Err(TempError::Busy);
            }
        }
        let file = tempfile::tempfile_in(&self.dir).map_err(|error| TempError::from_io(&error))?;
        Ok(TempFile { file, account: Account { shared: Arc::clone(&self.shared), bytes: 0 } })
    }

    /// Bytes currently held by this process (the readiness gauge).
    pub fn used_bytes(&self) -> u64 {
        self.shared.used.load(Ordering::SeqCst)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl TempFile {
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), TempError> {
        let limits = self.account.shared.limits;
        let len = bytes.len() as u64;
        let own = self.account.bytes + len;
        if limits.max_request_bytes.is_some_and(|max| own > max) || limits.max_total_bytes.is_some_and(|max| own > max) {
            return Err(TempError::TooLarge);
        }
        // Reserve before writing so concurrent bodies cannot jointly pass the total.
        let after = self.account.shared.used.fetch_add(len, Ordering::SeqCst) + len;
        if limits.max_total_bytes.is_some_and(|max| after > max) {
            self.account.shared.used.fetch_sub(len, Ordering::SeqCst);
            return Err(TempError::Busy);
        }
        self.account.bytes += len;
        self.file.write_all(bytes).map_err(|error| TempError::from_io(&error))
    }

    /// [`TempFile::write`] on the blocking pool, so a large body never stalls an async
    /// worker. Takes and returns `self` because the blocking task owns the file meanwhile.
    pub async fn write_blocking(mut self, bytes: Vec<u8>) -> Result<TempFile, TempError> {
        tokio::task::spawn_blocking(move || self.write(&bytes).map(|()| self))
            .await
            .map_err(|_| TempError::Io)?
    }

    pub fn into_file(self) -> CompletedTemp {
        CompletedTemp { file: self.file, _account: self.account }
    }
}
