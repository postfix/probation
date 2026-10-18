//! The exclusive data-directory lock (SPEC §10), taken before the database is
//! opened.
//!
//! The lock is an `flock` on `<data_dir>/lock`, so the kernel releases it when the
//! process dies however it dies. That is what makes a crashed instance's directory
//! usable by the next start without an operator clearing a stale marker by hand.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs4::FileExt;

/// The name of the lock file inside the data directory.
const LOCK_FILE: &str = "lock";

/// A held exclusive lock. Dropping it (or the process ending) releases the lock;
/// the file itself is left in place, because removing it would race a second
/// instance that has already opened it.
#[derive(Debug)]
pub struct DataDirLock {
    // Held for its `Drop`: closing the descriptor releases the `flock`.
    _file: File,
}

/// Takes the exclusive lock on `data_dir`, which must already exist.
///
/// A lock another process holds is fatal rather than a degraded mode: two
/// instances sharing one data directory would both believe they own the database,
/// the content cache and the temp files in it.
pub fn acquire(data_dir: &Path) -> Result<DataDirLock, LockError> {
    let path = data_dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| LockError::Open {
            path: path.clone(),
            source,
        })?;

    // `try_lock` rather than `lock`: a second instance must fail immediately with a
    // name an operator can act on, not block forever on a directory it will never get.
    //
    // Called through the trait on purpose. `std::fs::File` has grown an inherent
    // `try_lock` of its own with a same-named error type, and an inherent method wins
    // method resolution — so `file.try_lock()` would silently stop being the `fs4`
    // call Gate 3 chose.
    FileExt::try_lock(&file).map_err(|err| match err {
        fs4::TryLockError::WouldBlock => LockError::Held { path: path.clone() },
        fs4::TryLockError::Error(source) => LockError::Open {
            path: path.clone(),
            source,
        },
    })?;

    Ok(DataDirLock { _file: file })
}

#[derive(Debug)]
pub enum LockError {
    Open { path: PathBuf, source: io::Error },
    Held { path: PathBuf },
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Open { path, source } => {
                write!(f, "cannot open the lock file {}: {source}", path.display())
            }
            LockError::Held { path } => write!(
                f,
                "another instance holds the data-directory lock {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LockError::Open { source, .. } => Some(source),
            LockError::Held { .. } => None,
        }
    }
}
