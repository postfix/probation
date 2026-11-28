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
    /// The checked folder of this process (`dir`), held open: every file is created relative to it, never by path again.
    #[cfg(unix)]
    dirfd: std::os::fd::OwnedFd,
    /// The checked folders, held open without `FILE_SHARE_DELETE` (Windows): neither can be renamed or replaced while this lives.
    #[cfg(windows)]
    _pins: [File; 2],
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
    #[cfg(unix)]
    pub fn open(data_dir: &Path, limits: Limits) -> Result<CredentialTemp, TempError> {
        use rustix::fs::Mode;
        let parent_path = data_dir.join("credential-reads");
        // The folder is opened once, without following a symlink and only if it is a directory; the owner is read from
        // that descriptor, and everything after (mode, sweep, creates) goes through it, so swapping the path changes nothing.
        let parent = match fd::open_dir(rustix::fs::CWD, &parent_path) {
            Ok(parent) => parent,
            Err(errno) if errno == rustix::io::Errno::NOENT => {
                rustix::fs::mkdirat(rustix::fs::CWD, &parent_path, Mode::RWXU)
                    .map_err(|_| TempError::Io)?;
                fd::open_dir(rustix::fs::CWD, &parent_path).map_err(|_| TempError::Io)?
            }
            Err(errno)
                if errno == rustix::io::Errno::LOOP || errno == rustix::io::Errno::NOTDIR =>
            {
                return Err(TempError::UnsafeParent);
            }
            Err(_) => return Err(TempError::Io),
        };
        Self::check_owner(&rustix::fs::fstat(&parent).map_err(|_| TempError::Io)?)?;
        // A pre-existing parent that others can write is tightened before use.
        rustix::fs::fchmod(&parent, Mode::RWXU).map_err(|_| TempError::Io)?;
        fd::sweep(&parent);
        let name = Self::unique_name();
        rustix::fs::mkdirat(&parent, name.as_str(), Mode::RWXU).map_err(|_| TempError::Io)?;
        let dirfd = fd::open_dir(&parent, name.as_str()).map_err(|_| TempError::Io)?;
        rustix::fs::fchmod(&dirfd, Mode::RWXU).map_err(|_| TempError::Io)?;
        let lock = File::from(
            rustix::fs::openat(
                &dirfd,
                "lock",
                rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| TempError::Io)?,
        );
        lock.try_lock().map_err(|_| TempError::Io)?;
        Ok(CredentialTemp {
            dir: parent_path.join(name),
            dirfd,
            shared: Arc::new(Shared {
                limits,
                used: AtomicU64::new(0),
            }),
            _lock: lock,
        })
    }

    #[cfg(not(unix))]
    #[cfg_attr(not(windows), allow(unused_variables))]
    pub fn open(data_dir: &Path, limits: Limits) -> Result<CredentialTemp, TempError> {
        let parent_path = data_dir.join("credential-reads");
        // Each folder is opened once, as itself (a junction or symlink is refused), and held without delete sharing, so the path
        // cannot be pointed elsewhere while it is used; its owner and ACL are read from that handle.
        let parent = Self::pin_dir(&parent_path)?;
        Self::sweep(&parent_path);
        let dir = parent_path.join(Self::unique_name());
        let pin = Self::pin_dir(&dir)?;
        let lock = File::create(dir.join("lock")).map_err(|_| TempError::Io)?;
        lock.try_lock().map_err(|_| TempError::Io)?;
        Ok(CredentialTemp {
            dir,
            #[cfg(windows)]
            _pins: [parent, pin],
            shared: Arc::new(Shared {
                limits,
                used: AtomicU64::new(0),
            }),
            _lock: lock,
        })
    }

    /// Creates `path` with the protected ACL of `key_acl::protected_dir_sddl` if it is missing, then checks it, new or not (owner
    /// trusted, ACL private), and returns it open. A folder that is not a plain directory, or whose owner or ACL is not the
    /// service's, is `UnsafeParent`.
    #[cfg(windows)]
    fn pin_dir(path: &Path) -> Result<File, TempError> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
            FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, READ_CONTROL,
        };
        match crate::key_acl::create_protected_dir(path) {
            Ok(()) | Err(183) => {} // created private, or already there: checked below either way (183: ERROR_ALREADY_EXISTS)
            Err(_) => return Err(TempError::Io),
        }
        let access = READ_CONTROL | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES;
        let pin = std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE) // no FILE_SHARE_DELETE: nobody can rename or delete it while it is held
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| TempError::Io)?;
        if !Self::pinned_is_plain_dir(pin.metadata().map_err(|_| TempError::Io)?.file_attributes())
        {
            return Err(TempError::UnsafeParent);
        }
        let handle = pin.as_raw_handle();
        if !crate::key_acl::owner_is_trusted_handle(handle)
            || crate::key_acl::is_shared_handle(handle)
        {
            return Err(TempError::UnsafeParent);
        }
        Ok(pin)
    }

    /// A directory that is not a reparse point (junction, symlink, mount point), from the attributes of the opened handle.
    #[cfg(any(windows, test))]
    fn pinned_is_plain_dir(attributes: u32) -> bool {
        const DIRECTORY: u32 = 0x10;
        const REPARSE_POINT: u32 = 0x400;
        attributes & DIRECTORY != 0 && attributes & REPARSE_POINT == 0
    }

    #[cfg(not(any(unix, windows)))]
    fn pin_dir(path: &Path) -> Result<File, TempError> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(TempError::UnsafeParent);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(path).map_err(|_| TempError::Io)?
            }
            Err(_) => return Err(TempError::Io),
        }
        File::open(path).map_err(|_| TempError::Io)
    }

    fn unique_name() -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        format!(
            "{}-{nonce:08x}{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// The parent must belong to the service user: the user this process runs as. It is not compared with
    /// the data directory's owner: a volume root can belong to another user (a Kubernetes volume is root's,
    /// with only the group set), while the folder this process created on an earlier start is its own.
    #[cfg(unix)]
    fn check_owner(parent: &rustix::fs::Stat) -> Result<(), TempError> {
        if parent.st_uid == rustix::process::geteuid().as_raw() {
            Ok(())
        } else {
            Err(TempError::UnsafeParent)
        }
    }

    /// Removes only subdirectories whose lock file can be acquired (no live owner). A lock
    /// that is a symlink is never opened (it could point anywhere); a directory with no lock
    /// at all is removed only once it is older than a minute, so one a starting process has
    /// just created is not taken from it.
    #[cfg(not(unix))]
    fn sweep(parent: &Path) {
        const GRACE: std::time::Duration = std::time::Duration::from_secs(60);
        for entry in std::fs::read_dir(parent).into_iter().flatten().flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let lock_path = path.join("lock");
            match std::fs::symlink_metadata(&lock_path) {
                Ok(lock_meta) if lock_meta.file_type().is_file() => {
                    let Ok(lock) = File::options().read(true).write(true).open(&lock_path) else {
                        continue;
                    };
                    if lock.try_lock().is_ok() {
                        let _ = std::fs::remove_dir_all(&path);
                    }
                }
                Ok(_) => continue,
                Err(_) => {
                    let old = meta
                        .modified()
                        .ok()
                        .and_then(|at| at.elapsed().ok())
                        .is_some_and(|age| age > GRACE);
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
            if limits.max_request_bytes.is_some_and(|max| length > max)
                || limits.max_total_bytes.is_some_and(|max| length > max)
            {
                return Err(TempError::TooLarge);
            }
            if limits
                .max_total_bytes
                .is_some_and(|max| self.shared.used.load(Ordering::SeqCst) + length > max)
            {
                return Err(TempError::Busy);
            }
        }
        #[cfg(unix)]
        let file = fd::unlinked_file(&self.dirfd).map_err(|error| TempError::from_io(&error))?;
        #[cfg(not(unix))]
        let file = tempfile::tempfile_in(&self.dir).map_err(|error| TempError::from_io(&error))?;
        Ok(TempFile {
            file,
            account: Account {
                shared: Arc::clone(&self.shared),
                bytes: 0,
            },
        })
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
        if limits.max_request_bytes.is_some_and(|max| own > max)
            || limits.max_total_bytes.is_some_and(|max| own > max)
        {
            return Err(TempError::TooLarge);
        }
        // Reserve before writing so concurrent bodies cannot jointly pass the total.
        let after = self.account.shared.used.fetch_add(len, Ordering::SeqCst) + len;
        if limits.max_total_bytes.is_some_and(|max| after > max) {
            self.account.shared.used.fetch_sub(len, Ordering::SeqCst);
            return Err(TempError::Busy);
        }
        self.account.bytes += len;
        self.file
            .write_all(bytes)
            .map_err(|error| TempError::from_io(&error))
    }

    /// [`TempFile::write`] on the blocking pool, so a large body never stalls an async
    /// worker. Takes and returns `self` because the blocking task owns the file meanwhile.
    pub async fn write_blocking(mut self, bytes: Vec<u8>) -> Result<TempFile, TempError> {
        tokio::task::spawn_blocking(move || self.write(&bytes).map(|()| self))
            .await
            .map_err(|_| TempError::Io)?
    }

    pub fn into_file(self) -> CompletedTemp {
        CompletedTemp {
            file: self.file,
            _account: self.account,
        }
    }
}

/// Directory-descriptor operations (unix): nothing here resolves a path a second time, and no symlink is followed.
#[cfg(unix)]
mod fd {
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, openat, statat, unlinkat};
    use rustix::io::Errno;

    /// Opens `path` (relative to `base`) as a directory without following a symlink at its last component.
    pub(super) fn open_dir(
        base: impl AsFd,
        path: impl rustix::path::Arg,
    ) -> Result<OwnedFd, Errno> {
        openat(
            base,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    /// An anonymous read-write file in `dir`. On Linux it is an O_TMPFILE file that never has a name; on a filesystem without
    /// support (the three errors `tempfile` also falls back on) and on other unixes it is created exclusively, never through a
    /// symlink, and unlinked at once.
    pub fn unlinked_file(dir: impl AsFd) -> io::Result<File> {
        let dir = dir.as_fd();
        #[cfg(target_os = "linux")]
        match openat(
            dir,
            ".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => return Ok(File::from(file)),
            Err(Errno::OPNOTSUPP | Errno::ISDIR | Errno::NOENT) => {}
            Err(errno) => return Err(errno.into()),
        }
        named_unlinked_file(dir)
    }

    /// The portable branch of [`unlinked_file`]: created exclusively under a random name, never through a symlink, and unlinked at once.
    pub(super) fn named_unlinked_file(dir: BorrowedFd<'_>) -> io::Result<File> {
        let mut bytes = [0u8; 8];
        for _ in 0..8 {
            getrandom::fill(&mut bytes).map_err(|_| io::Error::other("no randomness"))?;
            let name = format!(
                "body-{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            let flags =
                OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            match openat(dir, name.as_str(), flags, Mode::RUSR | Mode::WUSR) {
                Ok(file) => {
                    unlinkat(dir, name.as_str(), AtFlags::empty())?;
                    return Ok(File::from(file));
                }
                Err(Errno::EXIST) => continue,
                Err(errno) => return Err(errno.into()),
            }
        }
        Err(io::Error::from(io::ErrorKind::AlreadyExists))
    }

    /// The entries of `dir` as the C strings the kernel gave, so a name that is not UTF-8 is still visited.
    fn names(dir: &OwnedFd) -> Vec<CString> {
        let Ok(reader) = Dir::read_from(dir) else {
            return Vec::new();
        };
        reader
            .flatten()
            .map(|entry| entry.file_name().to_owned())
            .filter(|name| name.as_bytes() != b"." && name.as_bytes() != b"..")
            .collect()
    }

    fn is_dir(stat: &Stat) -> bool {
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
    }

    /// Removes the contents of `dir` and then `name` itself from `parent`, all relative to descriptors.
    fn remove_tree(parent: &OwnedFd, name: &CStr, dir: &OwnedFd) {
        for child in names(dir) {
            match statat(dir, child.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) if is_dir(&stat) => {
                    if let Ok(sub) = open_dir(dir, child.as_c_str()) {
                        remove_tree(dir, &child, &sub);
                    }
                }
                Ok(_) => {
                    let _ = unlinkat(dir, child.as_c_str(), AtFlags::empty());
                }
                Err(_) => {}
            }
        }
        let _ = unlinkat(parent, name, AtFlags::REMOVEDIR);
    }

    /// Removes only subdirectories whose lock file can be acquired (no live owner). A lock
    /// that is a symlink is never opened (it could point anywhere); a directory with no lock
    /// at all is removed only once it is older than a minute, so one a starting process has
    /// just created is not taken from it.
    pub fn sweep(parent: &OwnedFd) {
        const GRACE: std::time::Duration = std::time::Duration::from_secs(60);
        for name in names(parent) {
            // Opening with O_NOFOLLOW|O_DIRECTORY skips anything that is not a real subdirectory.
            let Ok(dir) = open_dir(parent, name.as_c_str()) else {
                continue;
            };
            match statat(&dir, "lock", AtFlags::SYMLINK_NOFOLLOW) {
                Ok(lock) if FileType::from_raw_mode(lock.st_mode) == FileType::RegularFile => {
                    let flags =
                        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
                    let Ok(lock) = openat(&dir, "lock", flags, Mode::empty()).map(File::from)
                    else {
                        continue;
                    };
                    if lock.try_lock().is_ok() {
                        remove_tree(parent, &name, &dir);
                    }
                }
                Ok(_) => continue,
                Err(_) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs() as i64);
                    let old =
                        fstat(&dir).is_ok_and(|stat| now - stat.st_mtime > GRACE.as_secs() as i64);
                    if old {
                        remove_tree(parent, &name, &dir);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pinned_folder_must_be_a_directory_and_not_a_reparse_point() {
        use super::CredentialTemp as C;
        assert!(C::pinned_is_plain_dir(0x10), "a directory");
        assert!(C::pinned_is_plain_dir(0x10 | 0x2), "a hidden directory");
        assert!(
            !C::pinned_is_plain_dir(0x10 | 0x400),
            "a junction or symlink to a directory"
        );
        assert!(!C::pinned_is_plain_dir(0x20), "a file");
        assert!(
            !C::pinned_is_plain_dir(0x400),
            "a reparse point that is not a directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn named_fallback_file_is_unlinked_and_usable() {
        use std::io::{Read, Seek, Write};
        use std::os::fd::AsFd;
        let dir = tempfile::tempdir().unwrap();
        let fd = super::fd::open_dir(rustix::fs::CWD, dir.path()).unwrap();
        let mut file = super::fd::named_unlinked_file(fd.as_fd()).unwrap();
        file.write_all(b"secret").unwrap();
        file.rewind().unwrap();
        let mut back = String::new();
        file.read_to_string(&mut back).unwrap();
        assert_eq!(back, "secret");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the fallback leaves no name behind"
        );
    }
}
