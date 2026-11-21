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

/// The file system types whose `flock` is advisory across hosts or not reliable at all: a shared network file system lets two hosts
/// "hold" the same lock, which is two store owners (a node-loss replacement on a `ReadWriteOncePod` claim backed by NFS, EFS or
/// CephFS is the case this refuses). `fuseblk` (ntfs-3g on a local device) is local and is not listed.
pub fn is_network_filesystem(fstype: &str) -> bool {
    let t = fstype.to_ascii_lowercase();
    t.starts_with("nfs") || t.starts_with("cifs") || t.starts_with("smb") || t.starts_with("ceph") || t.starts_with("glusterfs")
        || t == "lustre" || t == "9p" || t == "afs" || t == "fuse" || t.starts_with("fuse.")
        || t.starts_with("gfs2") || t.starts_with("ocfs2") || t == "gpfs" || t == "beegfs" || t == "virtiofs"
}

/// The file system type of the mount that holds `path`, read from the text of `/proc/self/mountinfo` (longest mount point wins).
pub fn filesystem_type(mountinfo: &str, path: &Path) -> Option<String> {
    fn unescape(field: &str) -> String {
        let bytes = field.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b)) {
                out.push(u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 4]).unwrap_or("0"), 8).unwrap_or(b'?'));
                i += 4;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    let mut best: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else { continue };
        let Some(mount_point) = before.split(' ').nth(4) else { continue };
        let Some(fstype) = after.split(' ').next() else { continue };
        let mount_point = PathBuf::from(unescape(mount_point));
        if path.starts_with(&mount_point) {
            let depth = mount_point.components().count();
            if best.as_ref().is_none_or(|(d, _)| depth >= *d) {
                best = Some((depth, fstype.to_owned()));
            }
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// Startup refusal (unless `allow`): the data directory is on a network file system, or its file system cannot be classified (a mount table
/// that cannot be read refuses too: the check fails CLOSED). Linux only (other platforms have no mount table to read here); a directory
/// that does not exist yet is judged by its nearest existing parent.
pub fn refuse_network_filesystem(data_dir: &Path, allow: bool) -> Result<(), LockError> {
    if allow {
        return Ok(());
    }
    match probe_filesystem(data_dir) {
        Ok(Some(fstype)) if is_network_filesystem(&fstype) => Err(LockError::NetworkFilesystem { path: data_dir.to_path_buf(), fstype }),
        Ok(_) => Ok(()),
        Err(source) => Err(LockError::Unclassifiable { path: data_dir.to_path_buf(), source }),
    }
}

fn covering_type(mountinfo: &str, resolved: &Path) -> io::Result<String> {
    filesystem_type(mountinfo, resolved).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no line of the mount table covers the data directory"))
}

/// The type of the file system that holds `data_dir`, from the mount table; `Ok(None)` only where this platform has none (not Linux); on Linux a table that does not cover the path is an error.
fn probe_filesystem(data_dir: &Path) -> io::Result<Option<String>> {
    #[cfg(feature = "test-support")]
    if let Some(probe) = TEST_PROBE.lock().expect("the probe slot").clone() {
        return probe(data_dir);
    }
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut probe = data_dir.to_path_buf();
    let resolved = loop {
        match std::fs::canonicalize(&probe) {
            Ok(path) => break path,
            Err(err) => match probe.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => probe = parent.to_path_buf(),
                _ => return Err(err),
            },
        }
    };
    // A mount table that parses but covers the path is not a classification: it fails closed like an unreadable one.
    covering_type(&mountinfo, &resolved).map(Some)
}

/// **Test seam** (feature `test-support`): replaces the mount-table probe of `refuse_network_filesystem`, so a test can make `App::start`
/// see any file system type, or an unreadable mount table. `None` restores the real probe.
#[cfg(feature = "test-support")]
pub type FilesystemProbe = std::sync::Arc<dyn Fn(&Path) -> io::Result<Option<String>> + Send + Sync>;
#[cfg(feature = "test-support")]
static TEST_PROBE: std::sync::Mutex<Option<FilesystemProbe>> = std::sync::Mutex::new(None);
#[cfg(feature = "test-support")]
pub fn set_filesystem_probe(probe: Option<FilesystemProbe>) {
    *TEST_PROBE.lock().expect("the probe slot") = probe;
}

#[cfg(test)]
fn judge_filesystem(mountinfo: &str, resolved: &Path, data_dir: &Path) -> Result<(), LockError> {
    match filesystem_type(mountinfo, resolved) {
        Some(fstype) if is_network_filesystem(&fstype) => Err(LockError::NetworkFilesystem { path: data_dir.to_path_buf(), fstype }),
        _ => Ok(()),
    }
}

#[derive(Debug)]
pub enum LockError {
    Open { path: PathBuf, source: io::Error },
    Held { path: PathBuf },
    NetworkFilesystem { path: PathBuf, fstype: String },
    Unclassifiable { path: PathBuf, source: io::Error },
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
            LockError::Unclassifiable { path, source } => write!(
                f,
                "cannot tell what kind of file system holds the data directory {} ({source}); refusing to start because the exclusive lock \
                 is not reliable on a network file system (set allow_network_data_dir = true to start anyway)",
                path.display()
            ),
            LockError::NetworkFilesystem { path, fstype } => write!(
                f,
                "the data directory {} is on a {fstype} file system, where the exclusive lock is not reliable across hosts \
                 (two instances could both own the store); use a local or block-device volume, or set \
                 allow_network_data_dir = true to accept that risk",
                path.display()
            ),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LockError::Open { source, .. } => Some(source),
            LockError::Unclassifiable { source, .. } => Some(source),
            LockError::Held { .. } | LockError::NetworkFilesystem { .. } => None,
        }
    }
}

#[cfg(test)]
mod network_filesystem_tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime - ext4 /dev/nvme0n1p2 rw\n\
30 22 0:27 / /mnt/share rw,relatime - nfs4 server:/export rw,vers=4.2\n\
31 22 0:28 / /mnt/with\\040space rw - fuse.sshfs u@h:/ rw\n\
32 30 0:29 / /mnt/share/local rw - tmpfs tmpfs rw\n\
33 22 8:1 / /mnt/ntfs rw - fuseblk /dev/sda1 rw\n";

    #[test]
    fn the_longest_mount_point_decides_the_type() {
        assert_eq!(filesystem_type(MOUNTINFO, Path::new("/var/lib/probation")).as_deref(), Some("ext4"));
        assert_eq!(filesystem_type(MOUNTINFO, Path::new("/mnt/share/data")).as_deref(), Some("nfs4"));
        assert_eq!(filesystem_type(MOUNTINFO, Path::new("/mnt/share/local/x")).as_deref(), Some("tmpfs"));
        assert_eq!(filesystem_type(MOUNTINFO, Path::new("/mnt/with space/x")).as_deref(), Some("fuse.sshfs"), "octal escapes are decoded");
        assert_eq!(filesystem_type(MOUNTINFO, Path::new("/mnt/sharepoint")).as_deref(), Some("ext4"), "a prefix of a name is not a mount point");
    }

    #[test]
    fn a_mount_table_that_covers_nothing_is_an_error_not_a_pass() {
        assert!(covering_type("", Path::new("/var/lib/probation")).is_err());
        assert_eq!(covering_type(MOUNTINFO, Path::new("/var/lib/probation")).unwrap(), "ext4");
    }

    #[test]
    fn network_and_fuse_types_are_refused_and_local_ones_are_not() {
        for network in ["nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "lustre", "9p", "afs", "fuse", "fuse.sshfs", "fuse.s3fs", "gfs2", "ocfs2", "gpfs", "beegfs", "virtiofs"] {
            assert!(is_network_filesystem(network), "{network}");
        }
        for local in ["ext4", "xfs", "btrfs", "zfs", "tmpfs", "overlay", "fuseblk", "f2fs", "vfat"] {
            assert!(!is_network_filesystem(local), "{local}");
        }
    }

    #[test]
    fn a_data_directory_on_a_network_mount_is_refused_with_the_type_named() {
        let err = judge_filesystem(MOUNTINFO, Path::new("/mnt/share/data"), Path::new("/mnt/share/data")).unwrap_err();
        assert!(matches!(&err, LockError::NetworkFilesystem { fstype, .. } if fstype == "nfs4"), "{err:?}");
        assert!(err.to_string().contains("nfs4") && err.to_string().contains("allow_network_data_dir"), "{err}");
        assert!(judge_filesystem(MOUNTINFO, Path::new("/var/lib/probation"), Path::new("/var/lib/probation")).is_ok());
        assert!(judge_filesystem(MOUNTINFO, Path::new("/mnt/ntfs/data"), Path::new("/mnt/ntfs/data")).is_ok(), "fuseblk is a local device");
    }

    #[test]
    fn a_local_directory_is_accepted_and_the_switch_always_accepts() {
        let dir = tempfile::tempdir().unwrap();
        assert!(refuse_network_filesystem(&dir.path().join("not-yet"), false).is_ok());
        assert!(refuse_network_filesystem(Path::new("/"), true).is_ok());
    }
}
