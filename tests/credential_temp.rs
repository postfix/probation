//! Slice 28, LS-F16: credential-read temporary files are bounded by disk, not by a default cap.

use std::io::ErrorKind;
use std::path::Path;

use probation::http::credential_temp::{CredentialTemp, Limits, TempError};

fn open(dir: &Path, limits: Limits) -> CredentialTemp {
    CredentialTemp::open(dir, limits).unwrap()
}

fn files_under(dir: &Path) -> usize {
    walk(dir).filter(|path| path.is_file() && path.file_name().is_some_and(|n| n != "lock")).count()
}

fn walk(dir: &Path) -> impl Iterator<Item = std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            found.push(path);
        }
    }
    found.into_iter()
}

#[test]
fn credential_temp_no_default_request_cap_streams_large_body() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits::default());
    let mut file = temp.begin(None).unwrap();
    let chunk = vec![7u8; 1024 * 1024];
    for _ in 0..8 {
        file.write(&chunk).expect("no default cap");
    }
    assert_eq!(temp.used_bytes(), 8 * 1024 * 1024);
}

#[test]
fn credential_temp_optional_request_cap_refuses_413_without_retry_after() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits { max_request_bytes: Some(1024), max_total_bytes: None });
    let error = temp.begin(Some(2048)).err().expect("a known length over the cap is refused up front");
    assert_eq!((error.status(), error.retry_after()), (413, false));
    let mut file = temp.begin(None).unwrap();
    file.write(&[0; 1024]).unwrap();
    let error = file.write(&[0; 1]).unwrap_err();
    assert_eq!((error.status(), error.retry_after()), (413, false), "an unknown length is refused as soon as it passes the cap");
}

#[test]
fn credential_temp_total_cap_refuses_503_with_retry_after() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits { max_request_bytes: None, max_total_bytes: Some(1000) });
    let mut held = temp.begin(Some(600)).unwrap();
    held.write(&[0; 600]).unwrap();
    let error = temp.begin(Some(600)).err().expect("fits alone, not beside the bytes in use");
    assert_eq!((error.status(), error.retry_after()), (503, true));
    drop(held);
    temp.begin(Some(600)).expect("the bytes were released");
}

#[test]
fn credential_temp_single_request_over_total_refuses_413_without_retry_after() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits { max_request_bytes: None, max_total_bytes: Some(1000) });
    let error = temp.begin(Some(1500)).err().unwrap();
    assert_eq!((error.status(), error.retry_after()), (413, false));
    let mut file = temp.begin(None).unwrap();
    let error = file.write(&[0; 1001]).unwrap_err();
    assert_eq!((error.status(), error.retry_after()), (413, false), "its own bytes passed the total");
}

#[test]
fn credential_temp_enospc_refuses_503_without_retry_after() {
    let error = TempError::from_io(&std::io::Error::from(ErrorKind::StorageFull));
    assert_eq!((error.status(), error.retry_after()), (503, false));
    assert_eq!(error, TempError::NoSpace);
}

#[test]
fn credential_temp_startup_sweep_skips_locked_subdirectories() {
    let data = tempfile::tempdir().unwrap();
    let first = open(data.path(), Limits::default());
    let live = first.dir().to_owned();
    let second = open(data.path(), Limits::default());
    assert!(live.exists(), "an overlapping process keeps its live directory");
    assert_ne!(live, second.dir(), "each process has its own subdirectory");
}

#[test]
fn credential_temp_startup_sweep_removes_orphans() {
    let data = tempfile::tempdir().unwrap();
    let orphan = data.path().join("credential-reads").join("1-dead");
    std::fs::create_dir_all(&orphan).unwrap();
    std::fs::write(orphan.join("lock"), b"").unwrap();
    std::fs::write(orphan.join("leftover"), b"secret body").unwrap();
    let _temp = open(data.path(), Limits::default());
    assert!(!orphan.exists(), "a subdirectory whose lock can be acquired is removed");
}

#[test]
#[cfg(unix)]
fn credential_temp_symlinked_parent_refused() {
    let data = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), data.path().join("credential-reads")).unwrap();
    assert_eq!(CredentialTemp::open(data.path(), Limits::default()).err(), Some(TempError::UnsafeParent));
}

#[test]
fn credential_temp_removed_on_abort_and_on_completion() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits::default());
    let mut aborted = temp.begin(None).unwrap();
    aborted.write(b"partial").unwrap();
    assert_eq!(temp.used_bytes(), 7);
    drop(aborted);
    assert_eq!(temp.used_bytes(), 0, "abort releases the accounting");
    assert_eq!(files_under(data.path()), 0, "abort leaves no file");
    let mut done = temp.begin(None).unwrap();
    done.write(b"complete").unwrap();
    let completed = done.into_file();
    assert_eq!(temp.used_bytes(), 8, "counted while the response reads it");
    drop(completed);
    assert_eq!(temp.used_bytes(), 0, "completion releases the accounting");
    assert_eq!(files_under(data.path()), 0, "completion leaves no file");
}

#[test]
fn credential_temp_refusal_happens_before_first_body_byte() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits { max_request_bytes: Some(10), max_total_bytes: None });
    assert!(temp.begin(Some(11)).is_err(), "no TempFile exists to write a first byte to");
    assert_eq!(files_under(data.path()), 0);
}

// ---- S28-3 / R28-8 ----

#[test]
#[cfg(unix)]
fn credential_temp_loose_parent_is_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let data = tempfile::tempdir().unwrap();
    let parent = data.path().join("credential-reads");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let _temp = open(data.path(), Limits::default());
    let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & 0o077, 0, "an existing group/other-accessible parent is tightened, got {mode:o}");
}

#[test]
#[cfg(unix)]
fn credential_temp_sweep_does_not_follow_a_symlinked_lock() {
    let data = tempfile::tempdir().unwrap();
    let victim = data.path().join("victim");
    std::fs::write(&victim, b"keep me").unwrap();
    let parent = data.path().join("credential-reads");
    let planted = parent.join("1-planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::os::unix::fs::symlink(&victim, planted.join("lock")).unwrap();
    let _temp = open(data.path(), Limits::default());
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep me", "the symlink target is untouched");
    assert!(planted.exists(), "a directory whose lock is a symlink is skipped, not swept");
}

#[test]
fn credential_temp_sweep_removes_old_lockless_directory_and_keeps_a_fresh_one() {
    let data = tempfile::tempdir().unwrap();
    let parent = data.path().join("credential-reads");
    let old = parent.join("2-crashed-before-lock");
    let fresh = parent.join("3-just-created");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::File::open(&old).unwrap().set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600)).unwrap();
    let _temp = open(data.path(), Limits::default());
    assert!(!old.exists(), "a crash between create_dir and the lock leaves a directory the sweep removes");
    assert!(fresh.exists(), "a directory younger than a minute may belong to a starting process");
}
