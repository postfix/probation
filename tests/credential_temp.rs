//! Slice 28, LS-F16: credential-read temporary files are bounded by disk, not by a default cap.

use std::io::ErrorKind;
use std::path::Path;

use probation::http::credential_temp::{CredentialTemp, Limits, TempError};

fn open(dir: &Path, limits: Limits) -> CredentialTemp {
    CredentialTemp::open(dir, limits).unwrap()
}

fn files_under(dir: &Path) -> usize {
    walk(dir)
        .filter(|path| path.is_file() && path.file_name().is_some_and(|n| n != "lock"))
        .count()
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

/// Sets `dir`'s modification time `age` into the past. Windows opens a directory only with FILE_FLAG_BACKUP_SEMANTICS and writes
/// its times through FILE_WRITE_ATTRIBUTES; std's `File::open` asks for neither.
fn backdate(dir: &Path, age: std::time::Duration) {
    let mut options = std::fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_WRITE_ATTRIBUTES,
        };
        options
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    #[cfg(not(windows))]
    options.read(true);
    options
        .open(dir)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - age)
        .unwrap();
}

/// The service's own `credential-reads` folder as a first start leaves it (protected ACL on Windows, 0700 on unix), released, so a
/// test can plant entries in it without depending on the ACL of the temporary directory it lives in.
fn service_folder(data: &Path) -> std::path::PathBuf {
    drop(open(data, Limits::default()));
    data.join("credential-reads")
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
    let temp = open(
        data.path(),
        Limits {
            max_request_bytes: Some(1024),
            max_total_bytes: None,
        },
    );
    let error = temp
        .begin(Some(2048))
        .err()
        .expect("a known length over the cap is refused up front");
    assert_eq!((error.status(), error.retry_after()), (413, false));
    let mut file = temp.begin(None).unwrap();
    file.write(&[0; 1024]).unwrap();
    let error = file.write(&[0; 1]).unwrap_err();
    assert_eq!(
        (error.status(), error.retry_after()),
        (413, false),
        "an unknown length is refused as soon as it passes the cap"
    );
}

#[test]
fn credential_temp_total_cap_refuses_503_with_retry_after() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(
        data.path(),
        Limits {
            max_request_bytes: None,
            max_total_bytes: Some(1000),
        },
    );
    let mut held = temp.begin(Some(600)).unwrap();
    held.write(&[0; 600]).unwrap();
    let error = temp
        .begin(Some(600))
        .err()
        .expect("fits alone, not beside the bytes in use");
    assert_eq!((error.status(), error.retry_after()), (503, true));
    drop(held);
    temp.begin(Some(600)).expect("the bytes were released");
}

#[test]
fn credential_temp_single_request_over_total_refuses_413_without_retry_after() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(
        data.path(),
        Limits {
            max_request_bytes: None,
            max_total_bytes: Some(1000),
        },
    );
    let error = temp.begin(Some(1500)).err().unwrap();
    assert_eq!((error.status(), error.retry_after()), (413, false));
    let mut file = temp.begin(None).unwrap();
    let error = file.write(&[0; 1001]).unwrap_err();
    assert_eq!(
        (error.status(), error.retry_after()),
        (413, false),
        "its own bytes passed the total"
    );
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
    assert!(
        live.exists(),
        "an overlapping process keeps its live directory"
    );
    assert_ne!(live, second.dir(), "each process has its own subdirectory");
}

#[test]
fn credential_temp_startup_sweep_removes_orphans() {
    let data = tempfile::tempdir().unwrap();
    let orphan = service_folder(data.path()).join("1-dead");
    std::fs::create_dir(&orphan).unwrap();
    std::fs::write(orphan.join("lock"), b"").unwrap();
    std::fs::write(orphan.join("leftover"), b"secret body").unwrap();
    let _temp = open(data.path(), Limits::default());
    assert!(
        !orphan.exists(),
        "a subdirectory whose lock can be acquired is removed"
    );
}

#[test]
#[cfg(unix)]
fn credential_temp_symlinked_parent_refused() {
    let data = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), data.path().join("credential-reads")).unwrap();
    assert_eq!(
        CredentialTemp::open(data.path(), Limits::default()).err(),
        Some(TempError::UnsafeParent)
    );
}

#[test]
fn credential_temp_parent_that_is_a_regular_file_refused() {
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("credential-reads"), b"not a directory").unwrap();
    assert_eq!(
        CredentialTemp::open(data.path(), Limits::default()).err(),
        Some(TempError::UnsafeParent)
    );
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
    let temp = open(
        data.path(),
        Limits {
            max_request_bytes: Some(10),
            max_total_bytes: None,
        },
    );
    assert!(
        temp.begin(Some(11)).is_err(),
        "no TempFile exists to write a first byte to"
    );
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
    assert_eq!(
        mode & 0o077,
        0,
        "an existing group/other-accessible parent is tightened, got {mode:o}"
    );
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
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"keep me",
        "the symlink target is untouched"
    );
    assert!(
        planted.exists(),
        "a directory whose lock is a symlink is skipped, not swept"
    );
}

#[test]
fn credential_temp_sweep_removes_old_lockless_directory_and_keeps_a_fresh_one() {
    let data = tempfile::tempdir().unwrap();
    let parent = service_folder(data.path());
    let old = parent.join("2-crashed-before-lock");
    let fresh = parent.join("3-just-created");
    std::fs::create_dir(&old).unwrap();
    std::fs::create_dir(&fresh).unwrap();
    backdate(&old, std::time::Duration::from_secs(3600));
    let _temp = open(data.path(), Limits::default());
    assert!(
        !old.exists(),
        "a crash between create_dir and the lock leaves a directory the sweep removes"
    );
    assert!(
        fresh.exists(),
        "a directory younger than a minute may belong to a starting process"
    );
}

// ---- credential-temp-owner: the folder must belong to the service user, not to the data directory's owner ----

/// Runs `body` (a test's own function, by name) as a child of this test binary inside a user namespace where the
/// caller is uid 0 and uid 999 is mapped, so a data directory can belong to a different user than the process,
/// the way a Kubernetes volume root (root-owned, group set by fsGroup) does for the service account. The child
/// gets the directory in `PROBATION_NS_DIR`. Fails, never skips, when the host cannot create such a namespace (the tests
/// are `#[ignore]`d for that reason and run with `--include-ignored` in the `netns` job of cluster.yml).
#[cfg(unix)]
fn in_foreign_owner_namespace(test: &str, body: impl FnOnce(&Path)) {
    use std::process::Command;
    const NS: [&str; 4] = ["--user", "--map-root-user", "--map-auto", "--"];
    if let Ok(dir) = std::env::var("PROBATION_NS_DIR") {
        return body(Path::new(&dir));
    }
    if !Command::new("unshare")
        .args(NS)
        .arg("true")
        .status()
        .is_ok_and(|s| s.success())
    {
        panic!(
            "{test}: this host cannot create a user namespace with a subuid map (unshare --user --map-root-user --map-auto)"
        );
    }
    let data = tempfile::tempdir().unwrap();
    let output = Command::new("unshare")
        .args(NS)
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PROBATION_NS_DIR", data.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{test} failed in the namespace:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{test} did not run in the namespace"
    );
}

/// Hands `path` to uid 999 for the test's duration and back to the namespace root (the caller) afterwards, so
/// the host can delete the directory.
#[cfg(unix)]
struct Owned<'a>(&'a Path);

#[cfg(unix)]
impl<'a> Owned<'a> {
    fn new(path: &'a Path) -> Self {
        std::os::unix::fs::chown(path, Some(999), Some(999)).unwrap();
        Owned(path)
    }
}

#[cfg(unix)]
impl Drop for Owned<'_> {
    fn drop(&mut self) {
        let _ = std::os::unix::fs::chown(self.0, Some(0), Some(0));
    }
}

#[test]
#[cfg(unix)]
#[ignore = "needs unprivileged user namespaces with a subuid map (unshare --map-auto)"]
fn credential_temp_reopens_after_restart_when_data_dir_belongs_to_another_user() {
    in_foreign_owner_namespace(
        "credential_temp_reopens_after_restart_when_data_dir_belongs_to_another_user",
        |data| {
            // The volume root belongs to uid 999; the service process (uid 0 here) creates the folder, then restarts.
            let _root = Owned::new(data);
            let first = open(data, Limits::default());
            drop(first);
            CredentialTemp::open(data, Limits::default())
                .expect("a restart finds the folder its own user created");
        },
    );
}

#[test]
#[cfg(unix)]
#[ignore = "needs unprivileged user namespaces with a subuid map (unshare --map-auto)"]
fn credential_temp_folder_owned_by_another_user_is_refused_even_if_it_matches_the_data_dir() {
    in_foreign_owner_namespace(
        "credential_temp_folder_owned_by_another_user_is_refused_even_if_it_matches_the_data_dir",
        |data| {
            // Another user (999) owns both the data directory and the folder; this process (uid 0) is neither.
            let parent = data.join("credential-reads");
            std::fs::create_dir(&parent).unwrap();
            let _root = Owned::new(data);
            let _folder = Owned::new(&parent);
            assert_eq!(
                CredentialTemp::open(data, Limits::default()).err(),
                Some(TempError::UnsafeParent)
            );
        },
    );
}

// ---- Windows: the folder's owner SID must be the process user, SYSTEM, Administrators or the service account (decision logic, any host) ----

#[test]
fn credential_temp_windows_owner_must_be_a_trusted_sid() {
    use probation::key_acl::owner_trusted;
    const USER: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";
    let allowed = [USER];
    let spelled = |t: &str| Some(t.to_owned());
    let sddl = |owner: &str| format!("O:{owner}G:{owner}D:PAI(A;OICI;FA;;;{OTHER})");
    assert!(
        owner_trusted(&sddl(USER), &allowed, &spelled),
        "the process user owns it"
    );
    assert!(
        owner_trusted(&sddl("BA"), &allowed, &spelled),
        "Administrators"
    );
    assert!(owner_trusted(&sddl("SY"), &allowed, &spelled), "SYSTEM");
    assert!(
        !owner_trusted(&sddl(OTHER), &allowed, &spelled),
        "another user, even one the DACL grants"
    );
    assert!(
        !owner_trusted("D:PAI(A;OICI;FA;;;SY)", &allowed, &spelled),
        "no owner is not trusted"
    );
    let alias = |t: &str| (t == "LA").then(|| USER.to_owned());
    assert!(
        owner_trusted(&sddl("LA"), &allowed, &alias),
        "an alias is judged by the SID it resolves to"
    );
    assert!(
        !owner_trusted(&sddl("LG"), &allowed, &alias),
        "an owner the OS cannot resolve is refused"
    );
}

// ---- security-1-1: the folder is used through the descriptor that was checked, not through its path again ----

#[test]
#[cfg(unix)]
fn credential_temp_folder_swapped_for_a_symlink_after_open_is_not_followed() {
    let data = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits::default());
    let parent = data.path().join("credential-reads");
    // Another process swaps the checked folder for a symlink to a directory of its own.
    std::fs::rename(&parent, data.path().join("moved")).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), &parent).unwrap();
    let mut file = temp
        .begin(None)
        .expect("the body goes into the folder that was checked");
    file.write(b"secret").unwrap();
    assert_eq!(
        std::fs::read_dir(elsewhere.path()).unwrap().count(),
        0,
        "nothing is created through the symlink"
    );
    // A restart refuses the symlink outright.
    assert_eq!(
        CredentialTemp::open(data.path(), Limits::default()).err(),
        Some(TempError::UnsafeParent)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn credential_temp_body_file_never_has_a_name() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits::default());
    let names = |dir: &Path| -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    let mut file = temp.begin(None).unwrap();
    file.write(b"secret").unwrap();
    assert_eq!(
        names(temp.dir()),
        ["lock"],
        "the folder lists no body file while one is open"
    );
    // The body file is O_TMPFILE only where the folder's filesystem supports it (overlayfs before 6.6 and NFS do not): the
    // probe decides which branch ran, so this test never fails on, or skips, an unsupported filesystem. The fallback itself is
    // covered by the unit test `named_fallback_file_is_unlinked_and_usable`.
    let dir = rustix::fs::openat(
        rustix::fs::CWD,
        temp.dir(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    match rustix::fs::openat(
        &dir,
        ".",
        rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::RDWR,
        rustix::fs::Mode::RUSR,
    ) {
        Ok(_) => {}
        Err(rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::ISDIR | rustix::io::Errno::NOENT) => {
            return;
        }
        Err(errno) => panic!("O_TMPFILE probe failed unexpectedly: {errno}"),
    }
    // An O_TMPFILE file was never linked; a file created by name and unlinked at once still shows the name it had.
    let named: Vec<_> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.unwrap().path()).ok())
        .filter(|target| {
            target.starts_with(temp.dir())
                && target != temp.dir()
                && target.file_name().is_some_and(|n| n != "lock")
        })
        .filter(|target| !target.to_string_lossy().contains("/#"))
        .collect();
    assert!(
        named.is_empty(),
        "a body file had a name in the folder: {named:?}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn credential_temp_sweep_removes_non_utf8_entries() {
    use std::os::unix::ffi::OsStrExt;
    let data = tempfile::tempdir().unwrap();
    let dead = data.path().join("credential-reads").join("1-dead");
    std::fs::create_dir_all(&dead).unwrap();
    std::fs::write(dead.join("lock"), b"").unwrap();
    std::fs::write(
        dead.join(std::ffi::OsStr::from_bytes(b"\xff")),
        b"secret body",
    )
    .unwrap();
    let _temp = open(data.path(), Limits::default());
    assert!(
        !dead.exists(),
        "a dead folder is removed even when it holds a name that is not UTF-8"
    );
}

// ---- security-2-1 / security-2-2 (Windows): the folders are held as opened, and are private. These run only on a Windows host:
// the `tools win32-x64` job of native-service.yml runs them (step "Windows and macOS credential-reads folder checks") and fails
// unless every `credential_temp_windows_*` test passes. Linux runs this file in rust.yml, macOS in the same native-service.yml step.

#[cfg(windows)]
fn run(command: &mut std::process::Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[cfg(windows)]
fn credential_temp_windows_junction_parent_refused() {
    let data = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    run(std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(data.path().join("credential-reads"))
        .arg(elsewhere.path()));
    assert_eq!(
        CredentialTemp::open(data.path(), Limits::default()).err(),
        Some(TempError::UnsafeParent)
    );
    assert_eq!(
        std::fs::read_dir(elsewhere.path()).unwrap().count(),
        0,
        "nothing is created through the junction"
    );
}

#[test]
#[cfg(windows)]
fn credential_temp_windows_parent_cannot_be_renamed_while_open() {
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits::default());
    let parent = data.path().join("credential-reads");
    assert!(
        std::fs::rename(&parent, data.path().join("moved")).is_err(),
        "the folder that was checked cannot be swapped out"
    );
    assert!(
        std::fs::rename(temp.dir(), parent.join("moved")).is_err(),
        "nor can this process's own folder"
    );
}

#[test]
#[cfg(windows)]
fn credential_temp_windows_shared_parent_refused() {
    let data = tempfile::tempdir().unwrap();
    let parent = service_folder(data.path()); // protected: opening it again succeeds
    run(std::process::Command::new("icacls")
        .arg(&parent)
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"]));
    assert_eq!(
        CredentialTemp::open(data.path(), Limits::default()).err(),
        Some(TempError::UnsafeParent),
        "Users may write there"
    );
    run(std::process::Command::new("icacls")
        .arg(&parent)
        .args(["/remove:g", "*S-1-5-32-545"]));
    open(data.path(), Limits::default()); // the grant was the only reason for the refusal
}

#[test]
#[cfg(windows)]
fn credential_temp_windows_folder_owned_by_users_refused() {
    let data = tempfile::tempdir().unwrap();
    let parent = service_folder(data.path());
    run(std::process::Command::new("icacls")
        .arg(&parent)
        .args(["/setowner", "*S-1-5-32-545"]));
    assert_eq!(
        CredentialTemp::open(data.path(), Limits::default()).err(),
        Some(TempError::UnsafeParent),
        "the ACL is still private: the owner alone refuses it"
    );
    run(std::process::Command::new("icacls")
        .arg(&parent)
        .args(["/setowner", "*S-1-5-32-544"]));
    open(data.path(), Limits::default()); // Administrators own it again: accepted
}

#[test]
#[cfg(windows)]
fn credential_temp_windows_created_folders_are_private() {
    use probation::key_acl::is_shared;
    let data = tempfile::tempdir().unwrap();
    let temp = open(data.path(), Limits::default());
    assert!(
        !is_shared(&data.path().join("credential-reads")),
        "the folder the service created grants only SYSTEM, Administrators and its user"
    );
    assert!(!is_shared(temp.dir()), "so does this process's folder");
    drop(temp);
    open(data.path(), Limits::default());
}
