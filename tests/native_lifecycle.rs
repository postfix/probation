//! Row 25, the part of the native lifecycle that needs no service manager: the REAL `probation` binary as an
//! ordinary process, the way systemd, launchd and the Windows service host run it. Stop (SIGTERM), a crash
//! (SIGKILL) followed by a restart on the same state, the second-owner refusal, the data directory's permissions
//! and the loopback-only default listener. What a service manager adds (units, plist, SCM) is tested where
//! it can run: tests/service_scripts.rs and tests/e2e/native/service-lifecycle.mjs.
// Unix signals and modes; the Windows host is covered by tests/e2e/native (SCM) and by `cargo check --target`.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_probation");

struct Instance {
    child: Child,
    addr: SocketAddr,
    /// Everything the process logged after "listening", read when it has exited.
    lines: BufReader<std::process::ChildStdout>,
}

/// A configuration for `data_dir` on an ephemeral loopback port, written beside it.
fn config(root: &Path, data_dir: &Path, name: &str) -> PathBuf {
    let sample = std::fs::read_to_string("config.sample.toml").expect("the sample is readable");
    let text = sample
        .replace("listen = \"127.0.0.1:8080\"", "listen = \"127.0.0.1:0\"")
        .replace("data_dir = \"/var/lib/probation\"", &format!("data_dir = \"{}\"", data_dir.display()))
        .replace("blocklist_file = \"/etc/probation/blocklist.json\"", &format!("blocklist_file = \"{}\"", root.join("absent.json").display()));
    let path = root.join(name);
    std::fs::write(&path, text).expect("the configuration is written");
    path
}

/// Started the way the service manager starts it: umask 0077 (`UMask=0077` in the unit, `Umask` 63 in the plist).
fn start(config: &Path) -> Instance {
    let mut child = Command::new("sh")
        .args(["-c", "umask 077; exec \"$0\" serve --config \"$1\"", BINARY, config.to_str().expect("UTF-8")])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the binary starts");
    let lines = BufReader::new(child.stdout.take().expect("piped stdout"));
    // Owned from here, so a panic below still reaps the process (Drop).
    let mut instance = Instance { child, addr: SocketAddr::from(([127, 0, 0, 1], 0)), lines };
    let mut line = String::new();
    loop {
        line.clear();
        assert!(instance.lines.read_line(&mut line).expect("a log line") > 0, "the process ended before it listened");
        if line.contains("\"listening\"") {
            let start = line.find("\"addr\":\"").expect("the address field") + 8;
            let end = start + line[start..].find('"').expect("the end of the address");
            instance.addr = line[start..end].parse().expect("an address");
            return instance;
        }
    }
}

fn signal(child: &Child, name: &str) {
    let sent = Command::new("kill").args([&format!("-{name}"), &child.id().to_string()]).status().expect("kill runs");
    assert!(sent.success());
}

fn wait_within(child: &mut Child, within: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            return status;
        }
        assert!(Instant::now() < deadline, "the process did not exit within {within:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn rest(instance: &mut Instance) -> String {
    (&mut instance.lines).lines().map_while(Result::ok).collect::<Vec<_>>().join("\n")
}

/// A test that fails with the service still running must not leave it behind.
impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn private_data_dir(root: &Path) -> PathBuf {
    let data = root.join("data");
    std::fs::create_dir(&data).expect("the data directory");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).expect("0700, as the installer makes it");
    data
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).expect("a directory").flatten() {
        let path = entry.path();
        found.push(path.clone());
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            found.extend(files_under(&path));
        }
    }
    found
}

/// The state a restart must find unchanged: every file's content, by path.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut rows: Vec<_> = files_under(dir)
        .into_iter()
        .filter(|path| path.is_file() && path.file_name().is_some_and(|name| name != "lock"))
        .map(|path| (path.strip_prefix(dir).expect("under the directory").to_path_buf(), std::fs::read(&path).unwrap_or_default()))
        .collect();
    rows.sort();
    rows
}

/// A stop from the service manager is a clean exit with the shutdown summary: SIGTERM (systemd stop, `launchctl bootout`).
#[test]
fn a_sigterm_stop_exits_zero_and_says_so() {
    let dir = tempfile::tempdir().expect("a directory");
    let data = private_data_dir(dir.path());
    let mut instance = start(&config(dir.path(), &data, "a.toml"));
    signal(&instance.child, "TERM");
    let status = wait_within(&mut instance.child, Duration::from_secs(40));
    let log = rest(&mut instance);
    assert_eq!(status.code(), Some(0), "{status}:\n{log}");
    assert!(log.contains("shutting down") && log.contains("SIGTERM"), "{log}");
}

/// Second owner: another instance on the same data directory is refused at once with the lock named, exits non-zero, and
/// changes nothing; the first keeps serving and stops cleanly. After the first stops, the directory is free again.
#[test]
fn a_second_instance_on_a_held_data_directory_is_refused_and_the_first_keeps_serving() {
    let dir = tempfile::tempdir().expect("a directory");
    let data = private_data_dir(dir.path());
    let mut first = start(&config(dir.path(), &data, "a.toml"));
    let before = snapshot(&data);

    // A different port, the same data directory: only the data-directory lock can refuse it.
    let second_config = config(dir.path(), &data, "b.toml");
    let mut refused = Command::new(BINARY).args(["serve", "--config", second_config.to_str().unwrap()]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("the second instance runs");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = refused.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = refused.kill();
            let _ = refused.wait();
            panic!("the second instance on a held data directory was not refused: it was still running after 30 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut log = String::new();
    std::io::Read::read_to_string(&mut refused.stdout.take().expect("piped"), &mut log).expect("its log");
    assert_eq!(status.code(), Some(1), "{log}");
    assert!(log.contains("another instance holds the data-directory lock"), "{log}");
    assert_eq!(snapshot(&data), before, "the refused instance changed nothing in the data directory");
    assert!(TcpStream::connect_timeout(&first.addr, Duration::from_secs(2)).is_ok(), "the first instance still accepts connections");

    signal(&first.child, "TERM");
    assert_eq!(wait_within(&mut first.child, Duration::from_secs(40)).code(), Some(0));
    let mut third = start(&second_config);
    signal(&third.child, "TERM");
    assert_eq!(wait_within(&mut third.child, Duration::from_secs(40)).code(), Some(0), "the released directory is usable");
}

/// A crash (SIGKILL: OOM kill, power loss of the process) releases the lock with the process, so the supervisor's restart
/// starts on the SAME state: no file the first run wrote is lost or replaced, and the operator clears nothing by hand.
#[test]
fn a_killed_instance_restarts_on_the_same_state() {
    let dir = tempfile::tempdir().expect("a directory");
    let data = private_data_dir(dir.path());
    let path = config(dir.path(), &data, "a.toml");
    let mut first = start(&path);
    std::fs::write(data.join("operator-note.txt"), "kept\n").expect("an operator file in the data directory");
    signal(&first.child, "KILL");
    let status = wait_within(&mut first.child, Duration::from_secs(10));
    assert_eq!(status.signal(), Some(9));
    let before = snapshot(&data);
    assert!(before.iter().any(|(name, _)| name.ends_with("operator-note.txt")));

    let mut again = start(&path);
    signal(&again.child, "TERM");
    assert_eq!(wait_within(&mut again.child, Duration::from_secs(40)).code(), Some(0));
    let after = snapshot(&data);
    assert!(before.iter().all(|(name, _)| after.iter().any(|(n, _)| n == name)), "every file the crashed run left is still there after the restart");
    assert_eq!(std::fs::read_to_string(data.join("operator-note.txt")).unwrap(), "kept\n");
}

/// Permissions: the installer makes the data directory 0700 and the service runs with umask 0077. The service does not
/// widen the directory, and nothing it creates inside is accessible to the group or others.
#[test]
fn the_data_directory_stays_private_and_nothing_inside_it_is_shared() {
    let dir = tempfile::tempdir().expect("a directory");
    let data = private_data_dir(dir.path());
    let mut instance = start(&config(dir.path(), &data, "a.toml"));
    signal(&instance.child, "TERM");
    assert_eq!(wait_within(&mut instance.child, Duration::from_secs(40)).code(), Some(0));
    assert_eq!(std::fs::metadata(&data).unwrap().permissions().mode() & 0o777, 0o700, "the directory was not widened");
    let shared: Vec<_> = files_under(&data).into_iter().filter(|path| std::fs::metadata(path).is_ok_and(|meta| meta.mode() & 0o077 != 0)).collect();
    assert!(shared.is_empty(), "group/other-accessible entries: {shared:?}");
    assert!(data.join("lock").exists(), "the lock file is in the data directory");
}

/// A host this test reaches the network through has an address other than loopback; the default listener is loopback only, so
/// a caller addressing the machine from outside (here: by its own non-loopback address) is refused at the socket.
#[test]
fn the_default_listener_refuses_the_hosts_non_loopback_address() {
    let own = UdpSocket::bind("0.0.0.0:0").and_then(|socket| socket.connect("192.0.2.1:9").and_then(|()| socket.local_addr()));
    let Ok(own) = own else {
        eprintln!("SKIPPED: the host has no route, so no non-loopback address; the outside-host check did NOT run");
        return;
    };
    assert!(!own.ip().is_loopback(), "the probe address {own}");
    let dir = tempfile::tempdir().expect("a directory");
    let data = private_data_dir(dir.path());
    let mut instance = start(&config(dir.path(), &data, "a.toml"));
    assert!(instance.addr.ip().is_loopback(), "bound on {}", instance.addr);
    let outside = SocketAddr::new(own.ip(), instance.addr.port());
    assert!(TcpStream::connect_timeout(&outside, Duration::from_secs(2)).is_err(), "{outside} must not accept connections");
    assert!(TcpStream::connect_timeout(&instance.addr, Duration::from_secs(2)).is_ok());
    signal(&instance.child, "TERM");
    assert_eq!(wait_within(&mut instance.child, Duration::from_secs(40)).code(), Some(0));
}
