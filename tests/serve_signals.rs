//! `serve` under a service manager: a `SIGTERM` that arrives while startup is still
//! running must be caught, not left to the default disposition that kills the
//! process outright.

use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_probation");

/// Startup is held still at a known point by making the TLS certificate a FIFO:
/// `App::start` reads it after the startup blocklist pass and blocks there until the
/// test writes. The signal is sent while it is blocked, so whether it is caught
/// depends only on whether the handler was installed before `App::start` returned.
#[test]
fn a_sigterm_during_startup_is_caught() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    assert!(
        Command::new("mkfifo")
            .arg(&cert)
            .status()
            .expect("mkfifo runs")
            .success()
    );
    std::fs::write(&key, "").expect("the key file is written");

    let sample = std::fs::read_to_string("config.sample.toml").expect("the sample is readable");
    let mut config = sample
        .replace("listen = \"127.0.0.1:8080\"", "listen = \"127.0.0.1:0\"")
        .replace(
            "data_dir = \"/var/lib/probation\"",
            &format!("data_dir = \"{}\"", dir.path().join("data").display()),
        )
        .replace(
            "blocklist_file = \"/etc/probation/blocklist.json\"",
            &format!(
                "blocklist_file = \"{}\"",
                dir.path().join("absent.json").display()
            ),
        );
    config.push_str(&format!(
        "\ntls_cert_path = \"{}\"\ntls_key_path = \"{}\"\n",
        cert.display(),
        key.display()
    ));
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).expect("the configuration is written");

    let mut child = Command::new(BINARY)
        .args(["serve", "--config", path.to_str().expect("a UTF-8 path")])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the binary starts");

    // Logged from inside `App::start`, just before the certificate is read.
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();
    for line in lines.by_ref() {
        if line
            .expect("a log line")
            .contains("the blocklist file cannot be examined")
        {
            break;
        }
    }
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(killed.success());

    // Unblock the certificate read with an empty file. Opening a FIFO for writing
    // waits for its reader, which a killed process never becomes, so this runs on a
    // thread of its own rather than holding the assertion hostage.
    std::thread::spawn(move || {
        let _ = std::fs::OpenOptions::new().write(true).open(&cert);
    });

    let status = child.wait().expect("the process exits");
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    assert_eq!(
        status.signal(),
        None,
        "the SIGTERM was not caught: {status}; logged:\n{}",
        rest.join("\n")
    );
    assert_eq!(
        status.code(),
        Some(1),
        "an empty certificate stops startup with an ordinary failure: {status}"
    );
}

/// `SIGINT` (Ctrl-C) reaches the same graceful path as `SIGTERM`: the process says
/// which signal stopped it, writes its shutdown summary, and exits zero.
#[test]
fn a_sigint_once_listening_shuts_down_gracefully() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let sample = std::fs::read_to_string("config.sample.toml").expect("the sample is readable");
    let config = sample
        .replace("listen = \"127.0.0.1:8080\"", "listen = \"127.0.0.1:0\"")
        .replace(
            "data_dir = \"/var/lib/probation\"",
            &format!("data_dir = \"{}\"", dir.path().join("data").display()),
        )
        .replace(
            "blocklist_file = \"/etc/probation/blocklist.json\"",
            &format!(
                "blocklist_file = \"{}\"",
                dir.path().join("absent.json").display()
            ),
        );
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).expect("the configuration is written");

    let mut child = Command::new(BINARY)
        .args(["serve", "--config", path.to_str().expect("a UTF-8 path")])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the binary starts");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();
    for line in lines.by_ref() {
        if line.expect("a log line").contains("\"listening\"") {
            break;
        }
    }
    let sent = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(sent.success());

    let status = child.wait().expect("the process exits");
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    assert_eq!(status.code(), Some(0), "{status}:\n{}", rest.join("\n"));
    assert!(
        rest.iter()
            .any(|line| line.contains("shutting down") && line.contains("SIGINT")),
        "{}",
        rest.join("\n")
    );
}

/// `serve` refuses a configuration `check-config` would refuse, before it binds.
#[test]
fn serve_refuses_an_invalid_configuration() {
    let status = Command::new(BINARY)
        .args([
            "serve",
            "--config",
            "tests/fixtures/config/unknown_key.toml",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the binary runs");
    assert_eq!(status.code(), Some(1));
}
