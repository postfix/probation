//! Row 25: scripts/install-local.sh (machine setup: certificate, config, package-manager settings) is repeatable and
//! non-destructive. A second run, or a run over an existing installation, never replaces the configuration, the
//! blocklist, the TLS key or certificate, never drops a package-manager credential entry or an unrelated setting, and
//! changes only the registry/index lines it owns. `--no-service` keeps it off the host's service manager; a stand-in
//! `sudo` that just runs its command keeps it off the host's privilege system (the paths are all in a temporary directory).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_probation");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/install-local.sh");

struct Machine {
    dir: tempfile::TempDir,
}

impl Machine {
    fn new() -> Machine {
        let machine = Machine {
            dir: tempfile::tempdir().expect("a directory"),
        };
        let bin = machine.path("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(BINARY, bin.join("probation")).unwrap();
        let sudo = bin.join("sudo");
        std::fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").unwrap();
        std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
        machine
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn run(&self) -> String {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = Command::new("bash")
            .arg(SCRIPT)
            .args([
                "--self-signed",
                "--no-service",
                "--host",
                "localhost",
                "--listen-port",
                "18443",
            ])
            .args([
                "--etc-dir",
                self.path("etc").to_str().unwrap(),
                "--data-dir",
                self.path("data").to_str().unwrap(),
            ])
            .args([
                "--npmrc",
                self.path("npmrc").to_str().unwrap(),
                "--pip-conf",
                self.path("pip.conf").to_str().unwrap(),
            ])
            .env("PATH", path)
            .env("HOME", self.path("home"))
            .output()
            .expect("bash runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        text
    }
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(name)).unwrap_or_else(|err| panic!("{name}: {err}"))
    }
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

const NPMRC: &str = "//localhost:18443/npm/:_authToken=npm_SECRET_TOKEN\n//registry.corp.example/:_authToken=corp-token\nregistry=https://old.example/\nalways-auth=true\ncafile=/corp/ca.pem\naudit=true\n";
const PIP: &str = "# the corporate settings\n[global]\ntimeout = 60\nindex-url = https://old.example/simple/\n# keep this comment\n[install]\nextra-index-url = https://user:p%40ss@pkgs.corp.example/simple/\n";

#[test]
fn a_first_run_sets_registry_and_index_and_keeps_credentials_and_unrelated_settings() {
    let machine = Machine::new();
    std::fs::write(machine.path("npmrc"), NPMRC).unwrap();
    std::fs::write(machine.path("pip.conf"), PIP).unwrap();
    machine.run();
    let npmrc = machine.read("npmrc");
    let kept = lines(&npmrc);
    for entry in [
        "//localhost:18443/npm/:_authToken=npm_SECRET_TOKEN",
        "//registry.corp.example/:_authToken=corp-token",
        "always-auth=true",
        "cafile=/corp/ca.pem",
    ] {
        assert!(kept.contains(&entry), "{entry} survives: {npmrc}");
    }
    assert!(
        kept.contains(&"registry=https://localhost:18443/npm/")
            && !kept.contains(&"registry=https://old.example/"),
        "{npmrc}"
    );
    assert!(
        kept.contains(&"audit=false") && !kept.contains(&"audit=true"),
        "{npmrc}"
    );
    let pip = machine.read("pip.conf");
    for entry in [
        "# the corporate settings",
        "timeout = 60",
        "# keep this comment",
        "[install]",
        "extra-index-url = https://user:p%40ss@pkgs.corp.example/simple/",
    ] {
        assert!(lines(&pip).contains(&entry), "{entry} survives: {pip}");
    }
    assert!(
        pip.contains("index-url = https://localhost:18443/pypi/simple/")
            && !pip.contains("old.example"),
        "{pip}"
    );
    assert!(
        pip.contains("cert = "),
        "an untrusted certificate is named explicitly: {pip}"
    );
}

#[test]
fn a_second_run_over_an_existing_install_replaces_no_config_blocklist_key_or_certificate() {
    let machine = Machine::new();
    std::fs::write(machine.path("npmrc"), NPMRC).unwrap();
    machine.run();
    let key = machine.read("etc/tls/localhost-key.pem");
    let cert = machine.read("etc/tls/localhost.pem");
    // The operator edits the files the first run wrote.
    std::fs::write(
        machine.path("etc/config.toml"),
        format!("{}\n# operator edit\n", machine.read("etc/config.toml")),
    )
    .unwrap();
    std::fs::write(
        machine.path("etc/blocklist.json"),
        format!("{}\n\n", machine.read("etc/blocklist.json")),
    )
    .unwrap();
    let (config, blocklist, npmrc, pip) = (
        machine.read("etc/config.toml"),
        machine.read("etc/blocklist.json"),
        machine.read("npmrc"),
        machine.read("pip.conf"),
    );
    let output = machine.run();
    assert!(output.contains("Keeping the existing"), "{output}");
    assert_eq!(
        machine.read("etc/tls/localhost-key.pem"),
        key,
        "the private key is not regenerated"
    );
    assert_eq!(
        machine.read("etc/tls/localhost.pem"),
        cert,
        "the certificate is not regenerated"
    );
    assert_eq!(
        machine.read("etc/config.toml"),
        config,
        "an edited config.toml is not replaced by the sample"
    );
    assert_eq!(
        machine.read("etc/blocklist.json"),
        blocklist,
        "a producer's blocklist is not replaced by the sample"
    );
    assert_eq!(
        machine.read("npmrc"),
        npmrc,
        "repeat tool setup is idempotent for npm (credentials and all)"
    );
    assert_eq!(
        machine.read("pip.conf"),
        pip,
        "repeat tool setup is idempotent for pip"
    );
    assert!(machine.read("npmrc").contains("npm_SECRET_TOKEN"));
}

#[test]
fn an_existing_credential_file_is_never_widened_by_the_rewrite() {
    let machine = Machine::new();
    std::fs::write(machine.path("npmrc"), NPMRC).unwrap();
    std::fs::write(machine.path("pip.conf"), PIP).unwrap();
    std::fs::set_permissions(
        machine.path("npmrc"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::set_permissions(
        machine.path("pip.conf"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    machine.run();
    let mode = |name: &str| {
        std::fs::metadata(machine.path(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(
        (mode("npmrc"), mode("pip.conf")),
        (0o600, 0o640),
        "a 0600 npmrc with a token stays 0600 and 0640 stays 0640"
    );
    // A file this script creates holds no credential and is readable by every user's npm and pip.
    let fresh = Machine::new();
    fresh.run();
    assert_eq!(
        std::fs::metadata(fresh.path("npmrc"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[test]
fn an_abort_after_the_ownership_hand_over_restores_it_and_hits_no_unbound_variable() {
    let machine = Machine::new();
    let bin = machine.path("bin");
    let script = |name: &str, body: &str| {
        std::fs::write(bin.join(name), format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let log = machine.path("calls.log");
    // `sudo` marks its children; the plain `mkdir` fails, so the script takes the system-install branch; `openssl` fails, which aborts it
    // after the ownership was handed to the login user. chown, useradd and chgrp are recorded, not run.
    script("sudo", "VIA_SUDO=1 exec \"$@\"");
    script(
        "mkdir",
        "if [ -n \"$VIA_SUDO\" ]; then exec /bin/mkdir \"$@\"; fi; exit 1",
    );
    script("chown", &format!("echo chown \"$@\" >> {}", log.display()));
    script(
        "useradd",
        &format!("echo useradd \"$@\" >> {}", log.display()),
    );
    script("openssl", "echo 'openssl: forced failure' >&2; exit 1");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("bash")
        .arg(SCRIPT)
        .args([
            "--self-signed",
            "--no-service",
            "--host",
            "localhost",
            "--listen-port",
            "18443",
        ])
        .args([
            "--etc-dir",
            machine.path("etc").to_str().unwrap(),
            "--data-dir",
            machine.path("data").to_str().unwrap(),
        ])
        .args([
            "--npmrc",
            machine.path("npmrc").to_str().unwrap(),
            "--pip-conf",
            machine.path("pip.conf").to_str().unwrap(),
        ])
        .env("PATH", path)
        .env("HOME", machine.path("home"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "the forced failure aborts the script"
    );
    assert!(!stderr.contains("unbound variable"), "{stderr}");
    let calls = std::fs::read_to_string(&log).unwrap();
    let handed: Vec<&str> = calls.lines().filter(|l| l.starts_with("chown")).collect();
    assert!(
        handed
            .iter()
            .any(|l| l.contains("-R") && !l.contains("root:")),
        "ownership went to the login user first: {calls}"
    );
    assert!(
        handed.iter().skip(1).any(|l| l.contains("root:probation"))
            && handed
                .iter()
                .skip(1)
                .any(|l| l.contains("probation:probation")),
        "and the trap handed the policy back to root and the state to the service account: {calls}"
    );
}
