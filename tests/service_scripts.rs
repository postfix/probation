//! Row 25: the files scripts/install-service.sh writes for the machine-wide native service, in a disposable staging root
//! (`--root`: no service manager, account or ownership command runs and nothing outside the root is touched). What it
//! pins: nothing existing is ever replaced (config, blocklist, TLS key, data), an upgrade changes the binary and the
//! definition only, a second owner of a service name is refused, uninstall removes only what install recorded, and the
//! definitions carry the supervision contract (restart on exit 75 and crash but not on an operator stop, 45 s stop allowance,
//! owner-only umask). The real service managers run in tests/e2e/native (systemd here; launchd and the SCM on their runners).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_probation");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/install-service.sh");
const UNIT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/probation.service");

struct Root {
    dir: tempfile::TempDir,
}

impl Root {
    fn new() -> Root {
        Root { dir: tempfile::tempdir().expect("a staging root") }
    }
    fn path(&self, inside: &str) -> PathBuf {
        self.dir.path().join("root").join(inside.trim_start_matches('/'))
    }
    /// The script's own `bash` run, always staged; `extra` after the action.
    fn run(&self, action: &str, extra: &[&str]) -> Output {
        Command::new("bash")
            .arg(SCRIPT)
            .arg(action)
            .args(["--root", self.dir.path().join("root").to_str().unwrap(), "--binary", BINARY])
            .args(extra)
            .env("HOME", self.dir.path().join("home"))
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .expect("bash runs")
    }
    fn ok(&self, action: &str, extra: &[&str]) -> String {
        let out = self.run(action, extra);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "{action} {extra:?}: {text}");
        text
    }
    fn refused(&self, action: &str, extra: &[&str]) -> String {
        let out = self.run(action, extra);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success(), "{action} {extra:?} must be refused: {text}");
        text
    }
    fn read(&self, inside: &str) -> String {
        std::fs::read_to_string(self.path(inside)).unwrap_or_else(|err| panic!("{inside}: {err}"))
    }
    fn mode(&self, inside: &str) -> u32 {
        std::fs::metadata(self.path(inside)).unwrap_or_else(|err| panic!("{inside}: {err}")).permissions().mode() & 0o777
    }
    fn put(&self, inside: &str, content: &str) {
        let path = self.path(inside);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
}

fn exists(path: &Path) -> bool {
    path.exists()
}

#[test]
fn a_system_install_writes_the_documented_files_modes_and_the_deploy_unit_itself() {
    let root = Root::new();
    root.ok("install", &[]);
    assert_eq!(root.read("/etc/systemd/system/probation.service"), std::fs::read_to_string(UNIT).unwrap(), "the generated unit is deploy/probation.service");
    assert_eq!((root.mode("/etc/probation"), root.mode("/etc/probation/config.toml"), root.mode("/etc/probation/blocklist.json")), (0o750, 0o640, 0o640));
    assert_eq!((root.mode("/var/lib/probation"), root.mode("/var/log/probation"), root.mode("/usr/local/bin/probation")), (0o700, 0o750, 0o755));
    let config = root.read("/etc/probation/config.toml");
    assert!(config.contains("listen = \"127.0.0.1:8080\"") && config.contains("data_dir = \"/var/lib/probation\""), "{config}");
    assert!(config.contains("log_file_path = \"/var/log/probation/decisions.ndjson\""), "{config}");
    // The installed config is one the binary accepts.
    let checked = Command::new(BINARY).args(["check-config", root.path("/etc/probation/config.toml").to_str().unwrap()]).output().unwrap();
    // data_dir and the blocklist live under the staging root's real paths, so only the parse is judged here.
    let message = String::from_utf8_lossy(&checked.stderr).to_string();
    assert!(!message.contains("unknown") && !message.contains("invalid TOML"), "{message}");
}

#[test]
fn an_install_never_replaces_existing_config_blocklist_tls_material_or_data() {
    let root = Root::new();
    root.put("/etc/probation/config.toml", "# the operator's own\nlisten = \"127.0.0.1:9999\"\n");
    root.put("/etc/probation/blocklist.json", "{\"operator\":true}\n");
    root.put("/etc/probation/tls/localhost-key.pem", "PRIVATE KEY BYTES\n");
    root.put("/etc/probation/tls/ca.pem", "CERT BYTES\n");
    root.put("/var/lib/probation/state.db", "state\n");
    let output = root.ok("install", &[]);
    assert!(output.contains("Keeping the existing /etc/probation/config.toml") && output.contains("Keeping the existing /etc/probation/blocklist.json"), "{output}");
    for (path, content) in [
        ("/etc/probation/config.toml", "# the operator's own\nlisten = \"127.0.0.1:9999\"\n"),
        ("/etc/probation/blocklist.json", "{\"operator\":true}\n"),
        ("/etc/probation/tls/localhost-key.pem", "PRIVATE KEY BYTES\n"),
        ("/etc/probation/tls/ca.pem", "CERT BYTES\n"),
        ("/var/lib/probation/state.db", "state\n"),
    ] {
        assert_eq!(root.read(path), content, "{path} was not touched");
    }
}

#[test]
fn a_second_owner_of_a_service_name_is_refused_and_changes_nothing() {
    let root = Root::new();
    root.ok("install", &[]);
    let unit = root.read("/etc/systemd/system/probation.service");
    let text = root.refused("install", &[]);
    assert!(text.contains("already installed"), "{text}");
    assert_eq!(root.read("/etc/systemd/system/probation.service"), unit);

    // A unit of that name this script did not write is never taken over.
    let stranger = Root::new();
    stranger.put("/etc/systemd/system/probation.service", "[Service]\nExecStart=/opt/other/thing\n");
    let text = stranger.refused("install", &[]);
    assert!(text.contains("was not installed by this script"), "{text}");
    assert_eq!(stranger.read("/etc/systemd/system/probation.service"), "[Service]\nExecStart=/opt/other/thing\n");
    assert!(!exists(&stranger.path("/etc/probation/config.toml")), "a refused install created nothing");
}

#[test]
fn an_upgrade_swaps_the_binary_and_the_definition_and_nothing_else() {
    let root = Root::new();
    root.ok("install", &[]);
    root.put("/etc/probation/config.toml", "# edited since\nlisten = \"127.0.0.1:9999\"\n");
    root.put("/var/lib/probation/state.db", "state\n");
    let before_binary = std::fs::read(root.path("/usr/local/bin/probation")).unwrap();
    // A different binary: the real one with a byte appended (an ELF tolerates trailing bytes; staging never runs it).
    let newer = root.dir.path().join("probation-new");
    let mut bytes = before_binary.clone();
    bytes.extend_from_slice(b"upgrade");
    std::fs::write(&newer, &bytes).unwrap();
    std::fs::set_permissions(&newer, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new("bash")
        .args([SCRIPT, "upgrade", "--root", root.dir.path().join("root").to_str().unwrap(), "--binary", newer.to_str().unwrap()])
        .env("HOME", root.dir.path().join("home"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(root.path("/usr/local/bin/probation")).unwrap(), bytes);
    assert_eq!(std::fs::read(root.path("/usr/local/bin/probation.prev")).unwrap(), before_binary, "the previous binary is kept");
    assert_eq!(root.read("/etc/probation/config.toml"), "# edited since\nlisten = \"127.0.0.1:9999\"\n");
    assert_eq!(root.read("/var/lib/probation/state.db"), "state\n");
    assert_eq!(root.read("/etc/systemd/system/probation.service"), std::fs::read_to_string(UNIT).unwrap());
}

#[test]
fn an_upgrade_without_an_install_or_without_a_config_is_refused() {
    let root = Root::new();
    assert!(root.refused("upgrade", &[]).contains("nothing to upgrade"));
    root.ok("install", &[]);
    std::fs::remove_file(root.path("/etc/probation/config.toml")).unwrap();
    assert!(root.refused("upgrade", &[]).contains("an upgrade never creates one"));
    assert!(!exists(&root.path("/etc/probation/config.toml")), "an upgrade does not write a sample over a missing config");
}

#[test]
fn an_uninstall_removes_what_install_recorded_and_keeps_config_and_data() {
    let root = Root::new();
    root.ok("install", &["--log-namespace", "probation"]);
    root.put("/var/lib/probation/state.db", "state\n");
    assert!(exists(&root.path("/etc/systemd/journald@probation.conf")));
    assert!(root.read("/etc/systemd/system/probation.service").contains("LogNamespace=probation"));
    root.ok("uninstall", &[]);
    for gone in ["/etc/systemd/system/probation.service", "/usr/local/bin/probation", "/etc/systemd/journald@probation.conf"] {
        assert!(!exists(&root.path(gone)), "{gone} is removed");
    }
    for kept in ["/etc/probation/config.toml", "/etc/probation/blocklist.json", "/var/lib/probation/state.db"] {
        assert!(exists(&root.path(kept)), "{kept} stays");
    }
    assert!(root.refused("uninstall", &[]).contains("no install record"));
}

#[test]
fn a_binary_of_the_same_name_this_script_did_not_install_is_not_overwritten() {
    let root = Root::new();
    root.put("/usr/local/bin/probation", "somebody else's program\n");
    let text = root.refused("install", &[]);
    assert!(text.contains("was not installed by this script"), "{text}");
    assert_eq!(root.read("/usr/local/bin/probation"), "somebody else's program\n");
}

#[test]
fn a_custom_data_directory_is_granted_write_access_under_the_sandbox() {
    let root = Root::new();
    root.ok("install", &["--data-dir", "/srv/probation/data", "--log-dir", "/srv/probation/log", "--name", "probation-b"]);
    let unit = root.read("/etc/systemd/system/probation-b.service");
    assert!(unit.contains("ReadWritePaths=/srv/probation/data") && unit.contains("ReadWritePaths=/srv/probation/log"), "{unit}");
    assert!(!unit.contains("StateDirectory=") && unit.contains("ProtectSystem=strict"), "{unit}");
    assert_eq!(root.mode("/srv/probation/data"), 0o700);
}

#[test]
fn a_user_scope_unit_runs_as_the_login_with_no_account_switch() {
    let root = Root::new();
    root.ok("install", &["--scope", "user"]);
    let home = root.dir.path().join("home");
    let home = home.to_str().unwrap().trim_start_matches('/').to_owned();
    let unit = root.read(&format!("/{home}/.config/systemd/user/probation.service"));
    assert!(!unit.contains("User=") && !unit.contains("StateDirectory=") && unit.contains("WantedBy=default.target"), "{unit}");
    assert!(unit.contains("Restart=on-failure") && unit.contains("TimeoutStopSec=45") && unit.contains("UMask=0077"), "{unit}");
    assert_eq!(root.mode(&format!("/{home}/.config/probation")), 0o700);
    assert_eq!(root.mode(&format!("/{home}/.config/probation/config.toml")), 0o600);
}

#[test]
fn the_unit_carries_the_supervision_contract() {
    let unit = std::fs::read_to_string(UNIT).unwrap();
    for line in ["Restart=on-failure", "RestartSec=2", "TimeoutStopSec=45", "UMask=0077", "StateDirectoryMode=0700", "NoNewPrivileges=yes", "ProtectSystem=strict"] {
        assert!(unit.lines().any(|l| l == line), "{line} in the unit");
    }
    assert!(!unit.contains("Restart=always"), "an operator stop must stay stopped");
}

#[test]
fn the_launchd_definition_restarts_failures_but_not_a_stop_and_runs_as_the_service_account() {
    let root = Root::new();
    root.ok("install", &["--platform", "macos"]);
    let plist = root.path("/Library/LaunchDaemons/com.postfix.probation.plist");
    let program = "import plistlib,sys,json; print(json.dumps(plistlib.load(open(sys.argv[1],'rb'))))";
    let parsed = Command::new("python3").args(["-I", "-c", program, plist.to_str().unwrap()]).output().expect("python3 runs");
    assert!(parsed.status.success(), "the plist is well-formed XML: {}", String::from_utf8_lossy(&parsed.stderr));
    let value: serde_json::Value = serde_json::from_slice(&parsed.stdout).unwrap();
    assert_eq!(value["Label"], "com.postfix.probation");
    assert_eq!(value["ProgramArguments"], serde_json::json!(["/usr/local/bin/probation", "serve", "--config", "/etc/probation/config.toml"]));
    assert_eq!(value["KeepAlive"], serde_json::json!({"SuccessfulExit": false}), "a failure and exit 75 restart; an exit 0 stop does not");
    assert_eq!((value["ThrottleInterval"].as_i64(), value["ExitTimeOut"].as_i64(), value["Umask"].as_i64()), (Some(5), Some(45), Some(0o077)));
    assert_eq!((value["UserName"].as_str(), value["GroupName"].as_str(), value["RunAtLoad"].as_bool()), (Some("_probation"), Some("_probation"), Some(true)));
    assert!(root.read("/etc/newsyslog.d/probation.conf").contains("/var/log/probation-launchd/probation.stdout.log _probation:_probation 600"), "launchd does not rotate stdout; newsyslog does, in the root-owned directory");
    assert_eq!(root.mode("/var/log/probation-launchd"), 0o755, "the directory that holds launchd's files is not writable by the service");
    assert_eq!(root.mode("/var/log/probation-launchd/probation.stdout.log"), 0o600);
    assert_eq!(root.mode("/Library/LaunchDaemons/com.postfix.probation.plist"), 0o644);
}

#[test]
fn systemd_accepts_the_generated_system_unit() {
    if Command::new("systemd-analyze").arg("--version").output().is_err() {
        eprintln!("SKIPPED: no systemd-analyze on this host; the unit was NOT verified");
        return;
    }
    let root = Root::new();
    root.ok("install", &[]);
    // The host's own unit set is the context, so the staged unit is verified where it would be installed, with the
    // example binary path and account replaced by ones this host has.
    let me = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap().trim().to_owned();
    let unit = root
        .read("/etc/systemd/system/probation.service")
        .replace("/usr/local/bin/probation", BINARY)
        .replace("/etc/probation/config.toml", root.path("/etc/probation/config.toml").to_str().unwrap())
        .replace("User=probation", &format!("User={me}"))
        .replace("Group=probation", &format!("Group={me}"));
    let file = root.dir.path().join("probation-verify.service");
    std::fs::write(&file, unit).unwrap();
    let verified = Command::new("systemd-analyze").args(["verify", file.to_str().unwrap()]).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&verified.stdout), String::from_utf8_lossy(&verified.stderr));
    assert!(verified.status.success() && !text.contains("Unknown key") && !text.contains("not executable"), "{text}");
}

#[test]
fn the_system_unit_is_sandboxed_and_its_exposure_is_bounded() {
    let unit = std::fs::read_to_string(UNIT).unwrap();
    for line in [
        "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes", "ProtectProc=invisible", "ProcSubset=pid",
        "PrivateDevices=yes", "RestrictSUIDSGID=yes", "RestrictNamespaces=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
        "SystemCallArchitectures=native", "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources",
        "StartLimitIntervalSec=60", "StartLimitBurst=10",
    ] {
        assert!(unit.lines().any(|l| l == line), "{line} in the unit");
    }
    if Command::new("systemd-analyze").arg("--version").output().is_err() {
        eprintln!("SKIPPED: no systemd-analyze; the exposure score was NOT checked");
        return;
    }
    let out = Command::new("systemd-analyze").args(["security", "--offline=true", "--no-pager", UNIT]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let score: f64 = text.rsplit("exposure level for probation.service: ").next().and_then(|rest| rest.split_whitespace().next()).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("no exposure score in: {text}"));
    assert!(score <= 2.0, "the stated ceiling is 2.0 (OK); the unit scores {score}");
}

#[test]
fn the_user_scope_unit_keeps_the_directives_a_user_manager_can_apply() {
    let root = Root::new();
    root.ok("install", &["--scope", "user"]);
    let home = root.dir.path().join("home");
    let home = home.to_str().unwrap().trim_start_matches('/').to_owned();
    let unit = root.read(&format!("/{home}/.config/systemd/user/probation.service"));
    for kept in ["RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "SystemCallFilter=@system-service", "MemoryDenyWriteExecute=yes", "LockPersonality=yes", "StartLimitBurst=10"] {
        assert!(unit.lines().any(|l| l == kept), "{kept} in the user unit: {unit}");
    }
    for dropped in ["CapabilityBoundingSet", "PrivateDevices", "ProtectProc", "ProtectKernelTunables", "ProtectSystem"] {
        assert!(!unit.lines().any(|l| l.starts_with(dropped)), "{dropped} needs a mount namespace a user manager lacks: {unit}");
    }
}

// ---- fix round: containment, argument validation, root-owned launchd logs, attestation, rollback

#[test]
fn a_forged_install_record_deletes_nothing_outside_what_the_installer_created() {
    let root = Root::new();
    root.ok("install", &[]);
    root.put("/victim/important.txt", "keep me\n");
    root.put("/etc/passwd-like", "keep me too\n");
    let manifest = root.path("/etc/probation/.service-install-probation");
    let mut text = std::fs::read_to_string(&manifest).unwrap();
    text.push_str("file:/victim/important.txt\nfile:/../../../etc/passwd-like\nfile:relative/path\nfile:/usr/local/bin/../../../victim/important.txt\n");
    std::fs::write(&manifest, text).unwrap();
    let out = root.refused("uninstall", &[]);
    assert!(out.contains("never creates") && out.contains("not absolute") && out.contains("dot component"), "{out}");
    assert_eq!(root.read("/victim/important.txt"), "keep me\n");
    assert_eq!(root.read("/etc/passwd-like"), "keep me too\n");
    assert!(!root.path("/etc/systemd/system/probation.service").exists(), "the files it did create are still removed");
}

#[test]
fn files_that_were_already_there_are_not_recorded_as_ours_and_survive_an_uninstall() {
    let root = Root::new();
    // The same program already installed, and a journald file somebody else wrote.
    std::fs::create_dir_all(root.path("/usr/local/bin")).unwrap();
    std::fs::copy(BINARY, root.path("/usr/local/bin/probation")).unwrap();
    root.put("/etc/systemd/journald@probation.conf", "[Journal]\nStorage=volatile\n");
    root.ok("install", &["--log-namespace", "probation"]);
    root.ok("uninstall", &[]);
    assert!(root.path("/usr/local/bin/probation").exists(), "an identical pre-existing binary is not ours to remove");
    assert_eq!(root.read("/etc/systemd/journald@probation.conf"), "[Journal]\nStorage=volatile\n", "a pre-existing journald file is neither overwritten nor removed");
}

#[test]
fn unsafe_arguments_are_refused_before_anything_is_written() {
    let root = Root::new();
    for (flag, value) in [("--service-user", "a b"), ("--service-user", "x;rm"), ("--config-dir", "/etc/a b"), ("--data-dir", "/var/lib/a&b"), ("--log-dir", "/var/log/../etc"), ("--bin-dir", "relative/bin"), ("--public-url", "https://x\"y"), ("--listen", "127.0.0.1:80\\n"), ("--tls-cert", "/etc/a\\b.pem")] {
        let extra = if flag == "--tls-cert" { vec![flag, value, "--tls-key", "/etc/k.pem"] } else { vec![flag, value] };
        root.refused("install", &extra);
    }
    // `--root /` would be the running system.
    let out = Command::new("bash").args([SCRIPT, "install", "--root", "/", "--binary", BINARY]).output().unwrap();
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("--no-staging"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!root.path("/etc/probation").exists());
}

#[test]
fn a_certificate_the_system_unit_cannot_see_is_refused_at_install() {
    let root = Root::new();
    let out = root.refused("install", &["--tls-cert", "/home/me/cert.pem", "--tls-key", "/home/me/key.pem"]);
    assert!(out.contains("ProtectHome"), "{out}");
}

#[test]
fn an_existing_config_keeps_its_mode_and_directories_keep_theirs() {
    let root = Root::new();
    root.put("/etc/probation/config.toml", "# mine\nlisten = \"127.0.0.1:9\"\n");
    std::fs::set_permissions(root.path("/etc/probation/config.toml"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(root.path("/etc/probation"), std::fs::Permissions::from_mode(0o700)).unwrap();
    root.ok("install", &[]);
    assert_eq!((root.mode("/etc/probation/config.toml"), root.mode("/etc/probation")), (0o600, 0o700), "kept files and directories are not widened");
}

#[test]
fn the_launchd_log_files_sit_in_a_root_owned_directory_and_never_through_a_symlink() {
    let root = Root::new();
    std::fs::create_dir_all(root.path("/var/log/probation-launchd")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.path("/var/log/probation-launchd/probation.stdout.log")).unwrap();
    let out = root.refused("install", &["--platform", "macos"]);
    assert!(out.contains("symbolic link"), "{out}");
    assert!(std::fs::symlink_metadata(root.path("/var/log/probation-launchd/probation.stdout.log")).unwrap().file_type().is_symlink(), "the link was left alone, not followed or replaced");
}

fn package_with_gh(gh_status: i32) -> (tempfile::TempDir, PathBuf) {
    package_with_tools(gh_status, None)
}

fn package_with_tools(gh_status: i32, cosign_status: Option<i32>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    for file in ["scripts/install-service.sh", "config.sample.toml", "blocklist.sample.json"] {
        std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join(file), pkg.join(Path::new(file).file_name().unwrap())).unwrap();
    }
    std::fs::create_dir_all(pkg.join("deploy")).unwrap();
    std::fs::copy(UNIT, pkg.join("deploy/probation.service")).unwrap();
    std::fs::copy(BINARY, pkg.join("probation")).unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("gh"), format!("#!/bin/sh\necho \"$@\" >> \"$0.args\"\nexit {gh_status}\n")).unwrap();
    std::fs::set_permissions(bin.join("gh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    if let Some(status) = cosign_status {
        std::fs::write(bin.join("cosign"), format!("#!/bin/sh\necho \"$@\" >> \"$0.args\"\nexit {status}\n")).unwrap();
        std::fs::set_permissions(bin.join("cosign"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(pkg.join("probation.sigstore.json"), "{}").unwrap();
    }
    (dir, pkg)
}

fn install_from_package(dir: &tempfile::TempDir, pkg: &Path, extra: &[&str]) -> Output {
    // A package without the release marker needs --dev-package to be installed at all (tested separately).
    let dev: &[&str] = if pkg.join("RELEASE-PACKAGE").exists() { &[] } else { &["--dev-package"] };
    Command::new("bash")
        .arg(pkg.join("install-service.sh"))
        .args(["install", "--root", dir.path().join("root").to_str().unwrap()])
        .args(dev)
        .args(extra)
        .env("PATH", format!("{}:{}", dir.path().join("bin").display(), std::env::var("PATH").unwrap()))
        .env("HOME", dir.path().join("home"))
        .output()
        .unwrap()
}

#[test]
fn the_release_attestation_of_the_shipped_binary_is_verified_when_gh_is_there() {
    let (bad, pkg) = package_with_gh(1);
    let out = install_from_package(&bad, &pkg, &[]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("attestation"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!bad.path().join("root/etc/probation").exists(), "nothing was installed");
    assert!(install_from_package(&bad, &pkg, &["--no-verify"]).status.success(), "--no-verify is the explicit way past it");
    let (good, pkg) = package_with_gh(0);
    let out = install_from_package(&good, &pkg, &[]);
    assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Verified the release attestation"), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// REAL systemd --user: an upgrade whose new binary passes `check-config` and then dies at start is rolled back to the previous
/// binary and the service is running again. Skipped loudly where there is no user manager.
#[test]
fn an_upgrade_to_a_binary_that_validates_but_does_not_start_is_rolled_back() {
    let ok = Command::new("systemctl").args(["--user", "is-active", "default.target"]).output().is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("SKIPPED: no systemd --user manager; the upgrade rollback against a real service manager did NOT run");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = |n: &str| dir.path().join(n).to_str().unwrap().to_owned();
    let name = format!("probation-rb{}", std::process::id());
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port().to_string();
    struct Cleanup(String, Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("bash").arg(SCRIPT).args(["uninstall", "--scope", "user", "--name", &self.0]).args(&self.1).output();
            let _ = Command::new("systemctl").args(["--user", "stop", &format!("{}.service", self.0)]).output();
        }
    }
    let dirs = vec!["--config-dir".to_owned(), d("config"), "--data-dir".to_owned(), d("data"), "--log-dir".to_owned(), d("log"), "--bin-dir".to_owned(), d("bin")];
    let _cleanup = Cleanup(name.clone(), dirs.clone());
    let run = |action: &str, binary: &str| {
        Command::new("bash").arg(SCRIPT).args([action, "--scope", "user", "--name", &name, "--binary", binary, "--listen", &format!("127.0.0.1:{port}")]).args(&dirs).output().unwrap()
    };
    let out = run("install", BINARY);
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    // A program that accepts the configuration and then exits 1 when asked to serve.
    let stand_in = dir.path().join("stand-in");
    std::fs::write(&stand_in, "#!/bin/sh\n[ \"$1\" = check-config ] && exit 0\nexit 1\n").unwrap();
    std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = std::fs::read(d("bin") + "/probation").unwrap();
    let out = run("upgrade", stand_in.to_str().unwrap());
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success() && text.contains("previous binary and definition are back"), "{text}");
    assert_eq!(std::fs::read(d("bin") + "/probation").unwrap(), before, "the previous binary is back");
    let active = Command::new("systemctl").args(["--user", "is-active", &format!("{name}.service")]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&active.stdout).trim(), "active", "the previous service is running again: {text}");
}

#[test]
fn the_release_package_has_one_layout_with_sums_that_cover_what_is_installed() {
    let dir = tempfile::tempdir().unwrap();
    let dlls = dir.path().join("dlls");
    std::fs::create_dir_all(&dlls).unwrap();
    std::fs::write(dlls.join("libcrypto-3-x64.dll"), "dll").unwrap();
    let package = |target: &str, dll: Option<&Path>| {
        let mut cmd = Command::new("bash");
        cmd.arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/package-release.sh")).args([target, BINARY, dir.path().join("out").to_str().unwrap()]);
        if let Some(dll) = dll { cmd.arg(dll); }
        let out = cmd.env("VERSION", "v9.9.9").output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
    };
    let unix = package("x86_64-unknown-linux-gnu", None);
    for file in ["probation", "install-service.sh", "config.sample.toml", "blocklist.sample.json", "deploy/probation.service", "SHA256SUMS"] {
        assert!(unix.join(file).exists(), "{file}");
    }
    let sums = std::fs::read_to_string(unix.join("SHA256SUMS")).unwrap();
    assert!(sums.contains(" probation") && sums.contains("install-service.sh"), "{sums}");
    let windows = package("x86_64-pc-windows-msvc", Some(&dlls));
    let sums = std::fs::read_to_string(windows.join("SHA256SUMS")).unwrap();
    assert!(windows.join("probation.exe").exists() && windows.join("install-service.ps1").exists() && windows.join("libcrypto-3-x64.dll").exists());
    assert!(sums.contains("libcrypto-3-x64.dll") && sums.contains("probation.exe"), "{sums}");
    // A Windows package with no library to ship is refused, not shipped without it.
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let out = Command::new("bash").arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/package-release.sh")).args(["x86_64-pc-windows-msvc", BINARY, dir.path().join("o2").to_str().unwrap(), empty.to_str().unwrap()]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn the_cosign_signature_is_verified_when_cosign_and_a_bundle_are_there() {
    // gh passes (exit 0) in all three; only cosign differs.
    let (bad, pkg) = package_with_tools(0, Some(1));
    let out = install_from_package(&bad, &pkg, &[]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("cosign signature"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!bad.path().join("root/etc/probation").exists(), "nothing was installed");
    assert!(install_from_package(&bad, &pkg, &["--no-verify"]).status.success());
    let (good, pkg) = package_with_tools(0, Some(0));
    let out = install_from_package(&good, &pkg, &[]);
    assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Verified the cosign signature"), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    // A bundle named explicitly is the one checked.
    let (named, pkg) = package_with_tools(0, Some(0));
    std::fs::remove_file(pkg.join("probation.sigstore.json")).unwrap();
    std::fs::write(named.path().join("other.json"), "{}").unwrap();
    let out = install_from_package(&named, &pkg, &["--cosign-bundle", named.path().join("other.json").to_str().unwrap()]);
    assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Verified the cosign signature"));
    // Without a bundle, cosign has nothing to check: said out loud, not a failure.
    let (none, pkg) = package_with_tools(0, Some(1));
    std::fs::remove_file(pkg.join("probation.sigstore.json")).unwrap();
    let out = install_from_package(&none, &pkg, &[]);
    assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("NOT verified"));
}

// ---- recheck 1: a release package must verify, the pins are tested, launchd health, low ports

fn mark_release(pkg: &Path) {
    std::fs::write(pkg.join("RELEASE-PACKAGE"), "probation release package\n").unwrap();
}

#[test]
fn a_release_package_without_gh_cosign_or_a_bundle_is_refused_unless_explicitly_allowed() {
    // No gh and no cosign on PATH at all (the stand-in dir is empty): a plain package proceeds softly, a release package refuses.
    let (dir, pkg) = package_with_tools(0, None);
    std::fs::remove_file(dir.path().join("bin/gh")).unwrap();
    // A PATH that holds the tools the script needs and no gh or cosign (this host has a real gh).
    let tools = dir.path().join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    for tool in ["bash", "awk", "cp", "mv", "rm", "rmdir", "mkdir", "chmod", "install", "cmp", "grep", "printf", "id", "uname", "dirname", "cat", "sed", "stat", "date", "env", "sleep", "tr", "head", "mktemp", "python3"] {
        if let Ok(found) = Command::new("sh").args(["-c", &format!("command -v {tool}")]).output() {
            let path = String::from_utf8_lossy(&found.stdout).trim().to_owned();
            if !path.is_empty() && !tools.join(tool).exists() { std::os::unix::fs::symlink(path, tools.join(tool)).unwrap(); }
        }
    }
    let run = |extra: &[&str]| {
        let out = Command::new("bash")
            .arg(pkg.join("install-service.sh"))
            .args(["install", "--root", dir.path().join("root").to_str().unwrap()])
            .args(if pkg.join("RELEASE-PACKAGE").exists() { &[] as &[&str] } else { &["--dev-package"] })
            .args(extra)
            .env("PATH", tools.to_str().unwrap())
            .env("HOME", dir.path().join("home"))
            .output()
            .unwrap();
        (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
    };
    let (ok, text) = run(&[]);
    assert!(ok && text.contains("NOT verified"), "{text}");
    std::fs::remove_dir_all(dir.path().join("root")).unwrap();
    mark_release(&pkg);
    let (ok, text) = run(&[]);
    assert!(!ok && text.contains("release package") && text.contains("gh is not installed"), "{text}");
    assert!(!dir.path().join("root/etc/probation").exists(), "nothing was installed");
    let (ok, text) = run(&["--allow-unverified"]);
    assert!(ok && text.contains("WARNING") && text.contains("DISABLED"), "{text}");
}

#[test]
fn the_pins_given_to_gh_and_cosign_are_the_repository_the_workflow_the_issuer_and_the_bundle() {
    let (dir, pkg) = package_with_tools(0, Some(0));
    mark_release(&pkg);
    let out = install_from_package(&dir, &pkg, &[]);
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let gh = std::fs::read_to_string(dir.path().join("bin/gh.args")).unwrap();
    assert!(gh.contains("attestation verify") && gh.contains("--repo postfix/probation") && gh.contains("--signer-workflow postfix/probation/.github/workflows/release.yml"), "{gh}");
    let cosign = std::fs::read_to_string(dir.path().join("bin/cosign.args")).unwrap();
    assert!(cosign.contains("verify-blob") && cosign.contains("--bundle") && cosign.contains("probation.sigstore.json"), "{cosign}");
    assert!(cosign.contains("--certificate-oidc-issuer https://token.actions.githubusercontent.com"), "{cosign}");
    assert!(cosign.contains("--certificate-identity-regexp ^https://github\\.com/postfix/probation/\\.github/workflows/release\\.yml@refs/tags/.+$"), "{cosign}");
    // A release package with gh and cosign but no bundle refuses too.
    let (nobundle, pkg) = package_with_tools(0, Some(0));
    mark_release(&pkg);
    std::fs::remove_file(pkg.join("probation.sigstore.json")).unwrap();
    let out = install_from_package(&nobundle, &pkg, &[]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("bundle is missing"), "{}", String::from_utf8_lossy(&out.stderr));
}

/// The workflow whose attestation the installer accepts: release.yml by default, and with --signer-workflow another workflow file of the
/// SAME repository (the hosted lanes attest their CI package from native-service.yml). The repository pin stays; a path outside
/// .github/workflows, a `..`, a URL or another repository is refused before gh runs and nothing is installed.
#[test]
fn the_signer_workflow_defaults_to_release_yml_and_accepts_only_a_workflow_file_of_this_repository() {
    let (dir, pkg) = package_with_gh(0);
    mark_release(&pkg);
    // cosign is not there: a release package would need it, so this check runs on the soft path of a dev package
    std::fs::remove_file(pkg.join("RELEASE-PACKAGE")).unwrap();
    assert!(install_from_package(&dir, &pkg, &[]).status.success());
    let gh = std::fs::read_to_string(dir.path().join("bin/gh.args")).unwrap();
    assert!(gh.contains("--repo postfix/probation --signer-workflow postfix/probation/.github/workflows/release.yml"), "default: {gh}");

    let (dir, pkg) = package_with_gh(0);
    let out = install_from_package(&dir, &pkg, &["--signer-workflow", ".github/workflows/native-service.yml"]);
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let gh = std::fs::read_to_string(dir.path().join("bin/gh.args")).unwrap();
    assert!(gh.contains("--repo postfix/probation --signer-workflow postfix/probation/.github/workflows/native-service.yml"), "{gh}");

    for bad in [
        ".github/other/x.yml",
        "scripts/install-service.sh",
        ".github/workflows/../../evil.yml",
        ".github/workflows/..yml",
        "https://github.com/evil/repo/.github/workflows/release.yml",
        "evil/repo/.github/workflows/release.yml",
        "/.github/workflows/release.yml",
        ".github/workflows/release.yml extra",
        ".github/workflows/",
        "",
    ] {
        let (dir, pkg) = package_with_gh(0);
        let out = install_from_package(&dir, &pkg, &["--signer-workflow", bad]);
        assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("--signer-workflow"), "{bad:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(!dir.path().join("bin/gh.args").exists(), "{bad:?}: gh was not asked");
        assert!(!dir.path().join("root/etc/probation").exists(), "{bad:?}: nothing was installed");
    }
}

#[test]
fn launchd_health_means_running_for_five_polls_and_a_dying_job_is_not_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    // launchctl print: `state = running` for the first N calls, then `state = waiting` (a job that died and waits out the throttle).
    std::fs::write(bin.join("launchctl"), format!("#!/bin/sh\nn=$(cat {c} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {c}\n[ \"$n\" -le \"$HEALTHY_FOR\" ] && echo '\tstate = running' || echo '\tstate = waiting'\n", c = dir.path().join("count").display())).unwrap();
    std::fs::set_permissions(bin.join("launchctl"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let run = |healthy_for: u32| {
        let _ = std::fs::remove_file(dir.path().join("count"));
        let script = format!("source {SCRIPT} install --platform macos --root {}; STAGING=0; healthy", dir.path().join("root").display());
        Command::new("bash").args(["-c", &script]).env("INSTALL_SERVICE_SOURCE_ONLY", "1").env("HEALTH_SLEEP", "0").env("HEALTH_SETTLE", "0").env("HEALTHY_FOR", healthy_for.to_string()).env("PATH", format!("{}:/usr/bin:/bin", bin.display())).env("HOME", dir.path().join("home")).output().unwrap().status.success()
    };
    assert!(run(99), "running at every poll is healthy");
    assert!(!run(3), "running for three polls and then not is a failed start");
    assert!(!run(0));
}

#[test]
fn a_port_below_1024_gets_exactly_one_capability_and_only_for_a_system_service() {
    let root = Root::new();
    root.ok("install", &["--listen", "127.0.0.1:443"]);
    let dropin = root.read("/etc/systemd/system/probation.service.d/10-low-port.conf");
    assert!(dropin.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE") && dropin.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"), "{dropin}");
    assert!(root.read("/etc/systemd/system/probation.service").contains("CapabilityBoundingSet=\n"), "the unit itself keeps no capability");
    root.ok("uninstall", &[]);
    assert!(!root.path("/etc/systemd/system/probation.service.d").exists(), "the drop-in and its directory are removed");
    let plain = Root::new();
    plain.ok("install", &[]);
    assert!(!plain.path("/etc/systemd/system/probation.service.d").exists(), "no drop-in for a port of 1024 or more");
    let user = Root::new();
    assert!(user.refused("install", &["--scope", "user", "--listen", "127.0.0.1:80"]).contains("below 1024"));
    assert!(user.refused("install", &["--platform", "macos", "--listen", "127.0.0.1:80"]).contains("below 1024"));
}

#[test]
fn a_system_install_refuses_a_bin_directory_under_home() {
    let root = Root::new();
    let out = root.refused("install", &["--bin-dir", "/home/me/bin"]);
    assert!(out.contains("ProtectHome") && out.contains("--bin-dir"), "{out}");
}

// ---- recheck 2
#[test]
fn a_package_without_the_release_marker_needs_an_explicit_dev_package_flag() {
    let (dir, pkg) = package_with_tools(0, None);
    let plain = |extra: &[&str]| {
        Command::new("bash").arg(pkg.join("install-service.sh")).args(["install", "--root", dir.path().join("root").to_str().unwrap()]).args(extra).env("HOME", dir.path().join("home")).output().unwrap()
    };
    let out = plain(&[]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("--dev-package"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!dir.path().join("root/etc/probation").exists(), "nothing was written");
    let out = plain(&["--dev-package", "--no-verify"]);
    assert!(out.status.success() && String::from_utf8_lossy(&out.stderr).contains("DISABLED"), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn the_shipped_binary_is_verified_however_its_path_is_spelled() {
    let (dir, pkg) = package_with_tools(1, None); // gh fails: any spelling that reaches the check is refused
    mark_release(&pkg);
    let bin = dir.path().join("bin").display().to_string();
    let abs = pkg.join("probation").display().to_string();
    let spellings = [
        abs.clone(),
        format!("{}//probation", pkg.display()),
        "./probation".to_owned(),
    ];
    for spelling in spellings {
        let out = Command::new("bash")
            .current_dir(&pkg)
            .arg(pkg.join("install-service.sh"))
            .args(["install", "--root", dir.path().join("root").to_str().unwrap(), "--binary", &spelling])
            .env("PATH", format!("{bin}:{}", std::env::var("PATH").unwrap()))
            .env("HOME", dir.path().join("home"))
            .output()
            .unwrap();
        assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("attestation"), "{spelling}: {}", String::from_utf8_lossy(&out.stderr));
    }
    // A symlink to it is the same file.
    let link = dir.path().join("link-to-probation");
    std::os::unix::fs::symlink(&abs, &link).unwrap();
    let out = Command::new("bash").arg(pkg.join("install-service.sh")).args(["install", "--root", dir.path().join("root").to_str().unwrap(), "--binary", link.to_str().unwrap()])
        .env("PATH", format!("{bin}:{}", std::env::var("PATH").unwrap())).env("HOME", dir.path().join("home")).output().unwrap();
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("attestation"));
}

#[test]
fn the_low_port_drop_in_follows_the_configured_port_on_upgrade() {
    let root = Root::new();
    root.ok("install", &[]);
    assert!(!root.path("/etc/systemd/system/probation.service.d").exists());
    // The operator edits the kept config to a low port: the upgrade grants the one capability.
    let config = root.read("/etc/probation/config.toml").replace("listen = \"127.0.0.1:8080\"", "listen = \"127.0.0.1:443\"");
    root.put("/etc/probation/config.toml", &config);
    root.ok("upgrade", &[]);
    assert!(root.read("/etc/systemd/system/probation.service.d/10-low-port.conf").contains("CAP_NET_BIND_SERVICE"));
    // And back: the drop-in the installer made is removed again.
    root.put("/etc/probation/config.toml", &config.replace("127.0.0.1:443", "127.0.0.1:8443"));
    root.ok("upgrade", &[]);
    assert!(!root.path("/etc/systemd/system/probation.service.d/10-low-port.conf").exists());
}

#[test]
fn the_bundle_naming_is_one_scheme_everywhere() {
    for (file, text) in [("scripts/install-service.sh", "probation-<version>-<target>.sigstore.json"), ("docs/operations.md", "probation-<version>-<target>.sigstore.json")] {
        let content = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(file)).unwrap();
        assert!(content.contains(text), "{file} names the bundle as {text}");
    }
    let release = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml")).unwrap();
    assert!(release.contains("--bundle \"$name.sigstore.json\"") && release.contains("probation-*.sigstore.json"), "the release signs <package>.sigstore.json, the package name being probation-<version>-<target>");
}

/// The group named in a `chown` must exist when `chown` runs: the account (and its group) is created before the first
/// ownership change. Real install path (`--root /`, `--no-staging`) with `id`, `chown`, `dscl` and `useradd` stubbed to a log;
/// the run is expected to stop later (it cannot write the service definition), only the order of the calls is read.
#[test]
fn the_service_account_and_its_group_exist_before_anything_is_chowned_to_them() {
    if unsafe { libc_geteuid() } == 0 {
        return; // never run a no-staging install as the real root
    }
    // macos only: the linux path refuses data directories under /home (ProtectHome), where the scratch roots live; the ordering is shared code.
    let platform = "macos";
    {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let log = dir.path().join("calls.log");
        let stub = |name: &str, body: &str| {
            std::fs::write(bin.join(name), format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        stub("id", "case \"$1 $2\" in '-u ') echo 0 ;; '-u '*) exit 1 ;; *) exec /usr/bin/id \"$@\" ;; esac");
        stub("chown", &format!("echo \"chown $*\" >> {}", log.display()));
        stub("dscl", &format!("echo \"dscl $*\" >> {}", log.display()));
        stub("useradd", &format!("echo \"useradd $*\" >> {}", log.display()));
        let (cfg, data, logs, bindir) = (dir.path().join("etc"), dir.path().join("var"), dir.path().join("log"), dir.path().join("usrbin"));
        Command::new("bash")
            .arg(SCRIPT)
            .args(["install", "--root", "/", "--no-staging", "--no-start", "--dev-package", "--platform", platform, "--binary", BINARY, "--name", "probation-t"])
            .args(["--config-dir", cfg.to_str().unwrap(), "--data-dir", data.to_str().unwrap(), "--log-dir", logs.to_str().unwrap(), "--bin-dir", bindir.to_str().unwrap()])
            .env("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()))
            .env("HOME", dir.path().join("home"))
            .output()
            .unwrap();
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let lines: Vec<&str> = calls.lines().collect();
        let first_chown = lines.iter().position(|l| l.starts_with("chown ")).unwrap_or_else(|| panic!("{platform}: no chown ran: {calls}"));
        let account = lines.iter().position(|l| l.starts_with("useradd ") || l.contains("-create /Groups/")).unwrap_or_else(|| panic!("{platform}: no account created: {calls}"));
        assert!(account < first_chown, "{platform}: chown ran before the group existed:\n{calls}");
    }
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// The Windows installer runs as an elevated user whose files are owned by that user (hosted upgrade: config.toml owned by the
/// runner's -500 account, refused by Assert-Trusted). Every file it registers in `$Created` must get the Administrators owner.
#[test]
fn the_windows_installer_sets_the_owner_of_every_file_it_creates() {
    let script = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install-service.ps1")).unwrap();
    let created: std::collections::BTreeSet<&str> = script
        .lines()
        .filter_map(|l| l.split("$Created.Add($").nth(1))
        .filter_map(|r| r.split(')').next())
        .filter(|name| *name != "Path") // New-ProtectedDirectory's directory, owned by its own icacls call
        .collect();
    assert!(created.len() >= 3, "expected the config, blocklist and binary files, found {created:?}");
    for name in created {
        assert!(script.contains(&format!("Set-FileOwner ${name}")), "the installer creates ${name} without setting its owner (Set-FileOwner ${name})");
    }
    assert!(script.contains("function Set-FileOwner") && script.contains("/setowner"), "Set-FileOwner must run icacls /setowner");
}

/// Hosted upgrade round 5: `Copy-Item $f "$f.prev"` left a file owned by the elevated runner, which Test-DaclPrivate then refused.
/// Every destination of a Copy-Item, Move-Item or Write-Text must get the Administrators owner, whether or not it is in `$Created`.
/// Exempt: Save-Preserving, which rewrites the user's own package-manager settings, and `*.new` staging copies that a later
/// Move-Item renames over their target (the target is checked).
#[test]
fn the_windows_installer_sets_the_owner_of_every_file_it_writes() {
    let script = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install-service.ps1")).unwrap();
    let mut in_user_settings = false;
    let mut destinations = Vec::new();
    for line in script.lines() {
        if line.starts_with("function ") {
            in_user_settings = line.starts_with("function Save-Preserving");
        }
        if in_user_settings || line.starts_with("function ") {
            continue;
        }
        let dest = if let Some(rest) = line.split("-Destination ").nth(1) {
            rest.split_whitespace().next()
        } else if let Some(rest) = line.trim_start().strip_prefix("Write-Text ") {
            rest.split_whitespace().next()
        } else {
            None
        };
        if let Some(dest) = dest
            && !dest.trim_matches('"').ends_with(".new")
        {
            destinations.push(dest.to_string());
        }
    }
    assert!(destinations.len() >= 5, "expected the config, blocklist, target, .prev and restore destinations, found {destinations:?}");
    for dest in destinations {
        assert!(script.contains(&format!("Set-FileOwner {dest}")), "the installer writes {dest} without Set-FileOwner {dest}");
    }
}
