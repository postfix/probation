//! Slice 26: deploy/kubernetes/node/install-node.sh, verify-node.sh and install-firewall.sh, the node-side half of "no upstream
//! fallback".
//!
//! The installer writes one default hosts file naming the service as the registry `server`, one hosts file per mapped registry (its
//! `/registry/oci/<id>` route), the CA, a containerd drop-in AND the `imports` line that makes it load, and a systemd drop-in that
//! makes the service CA the only root of containerd. The verifier fails on anything that would let containerd reach a registry
//! origin (a [host] table, a per-registry override or legacy directory, another config_path, legacy mirrors, a CA that is added to the
//! system roots instead of pinned) and, online, on a service that does not answer, a name that does not resolve or an origin the node
//! can still reach (and on "cannot tell"). `containerd`, `ctr`, `curl`, `getent` and `nft` are fakes here: this file is about the
//! scripts' decisions. E2E-service-cluster runs the same scripts against the real containerd 2.2.0.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/kubernetes/node");
const ENDPOINT: &str = "https://probation.cluster.example:30443";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Node {
    root: tempfile::TempDir,
    bin: PathBuf,
    ca: PathBuf,
}

struct Layout {
    certs: PathBuf,
    conf: PathBuf,
    config: PathBuf,
    systemd: PathBuf,
    dump: PathBuf,
    proc: PathBuf,
}

impl Layout {
    /// The environment of a running daemon `pid` (`/proc/<pid>/environ`, NUL separated), as the lines given.
    fn set_daemon_env(&self, pid: u32, lines: &str) {
        let dir = self.proc.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("environ"), lines.split('\n').map(|l| format!("{l}\0")).collect::<String>()).unwrap();
    }
}

impl Node {
    fn new() -> Node {
        let root = tempfile::tempdir().expect("a directory");
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let write = |name: &str, body: &str| {
            let path = bin.join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        // containerd prints $FAKE_DUMP (the effective configuration the test decides on), or fails.
        // `--version` prints $FAKE_CONTAINERD_VERSION; `config dump` of the verifier's copy without the import line (`*.probation-verify.*`) prints the
        // `.base` file when the test wrote one. A main file that carries `discard_unpacked_layers` (a later edit) shows it in BOTH dumps.
        write("containerd", "#!/bin/sh\n[ \"$1\" = --version ] && { echo \"containerd github.com/containerd/containerd/v2 ${FAKE_CONTAINERD_VERSION:-v2.2.0} abc\"; exit 0; }\n[ -n \"$FAKE_DUMP_FAIL\" ] && { echo 'toml: line 3: bad' >&2; exit 1; }\n[ -n \"$FAKE_WARN\" ] && echo \"time=\\\"$(date +%s%N)\\\" level=warning msg=\\\"Configuration migrated from version 2\\\" t=\\\"$(date +%N)ns\\\"\" >&2\ncase \"$2\" in *.probation-verify.*) b=\"${FAKE_DUMP%.toml}.base\"; if [ -r \"$b\" ]; then cat \"$b\"; else cat \"$FAKE_DUMP\"; fi ;; *) cat \"$FAKE_DUMP\" ;; esac\ngrep -q discard_unpacked_layers \"$2\" && echo 'discard_unpacked_layers = true'\nexit 0\n");
        // systemctl: `show UNIT -p PROP --value` answers from $FAKE_SD_* (the effective environment systemd would compute).
        write("systemctl", "#!/bin/sh\necho \"systemctl $*\" >> \"$FAKE_SD_LOG\"\ncase \"$1\" in daemon-reload|enable|restart) exit 0 ;; is-active) [ -z \"$FAKE_UNIT_INACTIVE\" ]; exit $? ;; esac\n[ \"$1\" = show ] || exit 1\ncase \"$4\" in LoadState) echo \"${FAKE_SD_LOAD:-loaded}\" ;; Environment) echo \"$FAKE_SD_ENV\" ;; DropInPaths) echo \"$FAKE_SD_DROPINS\" ;; MainPID) echo \"${FAKE_SD_PID:-0}\" ;; esac\n");
        // The service answers $FAKE_CODE with the CA (--cacert); a call without it is a direct call to an origin that ends with $FAKE_ORIGIN_EXIT.
        write("curl", "#!/bin/sh\ncase \"$*\" in *--cacert*) printf '%s' \"${FAKE_CODE:-000}\"; exit 0 ;; esac\nexit \"${FAKE_ORIGIN_EXIT:-7}\"\n");
        // getent fails for the names in $FAKE_NO_DNS (space separated, `all` for every name).
        write("getent", "#!/bin/sh\ncase \" $FAKE_NO_DNS \" in *\" all \"*|*\" $2 \"*) exit 2 ;; esac\necho \"192.0.2.20 $2\"\n");
        // ctr: `images import` succeeds; `images ls name==REF` lists REF with $FAKE_CTR_DIGEST; `images rm` records.
        write("ctr", "#!/bin/sh\ncase \"$*\" in *\"images import\"*) exit 0 ;; *\"images rm\"*) echo removed >> \"$FAKE_CTR_LOG\"; exit 0 ;; *\"images ls\"*) [ -n \"$FAKE_CTR_DIGEST\" ] && printf 'REF TYPE DIGEST SIZE PLATFORMS LABELS\\nref application/x %s 1.0MiB linux/amd64 -\\n' \"$FAKE_CTR_DIGEST\"; exit 0 ;; esac\nexit 1\n");
        write("nft", "#!/bin/sh\necho \"nft $*\" >> \"$FAKE_NFT_LOG\"\ncase \"$*\" in *\"list table\"*) case \" $FAKE_NFT_MISSING \" in *\" $4 \"*|*\" all \"*) exit 1 ;; esac ;; esac\nexit 0\n");
        let ca = root.path().join("ca.pem");
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n").unwrap();
        Node { root, bin, ca }
    }

    fn layout(&self, n: usize) -> Layout {
        let base = self.root.path().join(format!("n{n}"));
        let certs = base.join("etc/containerd/certs.d");
        let dump = base.join("dump.toml");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(&dump, good_dump(&certs)).unwrap();
        Layout { certs, conf: base.join("etc/containerd"), config: base.join("etc/containerd/config.toml"), systemd: base.join("etc/systemd/system"), dump, proc: base.join("proc") }
    }

    fn run(&self, script: &str, args: &[String], env: &[(&str, &str)]) -> Output {
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap_or_default());
        Command::new("sh")
            .arg(Path::new(DIR).join(script))
            .args(args)
            .env("PATH", path)
            .env("FAKE_CTR_LOG", self.root.path().join("ctr.log"))
            .env("FAKE_NFT_LOG", self.root.path().join("nft.log"))
            .env("FAKE_SD_LOG", self.root.path().join("systemctl.log"))
            .envs(env.iter().copied())
            .output()
            .expect("sh runs")
    }

    fn install_args(&self, l: &Layout) -> Vec<String> {
        [
            ("--endpoint", ENDPOINT.to_owned()),
            ("--ca", self.ca.display().to_string()),
            ("--certs-dir", l.certs.display().to_string()),
            ("--config-dir", l.conf.display().to_string()),
            ("--systemd-dir", l.systemd.display().to_string()),
        ]
        .into_iter()
        .flat_map(|(f, v)| [f.to_owned(), v])
        .collect()
    }

    fn install(&self, l: &Layout) -> Output {
        self.run("install-node.sh", &self.install_args(l), &[])
    }

    fn install_with(&self, l: &Layout, extra: &[&str]) -> Output {
        let mut args = self.install_args(l);
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        self.run("install-node.sh", &args, &[])
    }

    fn verify(&self, l: &Layout, extra: &[&str], env: &[(&str, &str)]) -> Output {
        self.verify_endpoint(l, ENDPOINT, extra, env)
    }

    fn verify_endpoint(&self, l: &Layout, endpoint: &str, extra: &[&str], env: &[(&str, &str)]) -> Output {
        let mut args: Vec<String> = ["--endpoint", endpoint, "--certs-dir"].iter().map(|s| (*s).to_owned()).collect();
        args.extend([l.certs.display().to_string(), "--containerd-config".into(), l.config.display().to_string(), "--systemd-dir".into(), l.systemd.display().to_string()]);
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let dump = l.dump.display().to_string();
        // The node as installed and restarted: systemd's environment and the daemon's (pid 4242) hold the pin; a test overrides these.
        let good = format!("SSL_CERT_FILE={0}/_default/probation-ca.pem SSL_CERT_DIR={0}/_default/roots-empty", l.certs.display());
        l.set_daemon_env(4242, &good.replace(' ', "\n"));
        args.extend(["--proc-dir".into(), l.proc.display().to_string()]);
        let mut all = vec![("FAKE_DUMP", dump.as_str()), ("FAKE_SD_ENV", good.as_str()), ("FAKE_SD_PID", "4242")];
        all.extend(env.iter().copied());
        self.run("verify-node.sh", &args, &all)
    }
}

fn good_dump(certs: &Path) -> String {
    format!("[plugins.'io.containerd.cri.v1.images'.registry]\n  config_path = '{}'\n\n", certs.display())
}

fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn append(path: &Path, extra: &str) {
    let old = std::fs::read_to_string(path).unwrap();
    std::fs::write(path, format!("{old}{extra}")).unwrap();
}

fn rewrite(path: &Path, from: &str, to: &str) {
    let old = std::fs::read_to_string(path).unwrap();
    assert!(old.contains(from), "{path:?} has no {from:?}");
    std::fs::write(path, old.replace(from, to)).unwrap();
}

/// A verifier run that must exit 1 with a `FAIL:` line containing `what`.
fn assert_fails(out: &Output, what: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.code() == Some(1) && stdout.lines().any(|line| line.starts_with("FAIL: ") && line.contains(what)),
        "expected a FAIL line with {what:?}, got {:?}:\n{}",
        out.status.code(),
        text(out)
    );
}

#[test]
fn the_installer_writes_every_file_the_runtime_needs_and_the_verifier_accepts_exactly_that() {
    let node = Node::new();
    let l = node.layout(1);
    let out = node.install_with(&l, &["--registry", "ghcr.io=2", "--registry", "quay.io=3"]);
    assert!(out.status.success(), "{}", text(&out));
    let hosts = l.certs.join("_default/hosts.toml");
    assert_eq!(
        std::fs::read_to_string(&hosts).unwrap(),
        format!("# managed by probation install-node.sh\nserver = \"{ENDPOINT}\"\ncapabilities = [\"pull\", \"resolve\"]\nca = \"{}/_default/probation-ca.pem\"\n", l.certs.display()),
        "server, pull and resolve, the CA and nothing else"
    );
    let ghcr = std::fs::read_to_string(l.certs.join("ghcr.io/hosts.toml")).unwrap();
    assert!(ghcr.contains(&format!("server = \"{ENDPOINT}/registry/oci/2\"")), "a mapped registry has its own route: {ghcr}");
    assert!(std::fs::read_to_string(l.certs.join("quay.io/hosts.toml")).unwrap().contains("/registry/oci/3\""));
    assert_eq!(std::fs::read(l.certs.join("_default/probation-ca.pem")).unwrap(), std::fs::read(&node.ca).unwrap(), "the CA is copied");
    assert!(std::fs::read_to_string(l.conf.join("conf.d/probation.toml")).unwrap().contains(&format!("config_path = '{}'", l.certs.display())), "the drop-in names one directory");
    let config = std::fs::read_to_string(&l.config).unwrap();
    assert!(config.contains(&format!("imports = [\"{}/conf.d/*.toml\"]", l.conf.display())), "the drop-in is imported: {config}");
    let unit = std::fs::read_to_string(l.systemd.join("containerd.service.d/probation-ca.conf")).unwrap();
    assert!(unit.contains(&format!("Environment=\"SSL_CERT_FILE={}/_default/probation-ca.pem\"", l.certs.display())), "the service CA file: {unit}");
    assert!(unit.contains(&format!("Environment=\"SSL_CERT_DIR={}/_default/roots-empty\"", l.certs.display())), "and the certificate DIRECTORY is the empty one (Go reads /etc/ssl/certs otherwise): {unit}");
    assert!(l.certs.join("_default/roots-empty").is_dir() && std::fs::read_dir(l.certs.join("_default/roots-empty")).unwrap().next().is_none(), "the empty directory exists and is empty");
    assert_eq!(std::fs::metadata(&hosts).unwrap().permissions().mode() & 0o777, 0o644, "readable, not writable by others");
    let verified = node.verify(&l, &[], &[]);
    assert!(verified.status.success() && String::from_utf8_lossy(&verified.stdout).lines().any(|l| l == "verify-node: ok"), "{}", text(&verified));
    // A second install (same arguments) is the same files.
    let before = (std::fs::read_to_string(&hosts).unwrap(), config.clone());
    assert!(node.install_with(&l, &["--registry", "ghcr.io=2", "--registry", "quay.io=3"]).status.success());
    assert_eq!((std::fs::read_to_string(&hosts).unwrap(), std::fs::read_to_string(&l.config).unwrap()), before);
}

#[test]
fn the_imports_line_is_added_once_to_an_existing_config_with_a_backup_and_rolled_back() {
    let node = Node::new();
    let l = node.layout(2);
    std::fs::create_dir_all(&l.conf).unwrap();
    std::fs::write(&l.config, "version = 3\nroot = '/var/lib/containerd'\n\n[grpc]\n  address = '/run/containerd/containerd.sock'\n").unwrap();
    assert!(node.install(&l).status.success());
    let after = std::fs::read_to_string(&l.config).unwrap();
    assert_eq!(after.matches("imports =").count(), 1, "{after}");
    assert!(after.starts_with("version = 3\nimports = ["), "the import follows the version line (top level, before any table): {after}");
    assert!(after.contains("root = '/var/lib/containerd'") && after.contains("[grpc]"), "the rest is untouched");
    assert!(node.install(&l).status.success());
    assert_eq!(std::fs::read_to_string(&l.config).unwrap().matches("imports =").count(), 1, "idempotent");
    // Rollback removes what was written and restores the original config.
    let rolled = node.run("install-node.sh", &[node.install_args(&l), vec!["--rollback".into()]].concat(), &[]);
    assert!(rolled.status.success(), "{}", text(&rolled));
    assert!(!l.certs.join("_default/hosts.toml").exists() && !l.conf.join("conf.d/probation.toml").exists() && !l.systemd.join("containerd.service.d/probation-ca.conf").exists());
    assert_eq!(std::fs::read_to_string(&l.config).unwrap(), "version = 3\nroot = '/var/lib/containerd'\n\n[grpc]\n  address = '/run/containerd/containerd.sock'\n", "the config is as it was");
    // A config that already has its own imports line is never edited.
    std::fs::write(&l.config, "version = 3\nimports = [\"/etc/other/*.toml\"]\n").unwrap();
    let refused = node.install(&l);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("imports line that does not name"), "{}", text(&refused));
    assert_eq!(std::fs::read_to_string(&l.config).unwrap(), "version = 3\nimports = [\"/etc/other/*.toml\"]\n");
    assert!(!l.certs.join("_default/hosts.toml").exists() && !l.conf.join("conf.d/probation.toml").exists() && !l.systemd.join("containerd.service.d/probation-ca.conf").exists(), "refused before anything was written: no half install");
}

#[test]
fn the_installer_refuses_what_could_be_a_way_around_the_endpoint() {
    let node = Node::new();
    let missing = node.root.path().join("absent.pem").display().to_string();
    let not_pem = node.bin.join("getent").display().to_string();
    let cases: Vec<(&str, Vec<&str>, &str)> = vec![
        ("a path", vec!["--endpoint", "https://probation.cluster.example:30443/v2"], "must be an https origin"),
        ("http", vec!["--endpoint", "http://probation.cluster.example:30443"], "must be an https origin"),
        ("a user name", vec!["--endpoint", "https://u:p@probation.cluster.example"], "must be an https origin"),
        ("a quote", vec!["--endpoint", "https://probation\"x.example"], "quotes, backslashes and spaces"),
        ("a newline", vec!["--endpoint", "https://ok.example\nskip_verify = true"], "control character or a newline"),
        ("a carriage return", vec!["--endpoint", "https://ok.example\r"], "control character or a newline"),
        ("a relative certs dir", vec!["--certs-dir", "etc/certs.d"], "absolute"),
        ("a missing CA", vec!["--ca", missing.as_str()], "cannot read the CA"),
        ("a non-certificate CA", vec!["--ca", not_pem.as_str()], "no PEM certificate"),
        ("an unknown flag", vec!["--force", "1"], "unknown argument"),
        ("a bad registry pair", vec!["--registry", "ghcr.io"], "host=id"),
        ("a registry id that is no number", vec!["--registry", "ghcr.io=x"], "host=id"),
        ("a registry mapped twice", vec!["--registry", "ghcr.io=2", "--registry", "ghcr.io=3"], "mapped twice"),
        ("a preload without a digest", vec!["--preload-image", "/dev/null", "--image-ref", "repo/app:latest"], "digest-pinned"),
    ];
    for (n, (what, extra, reason)) in cases.iter().enumerate() {
        let l = node.layout(10 + n);
        // an override replaces the flag's value; a flag not already present is appended
        let mut args = node.install_args(&l);
        let mut i = 0;
        while i < extra.len() {
            match args.iter().position(|a| a == extra[i]) {
                Some(at) if !matches!(extra[i], "--registry") => args[at + 1] = extra[i + 1].to_owned(),
                _ => args.extend([extra[i].to_owned(), extra[i + 1].to_owned()]),
            }
            i += 2;
        }
        let out = node.run("install-node.sh", &args, &[]);
        assert_eq!(out.status.code(), Some(2), "{what} is refused: {}", text(&out));
        assert!(String::from_utf8_lossy(&out.stderr).contains(reason), "{what}: the reason is named: {}", text(&out));
        assert!(!l.certs.join("_default/hosts.toml").exists(), "{what}: nothing was written");
    }
    // A bracketed IPv6 endpoint is valid.
    let l = node.layout(40);
    let mut args = node.install_args(&l);
    args[1] = "https://[2001:db8::1]:30443".into();
    assert!(node.run("install-node.sh", &args, &[]).status.success(), "an IPv6 endpoint is accepted");
    // A hosts file somebody else wrote is never replaced.
    let l = node.layout(41);
    std::fs::create_dir_all(l.certs.join("_default")).unwrap();
    let foreign = l.certs.join("_default/hosts.toml");
    std::fs::write(&foreign, "server = \"https://registry-1.docker.io\"\n").unwrap();
    let out = node.install(&l);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("was not written by this script"));
    assert_eq!(std::fs::read_to_string(&foreign).unwrap(), "server = \"https://registry-1.docker.io\"\n", "the foreign file is untouched");
    // Neither is a containerd drop-in or a systemd drop-in that is not ours.
    for (n, foreign_file) in ["etc/containerd/conf.d/probation.toml", "etc/systemd/system/containerd.service.d/probation-ca.conf"].iter().enumerate() {
        let l = node.layout(50 + n);
        let path = l.certs.parent().unwrap().parent().unwrap().parent().unwrap().join(foreign_file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# somebody else's\n").unwrap();
        let out = node.install(&l);
        assert_eq!(out.status.code(), Some(2), "{foreign_file}: {}", text(&out));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# somebody else's\n");
    }
}

#[test]
fn a_registry_directory_the_installer_does_not_map_or_that_holds_legacy_files_is_refused() {
    let node = Node::new();
    // An existing certs.d/docker.io (legacy layout) decides for docker.io: the installer must map it and must not find legacy files.
    let l = node.layout(60);
    std::fs::create_dir_all(l.certs.join("docker.io")).unwrap();
    std::fs::write(l.certs.join("docker.io/ca.crt"), "x").unwrap();
    let out = node.install(&l);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not mapped"), "{}", text(&out));
    let out = node.install_with(&l, &["--registry", "docker.io=1"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("legacy certificate file"), "{}", text(&out));
    assert!(!l.certs.join("docker.io/hosts.toml").exists(), "nothing was written next to the legacy files");
    std::fs::remove_file(l.certs.join("docker.io/ca.crt")).unwrap();
    assert!(node.install_with(&l, &["--registry", "docker.io=1"]).status.success(), "mapped and clean: written");
}

#[test]
fn the_verifier_fails_on_each_way_containerd_could_still_reach_an_origin() {
    type Mutate = fn(&Layout);
    type Case = (&'static str, Mutate, &'static str, &'static [(&'static str, &'static str)]);
    let cases: Vec<Case> = vec![
        ("no default hosts file", |l| std::fs::remove_file(l.certs.join("_default/hosts.toml")).unwrap(), "is missing: containerd would use each registry's own address", &[]),
        ("another server", |l| rewrite(&l.certs.join("_default/hosts.toml"), ENDPOINT, "https://registry-1.docker.io"), "does not name the server", &[]),
        ("push granted", |l| rewrite(&l.certs.join("_default/hosts.toml"), "\"pull\", \"resolve\"", "\"pull\", \"resolve\", \"push\""), "must grant exactly pull and resolve", &[]),
        ("a host table, a second place to pull from", |l| append(&l.certs.join("_default/hosts.toml"), "\n[host.\"https://registry-1.docker.io\"]\n  capabilities = [\"pull\"]\n"), "has a table", &[]),
        ("TLS verification skipped", |l| append(&l.certs.join("_default/hosts.toml"), "skip_verify = true\n"), "weakens TLS", &[]),
        ("a plain http reference", |l| append(&l.certs.join("_default/hosts.toml"), "# http://mirror\n"), "weakens TLS", &[]),
        ("the CA file removed", |l| std::fs::remove_file(l.certs.join("_default/probation-ca.pem")).unwrap(), "the CA file", &[]),
        ("a per-registry override to the origin", |l| {
            std::fs::create_dir(l.certs.join("docker.io")).unwrap();
            std::fs::write(l.certs.join("docker.io/hosts.toml"), "server = \"https://registry-1.docker.io\"\n").unwrap();
        }, "overrides the endpoint for docker.io", &[]),
        ("a per-registry override with a host table", |l| {
            std::fs::create_dir(l.certs.join("ghcr.io")).unwrap();
            std::fs::write(l.certs.join("ghcr.io/hosts.toml"), format!("server = \"{ENDPOINT}\"\ncapabilities = [\"pull\", \"resolve\"]\n[host.\"https://ghcr.io\"]\n")).unwrap();
        }, "with a table", &[]),
        ("a per-registry route that is no oci route", |l| {
            std::fs::create_dir(l.certs.join("ghcr.io")).unwrap();
            std::fs::write(l.certs.join("ghcr.io/hosts.toml"), format!("server = \"{ENDPOINT}/registry/npm/2\"\ncapabilities = [\"pull\", \"resolve\"]\n")).unwrap();
        }, "overrides the endpoint for ghcr.io", &[]),
        ("a legacy certificate directory with no hosts.toml", |l| {
            std::fs::create_dir(l.certs.join("registry.k8s.io")).unwrap();
            std::fs::write(l.certs.join("registry.k8s.io/ca.crt"), "x").unwrap();
        }, "legacy certificate file", &[]),
        ("a registry directory with no hosts.toml", |l| std::fs::create_dir(l.certs.join("quay.io")).unwrap(), "has no hosts.toml", &[]),
        ("containerd reads containerd's own default directories", |l| {
            let dump = std::fs::read_to_string(&l.dump).unwrap();
            std::fs::write(&l.dump, dump.replace(l.certs.to_str().unwrap(), "/etc/containerd/certs.d:/etc/docker/certs.d")).unwrap();
        }, "probably not imported", &[]),
        ("containerd has no config_path", |l| std::fs::write(&l.dump, "[plugins.'io.containerd.cri.v1.images'.registry]\n\n").unwrap(), "config_path is 'unset'", &[]),
        ("legacy registry mirrors", |l| append(&l.dump, "[plugins.'io.containerd.cri.v1.images'.registry.mirrors.'docker.io']\n  endpoint = ['https://registry-1.docker.io']\n"), "mirrors or configs", &[]),
        ("a configuration containerd cannot load", |_| {}, "containerd cannot load", &[("FAKE_DUMP_FAIL", "1")]),
        ("the service CA is only added to the system roots", |l| std::fs::remove_file(l.systemd.join("containerd.service.d/probation-ca.conf")).unwrap(), "would also trust every CA of the system roots", &[]),
        ("the certificate directory is not pinned (SSL_CERT_DIR missing)", |l| rewrite(&l.systemd.join("containerd.service.d/probation-ca.conf"), &format!("Environment=\"SSL_CERT_DIR={}/_default/roots-empty\"\n", l.certs.display()), ""), "does not set SSL_CERT_DIR to the empty directory", &[]),
        ("a root dropped into the pinned directory", |l| std::fs::write(l.certs.join("_default/roots-empty/extra.pem"), "x").unwrap(), "must be an existing EMPTY directory", &[]),
        ("the drop-in changes more than the registry path (a v2 main config turned v3)", |l| {
            std::fs::write(l.dump.with_extension("base"), "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]\n  SystemdCgroup = true\n").unwrap();
            append(&l.dump, "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]\n  SystemdCgroup = false\n");
        }, "changes more than the registry config_path", &[]),
        ("the systemd drop-in pins another file", |l| rewrite(&l.systemd.join("containerd.service.d/probation-ca.conf"), "probation-ca.pem", "other.pem"), "does not set SSL_CERT_FILE to the service CA", &[]),
    ];
    let node = Node::new();
    for (n, (what, mutate, expected, env)) in cases.iter().enumerate() {
        let l = node.layout(100 + n);
        assert!(node.install(&l).status.success());
        mutate(&l);
        assert_fails(&node.verify(&l, &[], env), expected);
        let _ = what;
    }
    // A per-registry directory that names the same endpoint or its oci route changes nothing; an allowed origin names its own server.
    let l = node.layout(200);
    assert!(node.install_with(&l, &["--registry", "ghcr.io=2"]).status.success());
    std::fs::create_dir(l.certs.join("quay.io")).unwrap();
    std::fs::write(l.certs.join("quay.io/hosts.toml"), format!("server = \"{ENDPOINT}\"\ncapabilities = [\"pull\", \"resolve\"]\n")).unwrap();
    assert!(node.verify(&l, &[], &[]).status.success(), "the endpoint and its oci routes are fine");
    std::fs::create_dir(l.certs.join("images.example")).unwrap();
    std::fs::write(l.certs.join("images.example/hosts.toml"), "server = \"https://images.example\"\ncapabilities = [\"pull\", \"resolve\"]\n").unwrap();
    assert_fails(&node.verify(&l, &[], &[]), "overrides the endpoint for images.example");
    assert!(node.verify(&l, &["--allow-origin", "images.example"], &[]).status.success(), "the one named origin is allowed");
}

#[test]
fn a_service_pool_node_must_hold_the_service_image_by_digest() {
    let node = Node::new();
    let l = node.layout(210);
    assert!(node.install(&l).status.success());
    let image = format!("registry.example/probation/probation@{DIGEST}");
    let pool = |env: &[(&str, &str)]| node.verify(&l, &["--service-pool", "--image-ref", &image], env);
    assert!(pool(&[("FAKE_CTR_DIGEST", DIGEST)]).status.success(), "present with the digest");
    assert_fails(&pool(&[]), "is not in the k8s.io content store");
    assert_fails(&pool(&[("FAKE_CTR_DIGEST", "sha256:ffff")]), "is not in the k8s.io content store");
    assert_eq!(node.verify(&l, &["--service-pool", "--image-ref", "registry.example/app:latest"], &[]).status.code(), Some(2), "a tag is no reference to preload");
}

#[test]
fn the_installer_preloads_the_service_image_verified_by_digest() {
    let node = Node::new();
    let archive = node.root.path().join("probation.tar");
    std::fs::write(&archive, "archive").unwrap();
    let image = format!("registry.example/probation/probation@{DIGEST}");
    let run = |l: &Layout, digest: &str| {
        let mut args = node.install_args(l);
        args.extend(["--preload-image".into(), archive.display().to_string(), "--image-ref".into(), image.clone()]);
        node.run("install-node.sh", &args, &[("FAKE_CTR_DIGEST", digest)])
    };
    let l = node.layout(220);
    let out = run(&l, DIGEST);
    assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("preloaded"), "{}", text(&out));
    // An archive whose manifest is another digest is removed again and refused.
    let l = node.layout(221);
    let out = run(&l, "sha256:ffff");
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not sha256:0123"), "{}", text(&out));
    assert!(std::fs::read_to_string(node.root.path().join("ctr.log")).unwrap().contains("removed"), "the mismatching image was removed");
}

#[test]
fn online_the_service_must_answer_the_name_resolve_and_no_origin_be_reachable() {
    let node = Node::new();
    let l = node.layout(90);
    assert!(node.install(&l).status.success());
    let ca = node.ca.display().to_string();
    let online = |env: &[(&str, &str)], extra: &[&str]| {
        let mut args = vec!["--online", "--ca", ca.as_str()];
        args.extend_from_slice(extra);
        node.verify(&l, &args, env)
    };
    assert!(online(&[("FAKE_CODE", "401")], &[]).status.success(), "401 is the service asking for a login (a registry ping)");
    assert!(online(&[("FAKE_CODE", "200")], &["--check-egress"]).status.success(), "200 and a refused connection to every origin passes");
    assert!(online(&[("FAKE_CODE", "200"), ("FAKE_ORIGIN_EXIT", "56")], &["--check-egress"]).status.success(), "a reset is blocked too");
    assert_fails(&online(&[("FAKE_CODE", "000")], &[]), "answered '000'");
    assert_fails(&online(&[("FAKE_CODE", "503")], &[]), "answered '503'");
    assert_fails(&online(&[("FAKE_CODE", "401"), ("FAKE_NO_DNS", "probation.cluster.example")], &[]), "does not resolve");
    assert_fails(&online(&[("FAKE_CODE", "401"), ("FAKE_ORIGIN_EXIT", "0")], &["--check-egress"]), "reaches https://registry-1.docker.io/v2/ directly");
    // 'Cannot tell' is a failure, never a pass: no DNS, a timeout, a proxy or TLS error that is not a refusal.
    assert_fails(&online(&[("FAKE_CODE", "401"), ("FAKE_NO_DNS", "registry-1.docker.io")], &["--check-egress"]), "'blocked' cannot be told from 'no network'");
    assert_fails(&online(&[("FAKE_CODE", "401"), ("FAKE_ORIGIN_EXIT", "28")], &["--check-egress"]), "ended inconclusively (curl exit 28)");
    assert_fails(&online(&[("FAKE_CODE", "401"), ("FAKE_ORIGIN_EXIT", "6")], &["--check-egress"]), "ended inconclusively (curl exit 6)");
    assert!(online(&[("FAKE_CODE", "401"), ("FAKE_ORIGIN_EXIT", "0")], &[]).status.success(), "without --check-egress no origin is asked");
    let no_ca = node.verify(&l, &["--online"], &[]);
    assert_eq!(no_ca.status.code(), Some(2), "--online without --ca is a usage error, not a pass");
    // A bracketed IPv6 endpoint: the name asked of DNS has no brackets and no port.
    let mut args = node.install_args(&l);
    args[1] = "https://[2001:db8::1]:30443".into();
    let l6 = node.layout(91);
    let mut args6 = node.install_args(&l6);
    args6[1] = args[1].clone();
    assert!(node.run("install-node.sh", &args6, &[]).status.success());
    let out = node.verify_endpoint(&l6, "https://[2001:db8::1]:30443", &["--online", "--ca", &ca], &[("FAKE_CODE", "401"), ("FAKE_NO_DNS", "[2001 [2001:db8::1] 2001")]);
    assert!(out.status.success(), "a name made of brackets or a port would not resolve: {}", text(&out));
}

#[test]
fn the_firewall_installer_renders_checks_and_rolls_back_the_rules() {
    let node = Node::new();
    let root = node.root.path().join("fw");
    let args = |extra: &[&str]| -> Vec<String> {
        ["--root", root.to_str().unwrap(), "--service4", "192.0.2.20", "--service-port", "30443", "--cluster4", "10.0.0.0/8,172.16.0.0/12", "--dns4", "10.96.0.10", "--approved4", "192.0.2.11,192.0.2.12"]
            .iter().chain(extra.iter()).map(|s| (*s).to_owned()).collect()
    };
    let out = node.run("install-firewall.sh", &args(&[]), &[]);
    assert!(out.status.success(), "{}", text(&out));
    let egress = std::fs::read_to_string(root.join("etc/probation/node-egress.nft")).unwrap();
    for want in ["define service4 = { 192.0.2.20 }", "define service_port = 30443", "define cluster4 = { 10.0.0.0/8, 172.16.0.0/12 }", "define dns4 = { 10.96.0.10 }"] {
        assert!(egress.contains(want), "{want} in {egress}");
    }
    let ingress = std::fs::read_to_string(root.join("etc/probation/node-ingress.nft")).unwrap();
    assert!(ingress.contains("define approved4 = { 192.0.2.11, 192.0.2.12 }") && ingress.contains("define nodeport = 30443"), "{ingress}");
    assert!(root.join("etc/systemd/system/probation-node-firewall.service").exists());
    let log = std::fs::read_to_string(node.root.path().join("nft.log")).unwrap();
    assert!(log.contains("nft -c -f") && !log.contains("nft -f "), "staged: checked, never loaded: {log}");
    // Bad input is refused before anything is written.
    for (what, extra) in [("an injected define", vec!["--extra4", "1.2.3.4 }; flush ruleset; {"]), ("a word", vec!["--dns4", "resolver"]), ("a port that is no number", vec!["--service-port", "x"])] {
        let fresh = node.root.path().join(format!("fw-{what}"));
        let mut a = args(&extra);
        a[1] = fresh.to_str().unwrap().to_owned();
        let out = node.run("install-firewall.sh", &a, &[]);
        assert_eq!(out.status.code(), Some(2), "{what}: {}", text(&out));
        assert!(!fresh.join("etc/probation/node-egress.nft").exists(), "{what}: nothing written");
    }
    let rolled = node.run("install-firewall.sh", &["--root".to_owned(), root.to_str().unwrap().to_owned(), "--rollback".to_owned()], &[]);
    assert!(rolled.status.success() && !root.join("etc/probation/node-egress.nft").exists() && !root.join("etc/systemd/system/probation-node-firewall.service").exists());
}

/// M-1 (recheck-3): the install must leave the unit ACTIVE, so that `PartOf=` and `ReloadPropagatedFrom=` reach it when nftables.service is restarted
/// later (they are no-ops on an inactive unit). The unit loads the two files; the installer never loads them behind systemd's back. What systemd
/// does with a restart of nftables.service is NOT run here (no systemd manager of its own, and the user's units are not touched).
#[test]
fn the_firewall_installer_starts_the_unit_and_checks_it_is_active_with_both_tables_loaded() {
    let node = Node::new();
    let root = node.root.path().join("fwload");
    let args = ["--root", root.to_str().unwrap(), "--load", "--service4", "192.0.2.20", "--cluster4", "10.0.0.0/8", "--dns4", "10.96.0.10", "--approved4", "192.0.2.11"].map(str::to_owned).to_vec();
    let out = node.run("install-firewall.sh", &args, &[]);
    assert!(out.status.success(), "{}", text(&out));
    let sd = std::fs::read_to_string(node.root.path().join("systemctl.log")).unwrap();
    let steps: Vec<&str> = sd.lines().collect();
    let at = |what: &str| steps.iter().position(|l| *l == what).unwrap_or_else(|| panic!("{what} in {sd}"));
    assert!(at("systemctl daemon-reload") < at("systemctl enable probation-node-firewall.service") && at("systemctl enable probation-node-firewall.service") < at("systemctl restart probation-node-firewall.service"), "{sd}");
    assert!(steps.contains(&"systemctl is-active --quiet probation-node-firewall.service"), "the active state is checked: {sd}");
    let nft = std::fs::read_to_string(node.root.path().join("nft.log")).unwrap();
    assert!(!nft.contains("nft -f "), "the tables are loaded by the unit, never by a direct nft -f: {nft}");
    assert!(nft.contains("nft list table inet probation_node_egress") && nft.contains("nft list table inet probation_node_ingress"), "both tables are checked: {nft}");
    // The unit is not active after the start, or a table is missing: the install fails and says so.
    let out = node.run("install-firewall.sh", &args, &[("FAKE_UNIT_INACTIVE", "1")]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("is not active"), "{}", text(&out));
    let out = node.run("install-firewall.sh", &args, &[("FAKE_NFT_MISSING", "probation_node_ingress")]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("probation_node_ingress is not loaded"), "{}", text(&out));
    // A staged root without --load touches neither systemd nor the rule set.
    let staged = node.root.path().join("fwstaged");
    std::fs::remove_file(node.root.path().join("systemctl.log")).unwrap();
    let args = ["--root", staged.to_str().unwrap(), "--service4", "192.0.2.20", "--cluster4", "10.0.0.0/8", "--dns4", "10.96.0.10", "--approved4", "192.0.2.11"].map(str::to_owned).to_vec();
    assert!(node.run("install-firewall.sh", &args, &[]).status.success());
    assert!(!node.root.path().join("systemctl.log").exists(), "a staged root does not call systemctl");
}

#[test]
fn the_firewall_check_of_the_verifier_needs_the_unit_active_as_well_as_the_tables() {
    let node = Node::new();
    let l = node.layout(340);
    assert!(node.install(&l).status.success());
    assert!(node.verify(&l, &["--firewall"], &[]).status.success());
    assert_fails(&node.verify(&l, &["--firewall"], &[("FAKE_UNIT_INACTIVE", "1")]), "probation-node-firewall.service is not active");
}

/// L-4: a COMMENTED `imports` line is not the import (a `grep` anywhere in the file took it for the installed line and wrote nothing).
#[test]
fn a_commented_out_imports_line_is_not_taken_for_the_import() {
    let node = Node::new();
    let l = node.layout(350);
    std::fs::create_dir_all(&l.conf).unwrap();
    std::fs::write(&l.config, format!("version = 3\n# imports = [\"{}/conf.d/*.toml\"]\n", l.conf.display())).unwrap();
    let out = node.install(&l);
    assert!(out.status.success(), "{}", text(&out));
    let after = std::fs::read_to_string(&l.config).unwrap();
    let live: Vec<&str> = after.lines().filter(|line| line.trim_start().starts_with("imports")).collect();
    assert_eq!(live.len(), 1, "one real imports line was inserted next to the comment: {after}");
    assert!(live[0].contains("conf.d/*.toml") && after.contains("managed by probation"), "{after}");
}

/// L-5: the installer no longer makes a backup; a stale `config.toml.probation-backup` of an older install is removed by --rollback and never copied back.
#[test]
fn rollback_deletes_a_stale_backup_of_an_older_install_and_never_restores_it() {
    let node = Node::new();
    let l = node.layout(351);
    std::fs::create_dir_all(&l.conf).unwrap();
    std::fs::write(&l.config, MAIN_V3).unwrap();
    assert!(node.install(&l).status.success());
    let backup = format!("{}.probation-backup", l.config.display());
    std::fs::write(&backup, "version = 3\n# the file as an older installer saw it\n").unwrap();
    append(&l.config, "[plugins.'io.containerd.cri.v1.runtime']\n  enable_cdi = true\n");
    assert!(node.run("install-node.sh", &[node.install_args(&l), vec!["--rollback".into()]].concat(), &[]).status.success());
    let after = std::fs::read_to_string(&l.config).unwrap();
    assert!(after.contains("enable_cdi = true") && !after.contains("older installer"), "the stale backup was not copied back: {after}");
    assert!(!Path::new(&backup).exists(), "the stale backup is deleted");
}

/// L-6: the verifier's baseline copy of the main file lives in a private temporary directory, never next to the config (a kill between creating and
/// removing it left a file in /etc/containerd, and a read-only /etc made the verifier fail).
#[test]
fn the_verifier_writes_nothing_next_to_the_containerd_config() {
    let node = Node::new();
    let l = node.layout(352);
    assert!(node.install(&l).status.success());
    std::fs::set_permissions(&l.conf, std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = node.verify(&l, &[], &[]);
    std::fs::set_permissions(&l.conf, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(out.status.success(), "a read-only configuration directory does not stop the verifier: {}", text(&out));
    let leftovers: Vec<_> = std::fs::read_dir(&l.conf).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("probation-verify")).collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

const MAIN_V2: &str = "version = 2\n\n[plugins.\"io.containerd.grpc.v1.cri\"]\n  sandbox_image = \"registry.k8s.io/pause:3.9\"\n  [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]\n    SystemdCgroup = true\n";
const MAIN_V3: &str = "version = 3\n\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]\n  SystemdCgroup = true\n";

#[test]
fn the_drop_in_speaks_the_schema_of_the_main_config_and_never_a_version_of_its_own() {
    let node = Node::new();
    for (n, (main, section)) in [(MAIN_V2, "[plugins.\"io.containerd.grpc.v1.cri\".registry]"), (MAIN_V3, "[plugins.'io.containerd.cri.v1.images'.registry]")].into_iter().enumerate() {
        let l = node.layout(300 + n);
        std::fs::create_dir_all(&l.conf).unwrap();
        std::fs::write(&l.config, main).unwrap();
        let out = node.install(&l);
        assert!(out.status.success(), "{}", text(&out));
        let dropin = std::fs::read_to_string(l.conf.join("conf.d/probation.toml")).unwrap();
        assert!(!dropin.lines().any(|line| line.trim_start().starts_with("version")), "no version line, which would override the main file's: {dropin}");
        assert!(dropin.contains(section) && dropin.contains(&format!("config_path = '{}'", l.certs.display())), "the section of the main file's schema: {dropin}");
        let after = std::fs::read_to_string(&l.config).unwrap();
        assert!(after.contains("SystemdCgroup = true") && after.matches("imports =").count() == 1, "the main file's own settings are untouched: {after}");
    }
    // A main file whose schema cannot be determined is refused, with nothing written.
    for (n, (what, main)) in [("no version", "[grpc]\n  address = '/run/containerd/containerd.sock'\n"), ("version 1", "version = 1\n"), ("a version only inside a table", "[grpc]\n  version = 3\n")].into_iter().enumerate() {
        let l = node.layout(310 + n);
        std::fs::create_dir_all(&l.conf).unwrap();
        std::fs::write(&l.config, main).unwrap();
        let out = node.install(&l);
        assert_eq!(out.status.code(), Some(2), "{what}: {}", text(&out));
        assert!(String::from_utf8_lossy(&out.stderr).contains("cannot determine the schema version"), "{what}: {}", text(&out));
        assert!(!l.conf.join("conf.d/probation.toml").exists() && std::fs::read_to_string(&l.config).unwrap() == main, "{what}: nothing was written");
    }
}

#[test]
fn rollback_removes_only_what_the_installer_inserted() {
    let node = Node::new();
    let l = node.layout(320);
    std::fs::create_dir_all(&l.conf).unwrap();
    std::fs::write(&l.config, MAIN_V3).unwrap();
    assert!(node.install(&l).status.success());
    // An operator edits the main file AFTER the install (a new runtime option); a stale backup must not undo it.
    append(&l.config, "[plugins.'io.containerd.cri.v1.runtime']\n  enable_cdi = true\n");
    let out = node.run("install-node.sh", &[node.install_args(&l), vec!["--rollback".into()]].concat(), &[]);
    assert!(out.status.success(), "{}", text(&out));
    let after = std::fs::read_to_string(&l.config).unwrap();
    assert!(after.contains("enable_cdi = true") && after.contains("SystemdCgroup = true"), "later edits and the original survive: {after}");
    assert!(!after.contains("imports =") && !after.contains("managed by probation"), "only the inserted line went: {after}");
    // A main file the installer created goes entirely.
    let l = node.layout(321);
    assert!(node.install(&l).status.success());
    assert!(l.config.exists());
    assert!(node.run("install-node.sh", &[node.install_args(&l), vec!["--rollback".into()]].concat(), &[]).status.success());
    assert!(!l.config.exists(), "a file this script created is removed");
}

#[test]
fn the_firewall_rules_unit_and_ingress_are_ordered_and_scoped() {
    let unit = std::fs::read_to_string(Path::new(DIR).join("probation-node-firewall.service")).unwrap();
    assert!(unit.lines().any(|l| l == "After=nftables.service"), "after the unit whose start flushes the rule set: {unit}");
    assert!(unit.lines().any(|l| l == "Before=kubelet.service containerd.service"), "and before the runtime pulls: {unit}");
    // A later restart or reload of nftables.service (its file starts with `flush ruleset`) must put the tables back, and a stop after a flush must not fail.
    assert!(unit.lines().any(|l| l == "PartOf=nftables.service") && unit.lines().any(|l| l == "ReloadPropagatedFrom=nftables.service"), "restart and reload of nftables reach this unit: {unit}");
    assert_eq!(unit.lines().filter(|l| l.starts_with("ExecReload=/usr/sbin/nft -f /etc/probation/node-")).count(), 2, "the reload path loads both files: {unit}");
    assert!(unit.lines().filter(|l| l.starts_with("ExecStop=")).all(|l| l.starts_with("ExecStop=-")), "a stop after a flush is not a failure: {unit}");
    let ingress = std::fs::read_to_string(Path::new(DIR).join("ingress.nft")).unwrap();
    assert_eq!(ingress.matches("fib daddr type local tcp dport $nodeport").count(), 3, "all three NodePort rules judge only traffic destined to this node: {ingress}");
    let node = Node::new();
    let l = node.layout(330);
    assert!(node.install(&l).status.success());
    assert!(node.verify(&l, &["--firewall"], &[]).status.success(), "both tables loaded");
    assert_fails(&node.verify(&l, &["--firewall"], &[("FAKE_NFT_MISSING", "probation_node_egress")]), "probation_node_egress is not loaded");
    assert_fails(&node.verify(&l, &["--firewall"], &[("FAKE_NFT_MISSING", "all")]), "is not loaded");
}

/// R3: a step that aborts must make the lane script fail (an EXIT trap that ends in `exit "$failed"` turned every abort into 0), and a lane
/// that ran no assertion at all must fail too.
#[test]
fn the_kind_lane_script_fails_when_a_step_aborts_or_nothing_was_asserted() {
    let node = Node::new();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/cluster/run-kind-lane.sh");
    let stub = |name: &str, body: &str| {
        let path = node.bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let run = |env: &[(&str, &str)]| {
        let path = format!("{}:{}", node.bin.display(), std::env::var("PATH").unwrap_or_default());
        Command::new("bash").arg(&script).env("PATH", path).env("LANE", "cri").env("WORK_DIR", node.root.path().join("lane")).env("KIND_NODE_IMAGE", "x").envs(env.iter().copied()).output().unwrap()
    };
    let state = node.root.path().join("restarted");
    let docker = |fallback: bool| format!(
        "case \"$*\" in\n *\"systemctl restart\"*) touch '{}'; exit 0 ;;\n *\"crictl pull\"*) if [ -e '{}' ] && [ {} = 0 ]; then echo 'dial tcp: lookup probation.kind.test' >&2; exit 1; fi; exit 0 ;;\n *\"crictl inspecti\"*) exit {} ;;\nesac\nexit 0",
        state.display(), state.display(), if fallback { 1 } else { 0 }, if fallback { 0 } else { 1 }
    );
    stub("docker", &docker(false));
    for name in ["kubectl", "crictl", "ctr"] { stub(name, "exit 0"); }
    stub("kind", "exit 0");
    let ok = run(&[]);
    assert!(ok.status.success(), "every step succeeds and assertions ran: {}", text(&ok));
    assert!(String::from_utf8_lossy(&ok.stdout).contains("assertions ran:"), "{}", text(&ok));
    stub("kind", "[ \"$1\" = create ] && exit 7\nexit 0");
    let aborted = run(&[]);
    assert_eq!(aborted.status.code(), Some(7), "an aborted step keeps its own status, not 0: {}", text(&aborted));
    stub("kind", "exit 0");
    std::fs::remove_file(&state).ok();
    // The runtime still pulls after the installer (a fallback to the registry): the assertion that it must fail fails the lane.
    stub("docker", &docker(true));
    let failing = run(&[]);
    assert!(!failing.status.success(), "a failed assertion fails the lane: {}", text(&failing));
}

/// M2: the verifier reads the environment containerd really has (systemd's effective one and the running daemon's), not only its own file.
#[test]
fn the_verifier_checks_the_effective_environment_of_the_running_containerd() {
    let node = Node::new();
    let l = node.layout(400);
    assert!(node.install(&l).status.success());
    assert!(node.verify(&l, &[], &[]).status.success(), "installed and restarted");
    let (file, dir) = (format!("SSL_CERT_FILE={}/_default/probation-ca.pem", l.certs.display()), format!("SSL_CERT_DIR={}/_default/roots-empty", l.certs.display()));
    let corp = "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt";
    let drops = "/etc/systemd/system/containerd.service.d/probation-ca.conf /etc/systemd/system/containerd.service.d/zz-corp.conf";
    // A later drop-in (zz-corp.conf, the usual corporate-CA one) wins by file-name order: the file on disk is intact and the pin is off.
    let overridden = format!("{file} {dir} {corp}");
    assert_fails(&node.verify(&l, &[], &[("FAKE_SD_ENV", &overridden), ("FAKE_SD_DROPINS", drops)]), "a later drop-in overrides it");
    let overridden_dir = format!("{file} {dir} SSL_CERT_DIR=/etc/ssl/certs");
    assert_fails(&node.verify(&l, &[], &[("FAKE_SD_ENV", &overridden_dir)]), "SSL_CERT_DIR='/etc/ssl/certs'");
    // The last assignment wins, so an override that comes BEFORE ours is harmless.
    let before = format!("{corp} {file} {dir}");
    assert!(node.verify(&l, &[], &[("FAKE_SD_ENV", &before)]).status.success(), "ours is last");
    // The daemon was not restarted since the install (or something else sets its environment): its own environ decides.
    l.set_daemon_env(4343, "PATH=/usr/bin");
    assert_fails(&node.verify(&l, &[], &[("FAKE_SD_PID", "4343")]), "was not restarted since the install");
    l.set_daemon_env(4344, &format!("{file}\nSSL_CERT_DIR=/etc/ssl/certs"));
    assert_fails(&node.verify(&l, &[], &[("FAKE_SD_PID", "4344")]), "SSL_CERT_DIR='/etc/ssl/certs'");
    assert_fails(&node.verify(&l, &[], &[("FAKE_SD_PID", "0")]), "is not running");
    assert_fails(&node.verify(&l, &[], &[("FAKE_SD_PID", "999999")]), "cannot read");
    assert_fails(&node.verify(&l, &[], &[("FAKE_SD_LOAD", "not-found")]), "pass --containerd-unit");
}

/// L2: a legitimate later edit of the main config (a runtime option, a kubeadm rewrite) is in the baseline too, so it is no failure.
#[test]
fn a_later_edit_of_the_main_config_does_not_fail_the_verifier_for_good() {
    let node = Node::new();
    let l = node.layout(401);
    std::fs::create_dir_all(&l.conf).unwrap();
    std::fs::write(&l.config, MAIN_V3).unwrap();
    assert!(node.install(&l).status.success());
    append(&l.config, "[plugins.'io.containerd.cri.v1.images']\n  discard_unpacked_layers = true\n");
    let out = node.verify(&l, &[], &[]);
    assert!(out.status.success(), "{}", text(&out));
}

/// containerd logs its own warnings (a timestamp and a duration that differ on every call) on stderr, which the verifier reads with the dump:
/// the comparison of the two dumps must ignore them (the first hosted cri-node run failed on exactly this).
#[test]
fn log_lines_of_containerd_in_the_dump_do_not_count_as_a_changed_configuration() {
    let node = Node::new();
    let l = node.layout(402);
    std::fs::create_dir_all(&l.conf).unwrap();
    std::fs::write(&l.config, MAIN_V3).unwrap();
    assert!(node.install(&l).status.success());
    let out = node.verify(&l, &[], &[("FAKE_WARN", "1")]);
    assert!(out.status.success(), "{}", text(&out));
}

/// L3: the empty directory is checked for who can write in it, and the installer fixes the mode and refuses what it holds.
#[test]
fn the_empty_roots_directory_is_root_owned_unwritable_by_others_and_empty() {
    let node = Node::new();
    let l = node.layout(402);
    assert!(node.install(&l).status.success());
    let roots = l.certs.join("_default/roots-empty");
    assert_eq!(std::fs::metadata(&roots).unwrap().permissions().mode() & 0o777, 0o755);
    std::fs::set_permissions(&roots, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert_fails(&node.verify(&l, &[], &[]), "group or world writable");
    std::fs::set_permissions(&roots, std::fs::Permissions::from_mode(0o757)).unwrap();
    assert_fails(&node.verify(&l, &[], &[]), "group or world writable");
    assert!(node.install(&l).status.success(), "a re-run sets the mode again");
    assert_eq!(std::fs::metadata(&roots).unwrap().permissions().mode() & 0o777, 0o755);
    std::fs::write(roots.join("x.pem"), "x").unwrap();
    let out = node.install(&l);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not empty"), "{}", text(&out));
}

/// L5: containerd 2.0 or later; an older one is named, never written for.
#[test]
fn containerd_before_2_0_is_unsupported_and_named() {
    let node = Node::new();
    let l = node.layout(403);
    let out = node.run("install-node.sh", &node.install_args(&l), &[("FAKE_CONTAINERD_VERSION", "v1.7.20")]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("containerd 1.x is not supported"), "{}", text(&out));
    assert!(!l.certs.join("_default/hosts.toml").exists(), "nothing written");
    assert!(node.install(&l).status.success());
    assert_fails(&node.verify(&l, &[], &[("FAKE_CONTAINERD_VERSION", "1.7.20")]), "unsupported: containerd 1.x");
}

/// L10: rollback removes the `_default` directory the installer created (only when nothing else is in it), never one that was there before.
#[test]
fn rollback_removes_a_default_directory_only_when_the_installer_made_it_and_it_is_empty() {
    let node = Node::new();
    let rollback = |l: &Layout| assert!(node.run("install-node.sh", &[node.install_args(l), vec!["--rollback".into()]].concat(), &[]).status.success());
    let l = node.layout(404);
    assert!(node.install(&l).status.success());
    rollback(&l);
    assert!(!l.certs.join("_default").exists(), "the installer made it and nothing else is in it");
    let l = node.layout(405);
    std::fs::create_dir_all(l.certs.join("_default")).unwrap();
    assert!(node.install(&l).status.success());
    rollback(&l);
    assert!(l.certs.join("_default").is_dir(), "it was there before the install");
    let l = node.layout(406);
    assert!(node.install(&l).status.success());
    std::fs::write(l.certs.join("_default/other.txt"), "x").unwrap();
    rollback(&l);
    assert!(l.certs.join("_default/other.txt").exists(), "somebody else's file is never removed");
}

/// M3/L7: the lane's assertion helpers (tests/e2e/cluster/lane-lib.sh) decide on what `probe` prints; each is driven with stub output, and a
/// wrong outcome makes it fail. The empty-run branch of `finish` is driven too.
#[test]
fn the_kind_lane_assertion_helpers_pass_the_right_outcome_and_fail_the_wrong_one() {
    let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/cluster/lane-lib.sh");
    let work = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(work.path().join("logs")).unwrap();
    let kind = work.path().join("kind");
    std::fs::write(&kind, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&kind, std::fs::Permissions::from_mode(0o755)).unwrap();
    // kubectl: logs its arguments and prints $KOUT, then exits $KRC (a denial by an admission policy is exit 1 WITH the message).
    let kubectl = work.path().join("kubectl");
    std::fs::write(&kubectl, "#!/bin/sh\necho \"kubectl $*\" >> \"$WORK_DIR/kubectl.log\"\n[ -t 0 ] || cat >/dev/null\nprintf '%s' \"${KOUT:-}\"\nexit \"${KRC:-0}\"\n").unwrap();
    std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", work.path().display(), std::env::var("PATH").unwrap_or_default());
    // `probe` prints $OUT and exits with $RC, like the lane's curl-based one.
    let helper = |call: &str, out: &str, rc: &str| -> bool {
        let script = format!("set -euo pipefail\n. '{}'\nprobe() {{ printf '%s' \"$OUT\"; return \"$RC\"; }}\n{call}", lib.display());
        Command::new("bash").arg("-c").arg(script).env("PATH", &path).env("WORK_DIR", work.path()).env("CLUSTER", "c").env("OUT", out).env("RC", rc).status().unwrap().success()
    };
    let refusal = r#"{"error":"NETWORK_NOT_ALLOWED","message":"this API key may not be used from 10.0.0.3"}"#;
    let body = r#"{"errors":[{"code":"UNAUTHORIZED"}]}"#;
    for (call, out, rc, want) in [
        ("refused_by_service runner 1", refusal, "0", true),
        ("refused_by_service runner 1", body, "0", false),
        ("refused_by_service runner 1", "", "28", false),
        ("admitted runner 1", body, "0", true),
        ("admitted runner 1", refusal, "0", false),
        ("admitted runner 1", "", "28", false),
        ("admitted runner 1", "", "0", false),
        ("dropped runner 1", "", "28", true),
        ("dropped runner 1", body, "0", false),
        ("dropped_or_refused runner 1", "", "28", true),
        ("dropped_or_refused runner 1", refusal, "0", true),
        ("dropped_or_refused runner 1", body, "0", false),
        ("source_is 10.0.0.3 runner 1", refusal, "0", true),
        ("source_is 10.0.0.9 runner 1", refusal, "0", false),
        ("source_is 10.0.0.3 runner 1", body, "0", false),
        ("source_is 10.0.0.3 runner 1", "", "28", false),
    ] {
        assert_eq!(helper(call, out, rc), want, "`{call}` with output {out:?} (status {rc}) must {}", if want { "pass" } else { "fail" });
    }
    // M-2: `denied` is a pipeline-free capture. kubectl exits 1 WITH the policy's name when the admission policy denies; `kubectl | grep -q` under
    // `pipefail` returned non-zero for exactly that case and made the assertion always red.
    let denied = |kout: &str, krc: &str| -> bool {
        let script = format!("set -euo pipefail\n. '{}'\ndenied", lib.display());
        Command::new("bash").arg("-c").arg(script).env("PATH", &path).env("WORK_DIR", work.path()).env("CLUSTER", "c").env("KOUT", kout).env("KRC", krc).status().unwrap().success()
    };
    let denial = "Error from server (Forbidden): ... ValidatingAdmissionPolicy 'probation-one-local-service' with binding 'probation-one-local-service' denied request";
    assert!(denied(denial, "1"), "a denial (kubectl exit 1 with the policy's name) is recognised under pipefail");
    assert!(!denied("", "0"), "an accepted change is not a denial");
    assert!(!denied("Error from server (Forbidden): some other policy", "1"), "another policy's denial is not this one");
    // M-3: while the ingress layer is lifted (the allow-all policy of phase A, the admission binding, Cluster mode) an EXIT trap restores everything
    // with `kubectl apply -k`, whatever ended the lane; a lane that never lifted anything touches nothing.
    let log = work.path().join("kubectl.log");
    let lifted = |body: &str, expect_status: i32| -> String {
        std::fs::write(&log, "").unwrap();
        let script = format!("set -euo pipefail\n. '{}'\ntrap finish EXIT\n{body}", lib.display());
        let status = Command::new("bash").arg("-c").arg(script).env("PATH", &path).env("WORK_DIR", work.path()).env("CLUSTER", "c").status().unwrap().code();
        assert_eq!(status, Some(expect_status), "{body}");
        std::fs::read_to_string(&log).unwrap()
    };
    let calls = lifted("expect ok true; lift_ingress_policy; exit 7", 7);
    assert!(calls.contains("apply -f -") && calls.contains("delete networkpolicy phase-a-allow-ingress --ignore-not-found") && calls.contains("apply -k"), "an abort while lifted restores: {calls}");
    let calls = lifted("expect ok true; lift_ingress_policy; restore_policies", 0);
    assert_eq!(calls.matches("apply -k").count(), 1, "restored once, and the trap does not restore again: {calls}");
    let calls = lifted("expect ok true", 0);
    assert!(calls.is_empty(), "nothing was lifted, nothing is touched: {calls}");
    // finish: a lane that ran nothing fails (status 3), a failed assertion fails (1), and a clean run passes; an abort keeps its status.
    let finish = |body: &str| -> Option<i32> {
        let script = format!("set -euo pipefail\n. '{}'\ntrap finish EXIT\n{body}", lib.display());
        Command::new("bash").arg("-c").arg(script).env("PATH", &path).env("WORK_DIR", work.path()).env("CLUSTER", "c").status().unwrap().code()
    };
    assert_eq!(finish("true"), Some(3), "no assertion ran");
    assert_eq!(finish("expect ok true"), Some(0));
    assert_eq!(finish("expect bad false"), Some(1));
    assert_eq!(finish("exit 7"), Some(7));
}
