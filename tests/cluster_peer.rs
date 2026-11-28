//! The cluster endpoint's approved-node trust (slice 26, D1), on the shipped configuration and over real TCP.
//!
//! * `shipped_configmap_is_what_the_binary_accepts`: the `config.toml` of deploy/kubernetes/configmap.yaml, with only its
//!   paths pointed at a temporary directory, passes `probation check-config`; and it is refused when its safety lines are
//!   removed (no TLS, no approved nodes, a loopback listener is not what the pod runs).
//! * `real_tcp_peers_in_a_network_namespace` (ignored by default: it needs unprivileged user and network namespaces): the real
//!   binary, started from that same configuration, listens on a node-like address inside a private network namespace with four
//!   addresses on it: the service node, an approved node, an unapproved host, and a forwarder. Real TCP connections are made
//!   from chosen source addresses, so the peer the service sees is the kernel's, not an injected `ConnectInfo`. This is what
//!   `externalTrafficPolicy: Local` has to deliver in a cluster (the caller's own source address reaches the service) and what
//!   `Cluster` takes away (a forwarder that connects from an approved address makes every caller look approved). Whether
//!   kube-proxy does it is a cluster fact this host cannot show; the service's side of the contract is shown here.
//!
//!   cargo test --test cluster_peer -- --include-ignored
#![cfg(unix)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BINARY: &str = env!("CARGO_BIN_EXE_probation");
const INNER: &str = "PROBATION_CLUSTER_NETNS_INNER";
const SERVICE_NODE: &str = "10.77.0.1";
const APPROVED_NODE: &str = "10.77.0.2";
const EXTERNAL_HOST: &str = "10.77.0.3";
const FORWARDER: &str = "10.77.0.9";

/// The service's configuration as the cluster ships it: deploy/kubernetes/config.toml, the file the ConfigMap is generated from.
fn shipped_config() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/kubernetes/config.toml"),
    )
    .expect("deploy/kubernetes/config.toml is readable")
}

/// `config` with every line named in `edits` replaced; each old line must exist (a drifted manifest fails here).
fn edit(config: &str, edits: &[(&str, String)]) -> String {
    let mut out = config.to_owned();
    for (old, new) in edits {
        assert!(
            out.contains(old),
            "the shipped configuration no longer contains {old:?}"
        );
        out = out.replacen(old, new, 1);
    }
    out
}

struct Files {
    dir: tempfile::TempDir,
    cert: PathBuf,
    key: PathBuf,
    service_key: PathBuf,
    data: PathBuf,
}

fn files() -> Files {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let tls = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let service_key = dir.path().join("service.key");
    std::fs::write(&service_key, format!("prb_{}\n", "a".repeat(32)))
        .expect("the service key is written");
    std::fs::set_permissions(&service_key, std::fs::Permissions::from_mode(0o600))
        .expect("the key is private");
    let data = dir.path().join("data");
    Files {
        cert: tls.join("cert.pem"),
        key: tls.join("key.pem"),
        service_key,
        data,
        dir,
    }
}

fn render(files: &Files, extra: &[(&str, String)]) -> String {
    let mut edits = vec![
        (
            "data_dir = \"/var/lib/probation\"",
            format!("data_dir = \"{}\"", files.data.display()),
        ),
        (
            "tls_cert_path = \"/etc/probation/tls/tls.crt\"",
            format!("tls_cert_path = \"{}\"", files.cert.display()),
        ),
        (
            "tls_key_path = \"/etc/probation/tls/tls.key\"",
            format!("tls_key_path = \"{}\"", files.key.display()),
        ),
        (
            "service_key_file = \"/run/probation/service.key\"",
            format!("service_key_file = \"{}\"", files.service_key.display()),
        ),
    ];
    edits.extend(extra.iter().map(|(old, new)| (*old, new.clone())));
    edit(&shipped_config(), &edits)
}

fn check_config(config: &str, dir: &Path) -> std::process::Output {
    let path = dir.join("config.toml");
    std::fs::write(&path, config).expect("the configuration is written");
    Command::new(BINARY)
        .args(["check-config", path.to_str().expect("a UTF-8 path")])
        .output()
        .expect("the binary runs")
}

#[test]
fn shipped_configmap_is_what_the_binary_accepts() {
    let files = files();
    let ok = check_config(&render(&files, &[]), files.dir.path());
    assert!(
        ok.status.success(),
        "the shipped configuration is accepted: {}{}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr)
    );

    // What the pod's configuration must keep: each removal is refused by the product's own parser, so the manifest checker's
    // idea of "safe" and the service's agree.
    let rendered = render(&files, &[]);
    let nodes = "allowed_peer_cidrs = [\"192.0.2.11/32\", \"192.0.2.12/32\", \"192.0.2.13/32\"]";
    let no_tls = rendered
        .replace(
            &format!("tls_cert_path = \"{}\"\n", files.cert.display()),
            "",
        )
        .replace(&format!("tls_key_path = \"{}\"\n", files.key.display()), "");
    for (what, config) in [
        ("no TLS on a non-loopback listener", no_tls),
        (
            "no approved node",
            rendered.replace(nodes, "allowed_peer_cidrs = []"),
        ),
        (
            "the whole internet approved",
            rendered.replace(nodes, "allowed_peer_cidrs = [\"0.0.0.0/0\"]"),
        ),
        (
            "a /7 approved",
            rendered.replace(nodes, "allowed_peer_cidrs = [\"10.0.0.0/7\"]"),
        ),
    ] {
        assert_ne!(config, rendered, "{what}: the edit changed nothing");
        let refused = check_config(&config, files.dir.path());
        assert!(
            !refused.status.success(),
            "{what} must be refused: {}",
            String::from_utf8_lossy(&refused.stdout)
        );
    }
}

/// Runs the inner test in a new user and network namespace (root-mapped, so it may configure the namespace's own interfaces).
#[test]
#[ignore = "needs unprivileged user and network namespaces (unshare) and the ip command"]
fn real_tcp_peers_in_a_network_namespace() {
    if std::env::var_os(INNER).is_none() {
        let exe = std::env::current_exe().expect("the test binary path");
        let out = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "--"])
            .arg(exe)
            .args([
                "--ignored",
                "--exact",
                "real_tcp_peers_in_a_network_namespace",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(INNER, "1")
            .output()
            .expect(
                "unshare runs (this test fails, it never skips, when namespaces are unavailable)",
            );
        assert!(
            out.status.success(),
            "the namespace run failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout)
                .contains("cluster_peer inner: six peer checks held"),
            "the inner run did not reach its last check"
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(inner());
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("ip runs");
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn inner() {
    use std::io::Read;
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "node0", "type", "dummy"]);
    for address in [SERVICE_NODE, APPROVED_NODE, EXTERNAL_HOST, FORWARDER] {
        ip(&["addr", "add", &format!("{address}/24"), "dev", "node0"]);
    }
    ip(&["link", "set", "node0", "up"]);

    let files = files();
    // The pod's listener is the wildcard address on the container port; the NodePort of a node is reached on that node's address.
    let config = render(
        &files,
        &[
            (
                "listen = \"0.0.0.0:8443\"",
                "listen = \"0.0.0.0:18443\"".to_owned(),
            ),
            (
                "public_url = \"https://probation.cluster.example:30443\"",
                format!("public_url = \"https://{SERVICE_NODE}:18443\""),
            ),
            (
                "allowed_peer_cidrs = [\"192.0.2.11/32\", \"192.0.2.12/32\", \"192.0.2.13/32\"]",
                format!("allowed_peer_cidrs = [\"{APPROVED_NODE}/32\"]"),
            ),
            (
                "server_url = \"https://policy.example.org\"",
                "server_url = \"https://policy.invalid\"".to_owned(),
            ),
        ],
    );
    let path = files.dir.path().join("config.toml");
    std::fs::write(&path, config).expect("the configuration is written");
    let child = Command::new(BINARY)
        .args(["serve", "--config", path.to_str().expect("a UTF-8 path")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    let mut service = Service(child);

    // The service is up when an approved node can complete a TLS exchange with it (not merely connect).
    let client_from = |source: &str| {
        reqwest::Client::builder()
            .local_address(source.parse::<IpAddr>().expect("an address"))
            .danger_accept_invalid_certs(true)
            .http1_only()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("a client")
    };
    let get = |source: &'static str, url: String, headers: Vec<(&'static str, &'static str)>| {
        let client = client_from(source);
        async move {
            let mut request = client.get(url);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            let response = request
                .send()
                .await
                .expect("the request reaches the service");
            let status = response.status().as_u16();
            (status, response.text().await.unwrap_or_default())
        }
    };
    let base = format!("https://{SERVICE_NODE}:18443");
    let mut ready = false;
    for _ in 0..200 {
        if client_from(APPROVED_NODE)
            .get(format!("{base}/health/live"))
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        if let Some(status) = service.0.try_wait().expect("the child can be polled") {
            let (mut stdout, mut stderr) = (String::new(), String::new());
            let _ = service
                .0
                .stdout
                .take()
                .expect("piped")
                .read_to_string(&mut stdout);
            let _ = service
                .0
                .stderr
                .take()
                .expect("piped")
                .read_to_string(&mut stderr);
            panic!("the service exited early: {status}\n{stdout}\n{stderr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        ready,
        "the service did not start listening on {SERVICE_NODE}:18443"
    );

    // 1. An approved node is admitted (the service then has no policy to apply: 503 POLICY_UNAVAILABLE, not a refusal).
    let (status, body) = get(APPROVED_NODE, format!("{base}/v2/"), vec![]).await;
    assert!(
        status != 403 && !body.contains("NETWORK_NOT_ALLOWED"),
        "an approved node is admitted: {status} {body}"
    );
    assert!(
        body.contains("POLICY_UNAVAILABLE"),
        "it got as far as the policy: {status} {body}"
    );

    // 2. An unapproved host that reaches the node's port with its own source address is refused before any protocol work.
    let (status, body) = get(EXTERNAL_HOST, format!("{base}/v2/"), vec![]).await;
    assert_eq!(
        (status, body.contains("NETWORK_NOT_ALLOWED")),
        (403, true),
        "an unapproved source is refused: {status} {body}"
    );
    for path in [
        "/registry/oci/1/v2/",
        "/npm/left-pad",
        "/pypi/simple/requests/",
        "/v2/library/alpine/manifests/latest",
    ] {
        let (status, _) = get(EXTERNAL_HOST, format!("{base}{path}"), vec![]).await;
        assert_eq!(status, 403, "{path} from an unapproved source");
    }

    // 3. Forwarding headers never admit anybody: a caller names an approved address and is still refused.
    let forged = vec![
        ("x-forwarded-for", APPROVED_NODE),
        ("x-real-ip", APPROVED_NODE),
        ("forwarded", "for=10.77.0.2"),
    ];
    let (status, _) = get(EXTERNAL_HOST, format!("{base}/v2/"), forged).await;
    assert_eq!(
        status, 403,
        "a forged X-Forwarded-For from an unapproved source"
    );

    // 4. The kubelet's probes and a load balancer's checks reach the pod from any address, with the pod's own address as Host.
    let (status, _) = get(
        EXTERNAL_HOST,
        format!("{base}/health/live"),
        vec![("host", "10.244.1.7:8443")],
    )
    .await;
    assert_eq!(
        status, 200,
        "liveness answers every peer and needs no Host header"
    );
    let (status, body) = get(
        EXTERNAL_HOST,
        format!("{base}/health/ready"),
        vec![("host", "10.244.1.7:8443")],
    )
    .await;
    assert!(
        body.is_empty(),
        "an unapproved peer gets no readiness detail (status {status}): {body}"
    );

    // 5. What externalTrafficPolicy: Cluster would do: a forwarder on an approved node connects from the node's own address (kube-proxy's
    // source rewrite). The external host did nothing different, and the service now admits it. This is why the Service says Local.
    let listener = tokio::net::TcpListener::bind(format!("{FORWARDER}:18444"))
        .await
        .expect("the forwarder listens");
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let socket = tokio::net::TcpSocket::new_v4().expect("a socket");
                socket
                    .bind(format!("{APPROVED_NODE}:0").parse().expect("an address"))
                    .expect("bind the approved source");
                let Ok(mut outbound) = socket
                    .connect(
                        format!("{SERVICE_NODE}:18443")
                            .parse::<SocketAddr>()
                            .expect("an address"),
                    )
                    .await
                else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    let (status, body) = get(
        EXTERNAL_HOST,
        format!("https://{FORWARDER}:18444/v2/"),
        vec![("host", "10.77.0.1:18443")],
    )
    .await;
    assert!(
        status != 403 && body.contains("POLICY_UNAVAILABLE"),
        "behind a source-rewriting hop the external host IS admitted (the failure Local prevents): {status} {body}"
    );
    // And the same host, direct, is refused again: preserving the source is the whole difference.
    let (status, _) = get(EXTERNAL_HOST, format!("{base}/v2/"), vec![]).await;
    assert_eq!(status, 403, "the same host without the rewriting hop");

    // 6. The pod's own loopback is admitted (nothing outside the pod can be a loopback peer).
    let (status, body) = get(
        "127.0.0.1",
        "https://127.0.0.1:18443/v2/".to_owned(),
        vec![],
    )
    .await;
    assert!(
        status != 403 && body.contains("POLICY_UNAVAILABLE"),
        "a loopback peer is admitted: {status} {body}"
    );
    println!("cluster_peer inner: six peer checks held");
}
