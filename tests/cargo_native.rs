//! Row 18: the real native client (Cargo 1.96, sparse protocol) against the firewall on a real
//! TCP port, with real `.crate` archives built by `cargo package` and index lines in the shape
//! crates.io writes. Only the upstream is an in-process fake. A host without `cargo` skips
//! loudly (the lane did NOT run).

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Uri};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};
use probation::upstream::{OriginKind, OriginSet, Transport};
use sha2::{Digest, Sha256};
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn origins() -> OriginSet {
    fake_origins().with_cargo(
        Url::parse("https://cargo-index.invalid").unwrap(),
        Url::parse("https://cargo-files.invalid").unwrap(),
    )
}

fn index_path(segments: &[&str]) -> String {
    origins()
        .url_for(OriginKind::CargoIndex, segments)
        .unwrap()
        .path()
        .to_owned()
}

fn cargo_available() -> bool {
    std::process::Command::new("cargo")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

macro_rules! need_cargo {
    () => {
        if !cargo_available() {
            eprintln!("SKIPPED: no cargo on this host; the native Cargo lane did NOT run");
            return;
        }
    };
}

/// Runs the real `cargo` with a clean environment of its own: its own `CARGO_HOME`, none of this
/// build's `CARGO_*` variables (the outer cargo sets a target dir and flags the inner one must not inherit).
async fn cargo(cwd: &Path, home: &Path, args: &[&str]) -> (bool, String) {
    cargo_with(cwd, home, args, &[]).await
}

async fn cargo_with(
    cwd: &Path,
    home: &Path,
    args: &[&str],
    extra: &[(&str, &str)],
) -> (bool, String) {
    let (cwd, home) = (cwd.to_path_buf(), home.to_path_buf());
    let extra: Vec<(String, String)> = extra
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new("cargo");
        command.args(&args).current_dir(&cwd);
        for (key, _) in std::env::vars() {
            if key.starts_with("CARGO") || key.starts_with("RUSTFLAGS") || key.starts_with("RUSTC")
            {
                command.env_remove(key);
            }
        }
        let rustup_home = std::env::var("RUSTUP_HOME")
            .unwrap_or_else(|_| format!("{}/.rustup", std::env::var("HOME").unwrap()));
        command
            .env("CARGO_HOME", home.join("cargo-home"))
            .env("RUSTUP_HOME", rustup_home)
            .env("CARGO_TERM_COLOR", "never")
            .env("CARGO_NET_RETRY", "0");
        for (key, value) in &extra {
            command.env(key, value);
        }
        let output = command
            .output()
            .expect("cargo is the native baseline of this row");
        (
            output.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    })
    .await
    .unwrap()
}

/// `cargo package` of a one-file library, offline: the real archive the firewall will deliver.
async fn build_crate(root: &Path, version: &str) -> Vec<u8> {
    build_named_crate(root, "demo", version).await
}

async fn build_named_crate(root: &Path, name: &str, version: &str) -> Vec<u8> {
    let dir = root.join(format!("src-{name}-{version}"));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("Cargo.toml"), format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\ndescription = \"demo\"\nlicense = \"MIT\"\n")).unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        format!("pub fn version() -> &'static str {{ \"{version}\" }}\n"),
    )
    .unwrap();
    let (ok, log) = cargo(
        &dir,
        root,
        &["package", "--no-verify", "--allow-dirty", "--offline"],
    )
    .await;
    assert!(ok, "cargo package {version}: {log}");
    std::fs::read(dir.join(format!("target/package/{name}-{version}.crate"))).unwrap()
}

fn index_line(version: &str, crate_file: &[u8], pubtime: &str, yanked: bool) -> String {
    format!(
        r#"{{"name":"demo","vers":"{version}","deps":[],"cksum":"{}","features":{{}},"yanked":{yanked},"pubtime":"{pubtime}"}}"#,
        hex::encode(Sha256::digest(crate_file))
    )
}

struct Native {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    dir: tempfile::TempDir,
    _policy: Option<wiremock::MockServer>,
    port: u16,
}

/// A firewall on a real port whose `public_url` is that port (the rewritten `dl` must be reachable).
/// `service`: the shared service, where nothing of a caller's metadata is stored.
async fn start_in(service: bool, yanked_old: bool) -> Native {
    let dir = tempfile::tempdir().unwrap();
    let (one, two) = (
        build_crate(dir.path(), "1.0.0").await,
        build_crate(dir.path(), "2.0.0").await,
    );
    let registry = FakeRegistry::new();
    registry.answer(
        &index_path(&["config.json"]),
        FakeAnswer::Body(
            r#"{"dl":"https://cargo-files.invalid/crates","api":"https://cargo-api.invalid"}"#
                .to_owned(),
        ),
    );
    registry.answer(
        &index_path(&["de", "mo", "demo"]),
        FakeAnswer::Body(format!(
            "{}\n{}\n",
            index_line("1.0.0", &one, OLD, yanked_old),
            index_line("2.0.0", &two, YOUNG, false)
        )),
    );
    registry.answer("/crates/demo/1.0.0/download", FakeAnswer::Bytes(one));
    registry.answer("/crates/demo/2.0.0/download", FakeAnswer::Bytes(two));
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", ""),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut config = sample_config();
    config.blocklist_file = blocklist;
    config.cooldown_seconds = 7 * 86_400;
    config.listen = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    config.public_url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let clock = TestClock::at_rfc3339(NOW);
    let mut policy_server = None;
    if service {
        use probation::config::{FirewallToken, ServicePolicyConfig};
        use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
        let places = [
            PlaceRef {
                kind: LayerKind::Platform,
                id: 1,
            },
            PlaceRef {
                kind: LayerKind::Org,
                id: 10,
            },
        ];
        let snapshot = ServicePolicySnapshot {
            version: 1,
            key_id: KeyId(7),
            org: OrgId(10),
            account: places[1],
            revision: 1,
            place_chain: places
                .iter()
                .map(|place| ChainLink {
                    place: *place,
                    layer_revision: 1,
                })
                .collect(),
            layers: places
                .iter()
                .map(|place| PlaceLayer {
                    place: *place,
                    layer: Layer {
                        freeze_seconds: Some(7 * 86_400),
                        osv: Some(OsvSetting::Off),
                        ..Layer::empty(place.kind)
                    },
                    revision: 1,
                })
                .collect(),
            rate_limit: None,
            rate_limit_source: LimitSource::Default,
            registries: vec![RegistryDescriptor {
                registry: RegistryId(7),
                ecosystem: probation_policy::Ecosystem::Cargo,
                target_url: None,
                trusted: false,
                registry_private_cidrs: vec![],
                deletion_scopes: vec![],
                osv_scope: None,
                archive_origin: None,
                resource_path_prefix: None,
                token_origin: None,
            }],
        };
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/policy/snapshot"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(snapshot))
            .mount(&mock)
            .await;
        config.service_policy = Some(ServicePolicyConfig {
            server_url: mock.uri().parse().unwrap(),
            service_key_file: "/test/key".into(),
            service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
            sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
            trusted_proxies: vec![],
        });
        policy_server = Some(mock);
    }
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        origins(),
    )
    .await;
    Native {
        server,
        registry,
        dir,
        _policy: policy_server,
        port,
    }
}

/// A consumer project that reads crates.io through the firewall (source replacement, the way a
/// mirror is configured) and depends on `demo` with `requirement`.
fn project(native: &Native, requirement: &str) -> PathBuf {
    let project = native.dir.path().join(format!(
        "consumer-{}",
        requirement.replace(['=', '*', '.', '^'], "_")
    ));
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(project.join(".cargo")).unwrap();
    std::fs::write(project.join("src/lib.rs"), "").unwrap();
    std::fs::write(project.join("Cargo.toml"), format!("[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ndemo = \"{requirement}\"\n")).unwrap();
    std::fs::write(
        project.join(".cargo/config.toml"),
        format!("[source.crates-io]\nreplace-with = \"probation\"\n\n[source.probation]\nregistry = \"sparse+http://127.0.0.1:{}/cargo/\"\n", native.port),
    )
    .unwrap();
    project
}

async fn eligible_version_flow(service: bool) {
    need_cargo!();
    let n = start_in(service, false).await;
    let consumer = project(&n, "*");
    let (ok, log) = cargo(&consumer, n.dir.path(), &["generate-lockfile"]).await;
    assert!(ok, "cargo generate-lockfile (service={service}): {log}");
    let lock = std::fs::read_to_string(consumer.join("Cargo.lock")).unwrap();
    assert!(
        lock.contains("name = \"demo\"\nversion = \"1.0.0\""),
        "the young 2.0.0 is not offered: {lock}"
    );
    assert!(!lock.contains("2.0.0"), "{lock}");
    let (ok, log) = cargo(&consumer, n.dir.path(), &["fetch", "--locked"]).await;
    assert!(ok, "cargo fetch (service={service}): {log}");
    let fetched = n
        .registry
        .calls()
        .iter()
        .filter(|url| url.path() == "/crates/demo/1.0.0/download")
        .count();
    assert_eq!(
        fetched, 1,
        "the eligible archive came through the firewall, once"
    );
    assert!(
        !n.registry
            .calls()
            .iter()
            .any(|url| url.path() == "/crates/demo/2.0.0/download"),
        "the young archive was never requested"
    );
    // The archive cargo unpacked is the real one: the build of the consumer sees demo 1.0.0.
    let source = std::fs::read_to_string(consumer.join("Cargo.lock")).unwrap();
    assert!(
        source.contains("checksum = "),
        "cargo verified the index checksum: {source}"
    );
    n.server.shutdown().await;
}

#[tokio::test]
async fn native_cargo_resolves_and_fetches_only_the_eligible_version() {
    eligible_version_flow(false).await;
}

#[tokio::test]
async fn native_cargo_resolves_and_fetches_only_the_eligible_version_through_the_shared_service() {
    eligible_version_flow(true).await;
}

#[tokio::test]
async fn native_cargo_cannot_pin_a_version_the_firewall_withholds() {
    need_cargo!();
    let n = start_in(false, false).await;
    let consumer = project(&n, "=2.0.0");
    let (ok, log) = cargo(&consumer, n.dir.path(), &["generate-lockfile"]).await;
    assert!(
        !ok,
        "an exact pin of the young version must not resolve: {log}"
    );
    assert!(log.contains("demo") && log.contains("2.0.0"), "{log}");
    assert!(
        !n.registry
            .calls()
            .iter()
            .any(|url| url.path() == "/crates/demo/2.0.0/download")
    );
    n.server.shutdown().await;
}

/// A lockfile that names a yanked version still installs: yank only stops new resolutions, and the
/// index line, yank flag included, reaches cargo unchanged.
#[tokio::test]
async fn native_cargo_installs_a_locked_yanked_version() {
    need_cargo!();
    let n = start_in(false, true).await;
    let consumer = project(&n, "1.0.0");
    // Cargo refuses to *resolve* to a yanked version without a lockfile; with one it fetches it.
    let (ok, log) = cargo(&consumer, n.dir.path(), &["generate-lockfile"]).await;
    assert!(
        !ok,
        "a fresh resolution must not choose a yanked version: {log}"
    );
    let sum = n.registry.calls().len();
    assert!(sum > 0);
    let crate_file = std::fs::read(
        n.dir
            .path()
            .join("src-demo-1.0.0/target/package/demo-1.0.0.crate"),
    )
    .unwrap();
    std::fs::write(
        consumer.join("Cargo.lock"),
        format!(
            "version = 4\n\n[[package]]\nname = \"consumer\"\nversion = \"0.1.0\"\ndependencies = [\n \"demo\",\n]\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
            hex::encode(Sha256::digest(&crate_file))
        ),
    )
    .unwrap();
    let (ok, log) = cargo(&consumer, n.dir.path(), &["fetch", "--locked"]).await;
    assert!(ok, "cargo fetch of a locked yanked version: {log}");
    n.server.shutdown().await;
}

/// What `cargo` sends on a plain read is on the allow-list of LS-F4, so reads from the native
/// client stay cache-eligible (an unlisted header would cost hits, never safety).
#[tokio::test]
async fn cargo_native_client_sends_only_allow_listed_headers() {
    need_cargo!();
    let seen: Arc<Mutex<Vec<(Uri, HeaderMap)>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
        let sink = Arc::clone(&sink);
        async move {
            sink.lock().unwrap().push((uri, headers));
            axum::http::StatusCode::NOT_FOUND
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let consumer = dir.path().join("consumer");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::create_dir_all(consumer.join(".cargo")).unwrap();
    std::fs::write(consumer.join("src/lib.rs"), "").unwrap();
    std::fs::write(consumer.join("Cargo.toml"), "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ndemo = \"1\"\n").unwrap();
    std::fs::write(consumer.join(".cargo/config.toml"), format!("[source.crates-io]\nreplace-with = \"probation\"\n\n[source.probation]\nregistry = \"sparse+http://127.0.0.1:{port}/cargo/\"\n")).unwrap();
    let (ok, _) = cargo(&consumer, dir.path(), &["generate-lockfile"]).await;
    assert!(!ok, "the tap answers 404 to everything");
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "cargo reached the tap");
    for (uri, headers) in seen.iter() {
        let class = classify_read(
            &RequestParts {
                uri,
                headers,
                extra_pseudo_headers: &[],
            },
            &FamilyReadRules::CARGO,
        );
        assert!(
            matches!(class, ReadClass::CacheEligible(_)),
            "a native client header is off the allow-list: {uri} {headers:?}"
        );
    }
}

/// crates.io has one index file per published spelling (`proc_macro_error` is 404 there, checked
/// 2026-11-19), and Cargo needs the dependency spelled exactly; for a near miss it asks the other
/// spelling only to hint at it. The firewall adds no alias crates.io lacks: the near-miss spelling is
/// the registry's own 404 (and Cargo's own "similar names" hint), the exact spelling resolves, fetches
/// and unpacks. Policy still treats both spellings as one crate (tests/cargo_registry.rs).
#[tokio::test]
async fn native_cargo_needs_the_exact_spelling_as_on_crates_io() {
    need_cargo!();
    let n = start_in(false, false).await;
    let bytes = build_named_crate(n.dir.path(), "demo-alias", "1.0.0").await;
    n.registry.answer(
        &index_path(&["de", "mo", "demo-alias"]),
        FakeAnswer::Body(format!(
            "{}\n",
            index_line("1.0.0", &bytes, OLD, false).replace("\"demo\"", "\"demo-alias\"")
        )),
    );
    n.registry.answer(
        "/crates/demo-alias/1.0.0/download",
        FakeAnswer::Bytes(bytes),
    );
    n.registry.answer(
        &index_path(&["de", "mo", "demo_alias"]),
        FakeAnswer::Missing,
    );
    let near = project(&n, "*");
    std::fs::write(near.join("Cargo.toml"), "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ndemo_alias = \"1\"\n").unwrap();
    let (ok, log) = cargo(&near, n.dir.path(), &["generate-lockfile"]).await;
    assert!(
        !ok && log.contains("no matching package named `demo_alias`") && log.contains("demo-alias"),
        "the near-miss spelling fails as on crates.io, with Cargo's own hint: {log}"
    );
    let exact = n.dir.path().join("consumer-exact");
    std::fs::create_dir_all(exact.join("src")).unwrap();
    std::fs::create_dir_all(exact.join(".cargo")).unwrap();
    std::fs::write(exact.join("src/lib.rs"), "").unwrap();
    std::fs::copy(
        near.join(".cargo/config.toml"),
        exact.join(".cargo/config.toml"),
    )
    .unwrap();
    std::fs::write(exact.join("Cargo.toml"), "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ndemo-alias = \"1\"\n").unwrap();
    let (ok, log) = cargo(&exact, n.dir.path(), &["generate-lockfile"]).await;
    assert!(ok, "cargo generate-lockfile: {log}");
    let (ok, log) = cargo(&exact, n.dir.path(), &["fetch", "--locked"]).await;
    assert!(ok, "cargo fetch: {log}");
    let lock = std::fs::read_to_string(exact.join("Cargo.lock")).unwrap();
    assert!(
        lock.contains("name = \"demo-alias\"\nversion = \"1.0.0\""),
        "{lock}"
    );
    n.server.shutdown().await;
}

// ------------------------------------------------------------------ the registry API through the shared service

#[derive(Debug)]
struct Write {
    method: String,
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// The upstream: the file fake for reads, and a registry API that records what real cargo sends.
struct Recording {
    inner: Arc<FakeRegistry>,
    calls: Mutex<Vec<Write>>,
}

#[async_trait::async_trait]
impl Transport for Recording {
    async fn fetch_metadata(
        &self,
        request: probation::upstream::MetadataRequest,
    ) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError> {
        self.inner.fetch_metadata(request).await
    }
    async fn open_artifact(
        &self,
        request: probation::upstream::ArtifactRequest,
    ) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
        self.inner.open_artifact(request).await
    }
    async fn send_action(
        &self,
        mut request: probation::upstream::ActionRequest,
    ) -> Result<probation::upstream::ActionResponse, probation::upstream::UpstreamError> {
        use tokio::io::AsyncReadExt;
        let mut body = Vec::new();
        request.body.read_to_end(&mut body).await.unwrap();
        let (method, path) = (request.method.to_string(), request.url.path().to_owned());
        self.calls.lock().unwrap().push(Write {
            method: method.clone(),
            path: path.clone(),
            query: request.url.query().map(str::to_owned),
            authorization: request.authorization.clone(),
            body,
        });
        let answer = match (method.as_str(), path.as_str()) {
            ("PUT", "/api/v1/crates/new") => {
                r#"{"warnings":{"invalid_categories":[],"invalid_badges":[],"other":[]}}"#
            }
            ("GET", p) if p.ends_with("/owners") => {
                r#"{"users":[{"id":1,"login":"someone","name":null}]}"#
            }
            ("GET", "/api/v1/crates") => {
                r#"{"crates":[{"name":"demo","max_version":"1.0.0","description":"demo"}],"meta":{"total":1}}"#
            }
            ("PUT" | "DELETE", p) if p.ends_with("/owners") => {
                r#"{"ok":true,"msg":"owners changed"}"#
            }
            _ => r#"{"ok":true}"#,
        };
        Ok(probation::upstream::ActionResponse {
            status: 200,
            content_type: Some("application/json".into()),
            body: answer.as_bytes().to_vec().into(),
        })
    }
}

#[tokio::test]
async fn native_cargo_publish_yank_owner_and_search_reach_the_registry_with_the_callers_token_only()
{
    need_cargo!();
    use probation::config::{FirewallToken, ServicePolicyConfig};
    use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
    let dir = tempfile::tempdir().unwrap();
    let registry = FakeRegistry::new();
    registry.answer(
        &index_path(&["config.json"]),
        FakeAnswer::Body(
            r#"{"dl":"https://cargo-index.invalid/crates","api":"https://cargo-index.invalid"}"#
                .to_owned(),
        ),
    );
    let recording = Arc::new(Recording {
        inner: Arc::clone(&registry),
        calls: Mutex::default(),
    });
    let places = [
        PlaceRef {
            kind: LayerKind::Platform,
            id: 1,
        },
        PlaceRef {
            kind: LayerKind::Org,
            id: 10,
        },
    ];
    let snapshot = ServicePolicySnapshot {
        version: 1,
        key_id: KeyId(7),
        org: OrgId(10),
        account: places[1],
        revision: 1,
        place_chain: places
            .iter()
            .map(|place| ChainLink {
                place: *place,
                layer_revision: 1,
            })
            .collect(),
        layers: places
            .iter()
            .map(|place| PlaceLayer {
                place: *place,
                layer: Layer {
                    freeze_seconds: Some(0),
                    osv: Some(OsvSetting::Off),
                    ..Layer::empty(place.kind)
                },
                revision: 1,
            })
            .collect(),
        rate_limit: None,
        rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor {
            registry: RegistryId(7),
            ecosystem: probation_policy::Ecosystem::Cargo,
            target_url: Some("https://cargo-index.invalid/".into()),
            trusted: false,
            registry_private_cidrs: vec![],
            deletion_scopes: vec![],
            osv_scope: None,
            archive_origin: None,
            resource_path_prefix: None,
            token_origin: None,
        }],
    };
    let mock = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/api/v1/policy/snapshot"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(snapshot))
        .mount(&mock)
        .await;
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", ""),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut config = sample_config();
    config.blocklist_file = blocklist;
    config.listen = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    config.public_url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: mock.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&recording) as Arc<dyn Transport>,
        origins(),
    )
    .await;
    let krate = dir.path().join("pub");
    let archive = build_named_crate(dir.path(), "demo-pub", "1.0.0").await;
    let package = dir.path().join("src-demo-pub-1.0.0");
    std::fs::create_dir_all(package.join(".cargo")).unwrap();
    std::fs::write(
        package.join(".cargo/config.toml"),
        format!("[registries.probation]\nindex = \"sparse+http://127.0.0.1:{port}/cargo/\"\n"),
    )
    .unwrap();
    let _ = krate;
    let env = [
        ("CARGO_REGISTRIES_PROBATION_TOKEN", "tok-0123456789"),
        ("CARGO_PUBLISH_TIMEOUT", "1"),
    ];
    let (ok, log) = cargo_with(
        &package,
        dir.path(),
        &[
            "publish",
            "--registry",
            "probation",
            "--no-verify",
            "--allow-dirty",
        ],
        &env,
    )
    .await;
    assert!(ok, "cargo publish: {log}");
    for args in [
        vec!["yank", "demo-pub@1.0.0", "--registry", "probation"],
        vec![
            "yank",
            "demo-pub@1.0.0",
            "--undo",
            "--registry",
            "probation",
        ],
        vec!["owner", "--list", "demo-pub", "--registry", "probation"],
        vec![
            "owner",
            "--add",
            "someone",
            "demo-pub",
            "--registry",
            "probation",
        ],
        vec![
            "owner",
            "--remove",
            "someone",
            "demo-pub",
            "--registry",
            "probation",
        ],
        vec!["search", "demo", "--registry", "probation"],
    ] {
        let (ok, log) = cargo_with(&package, dir.path(), &args, &env).await;
        assert!(ok, "cargo {args:?}: {log}");
    }
    let seen = std::mem::take(&mut *recording.calls.lock().unwrap());
    let shape: Vec<(&str, &str)> = seen
        .iter()
        .map(|w| (w.method.as_str(), w.path.as_str()))
        .collect();
    assert_eq!(
        shape,
        [
            ("PUT", "/api/v1/crates/new"),
            ("DELETE", "/api/v1/crates/demo-pub/1.0.0/yank"),
            ("PUT", "/api/v1/crates/demo-pub/1.0.0/unyank"),
            ("GET", "/api/v1/crates/demo-pub/owners"),
            ("PUT", "/api/v1/crates/demo-pub/owners"),
            ("DELETE", "/api/v1/crates/demo-pub/owners"),
            ("GET", "/api/v1/crates"),
        ],
        "{seen:#?}"
    );
    for write in seen
        .iter()
        .filter(|w| w.method != "GET" || w.path.ends_with("/owners"))
    {
        assert_eq!(
            write.authorization.as_deref(),
            Some("tok-0123456789"),
            "the caller's own token, bare: {write:?}"
        );
    }
    assert_eq!(
        seen[6].authorization, None,
        "cargo search sends no token to a registry that does not require one"
    );
    assert!(
        seen[0].body.len() > archive.len(),
        "the publish body (length-prefixed JSON and the crate) arrived whole"
    );
    assert!(
        seen[0]
            .body
            .windows(archive.len())
            .any(|w| w == archive.as_slice()),
        "the real .crate is inside it"
    );
    assert_eq!(seen[4].body, br#"{"users":["someone"]}"#);
    assert!(
        seen[6]
            .query
            .as_deref()
            .is_some_and(|q| q.starts_with("q=demo")),
        "{:?}",
        seen[6].query
    );
    server.shutdown().await;
}
