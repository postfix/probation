//! Row 19: the real native client (the `go` command) against the firewall on a real TCP port, with
//! real module zips and `.info` documents in the shape proxy.golang.org writes. Only the upstream is
//! an in-process fake. A host without `go` skips loudly (the lane did NOT run).
//!
//! Client settings (the ones the keys page shows): `GOPROXY` is the single firewall URL with no
//! `,direct` or `|` fallback, `GOTOOLCHAIN=local` (no `GOFLAGS`: the default `-mod=readonly` guard stays on); the checksum database is off
//! here (`GOSUMDB=off`) because the fake upstream cannot sign a tree, and its forwarding is proven
//! at the HTTP level in tests/go_modules.rs.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Uri};
use common::go::{info, mod_text, module_zip};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};
use probation::upstream::{OriginKind, OriginSet, Transport};
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn origins() -> OriginSet {
    fake_origins().with_go(
        Url::parse("https://goproxy.invalid").unwrap(),
        Url::parse("https://sumdb.invalid").unwrap(),
    )
}

fn up(escaped_module: &str, tail: &str) -> String {
    let mut segments: Vec<&str> = escaped_module.split('/').collect();
    segments.extend(tail.split('/'));
    origins()
        .url_for(OriginKind::GoProxy, &segments)
        .unwrap()
        .path()
        .to_owned()
}

fn go_available() -> bool {
    std::process::Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|out| out.status.success())
}

macro_rules! need_go {
    () => {
        if !go_available() {
            eprintln!("SKIPPED: no go on this host; the native Go lane did NOT run");
            return;
        }
    };
}

/// Runs the real `go` with an environment of its own: its own module cache, build cache and home,
/// the firewall as the only proxy, and no variable of this build's environment that could redirect it.
async fn go(
    cwd: &Path,
    root: &Path,
    port: u16,
    args: &[&str],
    extra: &[(&str, &str)],
) -> (bool, String) {
    let (cwd, root) = (cwd.to_path_buf(), root.to_path_buf());
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let extra: Vec<(String, String)> = extra
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new("go");
        command.args(&args).current_dir(&cwd);
        for (key, _) in std::env::vars() {
            if key.starts_with("GO") || key.starts_with("CGO") {
                command.env_remove(key);
            }
        }
        command
            .env("HOME", root.join("home"))
            .env("GOPATH", root.join("gopath"))
            .env("GOMODCACHE", root.join("modcache"))
            .env("GOCACHE", root.join("gocache"))
            .env("GOPROXY", format!("http://127.0.0.1:{port}/go"))
            .env("GOSUMDB", "off")
            .env("GOTOOLCHAIN", "local")
            .env("GO111MODULE", "on")
            .env("GOVCS", "off");
        for (key, value) in &extra {
            command.env(key, value);
        }
        let output = command
            .output()
            .expect("go is the native baseline of this row");
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

struct Native {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    dir: tempfile::TempDir,
    _policy: Option<wiremock::MockServer>,
    port: u16,
}

fn serve_version(registry: &Arc<FakeRegistry>, escaped: &str, version: &str, time: &str) {
    let module = probation::go_modules::escape::unescape(escaped).unwrap();
    let ev = probation::go_modules::escape::escape(version).unwrap();
    registry.answer(
        &up(escaped, &format!("@v/{ev}.info")),
        FakeAnswer::Body(info(version, Some(time))),
    );
    registry.answer(
        &up(escaped, &format!("@v/{ev}.mod")),
        FakeAnswer::Body(mod_text(&module)),
    );
    registry.answer(
        &up(escaped, &format!("@v/{ev}.zip")),
        FakeAnswer::Bytes(module_zip(
            &module,
            version,
            &format!("package demo\n\nconst Version = \"{version}\"\n"),
        )),
    );
}

/// A firewall on a real port. `service`: the shared service (one Go registry, id 7), where nothing of a
/// caller's metadata is stored.
async fn start_in(service: bool) -> Native {
    let dir = tempfile::tempdir().unwrap();
    let registry = FakeRegistry::new();
    for (escaped, versions) in [
        ("example.com/demo", vec![("v1.0.0", OLD), ("v1.1.0", YOUNG)]),
        (
            "github.com/!big!corp/lib",
            vec![("v1.0.0-RC1", OLD), ("v1.0.0", OLD)],
        ),
    ] {
        let list: String = versions.iter().map(|(v, _)| format!("{v}\n")).collect();
        registry.answer(&up(escaped, "@v/list"), FakeAnswer::Body(list));
        for (version, time) in &versions {
            serve_version(&registry, escaped, version, time);
        }
    }
    registry.answer(
        &up("example.com/demo", "@latest"),
        FakeAnswer::Body(info("v1.1.0", Some(YOUNG))),
    );
    // Revision queries: a branch and a commit that resolve to an old pseudo-version, a branch that resolves to a young one.
    serve_version(
        &registry,
        "example.com/demo",
        "v0.0.0-20250101000000-abcdef123456",
        OLD,
    );
    serve_version(
        &registry,
        "example.com/demo",
        "v0.0.0-20260405120000-123456abcdef",
        YOUNG,
    );
    registry.answer(
        &up("example.com/demo", "@v/main.info"),
        FakeAnswer::Body(info("v0.0.0-20250101000000-abcdef123456", Some(OLD))),
    );
    registry.answer(
        &up("example.com/demo", "@v/abcdef123456.info"),
        FakeAnswer::Body(info("v0.0.0-20250101000000-abcdef123456", Some(OLD))),
    );
    registry.answer(
        &up("example.com/demo", "@v/dev.info"),
        FakeAnswer::Body(info("v0.0.0-20260405120000-123456abcdef", Some(YOUNG))),
    );
    registry.answer(
        &up("github.com/!big!corp/lib", "@latest"),
        FakeAnswer::Body(info("v1.0.0", Some(OLD))),
    );
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
                ecosystem: probation_policy::Ecosystem::Go,
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

/// A consumer module that has not chosen a version of anything yet.
fn consumer(native: &Native, name: &str, requires: &str) -> PathBuf {
    let dir = native.dir.path().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("go.mod"),
        format!("module consumer.example/app\n\ngo 1.21\n{requires}"),
    )
    .unwrap();
    std::fs::write(dir.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();
    dir
}

fn fetched(n: &Native, needle: &str) -> usize {
    n.registry
        .calls()
        .iter()
        .filter(|url| url.path().ends_with(needle))
        .count()
}

async fn eligible_flow(service: bool) {
    need_go!();
    let n = start_in(service).await;
    let root = n.dir.path().to_owned();
    let app = consumer(&n, "app", "");
    // `@latest` is the proxy's v1.1.0, which the firewall holds: go gets the best allowed version.
    let (ok, log) = go(
        &app,
        &root,
        n.port,
        &["get", "example.com/demo@latest"],
        &[],
    )
    .await;
    assert!(ok, "go get @latest (service={service}): {log}");
    let gomod = std::fs::read_to_string(app.join("go.mod")).unwrap();
    assert!(gomod.contains("example.com/demo v1.0.0"), "{gomod}");
    // The version list shows only what is allowed.
    let (ok, log) = go(
        &app,
        &root,
        n.port,
        &["list", "-m", "-versions", "example.com/demo"],
        &[],
    )
    .await;
    assert!(
        ok && log.trim() == "example.com/demo v1.0.0",
        "go list -m -versions (service={service}): {log}"
    );
    // The eligible module is really unpacked (the zip verified by go itself) and builds.
    let (ok, log) = go(
        &app,
        &root,
        n.port,
        &["mod", "download", "-json", "example.com/demo@v1.0.0"],
        &[],
    )
    .await;
    assert!(ok, "go mod download (service={service}): {log}");
    assert!(
        root.join("modcache/example.com/demo@v1.0.0/demo.go")
            .exists(),
        "{log}"
    );
    assert_eq!(
        fetched(&n, "@v/v1.0.0.zip"),
        1,
        "the eligible zip came through the firewall, once"
    );
    assert_eq!(
        fetched(&n, "@v/v1.1.0.zip") + fetched(&n, "@v/v1.1.0.mod"),
        0,
        "the held version's mod and zip were never requested"
    );
    n.server.shutdown().await;
}

#[tokio::test]
async fn native_go_resolves_lists_and_downloads_only_the_eligible_version() {
    eligible_flow(false).await;
}

#[tokio::test]
async fn native_go_resolves_lists_and_downloads_only_the_eligible_version_through_the_shared_service()
 {
    eligible_flow(true).await;
}

#[tokio::test]
async fn native_go_cannot_pin_a_version_the_firewall_withholds() {
    need_go!();
    let n = start_in(false).await;
    let root = n.dir.path().to_owned();
    for (name, gomod) in [("pin-mod", "\nrequire example.com/demo v1.1.0\n")] {
        let app = consumer(&n, name, gomod);
        // The build only asks for example.com/demo if something imports it.
        std::fs::write(
            app.join("main.go"),
            "package main\n\nimport _ \"example.com/demo\"\n\nfunc main() {}\n",
        )
        .unwrap();
        let (ok, log) = go(
            &app,
            &root,
            n.port,
            &["mod", "download", "example.com/demo@v1.1.0"],
            &[],
        )
        .await;
        assert!(
            !ok,
            "an exact pin of the young version must not download: {log}"
        );
        assert!(
            log.contains("403") || log.contains("Forbidden") || log.contains("v1.1.0"),
            "{log}"
        );
        // `-mod=mod` lets the build fetch what main.go imports; `-buildvcs=false` keeps go from probing for a VCS in the scratch module.
        let (ok, log) = go(
            &app,
            &root,
            n.port,
            &["build", "-mod=mod", "-buildvcs=false", "./..."],
            &[],
        )
        .await;
        assert!(!ok, "a build that needs the held version must fail: {log}");
        assert!(
            log.contains("403") || log.contains("Forbidden") || log.contains("v1.1.0"),
            "the build failed for the firewall's refusal, not for another reason: {log}"
        );
    }
    assert!(!root.join("modcache/example.com/demo@v1.1.0").exists());
    assert_eq!(
        fetched(&n, "@v/v1.1.0.zip") + fetched(&n, "@v/v1.1.0.mod"),
        0
    );
    n.server.shutdown().await;
}

/// `go get mod@branch` and `mod@<commit>` ask the proxy `@v/{rev}.info` and take the version it names: through the
/// firewall the resolved pseudo-version is judged by its own time, so an old commit resolves and downloads and a
/// branch that resolves to a young commit fails with the firewall's refusal.
#[tokio::test]
async fn native_go_resolves_a_branch_and_a_commit_and_a_young_branch_is_held() {
    need_go!();
    let n = start_in(false).await;
    let root = n.dir.path().to_owned();
    for rev in ["main", "abcdef123456"] {
        let app = consumer(&n, &format!("rev-{rev}"), "");
        let (ok, log) = go(
            &app,
            &root,
            n.port,
            &["get", &format!("example.com/demo@{rev}")],
            &[],
        )
        .await;
        assert!(ok, "go get @{rev}: {log}");
        let gomod = std::fs::read_to_string(app.join("go.mod")).unwrap();
        assert!(
            gomod.contains("example.com/demo v0.0.0-20250101000000-abcdef123456"),
            "{rev}: {gomod}"
        );
    }
    assert!(
        root.join("modcache/example.com/demo@v0.0.0-20250101000000-abcdef123456/demo.go")
            .exists()
    );
    let app = consumer(&n, "rev-dev", "");
    let (ok, log) = go(&app, &root, n.port, &["get", "example.com/demo@dev"], &[]).await;
    assert!(
        !ok,
        "a branch that resolves to a young version is held: {log}"
    );
    assert_eq!(
        fetched(&n, "v0.0.0-20260405120000-123456abcdef.zip")
            + fetched(&n, "v0.0.0-20260405120000-123456abcdef.mod"),
        0
    );
    n.server.shutdown().await;
}

/// A module path with capitals is `!`-escaped on the wire, and go decodes the cache directory the same
/// way: the real client, the firewall and the fake proxy agree on one identity.
#[tokio::test]
async fn native_go_downloads_a_mixed_case_module_and_version() {
    need_go!();
    let n = start_in(false).await;
    let root = n.dir.path().to_owned();
    let app = consumer(&n, "mixed", "");
    let (ok, log) = go(
        &app,
        &root,
        n.port,
        &["get", "github.com/BigCorp/lib@v1.0.0-RC1"],
        &[],
    )
    .await;
    assert!(ok, "go get of a case-encoded module and version: {log}");
    assert!(
        root.join("modcache/github.com/!big!corp/lib@v1.0.0-!r!c1/demo.go")
            .exists(),
        "cache dir uses the escaped spelling: {log}"
    );
    let (ok, log) = go(
        &app,
        &root,
        n.port,
        &["get", "github.com/BigCorp/lib@latest"],
        &[],
    )
    .await;
    assert!(ok, "{log}");
    let gomod = std::fs::read_to_string(app.join("go.mod")).unwrap();
    assert!(
        gomod.contains("github.com/BigCorp/lib v1.0.0") && !gomod.contains("RC1"),
        "{gomod}"
    );
    n.server.shutdown().await;
}

/// A GOPROXY that lists the firewall and a fallback would let a refusal be bypassed; the client's own
/// semantics are recorded: with `,direct` a 403 is NOT a fallback trigger for go (only 404/410 are),
/// which is why the keys page and the docs show the single URL.
#[tokio::test]
async fn native_go_with_one_protected_proxy_does_not_fall_back_on_a_refusal() {
    need_go!();
    let n = start_in(false).await;
    let root = n.dir.path().to_owned();
    let app = consumer(&n, "nofallback", "");
    let proxy = format!("http://127.0.0.1:{}/go|off", n.port);
    let (ok, log) = go(
        &app,
        &root,
        n.port,
        &["mod", "download", "example.com/demo@v1.1.0"],
        &[("GOPROXY", &proxy)],
    )
    .await;
    assert!(!ok, "{log}");
    n.server.shutdown().await;
}

/// What `go` sends on a plain read is on the allow-list of LS-F4, so reads from the native client stay
/// cache-eligible (an unlisted header would cost hits, never safety).
#[tokio::test]
async fn go_native_client_sends_only_allow_listed_headers() {
    need_go!();
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
    let project = dir.path().join("app");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("go.mod"),
        "module consumer.example/app\n\ngo 1.21\n",
    )
    .unwrap();
    for args in [
        vec!["get", "example.com/demo@latest"],
        vec!["list", "-m", "-versions", "example.com/demo"],
        vec!["mod", "download", "example.com/demo@v1.0.0"],
    ] {
        let (ok, _) = go(&project, dir.path(), port, &args, &[]).await;
        assert!(!ok, "the tap answers 404 to everything");
    }
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 3, "go reached the tap: {seen:?}");
    for (uri, headers) in seen.iter() {
        let class = classify_read(
            &RequestParts {
                uri,
                headers,
                extra_pseudo_headers: &[],
            },
            &FamilyReadRules::GO,
        );
        assert!(
            matches!(class, ReadClass::CacheEligible(_)),
            "a native client header is off the allow-list: {uri} {headers:?}"
        );
    }
}

// ------------------------------------------------------------------ live (network) witness

/// The production transport, with one switch that flips a byte of every archive it delivers (a hostile
/// or broken upstream): what `go` would then verify is the firewall's delivery, not the fake's.
struct Live {
    inner: probation::upstream::ReqwestTransport,
    flip: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Transport for Live {
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
        use futures_util::StreamExt;
        let body = self.inner.open_artifact(request).await?;
        if !self.flip.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(body);
        }
        let mut bytes = Vec::new();
        let mut stream = body.stream;
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
        }
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
        Ok(probation::upstream::ArtifactBody {
            declared_length: Some(bytes.len() as u64),
            stream: Box::pin(futures_util::stream::once(async move {
                Ok(bytes::Bytes::from(bytes))
            })),
        })
    }
}

/// Opt-in (`cargo test --test go_native -- --ignored`, needs the internet): the real `go` against the
/// firewall over the real proxy.golang.org and the real sum.golang.org, with the checksum database
/// ON. It witnesses what no fake can: the zip the firewall delivers hashes to the value the real
/// checksum database signed (so it is the proxy's exact bytes), the firewall answers `sumdb/.../supported`
/// and forwards the signed lookups and tiles, a zip over the proxy's size threshold arrives through
/// the 302 to the proxy's storage bucket, and a flipped byte is refused by `go` itself.
#[tokio::test]
#[ignore = "live network: real proxy.golang.org and sum.golang.org"]
async fn live_go_verifies_the_real_checksum_database_through_the_firewall() {
    need_go!();
    let dir = tempfile::tempdir().unwrap();
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
    let live = Arc::new(Live {
        inner: probation::upstream::ReqwestTransport::production(),
        flip: std::sync::atomic::AtomicBool::new(false),
    });
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&live) as Arc<dyn Transport>,
        OriginSet::production(),
    )
    .await;
    let root = dir.path().to_owned();
    let work = root.join("app");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(
        work.join("go.mod"),
        "module consumer.example/app\n\ngo 1.21\n",
    )
    .unwrap();
    let sumdb = [("GOSUMDB", "sum.golang.org")];
    // A small module: direct 200, verified against the real checksum database (go.sum is written only after it agrees).
    let (ok, log) = go(
        &work,
        &root,
        port,
        &["get", "github.com/pkg/errors@v0.9.1"],
        &sumdb,
    )
    .await;
    assert!(ok, "go get with the checksum database on: {log}");
    let gosum = std::fs::read_to_string(work.join("go.sum")).unwrap();
    assert!(
        gosum.contains(
            "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4="
        ),
        "the real hash of the real zip: {gosum}"
    );
    // A zip over the proxy's size threshold (25 MB): a 302 to the proxy's bucket, followed by the firewall only.
    let (ok, log) = go(
        &work,
        &root,
        port,
        &["mod", "download", "github.com/aws/aws-sdk-go@v1.44.0"],
        &sumdb,
    )
    .await;
    assert!(
        ok,
        "a large zip delivered through the proxy's own redirect and verified by the real checksum database: {log}"
    );
    assert!(
        root.join("modcache/github.com/aws/aws-sdk-go@v1.44.0/aws/version.go")
            .exists()
    );
    // The checksum database is the real one: asked through the firewall, it answers its signed tree.
    let latest = reqwest::get(server.url("/go/sumdb/sum.golang.org/latest"))
        .await
        .unwrap();
    assert!(
        latest.status().is_success()
            && latest
                .text()
                .await
                .unwrap()
                .starts_with("go.sum database tree"),
        "the signed tree head"
    );
    // A flipped byte in the delivered zip never gets past `go`.
    live.flip.store(true, std::sync::atomic::Ordering::SeqCst);
    let (ok, log) = go(
        &work,
        &root,
        port,
        &["mod", "download", "github.com/sirupsen/logrus@v1.9.3"],
        &sumdb,
    )
    .await;
    assert!(!ok, "a corrupted zip must be refused by go: {log}");
    assert!(
        log.contains("SECURITY ERROR") || log.contains("checksum") || log.contains("zip"),
        "{log}"
    );
    assert!(
        !root
            .join("modcache/github.com/sirupsen/logrus@v1.9.3")
            .exists()
    );
    server.shutdown().await;
}
