//! Row 20: the real native client (`dotnet restore`, dotnet SDK 8.0.416 / NuGet 6.11) against the firewall on a
//! real TCP port, with real `.nupkg` zips and the documents api.nuget.org writes. Only the upstream is an
//! in-process fake. A host without `dotnet` skips loudly (the lane did NOT run).
//!
//! Client settings (the ones the keys page shows): the firewall is the only package source (`<clear />`),
//! `allowInsecureConnections` because the test port is plain http (the E2E gateway has TLS), and a fresh package
//! folder and HTTP cache per test.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Uri};
use common::nuget::{
    self, FLAT, INDEX_ORIGIN, PUBLISH_ORIGIN, REG, SEARCH_ORIGIN, flat_index, leaf, registration,
};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};
use probation::upstream::{OriginSet, Transport};
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const OLD: &str = "2025-01-01T00:00:00.000+00:00";
const YOUNG: &str = "2026-04-05T12:00:00.000+00:00";

fn origins() -> OriginSet {
    fake_origins().with_nuget(
        Url::parse(INDEX_ORIGIN).unwrap(),
        Url::parse(SEARCH_ORIGIN).unwrap(),
        Url::parse(PUBLISH_ORIGIN).unwrap(),
    )
}

fn dotnet_available() -> bool {
    std::process::Command::new("dotnet")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

macro_rules! need_dotnet {
    () => {
        if !dotnet_available() {
            eprintln!("SKIPPED: no dotnet on this host; the native NuGet lane did NOT run");
            return;
        }
    };
}

/// Runs the real `dotnet` with an environment of its own: its own home, package folder and HTTP cache, no
/// build servers left behind, and no variable of this build's environment that could redirect it.
async fn dotnet(cwd: &Path, root: &Path, args: &[&str]) -> (bool, String) {
    let (cwd, root) = (cwd.to_path_buf(), root.to_path_buf());
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new("dotnet");
        command.args(&args).current_dir(&cwd);
        for (key, _) in std::env::vars() {
            if key.starts_with("DOTNET") || key.starts_with("NUGET") || key.starts_with("MSBUILD") {
                command.env_remove(key);
            }
        }
        command
            .env("HOME", root.join("home"))
            .env("DOTNET_CLI_HOME", root.join("home"))
            .env("NUGET_PACKAGES", root.join("packages"))
            .env("NUGET_HTTP_CACHE_PATH", root.join("httpcache"))
            .env("DOTNET_NOLOGO", "1")
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            .env("DOTNET_GENERATE_ASPNET_CERTIFICATE", "false")
            .env("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
            .env("MSBUILDDISABLENODEREUSE", "1")
            .env("DOTNET_ROLL_FORWARD", "Major");
        let output = command
            .output()
            .expect("dotnet is the native baseline of this row");
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

fn serve_package(registry: &Arc<FakeRegistry>, id: &str, versions: &[(&str, &str)]) {
    let names: Vec<&str> = versions.iter().map(|(v, _)| *v).collect();
    registry.answer(
        &format!("{FLAT}{id}/index.json"),
        FakeAnswer::Body(flat_index(&names)),
    );
    let leaves: Vec<serde_json::Value> = versions
        .iter()
        .map(|(v, t)| leaf(id, v, Some(t), true))
        .collect();
    let (index, _) = registration(id, &[leaves], &[]);
    registry.answer(&format!("{REG}{id}/index.json"), FakeAnswer::Body(index));
    for (version, _) in versions {
        registry.answer(
            &format!("{FLAT}{id}/{version}/{id}.{version}.nupkg"),
            FakeAnswer::Bytes(nuget::nupkg(id, version)),
        );
        registry.answer(
            &format!("{FLAT}{id}/{version}/{id}.nuspec"),
            FakeAnswer::Body(nuget::nuspec(id, version)),
        );
    }
}

/// A firewall on a real port. `service`: the shared service (one NuGet registry, id 7), where nothing of a
/// caller's metadata is stored.
async fn start_in(service: bool) -> Native {
    let dir = tempfile::tempdir().unwrap();
    let registry = FakeRegistry::new();
    registry.answer(
        "/v3/index.json",
        FakeAnswer::Body(nuget::service_index(&[])),
    );
    serve_package(&registry, "demo.pkg", &[("1.0.0", OLD), ("1.1.0", YOUNG)]);
    serve_package(&registry, "other.pkg", &[("2.0.0", OLD)]);
    registry.answer("/v3/vulnerabilities/index.json", FakeAnswer::Body(
        serde_json::json!([{"@name": "base", "@id": format!("{INDEX_ORIGIN}/v3-vulnerabilities/1/vulnerability.base.json"), "@updated": "2026-04-01T00:00:00Z"}]).to_string(),
    ));
    registry.answer(
        "/v3-vulnerabilities/1/vulnerability.base.json",
        FakeAnswer::Body("[{}]".to_owned()),
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
                ecosystem: probation_policy::Ecosystem::NuGet,
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

/// A consumer project (net8.0, whose targeting pack ships with the SDK so nothing else is restored) with the
/// firewall as its only package source. `audit` keeps NuGetAudit on (it asks the vulnerability resource).
fn consumer(native: &Native, name: &str, reference: &str, audit: bool) -> PathBuf {
    let dir = native.dir.path().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.csproj"), format!(
        r#"<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><NuGetAudit>{audit}</NuGetAudit><DisableImplicitNuGetFallbackFolder>true</DisableImplicitNuGetFallbackFolder></PropertyGroup><ItemGroup>{reference}</ItemGroup></Project>"#
    )).unwrap();
    let path = if native.server.app().service_policy().is_some() {
        "registry/nuget/7"
    } else {
        "nuget"
    };
    let _ = path;
    std::fs::write(dir.join("nuget.config"), format!(
        r#"<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /><add key="probation" value="http://127.0.0.1:{}/nuget/v3/index.json" protocolVersion="3" allowInsecureConnections="true" /></packageSources></configuration>"#,
        native.port
    )).unwrap();
    dir
}

fn fetched(n: &Native, needle: &str) -> usize {
    n.registry
        .calls()
        .iter()
        .filter(|url| url.path().ends_with(needle))
        .count()
}

async fn restore(n: &Native, name: &str, reference: &str, audit: bool) -> (bool, String, PathBuf) {
    let dir = consumer(n, name, reference, audit);
    let root = n.dir.path().to_owned();
    let (ok, log) = dotnet(
        &dir,
        &root,
        &["restore", "--no-cache", "--force", "-v", "n"],
    )
    .await;
    (ok, log, dir)
}

async fn eligible_flow(service: bool) {
    need_dotnet!();
    let n = start_in(service).await;
    let packages = n.dir.path().join("packages");
    // A floating version takes the best allowed one: 1.1.0 is held, so the firewall's list has only 1.0.0.
    let (ok, log, dir) = restore(
        &n,
        "float",
        r#"<PackageReference Include="Demo.Pkg" Version="*" />"#,
        true,
    )
    .await;
    assert!(
        ok,
        "dotnet restore of a floating version (service={service}): {log}"
    );
    let assets = std::fs::read_to_string(dir.join("obj/project.assets.json")).unwrap();
    assert!(
        assets.contains("demo.pkg/1.0.0") && !assets.contains("demo.pkg/1.1.0"),
        "{assets}"
    );
    // The eligible package is really unpacked (verified by dotnet itself) and nothing of the held one was fetched.
    assert!(
        packages.join("demo.pkg/1.0.0/Demo.Pkg.nuspec").exists()
            || packages.join("demo.pkg/1.0.0/demo.pkg.nuspec").exists(),
        "{log}"
    );
    assert_eq!(
        fetched(&n, "/1.0.0/demo.pkg.1.0.0.nupkg"),
        1,
        "the eligible package came through the firewall, once"
    );
    assert_eq!(
        fetched(&n, "/1.1.0/demo.pkg.1.1.0.nupkg") + fetched(&n, "/1.1.0/demo.pkg.nuspec"),
        0,
        "the held version's files were never requested"
    );
    // Audit data is advertised over plain http as well: with NuGetAudit on, the real client asks the vulnerability
    // resource through the firewall, which reads the registry's documents (the restore is unaffected).
    assert!(
        fetched(&n, "/v3/vulnerabilities/index.json") >= 1,
        "NuGetAudit asked for the vulnerability index: {:?}",
        n.registry.calls()
    );
    // The real client reads registration through the firewall (`--outdated`): every link in it is a route here, the held
    // version is never offered, and no catalog entry of the registry is ever asked for.
    let (ok, log) = dotnet(&dir, n.dir.path(), &["list", "package", "--outdated"]).await;
    assert!(
        ok && !log.contains("1.1.0"),
        "dotnet list package --outdated (service={service}): {log}"
    );
    assert!(
        fetched(&n, "/v3/registration5-gz-semver2/demo.pkg/index.json") >= 1,
        "registration was read"
    );
    assert_eq!(
        n.registry
            .calls()
            .iter()
            .filter(|u| u.path().contains("catalog0"))
            .count(),
        0,
        "no catalog entry was followed"
    );
    // An exact reference to the eligible version restores from the same source; another package restores too.
    let (ok, log, _) = restore(
        &n,
        "exact",
        r#"<PackageReference Include="Other.Pkg" Version="2.0.0" />"#,
        false,
    )
    .await;
    assert!(
        ok,
        "dotnet restore of an exact version (service={service}): {log}"
    );
    n.server.shutdown().await;
}

#[tokio::test]
async fn native_dotnet_restores_the_eligible_version_and_a_floating_version_picks_it() {
    eligible_flow(false).await;
}

#[tokio::test]
async fn native_dotnet_restores_the_eligible_version_through_the_shared_service() {
    eligible_flow(true).await;
}

#[tokio::test]
async fn native_dotnet_cannot_pin_a_version_the_firewall_withholds() {
    need_dotnet!();
    let n = start_in(false).await;
    let (ok, log, _) = restore(
        &n,
        "pin",
        r#"<PackageReference Include="Demo.Pkg" Version="1.1.0" />"#,
        false,
    )
    .await;
    assert!(
        !ok,
        "an exact pin of the young version must not restore: {log}"
    );
    assert!(
        log.contains("1.1.0")
            && (log.contains("NU1102") || log.contains("403") || log.contains("Forbidden")),
        "{log}"
    );
    assert!(!n.dir.path().join("packages/demo.pkg/1.1.0").exists());
    assert_eq!(
        fetched(&n, "/1.1.0/demo.pkg.1.1.0.nupkg") + fetched(&n, "/1.1.0/demo.pkg.nuspec"),
        0
    );
    n.server.shutdown().await;
}

/// What `dotnet` sends on a plain read is on the allow-list of LS-F4, so reads from the native client stay
/// cache-eligible (an unlisted header would cost hits, never safety).
#[tokio::test]
async fn dotnet_native_client_sends_only_allow_listed_headers() {
    need_dotnet!();
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
    std::fs::write(project.join("app.csproj"), r#"<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Demo.Pkg" Version="1.0.0" /></ItemGroup></Project>"#).unwrap();
    std::fs::write(project.join("nuget.config"), format!(r#"<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /><add key="tap" value="http://127.0.0.1:{port}/nuget/v3/index.json" protocolVersion="3" allowInsecureConnections="true" /></packageSources></configuration>"#)).unwrap();
    let (ok, _) = dotnet(&project, dir.path(), &["restore", "--no-cache", "--force"]).await;
    assert!(!ok, "the tap answers 404 to everything");
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "dotnet reached the tap");
    let mut names: Vec<String> = seen
        .iter()
        .flat_map(|(_, headers)| headers.keys().map(|k| k.as_str().to_owned()))
        .collect();
    names.sort();
    names.dedup();
    eprintln!("dotnet sends these header names on a plain read: {names:?}");
    for (uri, headers) in seen.iter() {
        let class = classify_read(
            &RequestParts {
                uri,
                headers,
                extra_pseudo_headers: &[],
            },
            &FamilyReadRules::NUGET,
        );
        assert!(
            matches!(class, ReadClass::CacheEligible(_)),
            "a native client header is off the allow-list: {uri} {headers:?}"
        );
    }
}

/// R1 with the real client: a 6,000-version project (past the 5,000 reference rows made at refresh) whose registration is
/// linked pages. The oldest version restores by exact pin, a floating version takes the newest allowed one (the ten
/// young versions wait), and `list package --outdated` reads this firewall's re-linked pages.
#[tokio::test]
async fn native_dotnet_restores_the_oldest_version_of_a_project_with_thousands_of_versions() {
    need_dotnet!();
    let n = start_in(false).await;
    let count = 6000usize;
    let versions: Vec<String> = (0..count).map(|k| format!("1.0.{k}")).collect();
    let names: Vec<&str> = versions.iter().map(String::as_str).collect();
    n.registry.answer(
        &format!("{FLAT}big.pkg/index.json"),
        FakeAnswer::Body(flat_index(&names)),
    );
    let leaves: Vec<serde_json::Value> = versions
        .iter()
        .enumerate()
        .map(|(k, v)| {
            leaf(
                "big.pkg",
                v,
                Some(if k >= count - 10 { YOUNG } else { OLD }),
                true,
            )
        })
        .collect();
    let groups: Vec<Vec<serde_json::Value>> = leaves
        .chunks(64)
        .map(<[serde_json::Value]>::to_vec)
        .collect();
    let (index, linked) = registration("big.pkg", &groups, &(0..groups.len()).collect::<Vec<_>>());
    n.registry
        .answer(&format!("{REG}big.pkg/index.json"), FakeAnswer::Body(index));
    for (path, document) in linked {
        n.registry.answer(&path, FakeAnswer::Body(document));
    }
    for version in ["1.0.0", "1.0.5989"] {
        n.registry.answer(
            &format!("{FLAT}big.pkg/{version}/big.pkg.{version}.nupkg"),
            FakeAnswer::Bytes(nuget::nupkg("big.pkg", version)),
        );
        n.registry.answer(
            &format!("{FLAT}big.pkg/{version}/big.pkg.nuspec"),
            FakeAnswer::Body(nuget::nuspec("big.pkg", version)),
        );
    }
    let (ok, log, dir) = restore(
        &n,
        "oldest",
        r#"<PackageReference Include="Big.Pkg" Version="[1.0.0]" />"#,
        false,
    )
    .await;
    assert!(
        ok,
        "an exact pin of the oldest of 6,000 versions restores: {log}"
    );
    assert!(
        n.dir.path().join("packages/big.pkg/1.0.0").exists(),
        "{log}"
    );
    let (ok, log) = dotnet(&dir, n.dir.path(), &["list", "package", "--outdated"]).await;
    assert!(
        ok && log.contains("1.0.5989") && !log.contains("1.0.5999"),
        "the newest allowed version is the latest the client sees through the pages: {log}"
    );
    let (ok, log, dir) = restore(
        &n,
        "float",
        r#"<PackageReference Include="Big.Pkg" Version="*" />"#,
        false,
    )
    .await;
    assert!(ok, "{log}");
    let assets = std::fs::read_to_string(dir.join("obj/project.assets.json")).unwrap();
    assert!(
        assets.contains("big.pkg/1.0.5989") && !assets.contains("big.pkg/1.0.5990"),
        "a floating version takes the newest allowed one"
    );
    n.server.shutdown().await;
}
