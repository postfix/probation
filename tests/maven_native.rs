//! Row 21: the real native client (`mvn` 3.9.16 on Java 21.0.12.1, from the pinned client image the E2E stack also uses) against
//! the firewall on a real TCP port, with real jars and the documents Maven Central writes. Only the upstream is an in-process
//! fake. The client runs in a container with host networking and the plugins its goals need already in the image
//! (`tests/e2e/compose/clients/maven.Dockerfile`: fetched at image build time, never at test time). A host without `podman` or
//! without that image skips loudly (the lane did NOT run).

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Uri};
use common::maven::{self, PUBLISH, REPO, at, http_date, metadata, serve_version};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};
use probation::upstream::{OriginSet, Transport};
use url::Url;

const IMAGE: &str = "localhost/probation-e2e-client:maven3.9.16";
const NOW: &str = "2026-04-06T12:00:00Z";
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

/// Row 25: `PROBATION_NATIVE_HOST=1` drives the host's own `mvn` (pinned 3.9.16 on Java 21) instead of the podman image, with the plugin
/// repository seeded in `PROBATION_MAVEN_SEED` by the CI job (provisioning, never at test time). It never skips: the tool must be the
/// pinned one, or the lane fails. The mirror and the firewall are plain HTTP on loopback, so no truststore needs a CA on any OS.
fn host_mode() -> bool {
    std::env::var("PROBATION_NATIVE_HOST").is_ok_and(|value| value == "1")
}

fn host_tool_ready() -> bool {
    // Through bash: Maven ships mvn.cmd on Windows, which Command::new("mvn") (mvn.exe only) cannot find. An explicit child PATH is searched first,
    // so the lane's Git bash wins over System32's WSL launcher.
    let output = std::process::Command::new("bash")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .args(["-c", "mvn --version"])
        .output()
        .unwrap_or_else(|err| panic!("PROBATION_NATIVE_HOST=1 but mvn does not run: {err}"));
    let version = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        version.contains("Apache Maven 3.9.16") && version.contains("Java version: 21."),
        "the pinned toolchain is Maven 3.9.16 on Java 21; the host has: {version}"
    );
    assert!(
        std::env::var("PROBATION_MAVEN_SEED").is_ok(),
        "PROBATION_MAVEN_SEED names the seeded plugin repository"
    );
    true
}

fn client_available() -> bool {
    if host_mode() {
        return host_tool_ready();
    }
    std::process::Command::new("podman")
        .args(["image", "exists", IMAGE])
        .status()
        .is_ok_and(|status| status.success())
}

macro_rules! need_mvn {
    () => {
        if !client_available() {
            // PROBATION_NATIVE_STRICT=1 (set by the CI jobs that own this lane) turns a skip into a failure: a lane that did not run must not report `3 passed`.
            assert!(std::env::var_os("PROBATION_NATIVE_STRICT").is_none(), "the native Maven lane did NOT run: no podman or no {IMAGE} (PROBATION_NATIVE_STRICT is set)");
            eprintln!("SKIPPED: no podman or no {IMAGE} on this host; the native Maven lane did NOT run");
            return;
        }
    };
}

/// Runs `script` in the client container in `dir` (mounted as `/work`), with its own home and local repository seeded with the
/// plugins from the image; returns whether it succeeded and everything it printed.
async fn mvn(dir: &Path, script: &str) -> (bool, String) {
    if host_mode() {
        let here = dir.display().to_string().replace('\\', "/");
        let seed = std::env::var("PROBATION_MAVEN_SEED")
            .unwrap()
            .replace('\\', "/");
        let script = format!(
            "trap 'kill $(jobs -p) 2>/dev/null' EXIT; export HOME={here}/home; rm -rf {here}/.m2repo {here}/out; mkdir -p {here}/.m2repo {here}/home && cp -r {seed}/. {here}/.m2repo/ && {}",
            script.replace("/work", &here)
        );
        let dir = dir.to_path_buf();
        return tokio::task::spawn_blocking(move || {
            let output = std::process::Command::new("bash")
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .current_dir(&dir)
                .args(["-c", &script])
                .output()
                .expect("bash runs the host mvn");
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
        .unwrap();
    }
    let dir = dir.to_path_buf();
    let script = format!(
        "export HOME=/work/home; rm -rf /work/.m2repo /work/out; mkdir -p /work/.m2repo /work/home && cp -r /opt/seed-m2/. /work/.m2repo/ && {script}"
    );
    tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new("podman")
            .args(["run", "--rm", "--network=host", "--userns=keep-id", "-v"])
            .arg(format!("{}:/work:Z", dir.display()))
            .args(["-w", "/work", "--entrypoint", "sh", IMAGE, "-c", &script])
            .output()
            .expect("podman runs the pinned client");
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

const COPY: &str = "mvn -B -s settings.xml -Dmaven.repo.local=/work/.m2repo org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies -DoutputDirectory=/work/out && ls /work/out";

fn project(dependencies: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>e2e</groupId><artifactId>app</artifactId><version>1</version><packaging>pom</packaging><repositories><repository><id>snaps</id><url>https://central.invalid/</url><snapshots><enabled>true</enabled></snapshots></repository></repositories><dependencies>{dependencies}</dependencies></project>"
    )
}

fn dependency(artifact: &str, version: &str) -> String {
    format!(
        "<dependency><groupId>org.demo</groupId><artifactId>{artifact}</artifactId><version>{version}</version></dependency>"
    )
}

fn settings(port: u16) -> String {
    format!(
        "<settings><mirrors><mirror><id>probation</id><mirrorOf>*</mirrorOf><url>http://127.0.0.1:{port}/maven/</url></mirror></mirrors></settings>"
    )
}

struct Native {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    dir: tempfile::TempDir,
    port: u16,
}

async fn start() -> Native {
    let dir = tempfile::tempdir().unwrap();
    let registry = FakeRegistry::new();
    registry.answer(
        &at("org/demo/lib/maven-metadata.xml"),
        FakeAnswer::Body(metadata(
            "org.demo",
            "lib",
            "2.0",
            "2.0",
            &["1.0", "1.1", "2.0"],
        )),
    );
    serve_version(&registry, "org.demo", "lib", "1.0", Some(OLD));
    serve_version(&registry, "org.demo", "lib", "1.1", Some(OLD));
    serve_version(&registry, "org.demo", "lib", "2.0", Some(YOUNG));
    let builds = ["20250101.120000-1", "20260405.120000-2"];
    registry.answer(
        &at("org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml"),
        FakeAnswer::Body(maven::snapshot_metadata(
            "org.demo",
            "snap",
            "1.0-SNAPSHOT",
            &builds,
        )),
    );
    registry.answer(
        &at("org/demo/snap/maven-metadata.xml"),
        FakeAnswer::Body(metadata(
            "org.demo",
            "snap",
            "1.0-SNAPSHOT",
            "",
            &["1.0-SNAPSHOT"],
        )),
    );
    for (build, date) in [(builds[0], OLD), (builds[1], YOUNG)] {
        let file = format!("snap-1.0-{build}");
        registry.answer(
            &at(&format!("org/demo/snap/1.0-SNAPSHOT/{file}.pom")),
            FakeAnswer::Dated {
                body: maven::pom("org.demo", "snap", "1.0-SNAPSHOT").into_bytes(),
                last_modified: http_date(date),
            },
        );
        registry.answer(
            &at(&format!("org/demo/snap/1.0-SNAPSHOT/{file}.jar")),
            FakeAnswer::Dated {
                body: maven::jar("snap", build),
                last_modified: http_date(date),
            },
        );
    }
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
    let origins: OriginSet =
        fake_origins().with_maven(Url::parse(REPO).unwrap(), Url::parse(PUBLISH).unwrap());
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        origins,
    )
    .await;
    std::fs::create_dir_all(dir.path().join("app")).unwrap();
    Native {
        server,
        registry,
        dir,
        port,
    }
}

fn write_project(n: &Native, dependencies: &str) -> std::path::PathBuf {
    let app = n.dir.path().join("app");
    std::fs::write(app.join("pom.xml"), project(dependencies)).unwrap();
    std::fs::write(app.join("settings.xml"), settings(n.port)).unwrap();
    app
}

#[tokio::test]
async fn native_mvn_takes_the_newest_allowed_version_of_a_range_and_the_pin_of_a_held_one_fails() {
    need_mvn!();
    let n = start().await;
    let app = write_project(&n, &dependency("lib", "[1.0,3.0)"));
    let (ok, output) = mvn(&app, COPY).await;
    assert!(ok, "{output}");
    assert!(
        output.contains("lib-1.1.jar") && !output.contains("lib-2.0.jar"),
        "{output}"
    );
    assert_eq!(
        std::fs::read(app.join("out/lib-1.1.jar")).unwrap(),
        maven::jar("lib", "1.1"),
        "the jar mvn copied is the repository's, exactly"
    );
    let held = write_project(&n, &dependency("lib", "2.0"));
    let (ok, output) = mvn(&held, COPY).await;
    assert!(
        !ok && (output.contains("403") || output.contains("Forbidden")),
        "the exact pin of the held version fails: {output}"
    );
    assert!(
        !n.registry
            .calls()
            .iter()
            .any(|url| url.path().ends_with("lib-2.0.jar")),
        "the held jar was never fetched"
    );
    n.server.shutdown().await;
}

#[tokio::test]
async fn native_mvn_resolves_a_snapshot_to_the_newest_allowed_build() {
    need_mvn!();
    let n = start().await;
    let app = write_project(&n, &dependency("snap", "1.0-SNAPSHOT"));
    let (ok, output) = mvn(&app, COPY).await;
    assert!(ok, "{output}");
    assert!(
        output.contains("snap-1.0") && !output.contains("20260405"),
        "the held build is never offered: {output}"
    );
    assert!(
        !n.registry
            .calls()
            .iter()
            .any(|url| url.path().contains("20260405.120000-2.jar")),
        "the held build's jar was never fetched"
    );
    n.server.shutdown().await;
}

/// What `mvn` sends on a plain read is on the allow-list of LS-F4, so reads from the native client stay cache-eligible (an
/// unlisted header would cost hits, never safety).
#[tokio::test]
async fn mvn_native_client_sends_only_allow_listed_headers() {
    need_mvn!();
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
    let app_dir = dir.path().join("app");
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::write(
        app_dir.join("pom.xml"),
        project(&dependency("lib", "[1.0,3.0)")),
    )
    .unwrap();
    std::fs::write(app_dir.join("settings.xml"), settings(port)).unwrap();
    let (ok, _) = mvn(&app_dir, COPY).await;
    assert!(!ok, "the tap answers 404 to everything");
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "mvn reached the tap");
    let mut names: Vec<String> = seen
        .iter()
        .flat_map(|(_, headers)| headers.keys().map(|k| k.as_str().to_owned()))
        .collect();
    names.sort();
    names.dedup();
    eprintln!("mvn sends these header names on a plain read: {names:?}");
    for (uri, headers) in seen.iter() {
        let class = classify_read(
            &RequestParts {
                uri,
                headers,
                extra_pseudo_headers: &[],
            },
            &FamilyReadRules::MAVEN,
        );
        assert!(
            matches!(class, ReadClass::CacheEligible(_)),
            "a native client header is off the allow-list: {uri} {headers:?}"
        );
    }
}
