//! Row 23: the real native client (`conan` 2.21.0 on Python 3.13.0, from the pinned client image the E2E stack also uses) against the
//! firewall on a real TCP port. A REAL `conan create` and `conan upload` leave real recipe and package files in a directory (through
//! tests/e2e/fixtures/conan_recorder.py, a recording Conan 2 remote); those files are what the in-process fake upstream serves, with
//! the revision times the test chooses. The client runs in a container with host networking; a host without `podman` or without the
//! image skips loudly (the lane did NOT run).

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Uri};
use common::conan::{REMOTE, PUBLISH, serve_store};
use common::{FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};
use probation::upstream::{OriginSet, Transport};
use url::Url;

const IMAGE: &str = "localhost/probation-e2e-client:conan2.21.0";
const NOW: &str = "2026-04-06T12:00:00Z";
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn client_available() -> bool {
    std::process::Command::new("podman").args(["image", "exists", IMAGE]).status().is_ok_and(|status| status.success())
}

macro_rules! need_conan {
    () => {
        if !client_available() {
            eprintln!("SKIPPED: no podman or no {IMAGE} on this host; the native Conan lane did NOT run");
            return;
        }
    };
}

/// Runs `script` in the client container in `dir` (mounted as `/work`); returns whether it succeeded and everything it printed.
async fn conan(dir: &Path, script: &str) -> (bool, String) {
    let dir = dir.to_path_buf();
    let script = format!("export HOME=/work/home CONAN_HOME=/work/home/.conan2 CONAN_LOGIN_USERNAME=user CONAN_PASSWORD=pass; mkdir -p $HOME; {script}");
    tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new("podman")
            .args(["run", "--rm", "--network=host", "--userns=keep-id", "-v"])
            .arg(format!("{}:/work:Z", dir.display()))
            .args(["-w", "/work", "--entrypoint", "sh", IMAGE, "-c", &script])
            .output()
            .expect("podman runs the pinned client");
        (output.status.success(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
    })
    .await
    .unwrap()
}

const PROFILE: &str = "[settings]\nos=Linux\narch=x86_64\nbuild_type=Release\ncompiler=gcc\ncompiler.version=12\ncompiler.libcxx=libstdc++11\ncompiler.cppstd=17\n";
const RECIPE: &str = "from conan import ConanFile\nfrom conan.tools.files import copy\n\n\nclass HelloConan(ConanFile):\n    name = \"hello\"\n    package_type = \"header-library\"\n    exports_sources = \"include/*\"\n    settings = \"build_type\"\n\n    def package(self):\n        copy(self, \"*.h\", self.source_folder, self.package_folder)\n";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Creates `hello/1.0` (a Release and a Debug binary) and `hello/2.0` (a Release binary) with the real client and uploads them to the
/// recording remote; returns the work directory whose `store` holds what was uploaded.
async fn seed() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("hello/include")).unwrap();
    std::fs::write(dir.path().join("hello/conanfile.py"), RECIPE).unwrap();
    std::fs::write(dir.path().join("hello/include/hello.h"), "#define HELLO 1\n").unwrap();
    std::fs::write(dir.path().join("profile"), PROFILE).unwrap();
    std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/fixtures/conan_recorder.py"), dir.path().join("conan_recorder.py")).unwrap();
    let port = free_port();
    let script = format!(
        "python3 /work/conan_recorder.py {port} /work/store /work/seed.log & sleep 1; \
         conan remote add rec http://127.0.0.1:{port} && conan remote login rec user -p pass && cd /work/hello && \
         conan create . --version=1.0 -pr:h=/work/profile -pr:b=/work/profile >/dev/null && \
         conan create . --version=1.0 -s build_type=Debug -pr:h=/work/profile -pr:b=/work/profile >/dev/null && \
         conan create . --version=2.0 -pr:h=/work/profile -pr:b=/work/profile >/dev/null && \
         conan upload 'hello/*' -r rec --confirm"
    );
    let (ok, output) = conan(dir.path(), &script).await;
    assert!(ok, "seeding with the real client failed: {output}");
    dir
}

/// The pkgid of each binary in the store (a Release and a Debug one of hello/1.0), told apart by what the client wrote in conaninfo.txt.
fn pkgid_of(store: &Path, version: &str, build_type: &str) -> String {
    let mut found = Vec::new();
    for rrev in std::fs::read_dir(store.join(format!("hello/{version}/_/_/revisions"))).unwrap().flatten() {
        let packages = rrev.path().join("packages");
        for pkgid in std::fs::read_dir(&packages).into_iter().flatten().flatten() {
            for prev in std::fs::read_dir(pkgid.path().join("revisions")).unwrap().flatten() {
                let info = std::fs::read_to_string(prev.path().join("conaninfo.txt")).unwrap();
                if info.contains(&format!("build_type={build_type}")) {
                    found.push(pkgid.file_name().to_string_lossy().into_owned());
                }
            }
        }
    }
    assert_eq!(found.len(), 1, "{version} {build_type}: {found:?}");
    found.remove(0)
}

struct Native {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    dir: tempfile::TempDir,
    port: u16,
}

async fn start() -> Native {
    let dir = seed().await;
    let store = dir.path().join("store");
    let debug_binary = pkgid_of(&store, "1.0", "Debug");
    let registry = FakeRegistry::new();
    serve_store(&registry, &store, &|key, pkgid| match (key, pkgid) {
        ("hello/1.0", None) => OLD.to_owned(),
        ("hello/1.0", Some(id)) if id == debug_binary => YOUNG.to_owned(),
        ("hello/1.0", Some(_)) => OLD.to_owned(),
        _ => YOUNG.to_owned(),
    });
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(&blocklist, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "")).unwrap();
    let port = free_port();
    let mut config = sample_config();
    config.blocklist_file = blocklist;
    config.cooldown_seconds = 7 * 86_400;
    config.listen = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    config.public_url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let origins: OriginSet = fake_origins().with_conan(Url::parse(REMOTE).unwrap(), Url::parse(PUBLISH).unwrap());
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339(NOW).shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins).await;
    Native { server, registry, dir, port }
}

fn install(n: &Native, args: &str) -> String {
    format!("rm -rf /work/home/.conan2 /work/out; conan remote add probation http://127.0.0.1:{}/conan && conan remote remove conancenter && conan install {args} -r probation -pr:h=/work/profile -pr:b=/work/profile", n.port)
}

#[tokio::test]
async fn native_conan_takes_the_newest_allowed_version_of_a_range_and_the_pin_of_a_held_one_fails() {
    need_conan!();
    let n = start().await;
    let (ok, output) = conan(n.dir.path(), &install(&n, "--requires='hello/[>=1.0]'")).await;
    assert!(ok, "{output}");
    assert!(output.contains("hello/1.0#") && !output.contains("hello/2.0"), "the range resolves to the allowed version: {output}");
    let cache = n.dir.path().join("home/.conan2/p");
    let header: Vec<_> = walk(&cache).into_iter().filter(|p| p.ends_with("hello.h")).collect();
    assert_eq!(header.len(), 1, "{header:?}");
    assert_eq!(std::fs::read_to_string(&header[0]).unwrap(), "#define HELLO 1\n", "the header the client unpacked is the one it uploaded, exactly");
    assert!(!n.registry.calls().iter().any(|url| url.path().contains("/hello/2.0/") && url.path().contains("/files/")), "no file of the held version was fetched");
    let (ok, output) = conan(n.dir.path(), &install(&n, "--requires=hello/2.0")).await;
    assert!(!ok, "the exact pin of the held version fails: {output}");
    assert!(!n.registry.calls().iter().any(|url| url.path().contains("/hello/2.0/") && url.path().contains("/files/")), "the held recipe was never fetched");
    n.server.shutdown().await;
}

#[tokio::test]
async fn native_conan_finds_no_new_binary_of_an_old_recipe_and_takes_the_old_one() {
    need_conan!();
    let n = start().await;
    // The Release binary of hello/1.0 is old and installs; the Debug binary was uploaded a day ago (a new binary on an old recipe).
    let (ok, output) = conan(n.dir.path(), &install(&n, "--requires=hello/1.0")).await;
    assert!(ok, "{output}");
    let store = n.dir.path().join("store");
    let (debug, release) = (pkgid_of(&store, "1.0", "Debug"), pkgid_of(&store, "1.0", "Release"));
    assert!(output.contains(&release), "the old binary is the one used: {output}");
    let (ok, output) = conan(n.dir.path(), &install(&n, "--requires=hello/1.0 -s build_type=Debug")).await;
    assert!(!ok, "the new binary is held and no other binary is offered: {output}");
    assert!(!n.registry.calls().iter().any(|url| url.path().contains(&debug) && url.path().contains("/files/")), "the held binary's files were never fetched");
    n.server.shutdown().await;
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}

/// What `conan` sends on a plain read is on the allow-list of LS-F4, so reads from the native client stay cache-eligible (an unlisted
/// header would cost hits, never safety).
#[tokio::test]
async fn conan_native_client_sends_only_allow_listed_headers() {
    need_conan!();
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
    std::fs::write(dir.path().join("profile"), PROFILE).unwrap();
    let script = format!("conan remote add tap http://127.0.0.1:{port}/conan && conan remote remove conancenter; conan install --requires='hello/[>=1.0]' -r tap -pr:h=/work/profile -pr:b=/work/profile; conan install --requires=hello/1.0 -r tap -pr:h=/work/profile -pr:b=/work/profile; true");
    let (_, _) = conan(dir.path(), &script).await;
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "conan reached the tap");
    let mut names: Vec<String> = seen.iter().flat_map(|(_, headers)| headers.keys().map(|k| k.as_str().to_owned())).collect();
    names.sort();
    names.dedup();
    eprintln!("conan sends these header names on a plain read: {names:?}");
    for (uri, headers) in seen.iter() {
        let class = classify_read(&RequestParts { uri, headers, extra_pseudo_headers: &[] }, &FamilyReadRules::CONAN);
        assert!(matches!(class, ReadClass::CacheEligible(_)), "a native client header is off the allow-list: {uri} {headers:?}");
    }
}
