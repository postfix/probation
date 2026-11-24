//! Row 24: the REAL native client (the host's `podman`, whose registry client is the one containerd-adjacent tools such as skopeo and
//! buildah share) against the firewall on a real TCP port, with the real transport. The registry is a real HTTP server that speaks the
//! distribution protocol: `/v2/` answers a Bearer challenge for a token service on its own origin, a blob answers a 307 to a signed
//! URL on another origin (the storage host), and the image is the REAL tiny image of tests/e2e/fixtures/oci (a gzip layer whose
//! `diff_id` the engine verifies). A host without `podman` skips loudly (the lane did NOT run).
//!
//! Row 25: the same three tests run against a REAL Docker Engine daemon with `PROBATION_OCI_ENGINE=docker`. That mode never skips:
//! the daemon must be Docker Engine exactly 29.9.2 (not a podman front end), or the lane fails. The CI job that sets it installs
//! the pinned engine (tests/e2e/native/docker-engine.sh, `.github/workflows/native-service.yml`). `docker pull 127.0.0.1:<port>/..`
//! reaches the firewall over plain HTTP because the engine treats loopback registries as insecure by default.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use common::{TestClock, TestServer, fake_origins, sample_config};
use probation::upstream::{OriginSet, ReqwestTransport, Transport};
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const DAY: i64 = 86_400;

/// The pinned Docker Engine of the native OCI lane (03-program-design.md, "Exact native test baseline").
const DOCKER_ENGINE: &str = "29.9.2";

fn docker_mode() -> bool {
    std::env::var("PROBATION_OCI_ENGINE").is_ok_and(|value| value == "docker")
}

/// `docker version` fields of the daemon this lane would use, or why there is none.
fn docker_server(format: &str) -> Result<String, String> {
    let output = std::process::Command::new("docker").args(["version", "--format", format]).output().map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Docker mode: the daemon is Docker Engine at the pinned version, or the lane FAILS. Podman mode: skip loudly without podman.
fn engine_ready() -> bool {
    if docker_mode() {
        let version = docker_server("{{.Server.Version}}").unwrap_or_else(|err| panic!("PROBATION_OCI_ENGINE=docker but no Docker Engine daemon answers: {err}"));
        let platform = docker_server("{{.Server.Platform.Name}}").unwrap_or_default();
        assert_eq!(version, DOCKER_ENGINE, "the pinned Docker Engine is {DOCKER_ENGINE}; this daemon is {version} ({platform})");
        assert!(platform.contains("Docker Engine"), "a real Docker Engine daemon, not a front end for another runtime: {platform:?}");
        return true;
    }
    let found = std::process::Command::new("podman").arg("--version").output().is_ok_and(|output| output.status.success());
    if !found {
        eprintln!("SKIPPED: no podman on this host; the native OCI lane did NOT run");
    }
    found
}

macro_rules! need_podman {
    () => {
        if !engine_ready() {
            return;
        }
    };
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/fixtures/oci").join(name)).expect("the fixture")
}

fn digest_of(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

type Seen = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

#[derive(Clone, Default)]
struct Registry {
    /// (path, authorization) of every request to the registry and to the storage host.
    seen: Seen,
    blobs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    manifests: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    storage: Arc<Mutex<String>>,
    origin: Arc<Mutex<String>>,
}

impl Registry {
    fn note(&self, who: &str, path: String, headers: &HeaderMap) {
        let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_owned);
        self.seen.lock().unwrap().push((who.to_owned(), path, auth));
    }
    fn requests(&self, who: &str) -> Vec<(String, Option<String>)> {
        self.seen.lock().unwrap().iter().filter(|(w, ..)| w == who).map(|(_, p, a)| (p.clone(), a.clone())).collect()
    }
}

async fn ping(State(r): State<Registry>, headers: HeaderMap) -> Response {
    r.note("registry", "/v2/".into(), &headers);
    unauthorised(&r, &headers).unwrap_or_else(|| (StatusCode::OK, [("docker-distribution-api-version", "registry/2.0")], "{}").into_response())
}

fn unauthorised(r: &Registry, headers: &HeaderMap) -> Option<Response> {
    let ok = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).is_some_and(|v| v == "Bearer registry-token");
    (!ok).then(|| (StatusCode::UNAUTHORIZED, [("www-authenticate", format!("Bearer realm=\"{}/token\",service=\"fake-registry\"", r.origin.lock().unwrap()))], "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}").into_response())
}

async fn token(State(r): State<Registry>, headers: HeaderMap) -> Response {
    r.note("registry", "/token".into(), &headers);
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], "{\"token\":\"registry-token\",\"expires_in\":300}").into_response()
}

async fn manifest(State(r): State<Registry>, UrlPath((name, reference)): UrlPath<(String, String)>, headers: HeaderMap) -> Response {
    r.note("registry", format!("/v2/{name}/manifests/{reference}"), &headers);
    if let Some(refusal) = unauthorised(&r, &headers) {
        return refusal;
    }
    match r.manifests.lock().unwrap().get(&reference).cloned() {
        Some(body) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/vnd.oci.image.manifest.v1+json".to_owned()), ("docker-content-digest".parse().unwrap(), digest_of(&body))], body).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn blob(State(r): State<Registry>, UrlPath((name, digest)): UrlPath<(String, String)>, headers: HeaderMap) -> Response {
    r.note("registry", format!("/v2/{name}/blobs/{digest}"), &headers);
    if let Some(refusal) = unauthorised(&r, &headers) {
        return refusal;
    }
    if r.blobs.lock().unwrap().contains_key(&digest) {
        let location = format!("{}/signed/{digest}?X-Signature=abc", r.storage.lock().unwrap());
        return (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, location)]).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn stored(State(r): State<Registry>, UrlPath(digest): UrlPath<String>, headers: HeaderMap) -> Response {
    r.note("storage", format!("/signed/{digest}"), &headers);
    match r.blobs.lock().unwrap().get(&digest).cloned() {
        Some(body) => (StatusCode::OK, body).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    url
}

/// Docker mode: the daemon is long-lived and shares layer content between images, so a test that pulled leaves its layers for the
/// next one, whose pull would then fetch no blob and prove nothing about the storage host. Every reference a lane pulled is
/// removed when the lane ends (only those references: nothing else on the daemon is touched).
#[derive(Default)]
struct DockerForget(Arc<Mutex<Vec<String>>>);

impl Drop for DockerForget {
    fn drop(&mut self) {
        for reference in self.0.lock().unwrap().iter() {
            let _ = std::process::Command::new("docker").args(["image", "rm", "--force", reference]).output();
        }
    }
}

struct Lane {
    forget: DockerForget,
    firewall: TestServer,
    registry: Registry,
    clock: Arc<TestClock>,
    _cleanup: Cleanup,
    scratch: tempfile::TempDir,
    old: String,
}

async fn lane() -> Lane {
    lane_with("").await
}

async fn lane_with(blocked: &str) -> Lane {
    let registry = Registry::default();
    let storage_url = serve(Router::new().route("/signed/{digest}", get(stored)).with_state(registry.clone())).await;
    let registry_url = serve(Router::new().route("/v2/", get(ping)).route("/token", get(token)).route("/v2/{*rest}", get(dispatch)).with_state(registry.clone())).await;
    *registry.storage.lock().unwrap() = storage_url.clone();
    *registry.origin.lock().unwrap() = registry_url.clone();
    let mut digests = Vec::new();
    for n in ["hello-1", "hello-2"] {
        let manifest_bytes = fixture(&format!("{n}-manifest"));
        let (config, layer) = (fixture(&format!("{n}-config")), fixture(&format!("{n}-layer")));
        let mut blobs = registry.blobs.lock().unwrap();
        blobs.insert(digest_of(&config), config);
        blobs.insert(digest_of(&layer), layer);
        let digest = digest_of(&manifest_bytes);
        let mut manifests = registry.manifests.lock().unwrap();
        manifests.insert(digest.clone(), manifest_bytes.clone());
        if n == "hello-1" {
            manifests.insert("old".into(), manifest_bytes);
        } else {
            manifests.insert("young".into(), manifest_bytes);
        }
        digests.push(digest);
    }
    let origins: OriginSet = fake_origins().with_oci(Url::parse(&registry_url).unwrap(), Url::parse(&storage_url).unwrap());
    let transport: Arc<dyn Transport> = Arc::new(ReqwestTransport::for_origins(origins.clone()));
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(&blocklist, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked)).unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist;
    config.cooldown_seconds = 7 * 86_400;
    let clock = TestClock::at_rfc3339(NOW);
    let firewall = TestServer::start_with_upstream(config, clock.shared(), transport, origins).await;
    // The engine's storage lives on disk beside the project, never in the RAM-backed temp directory.
    let base = scratch_base(std::env::var_os("PROBATION_OCI_RUNROOT"));
    std::fs::create_dir_all(&base).unwrap();
    let scratch = tempfile::tempdir_in(base).unwrap();
    let _cleanup = Cleanup(scratch.path().to_path_buf());
    Lane { forget: DockerForget::default(), firewall, registry, clock, _cleanup, scratch, old: digests[0].clone() }
}

/// Where the engine's storage goes: `PROBATION_OCI_RUNROOT` when set and non-empty (the hosted runner sets a short path under its temp
/// directory), else `.probation-scratch/native-oci` beside the project.
fn scratch_base(override_dir: Option<std::ffi::OsString>) -> std::path::PathBuf {
    match override_dir.filter(|dir| !dir.is_empty()) {
        Some(dir) => dir.into(),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(".probation-scratch").join("native-oci"),
    }
}

async fn dispatch(State(r): State<Registry>, UrlPath(rest): UrlPath<String>, headers: HeaderMap) -> Response {
    let parts: Vec<&str> = rest.split('/').collect();
    let n = parts.len();
    if n >= 3 && parts[n - 2] == "manifests" {
        return manifest(State(r), UrlPath((parts[..n - 2].join("/"), parts[n - 1].to_owned())), headers).await;
    }
    if n >= 3 && parts[n - 2] == "blobs" {
        return blob(State(r), UrlPath((parts[..n - 2].join("/"), parts[n - 1].to_owned())), headers).await;
    }
    StatusCode::NOT_FOUND.into_response()
}

/// The engine's storage holds files of a sub-uid the test user cannot delete: `podman unshare` removes them (nothing is left on disk).
struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new("podman").args(["unshare", "rm", "-rf"]).arg(&self.0).status();
    }
}

impl Lane {
    /// `docker <args>` against the pinned daemon. The podman spellings the tests use are translated: the engine verifies TLS the
    /// way it always does (loopback is insecure by default), and `Digest` is spelled through `RepoDigests`.
    async fn docker(&self, args: &[&str]) -> (bool, String) {
        let args: Vec<String> = args
            .iter()
            .filter(|arg| **arg != "--tls-verify=false")
            .map(|arg| if arg.contains("{{.Digest}}") { "{{range .RepoDigests}}{{.}} {{end}}{{.Os}} {{.Architecture}}".to_owned() } else { (*arg).to_owned() })
            .collect();
        if args.first().is_some_and(|verb| verb == "pull") {
            self.forget.0.lock().unwrap().push(args.last().expect("a reference").clone());
        }
        tokio::task::spawn_blocking(move || {
            let output = std::process::Command::new("docker").args(&args).output().expect("docker runs");
            (output.status.success(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
        })
        .await
        .unwrap()
    }

    /// `podman <args>` with a private storage root on disk; returns (success, everything it printed).
    async fn podman(&self, args: &[&str]) -> (bool, String) {
        if docker_mode() {
            return self.docker(args).await;
        }
        let root = self.scratch.path().join("root");
        let run = self.scratch.path().join("run");
        let (args, root, run) = (args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(), root, run);
        tokio::task::spawn_blocking(move || {
            let output = std::process::Command::new("podman")
                .args(["--root", root.to_str().unwrap(), "--runroot", run.to_str().unwrap(), "--storage-driver", "vfs"])
                .args(&args)
                .env("XDG_RUNTIME_DIR", std::env::var("XDG_RUNTIME_DIR").unwrap_or_default())
                .output()
                .expect("podman runs");
            (output.status.success(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
        })
        .await
        .unwrap()
    }

    fn reference(&self, what: &str) -> String {
        format!("{}/team/hello{what}", self.firewall.local_addr())
    }
}

/// A young image is held (403) and the engine's pull fails before any blob is asked of the registry; once it has aged, the REAL engine
/// pulls it through the token flow and the blob redirect and its stored manifest digest is the registry's.
#[tokio::test]
async fn a_real_podman_pull_waits_for_the_cooldown_then_succeeds_through_the_token_flow_and_the_blob_redirect() {
    need_podman!();
    let lane = lane().await;
    let (ok, output) = lane.podman(&["pull", "--tls-verify=false", &lane.reference(":old")]).await;
    assert!(!ok, "a young image is held: {output}");
    assert!(output.contains("denied") || output.contains("403") || output.to_lowercase().contains("forbidden"), "{output}");
    assert!(lane.registry.requests("registry").iter().all(|(path, _)| !path.contains("/blobs/")), "no blob was asked for: {:?}", lane.registry.requests("registry"));
    lane.clock.advance_seconds(8 * DAY);
    let (ok, output) = lane.podman(&["pull", "--tls-verify=false", &lane.reference(":old")]).await;
    assert!(ok, "{output}");
    let (ok, inspected) = lane.podman(&["image", "inspect", "--format", "{{.Digest}} {{.Os}} {{.Architecture}}", &lane.reference(":old")]).await;
    assert!(ok && inspected.contains(&lane.old) && inspected.contains("linux"), "{inspected}");
    // The registry saw tokens, the storage host saw none, and the firewall asked nobody else.
    let at_registry = lane.registry.requests("registry");
    assert!(at_registry.iter().any(|(path, _)| path == "/token"), "{at_registry:?}");
    assert!(at_registry.iter().filter(|(path, _)| path != "/token" && path != "/v2/").all(|(_, auth)| auth.as_deref() == Some("Bearer registry-token")), "{at_registry:?}");
    let at_storage = lane.registry.requests("storage");
    assert!(!at_storage.is_empty() && at_storage.iter().all(|(_, auth)| auth.is_none()), "the storage host never saw a credential: {at_storage:?}");
    // The young one is a different digest with its own age, still held.
    let (ok, output) = lane.podman(&["pull", "--tls-verify=false", &lane.reference(":young")]).await;
    assert!(!ok && output.contains("denied"), "a digest first seen now waits its own cooldown: {output}");
    lane.clock.advance_seconds(8 * DAY);
    let (ok, output) = lane.podman(&["pull", "--tls-verify=false", &lane.reference(":young")]).await;
    assert!(ok, "{output}");
    lane.firewall.shutdown().await;
}

/// The digest pull: the engine asks for the manifest by digest, the firewall verifies the bytes against it and serves them.
#[tokio::test]
async fn a_real_podman_pull_by_digest_is_verified_and_served_once_aged() {
    need_podman!();
    let lane = lane().await;
    lane.clock.advance_seconds(0);
    let by_digest = format!("{}/team/hello@{}", lane.firewall.local_addr(), lane.old);
    let (ok, _) = lane.podman(&["pull", "--tls-verify=false", &by_digest]).await;
    assert!(!ok, "first seen now: held");
    lane.clock.advance_seconds(8 * DAY);
    let (ok, output) = lane.podman(&["pull", "--tls-verify=false", &by_digest]).await;
    assert!(ok, "{output}");
    lane.firewall.shutdown().await;
}

/// A block (a repository, or one tag) refuses the real engine's pull before the registry is asked anything.
#[tokio::test]
async fn a_real_podman_pull_of_a_blocked_repository_or_tag_is_refused_before_the_registry_is_asked() {
    need_podman!();
    let lane = lane_with(r#"{"ecosystem":"oci","name":"team/evil","version":null,"reason":"malware"},{"ecosystem":"oci","name":"team/hello","version":"old","reason":"malware"}"#).await;
    for reference in [format!("{}/team/evil:latest", lane.firewall.local_addr()), lane.reference(":old")] {
        let (ok, output) = lane.podman(&["pull", "--tls-verify=false", &reference]).await;
        assert!(!ok && output.contains("denied"), "{reference}: {output}");
    }
    assert!(lane.registry.requests("registry").is_empty(), "nothing was asked: {:?}", lane.registry.requests("registry"));
    lane.firewall.shutdown().await;
}

/// Docker mode only: the witness that the daemon the other tests pull through is the pinned Docker Engine (its version, platform and
/// API are recorded in the test output). Without `PROBATION_OCI_ENGINE=docker` it records that the Docker lane did NOT run.
#[test]
fn the_docker_lane_runs_against_the_pinned_engine_daemon() {
    if !docker_mode() {
        eprintln!("NOT SELECTED: PROBATION_OCI_ENGINE is not docker, so this run used podman and the Docker Engine {DOCKER_ENGINE} lane did NOT run");
        return;
    }
    assert!(engine_ready());
    let record = docker_server("version {{.Server.Version}}, api {{.Server.APIVersion}}, platform {{.Server.Platform.Name}}, os/arch {{.Server.Os}}/{{.Server.Arch}}").expect("the daemon answers");
    eprintln!("DOCKER ENGINE WITNESS: {record}");
    assert!(record.contains(&format!("version {DOCKER_ENGINE}")), "{record}");
}

/// podman refuses a runroot longer than 50 characters. The default scratch base (beside the project, never in the RAM-backed /tmp) is too
/// long on a hosted runner, where the workspace sits deep under /home/runner/work, so PROBATION_OCI_RUNROOT names a short base instead.
#[test]
fn the_engine_storage_base_honours_a_short_override_and_keeps_the_default() {
    let short = scratch_base(Some("/home/runner/work/_temp/oci".into()));
    assert_eq!(short, Path::new("/home/runner/work/_temp/oci"));
    // a base plus tempfile's `.tmpXXXXXX` directory plus `/run` is what podman gets as --runroot
    assert!(short.join(".tmpAbCdEf/run").to_str().unwrap().len() <= 50, "{short:?}");
    assert!(scratch_base(None).ends_with(".probation-scratch/native-oci"));
    assert!(scratch_base(Some("".into())).ends_with(".probation-scratch/native-oci"), "an empty override is no override");
}
