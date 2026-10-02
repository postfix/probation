//! Slice 10's witness: a real `npm` client installs through a listening instance.
//!
//! `#[ignore]` by default and run explicitly with
//! `cargo test --test e2e_npm -- --ignored`, because these tests spawn the `npm`
//! binary and are slower than the rest of the suite.
//!
//! **Nothing here reaches the network.** The firewall's upstream is the in-process
//! [`Files`] transport below, and `npm` is pointed at the firewall's own loopback
//! port with a cache directory of its own — so the only sockets involved are the
//! two ends of one loopback connection. The tarballs are built by `npm pack` from a
//! package this test writes, so the bytes `npm` verifies are bytes a real `npm`
//! produced.
//!
//! The clock is the system clock, not [`common::TestClock`]: `npm` runs in real
//! time, so the fixture states its publication times relative to now instead.

mod common;

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use common::TestServer;
use probation::clock::SystemClock;
use probation::config::Config;
use probation::osv::OsvMode;
use probation::upstream::{
    ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, OriginSet, Transport,
    UpstreamError,
};
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use url::Url;

const WIDGET: &str = "fixture-widget";
/// Eligible: published well before the cooldown.
const OLD: &str = "1.0.0";
/// Held: published an hour ago, against a one-day cooldown.
const YOUNG: &str = "1.1.0";
const COOLDOWN_SECONDS: u64 = 86_400;

/// The previous npm major, which SPEC §13 requires alongside the current one.
///
/// Pinned rather than floating: "the previous major" resolves to a different release
/// every few weeks, and a test that silently changes what it exercises is not a
/// record of anything.
const PREVIOUS_NPM_MAJOR: &str = "10.9.9";

/// The current upstream stable major, pinned for the same reason.
///
/// npm 12 defaults `allow-remote` to `none` and exempts only tarballs whose URL
/// shares both the origin *and* the path prefix of the configured registry, which is
/// why artifacts are served under the ecosystem root.
const CURRENT_NPM_MAJOR: &str = "12.0.2";

/// npm 12 declares its supported engines as `^22.22.2 || ^24.15.0 || >=26.0.0`. The
/// Node on `PATH` here is older, and an install refused by a client warning that it
/// does not support this machine is not evidence about the firewall, so the npm 12
/// leg runs under a Node it does support.
const CURRENT_NPM_NODE: &str = "v24.19.0";

// ---------------------------------------------------------------------------
// Which client is under test
// ---------------------------------------------------------------------------

/// One npm binary, with the label its results are reported under.
#[derive(Clone)]
struct Client {
    label: String,
    bin: PathBuf,
    /// A Node installation this client must run under, prepended to `PATH`. `None`
    /// uses whatever Node the environment already provides.
    node_bin: Option<PathBuf>,
}

/// The `npm` on `PATH`. At the time of writing that is 11.16.0.
fn current_npm() -> Client {
    Client {
        label: "current npm (PATH)".to_owned(),
        bin: PathBuf::from("npm"),
        node_bin: None,
    }
}

/// The pinned current major, installed out of tree by the documented setup step and
/// run under the Node it supports.
///
/// Panics with that step rather than skipping, for the same reason as the previous
/// major: a compatibility test that quietly does nothing reports success for a matrix
/// it never ran.
fn current_npm_major() -> Client {
    let bin = previous_clients_root()
        .join(format!("npm-{CURRENT_NPM_MAJOR}"))
        .join("node_modules")
        .join(".bin")
        .join("npm");
    assert!(
        bin.is_file(),
        "npm {CURRENT_NPM_MAJOR} is not installed at {}.\n\
         Install it once with:\n  \
         npm install --prefix {}/npm-{CURRENT_NPM_MAJOR} npm@{CURRENT_NPM_MAJOR}\n\
         (see docs/operations.md §11)",
        bin.display(),
        previous_clients_root().display(),
    );
    let node_bin = supported_node_bin();
    assert!(
        node_bin.join("node").is_file(),
        "Node {CURRENT_NPM_NODE} is not installed at {}.\n\
         npm {CURRENT_NPM_MAJOR} supports ^22.22.2 || ^24.15.0 || >=26.0.0; install it \
         with:\n  nvm install {CURRENT_NPM_NODE}\n\
         or point PROBATION_E2E_NODE_BIN at a supported Node's bin directory \
         (see docs/operations.md §11)",
        node_bin.display(),
    );
    Client {
        label: format!("current npm major ({CURRENT_NPM_MAJOR}) on Node {CURRENT_NPM_NODE}"),
        bin,
        node_bin: Some(node_bin),
    }
}

/// Where a Node npm 12 supports lives. Overridable so a machine that manages Node
/// some other way than nvm does not have to edit this file.
fn supported_node_bin() -> PathBuf {
    if let Ok(bin) = std::env::var("PROBATION_E2E_NODE_BIN") {
        return PathBuf::from(bin);
    }
    PathBuf::from(std::env::var("HOME").expect("HOME is set"))
        .join(".nvm")
        .join("versions")
        .join("node")
        .join(CURRENT_NPM_NODE)
        .join("bin")
}

/// The pinned previous major, installed out of tree by the documented setup step.
///
/// Panics with that step rather than skipping: a client-compatibility test that
/// quietly does nothing when its client is absent reports success for a matrix it
/// never ran, which is the failure mode this whole file exists to avoid.
fn previous_npm_major() -> Client {
    let bin = previous_clients_root()
        .join(format!("npm-{PREVIOUS_NPM_MAJOR}"))
        .join("node_modules")
        .join(".bin")
        .join("npm");
    assert!(
        bin.is_file(),
        "npm {PREVIOUS_NPM_MAJOR} is not installed at {}.\n\
         Install it once with:\n  \
         npm install --prefix {}/npm-{PREVIOUS_NPM_MAJOR} npm@{PREVIOUS_NPM_MAJOR}\n\
         (see docs/operations.md §11)",
        bin.display(),
        previous_clients_root().display(),
    );
    Client {
        label: format!("previous npm major ({PREVIOUS_NPM_MAJOR})"),
        bin,
        node_bin: None,
    }
}

/// Where the out-of-tree pinned clients live. Overridable so a different machine can
/// put them somewhere else without editing this file.
fn previous_clients_root() -> PathBuf {
    if let Ok(root) = std::env::var("PROBATION_E2E_CLIENTS") {
        return PathBuf::from(root);
    }
    PathBuf::from(std::env::var("HOME").expect("HOME is set"))
        .join(".local")
        .join("share")
        .join("probation-e2e-clients")
}

// ---------------------------------------------------------------------------
// The upstream registry: in process, and able to carry binary artifact bodies
// ---------------------------------------------------------------------------

/// A [`Transport`] whose artifact bodies are bytes rather than text.
///
/// `common::FakeRegistry` answers with a `String`, which a real gzipped tarball is
/// not. Everything else about it is the same: it knows only what it was told, and
/// anything else is upstream `404`.
#[derive(Default)]
struct Files {
    metadata: HashMap<String, String>,
    artifacts: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl Transport for Files {
    async fn fetch_metadata(
        &self,
        req: MetadataRequest,
    ) -> Result<MetadataResponse, UpstreamError> {
        match self.metadata.get(req.url.path()) {
            Some(body) => Ok(MetadataResponse::Fresh {
                body: Bytes::from(body.clone()),
                validators: Default::default(),
            }),
            None => Ok(MetadataResponse::Missing),
        }
    }

    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        match self.artifacts.get(req.url.path()) {
            Some(bytes) => {
                let bytes = bytes.clone();
                let declared = bytes.len() as u64;
                Ok(ArtifactBody {
                    declared_length: Some(declared),
                    stream: probation::upstream::capped(
                        Box::pin(futures_util::stream::once(
                            async move { Ok(Bytes::from(bytes)) },
                        )),
                        req.max_bytes,
                    ),
                })
            }
            None => Err(UpstreamError::Status(404)),
        }
    }
}

fn fake_origins() -> OriginSet {
    OriginSet::for_tests(
        Url::parse("https://npm.invalid").expect("a fake npm origin"),
        Url::parse("https://pypi.invalid").expect("a fake pypi origin"),
        Url::parse("https://files.invalid").expect("a fake artifact origin"),
    )
}

// ---------------------------------------------------------------------------
// Building the fixture package with the real `npm pack`
// ---------------------------------------------------------------------------

/// A tarball `npm pack` produced, with the SRI `npm` itself would verify.
struct Tarball {
    filename: String,
    bytes: Vec<u8>,
    integrity: String,
}

/// Packs a one-file package at `version`. The bytes are a real `npm pack` output, so
/// the install path exercises `npm`'s own extraction and integrity check rather than
/// something this test made up.
fn pack(scratch: &Path, version: &str) -> Tarball {
    let source = scratch.join(format!("src-{version}"));
    std::fs::create_dir_all(&source).expect("the package source directory");
    std::fs::write(
        source.join("package.json"),
        json!({
            "name": WIDGET,
            "version": version,
            "description": "A harmless fixture package.",
            "main": "index.js",
            "license": "Apache-2.0",
        })
        .to_string(),
    )
    .expect("the fixture package.json");
    std::fs::write(
        source.join("index.js"),
        format!("module.exports = {{ version: \"{version}\" }};\n"),
    )
    .expect("the fixture module");

    let out = scratch.join("packed");
    std::fs::create_dir_all(&out).expect("the pack destination");
    let packed = run(
        Command::new("npm")
            .arg("pack")
            .arg("--pack-destination")
            .arg(&out)
            .current_dir(&source),
        scratch,
        // `npm pack` reads no registry, but a stray one in the environment would
        // still be consulted for lifecycle scripts; there are none here.
        "http://127.0.0.1:1/npm/",
        &out,
    );
    assert!(
        packed.status.success(),
        "npm pack failed: {}",
        String::from_utf8_lossy(&packed.stderr)
    );

    let filename = format!("{WIDGET}-{version}.tgz");
    let bytes = std::fs::read(out.join(&filename)).expect("npm pack wrote the tarball");
    let integrity = ssri::IntegrityOpts::new()
        .algorithm(ssri::Algorithm::Sha512)
        .chain(&bytes)
        .result()
        .to_string();

    Tarball {
        filename,
        bytes,
        integrity,
    }
}

/// The npm package document upstream would serve for the two versions.
fn document(old: &Tarball, young: &Tarball) -> String {
    let now = jiff::Timestamp::now();
    let ten_days_ago = now - jiff::SignedDuration::from_hours(24 * 10);
    let an_hour_ago = now - jiff::SignedDuration::from_hours(1);

    let mut versions = Map::new();
    versions.insert(OLD.to_owned(), record(OLD, old));
    versions.insert(YOUNG.to_owned(), record(YOUNG, young));

    let mut time = Map::new();
    time.insert(OLD.to_owned(), json!(ten_days_ago.to_string()));
    time.insert(YOUNG.to_owned(), json!(an_hour_ago.to_string()));

    json!({
        "name": WIDGET,
        // Upstream's own `latest` is the young release, which policy holds. The
        // fallback rule has to move it without anyone editing a requirement.
        "dist-tags": {"latest": YOUNG},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

fn record(version: &str, tarball: &Tarball) -> Value {
    json!({
        "name": WIDGET,
        "version": version,
        "description": "A harmless fixture package.",
        "main": "index.js",
        "license": "Apache-2.0",
        "dist": {
            "tarball": format!("https://npm.invalid/{WIDGET}/-/{}", tarball.filename),
            "integrity": tarball.integrity,
        },
    })
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

struct Harness {
    server: TestServer,
    client: Client,
    registry: String,
    blocklist_file: PathBuf,
    /// Holds the blocklist file and the packed tarballs for the server's lifetime.
    scratch: TempDir,
}

impl Harness {
    /// A firewall listening on a port of its own, upstream of which is nothing but
    /// the two packed tarballs. `blocked` is the raw contents of the blocklist's
    /// `blocked_packages`.
    async fn start(blocked: &str) -> Harness {
        Harness::start_for(current_npm(), blocked).await
    }

    /// The same instance, with the npm binary under test named explicitly.
    async fn start_for(client: Client, blocked: &str) -> Harness {
        Harness::start_full(
            client,
            blocked,
            probation::osv::unreachable_client(),
            None,
            OsvMode::Enforce,
        )
        .await
    }

    /// The same instance, with OSV itself wired to a real (test) endpoint instead of
    /// the offline default every other constructor uses — `osv` is
    /// `(reqwest::Client, base URL)`, e.g. a plain client and a local `wiremock`
    /// server's URL.
    async fn start_for_with_osv(
        client: Client,
        blocked: &str,
        osv: (reqwest::Client, Url),
    ) -> Harness {
        Harness::start_for_with_osv_mode(client, blocked, osv, OsvMode::Enforce).await
    }

    /// `start_for_with_osv`, with the operator's `osv_mode` set explicitly.
    async fn start_for_with_osv_mode(
        client: Client,
        blocked: &str,
        osv: (reqwest::Client, Url),
        mode: OsvMode,
    ) -> Harness {
        Harness::start_full(client, blocked, osv.0, Some(osv.1), mode).await
    }

    async fn start_full(
        client: Client,
        blocked: &str,
        osv_client: reqwest::Client,
        osv_base_url: Option<Url>,
        mode: OsvMode,
    ) -> Harness {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let old = pack(scratch.path(), OLD);
        let young = pack(scratch.path(), YOUNG);

        let mut files = Files::default();
        files
            .metadata
            .insert(format!("/{WIDGET}"), document(&old, &young));
        for tarball in [&old, &young] {
            files.artifacts.insert(
                format!("/{WIDGET}/-/{}", tarball.filename),
                tarball.bytes.clone(),
            );
        }

        let blocklist_file = scratch.path().join("blocklist.json");
        std::fs::write(
            &blocklist_file,
            common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked),
        )
        .expect("the blocklist is written");

        // `public_url` is what the rendered `dist.tarball` points at, so the client
        // has to be able to reach it: the port is chosen before the server binds it.
        // `Config::load` requires https, which is right for a deployment behind the
        // reverse proxy SPEC §3 assumes and wrong for a client talking to loopback
        // directly, so the field is set here rather than parsed.
        let addr = free_port();
        let mut config = Config::load(Path::new("config.sample.toml"))
            .expect("config.sample.toml is valid configuration");
        config.listen = addr;
        config.public_url = Url::parse(&format!("http://{addr}")).expect("a loopback public URL");
        config.blocklist_file = blocklist_file.clone();
        config.cooldown_seconds = COOLDOWN_SECONDS;
        config.osv_mode = mode;
        if osv_base_url.is_some() {
            // The sample config's `osv_request_timeout_ms` (500ms) is shorter than
            // `OSV_BATCH_INTERVAL` (2s): a solitary lookup — nothing else fills the
            // batch — only ever flushes on that interval, so `resolve`'s own
            // `request_timeout` bound (C12c) fires and fails the check open first.
            // A real single-package `npm install` never fills a batch either, so
            // this is the production default's actual behaviour, not a test-only
            // quirk — see the finding this test's own comment reports. Widening the
            // timeout here is what lets this test observe the round trip complete
            // instead of always exercising the fail-open path.
            config.osv_request_timeout_ms =
                std::num::NonZeroU64::new(4_000).expect("4000 is non-zero");
        }

        let server = match osv_base_url {
            Some(url) => {
                TestServer::start_with_upstream_and_osv(
                    config,
                    Arc::new(SystemClock),
                    Arc::new(files),
                    fake_origins(),
                    osv_client,
                    url,
                )
                .await
            }
            None => {
                TestServer::start_with_upstream(
                    config,
                    Arc::new(SystemClock),
                    Arc::new(files),
                    fake_origins(),
                )
                .await
            }
        };

        Harness {
            client,
            registry: format!("http://{addr}/npm/"),
            server,
            blocklist_file,
            scratch,
        }
    }

    /// Puts a new snapshot in force on this running instance, and leaves the same
    /// bytes in the blocklist file so the poller's own next pass agrees with it.
    ///
    /// Blocking by restarting onto a second instance would not do: a lockfile's
    /// `resolved` URL names the port it was written against, so the second instance's
    /// refusal would be a connection failure rather than a policy decision.
    fn block(&self, blocked: &str) {
        let document = common::snapshot(2, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked);
        common::replace_atomically(&self.blocklist_file, &document);
        common::publish_blocklist(
            &self.server,
            &document,
            probation::clock::Clock::now_utc_micros(&SystemClock),
        );
    }

    fn npm(&self, project: &Project, args: &[&str]) -> Output {
        let mut command = Command::new(&self.client.bin);
        command.args(args).current_dir(&project.root);
        // The `npm` shim resolves `node` off `PATH`, so this is what decides which
        // interpreter the client under test runs on.
        if let Some(node_bin) = &self.client.node_bin {
            let inherited = std::env::var("PATH").unwrap_or_default();
            command.env("PATH", format!("{}:{inherited}", node_bin.display()));
        }
        run(
            &mut command,
            self.scratch.path(),
            &self.registry,
            &project.cache,
        )
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

/// A consumer project and the client cache it installs with.
///
/// It lives in a directory the *test* owns rather than one a [`Harness`] owns,
/// because the cache-reuse and blocked-pin tests outlive the instance that seeded
/// them: a lockfile or a warm cache built against one instance is then used against
/// another.
struct Project {
    root: PathBuf,
    cache: PathBuf,
}

impl Project {
    /// A fresh project requiring `dependency`, with a client cache of its own. SPEC
    /// §13: proxy-enforcement tests use fresh caches.
    fn new(at: &Path, name: &str, dependency: &str) -> Project {
        let root = at.join(name);
        std::fs::create_dir_all(&root).expect("the project directory");
        std::fs::write(
            root.join("package.json"),
            json!({
                "name": "e2e-consumer",
                "version": "1.0.0",
                "private": true,
                "dependencies": {WIDGET: dependency},
            })
            .to_string(),
        )
        .expect("the consumer package.json");

        let cache = at.join(format!("{name}-cache"));
        std::fs::create_dir_all(&cache).expect("the npm cache directory");
        Project { root, cache }
    }

    fn requirement(&self) -> String {
        let manifest: Value =
            serde_json::from_str(&read(&self.root.join("package.json"))).expect("the manifest");
        manifest["dependencies"][WIDGET]
            .as_str()
            .expect("the dependency requirement")
            .to_owned()
    }

    /// The version `npm` actually put on disk.
    fn installed_version(&self) -> String {
        let installed: Value = serde_json::from_str(&read(
            &self
                .root
                .join("node_modules")
                .join(WIDGET)
                .join("package.json"),
        ))
        .expect("the installed manifest");
        installed["version"]
            .as_str()
            .expect("the installed version")
            .to_owned()
    }

    fn lockfile(&self) -> PathBuf {
        self.root.join("package-lock.json")
    }
}

/// One `npm` invocation, with every ambient influence closed off: the registry and
/// cache are this test's, `HOME` is a scratch directory so no `~/.npmrc` applies, and
/// audit, funding and update checks — the three things that would otherwise reach a
/// public network — are off.
fn run(command: &mut Command, home: &Path, registry: &str, cache: &Path) -> Output {
    command
        .env("HOME", home)
        .env("npm_config_registry", registry)
        .env("npm_config_cache", cache)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .env("npm_config_update_notifier", "false")
        .env("npm_config_progress", "false")
        .env("NO_UPDATE_NOTIFIER", "1")
        .env_remove("NPM_CONFIG_REGISTRY")
        .output()
        .expect("npm runs")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{} is readable: {err}", path.display()))
}

/// A loopback port nothing is listening on, released before it is handed back.
///
/// The listener is dropped, so between here and `App::start` binding it the port is
/// free for anything else to take. Nothing else on this machine is choosing ephemeral
/// ports in that window during a test run, and the alternative — binding first — would
/// mean the rendered `dist.tarball` could not name the port a client has to reach.
fn free_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free loopback port");
    listener.local_addr().expect("the bound address")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The blocklist record that blocks exactly one npm version.
fn blocked_npm(version: &str) -> String {
    json!({
        "ecosystem": "npm",
        "name": WIDGET,
        "version": version,
        "reason": "e2e fixture block",
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// SPEC §2, first row: the latest release is too young, so an older eligible one is
/// offered — and the requirement in `package.json` is the one the developer wrote.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn an_install_falls_back_to_an_older_eligible_release() {
    fallback_case(current_npm()).await;
}

/// The same behaviour on the previous npm major (SPEC §13). Resolution is the client's
/// own, so a change in how npm reads a filtered document would show up here first.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn an_install_falls_back_to_an_older_eligible_release_on_the_previous_npm_major() {
    fallback_case(previous_npm_major()).await;
}

async fn fallback_case(client: Client) {
    let label = client.label.clone();
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start_for(client, "").await;
    let project = Project::new(workspace.path(), "fallback", "^1.0.0");

    let output = harness.npm(&project, &["install", "--audit=false"]);
    assert!(
        output.status.success(),
        "[{label}] npm install failed: {}",
        stderr(&output)
    );

    assert_eq!(
        project.installed_version(),
        OLD,
        "[{label}] npm resolved past the held {YOUNG} to the eligible {OLD}"
    );
    assert_eq!(
        project.requirement(),
        "^1.0.0",
        "[{label}] the requirement is the developer's, unedited"
    );

    harness.shutdown().await;
}

/// npm 12 defaults `allow-remote` to `none` and exempts a registry's own tarballs
/// only when the tarball URL shares **both** the origin and the path prefix of the
/// configured registry. With metadata at `/npm/` and artifacts at `/artifacts/` every
/// rewritten `dist.tarball` failed the prefix half and was refused with
/// `npm error code EALLOWREMOTE`.
///
/// Serving artifacts under `/npm/artifacts/…` satisfies it. This install carries **no
/// `--allow-remote` flag and no `.npmrc`** — `HOME` is a scratch directory — because
/// the client-side workaround disables a supply-chain control for every tarball
/// dependency in the project, which is the thing this product exists to provide.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_12_installs_without_allow_remote() {
    let client = current_npm_major();
    let label = client.label.clone();
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start_for(client, "").await;
    let project = Project::new(workspace.path(), "allow-remote-default", "^1.0.0");

    let output = harness.npm(&project, &["install", "--audit=false"]);
    let refusal = stderr(&output);
    assert!(
        !refusal.contains("EALLOWREMOTE"),
        "[{label}] the rewritten tarball was classed as a remote dependency, so it \
         does not start with the registry path prefix: {refusal}"
    );
    assert!(
        output.status.success(),
        "[{label}] npm install failed: {refusal}"
    );
    assert_eq!(
        project.installed_version(),
        OLD,
        "[{label}] and it resolved past the held {YOUNG} as every other client does"
    );

    // Nothing wrote one, and the assertion says so out loud: an `.npmrc` carrying
    // `allow-remote=all` would make the install above prove nothing.
    for npmrc in [
        harness.scratch.path().join(".npmrc"),
        project.root.join(".npmrc"),
    ] {
        assert!(
            !npmrc.exists(),
            "[{label}] {} exists; this install must succeed on npm 12's own defaults",
            npmrc.display()
        );
    }

    harness.shutdown().await;
}

/// SPEC §13: `npm ci` succeeds on an allowed lockfile, against a fresh client cache.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_ci_succeeds_on_an_allowed_lockfile() {
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start("").await;

    // The lockfile is produced by npm itself rather than written here, so `npm ci`
    // reads exactly what a developer would have committed.
    let seed = Project::new(workspace.path(), "seed", "^1.0.0");
    let installed = harness.npm(&seed, &["install", "--audit=false"]);
    assert!(
        installed.status.success(),
        "the seed install failed: {}",
        stderr(&installed)
    );

    let project = Project::new(workspace.path(), "allowed", "^1.0.0");
    std::fs::copy(seed.lockfile(), project.lockfile()).expect("the lockfile is copied");
    let before = read(&project.lockfile());

    let output = harness.npm(&project, &["ci", "--audit=false"]);
    assert!(
        output.status.success(),
        "npm ci failed on an allowed lockfile: {}",
        stderr(&output)
    );
    assert_eq!(project.installed_version(), OLD);
    assert_eq!(
        read(&project.lockfile()),
        before,
        "npm ci never rewrites the lockfile"
    );

    harness.shutdown().await;
}

/// SPEC §2: "Frozen lockfile references a blocked artifact → refuse the download.
/// Updating the lockfile is a separate client operation." The install fails and the
/// lockfile is byte-identical afterwards.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_ci_fails_on_a_blocked_pin_without_rewriting_it() {
    blocked_pin_case(current_npm()).await;
}

/// The same refusal on the previous npm major (SPEC §13). `npm ci`'s frozen-lockfile
/// handling and what it does with a `403` are both client behaviour.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_ci_fails_on_a_blocked_pin_without_rewriting_it_on_the_previous_npm_major() {
    blocked_pin_case(previous_npm_major()).await;
}

async fn blocked_pin_case(client: Client) {
    let label = client.label.clone();
    // The lockfile is built while nothing is blocked, exactly as a developer's would
    // have been, and then the block arrives.
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start_for(client, "").await;

    let seed = Project::new(workspace.path(), "seed", "^1.0.0");
    let installed = harness.npm(&seed, &["install", "--audit=false"]);
    assert!(
        installed.status.success(),
        "[{label}] the seed install failed: {}",
        stderr(&installed)
    );
    let lockfile = read(&seed.lockfile());

    // A project of its own, so the cache is empty and the refusal has to come from
    // the firewall rather than from the absence of a cached copy.
    let project = Project::new(workspace.path(), "blocked", "^1.0.0");
    std::fs::write(project.lockfile(), &lockfile).expect("the lockfile is written");
    harness.block(&blocked_npm(OLD));

    let output = harness.npm(&project, &["ci", "--audit=false"]);
    assert!(
        !output.status.success(),
        "[{label}] npm ci succeeded against a blocked pin: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let refusal = stderr(&output);
    assert!(
        refusal.contains("403"),
        "[{label}] the refusal is the firewall's policy answer, not a transport failure: {refusal}"
    );
    assert_eq!(
        read(&project.lockfile()),
        lockfile,
        "[{label}] the refusal left the lockfile untouched; rewriting it is the client's own operation"
    );
    assert!(
        !project.root.join("node_modules").join(WIDGET).exists(),
        "[{label}] no bytes of a blocked release were installed"
    );

    harness.shutdown().await;
}

/// SPEC §2, last row, and SPEC §13's "one deliberate cache-reuse test documenting the
/// boundary".
///
/// Two boundary facts, and they are not the same fact:
///
/// 1. **An already-installed package is outside the boundary.** A block that arrives
///    after the install does not remove `node_modules`, and a later `npm install`
///    leaves the blocked bytes exactly where they are. The proxy enforces on
///    delivery, and this delivery already happened.
/// 2. **`npm`'s own content cache is *not* a second copy of that hole**, because SPEC
///    §10 sends `Cache-Control: no-store` on artifacts and `npm` honours it: the same
///    `npm ci` that succeeds against an unblocked instance fails after the block even
///    though the tarball was fetched through this very cache directory a moment
///    earlier. The proxy's reach is wider than SPEC §2's wording promises for npm —
///    but only for as long as npm keeps honouring the header, which is why this is
///    recorded as an observation rather than relied on as a control.
///
/// `docs/operations.md` states both.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn an_already_installed_package_is_outside_the_enforcement_boundary() {
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start("").await;
    let project = Project::new(workspace.path(), "cache-reuse", "^1.0.0");

    let installed = harness.npm(&project, &["install", "--audit=false"]);
    assert!(
        installed.status.success(),
        "the seeding install failed: {}",
        stderr(&installed)
    );

    // The same block that makes `npm ci` fail on a fresh cache, on the same instance
    // and the same URLs.
    harness.block(&blocked_npm(OLD));

    let again = harness.npm(&project, &["install", "--audit=false"]);
    assert!(
        again.status.success(),
        "an install over an already-satisfied tree does not refetch: {}",
        stderr(&again)
    );
    assert_eq!(
        project.installed_version(),
        OLD,
        "the blocked release is still installed; the proxy cannot recall it"
    );

    // The second fact: npm's content cache was written through in this very
    // directory, and it still cannot serve the blocked tarball.
    let fresh_tree = Project::new(workspace.path(), "cache-reuse-again", "^1.0.0");
    std::fs::copy(project.lockfile(), fresh_tree.lockfile()).expect("the lockfile is copied");
    let from_cache = run(
        Command::new("npm")
            .args(["ci", "--audit=false", "--prefer-offline"])
            .current_dir(&fresh_tree.root),
        harness.scratch.path(),
        &harness.registry,
        // Deliberately the *warm* cache, not the fresh one.
        &project.cache,
    );
    assert!(
        !from_cache.status.success(),
        "no-store kept the tarball out of npm's cache, so the block still bites"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// OSV: a real npm install, actually refused because OSV — not the producer's own
// blocklist — flagged the package as malicious.
//
// Renaming `WIDGET` itself to a real reported-malicious package name (Socket.dev's
// `xlsx-to-json-lh` typosquat, https://socket.dev/blog/npm-package-wipes-codebases-with-remote-trigger;
// Aikido's RAT-infected `rand-user-agent`, https://www.aikido.dev/blog/rand-user-agent-rat)
// would mean threading a second package name through every helper above
// (`pack`/`document`/`record`/`blocked_npm`/`Project`), all of which are hardwired
// to one fixture — real risk to the existing tests for a cosmetic label. What those
// two reports establish, and what this test actually exercises, is the same shape:
// a specific (ecosystem, name, version) that a malicious-packages feed lists gets
// blocked the moment OSV is asked about it, independent of the operator's own
// snapshot. `WIDGET`'s harmless fixture stands in for the flagged identity; only
// the OSV *mock's answer* — not the package's real bytes — says "malicious".
//
// Everything else about the harness — real `npm pack`, real `npm install` against
// the firewall's own loopback port, no other network reachable — is identical to
// the blocklist-only tests above.
// ---------------------------------------------------------------------------

/// A `wiremock` server standing in for `https://api.osv.dev`: it answers
/// `POST /v1/querybatch` with a `MAL-*` vuln for every query matching `(name,
/// version)`, and no vuln for anything else — the same shape `osv::batcher`'s own
/// unit tests use, just reached through the real HTTP server this time instead of
/// called in-process.
async fn osv_flags(name: &str, version: &str) -> (Url, wiremock::MockServer) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let flagged_name = name.to_owned();
    let flagged_version = version.to_owned();
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(move |request: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&request.body).expect("a JSON batch body");
            let queries = body["queries"].as_array().expect("a queries array");
            let results: Vec<Value> = queries
                .iter()
                .map(|query| {
                    let matches = query["package"]["name"] == flagged_name
                        && query["version"] == flagged_version;
                    if matches {
                        json!({"vulns": [{"id": "MAL-2026-1234"}]})
                    } else {
                        json!({"vulns": []})
                    }
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({"results": results}))
        })
        .mount(&server)
        .await;
    let url = Url::parse(&format!("{}/v1/querybatch", server.uri())).expect("the mock's own URL");
    (url, server)
}

/// SPEC C1/C4: OSV is an OR-only signal — a package the producer's own snapshot
/// never mentions is still refused once OSV's malicious-packages feed lists it. The
/// producer's blocklist here is empty (`""`); OSV alone is what blocks the install.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_install_is_refused_on_an_osv_malicious_package_match() {
    let workspace = tempfile::tempdir().expect("a client workspace");
    let (osv_url, _osv_server) = osv_flags(WIDGET, OLD).await;

    let harness = Harness::start_for_with_osv(
        current_npm(),
        /* blocklist: */ "",
        (reqwest::Client::new(), osv_url),
    )
    .await;

    // Pinned exactly to the flagged version: an unpinned `^1.0.0` would let the
    // cooldown fallback quietly resolve past it, which would prove nothing about
    // OSV.
    let project = Project::new(workspace.path(), "osv-blocked", OLD);
    let output = harness.npm(&project, &["install", "--audit=false"]);

    assert!(
        !output.status.success(),
        "npm install of a package OSV flags as malicious must not succeed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let refusal = stderr(&output);
    assert!(
        refusal.contains("403"),
        "the refusal is the firewall's policy answer, not a transport failure: {refusal}"
    );
    assert!(
        !project.root.join("node_modules").join(WIDGET).exists(),
        "no bytes of the OSV-flagged release were installed"
    );

    harness.shutdown().await;
}

/// The negative case alongside it: OSV is asked (and would flag `YOUNG` if it were
/// requested), but the cooldown fallback resolves this install to `OLD` instead,
/// which OSV clears — proving the refusal above is a real OSV match and not some
/// unrelated failure (a wrong URL, a client build error, the mock never mounting).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_install_succeeds_when_osv_does_not_flag_the_resolved_version() {
    let workspace = tempfile::tempdir().expect("a client workspace");
    let (osv_url, _osv_server) = osv_flags(WIDGET, YOUNG).await;

    let harness =
        Harness::start_for_with_osv(current_npm(), "", (reqwest::Client::new(), osv_url)).await;
    let project = Project::new(workspace.path(), "osv-clear", "^1.0.0");

    let output = harness.npm(&project, &["install", "--audit=false"]);
    assert!(
        output.status.success(),
        "npm install failed even though OSV does not flag the resolved version: {}",
        stderr(&output)
    );
    assert_eq!(
        project.installed_version(),
        OLD,
        "resolved past the held, OSV-flagged YOUNG to the eligible, OSV-clear OLD"
    );

    harness.shutdown().await;
}

/// `osv_mode: diagnostic` — OSV is still consulted and flags the pinned version, but
/// the install is served rather than refused.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_install_succeeds_but_consults_osv_in_diagnostic_mode() {
    let workspace = tempfile::tempdir().expect("a client workspace");
    let (osv_url, osv_server) = osv_flags(WIDGET, OLD).await;

    let harness = Harness::start_for_with_osv_mode(
        current_npm(),
        /* blocklist: */ "",
        (reqwest::Client::new(), osv_url),
        OsvMode::Diagnostic,
    )
    .await;
    let project = Project::new(workspace.path(), "osv-diagnostic", OLD);

    let output = harness.npm(&project, &["install", "--audit=false"]);
    assert!(
        output.status.success(),
        "diagnostic mode must not refuse an OSV match: {}",
        stderr(&output)
    );
    assert_eq!(project.installed_version(), OLD);
    assert!(
        !osv_server
            .received_requests()
            .await
            .expect("the mock records requests")
            .is_empty(),
        "diagnostic mode still asks OSV — that is what it logs"
    );

    harness.shutdown().await;
}

/// `osv_mode: off` — the check is skipped entirely: the install succeeds and OSV is
/// never contacted.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real npm client"]
async fn npm_install_succeeds_without_contacting_osv_when_off() {
    let workspace = tempfile::tempdir().expect("a client workspace");
    let (osv_url, osv_server) = osv_flags(WIDGET, OLD).await;

    let harness = Harness::start_for_with_osv_mode(
        current_npm(),
        /* blocklist: */ "",
        (reqwest::Client::new(), osv_url),
        OsvMode::Off,
    )
    .await;
    let project = Project::new(workspace.path(), "osv-off", OLD);

    let output = harness.npm(&project, &["install", "--audit=false"]);
    assert!(
        output.status.success(),
        "off mode must not refuse an OSV match: {}",
        stderr(&output)
    );
    assert_eq!(project.installed_version(), OLD);
    assert_eq!(
        osv_server
            .received_requests()
            .await
            .expect("the mock records requests")
            .len(),
        0,
        "off mode never asks OSV"
    );

    harness.shutdown().await;
}
