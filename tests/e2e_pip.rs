//! Slice 10's witness: a real `pip` client installs through a listening instance.
//!
//! `#[ignore]` by default and run explicitly with
//! `cargo test --test e2e_pip -- --ignored`.
//!
//! **Nothing here reaches the network.** The firewall's upstream is the in-process
//! [`Files`] transport below, `pip` is pointed at the firewall's own loopback port,
//! and `--no-build-isolation` keeps the sdist build on the system's installed
//! `setuptools` instead of fetching a build backend. The distributions are built by
//! `python -m build`, so the bytes `pip` installs are bytes a real build produced.
//!
//! The clock is the system clock, not [`common::TestClock`]: `pip` runs in real
//! time, so the fixture states its upload times relative to now instead.

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
use probation::upstream::{
    ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, OriginSet, Transport,
    UpstreamError,
};
use serde_json::{Value, json};
use sha2::Digest;
use tempfile::TempDir;
use url::Url;

/// The PEP 503 normalised project name, which is what the route and the index use.
const BARD: &str = "friendly-bard";
/// Eligible: uploaded well before the cooldown.
const OLD: &str = "1.0.0";
/// Held: uploaded an hour ago, against a one-day cooldown.
const YOUNG: &str = "1.1.0";
const COOLDOWN_SECONDS: u64 = 86_400;

/// The previous pip minor, which SPEC §13 requires alongside the current one.
///
/// Pinned rather than floating, for the same reason the npm suite pins its major: a
/// test whose subject drifts is not a record of anything.
const PREVIOUS_PIP_MINOR: &str = "25.0.1";

/// The current upstream stable minor, pinned for the same reason. The interpreter's
/// own pip is whatever the machine happens to ship — 25.1.1 here — which is neither
/// current nor stable across machines.
const CURRENT_PIP_MINOR: &str = "26.2.1";

// ---------------------------------------------------------------------------
// Which client is under test
// ---------------------------------------------------------------------------

/// One pip, identified by the `PYTHONPATH` entry that makes `python3 -m pip` resolve
/// to it. `None` is the interpreter's own pip, which on this machine is 25.1.1.
#[derive(Clone)]
struct Client {
    label: String,
    pythonpath: Option<PathBuf>,
}

fn current_pip() -> Client {
    Client {
        label: format!("current pip minor ({CURRENT_PIP_MINOR})"),
        pythonpath: Some(pinned_pip(CURRENT_PIP_MINOR)),
    }
}

/// The pinned previous minor, installed out of tree by the documented setup step.
///
/// Panics with that step rather than skipping: a client-compatibility test that
/// quietly does nothing when its client is absent reports success for a matrix it
/// never ran.
fn previous_pip_minor() -> Client {
    Client {
        label: format!("previous pip minor ({PREVIOUS_PIP_MINOR})"),
        pythonpath: Some(pinned_pip(PREVIOUS_PIP_MINOR)),
    }
}

/// One pinned pip, installed out of tree by the documented setup step.
fn pinned_pip(version: &str) -> PathBuf {
    let root = previous_clients_root().join(format!("pip-{version}"));
    assert!(
        root.join("pip").is_dir(),
        "pip {version} is not installed at {}.\n\
         Install it once with:\n  \
         python3 -m pip install --target {} pip=={version}\n\
         (see docs/operations.md §11)",
        root.display(),
        root.display(),
    );
    root
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
// The upstream index: in process, and able to carry binary artifact bodies
// ---------------------------------------------------------------------------

/// A [`Transport`] whose artifact bodies are bytes rather than text. A wheel is a
/// zip archive, which `common::FakeRegistry`'s `String` answers cannot hold.
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
// Building the fixture distributions with the real `python -m build`
// ---------------------------------------------------------------------------

struct Distribution {
    filename: String,
    bytes: Vec<u8>,
    sha256: String,
}

impl Distribution {
    fn read(path: &Path) -> Distribution {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|err| panic!("the build produced {}: {err}", path.display()));
        Distribution {
            filename: path
                .file_name()
                .expect("a filename")
                .to_string_lossy()
                .into_owned(),
            sha256: hex::encode(sha2::Sha256::digest(&bytes)),
            bytes,
        }
    }
}

/// Builds a wheel and an sdist for `version`, with the real backend.
///
/// `--no-isolation` keeps the build on the system's installed `setuptools`, so
/// nothing has to be downloaded to produce the fixtures.
fn build(scratch: &Path, version: &str) -> (Distribution, Distribution) {
    let source = scratch.join(format!("src-{version}"));
    let package = source.join("friendly_bard");
    std::fs::create_dir_all(&package).expect("the package source directory");
    std::fs::write(
        source.join("pyproject.toml"),
        format!(
            "[build-system]\n\
             requires = [\"setuptools\"]\n\
             build-backend = \"setuptools.build_meta\"\n\
             \n\
             [project]\n\
             name = \"{BARD}\"\n\
             version = \"{version}\"\n\
             description = \"A harmless fixture project.\"\n\
             \n\
             [tool.setuptools]\n\
             packages = [\"friendly_bard\"]\n"
        ),
    )
    .expect("the fixture pyproject.toml");
    std::fs::write(
        package.join("__init__.py"),
        format!("__version__ = \"{version}\"\n"),
    )
    .expect("the fixture module");

    let out = scratch.join(format!("dist-{version}"));
    let built = Command::new("python3")
        .args(["-m", "build", "--no-isolation", "--wheel", "--sdist"])
        .arg("--outdir")
        .arg(&out)
        .current_dir(&source)
        .output()
        .expect("python -m build runs");
    assert!(
        built.status.success(),
        "python -m build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let wheel = Distribution::read(&out.join(format!("friendly_bard-{version}-py3-none-any.whl")));
    let sdist = Distribution::read(&out.join(format!("friendly_bard-{version}.tar.gz")));
    (wheel, sdist)
}

/// A PEP 691 Simple API project document. Each file carries its own upload time,
/// which is what SPEC §7 filters on.
fn document(files: &[(&Distribution, String)]) -> String {
    let entries: Vec<Value> = files
        .iter()
        .map(|(distribution, upload_time)| {
            json!({
                "filename": distribution.filename,
                "url": format!("https://files.invalid/packages/ab/cd/{}", distribution.filename),
                "hashes": {"sha256": distribution.sha256},
                "upload-time": upload_time,
                "requires-python": ">=3.8",
            })
        })
        .collect();

    json!({
        "meta": {"api-version": "1.1"},
        "name": BARD,
        "versions": [OLD, YOUNG],
        "files": entries,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

struct Harness {
    server: TestServer,
    client: Client,
    index_url: String,
    /// Holds the blocklist file and the built distributions for the server's
    /// lifetime.
    scratch: TempDir,
}

impl Harness {
    /// A firewall listening on a port of its own, upstream of which is nothing but
    /// the four built distributions. `blocked` is the raw contents of the blocklist's
    /// `blocked_packages`.
    async fn start(blocked: &str) -> Harness {
        Harness::start_for(current_pip(), blocked).await
    }

    /// The same instance, with the pip under test named explicitly.
    async fn start_for(client: Client, blocked: &str) -> Harness {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let (old_wheel, old_sdist) = build(scratch.path(), OLD);
        let (young_wheel, young_sdist) = build(scratch.path(), YOUNG);

        let now = jiff::Timestamp::now();
        let ten_days_ago = (now - jiff::SignedDuration::from_hours(24 * 10)).to_string();
        let an_hour_ago = (now - jiff::SignedDuration::from_hours(1)).to_string();

        let mut files = Files::default();
        files.metadata.insert(
            format!("/simple/{BARD}/"),
            document(&[
                (&old_wheel, ten_days_ago.clone()),
                (&old_sdist, ten_days_ago),
                (&young_wheel, an_hour_ago.clone()),
                (&young_sdist, an_hour_ago),
            ]),
        );
        for distribution in [&old_wheel, &old_sdist, &young_wheel, &young_sdist] {
            files.artifacts.insert(
                format!("/packages/ab/cd/{}", distribution.filename),
                distribution.bytes.clone(),
            );
        }

        let blocklist_file = scratch.path().join("blocklist.json");
        std::fs::write(
            &blocklist_file,
            common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked),
        )
        .expect("the blocklist is written");

        // `public_url` is what the rendered file URLs point at, so the client has to
        // be able to reach it: the port is chosen before the server binds it.
        // `Config::load` requires https, which is right for a deployment behind the
        // reverse proxy SPEC §3 assumes and wrong for a client talking to loopback
        // directly, so the field is set here rather than parsed.
        let addr = free_port();
        let mut config = Config::load(Path::new("config.sample.toml"))
            .expect("config.sample.toml is valid configuration");
        config.listen = addr;
        config.public_url = Url::parse(&format!("http://{addr}")).expect("a loopback public URL");
        config.blocklist_file = blocklist_file;
        config.cooldown_seconds = COOLDOWN_SECONDS;

        let server = TestServer::start_with_upstream(
            config,
            Arc::new(SystemClock),
            Arc::new(files),
            fake_origins(),
        )
        .await;

        Harness {
            client,
            index_url: format!("http://{addr}/pypi/simple/"),
            server,
            scratch,
        }
    }

    /// One `pip install` into a target directory of its own.
    ///
    /// Every ambient influence is closed off: the index is this test's, the cache is
    /// off so each run is a real proxy-enforcement test (SPEC §13), `HOME` is a
    /// scratch directory so no user `pip.conf` applies, and `PIP_INDEX_URL` and
    /// friends are cleared from the environment.
    fn pip(&self, target: &Path, extra: &[&str]) -> Output {
        let mut command = Command::new("python3");
        match &self.client.pythonpath {
            // `python3 -m pip` resolves the first `pip` package on the path, so this
            // is what selects the pinned older client without installing it over the
            // interpreter's own.
            Some(path) => command.env("PYTHONPATH", path),
            None => command.env_remove("PYTHONPATH"),
        };
        command
            .args(["-m", "pip", "install"])
            .arg("--index-url")
            .arg(&self.index_url)
            // The index is plain HTTP on loopback, which pip refuses to treat as a
            // trusted source without being told. A deployment terminates TLS at the
            // reverse proxy SPEC §3 assumes and needs none of this.
            .args(["--trusted-host", "127.0.0.1"])
            .arg("--target")
            .arg(target)
            .args([
                "--no-cache-dir",
                "--no-build-isolation",
                "--disable-pip-version-check",
                "--no-input",
            ])
            .args(extra)
            .env("HOME", self.scratch.path())
            .env("PIP_CONFIG_FILE", "/dev/null")
            .env_remove("PIP_INDEX_URL")
            .env_remove("PIP_EXTRA_INDEX_URL")
            .env_remove("PIP_FIND_LINKS")
            .output()
            .expect("pip runs")
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

/// The version `pip` recorded on disk, read off the `.dist-info` directory name.
fn installed_version(target: &Path) -> String {
    let entries = std::fs::read_dir(target)
        .unwrap_or_else(|err| panic!("{} is readable: {err}", target.display()));
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".dist-info")
            && let Some((project, version)) = stem.rsplit_once('-')
            && project == "friendly_bard"
        {
            return version.to_owned();
        }
    }
    panic!("no friendly_bard .dist-info under {}", target.display());
}

fn free_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free loopback port");
    listener.local_addr().expect("the bound address")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn blocked_pypi(version: &str) -> String {
    json!({
        "ecosystem": "pypi",
        "name": BARD,
        "version": version,
        "reason": "e2e fixture block",
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// SPEC §13: "Test pip installation and resolution from both wheels and source
/// distributions" — the wheel half. It is also SPEC §2's first row: nothing pins a
/// version, the newest release is held, and pip resolves to the older eligible one
/// without anyone editing a requirement.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real pip client"]
async fn pip_installs_from_a_wheel_falling_back_to_an_older_eligible_release() {
    wheel_case(current_pip()).await;
}

/// The same behaviour on the previous pip minor (SPEC §13). Resolution is the client's
/// own, so a change in how pip reads a filtered Simple listing would show up here.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real pip client"]
async fn pip_installs_from_a_wheel_falling_back_on_the_previous_pip_minor() {
    wheel_case(previous_pip_minor()).await;
}

async fn wheel_case(client: Client) {
    let label = client.label.clone();
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start_for(client, "").await;
    let target = workspace.path().join("wheel-target");

    // The route this install actually drove. PyPI's move under the ecosystem root is
    // justified by symmetry rather than necessity, so the pip evidence has to be
    // gathered against the layout that now exists instead of carried forward from the
    // one it replaced.
    let listing = harness
        .server
        .get_with_headers(
            &format!("/pypi/simple/{BARD}/"),
            &[("accept", "application/vnd.pypi.simple.v1+json")],
        )
        .await
        .text()
        .await
        .expect("the listing body");
    assert!(
        listing.contains("/pypi/artifacts/"),
        "[{label}] pip is pointed at the ecosystem-rooted artifact route: {listing}"
    );

    let output = harness.pip(&target, &["--only-binary", ":all:", BARD]);
    assert!(
        output.status.success(),
        "[{label}] pip install failed: {}",
        stderr(&output)
    );
    assert_eq!(
        installed_version(&target),
        OLD,
        "[{label}] pip resolved past the held {YOUNG} to the eligible {OLD}"
    );
    assert!(
        target.join("friendly_bard").join("__init__.py").exists(),
        "[{label}] the package itself is on disk"
    );

    harness.shutdown().await;
}

/// The source-distribution half of the same SPEC §13 requirement: `--no-binary`
/// leaves pip nothing but the sdist, which it has to download through the firewall
/// and build.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real pip client"]
async fn pip_installs_from_an_sdist() {
    sdist_case(current_pip()).await;
}

/// The same on the previous pip minor (SPEC §13). The sdist path involves the client's
/// build invocation as well as its download, so it is the more fragile of the two.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real pip client"]
async fn pip_installs_from_an_sdist_on_the_previous_pip_minor() {
    sdist_case(previous_pip_minor()).await;
}

async fn sdist_case(client: Client) {
    let label = client.label.clone();
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start_for(client, "").await;
    let target = workspace.path().join("sdist-target");

    let output = harness.pip(
        &target,
        &["--no-binary", ":all:", &format!("{BARD}=={OLD}")],
    );
    assert!(
        output.status.success(),
        "[{label}] pip install from an sdist failed: {}",
        stderr(&output)
    );
    assert_eq!(
        installed_version(&target),
        OLD,
        "[{label}] installed version"
    );
    assert!(target.join("friendly_bard").join("__init__.py").exists());

    harness.shutdown().await;
}

/// SPEC §2: "All compatible candidates are excluded → resolution fails. Never weaken
/// dependency requirements." The young release is held and the old one is blocked, so
/// the listing is valid and empty and pip reports no matching distribution.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real pip client"]
async fn pip_fails_when_nothing_eligible_remains() {
    nothing_eligible_case(current_pip()).await;
}

/// The same failure on the previous pip minor (SPEC §13). What pip *says* when a
/// listing is valid but empty is client behaviour, and it is what a developer reads.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real pip client"]
async fn pip_fails_when_nothing_eligible_remains_on_the_previous_pip_minor() {
    nothing_eligible_case(previous_pip_minor()).await;
}

async fn nothing_eligible_case(client: Client) {
    let label = client.label.clone();
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start_for(client, &blocked_pypi(OLD)).await;
    let target = workspace.path().join("empty-target");

    let output = harness.pip(&target, &[BARD]);
    assert!(
        !output.status.success(),
        "[{label}] pip installed something although nothing was eligible: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let refusal = stderr(&output);
    assert!(
        refusal.contains("No matching distribution found"),
        "[{label}] pip reports the resolution failure rather than a transport error: {refusal}"
    );
    assert!(
        !target.join("friendly_bard").exists(),
        "[{label}] nothing was installed"
    );

    harness.shutdown().await;
}

/// SPEC §2: an exact pin on a held version is refused rather than substituted. The
/// requirement is `=={YOUNG}`, which is the release the cooldown is holding, and no
/// other version may be handed back in its place.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns the real pip client"]
async fn an_exact_pin_on_a_held_release_is_refused_not_substituted() {
    let workspace = tempfile::tempdir().expect("a client workspace");
    let harness = Harness::start("").await;
    let target = workspace.path().join("pinned-target");

    let output = harness.pip(&target, &[&format!("{BARD}=={YOUNG}")]);
    assert!(
        !output.status.success(),
        "a held exact pin was satisfied: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !target.exists() || installed_version_is_absent(&target),
        "no substitute version was installed in place of the held pin"
    );

    harness.shutdown().await;
}

fn installed_version_is_absent(target: &Path) -> bool {
    !target.join("friendly_bard").exists()
}
