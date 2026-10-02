//! Slice 6's witness: PyPI metadata, end to end.
//!
//! Everything here runs against an in-process `FakeRegistry` and a clock the test
//! moves by hand, so a run reaches no socket and depends on no wall clock.
//!
//! Two harness rules this file follows throughout. Content is read with `reqwest`,
//! which handles framing; **anything asserting on a redirect or on a hostile path is
//! read with the raw `TcpStream` helper instead**, because `reqwest` both follows
//! redirects and rewrites `%2E%2E` client-side — slice 4 recorded a test that passed
//! against broken code for exactly that reason.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, fake_origins, fixture, logs,
    pypi_upstream_path, sample_config, wait_until,
};
use probation::config::Config;
use probation::http::error::ApiError;
use probation::policy::Ecosystem;
use probation::pypi::filename::file_identity;
use probation::store::cache::{ProjectKey, RenderKey, Representation};
use probation::store::rows::ProjectRefresh;
use probation::upstream::UpstreamValidators;
use serde_json::{Value, json};
use tempfile::TempDir;

const BARD: &str = "friendly-bard";
const OTHER: &str = "other-project";

/// The instant every fixture in this file is read at.
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

const JSON_ACCEPT: &str = "application/vnd.pypi.simple.v1+json, \
                           application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.01";
const HTML_ACCEPT: &str = "text/html";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    /// Holds the blocklist file for as long as the server uses it.
    _dir: TempDir,
}

impl Harness {
    /// How many upstream *metadata* fetches this project has caused.
    fn metadata_calls(&self, project: &str) -> usize {
        let path = pypi_upstream_path(project);
        self.registry
            .calls()
            .iter()
            .filter(|url| url.path() == path)
            .count()
    }

    async fn listing(&self, project: &str, accept: &str) -> String {
        let response = self
            .server
            .get_with_headers(&format!("/pypi/simple/{project}/"), &[("accept", accept)])
            .await;
        let status = response.status();
        let body = response.text().await.expect("a body");
        assert!(status.is_success(), "the listing answered {status}: {body}");
        body
    }

    async fn json_listing(&self, project: &str) -> Value {
        let body = self.listing(project, JSON_ACCEPT).await;
        serde_json::from_str(&body).unwrap_or_else(|err| panic!("not JSON: {err}: {body}"))
    }

    /// The filenames a JSON listing names, in order.
    async fn json_filenames(&self, project: &str) -> Vec<String> {
        self.json_listing(project).await["files"]
            .as_array()
            .expect("`files` is an array")
            .iter()
            .map(|file| file["filename"].as_str().expect("a filename").to_owned())
            .collect()
    }

    /// The filenames an HTML listing names, in order. Read out of the anchor text,
    /// which is the only place a Simple API client looks.
    async fn html_filenames(&self, project: &str) -> Vec<String> {
        anchor_texts(&self.listing(project, HTML_ACCEPT).await)
    }

    /// `GET /pypi/simple/`, JSON. `TestServer::json` would send `reqwest`'s default
    /// `Accept: */*`, which negotiation answers with HTML.
    async fn index_json(&self) -> Value {
        let body = self
            .server
            .get_with_headers("/pypi/simple/", &[("accept", JSON_ACCEPT)])
            .await
            .text()
            .await
            .expect("a body");
        serde_json::from_str(&body).unwrap_or_else(|err| panic!("not JSON: {err}: {body}"))
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

/// A configuration whose blocklist is valid and holds exactly `blocked`.
fn config_with(dir: &Path, blocked: &str, cooldown: u64) -> Config {
    let blocklist_file = dir.join("blocklist.json");
    std::fs::write(
        &blocklist_file,
        common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked),
    )
    .expect("the blocklist is written");

    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config.cooldown_seconds = cooldown;
    config
}

async fn harness(now: &str, cooldown: u64, blocked: &str, answers: &[(&str, String)]) -> Harness {
    let answers: Vec<(&str, FakeAnswer)> = answers
        .iter()
        .map(|(project, body)| (*project, FakeAnswer::Body(body.clone())))
        .collect();
    harness_with_answers(now, cooldown, blocked, &answers).await
}

/// The same server, with upstream answers of the test's own choosing — the two parked
/// shapes are the only way a metadata refresh can be observed *while* it is in flight.
async fn harness_with_answers(
    now: &str,
    cooldown: u64,
    blocked: &str,
    answers: &[(&str, FakeAnswer)],
) -> Harness {
    harness_configured(now, cooldown, blocked, answers, |_| {}).await
}

/// The same server with the configuration the test asks for. The maximum-age tests
/// need a shorter metadata TTL and a shorter ceiling than the shipped sample, so that
/// a whole ceiling can be crossed without the arithmetic becoming a second puzzle.
async fn harness_configured(
    now: &str,
    cooldown: u64,
    blocked: &str,
    answers: &[(&str, FakeAnswer)],
    tweak: impl FnOnce(&mut Config),
) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with(dir.path(), blocked, cooldown);
    tweak(&mut config);

    let registry = FakeRegistry::new();
    for (project, answer) in answers {
        registry.answer(&pypi_upstream_path(project), answer.clone());
    }

    let clock = TestClock::at_rfc3339(now);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&registry) as Arc<dyn probation::upstream::Transport>,
        fake_origins(),
    )
    .await;

    Harness {
        server,
        registry,
        clock,
        _dir: dir,
    }
}

/// A PEP 691 Simple API project document.
fn document(project: &str, files: Vec<Value>) -> String {
    json!({
        "meta": {"api-version": "1.1"},
        "name": project,
        "versions": [],
        "files": files,
    })
    .to_string()
}

/// One file entry, with an upload time of its own — which is the whole point of the
/// PyPI half: SPEC §7 filters files individually.
fn file(filename: &str, upload_time: &str) -> Value {
    json!({
        "filename": filename,
        "url": format!("https://files.invalid/packages/ab/cd/{filename}"),
        "hashes": {"sha256": "aa".repeat(32)},
        "upload-time": upload_time,
    })
}

/// A file with no upload time at all, which SPEC §5 resolves through a committed
/// first-seen value rather than by guessing an age.
fn undated_file(filename: &str) -> Value {
    let mut entry = file(filename, "");
    entry
        .as_object_mut()
        .expect("an object")
        .remove("upload-time");
    entry
}

/// The text of every `<a>` element, which is where a Simple API client reads a
/// filename from.
fn anchor_texts(html: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<a ") {
        rest = &rest[start..];
        let Some(open) = rest.find('>') else { break };
        let Some(close) = rest.find("</a>") else {
            break;
        };
        found.push(unescape(&rest[open + 1..close]));
        rest = &rest[close + 4..];
    }
    found
}

/// The inverse of the renderer's text escaping, so a test compares the filename a
/// client would recover rather than the bytes on the wire.
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
}

fn status_of(raw: &str) -> u16 {
    raw.split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("a status line, got {raw:?}"))
        .parse()
        .expect("a numeric status")
}

fn header_of(raw: &str, name: &str) -> Option<String> {
    raw.split("\r\n\r\n")
        .next()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}

// ---------------------------------------------------------------------------
// Names and the canonical redirect
// ---------------------------------------------------------------------------

/// SPEC §7: names are normalised per PEP 503, and a non-canonical spelling gets the
/// required trailing-slash redirect *locally* rather than by sending the client
/// upstream.
///
/// The hostile-path half goes through the raw `TcpStream` helper: `reqwest` decodes
/// `%2E%2E` and removes dot segments client-side, so the same assertion made through
/// it would pass against a handler that never saw the attack.
#[tokio::test]
async fn name_normalisation_and_canonical_redirect() {
    let harness = harness(
        NOW,
        ONE_DAY,
        "",
        &[(
            BARD,
            document(
                BARD,
                vec![file(
                    "friendly_bard-1.0-py3-none-any.whl",
                    "2020-01-01T00:00:00Z",
                )],
            ),
        )],
    )
    .await;

    // Every spelling of one project lands on exactly one URL.
    for spelling in ["Friendly.Bard", "friendly_bard", "FRIENDLY--BARD"] {
        let raw = harness
            .server
            .raw_get(&format!("/pypi/simple/{spelling}/"), &[])
            .await;
        assert_eq!(status_of(&raw), 301, "`{spelling}` must redirect: {raw}");
        assert_eq!(
            header_of(&raw, "location").as_deref(),
            Some("/pypi/simple/friendly-bard/"),
            "and to the canonical form: {raw}"
        );
    }

    // The trailing slash is part of the canonical form.
    let raw = harness
        .server
        .raw_get("/pypi/simple/friendly-bard", &[])
        .await;
    assert_eq!(status_of(&raw), 301);
    assert_eq!(
        header_of(&raw, "location").as_deref(),
        Some("/pypi/simple/friendly-bard/")
    );

    // And the canonical form itself is served, not redirected again.
    let raw = harness
        .server
        .raw_get("/pypi/simple/friendly-bard/", &[])
        .await;
    assert_eq!(status_of(&raw), 200, "{raw}");

    // A route component that is not a project name never becomes one, and never
    // becomes a redirect target either.
    for hostile in [
        "/pypi/simple/%2E%2E/",
        "/pypi/simple/../",
        "/pypi/simple/.%2E/",
        "/pypi/simple/%2Fetc%2Fpasswd/",
        "/pypi/simple/_leading/",
        "/pypi/simple/friendly%20bard/",
    ] {
        let raw = harness.server.raw_get(hostile, &[]).await;
        let status = status_of(&raw);
        assert!(
            status == 400 || status == 404,
            "`{hostile}` answered {status}, not a refusal: {raw}"
        );
        assert!(
            header_of(&raw, "location").is_none(),
            "`{hostile}` must not produce a redirect target at all: {raw}"
        );
    }

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// The two serialisations
// ---------------------------------------------------------------------------

/// SPEC §7: "Serve both Simple API HTML and JSON with correct content negotiation."
/// The two are the same decision rendered twice, so they must never disagree about
/// which files survived.
#[tokio::test]
async fn html_and_json_list_the_same_files() {
    let harness = harness(
        NOW,
        ONE_DAY,
        r#"{"ecosystem":"pypi","name":"friendly-bard","version":"1.5","reason":"test block"}"#,
        &[(
            BARD,
            document(
                BARD,
                vec![
                    file("friendly_bard-1.0-py3-none-any.whl", "2020-01-01T00:00:00Z"),
                    file("friendly-bard-1.0.tar.gz", "2020-01-01T00:00:00Z"),
                    // Blocked outright.
                    file("friendly_bard-1.5-py3-none-any.whl", "2020-01-01T00:00:00Z"),
                    // Uploaded an hour ago, so still inside its cooldown.
                    file("friendly_bard-2.0-py3-none-any.whl", "2026-04-06T11:00:00Z"),
                ],
            ),
        )],
    )
    .await;

    let json = harness.json_filenames(BARD).await;
    let html = harness.html_filenames(BARD).await;

    assert_eq!(
        json,
        vec![
            "friendly_bard-1.0-py3-none-any.whl".to_owned(),
            "friendly-bard-1.0.tar.gz".to_owned()
        ],
        "the eligible files, and only those"
    );
    assert_eq!(html, json, "the HTML form lists exactly the same files");

    // And the JSON form recomputes the advertised version list from what remains
    // (SPEC §7), rather than echoing upstream's.
    assert_eq!(
        harness.json_listing(BARD).await["versions"],
        json!(["1.0"]),
        "1.5 is blocked and 2.0 is held, so neither is advertised"
    );

    harness.shutdown().await;
}

/// Artifacts live at `/pypi/artifacts/{reference_id}/{filename}`, beside the static
/// `simple` segment rather than inside it, so no project path reaches it at any
/// arity — including a project literally named `artifacts`.
#[tokio::test]
async fn a_project_named_artifacts_still_resolves() {
    let harness = harness(
        NOW,
        ONE_DAY,
        "",
        &[(
            "artifacts",
            document(
                "artifacts",
                vec![file(
                    "artifacts-1.0-py3-none-any.whl",
                    "2020-01-01T00:00:00Z",
                )],
            ),
        )],
    )
    .await;

    let listing = harness.json_listing("artifacts").await;
    assert_eq!(listing["name"], json!("artifacts"));
    assert_eq!(
        harness.json_filenames("artifacts").await,
        vec!["artifacts-1.0-py3-none-any.whl".to_owned()],
        "the project route is not shadowed by the artifact route: {listing}"
    );
    assert!(
        listing["files"][0]["url"]
            .as_str()
            .expect("a url")
            .starts_with("https://packages.example.org/pypi/artifacts/"),
        "and this project's own file is served under the PyPI root: {listing}"
    );

    harness.shutdown().await;
}

/// SPEC §7 keeps compatibility and yank metadata intact: the Python client, not this
/// proxy, decides whether a file is acceptable.
#[tokio::test]
async fn requires_python_and_yanked_preserved() {
    let mut yanked = file("friendly_bard-1.0-py3-none-any.whl", "2020-01-01T00:00:00Z");
    let entry = yanked.as_object_mut().expect("an object");
    entry.insert("requires-python".to_owned(), json!(">=3.9"));
    entry.insert("yanked".to_owned(), json!("built from the wrong tag"));

    let harness = harness(NOW, ONE_DAY, "", &[(BARD, document(BARD, vec![yanked]))]).await;

    let listing = harness.json_listing(BARD).await;
    assert_eq!(listing["files"][0]["requires-python"], json!(">=3.9"));
    assert_eq!(
        listing["files"][0]["yanked"],
        json!("built from the wrong tag")
    );
    assert_eq!(
        listing["files"][0]["hashes"]["sha256"],
        json!("aa".repeat(32)),
        "the upstream hash is preserved (SPEC §7)"
    );
    assert!(
        listing["files"][0]["url"]
            .as_str()
            .expect("a url")
            .starts_with("https://packages.example.org/pypi/artifacts/"),
        "and the artifact URL points here, not upstream: {listing}"
    );

    let html = harness.listing(BARD, HTML_ACCEPT).await;
    assert!(
        html.contains(r#"data-requires-python="&gt;=3.9""#),
        "{html}"
    );
    assert!(
        html.contains(r#"data-yanked="built from the wrong tag""#),
        "{html}"
    );
    assert!(
        !html.contains("https://files.invalid"),
        "no upstream auxiliary download link survives (SPEC §7): {html}"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Per-file ages
// ---------------------------------------------------------------------------

/// SPEC §7 filters files individually. A wheel uploaded today against a release that
/// shipped a year ago serves its own wait; it does not inherit the sdist's age, and
/// the sdist does not inherit the wheel's youth either.
#[tokio::test]
async fn new_wheel_does_not_inherit_old_sdist_age() {
    let harness = harness(
        NOW,
        ONE_DAY,
        "",
        &[(
            BARD,
            document(
                BARD,
                vec![
                    file("friendly-bard-1.0.tar.gz", "2025-04-06T12:00:00Z"),
                    // The same release, packaged an hour ago.
                    file("friendly_bard-1.0-py3-none-any.whl", "2026-04-06T11:00:00Z"),
                ],
            ),
        )],
    )
    .await;

    assert_eq!(
        harness.json_filenames(BARD).await,
        vec!["friendly-bard-1.0.tar.gz".to_owned()],
        "the year-old sdist is eligible and the hour-old wheel of the same release is not"
    );

    // It is a wait, not an exclusion: past its own cooldown the wheel appears, with
    // nothing else having changed.
    harness.clock.advance_seconds(2 * ONE_DAY as i64);
    let mut filenames = harness.json_filenames(BARD).await;
    filenames.sort();
    assert_eq!(
        filenames,
        vec![
            "friendly-bard-1.0.tar.gz".to_owned(),
            "friendly_bard-1.0-py3-none-any.whl".to_owned()
        ],
        "and the wheel's own waiting period is what released it"
    );

    harness.shutdown().await;
}

/// SPEC §5: a file upstream gives no time for is not guessed at. It waits out the
/// cooldown from the moment this instance first committed it.
#[tokio::test]
async fn a_file_without_an_upload_time_waits_from_its_committed_first_seen() {
    let harness = harness(
        NOW,
        ONE_DAY,
        "",
        &[(
            BARD,
            document(
                BARD,
                vec![undated_file("friendly_bard-1.0-py3-none-any.whl")],
            ),
        )],
    )
    .await;

    assert!(
        harness.json_filenames(BARD).await.is_empty(),
        "an age this instance has only just established is not a year of standing"
    );

    harness.clock.advance_seconds(2 * ONE_DAY as i64);
    assert_eq!(
        harness.json_filenames(BARD).await,
        vec!["friendly_bard-1.0-py3-none-any.whl".to_owned()],
        "and the committed first-seen time is what the cooldown ran from"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The ordinary cases, so the adversarial corpus below is not the only thing holding
/// the parser's shape.
#[tokio::test]
async fn wheel_filename_identity() {
    let harness = harness(
        NOW,
        0,
        r#"{"ecosystem":"pypi","name":"friendly-bard","version":"1.0","reason":"test block"}"#,
        &[(
            BARD,
            document(
                BARD,
                vec![
                    file("friendly_bard-1.0-py3-none-any.whl", "2020-01-01T00:00:00Z"),
                    file(
                        "friendly_bard-1.0-3-py3-none-any.whl",
                        "2020-01-01T00:00:00Z",
                    ),
                    file(
                        "friendly_bard-1.0.0-py3-none-any.whl",
                        "2020-01-01T00:00:00Z",
                    ),
                    file("friendly_bard-1.1-py3-none-any.whl", "2020-01-01T00:00:00Z"),
                ],
            ),
        )],
    )
    .await;

    assert_eq!(
        harness.json_filenames(BARD).await,
        vec!["friendly_bard-1.1-py3-none-any.whl".to_owned()],
        "a build tag does not move the version, and `1.0.0` is PEP 440's `1.0`"
    );

    harness.shutdown().await;
}

/// SPEC §7: "Exclude files whose project/version identity cannot be established; log
/// the unsupported filename rather than guessing."
#[tokio::test]
async fn unsupported_filename_excluded_and_logged() {
    let captured = logs::capture_warn();

    let unsupported = [
        "friendly_bard-1.0-extra-py3-none-any.whl",
        "friendly_bard-1.0.egg",
        "friendly-bard-notaversion.tar.gz",
        "notfriendly-bard-1.0.tar.gz",
    ];
    let mut files = vec![file(
        "friendly_bard-9.9-py3-none-any.whl",
        "2020-01-01T00:00:00Z",
    )];
    files.extend(
        unsupported
            .iter()
            .map(|filename| file(filename, "2020-01-01T00:00:00Z")),
    );

    let harness = harness(NOW, ONE_DAY, "", &[(BARD, document(BARD, files))]).await;

    assert_eq!(
        harness.json_filenames(BARD).await,
        vec!["friendly_bard-9.9-py3-none-any.whl".to_owned()],
        "only the file whose identity was established is served"
    );

    for filename in unsupported {
        assert!(
            captured.lines_mentioning(filename) > 0,
            "`{filename}` was excluded without being logged"
        );
    }

    harness.shutdown().await;
}

/// TM-2. `src/pypi/filename.rs` is a hand-rolled PEP 427/625 splitter, and a
/// misattributed filename is judged as some other version — which is exactly how a
/// version-specific block is escaped.
///
/// The corpus is asserted twice: once directly against the parser, so every case
/// yields the identity named in the fixture or no identity at all, and once end to
/// end with `friendly-bard` version `1.0` blocked, so a misattribution in either
/// direction — a blocked file served, or an unrelated release withheld — is visible.
#[tokio::test]
async fn adversarial_multi_separator_filenames() {
    let corpus: Value =
        serde_json::from_str(&fixture("pypi/adversarial-filenames.json")).expect("the corpus");
    let cases = corpus["cases"].as_array().expect("the cases").clone();
    assert!(cases.len() > 25, "the corpus is not a token gesture");

    for case in &cases {
        let project = case["project"].as_str().expect("a project");
        let filename = case["filename"].as_str().expect("a filename");
        let expected = case["version"].as_str();

        match (file_identity(filename, project), expected) {
            (Ok(found), Some(version)) => assert_eq!(
                found.version, version,
                "`{filename}` was read as version `{}`, not `{version}`",
                found.version
            ),
            (Ok(found), None) => panic!(
                "`{filename}` has no establishable identity, but was read as \
                 `{}` at `{}`",
                found.project, found.version
            ),
            (Err(reason), Some(version)) => {
                panic!("`{filename}` is `{version}`, but was excluded: {reason}")
            }
            (Err(_), None) => {}
        }
    }

    // End to end, with exactly one version blocked.
    let blocked = &corpus["blocked"];
    let files: Vec<Value> = cases
        .iter()
        .filter(|case| case["project"] == json!(BARD))
        .map(|case| {
            file(
                case["filename"].as_str().expect("a filename"),
                "2020-01-01T00:00:00Z",
            )
        })
        .collect();
    assert!(files.len() > 20, "and the served half exercises most of it");

    let record = format!(
        r#"{{"ecosystem":"pypi","name":"{}","version":"{}","reason":"TM-2 corpus"}}"#,
        blocked["project"].as_str().expect("a project"),
        blocked["version"].as_str().expect("a version"),
    );
    let harness = harness(NOW, 0, &record, &[(BARD, document(BARD, files))]).await;

    let mut served = harness.json_filenames(BARD).await;
    served.sort();
    let mut expected: Vec<String> = cases
        .iter()
        .filter(|case| case["project"] == json!(BARD) && case["listed"] == json!(true))
        .map(|case| case["filename"].as_str().expect("a filename").to_owned())
        .collect();
    expected.sort();

    assert_eq!(
        served, expected,
        "every corpus filename is either the release it names or excluded — never \
         another release's"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// SPEC §11: "Treat package names, filenames, upstream JSON, and HTML attributes as
/// untrusted data." Anyone who can publish a public package controls every one of
/// the three strings below.
#[tokio::test]
async fn html_escapes_filenames_and_attributes() {
    // A wheel's platform tag is upstream text with no structure of its own. It
    // carries no `/`, because `file_identity` refuses a filename containing one at
    // all — so the payload is the slash-free spelling of the same attack.
    const HOSTILE: &str = "friendly_bard-1.0-py3-none-any\"><img src=x onerror=alert(1)>.whl";

    let mut hostile = file(HOSTILE, "2020-01-01T00:00:00Z");
    let entry = hostile.as_object_mut().expect("an object");
    entry.insert(
        "requires-python".to_owned(),
        json!(">=3.7\"><script>alert(2)</script>"),
    );
    entry.insert(
        "yanked".to_owned(),
        json!("bad & '<img src=x onerror=alert(3)>'"),
    );

    let harness = harness(NOW, ONE_DAY, "", &[(BARD, document(BARD, vec![hostile]))]).await;
    let html = harness.listing(BARD, HTML_ACCEPT).await;

    assert!(
        !html.contains("<script>") && !html.contains("<img "),
        "upstream markup reached the document unescaped: {html}"
    );
    assert!(
        html.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "and the filename is present, escaped: {html}"
    );
    // Text content and an attribute value are different contexts and are escaped by
    // different rules: a bare `"` cannot end an element, but it can end an attribute.
    // The filename reaches the `href` percent-encoded rather than escaped, because
    // it is a URL path segment there.
    assert!(
        html.contains("any%22%3E%3Cimg"),
        "the filename cannot break out of the href it is a path segment of: {html}"
    );
    assert!(
        !html.contains("onerror=alert(1)>"),
        "nothing anywhere in the document leaves the payload able to close a tag: {html}"
    );
    assert!(
        html.contains(
            r#"data-requires-python="&gt;=3.7&quot;&gt;&lt;script&gt;alert(2)&lt;/script&gt;""#
        ),
        "the attribute value can neither close its quote nor open an element: {html}"
    );
    assert!(
        html.contains(r#"data-yanked="bad &amp; &#x27;&lt;img src=x onerror=alert(3)&gt;&#x27;""#),
        "and an ampersand and both quote characters are escaped: {html}"
    );

    // The client still recovers the filename exactly, in both forms.
    assert_eq!(anchor_texts(&html), vec![HOSTILE.to_owned()]);
    assert_eq!(harness.json_filenames(BARD).await, vec![HOSTILE.to_owned()]);

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// The empty listing and the index
// ---------------------------------------------------------------------------

/// SPEC §7: "For an existing project with no eligible files, return an empty valid
/// project listing; pip reports no matching distribution." This is where PyPI
/// deliberately differs from npm's `403`, because pip's own message is the better
/// one.
#[tokio::test]
async fn existing_project_with_no_eligible_files_returns_empty_listing() {
    let harness = harness(
        NOW,
        ONE_DAY,
        r#"{"ecosystem":"pypi","name":"friendly-bard","version":"1.0","reason":"test block"}"#,
        &[(
            BARD,
            document(
                BARD,
                vec![
                    // Blocked.
                    file("friendly_bard-1.0-py3-none-any.whl", "2020-01-01T00:00:00Z"),
                    // Held: uploaded an hour ago.
                    file("friendly_bard-2.0-py3-none-any.whl", "2026-04-06T11:00:00Z"),
                    // Unnameable.
                    file("friendly_bard-3.0.egg", "2020-01-01T00:00:00Z"),
                ],
            ),
        )],
    )
    .await;

    let response = harness
        .server
        .get_with_headers(&format!("/pypi/simple/{BARD}/"), &[("accept", JSON_ACCEPT)])
        .await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "a known project with nothing eligible is an empty listing, not a denial"
    );

    let listing = harness.json_listing(BARD).await;
    assert_eq!(listing["files"], json!([]));
    assert_eq!(listing["versions"], json!([]));
    assert_eq!(listing["name"], json!(BARD));
    assert_eq!(listing["meta"]["api-version"], json!("1.1"));

    let html = harness.listing(BARD, HTML_ACCEPT).await;
    assert!(anchor_texts(&html).is_empty(), "{html}");
    assert!(
        html.contains("pypi:repository-version"),
        "and it is still a valid Simple API page: {html}"
    );

    // A project this instance has never heard of is still a `404`, so the empty
    // listing does not swallow the absent case.
    assert_eq!(
        harness.server.status("/pypi/simple/nothing-here/").await,
        404
    );

    harness.shutdown().await;
}

/// SPEC §7: `/pypi/simple/` is "a valid index of projects already known to this
/// instance, not a mirror of all PyPI projects".
#[tokio::test]
async fn known_project_index_lists_only_seen_projects() {
    let harness = harness(
        NOW,
        ONE_DAY,
        "",
        &[
            (
                BARD,
                document(
                    BARD,
                    vec![file(
                        "friendly_bard-1.0-py3-none-any.whl",
                        "2020-01-01T00:00:00Z",
                    )],
                ),
            ),
            (
                OTHER,
                document(
                    OTHER,
                    vec![file(
                        "other_project-1.0-py3-none-any.whl",
                        "2020-01-01T00:00:00Z",
                    )],
                ),
            ),
        ],
    )
    .await;

    let empty = harness.index_json().await;
    assert_eq!(
        empty["projects"],
        json!([]),
        "before anything is fetched the index is empty rather than a mirror"
    );

    // Fetching one project is what makes it known.
    harness.json_listing(BARD).await;

    let index = harness.index_json().await;
    assert_eq!(index["projects"], json!([{"name": BARD}]));

    let html = harness
        .server
        .get_with_headers("/pypi/simple/", &[("accept", HTML_ACCEPT)])
        .await
        .text()
        .await
        .expect("a body");
    assert_eq!(anchor_texts(&html), vec![BARD.to_owned()]);
    assert!(
        html.contains(&format!("href=\"{BARD}/\"")),
        "each entry links to its own listing: {html}"
    );
    assert!(
        !html.contains(OTHER),
        "a project this instance has never fetched is not advertised: {html}"
    );

    // And installing the unlisted project still works (SPEC §7).
    assert_eq!(
        harness.json_filenames(OTHER).await,
        vec!["other_project-1.0-py3-none-any.whl".to_owned()]
    );

    harness.shutdown().await;
}

/// SPEC §10: a second identical request is answered from memory — no database
/// command reaches a queue and no upstream call is made.
#[tokio::test]
async fn a_warm_listing_touches_neither_the_database_nor_upstream() {
    let harness = harness(
        NOW,
        ONE_DAY,
        "",
        &[(
            BARD,
            document(
                BARD,
                vec![file(
                    "friendly_bard-1.0-py3-none-any.whl",
                    "2020-01-01T00:00:00Z",
                )],
            ),
        )],
    )
    .await;

    harness.json_listing(BARD).await;
    let after_cold = harness.server.store_commands();

    harness.json_listing(BARD).await;
    assert_eq!(
        harness.server.store_commands(),
        after_cold,
        "a warm listing issues no storage command"
    );

    // The HTML form is a different representation and therefore a different entry;
    // it must still not re-fetch the project.
    harness.listing(BARD, HTML_ACCEPT).await;
    assert_eq!(
        harness.server.store_commands(),
        after_cold,
        "and the other serialisation is rendered from the same cached project"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// One metadata refresh per project (SPEC §10)
// ---------------------------------------------------------------------------

/// How long a consequence is allowed to take before a test calls it a failure.
/// Generous on purpose: it bounds a wait, it does not create one.
const PATIENCE: Duration = Duration::from_secs(20);

/// The project document the two tests below park a refresh of.
fn bard_document() -> String {
    document(
        BARD,
        vec![file(
            "friendly_bard-1.0-py3-none-any.whl",
            "2020-01-01T00:00:00Z",
        )],
    )
}

/// SPEC §10: "Coalesce concurrent metadata refreshes per project."
///
/// Six requests arrive while the one refresh is parked mid-flight, so all six are
/// provably *concurrent with* it rather than served one after another from the cache —
/// the gate is not released until every one of them is sharing the slot. The gate hands
/// out exactly one permit, so a second upstream refresh would never come back.
#[tokio::test]
async fn concurrent_cold_requests_cause_exactly_one_metadata_refresh() {
    let gate = Gate::new();
    let harness = harness_with_answers(
        NOW,
        ONE_DAY,
        "",
        &[(
            BARD,
            FakeAnswer::GatedMetadata {
                body: bard_document(),
                gate: Arc::clone(&gate),
            },
        )],
    )
    .await;
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::PyPi, BARD);

    let requests: Vec<_> = (0..6)
        .map(|_| {
            let app = Arc::clone(&app);
            tokio::spawn(
                async move { probation::pypi::ensure_fresh_project(&app, BARD).await },
            )
        })
        .collect();

    gate.wait_until_reached().await;
    wait_until("all six requests share one refresh", PATIENCE, || {
        app.downloads.metadata().waiting_on(&key) == 6
    })
    .await;
    gate.release();

    for request in requests {
        tokio::time::timeout(PATIENCE, request)
            .await
            .expect(
                "every request is answered by the one refresh rather than waiting on a \
                 second upstream call that will never be let through",
            )
            .expect("the request task finishes")
            .expect("every waiter is served by the one refresh");
    }

    assert_eq!(
        harness.metadata_calls(BARD),
        1,
        "six concurrent cold requests, one upstream metadata refresh"
    );

    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

/// A metadata refresh that dies without answering must not take the project with it.
///
/// The refresh that is running owns the only sender for the slot and every waiter holds
/// that slot alive, so a refresh that unwinds without sending would leave its waiters on
/// a channel that can never close and leave the slot in the table for every later
/// request to join — a permanent per-project denial of service from one panic.
#[tokio::test]
async fn a_panic_in_a_metadata_refresh_does_not_wedge_the_project() {
    let gate = Gate::new();
    let harness = harness_with_answers(
        NOW,
        ONE_DAY,
        "",
        &[(
            BARD,
            FakeAnswer::PanicsMidRefresh {
                gate: Arc::clone(&gate),
            },
        )],
    )
    .await;
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::PyPi, BARD);

    let refreshing = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::pypi::ensure_fresh_project(&app, BARD).await })
    };
    gate.wait_until_reached().await;

    let waiter = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::pypi::ensure_fresh_project(&app, BARD).await })
    };
    wait_until(
        "the second request joined the one refresh",
        PATIENCE,
        || app.downloads.metadata().waiting_on(&key) == 2,
    )
    .await;
    gate.release();

    assert!(
        tokio::time::timeout(PATIENCE, refreshing)
            .await
            .expect("the panicking refresh ends rather than hanging")
            .is_err(),
        "the panic took its own request with it"
    );
    let answered = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the waiter was resolved rather than left on a channel that never closes")
        .expect("the waiter's task finishes");
    assert_eq!(
        answered.expect_err("the waiter is told the work did not finish"),
        ApiError::InternalFailure
    );
    assert_eq!(
        app.downloads.metadata().waiting_on(&key),
        0,
        "and the dead slot is gone from the in-flight table"
    );

    // Upstream is healthy again, and the project is servable rather than wedged behind
    // the dead refresh.
    harness
        .registry
        .answer(&pypi_upstream_path(BARD), FakeAnswer::Body(bard_document()));
    let later = tokio::time::timeout(
        Duration::from_secs(5),
        probation::pypi::ensure_fresh_project(&app, BARD),
    )
    .await
    .expect("a later request for the same project is not wedged behind the dead one");
    assert!(later.is_ok(), "and it is served: {later:?}");
    assert_eq!(
        harness.metadata_calls(BARD),
        2,
        "the later request started a refresh of its own rather than joining a dead slot"
    );

    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Conditional revalidation (SPEC §10)
// ---------------------------------------------------------------------------

/// A validator upstream serves [`BARD`]'s unchanged document under.
const ETAG: &str = "\"v1\"";
const ETAG_V2: &str = "\"v2\"";

const WHEEL_1_0: &str = "friendly_bard-1.0-py3-none-any.whl";
const WHEEL_1_1: &str = "friendly_bard-1.1-py3-none-any.whl";
const WHEEL_1_2: &str = "friendly_bard-1.2-py3-none-any.whl";

/// The metadata TTL the sample configuration ships, which is what every wait below
/// is measured against.
fn metadata_ttl() -> i64 {
    sample_config().metadata_ttl_seconds as i64
}

/// The wall-clock instant the server is reading right now.
fn server_now(harness: &Harness) -> i64 {
    harness.server.running().app().clock.now_utc_micros()
}

/// The cached projection for [`BARD`]'s JSON listing, or none if there is not one.
fn projection(harness: &Harness) -> Option<Arc<probation::store::cache::RenderedResponse>> {
    harness
        .server
        .running()
        .app()
        .store()
        .caches()
        .rendered
        .get(&RenderKey {
            project: ProjectKey::new(Ecosystem::PyPi, BARD),
            representation: Representation::PypiJson,
        })
}

/// Two files uploaded years ago, so nothing here is ever held and every exclusion
/// below is the blocklist's doing.
fn validated_document() -> String {
    document(
        BARD,
        vec![
            file(WHEEL_1_0, "2020-01-01T00:00:00Z"),
            file(WHEEL_1_1, "2020-02-01T00:00:00Z"),
        ],
    )
}

/// The same project after a third upload, which upstream serves under a new
/// validator.
fn extended_document() -> String {
    document(
        BARD,
        vec![
            file(WHEEL_1_0, "2020-01-01T00:00:00Z"),
            file(WHEEL_1_1, "2020-02-01T00:00:00Z"),
            file(WHEEL_1_2, "2020-03-01T00:00:00Z"),
        ],
    )
}

/// One file uploaded eight minutes before [`NOW`], which with a ten-minute cooldown
/// releases in two — sooner than the five-minute metadata TTL, which is what makes
/// the hold the earliest of the three deadlines.
fn held_document() -> String {
    document(
        BARD,
        vec![
            file(WHEEL_1_0, "2020-01-01T00:00:00Z"),
            file(WHEEL_1_1, "2026-04-06T11:52:00Z"),
        ],
    )
}

async fn validated_harness() -> Harness {
    harness_with_answers(
        NOW,
        ONE_DAY,
        "",
        &[(
            BARD,
            FakeAnswer::Validated {
                etag: ETAG.to_owned(),
                body: validated_document(),
            },
        )],
    )
    .await
}

/// SPEC §10: "After metadata TTL, revalidate upstream before responding. An upstream
/// `304` renews upstream freshness."
///
/// The validators this instance stored go *upstream*, which is the direction SPEC §10
/// requires; the separate prohibition on forwarding validators is about what reaches a
/// client, and `origin_guard` is what witnesses that.
#[tokio::test]
async fn an_upstream_304_renews_freshness_without_a_refetch() {
    let harness = validated_harness().await;
    let upstream = pypi_upstream_path(BARD);

    let first = harness.json_listing(BARD).await;
    assert_eq!(harness.metadata_calls(BARD), 1);
    assert!(
        harness.registry.conditional_calls(&upstream).is_empty(),
        "the first fetch has nothing stored to revalidate against"
    );

    harness.clock.advance_seconds(metadata_ttl() + 1);
    let second = harness.json_listing(BARD).await;
    assert_eq!(
        second, first,
        "a 304 serves the document upstream still has"
    );

    assert_eq!(harness.metadata_calls(BARD), 2);
    let conditional = harness.registry.conditional_calls(&upstream);
    assert_eq!(
        conditional.len(),
        1,
        "the revalidation carried this instance's own stored validators"
    );
    assert_eq!(conditional[0].etag.as_deref(), Some(ETAG));
    assert_eq!(
        harness.registry.not_modified_answers(),
        1,
        "and upstream therefore sent no document a second time"
    );

    // Freshness is renewed by the 304 itself: the next request inside the renewed TTL
    // asks nobody at all.
    harness.clock.advance_seconds(10);
    assert_eq!(harness.json_listing(BARD).await, first);
    assert_eq!(
        harness.metadata_calls(BARD),
        2,
        "the 304 renewed the metadata TTL rather than leaving the snapshot expired"
    );

    harness.shutdown().await;
}

/// SPEC §10's second clause: "the firewall still rebuilds its policy-dependent
/// representation when required."
///
/// A `304` says the *document* has not changed. It says nothing about the blocklist,
/// so a version blocked since the last full fetch must still disappear. Without this,
/// a revalidated project keeps serving a file the operator has already blocked.
#[tokio::test]
async fn a_304_still_rebuilds_the_representation_when_the_blocklist_changed() {
    let harness = validated_harness().await;

    assert!(
        harness
            .json_filenames(BARD)
            .await
            .contains(&WHEEL_1_1.to_owned()),
        "1.1 starts out listed"
    );
    // Warmed on purpose: HTML is a representation of its own, so both cached
    // projections have to be rebuilt, not just the one this test reads first.
    assert!(
        harness
            .html_filenames(BARD)
            .await
            .contains(&WHEEL_1_1.to_owned()),
        "in both serialisations"
    );

    // The operator blocks 1.1 after the last full fetch. Upstream's document is
    // unchanged, so the revalidation below is answered 304.
    harness.clock.advance_seconds(metadata_ttl() + 1);
    common::publish_blocklist(
        &harness.server,
        &common::snapshot(
            2,
            "2020-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            r#"{"ecosystem":"pypi","name":"friendly-bard","version":"1.1","reason":"malware"}"#,
        ),
        server_now(&harness),
    );

    let after = harness.json_filenames(BARD).await;
    assert_eq!(
        harness.registry.not_modified_answers(),
        1,
        "upstream answered the revalidation 304, which is the case this test is about"
    );
    assert!(
        !after.contains(&WHEEL_1_1.to_owned()),
        "a 304 renews freshness but still rebuilds the representation, so a version \
         blocked since the last full fetch stays excluded"
    );
    assert!(after.contains(&WHEEL_1_0.to_owned()));
    assert!(
        !harness
            .html_filenames(BARD)
            .await
            .contains(&WHEEL_1_1.to_owned()),
        "the warm HTML projection was rebuilt too, rather than served on"
    );

    harness.shutdown().await;
}

/// SPEC §13 item 10. A project upstream has stopped serving becomes a `404` once its
/// TTL is up — including after a revalidation upstream did recognise, so this is
/// removal rather than a cold miss.
#[tokio::test]
async fn upstream_removal_becomes_404() {
    let harness = validated_harness().await;
    let path = format!("/pypi/simple/{BARD}/");
    harness.json_listing(BARD).await;

    harness.clock.advance_seconds(metadata_ttl() + 1);
    assert_eq!(harness.server.status(&path).await, 200);
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // Then upstream forgets the project. SPEC §10 forbids serving expired metadata,
    // so the cached document does not outlive its renewed TTL.
    harness
        .registry
        .answer(&pypi_upstream_path(BARD), FakeAnswer::Missing);
    harness.clock.advance_seconds(metadata_ttl() + 1);
    assert_eq!(harness.server.status(&path).await, 404);

    harness.shutdown().await;
}

/// SPEC §13 item 10. Inside the TTL nothing is asked upstream; past it exactly one
/// conditional request goes out, and a changed document comes back in full.
#[tokio::test]
async fn revalidation_after_ttl() {
    let harness = validated_harness().await;
    harness.json_listing(BARD).await;

    harness.clock.advance_seconds(60);
    harness.json_listing(BARD).await;
    assert_eq!(
        harness.metadata_calls(BARD),
        1,
        "inside the TTL nothing is revalidated"
    );

    harness.clock.advance_seconds(metadata_ttl());
    harness.json_listing(BARD).await;
    assert_eq!(harness.metadata_calls(BARD), 2);
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // A changed document carries a different validator, so the same conditional
    // request is answered with the whole document instead.
    harness.registry.answer(
        &pypi_upstream_path(BARD),
        FakeAnswer::Validated {
            etag: ETAG_V2.to_owned(),
            body: extended_document(),
        },
    );
    harness.clock.advance_seconds(metadata_ttl() + 1);
    let after = harness.json_filenames(BARD).await;

    assert_eq!(harness.metadata_calls(BARD), 3);
    assert_eq!(
        harness.registry.not_modified_answers(),
        1,
        "the changed document was sent in full rather than revalidated away"
    );
    assert!(
        after.contains(&WHEEL_1_2.to_owned()),
        "and the new file is listed"
    );

    harness.shutdown().await;
}

/// SPEC §13 item 10, and SPEC §10's deadline rule: the projection expires at the next
/// held file's eligibility time, and a `304` recomputes it from the renewed validation
/// time.
#[tokio::test]
async fn projection_expires_at_next_hold_release() {
    const COOLDOWN: u64 = 600;
    let harness = harness_with_answers(
        NOW,
        COOLDOWN,
        "",
        &[(
            BARD,
            FakeAnswer::Validated {
                etag: ETAG.to_owned(),
                body: held_document(),
            },
        )],
    )
    .await;

    assert!(
        !harness
            .json_filenames(BARD)
            .await
            .contains(&WHEEL_1_1.to_owned()),
        "1.1 is two minutes short of its ten-minute cooldown"
    );
    assert_eq!(
        projection(&harness)
            .expect("the projection is cached")
            .deadline_utc_micros,
        common::parse_rfc3339("2026-04-06T12:02:00Z"),
        "the hold release is earlier than the metadata TTL, so it is the deadline"
    );

    // Two minutes and a second later the projection has expired and the file appears,
    // without anything being asked upstream.
    harness.clock.advance_seconds(121);
    assert!(
        harness
            .json_filenames(BARD)
            .await
            .contains(&WHEEL_1_1.to_owned())
    );
    assert_eq!(
        harness.metadata_calls(BARD),
        1,
        "the projection expired; the snapshot behind it had not"
    );

    // Past the metadata TTL the snapshot is revalidated. The 304 renews it, and the
    // projection is recomputed from that renewed validation time rather than from the
    // original fetch.
    harness.clock.advance_seconds(metadata_ttl());
    let revalidated_at = server_now(&harness);
    harness.json_listing(BARD).await;
    assert_eq!(harness.registry.not_modified_answers(), 1);
    assert_eq!(
        projection(&harness)
            .expect("the projection is cached again")
            .deadline_utc_micros,
        revalidated_at + metadata_ttl() * 1_000_000,
        "nothing is held any more, so the renewed metadata TTL is the deadline"
    );

    harness.shutdown().await;
}

/// SPEC §5 and §13 item 10: a backward wall-clock step must not extend a projection.
/// The monotonic deadline is what governs, so the projection is recomputed even though
/// the wall clock now reads before its expiry.
#[tokio::test]
async fn backward_clock_jump_recomputes_projections() {
    let harness = validated_harness().await;

    let before = harness.json_listing(BARD).await;
    let first = projection(&harness).expect("the projection is cached");

    // Real time passes the projection's five-minute deadline; then the wall clock is
    // stepped ten minutes back, so it now reads *before* that deadline while the
    // monotonic reading stays where real time left it.
    harness.clock.advance_seconds(metadata_ttl() + 1);
    harness.clock.rewind_wall_clock_seconds(metadata_ttl() * 2);
    assert!(
        server_now(&harness) < first.deadline_utc_micros,
        "the wall clock alone would call the old projection reusable"
    );

    assert_eq!(harness.json_listing(BARD).await, before);
    let second = projection(&harness).expect("the projection is cached again");
    assert!(
        second.deadline_monotonic > first.deadline_monotonic,
        "the monotonic deadline had passed, so the projection was recomputed rather \
         than extended by the step backwards"
    );
    assert_eq!(
        harness.metadata_calls(BARD),
        1,
        "and that recomputation is the projection's, not a refetch's"
    );

    // Forward again past the stored snapshot's own TTL: the revalidation is
    // conditional, the 304 renews it, and the projection is recomputed once more.
    harness.clock.advance_seconds(metadata_ttl() * 3);
    let revalidated_at = server_now(&harness);
    harness.json_listing(BARD).await;
    assert_eq!(harness.metadata_calls(BARD), 2);
    assert_eq!(harness.registry.not_modified_answers(), 1);
    assert_eq!(
        projection(&harness)
            .expect("the projection is cached a third time")
            .deadline_utc_micros,
        revalidated_at + metadata_ttl() * 1_000_000
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// The 304 fail-closed paths (SPEC §10)
// ---------------------------------------------------------------------------
//
// Three states a hostile or broken index can put the firewall in that
// `FakeAnswer::Validated` cannot reach, because it only ever answers 304 to a
// validator it actually matched. Each was correct by reading before these tests
// existed; none had an executed witness, and fail-closed is not a property to take
// on trust.

/// Names of their own, because `logs` is one buffer per test binary and an assertion
/// about a warning has to select its own line out of it.
const UNCONDITIONAL: &str = "unconditional-project";
const CORRUPT: &str = "corrupt-project";
const SURPRISING: &str = "surprising-project";

/// The cached JSON projection for one project, or none if there is not one.
fn projection_of(
    harness: &Harness,
    name: &str,
) -> Option<Arc<probation::store::cache::RenderedResponse>> {
    harness
        .server
        .running()
        .app()
        .store()
        .caches()
        .rendered
        .get(&RenderKey {
            project: ProjectKey::new(Ecosystem::PyPi, name),
            representation: Representation::PypiJson,
        })
}

/// (1) A `304` answering a request that carried no validator, because nothing was
/// stored to revalidate against. There is no document behind it and none may be
/// invented: SPEC §11's `502` row, plus a warning naming the project.
#[tokio::test]
async fn a_304_to_an_unconditional_request_is_refused_not_guessed() {
    let captured = logs::capture_warn();
    let harness = harness_with_answers(
        NOW,
        ONE_DAY,
        "",
        &[(
            UNCONDITIONAL,
            FakeAnswer::AlwaysNotModified {
                etag: Some(ETAG.to_owned()),
                last_modified: None,
            },
        )],
    )
    .await;
    let path = format!("/pypi/simple/{UNCONDITIONAL}/");
    let upstream = pypi_upstream_path(UNCONDITIONAL);

    let response = harness.server.get(&path).await;
    assert_eq!(response.status().as_u16(), 502);
    assert_eq!(
        common::body_error(response).await,
        "UPSTREAM_INVALID",
        "a 304 with nothing behind it is an unusable upstream answer, not a document"
    );
    assert!(
        harness.registry.conditional_calls(&upstream).is_empty(),
        "and the request that provoked it carried no validator, which is what makes \
         the 304 nonsense"
    );
    assert_eq!(
        captured.lines_containing_all(&[UNCONDITIONAL, "unconditional"]),
        1,
        "the refusal is logged rather than silent"
    );

    // Nothing was invented and nothing was kept: the next request refuses again
    // rather than serving something cached from the first.
    assert_eq!(harness.server.status(&path).await, 502);
    assert!(
        projection_of(&harness, UNCONDITIONAL).is_none(),
        "no representation was cached for a project that has no document"
    );

    harness.shutdown().await;
}

/// (2) A `304` whose stored document cannot be parsed. The snapshot is persisted
/// corrupt — committed directly, which is the only way to reach a state the refresh
/// path itself can never produce, since it parses before it commits. The parse must
/// fail before `commit_project_refresh` is reached, so nothing is written.
#[tokio::test]
async fn a_304_whose_stored_document_is_unparseable_commits_nothing() {
    let harness = harness_with_answers(
        NOW,
        ONE_DAY,
        "",
        &[(
            CORRUPT,
            FakeAnswer::Validated {
                etag: ETAG.to_owned(),
                body: validated_document(),
            },
        )],
    )
    .await;
    let app = harness.server.running().app();

    // Already expired, so the next request revalidates; and with the stored etag, so
    // that revalidation is answered 304.
    let stored_at = server_now(&harness) - (metadata_ttl() + 1) * 1_000_000;
    app.store()
        .commit_project_refresh(ProjectRefresh {
            ecosystem: Ecosystem::PyPi,
            name: CORRUPT.to_owned(),
            payload: Arc::from(&b"{\"files\": this is not a simple api document"[..]),
            validators: UpstreamValidators {
                etag: Some(ETAG.to_owned()),
                last_modified: None,
            },
            validated_at_micros: stored_at,
            fetched_at_micros: stored_at,
            references: Vec::new(),
        })
        .await
        .expect("the corrupt snapshot is persisted");

    let before = app
        .store()
        .get_project(Ecosystem::PyPi, CORRUPT)
        .await
        .expect("the row reads back")
        .expect("the row is there");

    let response = harness
        .server
        .get_with_headers(
            &format!("/pypi/simple/{CORRUPT}/"),
            &[("accept", JSON_ACCEPT)],
        )
        .await;
    assert_eq!(response.status().as_u16(), 502);
    assert_eq!(common::body_error(response).await, "UPSTREAM_INVALID");
    assert_eq!(
        harness.registry.not_modified_answers(),
        1,
        "the revalidation really was answered 304, which is the branch under test"
    );

    let after = app
        .store()
        .get_project(Ecosystem::PyPi, CORRUPT)
        .await
        .expect("the row reads back")
        .expect("the row is still there");
    assert_eq!(
        after.generation, before.generation,
        "the parse failed before the commit, so no new generation was published"
    );
    assert_eq!(
        after.validated_at_micros, stored_at,
        "and freshness was not renewed on a document that cannot be judged"
    );

    harness.shutdown().await;
}

/// (3) A `304` carrying validators this instance never sent. They are adopted for the
/// next revalidation and nothing else about the answer is trusted: the document
/// served is the stored one, judged under the blocklist in force now.
///
/// What this does *not* witness is a 304 carrying a body — `MetadataResponse::
/// NotModified` has no body field, so at this seam there is structurally nothing to
/// read. `a_304_with_a_body_and_extra_headers_yields_no_bytes` covers that against the
/// production transport instead.
#[tokio::test]
async fn a_304_with_unexpected_validators_is_still_a_revalidation() {
    let harness = harness_with_answers(
        NOW,
        ONE_DAY,
        "",
        &[(
            SURPRISING,
            FakeAnswer::Validated {
                etag: ETAG.to_owned(),
                body: document(
                    SURPRISING,
                    vec![file(
                        "surprising_project-1.0-py3-none-any.whl",
                        "2020-01-01T00:00:00Z",
                    )],
                ),
            },
        )],
    )
    .await;
    let upstream = pypi_upstream_path(SURPRISING);

    let first = harness.json_listing(SURPRISING).await;

    // Upstream now answers 304 with a validator pair we never asked about.
    harness.registry.answer(
        &upstream,
        FakeAnswer::AlwaysNotModified {
            etag: Some(ETAG_V2.to_owned()),
            last_modified: Some("Thu, 01 Jan 1970 00:00:00 GMT".to_owned()),
        },
    );
    harness.clock.advance_seconds(metadata_ttl() + 1);

    assert_eq!(
        harness.json_listing(SURPRISING).await,
        first,
        "the stored document is what is served; the surprising headers change nothing \
         about it"
    );
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // The new validators were adopted, so the next revalidation asks with them.
    harness.clock.advance_seconds(metadata_ttl() + 1);
    harness.json_listing(SURPRISING).await;
    let conditional = harness.registry.conditional_calls(&upstream);
    assert_eq!(conditional.len(), 2);
    assert_eq!(conditional[0].etag.as_deref(), Some(ETAG));
    assert_eq!(
        conditional[1].etag.as_deref(),
        Some(ETAG_V2),
        "the second revalidation carries what the 304 handed back"
    );
    assert_eq!(
        conditional[1].last_modified.as_deref(),
        Some("Thu, 01 Jan 1970 00:00:00 GMT")
    );

    harness.shutdown().await;
}

/// (3, the other half) The production transport, against a real socket, asking for
/// PyPI's PEP 691 serialisation: a `304` carrying a body and headers we never asked
/// for surfaces as `NotModified` with no bytes attached. `MetadataResponse` has
/// nowhere to put a body on that branch, and this is what proves the client never
/// hands one over.
#[tokio::test]
async fn a_304_with_a_body_and_extra_headers_yields_no_bytes() {
    use probation::upstream::{MetadataRequest, MetadataResponse, OriginKind};
    use wiremock::ResponseTemplate;
    use wiremock::matchers::{method, path};

    let upstream = common::WiremockUpstream::start().await;
    wiremock::Mock::given(method("GET"))
        .and(path("/simple/friendly-bard/"))
        .respond_with(
            ResponseTemplate::new(304)
                .insert_header("etag", ETAG)
                .insert_header("x-pypi-note", "ignore me")
                .insert_header("cache-control", "public, max-age=31536000")
                .set_body_string("THIS BODY MUST NEVER BE READ"),
        )
        .mount(&upstream.server)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::PypiMetadata, &["simple", BARD, ""])
        .expect("the wiremock origin builds a URL");
    let answered = upstream
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            accept: "application/vnd.pypi.simple.v1+json",
            validators: Some(UpstreamValidators {
                etag: Some(ETAG.to_owned()),
                last_modified: None,
            }),
            max_bytes: 64,
        })
        .await
        .expect("the 304 is an answer, not a transport failure");

    match answered {
        MetadataResponse::NotModified { validators } => {
            assert_eq!(validators.etag.as_deref(), Some(ETAG));
        }
        MetadataResponse::Fresh { body, .. } => panic!(
            "a 304 became a document of {} bytes, so its body was read",
            body.len()
        ),
        MetadataResponse::Missing => panic!("a 304 became a 404"),
    }
}

// ---------------------------------------------------------------------------
// Slice 13, the PyPI half: the same two mechanisms npm's witnesses cover.
//
// Row 13 is "both ecosystems, one mechanism", and `src/pypi/mod.rs` carries the same
// generation-checked project reuse and the same parsed-once advertised set as
// `src/npm/mod.rs`. Its witnesses live here rather than beside npm's because both
// need a PyPI project whose artifact can actually be downloaded, and one artifact
// harness in this file serves both — where putting them in `artifacts_verification.rs`
// would mean a second, PyPI-shaped harness in a file whose every helper is npm's.
// ---------------------------------------------------------------------------

/// A wheel whose distribution part normalises to [`BARD`], so `file_identity`
/// accepts it as a file of that project.
const PIN_FILENAME: &str = "friendly_bard-1.0.0-py3-none-any.whl";
const PIN_OTHER_FILENAME: &str = "friendly_bard-2.0.0-py3-none-any.whl";

/// Five days before [`NOW`], so the one-day cooldown is spent and both files are
/// eligible before anything blocks one of them.
const PIN_UPLOADED: &str = "2026-04-01T00:00:00Z";

/// `tests/fixtures/artifacts/harmless-widget-1.0.0.tgz`, as `sha256sum` reports it.
/// The bytes are a fixture; what matters is that this instance computes this digest
/// for itself, because the document below advertises none.
const PIN_SHA256: &str = "029830248baf17af5d9a9e23d3e7054a8860882d1cdc06bbbb1549056d347acb";

/// The upstream path a [`FakeRegistry`] answer for a PyPI file is registered under,
/// matching the `url` [`pin_document`] advertises.
fn pypi_artifact_upstream_path(filename: &str) -> String {
    format!("/packages/ab/cd/{filename}")
}

/// One file entry advertising **no** `hashes` at all. That is what makes a block on
/// this instance's own computed digest the only way to reach it — the same condition
/// npm's `no_advertised_digest` sets up.
fn unhashed_file(filename: &str) -> Value {
    json!({
        "filename": filename,
        "url": format!("https://files.invalid/packages/ab/cd/{filename}"),
        "upload-time": PIN_UPLOADED,
    })
}

fn pin_document() -> String {
    document(
        BARD,
        vec![
            unhashed_file(PIN_FILENAME),
            unhashed_file(PIN_OTHER_FILENAME),
        ],
    )
}

/// A server with a data directory, so an artifact can be downloaded, verified and
/// pinned — which is what `harness` above cannot do.
async fn artifact_harness() -> (TestServer, TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = config_with(dir.path(), "", ONE_DAY);

    let registry = FakeRegistry::new();
    registry.answer(&pypi_upstream_path(BARD), FakeAnswer::Body(pin_document()));
    registry.answer(
        &pypi_artifact_upstream_path(PIN_FILENAME),
        FakeAnswer::Body(fixture("artifacts/harmless-widget-1.0.0.tgz")),
    );
    registry.answer(
        &pypi_artifact_upstream_path(PIN_OTHER_FILENAME),
        FakeAnswer::Body(fixture("artifacts/tampered-widget-1.0.0.tgz")),
    );

    let server = TestServer::start_in_with_registry(
        &dir.path().join("data"),
        config,
        TestClock::at_rfc3339(NOW).shared(),
        registry,
    )
    .await;
    (server, dir)
}

/// This instance's own artifact path for one file of a rendered JSON listing.
fn file_path(listing: &Value, filename: &str) -> String {
    let files = listing["files"].as_array().expect("`files` is an array");
    let file = files
        .iter()
        .find(|file| file["filename"].as_str() == Some(filename))
        .unwrap_or_else(|| panic!("the listing names {filename}: {listing}"));
    let url = file["url"].as_str().expect("a rewritten URL");
    url::Url::parse(url)
        .expect("the rewritten URL parses")
        .path()
        .to_owned()
}

async fn json_listing_of(server: &TestServer, project: &str) -> Value {
    let body = server
        .get_with_headers(
            &format!("/pypi/simple/{project}/"),
            &[("accept", JSON_ACCEPT)],
        )
        .await
        .text()
        .await
        .expect("a body");
    serde_json::from_str(&body).unwrap_or_else(|err| panic!("not JSON: {err}: {body}"))
}

fn lists(listing: &Value, filename: &str) -> bool {
    listing["files"]
        .as_array()
        .expect("`files` is an array")
        .iter()
        .any(|file| file["filename"].as_str() == Some(filename))
}

/// SPEC §9: "If a computed digest reveals a block not visible in upstream metadata,
/// invalidate that project's filtered metadata. The next resolution hides the
/// affected artifact."
///
/// The PyPI counterpart of `blocklist_revocation`'s
/// `a_computed_digest_block_hides_the_version_from_the_next_metadata_listing`, which
/// exists only for npm. Everything here goes through the public route: the listing
/// that advertises the file, the artifact request that teaches this instance the
/// file's SHA-256 and drops the project's cache entry, and the listing afterwards.
///
/// **What only an end-to-end run can check.** `current_project` is a private
/// `async fn`, so no integration test can call it — which means nothing else witnesses
/// that `src/pypi/mod.rs` builds its `ProjectKey` with `Ecosystem::PyPi` and routes it
/// into the same cache entry `artifacts::download::fetch` drops. Get that wiring wrong
/// and every unit-level check still passes while a blocked file stays listed. This is
/// deliberately *not* a test of the invalidation guard: nothing here races, so the
/// stale snapshot is never re-installed and the guard is never consulted. The guard's
/// own regression test is `npm_metadata`'s hand-driven racing-reader test.
#[tokio::test]
async fn a_computed_digest_block_hides_the_file_from_the_next_metadata_listing() {
    let (server, _dir) = artifact_harness().await;

    let listing = json_listing_of(&server, BARD).await;
    assert!(lists(&listing, PIN_FILENAME));
    assert!(lists(&listing, PIN_OTHER_FILENAME));

    // One download, which is what teaches this instance the file's SHA-256. The
    // document advertises no hashes at all, so this is the only way that digest can
    // become known — and the only way a block on it can reach the listing.
    assert_eq!(server.status(&file_path(&listing, PIN_FILENAME)).await, 200);

    common::publish_blocklist(
        &server,
        &common::snapshot_with(
            2,
            "2026-04-05T00:00:00Z",
            "2099-01-01T00:00:00Z",
            "",
            &format!(
                r#"{{"algorithm":"sha256","digest":"{PIN_SHA256}","reason":"known malicious artifact"}}"#
            ),
        ),
        common::parse_rfc3339(NOW),
    );

    let listing = json_listing_of(&server, BARD).await;
    assert!(
        !lists(&listing, PIN_FILENAME),
        "the next resolution hides the file its computed digest revealed a block \
         for: {listing}"
    );
    assert!(
        lists(&listing, PIN_OTHER_FILENAME),
        "and hides nothing else: {listing}"
    );
    server.shutdown().await;
}

/// SPEC §9 makes every PyPI artifact request confirm that its file is still
/// advertised, warm ones included, and SPEC §12 gives a warm artifact a 5 ms budget.
/// `src/pypi/mod.rs` keeps the advertised set with the snapshot it was parsed from for
/// the same reason `src/npm/mod.rs` does, and this is the PyPI half of that claim —
/// the same `stored_parses()` counter, the same assertion.
#[tokio::test]
async fn a_warm_pypi_artifact_request_does_not_reparse_the_project_document() {
    let (server, _dir) = artifact_harness().await;
    let listing = json_listing_of(&server, BARD).await;
    let path = file_path(&listing, PIN_FILENAME);

    // Cold: the transfer, the hashing, and whatever parsing a first look costs.
    assert_eq!(server.status(&path).await, 200);

    let before = server.app().store().caches().stored_parses();
    assert_eq!(server.status(&path).await, 200);
    let warm = server.app().store().caches().stored_parses() - before;

    assert_eq!(
        warm, 0,
        "a warm PyPI artifact request parsed the stored Simple API document {warm} \
         time(s); the advertised reference-id set is supposed to be kept with the \
         snapshot it was parsed from"
    );
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 15: a bounded maximum age for a cached snapshot (SPEC rev 3 §10)
// ---------------------------------------------------------------------------

/// A short metadata TTL, so a revalidation is cheap to reach, and a short ceiling, so
/// a whole ceiling fits inside a test. The sample's 300 s / 86 400 s would need a day
/// of simulated time per assertion.
const CEILING_TTL: u64 = 100;
const CEILING_MAX_AGE: u64 = 1_000;

/// Two fixtures whose effective ceilings are far enough apart to tell apart — which
/// is the property `two_projects_fetched_together_do_not_expire_together` is about.
/// The test asserts the gap rather than trusting this comment.
const CEILING_EARLY: &str = OTHER;
const CEILING_LATE: &str = BARD;

/// [`validated_document`] for any project: two files uploaded years ago, so nothing
/// here is ever held and every refusal below is the ceiling's doing.
fn ceiling_document(project: &str) -> String {
    document(
        project,
        vec![
            file(
                &format!("{}-1.0-py3-none-any.whl", project.replace('-', "_")),
                "2020-01-01T00:00:00Z",
            ),
            file(
                &format!("{}-1.1-py3-none-any.whl", project.replace('-', "_")),
                "2020-02-01T00:00:00Z",
            ),
        ],
    )
}

async fn ceiling_harness(max_age: u64, projects: &[&str]) -> Harness {
    let owned: Vec<(String, FakeAnswer)> = projects
        .iter()
        .map(|project| {
            (
                (*project).to_owned(),
                FakeAnswer::Validated {
                    etag: ETAG.to_owned(),
                    body: ceiling_document(project),
                },
            )
        })
        .collect();
    let answers: Vec<(&str, FakeAnswer)> = owned
        .iter()
        .map(|(project, answer)| (project.as_str(), answer.clone()))
        .collect();
    harness_configured(NOW, ONE_DAY, "", &answers, |config| {
        config.metadata_ttl_seconds = CEILING_TTL;
        config.metadata_max_age_seconds = max_age;
    })
    .await
}

/// The row on disk, read through the store rather than through the memory cache: the
/// column itself is the subject of these tests, not a copy of it.
async fn stored_project(
    harness: &Harness,
    project: &str,
) -> probation::store::rows::ProjectRow {
    harness
        .server
        .running()
        .app()
        .store()
        .get_project(Ecosystem::PyPi, project)
        .await
        .expect("a query")
        .expect("this instance has fetched the project")
}

/// This project's effective ceiling in whole seconds.
fn ceiling_seconds(project: &str, max_age: u64) -> i64 {
    probation::store::effective_max_age_micros(
        &ProjectKey::new(Ecosystem::PyPi, project),
        max_age,
    )
    .expect("a nonzero maximum age has a ceiling")
        / 1_000_000
}

/// How many whole seconds of wall time the harness's clock has covered since `from`.
fn elapsed_seconds(harness: &Harness, from: i64) -> i64 {
    (server_now(harness) - from) / 1_000_000
}

/// The status of a JSON listing request, for the cases where it is a refusal rather
/// than a document.
async fn listing_status(harness: &Harness, project: &str) -> u16 {
    harness
        .server
        .get_with_headers(
            &format!("/pypi/simple/{project}/"),
            &[("accept", JSON_ACCEPT)],
        )
        .await
        .status()
        .as_u16()
}

/// **The centre of this slice.** SPEC rev 3 §10: "a `304` renews validation time
/// only, never full fetch time."
///
/// If a `304` ever wrote `now` into `fetched_at_micros` the ceiling would silently
/// stop existing, and every other test in this file would keep passing until a copy
/// had aged past it. So this one asserts the STORED COLUMN directly, and it fails
/// when the field is advanced rather than only when the whole ceiling is removed.
#[tokio::test]
async fn a_304_does_not_advance_the_full_fetch_time() {
    let harness = ceiling_harness(CEILING_MAX_AGE, &[BARD]).await;
    let t0 = server_now(&harness);

    harness.json_listing(BARD).await;
    let first = stored_project(&harness, BARD).await;
    assert_eq!(
        first.fetched_at_micros, t0,
        "a 200 records the instant the document actually arrived"
    );
    assert_eq!(first.validated_at_micros, t0);

    for round in 1..=2 {
        harness.clock.advance_seconds(CEILING_TTL as i64 + 1);
        harness.json_listing(BARD).await;

        let row = stored_project(&harness, BARD).await;
        assert_eq!(
            row.fetched_at_micros, t0,
            "round {round}: the stored full-fetch time is carried forward unchanged. \
             Advancing it here deletes the ceiling and changes nothing else visible."
        );
        assert_eq!(
            row.validated_at_micros,
            server_now(&harness),
            "round {round}: while validation time is renewed, which is what a 304 does renew"
        );
    }

    assert_eq!(
        harness.registry.not_modified_answers(),
        2,
        "both revalidations really were answered 304 rather than with a body"
    );
    harness.shutdown().await;
}

/// SPEC rev 3 §10: "the next request must fetch it in full, sending no validators, so
/// upstream cannot answer `304`."
#[tokio::test]
async fn an_over_age_snapshot_is_refetched_in_full_without_validators() {
    let harness = ceiling_harness(CEILING_MAX_AGE, &[BARD]).await;
    let upstream = pypi_upstream_path(BARD);
    let t0 = server_now(&harness);

    harness.json_listing(BARD).await;
    assert!(
        harness.registry.conditional_calls(&upstream).is_empty(),
        "the first fetch has nothing stored to revalidate against"
    );

    // An ordinary revalidation first, so the only thing different about the third
    // request is the ceiling.
    harness.clock.advance_seconds(CEILING_TTL as i64 + 1);
    harness.json_listing(BARD).await;
    assert_eq!(harness.registry.conditional_calls(&upstream).len(), 1);
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // Exactly at the ceiling: the age rule is "reaches", not "passes".
    let ceiling = ceiling_seconds(BARD, CEILING_MAX_AGE);
    harness
        .clock
        .advance_seconds(ceiling - elapsed_seconds(&harness, t0));
    harness.json_listing(BARD).await;

    assert_eq!(harness.metadata_calls(BARD), 3);
    assert_eq!(
        harness.registry.conditional_calls(&upstream).len(),
        1,
        "the over-age refresh carried no validators at all, so upstream was given no \
         opportunity to answer 304"
    );
    assert_eq!(harness.registry.not_modified_answers(), 1);
    assert_eq!(
        stored_project(&harness, BARD).await.fetched_at_micros,
        server_now(&harness),
        "and the full fetch the ceiling forced is recorded as one"
    );

    harness.shutdown().await;
}

/// SPEC rev 3 §10: "An over-age snapshot is never served: if the full fetch fails or
/// upstream is unreachable, refuse the request."
///
/// The snapshot here is comfortably inside its metadata TTL — a `304` renewed it
/// moments ago — so without the ceiling this request is a warm hit that never reaches
/// upstream at all. Fail-closed is the whole point, and it is deliberate.
#[tokio::test]
async fn an_over_age_snapshot_is_never_served_when_upstream_is_unreachable() {
    let harness = ceiling_harness(CEILING_MAX_AGE, &[BARD]).await;
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(BARD, CEILING_MAX_AGE);

    harness.json_listing(BARD).await;

    // Revalidated fifty seconds before the ceiling, then sixty seconds on: over-age,
    // and still well inside the hundred-second TTL.
    harness.clock.advance_seconds(ceiling - 50);
    harness.json_listing(BARD).await;
    harness.clock.advance_seconds(60);
    assert!(elapsed_seconds(&harness, t0) >= ceiling);

    harness.registry.go_offline();
    assert_eq!(
        listing_status(&harness, BARD).await,
        502,
        "an over-age snapshot is refused rather than served, even though its metadata \
         TTL has not expired"
    );
    assert_eq!(
        stored_project(&harness, BARD).await.fetched_at_micros,
        t0,
        "and the failed fetch committed nothing, so the copy is still exactly as old"
    );

    harness.shutdown().await;
}

/// TM-15-1: an unchanging or dishonest upstream answering `304` forever cannot hold
/// this firewall's view of a project fixed. However many revalidations succeed, the
/// ceiling still forces one unconditional full fetch.
#[tokio::test]
async fn repeated_304s_cannot_extend_age_past_the_ceiling() {
    let harness = ceiling_harness(CEILING_MAX_AGE, &[BARD]).await;
    let upstream = pypi_upstream_path(BARD);
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(BARD, CEILING_MAX_AGE);
    let step = CEILING_TTL as i64 + 1;

    harness.json_listing(BARD).await;

    let mut rounds = 0usize;
    while elapsed_seconds(&harness, t0) + step < ceiling {
        harness.clock.advance_seconds(step);
        harness.json_listing(BARD).await;
        rounds += 1;
        assert_eq!(
            stored_project(&harness, BARD).await.fetched_at_micros,
            t0,
            "round {rounds}: the copy keeps ageing while upstream keeps saying 304"
        );
    }
    assert!(rounds >= 5, "the ceiling was crossed too soon to be a test");
    assert_eq!(harness.registry.not_modified_answers(), rounds);
    assert_eq!(harness.registry.conditional_calls(&upstream).len(), rounds);

    // The step that crosses the ceiling.
    harness.clock.advance_seconds(step);
    harness.json_listing(BARD).await;

    assert_eq!(
        stored_project(&harness, BARD).await.fetched_at_micros,
        server_now(&harness),
        "the ceiling forced a full fetch however many 304s preceded it"
    );
    assert_eq!(
        harness.registry.conditional_calls(&upstream).len(),
        rounds,
        "and it asked unconditionally, so upstream could not answer 304 again"
    );
    assert_eq!(harness.registry.not_modified_answers(), rounds);

    harness.shutdown().await;
}

/// SPEC rev 3 §4: zero disables the ceiling. It is off, not merely very large — the
/// copy below is more than a week old and still revalidated conditionally.
#[tokio::test]
async fn a_zero_ceiling_restores_unbounded_revalidation() {
    let harness = ceiling_harness(0, &[BARD]).await;
    let upstream = pypi_upstream_path(BARD);
    let t0 = server_now(&harness);

    harness.json_listing(BARD).await;

    for round in 1..=5 {
        harness.clock.advance_seconds(2 * ONE_DAY as i64);
        harness.json_listing(BARD).await;
        assert_eq!(
            stored_project(&harness, BARD).await.fetched_at_micros,
            t0,
            "round {round}: with no ceiling nothing ever forces a full fetch"
        );
    }

    assert_eq!(elapsed_seconds(&harness, t0), 10 * ONE_DAY as i64);
    assert_eq!(
        harness.registry.conditional_calls(&upstream).len(),
        5,
        "every revalidation stayed conditional"
    );
    assert_eq!(harness.registry.not_modified_answers(), 5);

    harness.shutdown().await;
}

/// The spreading rule of SPEC rev 3 §10. Two projects fetched at the same instant do
/// not expire at the same instant, so an upstream outage crossing the ceiling lapses
/// them gradually rather than all at once.
#[tokio::test]
async fn two_projects_fetched_together_do_not_expire_together() {
    let early_ceiling = ceiling_seconds(CEILING_EARLY, CEILING_MAX_AGE);
    let late_ceiling = ceiling_seconds(CEILING_LATE, CEILING_MAX_AGE);
    assert!(
        late_ceiling > early_ceiling + 20,
        "these two fixtures were chosen for ceilings far enough apart to tell apart: \
         {early_ceiling} and {late_ceiling}"
    );

    let harness = ceiling_harness(CEILING_MAX_AGE, &[CEILING_EARLY, CEILING_LATE]).await;
    let t0 = server_now(&harness);

    // Fetched together, as a bulk seed or a restore would.
    harness.json_listing(CEILING_EARLY).await;
    harness.json_listing(CEILING_LATE).await;
    assert_eq!(
        stored_project(&harness, CEILING_EARLY)
            .await
            .fetched_at_micros,
        t0
    );
    assert_eq!(
        stored_project(&harness, CEILING_LATE)
            .await
            .fetched_at_micros,
        t0
    );

    // Revalidated together, shortly before the earlier of the two ceilings.
    harness.clock.advance_seconds(early_ceiling - 50);
    harness.json_listing(CEILING_EARLY).await;
    harness.json_listing(CEILING_LATE).await;

    // Sixty seconds on, both are inside their TTL and exactly one is over-age.
    harness.clock.advance_seconds(60);
    let elapsed = elapsed_seconds(&harness, t0);
    assert!(elapsed >= early_ceiling && elapsed < late_ceiling);

    harness.registry.go_offline();
    assert_eq!(
        listing_status(&harness, CEILING_EARLY).await,
        502,
        "the project whose ceiling has lapsed refuses"
    );
    assert_eq!(
        listing_status(&harness, CEILING_LATE).await,
        200,
        "the one fetched at the very same instant is still served: the two expiries \
         were spread apart by the per-project offset"
    );

    harness.shutdown().await;
}

/// SPEC rev 3 §10: "The offset only ever shortens: no snapshot is served beyond
/// `metadata_max_age_seconds`, and the configured value remains a true maximum."
#[tokio::test]
async fn the_effective_ceiling_never_exceeds_the_configured_maximum() {
    // The formula, over a wide spread of names and of configured values — including
    // the small ones where a tenth rounds away entirely.
    for max_age in [1u64, 9, 10, 11, 300, 1_000, 86_400, 31_536_000] {
        let configured = max_age as i64 * 1_000_000;
        for index in 0..500 {
            let key = ProjectKey::new(Ecosystem::PyPi, format!("fixture-spread-{index}"));
            let effective = probation::store::effective_max_age_micros(&key, max_age)
                .expect("a nonzero maximum age has a ceiling");

            assert!(
                effective <= configured,
                "max_age {max_age}, {key:?}: the offset lengthened the ceiling to {effective}"
            );
            assert!(
                effective > 0 && effective * 10 >= configured * 9,
                "max_age {max_age}, {key:?}: the offset took more than a tenth ({effective})"
            );
            assert_eq!(
                effective,
                probation::store::effective_max_age_micros(&key, max_age).unwrap(),
                "the offset is deterministic, so a restart lands on the same ceiling"
            );
        }
    }
    assert_eq!(
        probation::store::effective_max_age_micros(
            &ProjectKey::new(Ecosystem::PyPi, BARD),
            0
        ),
        None,
        "and zero is no ceiling at all rather than a ceiling of zero"
    );

    // And the guarantee where it is observable: at exactly the configured maximum,
    // whatever this project's offset happened to be, the snapshot is over-age.
    let harness = ceiling_harness(CEILING_MAX_AGE, &[BARD]).await;
    let upstream = pypi_upstream_path(BARD);
    let t0 = server_now(&harness);

    harness.json_listing(BARD).await;
    harness.clock.advance_seconds(CEILING_MAX_AGE as i64);
    harness.json_listing(BARD).await;

    assert!(
        harness.registry.conditional_calls(&upstream).is_empty(),
        "the configured maximum is a true maximum: by then the refresh is unconditional"
    );
    assert_eq!(
        stored_project(&harness, BARD).await.fetched_at_micros,
        t0 + CEILING_MAX_AGE as i64 * 1_000_000
    );

    harness.shutdown().await;
}

/// SPEC §5: the ceiling is a wall-clock comparison, because the instant it measures
/// from is persisted and must survive a restart. "A backward jump delays the trip by
/// at most the size of the jump, after which wall time advances again and the ceiling
/// applies as before."
#[tokio::test]
async fn a_backward_wall_clock_jump_only_delays_the_ceiling() {
    let harness = ceiling_harness(CEILING_MAX_AGE, &[BARD]).await;
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(BARD, CEILING_MAX_AGE);

    harness.json_listing(BARD).await;
    harness.clock.advance_seconds(ceiling - 50);
    harness.json_listing(BARD).await;
    harness.clock.advance_seconds(60);

    // An NTP step two hundred seconds backwards: the wall clock moves, the monotonic
    // reading does not. The copy now looks younger than its ceiling again.
    harness.clock.rewind_wall_clock_seconds(200);
    assert!(elapsed_seconds(&harness, t0) < ceiling);
    harness.registry.go_offline();
    assert_eq!(
        listing_status(&harness, BARD).await,
        200,
        "a backward jump delays the trip rather than defeating it: the snapshot is \
         under its ceiling again and is served from the stored copy"
    );

    // Wall time advances past the jump, and the ceiling applies exactly as before.
    harness.clock.advance_seconds(210);
    assert!(elapsed_seconds(&harness, t0) >= ceiling);
    assert_eq!(
        listing_status(&harness, BARD).await,
        502,
        "the delay was bounded by the size of the jump; once wall time is past the \
         ceiling the snapshot is over-age and is not served"
    );

    harness.shutdown().await;
}

/// The coalescing boundary: a request arrives while another request's refresh for the
/// same project is already in flight, and the wall clock crosses the ceiling during
/// that window.
///
/// The leader decided it was not over-age and sent validators; by the time the joiner
/// arrives the copy *is* over-age. Two things have to hold, and the second is what
/// keeps the first from being an exposure:
///
/// (a) the `304` that answers the leader carries the stored full-fetch time forward
///     unchanged, so the boundary crossing does not launder the copy into looking
///     freshly fetched; and
/// (b) the next request, with nothing in flight, re-evaluates over-age against the
///     wall clock it reads for itself, and refuses with upstream unreachable rather
///     than treating the just-completed refresh as evidence of freshness.
///
/// The joiner is answered from the leader's result — that is the latch working as
/// SPEC §10 asks — so one joiner does see a copy that went over-age mid-flight. That
/// window is bounded by a single in-flight refresh and closes at the very next
/// request, which is exactly what (b) witnesses.
#[tokio::test]
async fn a_joiner_across_the_ceiling_boundary_neither_launders_nor_outlives_it() {
    let gate = Gate::new();
    let harness = ceiling_harness(CEILING_MAX_AGE, &[BARD]).await;
    let upstream = pypi_upstream_path(BARD);
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::PyPi, BARD);
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(BARD, CEILING_MAX_AGE);

    // Seeded by a full fetch, then upstream starts parking every revalidation.
    harness.json_listing(BARD).await;
    assert_eq!(stored_project(&harness, BARD).await.fetched_at_micros, t0);
    harness.registry.answer(
        &upstream,
        FakeAnswer::GatedNotModified {
            etag: ETAG.to_owned(),
            gate: Arc::clone(&gate),
        },
    );

    // Sixty seconds short of the ceiling: past the TTL, so this refreshes, and not yet
    // over-age, so it asks conditionally.
    harness.clock.advance_seconds(ceiling - 60);
    let leader = tokio::spawn({
        let app = Arc::clone(&app);
        async move { probation::pypi::ensure_fresh_project(&app, BARD).await }
    });
    gate.wait_until_reached().await;
    assert_eq!(
        harness.registry.conditional_calls(&upstream).len(),
        1,
        "the parked refresh is a conditional one, which is the only shape this boundary has"
    );

    // The ceiling passes while that refresh is in the air. The leader is suspended
    // INSIDE the transport call, so its slot is already registered and it cannot
    // unregister before the joiner arrives — which is the ordering the whole test
    // depends on, and the one a `tokio::join!` of two futures cannot guarantee.
    harness.clock.advance_seconds(70);
    assert!(
        probation::store::is_over_age(&key, CEILING_MAX_AGE, t0, server_now(&harness)),
        "the joiner's own classification differs from the leader's: by this clock the \
         copy is over-age, so an UNCOALESCED request here would send no validators"
    );

    let joiner = tokio::spawn({
        let app = Arc::clone(&app);
        async move { probation::pypi::ensure_fresh_project(&app, BARD).await }
    });
    // Positive evidence that the joiner coalesced rather than becoming a second
    // leader: two `join()` calls landed on the one slot. Had it started a slot of its
    // own this would stay at 1 and the wait would fail the test rather than deadlock.
    wait_until("the joiner shares the leader's refresh", PATIENCE, || {
        app.downloads.metadata().waiting_on(&key) == 2
    })
    .await;
    gate.release();

    leader
        .await
        .expect("the leader task finishes")
        .expect("the leader is answered by its own 304");
    let joined = joiner.await.expect("the joiner task finishes");

    // What the JOINER received, which is the point of this test. An uncoalesced
    // request at this instant is over-age, sends no validators, and this registry
    // answers `304` to an unconditional request — so it would be `UpstreamInvalid`,
    // deterministically. The joiner succeeding is only possible through the slot.
    assert!(
        joined.is_ok(),
        "the joiner was handed the leader's result rather than making a decision of \
         its own: an independent over-age request here is refused, not served ({:?})",
        joined.err()
    );
    assert_eq!(
        harness.metadata_calls(BARD),
        2,
        "one seeding fetch and one refresh, and no third: the joiner made no upstream \
         call of its own. This is the one-attempt-versus-two signal that separates a \
         forced race from a lucky ordering."
    );

    // (a) The boundary crossing did not launder the copy.
    assert_eq!(
        stored_project(&harness, BARD).await.fetched_at_micros,
        t0,
        "the 304 carried the stored full-fetch time forward even though the ceiling \
         passed while it was in flight"
    );

    // The control for the assertion above, run in the same state: with nothing in
    // flight there is no slot to join, so this request IS its own leader. It takes
    // the over-age path, asks unconditionally, and is refused — which is what the
    // joiner would have got had it not coalesced, and is therefore what makes the
    // joiner's success mean something.
    harness.registry.answer(
        &upstream,
        FakeAnswer::AlwaysNotModified {
            etag: Some(ETAG.to_owned()),
            last_modified: None,
        },
    );
    assert!(
        matches!(
            probation::pypi::ensure_fresh_project(&app, BARD).await,
            Err(ApiError::UpstreamInvalid)
        ),
        "an uncoalesced over-age request sends no validators, so a 304 answering it is \
         an upstream protocol violation and the over-age copy is not served"
    );
    assert_eq!(
        harness.metadata_calls(BARD),
        3,
        "and it made an upstream call of its own, which the joiner did not"
    );

    // (b) A refresh that has just completed is not evidence of freshness either.
    harness.registry.go_offline();
    assert!(
        matches!(
            probation::pypi::ensure_fresh_project(&app, BARD).await,
            Err(ApiError::UpstreamFailure)
        ),
        "the copy is over-age against the clock this request reads, and is refused"
    );
    assert_eq!(
        listing_status(&harness, BARD).await,
        502,
        "and the served route refuses it too"
    );

    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}
