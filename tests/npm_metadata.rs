//! Slice 5's witness: npm metadata, end to end.
//!
//! Everything here runs against an in-process `FakeRegistry` and a clock the test
//! moves by hand, so a run reaches no socket and depends on no wall clock. The
//! 100-version fixture and the clock it is read at are chosen so that one snapshot
//! exercises every tag rule at once: `latest` points at a version that has not been
//! published yet, `beta` at another, `next` at an eligible release candidate, and
//! `legacy` at an ancient stable release.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, config_with_open_blocklist,
    fake_origins, fixture, logs, npm_upstream_path, publish_blocklist, sample_config, snapshot,
    wait_until,
};
use nodejs_semver::Version;
use probation::http::error::ApiError;
use probation::npm::tags::highest_eligible_stable_at_or_below;
use probation::policy::Ecosystem;
use probation::store::cache::{ProjectKey, RenderKey, Representation};
use probation::store::rows::ProjectRefresh;
use probation::upstream::UpstreamValidators;
use serde_json::Value;
use tempfile::TempDir;

const WIDGET: &str = "fixture-widget";
const SWARM: &str = "fixture-swarm";

/// The instant the 100-version fixture is read at in most tests.
///
/// `2.0.0` was published twelve hours earlier, so it is held; `2.0.1` to `2.0.4` are
/// not published yet; `2.0.0-rc.5` is thirty-six hours old and eligible. `latest`
/// therefore has to fall back past an eligible *prerelease* to a stable release, and
/// that is the case the rule is easiest to get wrong on.
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    /// Holds the blocklist file for as long as the server uses it.
    _dir: TempDir,
}

impl Harness {
    /// How many upstream *metadata* fetches this package has caused.
    fn metadata_calls(&self, name: &str) -> usize {
        let path = npm_upstream_path(name);
        self.registry
            .calls()
            .iter()
            .filter(|url| url.path() == path)
            .count()
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

/// How long a consequence is allowed to take before a test calls it a failure.
/// Generous on purpose: it bounds a wait, it does not create one.
const PATIENCE: Duration = Duration::from_secs(20);

async fn harness(now: &str, cooldown: u64, answers: &[(&str, FakeAnswer)]) -> Harness {
    harness_configured(now, answers, |config| config.cooldown_seconds = cooldown).await
}

/// The same server with the configuration the test asks for. The maximum-age tests
/// need a shorter metadata TTL and a shorter ceiling than the shipped sample, so that
/// a whole ceiling can be crossed without the arithmetic becoming a second puzzle.
async fn harness_configured(
    now: &str,
    answers: &[(&str, FakeAnswer)],
    tweak: impl FnOnce(&mut probation::config::Config),
) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    tweak(&mut config);

    let registry = FakeRegistry::new();
    for (name, answer) in answers {
        registry.answer(&npm_upstream_path(name), answer.clone());
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

/// The representative fixture, at [`NOW`], with the default one-day cooldown.
async fn widget() -> Harness {
    harness(
        NOW,
        ONE_DAY,
        &[(
            WIDGET,
            FakeAnswer::Body(fixture("npm/representative-100-versions.json")),
        )],
    )
    .await
}

/// `reqwest`'s `json` feature is not enabled — the crate carries only what the
/// application needs — so a body is read as text and parsed here.
async fn body_json(response: reqwest::Response) -> Value {
    let text = response.text().await.expect("a body");
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("the body is not JSON: {err}: {text}"))
}

fn upstream_document() -> Value {
    serde_json::from_str(&fixture("npm/representative-100-versions.json"))
        .expect("the fixture is JSON")
}

// ---------------------------------------------------------------------------
// Version precedence
// ---------------------------------------------------------------------------

/// The `latest` fallback rests entirely on npm version precedence, so the crate that
/// supplies it is asserted against a published corpus rather than trusted.
///
/// The corpus is the ordering example from the semantic-versioning specification
/// npm's own documentation points at (semver 2.0.0 §11), plus the build-metadata rule
/// from §10. A disagreement here is a blocker, not something to work around at the
/// call site.
#[test]
fn npm_version_precedence_matches_a_published_corpus() {
    // semver 2.0.0 §11.4.4, verbatim, with the major/minor/patch chain from §11.2
    // in front of it.
    const ASCENDING: &[&str] = &[
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.1.0",
        "2.0.0",
        "2.1.0",
        "2.1.1",
    ];

    let parsed: Vec<Version> = ASCENDING
        .iter()
        .map(|text| Version::parse(text).unwrap_or_else(|err| panic!("`{text}` parses: {err}")))
        .collect();

    for window in parsed.windows(2) {
        assert!(
            window[0] < window[1],
            "published precedence puts {} below {}, the crate does not",
            window[0],
            window[1]
        );
    }

    // §10: "Build metadata MUST be ignored when determining version precedence."
    assert_eq!(
        Version::parse("1.0.0+build.1").expect("parses"),
        Version::parse("1.0.0+build.2").expect("parses")
    );
    assert_eq!(
        Version::parse("1.0.0+build.1").expect("parses"),
        Version::parse("1.0.0").expect("parses")
    );

    // §11.4.1: numeric identifiers always compare below alphanumeric ones.
    assert!(
        Version::parse("1.0.0-1").expect("parses") < Version::parse("1.0.0-alpha").expect("parses")
    );
    // §11.3: a prerelease has lower precedence than the release it precedes.
    assert!(
        Version::parse("1.0.0-rc.1").expect("parses") < Version::parse("1.0.0").expect("parses")
    );

    // And the rule that consumes all of the above: the fallback orders by that
    // precedence, takes the highest, and never takes a prerelease.
    let eligible = ["0.9.0", "1.0.0-rc.1", "1.0.9", "1.0.10", "2.0.0"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        highest_eligible_stable_at_or_below("1.1.0", &eligible).as_deref(),
        Some("1.0.10"),
        "1.0.10 outranks 1.0.9 numerically, and 2.0.0 is above the target"
    );
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

#[tokio::test]
async fn latest_falls_back_to_highest_eligible_stable_at_or_below_target() {
    let harness = widget().await;
    let document = harness.server.json(&format!("/npm/{WIDGET}")).await;

    assert_eq!(
        upstream_document()["dist-tags"]["latest"],
        Value::from("2.0.4"),
        "the fixture's own latest is the version this test needs excluded"
    );
    assert_eq!(
        document["dist-tags"]["latest"],
        Value::from("1.0.89"),
        "the highest eligible stable release at or below 2.0.4; 2.0.0 is still held, \
         2.0.1 to 2.0.4 are not published yet, and 2.0.0-rc.5 is eligible but is not stable"
    );
    assert!(
        document["versions"].get("1.0.89").is_some(),
        "and the version latest now names is actually in the document"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn eligible_tags_including_a_prerelease_are_preserved_unchanged() {
    let harness = widget().await;
    let document = harness.server.json(&format!("/npm/{WIDGET}")).await;

    assert_eq!(
        document["dist-tags"]["next"],
        Value::from("2.0.0-rc.5"),
        "a tag deliberately pointing at an eligible prerelease stays where it is"
    );
    assert_eq!(document["dist-tags"]["legacy"], Value::from("1.0.0"));

    harness.shutdown().await;
}

#[tokio::test]
async fn custom_tag_on_excluded_version_is_omitted_not_guessed() {
    let harness = widget().await;
    let document = harness.server.json(&format!("/npm/{WIDGET}")).await;

    assert_eq!(
        upstream_document()["dist-tags"]["beta"],
        Value::from("2.0.2"),
        "upstream beta points at a version that is not published yet"
    );
    let tags = document["dist-tags"]
        .as_object()
        .expect("dist-tags is an object");
    assert!(
        !tags.contains_key("beta"),
        "beta is dropped, not moved onto another channel member: {tags:?}"
    );
    assert_eq!(
        tags.keys().collect::<Vec<_>>(),
        vec!["latest", "legacy", "next"],
        "exactly the tags the rules keep, and no invented one"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn latest_omitted_when_no_eligible_candidate_is_at_or_below_it() {
    // A tiny document of its own: `latest` is held, and the only other version is a
    // prerelease *above* it, so there is nothing the fallback is allowed to choose.
    let document = r#"{
        "name": "fixture-narrow",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {"name": "fixture-narrow", "version": "1.0.0",
                      "dist": {"tarball": "https://npm.invalid/n/-/n-1.0.0.tgz"}},
            "2.0.0-beta.1": {"name": "fixture-narrow", "version": "2.0.0-beta.1",
                      "dist": {"tarball": "https://npm.invalid/n/-/n-2.0.0-beta.1.tgz"}}
        },
        "time": {
            "1.0.0": "2026-04-06T06:00:00.000Z",
            "2.0.0-beta.1": "2026-04-01T00:00:00.000Z"
        }
    }"#;

    let harness = harness(
        NOW,
        ONE_DAY,
        &[("fixture-narrow", FakeAnswer::Body(document.to_owned()))],
    )
    .await;
    let rendered = harness.server.json("/npm/fixture-narrow").await;

    assert!(
        !rendered["dist-tags"]
            .as_object()
            .expect("dist-tags is an object")
            .contains_key("latest"),
        "no eligible stable release at or below 1.0.0, so latest is omitted rather than \
         pointed at the eligible prerelease above it"
    );
    assert!(rendered["versions"].get("2.0.0-beta.1").is_some());

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Filtering and rewriting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn excluded_versions_are_removed_from_the_document_and_the_time_map() {
    let harness = widget().await;
    let document = harness.server.json(&format!("/npm/{WIDGET}")).await;

    for excluded in ["2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4"] {
        assert!(
            document["versions"].get(excluded).is_none(),
            "{excluded} is held or unpublished and must not be offered"
        );
        assert!(
            document["time"].get(excluded).is_none(),
            "{excluded} must leave the publication-time map too"
        );
    }
    assert!(document["time"].get("1.0.89").is_some());
    assert!(
        document["time"].get("created").is_some() && document["time"].get("modified").is_some(),
        "created and modified are not versions and are not pruned"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn tarball_urls_are_rewritten_to_this_instance() {
    let harness = widget().await;
    let document = harness.server.json(&format!("/npm/{WIDGET}")).await;

    let dist = &document["versions"]["1.0.89"]["dist"];
    let tarball = dist["tarball"].as_str().expect("a tarball URL");
    assert!(
        tarball.starts_with("https://packages.example.org/npm/artifacts/"),
        "the client is pointed here, never upstream: {tarball}"
    );
    assert!(tarball.ends_with("/fixture-widget-1.0.89.tgz"));

    let reference_id = tarball
        .trim_start_matches("https://packages.example.org/npm/artifacts/")
        .split('/')
        .next()
        .expect("a reference id segment");
    assert_eq!(reference_id.len(), 64, "a reference id is a SHA-256 in hex");
    assert!(reference_id.chars().all(|c| c.is_ascii_hexdigit()));

    assert_eq!(
        dist["integrity"],
        upstream_document()["versions"]["1.0.89"]["dist"]["integrity"],
        "the upstream integrity field is preserved beside the rewritten URL"
    );

    harness.shutdown().await;
}

/// The one package name that collides with the artifact route's own segment, and the
/// file it advertises.
const COLLIDING: &str = "artifacts";
const COLLIDING_FILENAME: &str = "artifacts-1.0.0.tgz";
/// Its bytes upstream. No `integrity` or `shasum` is advertised for it, so nothing is
/// pinned and what comes back downstream is exactly this.
const COLLIDING_BYTES: &str = "the artifacts package's own tarball";

/// One package whose name collides with the artifact route's own segment.
fn artifacts_package() -> String {
    serde_json::json!({
        "name": COLLIDING,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": COLLIDING,
                "version": "1.0.0",
                "dist": {"tarball": common::npm_tarball_url(COLLIDING, COLLIDING_FILENAME)},
            }
        },
        "time": {"1.0.0": "2026-04-01T00:00:00Z"},
    })
    .to_string()
}

/// Artifacts live at `/npm/artifacts/{reference_id}/{filename}` — four segments,
/// against package routes of two and three. A package literally named `artifacts` is
/// therefore untouched, and a scoped name stays two and three because its `/` is
/// percent-encoded.
///
/// All four arities are exercised against the same running router and the same name,
/// ending in a real download: asserting the shape of the rendered URL would leave the
/// only interesting half of this — that the four-segment route still wins while the
/// two- and three-segment ones do too — proven by nothing.
#[tokio::test]
async fn a_package_named_artifacts_still_resolves() {
    let harness = harness(
        NOW,
        ONE_DAY,
        &[(COLLIDING, FakeAnswer::Body(artifacts_package()))],
    )
    .await;
    harness.registry.answer(
        &common::npm_artifact_upstream_path(COLLIDING, COLLIDING_FILENAME),
        FakeAnswer::Body(COLLIDING_BYTES.to_owned()),
    );

    let document = harness.server.json("/npm/artifacts").await;
    assert_eq!(document["name"], Value::from(COLLIDING));
    assert!(
        document["versions"]["1.0.0"].is_object(),
        "the two-segment package route is not shadowed by the artifact route: \
         {document}"
    );

    let version = harness.server.json("/npm/artifacts/1.0.0").await;
    assert_eq!(version["version"], Value::from("1.0.0"));

    let tarball = version["dist"]["tarball"].as_str().expect("a tarball URL");
    assert!(
        tarball.starts_with("https://packages.example.org/npm/artifacts/"),
        "and this package's own artifact is served under the npm root: {tarball}"
    );

    // The advertised URL, fetched. `/npm/artifacts/{id}/{filename}` has to reach the
    // artifact handler even though `/npm/artifacts` reached a package a moment ago,
    // and it has to deliver the bytes rather than merely answer.
    let path = common::artifact_path(&document, "1.0.0");
    let response = harness.server.get(&path).await;
    let status = response.status();
    let body = response.bytes().await.expect("the artifact body");
    assert!(
        status.is_success(),
        "{path} answered {status} for a package named {COLLIDING}: \
         {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        body.as_ref(),
        COLLIDING_BYTES.as_bytes(),
        "the tarball a client would install is this package's own bytes"
    );

    harness.shutdown().await;
}

/// SPEC §6: "Preserve dependency, optional dependency, peer dependency, platform,
/// and engine information. Never edit dependency constraints."
#[tokio::test]
async fn dependency_and_peer_fields_are_never_edited() {
    let harness = widget().await;
    let served = harness.server.json(&format!("/npm/{WIDGET}")).await;
    let upstream = upstream_document();

    const UNTOUCHED: &[&str] = &[
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
        "engines",
        "os",
        "cpu",
        "bin",
        "directories",
    ];

    let mut compared = 0usize;
    for version in served["versions"]
        .as_object()
        .expect("versions is an object")
        .keys()
    {
        for field in UNTOUCHED {
            let before = &upstream["versions"][version][field];
            let after = &served["versions"][version][field];
            assert_eq!(
                serde_json::to_string(before).expect("upstream field serialises"),
                serde_json::to_string(after).expect("served field serialises"),
                "{version}.{field} was edited"
            );
            compared += 1;
        }
    }
    assert!(compared >= 900, "only {compared} fields were compared");

    // And the one field that *is* rewritten really was, so the comparison above is
    // not passing because nothing happened at all.
    assert_ne!(
        served["versions"]["1.0.0"]["dist"]["tarball"],
        upstream["versions"]["1.0.0"]["dist"]["tarball"]
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn abbreviated_is_derived_from_the_same_snapshot_as_full() {
    let harness = widget().await;
    let full = harness.server.json(&format!("/npm/{WIDGET}")).await;

    let response = harness
        .server
        .get_with_headers(
            &format!("/npm/{WIDGET}"),
            &[("accept", "application/vnd.npm.install-v1+json")],
        )
        .await;
    assert_eq!(response.status().as_u16(), 200);
    assert!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("vnd.npm.install-v1+json")),
        "the abbreviated form is served as itself"
    );
    let abbreviated = body_json(response).await;

    assert_eq!(
        abbreviated["versions"]
            .as_object()
            .expect("versions is an object")
            .keys()
            .collect::<Vec<_>>(),
        full["versions"]
            .as_object()
            .expect("versions is an object")
            .keys()
            .collect::<Vec<_>>(),
        "both forms come from the same filtered snapshot, so they list the same versions"
    );
    assert_eq!(abbreviated["dist-tags"], full["dist-tags"]);
    assert_eq!(
        abbreviated["versions"]["1.0.0"]["dependencies"],
        full["versions"]["1.0.0"]["dependencies"]
    );
    assert!(
        abbreviated["versions"]["1.0.0"].get("_npmUser").is_none(),
        "the abbreviated form carries the documented field set and no more"
    );

    harness.shutdown().await;
}

/// SPEC §6: "Support unscoped and scoped package names, including npm's
/// percent-encoded scoped form."
#[tokio::test]
async fn scoped_and_percent_encoded_names() {
    let scoped = r#"{
        "name": "@fixture/widget",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {"name": "@fixture/widget", "version": "1.0.0",
                      "dist": {"tarball": "https://npm.invalid/@fixture/widget/-/widget-1.0.0.tgz"}}
        },
        "time": {"1.0.0": "2026-01-01T00:00:00.000Z"}
    }"#;

    let harness = harness(
        NOW,
        ONE_DAY,
        &[("@fixture/widget", FakeAnswer::Body(scoped.to_owned()))],
    )
    .await;

    let encoded = harness.server.json("/npm/@fixture%2Fwidget").await;
    assert_eq!(encoded["name"], Value::from("@fixture/widget"));
    assert!(encoded["versions"].get("1.0.0").is_some());

    // npm's registry accepts the unencoded spelling too, and it arrives here as two
    // path components rather than one.
    let plain = harness.server.json("/npm/@fixture/widget").await;
    assert_eq!(plain, encoded, "both spellings name the same package");

    let asked: Vec<String> = harness
        .registry
        .calls()
        .iter()
        .map(|url| url.path().to_owned())
        .collect();
    assert!(
        asked.iter().all(|path| path == "/@fixture%2Fwidget"),
        "the scope separator is percent-encoded on the way upstream, never turned into \
         a second path segment: {asked:?}"
    );

    assert_eq!(harness.server.status("/npm/@fixture").await, 400);
    // Written onto the socket by hand: `reqwest` decodes `%2E%2E` into `..` and then
    // removes the dot segment, so a route test that went through it would silently
    // be testing nothing (slice 4's carry-forward).
    assert_eq!(harness.server.raw_get_status("/npm/%2E%2E").await, 400);

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// The exact-version route
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exact_version_route_applies_the_same_checks() {
    let harness = widget().await;

    let eligible = harness.server.json(&format!("/npm/{WIDGET}/1.0.0")).await;
    assert_eq!(eligible["version"], Value::from("1.0.0"));
    assert!(
        eligible["dist"]["tarball"]
            .as_str()
            .expect("a tarball")
            .starts_with("https://packages.example.org/npm/artifacts/")
    );

    // A tag resolves through the filtered tag set, so `latest` gives the fallback and
    // a tag the rules dropped is simply not there.
    let latest = harness.server.json(&format!("/npm/{WIDGET}/latest")).await;
    assert_eq!(latest["version"], Value::from("1.0.89"));
    assert_eq!(
        harness.server.status(&format!("/npm/{WIDGET}/beta")).await,
        404
    );
    assert_eq!(
        harness.server.status(&format!("/npm/{WIDGET}/9.9.9")).await,
        404
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn a_held_version_is_403_with_eligible_at_and_retry_after() {
    let harness = widget().await;

    let response = harness.server.get(&format!("/npm/{WIDGET}/2.0.0")).await;
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("43200"),
        "2.0.0 was published at 00:00 and the cooldown is a day, so it is twelve hours out"
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let body = body_json(response).await;
    assert_eq!(body["error"], Value::from("HELD"));
    assert_eq!(
        body["eligible_at"],
        Value::from("2026-04-07T00:00:00Z"),
        "the deadline is the publication time plus the cooldown, not a fresh one"
    );
    assert!(body["request_id"].is_string());

    // A version that is published but whose time is in the future is a denial, not a
    // hold: there is nothing to wait for that would make it trustworthy.
    let future = harness.server.get(&format!("/npm/{WIDGET}/2.0.4")).await;
    assert_eq!(future.status().as_u16(), 403);
    let body = body_json(future).await;
    assert_eq!(body["error"], Value::from("BLOCKED"));
    assert!(
        body.get("eligible_at").is_none(),
        "a denial carries no deadline, because it is not something to wait out"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Bounded work and hostile documents
// ---------------------------------------------------------------------------

/// TM-1: a project whose reference count exceeds `max_references_per_project` is
/// refused and logged, rather than committed in one transaction that would hold the
/// single storage task and delay every other operation, including a blocklist commit.
#[tokio::test]
async fn project_exceeding_reference_cap_is_502_and_logged() {
    let captured = logs::capture();
    let document = fixture("npm/oversized-reference-count.json");

    let refused = with_reference_cap(24, &document).await;
    assert_eq!(
        refused.server.status(&format!("/npm/{SWARM}")).await,
        502,
        "a project above the cap is refused, not truncated and not committed"
    );
    assert!(
        captured.lines_mentioning("max_references_per_project") > 0,
        "TM-1 requires the outlier to be logged"
    );
    assert!(
        captured.lines_mentioning(SWARM) > 0,
        "and logged with its name"
    );
    refused.shutdown().await;

    // The same document under a cap that admits it is served, so the refusal above is
    // the cap doing its job rather than the document being unusable.
    let admitted = with_reference_cap(64, &document).await;
    assert_eq!(admitted.server.status(&format!("/npm/{SWARM}")).await, 200);
    admitted.shutdown().await;
}

async fn with_reference_cap(cap: u32, document: &str) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.max_references_per_project = std::num::NonZeroU32::new(cap).expect("a non-zero cap");

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(SWARM),
        FakeAnswer::Body(document.to_owned()),
    );

    let clock = TestClock::at_rfc3339(NOW);
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

/// Gate 3 dependency note 5: `serde_json`'s default recursion limit, which this
/// crate never lifts, is what makes this a `502` rather than a stack overflow.
#[tokio::test]
async fn deeply_nested_upstream_document_is_502() {
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let harness = harness(NOW, ONE_DAY, &[(WIDGET, FakeAnswer::Body(deep))]).await;

    assert_eq!(harness.server.status(&format!("/npm/{WIDGET}")).await, 502);

    harness.shutdown().await;
}

/// TM-4: a confirmed-absent name is remembered, so a client asking for thousands of
/// names that do not exist cannot turn into thousands of upstream requests.
#[tokio::test]
async fn absent_name_is_cached_and_does_not_refetch() {
    let harness = harness(NOW, ONE_DAY, &[]).await;

    assert_eq!(harness.server.status("/npm/no-such-package").await, 404);
    assert_eq!(
        harness.registry.calls().len(),
        1,
        "the first miss does ask upstream"
    );

    for _ in 0..5 {
        assert_eq!(harness.server.status("/npm/no-such-package").await, 404);
    }
    assert_eq!(
        harness.registry.calls().len(),
        1,
        "and no later one does, until the metadata TTL is up"
    );

    // Past the TTL the name is asked about again: absence is cached, not concluded.
    harness
        .clock
        .advance_seconds(sample_config().metadata_ttl_seconds as i64 + 1);
    assert_eq!(harness.server.status("/npm/no-such-package").await, 404);
    assert_eq!(harness.registry.calls().len(), 2);

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Warm requests
// ---------------------------------------------------------------------------

/// SPEC §10: "On a fully warm request, policy and response lookup require no
/// database query, upstream call, or repeated JSON parsing."
#[tokio::test]
async fn a_second_identical_request_issues_no_query_and_no_upstream_call() {
    let harness = widget().await;

    let first = harness.server.json(&format!("/npm/{WIDGET}")).await;
    let commands = harness.server.store_commands();
    let calls = harness.registry.calls().len();
    assert!(
        commands > 0 && calls == 1,
        "the first request is a cold one"
    );

    let second = harness.server.json(&format!("/npm/{WIDGET}")).await;
    assert_eq!(second, first);
    assert_eq!(
        harness.server.store_commands(),
        commands,
        "a warm request puts no command on a storage queue"
    );
    assert_eq!(
        harness.registry.calls().len(),
        calls,
        "and makes no upstream call"
    );

    // The two counts above are also satisfied by the *project* cache on its own,
    // which would leave the document re-filtered and re-serialised on every request —
    // the third thing SPEC §10 rules out. So the rendered entry is asserted directly:
    // the serialised body is kept, under the key this request used, and it is still
    // reusable against the generation and revision now in force.
    let key = RenderKey {
        project: ProjectKey::new(Ecosystem::Npm, WIDGET),
        representation: Representation::NpmFull,
    };
    let app = harness.server.running().app();
    let rendered = app
        .store()
        .caches()
        .rendered
        .get(&key)
        .expect("the serialised response itself is kept, not just the project record");
    assert_eq!(
        serde_json::from_slice::<Value>(&rendered.body).expect("the cached body is JSON"),
        first,
        "and it is the very bytes that were served"
    );
    let project = app
        .store()
        .caches()
        .projects
        .get(&key.project)
        .expect("the project record is kept too");
    assert!(
        rendered.is_reusable(
            project.row.generation,
            app.blocklist_revision().expect("a blocklist is in force"),
            project.row.digest_generation,
            app.clock.now_utc_micros(),
            app.clock.now_monotonic(),
        ),
        "all five conditions of SPEC §10 still hold, which is why the second request \
         was answered from it"
    );

    // The exact-version route is warm on its own key, not on the document's.
    harness.server.json(&format!("/npm/{WIDGET}/1.0.0")).await;
    let after_cold_version = harness.server.store_commands();
    harness.server.json(&format!("/npm/{WIDGET}/1.0.0")).await;
    assert_eq!(harness.server.store_commands(), after_cold_version);
    assert_eq!(harness.registry.calls().len(), calls);

    harness.shutdown().await;
}

/// SPEC §10: the rendered deadline is the earliest of the metadata TTL, blocklist
/// expiry, and the next held version's eligibility time — so a release appears on
/// its own, without waiting for a background scheduler.
#[tokio::test]
async fn a_release_appears_when_its_hold_expires_without_a_refetch() {
    let harness = widget().await;

    let before = harness.server.json(&format!("/npm/{WIDGET}")).await;
    assert!(before["versions"].get("2.0.0").is_none());

    // Twelve hours and a second later, 2.0.0 has served its cooldown. The metadata
    // TTL is five minutes, so upstream is asked again — but the version appearing is
    // the deadline's doing, not the refetch's.
    harness.clock.advance_seconds(12 * 3600 + 1);
    let after = harness.server.json(&format!("/npm/{WIDGET}")).await;
    assert!(
        after["versions"].get("2.0.0").is_some(),
        "the released version appears by itself"
    );
    assert_eq!(
        after["dist-tags"]["latest"],
        Value::from("2.0.0"),
        "and latest follows it up"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn a_project_with_nothing_eligible_is_a_policy_denial_not_an_empty_document() {
    let document = r#"{
        "name": "fixture-young",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {"name": "fixture-young", "version": "1.0.0",
                      "dist": {"tarball": "https://npm.invalid/y/-/y-1.0.0.tgz"}}
        },
        "time": {"1.0.0": "2026-04-06T11:00:00.000Z"}
    }"#;

    let harness = harness(
        NOW,
        ONE_DAY,
        &[("fixture-young", FakeAnswer::Body(document.to_owned()))],
    )
    .await;

    let response = harness.server.get("/npm/fixture-young").await;
    assert_eq!(
        response.status().as_u16(),
        403,
        "SPEC §6: an existing project with nothing left is a policy denial, not an \
         empty document and not a 404"
    );
    let body = body_json(response).await;
    assert_eq!(body["error"], Value::from("HELD"));
    assert_eq!(body["eligible_at"], Value::from("2026-04-07T11:00:00Z"));

    harness.shutdown().await;
}

#[tokio::test]
async fn an_upstream_failure_is_reported_as_itself() {
    let harness = harness(
        NOW,
        ONE_DAY,
        &[
            (
                WIDGET,
                FakeAnswer::Fail(probation::upstream::UpstreamError::Timeout),
            ),
            (
                "fixture-broken",
                FakeAnswer::Fail(probation::upstream::UpstreamError::Status(500)),
            ),
            ("fixture-garbage", FakeAnswer::Body("not json".to_owned())),
        ],
    )
    .await;

    assert_eq!(harness.server.status(&format!("/npm/{WIDGET}")).await, 504);
    assert_eq!(harness.server.status("/npm/fixture-broken").await, 502);
    assert_eq!(harness.server.status("/npm/fixture-garbage").await, 502);

    harness.shutdown().await;
}

#[tokio::test]
async fn no_blocklist_is_503_before_anything_is_fetched() {
    let mut config = sample_config();
    config.blocklist_file = std::path::PathBuf::from("/nonexistent/blocklist.json");

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(fixture("npm/representative-100-versions.json")),
    );

    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&registry) as Arc<dyn probation::upstream::Transport>,
        fake_origins(),
    )
    .await;

    assert_eq!(server.status(&format!("/npm/{WIDGET}")).await, 503);
    assert!(
        registry.calls().is_empty(),
        "with no policy in force nothing is fetched at all"
    );

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// One metadata refresh per project (SPEC §10)
// ---------------------------------------------------------------------------

/// SPEC §10: "Coalesce concurrent metadata refreshes per project."
///
/// Six requests arrive while the one refresh is parked mid-flight, so all six are
/// provably *concurrent with* it rather than served one after another from the cache —
/// the gate is not released until every one of them is sharing the slot. The gate hands
/// out exactly one permit, so a second upstream refresh would never come back.
#[tokio::test]
async fn concurrent_cold_requests_cause_exactly_one_metadata_refresh() {
    let gate = Gate::new();
    let harness = harness(
        NOW,
        ONE_DAY,
        &[(
            WIDGET,
            FakeAnswer::GatedMetadata {
                body: fixture("npm/representative-100-versions.json"),
                gate: Arc::clone(&gate),
            },
        )],
    )
    .await;
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::Npm, WIDGET);

    let requests: Vec<_> = (0..6)
        .map(|_| {
            let app = Arc::clone(&app);
            tokio::spawn(
                async move { probation::npm::ensure_fresh_project(&app, WIDGET).await },
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
        harness.metadata_calls(WIDGET),
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
    let harness = harness(
        NOW,
        ONE_DAY,
        &[(
            WIDGET,
            FakeAnswer::PanicsMidRefresh {
                gate: Arc::clone(&gate),
            },
        )],
    )
    .await;
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::Npm, WIDGET);

    let refreshing = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::npm::ensure_fresh_project(&app, WIDGET).await })
    };
    gate.wait_until_reached().await;

    let waiter = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::npm::ensure_fresh_project(&app, WIDGET).await })
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
    harness.registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(fixture("npm/representative-100-versions.json")),
    );
    let later = tokio::time::timeout(
        Duration::from_secs(5),
        probation::npm::ensure_fresh_project(&app, WIDGET),
    )
    .await
    .expect("a later request for the same project is not wedged behind the dead one");
    assert!(later.is_ok(), "and it is served: {later:?}");
    assert_eq!(
        harness.metadata_calls(WIDGET),
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

/// A package on a registry that validates, so a revalidation can be told apart from
/// a refetch.
const VALIDATED: &str = "fixture-validated";
const ETAG: &str = "\"v1\"";
const ETAG_V2: &str = "\"v2\"";

/// The metadata TTL the sample configuration ships, which is what every wait below
/// is measured against.
fn metadata_ttl() -> i64 {
    sample_config().metadata_ttl_seconds as i64
}

/// The wall-clock instant the server is reading right now.
fn server_now(harness: &Harness) -> i64 {
    harness.server.running().app().clock.now_utc_micros()
}

/// The cached projection for one package's full document, or none if there is not
/// one.
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
            project: ProjectKey::new(Ecosystem::Npm, name),
            representation: Representation::NpmFull,
        })
}

/// The same, for [`VALIDATED`], which is the package most of these tests use.
fn projection(harness: &Harness) -> Option<Arc<probation::store::cache::RenderedResponse>> {
    projection_of(harness, VALIDATED)
}

/// Two versions published years ago, so nothing here is ever held and every exclusion
/// below is the blocklist's doing.
fn validated_document() -> String {
    format!(
        r#"{{
        "name": "{VALIDATED}",
        "dist-tags": {{"latest": "1.1.0"}},
        "versions": {{
            "1.0.0": {{"name": "{VALIDATED}", "version": "1.0.0",
                       "dist": {{"tarball": "https://npm.invalid/{VALIDATED}/-/{VALIDATED}-1.0.0.tgz"}}}},
            "1.1.0": {{"name": "{VALIDATED}", "version": "1.1.0",
                       "dist": {{"tarball": "https://npm.invalid/{VALIDATED}/-/{VALIDATED}-1.1.0.tgz"}}}}
        }},
        "time": {{"1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2020-02-01T00:00:00.000Z"}}
    }}"#
    )
}

/// The same package after a third release, which upstream serves under a new
/// validator.
fn extended_document() -> String {
    format!(
        r#"{{
        "name": "{VALIDATED}",
        "dist-tags": {{"latest": "1.2.0"}},
        "versions": {{
            "1.0.0": {{"name": "{VALIDATED}", "version": "1.0.0",
                       "dist": {{"tarball": "https://npm.invalid/{VALIDATED}/-/{VALIDATED}-1.0.0.tgz"}}}},
            "1.1.0": {{"name": "{VALIDATED}", "version": "1.1.0",
                       "dist": {{"tarball": "https://npm.invalid/{VALIDATED}/-/{VALIDATED}-1.1.0.tgz"}}}},
            "1.2.0": {{"name": "{VALIDATED}", "version": "1.2.0",
                       "dist": {{"tarball": "https://npm.invalid/{VALIDATED}/-/{VALIDATED}-1.2.0.tgz"}}}}
        }},
        "time": {{"1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2020-02-01T00:00:00.000Z",
                  "1.2.0": "2020-03-01T00:00:00.000Z"}}
    }}"#
    )
}

/// One version published eight minutes before [`NOW`] with a ten-minute cooldown, so
/// its hold releases in two — sooner than the five-minute metadata TTL, which is what
/// makes the hold the earliest of the three deadlines.
fn held_document() -> String {
    format!(
        r#"{{
        "name": "{VALIDATED}",
        "dist-tags": {{"latest": "1.1.0"}},
        "versions": {{
            "1.0.0": {{"name": "{VALIDATED}", "version": "1.0.0",
                       "dist": {{"tarball": "https://npm.invalid/{VALIDATED}/-/{VALIDATED}-1.0.0.tgz"}}}},
            "1.1.0": {{"name": "{VALIDATED}", "version": "1.1.0",
                       "dist": {{"tarball": "https://npm.invalid/{VALIDATED}/-/{VALIDATED}-1.1.0.tgz"}}}}
        }},
        "time": {{"1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2026-04-06T11:52:00.000Z"}}
    }}"#
    )
}

async fn validated_harness() -> Harness {
    harness(
        NOW,
        ONE_DAY,
        &[(
            VALIDATED,
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
    let path = format!("/npm/{VALIDATED}");
    let upstream = npm_upstream_path(VALIDATED);

    let first = harness.server.json(&path).await;
    assert_eq!(harness.metadata_calls(VALIDATED), 1);
    assert!(
        harness.registry.conditional_calls(&upstream).is_empty(),
        "the first fetch has nothing stored to revalidate against"
    );

    harness.clock.advance_seconds(metadata_ttl() + 1);
    let second = harness.server.json(&path).await;
    assert_eq!(
        second, first,
        "a 304 serves the document upstream still has"
    );

    assert_eq!(harness.metadata_calls(VALIDATED), 2);
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
    assert_eq!(harness.server.json(&path).await, first);
    assert_eq!(
        harness.metadata_calls(VALIDATED),
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
/// a revalidated project keeps serving a version the operator has already blocked.
#[tokio::test]
async fn a_304_still_rebuilds_the_representation_when_the_blocklist_changed() {
    let harness = validated_harness().await;
    let path = format!("/npm/{VALIDATED}");

    let before = harness.server.json(&path).await;
    assert!(
        before["versions"].get("1.1.0").is_some(),
        "1.1.0 starts out served"
    );
    // Warmed on purpose: the exact-version route is a representation of its own, so
    // both cached projections have to be rebuilt, not just the one this test reads.
    assert_eq!(
        harness.server.status(&format!("{path}/1.1.0")).await,
        200,
        "and so does its own route"
    );

    // The operator blocks 1.1.0 after the last full fetch. Upstream's document is
    // unchanged, so the revalidation below is answered 304.
    harness.clock.advance_seconds(metadata_ttl() + 1);
    publish_blocklist(
        &harness.server,
        &snapshot(
            2,
            "2020-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            &format!(
                r#"{{"ecosystem":"npm","name":"{VALIDATED}","version":"1.1.0","reason":"malware"}}"#
            ),
        ),
        server_now(&harness),
    );

    let after = harness.server.json(&path).await;
    assert_eq!(
        harness.registry.not_modified_answers(),
        1,
        "upstream answered the revalidation 304, which is the case this test is about"
    );
    assert!(
        after["versions"].get("1.1.0").is_none(),
        "a 304 renews freshness but still rebuilds the representation, so a version \
         blocked since the last full fetch stays excluded"
    );
    assert!(after["versions"].get("1.0.0").is_some());
    assert_eq!(
        after["dist-tags"]["latest"],
        Value::from("1.0.0"),
        "and latest falls back rather than naming the blocked version"
    );
    assert_eq!(
        harness.server.status(&format!("{path}/1.1.0")).await,
        403,
        "the warm exact-version projection was rebuilt too, rather than served on"
    );

    harness.shutdown().await;
}

/// SPEC §13 item 10. A package upstream has stopped serving becomes a `404` once its
/// TTL is up — including after a revalidation upstream did recognise, so this is
/// removal rather than a cold miss.
#[tokio::test]
async fn upstream_removal_becomes_404() {
    let harness = validated_harness().await;
    let path = format!("/npm/{VALIDATED}");
    harness.server.json(&path).await;

    harness.clock.advance_seconds(metadata_ttl() + 1);
    assert_eq!(harness.server.status(&path).await, 200);
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // Then upstream forgets the package. SPEC §10 forbids serving expired metadata,
    // so the cached document does not outlive its renewed TTL.
    harness
        .registry
        .answer(&npm_upstream_path(VALIDATED), FakeAnswer::Missing);
    harness.clock.advance_seconds(metadata_ttl() + 1);
    assert_eq!(harness.server.status(&path).await, 404);

    harness.shutdown().await;
}

/// SPEC §13 item 10. Inside the TTL nothing is asked upstream; past it exactly one
/// conditional request goes out, and a changed document comes back in full.
#[tokio::test]
async fn revalidation_after_ttl() {
    let harness = validated_harness().await;
    let path = format!("/npm/{VALIDATED}");
    harness.server.json(&path).await;

    harness.clock.advance_seconds(60);
    harness.server.json(&path).await;
    assert_eq!(
        harness.metadata_calls(VALIDATED),
        1,
        "inside the TTL nothing is revalidated"
    );

    harness.clock.advance_seconds(metadata_ttl());
    harness.server.json(&path).await;
    assert_eq!(harness.metadata_calls(VALIDATED), 2);
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // A changed document carries a different validator, so the same conditional
    // request is answered with the whole document instead.
    harness.registry.answer(
        &npm_upstream_path(VALIDATED),
        FakeAnswer::Validated {
            etag: ETAG_V2.to_owned(),
            body: extended_document(),
        },
    );
    harness.clock.advance_seconds(metadata_ttl() + 1);
    let after = harness.server.json(&path).await;

    assert_eq!(harness.metadata_calls(VALIDATED), 3);
    assert_eq!(
        harness.registry.not_modified_answers(),
        1,
        "the changed document was sent in full rather than revalidated away"
    );
    assert!(
        after["versions"].get("1.2.0").is_some(),
        "and the new version is served"
    );

    harness.shutdown().await;
}

/// SPEC §13 item 10, and SPEC §10's deadline rule: the projection expires at the next
/// held version's eligibility time, and a `304` recomputes it from the renewed
/// validation time.
#[tokio::test]
async fn projection_expires_at_next_hold_release() {
    const COOLDOWN: u64 = 600;
    let harness = harness(
        NOW,
        COOLDOWN,
        &[(
            VALIDATED,
            FakeAnswer::Validated {
                etag: ETAG.to_owned(),
                body: held_document(),
            },
        )],
    )
    .await;
    let path = format!("/npm/{VALIDATED}");

    let before = harness.server.json(&path).await;
    assert!(
        before["versions"].get("1.1.0").is_none(),
        "1.1.0 is two minutes short of its ten-minute cooldown"
    );
    assert_eq!(
        projection(&harness)
            .expect("the projection is cached")
            .deadline_utc_micros,
        common::parse_rfc3339("2026-04-06T12:02:00Z"),
        "the hold release is earlier than the metadata TTL, so it is the deadline"
    );

    // Two minutes and a second later the projection has expired and the version
    // appears, without anything being asked upstream.
    harness.clock.advance_seconds(121);
    let after = harness.server.json(&path).await;
    assert!(after["versions"].get("1.1.0").is_some());
    assert_eq!(
        harness.metadata_calls(VALIDATED),
        1,
        "the projection expired; the snapshot behind it had not"
    );

    // Past the metadata TTL the snapshot is revalidated. The 304 renews it, and the
    // projection is recomputed from that renewed validation time rather than from the
    // original fetch.
    harness.clock.advance_seconds(metadata_ttl());
    let revalidated_at = server_now(&harness);
    harness.server.json(&path).await;
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
    let path = format!("/npm/{VALIDATED}");

    let before = harness.server.json(&path).await;
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

    assert_eq!(harness.server.json(&path).await, before);
    let second = projection(&harness).expect("the projection is cached again");
    assert!(
        second.deadline_monotonic > first.deadline_monotonic,
        "the monotonic deadline had passed, so the projection was recomputed rather \
         than extended by the step backwards"
    );
    assert_eq!(
        harness.metadata_calls(VALIDATED),
        1,
        "and that recomputation is the projection's, not a refetch's"
    );

    // Forward again past the stored snapshot's own TTL: the revalidation is
    // conditional, the 304 renews it, and the projection is recomputed once more.
    harness.clock.advance_seconds(metadata_ttl() * 3);
    let revalidated_at = server_now(&harness);
    harness.server.json(&path).await;
    assert_eq!(harness.metadata_calls(VALIDATED), 2);
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
// Three states a hostile or broken registry can put the firewall in that
// `FakeAnswer::Validated` cannot reach, because it only ever answers 304 to a
// validator it actually matched. Each was correct by reading before these tests
// existed; none had an executed witness, and fail-closed is not a property to take
// on trust.

/// Names of their own, because `logs` is one buffer per test binary and an assertion
/// about a warning has to select its own line out of it.
const UNCONDITIONAL: &str = "fixture-unconditional";
const CORRUPT: &str = "fixture-corrupt";
const SURPRISING: &str = "fixture-surprising";

/// (1) A `304` answering a request that carried no validator, because nothing was
/// stored to revalidate against. There is no document behind it and none may be
/// invented: SPEC §11's `502` row, plus a warning naming the package.
#[tokio::test]
async fn a_304_to_an_unconditional_request_is_refused_not_guessed() {
    let captured = logs::capture_warn();
    let harness = harness(
        NOW,
        ONE_DAY,
        &[(
            UNCONDITIONAL,
            FakeAnswer::AlwaysNotModified {
                etag: Some(ETAG.to_owned()),
                last_modified: None,
            },
        )],
    )
    .await;
    let path = format!("/npm/{UNCONDITIONAL}");
    let upstream = npm_upstream_path(UNCONDITIONAL);

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
    let harness = harness(
        NOW,
        ONE_DAY,
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
            ecosystem: Ecosystem::Npm,
            name: CORRUPT.to_owned(),
            payload: Arc::from(&b"{\"versions\": this is not a package document"[..]),
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
        .get_project(Ecosystem::Npm, CORRUPT)
        .await
        .expect("the row reads back")
        .expect("the row is there");

    let response = harness.server.get(&format!("/npm/{CORRUPT}")).await;
    assert_eq!(response.status().as_u16(), 502);
    assert_eq!(common::body_error(response).await, "UPSTREAM_INVALID");
    assert_eq!(
        harness.registry.not_modified_answers(),
        1,
        "the revalidation really was answered 304, which is the branch under test"
    );

    let after = app
        .store()
        .get_project(Ecosystem::Npm, CORRUPT)
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
    let harness = harness(
        NOW,
        ONE_DAY,
        &[(
            SURPRISING,
            FakeAnswer::Validated {
                etag: ETAG.to_owned(),
                body: validated_document(),
            },
        )],
    )
    .await;
    let path = format!("/npm/{SURPRISING}");
    let upstream = npm_upstream_path(SURPRISING);

    let first = harness.server.json(&path).await;

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
        harness.server.json(&path).await,
        first,
        "the stored document is what is served; the surprising headers change nothing \
         about it"
    );
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // The new validators were adopted, so the next revalidation asks with them.
    harness.clock.advance_seconds(metadata_ttl() + 1);
    harness.server.json(&path).await;
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

/// (3, the other half) The production transport, against a real socket: a `304`
/// carrying a body and headers we never asked for surfaces as `NotModified` with no
/// bytes attached. `MetadataResponse` has nowhere to put a body on that branch, and
/// this is what proves the client never hands one over.
#[tokio::test]
async fn a_304_with_a_body_and_extra_headers_yields_no_bytes() {
    use probation::upstream::{MetadataRequest, MetadataResponse, OriginKind};
    use wiremock::ResponseTemplate;
    use wiremock::matchers::{method, path};

    let upstream = common::WiremockUpstream::start().await;
    wiremock::Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(
            ResponseTemplate::new(304)
                .insert_header("etag", ETAG)
                .insert_header("x-registry-note", "ignore me")
                .insert_header("cache-control", "public, max-age=31536000")
                .set_body_string("THIS BODY MUST NEVER BE READ"),
        )
        .mount(&upstream.server)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["left-pad"])
        .expect("the wiremock origin builds a URL");
    let answered = upstream
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            accept: "application/json",
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
// Slice 13: the computed-digest block survives a racing reader
// ---------------------------------------------------------------------------

/// The second artifact the racing-reader test keeps, so a listing can lose one
/// version and still show another.
const RACE_VERSION: &str = "1.0.0";
const RACE_FILENAME: &str = "fixture-widget-1.0.0.tgz";
const RACE_OTHER_VERSION: &str = "2.0.0";
const RACE_OTHER_FILENAME: &str = "fixture-widget-2.0.0.tgz";
const RACE_PUBLISHED: &str = "2026-04-01T00:00:00Z";

/// `tests/fixtures/artifacts/harmless-widget-1.0.0.tgz`, as `sha256sum` and
/// `openssl dgst -sha512 -binary | base64` report it.
const RACE_SHA256: &str = "029830248baf17af5d9a9e23d3e7054a8860882d1cdc06bbbb1549056d347acb";
const RACE_SRI: &str = "sha512-cuZOnpQDIYuoiW0VpldsZLmUaQ/eZwGjVHeTZQoXRdTeBMh5mj1XyHMlEqTzPjYFW3AxzuKZi8cb4GZ2QP4G7g==";
const RACE_OTHER_SRI: &str = "sha512-hl/BywthAR9bBzuAS/JOKoCECO9fgaHl2bce2C43qs4r89tbyU9hMv02qnBf4Vn5193+NTmwCSt1RBlrihU54Q==";

fn race_document() -> String {
    let mut versions = serde_json::Map::new();
    let mut time = serde_json::Map::new();
    for (version, filename, integrity) in [
        (RACE_VERSION, RACE_FILENAME, RACE_SRI),
        (RACE_OTHER_VERSION, RACE_OTHER_FILENAME, RACE_OTHER_SRI),
    ] {
        versions.insert(
            version.to_owned(),
            serde_json::json!({
                "name": WIDGET,
                "version": version,
                "dist": {
                    "tarball": common::npm_tarball_url(WIDGET, filename),
                    "integrity": integrity,
                },
            }),
        );
        time.insert(version.to_owned(), serde_json::json!(RACE_PUBLISHED));
    }
    serde_json::json!({
        "name": WIDGET,
        "dist-tags": {"latest": RACE_OTHER_VERSION},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

/// SPEC §9: "If a computed digest reveals a block not visible in upstream metadata,
/// invalidate that project's filtered metadata. The next resolution hides the
/// affected artifact."
///
/// The pin and the cache drop that carries it are two steps, so a `current_project`
/// that read the project *before* the pin reaches its own insert *after* the drop.
/// This test is that reader, in its two halves and with the calls `current_project`
/// makes: it reads the snapshot and the invalidation count together through
/// `get_with_seen`, lets the download commit its pin in between, and only then
/// installs what it read.
/// Before slice 13 that insert was unguarded, the pre-pin snapshot went back into the
/// cache, and the version its own digest revealed a block for stayed listed for a
/// whole `metadata_ttl_seconds` — so SPEC §9's guarantee held only when nothing else
/// was reading.
///
/// The halves are driven from here rather than by two concurrent requests because
/// production runs them with no `.await` between: there is no point a test could park
/// a real reader at, and a test that raced two requests and hoped would witness
/// nothing. Everything after the second half is the ordinary rendering path, so what
/// this asserts on is still the listing a client would receive.
#[tokio::test]
async fn a_computed_digest_block_hides_the_version_at_the_next_resolution_under_a_racing_reader() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = config_with_open_blocklist(dir.path());
    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(race_document()),
    );
    registry.answer(
        &common::npm_artifact_upstream_path(WIDGET, RACE_FILENAME),
        FakeAnswer::Body(fixture("artifacts/harmless-widget-1.0.0.tgz")),
    );
    registry.answer(
        &common::npm_artifact_upstream_path(WIDGET, RACE_OTHER_FILENAME),
        FakeAnswer::Body(fixture("artifacts/tampered-widget-1.0.0.tgz")),
    );
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_in_with_registry(
        &dir.path().join("data"),
        config,
        clock.shared(),
        Arc::clone(&registry),
    )
    .await;

    let listing = server.json(&format!("/npm/{WIDGET}")).await;
    assert!(listing["versions"][RACE_VERSION].is_object());
    assert!(listing["versions"][RACE_OTHER_VERSION].is_object());

    let key = ProjectKey::new(Ecosystem::Npm, WIDGET);

    // The racing reader, first half: exactly what `current_project` does before it
    // can be told that anything has changed. `app` is scoped, because a live
    // `StoreHandle` outside this block would keep the store task from ending and
    // `shutdown` below would wait for it forever.
    let (seen, read) = {
        let app = server.app();
        let (seen, read) = app.store().caches().projects.get_with_seen(&key);
        (seen, read.expect("the listing above cached the project"))
    };
    assert!(
        read.pins.is_empty(),
        "the reader's snapshot predates every pin, which is the whole point"
    );

    // One download, which is what teaches this instance the artifact's SHA-256 and
    // drops the project cache entry the reader is holding.
    let path = common::artifact_path(&listing, RACE_VERSION);
    assert_eq!(server.status(&path).await, 200);

    // The racing reader, second half: it installs what it read, after the drop.
    {
        let app = server.app();
        let bytes = read.approximate_bytes();
        app.store()
            .caches()
            .projects
            .insert_if_current(key, read, bytes, seen);
    }

    publish_blocklist(
        &server,
        &common::snapshot_with(
            2,
            "2026-04-05T00:00:00Z",
            "2099-01-01T00:00:00Z",
            "",
            &format!(
                r#"{{"algorithm":"sha256","digest":"{RACE_SHA256}","reason":"known malicious artifact"}}"#
            ),
        ),
        common::parse_rfc3339(NOW),
    );

    let listing = server.json(&format!("/npm/{WIDGET}")).await;
    assert!(
        listing["versions"][RACE_VERSION].is_null(),
        "the next resolution hides the version its computed digest revealed a block \
         for, even though a reader re-installed a snapshot predating the pin: {listing}"
    );
    assert!(
        listing["versions"][RACE_OTHER_VERSION].is_object(),
        "and hides nothing else"
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
const CEILING_EARLY: &str = "fixture-beta";
const CEILING_LATE: &str = "fixture-delta";

/// [`validated_document`] for any name: two versions published years ago, so nothing
/// here is ever held and every refusal below is the ceiling's doing.
fn ceiling_document(name: &str) -> String {
    format!(
        r#"{{
        "name": "{name}",
        "dist-tags": {{"latest": "1.1.0"}},
        "versions": {{
            "1.0.0": {{"name": "{name}", "version": "1.0.0",
                       "dist": {{"tarball": "https://npm.invalid/{name}/-/{name}-1.0.0.tgz"}}}},
            "1.1.0": {{"name": "{name}", "version": "1.1.0",
                       "dist": {{"tarball": "https://npm.invalid/{name}/-/{name}-1.1.0.tgz"}}}}
        }},
        "time": {{"1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2020-02-01T00:00:00.000Z"}}
    }}"#
    )
}

fn validating_answer(name: &str) -> (String, FakeAnswer) {
    (
        name.to_owned(),
        FakeAnswer::Validated {
            etag: ETAG.to_owned(),
            body: ceiling_document(name),
        },
    )
}

async fn ceiling_harness(max_age: u64, names: &[&str]) -> Harness {
    let owned: Vec<(String, FakeAnswer)> =
        names.iter().map(|name| validating_answer(name)).collect();
    let answers: Vec<(&str, FakeAnswer)> = owned
        .iter()
        .map(|(name, answer)| (name.as_str(), answer.clone()))
        .collect();
    harness_configured(NOW, &answers, |config| {
        config.cooldown_seconds = ONE_DAY;
        config.metadata_ttl_seconds = CEILING_TTL;
        config.metadata_max_age_seconds = max_age;
    })
    .await
}

/// The row on disk, read through the store rather than through the memory cache: the
/// column itself is the subject of these tests, not a copy of it.
async fn stored_project(
    harness: &Harness,
    name: &str,
) -> probation::store::rows::ProjectRow {
    harness
        .server
        .running()
        .app()
        .store()
        .get_project(Ecosystem::Npm, name)
        .await
        .expect("a query")
        .expect("this instance has fetched the project")
}

/// This project's effective ceiling in whole seconds.
fn ceiling_seconds(name: &str, max_age: u64) -> i64 {
    probation::store::effective_max_age_micros(
        &ProjectKey::new(Ecosystem::Npm, name),
        max_age,
    )
    .expect("a nonzero maximum age has a ceiling")
        / 1_000_000
}

/// How many whole seconds of wall time the harness's clock has covered since `from`.
fn elapsed_seconds(harness: &Harness, from: i64) -> i64 {
    (server_now(harness) - from) / 1_000_000
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
    let harness = ceiling_harness(CEILING_MAX_AGE, &[VALIDATED]).await;
    let path = format!("/npm/{VALIDATED}");
    let t0 = server_now(&harness);

    harness.server.json(&path).await;
    let first = stored_project(&harness, VALIDATED).await;
    assert_eq!(
        first.fetched_at_micros, t0,
        "a 200 records the instant the document actually arrived"
    );
    assert_eq!(first.validated_at_micros, t0);

    for round in 1..=2 {
        harness.clock.advance_seconds(CEILING_TTL as i64 + 1);
        harness.server.json(&path).await;

        let row = stored_project(&harness, VALIDATED).await;
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
    let harness = ceiling_harness(CEILING_MAX_AGE, &[VALIDATED]).await;
    let path = format!("/npm/{VALIDATED}");
    let upstream = npm_upstream_path(VALIDATED);
    let t0 = server_now(&harness);

    harness.server.json(&path).await;
    assert!(
        harness.registry.conditional_calls(&upstream).is_empty(),
        "the first fetch has nothing stored to revalidate against"
    );

    // An ordinary revalidation first, so the only thing different about the third
    // request is the ceiling.
    harness.clock.advance_seconds(CEILING_TTL as i64 + 1);
    harness.server.json(&path).await;
    assert_eq!(harness.registry.conditional_calls(&upstream).len(), 1);
    assert_eq!(harness.registry.not_modified_answers(), 1);

    // Exactly at the ceiling: the age rule is "reaches", not "passes".
    let ceiling = ceiling_seconds(VALIDATED, CEILING_MAX_AGE);
    harness
        .clock
        .advance_seconds(ceiling - elapsed_seconds(&harness, t0));
    harness.server.json(&path).await;

    assert_eq!(harness.metadata_calls(VALIDATED), 3);
    assert_eq!(
        harness.registry.conditional_calls(&upstream).len(),
        1,
        "the over-age refresh carried no validators at all, so upstream was given no \
         opportunity to answer 304"
    );
    assert_eq!(harness.registry.not_modified_answers(), 1);
    assert_eq!(
        stored_project(&harness, VALIDATED).await.fetched_at_micros,
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
    let harness = ceiling_harness(CEILING_MAX_AGE, &[VALIDATED]).await;
    let path = format!("/npm/{VALIDATED}");
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(VALIDATED, CEILING_MAX_AGE);

    harness.server.json(&path).await;

    // Revalidated fifty seconds before the ceiling, then sixty seconds on: over-age,
    // and still well inside the hundred-second TTL.
    harness.clock.advance_seconds(ceiling - 50);
    harness.server.json(&path).await;
    harness.clock.advance_seconds(60);
    assert!(elapsed_seconds(&harness, t0) >= ceiling);

    harness.registry.go_offline();
    assert_eq!(
        harness.server.status(&path).await,
        502,
        "an over-age snapshot is refused rather than served, even though its metadata \
         TTL has not expired"
    );
    assert_eq!(
        stored_project(&harness, VALIDATED).await.fetched_at_micros,
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
    let harness = ceiling_harness(CEILING_MAX_AGE, &[VALIDATED]).await;
    let path = format!("/npm/{VALIDATED}");
    let upstream = npm_upstream_path(VALIDATED);
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(VALIDATED, CEILING_MAX_AGE);
    let step = CEILING_TTL as i64 + 1;

    harness.server.json(&path).await;

    let mut rounds = 0usize;
    while elapsed_seconds(&harness, t0) + step < ceiling {
        harness.clock.advance_seconds(step);
        harness.server.json(&path).await;
        rounds += 1;
        assert_eq!(
            stored_project(&harness, VALIDATED).await.fetched_at_micros,
            t0,
            "round {rounds}: the copy keeps ageing while upstream keeps saying 304"
        );
    }
    assert!(rounds >= 5, "the ceiling was crossed too soon to be a test");
    assert_eq!(harness.registry.not_modified_answers(), rounds);
    assert_eq!(harness.registry.conditional_calls(&upstream).len(), rounds);

    // The step that crosses the ceiling.
    harness.clock.advance_seconds(step);
    harness.server.json(&path).await;

    assert_eq!(
        stored_project(&harness, VALIDATED).await.fetched_at_micros,
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
    let harness = ceiling_harness(0, &[VALIDATED]).await;
    let path = format!("/npm/{VALIDATED}");
    let upstream = npm_upstream_path(VALIDATED);
    let t0 = server_now(&harness);

    harness.server.json(&path).await;

    for round in 1..=5 {
        harness.clock.advance_seconds(2 * ONE_DAY as i64);
        harness.server.json(&path).await;
        assert_eq!(
            stored_project(&harness, VALIDATED).await.fetched_at_micros,
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
    let early = format!("/npm/{CEILING_EARLY}");
    let late = format!("/npm/{CEILING_LATE}");
    let t0 = server_now(&harness);

    // Fetched together, as a bulk seed or a restore would.
    harness.server.json(&early).await;
    harness.server.json(&late).await;
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
    harness.server.json(&early).await;
    harness.server.json(&late).await;

    // Sixty seconds on, both are inside their TTL and exactly one is over-age.
    harness.clock.advance_seconds(60);
    let elapsed = elapsed_seconds(&harness, t0);
    assert!(elapsed >= early_ceiling && elapsed < late_ceiling);

    harness.registry.go_offline();
    assert_eq!(
        harness.server.status(&early).await,
        502,
        "the project whose ceiling has lapsed refuses"
    );
    assert_eq!(
        harness.server.status(&late).await,
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
            let key = ProjectKey::new(Ecosystem::Npm, format!("fixture-spread-{index}"));
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
            &ProjectKey::new(Ecosystem::Npm, VALIDATED),
            0
        ),
        None,
        "and zero is no ceiling at all rather than a ceiling of zero"
    );

    // And the guarantee where it is observable: at exactly the configured maximum,
    // whatever this project's offset happened to be, the snapshot is over-age.
    let harness = ceiling_harness(CEILING_MAX_AGE, &[VALIDATED]).await;
    let path = format!("/npm/{VALIDATED}");
    let upstream = npm_upstream_path(VALIDATED);
    let t0 = server_now(&harness);

    harness.server.json(&path).await;
    harness.clock.advance_seconds(CEILING_MAX_AGE as i64);
    harness.server.json(&path).await;

    assert!(
        harness.registry.conditional_calls(&upstream).is_empty(),
        "the configured maximum is a true maximum: by then the refresh is unconditional"
    );
    assert_eq!(
        stored_project(&harness, VALIDATED).await.fetched_at_micros,
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
    let harness = ceiling_harness(CEILING_MAX_AGE, &[VALIDATED]).await;
    let path = format!("/npm/{VALIDATED}");
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(VALIDATED, CEILING_MAX_AGE);

    harness.server.json(&path).await;
    harness.clock.advance_seconds(ceiling - 50);
    harness.server.json(&path).await;
    harness.clock.advance_seconds(60);

    // An NTP step two hundred seconds backwards: the wall clock moves, the monotonic
    // reading does not. The copy now looks younger than its ceiling again.
    harness.clock.rewind_wall_clock_seconds(200);
    assert!(elapsed_seconds(&harness, t0) < ceiling);
    harness.registry.go_offline();
    assert_eq!(
        harness.server.status(&path).await,
        200,
        "a backward jump delays the trip rather than defeating it: the snapshot is \
         under its ceiling again and is served from the stored copy"
    );

    // Wall time advances past the jump, and the ceiling applies exactly as before.
    harness.clock.advance_seconds(210);
    assert!(elapsed_seconds(&harness, t0) >= ceiling);
    assert_eq!(
        harness.server.status(&path).await,
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
    let harness = ceiling_harness(CEILING_MAX_AGE, &[VALIDATED]).await;
    let upstream = npm_upstream_path(VALIDATED);
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::Npm, VALIDATED);
    let t0 = server_now(&harness);
    let ceiling = ceiling_seconds(VALIDATED, CEILING_MAX_AGE);

    // Seeded by a full fetch, then upstream starts parking every revalidation.
    harness.server.json(&format!("/npm/{VALIDATED}")).await;
    assert_eq!(
        stored_project(&harness, VALIDATED).await.fetched_at_micros,
        t0
    );
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
        async move { probation::npm::ensure_fresh_project(&app, VALIDATED).await }
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
        async move { probation::npm::ensure_fresh_project(&app, VALIDATED).await }
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
        harness.metadata_calls(VALIDATED),
        2,
        "one seeding fetch and one refresh, and no third: the joiner made no upstream \
         call of its own. This is the one-attempt-versus-two signal that separates a \
         forced race from a lucky ordering."
    );

    // (a) The boundary crossing did not launder the copy.
    assert_eq!(
        stored_project(&harness, VALIDATED).await.fetched_at_micros,
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
            probation::npm::ensure_fresh_project(&app, VALIDATED).await,
            Err(ApiError::UpstreamInvalid)
        ),
        "an uncoalesced over-age request sends no validators, so a 304 answering it is \
         an upstream protocol violation and the over-age copy is not served"
    );
    assert_eq!(
        harness.metadata_calls(VALIDATED),
        3,
        "and it made an upstream call of its own, which the joiner did not"
    );

    // (b) A refresh that has just completed is not evidence of freshness either.
    harness.registry.go_offline();
    assert!(
        matches!(
            probation::npm::ensure_fresh_project(&app, VALIDATED).await,
            Err(ApiError::UpstreamFailure)
        ),
        "the copy is over-age against the clock this request reads, and is refused"
    );
    assert_eq!(
        harness.server.status(&format!("/npm/{VALIDATED}")).await,
        502,
        "and the served route refuses it too"
    );

    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}
