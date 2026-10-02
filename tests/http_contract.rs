//! Slice 9's witness: the whole SPEC §11 failure table, produced by the code and
//! asserted here, plus the three rules that apply to *every* answer — `no-store` on
//! all of them, no downstream `304` and no forwarded validator, and one decision line
//! per request carrying the ID the client was told.
//!
//! Everything runs against an in-process `FakeRegistry` and a clock the test moves by
//! hand, so a run reaches no socket and depends on no wall clock.
//!
//! Every assertion about a hostile path, and every assertion about a method or a
//! request line `reqwest` will not send, goes through the raw `TcpStream` helper in
//! `tests/common/mod.rs`. Slice 4 learned why: `reqwest` parses what it is given into
//! a `Url`, so `/npm/%2E%2E` never leaves the client as anything but `/` and a test
//! written through it silently asserts nothing.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, artifact_path, config_with_open_blocklist,
    fake_origins, logs, npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
    publish_blocklist, pypi_upstream_path, raw_header, raw_status, sample_config, snapshot,
};
use probation::http::error::ApiError;
use probation::upstream::{Transport, UpstreamError};
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use url::Url;

const WIDGET: &str = "fixture-widget";
const FILENAME: &str = "fixture-widget-1.0.0.tgz";

/// Five days before [`NOW`]: the one-day cooldown is long spent.
const ELIGIBLE: &str = "1.0.0";
const ELIGIBLE_PUBLISHED: &str = "2026-04-01T00:00:00Z";

/// One hour before [`NOW`]: twenty-three hours of the cooldown are left.
const HELD: &str = "2.0.0";
const HELD_PUBLISHED: &str = "2026-04-06T11:00:00Z";

const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

/// A PyPI project, so one harness can hold an artifact reference on each ecosystem —
/// which is what a cross-root test needs and what the npm fixture alone cannot give.
const BARD: &str = "friendly-bard";
const BARD_FILE: &str = "friendly_bard-1.0-py3-none-any.whl";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    _dir: TempDir,
}

impl Harness {
    async fn shutdown(self) {
        self.server.shutdown().await;
    }

    /// The artifact URL a client is actually given, taken out of the rendered
    /// document rather than spelled by hand.
    async fn artifact_path(&self) -> String {
        let document = self.server.json(&format!("/npm/{WIDGET}")).await;
        artifact_path(&document, ELIGIBLE)
    }

    /// The same, for the PyPI half: read out of the rendered Simple listing rather
    /// than spelled by hand, so the test follows whatever shape the renderer emits.
    async fn pypi_artifact_path(&self) -> String {
        let body = self
            .server
            .get_with_headers(
                &format!("/pypi/simple/{BARD}/"),
                &[("accept", "application/vnd.pypi.simple.v1+json")],
            )
            .await
            .text()
            .await
            .expect("a body");
        let listing: Value =
            serde_json::from_str(&body).unwrap_or_else(|err| panic!("not JSON: {err}: {body}"));
        let url = listing["files"][0]["url"]
            .as_str()
            .unwrap_or_else(|| panic!("the listing advertises a file URL: {listing}"));
        Url::parse(url)
            .expect("the rewritten file URL parses")
            .path()
            .to_owned()
    }
}

/// One npm document with an eligible version and a held one, so both `403` shapes are
/// reachable from the same project.
fn document() -> String {
    let mut versions = Map::new();
    for version in [ELIGIBLE, HELD] {
        versions.insert(
            version.to_owned(),
            json!({
                "name": WIDGET,
                "version": version,
                "dist": {"tarball": npm_tarball_url(WIDGET, FILENAME)},
            }),
        );
    }
    let mut time = Map::new();
    time.insert(ELIGIBLE.to_owned(), json!(ELIGIBLE_PUBLISHED));
    time.insert(HELD.to_owned(), json!(HELD_PUBLISHED));

    json!({
        "name": WIDGET,
        "dist-tags": {"latest": ELIGIBLE},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

async fn harness(answers: &[(&str, FakeAnswer)]) -> Harness {
    harness_with(answers, |_| {}).await
}

async fn harness_with(
    answers: &[(&str, FakeAnswer)],
    adjust: impl FnOnce(&mut probation::config::Config),
) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.cooldown_seconds = ONE_DAY;
    adjust(&mut config);

    let registry = FakeRegistry::new();
    for (path, answer) in answers {
        registry.answer(path, answer.clone());
    }

    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;

    Harness {
        server,
        registry,
        _dir: dir,
    }
}

/// One PEP 691 project document with a single eligible file.
fn pypi_document() -> String {
    json!({
        "meta": {"api-version": "1.1"},
        "name": BARD,
        "versions": [],
        "files": [{
            "filename": BARD_FILE,
            "url": format!("https://files.invalid/packages/ab/cd/{BARD_FILE}"),
            "hashes": {"sha256": "aa".repeat(32)},
            "upload-time": ELIGIBLE_PUBLISHED,
        }],
    })
    .to_string()
}

/// The project above, served from the fake registry.
async fn widget() -> Harness {
    harness(&[(&npm_upstream_path(WIDGET), FakeAnswer::Body(document()))]).await
}

/// The npm project and the PyPI one at once, so a request can carry a reference id
/// belonging to one ecosystem to the other one's artifact root.
async fn both_ecosystems() -> Harness {
    harness(&[
        (&npm_upstream_path(WIDGET), FakeAnswer::Body(document())),
        (&pypi_upstream_path(BARD), FakeAnswer::Body(pypi_document())),
    ])
    .await
}

async fn body(response: reqwest::Response) -> Value {
    let text = response.text().await.expect("a body");
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("the body is not JSON: {err}: {text}"))
}

fn error_of(value: &Value) -> String {
    value["error"]
        .as_str()
        .unwrap_or_else(|| panic!("the error body names an error: {value}"))
        .to_owned()
}

fn request_id_of(value: &Value) -> String {
    value["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("SPEC §11: an error body carries a request_id: {value}"))
        .to_owned()
}

/// SPEC §11's own field list, asserted on an error body once so every row below can
/// simply name the row it proves.
fn assert_error_body(value: &Value, expected_error: &str) {
    assert_eq!(error_of(value), expected_error, "in {value}");
    assert!(
        value["reason"].as_str().is_some_and(|it| !it.is_empty()),
        "SPEC §11: an error carries a reason: {value}"
    );
    assert!(
        !request_id_of(value).is_empty(),
        "SPEC §11: an error carries a request_id: {value}"
    );
}

// ---------------------------------------------------------------------------
// SPEC §11 failure table, row 1: exact artifact/version held or blocked -> 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn held_or_blocked_is_403_with_eligible_at_and_retry_after() {
    let captured = logs::capture_info();
    let harness = widget().await;

    let response = harness.server.get(&format!("/npm/{WIDGET}/{HELD}")).await;
    assert_eq!(response.status().as_u16(), 403);
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("SPEC §11: a cooldown response carries a numeric Retry-After");
    let seconds: u64 = retry_after
        .parse()
        .unwrap_or_else(|_| panic!("Retry-After is a number of seconds, got {retry_after:?}"));
    assert!(
        (1..=ONE_DAY).contains(&seconds),
        "twenty-three hours of the cooldown are left, so Retry-After is inside the \
         cooldown and never zero; got {seconds}"
    );

    let held = body(response).await;
    assert_error_body(&held, "HELD");
    assert_eq!(
        held["eligible_at"].as_str(),
        Some("2026-04-07T11:00:00Z"),
        "SPEC §11: a cooldown response says when the release becomes eligible: {held}"
    );
    assert_decided(&captured, &request_id_of(&held), 403);

    // The other half of the same row: a block has no deadline, so it must not look
    // like one.
    publish_blocklist(
        &harness.server,
        &snapshot(
            2,
            "2026-04-05T00:00:00Z",
            "2099-01-01T00:00:00Z",
            &format!(
                r#"{{"ecosystem":"npm","name":"{WIDGET}","version":"{ELIGIBLE}",
                     "reason":"known malicious release"}}"#
            ),
        ),
        common::parse_rfc3339(NOW),
    );

    let response = harness
        .server
        .get(&format!("/npm/{WIDGET}/{ELIGIBLE}"))
        .await;
    assert_eq!(response.status().as_u16(), 403);
    assert!(
        response.headers().get("retry-after").is_none(),
        "a block is not something to wait out, so it carries no Retry-After"
    );
    let blocked = body(response).await;
    assert_error_body(&blocked, "BLOCKED");
    assert!(
        blocked.get("eligible_at").is_none(),
        "a block has no eligibility deadline: {blocked}"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Row 2: unknown package/reference or upstream removal -> 404
// ---------------------------------------------------------------------------

/// The `404` row as an HTTP contract assertion: a name upstream does not have, and a
/// reference id nothing was ever advertised for.
///
/// This is deliberately **not** the Gate 3 test-plan case `upstream_removal_becomes_404`
/// (a project this instance already knows disappearing upstream). That test remains
/// unowned by any slice row and is not closed here.
#[tokio::test]
async fn unknown_package_or_reference_is_404() {
    let captured = logs::capture_info();
    let harness = widget().await;

    let response = harness.server.get("/npm/no-such-package").await;
    assert_eq!(response.status().as_u16(), 404);
    let missing = body(response).await;
    assert_error_body(&missing, "NOT_FOUND");
    assert_decided(&captured, &request_id_of(&missing), 404);

    // A well-formed reference id that names nothing. SPEC §9: the id is a lookup key,
    // so one nobody advertised is a miss rather than an error.
    let unknown_id = "a".repeat(64);
    let response = harness
        .server
        .get(&format!("/npm/artifacts/{unknown_id}/{FILENAME}"))
        .await;
    assert_eq!(response.status().as_u16(), 404);
    assert_error_body(&body(response).await, "NOT_FOUND");

    // A reference that exists, asked for under another filename: SPEC §9 makes the
    // filename part of what the reference *is*.
    let path = harness.artifact_path().await;
    let id = path.split('/').nth(3).expect("a reference id");
    let response = harness
        .server
        .get(&format!("/npm/artifacts/{id}/not-the-filename.tgz"))
        .await;
    assert_eq!(response.status().as_u16(), 404);
    assert_error_body(&body(response).await, "NOT_FOUND");

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Row 3: invalid input -> 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_input_is_400() {
    let captured = logs::capture_info();
    let harness = widget().await;

    // SPEC §9: a reference id is 64 hexadecimal characters and nothing else.
    let response = harness
        .server
        .get("/npm/artifacts/not-hexadecimal/f.tgz")
        .await;
    assert_eq!(response.status().as_u16(), 400);
    let invalid = body(response).await;
    assert_error_body(&invalid, "INVALID_INPUT");
    assert_decided(&captured, &request_id_of(&invalid), 400);

    // Hostile package names, over a raw socket: `reqwest` would decode `%2E` and
    // remove the dot segments client-side, so these would never reach the router.
    for hostile in [
        "/npm/%2E%2E",
        "/npm/%2E%2E%2F%2E%2E",
        "/npm/a%3Ab",
        "/npm/a%20b",
    ] {
        let response = harness.server.raw_get(hostile, &[]).await;
        assert_eq!(
            raw_status(&response),
            400,
            "{hostile} is not a package name this server will look up: {response}"
        );
    }

    assert!(
        harness.registry.calls().is_empty(),
        "no invalid name may leave the process as an upstream fetch, and these did: {:?}",
        harness.registry.calls()
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Row 4: unsupported route/method/representation -> 404, 405 or 406
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsupported_route_405_and_406() {
    let captured = logs::capture_info();
    let harness = widget().await;

    // A route that exists, with a method it does not support. SPEC §11: "Reject
    // request methods outside the supported set."
    let response = harness.server.post(&format!("/npm/{WIDGET}")).await;
    assert_eq!(response.status().as_u16(), 405);
    let allow = response
        .headers()
        .get("allow")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("a 405 says which methods the route does support");
    assert!(
        allow.contains("GET"),
        "the Allow header names GET, got {allow:?}"
    );
    let refused = body(response).await;
    assert_error_body(&refused, "METHOD_NOT_ALLOWED");
    assert_decided(&captured, &request_id_of(&refused), 405);

    // A method `reqwest` will not send, written straight onto the socket.
    for method in ["PUT", "DELETE", "PATCH", "TRACE", "PROPFIND"] {
        let addr = harness.server.local_addr();
        let response = harness
            .server
            .raw_send(&format!(
                "{method} /health/live HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
            ))
            .await;
        assert_eq!(
            raw_status(&response),
            405,
            "{method} is outside the supported set: {response}"
        );
    }

    // A representation this server does not produce. SPEC §11's `406`.
    for accept in [
        "application/xml",
        "text/plain",
        "text/html;q=0",
        "application/vnd.pypi.simple.v1+json;q=0, text/html;q=0",
    ] {
        let response = harness
            .server
            .get_with_headers("/pypi/simple/widget/", &[("accept", accept)])
            .await;
        assert_eq!(
            response.status().as_u16(),
            406,
            "Accept: {accept} names nothing this server produces"
        );
        assert_error_body(&body(response).await, "NOT_ACCEPTABLE");
    }

    // And the same route with an acceptable representation is not refused, so the
    // `406` above is negotiation and not a route that simply stopped working.
    let response = harness
        .server
        .get_with_headers("/pypi/simple/widget/", &[("accept", "text/html")])
        .await;
    assert_ne!(response.status().as_u16(), 406);

    // A route that does not exist at all.
    let response = harness.server.get("/no/such/route").await;
    assert_eq!(response.status().as_u16(), 404);
    assert_error_body(&body(response).await, "NOT_FOUND");

    // SPEC §6: "Unsupported API routes receive an explicit error and are never blindly
    // forwarded." npm's `-` namespace is not a package name.
    let before = harness.registry.calls().len();
    for unsupported in ["/npm/-", "/npm/-/whoami", "/npm/-/v1/search?text=widget"] {
        let response = harness.server.raw_get(unsupported, &[]).await;
        assert_eq!(
            raw_status(&response),
            404,
            "{unsupported} is npm's own API namespace: {response}"
        );
    }
    assert_eq!(
        harness.registry.calls().len(),
        before,
        "and none of them left the process as an upstream fetch: {:?}",
        harness.registry.calls()
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Row 5: missing/expired blocklist, local capacity exhausted, overloaded -> 503
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_unavailable_capacity_and_overload_are_503() {
    let captured = logs::capture_info();

    // No blocklist file at all: no policy is in force, so nothing is served.
    let unpoliced =
        TestServer::start_with(sample_config(), TestClock::at_rfc3339(NOW).shared()).await;
    let response = unpoliced.get(&format!("/npm/{WIDGET}")).await;
    assert_eq!(response.status().as_u16(), 503);
    let unavailable = body(response).await;
    assert_error_body(&unavailable, "POLICY_UNAVAILABLE");
    assert_decided(&captured, &request_id_of(&unavailable), 503);
    unpoliced.shutdown().await;

    // SPEC §10: "reject overload instead of allowing unbounded waiters or tasks."
    let harness = harness_with(&[], |config| {
        config.max_active_requests = std::num::NonZeroU32::new(1).expect("one");
    })
    .await;
    let held = harness
        .server
        .app()
        .limits
        .active_permit()
        .expect("the only permit");
    let response = harness.server.get(&format!("/npm/{WIDGET}")).await;
    assert_eq!(response.status().as_u16(), 503);
    assert_error_body(&body(response).await, "OVERLOADED");
    drop(held);

    // The remaining two conditions of this row reach HTTP through the same table.
    // Their production is witnessed where the code that produces them lives —
    // `disk_full_is_a_503_not_a_policy_relaxation` in `persistence_content.rs` and
    // the storage-failure path in `store` — so what is asserted here is the row.
    assert_eq!(ApiError::CapacityExhausted.status().as_u16(), 503);
    assert_eq!(ApiError::StorageUnusable.status().as_u16(), 503);
    assert_eq!(ApiError::InternalFailure.status().as_u16(), 503);
    assert_eq!(
        ApiError::CapacityExhausted.error_code(),
        "CAPACITY_EXHAUSTED"
    );
    assert_eq!(ApiError::StorageUnusable.error_code(), "STORAGE_UNUSABLE");
    assert_eq!(
        ApiError::InternalFailure.error_code(),
        "INTERNAL_FAILURE",
        "an instance-local failure is not reported as capacity: nothing was full"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Row 6: upstream failure, invalid upstream metadata, integrity failure -> 502;
// timeout is 504
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upstream_failure_invalid_metadata_and_integrity_are_502_and_timeout_is_504() {
    let captured = logs::capture_info();
    let harness = harness(&[
        (
            &npm_upstream_path("unreachable"),
            FakeAnswer::Fail(UpstreamError::Transport("no route to host".to_owned())),
        ),
        (
            &npm_upstream_path("slow"),
            FakeAnswer::Fail(UpstreamError::Timeout),
        ),
        (
            &npm_upstream_path("garbled"),
            FakeAnswer::Body("this is not a package document".to_owned()),
        ),
        (&npm_upstream_path(WIDGET), FakeAnswer::Body(document())),
        // Declares a length it does not deliver: the bytes are complete as far as the
        // stream is concerned and only the declared size says otherwise.
        (
            &npm_artifact_upstream_path(WIDGET, FILENAME),
            FakeAnswer::Truncated {
                declared_length: 4096,
                body: "not the whole artifact".to_owned(),
            },
        ),
    ])
    .await;

    let response = harness.server.get("/npm/unreachable").await;
    assert_eq!(response.status().as_u16(), 502);
    let failure = body(response).await;
    assert_error_body(&failure, "UPSTREAM_FAILURE");
    assert_decided(&captured, &request_id_of(&failure), 502);
    assert_no_upstream_detail(&failure);

    let response = harness.server.get("/npm/garbled").await;
    assert_eq!(response.status().as_u16(), 502);
    let invalid = body(response).await;
    assert_error_body(&invalid, "UPSTREAM_INVALID");
    assert_no_upstream_detail(&invalid);

    let path = harness.artifact_path().await;
    let response = harness.server.get(&path).await;
    assert_eq!(
        response.status().as_u16(),
        502,
        "SPEC §9: bytes that disagree with their declared size are an integrity failure"
    );
    let mismatch = body(response).await;
    assert_error_body(&mismatch, "INTEGRITY_MISMATCH");
    assert_no_upstream_detail(&mismatch);

    // The one upstream failure SPEC §11 separates out, because a client may retry it.
    let response = harness.server.get("/npm/slow").await;
    assert_eq!(response.status().as_u16(), 504);
    let timeout = body(response).await;
    assert_error_body(&timeout, "UPSTREAM_TIMEOUT");
    assert_no_upstream_detail(&timeout);

    harness.shutdown().await;
}

/// SPEC §11 fixes what an error body carries. Nothing that would tell a client where
/// this instance fetches from, what upstream said, or where its files are may travel
/// out with it.
fn assert_no_upstream_detail(value: &Value) {
    let text = value.to_string();
    for leak in [
        "npm.invalid",
        "pypi.invalid",
        "files.invalid",
        "https://",
        "http://",
        "/tmp",
        "no route to host",
        "etag",
        "last-modified",
    ] {
        assert!(
            !text.to_ascii_lowercase().contains(leak),
            "an error body must not carry {leak:?}: {text}"
        );
    }
    let object = value.as_object().expect("an error body is an object");
    for field in object.keys() {
        assert!(
            ["error", "reason", "request_id", "eligible_at"].contains(&field.as_str()),
            "SPEC §11 fixes the fields of an error body; {field} is not one of them: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Every response, not only the ones a row names
// ---------------------------------------------------------------------------

/// SPEC §10: "Send `Cache-Control: no-store` on downstream metadata, artifacts, and
/// errors."
///
/// A test that checked only success paths would not prove this, so every status this
/// server can produce is walked — and the statuses actually seen are asserted at the
/// end, so the walk cannot quietly stop covering one.
#[tokio::test]
async fn cache_control_no_store_on_every_response() {
    let harness = harness(&[
        (&npm_upstream_path(WIDGET), FakeAnswer::Body(document())),
        (
            &npm_upstream_path("unreachable"),
            FakeAnswer::Fail(UpstreamError::Transport("no route to host".to_owned())),
        ),
        (
            &npm_upstream_path("slow"),
            FakeAnswer::Fail(UpstreamError::Timeout),
        ),
        (
            &npm_artifact_upstream_path(WIDGET, FILENAME),
            FakeAnswer::Body("the artifact bytes".to_owned()),
        ),
    ])
    .await;
    let artifact = harness.artifact_path().await;

    let mut seen = Vec::new();
    for (path, accept) in [
        ("/health/live", None),
        ("/health/ready", None),
        ("/npm/-/ping", None),
        (&format!("/npm/{WIDGET}"), None),
        (&format!("/npm/{WIDGET}/{HELD}"), None),
        ("/npm/no-such-package", None),
        ("/npm/-/whoami", None),
        ("/npm/unreachable", None),
        ("/npm/slow", None),
        ("/npm/artifacts/not-hexadecimal/f.tgz", None),
        ("/pypi/simple/widget/", Some("application/xml")),
        ("/no/such/route", None),
        (&artifact, None),
    ] {
        let response = match accept {
            Some(accept) => {
                harness
                    .server
                    .get_with_headers(path, &[("accept", accept)])
                    .await
            }
            None => harness.server.get(path).await,
        };
        let status = response.status().as_u16();
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{path} answered {status} without Cache-Control: no-store"
        );
        seen.push(status);
    }

    // The `405` and the `301` do not come from a handler at all — one is the router's
    // method fallback and the other is built inside `pypi_routes` — so both are walked
    // the same way rather than assumed to inherit the header.
    let response = harness.server.post(&format!("/npm/{WIDGET}")).await;
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "the router's own 405 carries it too"
    );
    seen.push(response.status().as_u16());

    // SPEC §9's two range answers. `206` shares `ArtifactResponse::with_body` with the
    // `200` above, but `416` has a constructor of its own
    // (`stream::ArtifactResponse::range_not_satisfiable`), so neither is assumed: what
    // actually covers both is that `no_store` is an unconditional
    // `middleware::map_response` layer over the whole router, and this walks it.
    for (range, expected) in [("bytes=0-3", 206), ("bytes=99999-", 416)] {
        let response = harness
            .server
            .get_with_headers(&artifact, &[("range", range)])
            .await;
        assert_eq!(
            response.status().as_u16(),
            expected,
            "Range: {range} on an 18-byte artifact"
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "Range: {range} answered {expected} without Cache-Control: no-store"
        );
        seen.push(expected);
    }

    // On a raw socket, so this is what crossed the wire rather than what a client
    // library reassembled — and because `reqwest` follows the `301` rather than
    // showing it.
    for (raw_path, expected) in [("/npm/%2E%2E", 400), ("/pypi/simple/Widget/", 301)] {
        let raw = harness.server.raw_get(raw_path, &[]).await;
        assert_eq!(raw_status(&raw), expected, "{raw_path} answered: {raw}");
        assert_eq!(
            raw_header(&raw, "cache-control").as_deref(),
            Some("no-store"),
            "{raw_path} crossed the wire without it: {raw}"
        );
        seen.push(raw_status(&raw));
    }

    // SPEC §8: with no blocklist in force nothing is served, and that refusal is as
    // uncacheable as any other answer.
    let unpoliced =
        TestServer::start_with(sample_config(), TestClock::at_rfc3339(NOW).shared()).await;
    for path in ["/health/ready", "/npm/anything"] {
        let response = unpoliced.get(path).await;
        assert_eq!(response.status().as_u16(), 503, "{path}");
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store"),
            "{path} answered 503 without Cache-Control: no-store"
        );
        seen.push(503);
    }
    unpoliced.shutdown().await;

    seen.sort_unstable();
    seen.dedup();
    for required in [200, 206, 301, 400, 403, 404, 405, 406, 416, 502, 503, 504] {
        assert!(
            seen.contains(&required),
            "this walk has to keep covering {required}; it covered {seen:?}"
        );
    }

    harness.shutdown().await;
}

/// SPEC §10: "Do not forward upstream validators or return downstream `304` responses
/// in this release. This avoids intermediaries retaining previously allowed responses."
///
/// This is the **downstream** direction only. Whether the firewall sends validators
/// *upstream* and handles a not-modified answer is a separate, still-unowned
/// obligation and is not touched here.
#[tokio::test]
async fn no_downstream_304() {
    let harness = harness(&[
        (&npm_upstream_path(WIDGET), FakeAnswer::Body(document())),
        (
            &npm_artifact_upstream_path(WIDGET, FILENAME),
            FakeAnswer::Body("the artifact bytes".to_owned()),
        ),
    ])
    .await;
    let artifact = harness.artifact_path().await;

    let conditional = [
        ("if-none-match", "\"upstream-etag\""),
        ("if-modified-since", "Mon, 06 Apr 2026 00:00:00 GMT"),
    ];

    for path in [
        "/health/live".to_owned(),
        "/npm/-/ping".to_owned(),
        format!("/npm/{WIDGET}"),
        format!("/npm/{WIDGET}/{ELIGIBLE}"),
        "/pypi/simple/".to_owned(),
        artifact.clone(),
    ] {
        // Twice: the second request is the warm one, and a cache is exactly where a
        // stored validator would come back out.
        for attempt in 1..=2 {
            let response = harness.server.get_with_headers(&path, &conditional).await;
            let status = response.status().as_u16();
            assert_ne!(
                status, 304,
                "{path} answered 304 on attempt {attempt}; no downstream 304 is produced"
            );
            assert!(
                (200..300).contains(&status),
                "{path} answered {status}; a refusal would make the validator check \
                 below vacuous"
            );
            for validator in ["etag", "last-modified"] {
                assert!(
                    response.headers().get(validator).is_none(),
                    "{path} forwarded a {validator} downstream on attempt {attempt}; \
                     an intermediary could then retain a previously allowed response"
                );
            }
        }
    }

    // An error answer is the other place a validator could escape.
    let response = harness
        .server
        .get_with_headers("/npm/no-such-package", &conditional)
        .await;
    assert_eq!(response.status().as_u16(), 404);
    assert!(response.headers().get("etag").is_none());
    assert!(response.headers().get("last-modified").is_none());

    harness.shutdown().await;
}

/// SPEC §11 lists `GET /npm/-/ping` as its own endpoint, and `PackageName::parse_route`
/// admits `-` as a name — so without an explicit route this request leaves the process
/// as an upstream fetch for a package called `-`.
#[tokio::test]
async fn ping_route_is_not_read_as_a_package_name() {
    let harness = harness(&[(
        &npm_upstream_path("-"),
        FakeAnswer::Body(r#"{"name":"-","versions":{}}"#.to_owned()),
    )])
    .await;

    let response = harness.server.get("/npm/-/ping").await;
    assert_eq!(response.status().as_u16(), 200);
    let ping = body(response).await;
    assert_eq!(ping, json!({}), "npm's own registry answers ping with {{}}");

    assert!(
        harness.registry.calls().is_empty(),
        "ping is a connectivity answer from this process; it must reach no registry, \
         and it reached {:?}",
        harness.registry.calls()
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// The decision log
// ---------------------------------------------------------------------------

/// SPEC §11: "Log request ID, ecosystem, package/version when known, policy result,
/// reason, blocklist revision, cache status, duration, and bytes served."
#[tokio::test]
async fn one_decision_line_per_request_carries_the_request_id() {
    let captured = logs::capture_info();
    let harness = widget().await;

    let response = harness.server.get(&format!("/npm/{WIDGET}/{HELD}")).await;
    assert_eq!(response.status().as_u16(), 403);
    let held = body(response).await;
    let request_id = request_id_of(&held);

    assert_eq!(
        captured.lines_containing_all(&["request decided", &request_id]),
        1,
        "exactly one decision line, carrying the ID the client was told"
    );

    let line = captured
        .text()
        .lines()
        .find(|line| line.contains("request decided") && line.contains(&request_id))
        .expect("the decision line")
        .to_owned();
    for field in [
        "ecosystem=\"npm\"",
        &format!("package=\"\\\"{WIDGET}\\\"\""),
        &format!("version=\"\\\"{HELD}\\\"\""),
        "status=403",
        "result=\"HELD\"",
        "reason=",
        "blocklist_revision=",
        "cache=",
        "duration_micros=",
        "bytes=",
    ] {
        assert!(
            line.contains(field),
            "SPEC §11 names {field} as a field of the decision line: {line}"
        );
    }

    // A warm request says so, so the line can be read as evidence of SPEC §10's warm
    // path rather than only of the answer.
    let first = harness.server.get(&format!("/npm/{WIDGET}")).await;
    assert_eq!(first.status().as_u16(), 200);
    let second = harness.server.get(&format!("/npm/{WIDGET}")).await;
    assert_eq!(second.status().as_u16(), 200);
    assert!(
        captured.lines_containing_all(&["request decided", "cache=\"hit\""]) >= 1,
        "the second identical request is served warm and the line says so"
    );

    // A route the router answers without reaching a handler still gets a line.
    let response = harness.server.get("/no/such/route").await;
    assert_eq!(response.status().as_u16(), 404);
    let unknown = request_id_of(&body(response).await);
    assert_eq!(
        captured.lines_containing_all(&["request decided", &unknown]),
        1,
        "an unknown route never reaches a handler, and still has exactly one line"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Artifacts under the ecosystem root
// ---------------------------------------------------------------------------

/// A cross-root test that asserted only the status would be worthless, and would
/// have passed before this route existed: neither `/npm/artifacts/…` nor
/// `/pypi/artifacts/…` was registered, so both already answered `404` through the
/// router's unknown-route fallback.
///
/// This separates the two. A reference id that is not hexadecimal is refused by
/// `artifact_routes::serve` with `400 INVALID_INPUT`, which only a registered route
/// reaching that handler can produce — the fallback answers `404`.
async fn assert_artifact_route_reaches_the_handler(harness: &Harness, root: &str) {
    let response = harness
        .server
        .get(&format!("/{root}/artifacts/not-hexadecimal/f.tgz"))
        .await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "/{root}/artifacts/… must reach the artifact handler; a 404 here is the \
         router refusing an unregistered route, and the cross-root 404 below would \
         then prove nothing"
    );
    assert_error_body(&body(response).await, "INVALID_INPUT");
}

/// Asserts the one decision line for `request_id` names `expected` as its ecosystem
/// and never `never`.
fn assert_logged_ecosystem(
    captured: &logs::Captured,
    request_id: &str,
    expected: &str,
    never: &str,
) {
    assert_eq!(
        captured.lines_containing_all(&[
            "request decided",
            request_id,
            &format!("ecosystem=\"{expected}\""),
        ]),
        1,
        "the decision line carries the ecosystem of the reference row. Captured:\n{}",
        captured.text()
    );
    assert_eq!(
        captured.lines_containing_all(&[
            "request decided",
            request_id,
            &format!("ecosystem=\"{never}\""),
        ]),
        0,
        "and never the one the caller put in the path. Captured:\n{}",
        captured.text()
    );
}

/// A reference id is a deterministic hash over public metadata and explicitly not an
/// authorization token (SPEC §9), so anyone can carry an npm one to the PyPI root.
/// The handler compares the URL's ecosystem with the row's and refuses.
#[tokio::test]
async fn an_npm_reference_id_under_the_pypi_artifact_root_is_404() {
    let captured = logs::capture_info();
    let harness = both_ecosystems().await;

    assert_artifact_route_reaches_the_handler(&harness, "pypi").await;

    let path = harness.artifact_path().await;
    assert!(
        path.starts_with("/npm/artifacts/"),
        "an npm reference is advertised under the npm root: {path}"
    );
    let id = path.split('/').nth(3).expect("a reference id");
    let crossed = format!("/pypi/artifacts/{id}/{FILENAME}");

    let response = harness.server.get(&crossed).await;
    assert_eq!(response.status().as_u16(), 404);
    let refused = body(response).await;
    assert_error_body(&refused, "NOT_FOUND");
    assert_logged_ecosystem(&captured, &request_id_of(&refused), "npm", "pypi");

    // Every path through the handler, not only the plain `GET`: `HEAD` runs the same
    // checks and a byte range is still a request for bytes.
    assert_eq!(harness.server.head(&crossed).await.status().as_u16(), 404);
    assert_eq!(
        harness
            .server
            .get_with_headers(&crossed, &[("range", "bytes=0-1")])
            .await
            .status()
            .as_u16(),
        404
    );

    harness.shutdown().await;
}

/// The mirror image, so neither direction rests on the other.
#[tokio::test]
async fn a_pypi_reference_id_under_the_npm_artifact_root_is_404() {
    let captured = logs::capture_info();
    let harness = both_ecosystems().await;

    assert_artifact_route_reaches_the_handler(&harness, "npm").await;

    let path = harness.pypi_artifact_path().await;
    assert!(
        path.starts_with("/pypi/artifacts/"),
        "a PyPI reference is advertised under the PyPI root: {path}"
    );
    let id = path.split('/').nth(3).expect("a reference id");
    let crossed = format!("/npm/artifacts/{id}/{BARD_FILE}");

    let response = harness.server.get(&crossed).await;
    assert_eq!(response.status().as_u16(), 404);
    let refused = body(response).await;
    assert_error_body(&refused, "NOT_FOUND");
    assert_logged_ecosystem(&captured, &request_id_of(&refused), "pypi", "npm");

    assert_eq!(harness.server.head(&crossed).await.status().as_u16(), 404);
    assert_eq!(
        harness
            .server
            .get_with_headers(&crossed, &[("range", "bytes=0-1")])
            .await
            .status()
            .as_u16(),
        404
    );

    harness.shutdown().await;
}

/// The matching-root success path, and the witness for deriving the logged
/// `ecosystem` from the verified row: before this slice `Target::of` split on the
/// first path segment and wrote `ecosystem="artifact"` for every artifact request —
/// three values for two ecosystems, and none of them the one whose policy decided
/// the request.
#[tokio::test]
async fn the_artifact_decision_line_logs_the_ecosystem_of_the_reference_row() {
    let captured = logs::capture_info();
    let harness = harness(&[
        (&npm_upstream_path(WIDGET), FakeAnswer::Body(document())),
        (
            &npm_artifact_upstream_path(WIDGET, FILENAME),
            FakeAnswer::Body("the artifact bytes".to_owned()),
        ),
    ])
    .await;

    let path = harness.artifact_path().await;
    assert!(path.starts_with("/npm/artifacts/"), "{path}");
    let response = harness.server.get(&path).await;
    assert_eq!(response.status().as_u16(), 200);
    let bytes = response.bytes().await.expect("the artifact body");
    assert_eq!(&bytes[..], b"the artifact bytes");

    // A `200` carries no error body to read a request id out of, so the line is
    // selected by the reference id it names — `Target` logs that as `package`.
    let id = path.split('/').nth(3).expect("a reference id");
    let names_the_reference = format!("package=\"\\\"{id}\\\"\"");
    assert!(
        captured.lines_containing_all(&[
            "request decided",
            &names_the_reference,
            "ecosystem=\"npm\"",
        ]) >= 1,
        "the served artifact is logged under the ecosystem of its reference row. \
         Captured:\n{}",
        captured.text()
    );
    assert_eq!(
        captured.lines_containing_all(&["request decided", "ecosystem=\"artifact\""]),
        0,
        "`artifact` is not an ecosystem, and no request in this binary may log it as \
         one. Captured:\n{}",
        captured.text()
    );

    harness.shutdown().await;
}

/// SPEC §11: "Emit counts and timing summaries periodically to stdout; no separate
/// metrics service is required for the MVP."
#[tokio::test]
async fn the_periodic_counter_summary_is_emitted() {
    let captured = logs::capture_info();
    let harness = widget().await;

    // A witness for a periodic emission cannot wait a minute for it.
    probation::http::logging::set_summary_window(Duration::ZERO);

    let before = captured.lines_mentioning("request summary");
    harness.server.get("/health/live").await;
    harness.server.get("/health/live").await;
    let after = captured.lines_mentioning("request summary");
    assert!(
        after > before,
        "the window closed and nothing summarised it: {before} lines before, {after} after"
    );

    let summary = captured
        .text()
        .lines()
        .rev()
        .find(|line| line.contains("request summary"))
        .expect("a summary line")
        .to_owned();
    for field in [
        "requests=",
        "errors=",
        "bytes=",
        "mean_duration_micros=",
        "window_micros=",
    ] {
        assert!(
            summary.contains(field),
            "a summary carries counts and timings; {field} is missing: {summary}"
        );
    }

    harness.shutdown().await;
}

/// One decision line for `request_id`, at `status`.
fn assert_decided(captured: &logs::Captured, request_id: &str, status: u16) {
    assert_eq!(
        captured.lines_containing_all(&[
            "request decided",
            request_id,
            &format!("status={status}")
        ]),
        1,
        "SPEC §11: one decision line per request, carrying its request ID and what it \
         answered. Captured:\n{}",
        captured.text()
    );
}
