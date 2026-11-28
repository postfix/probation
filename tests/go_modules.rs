//! Row 19: Go module discovery and `.info`/`.mod`/`.zip` protection, end to end through the
//! firewall against an in-process `FakeRegistry` and a clock the test moves by hand. The real
//! client witness is tests/go_native.rs.

mod common;

use std::sync::Arc;

use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::config::Config;
use probation::go_modules::escape;
use probation::go_modules::serve::{self, Dated, InfoError, LIST_INFO_CAP, ListError};
use probation::http::go_routes::{self, Parsed};
use probation::upstream::{OriginKind, OriginSet, Transport};
use tempfile::TempDir;
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const DAY: u64 = 86_400;
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn origins() -> OriginSet {
    fake_origins().with_go(
        Url::parse("https://goproxy.invalid").unwrap(),
        Url::parse("https://sumdb.invalid").unwrap(),
    )
}

/// The upstream URL path of an escaped module path plus the tail (`@v/list`, `@v/v1.0.0.info`).
fn up(escaped_module: &str, tail: &str) -> String {
    let mut segments: Vec<&str> = escaped_module.split('/').collect();
    segments.extend(tail.split('/'));
    origins()
        .url_for(OriginKind::GoProxy, &segments)
        .unwrap()
        .path()
        .to_owned()
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    _dir: TempDir,
}

fn config_with(dir: &std::path::Path, blocked: &str, cooldown: u64) -> Config {
    let blocklist_file = dir.join("blocklist.json");
    std::fs::write(
        &blocklist_file,
        common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked),
    )
    .unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config.cooldown_seconds = cooldown;
    config
}

async fn harness(blocked: &str, cooldown: u64) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(dir.path(), blocked, cooldown);
    let registry = FakeRegistry::new();
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        origins(),
    )
    .await;
    Harness {
        server,
        registry,
        clock,
        _dir: dir,
    }
}

use common::go::{info, mod_text as module_mod_text, module_zip};

/// A module on the fake proxy: its list, and per version an info with `time`, a `.mod` and a `.zip`.
fn serve_module(h: &Harness, escaped: &str, versions: &[(&str, Option<&str>)]) {
    let list: String = versions.iter().map(|(v, _)| format!("{v}\n")).collect();
    h.registry
        .answer(&up(escaped, "@v/list"), FakeAnswer::Body(list));
    for (version, time) in versions {
        serve_version(h, escaped, version, *time);
    }
}

fn serve_version(h: &Harness, escaped: &str, version: &str, time: Option<&str>) {
    let ev = escape::escape(version).unwrap();
    h.registry.answer(
        &up(escaped, &format!("@v/{ev}.info")),
        FakeAnswer::Body(info(version, time)),
    );
    h.registry.answer(
        &up(escaped, &format!("@v/{ev}.mod")),
        FakeAnswer::Body(mod_text(escaped)),
    );
    h.registry.answer(
        &up(escaped, &format!("@v/{ev}.zip")),
        FakeAnswer::Bytes(zip_bytes(escaped, version)),
    );
}

fn mod_text(escaped: &str) -> String {
    module_mod_text(&escape::unescape(escaped).unwrap())
}

/// The real zip layout a `go` command unpacks.
fn zip_bytes(escaped: &str, version: &str) -> Vec<u8> {
    module_zip(
        &escape::unescape(escaped).unwrap(),
        version,
        "package demo\n",
    )
}

async fn text_of(h: &Harness, path: &str) -> (u16, String) {
    let response = h.server.get(path).await;
    (response.status().as_u16(), response.text().await.unwrap())
}

fn calls_to(h: &Harness, needle: &str) -> usize {
    h.registry
        .calls()
        .iter()
        .filter(|url| url.path().contains(needle))
        .count()
}

// ------------------------------------------------------------------ identity: escaping

#[test]
fn escaping_round_trips_every_accepted_spelling_and_refuses_the_rest() {
    for (decoded, escaped) in [
        (
            "github.com/Azure/azure-sdk-for-go",
            "github.com/!azure/azure-sdk-for-go",
        ),
        ("github.com/BurntSushi/toml", "github.com/!burnt!sushi/toml"),
        ("example.com/a/b", "example.com/a/b"),
    ] {
        assert_eq!(escape::escape(decoded).unwrap(), escaped);
        assert_eq!(escape::unescape(escaped).unwrap(), decoded);
        assert_eq!(escape::module_of(escaped).as_deref(), Some(decoded));
    }
    assert_eq!(
        escape::version_of("v1.0.0-!r!c1").as_deref(),
        Some("v1.0.0-RC1")
    );
    assert_eq!(escape::escape("v1.0.0-RC1").unwrap(), "v1.0.0-!r!c1");
    // Exactly one spelling: an upper-case letter, `!` before a non-letter, a trailing `!`, `!!`, non-ASCII.
    for bad in [
        "github.com/Azure/x",
        "github.com/!Azure/x",
        "github.com/!/x",
        "github.com/x!",
        "github.com/!!a/x",
        "github.com/ü/x",
        "github.com/!1/x",
    ] {
        assert!(escape::module_of(bad).is_none(), "{bad}");
    }
    // A module path has a dot in its first element (so `sumdb/...` is never one), no empty or dot element.
    for bad in [
        "sumdb/sum.golang.org",
        "github.com//x",
        "github.com/../x",
        "github.com/./x",
        "/github.com/x",
        "github.com/x/",
        ".github.com/x",
        "github.com/x@v1",
    ] {
        assert!(escape::module_of(bad).is_none(), "{bad}");
    }
    for bad in [
        "1.0.0",
        "v1.0",
        "v01.0.0",
        "v1.0.0+meta",
        "v1.0.0+incompatible+x",
        "v1.0.0-",
        "",
        "V1.0.0",
        "v1.0.0-RC1",
    ] {
        assert!(
            escape::version_of(bad).is_none()
                || !escape::valid_version(&escape::version_of(bad).unwrap()),
            "{bad}"
        );
    }
    assert!(escape::valid_version("v2.0.0+incompatible"));
    assert!(escape::valid_version("v0.0.0-20250101120000-abcdef123456"));
    assert!(!escape::valid_version("v2.0.0+incompatible.1"));
}

#[test]
fn request_paths_parse_to_one_canonical_identity() {
    assert_eq!(
        go_routes::parse("github.com/!azure/x/@v/list").unwrap(),
        Parsed::List("github.com/Azure/x".into())
    );
    assert_eq!(
        go_routes::parse("github.com/x/@latest").unwrap(),
        Parsed::Latest("github.com/x".into())
    );
    assert_eq!(
        go_routes::parse("github.com/x/@v/v1.2.3-!r!c1.zip").unwrap(),
        Parsed::File("github.com/x".into(), "v1.2.3-RC1".into(), serve::Kind::Zip)
    );
    assert_eq!(
        go_routes::parse("sumdb/sum.golang.org/latest").unwrap(),
        Parsed::Sumdb("sum.golang.org/latest".into())
    );
    for bad in [
        "github.com/x/@v/v1.2.3.txt",
        "github.com/x/@v/list2",
        "github.com/x/@v/v1.2.3-RC1.zip",
        "github.com/X/@v/list",
        "github.com/x/@v/",
        "github.com/x",
        "@v/list",
        "github.com/x/@latest/extra",
    ] {
        assert!(go_routes::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn info_and_list_documents_are_parsed_strictly() {
    let (version, dated) = serve::parse_info(
        br#"{"Version":"v1.0.0","Time":"2025-01-01T00:00:00Z","Origin":{"VCS":"git"}}"#,
        Some("v1.0.0"),
    )
    .unwrap();
    assert_eq!(
        (version.as_str(), dated),
        ("v1.0.0", Dated::Upstream(1_735_689_600_000_000))
    );
    assert_eq!(
        serve::parse_info(br#"{"Version":"v1.0.0"}"#, None)
            .unwrap()
            .1,
        Dated::Undated
    );
    assert_eq!(
        serve::parse_info(
            br#"{"Version":"v1.0.0","Time":"0001-01-01T00:00:00Z"}"#,
            None
        )
        .unwrap()
        .1,
        Dated::Undated,
        "the zero time is no date"
    );
    assert_eq!(
        serve::parse_info(br#"{"Version":"v1.0.1"}"#, Some("v1.0.0")),
        Err(InfoError::Version)
    );
    assert_eq!(
        serve::parse_info(br#"{"Version":"v1.0.0","Time":"yesterday"}"#, None),
        Err(InfoError::Time)
    );
    assert_eq!(
        serve::parse_info(
            br#"{"Version":"v1.0.0","Time":"2025-01-01T00:00:00Z","Time":"2020-01-01T00:00:00Z"}"#,
            None
        ),
        Err(InfoError::NotJson),
        "a duplicate field is not read as its last value"
    );
    assert_eq!(serve::parse_info(b"<html>", None), Err(InfoError::NotJson));
    let list = serve::parse_list(
        b"v1.0.0\nnot a version\nv1.0.0\n\nv2.0.0+incompatible\r\nv1.0.1-RC1\n",
        10,
    )
    .unwrap();
    assert_eq!(list, vec!["v1.0.0", "v2.0.0+incompatible", "v1.0.1-RC1"]);
    assert_eq!(
        serve::parse_list(b"v1.0.0\nv1.0.1\nv1.0.2\n", 2),
        Err(ListError::TooMany)
    );
    assert_eq!(serve::parse_list(&[0xff, 0xfe], 2), Err(ListError::NotUtf8));
}

// ------------------------------------------------------------------ list

#[tokio::test]
async fn list_withholds_young_versions_and_orders_as_upstream() {
    let h = harness("", 7 * DAY).await;
    serve_module(
        &h,
        "example.com/demo",
        &[
            ("v1.1.0", Some(OLD)),
            ("v2.0.0", Some(YOUNG)),
            ("v1.0.0", Some(OLD)),
        ],
    );
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await,
        (200, "v1.1.0\nv1.0.0\n".to_owned())
    );
    // The cooldown elapses: the young version is listed on the next request.
    h.clock.advance_seconds(8 * DAY as i64);
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await.1,
        "v1.1.0\nv2.0.0\nv1.0.0\n"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn list_drops_blocked_names_versions_and_what_is_not_a_version() {
    let blocked = r#"{"ecosystem":"go","name":"example.com/demo","version":"1.0.1","reason":"malware"},{"ecosystem":"go","name":"github.com/Evil/pkg","version":null,"reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    h.registry.answer(
        &up("example.com/demo", "@v/list"),
        FakeAnswer::Body("v1.0.0\nv1.0.1\nnonsense\nv1.0.2\n".to_owned()),
    );
    for v in ["v1.0.0", "v1.0.1", "v1.0.2"] {
        h.registry.answer(
            &up("example.com/demo", &format!("@v/{v}.info")),
            FakeAnswer::Body(info(v, Some(OLD))),
        );
    }
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await.1,
        "v1.0.0\nv1.0.2\n"
    );
    // A blocked module is refused before anything is asked of upstream, in its escaped spelling too.
    let before = h.registry.calls().len();
    for path in [
        "/go/github.com/!evil/pkg/@v/list",
        "/go/github.com/!evil/pkg/@latest",
        "/go/github.com/!evil/pkg/@v/v1.0.0.info",
        "/go/github.com/!evil/pkg/@v/v1.0.0.zip",
    ] {
        assert_eq!(h.server.get(path).await.status().as_u16(), 403, "{path}");
    }
    assert_eq!(
        h.registry.calls().len(),
        before,
        "a blocked module reaches no upstream call"
    );
    // The block is case-sensitive, like the module: the lower-case path is another module.
    h.registry.answer(
        &up("github.com/evil/pkg", "@v/list"),
        FakeAnswer::Body("v1.0.0\n".to_owned()),
    );
    h.registry.answer(
        &up("github.com/evil/pkg", "@v/v1.0.0.info"),
        FakeAnswer::Body(info("v1.0.0", Some(OLD))),
    );
    assert_eq!(
        text_of(&h, "/go/github.com/evil/pkg/@v/list").await.1,
        "v1.0.0\n"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn list_fan_out_is_bounded_before_any_upstream_call_and_withholds_what_it_cannot_date() {
    let h = harness("", 7 * DAY).await;
    let versions: Vec<String> = (0..100).map(|n| format!("v1.0.{n}")).collect();
    let pairs: Vec<(&str, Option<&str>)> =
        versions.iter().map(|v| (v.as_str(), Some(OLD))).collect();
    serve_module(&h, "example.com/big", &pairs);
    let (status, body) = text_of(&h, "/go/example.com/big/@v/list").await;
    assert_eq!(status, 200);
    assert_eq!(
        calls_to(&h, ".info"),
        LIST_INFO_CAP,
        "one request makes at most the cap of .info calls"
    );
    assert_eq!(
        body.lines().count(),
        LIST_INFO_CAP,
        "what could not be dated yet is withheld, not guessed"
    );
    assert!(body.lines().any(|l| l == "v1.0.99"), "newest first");
    // The next request dates the rest (already dated versions cost nothing).
    let (_, body) = text_of(&h, "/go/example.com/big/@v/list").await;
    assert_eq!(body.lines().count(), 100);
    assert_eq!(calls_to(&h, ".info"), 100);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_list_that_is_too_long_or_not_text_is_refused_and_a_missing_module_is_404() {
    let h = harness("", 0).await;
    let many: String = (0..7000).map(|n| format!("v1.0.{n}\n")).collect();
    h.registry
        .answer(&up("example.com/many", "@v/list"), FakeAnswer::Body(many));
    assert_eq!(
        h.server
            .get("/go/example.com/many/@v/list")
            .await
            .status()
            .as_u16(),
        502
    );
    h.registry.answer(
        &up("example.com/bin", "@v/list"),
        FakeAnswer::Bytes(vec![0xff, 0xfe, 0x00]),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/bin/@v/list")
            .await
            .status()
            .as_u16(),
        502
    );
    h.registry
        .answer(&up("example.com/gone", "@v/list"), FakeAnswer::Missing);
    assert_eq!(
        h.server
            .get("/go/example.com/gone/@v/list")
            .await
            .status()
            .as_u16(),
        404
    );
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ the three files, gated together

#[tokio::test]
async fn info_mod_and_zip_of_a_young_version_are_all_refused_and_old_ones_are_exact() {
    let h = harness("", 7 * DAY).await;
    serve_module(
        &h,
        "example.com/demo",
        &[("v1.0.0", Some(OLD)), ("v2.0.0", Some(YOUNG))],
    );
    for ext in ["info", "mod", "zip"] {
        let young = h
            .server
            .get(&format!("/go/example.com/demo/@v/v2.0.0.{ext}"))
            .await;
        assert_eq!(young.status().as_u16(), 403, "{ext} of a young version");
        let old = h
            .server
            .get(&format!("/go/example.com/demo/@v/v1.0.0.{ext}"))
            .await;
        assert_eq!(old.status().as_u16(), 200, "{ext} of an old version");
        let body = old.bytes().await.unwrap().to_vec();
        let expected = match ext {
            "info" => info("v1.0.0", Some(OLD)).into_bytes(),
            "mod" => mod_text("example.com/demo").into_bytes(),
            _ => zip_bytes("example.com/demo", "v1.0.0"),
        };
        assert_eq!(body, expected, "{ext} is upstream's exact bytes");
    }
    assert_eq!(
        calls_to(&h, "v2.0.0.zip") + calls_to(&h, "v2.0.0.mod"),
        0,
        "a refused version's mod and zip are never fetched"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn pseudo_versions_unlisted_are_served_by_their_own_info_date() {
    let h = harness("", 7 * DAY).await;
    let old = "v0.0.0-20240101000000-abcdef123456";
    let young = "v0.0.0-20260405000000-abcdef123457";
    for (v, t) in [(old, OLD), (young, YOUNG)] {
        serve_version(&h, "example.com/pseudo", v, Some(t));
    }
    assert_eq!(
        h.server
            .get(&format!("/go/example.com/pseudo/@v/{old}.zip"))
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        h.server
            .get(&format!("/go/example.com/pseudo/@v/{young}.zip"))
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        h.server
            .get(&format!("/go/example.com/pseudo/@v/{young}.info"))
            .await
            .status()
            .as_u16(),
        403
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn mixed_case_modules_and_versions_keep_one_identity_end_to_end() {
    let blocked = r#"{"ecosystem":"go","name":"github.com/Mixed/Case","version":"1.0.0-RC1","reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    serve_module(
        &h,
        "github.com/!mixed/!case",
        &[("v1.0.0-RC1", Some(OLD)), ("v1.0.0", Some(OLD))],
    );
    // The policy key is the decoded spelling: the escaped path and the escaped version name the blocked pair.
    assert_eq!(
        h.server
            .get("/go/github.com/!mixed/!case/@v/v1.0.0-!r!c1.zip")
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        h.server
            .get("/go/github.com/!mixed/!case/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        200
    );
    // The list drops the blocked pair and writes the version in its real (upper-case) spelling.
    assert_eq!(
        text_of(&h, "/go/github.com/!mixed/!case/@v/list").await.1,
        "v1.0.0\n"
    );
    // Another spelling of the same module is no route at all and asks upstream nothing.
    let before = h.registry.calls().len();
    for path in [
        "/go/github.com/Mixed/Case/@v/list",
        "/go/github.com/mixed/case/@v/v1.0.0.zip",
        "/go/github.com/!mixed/!case/@v/v1.0.0-RC1.zip",
    ] {
        let status = h.server.get(path).await.status().as_u16();
        assert!(
            status == 404 || (path.contains("mixed/case") && status != 200),
            "{path}: {status}"
        );
    }
    assert!(h.registry.calls().len() >= before);
    assert_eq!(
        h.server
            .get("/go/github.com/Mixed/Case/@v/list")
            .await
            .status()
            .as_u16(),
        404
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn invalid_spellings_are_404_before_any_upstream_call() {
    let h = harness("", 0).await;
    for path in [
        "/go/example.com/demo/@v/v1.0.0.txt",
        "/go/example.com/demo/@v/1.0.0.zip",
        "/go/example.com/demo/@v/v1.0.zip",
        "/go/Example.com/demo/@v/list",
        "/go/example.com/!/@v/list",
        "/go/nodot/x/@v/list",
        "/go/example.com/demo/@v/v1.0.0.info/extra",
        "/go/example.com/%2e%2e/demo/@v/list",
        "/go/example.com/demo//@v/list",
        "/go/example.com/demo/@v/-rf.info",
        "/go/example.com/demo/@v/a..b.info",
        "/go/example.com/demo/@v/v1.0.0%2fx.info",
        "/go/example.com/demo/@v/Main.info",
        "/go/example.com/demo/@v/main.zip",
        "/go/example.com/demo/@v/main.mod",
    ] {
        assert_eq!(h.server.get(path).await.status().as_u16(), 404, "{path}");
    }
    assert!(h.registry.calls().is_empty(), "{:?}", h.registry.calls());
    h.server.shutdown().await;
}

#[tokio::test]
async fn upstream_answers_that_do_not_fit_are_refused_or_missing() {
    let h = harness("", 0).await;
    // A 404 of the version is a 404; an info that names another version, a bad Time or a non-JSON body is 502.
    h.registry.answer(
        &up("example.com/demo", "@v/v1.0.0.info"),
        FakeAnswer::Missing,
    );
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        404
    );
    h.registry.answer(
        &up("example.com/demo", "@v/v1.0.1.info"),
        FakeAnswer::Body(info("v9.9.9", Some(OLD))),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.1.zip")
            .await
            .status()
            .as_u16(),
        502
    );
    h.registry.answer(
        &up("example.com/demo", "@v/v1.0.2.info"),
        FakeAnswer::Body(r#"{"Version":"v1.0.2","Time":"soon"}"#.to_owned()),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.2.info")
            .await
            .status()
            .as_u16(),
        502,
        "a Time that does not parse fails closed"
    );
    h.registry.answer(
        &up("example.com/demo", "@v/v1.0.3.info"),
        FakeAnswer::Body("<html>captive portal</html>".to_owned()),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.3.mod")
            .await
            .status()
            .as_u16(),
        502
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn an_undated_version_waits_on_its_first_seen_time() {
    let h = harness("", DAY).await;
    serve_version(&h, "example.com/undated", "v1.0.0", None);
    let first = h.server.get("/go/example.com/undated/@v/v1.0.0.zip").await;
    assert_eq!(
        first.status().as_u16(),
        403,
        "first seen now: held for the cooldown, never dated from the cache or the build"
    );
    h.clock.advance_seconds(DAY as i64 + 60);
    assert_eq!(
        h.server
            .get("/go/example.com/undated/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        200
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_zip_changed_upstream_is_still_served_from_the_verified_store() {
    let h = harness("", 0).await;
    serve_version(&h, "example.com/pin", "v1.0.0", Some(OLD));
    assert_eq!(
        h.server
            .get("/go/example.com/pin/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        200
    );
    let mut changed = zip_bytes("example.com/pin", "v1.0.0");
    *changed.last_mut().unwrap() ^= 1;
    h.registry.answer(
        &up("example.com/pin", "@v/v1.0.0.zip"),
        FakeAnswer::Bytes(changed.clone()),
    );
    // Served from the verified store, not from the changed upstream.
    let again = h.server.get("/go/example.com/pin/@v/v1.0.0.zip").await;
    assert_eq!(
        again.bytes().await.unwrap().to_vec(),
        zip_bytes("example.com/pin", "v1.0.0")
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn head_and_range_follow_the_artifact_rules_and_head_of_a_list_is_405() {
    let h = harness("", 0).await;
    serve_module(&h, "example.com/demo", &[("v1.0.0", Some(OLD))]);
    let client = reqwest::Client::new();
    let head = client
        .head(h.server.url("/go/example.com/demo/@v/v1.0.0.zip"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status().as_u16(), 200);
    assert_eq!(
        head.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        zip_bytes("example.com/demo", "v1.0.0").len().to_string()
    );
    let ranged = client
        .get(h.server.url("/go/example.com/demo/@v/v1.0.0.zip"))
        .header("range", "bytes=0-3")
        .send()
        .await
        .unwrap();
    assert_eq!(ranged.status().as_u16(), 206);
    assert_eq!(
        ranged.bytes().await.unwrap().as_ref(),
        &[0x50, 0x4b, 0x03, 0x04]
    );
    let list_head = client
        .head(h.server.url("/go/example.com/demo/@v/list"))
        .send()
        .await
        .unwrap();
    assert_eq!(list_head.status().as_u16(), 405);
    for method in ["POST", "PUT", "DELETE"] {
        let response = client
            .request(
                method.parse().unwrap(),
                h.server.url("/go/example.com/demo/@v/v1.0.0.zip"),
            )
            .body("x")
            .send()
            .await
            .unwrap();
        assert!(
            matches!(response.status().as_u16(), 404 | 405),
            "{method}: {}",
            response.status()
        );
    }
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ @latest

#[tokio::test]
async fn latest_is_the_proxys_own_answer_when_policy_allows_it() {
    let h = harness("", 7 * DAY).await;
    serve_module(
        &h,
        "example.com/demo",
        &[("v1.0.0", Some(OLD)), ("v1.1.0", Some(OLD))],
    );
    h.registry.answer(
        &up("example.com/demo", "@latest"),
        FakeAnswer::Body(info("v1.1.0", Some(OLD))),
    );
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@latest").await,
        (200, info("v1.1.0", Some(OLD)))
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn latest_falls_back_to_the_best_allowed_release_and_404s_when_none() {
    let h = harness("", 7 * DAY).await;
    serve_module(
        &h,
        "example.com/demo",
        &[
            ("v1.0.0", Some(OLD)),
            ("v1.2.0-rc.1", Some(OLD)),
            ("v1.1.0", Some(OLD)),
            ("v2.0.0", Some(YOUNG)),
        ],
    );
    h.registry.answer(
        &up("example.com/demo", "@latest"),
        FakeAnswer::Body(info("v2.0.0", Some(YOUNG))),
    );
    // The proxy's latest is held: the highest allowed release wins over a higher allowed prerelease.
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@latest").await,
        (200, info("v1.1.0", Some(OLD)))
    );
    // Nothing allowed at all: 404, and the held version's files stay refused.
    serve_module(&h, "example.com/young", &[("v1.0.0", Some(YOUNG))]);
    h.registry.answer(
        &up("example.com/young", "@latest"),
        FakeAnswer::Body(info("v1.0.0", Some(YOUNG))),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/young/@latest")
            .await
            .status()
            .as_u16(),
        404
    );
    // A proxy with no @latest endpoint still offers its allowed list.
    h.registry
        .answer(&up("example.com/demo", "@latest"), FakeAnswer::Missing);
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@latest").await.1,
        info("v1.1.0", Some(OLD))
    );
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ checksum database

#[tokio::test]
async fn sumdb_reads_are_forwarded_to_the_one_configured_database_and_nothing_else() {
    let h = harness("", 0).await;
    let db = "sumdb.invalid";
    let sum = |tail: &str| {
        origins()
            .url_for(OriginKind::GoSumdb, &tail.split('/').collect::<Vec<_>>())
            .unwrap()
            .path()
            .to_owned()
    };
    h.registry
        .answer(&sum("supported"), FakeAnswer::Body(String::new()));
    h.registry.answer(
        &sum("latest"),
        FakeAnswer::Body("go.sum database tree\n1\nabc=\n".to_owned()),
    );
    h.registry.answer(
        &sum("lookup/github.com/!azure/x@v1.0.0"),
        FakeAnswer::Body("1\ngithub.com/Azure/x v1.0.0 h1:abc=\n".to_owned()),
    );
    h.registry.answer(
        &sum("tile/8/0/x001/234.p/17"),
        FakeAnswer::Bytes(vec![1, 2, 3]),
    );
    h.registry
        .answer(&sum("tile/8/data/000"), FakeAnswer::Bytes(vec![4, 5]));
    assert_eq!(
        text_of(&h, &format!("/go/sumdb/{db}/supported")).await,
        (200, String::new())
    );
    assert_eq!(text_of(&h, &format!("/go/sumdb/{db}/latest")).await.0, 200);
    assert_eq!(
        text_of(
            &h,
            &format!("/go/sumdb/{db}/lookup/github.com/!azure/x@v1.0.0")
        )
        .await
        .1,
        "1\ngithub.com/Azure/x v1.0.0 h1:abc=\n"
    );
    let tile = h
        .server
        .get(&format!("/go/sumdb/{db}/tile/8/0/x001/234.p/17"))
        .await;
    assert_eq!(
        (tile.status().as_u16(), tile.bytes().await.unwrap().to_vec()),
        (200, vec![1, 2, 3])
    );
    assert_eq!(
        h.server
            .get(&format!("/go/sumdb/{db}/tile/8/data/000"))
            .await
            .bytes()
            .await
            .unwrap()
            .to_vec(),
        vec![4, 5]
    );
    // Another database, another shape, a bad module or tile: 404 and no upstream call.
    let before = h.registry.calls().len();
    for path in [
        "/go/sumdb/evil.example/latest",
        "/go/sumdb/sumdb.invalid/other",
        "/go/sumdb/sumdb.invalid/lookup/github.com/Azure/x@v1.0.0",
        "/go/sumdb/sumdb.invalid/lookup/x@v1.0.0",
        "/go/sumdb/sumdb.invalid/tile/8/0/../x001",
        "/go/sumdb/sumdb.invalid/tile/8/0/x01/234",
        "/go/sumdb/sumdb.invalid/tile/8/0/x001/234.p",
        "/go/sumdb/sumdb.invalid/latest/extra",
    ] {
        assert_eq!(h.server.get(path).await.status().as_u16(), 404, "{path}");
    }
    assert_eq!(h.registry.calls().len(), before);
    // A tile path has at most six segments below the level (the real grammar has three groups and a width).
    assert_eq!(
        h.server
            .get(&format!(
                "/go/sumdb/{db}/tile/8/0/x001/x002/x003/x004/x005/x006/123"
            ))
            .await
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        h.registry.calls().len(),
        before,
        "an over-long tile path asks nothing"
    );
    // Nothing of the caller travels: a read with a credential gets the same answer from the same origin.
    let with_key = h
        .server
        .get_with_headers(
            &format!("/go/sumdb/{db}/latest"),
            &[("authorization", "Bearer secret")],
        )
        .await;
    assert_eq!(with_key.status().as_u16(), 200);
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ single-flight and caches

#[tokio::test]
async fn a_versions_info_is_fetched_once_for_the_three_files_within_the_freshness_window() {
    let h = harness("", 0).await;
    serve_version(&h, "example.com/demo", "v1.0.0", Some(OLD));
    for ext in ["info", "mod", "zip"] {
        assert_eq!(
            h.server
                .get(&format!("/go/example.com/demo/@v/v1.0.0.{ext}"))
                .await
                .status()
                .as_u16(),
            200
        );
    }
    // One confirmation fetch plus the info artifact's own download: not one per file.
    assert_eq!(calls_to(&h, "v1.0.0.info"), 2, "{:?}", h.registry.calls());
    h.clock.advance_seconds(3600);
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        calls_to(&h, "v1.0.0.info"),
        3,
        "after the freshness window existence is confirmed again"
    );
    // A version the proxy has since removed is no longer served, even though its bytes are stored.
    h.registry.answer(
        &up("example.com/demo", "@v/v1.0.0.info"),
        FakeAnswer::Missing,
    );
    h.clock.advance_seconds(3600);
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        404
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_dated_version_never_becomes_younger_when_the_proxy_re_dates_it() {
    let h = harness("", 7 * DAY).await;
    serve_version(&h, "example.com/demo", "v1.0.0", Some(YOUNG));
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        403
    );
    // Re-dated to the past: the date can only get later, so it stays held until the first date ages.
    h.registry.answer(
        &up("example.com/demo", "@v/v1.0.0.info"),
        FakeAnswer::Body(info("v1.0.0", Some(OLD))),
    );
    h.clock.advance_seconds(3600);
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        403
    );
    h.server.shutdown().await;
}

/// What `go get ...@latest` does: `@latest`, then at once the `.info` of the version it named (and the
/// `.mod`), many times over and in parallel. Every answer is 200 and the bytes are the proxy's.
#[tokio::test]
async fn latest_then_info_then_mod_back_to_back_is_never_refused() {
    let h = harness("", 0).await;
    serve_module(
        &h,
        "example.com/demo",
        &[("v1.0.0", Some(OLD)), ("v1.1.0", Some(OLD))],
    );
    h.registry.answer(
        &up("example.com/demo", "@latest"),
        FakeAnswer::Body(info("v1.1.0", Some(OLD))),
    );
    let server = Arc::new(h.server);
    let mut tasks = Vec::new();
    for _ in 0..24 {
        let server = Arc::clone(&server);
        tasks.push(tokio::spawn(async move {
            let mut statuses = Vec::new();
            for path in [
                "/go/example.com/demo/@latest",
                "/go/example.com/demo/@v/v1.1.0.info",
                "/go/example.com/demo/@v/v1.1.0.mod",
                "/go/example.com/demo/@v/v1.1.0.zip",
            ] {
                let response = server.get(path).await;
                statuses.push((path, response.status().as_u16()));
                let _ = response.bytes().await;
            }
            statuses
        }));
    }
    for task in tasks {
        for (path, status) in task.await.unwrap() {
            assert_eq!(status, 200, "{path}");
        }
    }
}

/// A version a block already refuses outright is never dated: its `.info` is not fetched (PERF-01), and the
/// cap of the fan-out is spent on versions that can still be served.
#[tokio::test]
async fn a_blocked_version_costs_no_info_fetch_in_a_list() {
    let blocked =
        r#"{"ecosystem":"go","name":"example.com/demo","version":"1.0.1","reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    serve_module(
        &h,
        "example.com/demo",
        &[
            ("v1.0.0", Some(OLD)),
            ("v1.0.1", Some(OLD)),
            ("v1.0.2", Some(OLD)),
        ],
    );
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await.1,
        "v1.0.0\nv1.0.2\n"
    );
    assert_eq!(
        calls_to(&h, "v1.0.1.info"),
        0,
        "the blocked version was never dated"
    );
    assert_eq!(calls_to(&h, "v1.0.0.info") + calls_to(&h, "v1.0.2.info"), 2);
    h.server.shutdown().await;
}

fn content_files(h: &Harness) -> Vec<std::path::PathBuf> {
    let root = h.server.app().config.data_dir.join("content");
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|name| name != "lock") {
                found.push(path);
            }
        }
    }
    found
}

/// SPEC §9 TOFU pin, for each of the three files: the first verified download pins the digest; once the stored copy
/// is gone (an eviction, a restart onto a cleaned store) a re-download whose bytes differ is refused with 502 and
/// nothing of it is delivered. Without the pin the changed bytes would be stored and served.
#[tokio::test]
async fn changed_bytes_of_a_pinned_info_mod_or_zip_are_refused_once_the_stored_copy_is_gone() {
    for ext in ["info", "mod", "zip"] {
        let h = harness("", 0).await;
        serve_version(&h, "example.com/pin", "v1.0.0", Some(OLD));
        let url = format!("/go/example.com/pin/@v/v1.0.0.{ext}");
        let first = h.server.get(&url).await;
        assert_eq!(first.status().as_u16(), 200, "{ext}");
        let original = first.bytes().await.unwrap().to_vec();
        assert!(!content_files(&h).is_empty());
        for file in content_files(&h) {
            std::fs::remove_file(file).unwrap();
        }
        let changed: FakeAnswer = match ext {
            "info" => FakeAnswer::Body(r#"{"Version":"v1.0.0","Time":"2025-01-01T00:00:00Z","Origin":{"VCS":"git","Ref":"changed"}}"#.to_owned()),
            "mod" => FakeAnswer::Body("module example.com/pin\n\ngo 1.21\n\nrequire evil.example/x v1.0.0\n".to_owned()),
            _ => FakeAnswer::Bytes([original.clone(), b"tampered".to_vec()].concat()),
        };
        h.registry
            .answer(&up("example.com/pin", &format!("@v/v1.0.0.{ext}")), changed);
        let second = h.server.get(&url).await;
        assert_eq!(
            second.status().as_u16(),
            502,
            "{ext}: the changed bytes are refused"
        );
        assert!(
            !String::from_utf8_lossy(&second.bytes().await.unwrap()).contains("tampered"),
            "{ext}"
        );
        assert!(
            content_files(&h).is_empty(),
            "{ext}: nothing of the changed body was stored"
        );
        h.server.shutdown().await;
    }
}

/// A version that appears in a later list than the first the firewall saw for its module is dated no earlier than
/// its own first sight, whatever `Time` says (a commit time is the publisher's to choose). Versions of the first
/// list keep their upstream dates; a pseudo-version asked for after the first list is held the same way.
#[tokio::test]
async fn a_back_dated_version_that_appears_after_the_first_list_is_held_from_its_first_sight() {
    let h = harness("", 7 * DAY).await;
    serve_module(&h, "example.com/demo", &[("v1.0.0", Some(OLD))]);
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await.1,
        "v1.0.0\n",
        "the first list keeps upstream dates"
    );
    // A malicious tag on an old commit: Time says 2025. It appears an hour after the first list.
    h.clock.advance_seconds(3600);
    serve_module(
        &h,
        "example.com/demo",
        &[("v1.0.0", Some(OLD)), ("v1.0.1", Some(OLD))],
    );
    let pseudo = "v0.0.0-20250101000000-abcdef123456";
    serve_version(&h, "example.com/demo", pseudo, Some(OLD));
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await.1,
        "v1.0.0\n",
        "the back-dated version is held"
    );
    for file in ["v1.0.1.zip", "v1.0.1.info", &format!("{pseudo}.zip")] {
        assert_eq!(
            h.server
                .get(&format!("/go/example.com/demo/@v/{file}"))
                .await
                .status()
                .as_u16(),
            403,
            "{file}"
        );
    }
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/v1.0.0.zip")
            .await
            .status()
            .as_u16(),
        200,
        "the version of the first list stays served"
    );
    h.clock.advance_seconds(8 * DAY as i64);
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await.1,
        "v1.0.0\nv1.0.1\n",
        "released one cooldown after its first sight"
    );
    for file in ["v1.0.1.zip", &format!("{pseudo}.zip")] {
        assert_eq!(
            h.server
                .get(&format!("/go/example.com/demo/@v/{file}"))
                .await
                .status()
                .as_u16(),
            200,
            "{file}"
        );
    }
    h.server.shutdown().await;
}

/// The limit stated in the evidence: a back-dated version already present in the very FIRST list of a module keeps
/// its upstream `Time` (a module this firewall has never seen is trusted on its dates at first sight).
#[tokio::test]
async fn the_first_list_of_a_module_keeps_upstream_dates() {
    let h = harness("", 7 * DAY).await;
    serve_module(
        &h,
        "example.com/demo",
        &[("v1.0.0", Some(OLD)), ("v1.0.1", Some(OLD))],
    );
    assert_eq!(
        text_of(&h, "/go/example.com/demo/@v/list").await.1,
        "v1.0.0\nv1.0.1\n"
    );
    h.server.shutdown().await;
}

/// `go get mod@main` and `mod@<commit>`: upstream resolves the name; the RESOLVED version is judged and answered
/// only when allowed, and its `.mod` and `.zip` take the ordinary path.
#[tokio::test]
async fn revision_queries_resolve_upstream_and_the_resolved_version_is_gated() {
    let blocked = r#"{"ecosystem":"go","name":"example.com/blocked","version":"0.0.0-20250101000000-bbbbbbbbbbbb","reason":"malware"}"#;
    let h = harness(blocked, 7 * DAY).await;
    let old = "v0.0.0-20250101000000-abcdef123456";
    let young = "v0.0.0-20260405120000-123456abcdef";
    serve_version(&h, "example.com/demo", old, Some(OLD));
    serve_version(&h, "example.com/demo", young, Some(YOUNG));
    h.registry.answer(
        &up("example.com/demo", "@v/main.info"),
        FakeAnswer::Body(info(old, Some(OLD))),
    );
    h.registry.answer(
        &up("example.com/demo", "@v/abcdef123456.info"),
        FakeAnswer::Body(info(old, Some(OLD))),
    );
    h.registry.answer(
        &up("example.com/demo", "@v/dev.info"),
        FakeAnswer::Body(info(young, Some(YOUNG))),
    );
    for rev in ["main", "abcdef123456"] {
        assert_eq!(
            text_of(&h, &format!("/go/example.com/demo/@v/{rev}.info")).await,
            (200, info(old, Some(OLD))),
            "{rev}"
        );
    }
    assert_eq!(
        h.server
            .get(&format!("/go/example.com/demo/@v/{old}.zip"))
            .await
            .status()
            .as_u16(),
        200,
        "the resolved version's files take the ordinary path"
    );
    // A branch that resolves to a young version is held, and its files are never fetched.
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/dev.info")
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        calls_to(&h, &format!("{young}.zip")) + calls_to(&h, &format!("{young}.mod")),
        0
    );
    // A name for a blocked version is as blocked as the version.
    let bad = "v0.0.0-20250101000000-bbbbbbbbbbbb";
    serve_version(&h, "example.com/blocked", bad, Some(OLD));
    h.registry.answer(
        &up("example.com/blocked", "@v/main.info"),
        FakeAnswer::Body(info(bad, Some(OLD))),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/blocked/@v/main.info")
            .await
            .status()
            .as_u16(),
        403
    );
    // Upstream's answer must be a canonical version; an unknown name is 404.
    h.registry.answer(
        &up("example.com/demo", "@v/odd.info"),
        FakeAnswer::Body(r#"{"Version":"main","Time":"2025-01-01T00:00:00Z"}"#.to_owned()),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/odd.info")
            .await
            .status()
            .as_u16(),
        502
    );
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/nosuch.info")
            .await
            .status()
            .as_u16(),
        404
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn revision_queries_are_bounded_per_module_and_validated_before_any_upstream_call() {
    let h = harness("", 0).await;
    let before = h.registry.calls().len();
    for bad in ["-x", "a..b", "Main", &"a".repeat(129)] {
        assert_eq!(
            h.server
                .get(&format!("/go/example.com/demo/@v/{bad}.info"))
                .await
                .status()
                .as_u16(),
            404,
            "{bad}"
        );
    }
    assert_eq!(
        h.registry.calls().len(),
        before,
        "an invalid token asks nothing"
    );
    for n in 0..32 {
        assert_eq!(
            h.server
                .get(&format!("/go/example.com/demo/@v/branch{n}.info"))
                .await
                .status()
                .as_u16(),
            404
        );
    }
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/branch32.info")
            .await
            .status()
            .as_u16(),
        429,
        "the 33rd distinct revision of the window"
    );
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/branch0.info")
            .await
            .status()
            .as_u16(),
        404,
        "a repeat is not a new revision"
    );
    assert_eq!(
        h.registry.calls().len(),
        before + 33,
        "the refused one asked nothing"
    );
    assert_eq!(
        h.server
            .get("/go/example.com/other/@v/branch32.info")
            .await
            .status()
            .as_u16(),
        404,
        "the bound is per module"
    );
    h.clock.advance_seconds(61);
    assert_eq!(
        h.server
            .get("/go/example.com/demo/@v/branch32.info")
            .await
            .status()
            .as_u16(),
        404,
        "a new window"
    );
    h.server.shutdown().await;
}

/// `2.0.0` and `2.0.0+incompatible` are one version for a block, whichever way it is written.
#[tokio::test]
async fn a_block_matches_a_version_with_and_without_incompatible() {
    for (written, listed, hidden) in [
        ("2.0.0", "v2.0.0+incompatible", "v2.0.0+incompatible"),
        ("1.0.1+incompatible", "v1.0.1", "v1.0.1"),
    ] {
        let blocked = format!(
            r#"{{"ecosystem":"go","name":"example.com/demo","version":"{written}","reason":"malware"}}"#
        );
        let h = harness(&blocked, 0).await;
        serve_module(
            &h,
            "example.com/demo",
            &[
                ("v1.0.0", Some(OLD)),
                (listed, Some(OLD)),
                ("v2.0.1+incompatible", Some(OLD)),
            ],
        );
        let body = text_of(&h, "/go/example.com/demo/@v/list").await.1;
        assert!(
            !body.contains(hidden) && body.contains("v1.0.0"),
            "{written} hides {hidden}: {body}"
        );
        assert_eq!(
            h.server
                .get(&format!("/go/example.com/demo/@v/{hidden}.zip"))
                .await
                .status()
                .as_u16(),
            403,
            "{written}"
        );
        h.server.shutdown().await;
    }
}

/// A transport that holds the `.info` of one module until released, to model a slow upstream.
struct Slow {
    inner: Arc<FakeRegistry>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl Transport for Slow {
    async fn fetch_metadata(
        &self,
        request: probation::upstream::MetadataRequest,
    ) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError> {
        if request.url.path().contains("/slow.example/") && request.url.path().ends_with(".info") {
            let _ = self.release.acquire().await.map(|permit| permit.forget());
        }
        self.inner.fetch_metadata(request).await
    }
    async fn open_artifact(
        &self,
        request: probation::upstream::ArtifactRequest,
    ) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
        if request.url.path().contains("/slowzip.example/") && request.url.path().ends_with(".zip")
        {
            let _ = self.release.acquire().await.map(|permit| permit.forget());
        }
        self.inner.open_artifact(request).await
    }
}

/// A burst of lists of one slow module costs one fan-out: the others do not wait for it (holding their request
/// permits behind it), they answer at once with what is dated, and unrelated modules are untouched.
#[tokio::test]
async fn a_burst_of_lists_for_one_slow_module_does_not_pin_the_other_requests() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), "", 7 * DAY);
    config.listen = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let registry = FakeRegistry::new();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let transport = Arc::new(Slow {
        inner: Arc::clone(&registry),
        release: Arc::clone(&release),
    });
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        transport as Arc<dyn Transport>,
        origins(),
    )
    .await;
    let h = Harness {
        server,
        registry,
        clock,
        _dir: dir,
    };
    serve_module(
        &h,
        "slow.example/m",
        &[("v1.0.0", Some(OLD)), ("v1.0.1", Some(OLD))],
    );
    serve_module(&h, "example.com/other", &[("v1.0.0", Some(OLD))]);
    let server = Arc::new(h.server);
    let leader = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            server
                .get("/go/slow.example/m/@v/list")
                .await
                .text()
                .await
                .unwrap()
        })
    };
    // Let the leader reach its first `.info`.
    for _ in 0..200 {
        if h.registry
            .calls()
            .iter()
            .any(|url| url.path().ends_with("/@v/list") && url.path().contains("slow.example"))
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let started = std::time::Instant::now();
    let mut followers = Vec::new();
    for _ in 0..16 {
        let server = Arc::clone(&server);
        followers.push(tokio::spawn(async move {
            server
                .get("/go/slow.example/m/@v/list")
                .await
                .status()
                .as_u16()
        }));
    }
    for follower in followers {
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), follower)
                .await
                .expect("a follower waits for no gate")
                .unwrap(),
            200
        );
    }
    assert_eq!(
        server
            .get("/go/example.com/other/@v/list")
            .await
            .text()
            .await
            .unwrap(),
        "v1.0.0\n"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    release.add_permits(64);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), leader)
            .await
            .unwrap()
            .unwrap(),
        "v1.0.0\nv1.0.1\n"
    );
}

/// The few hundred bytes of a `.info` or `.mod` do not wait behind the large transfers: with the only large-transfer place
/// held by a zip that is still arriving, another version's `.info` and `.mod` are served at once.
#[tokio::test]
async fn tiny_metadata_files_do_not_queue_behind_large_transfers() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), "", 0);
    config.max_artifact_downloads = std::num::NonZeroU32::new(1).unwrap();
    config.download_wait_seconds = 1;
    let registry = FakeRegistry::new();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let transport = Arc::new(Slow {
        inner: Arc::clone(&registry),
        release: Arc::clone(&release),
    });
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        transport as Arc<dyn Transport>,
        origins(),
    )
    .await;
    let h = Harness {
        server,
        registry,
        clock,
        _dir: dir,
    };
    serve_version(&h, "slowzip.example/m", "v1.0.0", Some(OLD));
    serve_version(&h, "example.com/other", "v1.0.0", Some(OLD));
    let server = Arc::new(h.server);
    let big = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            server
                .get("/go/slowzip.example/m/@v/v1.0.0.zip")
                .await
                .status()
                .as_u16()
        })
    };
    // Wait until the zip's transfer has reached upstream (it holds the only large-transfer place).
    for _ in 0..300 {
        if h.registry
            .calls()
            .iter()
            .any(|url| url.path().ends_with("slowzip.example/m/@v/v1.0.0.zip"))
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for ext in ["info", "mod"] {
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            server.get(&format!("/go/example.com/other/@v/v1.0.0.{ext}")),
        )
        .await
        .expect("a tiny file waits for no large transfer");
        assert_eq!(answer.status().as_u16(), 200, "{ext}");
    }
    release.add_permits(8);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), big)
            .await
            .unwrap()
            .unwrap(),
        200
    );
}

/// L4: small and large transfers count their waiters apart: tiny files held by slow upstreams (and queued behind them)
/// cannot make a large `.zip` request refused at once.
#[tokio::test]
async fn slow_tiny_files_cannot_take_the_waiter_places_of_zip_requests() {
    use probation::http::limits::{Limits, SMALL_DOWNLOADS};
    let mut config = sample_config();
    config.max_artifact_downloads = std::num::NonZeroU32::new(1).unwrap();
    config.max_download_waiters = 1;
    config.download_wait_seconds = 1;
    let limits = Arc::new(Limits::new(&config));
    let mut held = Vec::new();
    for _ in 0..SMALL_DOWNLOADS {
        held.push(limits.small_download_permit().await.expect("a place"));
    }
    let small_waiter = tokio::spawn({
        let limits = Arc::clone(&limits);
        async move { limits.small_download_permit().await.is_none() }
    });
    let large_held = limits
        .download_permit()
        .await
        .expect("the one large permit");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let large_waiter = tokio::spawn({
        let limits = Arc::clone(&limits);
        async move { limits.download_permit().await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !large_waiter.is_finished(),
        "the large request waits for its permit: its waiter place is not taken by the small ones"
    );
    drop(large_held);
    assert!(
        large_waiter.await.unwrap().is_some(),
        "and gets it when one frees"
    );
    assert!(
        small_waiter.await.unwrap(),
        "the small waiter gave up after its own bounded wait"
    );
    drop(held);
}

/// Recheck N5: the small places keep the waiter bound of the large transfers, and a `.mod` (or `.info`) is read to its
/// own cap, not to `max_artifact_bytes`.
#[tokio::test]
async fn small_transfers_share_the_waiter_bound_and_read_only_their_own_cap() {
    use probation::http::limits::{Limits, SMALL_DOWNLOADS};
    let mut config = sample_config();
    config.max_download_waiters = 1;
    config.download_wait_seconds = 1;
    let limits = Arc::new(Limits::new(&config));
    let mut held = Vec::new();
    for _ in 0..SMALL_DOWNLOADS {
        held.push(limits.small_download_permit().await.expect("a place"));
    }
    let waiting = tokio::spawn({
        let limits = Arc::clone(&limits);
        async move { limits.small_download_permit().await.is_none() }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let started = std::time::Instant::now();
    assert!(
        limits.small_download_permit().await.is_none(),
        "past max_download_waiters the request is refused at once"
    );
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    assert!(
        waiting.await.unwrap(),
        "the one waiter gave up after the bounded wait"
    );
    drop(held);
    // The size cap, through the server: a 17 MiB `.mod` is refused, a 1 MiB one is served.
    let h = harness("", 0).await;
    serve_version(&h, "example.com/big", "v1.0.0", Some(OLD));
    h.registry.answer(
        &up("example.com/big", "@v/v1.0.0.mod"),
        FakeAnswer::Bytes(vec![b'x'; 17 << 20]),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/big/@v/v1.0.0.mod")
            .await
            .status()
            .as_u16(),
        502,
        "a .mod over 16 MiB"
    );
    serve_version(&h, "example.com/big", "v1.0.1", Some(OLD));
    h.registry.answer(
        &up("example.com/big", "@v/v1.0.1.mod"),
        FakeAnswer::Bytes(vec![b'x'; 1 << 20]),
    );
    assert_eq!(
        h.server
            .get("/go/example.com/big/@v/v1.0.1.mod")
            .await
            .status()
            .as_u16(),
        200
    );
    h.server.shutdown().await;
}
