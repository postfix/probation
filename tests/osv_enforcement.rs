//! OSV enforcement at the shipped configuration: a `MAL-*` match denies within the
//! request that asked, at the sample config's own `osv_request_timeout_ms`, with no
//! test-only widening.

mod common;

use std::sync::Arc;

use common::{
    FakeAnswer, FakeRegistry, TestServer, config_with_open_blocklist, fake_origins,
    npm_tarball_url, npm_upstream_path, osv_flagging,
};
use probation::clock::SystemClock;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use serde_json::{Value, json};
use tempfile::TempDir;

const PACKAGE: &str = "osv-widget";
const ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json";

/// An npm document advertising `versions`, every one published in 2020 and so past
/// any cooldown, with `latest` on the highest.
fn npm_document(versions: &[String]) -> String {
    let records: serde_json::Map<String, Value> = versions
        .iter()
        .map(|version| {
            let tarball = npm_tarball_url(PACKAGE, &format!("{PACKAGE}-{version}.tgz"));
            let record = json!({"name": PACKAGE, "version": version, "dist": {"tarball": tarball}});
            (version.clone(), record)
        })
        .collect();
    let time: serde_json::Map<String, Value> = versions
        .iter()
        .map(|version| (version.clone(), json!("2020-01-01T00:00:00Z")))
        .collect();
    json!({
        "name": PACKAGE,
        "dist-tags": {"latest": versions.last()},
        "versions": records,
        "time": time,
    })
    .to_string()
}

/// The shipped sample config (open blocklist), an in-process registry serving
/// `document` for [`PACKAGE`], and OSV at `osv_url`.
async fn server(document: String, osv_url: url::Url) -> (TestServer, TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(PACKAGE), FakeAnswer::Body(document));
    let server = TestServer::start_with_upstream_and_osv(
        config_with_open_blocklist(dir.path()),
        Arc::new(SystemClock),
        registry,
        fake_origins(),
        reqwest::Client::new(),
        osv_url,
    )
    .await;
    (server, dir)
}

/// Every version string a rendered document names: `versions` keys, `time` keys and
/// `dist-tags` targets.
fn named_versions(document: &Value) -> Vec<String> {
    let keys = |field: &str| {
        document[field]
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let mut named = keys("versions");
    named.extend(keys("time"));
    if let Some(tags) = document["dist-tags"].as_object() {
        named.extend(tags.values().filter_map(Value::as_str).map(str::to_owned));
    }
    named
}

proptest! {
    // `SourceParallel` finds no `src/lib.rs` beside `tests/`, so the regressions
    // file is named outright.
    #![proptest_config(ProptestConfig {
        cases: 16,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "proptest-regressions/osv_enforcement.txt",
        ))),
        ..ProptestConfig::default()
    })]

    /// For any set of eligible versions with any subset MAL-flagged by OSV, no flagged
    /// version appears in any field of the full or abbreviated document, and every
    /// unflagged one does. With every version flagged the project is a `403 BLOCKED`.
    #[test]
    fn no_osv_flagged_version_is_ever_rendered(
        flags in proptest::collection::btree_map(0u32..40, any::<bool>(), 1..12)
    ) {
        let versions: Vec<String> = flags.keys().map(|patch| format!("1.0.{patch}")).collect();
        let flagged: Vec<String> = flags
            .iter()
            .filter(|(_, flagged)| **flagged)
            .map(|(patch, _)| format!("1.0.{patch}"))
            .collect();
        let clear: Vec<&String> = versions.iter().filter(|v| !flagged.contains(v)).collect();

        common::run(async {
            let pairs: Vec<(&str, &str)> = flagged.iter().map(|v| (PACKAGE, v.as_str())).collect();
            let (osv_url, _osv) = osv_flagging(&pairs).await;
            let (server, _dir) = server(npm_document(&versions), osv_url).await;

            for accept in ["application/json", ABBREVIATED_ACCEPT] {
                let response = server
                    .get_with_headers(&format!("/npm/{PACKAGE}"), &[("accept", accept)])
                    .await;
                let status = response.status().as_u16();
                let body: Value =
                    serde_json::from_str(&response.text().await.expect("a body")).expect("JSON");
                if clear.is_empty() {
                    assert_eq!((status, body["error"].as_str()), (403, Some("BLOCKED")), "{body}");
                    continue;
                }
                assert_eq!(status, 200, "{body}");
                let named = named_versions(&body);
                for version in &flagged {
                    assert!(!named.contains(version), "flagged {version} rendered ({accept}): {body}");
                }
                for version in &clear {
                    assert!(
                        body["versions"].get(version.as_str()).is_some(),
                        "unflagged {version} missing ({accept}): {body}"
                    );
                }
            }
            server.shutdown().await;
        });
    }
}

/// A MAL match on the exact-version route is a `403 BLOCKED` naming OSV, answered
/// within the request that asked, at the shipped `osv_request_timeout_ms`.
#[tokio::test]
async fn an_exact_version_osv_flags_is_403_blocked_with_the_osv_reason() {
    let versions = ["1.0.0".to_owned(), "1.0.1".to_owned()];
    let (osv_url, _osv) = osv_flagging(&[(PACKAGE, "1.0.1")]).await;
    let (server, _dir) = server(npm_document(&versions), osv_url).await;

    let response = server.get(&format!("/npm/{PACKAGE}/1.0.1")).await;
    let status = response.status().as_u16();
    let body: Value = serde_json::from_str(&response.text().await.expect("a body")).expect("JSON");

    assert_eq!(
        (status, body["error"].as_str()),
        (403, Some("BLOCKED")),
        "{body}"
    );
    assert_eq!(
        body["reason"], "the version is blocked by a known OSV malicious-package advisory",
        "{body}"
    );
    assert_eq!(server.status(&format!("/npm/{PACKAGE}/1.0.0")).await, 200);

    server.shutdown().await;
}
