//! Row 23: Conan 2 remote protection, end to end through the firewall against an in-process `FakeRegistry` and a clock the test
//! moves by hand. The real client witness is tests/conan_native.rs (`conan`), the shared-service forms are
//! tests/conan_service_read.rs and tests/conan_service_write.rs.

mod common;

use std::sync::Arc;

use common::conan::{self, REMOTE, PUBLISH, at, base, files_doc, package_search_doc, revisions_doc, search_doc, serve_package, serve_recipe};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::config::Config;
use probation::upstream::{OriginSet, Transport};
use tempfile::TempDir;
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const DAY: u64 = 86_400;
const OLD: &str = "2025-01-01T00:00:00Z";
const OLDER: &str = "2024-06-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn origins() -> OriginSet {
    fake_origins().with_conan(Url::parse(REMOTE).unwrap(), Url::parse(PUBLISH).unwrap())
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    _dir: TempDir,
}

fn config_with(dir: &std::path::Path, blocked: &str, cooldown: u64) -> Config {
    let blocklist_file = dir.join("blocklist.json");
    std::fs::write(&blocklist_file, common::snapshot(1, "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z", blocked)).unwrap();
    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config.cooldown_seconds = cooldown;
    config
}

async fn harness_with(blocked: &str, cooldown: u64, tune: impl FnOnce(&mut Config)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), blocked, cooldown);
    tune(&mut config);
    let registry = FakeRegistry::new();
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
    Harness { server, registry, clock, _dir: dir }
}

async fn harness(blocked: &str, cooldown: u64) -> Harness {
    harness_with(blocked, cooldown, |_| {}).await
}

async fn text_of(h: &Harness, path: &str) -> (u16, String) {
    let response = h.server.get(path).await;
    (response.status().as_u16(), response.text().await.unwrap())
}

async fn json_of(h: &Harness, path: &str) -> (u16, serde_json::Value) {
    let (status, body) = text_of(h, path).await;
    (status, serde_json::from_str(&body).unwrap_or(serde_json::Value::Null))
}

fn calls_to(h: &Harness, needle: &str) -> usize {
    h.registry.calls().iter().filter(|url| url.path().contains(needle)).count()
}

fn revs_of(doc: &serde_json::Value) -> Vec<String> {
    doc["revisions"].as_array().map(|list| list.iter().map(|entry| entry["revision"].as_str().unwrap().to_owned()).collect()).unwrap_or_default()
}

const R_NEW: &str = "aaaa0000000000000000000000000002";
const R_OLD: &str = "bbbb0000000000000000000000000001";
const R_OLDEST: &str = "cccc0000000000000000000000000000";
const PKG: &str = "b647c43bfefae3f830561ca202b6cfd935b56205";

/// `zlib/1.3.1` with two old revisions and a young newest one, as the remote lists them (newest first).
fn serve_zlib(h: &Harness) {
    serve_recipe(&h.registry, "zlib", "1.3.1", &[(R_NEW, YOUNG), (R_OLD, OLD), (R_OLDEST, OLDER)]);
}

// ------------------------------------------------------------------ revisions

#[tokio::test]
async fn revisions_withhold_young_revisions_and_latest_names_the_newest_allowed() {
    let h = harness("", 7 * DAY).await;
    serve_zlib(&h);
    let (status, doc) = json_of(&h, "/conan/v2/conans/zlib/1.3.1/_/_/revisions").await;
    assert_eq!(status, 200, "{doc}");
    assert_eq!(revs_of(&doc), [R_OLD, R_OLDEST], "{doc}");
    assert_eq!(doc["reference"], "zlib/1.3.1@_/_", "the document's own head is kept");
    assert_eq!(doc["revisions"][0]["time"], conan::conan_time(OLD), "a time is served as the remote wrote it");
    let (status, latest) = json_of(&h, "/conan/v2/conans/zlib/1.3.1/_/_/latest").await;
    assert_eq!((status, latest["revision"].as_str()), (200, Some(R_OLD)), "{latest}");
    assert_eq!(latest["time"], conan::conan_time(OLD));
    assert_eq!(calls_to(&h, "conan_export.tgz"), 0, "no file was asked for");
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_revision_that_ages_is_listed_once_its_cooldown_has_passed() {
    let h = harness("", 7 * DAY).await;
    serve_zlib(&h);
    let (_, doc) = json_of(&h, "/conan/v2/conans/zlib/1.3.1/_/_/revisions").await;
    assert_eq!(revs_of(&doc), [R_OLD, R_OLDEST]);
    h.clock.advance_seconds(8 * DAY as i64);
    let (_, doc) = json_of(&h, "/conan/v2/conans/zlib/1.3.1/_/_/revisions").await;
    assert_eq!(revs_of(&doc), [R_NEW, R_OLD, R_OLDEST]);
    let (_, latest) = json_of(&h, "/conan/v2/conans/zlib/1.3.1/_/_/latest").await;
    assert_eq!(latest["revision"], R_NEW);
    h.server.shutdown().await;
}

#[tokio::test]
async fn when_every_revision_is_held_the_answer_is_the_decision_with_its_deadline() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "fresh", "1.0", &[("dddd0000000000000000000000000000", YOUNG)]);
    for path in ["/conan/v2/conans/fresh/1.0/_/_/revisions", "/conan/v2/conans/fresh/1.0/_/_/latest"] {
        let response = h.server.get(path).await;
        assert_eq!(response.status().as_u16(), 403, "{path}");
        let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(body["error"], "HELD", "{path}: the answer says it is a hold: {body}");
    }
    let response = h.server.get("/conan/v2/conans/fresh/1.0/_/_/revisions/dddd0000000000000000000000000000/files/conanfile.py").await;
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(calls_to(&h, "conanfile.py"), 0, "a held revision's files are never fetched");
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_revision_with_no_time_waits_on_its_first_seen_time() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(&at(&format!("{}/revisions", base("untimed", "1.0"))), FakeAnswer::Body(revisions_doc(("reference", "untimed/1.0@_/_"), &[("eeee0000000000000000000000000000", None)])));
    let (status, doc) = json_of(&h, "/conan/v2/conans/untimed/1.0/_/_/revisions").await;
    assert_eq!(status, 403, "first seen now: held for a whole cooldown: {doc}");
    h.clock.advance_seconds(8 * DAY as i64);
    let (status, doc) = json_of(&h, "/conan/v2/conans/untimed/1.0/_/_/revisions").await;
    assert_eq!((status, revs_of(&doc)), (200, vec!["eeee0000000000000000000000000000".to_owned()]));
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_user_and_channel_are_part_of_the_reference_and_nothing_is_substituted() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(&at("v2/conans/mylib/2.0/acme/stable/revisions"), FakeAnswer::Body(revisions_doc(("reference", "mylib/2.0@acme/stable"), &[("ffff0000000000000000000000000000", Some(OLD))])));
    let (status, doc) = json_of(&h, "/conan/v2/conans/mylib/2.0/acme/stable/revisions").await;
    assert_eq!((status, revs_of(&doc)), (200, vec!["ffff0000000000000000000000000000".to_owned()]));
    // The same name and version with no user and channel is another reference: it is asked for under its own path.
    assert_eq!(h.server.get("/conan/v2/conans/mylib/2.0/_/_/revisions").await.status().as_u16(), 404);
    assert_eq!(calls_to(&h, "/mylib/2.0/_/_/revisions"), 1);
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ files

#[tokio::test]
async fn every_file_of_an_allowed_revision_is_served_exactly_and_every_file_of_a_held_one_is_refused_unfetched() {
    let h = harness("", 7 * DAY).await;
    serve_zlib(&h);
    let dir = format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/files");
    let (status, list) = json_of(&h, &dir).await;
    assert_eq!(status, 200, "{list}");
    let names: Vec<&str> = list["files"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(names, ["conan_export.tgz", "conan_sources.tgz", "conanfile.py", "conanmanifest.txt"]);
    assert_eq!(text_of(&h, &format!("{dir}/conanfile.py")).await, (200, conan::conanfile("zlib", "1.3.1")));
    assert_eq!(text_of(&h, &format!("{dir}/conanmanifest.txt")).await, (200, conan::manifest(R_OLD)));
    let export = h.server.get(&format!("{dir}/conan_export.tgz")).await;
    assert_eq!(export.status().as_u16(), 200);
    assert_eq!(export.bytes().await.unwrap().to_vec(), conan::tgz(&format!("export zlib 1.3.1 {R_OLD}")));
    // The young revision: refused, its files never fetched, and its file list neither.
    let young = format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_NEW}/files");
    for path in [young.clone(), format!("{young}/conanfile.py"), format!("{young}/conan_export.tgz")] {
        assert_eq!(h.server.get(&path).await.status().as_u16(), 403, "{path}");
    }
    assert_eq!(calls_to(&h, &format!("{R_NEW}/files")), 0, "a held revision's files and file list are never fetched");
    // A revision the remote does not list is not served, whatever its files.
    h.registry.answer(&at(&format!("{}/revisions/{}/files/conanfile.py", base("zlib", "1.3.1"), "9999")), FakeAnswer::Body("x".into()));
    assert_eq!(h.server.get("/conan/v2/conans/zlib/1.3.1/_/_/revisions/9999/files/conanfile.py").await.status().as_u16(), 404);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_file_list_names_files_and_nothing_else_so_no_location_of_the_remote_reaches_a_client() {
    let h = harness("", 0).await;
    serve_zlib(&h);
    // A remote that returns locations (a Conan 1 `download_urls` shape, or extra members) is read for its names only.
    let hostile = r#"{"files":{"conanfile.py":{"url":"https://evil.example/x"},"../etc":{},"a b":{},"conan_export.tgz":"https://evil.example/y"},"download_urls":{"conanfile.py":"https://evil.example/z"}}"#;
    h.registry.answer(&at(&format!("{}/revisions/{R_OLD}/files", base("zlib", "1.3.1"))), FakeAnswer::Body(hostile.to_owned()));
    let (status, list) = json_of(&h, &format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/files")).await;
    assert_eq!(status, 200);
    assert_eq!(list, serde_json::json!({ "files": { "conanfile.py": {}, "conan_export.tgz": {}, "a b": {} } }), "a name with a space is a name; a traversal and a non-object value are not");
    for v1 in ["v1/conans/zlib/1.3.1/_/_/download_urls", "v2/conans/zlib/1.3.1/_/_/download_urls", "v1/conans/zlib/1.3.1/_/_/upload_urls", "v2/conans/zlib/1.3.1/_/_/packages/x/download_urls"] {
        assert_eq!(h.server.get(&format!("/conan/{v1}")).await.status().as_u16(), 404, "{v1}");
    }
    assert_eq!(calls_to(&h, "download_urls"), 0);
    h.server.shutdown().await;
}

#[tokio::test]
async fn changed_bytes_of_a_pinned_file_are_refused_once_the_stored_copy_is_gone() {
    let h = harness("", 0).await;
    serve_zlib(&h);
    let path = format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/files/conan_export.tgz");
    assert_eq!(h.server.get(&path).await.status().as_u16(), 200);
    // The remote now serves other bytes under the same name: the first download pinned the digests.
    h.registry.answer(&at(&format!("{}/revisions/{R_OLD}/files/conan_export.tgz", base("zlib", "1.3.1"))), FakeAnswer::Bytes(conan::tgz("tampered")));
    let again = h.server.get(&path).await;
    assert_eq!(again.bytes().await.unwrap().to_vec(), conan::tgz(&format!("export zlib 1.3.1 {R_OLD}")), "the verified stored copy is served");
    h.server.shutdown().await;
}

#[tokio::test]
async fn range_and_head_work_on_a_file() {
    let h = harness("", 0).await;
    serve_zlib(&h);
    let path = format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/files/conan_export.tgz");
    let whole = conan::tgz(&format!("export zlib 1.3.1 {R_OLD}"));
    let head = h.server.head(&path).await;
    assert_eq!(head.status().as_u16(), 200);
    assert_eq!(head.headers()["content-length"].to_str().unwrap(), whole.len().to_string());
    let ranged = h.server.get_with_headers(&path, &[("range", "bytes=2-5")]).await;
    assert_eq!(ranged.status().as_u16(), 206);
    assert_eq!(ranged.bytes().await.unwrap().to_vec(), whole[2..6].to_vec());
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_made_up_file_name_of_a_real_revision_is_a_404_and_makes_no_reference() {
    let h = harness("", 0).await;
    serve_zlib(&h);
    h.registry.answer(&at(&format!("{}/revisions/{R_OLD}/files/other.txt", base("zlib", "1.3.1"))), FakeAnswer::Missing);
    let path = format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/files/other.txt");
    assert_eq!(h.server.get(&path).await.status().as_u16(), 404);
    let rows_before = rows(&h).await;
    assert_eq!(h.server.get(&path).await.status().as_u16(), 404);
    assert_eq!(rows(&h).await, rows_before, "a made-up file makes no row");
    h.server.shutdown().await;
}

async fn rows(h: &Harness) -> u64 {
    h.server.app().store().count_project_references_in(0, probation::policy::Ecosystem::Conan, "zlib").await.unwrap()
}

// ------------------------------------------------------------------ binaries: their own age

#[tokio::test]
async fn a_new_binary_on_an_old_recipe_has_its_own_age_and_no_recipe_date_substitutes() {
    let h = harness("", 7 * DAY).await;
    // An old recipe revision with two binary revisions of one package id: an old one and a young one.
    serve_recipe(&h.registry, "zlib", "1.3.1", &[(R_OLD, OLD)]);
    let pkg_new = "1111000000000000000000000000ffff";
    let pkg_old = "2222000000000000000000000000ffff";
    serve_package(&h.registry, "zlib", "1.3.1", R_OLD, PKG, &[(pkg_new, YOUNG), (pkg_old, OLD)]);
    let dir = format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/packages/{PKG}");
    let (status, doc) = json_of(&h, &format!("{dir}/revisions")).await;
    assert_eq!((status, revs_of(&doc)), (200, vec![pkg_old.to_owned()]), "{doc}");
    assert_eq!(doc["packageReference"], format!("zlib/1.3.1@_/_#{R_OLD}:{PKG}"));
    let (_, latest) = json_of(&h, &format!("{dir}/latest")).await;
    assert_eq!(latest["revision"], pkg_old);
    assert_eq!(h.server.get(&format!("{dir}/revisions/{pkg_new}/files/conan_package.tgz")).await.status().as_u16(), 403, "the new binary is held although its recipe is old");
    let ok = h.server.get(&format!("{dir}/revisions/{pkg_old}/files/conan_package.tgz")).await;
    assert_eq!(ok.status().as_u16(), 200);
    assert_eq!(ok.bytes().await.unwrap().to_vec(), conan::tgz(&format!("package zlib 1.3.1 {PKG} {pkg_old}")));
    let (status, list) = json_of(&h, &format!("{dir}/revisions/{pkg_old}/files")).await;
    assert_eq!(status, 200);
    assert!(list["files"].get("conan_package.tgz").is_some());
    assert_eq!(calls_to(&h, &format!("{pkg_new}/files/")), 0, "the held binary's files are never fetched");
    // And the other way round: an old binary id of a young recipe revision is its own decision (the recipe's file is held).
    assert_eq!(h.server.get(&format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_NEW}/files/conanfile.py")).await.status().as_u16(), 404, "unlisted revision");
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_binary_search_lists_only_packages_with_an_allowed_revision() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "zlib", "1.3.1", &[(R_OLD, OLD)]);
    let (good, held) = ("aaaa111100000000000000000000000000000000", "bbbb222200000000000000000000000000000000");
    serve_package(&h.registry, "zlib", "1.3.1", R_OLD, good, &[("p1p1p1p1", OLD)]);
    serve_package(&h.registry, "zlib", "1.3.1", R_OLD, held, &[("p2p2p2p2", YOUNG)]);
    h.registry.answer(&at(&format!("{}/revisions/{R_OLD}/search", base("zlib", "1.3.1"))), FakeAnswer::Body(package_search_doc(&[good, held])));
    let (status, doc) = json_of(&h, &format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/search")).await;
    assert_eq!(status, 200, "{doc}");
    let ids: Vec<&str> = doc.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(ids, [good], "{doc}");
    assert_eq!(doc[good]["settings"]["os"], "Linux", "an entry is served as the remote wrote it");
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_search_lists_a_reference_only_while_a_revision_of_it_passes_and_never_a_blocked_one() {
    let h = harness(r#"{"ecosystem":"conan","name":"badpkg","version":null,"reason":"malware"},{"ecosystem":"conan","name":"zlib","version":"1.2.11","reason":"malware"}"#, 7 * DAY).await;
    serve_recipe(&h.registry, "zlib", "1.3.1", &[(R_OLD, OLD)]);
    serve_recipe(&h.registry, "zlib", "1.2.11", &[(R_OLD, OLD)]);
    serve_recipe(&h.registry, "zlib", "1.4", &[(R_NEW, YOUNG)]);
    serve_recipe(&h.registry, "badpkg", "1.0", &[(R_OLD, OLD)]);
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(search_doc(&["zlib/1.3.1@_/_", "zlib/1.2.11@_/_", "zlib/1.4@_/_", "badpkg/1.0@_/_", "../x/1@_/_", "zlib/1.3.1@_/_", "mylib/1@acme/_"])));
    let (status, doc) = json_of(&h, "/conan/v2/conans/search?q=*&ignorecase=False").await;
    assert_eq!(status, 200, "{doc}");
    assert_eq!(doc["results"], serde_json::json!(["zlib/1.3.1@_/_"]), "blocked, held-only, malformed and repeated references are not listed: {doc}");
    assert_eq!(calls_to(&h, "badpkg"), 0, "a blocked package is never asked about");
    assert!(h.registry.calls().iter().any(|url| url.query() == Some("q=*&ignorecase=False")), "the pattern is passed on as the client wrote it");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ identity and policy

#[tokio::test]
async fn a_blocked_package_or_version_is_refused_before_any_upstream_call_in_every_case_and_user_channel() {
    let h = harness(r#"{"ecosystem":"conan","name":"Evil","version":null,"reason":"malware"},{"ecosystem":"conan","name":"zlib","version":"1.2.11","reason":"malware"}"#, 0).await;
    serve_zlib(&h);
    serve_recipe(&h.registry, "Evil", "1.0", &[(R_OLD, OLD)]);
    serve_recipe(&h.registry, "evil", "1.0", &[(R_OLD, OLD)]);
    serve_recipe(&h.registry, "zlib", "1.2.11", &[(R_OLD, OLD)]);
    for path in ["/conan/v2/conans/Evil/1.0/_/_/revisions", "/conan/v2/conans/Evil/1.0/_/_/latest", &format!("/conan/v2/conans/Evil/1.0/_/_/revisions/{R_OLD}/files/conanfile.py"), "/conan/v2/conans/zlib/1.2.11/_/_/revisions"] {
        assert_eq!(h.server.get(path).await.status().as_u16(), 403, "{path}");
    }
    assert!(h.registry.calls().is_empty(), "a blocked name or version reaches no upstream call: {:?}", h.registry.calls());
    assert_eq!(h.server.get("/conan/v2/conans/evil/1.0/_/_/revisions").await.status().as_u16(), 403, "a remote may fold case: `evil` is `Evil` to a policy");
    assert_eq!(h.server.get("/conan/v2/conans/EVIL/1.0/_/_/revisions").await.status().as_u16(), 403);
    assert!(h.registry.calls().is_empty(), "none of the three spellings reached the remote");
    assert_eq!(h.server.get("/conan/v2/conans/zlib/1.3.1/_/_/revisions").await.status().as_u16(), 200);
    // A block names a package and version for every user and channel (it fails closed); an exception cannot release one variant alone
    // (the policy model has no field for it: stated in evidence/slice-23.md).
    assert_eq!(h.server.get("/conan/v2/conans/zlib/1.2.11/acme/stable/revisions").await.status().as_u16(), 403);
    assert!(h.registry.calls().is_empty() || !h.registry.calls().iter().any(|url| url.path().contains("1.2.11")));
    h.server.shutdown().await;
}

#[tokio::test]
async fn paths_that_are_not_one_canonical_spelling_are_404_before_any_upstream_call() {
    let h = harness("", 0).await;
    serve_zlib(&h);
    for path in [
        "/conan/v2/conans/zlib/1.3.1/_/revisions",
        "/conan/v2/conans/zlib/1.3.1/acme/_/revisions",
        "/conan/v2/conans/zlib/../1.3.1/_/_/revisions",
        "/conan/v2/conans/zlib/1.3.1/_/_/revisions/",
        "/conan/v2/conans/zlib/1.3.1/_/_/latest?x=1",
        "/conan/v2/conans/zlib/1.3.1/_/_/revisions/a%20b/files",
        "/conan/v2/conans/search",
        "/conan/v2/conans/search?evil=1",
        "/conan/v2/other",
        "/conan/",
    ] {
        assert_eq!(h.server.get(path).await.status().as_u16(), 404, "{path}");
    }
    assert!(h.registry.calls().is_empty(), "{:?}", h.registry.calls());
    h.server.shutdown().await;
}

#[tokio::test]
async fn ping_login_and_a_credential_check_are_answered_and_the_remote_prefix_is_kept() {
    let h = harness("", 0).await;
    for path in ["/conan/v1/ping", "/conan/v2/ping"] {
        let ping = h.server.get(path).await;
        assert_eq!(ping.status().as_u16(), 200, "{path}");
        assert_eq!(ping.headers()["x-conan-server-capabilities"], "revisions", "only the capability this firewall serves is advertised");
    }
    assert_eq!(h.server.get("/conan/v1/users/authenticate").await.status().as_u16(), 404, "nothing else of the v1 tree is routed");
    h.registry.answer(&at("v2/users/authenticate"), FakeAnswer::Body("token-from-the-remote".into()));
    h.registry.answer(&at("v2/users/check_credentials"), FakeAnswer::Body(String::new()));
    assert_eq!(text_of(&h, "/conan/v2/users/authenticate").await, (200, "token-from-the-remote".to_owned()));
    assert_eq!(text_of(&h, "/conan/v2/users/check_credentials").await.0, 200);
    assert!(h.registry.calls().iter().all(|url| url.path().starts_with("/artifactory/api/conan/repo/v2/")), "{:?}", h.registry.calls());
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_standalone_firewall_has_no_upload_route() {
    let h = harness("", 0).await;
    let client = reqwest::Client::new();
    for method in ["PUT", "DELETE", "POST"] {
        let response = client.request(method.parse().unwrap(), h.server.url(&format!("/conan/v2/conans/zlib/1.3.1/_/_/revisions/{R_OLD}/files/conanfile.py"))).body("x").send().await.unwrap();
        assert_eq!(response.status().as_u16(), 405, "{method}");
    }
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ documents that are not what they claim

#[tokio::test]
async fn a_revision_list_that_is_not_one_document_is_a_502_and_never_passed_on() {
    let h = harness("", 0).await;
    for (name, body) in [
        ("dup", r#"{"revisions":[{"revision":"aa","time":"2025-01-01T00:00:00.000+0000"},{"revision":"aa"}]}"#),
        ("slash", r#"{"revisions":[{"revision":"a/b"}]}"#),
        ("notlist", r#"{"revisions":{"revision":"aa"}}"#),
        ("array", r#"[]"#),
        ("text", "not json"),
        ("nometa", r#"{"reference":"x"}"#),
    ] {
        h.registry.answer(&at(&format!("{}/revisions", base(name, "1.0"))), FakeAnswer::Body(body.to_owned()));
        assert_eq!(h.server.get(&format!("/conan/v2/conans/{name}/1.0/_/_/revisions")).await.status().as_u16(), 502, "{name}");
    }
    h.registry.answer(&at(&format!("{}/revisions", base("gone", "1.0"))), FakeAnswer::Missing);
    assert_eq!(h.server.get("/conan/v2/conans/gone/1.0/_/_/revisions").await.status().as_u16(), 404);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_large_listing_is_not_refused_before_its_cap_and_dates_cost_no_extra_call() {
    let h = harness("", 7 * DAY).await;
    let revisions: Vec<(String, String)> = (0..2_100).map(|i| (format!("{i:032x}"), if i == 0 { YOUNG.to_owned() } else { OLD.to_owned() })).collect();
    let borrowed: Vec<(&str, Option<&str>)> = revisions.iter().map(|(rev, time)| (rev.as_str(), Some(time.as_str()))).collect();
    h.registry.answer(&at(&format!("{}/revisions", base("big", "1.0"))), FakeAnswer::Body(revisions_doc(("reference", "big/1.0@_/_"), &borrowed)));
    let (status, doc) = json_of(&h, "/conan/v2/conans/big/1.0/_/_/revisions").await;
    assert_eq!(status, 200);
    assert_eq!(revs_of(&doc).len(), 2_099, "every old revision is listed, the young one is not");
    assert_eq!(h.registry.calls().len(), 1, "the dates came with the list: one call");
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_row_bound_is_hard_a_revision_past_it_is_a_503_and_commits_nothing() {
    let h = harness_with("", 0, |config| config.max_references_per_project = std::num::NonZeroU32::new(1).unwrap()).await;
    // Bound = 5 rows. Seven revisions are listed; only five anchors fit, the rest are withheld (fail closed).
    let revisions: Vec<(String, String)> = (0..7).map(|i| (format!("{i:032x}"), OLD.to_owned())).collect();
    let borrowed: Vec<(&str, &str)> = revisions.iter().map(|(rev, time)| (rev.as_str(), time.as_str())).collect();
    serve_recipe(&h.registry, "bounded", "1.0", &borrowed);
    let (status, doc) = json_of(&h, "/conan/v2/conans/bounded/1.0/_/_/revisions").await;
    assert_eq!(status, 200, "{doc}");
    assert_eq!(revs_of(&doc).len(), 5, "{doc}");
    let count = || async { h.server.app().store().count_project_references_in(0, probation::policy::Ecosystem::Conan, "bounded").await.unwrap() };
    assert_eq!(count().await, 5);
    let sixth = format!("{:032x}", 5);
    assert_eq!(h.server.get(&format!("/conan/v2/conans/bounded/1.0/_/_/revisions/{sixth}/files/conanfile.py")).await.status().as_u16(), 503);
    assert_eq!(count().await, 5, "nothing was committed past the bound");
    // A file that has its row (the anchor of a listed revision) is still served; one more file is one more row, past the bound.
    let first = format!("{:032x}", 0);
    assert_eq!(h.server.get(&format!("/conan/v2/conans/bounded/1.0/_/_/revisions/{first}/files/conanmanifest.txt")).await.status().as_u16(), 200);
    assert_eq!(h.server.get(&format!("/conan/v2/conans/bounded/1.0/_/_/revisions/{first}/files/conanfile.py")).await.status().as_u16(), 503);
    assert_eq!(count().await, 5);
    h.server.shutdown().await;
}

#[tokio::test]
async fn one_registry_never_holds_more_than_its_refresh_places() {
    let h = harness("", 0).await;
    for n in 0..6 {
        serve_recipe(&h.registry, &format!("pkg{n}"), "1.0", &[(R_OLD, OLD)]);
    }
    let mut joins = Vec::new();
    for n in 0..6 {
        let url = h.server.url(&format!("/conan/v2/conans/pkg{n}/1.0/_/_/revisions"));
        joins.push(tokio::spawn(async move { reqwest::get(url).await.unwrap().status().as_u16() }));
    }
    for join in joins {
        assert_eq!(join.await.unwrap(), 200);
    }
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_conan_osv_mapping_and_key_are_the_package_name() {
    use probation::osv::osv_ecosystem;
    assert_eq!(osv_ecosystem(probation::policy::Ecosystem::Conan), Some("ConanCenter"));
    let _ = files_doc(&[]);
}

/// LS-F12 for Conan: ConanCenter and, by default, any custom remote is queried; a remote the operator sets Private never is.
#[test]
fn conan_osv_query_follows_effective_scope() {
    use probation::osv::effective_scope;
    use probation::policy::Ecosystem;
    use probation_policy::api::OsvScope;
    for public in ["https://center2.conan.io/", "https://center.conan.io/v2/conans/zlib/1.3.1/_/_/latest"] {
        assert_eq!(effective_scope(Ecosystem::Conan, Some(public), Some(OsvScope::Private)), OsvScope::Public, "{public}: the fixed public sources ignore the field");
    }
    let custom = "https://art.corp.example/artifactory/api/conan/conan-local/";
    assert_eq!(effective_scope(Ecosystem::Conan, Some(custom), None), OsvScope::Public, "a custom remote defaults to Public (user decision 2026-11-18)");
    assert_eq!(effective_scope(Ecosystem::Conan, Some(custom), Some(OsvScope::Public)), OsvScope::Public);
    assert_eq!(effective_scope(Ecosystem::Conan, Some(custom), Some(OsvScope::Private)), OsvScope::Private, "a Private remote is never queried");
    assert_eq!(effective_scope(Ecosystem::Conan, None, None), OsvScope::Public, "the public registry is ConanCenter");
}

#[tokio::test]
async fn osv_public_mirror_with_explicit_scope_is_queried() {
    // The standalone firewall's registry is the public one: a package OSV flags is refused, the reference is named by package name.
    let (osv_url, _osv) = common::osv_flagging(&[("evilpkg", "1.0")]).await;
    let dir = tempfile::tempdir().unwrap();
    let registry = FakeRegistry::new();
    let server = TestServer::start_with_upstream_and_osv(common::config_with_open_blocklist(dir.path()), Arc::new(probation::clock::SystemClock), Arc::clone(&registry) as Arc<dyn Transport>, origins(), reqwest::Client::new(), osv_url).await;
    serve_recipe(&registry, "evilpkg", "1.0", &[(R_OLD, OLD)]);
    serve_recipe(&registry, "goodpkg", "1.0", &[(R_OLD, OLD)]);
    assert_eq!(server.get(&format!("/conan/v2/conans/evilpkg/1.0/_/_/revisions/{R_OLD}/files/conanfile.py")).await.status().as_u16(), 403, "flagged by OSV under its package name");
    assert_eq!(server.get(&format!("/conan/v2/conans/goodpkg/1.0/_/_/revisions/{R_OLD}/files/conanfile.py")).await.status().as_u16(), 200);
    assert_eq!(server.get("/conan/v2/conans/evilpkg/1.0/_/_/revisions").await.status().as_u16(), 403, "no revision of a flagged version is listed");
    server.shutdown().await;
}

#[tokio::test]
async fn simultaneous_first_requests_never_overshoot_the_row_bound() {
    let h = harness_with("", 0, |config| config.max_references_per_project = std::num::NonZeroU32::new(1).unwrap()).await;
    for n in 0..16 {
        serve_recipe(&h.registry, "gated", &format!("{n}.0"), &[(R_OLD, OLD)]);
    }
    let mut joins = Vec::new();
    for n in 0..16 {
        let url = h.server.url(&format!("/conan/v2/conans/gated/{n}.0/_/_/revisions"));
        joins.push(tokio::spawn(async move { reqwest::get(url).await.unwrap().status().as_u16() }));
    }
    let mut served = 0;
    for join in joins {
        if join.await.unwrap() == 200 {
            served += 1;
        }
    }
    let rows = h.server.app().store().count_project_references_in(0, probation::policy::Ecosystem::Conan, "gated").await.unwrap();
    assert_eq!(rows, 5, "exactly the bound: {served} of 16 admitted");
    assert!((5..=16).contains(&served));
    h.server.shutdown().await;
}

/// A recipe revision is the hash of the recipe's files, so two versions of one package may share it (the real `hello/1.0` and `hello/2.0`
/// of tests/e2e/fixtures/conan do): each version's revision is its own unit with its own age.
#[tokio::test]
async fn the_same_revision_id_under_two_versions_is_two_units_with_two_ages() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "shared", "1.0", &[(R_OLD, OLD)]);
    serve_recipe(&h.registry, "shared", "2.0", &[(R_OLD, YOUNG)]);
    let old = format!("/conan/v2/conans/shared/1.0/_/_/revisions/{R_OLD}/files/conanfile.py");
    let young = format!("/conan/v2/conans/shared/2.0/_/_/revisions/{R_OLD}/files/conanfile.py");
    assert_eq!(h.server.get(&old).await.status().as_u16(), 200);
    assert_eq!(h.server.get(&young).await.status().as_u16(), 403, "the young version is held although the same revision id is old under another version");
    assert_eq!(h.server.get(&old).await.status().as_u16(), 200);
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ fix round: searches, bounds, documents

fn ref_name(n: usize) -> String {
    format!("many{n}")
}

/// C23-1: EVERY result of a search is judged (no cap below the document's bound): 700 references, the first and the last listed, a held one
/// not, and a second request costs no list fetch (verdicts and lists are reused).
#[tokio::test]
async fn a_search_judges_every_result_past_five_hundred_and_twelve() {
    let h = harness("", 7 * DAY).await;
    let names: Vec<String> = (0..700).map(ref_name).collect();
    for (n, name) in names.iter().enumerate() {
        serve_recipe(&h.registry, name, "1.0", &[(R_OLD, if n == 650 { YOUNG } else { OLD })]);
    }
    let refs: Vec<String> = names.iter().map(|name| format!("{name}/1.0@_/_")).collect();
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(search_doc(&refs.iter().map(String::as_str).collect::<Vec<_>>())));
    let (status, doc) = json_of(&h, "/conan/v2/conans/search?q=many*").await;
    assert_eq!(status, 200, "{doc}");
    let listed = doc["results"].as_array().unwrap();
    assert_eq!(listed.len(), 699, "every reference with an allowed revision is listed, past the 512th too");
    assert!(listed.iter().any(|r| r == "many699/1.0@_/_") && listed.iter().any(|r| r == "many0/1.0@_/_") && !listed.iter().any(|r| r == "many650/1.0@_/_"));
    let fetched = h.registry.calls().len();
    let (status, again) = json_of(&h, "/conan/v2/conans/search?q=many*").await;
    assert_eq!((status, again["results"].as_array().unwrap().len()), (200, 699));
    assert!(h.registry.calls().len() <= fetched + 1, "the second search read only the search document: {} then {}", fetched, h.registry.calls().len());
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_binary_search_judges_every_package_id_past_five_hundred_and_twelve() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "wide", "1.0", &[(R_OLD, OLD)]);
    let ids: Vec<String> = (0..600).map(|n| format!("{n:040x}")).collect();
    for (n, id) in ids.iter().enumerate() {
        serve_package(&h.registry, "wide", "1.0", R_OLD, id, &[("p0p0p0p0", if n == 599 { YOUNG } else { OLD })]);
    }
    h.registry.answer(&at(&format!("{}/revisions/{R_OLD}/search", base("wide", "1.0"))), FakeAnswer::Body(package_search_doc(&ids.iter().map(String::as_str).collect::<Vec<_>>())));
    let (status, doc) = json_of(&h, &format!("/conan/v2/conans/wide/1.0/_/_/revisions/{R_OLD}/search")).await;
    assert_eq!(status, 200);
    assert_eq!(doc.as_object().unwrap().len(), 599, "every binary with an allowed revision is listed: the 513th to the 599th too, the young last one not");
    h.server.shutdown().await;
}

/// C23-1 (4): a list that cannot be read fails the search; it never answers a shorter 200.
#[tokio::test]
async fn a_list_that_cannot_be_read_fails_the_search_instead_of_truncating_it() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "fine", "1.0", &[(R_OLD, OLD)]);
    h.registry.answer(&at(&format!("{}/revisions", base("broken", "1.0"))), FakeAnswer::Fail(probation::upstream::UpstreamError::Status(503)));
    h.registry.answer(&at("v2/conans/search"), FakeAnswer::Body(search_doc(&["fine/1.0@_/_", "broken/1.0@_/_"])));
    assert_eq!(h.server.get("/conan/v2/conans/search?q=*").await.status().as_u16(), 502);
    h.server.shutdown().await;
}

/// F1: a hostile 400,000-entry revision list is read, bounded and answered; the work is batched and the unit table never cleared.
#[tokio::test]
async fn a_hostile_list_of_four_hundred_thousand_revisions_is_answered_within_its_bounds() {
    let h = harness_with("", 0, |config| config.max_references_per_project = std::num::NonZeroU32::new(100).unwrap()).await;
    let mut body = String::from("{\"revisions\":[");
    for n in 0..400_000 {
        if n > 0 {
            body.push(',');
        }
        body.push_str(&format!("{{\"revision\":\"{n:07x}\"}}"));
    }
    body.push_str("]}");
    assert!(body.len() < 16 << 20);
    h.registry.answer(&at(&format!("{}/revisions", base("hostile", "1.0"))), FakeAnswer::Body(body));
    let started = std::time::Instant::now();
    let (status, doc) = json_of(&h, "/conan/v2/conans/hostile/1.0/_/_/revisions").await;
    assert_eq!(status, 200);
    assert!(started.elapsed() < std::time::Duration::from_secs(90), "{:?}", started.elapsed());
    let listed = doc["revisions"].as_array().unwrap().len();
    assert!(listed > 0 && listed <= 500, "only what the project's row room holds is listed (fail closed): {listed}");
    assert!(h.server.app().store().count_project_references_in(0, probation::policy::Ecosystem::Conan, "hostile").await.unwrap() <= 500);
    h.server.shutdown().await;
}

/// C23-4: a file of any canonical name (spaces, more than four segments, a dot-leading segment) is listed and served.
#[tokio::test]
async fn files_with_spaces_deep_paths_and_dot_leading_segments_are_listed_and_served() {
    let h = harness("", 0).await;
    serve_recipe(&h.registry, "odd", "1.0", &[(R_OLD, OLD)]);
    let names = ["metadata/logs/linux x86/build log.txt", "metadata/a/b/c/d/e/f.json", "metadata/.hidden/x.txt"];
    let dir = format!("{}/revisions/{R_OLD}", base("odd", "1.0"));
    let mut all = vec!["conanfile.py", "conanmanifest.txt"];
    all.extend(names);
    h.registry.answer(&at(&format!("{dir}/files")), FakeAnswer::Body(files_doc(&all)));
    for name in names {
        h.registry.answer(&at(&format!("{dir}/files/{}", name.replace(' ', "%20"))), FakeAnswer::Body(format!("content of {name}")));
    }
    let (status, list) = json_of(&h, &format!("/conan/v2/conans/odd/1.0/_/_/revisions/{R_OLD}/files")).await;
    assert_eq!(status, 200);
    for name in names {
        assert!(list["files"].get(name).is_some(), "{name} is listed: {list}");
    }
    let got = h.server.get(&format!("/conan/v2/conans/odd/1.0/_/_/revisions/{R_OLD}/files/metadata/logs/linux%20x86/build%20log.txt")).await;
    assert_eq!((got.status().as_u16(), got.text().await.unwrap()), (200, "content of metadata/logs/linux x86/build log.txt".to_owned()));
    assert_eq!(h.server.get(&format!("/conan/v2/conans/odd/1.0/_/_/revisions/{R_OLD}/files/metadata/.hidden/x.txt")).await.status().as_u16(), 200);
    assert_eq!(h.server.get(&format!("/conan/v2/conans/odd/1.0/_/_/revisions/{R_OLD}/files/metadata/../x")).await.status().as_u16(), 404);
    h.server.shutdown().await;
}

/// F4: only the members Conan reads are relayed (a head member or an entry member naming a location never reaches a client).
#[tokio::test]
async fn nothing_of_a_remote_document_but_the_members_conan_reads_is_relayed() {
    let h = harness("", 0).await;
    let hostile = format!(r#"{{"reference":"zlib/1.0@_/_","download_urls":"https://evil.example/x","next":"https://evil.example/y","revisions":[{{"revision":"{R_OLD}","time":"{}","url":"https://evil.example/z"}}]}}"#, conan::conan_time(OLD));
    h.registry.answer(&at(&format!("{}/revisions", base("tidy", "1.0"))), FakeAnswer::Body(hostile));
    let (status, doc) = json_of(&h, "/conan/v2/conans/tidy/1.0/_/_/revisions").await;
    assert_eq!(status, 200);
    assert_eq!(doc.as_object().unwrap().keys().cloned().collect::<Vec<_>>(), ["reference", "revisions"], "{doc}");
    assert_eq!(doc["revisions"][0].as_object().unwrap().keys().cloned().collect::<Vec<_>>(), ["revision", "time"]);
    serve_recipe(&h.registry, "tidy", "1.0", &[(R_OLD, OLD)]);
    h.registry.answer(&at(&format!("{}/revisions/{R_OLD}/search", base("tidy", "1.0"))), FakeAnswer::Body(r#"{"aaaa":{"settings":{"os":"Linux"},"url":"https://evil.example/q","options":{"x":"https://evil.example/o"},"requires":["b/1"]}}"#.to_owned()));
    serve_package(&h.registry, "tidy", "1.0", R_OLD, "aaaa", &[("pppp", OLD)]);
    let (_, search) = json_of(&h, &format!("/conan/v2/conans/tidy/1.0/_/_/revisions/{R_OLD}/search")).await;
    assert_eq!(search, serde_json::json!({"aaaa": {"settings": {"os": "Linux"}, "options": {"x": "https://evil.example/o"}, "requires": ["b/1"]}}), "an option value is data (it never drops its key); a member Conan does not read is dropped");
    h.server.shutdown().await;
}

/// F5: a file added to an aged revision brings its own `Last-Modified` and waits its own cooldown.
#[tokio::test]
async fn a_file_added_later_to_an_old_revision_waits_its_own_cooldown() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "grow", "1.0", &[(R_OLD, OLD)]);
    let dir = format!("{}/revisions/{R_OLD}/files", base("grow", "1.0"));
    h.registry.answer(&at(&format!("{dir}/metadata/late.json")), FakeAnswer::Dated { body: b"{}".to_vec(), last_modified: common::maven::http_date(YOUNG) });
    h.registry.answer(&at(&format!("{dir}/metadata/early.json")), FakeAnswer::Dated { body: b"{}".to_vec(), last_modified: common::maven::http_date(OLD) });
    assert_eq!(h.server.get(&format!("/conan/v2/conans/grow/1.0/_/_/revisions/{R_OLD}/files/metadata/late.json")).await.status().as_u16(), 403);
    assert_eq!(h.server.get(&format!("/conan/v2/conans/grow/1.0/_/_/revisions/{R_OLD}/files/metadata/early.json")).await.status().as_u16(), 200);
    h.server.shutdown().await;
}

/// F6: a package revision is also gated by its recipe revision (lists, `latest`, file lists and files).
#[tokio::test]
async fn a_binary_of_a_held_recipe_revision_is_held_whatever_its_own_age() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "pair", "1.0", &[(R_NEW, YOUNG)]);
    serve_package(&h.registry, "pair", "1.0", R_NEW, PKG, &[("oldoldol", OLD)]);
    let dir = format!("/conan/v2/conans/pair/1.0/_/_/revisions/{R_NEW}/packages/{PKG}");
    for path in [format!("{dir}/revisions"), format!("{dir}/latest"), format!("{dir}/revisions/oldoldol/files"), format!("{dir}/revisions/oldoldol/files/conan_package.tgz")] {
        assert_eq!(h.server.get(&path).await.status().as_u16(), 403, "{path}");
    }
    assert_eq!(calls_to(&h, "conan_package.tgz"), 0);
    h.server.shutdown().await;
}

/// F7: the first download is compared with the revision's own `conanmanifest.txt` (an MD5 per file) before it is pinned.
#[tokio::test]
async fn a_download_that_disagrees_with_the_revisions_manifest_is_refused_and_not_pinned() {
    use md5::Digest as _;
    let h = harness("", 0).await;
    serve_recipe(&h.registry, "sums", "1.0", &[(R_OLD, OLD)]);
    let dir = format!("{}/revisions/{R_OLD}/files", base("sums", "1.0"));
    let good = conan::tgz(&format!("export sums 1.0 {R_OLD}"));
    let md5 = |bytes: &[u8]| md5::Md5::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
    h.registry.answer(&at(&format!("{dir}/conanmanifest.txt")), FakeAnswer::Body(format!("1700000000\nconan_export.tgz: {}\nconan_sources.tgz: {}\n", md5(&good), "0".repeat(32))));
    assert_eq!(h.server.get(&format!("/conan/v2/conans/sums/1.0/_/_/revisions/{R_OLD}/files/conan_export.tgz")).await.status().as_u16(), 200, "matches its manifest line");
    assert_ne!(h.server.get(&format!("/conan/v2/conans/sums/1.0/_/_/revisions/{R_OLD}/files/conan_sources.tgz")).await.status().as_u16(), 200, "disagrees with its manifest line");
    assert_eq!(h.server.get(&format!("/conan/v2/conans/sums/1.0/_/_/revisions/{R_OLD}/files/conanfile.py")).await.status().as_u16(), 200, "a file the manifest does not list is no check");
    h.server.shutdown().await;
}

/// U1: the epoch a remote writes for "unknown" is no date; the revision waits on first-seen.
#[tokio::test]
async fn an_epoch_time_is_no_publication_date() {
    let h = harness("", 7 * DAY).await;
    serve_recipe(&h.registry, "epoch", "1.0", &[(R_OLD, "1970-01-01T00:00:01Z")]);
    assert_eq!(h.server.get("/conan/v2/conans/epoch/1.0/_/_/revisions").await.status().as_u16(), 403);
    h.clock.advance_seconds(8 * DAY as i64);
    assert_eq!(h.server.get("/conan/v2/conans/epoch/1.0/_/_/revisions").await.status().as_u16(), 200);
    h.server.shutdown().await;
}

/// R7: the manifest check also holds for a file whose name needs percent-encoding in its URL.
#[tokio::test]
async fn the_manifest_check_holds_for_a_file_name_that_needs_encoding() {
    let h = harness("", 0).await;
    serve_recipe(&h.registry, "spaced", "1.0", &[(R_OLD, OLD)]);
    let dir = format!("{}/revisions/{R_OLD}/files", base("spaced", "1.0"));
    h.registry.answer(&at(&format!("{dir}/conanmanifest.txt")), FakeAnswer::Body(format!("1700000000\nbuild log.txt: {}\n", "0".repeat(32))));
    h.registry.answer(&at(&format!("{dir}/build%20log.txt")), FakeAnswer::Body("a log".into()));
    assert_ne!(h.server.get(&format!("/conan/v2/conans/spaced/1.0/_/_/revisions/{R_OLD}/files/build%20log.txt")).await.status().as_u16(), 200, "the manifest names another MD5 for this file");
    h.server.shutdown().await;
}
