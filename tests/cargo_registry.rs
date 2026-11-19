//! Row 18: Cargo sparse index and verified crate downloads, end to end through the firewall
//! against an in-process `FakeRegistry` and a clock the test moves by hand. The real client
//! witness is tests/cargo_native.rs. Real fixture: tests/fixtures/cargo (a slice of the live
//! `proc-macro-error` index file).

mod common;

use std::sync::Arc;

use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::config::Config;
use probation::upstream::{OriginKind, OriginSet, Transport};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const DAY: u64 = 86_400;
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";
const DL: &str = "https://cargo-files.invalid/crates";

fn origins() -> OriginSet {
    fake_origins().with_cargo(Url::parse("https://cargo-index.invalid").unwrap(), Url::parse("https://cargo-files.invalid").unwrap())
}

fn index_path(segments: &[&str]) -> String {
    origins().url_for(OriginKind::CargoIndex, segments).unwrap().path().to_owned()
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

async fn harness(blocked: &str, cooldown: u64) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(dir.path(), blocked, cooldown);
    let registry = FakeRegistry::new();
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
    registry.answer(&index_path(&["config.json"]), FakeAnswer::Body(format!(r#"{{"dl":"{DL}","api":"https://cargo-api.invalid"}}"#)));
    Harness { server, registry, clock, _dir: dir }
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn crate_bytes(label: &str) -> Vec<u8> {
    format!("not really a crate, but verified bytes: {label}").into_bytes()
}

/// One index line as crates.io writes it (extra fields kept in a fixed, unusual order so a
/// re-encoding would be visible).
fn line(name: &str, vers: &str, bytes: &[u8], pubtime: Option<&str>, yanked: bool) -> String {
    let pubtime = pubtime.map(|at| format!(r#","pubtime":"{at}""#)).unwrap_or_default();
    format!(
        r#"{{"name":"{name}","vers":"{vers}","deps":[{{"name":"serde","req":"^1","features":["derive"],"optional":false,"default_features":true,"target":null,"kind":"normal"}}],"cksum":"{}","features":{{"default":["std"],"std":[]}},"yanked":{yanked},"rust_version":"1.56","v":2{pubtime}}}"#,
        sha(bytes)
    )
}

fn index(lines: &[String]) -> String {
    format!("{}\n", lines.join("\n"))
}

async fn index_of(h: &Harness, path: &str) -> (u16, String) {
    let response = h.server.get(path).await;
    (response.status().as_u16(), response.text().await.unwrap())
}

fn serve_crate(h: &Harness, name: &str, vers: &str, bytes: &[u8]) {
    h.registry.answer(&format!("/crates/{name}/{vers}/download"), FakeAnswer::Bytes(bytes.to_vec()));
}

// ------------------------------------------------------------------ config.json

#[tokio::test]
async fn config_json_points_dl_and_api_at_the_firewall_and_keeps_auth_required() {
    let h = harness("", 0).await;
    let response = h.server.get("/cargo/config.json").await;
    assert_eq!(response.status().as_u16(), 200);
    let config: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(config["dl"], "https://packages.example.org/cargo/crates", "cargo appends /{{crate}}/{{version}}/download");
    assert_eq!(config["api"], "https://packages.example.org/cargo");
    assert!(config.get("auth-required").is_none());
    h.registry.answer(&index_path(&["config.json"]), FakeAnswer::Body(format!(r#"{{"dl":"{DL}","auth-required":true}}"#)));
    h.clock.advance_seconds(61);
    let config: serde_json::Value = serde_json::from_slice(&h.server.get("/cargo/config.json").await.bytes().await.unwrap()).unwrap();
    assert!(config.get("api").is_none(), "no api upstream, none advertised");
    assert_eq!(config["auth-required"], true);
    h.server.shutdown().await;
}

#[tokio::test]
async fn config_json_that_is_not_a_cargo_config_is_refused() {
    let h = harness("", 0).await;
    h.registry.answer(&index_path(&["config.json"]), FakeAnswer::Body("<html>captive portal</html>".to_owned()));
    assert_eq!(h.server.get("/cargo/config.json").await.status().as_u16(), 502);
    h.server.shutdown().await;
}

#[tokio::test]
async fn upstream_config_is_fetched_once_for_many_requests() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("a");
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(index(&[line("demo", "1.0.0", &bytes, Some(OLD), false)])));
    for _ in 0..4 {
        assert_eq!(index_of(&h, "/cargo/de/mo/demo").await.0, 200);
        assert_eq!(h.server.get("/cargo/config.json").await.status().as_u16(), 200);
    }
    let fetched = h.registry.calls().iter().filter(|url| url.path().ends_with("/config.json")).count();
    assert_eq!(fetched, 1, "config.json is cached 60 s and fetched by one request at a time");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ index

#[tokio::test]
async fn index_withholds_young_versions_and_keeps_every_other_line_byte_for_byte() {
    let h = harness("", 7 * DAY).await;
    let (old, young) = (crate_bytes("1.0.0"), crate_bytes("2.0.0"));
    let old_line = line("demo", "1.0.0", &old, Some(OLD), true);
    let young_line = line("demo", "2.0.0", &young, Some(YOUNG), false);
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(index(&[old_line.clone(), young_line.clone()])));
    let (status, body) = index_of(&h, "/cargo/de/mo/demo").await;
    assert_eq!(status, 200);
    assert_eq!(body, format!("{old_line}\n"), "the young line is withheld; the old line (checksum, features, yank flag) is upstream's text");
    h.clock.advance_seconds(8 * 86_400);
    assert_eq!(index_of(&h, "/cargo/de/mo/demo").await.1, index(&[old_line, young_line]), "after the cooldown both are served");
    h.server.shutdown().await;
}

#[tokio::test]
async fn index_without_a_registry_date_waits_on_the_committed_first_seen_time() {
    let h = harness("", 7 * DAY).await;
    let bytes = crate_bytes("undated");
    let undated = line("undated", "1.0.0", &bytes, None, false);
    h.registry.answer(&index_path(&["un", "da", "undated"]), FakeAnswer::Body(index(std::slice::from_ref(&undated))));
    assert_eq!(index_of(&h, "/cargo/un/da/undated").await.1, "", "an undated version is held from the moment it was first seen");
    h.clock.advance_seconds(6 * 86_400);
    assert_eq!(index_of(&h, "/cargo/un/da/undated").await.1, "", "six days since first seen");
    h.clock.advance_seconds(2 * 86_400);
    assert_eq!(index_of(&h, "/cargo/un/da/undated").await.1, index(&[undated]), "eight days since first seen");
    h.server.shutdown().await;
}

#[tokio::test]
async fn index_takes_the_later_of_two_dates_and_never_a_future_one() {
    let h = harness("", 7 * DAY).await;
    let bytes = crate_bytes("d");
    // `created_at` (a mirror's spelling) is accepted; when it disagrees with `pubtime` the later wins.
    let both = line("both", "1.0.0", &bytes, Some(OLD), false).replace("\"v\":2", &format!("\"v\":2,\"created_at\":\"{YOUNG}\""));
    let future = line("both", "2.0.0", &bytes, Some("2999-01-01T00:00:00Z"), false);
    h.registry.answer(&index_path(&["bo", "th", "both"]), FakeAnswer::Body(index(&[both, future])));
    assert_eq!(index_of(&h, "/cargo/bo/th/both").await.1, "", "a date in the future is refused and the later of two dates holds the version");
    h.server.shutdown().await;
}

#[tokio::test]
async fn index_hides_blocked_versions_and_every_spelling_of_a_blocked_name() {
    let blocked = r#"{"ecosystem":"cargo","name":"Foo_Bar","version":null,"reason":"malware"},{"ecosystem":"cargo","name":"demo","version":"1.0.1","reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    let bytes = crate_bytes("x");
    let keep = line("demo", "1.0.0", &bytes, Some(OLD), false);
    // The build metadata is not part of the identity: a block on 1.0.1 covers 1.0.1+build.7.
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(index(&[keep.clone(), line("demo", "1.0.1+build.7", &bytes, Some(OLD), false)])));
    assert_eq!(index_of(&h, "/cargo/de/mo/demo").await.1, format!("{keep}\n"));
    // A block written `Foo_Bar` hides the crate however its index spells it.
    h.registry.answer(&index_path(&["fo", "o-", "foo-bar"]), FakeAnswer::Body(index(&[line("foo-bar", "1.0.0", &bytes, Some(OLD), false)])));
    h.registry.answer(&index_path(&["fo", "o_", "foo_bar"]), FakeAnswer::Body(index(&[line("foo_bar", "1.0.0", &bytes, Some(OLD), false)])));
    assert_eq!(index_of(&h, "/cargo/fo/o-/foo-bar").await, (200, String::new()));
    assert_eq!(index_of(&h, "/cargo/fo/o_/foo_bar").await, (200, String::new()));
    h.server.shutdown().await;
}

#[tokio::test]
async fn index_paths_follow_the_sparse_layout_and_nothing_else_reaches_upstream() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("p");
    for (url, name) in [("/cargo/1/a", "a"), ("/cargo/2/ab", "ab"), ("/cargo/3/a/abc", "abc"), ("/cargo/ab/cd/abcd", "abcd")] {
        let segments: Vec<String> = probation::cargo_registry::index::index_segments(name);
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        h.registry.answer(&index_path(&segments), FakeAnswer::Body(index(&[line(name, "1.0.0", &bytes, Some(OLD), false)])));
        assert_eq!(index_of(&h, url).await.0, 200, "{url}");
    }
    let before = h.registry.calls().len();
    for url in ["/cargo/ab/cd/ABCD", "/cargo/AB/CD/ABCD", "/cargo/1/A", "/cargo/AB/cd/abcd", "/cargo/ab/ce/abcd", "/cargo/1/ab", "/cargo/2/a", "/cargo/3/b/abc", "/cargo/ab/cd/abc.d", "/cargo/ab/cd/ab%2Fcd", "/cargo/xx/yy/zz/ww", "/cargo/%2e%2e/etc/passwd", "/cargo/ab/cd/"] {
        assert_eq!(h.server.get(url).await.status().as_u16(), 404, "{url}");
    }
    let overlong = format!("/cargo/ab/cd/ab{}", "c".repeat(200));
    assert_eq!(h.server.get(&overlong).await.status().as_u16(), 404);
    assert_eq!(h.registry.calls().len(), before, "a path the layout cannot build asks upstream nothing");
    // A download names one crate and one SemVer version: anything else is refused before upstream is asked.
    let long_version = format!("1.0.0-{}", "a".repeat(300));
    for url in [
        "/cargo/crates/ab.cd/1.0.0/download".to_owned(),
        "/cargo/crates/ab%2Fcd/1.0.0/download".to_owned(),
        // (A crate whose index this server has never fetched: nothing is cached to hide a call.)
        "/cargo/crates/zzzz/1.0/download".to_owned(),
        "/cargo/crates/zzzz/latest/download".to_owned(),
        format!("/cargo/crates/zzzz/{long_version}/download"),
        format!("/cargo/crates/{}/1.0.0/download", "a".repeat(129)),
        "/cargo/crates/zzzz/1.0.0/other".to_owned(),
    ] {
        assert_eq!(h.server.get(&url).await.status().as_u16(), 404, "{url}");
    }
    assert_eq!(h.registry.calls().len(), before, "a download that cannot name a crate version asks upstream nothing");
    h.server.shutdown().await;
}

#[tokio::test]
async fn at_most_four_spellings_of_one_crate_are_committed_per_registry() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("s");
    let variants = ["a-b-c-d", "a_b-c-d", "a-b_c-d", "a-b-c_d", "a_b_c_d"];
    for variant in variants {
        let segments = probation::cargo_registry::index::index_segments(variant);
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        h.registry.answer(&index_path(&segments), FakeAnswer::Body(index(&[line(variant, "1.0.0", &bytes, Some(OLD), false)])));
    }
    let url = |variant: &str| format!("/cargo/{}", probation::cargo_registry::index::index_segments(variant).join("/"));
    for variant in &variants[..4] {
        assert_eq!(index_of(&h, &url(variant)).await.0, 200, "{variant}");
    }
    let before = h.registry.calls().len();
    assert_eq!(index_of(&h, &url(variants[4])).await.0, 404, "a fifth spelling of the same crate is not committed");
    assert_eq!(h.registry.calls().len(), before, "and costs upstream nothing");
    assert_eq!(index_of(&h, &url(variants[0])).await.0, 200, "an already committed spelling keeps working");
    h.server.shutdown().await;
}

/// LS-F6: the version policy and OSV see is SemVer with the build metadata dropped; the archive's
/// identity (file name, download path) keeps it, because that is the file the registry has.
#[test]
fn policy_version_drops_build_metadata_and_the_archive_name_keeps_it() {
    use probation::cargo_registry::index::parse_index;
    let line = line("demo", "1.0.0-rc.1+build.7", &crate_bytes("b"), Some(OLD), false);
    let entries = parse_index(line.as_bytes(), "demo", 10).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].policy_version(), "1.0.0-rc.1");
    assert_eq!(entries[0].filename(), "demo-1.0.0-rc.1+build.7.crate");
    assert_eq!(entries[0].vers, "1.0.0-rc.1+build.7");
}

#[tokio::test]
async fn index_refuses_what_is_not_an_index_and_drops_what_is_not_a_line() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("i");
    let good = line("mix", "1.0.0", &bytes, Some(OLD), false);
    // A line that is not JSON, or has a version that is not SemVer, or a checksum that is not sha256, is never delivered.
    let mixed = [good.clone(), "not json at all".to_owned(), line("mix", "1.0", &bytes, Some(OLD), false), line("mix", "2.0.0", &bytes, Some(OLD), false).replace(&sha(&bytes), "abcd")].join("\n");
    h.registry.answer(&index_path(&["mi", "x_", "mix_"]), FakeAnswer::Body(mixed.clone()));
    h.registry.answer(&index_path(&["mi", "x"]), FakeAnswer::Missing);
    h.registry.answer(&index_path(&["mi", "xx", "mixx"]), FakeAnswer::Body(index(&[good.replace("mix", "mixx")])));
    assert_eq!(index_of(&h, "/cargo/mi/xx/mixx").await.0, 200);
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(mixed.replace("mix", "demo")));
    assert_eq!(index_of(&h, "/cargo/de/mo/demo").await, (200, format!("{}\n", good.replace("mix", "demo"))), "only the well-formed line survives");
    h.registry.answer(&index_path(&["ba", "d1", "bad1"]), FakeAnswer::Body("<html>captive portal</html>\n".to_owned()));
    assert_eq!(index_of(&h, "/cargo/ba/d1/bad1").await.0, 502, "nothing usable in a document: refused, never passed through");
    // Two lines for one version, or a line that names another crate: the document is not trustworthy.
    h.registry.answer(&index_path(&["du", "p1", "dup1"]), FakeAnswer::Body(index(&[line("dup1", "1.0.0", &bytes, Some(OLD), false), line("dup1", "1.0.0", &bytes, Some(OLD), false)])));
    assert_eq!(index_of(&h, "/cargo/du/p1/dup1").await.0, 502);
    h.registry.answer(&index_path(&["ot", "he", "other"]), FakeAnswer::Body(index(&[line("someone-else", "1.0.0", &bytes, Some(OLD), false)])));
    assert_eq!(index_of(&h, "/cargo/ot/he/other").await.0, 502);
    h.registry.answer(&index_path(&["mi", "ss", "missing"]), FakeAnswer::Missing);
    assert_eq!(index_of(&h, "/cargo/mi/ss/missing").await.0, 404);
    h.server.shutdown().await;
}

#[tokio::test]
async fn index_answers_304_to_the_validator_of_the_filtered_body() {
    let h = harness("", 7 * DAY).await;
    let (old, young) = (crate_bytes("o"), crate_bytes("y"));
    h.registry.answer(&index_path(&["et", "ag", "etag"]), FakeAnswer::Body(index(&[line("etag", "1.0.0", &old, Some(OLD), false), line("etag", "2.0.0", &young, Some(YOUNG), false)])));
    let first = h.server.get("/cargo/et/ag/etag").await;
    let tag = first.headers().get("etag").expect("a validator").to_str().unwrap().to_owned();
    let again = h.server.get_with_headers("/cargo/et/ag/etag", &[("if-none-match", &tag)]).await;
    assert_eq!(again.status().as_u16(), 304);
    assert!(again.bytes().await.unwrap().is_empty());
    // Once policy lets the young version through, the body and its validator change: no stale 304.
    h.clock.advance_seconds(8 * 86_400);
    let later = h.server.get_with_headers("/cargo/et/ag/etag", &[("if-none-match", &tag)]).await;
    assert_eq!(later.status().as_u16(), 200, "the validator belongs to the filtered body, not to upstream's");
    assert_ne!(later.headers().get("etag").unwrap().to_str().unwrap(), tag);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_missing_hyphen_spelling_never_hides_the_underscore_spelling() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("u");
    h.registry.answer(&index_path(&["se", "rd", "serde_json"]), FakeAnswer::Body(index(&[line("serde_json", "1.0.0", &bytes, Some(OLD), false)])));
    h.registry.answer(&index_path(&["se", "rd", "serde-json"]), FakeAnswer::Missing);
    assert_eq!(index_of(&h, "/cargo/se/rd/serde-json").await.0, 404, "crates.io has no such index file; cargo then tries the other spelling");
    assert_eq!(index_of(&h, "/cargo/se/rd/serde_json").await.0, 200);
    assert_eq!(index_of(&h, "/cargo/se/rd/serde-json").await.0, 404, "and the stored row of serde_json is not served under the other spelling");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ downloads

#[tokio::test]
async fn crate_download_is_verified_against_the_index_checksum_and_gated_like_its_line() {
    let h = harness("", 7 * DAY).await;
    let (old, young) = (crate_bytes("old"), crate_bytes("young"));
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(index(&[line("demo", "1.0.0", &old, Some(OLD), true), line("demo", "2.0.0+meta.1", &young, Some(YOUNG), false)])));
    serve_crate(&h, "demo", "1.0.0", &old);
    serve_crate(&h, "demo", "2.0.0+meta.1", &young);
    let ok = h.server.get("/cargo/crates/demo/1.0.0/download").await;
    assert_eq!(ok.status().as_u16(), 200, "a yanked version stays downloadable: lockfiles name it");
    assert_eq!(ok.bytes().await.unwrap().as_ref(), old.as_slice());
    assert_eq!(h.server.head("/cargo/crates/demo/1.0.0/download").await.status().as_u16(), 200);
    assert_eq!(h.server.get("/cargo/crates/demo/2.0.0+meta.1/download").await.status().as_u16(), 403, "a young version is refused by the same policy as its index line");
    assert_eq!(h.server.get("/cargo/crates/demo/9.9.9/download").await.status().as_u16(), 404);
    assert_eq!(h.server.get("/cargo/crates/Demo/1.0.0/download").await.status().as_u16(), 404, "file names are exact: another case is no crate of this index");
    assert_eq!(h.server.get("/cargo/crates/demo/1.0/download").await.status().as_u16(), 404, "not a SemVer version");
    h.server.shutdown().await;
}

#[tokio::test]
async fn crate_download_keeps_the_registry_spelling_of_the_name() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("Inflector");
    h.registry.answer(&index_path(&["in", "fl", "inflector"]), FakeAnswer::Body(index(&[line("Inflector", "0.11.4", &bytes, Some(OLD), false)])));
    serve_crate(&h, "Inflector", "0.11.4", &bytes);
    assert_eq!(h.server.get("/cargo/in/fl/inflector").await.text().await.unwrap(), index(&[line("Inflector", "0.11.4", &bytes, Some(OLD), false)]));
    let ok = h.server.get("/cargo/crates/Inflector/0.11.4/download").await;
    assert_eq!(ok.status().as_u16(), 200);
    assert_eq!(ok.bytes().await.unwrap().as_ref(), bytes.as_slice());
    assert_eq!(h.server.get("/cargo/crates/inflector/0.11.4/download").await.status().as_u16(), 404, "upstream's file is Inflector-0.11.4.crate");
    h.server.shutdown().await;
}

#[tokio::test]
async fn crate_whose_bytes_do_not_match_the_index_checksum_is_refused() {
    let h = harness("", 0).await;
    let promised = crate_bytes("what the index promised");
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(index(&[line("demo", "1.0.0", &promised, Some(OLD), false)])));
    serve_crate(&h, "demo", "1.0.0", &crate_bytes("something else entirely"));
    let response = h.server.get("/cargo/crates/demo/1.0.0/download").await;
    assert_eq!(response.status().as_u16(), 502);
    assert!(!response.text().await.unwrap().contains("something else entirely"), "no unverified byte reaches the client");
    h.server.shutdown().await;
}

#[tokio::test]
async fn blocked_versions_are_refused_at_download_too() {
    let h = harness(r#"{"ecosystem":"cargo","name":"demo","version":"1.0.0","reason":"malware"}"#, 0).await;
    let bytes = crate_bytes("b");
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(index(&[line("demo", "1.0.0", &bytes, Some(OLD), false)])));
    serve_crate(&h, "demo", "1.0.0", &bytes);
    assert_eq!(h.server.get("/cargo/crates/demo/1.0.0/download").await.status().as_u16(), 403);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_dl_outside_the_registrys_own_origin_is_refused_everywhere() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("e");
    h.registry.answer(&index_path(&["de", "mo", "demo"]), FakeAnswer::Body(index(&[line("demo", "1.0.0", &bytes, Some(OLD), false)])));
    h.registry.answer(&index_path(&["config.json"]), FakeAnswer::Body(r#"{"dl":"https://evil.invalid/crates"}"#.to_owned()));
    assert_eq!(index_of(&h, "/cargo/de/mo/demo").await.0, 502, "a dl on a host this registry does not own is not delivered from");
    assert_eq!(h.server.get("/cargo/crates/demo/1.0.0/download").await.status().as_u16(), 502);
    for hostile in [r#"{"dl":"https://user:pw@cargo-files.invalid/crates"}"#, r#"{"dl":"ftp://cargo-files.invalid/crates"}"#, r#"{"dl":"/crates"}"#] {
        h.clock.advance_seconds(61);
        h.registry.answer(&index_path(&["config.json"]), FakeAnswer::Body(hostile.to_owned()));
        assert_eq!(h.server.get("/cargo/crates/demo/1.0.0/download").await.status().as_u16(), 502, "{hostile}");
    }
    assert!(h.registry.calls().iter().all(|url| url.host_str() != Some("evil.invalid")), "nothing was fetched from the foreign host");
    h.server.shutdown().await;
}

#[tokio::test]
async fn dl_markers_are_expanded_as_cargo_does() {
    let h = harness("", 0).await;
    let bytes = crate_bytes("m");
    h.registry.answer(&index_path(&["config.json"]), FakeAnswer::Body(format!(r#"{{"dl":"{DL}/{{lowerprefix}}/{{crate}}-{{version}}.crate"}}"#)));
    h.registry.answer(&index_path(&["ma", "rk", "Mark"]), FakeAnswer::Missing);
    h.registry.answer(&index_path(&["ma", "rk", "mark"]), FakeAnswer::Body(index(&[line("Mark", "1.0.0", &bytes, Some(OLD), false)])));
    h.registry.answer("/crates/ma/rk/Mark-1.0.0.crate", FakeAnswer::Bytes(bytes.clone()));
    let ok = h.server.get("/cargo/crates/Mark/1.0.0/download").await;
    assert_eq!((ok.status().as_u16(), ok.bytes().await.unwrap().to_vec()), (200, bytes));
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_largest_real_index_sized_document_is_not_refused() {
    // LS-F7: the real largest index measured (aws-sdk-ec2, 1,484,079 B) is far under the cap, and
    // a document of that size parses and filters.
    let h = harness("", 0).await;
    let bytes = crate_bytes("big");
    let lines: Vec<String> = (0..4_000).map(|n| line("big", &format!("1.0.{n}"), &bytes, Some(OLD), false)).collect();
    let document = index(&lines);
    assert!(document.len() > 1_400_000, "{}", document.len());
    h.registry.answer(&index_path(&["3", "b", "big"]), FakeAnswer::Body(document.clone()));
    let (status, body) = index_of(&h, "/cargo/3/b/big").await;
    assert_eq!((status, body.len()), (200, document.len()));
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ real fixture

#[tokio::test]
async fn real_crates_io_index_slice_is_filtered_by_its_own_pubtime() {
    let raw = std::fs::read_to_string(format!("{}/tests/fixtures/cargo/proc-macro-error.index", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let total = raw.lines().count();
    assert_eq!(total, 38, "the live file of 2026-11-19");
    // The oracle is the fixture's own `pubtime`, read here with a different parser than the firewall's.
    let published = |line: &str| -> jiff::Timestamp { serde_json::from_str::<serde_json::Value>(line).unwrap()["pubtime"].as_str().unwrap().parse().unwrap() };
    let now: jiff::Timestamp = "2020-02-10T00:00:00Z".parse().unwrap();
    let cutoff = now - jiff::SignedDuration::from_secs(10 * DAY as i64);
    let expected: Vec<&str> = raw.lines().filter(|line| published(line) <= cutoff).collect();
    assert!(expected.len() > 20 && expected.len() < total, "the cut falls inside the real history: {} of {total}", expected.len());
    let h = harness("", 10 * DAY).await;
    h.clock.set_rfc3339("2020-02-10T00:00:00Z");
    h.registry.answer(&index_path(&["pr", "oc", "proc-macro-error"]), FakeAnswer::Body(raw.clone()));
    let (status, body) = index_of(&h, "/cargo/pr/oc/proc-macro-error").await;
    assert_eq!(status, 200);
    assert_eq!(body.lines().collect::<Vec<_>>(), expected, "every eligible line, byte for byte and in upstream's order; the young and the future ones withheld");
    h.server.shutdown().await;
}
