//! Row 17: RubyGems end to end through the firewall, against an in-process `FakeRegistry`
//! and a clock the test moves by hand. Real fixtures: tests/fixtures/rubygems.

mod common;

use std::io::Write;
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

fn origins() -> OriginSet {
    fake_origins().with_rubygems(Url::parse("https://rubygems.invalid").unwrap())
}

fn path(segments: &[&str]) -> String {
    origins()
        .url_for(OriginKind::RubygemsMetadata, segments)
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

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// One compact-index line as rubygems.org writes it.
fn line(version: &str, platform: Option<&str>, bytes: &[u8], created: Option<&str>) -> String {
    let head = match platform {
        Some(platform) => format!("{version}-{platform}"),
        None => version.to_owned(),
    };
    let created = created
        .map(|at| format!(",created_at:{at}"))
        .unwrap_or_default();
    format!(
        "{head} dep:>= 1|checksum:{}{created},ruby:>= 2.5.0",
        sha(bytes)
    )
}

fn info(lines: &[String]) -> String {
    format!("---\n{}\n", lines.join("\n"))
}

fn gem_bytes(label: &str) -> Vec<u8> {
    format!("not really a gem, but verified bytes: {label}").into_bytes()
}

async fn info_of(h: &Harness, gem: &str) -> (u16, String) {
    let response = h.server.get(&format!("/rubygems/info/{gem}")).await;
    (response.status().as_u16(), response.text().await.unwrap())
}

// ------------------------------------------------------------------ compact index

#[tokio::test]
async fn info_withholds_young_versions_and_keeps_every_other_line_byte_for_byte() {
    let h = harness("", 7 * DAY).await;
    let (old, young) = (gem_bytes("1.0.0"), gem_bytes("2.0.0"));
    let old_line = line("1.0.0", None, &old, Some(OLD));
    let young_line = line("2.0.0", None, &young, Some(YOUNG));
    h.registry.answer(
        &path(&["info", "demo"]),
        FakeAnswer::Body(info(&[old_line.clone(), young_line.clone()])),
    );
    let (status, body) = info_of(&h, "demo").await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        format!("---\n{old_line}\n"),
        "the young line is withheld, the old line is upstream's text"
    );
    // Once the cooldown has passed (and the snapshot is past its TTL) the young line is served too.
    h.clock.advance_seconds(8 * 86_400);
    let (_, later) = info_of(&h, "demo").await;
    assert_eq!(later, info(&[old_line, young_line]));
    h.server.shutdown().await;
}

#[tokio::test]
async fn info_judges_each_platform_by_its_own_date() {
    let h = harness("", 7 * DAY).await;
    let (ruby, java) = (gem_bytes("ruby"), gem_bytes("java"));
    let ruby_line = line("2.0.0", None, &ruby, Some(OLD));
    let java_line = line("2.0.0", Some("java"), &java, Some(YOUNG));
    h.registry.answer(
        &path(&["info", "plat"]),
        FakeAnswer::Body(info(&[ruby_line.clone(), java_line])),
    );
    let (_, body) = info_of(&h, "plat").await;
    assert_eq!(
        body,
        format!("---\n{ruby_line}\n"),
        "an old ruby build does not age the new java build"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn info_hides_blocked_versions_and_packages() {
    let blocked = r#"{"ecosystem":"rubygems","name":"demo","version":"1.0.1","reason":"malware"},{"ecosystem":"rubygems","name":"gone","version":null,"reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    let bytes = gem_bytes("x");
    let keep = line("1.0.0", None, &bytes, Some(OLD));
    h.registry.answer(
        &path(&["info", "demo"]),
        FakeAnswer::Body(info(&[
            keep.clone(),
            line("1.0.1", None, &bytes, Some(OLD)),
            line("1.0.1", Some("java"), &bytes, Some(OLD)),
        ])),
    );
    h.registry.answer(
        &path(&["info", "gone"]),
        FakeAnswer::Body(info(&[line("1.0.0", None, &bytes, Some(OLD))])),
    );
    let (_, body) = info_of(&h, "demo").await;
    assert_eq!(
        body,
        format!("---\n{keep}\n"),
        "a version block covers every platform of that version"
    );
    let (status, gone) = info_of(&h, "gone").await;
    assert_eq!(
        (status, gone.as_str()),
        (200, "---\n"),
        "a blocked gem lists nothing"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn info_without_a_registry_date_waits_on_the_committed_first_seen_time() {
    let h = harness("", 7 * DAY).await;
    let bytes = gem_bytes("undated");
    let undated = line("1.0.0", None, &bytes, None);
    h.registry.answer(
        &path(&["info", "undated"]),
        FakeAnswer::Body(info(std::slice::from_ref(&undated))),
    );
    let (_, first) = info_of(&h, "undated").await;
    assert_eq!(
        first, "---\n",
        "an undated version is held from the moment it was first seen"
    );
    h.clock.advance_seconds(6 * 86_400);
    assert_eq!(
        info_of(&h, "undated").await.1,
        "---\n",
        "not yet: six days since first seen"
    );
    h.clock.advance_seconds(2 * 86_400);
    assert_eq!(
        info_of(&h, "undated").await.1,
        info(&[undated]),
        "eight days since first seen"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn info_refuses_what_is_not_a_compact_index() {
    let h = harness("", 0).await;
    h.registry.answer(
        &path(&["info", "bad"]),
        FakeAnswer::Body("<html>captive portal</html>".to_owned()),
    );
    let (status, _) = info_of(&h, "bad").await;
    assert_eq!(
        status, 502,
        "an unparseable upstream document is refused, never passed through"
    );
    h.registry
        .answer(&path(&["info", "missing"]), FakeAnswer::Missing);
    assert_eq!(info_of(&h, "missing").await.0, 404);
    for hostile in ["..%2Fetc", "a%2Fb", "%00x"] {
        assert_ne!(info_of(&h, hostile).await.0, 200, "{hostile}");
    }
    h.server.shutdown().await;
}

#[tokio::test]
async fn versions_and_names_pass_through_unchanged_and_non_indexes_refuse() {
    let h = harness("", 0).await;
    h.registry.answer(&path(&["versions"]), FakeAnswer::Body("created_at: 2026-04-06T00:00:00Z\n---\nrack 3.0.0,3.1.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nnokogiri 1.0.0,1.0.0-java,-1.0.1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n".to_owned()));
    h.registry.answer(
        &path(&["names"]),
        FakeAnswer::Body("---\nrack\nnokogiri\n".to_owned()),
    );
    let versions = h
        .server
        .get("/rubygems/versions")
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(
        versions,
        "created_at: 2026-04-06T00:00:00Z\n---\nrack 3.0.0,3.1.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nnokogiri 1.0.0,1.0.0-java,-1.0.1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        "Bundler needs the third column, so it stays"
    );
    assert_eq!(
        h.server.get("/rubygems/names").await.text().await.unwrap(),
        "---\nrack\nnokogiri\n"
    );
    h.registry.answer(
        &path(&["versions"]),
        FakeAnswer::Body("no header".to_owned()),
    );
    assert_eq!(
        h.server.get("/rubygems/versions").await.status().as_u16(),
        502
    );
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ gem files

#[tokio::test]
async fn gem_file_is_delivered_verified_and_refused_while_young() {
    let h = harness("", 7 * DAY).await;
    let (old, young) = (gem_bytes("old"), gem_bytes("young"));
    h.registry.answer(
        &path(&["info", "demo"]),
        FakeAnswer::Body(info(&[
            line("1.0.0", None, &old, Some(OLD)),
            line("2.0.0", Some("java"), &young, Some(YOUNG)),
        ])),
    );
    h.registry.answer(
        &path(&["gems", "demo-1.0.0.gem"]),
        FakeAnswer::Bytes(old.clone()),
    );
    h.registry.answer(
        &path(&["gems", "demo-2.0.0-java.gem"]),
        FakeAnswer::Bytes(young.clone()),
    );
    let ok = h.server.get("/rubygems/gems/demo-1.0.0.gem").await;
    assert_eq!(ok.status().as_u16(), 200);
    assert_eq!(ok.bytes().await.unwrap().as_ref(), old.as_slice());
    let held = h.server.get("/rubygems/gems/demo-2.0.0-java.gem").await;
    assert_eq!(
        held.status().as_u16(),
        403,
        "a young platform build is refused by the same policy as its info line"
    );
    let unknown = h.server.get("/rubygems/gems/demo-9.9.9.gem").await;
    assert_eq!(unknown.status().as_u16(), 404);
    assert_eq!(
        h.server
            .head("/rubygems/gems/demo-1.0.0.gem")
            .await
            .status()
            .as_u16(),
        200
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn gem_file_whose_bytes_do_not_match_the_index_checksum_is_refused() {
    let h = harness("", 0).await;
    let promised = gem_bytes("what the index promised");
    h.registry.answer(
        &path(&["info", "demo"]),
        FakeAnswer::Body(info(&[line("1.0.0", None, &promised, Some(OLD))])),
    );
    h.registry.answer(
        &path(&["gems", "demo-1.0.0.gem"]),
        FakeAnswer::Bytes(gem_bytes("something else entirely")),
    );
    let response = h.server.get("/rubygems/gems/demo-1.0.0.gem").await;
    assert_ne!(response.status().as_u16(), 200);
    assert!(
        !response
            .text()
            .await
            .unwrap()
            .contains("something else entirely"),
        "no unverified byte reaches the client"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn gem_file_names_that_fit_two_index_entries_refuse_instead_of_guessing() {
    let h = harness("", 0).await;
    let bytes = gem_bytes("a");
    // `foo-1-2.0.gem` is gem `foo` version `1` platform `2.0`, or gem `foo-1` version `2.0`.
    h.registry.answer(
        &path(&["info", "foo"]),
        FakeAnswer::Body(info(&[line("1", Some("2.0"), &bytes, Some(OLD))])),
    );
    h.registry.answer(
        &path(&["info", "foo-1"]),
        FakeAnswer::Body(info(&[line("2.0", None, &bytes, Some(OLD))])),
    );
    h.registry
        .answer(&path(&["gems", "foo-1-2.0.gem"]), FakeAnswer::Bytes(bytes));
    assert_eq!(
        h.server
            .get("/rubygems/gems/foo-1-2.0.gem")
            .await
            .status()
            .as_u16(),
        404
    );
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ quick gemspecs

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/rubygems/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn zlib(raw: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(raw).unwrap();
    z.finish().unwrap()
}

#[tokio::test]
async fn quick_gemspec_real_fixture_served_byte_identical_to_native_client() {
    let h = harness("", 7 * DAY).await;
    let spec = fixture("rack-3.2.8.gemspec.rz");
    h.registry.answer(
        &path(&["info", "rack"]),
        FakeAnswer::Body(info(&[line("3.2.8", None, b"rack", Some(OLD))])),
    );
    h.registry.answer(
        &path(&["quick", "Marshal.4.8", "rack-3.2.8.gemspec.rz"]),
        FakeAnswer::Bytes(spec.clone()),
    );
    let response = h
        .server
        .get("/rubygems/quick/Marshal.4.8/rack-3.2.8.gemspec.rz")
        .await;
    assert_eq!(response.status().as_u16(), 200);
    let served = response.bytes().await.unwrap().to_vec();
    assert_eq!(served, spec, "the original bytes, not a re-encoding");
    // A conformant client (Ruby's own RubyGems loader) reads what was served.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rack.rz"), &served).unwrap();
    let out = std::process::Command::new("ruby")
        .args(["-e", "require 'rubygems'; require 'zlib'; spec = Marshal.load(Zlib::Inflate.inflate(File.binread(ARGV[0]))); abort 'wrong gem' unless spec.name == 'rack' && spec.version.to_s == '3.2.8'; puts spec.full_name", "--"])
        .arg(dir.path().join("rack.rz"))
        .output()
        .expect("ruby 3.x is the native baseline of this row");
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn quick_gemspec_is_identity_gated_and_refuses_hostile_classes() {
    let h = harness("", 7 * DAY).await;
    let hostile = zlib(&[
        4, 8, b'o', b':', 12, b'G', b'e', b'm', b':', b':', b'I', b'n', b's', b't', b'a', b'l',
        b'l', b'e', b'r', 0,
    ]);
    h.registry.answer(
        &path(&["info", "evil"]),
        FakeAnswer::Body(info(&[
            line("1.0.0", None, b"x", Some(OLD)),
            line("2.0.0", None, b"y", Some(YOUNG)),
        ])),
    );
    h.registry.answer(
        &path(&["quick", "Marshal.4.8", "evil-1.0.0.gemspec.rz"]),
        FakeAnswer::Bytes(hostile),
    );
    h.registry.answer(
        &path(&["quick", "Marshal.4.8", "evil-2.0.0.gemspec.rz"]),
        FakeAnswer::Bytes(fixture("rack-3.2.8.gemspec.rz")),
    );
    assert_eq!(
        h.server
            .get("/rubygems/quick/Marshal.4.8/evil-1.0.0.gemspec.rz")
            .await
            .status()
            .as_u16(),
        502,
        "hostile class refused"
    );
    assert_eq!(
        h.server
            .get("/rubygems/quick/Marshal.4.8/evil-2.0.0.gemspec.rz")
            .await
            .status()
            .as_u16(),
        404,
        "a young version's gemspec is gated like its gem"
    );
    assert_eq!(
        h.server
            .get("/rubygems/quick/Marshal.4.8/evil-3.0.0.gemspec.rz")
            .await
            .status()
            .as_u16(),
        404,
        "not in the index"
    );
    assert_eq!(
        h.server
            .get("/rubygems/quick/Marshal.4.8/evil-1.0.0.gem")
            .await
            .status()
            .as_u16(),
        404
    );
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ tuple indexes

/// Names and versions of every tuple a served `specs` file holds, as Ruby reads it.
fn ruby_tuples(gz: &[u8]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.gz"), gz).unwrap();
    let out = std::process::Command::new("ruby")
        .args(["-e", "require 'rubygems'; require 'zlib'; Marshal.load(Zlib::GzipReader.open(ARGV[0], &:read)).each { |n, v, p| puts \"#{n} #{v} #{p}\" }", "--"])
        .arg(dir.path().join("index.gz"))
        .output()
        .expect("ruby 3.x is the native baseline of this row");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn specs_index_is_filtered_by_blocks_and_by_what_the_instance_has_indexed() {
    let h = harness(
        r#"{"ecosystem":"rubygems","name":"rack","version":null,"reason":"malware"}"#,
        7 * DAY,
    )
    .await;
    let upstream = fixture("full-index-slice.4.8.gz");
    let before = ruby_tuples(&upstream);
    assert!(
        before.iter().any(|t| t.starts_with("rack "))
            && before.iter().any(|t| t.starts_with("rake 13.0.6 ")),
        "the real slice has both"
    );
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(upstream.clone()),
    );
    // Before a recent-versions source exists, no unindexed tuple has a date and none is listed.
    let dark = ruby_tuples(
        &h.server
            .get("/rubygems/specs.4.8.gz")
            .await
            .bytes()
            .await
            .unwrap(),
    );
    assert!(
        dark.is_empty(),
        "no invented dates: {} tuples listed",
        dark.len()
    );
    h.clock.advance_seconds(61);
    // rubygems.org's own list of versions published inside the cooldown window (real dates).
    h.registry.answer(
        &path(&["api", "v1", "timeframe_versions.json"]),
        FakeAnswer::Body(format!(r#"[{{"name":"rake","number":"13.0.6","platform":"ruby","version_created_at":"{YOUNG}"}},{{"name":"nokogiri","number":"1.0.0","platform":"java","version_created_at":"{YOUNG}"}}]"#)),
    );
    // rake is indexed here, and its 13.0.6 is young; every other rake tuple has no line to judge.
    h.registry.answer(
        &path(&["info", "rake"]),
        FakeAnswer::Body(info(&[line("13.0.6", None, b"x", Some(YOUNG))])),
    );
    assert_eq!(info_of(&h, "rake").await.1, "---\n");
    let response = h.server.get("/rubygems/specs.4.8.gz").await;
    assert_eq!(response.status().as_u16(), 200);
    let served = ruby_tuples(&response.bytes().await.unwrap());
    assert!(
        !served.iter().any(|t| t.starts_with("rack ")),
        "a blocked gem is not listed"
    );
    assert!(
        !served.iter().any(|t| t.starts_with("rake 13.0.6 ")),
        "a version the compact index withholds is not listed"
    );
    let expected: Vec<&String> = before
        .iter()
        .filter(|t| {
            !t.starts_with("rack ") && !t.starts_with("rake 13.0.6 ") && *t != "nokogiri 1.0.0 java"
        })
        .collect();
    assert!(
        !served.contains(&"nokogiri 1.0.0 java".to_owned()),
        "an unindexed young tuple takes its real date from the recent list"
    );
    assert_eq!(
        served.iter().collect::<Vec<_>>(),
        expected,
        "every other tuple, in order"
    );
    // Not an index: refused, never passed through.
    h.registry.answer(
        &path(&["latest_specs.4.8.gz"]),
        FakeAnswer::Bytes(b"<html>portal</html>".to_vec()),
    );
    assert_eq!(
        h.server
            .get("/rubygems/latest_specs.4.8.gz")
            .await
            .status()
            .as_u16(),
        502
    );
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ names (SR17-4)

/// Evidence 2026-11-19 (one read-only request each to rubygems.org): `GET /info/Rack` answers
/// 200 with the index of `rack`, while `GET /gems/Rack-3.2.8.gem` and the quick gemspec answer
/// 403. Names are case-insensitive for the compact index and case-sensitive for files, so a
/// block or an OSV match on `rack` has to apply to the spelling `Rack` too.
#[tokio::test]
async fn gem_names_are_judged_case_insensitively_so_a_spelling_cannot_dodge_a_block() {
    let h = harness(r#"{"ecosystem":"rubygems","name":"rack","version":null,"reason":"malware"},{"ecosystem":"rubygems","name":"Sinatra","version":"1.0.0","reason":"malware"}"#, 0).await;
    let bytes = gem_bytes("r");
    for spelling in ["rack", "Rack", "RACK"] {
        h.registry.answer(
            &path(&["info", spelling]),
            FakeAnswer::Body(info(&[line("1.0.0", None, &bytes, Some(OLD))])),
        );
        assert_eq!(
            info_of(&h, spelling).await.1,
            "---\n",
            "{spelling} is the blocked gem"
        );
    }
    for spelling in ["sinatra", "SINATRA"] {
        h.registry.answer(
            &path(&["info", spelling]),
            FakeAnswer::Body(info(&[
                line("1.0.0", None, &bytes, Some(OLD)),
                line("1.0.1", None, &bytes, Some(OLD)),
            ])),
        );
        let body = info_of(&h, spelling).await.1;
        assert!(
            !body.contains("\n1.0.0 ") && body.contains("\n1.0.1 "),
            "{spelling}: the operator's `Sinatra` block applies to every spelling: {body}"
        );
    }
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ resource bounds (SR17-1, SR17-2, CR F6, F10)

fn calls_to(h: &Harness, prefix: &str) -> usize {
    h.registry
        .calls()
        .iter()
        .filter(|u| u.path().starts_with(prefix))
        .count()
}

#[tokio::test]
async fn gem_file_name_fan_out_is_bounded_before_any_upstream_call() {
    let h = harness("", 0).await;
    // 60 digit-led hyphens: a real gem name has a few at most.
    let hostile = format!("{}x-1.0.gem", "a-1-".repeat(30));
    assert_eq!(
        h.server
            .get(&format!("/rubygems/gems/{hostile}"))
            .await
            .status()
            .as_u16(),
        404
    );
    let spec = format!("{}x-1.0.gemspec.rz", "a-1-".repeat(30));
    assert_eq!(
        h.server
            .get(&format!("/rubygems/quick/Marshal.4.8/{spec}"))
            .await
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        calls_to(&h, &path(&["info"])),
        0,
        "no /info fetch for a name that cannot be a gem file"
    );
    // A name at the bound asks about at most that many gems, and a real platform gem still resolves.
    let _ = h.server.get("/rubygems/gems/a-1-b-2-c-3.gem").await;
    assert!(calls_to(&h, &path(&["info"])) <= 3);
    let bytes = gem_bytes("n");
    h.registry.answer(
        &path(&["info", "nokogiri"]),
        FakeAnswer::Body(info(&[line(
            "1.16.0",
            Some("x86_64-linux"),
            &bytes,
            Some(OLD),
        )])),
    );
    h.registry.answer(
        &path(&["gems", "nokogiri-1.16.0-x86_64-linux.gem"]),
        FakeAnswer::Bytes(bytes.clone()),
    );
    assert_eq!(
        h.server
            .get("/rubygems/gems/nokogiri-1.16.0-x86_64-linux.gem")
            .await
            .status()
            .as_u16(),
        200
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn names_are_validated_and_a_filtered_index_is_built_once_per_window() {
    let h = harness("", 0).await;
    h.registry.answer(
        &path(&["names"]),
        FakeAnswer::Body("<html>portal</html>".to_owned()),
    );
    assert_eq!(h.server.get("/rubygems/names").await.status().as_u16(), 502);
    h.registry.answer(
        &path(&["names"]),
        FakeAnswer::Body("---\nrack\n../evil\n".to_owned()),
    );
    assert_eq!(h.server.get("/rubygems/names").await.status().as_u16(), 502);
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    let first = h
        .server
        .get("/rubygems/specs.4.8.gz")
        .await
        .bytes()
        .await
        .unwrap();
    let second = h
        .server
        .get("/rubygems/specs.4.8.gz")
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        calls_to(&h, &path(&["specs.4.8.gz"])),
        1,
        "one upstream fetch and one filter pass serve both"
    );
    h.clock.advance_seconds(61);
    let _ = h.server.get("/rubygems/specs.4.8.gz").await;
    assert_eq!(
        calls_to(&h, &path(&["specs.4.8.gz"])),
        2,
        "the cached answer ends after its window"
    );
    // Concurrent requests share the heavy-path limiter: all complete and agree.
    h.clock.advance_seconds(61);
    let url = h.server.url("/rubygems/specs.4.8.gz");
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            reqwest::get(url).await.unwrap().bytes().await.unwrap()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), first);
    }
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ recheck fix round (N1-N7)

/// rubygems.org's `timeframe_versions` page (30 rows, newest first), as the real API writes the
/// fields the firewall reads (checked live 2026-11-19: `name`, `version`, `platform`,
/// `version_created_at` with milliseconds, plus many fields it ignores).
fn page_of(items: &[(&str, &str, &str)]) -> String {
    let rows: Vec<String> = items
        .iter()
        .map(|(name, version, platform)| format!(r#"{{"name":"{name}","downloads":1,"version":"{version}","version_created_at":"{YOUNG}","platform":"{platform}","info":"x\ny","licenses":["MIT"],"yanked":false}}"#))
        .collect();
    format!("[{}]", rows.join(","))
}

fn timeframe() -> String {
    path(&["api", "v1", "timeframe_versions.json"])
}

async fn tuples_of(h: &Harness, file: &str) -> Vec<String> {
    let response = h.server.get(&format!("/rubygems/{file}")).await;
    assert_eq!(response.status().as_u16(), 200, "{file}");
    ruby_tuples(&response.bytes().await.unwrap())
}

/// N1: the real API pages (30 rows, `page=`); a young version past page 1 is still young.
#[tokio::test]
async fn young_versions_beyond_the_first_page_are_withheld() {
    let h = harness("", 7 * DAY).await;
    let upstream = fixture("full-index-slice.4.8.gz");
    assert!(ruby_tuples(&upstream).contains(&"nokogiri 1.2.0 java".to_owned()));
    h.registry
        .answer(&path(&["specs.4.8.gz"]), FakeAnswer::Bytes(upstream));
    let filler: Vec<(String, String, String)> = (0..30)
        .map(|i| (format!("filler{i}"), "1.0.0".to_owned(), "ruby".to_owned()))
        .collect();
    let filler: Vec<(&str, &str, &str)> = filler
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    h.registry.answer(
        &format!("{}?page=1", timeframe()),
        FakeAnswer::Body(page_of(&filler)),
    );
    h.registry.answer(
        &format!("{}?page=2", timeframe()),
        FakeAnswer::Body(page_of(&[("nokogiri", "1.2.0", "java")])),
    );
    h.registry.answer(
        &format!("{}?page=3", timeframe()),
        FakeAnswer::Body("[]".to_owned()),
    );
    let served = tuples_of(&h, "specs.4.8.gz").await;
    assert!(
        !served.contains(&"nokogiri 1.2.0 java".to_owned()),
        "a young version on page 2 is withheld"
    );
    assert!(
        served.contains(&"rake 13.0.6 ruby".to_owned())
            || served.iter().any(|t| t.starts_with("rake 13.0.6")),
        "old tuples stay listed"
    );
    let pages: Vec<String> = h
        .registry
        .calls()
        .iter()
        .filter(|u| u.path() == timeframe())
        .map(|u| u.query().unwrap_or("").to_owned())
        .collect();
    assert_eq!(pages.len(), 3, "pages 1, 2 and the empty 3: {pages:?}");
    assert!(pages.iter().all(|q| q.contains("page=")) && pages[2].contains("page=3"));
    h.server.shutdown().await;
}

/// N1 cap: a registry that never runs out of pages fails closed (nothing unindexed is listed).
#[tokio::test]
async fn an_endless_recent_list_fails_closed() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    h.registry.answer(
        &format!("{}?page=*", timeframe()),
        FakeAnswer::Body(page_of(&[("filler", "1.0.0", "ruby")])),
    );
    assert!(
        tuples_of(&h, "specs.4.8.gz").await.is_empty(),
        "the page cap was hit: unindexed tuples are not listed"
    );
    let asked = h
        .registry
        .calls()
        .iter()
        .filter(|u| u.path() == timeframe())
        .count();
    assert!(
        (2..=3000).contains(&asked),
        "bounded: {asked} page requests"
    );
    h.server.shutdown().await;
}

/// N4: a page over the byte cap is refused unparsed, so the list fails closed.
#[tokio::test]
async fn an_oversized_recent_page_fails_closed() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    let padded = format!(
        "{}{}",
        page_of(&[("filler", "1.0.0", "ruby")]),
        " ".repeat(5 << 20)
    );
    h.registry.answer(&timeframe(), FakeAnswer::Body(padded));
    assert!(tuples_of(&h, "specs.4.8.gz").await.is_empty());
    h.server.shutdown().await;
}

/// N3: a registry without the API is probed once per short window, not once per index build.
#[tokio::test]
async fn a_failed_recent_list_is_remembered_briefly() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    h.registry.answer(
        &path(&["latest_specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    assert!(tuples_of(&h, "specs.4.8.gz").await.is_empty());
    assert!(tuples_of(&h, "latest_specs.4.8.gz").await.is_empty());
    assert_eq!(calls_to(&h, &timeframe()), 1, "the failure is cached");
    h.clock.advance_seconds(20);
    h.registry
        .answer(&timeframe(), FakeAnswer::Body("[]".to_owned()));
    h.registry.answer(
        &path(&["prerelease_specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    let _ = tuples_of(&h, "prerelease_specs.4.8.gz").await;
    assert_eq!(calls_to(&h, &timeframe()), 2);
    h.server.shutdown().await;
}

/// N6: N cold concurrent requests cause one fetch and one filter pass.
#[tokio::test]
async fn cold_concurrent_index_requests_share_one_build() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    let gate = common::Gate::new();
    h.registry.answer(
        &timeframe(),
        FakeAnswer::GatedMetadata {
            body: "[]".to_owned(),
            gate: Arc::clone(&gate),
        },
    );
    let url = h.server.url("/rubygems/specs.4.8.gz");
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            reqwest::get(url).await.unwrap().bytes().await.unwrap()
        }));
    }
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for _ in 0..8 {
        gate.release();
    }
    let mut bodies = Vec::new();
    for task in tasks {
        bodies.push(task.await.unwrap());
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(
        calls_to(&h, &path(&["specs.4.8.gz"])),
        1,
        "one upstream fetch and one filter pass"
    );
    assert_eq!(calls_to(&h, &timeframe()), 1, "and one recent list");
    h.server.shutdown().await;
}

/// N7: a cooldown beyond the 42 days the API can be asked for lists no unindexed tuple (fail
/// closed, documented), and asks nothing.
#[tokio::test]
async fn a_freeze_beyond_the_recent_horizon_lists_no_unindexed_tuple() {
    let h = harness("", 43 * DAY).await;
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    h.registry
        .answer(&timeframe(), FakeAnswer::Body("[]".to_owned()));
    assert!(tuples_of(&h, "specs.4.8.gz").await.is_empty());
    assert_eq!(calls_to(&h, &timeframe()), 0);
    h.server.shutdown().await;
}

/// N2 + N7: gems whose real name has capitals (RedCloth) download end to end (info, quick
/// gemspec, gem file) with the client's spelling upstream, while one project row serves every
/// spelling and policy keys stay lower-case.
#[tokio::test]
async fn mixed_case_gems_download_and_spellings_share_one_project_row() {
    let h = harness(
        r#"{"ecosystem":"rubygems","name":"blocked-gem","version":null,"reason":"malware"}"#,
        7 * DAY,
    )
    .await;
    let bytes = gem_bytes("redcloth");
    let spec = fixture("rack-3.2.8.gemspec.rz");
    h.registry.answer(
        &path(&["info", "RedCloth"]),
        FakeAnswer::Body(info(&[line("4.3.2", None, &bytes, Some(OLD))])),
    );
    h.registry.answer(
        &path(&["info", "redcloth"]),
        FakeAnswer::Body(info(&[line("4.3.2", None, &bytes, Some(OLD))])),
    );
    h.registry.answer(
        &path(&["gems", "RedCloth-4.3.2.gem"]),
        FakeAnswer::Bytes(bytes.clone()),
    );
    h.registry.answer(
        &path(&["quick", "Marshal.4.8", "RedCloth-4.3.2.gemspec.rz"]),
        FakeAnswer::Bytes(spec.clone()),
    );
    assert!(info_of(&h, "RedCloth").await.1.contains("4.3.2"));
    let quick = h
        .server
        .get("/rubygems/quick/Marshal.4.8/RedCloth-4.3.2.gemspec.rz")
        .await;
    assert_eq!(
        (
            quick.status().as_u16(),
            quick.bytes().await.unwrap().to_vec()
        ),
        (200, spec)
    );
    let gem = h.server.get("/rubygems/gems/RedCloth-4.3.2.gem").await;
    assert_eq!(
        (gem.status().as_u16(), gem.bytes().await.unwrap().to_vec()),
        (200, bytes.clone())
    );
    // Another spelling of the same gem reads (and is judged) as the same project.
    assert!(info_of(&h, "redcloth").await.1.contains("4.3.2"));
    h.registry.answer(
        &path(&["gems", "redcloth-4.3.2.gem"]),
        FakeAnswer::Bytes(bytes.clone()),
    );
    assert_eq!(
        h.server
            .get("/rubygems/gems/redcloth-4.3.2.gem")
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        h.server
            .get("/rubygems/gems/RedCloth-4.3.2.gem")
            .await
            .status()
            .as_u16(),
        200,
        "and the first spelling still works"
    );
    let known = h
        .server
        .app()
        .store()
        .list_known_projects_in(0, probation::policy::Ecosystem::RubyGems)
        .await
        .unwrap();
    assert_eq!(
        known,
        vec!["redcloth".to_owned()],
        "one stored project row for every spelling"
    );
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ recheck 2 (R1, R2, R5)

/// R1: a gem name has a handful of committed case spellings per registry; beyond the cap the
/// spelling is refused before any upstream fetch (reference rows are never reclaimed).
#[tokio::test]
async fn case_spellings_per_gem_are_capped() {
    let h = harness("", 0).await;
    let bytes = gem_bytes("d");
    let spellings = [
        "demo", "Demo", "dEmo", "deMo", "demO", "DEmo", "DeMo", "dEMo", "DEMO", "dEmO",
    ];
    for spelling in spellings {
        h.registry.answer(
            &path(&["info", spelling]),
            FakeAnswer::Body(info(&[line("1.0.0", None, &bytes, Some(OLD))])),
        );
    }
    let mut statuses = Vec::new();
    for spelling in spellings {
        statuses.push(info_of(&h, spelling).await.0);
    }
    assert_eq!(
        statuses,
        [200, 200, 200, 200, 404, 404, 404, 404, 404, 404],
        "four spellings, then refused"
    );
    assert_eq!(
        calls_to(&h, &path(&["info"])),
        4,
        "the refused spellings cost no upstream fetch"
    );
    // A spelling already committed keeps working.
    assert_eq!(info_of(&h, "Demo").await.0, 200);
    h.server.shutdown().await;
}

/// R2: the list is stamped when its crawl ends, so a crawl longer than the cache lifetime is
/// still reused by the next index build.
#[tokio::test]
async fn a_slow_crawl_is_stamped_when_it_ends() {
    let h = harness("", 7 * DAY).await;
    for file in ["specs.4.8.gz", "latest_specs.4.8.gz"] {
        h.registry.answer(
            &path(&[file]),
            FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
        );
    }
    let gate = common::Gate::new();
    h.registry.answer(
        &timeframe(),
        FakeAnswer::GatedMetadata {
            body: "[]".to_owned(),
            gate: Arc::clone(&gate),
        },
    );
    let url = h.server.url("/rubygems/specs.4.8.gz");
    let first = tokio::spawn(async move { reqwest::get(url).await.unwrap().status() });
    gate.wait_until_reached().await;
    h.clock.advance_seconds(61);
    gate.release();
    assert_eq!(first.await.unwrap().as_u16(), 200);
    assert_eq!(
        h.server
            .get("/rubygems/latest_specs.4.8.gz")
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        calls_to(&h, &timeframe()),
        1,
        "the second index build reuses the list that took longer than its lifetime"
    );
    h.server.shutdown().await;
}

/// R2: a client that gives up does not drop the crawl; it finishes and fills the cache.
#[tokio::test]
async fn a_dropped_request_does_not_drop_the_crawl() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    let gate = common::Gate::new();
    h.registry.answer(
        &timeframe(),
        FakeAnswer::GatedMetadata {
            body: "[]".to_owned(),
            gate: Arc::clone(&gate),
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(300))
        .build()
        .unwrap();
    let url = h.server.url("/rubygems/specs.4.8.gz");
    let waiter = tokio::spawn(async move { client.get(url).send().await.is_err() });
    gate.wait_until_reached().await;
    assert!(waiter.await.unwrap(), "the client gave up");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    gate.release();
    let response = h.server.get("/rubygems/specs.4.8.gz").await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        calls_to(&h, &timeframe()),
        1,
        "the abandoned crawl finished and served the next request"
    );
    h.server.shutdown().await;
}

/// R5: more rows than the cap fail closed after a bounded number of pages.
#[tokio::test]
async fn a_recent_list_over_the_row_cap_fails_closed() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    let row =
        format!(r#"{{"name":"a","version":"1","platform":"ruby","version_created_at":"{YOUNG}"}}"#);
    let page = format!("[{}]", vec![row; 16_000].join(","));
    h.registry
        .answer(&format!("{}?page=*", timeframe()), FakeAnswer::Body(page));
    assert!(tuples_of(&h, "specs.4.8.gz").await.is_empty());
    assert_eq!(
        calls_to(&h, &timeframe()),
        4,
        "60,000 rows are exceeded on the fourth page of 16,000"
    );
    h.server.shutdown().await;
}

/// R5: a crawl over its deadline fails closed (the deadline is shortened, nothing sleeps for minutes).
#[tokio::test]
async fn a_recent_crawl_over_its_deadline_fails_closed() {
    let h = harness("", 7 * DAY).await;
    h.server
        .app()
        .set_rubygems_recent_deadline(std::time::Duration::from_millis(150));
    h.registry.answer(
        &path(&["specs.4.8.gz"]),
        FakeAnswer::Bytes(fixture("full-index-slice.4.8.gz")),
    );
    let gate = common::Gate::new();
    h.registry.answer(
        &timeframe(),
        FakeAnswer::GatedMetadata {
            body: "[]".to_owned(),
            gate: Arc::clone(&gate),
        },
    );
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        h.server.get("/rubygems/specs.4.8.gz"),
    )
    .await
    .expect("the deadline ends the crawl");
    assert_eq!(response.status().as_u16(), 200);
    assert!(
        ruby_tuples(&response.bytes().await.unwrap()).is_empty(),
        "no date, nothing unindexed listed"
    );
    gate.release();
    h.server.shutdown().await;
}
