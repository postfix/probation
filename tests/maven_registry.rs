//! Row 21: Maven repository protection, end to end through the firewall against an in-process `FakeRegistry` and a clock the
//! test moves by hand. The real client witness is tests/maven_native.rs (`mvn`), the shared-service forms are
//! tests/maven_service_read.rs and tests/maven_service_write.rs.

mod common;

use std::sync::Arc;

use common::maven::{self, PUBLISH, REPO, at, http_date, metadata, serve_version};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::config::Config;
use probation::upstream::{OriginSet, Transport};
use tempfile::TempDir;
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const DAY: u64 = 86_400;
const OLD: &str = "2025-01-01T00:00:00Z";
const YOUNG: &str = "2026-04-05T12:00:00Z";

fn origins() -> OriginSet {
    fake_origins().with_maven(Url::parse(REPO).unwrap(), Url::parse(PUBLISH).unwrap())
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

fn versions_of(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("<version>")?
                .strip_suffix("</version>")
        })
        .map(str::to_owned)
        .collect()
}

fn tag_of(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{tag}>"))? + start;
    Some(body[start..end].to_owned())
}

/// `org.demo:lib` with 1.0 and 1.1 old and 2.0 young, as the repository lists it.
fn serve_lib(h: &Harness) {
    h.registry.answer(
        &at("org/demo/lib/maven-metadata.xml"),
        FakeAnswer::Body(metadata(
            "org.demo",
            "lib",
            "2.0",
            "2.0",
            &["1.0", "1.1", "2.0"],
        )),
    );
    serve_version(&h.registry, "org.demo", "lib", "1.0", Some(OLD));
    serve_version(&h.registry, "org.demo", "lib", "1.1", Some(OLD));
    serve_version(&h.registry, "org.demo", "lib", "2.0", Some(YOUNG));
}

// ------------------------------------------------------------------ metadata

#[tokio::test]
async fn metadata_withholds_young_versions_names_the_newest_allowed_and_rebuilds_every_checksum() {
    let h = harness("", 7 * DAY).await;
    serve_lib(&h);
    // The repository HAS signatures of its own document: they sign other bytes than the filtered ones and are never relayed.
    h.registry.answer(
        &at("org/demo/lib/maven-metadata.xml.asc"),
        FakeAnswer::Body("-----BEGIN PGP SIGNATURE-----".to_owned()),
    );
    h.registry.answer(
        &at("org/demo/lib/maven-metadata.xml.asc.sha1"),
        FakeAnswer::Body("00".repeat(20)),
    );
    let (status, body) = text_of(&h, "/maven/org/demo/lib/maven-metadata.xml").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(versions_of(&body), ["1.0", "1.1"], "{body}");
    assert_eq!(tag_of(&body, "latest").as_deref(), Some("1.1"));
    assert_eq!(tag_of(&body, "release").as_deref(), Some("1.1"));
    assert_eq!(
        tag_of(&body, "lastUpdated").as_deref(),
        Some("20260405120000"),
        "what is not changed stays as the repository wrote it"
    );
    assert!(
        body.starts_with(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>org.demo</groupId>"
        ),
        "{body}"
    );
    // Every checksum file is the checksum of what was served, not of what the repository holds.
    for (ext, expected) in [
        ("sha1", common::maven::sha1_hex(body.as_bytes())),
        (
            "md5",
            probation::maven::coords::Sum::Md5.hex(body.as_bytes()),
        ),
        (
            "sha256",
            probation::maven::coords::Sum::Sha256.hex(body.as_bytes()),
        ),
        (
            "sha512",
            probation::maven::coords::Sum::Sha512.hex(body.as_bytes()),
        ),
    ] {
        let (status, sum) =
            text_of(&h, &format!("/maven/org/demo/lib/maven-metadata.xml.{ext}")).await;
        assert_eq!((status, sum), (200, expected), "{ext}");
    }
    // A signature of the repository's bytes does not sign these: it is not offered (nothing asked of the repository).
    let before = h.registry.calls().len();
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/maven-metadata.xml.asc")
            .await
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/maven-metadata.xml.asc.sha1")
            .await
            .status()
            .as_u16(),
        404
    );
    assert!(h.registry.calls().len() >= before);
    assert_eq!(calls_to(&h, "lib-2.0.jar"), 0);
    h.server.shutdown().await;
}

#[tokio::test]
async fn unchanged_metadata_is_byte_identical_and_its_signature_is_the_repositorys() {
    let h = harness("", 7 * DAY).await;
    let original = metadata("org.demo", "lib", "1.1", "1.1", &["1.0", "1.1"]);
    h.registry.answer(
        &at("org/demo/lib/maven-metadata.xml"),
        FakeAnswer::Body(original.clone()),
    );
    h.registry.answer(
        &at("org/demo/lib/maven-metadata.xml.asc"),
        FakeAnswer::Body("-----BEGIN PGP SIGNATURE-----".to_owned()),
    );
    serve_version(&h.registry, "org.demo", "lib", "1.0", Some(OLD));
    serve_version(&h.registry, "org.demo", "lib", "1.1", Some(OLD));
    let (status, body) = text_of(&h, "/maven/org/demo/lib/maven-metadata.xml").await;
    assert_eq!((status, body.as_str()), (200, original.as_str()));
    assert_eq!(
        text_of(&h, "/maven/org/demo/lib/maven-metadata.xml.asc").await,
        (200, "-----BEGIN PGP SIGNATURE-----".to_owned())
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_version_that_ages_is_listed_once_its_cooldown_has_passed() {
    let h = harness("", 7 * DAY).await;
    serve_lib(&h);
    let (_, body) = text_of(&h, "/maven/org/demo/lib/maven-metadata.xml").await;
    assert_eq!(versions_of(&body), ["1.0", "1.1"]);
    h.clock.advance_seconds(8 * DAY as i64);
    let (_, body) = text_of(&h, "/maven/org/demo/lib/maven-metadata.xml").await;
    assert_eq!(versions_of(&body), ["1.0", "1.1", "2.0"]);
    assert_eq!(tag_of(&body, "release").as_deref(), Some("2.0"));
    h.server.shutdown().await;
}

#[tokio::test]
async fn when_every_version_is_withheld_latest_and_release_go_and_the_listing_is_empty() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &at("org/demo/new/maven-metadata.xml"),
        FakeAnswer::Body(metadata("org.demo", "new", "1.0", "1.0", &["1.0"])),
    );
    serve_version(&h.registry, "org.demo", "new", "1.0", Some(YOUNG));
    let (status, body) = text_of(&h, "/maven/org/demo/new/maven-metadata.xml").await;
    assert_eq!(status, 200);
    assert!(
        versions_of(&body).is_empty() && !body.contains("<latest>") && !body.contains("<release>"),
        "{body}"
    );
    probation::maven::meta::read(body.as_bytes(), 10)
        .expect("the filtered document is still a metadata document");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ files

#[tokio::test]
async fn every_file_of_an_allowed_version_is_served_exactly_and_every_file_of_a_held_one_is_refused_unfetched()
 {
    let h = harness("", 7 * DAY).await;
    serve_lib(&h);
    for file in [
        "lib-1.0.pom",
        "lib-1.0.jar",
        "lib-1.0-sources.jar",
        "lib-1.0.jar.sha1",
    ] {
        let response = h
            .server
            .get(&format!("/maven/org/demo/lib/1.0/{file}"))
            .await;
        assert_eq!(response.status().as_u16(), 200, "{file}");
    }
    let jar = h
        .server
        .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(
        jar.to_vec(),
        maven::jar("lib", "1.0"),
        "delivered exactly as the repository sent it"
    );
    assert_eq!(
        text_of(&h, "/maven/org/demo/lib/1.0/lib-1.0.jar.sha1")
            .await
            .1,
        common::maven::sha1_hex(&maven::jar("lib", "1.0"))
    );
    for file in [
        "lib-2.0.pom",
        "lib-2.0.jar",
        "lib-2.0-sources.jar",
        "lib-2.0.jar.sha1",
    ] {
        let response = h
            .server
            .get(&format!("/maven/org/demo/lib/2.0/{file}"))
            .await;
        assert_eq!(response.status().as_u16(), 403, "{file}");
        assert!(
            response.headers().contains_key("retry-after"),
            "{file}: a hold names its deadline"
        );
    }
    assert_eq!(
        calls_to(&h, "lib-2.0.jar"),
        0,
        "a held version's files are never fetched"
    );
    assert_eq!(calls_to(&h, "lib-2.0-sources"), 0);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_made_up_file_name_of_a_real_version_is_a_404_and_makes_no_reference() {
    let h = harness("", 0).await;
    serve_lib(&h);
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0-nothing.jar")
            .await
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/9.9/lib-9.9.jar")
            .await
            .status()
            .as_u16(),
        404,
        "a version the repository has not"
    );
    let rows = h
        .server
        .app()
        .store()
        .count_project_references_in(0, probation::policy::Ecosystem::Maven, "org.demo:lib")
        .await
        .unwrap();
    assert_eq!(
        rows, 1,
        "only the POM anchor of 1.0 exists, no row for the made-up file"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_blocked_package_or_version_is_refused_before_any_upstream_call_and_case_is_identity() {
    let blocked = r#"{"ecosystem":"maven","name":"org.evil:Bad","version":null,"reason":"malware"},{"ecosystem":"maven","name":"org.demo:lib","version":"1.1","reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    serve_lib(&h);
    serve_version(&h.registry, "org.evil", "Bad", "1.0", Some(OLD));
    serve_version(&h.registry, "org.evil", "bad", "1.0", Some(OLD));
    let before = h.registry.calls().len();
    assert_eq!(
        h.server
            .get("/maven/org/evil/Bad/maven-metadata.xml")
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        h.server
            .get("/maven/org/evil/Bad/1.0/Bad-1.0.jar")
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        h.server
            .get("/maven/org/evil/Bad/1.0/Bad-1.0.pom.sha1")
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.1/lib-1.1.jar")
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        h.registry.calls().len(),
        before,
        "locally conclusive: upstream is never asked"
    );
    // `bad` is another artifact than `Bad`: the repository is case-sensitive and so is the identity.
    assert_eq!(
        h.server
            .get("/maven/org/evil/bad/1.0/bad-1.0.jar")
            .await
            .status()
            .as_u16(),
        200
    );
    let (_, body) = text_of(&h, "/maven/org/demo/lib/maven-metadata.xml").await;
    assert_eq!(
        versions_of(&body),
        ["1.0", "2.0"],
        "the blocked version is absent from the listing: {body}"
    );
    assert_eq!(tag_of(&body, "latest").as_deref(), Some("2.0"));
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_version_with_no_date_waits_on_its_first_seen_time() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &at("org/demo/lib/maven-metadata.xml"),
        FakeAnswer::Body(metadata("org.demo", "lib", "1.0", "1.0", &["1.0"])),
    );
    serve_version(&h.registry, "org.demo", "lib", "1.0", None);
    let (_, body) = text_of(&h, "/maven/org/demo/lib/maven-metadata.xml").await;
    assert!(
        versions_of(&body).is_empty(),
        "no Last-Modified: never dated by invention: {body}"
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
            .await
            .status()
            .as_u16(),
        403
    );
    h.clock.advance_seconds(8 * DAY as i64);
    let (_, body) = text_of(&h, "/maven/org/demo/lib/maven-metadata.xml").await;
    assert_eq!(
        versions_of(&body),
        ["1.0"],
        "released once the committed first-seen time has aged"
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
            .await
            .status()
            .as_u16(),
        200
    );
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

#[tokio::test]
async fn changed_bytes_of_a_pinned_file_are_refused_once_the_stored_copy_is_gone() {
    for file in ["lib-1.0.jar", "lib-1.0.pom", "lib-1.0.jar.sha1"] {
        let h = harness("", 0).await;
        serve_lib(&h);
        let url = format!("/maven/org/demo/lib/1.0/{file}");
        let first = h.server.get(&url).await;
        assert_eq!(first.status().as_u16(), 200, "{file}");
        let original = first.bytes().await.unwrap().to_vec();
        assert!(!content_files(&h).is_empty());
        for stored in content_files(&h) {
            std::fs::remove_file(stored).unwrap();
        }
        h.registry.answer(
            &at(&format!("org/demo/lib/1.0/{file}")),
            FakeAnswer::Dated {
                body: [original.clone(), b"tampered".to_vec()].concat(),
                last_modified: http_date(OLD),
            },
        );
        let second = h.server.get(&url).await;
        assert_eq!(
            second.status().as_u16(),
            502,
            "{file}: the changed bytes are refused"
        );
        assert!(
            !String::from_utf8_lossy(&second.bytes().await.unwrap()).contains("tampered"),
            "{file}"
        );
        h.server.shutdown().await;
    }
}

// ------------------------------------------------------------------ snapshots

#[tokio::test]
async fn a_snapshot_build_ages_by_its_own_date_and_the_pointer_falls_back_to_the_newest_allowed_build()
 {
    let h = harness("", 7 * DAY).await;
    let builds = ["20250101.120000-1", "20260405.120000-2"];
    h.registry.answer(
        &at("org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml"),
        FakeAnswer::Body(maven::snapshot_metadata(
            "org.demo",
            "snap",
            "1.0-SNAPSHOT",
            &builds,
        )),
    );
    for (build, date) in [(builds[0], OLD), (builds[1], YOUNG)] {
        let file = format!("snap-1.0-{build}");
        h.registry.answer(
            &at(&format!("org/demo/snap/1.0-SNAPSHOT/{file}.pom")),
            FakeAnswer::Dated {
                body: maven::pom("org.demo", "snap", "1.0-SNAPSHOT").into_bytes(),
                last_modified: http_date(date),
            },
        );
        h.registry.answer(
            &at(&format!("org/demo/snap/1.0-SNAPSHOT/{file}.jar")),
            FakeAnswer::Dated {
                body: maven::jar("snap", build),
                last_modified: http_date(date),
            },
        );
    }
    let (status, body) = text_of(&h, "/maven/org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml").await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("1.0-20250101.120000-1") && !body.contains("1.0-20260405.120000-2"),
        "{body}"
    );
    assert_eq!(
        tag_of(&body, "timestamp").as_deref(),
        Some("20250101.120000")
    );
    assert_eq!(tag_of(&body, "buildNumber").as_deref(), Some("1"));
    assert_eq!(
        h.server
            .get("/maven/org/demo/snap/1.0-SNAPSHOT/snap-1.0-20250101.120000-1.jar")
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/snap/1.0-SNAPSHOT/snap-1.0-20260405.120000-2.jar")
            .await
            .status()
            .as_u16(),
        403
    );
    assert_eq!(calls_to(&h, "20260405.120000-2.jar"), 0);
    // The artifact-level listing names the directory, which is not itself aged.
    h.registry.answer(
        &at("org/demo/snap/maven-metadata.xml"),
        FakeAnswer::Body(metadata(
            "org.demo",
            "snap",
            "1.0-SNAPSHOT",
            "",
            &["1.0-SNAPSHOT"],
        )),
    );
    let (_, listing) = text_of(&h, "/maven/org/demo/snap/maven-metadata.xml").await;
    assert_eq!(versions_of(&listing), ["1.0-SNAPSHOT"]);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_snapshot_whose_only_build_is_young_is_refused_with_its_hold() {
    let h = harness("", 7 * DAY).await;
    let builds = ["20260405.120000-1"];
    h.registry.answer(
        &at("org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml"),
        FakeAnswer::Body(maven::snapshot_metadata(
            "org.demo",
            "snap",
            "1.0-SNAPSHOT",
            &builds,
        )),
    );
    h.registry.answer(
        &at("org/demo/snap/1.0-SNAPSHOT/snap-1.0-20260405.120000-1.pom"),
        FakeAnswer::Dated {
            body: maven::pom("org.demo", "snap", "1.0-SNAPSHOT").into_bytes(),
            last_modified: http_date(YOUNG),
        },
    );
    let response = h
        .server
        .get("/maven/org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml")
        .await;
    assert_eq!(response.status().as_u16(), 403);
    assert!(response.headers().contains_key("retry-after"));
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ plugin prefixes and the archetype catalog

#[tokio::test]
async fn plugin_group_metadata_lists_no_plugin_a_policy_blocks() {
    let blocked = r#"{"ecosystem":"maven","name":"org.demo.plugins:evil-maven-plugin","version":null,"reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    h.registry.answer(
        &at("org/demo/plugins/maven-metadata.xml"),
        FakeAnswer::Body(maven::plugin_metadata(&[
            ("Good", "good", "good-maven-plugin"),
            ("Evil", "evil", "evil-maven-plugin"),
        ])),
    );
    let (status, body) = text_of(&h, "/maven/org/demo/plugins/maven-metadata.xml").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("good-maven-plugin") && !body.contains("evil-maven-plugin"),
        "{body}"
    );
    probation::maven::meta::read(body.as_bytes(), 10).unwrap();
    h.server.shutdown().await;
}

#[tokio::test]
async fn the_archetype_catalog_drops_what_a_policy_blocks() {
    let blocked = r#"{"ecosystem":"maven","name":"org.evil:arch","version":null,"reason":"malware"},{"ecosystem":"maven","name":"org.demo:arch","version":"2.0","reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    let entry = |g: &str, a: &str, v: &str| {
        format!(
            "    <archetype>\n      <groupId>{g}</groupId>\n      <artifactId>{a}</artifactId>\n      <version>{v}</version>\n      <description>d</description>\n    </archetype>\n"
        )
    };
    let with_repository = entry("org.demo", "other", "1.0").replace(
        "    </archetype>",
        "      <repository>https://direct.invalid/maven</repository>\n    </archetype>",
    );
    let catalog = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<archetype-catalog>\n  <archetypes>\n{}{}{}{}  </archetypes>\n</archetype-catalog>\n",
        entry("org.demo", "arch", "1.0"),
        entry("org.demo", "arch", "2.0"),
        entry("org.evil", "arch", "1.0"),
        with_repository
    );
    h.registry
        .answer(&at("archetype-catalog.xml"), FakeAnswer::Body(catalog));
    let (status, body) = text_of(&h, "/maven/archetype-catalog.xml").await;
    assert_eq!(status, 200);
    assert_eq!(body.matches("<archetype>").count(), 2, "{body}");
    assert!(
        body.contains("<version>1.0</version>")
            && !body.contains("org.evil")
            && !body.contains("<version>2.0</version>"),
        "{body}"
    );
    assert!(
        body.contains("<artifactId>other</artifactId>")
            && !body.contains("direct.invalid")
            && !body.contains("<repository>"),
        "an entry's own repository URL is removed, the entry stays: {body}"
    );
    probation::maven::meta::read(body.as_bytes(), 10)
        .expect("the filtered catalog is still the same strict format");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ strict inputs

#[tokio::test]
async fn a_document_with_a_doctype_or_an_entity_is_a_502_and_never_expanded_or_fetched() {
    let h = harness("", 0).await;
    let evil = "<?xml version=\"1.0\"?>\n<!DOCTYPE metadata [<!ENTITY x SYSTEM \"https://attacker.invalid/x\">]>\n<metadata><versioning><versions><version>&x;</version></versions></versioning></metadata>";
    h.registry.answer(
        &at("org/demo/lib/maven-metadata.xml"),
        FakeAnswer::Body(evil.to_owned()),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/maven-metadata.xml")
            .await
            .status()
            .as_u16(),
        502
    );
    assert_eq!(calls_to(&h, "attacker"), 0);
    h.registry.answer(&at("org/demo/lib2/maven-metadata.xml"), FakeAnswer::Body("<metadata><versioning><versions><version>&bogus;</version></versions></versioning></metadata>".to_owned()));
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib2/maven-metadata.xml")
            .await
            .status()
            .as_u16(),
        502
    );
    h.registry.answer(
        &at("org/demo/lib3/maven-metadata.xml"),
        FakeAnswer::Body("<html>not metadata</html>".to_owned()),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib3/maven-metadata.xml")
            .await
            .status()
            .as_u16(),
        502
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn paths_that_are_not_one_canonical_spelling_are_404_before_any_upstream_call() {
    let h = harness("", 0).await;
    serve_lib(&h);
    let before = h.registry.calls().len();
    for bad in [
        "/maven/org/demo/lib/1.0/lib-2.0.jar",
        "/maven/org.demo/lib/1.0/lib-1.0.jar",
        "/maven/org/demo/lib/1.0/",
        "/maven/org/demo/lib/",
        "/maven/org/demo/lib/maven-metadata.xml?x=1",
        "/maven/org/demo/lib/maven-metadata.xml.bad",
        "/maven/org//demo/lib/1.0/lib-1.0.jar",
        "/maven/org/demo/lib/1.0/lib-1.0.jar/x",
        "/maven/maven-metadata.xml",
    ] {
        assert_eq!(h.server.get(bad).await.status().as_u16(), 404, "{bad}");
    }
    assert_eq!(
        h.server
            .raw_get_status("/maven/org/demo/lib/%2e%2e/lib/1.0/lib-1.0.jar")
            .await,
        404,
        "an encoded dot segment is no directory"
    );
    assert_eq!(h.registry.calls().len(), before);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_large_listing_is_not_refused_before_its_cap_and_the_dating_fan_out_settles_across_requests()
 {
    let h = harness("", 7 * DAY).await;
    let versions: Vec<String> = (0..2100).map(|n| format!("1.{n}")).collect();
    let refs: Vec<&str> = versions.iter().map(String::as_str).collect();
    h.registry.answer(
        &at("org/demo/big/maven-metadata.xml"),
        FakeAnswer::Body(metadata("org.demo", "big", "1.2099", "1.2099", &refs)),
    );
    for version in &versions {
        h.registry.answer(
            &at(&format!("org/demo/big/{version}/big-{version}.pom")),
            FakeAnswer::Dated {
                body: maven::pom("org.demo", "big", version).into_bytes(),
                last_modified: http_date(OLD),
            },
        );
    }
    let (_, first) = text_of(&h, "/maven/org/demo/big/maven-metadata.xml").await;
    assert_eq!(
        versions_of(&first).len(),
        probation::maven::serve::DATE_CAP,
        "newest first, bounded before the first call"
    );
    assert!(
        versions_of(&first).contains(&"1.2099".to_owned())
            && !versions_of(&first).contains(&"1.0".to_owned())
    );
    let (_, second) = text_of(&h, "/maven/org/demo/big/maven-metadata.xml").await;
    assert_eq!(
        versions_of(&second).len(),
        2100,
        "the dates are committed, so the next request settles the rest"
    );
    let before = calls_to(&h, ".pom");
    let (_, third) = text_of(&h, "/maven/org/demo/big/maven-metadata.xml").await;
    assert_eq!(versions_of(&third).len(), 2100);
    assert_eq!(
        calls_to(&h, ".pom"),
        before,
        "a settled listing asks for no POM"
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn range_and_head_work_on_an_allowed_file_and_a_held_one_is_refused_for_both() {
    let h = harness("", 7 * DAY).await;
    serve_lib(&h);
    let head = h.server.head("/maven/org/demo/lib/1.0/lib-1.0.jar").await;
    assert_eq!(head.status().as_u16(), 200);
    let ranged = h
        .server
        .get_with_headers(
            "/maven/org/demo/lib/1.0/lib-1.0.jar",
            &[("Range", "bytes=0-3")],
        )
        .await;
    assert_eq!(ranged.status().as_u16(), 206);
    assert_eq!(ranged.bytes().await.unwrap().len(), 4);
    assert_eq!(
        h.server
            .head("/maven/org/demo/lib/2.0/lib-2.0.jar")
            .await
            .status()
            .as_u16(),
        403
    );
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_standalone_firewall_has_no_deploy_route() {
    let h = harness("", 0).await;
    let client = reqwest::Client::new();
    for method in ["PUT", "DELETE", "POST"] {
        let response = client
            .request(
                method.parse().unwrap(),
                h.server.url("/maven/org/demo/lib/1.0/lib-1.0.jar"),
            )
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 405, "{method}");
    }
    h.server.shutdown().await;
}

/// Refreshes are bounded per registry: with the registry's four places taken by slow documents, a fifth artifact's listing waits
/// (it does not start a fifth upstream read), and every one completes once the first are released.
#[tokio::test]
async fn one_registry_never_holds_more_than_its_refresh_places() {
    let h = harness("", 0).await;
    let gate = common::Gate::new();
    for n in 0..6 {
        h.registry.answer(
            &at(&format!("org/demo/slow{n}/maven-metadata.xml")),
            FakeAnswer::GatedMetadata {
                body: metadata("org.demo", &format!("slow{n}"), "1.0", "1.0", &[]),
                gate: Arc::clone(&gate),
            },
        );
    }
    let base = h.server.url("/maven");
    let tasks: Vec<_> = (0..6)
        .map(|n| {
            let url = format!("{base}/org/demo/slow{n}/maven-metadata.xml");
            tokio::spawn(async move { reqwest::get(url).await.unwrap().status().as_u16() })
        })
        .collect();
    for _ in 0..4 {
        gate.wait_until_reached().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        calls_to(&h, "/maven-metadata.xml"),
        4,
        "the fifth and sixth wait for a place of this registry"
    );
    for _ in 0..6 {
        gate.release();
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 200);
    }
    assert_eq!(calls_to(&h, "/maven-metadata.xml"), 6);
    h.server.shutdown().await;
}

/// The rows a project may hold are bounded (five times `max_references_per_project`): past the bound a file of one more unit is a
/// 503 and the files that have rows keep being served; a listing is dated only up to the bound.
#[tokio::test]
async fn a_project_at_its_row_bound_refuses_the_file_of_one_more_version_and_keeps_serving_the_rest()
 {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), "", 0);
    config.max_references_per_project = std::num::NonZeroU32::new(1).unwrap();
    let registry = FakeRegistry::new();
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        origins(),
    )
    .await;
    let versions = ["1.0", "1.1", "1.2", "1.3"];
    registry.answer(
        &at("org/demo/lib/maven-metadata.xml"),
        FakeAnswer::Body(metadata("org.demo", "lib", "1.3", "1.3", &versions)),
    );
    for version in versions {
        serve_version(&registry, "org.demo", "lib", version, Some(OLD));
    }
    let status = |path: &str| {
        let path = path.to_owned();
        let server = &server;
        async move { server.get(&path).await.status().as_u16() }
    };
    assert_eq!(status("/maven/org/demo/lib/1.0/lib-1.0.jar").await, 200);
    assert_eq!(status("/maven/org/demo/lib/1.1/lib-1.1.jar").await, 200);
    // Five rows exist (an anchor and a jar for each of two versions, and the third version's anchor): the next file is refused.
    assert_eq!(
        status("/maven/org/demo/lib/1.2/lib-1.2.jar").await,
        503,
        "the project is at its row bound"
    );
    assert_eq!(
        status("/maven/org/demo/lib/1.0/lib-1.0.jar").await,
        200,
        "files that have rows are still served"
    );
    assert_eq!(
        status("/maven/org/demo/lib/1.1/lib-1.1.pom").await,
        200,
        "so are the anchors"
    );
    assert_eq!(
        status("/maven/org/demo/lib/maven-metadata.xml").await,
        200,
        "a listing is still served"
    );
    server.shutdown().await;
}

// ------------------------------------------------------------------ fix round (reviews/slice-21)

async fn bounded_harness(rows: u32) -> (TestServer, Arc<FakeRegistry>, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), "", 0);
    config.max_references_per_project = std::num::NonZeroU32::new(rows).unwrap();
    let registry = FakeRegistry::new();
    let server = TestServer::start_with_upstream(
        config,
        TestClock::at_rfc3339(NOW).shared(),
        Arc::clone(&registry) as Arc<dyn Transport>,
        origins(),
    )
    .await;
    (server, registry, dir)
}

/// S21-1: the row bound is hard. Past it the POM of a fresh version makes no anchor row either and is a 503.
#[tokio::test]
async fn the_pom_of_a_fresh_version_past_the_row_bound_is_a_503_and_makes_no_row() {
    let (server, registry, _dir) = bounded_harness(1).await;
    for version in ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"] {
        serve_version(&registry, "org.demo", "lib", version, Some(OLD));
    }
    let rows = || async {
        server
            .app()
            .store()
            .count_project_references_in(0, probation::policy::Ecosystem::Maven, "org.demo:lib")
            .await
            .unwrap()
    };
    for pom in ["1.0", "1.1", "1.2", "1.3", "1.4"] {
        assert_eq!(
            server
                .get(&format!("/maven/org/demo/lib/{pom}/lib-{pom}.pom"))
                .await
                .status()
                .as_u16(),
            200,
            "{pom}: under the bound"
        );
    }
    assert_eq!(rows().await, 5, "five anchors: the bound of five times one");
    for pom in ["1.5", "1.6"] {
        assert_eq!(
            server
                .get(&format!("/maven/org/demo/lib/{pom}/lib-{pom}.pom"))
                .await
                .status()
                .as_u16(),
            503,
            "{pom}: at the bound a new anchor is refused"
        );
    }
    assert_eq!(rows().await, 5, "and the count stays");
    assert_eq!(
        server
            .get("/maven/org/demo/lib/1.0/lib-1.0.pom")
            .await
            .status()
            .as_u16(),
        200,
        "an anchor that has its row is still served"
    );
    server.shutdown().await;
}

/// S21-2: documents with the most entries the bounds allow are answered in bounded time (hash lookups, no quadratic scans).
#[tokio::test]
async fn a_hostile_snapshot_document_and_catalog_of_a_hundred_thousand_entries_are_answered_fast() {
    let h = harness("", 7 * DAY).await;
    let builds: Vec<String> = (0..100_000u32)
        .map(|n| format!("{:08}.{:06}-{}", 20_000_000 + n / 1000, n % 1000, n + 1))
        .collect();
    let entries: String = builds.iter().map(|b| format!("<snapshotVersion><extension>jar</extension><value>1.0-{b}</value></snapshotVersion>")).collect();
    let (stamp, number) = builds.last().unwrap().split_once('-').unwrap();
    let doc = format!(
        "<metadata><groupId>org.demo</groupId><artifactId>snap</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>{stamp}</timestamp><buildNumber>{number}</buildNumber></snapshot><snapshotVersions>{entries}</snapshotVersions></versioning></metadata>"
    );
    h.registry.answer(
        &at("org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml"),
        FakeAnswer::Body(doc),
    );
    let started = std::time::Instant::now();
    let status = h
        .server
        .get("/maven/org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml")
        .await
        .status()
        .as_u16();
    let snapshot_time = started.elapsed();
    assert!(matches!(status, 200 | 403), "{status}");
    assert!(
        snapshot_time < std::time::Duration::from_secs(30),
        "a 100,000-build document took {snapshot_time:?}"
    );
    let blocked: String = (0..100_000).map(|n| format!("<archetype><groupId>bad group {n}</groupId><artifactId>a</artifactId><version>1</version><repository>https://direct.invalid/{n}</repository></archetype>")).collect();
    h.registry.answer(
        &at("archetype-catalog.xml"),
        FakeAnswer::Body(format!(
            "<archetype-catalog><archetypes>{blocked}</archetypes></archetype-catalog>"
        )),
    );
    let started = std::time::Instant::now();
    let answer = h.server.get("/maven/archetype-catalog.xml").await;
    assert_eq!(answer.status().as_u16(), 200);
    let body = answer.text().await.unwrap();
    let catalog_time = started.elapsed();
    assert!(
        !body.contains("<archetype>") && !body.contains("direct.invalid"),
        "every entry was cut"
    );
    assert!(
        catalog_time < std::time::Duration::from_secs(5),
        "a 100,000-entry catalog took {catalog_time:?}"
    );
    h.server.shutdown().await;
}

/// S21-4: a listed version with no POM (a bare jar of a private repository) is not cut for ever: it ages from its first sight.
#[tokio::test]
async fn a_listed_version_with_no_pom_ages_from_its_first_seen_time() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(
        &at("org/demo/bare/maven-metadata.xml"),
        FakeAnswer::Body(metadata("org.demo", "bare", "1.0", "1.0", &["1.0"])),
    );
    h.registry.answer(
        &at("org/demo/bare/1.0/bare-1.0.jar"),
        FakeAnswer::Bytes(maven::jar("bare", "1.0")),
    );
    let (_, body) = text_of(&h, "/maven/org/demo/bare/maven-metadata.xml").await;
    assert!(
        versions_of(&body).is_empty(),
        "held for a whole cooldown: {body}"
    );
    // (No file is asked for meanwhile: the listing alone starts the clock.)
    h.clock.advance_seconds(8 * DAY as i64);
    let (_, body) = text_of(&h, "/maven/org/demo/bare/maven-metadata.xml").await;
    assert_eq!(
        versions_of(&body),
        ["1.0"],
        "listed once the first-seen time has aged: {body}"
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/bare/1.0/bare-1.0.jar")
            .await
            .status()
            .as_u16(),
        200
    );
    h.server.shutdown().await;
}

/// S21-7: a comment may hold an ampersand, and a document that declares ISO-8859-1 is read: served as the repository wrote it when
/// nothing is removed, as UTF-8 (declared so) when something is.
#[tokio::test]
async fn comments_with_ampersands_and_latin1_documents_are_read() {
    let h = harness("", 7 * DAY).await;
    let latin1 = |versions: &str| {
        format!("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<metadata>\n<!-- R&D caf\u{e9} -->\n<groupId>org.demo</groupId>\n<artifactId>lat</artifactId>\n<versioning>\n<latest>1.1</latest>\n<release>1.1</release>\n<versions>\n{versions}</versions>\n</versioning>\n</metadata>\n").chars().map(|c| c as u32 as u8).collect::<Vec<u8>>()
    };
    h.registry.answer(
        &at("org/demo/lat/maven-metadata.xml"),
        FakeAnswer::Bytes(latin1("<version>1.0</version>\n<version>1.1</version>\n")),
    );
    for v in ["1.0", "1.1"] {
        serve_version(&h.registry, "org.demo", "lat", v, Some(OLD));
    }
    let original = h
        .server
        .get("/maven/org/demo/lat/maven-metadata.xml")
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(
        original.to_vec(),
        latin1("<version>1.0</version>\n<version>1.1</version>\n"),
        "nothing removed: the repository's own bytes"
    );
    // The same document of an artifact whose 1.1 is young: something is removed, so it is served as UTF-8 and says so.
    h.registry.answer(
        &at("org/demo/lat2/maven-metadata.xml"),
        FakeAnswer::Bytes(latin1("<version>1.0</version>\n<version>1.1</version>\n")),
    );
    serve_version(&h.registry, "org.demo", "lat2", "1.0", Some(OLD));
    serve_version(&h.registry, "org.demo", "lat2", "1.1", Some(YOUNG));
    let (status, body) = text_of(&h, "/maven/org/demo/lat2/maven-metadata.xml").await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("encoding=\"UTF-8\"")
            && body.contains("caf\u{e9}")
            && !body.contains("<version>1.1</version>"),
        "{body}"
    );
    let sum = text_of(&h, "/maven/org/demo/lat2/maven-metadata.xml.sha1")
        .await
        .1;
    assert_eq!(
        sum,
        common::maven::sha1_hex(body.as_bytes()),
        "the checksum is of the UTF-8 document served"
    );
    h.server.shutdown().await;
}

/// F3 / S21-8: a document no strict reader would read as one thing is a 502, never filtered and passed on.
#[tokio::test]
async fn ambiguous_metadata_is_refused_not_passed_on() {
    let h = harness("", 0).await;
    for (n, doc) in [
        "<metadata><versioning><latest>1</latest><latest>2.0</latest><versions><version>1</version></versions></versioning></metadata>",
        "<metadata><versioning><versions><version>2.0<x/></version></versions></versioning></metadata>",
        "<metadata><plugins/><versioning><versions><version>1</version></versions></versioning></metadata>",
        "<metadata xmlns:m=\"u\"><versioning><m:versions><version>1</version></m:versions></versioning></metadata>",
    ].into_iter().enumerate() {
        h.registry.answer(&at(&format!("org/demo/amb{n}/maven-metadata.xml")), FakeAnswer::Body(doc.to_owned()));
        assert_eq!(h.server.get(&format!("/maven/org/demo/amb{n}/maven-metadata.xml")).await.status().as_u16(), 502, "{doc}");
    }
    h.server.shutdown().await;
}

/// F1: waiting for the one catalog slot holds no refresh place, and credential-free reads share the fetched catalog for a moment.
#[tokio::test]
async fn catalog_requests_queue_without_blocking_metadata_and_share_one_fetch() {
    let h = harness("", 0).await;
    serve_lib(&h);
    let gate = common::Gate::new();
    let catalog = "<archetype-catalog><archetypes></archetypes></archetype-catalog>".to_owned();
    h.registry.answer(
        &at("archetype-catalog.xml"),
        FakeAnswer::GatedMetadata {
            body: catalog,
            gate: Arc::clone(&gate),
        },
    );
    let url = h.server.url("/maven/archetype-catalog.xml");
    let tasks: Vec<_> = (0..12)
        .map(|_| {
            let url = url.clone();
            tokio::spawn(async move { reqwest::get(url).await.unwrap().status().as_u16() })
        })
        .collect();
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // Eleven requests wait for the slot; none of them holds a refresh place, so a listing of another artifact is answered at once.
    let started = std::time::Instant::now();
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/maven-metadata.xml")
            .await
            .status()
            .as_u16(),
        200
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    gate.release();
    for task in tasks {
        assert_eq!(task.await.unwrap(), 200);
    }
    assert_eq!(
        calls_to(&h, "archetype-catalog.xml"),
        1,
        "one upstream fetch for the whole burst"
    );
    h.server.shutdown().await;
}

/// F5: a file added later to an old version carries its own `Last-Modified` and waits its own cooldown.
#[tokio::test]
async fn a_classifier_added_to_an_old_version_waits_its_own_cooldown() {
    let h = harness("", 7 * DAY).await;
    serve_lib(&h);
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0-natives.jar"),
        FakeAnswer::Dated {
            body: maven::jar("natives", "1.0"),
            last_modified: http_date(YOUNG),
        },
    );
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0-tests.jar"),
        FakeAnswer::Dated {
            body: maven::jar("tests", "1.0"),
            last_modified: http_date(OLD),
        },
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0-natives.jar")
            .await
            .status()
            .as_u16(),
        403,
        "the young classifier is held although the POM is old"
    );
    assert_eq!(
        calls_to(&h, "lib-1.0-natives.jar"),
        1,
        "probed for its date, never downloaded"
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0-tests.jar")
            .await
            .status()
            .as_u16(),
        200,
        "an old classifier is unaffected"
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
            .await
            .status()
            .as_u16(),
        200
    );
    h.clock.advance_seconds(8 * DAY as i64);
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0-natives.jar")
            .await
            .status()
            .as_u16(),
        200,
        "released when its own cooldown has passed"
    );
    h.server.shutdown().await;
}

/// F4: a Gradle module file that names an absolute location outside the repository is refused; a relative one is served.
#[tokio::test]
async fn a_gradle_module_file_naming_another_host_is_refused() {
    let h = harness("", 0).await;
    serve_lib(&h);
    let module = |url: &str| {
        format!(
            "{{\"formatVersion\":\"1.1\",\"variants\":[{{\"name\":\"api\",\"files\":[{{\"name\":\"lib.jar\",\"url\":\"{url}\"}}],\"available-at\":{{\"url\":\"../../x/1/x-1.module\",\"group\":\"g\",\"module\":\"x\",\"version\":\"1\"}}}}]}}"
        )
    };
    let dated = |body: String| FakeAnswer::Dated {
        body: body.into_bytes(),
        last_modified: http_date(OLD),
    };
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0.module"),
        dated(module("lib-1.0.jar")),
    );
    h.registry.answer(
        &at("org/demo/lib/1.1/lib-1.1.module"),
        dated(module("https://elsewhere.invalid/lib-1.1.jar")),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.module")
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.1/lib-1.1.module")
            .await
            .status()
            .as_u16(),
        403
    );
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0-b.module"),
        dated(module("//elsewhere.invalid/x.jar")),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0-b.module")
            .await
            .status()
            .as_u16(),
        403
    );
    h.server.shutdown().await;
}

/// F6: the first download is checked against the registry's own `.sha1` before its digests are pinned.
#[tokio::test]
async fn a_download_that_disagrees_with_the_registrys_checksum_file_is_refused_and_not_pinned() {
    let h = harness("", 0).await;
    serve_lib(&h);
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0.jar.sha1"),
        FakeAnswer::Body("0".repeat(40)),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
            .await
            .status()
            .as_u16(),
        502
    );
    assert!(content_files(&h).is_empty(), "nothing was stored");
    let pins = h
        .server
        .app()
        .store()
        .list_project_pins_in(0, probation::policy::Ecosystem::Maven, "org.demo:lib")
        .await
        .unwrap();
    assert!(pins.is_empty(), "nothing was pinned");
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0.jar.sha1"),
        FakeAnswer::Body(format!(
            "{}  lib-1.0.jar\n",
            common::maven::sha1_hex(&maven::jar("lib", "1.0")).to_uppercase()
        )),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
            .await
            .status()
            .as_u16(),
        200,
        "the right checksum (any case, with a file name) passes"
    );
    h.server.shutdown().await;
}

/// R2: a registry that answers 403 (or 404) for a checksum file it does not publish is not a refusal of the file; a present
/// sidecar that disagrees still is.
#[tokio::test]
async fn an_absent_checksum_file_answered_403_is_no_check_and_a_present_wrong_one_still_blocks() {
    let h = harness("", 0).await;
    serve_lib(&h);
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0.jar.sha1"),
        FakeAnswer::Fail(probation::upstream::UpstreamError::Status(403)),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
            .await
            .status()
            .as_u16(),
        200,
        "403 for the absent sidecar is no check"
    );
    h.registry.answer(
        &at("org/demo/lib/1.1/lib-1.1.jar.sha1"),
        FakeAnswer::Body("1".repeat(40)),
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.1/lib-1.1.jar")
            .await
            .status()
            .as_u16(),
        502,
        "a present sidecar that disagrees blocks"
    );
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0.pom.sha1"),
        FakeAnswer::Fail(probation::upstream::UpstreamError::Status(503)),
    );
    assert_ne!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.pom")
            .await
            .status()
            .as_u16(),
        500
    );
    h.server.shutdown().await;
}

/// R3: a file whose stored date is later than its unit's is not rewritten on every GET.
#[tokio::test]
async fn a_file_with_a_later_date_than_its_unit_is_not_written_again_on_every_get() {
    let h = harness("", 0).await;
    serve_lib(&h);
    h.registry.answer(
        &at("org/demo/lib/1.0/lib-1.0-late.jar"),
        FakeAnswer::Dated {
            body: maven::jar("late", "1.0"),
            last_modified: http_date("2025-06-01T00:00:00Z"),
        },
    );
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0-late.jar")
            .await
            .status()
            .as_u16(),
        200
    );
    // A GET that only reads costs the same number of store commands whether the row's date is the unit's or a later one: the plain
    // file is the oracle, and a write on every GET of the later-dated file would cost one command more.
    assert_eq!(
        h.server
            .get("/maven/org/demo/lib/1.0/lib-1.0.jar")
            .await
            .status()
            .as_u16(),
        200
    );
    let cost = |path: &'static str| {
        let h = &h;
        async move {
            let before = h.server.store_commands();
            assert_eq!(h.server.get(path).await.status().as_u16(), 200);
            h.server.store_commands() - before
        }
    };
    let plain = cost("/maven/org/demo/lib/1.0/lib-1.0.jar").await;
    let late = cost("/maven/org/demo/lib/1.0/lib-1.0-late.jar").await;
    assert_eq!(
        late, plain,
        "the later-dated file is read like any other: {late} vs {plain}"
    );
    h.server.shutdown().await;
}

/// Row bound, atomic: simultaneous first requests for POMs of fresh versions never take the project past its bound.
#[tokio::test]
async fn simultaneous_first_requests_never_overshoot_the_row_bound() {
    let (server, registry, _dir) = bounded_harness(1).await;
    let gate = common::Gate::new();
    let versions: Vec<String> = (0..16).map(|n| format!("1.{n}")).collect();
    for v in &versions {
        registry.answer(
            &at(&format!("org/demo/lib/{v}/lib-{v}.pom")),
            FakeAnswer::GatedMetadata {
                body: maven::pom("org.demo", "lib", v),
                gate: Arc::clone(&gate),
            },
        );
    }
    let base = server.url("/maven");
    let tasks: Vec<_> = versions
        .iter()
        .map(|v| {
            let url = format!("{base}/org/demo/lib/{v}/lib-{v}.pom");
            tokio::spawn(async move { reqwest::get(url).await.unwrap().status().as_u16() })
        })
        .collect();
    for _ in 0..4 {
        gate.wait_until_reached().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for _ in 0..versions.len() {
        gate.release();
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.unwrap());
    }
    let rows = server
        .app()
        .store()
        .count_project_references_in(0, probation::policy::Ecosystem::Maven, "org.demo:lib")
        .await
        .unwrap();
    assert_eq!(rows, 5, "exactly the bound: {statuses:?}");
    // (The five that were admitted then fail to download the POM from a gated fake: a 502; the rest are refused at the bound.)
    assert_eq!(
        statuses.iter().filter(|s| **s != 503).count(),
        5,
        "{statuses:?}"
    );
    server.shutdown().await;
}
