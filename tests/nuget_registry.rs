//! Row 20: NuGet v3 discovery and `.nupkg`/`.nuspec` protection, end to end through the firewall against an
//! in-process `FakeRegistry` and a clock the test moves by hand. The real client witness is tests/nuget_native.rs
//! (dotnet 8.0.416), the shared-service forms are tests/nuget_service_read.rs and tests/nuget_service_write.rs.

mod common;

use std::sync::Arc;

use common::nuget::{self, FLAT, INDEX_ORIGIN, PUBLISH_ORIGIN, REG, SEARCH_ORIGIN, flat_index, leaf, registration};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, sample_config};
use probation::config::Config;
use probation::http::nuget_routes::{self, Parsed};
use probation::upstream::{OriginSet, Transport};
use serde_json::{Value, json};
use tempfile::TempDir;
use url::Url;

const NOW: &str = "2026-04-06T12:00:00Z";
const DAY: u64 = 86_400;
const OLD: &str = "2025-01-01T00:00:00.000+00:00";
const YOUNG: &str = "2026-04-05T12:00:00.000+00:00";
const SENTINEL: &str = "1900-01-01T00:00:00+00:00";

fn origins() -> OriginSet {
    fake_origins().with_nuget(Url::parse(INDEX_ORIGIN).unwrap(), Url::parse(SEARCH_ORIGIN).unwrap(), Url::parse(PUBLISH_ORIGIN).unwrap())
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
    registry.answer("/v3/index.json", FakeAnswer::Body(nuget::service_index(&[])));
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
    Harness { server, registry, clock, _dir: dir }
}

/// A package on the fake registry: flat container list, one inline registration page, and the four files of
/// every version in `versions` as `(version, published, listed)`.
fn serve_package(h: &Harness, id: &str, versions: &[(&str, Option<&str>, bool)]) {
    let names: Vec<&str> = versions.iter().map(|(v, ..)| *v).collect();
    h.registry.answer(&format!("{FLAT}{id}/index.json"), FakeAnswer::Body(flat_index(&names)));
    let leaves: Vec<Value> = versions.iter().map(|(v, published, listed)| leaf(id, v, *published, *listed)).collect();
    let (index, _) = registration(id, &[leaves], &[]);
    h.registry.answer(&format!("{REG}{id}/index.json"), FakeAnswer::Body(index));
    for (version, ..) in versions {
        serve_files(h, id, version);
    }
}

fn serve_files(h: &Harness, id: &str, version: &str) {
    let lower = version.to_ascii_lowercase();
    h.registry.answer(&format!("{FLAT}{id}/{lower}/{id}.{lower}.nupkg"), FakeAnswer::Bytes(nuget::nupkg(id, &lower)));
    h.registry.answer(&format!("{FLAT}{id}/{lower}/{id}.nuspec"), FakeAnswer::Body(nuget::nuspec(id, &lower)));
    h.registry.answer(&format!("{FLAT}{id}/{lower}/readme"), FakeAnswer::Body("# readme".to_owned()));
    h.registry.answer(&format!("{FLAT}{id}/{lower}/icon"), FakeAnswer::Bytes(vec![0x89, b'P', b'N', b'G']));
}

async fn text_of(h: &Harness, path: &str) -> (u16, String) {
    let response = h.server.get(path).await;
    (response.status().as_u16(), response.text().await.unwrap())
}

fn calls_to(h: &Harness, needle: &str) -> usize {
    h.registry.calls().iter().filter(|url| url.path().contains(needle)).count()
}

fn versions_of(body: &str) -> Vec<String> {
    let value: Value = serde_json::from_str(body).unwrap();
    value["versions"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect()
}

// ------------------------------------------------------------------ routing: one canonical spelling

#[test]
fn request_paths_parse_to_one_canonical_identity() {
    assert_eq!(nuget_routes::parse("v3/index.json").unwrap(), Parsed::ServiceIndex);
    assert_eq!(nuget_routes::parse("v3-flatcontainer/newtonsoft.json/index.json").unwrap(), Parsed::FlatIndex("newtonsoft.json".into()));
    assert_eq!(
        nuget_routes::parse("v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg").unwrap(),
        Parsed::File("newtonsoft.json".into(), "13.0.3".into(), "newtonsoft.json.13.0.3.nupkg".into())
    );
    assert_eq!(nuget_routes::parse("v3/registration/a.b/index.json").unwrap(), Parsed::RegistrationIndex("a.b".into()));
    assert_eq!(nuget_routes::parse("v3/registration/a.b/1.0.0-beta.json").unwrap(), Parsed::RegistrationLeaf("a.b".into(), "1.0.0-beta".into()));
    assert_eq!(nuget_routes::parse("v3/query").unwrap(), Parsed::Search);
    assert_eq!(nuget_routes::parse("v3/vulnerabilities/base.json").unwrap(), Parsed::VulnerabilityFile("base".into()));
    for bad in [
        "v3-flatcontainer/Newtonsoft.Json/index.json", // an upper-case id is no spelling at all
        "v3-flatcontainer/a/1.0/a.1.0.nupkg",           // a version that is not the normalised one
        "v3-flatcontainer/a/1.0.0.0/a.1.0.0.0.nupkg",
        "v3-flatcontainer/a/1.0.0-Beta/a.1.0.0-Beta.nupkg",
        "v3-flatcontainer/a/1.0.0+meta/x",
        "v3-flatcontainer/a b/index.json",
        "v3-flatcontainer/a/b/c/d",
        "v3-flatcontainer//index.json",
        "v3/registration/a/1.0.0",
        "v3/registration/a/01.0.0.json",
        "v3/vulnerabilities/other.json",
        "v3/repository-signatures/5.0.0/other.json",
        "v3/index.json/",
        "v4/index.json",
        "",
    ] {
        assert!(nuget_routes::parse(bad).is_err(), "{bad}");
    }
}

#[tokio::test]
async fn invalid_spellings_are_404_before_any_upstream_call() {
    let h = harness("", 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true)]);
    let before = h.registry.calls().len();
    for path in [
        "/nuget/v3-flatcontainer/Demo.Pkg/index.json",
        "/nuget/v3-flatcontainer/demo.pkg/1.0/demo.pkg.1.0.nupkg",
        "/nuget/v3-flatcontainer/demo.pkg/1.0.0.0/demo.pkg.1.0.0.0.nupkg",
        "/nuget/v3-flatcontainer/demo.pkg/1.0.0/Demo.Pkg.1.0.0.nupkg",
        "/nuget/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.zip",
        "/nuget/v3-flatcontainer/demo.pkg/1.0.0/other",
        "/nuget/v3/registration/Demo.Pkg/index.json",
        "/nuget/v3-flatcontainer/demo.pkg/index.json?x=1",
    ] {
        assert_eq!(h.server.get(path).await.status().as_u16(), 404, "{path}");
    }
    assert_eq!(h.registry.calls().len(), before, "no upstream call for any of them");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ the service index

#[tokio::test]
async fn service_index_points_every_served_resource_at_this_firewall() {
    let h = harness("", 7 * DAY).await;
    let (status, body) = text_of(&h, "/nuget/v3/index.json").await;
    assert_eq!(status, 200, "{body}");
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["version"], "3.0.0");
    let by_type = |kind: &str| -> Vec<String> {
        doc["resources"].as_array().unwrap().iter().filter(|r| r["@type"] == kind).map(|r| r["@id"].as_str().unwrap().to_owned()).collect()
    };
    let root = "https://packages.example.org/nuget/";
    assert_eq!(by_type("PackageBaseAddress/3.0.0"), [format!("{root}v3-flatcontainer/")]);
    for kind in ["RegistrationsBaseUrl", "RegistrationsBaseUrl/3.6.0", "RegistrationsBaseUrl/Versioned"] {
        assert_eq!(by_type(kind), [format!("{root}v3/registration/")], "{kind}");
    }
    assert_eq!(by_type("SearchQueryService"), [format!("{root}v3/query")]);
    assert_eq!(by_type("SearchQueryService/3.5.0"), [format!("{root}v3/query")]);
    assert_eq!(by_type("SearchAutocompleteService"), [format!("{root}v3/autocomplete")]);
    assert_eq!(by_type("VulnerabilityInfo/6.7.0"), [format!("{root}v3/vulnerabilities/index.json")]);
    assert_eq!(by_type("RepositorySignatures/5.0.0"), [format!("{root}v3/repository-signatures/5.0.0/index.json")]);
    assert_eq!(by_type("ReadmeUriTemplate/6.13.0"), [format!("{root}v3-flatcontainer/{{lower_id}}/{{lower_version}}/readme")]);
    // The standalone firewall has no publish route; resources it does not serve are not advertised; nothing names upstream.
    assert!(by_type("PackagePublish/2.0.0").is_empty() && by_type("SymbolPackagePublish/4.9.0").is_empty());
    assert!(by_type("LegacyGallery").is_empty() && by_type("Catalog/3.0.0").is_empty());
    assert!(!body.contains(".invalid") && !body.contains("nuget.org"), "{body}");
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_resource_on_an_unconfigured_origin_is_never_used() {
    let h = harness("", 7 * DAY).await;
    // The flat container on a host nobody configured: the registry cannot be served, and that host is never asked.
    h.registry.answer("/v3/index.json", FakeAnswer::Body(
        json!({"version": "3.0.0", "resources": [{"@id": "https://evil.invalid/flat/", "@type": "PackageBaseAddress/3.0.0"}]}).to_string(),
    ));
    assert_eq!(h.server.get("/nuget/v3/index.json").await.status().as_u16(), 502);
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/demo/index.json").await.status().as_u16(), 502);
    assert!(h.registry.calls().iter().all(|url| url.host_str() != Some("evil.invalid")));
    // A search service on an unconfigured host is skipped; the registry still serves everything else.
    h.registry.answer("/v3/index.json", FakeAnswer::Body(
        json!({"version": "3.0.0", "resources": [
            {"@id": format!("{INDEX_ORIGIN}{FLAT}"), "@type": "PackageBaseAddress/3.0.0"},
            {"@id": "https://evil.invalid/query", "@type": "SearchQueryService"},
        ]}).to_string(),
    ));
    h.clock.advance_seconds(120);
    let (status, body) = text_of(&h, "/nuget/v3/index.json").await;
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("SearchQueryService") && !body.contains("evil.invalid"), "{body}");
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_service_index_that_is_not_one_is_a_502() {
    let h = harness("", 7 * DAY).await;
    for body in ["not json", "[]", r#"{"version":"2.0.0","resources":[]}"#, r#"{"version":"3.0.0"}"#, r#"{"version":"3.0.0","resources":[{"@id":"x","@type":"y"}]}"#] {
        h.registry.answer("/v3/index.json", FakeAnswer::Body(body.to_owned()));
        h.clock.advance_seconds(120);
        assert_eq!(h.server.get("/nuget/v3/index.json").await.status().as_u16(), 502, "{body}");
    }
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ the flat container: age

#[tokio::test]
async fn flat_index_withholds_young_versions_and_the_four_files_of_a_young_version_are_all_refused() {
    let h = harness("", 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("1.1.0", Some(YOUNG), true)]);
    let (status, body) = text_of(&h, "/nuget/v3-flatcontainer/demo.pkg/index.json").await;
    assert_eq!((status, versions_of(&body)), (200, vec!["1.0.0".to_owned()]), "{body}");
    for (file, content_type_ok) in [("demo.pkg.1.0.0.nupkg", true), ("demo.pkg.nuspec", true), ("readme", true), ("icon", true)] {
        let response = h.server.get(&format!("/nuget/v3-flatcontainer/demo.pkg/1.0.0/{file}")).await;
        assert_eq!(response.status().as_u16(), 200, "{file}");
        assert!(content_type_ok);
    }
    let nupkg = h.server.get("/nuget/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg").await.bytes().await.unwrap();
    assert_eq!(nupkg.to_vec(), nuget::nupkg("demo.pkg", "1.0.0"), "delivered exactly as the registry sent it");
    for file in ["demo.pkg.1.1.0.nupkg", "demo.pkg.nuspec", "readme", "icon"] {
        let response = h.server.get(&format!("/nuget/v3-flatcontainer/demo.pkg/1.1.0/{file}")).await;
        assert_eq!(response.status().as_u16(), 403, "{file}");
    }
    assert_eq!(calls_to(&h, "/1.1.0/"), 0, "a held version's files are never fetched");
    h.server.shutdown().await;
}

#[tokio::test]
async fn an_unlisted_sentinel_date_and_a_version_registration_does_not_name_wait_on_first_seen() {
    let h = harness("", 7 * DAY).await;
    // 1.0.0: the unlisted sentinel (an old package); 1.1.0: in the flat container only (registration lags).
    h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(flat_index(&["1.0.0", "1.1.0", "2.0.0"])));
    let (index, _) = registration("demo.pkg", &[vec![leaf("demo.pkg", "1.0.0", Some(SENTINEL), false), leaf("demo.pkg", "2.0.0", Some(OLD), true)]], &[]);
    h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Body(index));
    for version in ["1.0.0", "1.1.0", "2.0.0"] {
        serve_files(&h, "demo.pkg", version);
    }
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/demo.pkg/index.json").await;
    assert_eq!(versions_of(&body), ["2.0.0"], "undated versions are held for a whole cooldown, never dated by invention");
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg").await.status().as_u16(), 403);
    h.clock.advance_seconds(8 * DAY as i64);
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/demo.pkg/index.json").await;
    assert_eq!(versions_of(&body), ["1.0.0", "1.1.0", "2.0.0"], "released once the committed first-seen time has aged");
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/demo.pkg/1.1.0/demo.pkg.1.1.0.nupkg").await.status().as_u16(), 200);
    h.server.shutdown().await;
}

#[tokio::test]
async fn versions_are_judged_in_the_one_normalised_spelling() {
    let h = harness("", 7 * DAY).await;
    // The registry lists the flat container's normalised spelling; registration spells the same versions otherwise.
    h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(flat_index(&["1.0.0", "2.0.0-beta.1", "3.0.0.1"])));
    let (index, _) = registration("demo.pkg", &[vec![
        leaf("demo.pkg", "1.0.0.0", Some(OLD), true),
        leaf("demo.pkg", "2.0.0-Beta.1", Some(YOUNG), true),
        leaf("demo.pkg", "3.0.0.1+build7", Some(OLD), true),
    ]], &[]);
    h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Body(index));
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/demo.pkg/index.json").await;
    assert_eq!(versions_of(&body), ["1.0.0", "3.0.0.1"], "{body}");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ the local gate and policy keys

#[tokio::test]
async fn a_blocked_id_or_version_is_refused_before_any_upstream_call_and_the_block_is_case_insensitive() {
    let blocked = r#"{"ecosystem":"nuget","name":"Evil.Pkg","version":null,"reason":"malware"},{"ecosystem":"nuget","name":"Demo.Pkg","version":"1.0.0.0","reason":"malware"}"#;
    let h = harness(blocked, 0).await;
    serve_package(&h, "evil.pkg", &[("1.0.0", Some(OLD), true)]);
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("2.0.0", Some(OLD), true)]);
    let before = h.registry.calls().len();
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/evil.pkg/index.json").await.status().as_u16(), 403);
    assert_eq!(h.server.get("/nuget/v3/registration/evil.pkg/index.json").await.status().as_u16(), 403);
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/evil.pkg/1.0.0/evil.pkg.1.0.0.nupkg").await.status().as_u16(), 403);
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.nuspec").await.status().as_u16(), 403, "a version block written 1.0.0.0 matches 1.0.0");
    assert_eq!(h.registry.calls().len(), before, "locally conclusive: upstream is never asked");
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/demo.pkg/index.json").await;
    assert_eq!(versions_of(&body), ["2.0.0"], "the blocked version is absent from the listing");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ registration

async fn json_of(h: &Harness, path: &str) -> (u16, Value) {
    let (status, body) = text_of(h, path).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::String(body)))
}

fn leaf_versions(doc: &Value) -> Vec<String> {
    doc["items"].as_array().unwrap().iter().flat_map(|page| page["items"].as_array().unwrap().iter()).map(|leaf| leaf["catalogEntry"]["version"].as_str().unwrap().to_owned()).collect()
}

#[tokio::test]
async fn registration_filters_leaves_inline_and_linked_and_rewrites_every_url() {
    let h = harness("", 7 * DAY).await;
    let mut with_dependency = leaf("demo.pkg", "1.0.0", Some(OLD), true);
    with_dependency["catalogEntry"]["dependencyGroups"][0]["dependencies"] = json!([
        {"@id": format!("{INDEX_ORIGIN}/v3/catalog0/data/x/demo.pkg.1.0.0.json#dep/Other.Dep"), "id": "Other.Dep", "range": "[1.0.0, )", "registration": format!("{INDEX_ORIGIN}{REG}other.dep/index.json")},
        {"id": "no id here", "range": "1.0", "registration": "https://evil.invalid/x.json"},
    ]);
    let page_one = vec![with_dependency, leaf("demo.pkg", "1.1.0", Some(YOUNG), true)];
    let page_two = vec![leaf("demo.pkg", "2.0.0-Beta.1", Some(YOUNG), true)];
    let page_three = vec![leaf("demo.pkg", "3.0.0", Some(OLD), true), leaf("demo.pkg", "3.1.0", Some(OLD), true)];
    // Page two is only a link in the index: it must be fetched, and it is held back whole (one young leaf).
    let (index, linked) = registration("demo.pkg", &[page_one, page_two, page_three], &[1]);
    h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Body(index));
    for (path, document) in linked {
        h.registry.answer(&path, FakeAnswer::Body(document));
    }
    h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(flat_index(&["1.0.0", "1.1.0", "2.0.0-beta.1", "3.0.0", "3.1.0"])));
    let (status, doc) = json_of(&h, "/nuget/v3/registration/demo.pkg/index.json").await;
    assert_eq!(status, 200, "{doc}");
    assert_eq!(leaf_versions(&doc), ["1.0.0", "3.0.0", "3.1.0"]);
    assert_eq!(doc["count"], 2, "the page with no leaf left is dropped");
    let root = "https://packages.example.org/nuget/";
    assert_eq!(doc["@id"], format!("{root}v3/registration/demo.pkg/index.json"));
    let pages = doc["items"].as_array().unwrap();
    assert_eq!((pages[0]["lower"].as_str(), pages[0]["upper"].as_str(), pages[0]["count"].as_u64()), (Some("1.0.0"), Some("1.0.0"), Some(1)));
    assert_eq!((pages[1]["lower"].as_str(), pages[1]["upper"].as_str(), pages[1]["count"].as_u64()), (Some("3.0.0"), Some("3.1.0"), Some(2)));
    assert_eq!(pages[0]["parent"], format!("{root}v3/registration/demo.pkg/index.json"));
    let first = &pages[0]["items"][0];
    assert_eq!(first["@id"], format!("{root}v3/registration/demo.pkg/1.0.0.json"));
    assert_eq!(first["packageContent"], format!("{root}v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg"));
    assert_eq!(first["registration"], format!("{root}v3/registration/demo.pkg/index.json"));
    assert_eq!(first["catalogEntry"]["packageContent"], first["packageContent"]);
    assert_eq!(first["catalogEntry"]["iconUrl"], format!("{root}v3-flatcontainer/demo.pkg/1.0.0/icon"), "an icon on the registry's own host is served here");
    // U-1: a nuget.org-shaped leaf names its readme on the flat container; that is this firewall's readme route, the
    // packager's own project URL stays.
    assert_eq!(first["catalogEntry"]["readmeUrl"], format!("{root}v3-flatcontainer/demo.pkg/1.0.0/readme"), "{first}");
    assert_eq!(first["catalogEntry"]["projectUrl"], "https://project.invalid/home");
    assert!(!first.to_string().contains(INDEX_ORIGIN), "no URL of the registry is left: {first}");
    // Everything else is carried through untouched.
    assert_eq!(first["catalogEntry"]["licenseUrl"], "https://licenses.invalid/mit");
    assert_eq!(first["catalogEntry"]["dependencyGroups"][0]["targetFramework"], ".NETStandard2.0");
    assert_eq!(first["catalogEntry"]["authors"], "someone");
    let dependencies = &first["catalogEntry"]["dependencyGroups"][0]["dependencies"];
    assert_eq!(dependencies[0]["registration"], format!("{root}v3/registration/other.dep/index.json"), "a dependency's registration link is this firewall's");
    assert_eq!(dependencies[0]["range"], "[1.0.0, )");
    assert!(dependencies[1].get("registration").is_none(), "a link that names no valid id is dropped, never followed");
    // Nothing of the registry survives: a catalog identifier leads to a route of this firewall that is not served, and a
    // dependency's registration link is this firewall's own.
    let text = doc.to_string();
    assert!(!text.contains("nuget-index.invalid"), "{text}");
    assert_eq!(first["catalogEntry"]["@id"], format!("{root}v3/catalog/v3/catalog0/data/2024.01.01.00.00.00/demo.pkg.1.0.0.json"));
    assert_eq!(h.server.get("/nuget/v3/catalog/v3/catalog0/data/2024.01.01.00.00.00/demo.pkg.1.0.0.json").await.status().as_u16(), 404);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_registration_leaf_is_served_rewritten_only_when_the_version_is_allowed() {
    let h = harness("", 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("1.1.0", Some(YOUNG), true)]);
    let single = |version: &str, published: &str| {
        let mut doc = leaf("demo.pkg", version, Some(published), true);
        // A leaf document names its catalog entry as a URL and `published` at its own level.
        doc["catalogEntry"] = doc["catalogEntry"]["@id"].clone();
        doc["published"] = json!(published);
        doc["listed"] = json!(true);
        doc.to_string()
    };
    h.registry.answer(&format!("{REG}demo.pkg/1.0.0.json"), FakeAnswer::Body(single("1.0.0", OLD)));
    h.registry.answer(&format!("{REG}demo.pkg/1.1.0.json"), FakeAnswer::Body(single("1.1.0", YOUNG)));
    let (status, doc) = json_of(&h, "/nuget/v3/registration/demo.pkg/1.0.0.json").await;
    assert_eq!(status, 200, "{doc}");
    let root = "https://packages.example.org/nuget/";
    assert_eq!(doc["@id"], format!("{root}v3/registration/demo.pkg/1.0.0.json"));
    assert_eq!(doc["packageContent"], format!("{root}v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg"));
    assert!(doc["catalogEntry"].as_str().unwrap().contains("/catalog0/"), "a catalog entry URL is an identifier and stays");
    assert_eq!(h.server.get("/nuget/v3/registration/demo.pkg/1.1.0.json").await.status().as_u16(), 403);
    assert_eq!(calls_to(&h, "/1.1.0.json"), 0, "a held version's leaf is not fetched");
    h.server.shutdown().await;
}

#[tokio::test]
async fn registration_refuses_pages_outside_its_own_directory_and_documents_that_are_not_registration() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(flat_index(&["1.0.0"])));
    // A page link to another package's directory, to another host, with a query, and a missing page.
    for link in [
        format!("{INDEX_ORIGIN}{REG}other.pkg/page/1.0.0/1.0.0.json"),
        "https://evil.invalid/page.json".to_owned(),
        format!("{INDEX_ORIGIN}{REG}demo.pkg/page/1.0.0/1.0.0.json?x=1"),
        format!("{INDEX_ORIGIN}{REG}demo.pkg/page/1.0.0/1.0.0.json"),
    ] {
        let index = json!({"count": 1, "items": [{"@id": link, "count": 1, "lower": "1.0.0", "upper": "1.0.0"}]}).to_string();
        h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Body(index));
        h.clock.advance_seconds(1000);
        assert_eq!(h.server.get("/nuget/v3/registration/demo.pkg/index.json").await.status().as_u16(), 502, "{link}");
    }
    assert!(h.registry.calls().iter().all(|url| url.host_str() != Some("evil.invalid")));
    assert_eq!(calls_to(&h, "/other.pkg/"), 0);
    for body in ["not json", "[]", r#"{"items":"x"}"#, r#"{"count":0}"#] {
        h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Body(body.to_owned()));
        h.clock.advance_seconds(1000);
        assert_eq!(h.server.get("/nuget/v3/registration/demo.pkg/index.json").await.status().as_u16(), 502, "{body}");
    }
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ files: pins, membership

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

/// SPEC §9 pin: the first verified download of each file fixes its digest. Once the stored copy is gone an
/// re-download whose bytes differ is refused with 502 and nothing of it is delivered or stored.
#[tokio::test]
async fn changed_bytes_of_a_pinned_file_are_refused_once_the_stored_copy_is_gone() {
    for file in ["demo.pkg.1.0.0.nupkg", "demo.pkg.nuspec", "readme", "icon"] {
        let h = harness("", 0).await;
        serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true)]);
        let url = format!("/nuget/v3-flatcontainer/demo.pkg/1.0.0/{file}");
        let first = h.server.get(&url).await;
        assert_eq!(first.status().as_u16(), 200, "{file}");
        let original = first.bytes().await.unwrap().to_vec();
        assert!(!content_files(&h).is_empty());
        for stored in content_files(&h) {
            std::fs::remove_file(stored).unwrap();
        }
        h.registry.answer(&format!("{FLAT}demo.pkg/1.0.0/{file}"), FakeAnswer::Bytes([original.clone(), b"tampered".to_vec()].concat()));
        let second = h.server.get(&url).await;
        assert_eq!(second.status().as_u16(), 502, "{file}: the changed bytes are refused");
        assert!(!String::from_utf8_lossy(&second.bytes().await.unwrap()).contains("tampered"), "{file}");
        assert!(content_files(&h).is_empty(), "{file}: nothing of the changed body was stored");
        h.server.shutdown().await;
    }
}

#[tokio::test]
async fn a_version_the_registry_no_longer_lists_is_not_served_even_when_its_bytes_are_stored() {
    let h = harness("", 0).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("1.1.0", Some(OLD), true)]);
    let path = "/nuget/v3-flatcontainer/demo.pkg/1.1.0/demo.pkg.1.1.0.nupkg";
    assert_eq!(h.server.get(path).await.status().as_u16(), 200);
    // The registry withdraws 1.1.0 and the project's metadata ages out.
    h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(flat_index(&["1.0.0"])));
    h.clock.advance_seconds(1000);
    assert_eq!(h.server.get(path).await.status().as_u16(), 404);
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.nuspec").await.status().as_u16(), 200);
    h.server.shutdown().await;
}

#[tokio::test]
async fn an_unknown_id_is_a_404_and_a_head_request_runs_every_check() {
    let h = harness("", 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("1.1.0", Some(YOUNG), true)]);
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/nothing.here/index.json").await.status().as_u16(), 404);
    assert_eq!(h.server.head("/nuget/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg").await.status().as_u16(), 200);
    assert_eq!(h.server.head("/nuget/v3-flatcontainer/demo.pkg/1.1.0/demo.pkg.1.1.0.nupkg").await.status().as_u16(), 403);
    assert_eq!(h.server.head("/nuget/v3-flatcontainer/demo.pkg/index.json").await.status().as_u16(), 405, "a document is read with GET only");
    assert_eq!(h.server.post("/nuget/v3-flatcontainer/demo.pkg/index.json").await.status().as_u16(), 405);
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ strict decoding and bounds

#[tokio::test]
async fn upstream_documents_that_are_not_what_the_protocol_names_are_a_502_and_never_delivered() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Missing);
    for body in ["not json", "[]", r#"{"versions":"1.0.0"}"#, r#"{"nothing":[]}"#] {
        h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(body.to_owned()));
        h.clock.advance_seconds(1000);
        assert_eq!(h.server.get("/nuget/v3-flatcontainer/demo.pkg/index.json").await.status().as_u16(), 502, "{body}");
    }
    // An entry that is no NuGet version is dropped, a repeat (any spelling) is kept once, the rest is exactly what was listed.
    h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(json!({"versions": ["1.0.0", "x.y", "1.0.0", "1.0.0.0", 7, "2.0.0"]}).to_string()));
    let (index, _) = registration("demo.pkg", &[vec![leaf("demo.pkg", "1.0.0", Some(OLD), true), leaf("demo.pkg", "2.0.0", Some(OLD), true)]], &[]);
    h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Body(index));
    h.clock.advance_seconds(1000);
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/demo.pkg/index.json").await;
    assert_eq!(versions_of(&body), ["1.0.0", "2.0.0"], "{body}");
    h.server.shutdown().await;
}

/// R1: every version of a project is kept, judged and listed, whatever the number: only the newest 5,000 have their four
/// reference rows at refresh, any other gets its rows when a file of it is asked for, so an exact pin of the oldest version
/// of a 5,001-version (and a 20,001-version) project restores.
#[tokio::test]
async fn a_project_over_the_reference_bound_keeps_every_version_and_restores_an_old_pin() {
    for count in [5001usize, 20_001] {
        let h = harness("", 0).await;
        let many: Vec<String> = (0..count).map(|n| format!("1.0.{n}")).collect();
        let names: Vec<&str> = many.iter().map(String::as_str).collect();
        h.registry.answer("/v3-flatcontainer/big.pkg/index.json", FakeAnswer::Body(flat_index(&names)));
        h.registry.answer(&format!("{REG}big.pkg/index.json"), FakeAnswer::Missing);
        serve_files(&h, "big.pkg", "1.0.0");
        serve_files(&h, "big.pkg", &format!("1.0.{}", count - 1));
        let (status, body) = text_of(&h, "/nuget/v3-flatcontainer/big.pkg/index.json").await;
        assert_eq!(status, 200, "{}", &body[..body.len().min(300)]);
        let listed = versions_of(&body);
        assert_eq!((listed.len(), listed.first().map(String::as_str)), (count, Some("1.0.0")), "every version is listed, the oldest too");
        for version in ["1.0.0".to_owned(), format!("1.0.{}", count - 1)] {
            let response = h.server.get(&format!("/nuget/v3-flatcontainer/big.pkg/{version}/big.pkg.{version}.nupkg")).await;
            assert_eq!(response.status().as_u16(), 200, "an exact pin of {version} restores");
            assert_eq!(response.bytes().await.unwrap().to_vec(), nuget::nupkg("big.pkg", &version));
        }
        assert_eq!(h.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.0/readme").await.status().as_u16(), 200, "the other files of an old version too");
        assert_eq!(h.server.get(&format!("/nuget/v3-flatcontainer/big.pkg/1.0.{count}/big.pkg.1.0.{count}.nupkg")).await.status().as_u16(), 404, "a version nobody lists is still 404");
        h.server.shutdown().await;
    }
}

/// R1: registration of a large project is re-linked pages (a route of this firewall each), not every leaf inline; the
/// oldest version restores, a young one still waits, and a page names no version the policy holds.
#[tokio::test]
async fn a_large_registration_is_served_as_firewall_pages_and_an_old_pin_restores_while_a_young_version_waits() {
    let h = harness("", 7 * DAY).await;
    let count = 6000usize;
    let versions: Vec<String> = (0..count).map(|n| format!("1.0.{n}")).collect();
    let names: Vec<&str> = versions.iter().map(String::as_str).collect();
    h.registry.answer("/v3-flatcontainer/big.pkg/index.json", FakeAnswer::Body(flat_index(&names)));
    let leaves: Vec<Value> = versions.iter().enumerate().map(|(n, v)| leaf("big.pkg", v, Some(if n >= count - 10 { YOUNG } else { OLD }), true)).collect();
    let groups: Vec<Vec<Value>> = leaves.chunks(64).map(<[Value]>::to_vec).collect();
    let (index, linked) = registration("big.pkg", &groups, &(0..groups.len()).collect::<Vec<_>>());
    h.registry.answer(&format!("{REG}big.pkg/index.json"), FakeAnswer::Body(index));
    for (path, document) in linked {
        h.registry.answer(&path, FakeAnswer::Body(document));
    }
    serve_files(&h, "big.pkg", "1.0.0");
    serve_files(&h, "big.pkg", "1.0.5999");
    let (status, doc) = json_of(&h, "/nuget/v3/registration/big.pkg/index.json").await;
    assert_eq!(status, 200);
    let pages = doc["items"].as_array().unwrap();
    assert_eq!(pages.len(), 94, "every page of the registry is a page here");
    assert!(pages.iter().all(|page| page.get("items").is_none() && page["@id"].as_str().unwrap().starts_with("https://packages.example.org/nuget/v3/registration/big.pkg/page/")), "no leaf is inline: {}", pages[0]);
    assert_eq!(pages[93]["count"], 38, "the last page lost its 10 young versions");
    assert!(doc.to_string().len() < 64 << 10, "the index is a few descriptors, not 6,000 leaves");
    let page_path = |page: &Value| page["@id"].as_str().unwrap().strip_prefix("https://packages.example.org").unwrap().to_owned();
    let (status, first) = json_of(&h, &page_path(&pages[0])).await;
    assert_eq!((status, first["items"].as_array().map(Vec::len), first["lower"].as_str(), first["upper"].as_str()), (200, Some(64), Some("1.0.0"), Some("1.0.63")));
    assert_eq!(first["items"][0]["catalogEntry"]["packageContent"], "https://packages.example.org/nuget/v3-flatcontainer/big.pkg/1.0.0/big.pkg.1.0.0.nupkg");
    let (_, last) = json_of(&h, &page_path(&pages[93])).await;
    assert_eq!(last["items"].as_array().map(Vec::len), Some(38), "a page holds only the versions the policy allows");
    assert_eq!(last["items"].as_array().unwrap().last().unwrap()["catalogEntry"]["version"], "1.0.5989", "the young versions are not in it");
    assert_eq!(last["upper"], "1.0.5989");
    assert_eq!(calls_to(&h, "registration5-gz-semver2/big.pkg/index.json"), 1, "walking pages reads the registry's index once (the 5 s share), not once a page");
    assert_eq!(h.server.get("/nuget/v3/registration/big.pkg/page/1.0.0/1.0.64.json").await.status().as_u16(), 404, "a page the registry does not have");
    assert_eq!(h.server.get("/nuget/v3/registration/big.pkg/page/1.0.0/1.0.63.json").await.status().as_u16(), 200);
    // The oldest version restores; the young one waits; both through the one rule.
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.0/big.pkg.1.0.0.nupkg").await.status().as_u16(), 200);
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.5999/big.pkg.1.0.5999.nupkg").await.status().as_u16(), 403);
    h.server.shutdown().await;
}

/// Recheck-2 N1: the rows made when a file of an old version is asked for are bounded per project (four times
/// `max_references_per_project` beyond the newest versions' own); past the bound one more old version is a 503, the newest
/// and the ones that have rows keep being served.
#[tokio::test]
async fn lazy_rows_are_bounded_per_project() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), "", 0);
    config.max_references_per_project = std::num::NonZeroU32::new(40).unwrap();
    let registry = FakeRegistry::new();
    registry.answer("/v3/index.json", FakeAnswer::Body(nuget::service_index(&[])));
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
    let h = Harness { server, registry, clock, _dir: dir };
    let many: Vec<String> = (0..60).map(|n| format!("1.0.{n}")).collect();
    let names: Vec<&str> = many.iter().map(String::as_str).collect();
    h.registry.answer("/v3-flatcontainer/big.pkg/index.json", FakeAnswer::Body(flat_index(&names)));
    h.registry.answer(&format!("{REG}big.pkg/index.json"), FakeAnswer::Missing);
    for version in &many {
        serve_files(&h, "big.pkg", version);
    }
    let status = |version: String| {
        let server = &h.server;
        async move { server.get(&format!("/nuget/v3-flatcontainer/big.pkg/{version}/big.pkg.{version}.nupkg")).await.status().as_u16() }
    };
    // 10 versions have rows from the refresh (40 rows); 160 more rows are allowed: 40 old versions.
    for n in 0..40 {
        assert_eq!(status(format!("1.0.{n}")).await, 200, "1.0.{n}");
    }
    let rows = |h: &Harness| {
        let app = h.server.app();
        async move { app.store().count_project_references_in(0, probation::policy::Ecosystem::NuGet, "big.pkg").await.unwrap() }
    };
    assert_eq!(rows(&h).await, 200, "40 + 160 rows");
    assert_eq!(status("1.0.40".to_owned()).await, 503, "one more old version is past the bound");
    assert_eq!(rows(&h).await, 200, "and made no rows");
    assert_eq!(status("1.0.39".to_owned()).await, 200, "a version that has rows is still served");
    assert_eq!(status("1.0.59".to_owned()).await, 200, "so is a newest one");
    h.server.shutdown().await;
}

/// Recheck-2 N5: a search whose result cannot be judged (the registry fails on one of its projects) fails as a whole,
/// it does not silently drop that result; a result the registry does not have is simply not shown.
#[tokio::test]
async fn a_search_fails_when_a_result_cannot_be_judged() {
    let h = harness("", 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true)]);
    h.registry.answer("/query", FakeAnswer::Body(search_doc(&[("Demo.Pkg", "1.0.0", &["1.0.0"]), ("Unknown.Pkg", "1.0.0", &["1.0.0"])])));
    let (status, doc) = json_of(&h, "/nuget/v3/query?q=pkg").await;
    assert_eq!((status, doc["data"].as_array().map(Vec::len)), (200, Some(1)), "an unknown package is not shown: {doc}");
    h.registry.answer("/v3-flatcontainer/broken.pkg/index.json", FakeAnswer::Fail(probation::upstream::UpstreamError::Status(500)));
    h.registry.answer("/query", FakeAnswer::Body(search_doc(&[("Demo.Pkg", "1.0.0", &["1.0.0"]), ("Broken.Pkg", "1.0.0", &["1.0.0"])])));
    assert_eq!(h.server.get("/nuget/v3/query?q=pkg").await.status().as_u16(), 502, "a result that cannot be judged fails the search");
    h.server.shutdown().await;
}

/// Recheck-2 N6: one search judges at most two cold projects at once (of a registry's four places), so a large `take` leaves
/// places for everyone else's reads.
#[tokio::test]
async fn a_large_search_leaves_refresh_places_to_other_reads() {
    let h = harness("", 7 * DAY).await;
    let gate = common::Gate::new();
    let ids: Vec<String> = (0..12).map(|n| format!("wide.p{n}")).collect();
    let items: Vec<(&str, &str, &[&str])> = ids.iter().map(|id| (id.as_str(), "1.0.0", &["1.0.0"][..])).collect();
    h.registry.answer("/query", FakeAnswer::Body(search_doc(&items)));
    for id in &ids {
        h.registry.answer(&format!("/v3-flatcontainer/{id}/index.json"), FakeAnswer::GatedMetadata { body: flat_index(&["1.0.0"]), gate: Arc::clone(&gate) });
    }
    serve_package(&h, "other.pkg", &[("1.0.0", Some(OLD), true)]);
    let server = Arc::new(h.server);
    let search = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.get("/nuget/v3/query?q=wide&take=1000").await.status().as_u16() })
    };
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let in_flight = h.registry.calls().iter().filter(|u| u.path().starts_with("/v3-flatcontainer/wide.p") && u.path().ends_with("/index.json")).count();
    assert_eq!(in_flight, 2, "the search holds two of the four places");
    assert_eq!(server.get("/nuget/v3-flatcontainer/other.pkg/index.json").await.status().as_u16(), 200, "another read is served meanwhile");
    for _ in 0..100 {
        gate.release();
    }
    assert_eq!(search.await.unwrap(), 200);
}

/// R1: a version with no date that is not among the newest has no rows; it still waits on when this firewall first saw
/// it (stamped in the stored project and carried over refreshes), so it is listed once the cooldown has passed whether or
/// not anyone asked for a file of it.
#[tokio::test]
async fn an_undated_version_beyond_the_row_window_waits_on_its_first_seen_time_and_is_then_listed() {
    let h = harness("", 7 * DAY).await;
    let many: Vec<String> = (0..5001).map(|n| format!("1.0.{n}")).collect();
    let names: Vec<&str> = many.iter().map(String::as_str).collect();
    h.registry.answer("/v3-flatcontainer/big.pkg/index.json", FakeAnswer::Body(flat_index(&names)));
    h.registry.answer(&format!("{REG}big.pkg/index.json"), FakeAnswer::Missing);
    serve_files(&h, "big.pkg", "1.0.0");
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/big.pkg/index.json").await;
    assert!(versions_of(&body).is_empty(), "every undated version waits a whole cooldown");
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.0/big.pkg.1.0.0.nupkg").await.status().as_u16(), 403, "the oldest too");
    h.clock.advance_seconds(8 * DAY as i64);
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/big.pkg/index.json").await;
    assert_eq!(versions_of(&body).len(), 5001, "the first-seen time of a version without rows is kept across refreshes");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ what only one document names

/// A version only registration names is not a downloadable one: the flat container never lists it and its files are
/// 404 (membership is the flat container's), while registration still shows it when the policy allows it.
#[tokio::test]
async fn a_version_only_registration_names_is_never_listed_by_the_flat_container_or_served() {
    let h = harness("", 0).await;
    h.registry.answer("/v3-flatcontainer/demo.pkg/index.json", FakeAnswer::Body(flat_index(&["1.0.0"])));
    let (index, _) = registration("demo.pkg", &[vec![leaf("demo.pkg", "1.0.0", Some(OLD), true), leaf("demo.pkg", "2.0.0", Some(OLD), true)]], &[]);
    h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::Body(index));
    serve_files(&h, "demo.pkg", "1.0.0");
    serve_files(&h, "demo.pkg", "2.0.0");
    let (_, body) = text_of(&h, "/nuget/v3-flatcontainer/demo.pkg/index.json").await;
    assert_eq!(versions_of(&body), ["1.0.0"]);
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/demo.pkg/2.0.0/demo.pkg.2.0.0.nupkg").await.status().as_u16(), 404);
    assert_eq!(calls_to(&h, "/2.0.0/"), 0, "its files are never fetched");
    let (_, doc) = json_of(&h, "/nuget/v3/registration/demo.pkg/index.json").await;
    assert_eq!(leaf_versions(&doc), ["1.0.0", "2.0.0"]);
    h.server.shutdown().await;
}

/// The RepositorySignatures resource is advertised only over https (NuGet refuses it over http: NU1301).
#[tokio::test]
async fn repository_signatures_are_advertised_only_when_the_public_url_is_https() {
    for (public, advertised) in [("https://packages.example.org/", true), ("http://packages.example.org/", false)] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_with(dir.path(), "", 7 * DAY);
        config.public_url = Url::parse(public).unwrap();
        let registry = FakeRegistry::new();
        registry.answer("/v3/index.json", FakeAnswer::Body(nuget::service_index(&[])));
        let clock = TestClock::at_rfc3339(NOW);
        let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
        let body = server.get("/nuget/v3/index.json").await.text().await.unwrap();
        assert_eq!(body.contains("RepositorySignatures/5.0.0"), advertised, "{public}: {body}");
        assert!(body.contains("VulnerabilityInfo/6.7.0"), "audit data is advertised over http as well: {public}");
        assert!(body.contains("PackageBaseAddress/3.0.0"), "{public}");
        server.shutdown().await;
    }
}

/// A resumed download: the `.nupkg` honours a byte range exactly (the shared artifact pipeline), and a range the
/// file cannot satisfy is 416.
#[tokio::test]
async fn a_nupkg_honours_a_byte_range() {
    let h = harness("", 0).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true)]);
    let whole = nuget::nupkg("demo.pkg", "1.0.0");
    let url = h.server.url("/nuget/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg");
    let client = reqwest::Client::new();
    let part = client.get(&url).header("range", "bytes=4-11").send().await.unwrap();
    assert_eq!(part.status().as_u16(), 206);
    assert_eq!(part.bytes().await.unwrap().to_vec(), whole[4..12].to_vec());
    let beyond = client.get(&url).header("range", format!("bytes={}-", whole.len() + 10)).send().await.unwrap();
    assert_eq!(beyond.status().as_u16(), 416);
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ F1: shared documents, bounded work

fn registration_calls(h: &Harness, id: &str) -> usize {
    calls_to(h, &format!("{REG}{id}/index.json"))
}

/// Reads share the registration documents another one fetched a few seconds ago; after the share window they are fetched
/// again (the credential-bearing case is tests/nuget_service_read.rs).
#[tokio::test]
async fn registration_documents_are_shared_for_a_few_seconds() {
    let h = harness("", 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("1.1.0", Some(YOUNG), true)]);
    for _ in 0..3 {
        assert_eq!(h.server.get("/nuget/v3/registration/demo.pkg/index.json").await.status().as_u16(), 200);
    }
    assert_eq!(registration_calls(&h, "demo.pkg"), 1, "three reads in the window cost one fetch");
    h.clock.advance_seconds(6);
    assert_eq!(h.server.get("/nuget/v3/registration/demo.pkg/index.json").await.status().as_u16(), 200);
    assert_eq!(registration_calls(&h, "demo.pkg"), 2, "after the window the documents are fetched again");
    h.server.shutdown().await;
}

/// Forty simultaneous reads of one registration cost one upstream fetch: the others wait for it and use what it stored.
#[tokio::test]
async fn simultaneous_registration_reads_cost_one_fetch() {
    let h = harness("", 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true)]);
    let gate = common::Gate::new();
    let (index, _) = registration("demo.pkg", &[vec![leaf("demo.pkg", "1.0.0", Some(OLD), true)]], &[]);
    h.registry.answer(&format!("{REG}demo.pkg/index.json"), FakeAnswer::GatedMetadata { body: index, gate: Arc::clone(&gate) });
    let server = Arc::new(h.server);
    let tasks: Vec<_> = (0..40).map(|_| {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.get("/nuget/v3/registration/demo.pkg/index.json").await.status().as_u16() })
    }).collect();
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    gate.release();
    for task in tasks {
        assert_eq!(task.await.unwrap(), 200);
    }
    assert_eq!(h.registry.calls().iter().filter(|u| u.path() == format!("{REG}demo.pkg/index.json")).count(), 1);
    assert_eq!(h.registry.calls().iter().filter(|u| u.path() == "/v3-flatcontainer/demo.pkg/index.json").count(), 1, "and one flat container read");
}

/// The vulnerability and signature documents are kept for a short time for credential-free reads (the same bytes, not
/// copies) and fetched fresh by a read that carries a credential.
#[tokio::test]
async fn aux_documents_are_cached_briefly() {
    let h = harness("", 7 * DAY).await;
    let base = format!("{INDEX_ORIGIN}/v3-vulnerabilities/1/vulnerability.base.json");
    h.registry.answer("/v3/vulnerabilities/index.json", FakeAnswer::Body(json!([{"@name": "base", "@id": base, "@updated": "x"}]).to_string()));
    h.registry.answer("/v3-vulnerabilities/1/vulnerability.base.json", FakeAnswer::Body("{}".to_owned()));
    for _ in 0..3 {
        assert_eq!(h.server.get("/nuget/v3/vulnerabilities/base.json").await.status().as_u16(), 200);
    }
    assert_eq!((calls_to(&h, "/vulnerabilities/index.json"), calls_to(&h, "vulnerability.base.json")), (1, 1));
    h.clock.advance_seconds(31);
    assert_eq!(h.server.get("/nuget/v3/vulnerabilities/base.json").await.status().as_u16(), 200);
    assert_eq!(calls_to(&h, "vulnerability.base.json"), 2);
    // A vulnerability file over its cap (32 MiB) is refused, never relayed.
    h.registry.answer("/v3-vulnerabilities/1/vulnerability.base.json", FakeAnswer::Bytes(vec![b' '; 33 << 20]));
    h.clock.advance_seconds(31);
    assert_eq!(h.server.get("/nuget/v3/vulnerabilities/base.json").await.status().as_u16(), 502);
    h.server.shutdown().await;
}

/// Search judges at most 1000 results whatever the registry sends, and at most 16 project refreshes run at once in the
/// process: 24 different projects of one registry asked for together never have more than its 4 in flight (R4).
#[tokio::test]
async fn search_work_is_bounded_per_request_and_across_requests() {
    let h = harness("", 7 * DAY).await;
    // A registry that sends 120 results: every one is judged (the ceiling is the search API's own, 1000).
    let ids: Vec<String> = (0..120).map(|n| format!("many.p{n}")).collect();
    let items: Vec<(&str, &str, &[&str])> = ids.iter().map(|id| (id.as_str(), "1.0.0", &["1.0.0"][..])).collect();
    h.registry.answer("/query", FakeAnswer::Body(search_doc(&items)));
    let (status, _) = json_of(&h, "/nuget/v3/query?q=many").await;
    assert_eq!(status, 200);
    let flat_asked = h.registry.calls().iter().filter(|u| u.path().starts_with("/v3-flatcontainer/many.p") && u.path().ends_with("/index.json")).count();
    assert_eq!(flat_asked, 120, "every returned result is judged");
    // Twenty-four different projects asked for at once, each held at the gate: no more than 16 refreshes run at a time.
    let gate = common::Gate::new();
    for n in 0..24 {
        h.registry.answer(&format!("/v3-flatcontainer/gated.p{n}/index.json"), FakeAnswer::GatedMetadata { body: flat_index(&["1.0.0"]), gate: Arc::clone(&gate) });
    }
    let server = Arc::new(h.server);
    let reads: Vec<_> = (0..24).map(|n| {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.get(&format!("/nuget/v3-flatcontainer/gated.p{n}/index.json")).await.status().as_u16() })
    }).collect();
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let in_flight = h.registry.calls().iter().filter(|u| u.path().starts_with("/v3-flatcontainer/gated.p") && u.path().ends_with("/index.json")).count();
    assert_eq!(in_flight, 4, "one registry holds at most its 4 of the 16 refresh places, the others wait");
    for _ in 0..200 {
        gate.release();
    }
    for read in reads {
        assert_eq!(read.await.unwrap(), 200);
    }
}

/// A blocked id is refused before any upstream call: no project of it is read for a search result or for `?id=` autocomplete.
#[tokio::test]
async fn blocked_ids_cost_search_and_autocomplete_no_upstream_call() {
    let h = harness(r#"{"ecosystem":"nuget","name":"evil.pkg","version":null,"reason":"malware"}"#, 7 * DAY).await;
    serve_package(&h, "evil.pkg", &[("1.0.0", Some(OLD), true)]);
    h.registry.answer("/query", FakeAnswer::Body(search_doc(&[("Evil.Pkg", "1.0.0", &["1.0.0"])])));
    h.registry.answer("/autocomplete", FakeAnswer::Body(json!({"totalHits": 1, "data": ["1.0.0"]}).to_string()));
    let (status, doc) = json_of(&h, "/nuget/v3/query?q=evil").await;
    assert_eq!((status, doc["data"].as_array().map(Vec::len)), (200, Some(0)));
    assert_eq!(calls_to(&h, "/evil.pkg/"), 0, "no project of a blocked id was read");
    assert_eq!(h.server.get("/nuget/v3/autocomplete?id=evil.pkg").await.status().as_u16(), 403);
    assert_eq!(calls_to(&h, "/autocomplete"), 0, "the registry was not asked");
    h.server.shutdown().await;
}

/// U20-2 / R2: `take` is passed on exactly, whatever its size (no 400, no clamp), so a client's own paging never skips results;
/// `supportedFramework` is passed on.
#[tokio::test]
async fn take_is_passed_on_exactly_never_refused_or_clamped() {
    let h = harness("", 7 * DAY).await;
    h.registry.answer("/query", FakeAnswer::Body(search_doc(&[])));
    for (take, expected) in [("1", 200), ("100", 200), ("101", 200), ("1000", 200), ("5000", 200), ("x", 400), ("-1", 400)] {
        assert_eq!(h.server.get(&format!("/nuget/v3/query?q=a&skip=100&take={take}&supportedFramework=net8.0")).await.status().as_u16(), expected, "take={take}");
    }
    let asked: Vec<String> = h.registry.calls().iter().filter(|u| u.path() == "/query").map(|u| u.query().unwrap_or_default().to_owned()).collect();
    assert_eq!(asked.len(), 5, "a malformed take asks upstream nothing");
    for (asked, take) in asked.iter().zip(["1", "100", "101", "1000", "5000"]) {
        assert_eq!(asked, &format!("q=a&skip=100&take={take}&supportedFramework=net8.0"), "take is passed on exactly");
    }
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ S20-3: the bounds, pinned

#[tokio::test]
async fn a_service_index_of_more_than_512_resources_is_refused() {
    let h = harness("", 7 * DAY).await;
    for (count, expected) in [(512, 200), (513, 502)] {
        let mut resources: Vec<Value> = vec![json!({"@id": format!("{INDEX_ORIGIN}{FLAT}"), "@type": "PackageBaseAddress/3.0.0"})];
        resources.extend((1..count).map(|n| json!({"@id": format!("{INDEX_ORIGIN}/other/{n}"), "@type": "Other/1.0.0"})));
        h.registry.answer("/v3/index.json", FakeAnswer::Body(json!({"version": "3.0.0", "resources": resources}).to_string()));
        h.clock.advance_seconds(120);
        assert_eq!(h.server.get("/nuget/v3/index.json").await.status().as_u16(), expected, "{count} resources");
    }
    h.server.shutdown().await;
}

fn linked_registration(h: &Harness, id: &str, pages: usize) {
    let versions: Vec<String> = (0..pages).map(|n| format!("1.0.{n}")).collect();
    let names: Vec<&str> = versions.iter().map(String::as_str).collect();
    h.registry.answer(&format!("/v3-flatcontainer/{id}/index.json"), FakeAnswer::Body(flat_index(&names)));
    let groups: Vec<Vec<Value>> = versions.iter().map(|v| vec![leaf(id, v, Some(OLD), true)]).collect();
    let (index, linked) = registration(id, &groups, &(0..pages).collect::<Vec<_>>());
    h.registry.answer(&format!("{REG}{id}/index.json"), FakeAnswer::Body(index));
    for (path, document) in linked {
        h.registry.answer(&path, FakeAnswer::Body(document));
    }
}

#[tokio::test]
async fn a_registration_of_more_than_4096_pages_is_refused_before_any_page_is_fetched() {
    let h = harness("", 7 * DAY).await;
    linked_registration(&h, "pages.pkg", 4096);
    let (status, doc) = json_of(&h, "/nuget/v3/registration/pages.pkg/index.json").await;
    assert_eq!((status, doc["items"].as_array().map(Vec::len)), (200, Some(4096)), "4096 pages are the bound itself, each linked to this firewall");
    linked_registration(&h, "toomany.pkg", 4097);
    let before = h.registry.calls().len();
    assert_eq!(h.server.get("/nuget/v3/registration/toomany.pkg/index.json").await.status().as_u16(), 502);
    assert!(h.registry.calls().len() - before <= 2, "the index and the flat container only: no page was fetched");
    h.server.shutdown().await;
}

/// One registration page is held to the document cap (a registry cannot make one request hold more than that); pages are
/// read one at a time and their bytes dropped, so many pages that are each within the cap are served.
#[tokio::test]
async fn a_registration_page_over_the_size_cap_is_refused_and_pages_within_it_are_not_added_up() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), "", 7 * DAY);
    config.max_metadata_bytes = std::num::NonZeroU64::new(1 << 20).unwrap();
    let registry = FakeRegistry::new();
    registry.answer("/v3/index.json", FakeAnswer::Body(nuget::service_index(&[])));
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, origins()).await;
    registry.answer("/v3-flatcontainer/fat.pkg/index.json", FakeAnswer::Body(flat_index(&["1.0.0", "1.0.1", "1.0.2"])));
    let groups: Vec<Vec<Value>> = (0..3).map(|n| vec![leaf("fat.pkg", &format!("1.0.{n}"), Some(OLD), true)]).collect();
    let (index, linked) = registration("fat.pkg", &groups, &[0, 1, 2]);
    registry.answer(&format!("{REG}fat.pkg/index.json"), FakeAnswer::Body(index));
    let pad = |megabytes: usize| {
        for (path, document) in &linked {
            let mut value: Value = serde_json::from_str(document).unwrap();
            value["pad"] = json!("x".repeat(megabytes << 20));
            registry.answer(path, FakeAnswer::Body(value.to_string()));
        }
    };
    // Three pages of 6 MiB (18 MiB together, over the 16 MiB cap of one document) are each within it.
    pad(6);
    assert_eq!(server.get("/nuget/v3/registration/fat.pkg/index.json").await.status().as_u16(), 200);
    // One page of 17 MiB is over it.
    clock.advance_seconds(1000);
    pad(17);
    assert_eq!(server.get("/nuget/v3/registration/fat.pkg/index.json").await.status().as_u16(), 502);
    server.shutdown().await;
}

#[tokio::test]
async fn vulnerability_and_signature_indexes_over_their_entry_bounds_are_refused() {
    let h = harness("", 7 * DAY).await;
    let file = |n: usize| json!({"@name": if n.is_multiple_of(2) { "base" } else { "update" }, "@id": format!("{INDEX_ORIGIN}/v3-vulnerabilities/{n}/v.json"), "@updated": "x"});
    for (count, expected) in [(16, 200), (17, 502)] {
        h.registry.answer("/v3/vulnerabilities/index.json", FakeAnswer::Body(Value::Array((0..count).map(file).collect()).to_string()));
        h.clock.advance_seconds(60);
        assert_eq!(h.server.get("/nuget/v3/vulnerabilities/index.json").await.status().as_u16(), expected, "vulnerability index of {count}");
        // The file route parses the same index.
        let route = h.server.get("/nuget/v3/vulnerabilities/base.json").await.status().as_u16();
        assert_eq!(route == 502 || route == 404, count == 17 || route == 404, "{count}: {route}");
    }
    let certificate = |n: usize| {
        let fingerprint = format!("{n:064x}");
        json!({"fingerprints": {"2.16.840.1.101.3.4.2.1": fingerprint}, "contentUrl": format!("{INDEX_ORIGIN}/v3-index/repository-signatures/certificates/{fingerprint}.crt")})
    };
    for (count, expected) in [(64, 200), (65, 502)] {
        h.registry.answer("/v3-index/repository-signatures/5.0.0/index.json", FakeAnswer::Body(json!({"allRepositorySigned": false, "signingCertificates": (0..count).map(certificate).collect::<Vec<_>>()}).to_string()));
        h.clock.advance_seconds(60);
        let status = h.server.get("/nuget/v3/repository-signatures/5.0.0/index.json").await.status().as_u16();
        assert_eq!(status, expected, "the signature index of {count}");
        let route = h.server.get(&format!("/nuget/v3/repository-signatures/certificates/{:064x}.crt", 1)).await.status().as_u16();
        assert_eq!(route == 502, expected == 502, "{count} certificates: {route}");
    }
    h.server.shutdown().await;
}

/// The tables the process keeps stay bounded: registration documents (8) and, with the others, never grow past their bound.
#[tokio::test]
async fn the_process_tables_are_bounded() {
    let h = harness("", 7 * DAY).await;
    for n in 0..20 {
        let id = format!("table.p{n}");
        serve_package(&h, &id, &[("1.0.0", Some(OLD), true)]);
        assert_eq!(h.server.get(&format!("/nuget/v3/registration/{id}/index.json")).await.status().as_u16(), 200);
    }
    let [services, _, raw, docs, gates] = probation::nuget::serve::table_sizes(&h.server.app());
    assert!((1..=64).contains(&services) && (1..=8).contains(&raw) && docs <= 16 && gates <= 256, "{services} {raw} {docs} {gates}");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ search and autocomplete

fn search_doc(items: &[(&str, &str, &[&str])]) -> String {
    let data: Vec<Value> = items
        .iter()
        .map(|(id, version, versions)| {
            let lower = id.to_ascii_lowercase();
            json!({
                "@id": format!("{INDEX_ORIGIN}{REG}{lower}/index.json"),
                "@type": "Package",
                "registration": format!("{INDEX_ORIGIN}{REG}{lower}/index.json"),
                "id": id, "version": version, "description": "d",
                "iconUrl": format!("{INDEX_ORIGIN}{FLAT}{lower}/{version}/icon"),
                "projectUrl": "https://project.invalid/",
                "totalDownloads": 12,
                "versions": versions.iter().map(|v| json!({"version": v, "downloads": 1, "@id": format!("{INDEX_ORIGIN}{REG}{lower}/{v}.json")})).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({"@context": {"@vocab": "http://schema.nuget.org/schema#", "@base": format!("{INDEX_ORIGIN}{REG}")}, "totalHits": items.len(), "data": data}).to_string()
}

#[tokio::test]
async fn search_shows_only_allowed_versions_drops_packages_with_none_and_rewrites_links() {
    let h = harness(r#"{"ecosystem":"nuget","name":"evil.pkg","version":null,"reason":"malware"}"#, 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("2.0.0", Some(YOUNG), true)]);
    serve_package(&h, "young.pkg", &[("1.0.0", Some(YOUNG), true)]);
    serve_package(&h, "evil.pkg", &[("1.0.0", Some(OLD), true)]);
    h.registry.answer("/query", FakeAnswer::Body(search_doc(&[("Demo.Pkg", "2.0.0", &["1.0.0", "2.0.0"]), ("Young.Pkg", "1.0.0", &["1.0.0"]), ("Evil.Pkg", "1.0.0", &["1.0.0"]), ("Unknown.Pkg", "1.0.0", &["1.0.0"])])));
    let (status, doc) = json_of(&h, "/nuget/v3/query?q=pkg&take=100&skip=0&prerelease=true&semVerLevel=2.0.0&secret=1&q=again&supportedFramework=net8.0").await;
    assert_eq!(status, 200, "{doc}");
    let data = doc["data"].as_array().unwrap();
    assert_eq!(data.len(), 1, "only a package with an allowed version, not blocked and known to the registry: {doc}");
    let item = &data[0];
    let root = "https://packages.example.org/nuget/";
    assert_eq!(item["id"], "Demo.Pkg");
    assert_eq!(item["version"], "1.0.0", "the headline becomes the best allowed version");
    assert_eq!(item["versions"].as_array().unwrap().len(), 1);
    assert_eq!(item["versions"][0]["@id"], format!("{root}v3/registration/demo.pkg/1.0.0.json"));
    assert_eq!(item["registration"], format!("{root}v3/registration/demo.pkg/index.json"));
    assert_eq!(item["iconUrl"], format!("{root}v3-flatcontainer/demo.pkg/1.0.0/icon"));
    assert_eq!(item["projectUrl"], "https://project.invalid/");
    assert_eq!(doc["@context"]["@base"], format!("{root}v3/registration/"));
    let asked: Vec<Url> = h.registry.calls().into_iter().filter(|u| u.path() == "/query").collect();
    assert_eq!(asked.len(), 1);
    let pairs: Vec<(String, String)> = asked[0].query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    assert_eq!(pairs, [("q".into(), "pkg".into()), ("take".into(), "100".into()), ("skip".into(), "0".into()), ("prerelease".into(), "true".into()), ("semVerLevel".into(), "2.0.0".into()), ("supportedFramework".into(), "net8.0".into())]);
    h.server.shutdown().await;
}

#[tokio::test]
async fn autocomplete_lists_allowed_versions_and_hides_blocked_ids() {
    let h = harness(r#"{"ecosystem":"nuget","name":"Evil.Pkg","version":null,"reason":"malware"}"#, 7 * DAY).await;
    serve_package(&h, "demo.pkg", &[("1.0.0", Some(OLD), true), ("2.0.0", Some(YOUNG), true)]);
    h.registry.answer("/autocomplete", FakeAnswer::Body(json!({"@context": {}, "totalHits": 2, "data": ["1.0.0", "2.0.0"]}).to_string()));
    let (status, doc) = json_of(&h, "/nuget/v3/autocomplete?id=Demo.Pkg&prerelease=true").await;
    assert_eq!((status, doc["data"].clone()), (200, json!(["1.0.0"])), "{doc}");
    h.registry.answer("/autocomplete", FakeAnswer::Body(json!({"totalHits": 3, "data": ["Demo.Pkg", "Evil.Pkg", "bad id"]}).to_string()));
    let (_, doc) = json_of(&h, "/nuget/v3/autocomplete?q=pkg&take=3").await;
    assert_eq!(doc["data"], json!(["Demo.Pkg"]), "a blocked id and a name that is no id are not offered");
    assert_eq!(h.server.get("/nuget/v3/autocomplete?id=bad%20id").await.status().as_u16(), 404);
    assert_eq!(h.server.get("/nuget/v3/index.json?q=1").await.status().as_u16(), 404, "only search and autocomplete take a query");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ vulnerability and signature documents

#[tokio::test]
async fn the_vulnerability_database_is_served_through_this_firewall_and_only_the_files_its_index_names() {
    let h = harness("", 7 * DAY).await;
    let base = format!("{INDEX_ORIGIN}/v3-vulnerabilities/2026.11.14/vulnerability.base.json");
    let update = format!("{INDEX_ORIGIN}/v3-vulnerabilities/2026.11.14/2026.11.19/vulnerability.update.json");
    h.registry.answer("/v3/vulnerabilities/index.json", FakeAnswer::Body(json!([
        {"@name": "base", "@id": base, "@updated": "2026-11-14T05:29:55Z", "comment": "b"},
        {"@name": "update", "@id": update, "@updated": "2026-11-19T05:30:33Z", "comment": "u"},
        {"@name": "other", "@id": "https://evil.invalid/x.json", "@updated": "2026-11-19T05:30:33Z"},
    ]).to_string()));
    h.registry.answer("/v3-vulnerabilities/2026.11.14/vulnerability.base.json", FakeAnswer::Body(r#"{"demo.pkg":[{"url":"u","severity":3,"versions":"[1.0.0, 2.0.0)"}]}"#.to_owned()));
    h.registry.answer("/v3-vulnerabilities/2026.11.14/2026.11.19/vulnerability.update.json", FakeAnswer::Body("{}".to_owned()));
    let (status, doc) = json_of(&h, "/nuget/v3/vulnerabilities/index.json").await;
    assert_eq!(status, 200, "{doc}");
    let root = "https://packages.example.org/nuget/";
    let files = doc.as_array().unwrap();
    assert_eq!(files.len(), 2, "an entry that is neither base nor update is dropped: {doc}");
    assert_eq!(files[0]["@id"], format!("{root}v3/vulnerabilities/base.json"));
    assert_eq!(files[1]["@id"], format!("{root}v3/vulnerabilities/update.json"));
    assert_eq!(files[0]["@updated"], "2026-11-14T05:29:55Z", "every other field is kept");
    let (status, body) = text_of(&h, "/nuget/v3/vulnerabilities/base.json").await;
    assert_eq!((status, body.contains("demo.pkg")), (200, true));
    assert_eq!(text_of(&h, "/nuget/v3/vulnerabilities/update.json").await, (200, "{}".to_owned()));
    assert_eq!(h.server.get("/nuget/v3/vulnerabilities/other.json").await.status().as_u16(), 404);
    // An index whose file lies on another host is refused and that host is never asked.
    h.clock.advance_seconds(60);
    h.registry.answer("/v3/vulnerabilities/index.json", FakeAnswer::Body(json!([{"@name": "base", "@id": "https://evil.invalid/base.json", "@updated": "x"}]).to_string()));
    assert_eq!(h.server.get("/nuget/v3/vulnerabilities/base.json").await.status().as_u16(), 502);
    assert!(h.registry.calls().iter().all(|url| url.host_str() != Some("evil.invalid")));
    h.server.shutdown().await;
}

#[tokio::test]
async fn repository_signature_certificates_are_served_only_for_the_fingerprints_the_index_names() {
    use sha2::Digest as _;
    let h = harness("", 7 * DAY).await;
    let der = vec![0x30, 0x82, 1, 2, 3];
    let fingerprint = hex::encode(sha2::Sha256::digest(&der));
    let fingerprint = fingerprint.as_str();
    let index = json!({"allRepositorySigned": true, "signingCertificates": [
        {"fingerprints": {"2.16.840.1.101.3.4.2.1": fingerprint}, "subject": "CN=x", "contentUrl": format!("{INDEX_ORIGIN}/v3-index/repository-signatures/certificates/{fingerprint}.crt")},
        {"fingerprints": {"2.16.840.1.101.3.4.2.1": "NOTHEX"}, "contentUrl": "https://evil.invalid/c.crt"},
    ]});
    h.registry.answer("/v3-index/repository-signatures/5.0.0/index.json", FakeAnswer::Body(index.to_string()));
    h.registry.answer(&format!("/v3-index/repository-signatures/certificates/{fingerprint}.crt"), FakeAnswer::Bytes(der.clone()));
    let (status, doc) = json_of(&h, "/nuget/v3/repository-signatures/5.0.0/index.json").await;
    assert_eq!(status, 200, "{doc}");
    let certificates = doc["signingCertificates"].as_array().unwrap();
    assert_eq!(certificates.len(), 1, "an entry without a valid fingerprint is dropped");
    assert_eq!(certificates[0]["contentUrl"], format!("https://packages.example.org/nuget/v3/repository-signatures/certificates/{fingerprint}.crt"));
    assert_eq!(doc["allRepositorySigned"], true);
    let response = h.server.get(&format!("/nuget/v3/repository-signatures/certificates/{fingerprint}.crt")).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.bytes().await.unwrap().to_vec(), der);
    // Bytes that do not hash to the fingerprint the index names are never relayed.
    h.registry.answer(&format!("/v3-index/repository-signatures/certificates/{fingerprint}.crt"), FakeAnswer::Bytes(vec![0x30, 9, 9]));
    h.clock.advance_seconds(60);
    assert_eq!(h.server.get(&format!("/nuget/v3/repository-signatures/certificates/{fingerprint}.crt")).await.status().as_u16(), 502);
    let other = "f".repeat(64);
    assert_eq!(h.server.get(&format!("/nuget/v3/repository-signatures/certificates/{other}.crt")).await.status().as_u16(), 404);
    assert_eq!(h.server.get("/nuget/v3/repository-signatures/certificates/short.crt").await.status().as_u16(), 404);
    assert_eq!(h.server.get("/nuget/v3/repository-signatures/4.7.0/index.json").await.status().as_u16(), 404, "a version the registry does not offer");
    h.server.shutdown().await;
}

// ------------------------------------------------------------------ bounded transfers

/// A transport that holds the `.nupkg` of one package until released, to model a large transfer in flight.
struct Slow {
    inner: Arc<FakeRegistry>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl Transport for Slow {
    async fn fetch_metadata(&self, request: probation::upstream::MetadataRequest) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError> {
        self.inner.fetch_metadata(request).await
    }
    async fn open_artifact(&self, request: probation::upstream::ArtifactRequest) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
        if request.url.path().contains("/slow.pkg/") && request.url.path().ends_with(".nupkg") {
            let _ = self.release.acquire().await.map(|permit| permit.forget());
        }
        self.inner.open_artifact(request).await
    }
}

#[tokio::test]
async fn tiny_files_do_not_queue_behind_large_transfers() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with(dir.path(), "", 0);
    config.max_artifact_downloads = std::num::NonZeroU32::new(1).unwrap();
    config.download_wait_seconds = 1;
    let registry = FakeRegistry::new();
    registry.answer("/v3/index.json", FakeAnswer::Body(nuget::service_index(&[])));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let transport = Arc::new(Slow { inner: Arc::clone(&registry), release: Arc::clone(&release) });
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(config, clock.shared(), transport as Arc<dyn Transport>, origins()).await;
    let h = Harness { server, registry, clock, _dir: dir };
    serve_package(&h, "slow.pkg", &[("1.0.0", Some(OLD), true)]);
    serve_package(&h, "other.pkg", &[("1.0.0", Some(OLD), true)]);
    let server = Arc::new(h.server);
    let big = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.get("/nuget/v3-flatcontainer/slow.pkg/1.0.0/slow.pkg.1.0.0.nupkg").await.status().as_u16() })
    };
    for _ in 0..300 {
        if h.registry.calls().iter().any(|url| url.path().ends_with("slow.pkg.1.0.0.nupkg")) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for file in ["other.pkg.nuspec", "readme", "icon"] {
        let answer = tokio::time::timeout(std::time::Duration::from_secs(3), server.get(&format!("/nuget/v3-flatcontainer/other.pkg/1.0.0/{file}"))).await.expect("a small file waits for no large transfer");
        assert_eq!(answer.status().as_u16(), 200, "{file}");
    }
    release.add_permits(8);
    assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(10), big).await.unwrap().unwrap(), 200);
}

#[tokio::test]
async fn small_files_are_read_only_to_their_own_cap() {
    let h = harness("", 0).await;
    serve_package(&h, "big.pkg", &[("1.0.0", Some(OLD), true), ("1.0.1", Some(OLD), true)]);
    h.registry.answer("/v3-flatcontainer/big.pkg/1.0.0/big.pkg.nuspec", FakeAnswer::Bytes(vec![b'x'; 17 << 20]));
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.0/big.pkg.nuspec").await.status().as_u16(), 502, "a nuspec over 16 MiB");
    h.registry.answer("/v3-flatcontainer/big.pkg/1.0.1/big.pkg.nuspec", FakeAnswer::Bytes(vec![b'x'; 1 << 20]));
    assert_eq!(h.server.get("/nuget/v3-flatcontainer/big.pkg/1.0.1/big.pkg.nuspec").await.status().as_u16(), 200);
    h.server.shutdown().await;
}

#[tokio::test]
async fn a_large_registration_is_not_refused_before_its_cap() {
    let h = harness("", 0).await;
    let versions: Vec<String> = (0..4000).map(|n| format!("1.0.{n}")).collect();
    let names: Vec<&str> = versions.iter().map(String::as_str).collect();
    h.registry.answer("/v3-flatcontainer/large.pkg/index.json", FakeAnswer::Body(flat_index(&names)));
    let pages: Vec<Vec<Value>> = versions.chunks(64).map(|chunk| chunk.iter().map(|v| leaf("large.pkg", v, Some(OLD), true)).collect()).collect();
    let (index, _) = registration("large.pkg", &pages, &[]);
    assert!(index.len() > 3_000_000, "{}", index.len());
    h.registry.answer(&format!("{REG}large.pkg/index.json"), FakeAnswer::Body(index));
    let (status, doc) = json_of(&h, "/nuget/v3/registration/large.pkg/index.json").await;
    assert_eq!((status, leaf_versions(&doc).len()), (200, 4000));
    h.server.shutdown().await;
}
