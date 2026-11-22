//! Slice 27 fix round (C): shared-service npm and PyPI metadata reads. A credential-free read shares one fetched
//! project for a few seconds (as cargo, NuGet, Maven and RubyGems do), so the hot read is not an upstream revalidation
//! plus a store commit per request; a read that carries the caller's credential never reads or fills the share, and a
//! published policy governs the very next read.
mod common;

use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins, npm_upstream_path, pypi_upstream_path};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::Transport;
use probation_policy::api::*;
use probation_policy::{Block, Ecosystem, Layer, LayerKind, OsvSetting, PlaceRef};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU64, sync::Arc};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

fn snapshot(revision: u64, blocked: bool) -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    let descriptor = |id, ecosystem| RegistryDescriptor {
        registry: RegistryId(id), ecosystem, target_url: None, trusted: false,
        registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None, token_origin: None,
    };
    ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer {
                freeze_seconds: Some(0), osv: Some(OsvSetting::Off),
                blocks: if blocked && place.kind == LayerKind::Org {
                    vec![Block::Package { ecosystem: Ecosystem::Npm, name: "open-pkg".into(), reason: None }, Block::Package { ecosystem: Ecosystem::PyPi, name: "open-proj".into(), reason: None }]
                } else { vec![] },
                ..Layer::empty(place.kind)
            },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![descriptor(3, Ecosystem::Npm), descriptor(4, Ecosystem::PyPi)],
    }
}

struct Fixture {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    policy: MockServer,
    _dir: tempfile::TempDir,
}

async fn start() -> Fixture {
    let policy = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot(1, false))).mount(&policy).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path("open-pkg"), FakeAnswer::Body(serde_json::json!({
        "name":"open-pkg", "dist-tags":{"latest":"1.0.0"},
        "versions":{"1.0.0":{"name":"open-pkg","version":"1.0.0","dist":{"tarball":"https://npm.invalid/open-pkg/-/open-pkg-1.0.0.tgz",
            "integrity":format!("sha256-{}", common::sync::base64(Sha256::digest(b"open bytes")))}}},
        "time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    registry.answer(&pypi_upstream_path("open-proj"), FakeAnswer::Body(serde_json::json!({
        "meta":{"api-version":"1.1"}, "name":"open-proj", "files":[{
            "filename": "open_proj-1.0.0-py3-none-any.whl", "url": "https://files.invalid/packages/open_proj-1.0.0-py3-none-any.whl",
            "hashes":{"sha256": hex::encode(Sha256::digest(b"w"))}, "upload-time":"2026-01-01T00:00:00Z"
        }]
    }).to_string()));
    let clock = TestClock::at_rfc3339("2026-04-06T12:00:00Z");
    let server = TestServer::start_with_upstream(config, clock.shared(), Arc::clone(&registry) as Arc<dyn Transport>, fake_origins()).await;
    Fixture { server, registry, clock, policy, _dir: dir }
}

fn calls(f: &Fixture, path: &str) -> usize {
    f.registry.calls().iter().filter(|url| url.path() == path).count()
}

const PYPI_JSON: [(&str, &str); 1] = [("accept", "application/vnd.pypi.simple.v1+json")];

#[tokio::test]
async fn service_mode_npm_and_pypi_metadata_reads_are_shared_for_plain_reads_and_never_for_credentialed_ones() {
    let f = start().await;
    let npm = npm_upstream_path("open-pkg");
    let pypi = pypi_upstream_path("open-proj");
    for _ in 0..3 {
        assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
        assert_eq!(f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &PYPI_JSON).await.status(), 200);
    }
    assert_eq!(calls(&f, &npm), 1, "three plain npm reads cost one upstream fetch");
    assert_eq!(calls(&f, &pypi), 1, "three plain PyPI reads cost one upstream fetch");
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &PYPI_JSON).await.status(), 200);
    assert_eq!((calls(&f, &npm), calls(&f, &pypi)), (2, 2), "the share is short");
    // Past the share's lifetime, so the table is EMPTY: only a credential-bearing read could fill it now, and none may.
    f.clock.advance_seconds(10);
    let (npm_before, pypi_before) = (calls(&f, &npm), calls(&f, &pypi));
    for round in 0..3 {
        let credentialed = f.server.get_with_headers("/registry/npm/3/open-pkg", &[("authorization", "Basic dDp0"), ("accept", "application/json")]).await;
        let (status, body) = (credentialed.status(), credentialed.text().await.unwrap());
        assert_eq!(status, 200, "round {round}: {body}");
        let mut headers = PYPI_JSON.to_vec();
        headers.push(("authorization", "Basic dDp0"));
        assert_eq!(f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &headers).await.status(), 200);
    }
    assert_eq!((calls(&f, &npm), calls(&f, &pypi)), (npm_before + 3, pypi_before + 3), "a credential-bearing read never reads the share");
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), npm_before + 4, "none of them filled it: the first plain read had to fetch for itself");
    assert_eq!(f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &PYPI_JSON).await.status(), 200);
    assert_eq!(calls(&f, &pypi), pypi_before + 4, "PyPI: none of the credentialed reads filled it either");
    f.server.shutdown().await;
}

#[tokio::test]
async fn a_policy_publication_governs_the_next_shared_read() {
    let f = start().await;
    let npm = npm_upstream_path("open-pkg");
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), 1);
    f.policy.reset().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot(2, true))).mount(&f.policy).await;
    f.server.app().service_policy().unwrap().sync_once().await.unwrap();
    let blocked = f.server.get("/registry/npm/3/open-pkg").await;
    assert_ne!(blocked.status(), 200, "the block published a moment ago governs a read the share could still answer");
    assert!(!blocked.text().await.unwrap().contains("1.0.0"), "no version is advertised under the new policy");
    let pypi = f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &PYPI_JSON).await;
    let body = pypi.text().await.unwrap();
    assert!(!body.contains("open_proj-1.0.0"), "PyPI: the block governs too: {body}");
    f.server.shutdown().await;
}

async fn publish(f: &Fixture, snapshot: ServicePolicySnapshot) {
    f.policy.reset().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot)).mount(&f.policy).await;
    f.server.app().service_policy().unwrap().sync_once().await.unwrap();
}

/// The share never crosses registries or origins: a second registry of the same family asks its own upstream, and a registry whose target
/// a publication moved to another origin is not answered from what the old origin served.
#[tokio::test]
async fn the_share_is_per_registry_and_per_origin() {
    let f = start().await;
    let npm = npm_upstream_path("open-pkg");
    let mut second = snapshot(2, false);
    let sibling = RegistryDescriptor { registry: RegistryId(5), ..second.registries[0].clone() };
    let pypi_sibling = RegistryDescriptor { registry: RegistryId(6), ..second.registries[1].clone() };
    second.registries.push(sibling);
    second.registries.push(pypi_sibling);
    publish(&f, second.clone()).await;
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), 1);
    assert_eq!(f.server.get("/registry/npm/5/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), 2, "registry 5 does not read what registry 3 fetched");
    let pypi = pypi_upstream_path("open-proj");
    assert_eq!(f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &PYPI_JSON).await.status(), 200);
    assert_eq!(calls(&f, &pypi), 1);
    assert_eq!(f.server.get_with_headers("/registry/pypi/6/simple/open-proj/", &PYPI_JSON).await.status(), 200);
    assert_eq!(calls(&f, &pypi), 2, "PyPI registry 6 does not read what registry 4 fetched");
    let moved_before = f.registry.calls().iter().filter(|url| url.host_str() == Some("npm-b.invalid")).count();
    second.revision = 3;
    second.registries[0].target_url = Some("https://npm-b.invalid/".into());
    publish(&f, second).await;
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    let moved = f.registry.calls().iter().filter(|url| url.host_str() == Some("npm-b.invalid")).count();
    assert_eq!(moved, moved_before + 1, "registry 3 now reads from its new origin, not from the share its old origin filled");
    f.server.shutdown().await;
}

/// The table is bounded (256 projects): a full table evicts its OLDEST cell, so the first project is fetched again while the rest stay shared,
/// and memory never holds more than the cap however many projects are read.
#[tokio::test]
async fn the_share_holds_at_most_256_projects() {
    let f = start().await;
    for n in 0..258 {
        let name = format!("bulk-{n}");
        f.registry.answer(&npm_upstream_path(&name), FakeAnswer::Body(serde_json::json!({
            "name": name, "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"name": name, "version": "1.0.0", "dist": {"tarball": format!("https://npm.invalid/{name}/-/{name}-1.0.0.tgz"),
                "integrity": format!("sha256-{}", common::sync::base64(Sha256::digest(b"bulk bytes")))}}},
            "time": {"1.0.0": "2026-01-01T00:00:00Z"}
        }).to_string()));
    }
    let first = npm_upstream_path("bulk-0");
    assert_eq!(f.server.get("/registry/npm/3/bulk-0").await.status(), 200);
    assert_eq!(f.server.get("/registry/npm/3/bulk-0").await.status(), 200);
    assert_eq!(calls(&f, &first), 1, "while the table is not full a repeated read is shared");
    for n in 1..257 {
        assert_eq!(f.server.get(&format!("/registry/npm/3/bulk-{n}")).await.status(), 200);
    }
    assert_eq!(f.server.get("/registry/npm/3/bulk-0").await.status(), 200);
    assert_eq!(calls(&f, &first), 2, "the 257th distinct project found the table full: the oldest cell (the first project) was evicted, so it is fetched again");
    let second = npm_upstream_path("bulk-2");
    let before = calls(&f, &second);
    assert_eq!(f.server.get("/registry/npm/3/bulk-2").await.status(), 200);
    assert_eq!(calls(&f, &second), before, "only the oldest cell went: the table was not cleared");
    f.server.shutdown().await;
}

// ---- Fix round 4: artifact requests never touch the share; the share is bounded by bytes; one fetch per cold burst ----

const NPM_TARBALL: &str = "/registry/npm/3/open-pkg/-/open-pkg-1.0.0.tgz";

fn npm_doc(name: &str, version: &str, padding: usize) -> String {
    serde_json::json!({
        "name": name, "description": "x".repeat(padding), "dist-tags": {"latest": version},
        "versions": {version: {"name": name, "version": version, "dist": {"tarball": format!("https://npm.invalid/{name}/-/{name}-{version}.tgz"),
            "integrity": format!("sha256-{}", common::sync::base64(Sha256::digest(b"open bytes")))}}},
        "time": {version: "2026-01-01T00:00:00Z"}
    }).to_string()
}

fn seed_artifacts(f: &Fixture) {
    f.registry.answer(&common::npm_artifact_upstream_path("open-pkg", "open-pkg-1.0.0.tgz"), FakeAnswer::Body("open bytes".into()));
    f.registry.answer("/packages/open_proj-1.0.0-py3-none-any.whl", FakeAnswer::Body("w".into()));
}

/// F2 (owner decision): the share serves metadata only. An ARTIFACT request in the same window goes upstream (credential-free or not),
/// and neither reads nor fills the share.
#[tokio::test]
async fn artifact_requests_always_revalidate_upstream_and_never_use_the_share() {
    let f = start().await;
    seed_artifacts(&f);
    let (npm, pypi) = (npm_upstream_path("open-pkg"), pypi_upstream_path("open-proj"));
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &PYPI_JSON).await.status(), 200);
    assert_eq!((calls(&f, &npm), calls(&f, &pypi)), (1, 1), "(a) the metadata reads shared one fetch each");
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), 1, "(a) a second credential-free metadata read within the window is served from the share");
    let listing: serde_json::Value = serde_json::from_str(&f.server.get_with_headers("/registry/pypi/4/simple/open-proj/", &PYPI_JSON).await.text().await.unwrap()).unwrap();
    let wheel = reqwest::Url::parse(listing["files"][0]["url"].as_str().unwrap()).unwrap().path().to_owned();
    // An artifact request revalidates its project upstream (the download path may ask more than once), so it is a count that RISES.
    for round in 1..3 {
        let before = (calls(&f, &npm), calls(&f, &pypi));
        assert_eq!(f.server.get(NPM_TARBALL).await.text().await.unwrap(), "open bytes");
        assert!(calls(&f, &npm) > before.0, "(b) npm artifact request {round}: it revalidated upstream inside the share's window");
        assert_eq!(f.server.get(&wheel).await.text().await.unwrap(), "w");
        assert!(calls(&f, &pypi) > before.1, "(b) PyPI artifact request {round}: it revalidated upstream inside the share's window");
    }
    let before = calls(&f, &npm);
    let authorized = f.server.get_with_headers(NPM_TARBALL, &[("authorization", "Basic dDp0")]).await;
    assert_eq!(authorized.status(), 200);
    assert!(calls(&f, &npm) > before, "(c) a credentialed artifact request goes upstream too");
    // The share still answers metadata (an artifact request did not drop it) ...
    let before = calls(&f, &npm);
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), before, "the artifact requests did not evict the metadata cell");
    // ... and an artifact request never fills it: with the table empty, a plain metadata read after one must fetch for itself.
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get(NPM_TARBALL).await.status(), 200);
    let before = calls(&f, &npm);
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), before + 1, "an artifact request did not fill the share");
    f.server.shutdown().await;
}

/// F2 (d): an upstream takedown or yank is visible to an artifact request at once, though a metadata read filled the share a moment ago.
#[tokio::test]
async fn an_upstream_takedown_is_seen_by_the_next_artifact_request() {
    let f = start().await;
    seed_artifacts(&f);
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(f.server.get(NPM_TARBALL).await.status(), 200);
    f.registry.answer(&npm_upstream_path("open-pkg"), FakeAnswer::Body(npm_doc("open-pkg", "2.0.0", 0)));
    let taken_down = f.server.get(NPM_TARBALL).await;
    assert_eq!(taken_down.status(), 404, "the yanked version is unavailable at once, though its bytes are still upstream and the share holds the old listing");
    f.server.shutdown().await;
}

/// F4: a cold burst of credential-free reads of one project costs one upstream fetch.
#[tokio::test]
async fn a_cold_burst_of_plain_reads_costs_one_upstream_fetch() {
    let f = start().await;
    f.registry.set_delay_ms(400);
    let npm = npm_upstream_path("open-pkg");
    let reads: Vec<_> = (0..12).map(|_| { let url = f.server.url("/registry/npm/3/open-pkg"); tokio::spawn(async move { reqwest::get(url).await.unwrap().status() }) }).collect();
    for read in reads {
        assert_eq!(read.await.unwrap(), 200);
    }
    assert_eq!(calls(&f, &npm), 1, "twelve concurrent reads of a cold project shared one fetch");
    f.server.shutdown().await;
}

/// F4: a failing first fetch is never cached and never hangs the waiters; the next read after upstream recovers succeeds with one fetch.
#[tokio::test]
async fn a_failed_first_fetch_is_not_cached_and_hangs_nobody() {
    let f = start().await;
    f.registry.answer(&npm_upstream_path("open-pkg"), FakeAnswer::Fail(probation::upstream::UpstreamError::Status(503)));
    f.registry.set_delay_ms(200);
    let reads: Vec<_> = (0..6).map(|_| { let url = f.server.url("/registry/npm/3/open-pkg"); tokio::spawn(async move { reqwest::get(url).await.unwrap().status() }) }).collect();
    for read in reads {
        let status = tokio::time::timeout(std::time::Duration::from_secs(20), read).await.expect("no waiter hangs").unwrap();
        assert_ne!(status, 200, "the failure reached the caller");
    }
    f.registry.set_delay_ms(0);
    f.registry.answer(&npm_upstream_path("open-pkg"), FakeAnswer::Body(npm_doc("open-pkg", "1.0.0", 0)));
    let npm = npm_upstream_path("open-pkg");
    let before = calls(&f, &npm);
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    assert_eq!(calls(&f, &npm), before + 1, "the failure was not cached: one fetch served the recovery and the read after it");
    f.server.shutdown().await;
}

fn answer_large(f: &Fixture, name: &str, padding: usize) {
    f.registry.answer(&npm_upstream_path(name), FakeAnswer::Body(npm_doc(name, "1.0.0", padding)));
}

/// F1: the table is bounded by bytes (256 MiB in all), the oldest cells go first, expired cells are removed on the next put, and a document
/// above the per-cell cap (32 MiB) is served but not kept.
#[tokio::test]
async fn the_share_is_bounded_by_bytes_and_drops_expired_and_oversized_cells() {
    let f = start().await;
    const MIB: usize = 1 << 20;
    for n in 0..20 {
        answer_large(&f, &format!("big-{n}"), 16 * MIB);
    }
    for n in 0..20 {
        assert_eq!(f.server.get(&format!("/registry/npm/3/big-{n}")).await.status(), 200);
        let (cells, bytes) = f.server.app().service_share_stats();
        assert!(bytes <= 256 * MIB as u64, "after {n} large reads the share accounts {bytes} bytes in {cells} cells");
    }
    let (cells, bytes) = f.server.app().service_share_stats();
    assert!((13..=16).contains(&cells) && bytes > 200 * MIB as u64, "the budget is used, not exceeded: {cells} cells, {bytes} bytes");
    let (newest, middle_old, oldest) = (npm_upstream_path("big-19"), npm_upstream_path("big-12"), npm_upstream_path("big-0"));
    let before = (calls(&f, &newest), calls(&f, &middle_old), calls(&f, &oldest));
    for name in ["big-19", "big-12"] {
        assert_eq!(f.server.get(&format!("/registry/npm/3/{name}")).await.status(), 200);
    }
    assert_eq!((calls(&f, &newest), calls(&f, &middle_old)), (before.0, before.1), "recent cells survive the pressure: the table is not cleared");
    assert_eq!(f.server.get("/registry/npm/3/big-0").await.status(), 200);
    assert_eq!(calls(&f, &oldest), before.2 + 1, "the oldest cells were evicted to make room");
    // Expired cells leave on the next put, even though the table is nowhere near full.
    f.clock.advance_seconds(10);
    assert_eq!(f.server.get("/registry/npm/3/open-pkg").await.status(), 200);
    let (cells, bytes) = f.server.app().service_share_stats();
    assert_eq!(cells, 1, "every expired cell was removed by that put ({bytes} bytes left)");
    assert!(bytes < MIB as u64);
    // A document above the per-cell cap is served and never kept.
    answer_large(&f, "huge", 33 * MIB);
    let huge = npm_upstream_path("huge");
    assert_eq!(f.server.get("/registry/npm/3/huge").await.status(), 200);
    assert_eq!(f.server.get("/registry/npm/3/huge").await.status(), 200);
    assert_eq!(calls(&f, &huge), 2, "a 33 MiB document is not shared");
    assert_eq!(f.server.app().service_share_stats().0, 1, "and it holds no cell");
    f.server.shutdown().await;
}
