//! Slice 27: the nine transports in shared-service mode through the real router, for the cross-plan
//! acceptance walk (tests/cross_plan_acceptance.rs), the rated-load test (tests/transport_rated_load.rs)
//! and the hot-path bench (benches/transport_hot_paths.rs).
//!
//! What is measured is the in-process path a request takes in the shared service: peer admission, Host
//! check, route classification, registry resolution from the pushed snapshot, the policy decision and the
//! (in-process fake) upstream. No socket and no TLS are involved, and the client runs on the same cores as
//! the server, so a figure here is a floor for CPU cost, not a network figure.

/// How the stated bounds of this slice are derived, ONE rule for the debug test and the release bench: run the measurement `RUNS` times on the
/// development host, take the WORST value of each kind (the highest latency, the lowest throughput), and multiply (or divide) by `MARGIN`; the
/// result is rounded further in the safe direction (up for a ceiling, down for a floor). A host more than `MARGIN` times slower than the
/// development host in the worst run fails and the bounds must be re-derived, which docs/operations.md ("Rated load per transport") says.
pub const RUNS: usize = 5;
pub const MARGIN: f64 = 4.0;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::Transport;
use probation_policy::api::*;
use probation_policy::{Ecosystem, Layer, LayerKind, OsvSetting, PlaceRef};
use tower::ServiceExt;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

use super::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins, fixture, npm_upstream_path};

/// The snapshot's descriptors: one registry per family.
pub fn snapshot() -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    let descriptor = |id, ecosystem, target: Option<&str>| RegistryDescriptor {
        registry: RegistryId(id), ecosystem, target_url: target.map(str::to_owned), trusted: false,
        registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None, token_origin: None,
    };
    ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer { freeze_seconds: Some(0), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![
            descriptor(3, Ecosystem::Npm, None), descriptor(4, Ecosystem::PyPi, None), descriptor(5, Ecosystem::RubyGems, None),
            descriptor(7, Ecosystem::Cargo, Some("https://cargo-reg.invalid/")), descriptor(6, Ecosystem::Go, Some("https://go-reg.invalid/")),
            descriptor(8, Ecosystem::NuGet, Some("https://nuget-reg.invalid/v3/index.json")), descriptor(9, Ecosystem::Maven, Some("https://maven-reg.invalid/repo/")),
            descriptor(10, Ecosystem::Conan, Some("https://conan-reg.invalid/repo/")), descriptor(11, Ecosystem::Oci, Some("https://oci-reg.invalid/repo/")),
        ],
    }
}

/// A shared service that admits `10.1.0.0/16` and loopback, with the fake registry answering the warm npm fixture.
/// The fourth value owns the server's scratch directory (the blocklist file): keep it bound for as long as the server runs, and it is removed when it drops.
pub async fn service() -> (TestServer, Arc<FakeRegistry>, MockServer, tempfile::TempDir) {
    let policy_server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot")).respond_with(ResponseTemplate::new(200).set_body_json(snapshot())).mount(&policy_server).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.allowed_peer_cidrs = vec!["10.1.0.0/16".parse().unwrap()];
    // A small decision-log queue: what the delivery pipeline may hold is then a stated, small bound, so growth beyond it is not the queue.
    config.log_queue_max_bytes = std::num::NonZeroU64::new(64 * 1024 * 1024).unwrap();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy_server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(WIDGET), FakeAnswer::Body(fixture("npm/representative-100-versions.json")));
    let server = TestServer::start_with_upstream(config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(), Arc::clone(&registry) as Arc<dyn Transport>, fake_origins()).await;
    (server, registry, policy_server, dir)
}

/// The npm package of the warm fixture (100 versions, one held by the cooldown).
pub const WIDGET: &str = "fixture-widget";

/// The request a client sends: peer address, verb, path and headers, through the real router.
pub fn request(peer: &str, method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo(format!("{peer}:50000").parse::<SocketAddr>().unwrap()));
    request
}

pub async fn from_peer(server: &TestServer, peer: &str, method: &str, uri: &str, headers: &[(&str, &str)]) -> StatusCode {
    probation::http::router(server.app()).oneshot(request(peer, method, uri, headers)).await.unwrap().status()
}

/// A read, and the write (or the absence of one) of each family, on its `/registry/<tag>/<id>/` route.
pub struct Surface {
    pub ecosystem: Ecosystem,
    /// The registry id of the snapshot's descriptor.
    pub id: u32,
    pub read: &'static str,
    /// `None`: the family has no write route (Go modules are read-only).
    pub write: Option<(&'static str, &'static str)>,
    /// The one status the read answers against the in-process fake: 200 for npm's warm document and Conan's ping (served locally),
    /// the fake's miss (404, or 502 where the family reports an upstream failure) for the rest. A measurement that sees any other
    /// status is not measuring this path, and fails.
    pub expected: u16,
}

pub fn surfaces() -> Vec<Surface> {
    let s = |ecosystem, id, read, write| {
        let expected = match ecosystem {
            Ecosystem::Npm | Ecosystem::Conan => 200,
            Ecosystem::Cargo | Ecosystem::NuGet | Ecosystem::Oci => 502,
            Ecosystem::PyPi | Ecosystem::RubyGems | Ecosystem::Go | Ecosystem::Maven => 404,
        };
        Surface { ecosystem, id, read, write, expected }
    };
    vec![
        s(Ecosystem::Npm, 3, "/registry/npm/3/left-pad", Some(("PUT", "/registry/npm/3/left-pad"))),
        s(Ecosystem::PyPi, 4, "/registry/pypi/4/simple/requests/", Some(("POST", "/registry/pypi/4/"))),
        s(Ecosystem::RubyGems, 5, "/registry/rubygems/5/info/rake", Some(("POST", "/registry/rubygems/5/api/v1/gems"))),
        s(Ecosystem::Cargo, 7, "/registry/cargo/7/config.json", Some(("PUT", "/registry/cargo/7/api/v1/crates/new"))),
        s(Ecosystem::Go, 6, "/registry/go/6/example.com/m/@v/list", None),
        s(Ecosystem::NuGet, 8, "/registry/nuget/8/v3/index.json", Some(("PUT", "/registry/nuget/8/api/v2/package"))),
        s(Ecosystem::Maven, 9, "/registry/maven/9/org/x/a/maven-metadata.xml", Some(("PUT", "/registry/maven/9/org/x/a/1.0/a-1.0.jar"))),
        s(Ecosystem::Conan, 10, "/registry/conan/10/v1/ping", Some(("PUT", "/registry/conan/10/v2/conans/p/1.0/_/_/revisions/abc/files/conanfile.py"))),
        s(Ecosystem::Oci, 11, "/registry/oci/11/v2/", Some(("POST", "/registry/oci/11/v2/app/blobs/uploads/"))),
    ]
}

/// The hot read of a family for the load measurements. With `warm_metadata` the npm read is the warm
/// 100-version metadata document (a real filtered response: the bench measures it in a release build, a
/// debug build is too slow to bound it); every other family's read is the surface's own read route, which
/// the in-process fake answers with whatever it has (the status is reported with every figure).
pub fn hot_read(surface: &Surface, warm_metadata: bool) -> String {
    match surface.ecosystem {
        Ecosystem::Npm if warm_metadata => format!("/registry/npm/3/{WIDGET}"),
        _ => surface.read.to_owned(),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Latency {
    pub samples: usize,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub max: Duration,
}

pub fn latency(mut samples: Vec<Duration>) -> Latency {
    samples.sort_unstable();
    let at = |q: f64| samples[(((samples.len() as f64) * q).ceil() as usize).clamp(1, samples.len()) - 1];
    Latency { samples: samples.len(), p50: at(0.50), p95: at(0.95), p99: at(0.99), max: *samples.last().unwrap() }
}

/// `n` sequential requests; the statuses seen (sorted, deduplicated) say what was measured.
pub async fn sequential(router: &axum::Router, peer: &str, method: &str, uri: &str, headers: &[(&str, &str)], n: usize) -> (Latency, Vec<u16>) {
    let mut times = Vec::with_capacity(n);
    let mut statuses = Vec::new();
    for _ in 0..n {
        let started = Instant::now();
        let status = router.clone().oneshot(request(peer, method, uri, headers)).await.unwrap().status().as_u16();
        times.push(started.elapsed());
        if !statuses.contains(&status) {
            statuses.push(status);
        }
    }
    statuses.sort_unstable();
    (latency(times), statuses)
}

/// `concurrency` clients hammering one route for `duration`: the requests that answered `expect` (a 404 fast path or an error
/// is NOT a valid answer and is not counted), their rate per second, and the number of other answers (callers assert it is 0).
pub async fn concurrent(router: &axum::Router, peer: &'static str, uri: String, headers: &'static [(&'static str, &'static str)], concurrency: usize, duration: Duration, expect: u16) -> (u64, f64, u64) {
    let deadline = Instant::now() + duration;
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..concurrency {
        let router = router.clone();
        let uri = uri.clone();
        tasks.push(tokio::spawn(async move {
            let (mut valid, mut other) = (0u64, 0u64);
            while Instant::now() < deadline {
                let response = router.clone().oneshot(request(peer, "GET", &uri, headers)).await.unwrap();
                let status = response.status().as_u16();
                // The body is read, as a client would: a response that is never drained costs nothing.
                let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;
                if status == expect { valid += 1 } else { other += 1 }
            }
            (valid, other)
        }));
    }
    let (mut valid, mut other) = (0, 0);
    for task in tasks {
        let (v, o) = task.await.unwrap();
        valid += v;
        other += o;
    }
    (valid, valid as f64 / started.elapsed().as_secs_f64(), other)
}

/// The warm npm read answers the real filtered document: 200, JSON, the fixture's package name and its versions (the cooldown holds one
/// back). Returns the version count. A fast 404 (a broken fixture path) fails here, not in a latency bound.
pub async fn assert_warm_npm_document(router: &axum::Router, peer: &str, host: &[(&str, &str)]) -> usize {
    let response = router.clone().oneshot(request(peer, "GET", &format!("/registry/npm/3/{WIDGET}"), host)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "the warm npm document is served");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let document: serde_json::Value = serde_json::from_slice(&bytes).expect("the warm npm document is JSON");
    assert_eq!(document["name"], WIDGET, "the document is the fixture package's");
    let versions = document["versions"].as_object().expect("a versions object").len();
    assert!(versions >= 90, "the document carries the fixture's versions (the cooldown holds back at most a few), got {versions}");
    versions
}

/// The resident set of this process, in KiB (Linux `VmRSS`, else `ps`); panics where neither exists.
pub fn rss_kib() -> u64 {
    let proc = std::fs::read_to_string("/proc/self/status").ok().and_then(|text| {
        text.lines().find_map(|line| line.strip_prefix("VmRSS:").and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok()))
    });
    // macOS and the BSDs: `ps -o rss=` (KiB). A figure that cannot be read fails the run: a bound checked against 0 would pass vacuously.
    proc.or_else(|| {
        let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().ok()?;
        String::from_utf8(out.stdout).ok()?.trim().parse().ok()
    }).expect("the resident set size of this process cannot be read on this OS (no /proc, no ps)")
}
