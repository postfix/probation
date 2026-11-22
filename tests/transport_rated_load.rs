//! Slice 27 rated load: the hot path of every one of the nine transports in shared-service mode, through
//! the real router, with stated bounds that were MEASURED on the development host (the figures are in
//! docs/operations.md, "Rated load per transport"; the release-build figures come from
//! `cargo bench --bench transport_hot_paths`). A debug build is several times slower than a release one.
//! Every bound below is the worst of `RUNS` (5) runs of this test multiplied (ceilings) or divided (floors) by
//! `MARGIN` (4), the one rule of tests/common/transport_load.rs, rounded in the safe direction.
//!
//! The path measured: peer admission, Host check, route classification, registry resolution from the
//! pushed snapshot, the policy decision and the in-process fake upstream; no socket, no TLS (see
//! tests/common/transport_load.rs). Every read must answer its one known status (npm: the real warm 100-version document, shared for a few
//! seconds by src/service_share.rs; Conan: its ping; the rest: the fake's miss), so a fast 404 cannot pass as a hot path.
//! Run alone: `cargo test --test transport_rated_load -- --nocapture`.

mod common;

use std::time::Duration;

use common::transport_load::{assert_warm_npm_document, concurrent, hot_read, rss_kib, sequential, service, surfaces};
use probation_policy::Ecosystem;

/// Sequential samples per route and family.
const SAMPLES: usize = 100;
/// Concurrent clients and how long they run on the hot read of each family.
const CLIENTS: usize = 16;
const RUN: Duration = Duration::from_millis(1000);

/// Debug-build bounds. Worst of five runs on the development host (host load average 30), then x4 / /4: eight cheap reads p95 worst 0.457 ms
/// (bound 1.9 ms), npm's warm document p95 worst 27.6 ms (110 ms), refusal p95 worst 0.096 ms (0.4 ms), write refusal p95 worst 0.424 ms
/// (1.7 ms), cheap reads at least 2,903 per second at 16 clients (floor 700), npm at least 122 per second (floor 30), resident growth worst
/// 8,376 KiB (34 MiB).
const P95_READ: Duration = Duration::from_micros(1900);
const P95_NPM_READ: Duration = Duration::from_millis(110);
const P95_REFUSAL: Duration = Duration::from_micros(400);
const P95_WRITE_REFUSAL: Duration = Duration::from_micros(1700);
const FLOOR_RPS: f64 = 700.0;
const FLOOR_NPM_RPS: f64 = 30.0;
/// What the whole run may add to the process's resident set, KiB.
const RSS_GROWTH_KIB: u64 = 34 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_transports_hot_path_meets_its_stated_bounds() {
    let (server, registry, _policy, _dir) = service().await;
    let router = probation::http::router(server.app());
    let host: &[(&str, &str)] = &[("host", "packages.example.org")];
    let surfaces = surfaces();
    assert_eq!(surfaces.len(), Ecosystem::ALL.len(), "one surface per family");
    // npm's read is the warm fixture document (what the release bench measures), asserted to be the real document.
    assert_warm_npm_document(&router, "10.1.2.3", host).await;
    // Warm every route once so the first sample is not the cold one.
    for surface in &surfaces {
        let _ = sequential(&router, "10.1.2.3", "GET", &hot_read(surface, true), host, 5).await;
    }
    let before = rss_kib();
    let mut report = Vec::new();
    let mut violations = Vec::new();
    for surface in &surfaces {
        let tag = surface.ecosystem.as_tag();
        let uri = hot_read(surface, true);
        let fetched_before = registry.calls().len();
        let (read, statuses) = sequential(&router, "10.1.2.3", "GET", &uri, host, SAMPLES).await;
        assert_eq!(statuses, [surface.expected], "{tag}: the read answers {} every time (anything else is not the path being measured)", surface.expected);
        let (refusal, refused) = sequential(&router, "203.0.113.9", "GET", &uri, host, SAMPLES).await;
        assert_eq!(refused, [403], "{tag}: an unlisted peer is refused every time");
        let write = match surface.write {
            Some((verb, write_uri)) => {
                let (latency, statuses) = sequential(&router, "10.1.2.3", verb, write_uri, host, SAMPLES).await;
                assert_eq!(statuses, [401], "{tag}: a write without a credential is 401 every time");
                Some(latency)
            }
            None => None,
        };
        let (done, per_second, other) = concurrent(&router, "10.1.2.3", uri.clone(), &[("host", "packages.example.org")], CLIENTS, RUN, surface.expected).await;
        assert_eq!(other, 0, "{tag}: every concurrent read answered {}", surface.expected);
        if tag == "npm" {
            // The credential-free read is shared for a few seconds (src/service_share.rs): hundreds of reads cost a handful of upstream fetches,
            // not one each. This is what makes the npm bound a share bound and not a store-commit bound.
            let fetched = registry.calls().len() - fetched_before;
            println!("npm: {fetched} upstream fetches for the whole phase");
            assert!(fetched <= 6, "npm reads were not shared: {fetched} upstream fetches");
        }
        report.push(format!("{tag:9} read {statuses:?} p50 {:?} p95 {:?} p99 {:?} | refusal p95 {:?} | write p95 {:?} | {CLIENTS} clients {done} req {per_second:.0}/s", read.p50, read.p95, read.p99, refusal.p95, write.map(|w| w.p95)));
        // Every figure is printed before any bound is judged, so a failure shows the whole table.
        let (ceiling, floor) = if tag == "npm" { (P95_NPM_READ, FLOOR_NPM_RPS) } else { (P95_READ, FLOOR_RPS) };
        if read.p95 > ceiling { violations.push(format!("{tag}: read p95 {:?} over {ceiling:?}", read.p95)); }
        if refusal.p95 > P95_REFUSAL { violations.push(format!("{tag}: refusal p95 {:?} over {P95_REFUSAL:?}", refusal.p95)); }
        if let Some(write) = write.filter(|write| write.p95 > P95_WRITE_REFUSAL) { violations.push(format!("{tag}: write refusal p95 {:?} over {P95_WRITE_REFUSAL:?}", write.p95)); }
        if per_second < floor { violations.push(format!("{tag}: {per_second:.0} req/s under {floor}")); }
    }
    let grown = rss_kib().saturating_sub(before);
    println!("{}\nrss before {before} KiB, growth {grown} KiB", report.join("\n"));
    if grown > RSS_GROWTH_KIB { violations.push(format!("the run grew the resident set by {grown} KiB (bound {RSS_GROWTH_KIB})")); }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}
