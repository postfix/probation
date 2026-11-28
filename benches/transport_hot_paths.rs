//! Slice 27: the hot path of each of the nine transports in shared-service mode, in a release build.
//!
//! Run with `cargo bench --bench transport_hot_paths` (about a minute). Every family prints one line with
//! the status its read answers, p50/p95/p99 of an admitted read, of the refusal of an unlisted peer and of a
//! credential-less write, and the throughput of `CLIENTS` concurrent clients on the read; the run ends with
//! the resident-set growth and one `slice 27 <target> PASS` (or `FAIL`) line per stated bound. With
//! `-- --assert` a `FAIL` makes the run exit non-zero. The bounds are the ones in docs/operations.md
//! ("Rated load per transport"), each the worst of five runs on the development host multiplied (ceilings) or divided (floors) by
//! four, the one rule of tests/common/transport_load.rs; a machine more than four times slower than that host in its worst run fails.
//!
//! What this measures, and what it does not (the same limits as benches/warm_metadata.rs): an in-process
//! client on the server's runtime (its cost is in every number), the in-process fake registry as the upstream,
//! no socket and no TLS. npm's read is the warm 100-version metadata document (a real filtered response); the
//! other families' reads are their own routes answered by whatever the fake has, which the status column says
//! (`200` served from the firewall, `404`/`502` an upstream miss: admission, routing, registry resolution and the
//! policy path, without a family-specific metadata rewrite). A per-family warm metadata figure needs the
//! family's own fixture and is not claimed.

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::Duration;

use common::transport_load::{
    assert_warm_npm_document, concurrent, hot_read, rss_kib, sequential, service, surfaces,
};

const SAMPLES: usize = 2_000;
const CLIENTS: usize = 32;
const RUN: Duration = Duration::from_secs(2);

/// Bounds (release build): worst of five runs on the development host (load average 30), x4 for ceilings and /4 for floors, rounded in the safe
/// direction. Worst values: the eight cheap reads p95 0.029 ms (bound 0.12 ms), npm's warm document p95 1.861 ms (7.5 ms; the shared service
/// shares one fetch per few seconds, src/service_share.rs), refusal p95 0.006 ms (0.025 ms), write refusal p95 0.017 ms (0.07 ms), cheap reads
/// at least 22,557 per second at 32 clients (floor 5,600), npm at least 4,698 per second (floor 1,100), resident growth: none measured (the worst
/// figure was not positive), so the bound is four times the 1 MiB resolution of the figure.
const P95_READ_MS: f64 = 0.12;
const P95_NPM_WARM_MS: f64 = 7.5;
const P95_REFUSAL_MS: f64 = 0.025;
const P95_WRITE_REFUSAL_MS: f64 = 0.07;
const FLOOR_RPS: f64 = 5_600.0;
const FLOOR_NPM_WARM_RPS: f64 = 1_100.0;
/// What the firewall's own resident set may grow under a load that never reaches the (recording) fake upstream.
const RSS_GROWTH_MIB: f64 = 4.0;

fn main() {
    let assert = std::env::args()
        .skip(1)
        .any(|argument| argument == "--assert");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a benchmark runtime");
    let verdicts = runtime.block_on(run());
    let mut failed = false;
    for (target, met) in &verdicts {
        println!("slice 27 {target} {}", if *met { "PASS" } else { "FAIL" });
        failed |= !met;
    }
    if failed && assert {
        std::process::exit(1);
    }
}

async fn run() -> Vec<(String, bool)> {
    let (server, registry, _policy, _dir) = service().await;
    println!(
        "harness: OSV is OFF for every registry (tests/common/transport_load.rs), so these figures exclude the OSV batch and its outage cost; they are a transport floor, not an end-to-end rate"
    );
    let router = probation::http::router(server.app());
    let host: &[(&str, &str)] = &[("host", "packages.example.org")];
    // What is measured is what the read answers: the warm npm document is the real filtered document (a fast 404 fails here, not in a bound).
    let versions = assert_warm_npm_document(&router, "10.1.2.3", host).await;
    println!("npm warm document: 200, {versions} versions");
    for surface in &surfaces() {
        let _ = sequential(
            &router,
            "10.1.2.3",
            "GET",
            &hot_read(surface, true),
            host,
            50,
        )
        .await;
    }
    let mut verdicts = Vec::new();
    // Contrast row: the common (non-selected) npm route is the warm-cached one (`reusable`), served from memory.
    {
        let (read, statuses) = sequential(
            &router,
            "10.1.2.3",
            "GET",
            "/npm/fixture-widget",
            host,
            SAMPLES,
        )
        .await;
        assert_eq!(
            statuses,
            [200],
            "the common npm route answers the warm document"
        );
        let (done, per_second, other) = concurrent(
            &router,
            "10.1.2.3",
            "/npm/fixture-widget".to_owned(),
            &[("host", "packages.example.org")],
            CLIENTS,
            RUN,
            200,
        )
        .await;
        assert_eq!(
            other, 0,
            "every concurrent read of the common npm route answered 200"
        );
        println!(
            "npm common route /npm/{{package}} {statuses:?} {:.3} / {:.3} / {:.3} ms | {done} req, {per_second:.0}/s",
            read.p50.as_secs_f64() * 1e3,
            read.p95.as_secs_f64() * 1e3,
            read.p99.as_secs_f64() * 1e3
        );
    }
    println!(
        "family    status   read p50 / p95 / p99 | unlisted-peer refusal p95 | write refusal p95 | {CLIENTS} clients"
    );
    for surface in &surfaces() {
        let tag = surface.ecosystem.as_tag();
        let uri = hot_read(surface, true);
        let (read, statuses) = sequential(&router, "10.1.2.3", "GET", &uri, host, SAMPLES).await;
        assert_eq!(
            statuses,
            [surface.expected],
            "{tag}: the read answers {} every time (anything else is not the path being measured)",
            surface.expected
        );
        let (refusal, refused) =
            sequential(&router, "203.0.113.9", "GET", &uri, host, SAMPLES).await;
        assert_eq!(
            refused,
            [403],
            "{tag}: an unlisted peer is refused every time"
        );
        let write = match surface.write {
            Some((verb, write_uri)) => {
                let (latency, written) =
                    sequential(&router, "10.1.2.3", verb, write_uri, host, SAMPLES).await;
                assert_eq!(
                    written,
                    [401],
                    "{tag}: a write without a credential is 401 every time"
                );
                Some(latency)
            }
            None => None,
        };
        let (done, per_second, other) = concurrent(
            &router,
            "10.1.2.3",
            uri,
            &[("host", "packages.example.org")],
            CLIENTS,
            RUN,
            surface.expected,
        )
        .await;
        assert_eq!(
            other, 0,
            "{tag}: every concurrent read answered {}",
            surface.expected
        );
        let ms = |duration: Duration| duration.as_secs_f64() * 1000.0;
        println!(
            "{tag:9} {statuses:?} {:.3} / {:.3} / {:.3} ms | {:.3} ms | {} | {done} req, {per_second:.0}/s",
            ms(read.p50),
            ms(read.p95),
            ms(read.p99),
            ms(refusal.p95),
            write.map_or("no write route".to_owned(), |w| format!(
                "{:.3} ms",
                ms(w.p95)
            )),
        );
        println!(
            "          resident set after {tag}: {:.1} MiB",
            rss_kib() as f64 / 1024.0
        );
        let warm = tag == "npm";
        verdicts.push((
            format!(
                "{tag} read p95 {:.3} ms <= {} ms",
                ms(read.p95),
                if warm { P95_NPM_WARM_MS } else { P95_READ_MS }
            ),
            ms(read.p95) <= if warm { P95_NPM_WARM_MS } else { P95_READ_MS },
        ));
        verdicts.push((
            format!(
                "{tag} refusal p95 {:.3} ms <= {P95_REFUSAL_MS} ms",
                ms(refusal.p95)
            ),
            ms(refusal.p95) <= P95_REFUSAL_MS,
        ));
        if let Some(write) = write {
            verdicts.push((
                format!(
                    "{tag} write refusal p95 {:.3} ms <= {P95_WRITE_REFUSAL_MS} ms",
                    ms(write.p95)
                ),
                ms(write.p95) <= P95_WRITE_REFUSAL_MS,
            ));
        }
        let floor = if warm { FLOOR_NPM_WARM_RPS } else { FLOOR_RPS };
        verdicts.push((
            format!("{tag} throughput {per_second:.0}/s >= {floor}/s"),
            per_second >= floor,
        ));
    }
    // Let the delivery pipeline drain before the memory figures are taken.
    tokio::time::sleep(Duration::from_secs(5)).await;
    // Where does the growth of the reads come from? The in-process fake upstream (the test double) records every call it
    // answers, about 100 bytes each, so reads that reach it grow the process; the firewall's own memory is what a load
    // that never reaches the upstream shows: the same number of requests, refused at admission, twice.
    let calls = registry.calls().len();
    println!(
        "the fake upstream recorded {calls} calls (about {:.0} MiB at 112 bytes each)",
        calls as f64 * 112.0 / 1_048_576.0
    );
    let pypi = surfaces()
        .into_iter()
        .find(|surface| surface.ecosystem.as_tag() == "pypi")
        .unwrap();
    let settled = rss_kib();
    let mut refused_growth = Vec::new();
    for _ in 0..3 {
        let (done, _, other) = concurrent(
            &router,
            "203.0.113.9",
            hot_read(&pypi, true),
            &[("host", "packages.example.org")],
            CLIENTS,
            RUN,
            403,
        )
        .await;
        assert_eq!(
            other, 0,
            "every request of the unlisted peer was refused 403"
        );
        refused_growth.push((done, (rss_kib() as f64 - settled as f64) / 1024.0));
    }
    println!(
        "refused-at-admission load, three runs: {:?} (requests, resident growth in MiB over the settled figure)",
        refused_growth
            .iter()
            .map(|(done, mib)| (*done, (mib * 10.0).round() / 10.0))
            .collect::<Vec<_>>()
    );
    // The largest growth of the three runs, not the last: a later run that gives memory back must not hide an earlier growth.
    let grown = refused_growth
        .iter()
        .map(|(_, mib)| *mib)
        .fold(f64::MIN, f64::max);
    verdicts.push((format!("firewall resident growth under {} refused requests {grown:.1} MiB <= {RSS_GROWTH_MIB} MiB", refused_growth.iter().map(|(done, _)| done).sum::<u64>()), grown <= RSS_GROWTH_MIB));
    verdicts
}
