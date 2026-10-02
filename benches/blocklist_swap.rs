//! SPEC §12, last row: a valid blocklist replacement is active within two configured
//! polling intervals for a 100,000-entry fixture, under the benchmark load.
//!
//! Run with `cargo bench --bench blocklist_swap`. The numbers this prints are the
//! ones recorded in `docs/operations.md`.
//!
//! "Active" is measured the way an operator would care about it: the clock starts
//! when the producer's replacement lands on disk and stops when a client request that
//! was being answered `200` is answered `403`. Everything between — the poller
//! noticing, the whole candidate being validated off the request path, the commit,
//! and the atomic publication — is inside the measurement. Metadata requests run
//! continuously against the same instance throughout, so the swap is not being timed
//! on an idle server.
//!
//! This bench also prints resident set size, which SPEC §10 asks to be documented and
//! SPEC §12 asks to be recorded: it is the bench with the largest blocklist in memory,
//! so it is the one where that number means something.

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, fixture, npm_upstream_path,
    replace_atomically, sample_config,
};

const WIDGET: &str = "fixture-widget";
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

/// SPEC §12 names this size exactly.
const ENTRIES: usize = 100_000;
const LOAD_WORKERS: usize = 16;
/// How often the swap's effect is looked for. Small against the polling interval, so
/// the reported time is the firewall's and not this loop's.
const OBSERVE_EVERY: Duration = Duration::from_millis(10);

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a benchmark runtime");
    runtime.block_on(run());
}

async fn run() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let blocklist_file = dir.path().join("blocklist.json");

    let first = blocklist(1, "");
    std::fs::write(&blocklist_file, &first).expect("the first blocklist is written");

    let mut config = sample_config();
    config.blocklist_file = blocklist_file.clone();
    config.cooldown_seconds = ONE_DAY;
    let interval = config.blocklist_poll_seconds.get();

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(fixture("npm/representative-100-versions.json")),
    );

    println!("SPEC §12 blocklist replacement");
    println!(
        "  fixture: {ENTRIES} blocked packages, {} bytes; polling interval {interval} s, so the target is {} s",
        first.len(),
        interval * 2
    );

    let started = Instant::now();
    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_with_upstream(config, clock.shared(), registry, fake_origins()).await;
    println!(
        "  startup with that snapshot already on disk: {:.0} ms (validate, commit and publish, plus opening the database)",
        started.elapsed().as_secs_f64() * 1_000.0
    );

    let document = format!("/npm/{WIDGET}");
    assert_eq!(
        server.status(&document).await,
        200,
        "the project is served before the replacement"
    );

    // Continuous load for the whole measurement, so the poller is competing with real
    // request work rather than running on an idle instance.
    let stop = Arc::new(AtomicBool::new(false));
    let mut load = Vec::with_capacity(LOAD_WORKERS);
    for _ in 0..LOAD_WORKERS {
        let client = common::downstream_client();
        let url = server.url(&document);
        let stop = Arc::clone(&stop);
        load.push(tokio::spawn(async move {
            let mut served = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let response = client
                    .get(&url)
                    .send()
                    .await
                    .expect("the request completes");
                let _ = response.bytes().await.expect("a body");
                served += 1;
            }
            served
        }));
    }

    let replacement = blocklist(
        2,
        r#"{"ecosystem":"npm","name":"fixture-widget","version":null,"reason":"benchmark replacement"}"#,
    );
    let swapped = Instant::now();
    replace_atomically(&blocklist_file, &replacement);

    let deadline = swapped + Duration::from_secs(interval * 4);
    let mut active = None;
    while active.is_none() {
        assert!(
            Instant::now() < deadline,
            "the replacement was still not active after four polling intervals"
        );
        if server.status(&document).await == 403 {
            active = Some(swapped.elapsed());
        } else {
            tokio::time::sleep(OBSERVE_EVERY).await;
        }
    }
    let active = active.expect("the replacement became active");

    stop.store(true, Ordering::Relaxed);
    let mut served = 0u64;
    for worker in load {
        served += worker.await.expect("the worker finishes");
    }

    println!(
        "  replacement active after {:.2} s (target: at most {} s, two polling intervals) — {}",
        active.as_secs_f64(),
        interval * 2,
        if active <= Duration::from_secs(interval * 2) {
            "MET"
        } else {
            "BREACH"
        }
    );
    println!("  load during the swap: {served} metadata responses across {LOAD_WORKERS} workers");
    println!(
        "  resident set size with the {ENTRIES}-entry snapshot in force: {:.0} MiB (SPEC §10: total process RSS, not the memory-cache budget)",
        rss_mib()
    );

    server.shutdown().await;
}

/// A valid snapshot with [`ENTRIES`] blocked packages. `extra` is one further record,
/// written verbatim, which is what the replacement adds to make the effect observable.
fn blocklist(revision: u64, extra: &str) -> String {
    let mut blocked = String::with_capacity(ENTRIES * 96);
    for index in 0..ENTRIES {
        if index > 0 {
            blocked.push(',');
        }
        blocked.push_str(&format!(
            r#"{{"ecosystem":"npm","name":"blocked-package-{index:06}","version":null,"reason":"benchmark fixture"}}"#
        ));
    }
    if !extra.is_empty() {
        blocked.push(',');
        blocked.push_str(extra);
    }
    common::snapshot(
        revision,
        "2020-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        &blocked,
    )
}

/// Resident set size, from `/proc/self/statm`'s second field in pages.
fn rss_mib() -> f64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("procfs is mounted");
    let pages: f64 = statm
        .split_whitespace()
        .nth(1)
        .expect("statm has a resident field")
        .parse()
        .expect("a page count");
    pages * 4096.0 / (1024.0 * 1024.0)
}
