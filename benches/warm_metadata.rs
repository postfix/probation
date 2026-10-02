//! SPEC §12, rows 1 and 2: warm metadata throughput and latency, and warm policy
//! denial latency.
//!
//! Run with `cargo bench --bench warm_metadata`. The numbers this prints are the ones
//! recorded in `docs/operations.md`.
//!
//! **What this measures, and what it does not.** SPEC §12's reference environment
//! names a separate load-generator process; this is an in-process client on the same
//! runtime as the server, so every number includes the client's own cost and the two
//! contend for the same cores. That biases *against* the server, which is the safe
//! direction for an acceptance measurement, but it means these are not
//! client-isolated figures. The upstream is the in-process fake registry, so nothing
//! here touches a socket other than loopback.

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins,
    fixture, npm_upstream_path,
};

const WIDGET: &str = "fixture-widget";
/// The instant `tests/fixtures/npm/representative-100-versions.json` is read at, the
/// same one `tests/npm_metadata.rs` uses: some versions are eligible, `2.0.0` is held
/// with twelve hours of its cooldown left, and `2.0.1`..`2.0.4` are not published yet.
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

/// A version the cooldown is holding, which is what a "warm policy denial" is.
const HELD: &str = "2.0.0";

const WARMUP: usize = 200;
const SAMPLES: usize = 3_000;
const CONCURRENCY: usize = 32;
const THROUGHPUT_SECONDS: u64 = 5;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a benchmark runtime");
    runtime.block_on(run());
}

async fn run() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.cooldown_seconds = ONE_DAY;

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(fixture("npm/representative-100-versions.json")),
    );

    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_with_upstream(config, clock.shared(), registry, fake_origins()).await;

    println!("SPEC §12 warm metadata and warm policy denial");
    println!(
        "  fixture: representative 100-version npm project, {} bytes upstream",
        fixture("npm/representative-100-versions.json").len()
    );

    let document = format!("/npm/{WIDGET}");
    let denial = format!("/npm/{WIDGET}/{HELD}");

    // The first pass populates the rendered response cache. SPEC §10 requires a warm
    // request to need no database query, so the measured window is checked to have
    // issued none — a run that quietly measured a cold path would otherwise report a
    // number for the wrong thing.
    warm(&server, &document).await;
    warm(&server, &denial).await;
    let commands_before = server.store_commands();

    latency(&server, "warm metadata, p95 target 5 ms", &document, 200).await;
    latency(&server, "warm policy denial, p95 target 2 ms", &denial, 403).await;
    throughput(
        &server,
        "warm metadata, target 1000 responses/second",
        &document,
    )
    .await;

    assert_eq!(
        server.store_commands(),
        commands_before,
        "the measured window issued a database command, so it was not warm"
    );

    server.shutdown().await;
}

async fn warm(server: &TestServer, path: &str) {
    for _ in 0..WARMUP {
        let response = server.get(path).await;
        let _ = response.bytes().await.expect("a body");
    }
}

/// `SAMPLES` sequential requests, reported as percentiles.
///
/// Sequential rather than concurrent on purpose: SPEC §12 states latency as a p95 per
/// response, and a concurrent run reports queueing delay as latency. Throughput is
/// measured separately, below.
async fn latency(server: &TestServer, what: &str, path: &str, expect: u16) {
    let mut samples = Vec::with_capacity(SAMPLES);
    let mut bytes = 0usize;
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let response = server.get(path).await;
        let status = response.status().as_u16();
        let body = response.bytes().await.expect("a body");
        samples.push(start.elapsed());
        assert_eq!(status, expect, "{path} answered {status}");
        bytes = body.len();
    }
    report(what, &mut samples, bytes);
}

/// Sustained load at a fixed concurrency, reported as responses per second.
async fn throughput(server: &TestServer, what: &str, path: &str) {
    let url = server.url(path);
    let deadline = Instant::now() + Duration::from_secs(THROUGHPUT_SECONDS);
    let mut workers = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let client = common::downstream_client();
        let url = url.clone();
        workers.push(tokio::spawn(async move {
            let mut served = 0u64;
            while Instant::now() < deadline {
                let response = client
                    .get(&url)
                    .send()
                    .await
                    .expect("the request completes");
                assert!(response.status().is_success());
                let _ = response.bytes().await.expect("a body");
                served += 1;
            }
            served
        }));
    }

    let start = Instant::now();
    let mut served = 0u64;
    for worker in workers {
        served += worker.await.expect("the worker finishes");
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "  {what}: {:.0} responses/second at concurrency {CONCURRENCY} ({served} responses in {elapsed:.2} s)",
        served as f64 / elapsed
    );
}

fn report(what: &str, samples: &mut [Duration], body_bytes: usize) {
    samples.sort_unstable();
    println!(
        "  {what}: p50 {:.3} ms, p95 {:.3} ms, p99 {:.3} ms, max {:.3} ms, n={} , body {body_bytes} bytes",
        millis(percentile(samples, 0.50)),
        millis(percentile(samples, 0.95)),
        millis(percentile(samples, 0.99)),
        millis(*samples.last().expect("at least one sample")),
        samples.len(),
    );
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    let last = sorted.len().saturating_sub(1);
    let at = ((sorted.len() as f64) * fraction).ceil() as usize;
    sorted[at.saturating_sub(1).min(last)]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
