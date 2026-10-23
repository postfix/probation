//! SPEC §12, rows 1 and 2: warm metadata throughput and latency, and warm policy
//! denial latency.
//!
//! Run with `cargo bench --bench warm_metadata`. The numbers this prints are the ones
//! recorded in `docs/operations.md`. Every target ends in one `SPEC §12 <target> PASS`
//! (or `FAIL`) line; with `-- --assert` a `FAIL` makes the run exit non-zero.
//!
//! `-- --managed` measures C83 instead: a standalone firewall and a managed one (warm
//! key cache, fake management server) with the same effective policy, sampled
//! alternately, one request each. It prints `managed overhead p95 <x> ms <= 1 ms` and
//! `managed throughput <r>% >= 90%`, each `PASS` or `FAIL`, and exits non-zero on a
//! `FAIL`.
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

use common::sync::{client_with_key, standalone_equivalent};
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
    let (assert, managed) = flags();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a benchmark runtime");
    let mut failed = false;
    if assert || !managed {
        let verdicts = runtime.block_on(run());
        for (target, met) in &verdicts {
            println!("SPEC §12 {target} {}", if *met { "PASS" } else { "FAIL" });
        }
        failed |= assert && verdicts.iter().any(|(_, met)| !met);
    }
    if managed {
        let verdicts = runtime.block_on(run_managed());
        for (target, met) in &verdicts {
            println!("{target} {}", if *met { "PASS" } else { "FAIL" });
        }
        failed |= verdicts.iter().any(|(_, met)| !met);
    }
    if failed {
        std::process::exit(1);
    }
}

/// `--assert` turns a missed SPEC §12 target into a failing exit; `--managed` runs the
/// C83 comparison instead, and fails on a miss by itself. Cargo itself passes
/// `--bench`; anything else is refused rather than silently ignored.
fn flags() -> (bool, bool) {
    let (mut assert, mut managed) = (false, false);
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--assert" => assert = true,
            "--managed" => managed = true,
            "--bench" => {}
            other => {
                eprintln!("unknown argument `{other}`; the options are --assert and --managed");
                std::process::exit(2);
            }
        }
    }
    (assert, managed)
}

/// The two firewalls the managed comparison runs: one standalone, one managed, on the
/// same fixture, clock and effective policy, each with a client that can reach it.
async fn start(managed: bool) -> (TestServer, reqwest::Client, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.cooldown_seconds = ONE_DAY;
    let client = if managed {
        let (sync, key) = standalone_equivalent(ONE_DAY).await;
        // The fake server's task outlives this handle, for as long as the runtime runs.
        config = sync.managed(config);
        client_with_key(&key)
    } else {
        common::downstream_client()
    };

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(fixture("npm/representative-100-versions.json")),
    );
    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_with_upstream(config, clock.shared(), registry, fake_origins()).await;
    (server, client, dir)
}

/// C83: the cached managed path adds at most 1 ms at p95 and keeps at least 90 % of the
/// standalone throughput, both measured against a standalone firewall sampled
/// alternately with it.
async fn run_managed() -> Vec<(String, bool)> {
    let (standalone, standalone_client, _a) = start(false).await;
    let (managed, managed_client, _b) = start(true).await;
    let document = format!("/npm/{WIDGET}");
    let sides = [
        (&standalone_client, standalone.url(&document)),
        (&managed_client, managed.url(&document)),
    ];
    for (client, url) in &sides {
        for _ in 0..WARMUP {
            let response = client.get(url).send().await.expect("the request completes");
            assert_eq!(response.status(), 200, "{url}");
            let _ = response.bytes().await.expect("a body");
        }
    }

    println!("C83 managed overhead, warm metadata: standalone and managed sampled alternately");
    let mut samples = [Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES)];
    let mut bytes = [0usize; 2];
    for _ in 0..SAMPLES {
        for (side, (client, url)) in sides.iter().enumerate() {
            let start = Instant::now();
            let response = client.get(url).send().await.expect("the request completes");
            let status = response.status();
            bytes[side] = response.bytes().await.expect("a body").len();
            samples[side].push(start.elapsed());
            assert_eq!(status, 200, "{url}");
        }
    }
    let [mut standalone_samples, mut managed_samples] = samples;
    report("standalone", &mut standalone_samples, bytes[0]);
    report("managed", &mut managed_samples, bytes[1]);
    let overhead =
        millis(percentile(&managed_samples, 0.95)) - millis(percentile(&standalone_samples, 0.95));

    // Throughput in alternating one-second rounds, so drift on the host lands on both,
    // and with the side that goes first swapped each round, so warm-up order does not.
    // The verdict is the median of the per-round ratios, so one round that a burst of
    // host load lands on cannot decide it (S2-4, S2-8).
    let mut served = [0.0f64; 2];
    let mut ratios = Vec::with_capacity(THROUGHPUT_SECONDS as usize);
    for round in 0..THROUGHPUT_SECONDS as usize {
        let mut this_round = [0.0f64; 2];
        for side in [round % 2, 1 - round % 2] {
            let (client, url) = &sides[side];
            this_round[side] = rate(client, url, Duration::from_secs(1)).await;
            served[side] += this_round[side];
        }
        ratios.push(this_round[1] / this_round[0]);
    }
    ratios.sort_by(f64::total_cmp);
    let ratio = ratios[ratios.len() / 2];
    println!(
        "  throughput: standalone {:.0}/s, managed {:.0}/s",
        served[0] / THROUGHPUT_SECONDS as f64,
        served[1] / THROUGHPUT_SECONDS as f64
    );

    standalone.shutdown().await;
    managed.shutdown().await;
    vec![
        (
            format!("managed overhead p95 {overhead:.3} ms <= 1 ms"),
            overhead <= 1.0,
        ),
        (
            format!(
                "managed throughput {:.1}% >= 90% (median of {} rounds)",
                ratio * 100.0,
                ratios.len()
            ),
            ratio >= 0.9,
        ),
    ]
}

/// Responses a second from `CONCURRENCY` workers on `url` for `window`.
async fn rate(client: &reqwest::Client, url: &str, window: Duration) -> f64 {
    let deadline = Instant::now() + window;
    let start = Instant::now();
    let workers: Vec<_> = (0..CONCURRENCY)
        .map(|_| {
            let client = client.clone();
            let url = url.to_owned();
            tokio::spawn(async move {
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
            })
        })
        .collect();
    let mut served = 0u64;
    for worker in workers {
        served += worker.await.expect("the worker finishes");
    }
    served as f64 / start.elapsed().as_secs_f64()
}

async fn run() -> Vec<(String, bool)> {
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

    let metadata = latency(&server, "warm metadata, p95 target 5 ms", &document, 200).await;
    let denial = latency(&server, "warm policy denial, p95 target 2 ms", &denial, 403).await;
    let rate = throughput(
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

    vec![
        (
            format!("warm metadata p95 {metadata:.3} ms <= 5 ms"),
            metadata <= 5.0,
        ),
        (
            format!("warm policy denial p95 {denial:.3} ms <= 2 ms"),
            denial <= 2.0,
        ),
        (
            format!("warm metadata throughput {rate:.0} responses/s >= 1000"),
            rate >= 1_000.0,
        ),
    ]
}

async fn warm(server: &TestServer, path: &str) {
    for _ in 0..WARMUP {
        let response = server.get(path).await;
        let _ = response.bytes().await.expect("a body");
    }
}

/// `SAMPLES` sequential requests, reported as percentiles. Returns the p95 in ms.
///
/// Sequential rather than concurrent on purpose: SPEC §12 states latency as a p95 per
/// response, and a concurrent run reports queueing delay as latency. Throughput is
/// measured separately, below.
async fn latency(server: &TestServer, what: &str, path: &str, expect: u16) -> f64 {
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
    millis(percentile(&samples, 0.95))
}

/// Sustained load at a fixed concurrency, reported (and returned) as responses per
/// second.
async fn throughput(server: &TestServer, what: &str, path: &str) -> f64 {
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
    let rate = served as f64 / elapsed;
    println!(
        "  {what}: {rate:.0} responses/second at concurrency {CONCURRENCY} ({served} responses in {elapsed:.2} s)"
    );
    rate
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
