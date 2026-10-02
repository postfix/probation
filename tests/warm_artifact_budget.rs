//! Slice 13's measured witness: SPEC §12's warm-artifact budget on a project of the
//! shape SPEC §12 calls "large real-shaped metadata".
//!
//! SPEC §12: "Verified warm artifact — p95 additional time-to-first-byte at most 5 ms
//! versus the same unfiltered local-file server." SPEC §9 makes every artifact
//! request, warm ones included, confirm that its reference is still advertised by a
//! current project snapshot, and the cost of doing that scales with the size of the
//! *project document*, not the artifact. A number taken on a 100-version fixture says
//! nothing about a real package carrying thousands of versions, so this measures the
//! several-thousand-version shape — the one the pre-slice-13 code breached by 37.9 ms.
//!
//! **This asserts; it does not report.** `benches/artifact_throughput.rs` is where the
//! numbers for `docs/operations.md` come from, with its 8 MiB payload and its three
//! project shapes. This is the same measurement reduced to one threshold, so a
//! regression fails a test run instead of waiting for someone to read a bench.
//!
//! `#[ignore]` for the same reason every measurement in this plan is: it takes
//! seconds, and a timing threshold does not belong in the default suite. Run it with
//! `cargo test --test warm_artifact_budget -- --ignored`.
//!
//! **What "additional" is measured against.** An axum server on the same runtime,
//! streaming the same bytes from a file in the same 64 KiB chunks `src/artifacts/
//! stream.rs` uses, with no policy, no lookup and no verification. Both sides are
//! measured by the same in-process client in the same build, so the client cost and
//! the core contention are common to both and cancel in the difference.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, artifact_path, config_with_open_blocklist,
    npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
};
use serde_json::{Map, Value, json};
use tokio::io::AsyncReadExt;

const WIDGET: &str = "fixture-widget";
const TARGET: &str = "1.0.0";
const FILENAME: &str = "fixture-widget-1.0.0.tgz";
const PUBLISHED: &str = "2026-04-01T00:00:00Z";
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

/// SPEC §12's warm-artifact target, in milliseconds of additional p95 time to first
/// byte over the unfiltered local-file baseline.
const BUDGET_MS: f64 = 5.0;

/// "Large real-shaped metadata" (SPEC §12). Real npm packages in this range exist;
/// this is that shape, not a stress value.
const VERSIONS: usize = 5_000;

/// Time to first byte is what this asserts on, and it is paid before a single body
/// byte moves — so the payload is small enough to keep the run short. The throughput
/// half of SPEC §12's row is `benches/artifact_throughput.rs`, with its 8 MiB body.
const PAYLOAD_BYTES: usize = 256 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;

const WARMUP: usize = 10;
const SAMPLES: usize = 120;

/// SPEC §12, row 3, on the large real-shaped project shape.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a timing measurement; run with --ignored"]
async fn warm_artifact_ttfb_is_within_the_spec_12_target() {
    let payload = payload();

    let dir = tempfile::tempdir().expect("a temporary directory");
    let blob = dir.path().join("blob.bin");
    std::fs::write(&blob, &payload).expect("the baseline file is written");
    let baseline_addr = start_baseline(blob).await;

    let client = common::downstream_client();
    let baseline = measure(&client, &format!("http://{baseline_addr}/blob")).await;
    let firewall = through_firewall(&payload).await;

    let baseline_p95 = millis(percentile(&baseline, 0.95));
    let firewall_p95 = millis(percentile(&firewall, 0.95));
    let additional = firewall_p95 - baseline_p95;

    assert!(
        additional <= BUDGET_MS,
        "SPEC §12: a verified warm artifact may add at most {BUDGET_MS:.1} ms to p95 \
         time to first byte over the same unfiltered local-file server. On a \
         {VERSIONS}-version project it added {additional:.3} ms — baseline p95 \
         {baseline_p95:.3} ms, firewall p95 {firewall_p95:.3} ms, n={SAMPLES}."
    );
}

/// The same artifact, behind the firewall, with its bytes already verified on disk.
async fn through_firewall(payload: &str) -> Vec<Duration> {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.cooldown_seconds = ONE_DAY;

    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(WIDGET), FakeAnswer::Body(document()));
    registry.answer(
        &npm_artifact_upstream_path(WIDGET, FILENAME),
        FakeAnswer::Body(payload.to_owned()),
    );

    let server = TestServer::start_in_with_registry(
        &dir.path().join("data"),
        config,
        TestClock::at_rfc3339(NOW).shared(),
        registry,
    )
    .await;

    // The URL a client is actually given, taken out of the rendered document rather
    // than constructed here.
    let rendered = server.json(&format!("/npm/{WIDGET}")).await;
    let url = server.url(&artifact_path(&rendered, TARGET));

    let client = common::downstream_client();
    // The first request is the cold one SPEC §12 documents separately: it waits for
    // the whole upstream transfer and hashes it. Everything measured is a verified
    // cache hit afterwards.
    for _ in 0..WARMUP {
        let response = client
            .get(&url)
            .send()
            .await
            .expect("the request completes");
        assert!(
            response.status().is_success(),
            "the artifact answered {}",
            response.status()
        );
        let _ = response.bytes().await.expect("a body");
    }

    let measured = measure(&client, &url).await;
    server.shutdown().await;
    measured
}

/// An npm document advertising [`VERSIONS`] releases, exactly one of which — [`TARGET`]
/// — carries the artifact under measurement. The rest are filler with the shape of a
/// real version record, because it is the whole document that the membership check
/// would otherwise re-read on every request.
fn document() -> String {
    let mut records = Map::new();
    let mut time = Map::new();

    records.insert(
        TARGET.to_owned(),
        json!({
            "name": WIDGET,
            "version": TARGET,
            "dist": {"tarball": npm_tarball_url(WIDGET, FILENAME)},
        }),
    );
    time.insert(TARGET.to_owned(), json!(PUBLISHED));

    for index in 1..VERSIONS {
        let version = format!("1.{}.{}", index / 100, index % 100);
        records.insert(
            version.clone(),
            json!({
                "name": WIDGET,
                "version": version,
                "description": "A harmless fixture package.",
                "main": "index.js",
                "dependencies": {"left-pad": "^1.3.0", "safe-buffer": "~5.2.1"},
                "devDependencies": {"tap": "^16.0.0"},
                "peerDependencies": {"react": ">=16.8.0 <19.0.0"},
                "engines": {"node": ">=14"},
                "dist": {
                    "tarball": npm_tarball_url(WIDGET, &format!("{WIDGET}-{version}.tgz")),
                    "integrity": "sha512-cuZOnpQDIYuoiW0VpldsZLmUaQ/eZwGjVHeTZQoXRdTeBMh5mj1XyHMlEqTzPjYFW3AxzuKZi8cb4GZ2QP4G7g==",
                },
            }),
        );
        time.insert(version, json!(PUBLISHED));
    }

    json!({
        "name": WIDGET,
        "dist-tags": {"latest": TARGET},
        "versions": Value::Object(records),
        "time": Value::Object(time),
    })
    .to_string()
}

/// ASCII, because the in-process fake registry carries artifact bodies as text. Only
/// its length matters here, and that it is hashed and verified exactly once.
fn payload() -> String {
    let mut bytes = String::with_capacity(PAYLOAD_BYTES);
    while bytes.len() < PAYLOAD_BYTES {
        bytes.push_str("probation-warm-artifact-budget-payload\n");
    }
    bytes.truncate(PAYLOAD_BYTES);
    bytes
}

/// The baseline SPEC §12 names: the same bytes, no policy and no verification.
async fn start_baseline(blob: PathBuf) -> SocketAddr {
    let router = Router::new().route(
        "/blob",
        get(move || {
            let blob = blob.clone();
            async move {
                let file = tokio::fs::File::open(&blob)
                    .await
                    .expect("the baseline file opens");
                Body::from_stream(futures_util::stream::unfold(file, |mut file| async move {
                    let mut buffer = vec![0u8; CHUNK_BYTES];
                    match file.read(&mut buffer).await {
                        Ok(0) => None,
                        Ok(read) => {
                            buffer.truncate(read);
                            Some((Ok::<_, std::io::Error>(bytes::Bytes::from(buffer)), file))
                        }
                        Err(err) => Some((Err(err), file)),
                    }
                }))
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the baseline binds");
    let addr = listener.local_addr().expect("the baseline address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// `SAMPLES` sequential requests. `send().await` resolves when the response headers
/// arrive, which is the time to first byte; the body is then read to completion so the
/// next sample starts from a quiet connection.
async fn measure(client: &reqwest::Client, url: &str) -> Vec<Duration> {
    let mut ttfb = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let response = client.get(url).send().await.expect("the request completes");
        let headers = start.elapsed();
        assert!(
            response.status().is_success(),
            "the request answered {}",
            response.status()
        );
        let body = response.bytes().await.expect("a body");
        assert_eq!(body.len(), PAYLOAD_BYTES, "the whole payload was delivered");
        ttfb.push(headers);
    }
    ttfb.sort_unstable();
    ttfb
}

/// The nearest-rank percentile of an already sorted sample.
fn percentile(sorted: &[Duration], quantile: f64) -> Duration {
    let rank = ((sorted.len() as f64) * quantile).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
