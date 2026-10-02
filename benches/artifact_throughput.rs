//! SPEC §12, rows 3 and 4: verified warm-artifact time-to-first-byte against an
//! unfiltered local-file server, and verified artifact throughput as a fraction of
//! that same baseline.
//!
//! Run with `cargo bench --bench artifact_throughput`. The numbers this prints are
//! the ones recorded in `docs/operations.md`.
//!
//! **Two project shapes, deliberately.** SPEC §12 says "Test both the representative
//! fixture and large real-shaped metadata", and for this row that instruction is
//! load-bearing rather than thorough: every artifact request revalidates project
//! membership (SPEC §9), and the cost of doing so scales with the size of the project
//! document, not with the size of the artifact. A number taken only on a 100-version
//! fixture would say nothing about a real package carrying thousands of versions. So
//! the same artifact, the same bytes and the same cache state are measured behind a
//! 100-version document and behind a several-thousand-version one, and both numbers
//! are reported.
//!
//! **What the baseline is.** An axum server on the same runtime, streaming the same
//! bytes from a file in 64 KiB chunks — the same chunk size `src/artifacts/stream.rs`
//! uses — with no policy, no lookup and no verification. It is the "same unfiltered
//! local-file server" SPEC §12 names. Like `warm_metadata`, the client is in process,
//! so both sides of the comparison carry the same client cost and the same core
//! contention.

#[path = "../tests/common/mod.rs"]
mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, artifact_path, config_with_open_blocklist,
    fake_origins, npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
};
use serde_json::{Map, Value, json};
use tokio::io::AsyncReadExt;

const WIDGET: &str = "fixture-widget";
const TARGET: &str = "1.0.0";
const FILENAME: &str = "fixture-widget-1.0.0.tgz";
const PUBLISHED: &str = "2026-04-01T00:00:00Z";
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

/// 8 MiB: large enough that throughput is about moving bytes rather than about
/// per-request overhead, and close to the size of a real large npm tarball.
const PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;

/// The "representative" shape and the "large real-shaped" one. Real npm packages in
/// the multi-thousand-version range exist; this is that shape, not a stress value.
/// Three points rather than two, so the shape of the cost is visible: if the extra
/// time tracks document size rather than payload size, it is being paid per request
/// on the metadata, not on the bytes.
const SHAPES: [(&str, usize); 3] = [
    ("representative, 100 versions", 100),
    ("intermediate, 1000 versions", 1_000),
    ("large real-shaped, 5000 versions", 5_000),
];

const WARMUP: usize = 10;
/// Per side, so a shape costs `2 * SAMPLES` downloads. 150 was too thin to resolve a
/// ratio whose baseline spreads an order of magnitude between its own p50 and p95.
const SAMPLES: usize = 1_000;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a benchmark runtime");
    runtime.block_on(run());
}

async fn run() {
    let payload = payload();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let blob = dir.path().join("blob.bin");
    std::fs::write(&blob, &payload).expect("the baseline file is written");

    println!("SPEC §12 verified warm artifact: time-to-first-byte and throughput");
    println!("  payload: {PAYLOAD_BYTES} bytes, {CHUNK_BYTES}-byte chunks on both sides");

    let baseline_addr = start_baseline(blob).await;
    let baseline_client = common::downstream_client();
    let baseline_url = format!("http://{baseline_addr}/blob");

    for (shape, versions) in SHAPES {
        let upstream = document(versions);
        println!(
            "  firewall, {shape}: upstream project document {} bytes",
            upstream.len()
        );
        let (baseline, measured) =
            through_firewall(&payload, &upstream, &baseline_client, &baseline_url).await;
        report(
            &format!("  baseline, unfiltered local file, paired with {shape}"),
            &baseline,
        );
        report(&format!("  firewall, {shape}"), &measured);
        compare(shape, &baseline, &measured);
    }
}

// ---------------------------------------------------------------------------
// The firewall side
// ---------------------------------------------------------------------------

/// Returns the baseline and the firewall measured **against each other**, sampled
/// alternately inside one loop. The baseline is re-measured for every shape rather
/// than once up front, because a baseline taken minutes earlier is a baseline taken
/// on a different machine.
async fn through_firewall(
    payload: &str,
    upstream: &str,
    baseline_client: &reqwest::Client,
    baseline_url: &str,
) -> (Measured, Measured) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.cooldown_seconds = ONE_DAY;

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(upstream.to_owned()),
    );
    registry.answer(
        &npm_artifact_upstream_path(WIDGET, FILENAME),
        FakeAnswer::Body(payload.to_owned()),
    );

    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_with_upstream(config, clock.shared(), registry, fake_origins()).await;

    // The URL a client is actually given, taken out of the rendered document rather
    // than constructed here.
    let rendered = server.json(&format!("/npm/{WIDGET}")).await;
    let path = artifact_path(&rendered, TARGET);
    let url = server.url(&path);

    let client = common::downstream_client();
    // The first request is the cold one SPEC §12 says to document separately: it waits
    // for the whole upstream transfer and hashes it. Everything measured afterwards is
    // a verified cache hit.
    warm_up(&client, &url).await;
    warm_up(baseline_client, baseline_url).await;

    let paired = measure_paired((baseline_client, baseline_url), (&client, &url)).await;
    server.shutdown().await;
    paired
}

/// An npm document advertising `versions` releases, exactly one of which — [`TARGET`]
/// — carries the artifact under measurement. The rest are filler with the shape of a
/// real version record, because it is the whole document's size that the membership
/// check pays for.
fn document(versions: usize) -> String {
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

    for index in 1..versions {
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

/// ASCII, because the in-process fake registry carries artifact bodies as text. The
/// content is irrelevant to this measurement — only its length and the fact that it
/// is hashed and verified once are.
fn payload() -> String {
    let mut bytes = String::with_capacity(PAYLOAD_BYTES);
    while bytes.len() < PAYLOAD_BYTES {
        bytes.push_str("probation-artifact-throughput-benchmark-payload\n");
    }
    bytes.truncate(PAYLOAD_BYTES);
    bytes
}

// ---------------------------------------------------------------------------
// The baseline: the same bytes, no policy and no verification
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Measured {
    ttfb: Vec<Duration>,
    total: Vec<Duration>,
    bytes: usize,
}

/// `WARMUP` unmeasured downloads. SPEC §12 asks for the ratio "under identical
/// conditions", so **both** sides get this and get it identically: without it the
/// baseline's first measured sample pays a cold-connection cost the firewall's does
/// not, and the bias runs in the firewall's favour. Symmetry here is the whole point —
/// if you change one caller, change the other.
async fn warm_up(client: &reqwest::Client, url: &str) {
    for _ in 0..WARMUP {
        let response = client.get(url).send().await.expect("the request completes");
        assert!(
            response.status().is_success(),
            "the request answered {}",
            response.status()
        );
        let _ = response.bytes().await.expect("a body");
    }
}

/// `SAMPLES` downloads from each side, **alternating**: one baseline request, then one
/// firewall request, repeatedly.
///
/// Measuring the two sides in separate blocks is what made this bench unusable. SPEC
/// §12 asks for a ratio, and a ratio taken from two blocks minutes apart charges every
/// drift in machine load between them to the firewall: on a host with other work on it
/// the ratio was observed swinging 56–252 % on identical code, which is a measurement
/// of the host and not of this service. Interleaving puts both sides under the same
/// conditions sample for sample, so shared drift cancels instead of accumulating.
///
/// The two sides still contend with each other, which is deliberate: they contend
/// equally.
async fn measure_paired(
    baseline: (&reqwest::Client, &str),
    firewall: (&reqwest::Client, &str),
) -> (Measured, Measured) {
    let mut first = Collected::default();
    let mut second = Collected::default();

    for _ in 0..SAMPLES {
        sample(baseline.0, baseline.1, &mut first).await;
        sample(firewall.0, firewall.1, &mut second).await;
    }

    (first.finish(), second.finish())
}

#[derive(Default)]
struct Collected {
    ttfb: Vec<Duration>,
    total: Vec<Duration>,
    bytes: usize,
}

impl Collected {
    fn finish(mut self) -> Measured {
        assert_eq!(self.bytes, PAYLOAD_BYTES, "the whole payload was delivered");
        self.ttfb.sort_unstable();
        self.total.sort_unstable();
        Measured {
            ttfb: self.ttfb,
            total: self.total,
            bytes: self.bytes,
        }
    }
}

/// One download. `send().await` resolves when the response headers arrive, which is
/// the time to first byte; the body is then read to completion for the throughput half.
async fn sample(client: &reqwest::Client, url: &str, into: &mut Collected) {
    let start = Instant::now();
    let response = client.get(url).send().await.expect("the request completes");
    let headers = start.elapsed();
    assert!(
        response.status().is_success(),
        "the request answered {}",
        response.status()
    );
    let body = response.bytes().await.expect("a body");
    into.total.push(start.elapsed());
    into.ttfb.push(headers);
    into.bytes = body.len();
}

fn report(what: &str, measured: &Measured) {
    println!(
        "{what}: ttfb p50 {:.3} ms, p95 {:.3} ms | total p50 {:.3} ms, p95 {:.3} ms | {:.1} MiB/s at p50, n={}, body {} bytes",
        millis(percentile(&measured.ttfb, 0.50)),
        millis(percentile(&measured.ttfb, 0.95)),
        millis(percentile(&measured.total, 0.50)),
        millis(percentile(&measured.total, 0.95)),
        mib_per_second(measured.bytes, percentile(&measured.total, 0.50)),
        measured.total.len(),
        measured.bytes,
    );
}

fn compare(shape: &str, baseline: &Measured, measured: &Measured) {
    let extra = millis(percentile(&measured.ttfb, 0.95)) - millis(percentile(&baseline.ttfb, 0.95));
    let ratio = mib_per_second(measured.bytes, percentile(&measured.total, 0.50))
        / mib_per_second(baseline.bytes, percentile(&baseline.total, 0.50));
    println!(
        "    {shape}: additional p95 ttfb {extra:+.3} ms (target: at most 5 ms) — {}",
        verdict(extra <= 5.0)
    );
    println!(
        "    {shape}: throughput {:.1}% of baseline (target: at least 85%) — {}",
        ratio * 100.0,
        verdict(ratio >= 0.85)
    );
}

fn verdict(met: bool) -> &'static str {
    if met { "MET" } else { "BREACH" }
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    let last = sorted.len().saturating_sub(1);
    let at = ((sorted.len() as f64) * fraction).ceil() as usize;
    sorted[at.saturating_sub(1).min(last)]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn mib_per_second(bytes: usize, duration: Duration) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / duration.as_secs_f64()
}
