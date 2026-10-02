//! The rated load: how many decided requests per second one process takes through
//! the request path and the file sink with nothing lost, held for ten minutes.
//!
//! Run with `cargo bench --bench delivery_rated_load` (release; ten minutes). It
//! prints the rated figure `N` (the machine's ceiling, published for reference —
//! `DEFAULT_QUEUE_MAX_BYTES` is derived from a stated 200 req/s reference load
//! instead, C39, because `N` is too large for any honest budget to cover), the
//! outage tolerance a default deployment gets at both the reference load and at `N`,
//! and the `BYTES_PER_RECORD` derivation. Fails nothing: the numbers are for
//! `docs/operations.md`, which records them beside the hardware that produced them.
//!
//! **Why the file sink.** It is local, has no collector to wedge and reproduces on
//! any machine. `N` is a property of the request path and the delivery pipeline;
//! outage tolerance is then arithmetic per sink, `budget / BYTES_PER_RECORD / rate`,
//! not a measured collector outage.
//!
//! **Probe, then calibrate, then pace.** An unpaced ten-second probe against the 4 GiB
//! queue ceiling finds what the file writer sustains as a burst. That burst rate is not
//! always what the pipeline sustains once queueing catches up over minutes rather than
//! seconds, so a short calibration run steps down from 80% of it until one trial loses
//! nothing, and only then does the full sustained run confirm that rate. `N` is the
//! lower of what the request path answered and what reached the file; it is a rated
//! figure only if `dropped` is zero, which calibration exists to make the normal case.

#[path = "../tests/common/mod.rs"]
mod common;

use std::num::NonZeroU64;
use std::time::Duration;

use common::{drive_rated_load, sample_config};

/// Restated from `src/delivery/mod.rs`, whose constants are `pub(crate)`.
const FIELD_CEILING_BYTES: u64 = 256 * 4 * 10 + 2;
const BYTES_PER_RECORD: u64 = 32 * 1024;
const MAX_QUEUE_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const OUTAGE_TARGET_SECS: f64 = 300.0;
/// The stated reference load `DEFAULT_QUEUE_MAX_BYTES` is derived from (C39) — not
/// the measured `N`, which this bench also reports for reference but which no
/// honest budget could cover (`ceil(5 min x N x BYTES_PER_RECORD)` runs to hundreds
/// of GiB).
const REFERENCE_LOAD_RPS: f64 = 200.0;
/// Restated from `src/delivery/mod.rs` (C39).
const DEFAULT_QUEUE_MAX_BYTES: u64 = 1875 * 1024 * 1024;

fn main() {
    // `BENCH_SECS` shortens a smoke run; the published figure is the default.
    let secs: u64 = std::env::var("BENCH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a benchmark runtime");
    let run = |rate: u32, secs: u64| {
        let mut config = sample_config();
        config.log_queue_max_bytes = NonZeroU64::new(MAX_QUEUE_MAX_BYTES).unwrap();
        runtime.block_on(drive_rated_load(config, rate, Duration::from_secs(secs)))
    };
    // A ten-second unpaced probe finds what the file writer sustains as a burst.
    let probe = run(u32::MAX, 10);
    let ceiling = probe.delivered as f64 / 10.0;
    println!("probe, unpaced 10 s: {probe:?}");
    println!(
        "  request path {:.0}/s, file writer {ceiling:.0}/s",
        probe.achieved
    );

    // Calibrate on short trials before committing the full sustained run: 80% of the
    // ten-second burst is a guess, not a proof, and stepping down here costs seconds
    // per trial instead of minutes. Floor at 20% of the burst rate; below that the
    // pipeline is not sustaining a useful fraction of what it burst at, and the last
    // trial's number ships with its honest `zero loss: false` caveat below.
    let calibration_secs = secs.clamp(5, 30);
    let mut fraction = 0.8;
    let mut target = (ceiling * fraction) as u32;
    let mut trial = run(target, calibration_secs);
    println!(
        "calibration at {:.0}% of burst, {calibration_secs} s, {target}/s: {trial:?}",
        fraction * 100.0
    );
    while trial.dropped > 0 && fraction > 0.2 {
        fraction -= 0.1;
        target = (ceiling * fraction) as u32;
        trial = run(target, calibration_secs);
        println!(
            "calibration at {:.0}% of burst, {calibration_secs} s, {target}/s: {trial:?}",
            fraction * 100.0
        );
    }

    // Even a loss-free short calibration trial is not proof at ten minutes: page cache,
    // allocator and disk-writeback behavior can degrade over minutes in ways thirty
    // seconds never surfaces. So the full-duration run gets the same step-down
    // treatment calibration did, at the real duration this time, until it is itself
    // loss-free or the floor is reached — the number this bench ships is never one a
    // longer run has already falsified.
    let mut r = run(target, secs);
    println!("{r:?}");
    while r.dropped > 0 && fraction > 0.2 {
        fraction -= 0.1;
        target = (ceiling * fraction) as u32;
        println!(
            "full run at {target}/s still dropped records; stepping down and re-running at {:.0}% of burst",
            fraction * 100.0
        );
        r = run(target, secs);
        println!("{r:?}");
    }

    let n = r.achieved.min(r.delivered as f64 / secs as f64);
    println!("sustained for {secs} s, paced at {target}/s, file sink, 4 GiB queue");
    println!(
        "  request path answered {:.0}/s; {} records reached the file; {} dropped",
        r.achieved, r.delivered, r.dropped
    );
    println!(
        "rated figure N = {n:.0} decided requests per second (zero loss: {}) — this machine's ceiling, published for reference only",
        r.dropped == 0
    );

    let formula_at_n =
        (OUTAGE_TARGET_SECS * n * BYTES_PER_RECORD as f64 / MIB as f64).ceil() as u64 * MIB;
    println!(
        "ceil(5 min x N x BYTES_PER_RECORD) = {} MiB ({} bytes) — {}x past the {} MiB ceiling; no honest budget covers this, so it is NOT the default (C39)",
        formula_at_n / MIB,
        formula_at_n,
        formula_at_n / MAX_QUEUE_MAX_BYTES,
        MAX_QUEUE_MAX_BYTES / MIB
    );

    println!(
        "default budget = ceil(5 min x {REFERENCE_LOAD_RPS:.0} req/s reference load x BYTES_PER_RECORD) = {} MiB ({} bytes)",
        DEFAULT_QUEUE_MAX_BYTES / MIB,
        DEFAULT_QUEUE_MAX_BYTES
    );
    let default_records = DEFAULT_QUEUE_MAX_BYTES / BYTES_PER_RECORD;
    println!(
        "outage tolerance at the default: {:.1} s at the {REFERENCE_LOAD_RPS:.0} req/s reference load, {:.1} s at the measured N",
        default_records as f64 / REFERENCE_LOAD_RPS,
        default_records as f64 / n
    );

    println!("BYTES_PER_RECORD = {BYTES_PER_RECORD} bytes, rounded up to a power of two from:");
    println!(
        "  3 x FIELD_CEILING_BYTES = {} (256 chars x 4 bytes UTF-8 x 10 bytes worst Debug escape + 2 quotes = {FIELD_CEILING_BYTES}; package, version, method)",
        3 * FIELD_CEILING_BYTES
    );
    println!("  timestamp 64 + request_id 64 + reason 512 + size_of::<Decision>() 256 allowed");
    println!(
        "  total {} <= {BYTES_PER_RECORD}",
        3 * FIELD_CEILING_BYTES + 64 + 64 + 512 + 256
    );
}
