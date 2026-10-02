//! The rated-load floor: the file sink, paced at a rate this build can sustain, loses
//! nothing and reconciles exactly. The loop itself is `common::drive_rated_load`.
//!
//! No test here may set a short summary window: `set_summary_window` writes a
//! process-global that every test in this binary shares (C65). The driver sets one
//! longer than any run and that is the only value ever written.

mod common;

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use common::{drive_rated_load, sample_config};

/// Debug-build floor, records per second: one quarter of the rate the driver achieved
/// unpaced in a debug build (6583-6971/s over three
/// runs), so a loaded machine still clears it (C60).
const F: u32 = 1500;
const D: Duration = Duration::from_secs(5);
/// `F × (D/2) × BYTES_PER_RECORD` = 1500 × 2.5 × 32768 (`BYTES_PER_RECORD`, `pub(crate)`,
/// final from slice 1). Half the run's records fit in the queue.
const B: u64 = 122_880_000;

/// rl17: a deliberately small queue, so records are dropped, and the three
/// measurements still reconcile exactly.
#[tokio::test]
async fn rl17_the_three_measurements_reconcile() {
    let mut config = sample_config();
    // One record of room: the file writer cannot keep up with concurrent requests.
    config.log_queue_max_bytes = NonZeroU64::new(32 * 1024).unwrap();
    let r = drive_rated_load(config, 1_000_000, Duration::from_secs(2)).await;
    assert!(
        r.dropped > 0,
        "a one-record queue must drop under load: {r:?}"
    );
    assert_eq!((r.offered + 1) - r.delivered, r.dropped, "{r:?}");
}

/// rl18: the floor holds on every `cargo test`.
#[tokio::test]
async fn rl18_the_floor_holds() {
    let mut config = sample_config();
    config.log_queue_max_bytes = NonZeroU64::new(B).unwrap();
    let started = Instant::now();
    let r = drive_rated_load(config, F, D).await;
    assert!(started.elapsed() < D + Duration::from_secs(30), "{r:?}");
    assert_eq!(r.dropped, 0, "limb 1: {r:?}");
    assert!(r.delivered >= u64::from(F) * D.as_secs(), "limb 2: {r:?}");
    assert_eq!((r.offered + 1) - r.delivered, r.dropped, "limb 3: {r:?}");
}

/// rl19: a rotated file is a void run, not a low `delivered`.
#[tokio::test]
#[should_panic(expected = "rotat")]
async fn rl19_a_rotated_run_is_void() {
    let mut config = sample_config();
    config.log_file_max_bytes = NonZeroU64::new(2048).unwrap();
    drive_rated_load(config, 1_000_000, Duration::from_secs(1)).await;
}
