# Slice 4 evidence — the closed-loop load driver and the cargo test floor

## Diff summary
- `tests/common/mod.rs`: appended `RatedLoadResult { offered, delivered, dropped, achieved }` and `drive_rated_load(config, target_rate, duration)`. File sink only, exactly one sink, paced closed loop against `GET /health/live`, summary window pinned to 3600 s, `delivered` counted at the destination (distinct decided `request_id`s plus summary records), panics naming rotation if `<path>.1` exists.
- `tests/delivery_rated_load.rs` (new): `rl17_the_three_measurements_reconcile`, `rl18_the_floor_holds`, `rl19_a_rotated_run_is_void`.
- Literals: `D = 5 s`, `F = 1500`, `B = 122_880_000` (= F × D/2 × `BYTES_PER_RECORD` 32768).

## Measured debug rate (fixes F)
Unpaced probe, 32 workers, 5 s, debug build: 6971, 6723, 6583 requests/s. F = 1500 <= a quarter of the lowest (1645). Slice 7 compares the release figure with these.

## Witness
- `cargo check --all-targets` -> exit 0.
- `cargo test --test delivery_rated_load` -> `test result: ok. 3 passed; 0 failed`, ~6 s (limit D + 30 s).

## tdd lines
See `evidence/tdd-slice-4.md` (rl17, rl18, rl19, F).

## Deviation from the approved design — needs the user's decision
Design: read `delivery_lost_total()` after `shutdown().await` returns. Not possible: `Running::shutdown` drops its `App` then awaits a store task that ends only when every `App` handle is gone, so the `Arc<App>` clone the driver holds hangs shutdown. Implemented instead: spawn shutdown, poll the file for the shutdown `request_summary`, read the total once it appears, then drop the clone and await shutdown; drain-deadline check is "summary seen OR dropped > 0". Code review judged this sound (the summary is the last record queued; no loss site fires after it is written). Alternative: change `Running::shutdown` in `src/lib.rs` to return the total (outside this slice). Also: `achieved = (offered − 32 warm-ups)/elapsed`.

## Review verdicts
- code-review: SHIP. Minor, not reproduced: a failed warm-up request would hang the barrier rather than fail the test. rl18 limb 2 margin is about 53 records over 7500.
- adversarial-testing: PASS. 5 of 6 mutations tripped the intended limb; the uncounted drain-deadline cut could not be isolated (covered by `tp19`/`rl7` unit tests); 8/8 green runs including under load.
- verification: VERIFIED.
