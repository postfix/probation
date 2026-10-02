## Delivered
Test-only slice; no signature in `src/` changes. `cargo test` now fails if the delivery pipeline collapses under a paced closed-loop load.

```
tests/common/mod.rs              + RatedLoadResult { offered, delivered, dropped, achieved }
                                 + drive_rated_load(config, target_rate, duration)
tests/delivery_rated_load.rs     new: rl17, rl18, rl19
```

- Driver: file sink only, exactly one sink, paced against `GET /health/live`, summary window pinned to 3600 s, `delivered` counted at the destination (distinct decided `request_id`s plus summary records), panics naming rotation if `<path>.1` exists. `achieved = (offered - 32 warm-ups)/elapsed`.
- Literals: `D = 5 s`, `F = 1500`, `B = 122_880_000` (= F x D/2 x `BYTES_PER_RECORD` 32768).
- F is set from the measured debug rate (unpaced, 32 workers, 5 s): 6971, 6723, 6583 requests/s; F <= a quarter of the lowest (1645). Slice 7 compares the release figure with these.

## Proof
- rl17 -> `cargo test --test delivery_rated_load` -> ok (one-record queue, 2 s at 1M/s, dropped > 0). Red before: E0432 unresolved import `common::drive_rated_load`; also red under mutation `summaries += 0`: left 14498, right 14497.
- rl18 -> ok x3 (F=1500, D=5 s). Red before: E0432; red under mutation `summaries += 0`: limb 3 left 1, right 0.
- rl19 -> ok (panics "the file sink rotated"). Red before: E0432; with the `<path>.1` assertion neutralised: "test did not panic as expected".
- `cargo check --all-targets` -> exit 0. `cargo test --test delivery_rated_load` -> `test result: ok. 3 passed; 0 failed`, ~6 s (limit D + 30 s).
- Reviews: code-review SHIP; adversarial-testing PASS (5 of 6 mutations tripped the intended limb); verification VERIFIED (qa).

## Limits
- Open decision (deviation from the approved design). Design: read `delivery_lost_total()` after `shutdown().await`. Not possible: `Running::shutdown` drops its `App`, then awaits a store task that ends only when every `App` handle is gone, so the driver's `Arc<App>` clone hangs shutdown. Built instead: spawn shutdown, poll the file for the shutdown `request_summary`, read the total once it appears, then drop the clone and await shutdown; the drain-deadline check is "summary seen OR dropped > 0". Code review judged this sound (the summary is the last record queued; no loss site fires after it is written). Alternative: change `Running::shutdown` in `src/lib.rs` to return the total (outside this slice).
- The uncounted drain-deadline cut could not be isolated by mutation (covered by `tp19` / `rl7` unit tests).
- Minor, not reproduced: a failed warm-up request would hang the barrier rather than fail the test. rl18 limb 2 margin is about 53 records over 7500.
- 8/8 green runs, including under load.

## Next
Slice 5: `GET /health/delivery` reports shedding for 60 s while `/health/ready` stays green.

## Recommendation
Approve as built and continue: the shutdown-time tally read was reviewed sound, and changing `Running::shutdown` would widen this slice into `src/lib.rs`.

Status: slice 4 proof line recorded in `00-status.md`; slices 1-4 done, 5-7 open.
Sources: `docs/plans/rated-load-guard/evidence/slice-4.md`, `evidence/tdd-slice-4.md`, `04-slices.md` row 4, `00-status.md`.
Approve slice 4 as built (keeping the shutdown-time tally read) and continue to slice 5?
