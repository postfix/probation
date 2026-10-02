## Delivered
The firewall now publishes a real number for "rated load" instead of a provisional guess: a
ten-minute calibrated bench measures the sustained rate the file sink survives with zero loss,
and the default queue budget is finally derived from a **stated 200 req/s reference load** — not
from that measured ceiling. No source behaviour changes beyond one constant; every function
signature involved (`drive_rated_load`, `Sinks::drops`, `Sink::push`) is unchanged.

```diff
 benches/delivery_rated_load.rs           (new, harness = false, bench = false)
+  probes an unpaced 10 s burst, then calibrates: 80% -> step down 10% (floor 20%) on any drop
+  confirms the calibrated rate over 600 s (BENCH_SECS override) -- and if that full run still
+  drops, steps down and reruns at full duration until it is loss-free (mid-slice fix #2)
+  prints rated figure N, outage tolerance at the 200 rps default and at N, BYTES_PER_RECORD
 Cargo.toml
+  [[bench]] name = "delivery_rated_load", harness = false, bench = false   (C86: excluded from bare `cargo bench`)
 src/delivery/mod.rs
-  DEFAULT_QUEUE_MAX_BYTES = <provisional 64 MiB literal>
+  DEFAULT_QUEUE_MAX_BYTES = 1875 * 1024 * 1024   (1,875 MiB; ceil(5 min x 200 req/s x
   BYTES_PER_RECORD), C13 as amended, C39 -- not derived from the measured ceiling N)
 tests/config_validation.rs
   rl5: DEFAULT_QUEUE_MAX_BYTES literal updated to match; comment updated
 docs/operations.md
+  new §8 subsection "The rated load, and what a default deployment survives"
+  log_queue_max_bytes / siem_queue_max_bytes rows; /health/delivery row; one RUST_LOG sentence
 README.md
+  bench invocation beside the existing canonical commands; headline "Rated load" paragraph
 04-slices.md
   stale pre-backtrack text corrected to match the already-approved C39 (see "Mid-slice
   correction" below) -- not new source behaviour, a plan-document fix
```

Mechanical churn: none beyond the constant swap above.

## Proof
| Promise | Witness | Observed |
|---|---|---|
| rl20: the bench calibrates, confirms loss-free at 600 s, prints N and the derivation | `cargo bench --bench delivery_rated_load` (BENCH_SECS=600) | calibrated and confirmed loss-free over the full 600 s, exit 0, all figures printed |
| The measurement itself | full 600 s run | **N = 59,288 decided requests/s, zero loss, confirmed over 600 s** — published for reference only |
| rl21: the whole suite passes under the final default literal and the updated rl5 literal | `cargo test --no-fail-fast` (all targets), re-run after the correction | every target `ok`, 0 failed |
| Compile sanity | `cargo check --all-targets` | exit 0 |
| C86: delivery_rated_load stays out of bare `cargo bench` | `cargo bench` (bare) | runs only the three pre-existing SPEC §12 benches |
| The eight documentary items | manual read-back of `docs/operations.md` / `README.md` against the shipped code and corrected numbers | present and consistent |

Two bugs found and fixed in this session's own bench before it produced a number to trust:
1. **Pacing bug.** The first cut paced the ten-minute run at a flat 80% of the ten-second unpaced
   burst rate. Run for real, it dropped 9.1M of 48.5M records. Fixed with a calibration
   step-down loop ahead of the full run.
2. **Calibration was not proof at scale.** Even a loss-free 30 s calibration trial still dropped
   2.85M records when run for the full 600 s at that same rate. Fixed by having the full-duration
   run itself step down and retry until it is loss-free, not just the calibration trial.

**Mid-slice correction (the significant finding).** This session first answered a real conflict
live in chat as its own decision, **C98**: the measured `N` puts `ceil(5 min x N x
BYTES_PER_RECORD)` ~135-150x past `MAX_QUEUE_MAX_BYTES`, so C98 capped the default at that ceiling
instead. That was implemented, reviewed (code-review = SHIP, qa = VERIFIED) and presented as
complete — without this session having read `02-architecture.md`'s **C39**, an already-approved
Gate 2/3 decision (2026-09-26 backtrack) answering the identical conflict differently: derive the
default from the stated 200 req/s reference load instead (1,875 MiB), publishing `N` for reference
only. `03-program-design.md` already encoded C39; `04-slices.md`'s C76/C80 and the slice 7
interfaces text had never been updated to match, which is what let this session miss it. Caught
before final sign-off, on a full re-read of `02-architecture.md`. C98 is now marked WITHDRAWN,
C76 carries a superseded-note, and 04-slices.md's text is corrected. The implementation, tests
and documentation were reverted from C98's ceiling-cap to C39's 200 req/s formula.

Reviews: first pass (on the withdrawn C98 implementation) code-review = SHIP, qa = VERIFIED — both
superseded. Re-review after the C39 correction: code-review = SHIP (N=59,288 and
DEFAULT_QUEUE_MAX_BYTES=1,875 MiB consistent across all six changed files, no leftover C98
residue, full-duration retry loop never silently ships a lossy result); qa = VERIFIED
(independently re-ran `cargo check --all-targets`, the full `cargo test` suite, bare `cargo
bench`, and a `BENCH_SECS=20` structural run reproducing both bug fixes' mechanism; took the full
600 s run's N=59,288 on trust per its packet's stated allowance).

## Limits
None carried forward as open. This is the plan's only remaining temporary artifact removal:
slice 1's provisional `DEFAULT_QUEUE_MAX_BYTES` and the `rl5` literal that tracked it are gone
(C76, C80).

## Next
None left to build. Slice 7 is the last row in `04-slices.md`'s slice table — no slice 8 exists —
so with it checked, all seven slices are checked while Gate 4 itself (`00-status.md`: "Gate 4 —
Slice plan: in progress") is still open pending this approval. Closing Gate 4 completes the
`rated-load-guard` plan; there is no next slice to continue to.

## Recommendation
Close Gate 4 and complete the plan. All seven slice acceptance rows are witnessed, the final
default budget literal matches the already-approved C39 formula rather than the withdrawn C98
answer, and the plan-consistency gap that let this session miss C39 has been corrected in
04-slices.md itself.

Status: Gates 1-3 approved; Gate 4 in progress with all seven slices now complete; this session's
own C98 answer withdrawn in favor of the prior approved C39.
Sources: 00-status.md (slice 7 corrected proof line; Gate 4 status); evidence/slice-7.md;
evidence/tdd-slice-7.md; 04-slices.md (Slice table row 7, C39, C76 superseded-note, C98
withdrawn, Slice 7 interfaces).
Slice 7 is the last slice in Gate 4's plan — approve closing Gate 4 and completing the
rated-load-guard plan, or hold it open?
