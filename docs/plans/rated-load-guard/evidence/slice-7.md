# Slice 7 evidence — the bench, the published numbers, and the final default budget literal

## Diff summary
- `benches/delivery_rated_load.rs` (new): drives `drive_rated_load` (slice 4) through the file
  sink. Probes an unpaced 10 s burst, calibrates in short (clamped 5-30 s) trials stepping down
  from 80% of the burst rate by 10% on any drop (floor 20%), then confirms the calibrated rate
  over the full duration (600 s by default) — itself stepping down further and re-running at
  full duration if that run is not loss-free. Prints the rated figure `N` (informational
  reference only), the default budget derived from a stated 200 req/s reference load, the
  outage tolerance at both that load and at `N`, and the `BYTES_PER_RECORD` derivation.
- `Cargo.toml`: `[[bench]] name = "delivery_rated_load", harness = false, bench = false` (C86).
- `src/delivery/mod.rs`: `DEFAULT_QUEUE_MAX_BYTES` changed from the provisional 64 MiB literal
  to `1875 * 1024 * 1024` (1,875 MiB), derived from `ceil(5 min x 200 req/s x
  BYTES_PER_RECORD)` (C13 as amended, C39) — **not** from the measured ceiling `N`.
- `tests/config_validation.rs`: `rl5`'s literal updated to match, comment updated.
- `docs/operations.md`: new "The rated load, and what a default deployment survives"
  subsection under §8; `log_queue_max_bytes` / `siem_queue_max_bytes` key-table rows;
  `/health/delivery` health-endpoint row; one sentence near `RUST_LOG`.
- `README.md`: bench invocation; headline "Rated load" paragraph.
- `docs/plans/rated-load-guard/04-slices.md`: corrected stale text left over from a prior
  session's Gate 2/3 backtrack (C39) that was never carried into this file — see "Mid-slice
  correction" below.

## Mid-slice findings and fixes
1. **Bench pacing bug.** The first cut paced the ten-minute run at a flat 80% of the ten-second
   unpaced burst rate. Run for real, it dropped 9.1M of 48.5M records. Fixed with a short
   calibration step-down loop before the full run.
2. **Calibration was not proof at scale.** Even a loss-free 30 s calibration trial still dropped
   2.85M records when the *same rate* was run for the full 600 s. Fixed by having the
   full-duration run itself step down and retry until it is loss-free, not just the calibration.
3. **Plan-consistency defect (the significant one).** This session independently rediscovered a
   conflict a prior session had already resolved: the bench's measured `N` (~59,000-65,000 rps
   across several runs) puts `ceil(5 min x N x BYTES_PER_RECORD)` ~135-150x past
   `MAX_QUEUE_MAX_BYTES`. This session first resolved it live in chat as **C98** (cap the
   default at the ceiling) and implemented, reviewed and presented that as complete — without
   having read `02-architecture.md`'s **C39**, an already-approved Gate 2/3 decision (from a
   2026-09-26 backtrack) answering the identical conflict differently: derive the default from
   a **stated 200 req/s reference load** instead (`1,875 MiB`), publishing `N` for reference
   only. `03-program-design.md` (approved) already encoded C39's formula; `04-slices.md`'s
   C76/C80 and the slice 7 interfaces text were never updated to match, which is what let this
   session miss it. Caught before final sign-off, when re-reading `02-architecture.md` in full.
   C98 is marked WITHDRAWN in `04-slices.md`, C76 carries a superseded-note, and the interfaces
   text is corrected. Implementation, tests and docs were reverted to C39's formula.

## Witness
- `cargo check --all-targets` -> exit 0.
- `cargo bench --bench delivery_rated_load` (`BENCH_SECS=600`) -> ten minutes sustained,
  calibrated and confirmed loss-free at full duration on the corrected bench: `N = 59,288`
  decided requests/s, zero drops, exit 0, printed the rated figure, the C39-derived default,
  both outage-tolerance figures and the `BYTES_PER_RECORD` derivation (rl20).
- `cargo test --no-fail-fast` (all targets) -> every target `ok`, 0 failed, re-run after the
  correction (rl21).
- `cargo bench` (bare) -> runs only the three pre-existing SPEC §12 benches (C86).
- Manual: the eight `docs/operations.md` / `README.md` documentary items read back against the
  shipped code and the corrected numbers.

## tdd lines
See `evidence/tdd-slice-7.md`.

## Review verdicts
- code-review (first pass, on the pre-correction C98 implementation): FIX FIRST -> SHIP after
  two fixes (a MiB-to-GiB conversion error; two dead lines in the bench). That implementation
  was subsequently withdrawn (see "Mid-slice findings" #3) and superseded by the C39 correction
  below — the SHIP verdict does not apply to the code as finally shipped.
- qa (first pass, sf-verification, on the pre-correction implementation): VERIFIED. Also
  superseded by the C39 correction.
- Re-review after the C39 correction: code-review = SHIP (no defects; confirmed N=59,288 and
  DEFAULT_QUEUE_MAX_BYTES=1,875 MiB identical and consistent across all six changed files, no
  leftover C98 residue, full-duration retry loop correct and never silently ships a lossy
  result; independently re-ran `cargo test --no-fail-fast`, all green). qa (sf-verification) =
  VERIFIED (independently ran `cargo check --all-targets`, the full `cargo test` suite, bare
  `cargo bench` for C86, and a `BENCH_SECS=20` structural run that reproduced both bug fixes'
  mechanism live; took the full 600 s run's exact N=59,288 figure on trust per its packet's
  stated allowance).
