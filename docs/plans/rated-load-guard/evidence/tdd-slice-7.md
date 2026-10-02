tdd: rl20 (execution) — bench target absent before. First run (uncalibrated 80%-of-burst
pacing): 600 s sustained, exit 0, printed the rated figure, tolerance and derivation, but
`dropped = 9,106,962` of 48,473,920 (zero loss: false) — the 80%-of-10s-burst guess did not
hold over ten minutes. Result also far outside the 60-250 MiB band, literal NOT adopted (C76).
Root cause: the bench paced from a single unpaced 10 s probe, which overstates what the file
writer sustains once queueing runs for minutes rather than seconds.
tdd: bench fix #1 — added a short (clamped 5-30 s) calibration step-down loop before the full
run: trial at 80% of burst, step down by 10% on any drop, floor 20%, confirm the first
zero-loss trial's rate for the full duration.
tdd: rl20 (execution, calibration #1) — full 600 s run at the calibrated rate: zero loss,
N = 60,802 decided requests/s. Session initially adopted a C98 decision (cap default at
MAX_QUEUE_MAX_BYTES) built on this figure — see "Correction" below.
tdd: Correction — cross-checking `02-architecture.md` before presenting slice 7 as complete
found **C39**, an already-approved Gate 2/3 decision (from a prior session's own backtrack on
this exact conflict, 2026-09-26) that the live-chat C98 decision superseded without knowledge
of. C39's answer governs: `DEFAULT_QUEUE_MAX_BYTES` is derived from a **stated 200 req/s
reference load**, `ceil(5 min x 200 x BYTES_PER_RECORD) = 1,875 MiB`, not from the measured
ceiling `N`. `03-program-design.md` (approved) already stated this; `04-slices.md`'s C76/C80
and the slice 7 interfaces text were never updated to match after the backtrack — the gap C39
itself said still needed doing. C98 marked WITHDRAWN in `04-slices.md`; C76 given a
superseded-note; slice 7 interfaces text corrected. `src/delivery/mod.rs`,
`tests/config_validation.rs`, the bench and the docs reverted to the C39 formula.
tdd: rl20 (execution, re-run for the corrected bench) — the bench itself was also changed to
report `N` as an informational reference figure only, with the default/tolerance derived from
the 200 req/s constant. Re-run to confirm: full 600 s run at the same calibrated rate
(59,288-69,000 depending on run) **dropped 2,849,956 records** — a 30 s zero-loss calibration
trial was not proof at ten minutes. Second real bug found and fixed.
tdd: bench fix #2 — the full-duration run now also steps down and re-runs (bounded, floor 20%
of burst) until it is itself loss-free, not just the short calibration trial.
tdd: rl20 (execution, final) — full 600 s run, calibrated and confirmed loss-free at the full
duration on the first attempt after the fix: `offered = 35,572,822`, `delivered = 35,572,823`,
`dropped = 0`. **N = 59,288 decided requests/s, zero loss, genuinely confirmed over 600 s.**
Adopted as the published reference figure; `DEFAULT_QUEUE_MAX_BYTES` remains 1,875 MiB (C39,
independent of `N`).
tdd: rl21 — `cargo test` (all targets, `--no-fail-fast`), re-run after the correction: every
target `ok`, 0 failed.
tdd: docs — `docs/operations.md` §8 and `README.md` updated to state the corrected story: `N`
published for reference only; the default derived from the 200 req/s reference load, buying
the full 5 minutes there and about 1 s at the measured `N`; the formula-at-`N` figure (~543
GiB, ~136x the ceiling) stated as the reason it is not used.
