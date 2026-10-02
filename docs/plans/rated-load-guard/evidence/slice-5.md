# Slice 5 evidence: GET /health/delivery

## Diff summary
- `src/delivery/mod.rs`: `SHED_QUIET` (60 s), `Sinks::new`, `Sinks::is_shedding` and the process-wide watch pair (`last_change_micros` stored first, `last_total` Release/Acquire; true only for a delta in `0..SHED_QUIET`).
- `src/http/health.rs`: `health::delivery`, bare status, no body.
- `src/http/mod.rs`: `.route("/health/delivery", get(health::delivery))`.
- `tests/decision_log_delivery.rs`: `rl12`, `rl13`, `rl14`, `rl15`, `rl16c`, `rl25`, plus test-only `gated_collector`/`recover`/`shedding_server`.

## Witness
`cargo check --all-targets` exit 0; `cargo test --lib --test decision_log_delivery`: 94 lib ok, 27 integration ok (main-agent run, after the review fixes).

## Deviations
- Recovery tests use `gated_collector()` instead of `wedged_collector()`: each probe's own record is lost on a permanently full queue and re-stamps the watch pair.
- All six tests were written before the code, not one red-green pair at a time; each was seen red (404) before the route existed.
- `rl16` structural, no executable witness on x86-64 (C52).

## tdd lines
tdd: rl12 | red: 404 on /health/delivery (no route) | green: rl12_delivery_is_200_when_nothing_is_shed ok (no-sink App and file-sink App with traffic, no loss) | tests/decision_log_delivery.rs
tdd: rl13 | red: left 404, right 503 | green: rl13_delivery_is_503_right_after_a_loss ok (gated SIEM collector, 5000 requests, lost_total > 0) | tests/decision_log_delivery.rs
tdd: rl14 | red: left 404, right 503 | green: rl14_delivery_recovers_after_sixty_quiet_seconds ok (probe 503, collector released and queue drained, +61 s, probe 200) | tests/decision_log_delivery.rs
tdd: rl15 | red: /health/delivery 404, ready 200 | green: rl15_readiness_stays_green_while_delivery_sheds ok (ready 200, delivery 503) | tests/decision_log_delivery.rs
tdd: rl16c | red: left 404, right 503 | green: rl16c_a_backwards_clock_step_does_not_latch_503 ok | also red under mutation `since < SHED_QUIET` (no non-negative bound): left 503, right 200 | tests/decision_log_delivery.rs
tdd: rl25 | red: left 404, right 503 ("shedding" limb) | green: rl25_delivery_has_no_body_and_is_not_cacheable ok (empty body and Cache-Control: no-store in both 503 and 200) | tests/decision_log_delivery.rs
tdd: rl14 lower bound | red under mutation SHED_QUIET = 1 s: left 200, right 503 at +59 s (restored to 60 s) | green: rl14 ok (503 at +59 s, 200 at +61 s) | tests/decision_log_delivery.rs
tdd: rl13/rl15 gate release | not a behaviour change: `gate.send_replace(true)` before `server.shutdown()` so shutdown does not drain against a wedged collector | tests stay green, run time measured below | tests/decision_log_delivery.rs

## Review verdicts
- code-review: SHIP. MINOR 1 (no 59 s pin) and MINOR 2 (slow wedged tests) fixed in `rl14`, `rl13`, `rl15`; MINOR 3 accepted.
- security: CLEAR. No unmodeled surface. MINOR: quiet window uses wall clock, accepted by design (C47).
- adversarial: FIX for D1 (probe stamps its own time; wedged sink under continued probing stays 503). Accepted by user, C96, no code change.
- qa (sf-verification): VERIFIED.

## Carried to slice 7 (documentary, C96)
`docs/operations.md` states: a probe gap over 60 s reads `503` once more; a wedged sink under continued probing stays `503`; the probe interval must be strictly shorter than 60 s.
