## Delivered
An operator can alert on `GET /health/delivery`: `503` while a record was lost in the last 60 seconds, `200` after 60 quiet seconds, `200` with no sink configured. `/health/ready` stays `200` throughout. `/health/live` and `/health/ready` are unchanged.

```diff
 src/delivery/mod.rs
+  const SHED_QUIET: Duration = Duration::from_secs(60)
+  pub(crate) fn is_shedding(&self, now_utc_micros: i64) -> bool   // on Sinks
+  watch pair: last_change_micros (stored first), last_total (Release store / Acquire load)
+  true only when now - last_change_micros is in 0..SHED_QUIET
 src/http/health.rs
+  pub async fn delivery(State(app): State<Arc<App>>) -> StatusCode   // bare status, no body
 src/http/mod.rs
+  .route("/health/delivery", get(health::delivery))
 tests/decision_log_delivery.rs
+  rl12 rl13 rl14 rl15 rl16c rl25; test-only gated_collector / recover / shedding_server
```

## Proof
- Witness: `cargo check --all-targets` exit 0; `cargo test --lib --test decision_log_delivery` -> ok: 94 lib + 27 integration passed, including rl12 rl13 rl14 rl15 rl16c rl25 (main-agent run, after the review fixes).
- Red before code: rl12 "404 on /health/delivery (no route)"; rl13, rl14, rl16c, rl25 "left 404, right 503"; rl15 "/health/delivery 404, ready 200".
- Mutations seen red: `since < SHED_QUIET` without the non-negative bound (rl16c: left 503, right 200); `SHED_QUIET = 1 s` (rl14 at +59 s: left 200, right 503).
- rl14: 503 at +59 s, 200 at +61 s. rl25: empty body and `Cache-Control: no-store` in both 503 and 200.
- Reviews: code-review SHIP (MINOR 1 and 2 fixed, MINOR 3 accepted); security CLEAR (wall-clock quiet window accepted by design, C47); adversarial FIX for D1, accepted by the user as C96 with no code change; verification (qa) VERIFIED.
- Evidence limit: `rl16` (store/load ordering, G3-T1) is structural only, with no executable witness on x86-64 (C52).

## Limits
- Deviations: recovery tests use `gated_collector()` instead of `wedged_collector()`, because a probe's own record is lost on a permanently full queue and re-stamps the watch pair. All six tests were written before the code, not as one red-green pair at a time; each was seen red (404) before the route existed. The `gate.send_replace(true)` before `server.shutdown()` in rl13/rl15 is not a behaviour change.
- C96 (accepted by the user): the stamp is the first probe's time, not the loss's time. A probe gap over 60 s reads `503` once more; a wedged sink under continued probing stays `503`; the probe interval must be strictly shorter than 60 s. This errs toward alerting, never silence. `docs/operations.md` states it in slice 7.
- One status covers both sinks (a healthy file sink and a wedged collector look identical).

## Next
Slice 6: the SIEM sink holds its batch while the collector is unreachable, bounded and cancellable.

## Recommendation
Continue to slice 6: the witness is green, all four reviews landed, and the one open finding is an accepted, documented limit.

Status: slices 1-5 done; slices 6-7 open; Gates 1-4 approved.
Sources: docs/plans/rated-load-guard/00-status.md (slice 5 proof line); docs/plans/rated-load-guard/evidence/slice-5.md; docs/plans/rated-load-guard/evidence/tdd-slice-5.md; docs/plans/rated-load-guard/04-slices.md (row 5, Slice 5 interfaces, C96)
Continue to slice 6, or re-steer?
