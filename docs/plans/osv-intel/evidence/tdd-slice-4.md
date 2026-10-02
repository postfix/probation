# TDD evidence — Slice 4

## Starting state (session resume)

Production code for D5-D8 (`OsvMode` enum and `OsvClient.mode` field in
`src/osv/mod.rs`, `config.rs`'s `osv_mode` key, `http::logging`'s
`RequestContext.osv_diagnostic_match`/`record_osv_diagnostic_match`/
`OSV_DIAGNOSTIC_REASON` seam) was already present on disk from a prior session.
`cargo build --lib` was clean. Running the slice's approved witness commands
surfaced two real test failures — both test-construction bugs, not production
defects:

1. `osv::tests::evaluate_enforce_mode_denies_on_match` (`src/osv/mod.rs`) — FAILED:
   `assertion left == right failed / left: Allow / right: Deny(BlockedByOsv)`.
2. `record_osv_diagnostic_match_sets_the_reason_without_changing_result`
   (`tests/decision_log_delivery.rs`) — FAILED:
   `left: "the request was served" / right: "the request would be blocked by a
   known OSV malicious-package advisory (diagnostic mode: not enforced)"`.

## Root cause

Both tests spun up a real `OsvClient` batcher (via `spawn_with`/the full
`App::start` wiring) with `request_timeout` shorter than the batcher's fixed
`OSV_BATCH_INTERVAL` (2s, `src/osv/batcher.rs`). A solitary lookup's flush
deadline is only reached at `OSV_BATCH_INTERVAL` (the batcher's `deadline`
is set to `now + OSV_BATCH_INTERVAL` when the first request of a batch
arrives — see `batcher::run`), so a 500ms `request_timeout` always loses the
race and `OsvClient::check` fails open (`false`) before the mock server's
answer ever arrives — this is the existing, Gate-3-approved behavior proven by
`check_bounds_a_solitary_lookup_to_request_timeout_not_the_batch_interval`
(a solitary lookup is bounded by `request_timeout`, not by waiting for the
batch interval). The two failing tests needed `request_timeout` set above
`OSV_BATCH_INTERVAL` to actually observe a real match; this is a test-fixture
gap, not a change to Slice 1-3's approved design.

## Fix

- `src/osv/mod.rs`: the three `mode_server`-backed unit tests
  (`evaluate_enforce_mode_denies_on_match`,
  `evaluate_diagnostic_mode_allows_on_match`,
  `evaluate_diagnostic_mode_allows_without_match`) now pass
  `OSV_BATCH_INTERVAL + Duration::from_secs(1)` as `request_timeout` instead
  of a fixed 500ms.
- `tests/decision_log_delivery.rs`:
  `record_osv_diagnostic_match_sets_the_reason_without_changing_result` sets
  `config.osv_request_timeout_ms = 3_000` (ms) instead of relying on the
  500ms production default, for the same reason.

No production code changed.

## Result

```
cargo test --lib -- osv:: config:: http::logging:: -> 25 passed, 0 failed
cargo test --test config_validation                -> 26 passed, 0 failed
cargo test --test decision_log_delivery             -> 32 passed, 0 failed
```

All three required witness commands for Slice 4 now pass.

## Note (later pass over the same slice)

A second implementation pass over this slice (same session lineage) independently
converged on the identical `OSV_BATCH_INTERVAL`-widening fix for the same three
tests, landing a duplicate `config.osv_request_timeout_ms` assignment in
`record_osv_diagnostic_match_sets_the_reason_without_changing_result`
(`tests/decision_log_delivery.rs`) with a slightly different constant (3000ms vs
4000ms) and a redundant doc comment. Deduplicated to the single 4000ms assignment
already documented above; no other scoped file carried a duplicate. Full suite
(`cargo test`) and `cargo clippy --all-targets -- -D warnings` (scoped to the 8
files' own changes; pre-existing findings in `src/artifacts/mod.rs`, `src/npm/mod.rs`,
`src/osv/batcher.rs` are unrelated and out of scope) both re-verified clean after the
dedup.
