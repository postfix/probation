# Slice 1 evidence: OSV vulnerability intelligence — tracer bullet

## Outcome

A real request through `artifacts::serve_artifact` gets OSV-checked end to end —
`osv::OsvClient` batches a live `POST /v1/querybatch` (fake transport in tests), caches
the answer, and `policy::evaluate`'s new `osv_matched` tier denies a matched candidate
at the correct order.

## Diff summary

New: `src/osv/mod.rs`, `src/osv/batcher.rs`.

Changed: `src/policy/mod.rs` (`evaluate` gains `osv_matched: bool`; `DenyReason` gains
`BlockedByOsv`), `src/policy/blocklist.rs` (test call sites), `src/lib.rs` (`AppDeps`
gains `osv_client: reqwest::Client`; `App::start` constructs `osv::OsvClient::new`
directly using the `drain` shutdown token, D3-literal), `src/config.rs`
(`osv_cache_ttl_seconds`, `osv_request_timeout_ms`), `src/artifacts/mod.rs` (`evaluate`
wrapper becomes async, calls `osv::evaluate`; `deny_reason` gains `BlockedByOsv` arm),
`src/main.rs` (builds the production `reqwest::Client` for `AppDeps.osv_client`),
`tests/config_validation.rs`, `config.sample.toml`, `tests/common/mod.rs`,
`tests/persistence_recovery.rs`, `tests/decision_log_delivery.rs` (fake OSV client
wiring; `tp3_default_config_opens_nothing`'s `background_task_count()` fixture updated
2 → 3, since the osv batcher is now always spawned).

Minimal build-green mechanical edits outside Slice 1's own scope (Slice 2's files,
each marked `// ponytail:`, no real wiring): `src/npm/mod.rs` (one `DenyReason::BlockedByOsv`
match arm, plus one new unit test `deny_reason_maps_blocked_by_osv_in_npm_mod`),
`src/pypi/mod.rs`, `src/artifacts/download.rs` (each: literal `false` as the 5th
argument to the existing `policy::evaluate(...)` call).

## Witness

Command: `cargo test --lib -- osv:: policy:: config::` and `cargo test --test config_validation`.

```
$ cargo test --lib -- osv:: policy:: config::
test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 81 filtered out

$ cargo test --test config_validation
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Run independently by the main agent (not just relayed from Engineering) after both
post-review fixes landed; `cargo test --workspace` also confirmed green with no
regressions outside this slice's own files.

## tdd: lines

See `docs/plans/osv-intel/evidence/tdd-slice-1.md` for the full red/green trail (22
Gate 3 test-plan lines plus the 3 post-review fix lines: the reply-timeout bound test,
the rewritten shutdown-join tests, and `osv_matched_false_is_indistinguishable_from_todays_behavior`).

## Invariant spec dispositions

Five invariants Gate 3 deferred "to slice 1: source absent", all resolved in
`03-program-design.md`'s `## Invariants & spec dispositions`:

- C1 (OR-only merge) — REJECT: SMTC spec vacuously flags its own test module (no
  test-path exclude in the dominance engine); existing check
  `evaluate_never_lets_osv_unblock_a_producer_deny` covers it instead.
- C3/C14 (never fail-closed) — REJECT: `Decision::Unavailable` is a bare-path
  expression, not a call expression, so no supported SMTC shape can target it honestly;
  existing checks (`check_fails_open_on_batcher_timeout`,
  `check_fails_open_on_full_channel`, `check_writes_negative_ttl_on_failure`) cover it.
- C12a (bounded channel + enqueue-timeout fail-open) — **KEEP**:
  `.smtc/analyzers/enqueue-timeout-guard.yaml`; controls
  `docs/plans/osv-intel/controls/{unsafe,safe}/`; `sf-verify-cert` SOUND, 0 findings
  against product root `src/osv/mod.rs`, non-vacuous.
- C12b (length-equality check before pairing) — REJECT: guard is a comparison, operation
  is a subscript, neither is a call expression, no supported SMTC shape fits; existing
  check `batcher_fails_open_the_whole_batch_on_length_mismatch` covers it.
- C12c (outbound call timeout-wrapped) — **KEEP**:
  `.smtc/analyzers/outbound-timeout-guard.yaml`; controls
  `docs/plans/osv-intel/controls/{unsafe,safe}/`; `sf-verify-cert` SOUND against
  product root `src/osv/batcher.rs`, matching a documented non-zero pass condition
  (7 known noise lines from an unrelated same-named `send`, target line 149 absent),
  following this repo's existing `consumer-identity-extension-read.yaml` precedent for
  the identical schema limitation (independently verified, not taken on the author's
  claim).

## Review verdicts

- **code-review**: round 1 UNKNOWN (file mid-edit) with one confirmed MAJOR (production
  osv batcher never joined on shutdown, contradicting D3) and one MINOR (undocumented
  test substitution); both fixed. Round 2 (fresh subagent, settled diff): **SHIP**,
  0 defects, all 5 re-verification points confirmed by independent tracing and test
  runs.
- **security**: round 1 **CLEAR**, 0 findings, no unmodeled surface. Round 2 (fresh
  subagent, after the reply-timeout and shutdown-construction fixes touched
  `src/osv/mod.rs`/`src/lib.rs`/`src/main.rs`): **CLEAR** again, 0 findings, fail-open
  guarantee and test-only surface isolation both reconfirmed.
- **qa (adversarial)**: round 1 **FIX** — found a real, reproducible defect: a solitary
  OSV lookup was bounded by the hardcoded `OSV_BATCH_INTERVAL` (2s), not by
  `osv_request_timeout_ms` (500ms default), because `resolve()`'s reply-await had no
  timeout wrapper. Fixed (`reply_rx.await` now wrapped in
  `tokio::time::timeout(self.request_timeout, reply_rx)`). Round 2 (fresh subagent):
  confirmed fixed, non-vacuous regression test, no dangling-sender panic/leak, no new
  defect.

## Deviations from the literal design text (both reviewed and accepted)

1. `AppDeps.osv` (design's literal `osv::OsvClient` field) was briefly built as
   caller-supplied, then reworked back to match D3 literally: `AppDeps.osv_client:
   reqwest::Client`, with `App::start` itself calling `osv::OsvClient::new(...)` using
   the pre-existing `drain` token (not `shutdown`, which is created too late) — the
   same pattern `delivery::build` already uses. `Running::shutdown`'s existing
   join-then-drain sequence now genuinely joins the osv batcher, as D3 promised.
2. Minimal build-green edits landed in three Slice-2-owned files
   (`src/npm/mod.rs`, `src/pypi/mod.rs`, `src/artifacts/download.rs`) to keep the
   whole-crate build compiling after `policy::evaluate`'s signature changed — each
   edit is a single literal argument or match arm, marked `// ponytail:`, confirmed
   by two independent code-review passes to carry no Slice 2 wiring.
