# Slice 1 — OSV vulnerability intelligence: tracer bullet

## Delivered

A real request through `artifacts::serve_artifact` is now OSV-checked end to end.
Signatures changed: `policy::evaluate` gains a new `osv_matched: bool` parameter, and
`policy::DenyReason` gains a `BlockedByOsv` variant.

New: `src/osv/mod.rs` (`OsvClient::new`, `OsvClient::check`, `osv::evaluate`),
`src/osv/batcher.rs` (`batcher::run`).

Changed:
- `src/policy/mod.rs` / `src/policy/blocklist.rs` — `evaluate`'s new tier, call sites updated.
- `src/lib.rs` — `AppDeps` gains `osv_client: reqwest::Client`; `App::start` constructs
  `osv::OsvClient::new` itself, using the pre-existing `drain` shutdown token (matching
  `delivery::build`'s pattern).
- `src/config.rs` / `config.sample.toml` — new `osv_cache_ttl_seconds`, `osv_request_timeout_ms`.
- `src/artifacts/mod.rs` — the private `evaluate` wrapper becomes `async`, calls `osv::evaluate`;
  `deny_reason` gains the `BlockedByOsv` arm.
- `src/main.rs` — builds the production `reqwest::Client` for `AppDeps.osv_client`.
- `tests/config_validation.rs`, `tests/common/mod.rs`, `tests/persistence_recovery.rs`,
  `tests/decision_log_delivery.rs` — fake OSV client wiring; the batcher is now always spawned,
  so `background_task_count()` fixture moved 2 → 3.

Minimal build-green edits in three Slice-2-owned files (`src/npm/mod.rs`, `src/pypi/mod.rs`,
`src/artifacts/download.rs`), each a single literal `false` argument or match arm, marked
`// ponytail:` — no Slice 2 wiring, confirmed by two independent code-review passes.

## Proof

| Promise | Witness | Result |
|---|---|---|
| `cargo test --lib -- osv:: policy:: config::` all PASS | run | 33 passed, 0 failed |
| `cargo test --test config_validation` all PASS | run | 25 passed, 0 failed |
| `cargo test --workspace` green, no regressions | run | confirmed green |

Run independently by the main agent (not just relayed) after both post-review fixes landed.

Five invariants Gate 3 deferred "to slice 1: source absent" are now resolved:
- C1, C3/C14, C12b — **REJECT**: no supported SMTC shape targets them honestly; existing
  unit tests cover each instead (named in `03-program-design.md`).
- C12a, C12c — **KEEP**: `.smtc/analyzers/enqueue-timeout-guard.yaml` and
  `outbound-timeout-guard.yaml`; `sf-verify-cert` SOUND against `src/osv/mod.rs` and
  `src/osv/batcher.rs`, both non-vacuous.

Reviews: code-review round 1 found one confirmed MAJOR (the production osv batcher was
never joined on shutdown, contradicting the design) and one MINOR, both fixed; round 2
(fresh subagent, settled diff) **SHIP**, 0 defects. Security: **CLEAR** both rounds.
QA (adversarial) round 1 found a real defect — a solitary OSV lookup was bounded by the
hardcoded 2s batch interval, not by the configured `osv_request_timeout_ms` (500ms
default), because `resolve()`'s reply-await had no timeout wrapper; fixed by wrapping
`reply_rx.await` in `tokio::time::timeout(self.request_timeout, reply_rx)`. Round 2:
confirmed fixed, non-vacuous regression test, no dangling-sender panic or leak.

## Limits

`tests/common/mod.rs`'s fake `OsvClient` is not temporary — it is the lasting test
convention Slice 2 and all later tests reuse.

## Next

Slice 2 wires the same `osv::evaluate` into npm and PyPI per-version resolution and the
artifact download path, so a version OSV blocks is denied everywhere it can be requested,
not only through `serve_artifact`. Slice 2 has not started.

## Recommendation

Continue to Slice 2 — Slice 1 is verified end to end with no open defects.

Gate 4 approved with 2 slices; Slice 1 done, Slice 2 not started.

Sources: `docs/plans/osv-intel/evidence/slice-1.md`, `docs/plans/osv-intel/evidence/tdd-slice-1.md`, `docs/plans/osv-intel/04-slices.md`.

Slice 1 is complete and verified. Proceed to Slice 2 (extend `osv::evaluate` to npm/PyPI resolve and the artifact download path), or pause here?
