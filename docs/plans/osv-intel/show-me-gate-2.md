## What problem do we have?
Gate 2 was approved, then reopened a second time: the user asked whether OSV blocking can be
switched on/off in config, and whether a diagnostic mode exists that only logs malicious matches
without refusing them. Neither existed — every OSV match denied unconditionally, with no operator
control (02-architecture.md clarifications C16-C18b).

## How will we solve it?
A new `osv_mode` config key with three states — `enforce` (today's only behavior, denies on a
match), `diagnostic` (runs the same check but never denies, only logs that OSV would have matched),
`off` (skips the OSV check entirely, no network call, no cache lookup) — defaulting to `enforce` so
every existing deployment and Slices 1-3's tests stay behaved exactly as today (C16).

Requirement -> module:
- Operator picks enforce/diagnostic/off, invalid value hard-fails startup -> `config` adds `osv_mode: enforce/diagnostic/off` (default `enforce`) to `REQUIRED_KEYS`/`OPTIONAL_KEYS`, validated like every other key (`src/config.rs`, change, C18/C18b).
- `off` skips the check before it starts; `enforce`/`diagnostic` both still run it, only what `evaluate` is told and what the log records differs -> route handler's C15 OSV-blind-first step, gated by `osv_mode` (change, C18).
- `evaluate` stays pure and mode-unaware; the impure shell decides what `osv_matched` value to pass -> `policy::evaluate` (`src/policy/mod.rs`, unchanged shape; `enforce` passes the real value, `diagnostic` always passes `false`, C17).
- A `diagnostic`-mode match must log without flipping `result` off `"ALLOWED"` or touching `ApiError` -> `http::logging` adds `record_osv_diagnostic_match()` and the `OSV_DIAGNOSTIC_REASON` constant, plus `osv_diagnostic_match: AtomicBool` on the existing task-local `RequestContext`, mirroring the already-present `cache`/`ecosystem` fields (`src/http/logging.rs`, change, C17b/C17c).

```
src/
  config.rs      chg   osv_mode: enforce/diagnostic/off (default enforce), hard-fail on unrecognized value (C18, C18b)
  http/
    logging.rs   chg   RequestContext gains osv_diagnostic_match: AtomicBool; record_osv_diagnostic_match();
                        OSV_DIAGNOSTIC_REASON constant; decide()'s no-ApiError branch reads it (C17b/C17c)
  policy/mod.rs  --    unchanged shape: evaluate() still just takes osv_matched: bool (C17)
```

Why `http::logging` owns a new constant rather than reusing a deny-path string: `sf-red-team`
flagged that "`BlockedByOsv`'s existing reason string" does not exist as one value —
`artifacts::deny_reason` and `npm::deny_reason` are two different private per-module strings, and
PyPI has none. C17c's fix is a fourth, dedicated `pub(crate) OSV_DIAGNOSTIC_REASON` constant owned
by `http::logging` itself, independent of any ecosystem's deny-path strings.

Flow (steps 1-8, `02-architecture.md`): steps 1-2 unchanged (producer's snapshot decides first,
C15); step 3 is new — `Allow` + `osv_mode: off` is final, no OSV call at all; step 4 runs the OSV
check under `enforce` or `diagnostic`; steps 5-7 (batcher, pairing, fail-open) are unchanged from
the prior approval; step 8 is new — under `enforce`, `evaluate` is called again with the real
match value; under `diagnostic`, `evaluate` is always called with `false` (never denies), and a
real match instead calls `record_osv_diagnostic_match()` so `decide()` logs
`OSV_DIAGNOSTIC_REASON` while `result` stays `"ALLOWED"`.

## How will we confirm it is solved?
- Scenario: `osv_mode: enforce`, OSV matches -> expected: request denied, same as today -> check: existing `check_order_is_unavailable_deny_hold_allow` (`src/policy/mod.rs`), unchanged (planned, Gate 3/4).
- Scenario: `osv_mode: diagnostic`, OSV matches -> expected: request allowed, decision log's `reason` field carries `OSV_DIAGNOSTIC_REASON`, `result` stays `"ALLOWED"` -> check: `decide()`'s no-`ApiError` branch reading `record_osv_diagnostic_match()` (planned, Gate 3/4).
- Scenario: `osv_mode: off` -> expected: no network call, no cache lookup, request decided on the producer's snapshot alone -> check: C18's short-circuit before the C15 OSV-blind-first step even runs (planned, Gate 3/4).
- Scenario: config sets an unrecognized `osv_mode` value -> expected: startup hard-fails, never a silent fallback to a weaker mode -> check: new `tests/config_validation.rs` case (C18b) (planned, Gate 3/4).
- Threat model: `sf-threat-model` reopened against the `osv_mode` trust-boundary change, first pass returned UNKNOWN with blocking gap G1 (C17's original "set `Decision.reason` directly" mechanism is unbuildable against `decide()`'s actual `result`/`reason` derivation, `src/http/logging.rs:189-193`) plus T1 (unstated invalid-value failure mode) and T2 (accepted operational limitation: `diagnostic` has no distinct metric, documented not code-mitigated); closed by C17b (task-local `RequestContext` seam) and C18b (hard-fail), re-review returned **MODELED**, non-regression on C1/C3/C15 confirmed (`evidence/threat-model-3.md`, observed).
- Red Team: `sf-red-team` (mandatory for this security-control change) returned **FIX FIRST** against C17b's reason-string claim, closed by C17c's dedicated constant; coverage, dependencies, risk order, sizing, hard-bar, and security checks otherwise clean (02-architecture.md lines 165-171, 207-211, observed).
- Gate readiness: `sf-gate-qa` returned **READY**, two prior REVISE rounds fixed (round 1: broken table pipe + duplicate Flow step; round 2: Fit table missing the new `http::logging` row); no open questions remain (`docs/plans/osv-intel/gate-2-qa.md`, observed).

Recommendation: approve — the three-mode switch answers exactly the user's two questions
(on/off, diagnostic), defaults to today's behavior so Slices 1-3 need no rework, `evaluate` stays
pure and mode-unaware, the diagnostic-log mechanism reuses an existing seam rather than inventing
one, and every threat-model and red-team gap this reopen raised is closed by a cited decision with
Gate QA READY.

Limits: `diagnostic` mode has no counter/metric distinct from ordinary allowed traffic — only the
NDJSON `reason` string signals it (T2, accepted operational limitation, not a code change). Exact
cache TTL, per-check timeout, and channel capacity remain Gate 3 config/constant values, unchanged
by this reopen. `docs/plans/rated-load-guard/` is a separate, in-flight plan touching
`src/delivery/*` and `src/http/{health,logging,mod}.rs`; slice work must check its current state
before editing those files.

Current Gate: 2, reopened a second time, in progress pending this approval (Gate 1 approved
2026-09-27; Slices 1-3 complete and approved; Gates 3-4 will re-run once this Gate re-approves).

Sources: docs/plans/osv-intel/02-architecture.md (C16-C18b, Fit table's http::logging row, Flow
1-8, Threat model); docs/plans/osv-intel/evidence/threat-model-3.md (MODELED); docs/plans/osv-intel/gate-2-qa.md (READY).

Approve Gate 2, or what should change?
