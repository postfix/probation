# Slice 4 — operator-configurable `osv_mode` (enforce/diagnostic/off)

## Change summary

Implements D5-D8 from `03-program-design.md`: an `OsvMode` enum
(`Enforce`/`Diagnostic`/`Off`) threaded through `OsvClient` and
`osv::evaluate`, a validated `osv_mode` config key (default `enforce`,
hard-fails on an unrecognized value), and a diagnostic-match logging seam in
`http::logging` (`RequestContext.osv_diagnostic_match`,
`record_osv_diagnostic_match`, `OSV_DIAGNOSTIC_REASON`) so a diagnostic-mode
match is recorded in the decision log without changing the served result.

Production code for D5-D8 was already implemented on disk when this session
resumed the plan. This session found and fixed two test-timing bugs
uncovered by running the slice's approved witness commands (see
`tdd-slice-4.md`), plus one code-review-flagged simplification
(`osv::evaluate`'s `Diagnostic` branch now reuses `blind` instead of
recomputing `policy::evaluate` a second time) and one code-review-flagged
dead-code cleanup (a duplicate, overwritten `osv_request_timeout_ms`
assignment in `tests/decision_log_delivery.rs`).

Files touched by this slice: `src/osv/mod.rs`, `src/config.rs`, `src/lib.rs`,
`src/http/logging.rs`, `tests/config_validation.rs`,
`tests/decision_log_delivery.rs`, `config.sample.toml`,
`docs/operations.md`, `tests/fixtures/config/invalid_osv_mode.toml`.

## Check command and output

```
cargo test --lib -- osv:: config:: http::logging:: -> 25 passed, 0 failed
cargo test --test config_validation                -> 26 passed, 0 failed
cargo test --test decision_log_delivery             -> 32 passed, 0 failed
```

## `tdd:`

See `docs/plans/osv-intel/evidence/tdd-slice-4.md` (copied verbatim into the
code-review dispatch).

## Review verdicts

- `qa` (sf-verification): VERIFIED — all D5-D8 requirement checks verified
  against live source and the three witness commands; ready for slice
  acceptance.
- `code-review` (sf-code-review): SHIP — no defects or convention breaches;
  two minor simplification/cleanup findings, both applied (redundant
  `policy::evaluate` call removed; duplicate test assignment removed).
- `security` (sf-security-review): CLEAR — no findings; fail-open discipline
  preserved across all three modes, mode is set-once and non-reloadable, no
  sensitive data in the diagnostic-match logging path.
