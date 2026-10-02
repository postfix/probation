# Slice 2 evidence: OSV vulnerability intelligence — extend to npm/PyPI/download

## Outcome

The same OSV check now covers every production decision point — npm and PyPI
per-version resolution and the artifact download path — so a version blocked by OSV
is denied everywhere a version can be requested, not only through `serve_artifact`.

## Diff summary

Changed: `src/npm/mod.rs`, `src/pypi/mod.rs`, `src/artifacts/download.rs` — each file's
Slice-1-era mechanical build-green edit (a literal `false` argument to
`policy::evaluate(...)`) replaced with a real `crate::osv::evaluate(&app.osv, ...).await`
call, matching `03-program-design.md`'s `## Call stack` rows exactly:

- `npm::resolve`'s per-version call (loop over `entries`).
- `pypi::resolve`'s per-file call (loop over `files`).
- `artifacts::download.rs::transfer`'s single call (already `async`, no signature ripple).

No `deny_reason` change needed in `pypi/mod.rs` (D1 — none exists there); `npm/mod.rs`'s
`BlockedByOsv` match arm and its test (`deny_reason_maps_blocked_by_osv_in_npm_mod`)
already existed from Slice 1's mechanical fix and are unchanged. No `// ponytail:`
markers remain in any of the three files.

## Witness

Command: `cargo test --lib -- npm:: pypi:: artifacts::download` and
`cargo test --test decision_log_delivery`.

```
$ cargo test --lib -- npm:: pypi:: artifacts::download
test result: ok. 36 passed; 0 failed; 0 ignored; 0 measured; 78 filtered out

$ cargo test --test decision_log_delivery
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Run independently by the main agent, and again independently by `sf-verification`.

## Review verdicts

- **code-review**: **SHIP**, 0 defects. Two non-blocking MINORs: (1) existing
  npm/pypi/download tests use `osv::unreachable_client()` (fail-open), so none exercises
  a genuine OSV-matched-deny outcome at these three specific call sites — coverage
  relies on Slice 1's seam-level tests instead; (2) cosmetic — these three sites use
  fully-qualified `crate::osv::evaluate(...)` rather than Slice 1's `use crate::{...,
  osv, ...}` + `osv::evaluate(...)` import convention.
- **qa (adversarial)**: **PASS**. Checked correct candidate wiring at each site (no
  copy-paste/stale-reference risk), independent per-iteration OSV checks in both loops,
  no unconverted/bypassing second decision path (`grep` confirmed the only remaining
  `policy::evaluate` calls are inside `osv::evaluate` itself), and that the `.await`
  insertion in `download.rs::transfer` doesn't change publish ordering (the OSV/policy
  gate still runs before `publish`, same as pre-Slice-2). No defects found.
- **qa (verification)**: **VERIFIED**, independently reran both witness commands,
  independently traced all three call sites' argument wiring against `osv::evaluate`'s
  actual signature, confirmed scope was respected (`git diff --stat` shows only the 3
  approved files), and assessed the coverage-boundary MINOR as an acceptable, non-blocking
  trade-off given the shared-wrapper design (D2) and Slice 1's already-proven seam.

## Limits

The coverage-boundary MINOR from code-review stands as a known, accepted limitation:
no test exercises a real OSV match flowing specifically through npm/pypi/download's
deny handling (only through the shared `osv::evaluate`/`policy::evaluate` seam). Low
marginal value given D2's single-wrapper design; not required for this slice's
Done-when.
