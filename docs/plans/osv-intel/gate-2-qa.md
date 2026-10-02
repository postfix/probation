# Gate 2 QA
## Verdict
READY

## Overall assessment
This is a fresh review of Gate 2's reopened content (clarifications C16-C18b, the `## Fit` table's
new `http::logging` row, `## Program behavior`, `## Flow`, `## Constraints`, and `## Threat model`)
against `01-product.md` and `evidence/threat-model-3.md`. The osv_mode enforce/diagnostic/off
feature is grounded in the actual repository: every interface claim I checked against source
(`src/http/logging.rs`'s `RequestContext`/`decide()`, `src/policy/mod.rs`'s existing
`DenyReason::BlockedByOsv`, `src/artifacts/mod.rs`/`src/npm/mod.rs`'s divergent private
`deny_reason` functions, the absence of a PyPI equivalent, `src/config.rs`'s hard-fail validation
convention) matches the document's description exactly, including the specific line numbers cited.
The two defects flagged by the two prior interrupted rounds (an escaped-pipe table cell, a
duplicated Flow step number) are both absent from the current text: the clarifications table
(lines 5-28) and the Fit table (lines 53-62) both have consistent per-row column counts, and Flow
steps are numbered 1-8 with no repeats. The new `http::logging` Fit row (line 62) is present,
6 columns match the header, and its claims (`record_osv_diagnostic_match()`, `OSV_DIAGNOSTIC_REASON`,
`osv_diagnostic_match: AtomicBool`) are consistent with C17b/C17c's text and with the real, currently
unmodified `RequestContext` struct's shape (`cache`/`ecosystem: AtomicU8` fields, `record_cache`/
`record_ecosystem` functions) that the new field and function are designed to mirror.

The required threat model (`evidence/threat-model-3.md`) ran two passes: first UNKNOWN with a
blocking structural gap G1 (C17's original "set `Decision.reason` directly" claim is unbuildable
against `decide()`'s actual `result`/`reason` derivation, confirmed by direct read of
`src/http/logging.rs:189-193`) plus T1 (unstated failure mode for a bad `osv_mode` value) and T2
(accepted operational limitation), then MODELED after C17b (task-local seam) and C18b (hard-fail)
closed G1 and T1. Both closures are reflected in the live `02-architecture.md` text, not just
asserted in the evidence file. The required `sf-red-team` pass is recorded inline (lines 165-171,
207-211): it returned FIX FIRST because C17b's "BlockedByOsv's existing reason string" claim did
not hold up against two divergent private per-ecosystem strings and no PyPI mapping at all — a
claim I independently confirmed by reading `src/artifacts/mod.rs:324-336` and `src/npm/mod.rs:
749-761`. C17c's fix, a new dedicated `pub(crate) OSV_DIAGNOSTIC_REASON` constant owned by
`http::logging` and independent of every ecosystem's deny-path strings, resolves it without
touching either module. No blocking findings.

## Questions and findings
None.

## What was checked
- **Completeness (requirement coverage):** Traced 01-product.md's C1-C4 (OR-only merge, no digest
  matching, fail-open on outage, malicious-package-only scope) against the reopened text's
  Constraints and Flow sections — all preserved (Constraints lines 109-129; Flow step 2 preserves
  OSV-blind-first ordering per C15). The new osv_mode feature (C16-C18b) is a Gate-2-owned
  extension answering a live re-steer question, not a Gate 1 requirement gap; its default
  (`enforce`) keeps existing behavior and Slices 1-3 unchanged, consistent with the router's
  reopen note. Result: satisfied.
- **Design quality (module responsibilities, interfaces, ownership):** Read `src/http/logging.rs`
  in full around `RequestContext`/`decide()` (lines 90-205) to confirm the proposed
  `osv_diagnostic_match: AtomicBool` field and `record_osv_diagnostic_match()` function follow the
  exact existing `cache`/`ecosystem` pattern, and that `decide()`'s no-`ApiError` branch (line 189-193)
  is the correct, and only, place that can read a task-local override without touching `ApiError`.
  Confirmed `DenyReason::BlockedByOsv` already exists (`src/policy/mod.rs:79`, wired at line 134) from
  prior slices, and that `artifacts::deny_reason`/`npm::deny_reason` are indeed two separate private
  per-module functions with no PyPI equivalent (grep confirmed zero `DenyReason`/`deny_reason` hits
  under `src/pypi/`), grounding C17c's premise. Result: satisfied.
- **Test readiness:** Flow steps 6-7 and C12a/b/c specify concrete, distinguishable fail-open paths
  (length mismatch, timeout, channel-full) each with a stated outcome, which gives Gate 3 testable
  seams; C18b calls for a `tests/config_validation.rs` case for the hard-fail path. Exact test names
  are correctly deferred to Gate 3. Result: satisfied for this Gate's altitude.
- **Security and performance:** The required threat model (`evidence/threat-model-3.md`) and Red
  Team pass are both complete, and I independently verified their closures are reflected in the
  live document text (not just asserted) as detailed above. Cache/batcher boundaries, fail-open
  behavior, and the OR-only merge constraint are all addressed. Result: satisfied.
- **Clarity:** Program behavior, Flow (steps 1-8, no duplicates), and Constraints sections describe
  the three-mode behavior (enforce/diagnostic/off) consistently with each other and with the
  clarification rows that justify them. Result: satisfied.
- **Formatting regressions from prior rounds:** Verified via `awk`-based column counts that the
  clarifications table (lines 5-28, 8 columns throughout) and Fit table (lines 53-62, 6 columns
  throughout) have no broken rows, and via `grep` that no stray escaped-pipe (`\|`) remains anywhere
  in the document. Result: both prior defects confirmed fixed.
- **Clarification inventory:** C16-C18b each carry ID, class, status (all `resolved`), owning/target
  Gate, exact question, selected value, and a specific decision source (user grilling answers Q1/Q2,
  or an architect decision resolving a named threat-model/red-team finding ID). No open questions
  remain in this reopened scope. Result: satisfied.

## Limitations
The out-of-scope original Gate 2 content (C1-C15) was read for context (to confirm the reopened
rows integrate correctly) but not re-litigated, per the task's explicit instruction. No standalone
red-team evidence artifact exists in `evidence/`; the finding and its resolution are recorded
inline in `02-architecture.md`'s `## Threat model` section, which I treated as sufficient per the
shared protocol's "or that the Gate records why the review was not required" allowance, since the
finding, its grounding, and its closure are all present and independently verifiable in the
document and in source.

## Next steps
Gate 2 is ready for presentation. The main agent should present this Gate for user approval; no
further revision or clarification is needed before that step.
