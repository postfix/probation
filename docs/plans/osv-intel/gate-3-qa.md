# Gate 3 QA
## Verdict
READY

## Overall assessment
This is round 5 of a reopened Gate 3, scoped only to verifying the fixes for F6 (blocking) and
F7 (minor) from round 4, plus a re-scan of the whole D5-D8 clarification scope. Both fixes hold
up against the current repository source, not just the document's own claims. F6's three "## Files"
bullets (`src/config.rs`, `tests/config_validation.rs`, `config.sample.toml`) now each separately
describe the `osv_mode` addition, and the described shapes match what is actually in those files
today. F7's rewritten D6 text describes `osv_mode`'s `validate()` arm as matching the exact,
already-implemented `osv_cache_ttl_seconds`/`osv_request_timeout_ms` pattern at
`src/config.rs:393-399` (inline `Some`/`None` handling, no serde default attribute, no separate
`DEFAULT_OSV_MODE` constant) — verified directly against the file, and it is accurate. D5-D8's
other claims (osv::evaluate's mode-aware wrapper, http::logging's RequestContext seam, the D8
non-regression check against threat-model-3.md, and the reopen's Red Team disposition) are all
grounded correctly against current source and upstream documents. One purely cosmetic line-range
inaccuracy was found (OPTIONAL_KEYS cited as `179-198`, actually `179-191`); it does not block
implementation and is noted below for completeness rather than as a defect requiring correction.
No new blocking or non-blocking defect was found. The specification is ready for presentation.

## Questions and findings
None new. F1-F5 remain closed (confirmed in round 4, not re-litigated here per instructions).

F6 (was blocking) — CLOSED, confirmed by direct source read.
- Location: `docs/plans/osv-intel/03-program-design.md` "## Files" bullets for `src/config.rs`
  (line 23), `tests/config_validation.rs` (line 29), `config.sample.toml` (line 30).
- Verification: `src/config.rs` currently has `OPTIONAL_KEYS` at lines 179-191 (not yet
  including `osv_mode`, as expected pre-implementation), `RawConfig`'s `osv_cache_ttl_seconds`/
  `osv_request_timeout_ms: Option<u64>` fields at lines 142-143, `Config`'s matching fields at
  lines 74-78, and the `validate()` match arms at lines 393-399 — exactly the four places the
  bullet names for the new `osv_mode` key. `tests/config_validation.rs` currently has
  `INVALID_CONFIGS` with two OSV rows (`zero_osv_cache_ttl_seconds.toml`,
  `zero_osv_request_timeout_ms.toml`, lines 77-84) and `WITH_DEFAULTS` with both OSV keys
  (lines 182-187) — exactly the pattern the bullet says a third row/entry extends.
  `config.sample.toml` currently ships both OSV keys (lines 95, 98) with no `osv_mode` yet,
  matching the bullet's claim that this reopen adds `osv_mode = "enforce"` on top of that.
  All three bullets are accurate and no longer silently drop the `osv_mode` addition.
- Result: fix confirmed, closed.

F7 (minor) — CLOSED, confirmed by direct source read.
- Location: D6 in "## Clarifications and decisions" (line 12).
- Verification: `src/config.rs:393-399` today reads
  `osv_cache_ttl_seconds: match self.osv_cache_ttl_seconds { Some(value) => nonzero_u64(...)?,
  None => DEFAULT_OSV_CACHE_TTL_SECONDS }` (and the same shape for `osv_request_timeout_ms`) —
  no `#[serde(default = ...)]` attribute anywhere on either `RawConfig` field (contrast with
  `metadata_max_age_seconds`/`max_references_per_project`, which do use
  `#[serde(default = "...")]`). D6's rewritten text describes `osv_mode`'s arm using exactly this
  inline-match shape, explicitly contrasting it with the serde-default convention it no longer
  claims to use, and explicitly declines a separate `DEFAULT_OSV_MODE` constant on the grounds
  that the default is a fieldless enum variant. This matches both the letter and the spirit of
  the existing `config.rs` convention.
- Result: fix confirmed, closed.

## What was checked
- Completeness (sf-specification-qa): re-read all of D5-D8, the "## Files" bullets they touch,
  "## Modules and interfaces" (`osv`, `osv::batcher`, `config`, `http::logging` sections),
  "## Call stack" rows for the `OsvMode`-gated paths, and the Threat model's reopen paragraph.
  All parameters, return types, and failure/fail-open paths for the mode-aware `osv::evaluate`
  wrapper are stated explicitly (Off short-circuits before `OsvClient::check`; Enforce is D2's
  unchanged two-phase dance; Diagnostic runs the same dance but forces `osv_matched: false` and
  conditionally calls `record_osv_diagnostic_match()`). No omission or contradiction found in the
  D5-D8 scope.
- Design quality (`sf-codebase-design`, invoked): D5's placement of `OsvMode` inside `osv::mod`
  and the mode-aware branch kept entirely inside the one `osv::evaluate` wrapper (rather than
  pushed out to the 4 call sites) follows the skill's "push branching into the one seam that
  already has all the state it needs, not out to every caller" guidance, and is grounded directly
  against `src/osv/mod.rs:119-155`'s existing `new`/`spawn_with` split and `src/lib.rs:197-211`'s
  two call sites, both of which I read and confirmed match the document's line citations closely.
  D7's `RequestContext` extension reuses the existing `record_cache`/`AtomicU8` seam exactly
  (`src/http/logging.rs:100-107,126-128,171-193`, read and confirmed) rather than inventing a new
  channel — a minimal, consistent extension of an established interface.
- Testing strategy (`sf-tdd`, invoked): the Test plan rows added for D5-D8 (lines 266-273 of
  `03-program-design.md`) each name a test, the interface exercised (`osv::evaluate`,
  `OsvClient::spawn_with`, `Config::load`, `record_osv_diagnostic_match`), and an independently
  checkable expected result (mode-specific `Decision`, zero-request assertion via
  `counting_server`, `ConfigError::Invalid { key: "osv_mode", .. }`, delivered
  `Decision.reason == OSV_DIAGNOSTIC_REASON` with `result` unchanged). This supports a red-first
  TDD cycle per row; no test-plan line in the D5-D8 scope is missing its interface or assertion.
- Security and performance: D8's non-regression claim was checked directly against
  `docs/plans/osv-intel/evidence/threat-model-3.md` (read in full) rather than taken on faith.
  The threat model's G1 (structural gap in C17's original mechanism), T1 (unrecognized `osv_mode`
  failure mode), and T2 (diagnostic mode has no distinct metric, accepted) all match what D5-D7
  implement, and the threat model's own "Second pass: MODELED" conclusion supports D8's claim
  that nothing new needs modeling. The Red Team disposition for the reopen (document's final two
  paragraphs) correctly states Gate 2's Red Team already reviewed this design (FIX FIRST closed
  by C17c) and that D5-D8 are a concrete pinning of that same design, not a new one.
- Documentation clarity: D5-D8 state exact types, signatures, and control flow (down to which
  branch calls `policy::evaluate` with which `osv_matched` value) needed to implement without
  inventing a decision. Cross-checked against `02-architecture.md`'s C16-C18b (`grep`'d and read)
  and found consistent: architecture's flow steps 3-4 ("off short-circuits... no OSV call at all"
  / "enforce or diagnostic... asks OsvClient::check") match D5's wrapper description exactly.

## Limitations
One cosmetic inaccuracy, not blocking: the "## Files" bullet for `src/config.rs` (line 23) cites
`OPTIONAL_KEYS (line 179-198)`; the array in the current file spans lines 179-191, with lines
193-198 instead being the start of `impl Config`. This is a minor line-range drift (the other
three cited ranges in the same bullet — 142-143, 74-78, 393-399 — are exact), and does not
obscure where the new key belongs or block an implementer, who would grep for `OPTIONAL_KEYS`
regardless. Not raised as a new finding ID since it does not create ambiguity about the design or
require a decision; noted here only for completeness.

No missing evidence. All files named in the round's verification instructions were tracked and
read in full or at the cited ranges: `03-program-design.md`, `01-product.md`, `02-architecture.md`,
`src/config.rs`, `tests/config_validation.rs`, `config.sample.toml`,
`docs/plans/osv-intel/evidence/threat-model-3.md`, `src/osv/mod.rs`, `src/lib.rs`,
`src/http/logging.rs`.

## Next steps
READY: present this Gate for approval. F6 and F7 are confirmed closed against live source, and
the round's re-scan of the full D5-D8 scope surfaced no new blocking or clarification-worthy
issue. The main agent may proceed to the approval step for this reopen.
