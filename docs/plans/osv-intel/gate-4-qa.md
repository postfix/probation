# Gate 4 QA
## Verdict
READY

## Overall assessment
This is a fresh review of the reopened Gate 4, scoped to Slice 4's summary-table row
(`04-slices.md` line 14) and its "### Slice 4 interfaces" subsection (lines 56-68), plus how
Slice 4 fits the document's required structure and cross-slice consistency. Slices 1-3 are
unaffected, already complete (`done: true` in router state with recorded proof), and were not
re-reviewed.

The two REVISE findings from the prior review round are both corrected in the current document:

- F1 (previously: `tests/decision_log_delivery.rs` missing from Slice 4's "Exact files") — the
  column now reads `src/osv/mod.rs, src/config.rs, src/lib.rs, src/http/logging.rs,
  tests/config_validation.rs, tests/decision_log_delivery.rs, config.sample.toml,
  docs/operations.md` (line 14). `tests/decision_log_delivery.rs` is present.
- F2 (previously: "security" missing from Slice 4's Reviews column) — the column now reads
  "qa, code-review, security" (line 14), matching Slice 1's Reviews list for the same file
  (`src/osv/mod.rs`).

Beyond re-verifying F1/F2, I independently re-derived Slice 4's claims against current source
rather than trusting the document or the prior report: `OsvMode`, `osv_mode`, and
`record_osv_diagnostic_match` are all genuinely absent today from `src/osv/mod.rs`,
`src/config.rs`, `config.sample.toml`, `tests/config_validation.rs`, `tests/decision_log_delivery.rs`,
and `docs/operations.md` — the Direct witness commands will fail today exactly as claimed and
will only pass once the promised behavior exists. I also independently confirmed the 6 named
existing `OsvClient` constructor/struct-literal test sites in `src/osv/mod.rs` (lines 276-281,
421-426, 464, 502, 531, 568) and both `App::start` match arms in `src/lib.rs` (196-209) match the
line numbers and call shapes the slice and `03-program-design.md`'s D5 claim, and that
`http::logging`'s `RequestContext`/`record_cache`/`decide()` shapes (lines 100-107, 126-128,
190-193) match D7's grounding exactly. `docs/operations.md`'s `## 4. The blocklist` section
(line 199) exists as the slice's Changes text names. No Gate 3 invariant in
`## Invariants & spec dispositions` is worded `deferred to slice 4` (all five deferrals from the
original Gate 3 pass resolve to `deferred to slice 1`, already witnessed and closed in Slice 1's
row), so the mandatory `sf-verify-cert verdict` witness rule for such deferrals does not apply
here — no finding.

No new defects found in this round.

## Questions and findings
None.

## What was checked
- **Completeness (review question 1):** Every clarification C16-C18b from `02-architecture.md`
  (operator-configurable mode, log field shape, diagnostic-reason mechanism, hard-fail
  validation) maps to a resolved D5-D8 decision in `03-program-design.md`, and each is covered by
  a named test in Slice 4's Acceptance list, cross-checked against the Test plan table (lines
  266-273) — all 8 test names present, none invented. `evidence/threat-model-3.md`'s three
  resolutions (G1 -> C17b, T1 -> C18b, T2 -> accepted/documented) are each represented: G1/T1 by
  the D7 logging seam and D6 hard-fail validation, T2 by the `docs/operations.md` bullet the
  slice's Changes text commits to. F1 is closed: `tests/decision_log_delivery.rs` is now listed.
  No other approved requirement, test, mitigation, or deferred invariant check was found missing
  from Slice 4's scope, and no unrelated scope creep was found in its Changes/Acceptance text.
  Result: pass.
- **Sequence and dependencies (review question 2):** Slice 4 depends only on `osv::evaluate`/
  `OsvClient` (Slices 1-2, both `done: true` with recorded proof in router state) and on
  `http::logging`'s existing `RequestContext`/`record_cache` seam, confirmed present in current
  source. It is purely additive — no earlier slice's behavior changes when `osv_mode` is absent
  (explicitly stated and consistent with the default-`Enforce` design). No missing prerequisite,
  no reordering issue. Result: pass.
- **Verification (review question 3):** Direct witness names exact commands (`cargo test --lib
  osv:: config:: http::logging::`, `cargo test --test config_validation`, `cargo test --test
  decision_log_delivery`) with an expected result ("all PASS") and a concrete reason the check
  fails today ("`OsvMode` does not exist, `osv_mode` is not a config key,
  `record_osv_diagnostic_match` does not exist"). I independently grepped all three absences
  against current source and confirmed each is genuinely missing — the witness is a real,
  currently-failing check that only the promised runtime behavior can satisfy. Result: pass.
- **Security and performance (review question 4):** `osv_mode`'s design was threat-modeled twice
  at Gate 2 (`evidence/threat-model-3.md`, MODELED, G1/T1/T2 all closed) and Gate 3's D8
  confirmed no new entry point, trust boundary, or asset. Slice 4's Reviews column now includes
  "security" (F2 closed), scheduling the source-level `sf-security-review` that
  `03-program-design.md`'s Threat model section explicitly calls for once `osv/mod.rs` gains the
  new mode-branch logic — this is exactly the right point to catch a bypass bug (e.g., `Off`/
  `Diagnostic` reachable without explicit config, or a diagnostic match leaking into `result`).
  Temporary artifacts are explicitly "none," and the default (`Enforce`) is confirmed to match
  today's behavior in current source (no `osv_mode` key exists in `config.sample.toml` or
  `config.rs` yet, so every existing deployment/test is unaffected until the key is set). Result:
  pass.
- **Implementation readiness (review question 5):** D5-D8 pin concrete Rust types, field names,
  function signatures, and exact match-arm bodies with no open product or architecture choice
  left to the implementing engineer. `## Clarifications and decisions` in `04-slices.md` records
  no incoming deferral or unresolved choice ("None — checked for incoming deferrals and
  unresolved choices"), consistent with D5-D8 all being `resolved` in `03-program-design.md`.
  Cross-checked D5's claimed `OsvClient::new`/`spawn_with` signatures and both `src/lib.rs` call
  sites against current source — match exactly. The slice is scoped to one coherent outcome (the
  `osv_mode` switch) across a bounded, accurately-enumerated file set. No hidden dependency or
  overlapping ownership found. Result: pass.
- **Red Team requirement (Gate QA protocol step 5):** Slice 4 states "sf-red-team: not
  triggered," justified by Gate 2's completed Red Team pass (FIX FIRST, closed by C17c) already
  covering this exact design, and Gate 3's D8 non-regression check confirming no new
  architecture. This is an adequate, evidenced reason rather than a bare assertion. Result: no
  finding.

## Limitations
Review was scoped, per dispatch instructions, to Slice 4's row and its interfaces section, plus
overall document structure/cross-slice consistency; Slices 1-3 were treated as already-approved
and complete (confirmed `done: true` with recorded proof in router state) and were not
re-reviewed. `evidence/threat-model-3.md`'s own stated limitation ("does not independently
re-derive the trust boundary") was accepted as-is, consistent with Gate 3's D8 non-regression
finding; this review did not re-run threat modeling.

## Next steps
Gate 4 is ready for presentation with Slice 4 included. The main agent should present this Gate
for user approval; implementation of Slice 4 begins only after that approval.
