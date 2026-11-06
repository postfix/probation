Review kind: code-review
Verdict: SHIP
Question: Does the verifier compatibility/archive repair, including selected-caller graph completeness, preserve the encoded intraprocedural order obligations?
Reviewing: supplied tooling.diff against installed verifier SHA256 944e8b6b9539f92f7ec691744242ab0f36c7444f7c563f127b3ffae998a45fc8; final tooling source, focused tests and test support. Unrelated Factory working-tree changes are excluded.

The scoped graph-completeness correction is accepted. The approved contracts expressly promise selected call order, with route/value binding and concurrency assigned to separate runtime/source witnesses. Requiring zero unresolved dispatches across unrelated functions exceeds that promise. The replacement requires a complete independent operation inventory, unique selected owner/span binding, successful dominance analysis, and detecting unsafe controls. It records the unrelated count rather than presenting a whole-program completeness claim.

Defects: none open on final bytes.

Conventions (software-factory/AGENTS.md): none in the reviewed changes. CLAUDE.md, CONTRIBUTING*, CODING_STANDARDS*, and docs/codebase-overview.md were not found by the prescribed searches. Installation/drift checks remain the delivering agent's responsibility; this read-only review does not certify an installed release.

Simplifications: none evidenced or recommended. The restricted import resolver is needed to include the real declaration in the hashed archive; it does not attempt general Rust name resolution.

Evidence:

1. Compatibility retains the exact supported `caller_function == 'owner'` filter, rejects a filter excluding the declared owner, and explicitly normalizes omitted `allow_caller_paths` to false. It does not remove the guard, operation, or dominance requirement. The six existing-source contract specs were inspected, and their hashes and sidecar hash remained unchanged. Tier: Structural.
2. Declaration/module closure is captured and hashed, including src/managed/service_policy.rs and crate roots. Structural cross-file edges require an explicit unique crate import, the selected caller identity, and a unique direct top-level target declaration. Alias/glob/duplicate/shadowed/spoofed imports, attributed or nested targets/modules/imports, inner attributes, and selected-owner macros remain unsupported. Review found conditional-binding and closure-race defects in intermediate bytes; bounded RED/GREEN controls confirmed the corrections. Tier: Structural, with focused executable controls.
3. Selected inventory attribution excludes only byte spans and whole inventory lines disjoint from the resolved declaration. Shared-line ambiguity, missing selected edges, receiver calls masquerading as bare free functions, crossing spans, invalid locations, conflicting identities, parse/drop errors, partial reports and missing inventory stay UNKNOWN. `selectedUnresolved: 0` is written only after attribution succeeds. Tier: Structural.
4. Every captured file is rechecked after analyzer commands and against the live source at completion. The live import/module closure is re-resolved to catch added alternate module paths, which a hash-only check missed. The race control changed from incorrect PASS to UNKNOWN/SOURCE_CHANGED. Unsafe controls must still detect an unchanged production operation through byte-origin mapping. Tier: Structural, with executable controls.
5. Final regression reports `molecule source contracts: PASS`; typecheck completed successfully. The actual plan model is PASS; source results contain six PASS checks with six detecting controls, zero UNKNOWN/FAIL, and three future Slice 3 SOURCE_PENDING checks. Each production attribution records one selected operation, selectedUnresolved 0 and globalUnresolved [152]. Overall source verdict is PENDING because those future files are absent. Tier: Structural; no whole-program or arbitrary functional-correctness proof is claimed.

Final subject fingerprints (SHA256):

| Subject | Hash |
|---|---|
| scripts/molecule-source.mjs | 487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea |
| scripts/molecule-source.test.mjs | d09d8528ca6506f9303983c534a5276ea4e8ad5b3ae3557130286bad2eb03a5d |
| scripts/molecule-source.test-support.mjs | a13246adca8fefdc4c81e6f0926d81f68a867861f8bdf0fdd3581760ef0ee2dd |
| .scratch/verifier-repair/tooling.diff | ca4647314380dd520dc14bd8e6ecf1cb01633a368b3d08aae4f82b9dc90d2b0d |
| .scratch/verifier-repair/final-regression.log | fc8e1319ad23165195d85c03802995097cdcd456f68c014316d3ae7505da2b1c |
| .scratch/verifier-repair/final-typecheck.log | 8fa1cf5506304e8abac55868e7f1a136c9b1dde57a3981a382da4c21ea129a6f |
| .scratch/verifier-repair/final-model.json | becad19e99af66fb300bdbc1dc1d1998a5848ac2a8f9790892d7922ab5b05b7f |
| .scratch/verifier-repair/final-source.json | c2280615b432003e93ec79650110edac88caf32df6cfa102f42c7f90fb04eb65 |

Controls inspected: .scratch/verifier-repair/review-controls-red.log and review-controls-green.log (conditional targets/modules and alternate-module race); owner-scope-red.log and owner-scope-green.log (unrelated same-name receiver outside the selected owner). The final regression additionally covers conditional/inner-attribute imports and targets, selected macros, unrelated dispatch counts, missing selected edges, selected receivers and dropped statements. These controls cross the public verifier seam with the installed analyzer; unit doubles separately exercise malformed envelopes. The final .scratch/verifier-repair/repair-receipt.json binds these bytes and records four explicit tdd RED/GREEN lines for caller scope, archive closure, selected attribution and import closure.

The final immutable source proof is .scratch/state/software-factory/contract-evidence/repo-cc718bf594b6832a/run-tsDHc6. Its bindings.json and attribution.json files were inspected as execution evidence; source discovery and declaration inspection used SMTC.

SMTC receipt:

Repository root R=/home/john/go/src/github.com/agenthands/software-factory; product root P=/home/john/go/src/github.com/postfix/probation; session S=sf-verifier-review-2026-11-03. In the exact argv templates below, expand R/P/S literally. Every question-specific command ends with `--format json --max-tokens 2048 --session-id S`. No shell pipelines or wrappers were used for SMTC commands.

| Operation and argv (before common suffix) | Status and interpretation |
|---|---|
| `smtc file find --root R --pattern <pattern> --max-results 20`, independently for AGENTS.md, CLAUDE.md, CONTRIBUTING*, CODING_STANDARDS*, docs/codebase-overview.md | run; outer ok true, no inner refusal; complete, no refs. AGENTS.md found and read; other four absent. Text evidence only; functions not reported. |
| `smtc file read --root R --path AGENTS.md` | run; ok true, complete, unclamped, no refs/diagnostics. Standards input. |
| `smtc search symbol --root R --name-pattern <name> --limit 6`, independently for operationSpec, topLevelItem, rustImportFiles, exactRustImport, validateGraph, attributeSites | run; ok true, complete, no refs/diagnostics. Exact reviewed file distinguished from other validateGraph declarations; no identity guessing. Functions resolved, not a semantic safety proof. |
| `smtc inspect symbol --root R --handle R/scripts/molecule-source.mjs:<start>:<end>`, independently for 493:504, 505:513, 515:584, 585:601, 622:625, 626:675 | run on final source hash; ok true; complete bodies, no refs/diagnostics/truncation. Structural declaration identity plus Manual body inspection; analyzer function-count metric not supplied. |
| `smtc file read --root R --path scripts/molecule-source.mjs --start-line <a> --end-line <b>` | run for changed units and neighbors: Rust masking/IIFE, report validation, subject/span binding, attribution, byte-origin control matching, report assessment, capture, analyzer execution and final revalidation. Final small reads complete/unclamped, no refs. An earlier 560:700 read returned ref-79/truncation and was replaced with narrow complete reads; it was not used as a clean negative. |
| `smtc file read --root R --path scripts/molecule-source.test.mjs --start-line <a> --end-line <b>` and `smtc file read --root R --path scripts/molecule-source.test-support.mjs --start-line 1 --end-line 80` | run; focused controls and malformed-envelope modes inspected; complete bounded reads. Text evidence; executable results are the retained logs above. |
| `smtc file read --root P --path <spec>` | run for the six existing-source specs named by the passing final checks. ok true, complete/unclamped; each encodes call-order dominance, no wider dynamic-value proof. Sidecar read in bounded segments; final overlarge end was clamped to EOF, used only as declaration text. |
| `smtc file find --root P --pattern 'docs/plans/publishing-proxy/specs/*.yaml' --max-results 20` | run; ok true but truncated at 20; not used to assert complete spec inventory. Exact contract paths supplied the deciding reads. |
| `smtc review impact --root R --file scripts/molecule-source.mjs --start-line 492 --end-line 587` | run during intermediate edits; outer ok false, analysis_failed: workspace sources changed/could not be acquired; no graph verdict obtained. This leg did not support SHIP. Final direct bounded declarations, callers' verifier execution and tests settle the scoped review; no global blast-radius or deletion recommendation is made. |

No unsupported-language or host-refusal fallback was used. Broader dependency, deletion, placement, and interface simplification checks were irrelevant because no cut/replacement was recommended and the public verifier interface is unchanged. Native Git/diff/fingerprints, supplied execution logs, and the focused reproducer are separately identified evidence, not substitutes for SMTC source inspection.

Unchanged during review: yes for the final sealed window at source SHA487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea; before/after Git path lists, all three tooling hashes, standards hash, supplied diff hash, sidecar and six relevant spec hashes matched. Earlier intermediate windows were explicitly superseded after coordinated corrections.
Reviewed: molecule-source.mjs repair units and risk-bearing neighbors listed in the receipt; molecule-source.test.mjs focused behavioral controls; molecule-source.test-support.mjs added envelope modes; approved sidecar and six existing-source specs. Deleted: none.
Checked clean: correctness/totality/boundaries/types/numeric behavior; errors/rollback/partial failure; ownership/cleanup/cancellation/lifecycle; shared state/ordering/races/deadlocks/termination within this synchronous verifier scope; preconditions/postconditions/invariants/compatibility/side effects; input-driven bounds/obvious implementation security defects; credible maintainability defects; behavioral tests; approved-scope creep; conventions; simplifications.
Omitted: defects 0, conventions 0, simplifications 0; repeated successful receipts are consolidated above.
Limitations: bounded Structural source-order assurance; global unresolved count 152 is disclosed, not proven away. General Rust expansion/name resolution and arbitrary functional correctness remain outside scope. No independent heavy suite, release matrix, installation/drift, native-host conformance, or product runtime/security rerun was performed by this reviewer.
