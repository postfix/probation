# Design QA
## Verdict
READY

## Overall assessment
The only change since the previous READY is bookkeeping: clarification rows C1003 and C1018 in 02-architecture.md, 03-program-design.md and 04-slices.md moved from `deferred | 1 | 2` to `resolved | 1 | none` with an appended RESOLVED note. The resolutions are supported by the design, no deferred or open inventory row remains, and no blocking finding exists. `router check` findings are empty, `molecule-check` returns PASS, and source verification is PENDING only for the not-yet-existing guard files (src/managed/publication_gate.rs, src/managed/order_guards.rs, crates/probation-server/src/order_guards.rs), delivered by rows 16 and 28. No user question is open.

## Questions and findings
None. DQ-1 to DQ-15 remain resolved as recorded in the previous sealed report; this round raised no new finding.

## What was checked
- Change scope: the previous sealed subject was compared by hash with current bytes. Only 02-architecture.md, 03-program-design.md and 04-slices.md differ; 01-product.md, molecule-flow.json, molecule-contracts.json, the three service-policy specs, gate-1-qa.md and the relied-on evidence files are unchanged. Preparation's source-verification set is the same pending obligations as before.
- Clarifications: all inventory rows in 02, 03 and 04 are now `resolved` (C1003, C1018, C1019 to C1029); none is deferred or open. 01-product.md still lists C1003 and C1018 as `deferred | 1 | 2` because approved Gate 1 is unchanged; this is the correct incoming-deferral form (current-Gate decision, owner 1, target 2), and the design inventories carry the same IDs as resolved. Both are technical selections within approved scope, authored for this design with recorded rationale.
- C1003 support: 03-program-design.md specifies GET /api/v1/policy/snapshot with the organisation service key, the rejection statuses, the registry model and the full-snapshot choice; no package-request login and durable refusal are in the shared-service API; standalone TOML is retained; delivery is rows 16 and 28 in 04-slices.md.
- C1018 support: 03-program-design.md defines ordinary native Ubuntu, macOS and Windows jobs, Desktop and cluster lanes with fail-on-missing-runner, and the platform lifecycle test row that rejects build-only evidence; 04-slices.md maps them to rows 29 (early spike), 25 (lifecycle), 26 (cluster) and 27 (acceptance), each after its prerequisites.
- Combined-design categories (sf-codebase-design and sf-tdd lenses, security coverage, slice order, test plan) are unchanged from the previous READY and were not reopened; the changed rows alter no contract, test or slice.
- Model and source: `molecule-check` PASS; `molecule-verify` not run because proposed source is absent.

## Limitations
- No builds or tests were run. Source controls cannot be shown to trigger until the guard files exist (rows 16 and 28).
- Native OS and cluster behavior is design-level; row 29 is the planned spike.
- Previous-version bytes of the three changed documents are not retained, so "only the two rows changed" rests on the author's statement plus unchanged hashes of every other input and a re-read of the changed rows; the previous review's non-blocking note (03 dispositions intro wording) still stands.

## Next steps
Main agent: run `router gate-qa verify`, then present the combined design for approval.
