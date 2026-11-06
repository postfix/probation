# Red Team: active npm unpublish marker lifecycle

Review kind: red-team  
Verdict: SOUND  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=91bae20dd1f7a60f78684052c43be2ed99eaa882009f3ac4abf90afa368d3b73; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc, `docs/plans/publishing-proxy/04-slices.md`=10d5cd0a8ed7aa52b023e99369dad3d32f3672a6c9fac2971ef4eeb51c38728f; `docs/plans/publishing-proxy/molecule-flow.json`=3d013dc814c577823e59b5138a3c4e894110b8591960b73bbde40a0cc7e6a8ac, `docs/plans/publishing-proxy/molecule-contracts.json`=6d0274fa0db40cd2e0232c7a41666818c0a204cc1b28dec9b3fa37c01322da3c, `specs/npm-delete-routes-classify-before-dispatch.yaml`=8708559028a35ec74bed5a823ca3f69b61ccbc4f31433427676108ca6f1c68d6, `specs/service-removal-marker-after-put.yaml`=c9479a9b32d523d6b2b5478e6daca997aa4098bfaa68bab8481df29e253875b6

## Bottom line

The active design models version unpublish as an accepted upstream revision PUT, exact-version removal verification, revision-bound marker commit, then a DELETE that requires and consumes that marker. Denied, unchanged, or unverified PUTs leave the reference unmarked; marker-commit failure is an uncertain partial write. The two other DELETE routes remain separate and marker-free.

Findings: none.

Checked clean: Coverage—Slice 3 names distinct checks for the three DELETE routes and marker provenance; Dependencies—the service policy/read foundation precedes npm actions; Risk order—the route and upstream outcomes are exercised at the npm action slice; Foundations—the unpublish flow requires a service-scoped reference and starts from an unmarked reference; Verifiability—the flow includes denied, unchanged, unverified, commit-failure, replay and accepted/denied DELETE outcomes; Sizing—these checks fit the single npm publishing/unpublish slice; Hard bar—direct tarball DELETE refuses before outbound I/O while whole-package DELETE preserves selected-upstream allow/deny; Security—the supplied threat model's API-key/registry-credential split and marker lifecycle are reflected in the model and witnesses.

Threat model: MODELED (supplied), `evidence/threat-model-marker-provenance.md`.

Evidence (Structural and Manual tier):

1. `molecule-flow.json`'s `service-scoped-version-unpublish` flow routes only an upstream-accepted revision PUT to `record_successful_service_removal`. That operation requires a revision-PUT request, upstream authorization, a service-scoped reference and an unmarked reference. Only `removed_and_committed` establishes the revision-bound marker and clears the unmarked fact. Denied, unchanged, unverified and marker-commit-failure outcomes do not establish a marker.
2. The same flow calls `consume_service_marker_then_send` only after marker commit. Its operation requires the scoped reference, committed marker and matching revision-bound marker; accepted and upstream-denied DELETE outcomes consume the marker.
3. `npm-direct-and-whole-package-delete` is separate: direct canonical tarball DELETE terminates in local refusal; whole-package revision DELETE uses the selected-registry action and preserves upstream acceptance or denial without a version marker.
4. Active Slice 3 requires denied, unchanged, malformed or unverified revision PUTs to create no marker, uncertain partial-write on marker persistence failure, exact revision binding, one-winner concurrency, direct-route zero outbound calls, and selected-upstream whole-package allow/deny. It also traces the policy key only to the policy snapshot Authorization header and package-manager credentials only to selected-registry requests.
5. `service-removal-marker-after-put.yaml` and its contract check verification-before-commit call order; they explicitly leave exact value binding, persistence, failure recovery and concurrency to the Slice 3 source/runtime witnesses. `router molecule-check` returned PASS for declared-flow consistency.

Limitations: This is a design review. Proposed service source is absent; no product tests or source analysis were run. Exact response/reference/revision binding, credential bytes, durable atomicity and concurrent one-winner behavior remain Slice 1/3 implementation evidence.

Omitted count: 0.

## SMTC receipt

- `file read` of `01-product.md`, `02-architecture.md`, active `03-program-design.md`, active `04-slices.md`, `molecule-flow.json`, `molecule-contracts.json`, both route specs and `threat-model-marker-provenance.md`: run; outer/inner `ok`; Manual/Structural. Broad context-pack reads of 03, 04, model, contracts and threat model were truncated; deciding ranges were reread narrowly. No oversized reference (>4,096 estimated tokens) was opened.
- `file read` of active Slice 1–5 rows and decisive 03 interface/marker sections, plus the version-unpublish flow and marker operation: run; outer/inner `ok`; complete narrowed ranges, Manual/Structural.
- `file grep` on flow operations, marker predicates and source-contract IDs: run; outer/inner `ok`; Structural; bounded matches, no truncation on the decisive model query.
- `ref show` of the narrowed product and version-unpublish flow references: run; outer/inner `ok`; complete, token estimates below 4,096; Manual/Structural.
- `router molecule-check --plan-root docs/plans/publishing-proxy`: run; PASS; finite declared-contract consistency only, not source behavior.
- No SMTC source symbol analysis or product tests were relevant to the proposed-source design claim.
