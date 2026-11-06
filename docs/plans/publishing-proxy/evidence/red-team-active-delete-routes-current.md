# Red Team: active local publishing design

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=15c4c6221589c7354d487e42ed4527ab8a3af8440d45a6a151f025d83c62db88; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc, `docs/plans/publishing-proxy/04-slices.md`=8c66cd060913b48351869cd548c0945d7ded44b258c48537a55848b068fced23; `docs/plans/publishing-proxy/molecule-flow.json`=cfddafa88ce1efd5d73f3f579c7b9fc62506a81708d68e790253b95d89479a57, `docs/plans/publishing-proxy/molecule-contracts.json`=986bb02471ab6086cd95345bdb027917c14769f86653749c30a5c49b36b5dc7a, `docs/plans/publishing-proxy/specs/npm-delete-routes-classify-before-dispatch.yaml`=8708559028a35ec74bed5a823ca3f69b61ccbc4f31433427676108ca6f1c68d6, `docs/plans/publishing-proxy/evidence/threat-model-active-delete-routes.md`=78fa58ff8acc85a8d1de6c2a619b0f19c45073c0ec789011cd745f00712f8784

## Bottom line

The API-key split and all three DELETE route decisions are explicit and consistent. The model begins version-reference DELETE with a committed removal marker, but no modeled or explicitly witnessed transition proves that only a successful revision PUT creates that marker.

## Findings

- **MAJOR — Coverage / Verifiability / Security — marker creation before version-reference DELETE:** `molecule-flow.json`'s `service-scoped-version-unpublish` begins with `service_removal_marker_committed(service, registry, reference)` as an initial assumption, then models only marker consumption. It has no revision-PUT operation that establishes the committed-marker fact. The active Slice 3 witness requires a marker at DELETE time and covers replay/race behavior, but does not explicitly require that a successful upstream-authorized PUT removing that exact leased version commits the resulting revision before success, or that denied/unchanged PUTs create no marker. As written, the core provenance/authorization rule is prose rather than a modeled or discriminating acceptance obligation. Add an active revision-PUT-to-marker-commit outcome (or an explicitly scoped source/runtime obligation) and a Slice 3 witness for accepted removal, denied PUT, unchanged PUT, exact resulting revision, and commit failure/uncertain partial write. Keep marker requirements exclusive to version-reference DELETE.

## Checked clean

Dependencies: Slice 3 follows the lead local-service foundation and route classification. Risk order: pinned client shape and selected-destination cases precede implementation. Foundations: the route classifier has a matching future-source spec/control, and its absent source is assigned to Slice 1. Sizing: npm writes and unpublish remain one coherent Slice 3. Hard bar: direct canonical tarball DELETE refuses before outbound I/O; whole-package revision DELETE preserves selected-upstream allow/deny without a version marker.

The active design states that the firewall API key authenticates to `GET /api/v1/policy/snapshot` in the HTTP `Authorization` header, while package-manager credentials authorize only selected-upstream operations. The model separates direct canonical tarball DELETE, whole-package revision DELETE, and version-reference DELETE. The route-specific classifier spec/control matches its operation; the original selected-registry classifier contract remains bound to its original spec. The guarded version-reference flow requires both a service-scoped reference and a committed marker before send, and accepted/denied terminals require marker consumption plus selected-registry credential routing.

## Limitations

This is a plan/model review, not source or implementation verification. Five future source obligations remain PENDING; credential bytes, exact destination enforcement, durable marker atomicity, and one-winner concurrency remain Slice 1/3 runtime and source-review obligations. No product tests were run.

## SMTC receipt

- `sha256sum -- <path>` on each subject file: run; hashes recorded above; establishes the reviewed byte identity.
- `smtc file read` for active design, active slices, flow, contracts, route spec, threat model and product: run; outer/inner status `ok`; broad reads of 03, 04, flow, contracts and threat model returned truncated references, so narrowed reads supplied the deciding text. No reference over 4,096 estimated tokens was opened.
- `smtc file grep` for the classifier/spec bindings and marker predicates in the model: run; outer/inner status `ok`; exact matches confirm classifier guard and the committed-marker fact occurs as an initial predicate in the version-reference flow, with no marker-creation operation.
- Evidence tier: Manual for document requirements; Structural for model and contract correspondence. No source code analysis or tests were needed for this design finding.

Omitted deciding evidence: 0.
