# Red Team: active npm DELETE route model cleanup

Review kind: red-team  
Verdict: SOUND  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=cd86e2a736e1ef8615c6c4f7c4f29875e3b7ebb3f5171557096629b9ca4c9c6e; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc; slices `docs/plans/publishing-proxy/04-slices.md`=8c66cd060913b48351869cd548c0945d7ded44b258c48537a55848b068fced23; model `docs/plans/publishing-proxy/molecule-flow.json`=cfddafa88ce1efd5d73f3f579c7b9fc62506a81708d68e790253b95d89479a57; contracts `docs/plans/publishing-proxy/molecule-contracts.json`=0f6ebff75a1cd92c8b893dc4c4534f09f96007e4ef3f0fb10c5be0a4efb1516f; threat model `docs/plans/publishing-proxy/evidence/threat-model-active-delete-routes.md`=78fa58ff8acc85a8d1de6c2a619b0f19c45073c0ec789011cd745f00712f8784

## Bottom line

The prior cleanup is complete. The active model separates the two direct/whole-package routes from the guarded service-scoped version-reference flow, and the threat report names the current flow. Slice 3 specifies a distinct witness for each DELETE path.

## Findings

None.

## Checked clean

Coverage: all three DELETE paths map to distinct model outcomes and Slice 3 witnesses. Dependencies: package publishing follows service and route-classification prerequisites; the marker flow is scoped to version-reference deletion. Risk order: selected destination, upstream decision and zero-I/O refusal are explicit before implementation. Foundations: the service API key is confined to policy snapshot HTTP `Authorization`; package-manager credentials authorize only the selected upstream. Verifiability: whole-package allow/deny, direct canonical tarball zero-outbound refusal, and reference-marker consumption/replay each have observable outcomes. Sizing: these checks fit the existing npm publishing slice. Hard bar: no local marker authorizes whole-package DELETE and no direct canonical tarball DELETE bypasses the marker flow. Security: the threat model covers credential noninterference, route confusion, destination validation, reference binding and replay.

Threat model: MODELED (supplied), `evidence/threat-model-active-delete-routes.md`.

## Limitations

This is a plan/model review. The new route source files do not exist. Runtime credential destination, exact route dispatch, marker durability/atomicity and concurrent one-winner behavior remain Slice 1/3 proof obligations; no product tests or source review were run.

## SMTC receipt

- `file read` active program design, slices, flow model and threat model: run; outer and inner status `ok`; Manual/Structural. Initial broad reads were truncated; narrowed complete ranges supplied deciding evidence. The 03/model broad reads exceeded 4,096 tokens and their refs were not opened.
- `file grep` flow IDs, DELETE route contracts, and marker terms: run; outer and inner status `ok`; Structural. A narrowed read resolved the flow structure and showed the version-reference flow starts with both service-scoped reference and committed-marker predicates.
- `molecule-check` was not run in this review; no implementation or product tests were run. The reviewed plan already records a PASS for the revised finite model.
- Omitted deciding evidence: 0.
