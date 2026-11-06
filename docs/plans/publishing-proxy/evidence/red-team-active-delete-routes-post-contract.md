# Red Team: active DELETE route design after source-contract addition

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=298bcc00b8dc20ca57824c022e22d318865507026d7ba19c08b58592b4026a4a; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc, `docs/plans/publishing-proxy/04-slices.md`=8c66cd060913b48351869cd548c0945d7ded44b258c48537a55848b068fced23, `docs/plans/publishing-proxy/molecule-flow.json`=cfddafa88ce1efd5d73f3f579c7b9fc62506a81708d68e790253b95d89479a57, `docs/plans/publishing-proxy/molecule-contracts.json`=b374a354d6291acdf1dc625050c283bab244c21621c3ff7da8d69f73a12ca34a; security input `docs/plans/publishing-proxy/evidence/threat-model-active-delete-routes.md`=78fa58ff8acc85a8d1de6c2a619b0f19c45073c0ec789011cd745f00712f8784

## Bottom line

The active design correctly separates the firewall API key in the policy snapshot HTTP Authorization header from package-manager credentials sent to registry operations. The three npm DELETE paths are distinct in the flow and Slice 3 witness, and the version-reference path requires both a service-scoped reference and a committed revision marker.

One source-contract mapping is inaccurate: the new route-classification operation is bound to a spec and unsafe mutation for a different classifier. That future obligation could pass without checking the direct/whole-package DELETE classifier it claims to cover.

## Findings

- **MAJOR — Verifiability — `molecule-contracts.json` contract `classify-npm-delete-routes`:** It binds `classify_direct_or_whole_package_delete` to `service-route-classify-before-dispatch.yaml`, whose guard only calls `classify_selected_registry` before `dispatch_selected_registry`; its unsafe mutation only replaces `classify_selected_registry` with `unchecked_selected_registry`. The contract control therefore does not exercise the new DELETE-route classifier or its direct-refusal/whole-package-dispatch branches. A future source review may report a passing unrelated guard while the DELETE classifier is missing or bypassed. Add a route-specific spec/control that targets this operation and the relevant dispatch, or make the source obligation accurately state that no analyzer proof is claimed and rely on the named Slice 3 runtime witness for route-specific behavior.

## Checked clean

Coverage: Active 03 caller contracts and the Slice 3 direct witness distinguish whole-package upstream allow/deny without a version marker, direct canonical tarball zero-outbound refusal, and version-reference marker-gated deletion. Dependencies: Slice 3 follows the lead Slice 1 service foundation and Slice 2 classification. Risk order: selected-registry and current-policy foundation precede writes. Foundations: the service API key is reserved for policy snapshot retrieval; package-manager credentials go to selected registry actions, with D41's explicit destination scope for version-reference sends. Hard bar: the named direct witness checks zero outbound calls with a valid developer credential. Security: the active threat model covers credential noninterference, routing and all three DELETE routes.

## Limitations

The proposed service route sources do not exist. This review found a design-time spec/control mapping issue; it did not inspect implementation source or run product tests. Route completeness, credential destinations, upstream decisions, marker durability and concurrency remain Slice 1/3 runtime and source-review obligations.

## SMTC receipt

- `file read` on full 01–04 docs, flow, contracts and threat model: run; outer/inner `ok`; broad outputs truncated (token estimates >4,096); deciding refs were not opened.
- `file read` on 04 active rows, version-reference flow (lines 1243–1362), direct/whole flow (1364–1495), contract (180–213), threat model (13–29), and active program-design ranges (1–60, 92–120): run; outer/inner `ok`; complete deciding ranges, Manual/Structural.
- `file read` on `specs/service-route-classify-before-dispatch.yaml`: run; outer/inner `ok`; complete 10-line spec, Manual. It checks only `classify_selected_registry` dominating `dispatch_selected_registry`.
- `file grep` for the flow/operation IDs, contract ID, credential boundary and three route terms: run; outer/inner `ok`; bounded matches, used to locate deciding ranges only.
- Native source analysis and tests: irrelevant to the missing future source and proposed-design claim.

Omitted deciding evidence: 0. No ref over 4,096 estimated tokens was opened.
