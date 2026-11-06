# Red Team: active npm DELETE route model verification

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=cd86e2a736e1ef8615c6c4f7c4f29875e3b7ebb3f5171557096629b9ca4c9c6e; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc; `docs/plans/publishing-proxy/04-slices.md`=8c66cd060913b48351869cd548c0945d7ded44b258c48537a55848b068fced23; `docs/plans/publishing-proxy/molecule-flow.json`=b383c000894963828d0f0d4a4833529bc974adb5aea88b34b0251293e5178e19; `docs/plans/publishing-proxy/molecule-contracts.json`=0f6ebff75a1cd92c8b893dc4c4534f09f96007e4ef3f0fb10c5be0a4efb1516f

## Bottom line

The security blocker from the prior review is resolved: version-reference DELETE is modeled in a separate flow that requires the service-scoped reference and committed revision marker before the DELETE operation. Whole-package DELETE preserves selected-upstream allow/deny without a version marker, and direct canonical tarball DELETE refuses before outbound I/O. One minor evidence cleanup remains before signoff.

## Findings

- **MINOR — Coverage / `molecule-flow.json` and `evidence/threat-model-active-delete-routes.md`:** The active model now names the whole-package/direct flow `npm-direct-and-whole-package-delete`, but the fresh threat report still cites the superseded name `npm-delete-route-authority`. The new flow also retains unused `service`/`reference` values and three unreachable version-reference refusal terminals. This does not restore the previously identified unguarded send path, but it makes the security evidence point at a flow that no longer exists and obscures which flow owns version-reference refusals. Update the threat report's flow reference and remove the unused values/terminals (the separate `service-scoped-version-unpublish` flow already owns those outcomes).

## Checked clean

Dependencies, Risk order, Foundations, Verifiability, Sizing, Hard bar, and Security: Slice 3 is ordered after selected-route classification and its witness distinguishes all three DELETE outcomes; future route source remains explicitly absent. The package API key is confined to policy snapshot HTTP Authorization, while package-manager credentials go to the selected upstream. The existing version-reference flow starts with `service_scoped_reference(service, registry, reference)` and `service_removal_marker_committed(service, registry, reference)`; accepted and upstream-denied terminals require marker consumption and selected-registry credential routing. Whole-package success/denial requires the selected-registry credential, and direct canonical tarball deletion has a local refusal terminal. Runtime credential routing, route completeness, and marker atomicity/concurrency remain slice obligations.

Threat model: MODELED (supplied), `evidence/threat-model-active-delete-routes.md`.

Limitations: This review covers plan text and the finite model only. It did not inspect proposed source or run product tests.

## SMTC receipt

- `file read` on the active design, Slice 3 plan, finite model, threat model, source evidence, product/architecture and lead FIX-16-A documents: run; outer/inner `ok`; Manual/Structural. Broad reads of the large design/model returned truncated references; deciding passages were read with narrow complete ranges. References over 4,096 tokens were not opened.
- `file grep` on the model, active design/slices, and threat report: run; outer/inner `ok`; Structural. The narrow matches confirmed the model's current flow names, Slice 3 three-route witness, and the stale flow-name reference in the threat report.
- No source-code analysis or tests were needed for this proposed-design review. Omitted deciding evidence: 0.
