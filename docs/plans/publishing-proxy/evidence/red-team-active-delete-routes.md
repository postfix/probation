# Red Team: active local publishing design

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design docs/plans/publishing-proxy/03-program-design.md=45baea29fc172a7450d8d7d1537d2a9c55185aaf7e9e97eb5095cd1f766ae5f6; upstream docs/plans/publishing-proxy/01-product.md=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, docs/plans/publishing-proxy/02-architecture.md=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc, docs/plans/publishing-proxy/04-slices.md=8c66cd060913b48351869cd548c0945d7ded44b258c48537a55848b068fced23; docs/plans/publishing-proxy/molecule-flow.json=167ca82aac9de5e93eaca3b0c369693e8ee2122875b749704d249c94798b3bcf, docs/plans/publishing-proxy/molecule-contracts.json=0f6ebff75a1cd92c8b893dc4c4534f09f96007e4ef3f0fb10c5be0a4efb1516f

Bottom line: The active design and Slice 3 witness now distinguish all three npm DELETE routes and preserve the policy-key/registry-credential split. The new route flow still permits a successful version-reference DELETE without requiring a previously committed removal marker, so its finite model does not enforce the central authorization condition.

Findings:

- **BLOCKER — Security / verifiability — `molecule-flow.json` around `consume_service_marker_then_send` and `npm-delete-route-authority`:** The operation declares `"requires": []` (around line 655). The new route flow starts with selected registry, loaded policy, local allow, and action route only; its version-reference branch then invokes that operation. The operation's accepted outcome itself establishes `service_delete_marker_consumed`, while the flow has no prior `service_removal_marker_committed` or service-scoped reference precondition on that branch (around lines 1385–1455). The separate `service-scoped-version-unpublish` flow does have those initial predicates, but the new three-route flow does not compose with it. As modeled, the version-reference branch can report an accepted outbound DELETE without the successful revision PUT/marker prerequisite described by the active design. Add route-specific preconditions to the version-reference branch or route it through the existing guarded flow; preserve the distinction so whole-package and direct-tarball paths do not inherit version-marker requirements.

Checked clean: Coverage—active caller contract, model outcomes, and Slice 3 witness cover whole-package upstream allow/deny without a marker, direct canonical tarball zero-outbound refusal, and version-reference deletion; Dependencies—Slice 3 follows local service and route classification prerequisites; Risk order—pinned client shape and destination cases precede implementation; Foundations—the service API key is confined to the policy snapshot `Authorization` header and package-manager credentials go only to selected upstream operations; Sizing—Slice 3 is a coherent npm publishing increment; Hard bar—every route has a separate observable witness.

Threat model: MODELED (supplied), `evidence/threat-model-active-delete-routes.md`.

Limitations: This review covers the proposed design and finite model, not implementation. The four future-source obligations remain PENDING; runtime credential bytes, selected destination enforcement, marker persistence/atomicity, and concurrent one-winner behavior still require the named Slice 1/3 witnesses and source review.

SMTC receipt:

- `file read` 03 active design and 04 active slice rows: run; outer/inner status `ok`; Manual; complete relevant ranges, with full 03 read truncated and narrowed reads used instead.
- `file read` active threat model and molecule flow operations/route flow: run; outer/inner status `ok`; Manual/Structural; narrowed, complete relevant ranges.
- `file grep` molecule operation/flow names: run; outer/inner status `ok`; Structural; four matches, no truncation.
- `file read` `02-architecture.md` and `01-product.md`: run; outer/inner status `ok`; initial ranges truncated, and these did not decide the finding.
- Omitted deciding evidence: 0. No code symbol analysis or tests were needed for this proposed-design finding.
