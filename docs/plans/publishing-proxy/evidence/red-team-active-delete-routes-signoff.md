# Red Team: npm DELETE route classifier contract

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=18881953a1c27c99d07f18b4624f0f5c275e0fcafbd7746064509e8bee09e2a6; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc; slices `docs/plans/publishing-proxy/04-slices.md`=8c66cd060913b48351869cd548c0945d7ded44b258c48537a55848b068fced23; model `docs/plans/publishing-proxy/molecule-flow.json`=cfddafa88ce1efd5d73f3f579c7b9fc62506a81708d68e790253b95d89479a57; contracts `docs/plans/publishing-proxy/molecule-contracts.json`=986bb02471ab6086cd95345bdb027917c14769f86653749c30a5c49b36b5dc7a; spec `docs/plans/publishing-proxy/specs/npm-delete-routes-classify-before-dispatch.yaml`=8708559028a35ec74bed5a823ca3f69b61ccbc4f31433427676108ca6f1c68d6

## Bottom line

The new route-classifier obligation now targets the right operation and a matching route-specific spec/control. The active design's Red Team link still points to an earlier report whose subject predates this model/contract update, so the approval record does not yet point to a review of these exact bytes.

## Findings

- **MINOR — Verifiability / `03-program-design.md` Repository evidence:** It links `evidence/red-team-active-delete-routes-final.md`, whose subject hash for `molecule-contracts.json` is the earlier `0f6ebff…`, while the current contract file is `986bb024…`. That earlier review could not verify `classify-npm-delete-routes` or its new route-specific spec/control. Point the durable review record outside the hashed design to this report (for example, the Gate 4 progress result), and remove the stale in-design report link to avoid making the reviewed design hash self-referential.

## Checked clean

Coverage: Slice 3 separately witnesses whole-package allow/deny, direct canonical tarball zero-I/O refusal, and marker-gated version-reference deletion. Dependencies: route classification is assigned to the shared service entry in Slice 1, while route outcomes are exercised in Slice 3. Risk order: policy and selected-registry foundations precede writes. Foundations: the API key is confined to policy snapshot HTTP `Authorization`; package-manager credentials go only to selected upstream operations. Verifiability: the new spec checks classifier-before-dispatch order only, with route semantics and zero-I/O refusal left to Slice 3; its unsafe mutation names the same classifier and dispatch call. Sizing: the three route witnesses fit the npm publishing slice. Hard bar: whole-package DELETE uses no version marker, direct tarball DELETE sends no request, and version-reference DELETE requires both service scope and the committed marker. Security: the active MODELED threat review addresses all three routes; future credential destination and marker guarantees remain runtime work.

Threat model: MODELED (supplied), `evidence/threat-model-active-delete-routes.md`.

## Limitations

This review is based on active plan and model text. It did not inspect source or run product tests; future source is absent, so the new obligation remains pending. Exact credential routing, route completeness, marker durability/atomicity and concurrent one-winner behavior remain Slice 1/3 proof obligations.

## SMTC receipt

- `file read` on active 03, 04, molecule flow/contracts, route specs, threat model, prior Red Team report, 01 and 02: run; outer and inner status `ok`; Manual/Structural. Broad reads of 03, 04, model, contracts, 01, 02 and the threat model were truncated; deciding ranges were read with bounded line ranges. The 01/02 broad refs exceeded 4,096 estimated tokens and were not opened.
- `sha256sum` on current subject files: run; values recorded in Subject above.
- No source-code analysis or tests were needed for this design review. Omitted deciding evidence: 0.
