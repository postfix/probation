# Red team: local package publishing service

Review kind: red-team
Verdict: SOUND
Review: independent
Subject: architecture docs/plans/publishing-proxy/02-architecture.md=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc; design docs/plans/publishing-proxy/03-program-design.md=ddd8f997850bc83d2fd910e0c83bd77e51b7b9bc0a24779625e8ac81e7e96f04; slices docs/plans/publishing-proxy/04-slices.md=1337a289337f89506f42cb126e2b0c2a9bd886b8ff603c74d2897ead722ccb6d; upstream docs/plans/publishing-proxy/01-product.md=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46; docs/plans/publishing-proxy/molecule-flow.json=cd7da33e9fa56f09df91b513c9ec9988473ee6b9ab92ec2b6d61d70c67aa65bc; docs/plans/publishing-proxy/molecule-contracts.json=0f6ebff75a1cd92c8b893dc4c4534f09f96007e4ef3f0fb10c5be0a4efb1516f; docs/plans/publishing-proxy/evidence/threat-model-local-service.md=23042fb1d5b5f8538e75cac498f4f5eea3039cec6e96117ac8c50973cb68dbd3; docs/plans/publishing-proxy/evidence/local-client-repository-map.md=12ea9902dee5524c636862b8419a9134628f0cbb4a2706d680a1ddf6c09abddd; docs/plans/publishing-proxy/evidence/source-contract-rebind.md=0dd1762eb197aac1930361e7ac2228d4921161a6dfc889d632c49f759f7d635a; docs/plans/package-firewall-mvp/02-architecture.md=bb1d5c5a5c7009ecbfb936e6c5a1c30a99efc0e16fffaf72dd4cb4b0baf7b50e; docs/plans/package-firewall-mvp/03-program-design.md=9f0ecfea83e59550de2dd5b3916175af27d20e00897a62b14e74791ba93b89f5
Bottom line: The active npm/PyPI publishing design is internally consistent with the shared service boundary and the supplied MODELED threat review. No blocking design flaw remains; the highest-risk runtime guarantees are explicitly assigned to future slices with witnesses that can falsify them.
Findings: none.
Checked clean: coverage, dependencies, risk order, foundations, verifiability, sizing, hard bar, security.
Threat model: MODELED (supplied)
Limitations: The revised route and unpublish implementations are future work, so this review establishes design consistency only. Source/runtime behavior, durable-store atomicity, concurrent one-winner semantics, OS listener exposure, cache behavior, registry credential routing, native client behavior, and the stated release tests remain unverified. No tests were run.
Evidence tier: Manual. Evidence items: 5; omitted: 0.

## Evidence

- The active design keeps the two credential roles separate: the organization service API key authenticates the enforcement service to the policy server via the snapshot request's HTTP Authorization header; package-manager registry credentials authorize the selected upstream operation. The local package request has no asserted user identity and credentials cannot select policy or registry (active design, lines 1–15 and 44–65; lead architecture decisions C1019–C1024).
- Current-policy response release is assigned to the lead plan's shared `PolicyPublicationGate` and non-cloneable authorization handoff. The publishing plan requires completion of asynchronous preparation before final authorization, exact prepared content/registry binding, cold and warm coverage, and an explicit before/after publication ordering witness (active design, lines 44–65; Slice 1).
- Selected-registry classification precedes protocol dispatch. Model/contract caveats are explicit: structural checks prove call order only, leaving route completeness and exact value binding to implementation review and runtime tests (molecule-contracts.json lines 5–25; active design line 76).
- Version unpublish has an explicit service-scoped migration: opaque reference binds to durable service store, immutable registry/package/version/filename, approved destination and resulting revision; the marker is atomically consumed before DELETE. Two concurrent requests, replay, wrong revision, and restart are assigned concrete zero-I/O / at-most-one-send assertions (architecture D42; active design lines 49–55; Slice 3).
- The shared listener's lack of per-caller identity is an acknowledged boundary, with host/approved-node network controls and one common service policy. The supplied threat model is MODELED and expressly excludes historical member-bound certificate assumptions. No firewall API key is reinterpreted as package-manager authorization.

## SMTC receipt

All legs used session `sf-red_team_local_service-2026-11-02`, root `/home/john/go/src/github.com/postfix/probation`; commands below omit only that repeated root/session pair. Outputs were structurally complete for the inline evidence used, with no inner refusal. Initial broad file reads that returned refs estimated above 4,096 tokens were not opened; narrower ranges/greps were used instead.

| Operation | Redacted argv | Status | Outer/inner status; fidelity | Truncation/ref | Interpretation |
|---|---|---|---|---|---|
| file read | `file read --path publishing-proxy/02-architecture.md --start-line 1 --end-line 15` | run | ok; text/manual | complete | Active authority and historical boundary identified. |
| file read | `file read --path publishing-proxy/03-program-design.md --start-line 44 --end-line 65` | run | ok; text/manual | complete | Current-policy handoff, D42 unpublish contract, and credential boundaries reviewed. |
| file read | `file read --path publishing-proxy/04-slices.md --start-line 1 --end-line 13` | run | ok; text/manual | complete | Dependencies and falsifiable slice witnesses reviewed. |
| file read | `file read --path publishing-proxy/molecule-flow.json --start-line 1 --end-line 20` | run | ok; text/manual | complete | Model assumptions bind service policy, credentials, identity and unpublish; implementation explicitly future work. |
| file read | `file read --path publishing-proxy/molecule-contracts.json --start-line 1 --end-line 17` | run | ok; text/manual | complete | Route-classification source contract reviewed; narrow check scope acknowledged. |
| file grep | `file grep --pattern PolicyPublicationGate --path-include publishing-proxy/03-program-design.md --max-results 6` | run | ok; text/manual | complete | Exact handoff ordering contract and verification requirement found. |
| file grep | `file grep --pattern FIX-16-A --path-include package-firewall-mvp/03-program-design.md --max-results 6` | run | ok; text/manual | complete | Lead contract requires authority/policy publication ordering at release. |
| file read | `file read --path package-firewall-mvp/03-program-design.md --start-line 1 --end-line 20` | run | ok; text/manual | complete | Shared-service decisions C1019–C1024 reviewed. |

Additional decisive greps found D42 and its explicit no-member-identity rule, the service-scoped slice outcome, and the threat model's MODELED boundary. These are document-level conclusions; SMTC tier is Manual, not a source/runtime proof.
