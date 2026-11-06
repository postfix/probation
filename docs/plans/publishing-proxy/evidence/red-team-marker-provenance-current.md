# Red Team: active local-service design and npm marker provenance

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=58ac00e26f78eaefa89af36fc95695e0e4f841b4ae47151e7319d96ce969b4b2; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=32e09a4381811028ef23e651cde720554d122ae39e3fe08718757dbb6c761ebc, `docs/plans/publishing-proxy/04-slices.md`=10d5cd0a8ed7aa52b023e99369dad3d32f3672a6c9fac2971ef4eeb51c38728f; model `docs/plans/publishing-proxy/molecule-flow.json`=3d013dc814c577823e59b5138a3c4e894110b8591960b73bbde40a0cc7e6a8ac, contracts `docs/plans/publishing-proxy/molecule-contracts.json`=6d0274fa0db40cd2e0232c7a41666818c0a204cc1b28dec9b3fa37c01322da3c

## Bottom line

The active design preserves the user-defined credential boundary: the firewall's API key authenticates its policy snapshot request in the HTTP `Authorization` header, while package-manager credentials authorize only selected-registry operations. The three npm DELETE routes are distinct, and the marker flow covers accepted, denied, unchanged and failed-commit outcomes. Two mismatches with the settled architecture remain before signoff.

## Findings

- **MAJOR — Contract consistency — `03-program-design.md` marker-recording paragraph, `molecule-flow.json` `record_successful_service_removal`, and Slice 3 witness:** Architecture D41 allows the accepted revision PUT response **or** an immediate authenticated selected-upstream GET that confirms the exact version is absent and supplies the resulting revision. The active program contract restricts verification to the PUT response, and the modeled operation has only the PUT response input; Slice 3 does not test the D41 fallback. A registry whose PUT response lacks enough revision/removal evidence could be rejected despite satisfying the approved contract. Align the active design and flow with D41's fallback, and test PUT-response confirmation and fresh-GET confirmation before marker commit; neither path may create a marker on denial or mismatch.
- **MAJOR — Resource bound — `02-architecture.md` D40/D42, active `molecule-flow.json`, and Slice 3:** D40's lease cap is 20,000 live leases per admitted member, 100,000 per registry and 1,000,000 globally. D42 removes member identity on this shared-service path, leaving the per-member cap without a defined scope. The active service flow and Slice 3 witness do not define a service-wide replacement cap. Without a usable service-scope bound, repeated preflights can grow durable marker/lease state without the approved limit. Define a service-scoped cap that preserves the registry/global limits, then include cap+1 and restart/store-growth witnesses in Slice 3.

## Checked clean

- **Coverage:** The API-key/registry-credential split and three DELETE route witnesses are present; D41's fresh-GET revision fallback and D40's service-scope lease bound are missing from active acceptance.
- **Dependencies:** npm actions and unpublish depend on the local-service route and policy foundation; version-reference DELETE follows an upstream-authorized revision PUT and marker verification.
- **Risk order:** Route and credential separation precede package writes; Slice 3 owns marker provenance, partial-write recovery, restart, concurrency and lease-cap witnesses.
- **Foundations:** The API key has policy-server scope; package-manager credentials remain selected-upstream authorization; D42 removes member identity, which makes D40's per-member quota inapplicable without a replacement scope.
- **Verifiability:** The finite model returns PASS. Source specs prove call order only; exact value binding, durable marker behavior and concurrency remain Slice 3 witnesses.
- **Sizing:** The route outcomes and marker lifecycle fit within the coherent npm publishing/unpublish slice; its direct witness needs the two missing acceptance cases above.
- **Hard bar:** Whole-package DELETE preserves selected-upstream allow/deny without a marker; direct canonical tarball DELETE refuses before outbound I/O; version-reference DELETE requires and consumes the revision-bound marker.
- **Security:** The active threat model covers credential noninterference, policy authority, route confusion and marker provenance; the missing D41 fallback and service-scope storage cap leave bounded gaps.

Threat model: MODELED (supplied), `evidence/threat-model-marker-provenance.md`.

Limitations: This is a design review. It did not inspect implementation source or run product tests. Actual credential routing, exact response-to-version/revision binding, marker durability and atomicity, and concurrent one-winner behavior remain unverified until Slice 1/3 implementation witnesses pass.

SMTC receipt:

- **Active design and scope reads:** `smtc file read --root /home/john/go/src/github.com/postfix/probation --path docs/plans/publishing-proxy/03-program-design.md --start-line 49 --end-line 67 --format json --max-tokens 2048 --session-id sf-redteam-marker-provenance-current-2026-11-02` and narrowed reads for 03 lines 1–40 and 89–122; analogous reads for `01-product.md`, `02-architecture.md` lines 60–86, and `04-slices.md` lines 7–12. All legs ran with outer/inner status `ok`; Manual fidelity; complete deciding passages. The initial broad reads of 03, 01, 02 and the model were truncated (refs over 4,096 tokens were not opened); narrower reads replaced them. D40–D42 were read through `smtc ref show ref-359 --session-id sf-redteam-marker-provenance-current-2026-11-02` (complete, 2,110-token estimate).
- **Credential and contract search:** `smtc file grep --root /home/john/go/src/github.com/postfix/probation --pattern 'policy API key|HTTP Authorization|API key authenticates policy retrieval|package-manager credentials' --path-include 'docs/plans/publishing-proxy/01-product.md' --max-results 8 --format json --max-tokens 2048 --session-id sf-redteam-marker-provenance-current-2026-11-02`; plus focused greps on the model/contracts. All legs ran with outer/inner status `ok`; Manual/Structural fidelity; bounded matches, no deciding evidence omitted. The compact product grep ref (2,533-token estimate) was opened.
- **Flow and witness reads:** `smtc file read --root /home/john/go/src/github.com/postfix/probation --path docs/plans/publishing-proxy/molecule-flow.json --start-line 916 --end-line 1060 --format json --max-tokens 2048 --session-id sf-redteam-marker-provenance-current-2026-11-02`, plus focused ranges 1477–1518, 1519–1575, 1576–1635, and 1610–1715. `smtc file read` on contract lines 185–240 and Slice 3 lines 9–12 also ran with outer/inner status `ok`; Structural/Manual fidelity; complete deciding ranges. The initial full flow read was truncated (ref over 4,096 tokens not opened); the focused ranges replaced it.
- **Threat model read:** `smtc file read --root /home/john/go/src/github.com/postfix/probation --path docs/plans/publishing-proxy/evidence/threat-model-marker-provenance.md --start-line 20 --end-line 40 --format json --max-tokens 2048 --session-id sf-redteam-marker-provenance-current-2026-11-02`; run with outer/inner status `ok`; Manual fidelity; complete route/marker threat rows.
- **Finite model check:** `router molecule-check --plan-root docs/plans/publishing-proxy` returned PASS. This is structural consistency only, not proof of implementation behavior.

Omitted deciding evidence: 0.
