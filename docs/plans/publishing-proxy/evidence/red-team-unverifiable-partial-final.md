# Red Team: unverifiable revision recovery and service-scoped lease limits

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=87b7e385f806e00ac1f321e2d40a5a2f5b453b1a07051023189e76a5ebfb1d07; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=43a274cd19eeb8fa244b79c23706b765b36e61e16d26c90a1c56f0da2cfba19b, `docs/plans/publishing-proxy/04-slices.md`=b992d588084b41d8b0c6dc25ab0e087d54f693d59c6db3a13068e28bbbdba7e9, `docs/plans/publishing-proxy/molecule-flow.json`=4f189b86d1b020f7cbfd465a865c0ac5727e381f3a44fa294bc182092e0c750a, `docs/plans/publishing-proxy/molecule-contracts.json`=7cb3bb8cc92af0e220b771dfc672592b8b7ce9d46a33c70b912df22bbdbbbd7b; threat model `docs/plans/publishing-proxy/evidence/threat-model-unverifiable-revision.md`=70f6823f826277295f5aa6200cc084dd3adddd103cac536f370624c1656c53eb

## Bottom line

The active documents cover both revision sources, uncertain partial-write recovery, the service-scoped quotas, and all three DELETE routes. One credential-flow gap remains in the modeled authenticated-GET fallback: the GET has no explicit package-manager credential input or route-specific credential-destination guarantee.

## Findings

- **BLOCKER — Security and verifiability — `molecule-flow.json`, `record_successful_service_removal` and `service-scoped-version-unpublish`:** D42 and Slice 3 require an immediate authenticated GET to the selected upstream when the accepted revision PUT omits its revision. The modeled `record_successful_service_removal` operation takes request, response, service, registry, and reference, but no `Credential`; its `removed_with_authenticated_get_fallback` outcome establishes only `authenticated_fresh_get_confirmed_removal`. The flow already has `credential_sent_to_registry` from the earlier PUT, so that fact cannot prove the fallback GET carried the package-manager credential to the selected registry. This leaves the read's authentication source and destination implicit in a security-sensitive branch and could mask credential crossover. Model the fallback GET as a distinct selected-upstream operation (or add an explicit credential input and branch-specific guarantee) and make the Slice 3 witness trace its credential to the selected registry while confirming the policy API key is absent.

## Checked clean

Coverage, Dependencies, Risk order, Foundations, Sizing, and Hard bar: D42's 24-hour and 2 KiB limits and 20,000-per-service, 100,000-per-registry, and 1,000,000-global caps are explicit; batch/quota failure refuses before advertising and Slice 3 checks each cap+1 with unchanged store rows. The model and active witness distinguish whole-package upstream allow/deny without a marker, direct canonical tarball zero-I/O refusal, and service-scoped version-reference deletion. The accepted PUT revision and immediate authenticated-GET fallback both reach revision-bound marker creation; denied, unchanged, and unverifiable outcomes leave no marker, and unverifiable revision or marker persistence failure returns an uncertain partial write. The service API key is reserved for the policy snapshot Authorization header and package-manager credentials are assigned to selected-registry operations.

Threat model: MODELED (supplied), `evidence/threat-model-unverifiable-revision.md`.

Deciding evidence (Structural and Manual tier):

1. `02-architecture.md` D42 specifies the authenticated-GET fallback and service-scoped cap.
2. `04-slices.md` Slice 3 directly witnesses the fallback and cap+1 behaviors.
3. `molecule-flow.json` models the GET-fallback outcome without a credential input; its credential fact may already come from the preceding PUT.

Limitations: This is a design review. No source analysis or product tests were run. Runtime credential routing, exact GET behavior, durable marker persistence, quota transactionality, and concurrent one-winner behavior remain unverified.

SMTC receipt:

- `file grep` on approved product credential ownership: run; outer/inner `ok`; Manual; bounded three-match output, not truncated.
- `file read` on architecture D40–D42: run; outer/inner `ok`; Manual; complete deciding rows.
- `file read` on active program contracts, invariants, and repository evidence: run; outer/inner `ok`; Manual; complete deciding range.
- `file read` on active Slice 3: run; outer/inner `ok`; Manual; complete active row, including GET fallback, quota caps, and three DELETE routes.
- `file read` on marker lifecycle flow and operation contract: run; outer/inner `ok`; Structural; complete deciding ranges show the fallback outcome has no credential port; the existing selected-registry credential fact is established earlier by the PUT.
- `file read` on the new marker source spec and supplied threat model: run; outer/inner `ok`; Manual; complete deciding files.
- No source-code analysis or tests were needed for this proposed-design finding. Omitted deciding evidence: 0.
