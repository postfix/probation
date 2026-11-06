# Red Team: active version-unpublish lifecycle

Review kind: red-team  
Verdict: NEEDS REVISION  
Review: independent  
Subject: design `docs/plans/publishing-proxy/03-program-design.md`=f983bb5bcc7806215880f6cb54dc40067a459273abdd8b2f1694f6e41e32c51b; upstream `docs/plans/publishing-proxy/01-product.md`=39ed1758b6e83d4effb0205474f71b107cbeb66ded55bee93693c4c424d8fa46, `docs/plans/publishing-proxy/02-architecture.md`=a2f54afc692a9cbb8ef83a9e452ce6c40807693e00e0ab457a7dd1f2fba5fdab; `docs/plans/publishing-proxy/04-slices.md`=df9da3d8c68b58f9f9586792ac131ca26b9244afc1bff5fb37196e991ccefe50; `docs/plans/publishing-proxy/molecule-flow.json`=4e3d936469c24915e0a162f21c16be40b790c0ab3fe91045f7d4c37080234802; `docs/plans/publishing-proxy/molecule-contracts.json`=7cb3bb8cc92af0e220b771dfc672592b8b7ce9d46a33c70b912df22bbdbbbd7b

## Bottom line

The active design now distinguishes all three DELETE routes, models both revision sources, scopes lease caps to the service, and preserves the policy-key/registry-credential split. One blocker remains: when an accepted PUT omits its revision and the immediate GET cannot verify it, the design says no marker is created but does not require the uncertain-partial-write outcome required by D41; Slice 3 also lacks that assertion.

## Findings

- **BLOCKER — Verifiability — active `record_successful_service_removal` behavior and Slice 3 witness:** `02-architecture.md` D41 says unavailable or inconsistent revision verification after an upstream-accepted PUT is an uncertain partial write requiring recovery. Active `03-program-design.md` says a failed GET creates no marker, but reserves uncertain partial-write for marker-commit failure. The `verification_failed` model outcome is only `revision-removal-unverified-no-marker`, and the Slice 3 witness does not assert an uncertain partial-write when the fallback GET is unavailable or inconsistent. This can report an ordinary failure after the upstream may already have removed the version, leaving the caller unaware that manual recovery is needed. Require the uncertain-partial-write response for accepted PUTs whose resulting revision cannot be verified, keep the marker absent, and add a Slice 3 witness for unavailable/inconsistent fallback GET.

## Checked clean

Coverage: The policy API key goes only to the policy snapshot HTTP Authorization header; package-manager credentials go only to the selected registry. The three DELETE routes have separate outcomes and witnesses. D42 explicitly caps leases at 20,000 per service, 100,000 per registry, and 1,000,000 globally, retains 24-hour/2 KiB limits, and requires quota failure before URL advertisement.

Dependencies: The version-reference flow orders accepted revision PUT, exact removal confirmation, marker commit, then marker-gated DELETE. The fallback GET is authenticated to the selected upstream.

Risk order: The service-policy/selected-registry foundation precedes npm publishing, while Slice 3 owns the higher-risk marker, quota, destination and concurrency cases.

Foundations: The caller has a service-scoped reference and an unmarked initial state; the revision marker is bound to that reference and resulting revision. Other DELETE routes do not use the marker.

Sizing: Slice 3 remains a coherent npm publishing increment with one direct client witness.

Hard bar: Direct canonical tarball DELETE refuses before I/O; whole-package revision DELETE preserves selected-upstream allow/deny; version-reference DELETE requires the exact one-use marker.

Security: No extra credential path or route bypass was found. Exact runtime credential routing, marker durability/atomicity, quota transactionality and concurrent one-winner behavior remain Slice 3 checks.

Threat model: MODELED (supplied), `evidence/threat-model-final-unpublish.md`.

## Limitations

This is a design review. The service route sources are future work. No product tests or source analysis were run; runtime credential routing, marker durability and concurrency remain unverified.

## SMTC receipt

- `file read`: active `03-program-design.md`, `02-architecture.md`, `04-slices.md`, `molecule-flow.json`, `molecule-contracts.json`, marker spec and threat model; outer/inner status `ok`. Broad reads of active design/model files were truncated; narrowed reads supplied the deciding passages. The threat-model read was complete.
- `file grep`: D42, route/marker predicates and Slice 3 witness; outer/inner status `ok`, bounded matches, no deciding truncation in the D42/model legs.
- `ref show`: narrowed `molecule-flow.json` lifecycle and active `03-program-design.md` sections; outer/inner status `ok`; complete deciding passages.
- `sha256sum`: exact subject hashes above, one path per command; all rechecked after review, no subject drift.
- Tier: Structural and Manual. No source-code analysis or tests were needed for this proposed-design finding.

Omitted deciding evidence: 0.
