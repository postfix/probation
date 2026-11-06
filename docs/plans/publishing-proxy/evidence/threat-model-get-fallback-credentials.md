# Threat model: active package publishing and revision lookup

Verdict: MODELED.

Scope: Active local-service package publishing design, including the revision PUT → marker → version-reference DELETE lifecycle and revision lookup fallback.

## Entry points and boundaries

Entry points are policy snapshot retrieval; selected-registry reads and writes; npm revision PUT; version-reference DELETE; direct canonical tarball DELETE; and whole-package revision DELETE.

The service API key authenticates the firewall to the policy server in the snapshot request's HTTP `Authorization` header. Package-manager credentials authorize operations at the selected registry. The shared service has no per-request member identity. Assets include policy, both credential types, package metadata and artifacts, registry state, references, markers, logs, and service availability.

## Threats and controls

| Threat | Mitigation and observable property | Evidence |
|---|---|---|
| Credential crossover | Keep credentials on separate request paths. Traces show the service key only on `GET /api/v1/policy/snapshot`, and package-manager credentials only on the selected registry, including the revision lookup GET fallback. | Active design and Slice 1/3 witnesses. |
| Policy downgrade or stale authority | Make managed and standalone modes explicit; managed mode never falls back to TOML; recheck current authority before response release. | C19/C20, lead FIX-16-A, Slice 1. |
| Route confusion or SSRF | Enforce named routes, selected-registry routing, current destination scopes, peer checks, and redirect refusal. Whole-package revision DELETE follows upstream allow/deny without a marker; direct canonical tarball DELETE refuses before I/O; version-reference DELETE uses the guarded marker flow. | Active route model and Slice 3. |
| Unauthorized version removal or replay | Commit a revision-bound marker only after an upstream-authorized PUT confirms removal of the exact leased version; consume it once before DELETE. Denied and unchanged PUTs leave no marker. | Active lifecycle flow and Slice 3. |
| Missing or inconsistent resulting revision | Use the PUT revision or an immediate authenticated GET to the selected upstream confirming the version is absent. If verification fails after PUT acceptance, return an uncertain partial-write result with no marker and require recovery. | D41/D42 and Slice 3 fallback and recovery witnesses. |
| Lease exhaustion | Enforce 20,000 live leases per service, 100,000 per registry, and 1,000,000 globally, with 24-hour and 2 KiB limits. Reject a batch before advertising URLs when storage or quota checks fail. | D42 and Slice 3 cap+1 and unchanged-store witnesses. |
| Private metadata or secret disclosure | Keep token-bearing packuments request-local; seal approved query data; redact secrets; refuse credential-bearing redirects. | Existing controls and Slice 2/3 witnesses. |

No accepted or transferred risk is proposed. Exact credential routing, authenticated GET behavior, marker durability, quota atomicity, and concurrent one-winner behavior remain Slice 1/3 verification work; the finite model and ordered source checks do not prove runtime behavior. No source analysis or product tests were run.

Omitted threats: 0.
