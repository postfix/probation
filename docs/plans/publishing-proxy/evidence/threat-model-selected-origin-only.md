# Threat model: selected-origin credentials and npm unpublish

Verdict: MODELED. Blocking findings: none.

## Scope and boundaries

This design review covers managed and standalone local-service package operations, including policy snapshot retrieval, npm publishing and its three DELETE routes, revision PUT/marker/GET fallback, PyPI upload, and shared-service access.

The service API key authenticates the firewall to the policy server through the snapshot request's HTTP `Authorization` header. Package-manager credentials authorize operations at the selected registry only. The shared service has no per-request member identity. Assets include policy and credentials, package metadata and artifacts, registry state, references and markers, logs, and service availability.

## Threats and controls

| Threat | Mitigation and observable property | Evidence |
|---|---|---|
| Credential crossover | Keep credential purposes and destinations separate. The service key appears only on `GET /api/v1/policy/snapshot`; package-manager credentials go only to the selected registry, including the revision lookup GET fallback. | Active design and Slice 1/3 witnesses. |
| Policy downgrade or stale authority | Make managed and standalone modes explicit; managed mode never falls back to TOML; recheck current authority before response release. | C19/C20, lead FIX-16-A, Slice 1. |
| Route confusion or SSRF | Enforce named routes, selected-registry routing, current destination scopes, peer checks, and redirect refusal. Whole-package revision DELETE follows selected-upstream allow/deny without a marker; direct canonical tarball DELETE refuses locally; version-reference DELETE uses its guarded marker flow. | Active route model and Slice 3. |
| Extra-origin credential leak | Refuse extra-origin tarball URLs before advertising a local action URL; refuse forged extra-origin references before I/O. D42 supersedes D41's extra-origin bearer option under C1015/C1024. | Active D42 and Slice 3 preflight/refusal witnesses. |
| Marker provenance, replay, or race | Commit a revision-bound marker only after an upstream-authorized PUT confirms removal of the exact leased version; consume it atomically once. Denied, unchanged, or unverified PUTs leave no marker. | Active lifecycle flow and Slice 3. |
| Missing or inconsistent resulting revision | Use the PUT revision or an immediate authenticated GET to the selected upstream confirming the version is absent. If verification fails after PUT acceptance, return an uncertain partial-write result with no marker and require recovery. | D41/D42 and Slice 3 fallback/recovery witnesses. |
| Lease exhaustion | Enforce 20,000 leases per service, 100,000 per registry, 1,000,000 globally, a 24-hour lifetime, and a 2 KiB URL limit. Refuse an over-quota batch before advertising URLs. | D42 and Slice 3 cap+1/unchanged-store witnesses. |
| Private metadata or secret disclosure | Keep token-bearing packuments request-local; seal approved query data; redact secrets; refuse credential-bearing redirects. | Existing controls and Slice 2/3 witnesses. |
| Service or listener compromise | Restrict access to the selected local/approved-node boundary and protect service-key files. | Lead deployment design and Slice 25/Slice 5 witnesses. |

No accepted or transferred risk is proposed. Runtime credential destinations, authenticated GET behavior, marker durability, quota atomicity, and concurrent one-winner behavior remain planned verification work. Proposed source was not analyzed and no product tests were run.

Omitted threats: 0.
