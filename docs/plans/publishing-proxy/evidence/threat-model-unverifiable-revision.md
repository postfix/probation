# Threat model: active local-service publishing and unpublish

**Verdict: MODELED.** The active local-service design covers the policy and registry credential boundary, the npm DELETE routes, marker provenance and the uncertain partial-write recovery case.

## Scope and boundaries

Entry points: policy snapshot retrieval; named npm/PyPI reads and writes; npm revision PUT; version-reference DELETE; direct canonical tarball DELETE; whole-package revision DELETE; local service and registry configuration.

The service API key authenticates the firewall to the policy server through the snapshot request's HTTP `Authorization` header. Package-manager credentials authorize operations at the selected registry. The shared service has no per-request member identity. Assets include policy and credentials, private package metadata and artifacts, registry state, references and revision markers, logs, and service availability.

## Threats and controls

| Threat | Mechanism and mitigation | Observable verification property | Tier and design evidence |
|---|---|---|---|
| Credential crossover | The policy key reaches a registry or package-manager credentials reach the policy server. Keep credentials on separate request paths and destinations. | The service key appears only on `GET /api/v1/policy/snapshot`; registry credentials appear only on requests to the selected registry. | Structural + manual; active design and Slice 1/3 traces. |
| Policy downgrade or stale authority | Configuration or outage permits weaker TOML fallback or stale authorization. Keep modes explicit, prohibit managed fallback, and recheck current authority before releasing responses. | Managed failure never loads standalone TOML; a denial published before final authorization prevents release. | Structural + manual; C19/C20, lead FIX-16-A, Slice 1. |
| Route confusion or SSRF | A request or URL sends credentials or mutations to an unintended route, host, path, or peer. Enforce named routes, selected-registry routing, destination scopes, and redirect refusal. | Whole-package revision DELETE follows selected-upstream allow/deny without a version marker; direct canonical tarball DELETE makes zero outbound calls; version-reference DELETE uses the guarded marker path. | Structural + manual; active route model and Slice 3. |
| Unauthorized version removal or replay | Denied, unchanged, or unverified revision PUTs create authority, or a stale/concurrent DELETE reuses it. Create a revision-bound marker only after the selected upstream accepts the PUT and confirms removal of the exact leased version; consume it atomically once. | Denied, unchanged, or unverified PUTs leave no marker; a matching DELETE consumes one marker; replay and concurrency produce no second outbound DELETE. | Structural + manual; D42, lifecycle flow, Slice 3. |
| Missing or inconsistent resulting revision | PUT response omits the resulting revision and the authenticated fallback GET cannot verify it. Use the PUT revision or an immediate authenticated selected-upstream GET confirming the version is absent. Return an uncertain partial-write result with no marker if verification fails; require recovery. | GET success yields a matching revision-bound marker; unavailable or inconsistent GET yields uncertain partial write and no marker. | Manual; D41/D42, lifecycle flow, Slice 3. |
| Lease exhaustion | Excessive URLs or quota races exhaust storage or advertise unusable links. Enforce 20,000 live leases per service, 100,000 per registry, and 1,000,000 globally, with 24-hour and 2 KiB limits; fail the batch before advertising new URLs. | Each cap+1 case refuses before advertising a URL and leaves store rows unchanged. | Structural + manual; D42 and Slice 3. |
| Private metadata or secret disclosure | Metadata, sealed query data, or credentials escape through caches, logs, links, or redirects. Keep token packuments request-local, seal approved query data, redact secrets, and refuse credential-bearing redirects. | Another request receives no token-private metadata; queries and credentials do not appear in logs or client links or reach unapproved origins. | Structural + manual; existing controls and Slice 2/3 witnesses. |
| Listener or service compromise | An unapproved process or node reaches the shared service, or native setup exposes secrets. Restrict local and approved-node access and protect service-key files. | Unapproved peers are refused; unrelated users/jobs cannot read the service key. | Manual; lead deployment design and lead Slice 25/Slice 5. |

## Decisions and limitations

No accepted or transferred risk is proposed. Runtime credential routing, authenticated GET behavior, marker durability, quota atomicity, and concurrent one-winner behavior remain Slice 1/3 verification work. No source analysis or product tests were run.

**Omitted threats: 0.**
