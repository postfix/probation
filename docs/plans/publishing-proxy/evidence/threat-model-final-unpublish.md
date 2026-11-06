MODELED

Scope: Active local-service package publishing design, including managed policy retrieval, selected-registry operations, and npm version-unpublish from revision PUT through marker consumption.

## Actors, entry points, boundaries, and assets

Actors are local package managers and CI jobs, the Probation service, the policy server, selected registries, and local administrators. Entry points include the policy snapshot request; named npm/PyPI reads and writes; revision PUT; version-reference DELETE; direct canonical tarball DELETE; and whole-package revision DELETE.

The service API key authenticates the firewall to the policy server through the snapshot request’s HTTP `Authorization` header. Package-manager credentials authorize operations at the selected registry. The shared service has no per-request member identity. D42 scopes leases to its durable service store, then to registry, package, version, filename, advertised destination, and approval scope.

Assets include policy, both credential types, private package metadata and artifacts, registry state, lease and marker records, logs, and service availability.

## Threats and controls

| ID / property | Mechanism and asset | Mitigation and observable property | Tier and evidence |
|---|---|---|---|
| T1 Credential noninterference | The service key reaches a registry, or a package-manager credential reaches policy retrieval. | Separate credentials and destinations. Traces show the service key only on `GET /api/v1/policy/snapshot` and package credentials only on the selected registry operation. | Structural + manual; active credential boundary and Slice 1/3 traces. |
| T2 Policy downgrade or stale authority | Configuration error, outage, or stale policy authorizes a request. | Managed and standalone modes are explicit; managed mode never falls back to TOML. Current authority is checked before response release. | Structural + manual; C19/C20, lead FIX-16-A and Slice 1 witnesses. |
| T3 Route confusion or SSRF | A request or URL sends credentials or mutations to an unintended route, host, path, or peer. | Named routes and selected registry are enforced; unsafe paths, unapproved destinations, peers, and redirects refuse. Whole-package revision DELETE remains upstream-authorized and marker-free; direct canonical tarball DELETE refuses before outbound I/O; version-reference DELETE uses the scoped marker flow. | Structural + manual; active route model and Slice 3 route witnesses. |
| T4 Unauthorized version removal or replay | Denied/unchanged PUT, wrong revision, stale reference, or concurrent/replayed DELETE creates or reuses authority. | Only an upstream-accepted PUT confirming removal of the exact leased version commits a revision-bound marker. DELETE requires and atomically consumes it once. Denied, unchanged, and unverified PUTs leave the reference unmarked; commit failure returns uncertain partial-write. | Structural + manual; active lifecycle flow and Slice 3 marker, replay, restart, and concurrency witnesses. |
| T5 Incorrect revision verification | PUT response omits its resulting revision, or a fallback read fails to confirm removal. | Use the PUT response revision or immediately issue an authenticated GET to the selected upstream and confirm the version is absent. No marker is committed without confirmation. | Manual; D42 and Slice 3 PUT-response/GET-fallback cases. |
| T6 Lease exhaustion or unsafe input complexity | Excessive URLs, oversized data, or quota races consume storage or advertise unusable links. | Limit leases to 20,000 per service, 100,000 per registry, and 1,000,000 globally; retain the 24-hour and 2 KiB limits. Batch/quota failure refuses before advertising a URL. | Structural + manual; D42 and Slice 3 cap+1 plus unchanged-store assertions. |
| T7 Private metadata or secret disclosure | Token-bearing metadata, sealed query values, or credentials escape through caches, logs, links, or redirects. | Keep token packuments request-local; seal approved query data; redact secrets; refuse credential-bearing redirects. | Structural + manual; existing packument/audit controls and Slice 2/3 cache and secret witnesses. |
| T8 Service or listener compromise | Unapproved local process/node accesses the shared service, or native setup exposes secrets. | Restrict machine access to local service boundaries and cluster access to approved nodes; protect the service key and require native acceptance checks. | Manual; lead deployment design and lead Slice 25/Slice 5 witnesses. |

No accepted or transferred risk is proposed. Exact credential routing, GET fallback behavior, marker durability, quota atomicity, and concurrent one-winner behavior remain planned verification work; the finite model and ordered source checks do not prove those runtime properties.

Omitted threats: 0.
