# Shared-service threat model — public upstream scope

Reviewer: sf-threat-model, shared_service_threats, 2026-11-02. Verdict: UNKNOWN. This is a bounded summary of the returned design report; no source-safety or runtime claim.

## Blocking design gaps

1. Specify complete machine/cluster deployment admission, process supervision, endpoint placement, node-runtime configuration, startup behavior and no-fallback controls.
2. Specify canonical identity, origin/redirect/auxiliary endpoints, age and integrity contracts for the eight added adapters.

This report predates the final C1024 clarification. Its public-only/authentication-exclusion interpretation is superseded: handle requested registries using existing public-registry behavior and keep publishing credentials/upstream authorization as before. No new public/private mode, removal of authentication behavior or credential redesign was requested. Missing proposed implementation is expected; the deployment/adapter gaps above remain design work.

## Scope and evidence

One machine-wide or logical cluster service, one organisation service-key policy, no downstream Probation login, approved-node trust including every workload on an approved node, and public-registry consumption/public-package freeze across the ten selected families. Linux/macOS/Windows clients; Linux policy server; explicit standalone TOML alternative.

Inputs: lead 01-product.md and 02-architecture.md; evidence/design-service-policy-api.md; evidence/design-local-client-grounding.md; evidence/research-cluster-image-routing.md; historical 03-program-design.md threat model; management C19/C20/C30 and publishing C35. Existing PARTIAL grounding was supplied evidence, not promoted to a new source verdict. Existing publishing credential handling remains required; this report does not change it.

Assets: correct common policy, organisation isolation, service-key secrecy, requested upstream identity, durable first-seen/digest/refusal state, zero newly refused artifact bytes, availability, truthful decisions/readiness. Boundaries: admitted machine/node to listener; request to canonical registry identity/outbound destination; public metadata/bytes to verified delivery; service key to scoped policy API; remembered authority to restart recovery; runtime configuration to actual network path; service state to decisions.

## Threats, minimal controls and required witnesses

| ID / severity | Mechanism and control | Required future evidence |
|---|---|---|
| SS-1 High | Wrong-kind/fleet key, arbitrary place selectors or mixed-revision layers broaden policy authority. Require live database service-key kind; derive organisation/chain server-side; read one coherent transaction; validate before atomic activation; separate policy transport. | Wrong-kind/foreign-place API refusals; coherent snapshot tests; destination confinement. |
| SS-2 High | Crash/previous-cache recovery or a late in-flight response resurrects refused/old authority. Bind cache to server/key/mode/registry set; persist refusal across both recovery files; fail closed on refusal-persistence failure; fence configuration generations; final policy checks before responses. | Refusal/restart/fault-injection and late-response tests; no warm delivery after applied denial. Preserve C19/C20 outage behavior. |
| SS-3 High | Exposed listener, spoofed forwarding headers or writable service config admits unapproved hosts or exposes policy authority. Restrict machine listeners locally; enforce cluster approved-node admission; identify trusted forwarding hops; encrypted cluster transport; service-owned key/config/data permissions; validate before listening. | Native OS permission/startup tests; unapproved-host and forged-forward-header negatives. Concrete deployment contract still open. |
| SS-4 High | Runtime upstream fallback, registry-specific override or unprotected startup pulls bypass denial. Explicit server with pull/resolve; reconcile all node configurations; host egress controls; verified node DNS/CA/routing; bootstrap independent of unprotected pulls. | Fresh tag/digest pulls with healthy origin: denial and service outage cause zero direct-origin pulls. Verify anonymous public OCI challenges and every node route. Candidate documented, not executed. |
| SS-5 High | Ambiguous canonical names/URLs or mutable references evade blocks, reset age or cause SSRF. Define per-family canonical registry/artifact identities; reject ambiguity; bind mutable refs to immutable content; enumerate allowed metadata/artifact/token/auxiliary origins; validate redirects/resolution; persist per-artifact first-seen; verify before delivery. | Per-adapter adversarial/native exact-request, identity, age/restart, integrity and origin tests. New adapter contracts remain open. |
| SS-6 Medium | Public token challenges or historical publishing credentials leak into pooled headers, other destinations, responses or decisions. Separate transports/context; avoid global secret headers; constrain token realm/scope; isolate secret-bearing responses; allowlist logs. | Canary policy/publisher tokens absent from unrelated requests/logs/responses; anonymous tokens scoped to admitted public registry/repository. Preserve existing authentication behavior; no new mode is selected. |
| SS-7 Medium | Unique-name floods, large/deep/compressed metadata, slow callers or excessive graphs starve common service/policy updates. Bound bytes, parser features/expansion/references, concurrency, time, queues and outbound requests; reserve update capacity. | Hostile parser/load checks with bounded memory/outbound rate and timely policy update capacity. Negative cache alone does not bound distinct-name floods. |
| SS-8 High | Historical npm token-packument exception becomes general bypass, leaks via shared cache or falsely attributes a node to a person/workload. Preserve only C35 metadata exception; artifacts retain policy; upstream authorizes writes; service key is policy authority, node is observed context. | Existing npm/PyPI publishing compatibility tests; exception cache isolation; policy on every artifact; truthful attribution. |

Every verification item is planned. Evidence tier: manual design review. Future structural checks cannot replace runtime behavior; runtime tests do not prove unencoded source properties. Omitted threats: zero.

## Fixed decisions and limits

C1020-C1022 select common policy, no separate downstream login and approved-node trust. Kubernetes permissions control deployment/image-secret use; mandatory per-user/workload authentication would conflict. C19/C20 permit known matching remembered policy during outages, including delayed revocation; explicit received refusal still requires durable invalidation. Native caches/installed code are outside network re-delivery enforcement. Local-administrator bypass remains the accepted C30 device/network boundary. Managed failures never select standalone. Operators own deployment configuration, but admission/no-fallback acceptance must name and test their controls rather than silently transfer unverified guarantees.

Actual native tools on all three client OSes, Linux policy-server integration and real daemon/node pulls remain required. Builds, HTTP mocks or Pod failure alone cannot prove them. SMTC receipt: no source-analysis legs run; supplied grounding only. No runtime probes or infrastructure changes. Do not approve the incomplete deployment/adapter contracts as verified.
