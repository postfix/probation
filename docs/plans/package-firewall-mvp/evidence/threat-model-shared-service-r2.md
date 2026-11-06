# Shared-service threat model r2 (sf-threat-model, 2026-11-04)

Verdict: MODELED. Blocking findings: none. Evidence tier: manual design review of the packet. No source analysis was run, and every source claim is proposed, not verified. This report supersedes evidence/threat-model-shared-service.md (UNKNOWN). The C1024 withdrawal is honored: no public/private mode, no authentication redesign. C1021/C1022 are treated as fixed.

## Scope
- One machine-wide or logical cluster enforcing service.
- One organisation-service-key policy (C1020), with no per-request Probation login.
- Nine families: npm, PyPI, Maven, Go, Cargo, NuGet, RubyGems, Conan, OCI.
- Standalone TOML mode, the FIX-16-A release gate, migration 0014, and decision logs.

## Entry points
- Package-client HTTP routes: legacy /npm and /pypi, /registry/{eco}/{registry}/..., and the new native protocol routes.
- OCI /v2 routes, selected by the `ns` namespace.
- Existing publishing and action routes on the same listener.
- Health routes.
- Outbound GET /api/v1/policy/snapshot, authenticated with the service key.
- Upstream metadata, redirects, token realms, and auxiliary sources (sumdb, NuGet resources, Cargo dl).
- Data-directory files: policy cache envelope, refusal marker, store.
- Server migration 0014.
- Decision-log sinks.

## Trust boundaries
1. Peer to listener (host/network admission).
2. Request to registry namespace and outbound destination.
3. Upstream bytes to verified delivery.
4. Service key to policy server (read-only scoped API).
5. Policy and descriptor data to outbound authority.
6. Remembered authority to restart recovery.
7. Policy publication to final authorization to response handoff.
8. Node runtime configuration to actual network path.
9. Shared cache to caller upstream-credential scope.
10. Old and new binaries across migration.
11. Service state to logs.

## Assets
- Correct common policy.
- Organisation isolation and service-key secrecy.
- Zero bytes for a refused artifact.
- Per-artifact first-seen and digest pins.
- Canonical ecosystem/registry identity.
- Egress confinement.
- Caller upstream credentials.
- Truthful decisions and readiness.

## Threats
Eight are displayed. The omitted count is at the end.

### T1: Listener admission and ambient authority (High; tiers: structural, manual, decision)
- Mechanism:
  - A non-loopback listener is reached by unapproved peers.
  - Cluster NodePort traffic is source-NATed to an approved node IP, so pods or hosts on unapproved nodes appear approved.
  - Overly broad CIDRs such as /1 or /8, or IPv4-mapped IPv6 forms, bypass the 0.0.0.0/0 and ::/0 exclusion.
  - Forwarded headers are trusted.
  - Browser or DNS-rebinding requests reach the loopback port.
  - Legacy action routes (for example unpublish_reference, settings) on the now-login-free listener lose their old admission.
- Asset: policy integrity, the service's egress position, and any action routes.
- Location: config validation, the listener accept path, router inventory, deploy/kubernetes.
- Design evidence: 02 'Concrete deployment' and 'Required deployment' bullet 5; 03 'Configuration, data and platform contract'; C1021, C1022.
- Mitigation:
  - Check the peer address from the TCP socket, after normalizing v4-mapped addresses, before any routing.
  - Validate the CIDR set at startup. Reject empty sets and anything wider than a documented minimum prefix. Unmapped zero-address forms are already excluded.
  - Pin the actual-peer mechanism for the cluster. Use externalTrafficPolicy Local, or an equivalent that preserves the node source address, and verify it.
  - Validate the Host header against public_url.
  - Give every route an explicit admission class: read-only or forwarding only, or authorized by the caller's upstream credential. No route may rely on peer trust for a write.
- Verification property:
  - 'No package, protocol, or action handler runs for a peer outside the allowlist, including with forged X-Forwarded-For or a mismatched Host.'
  - 'Route inventory equals the classified set.'
  - 'A pod on an unapproved node, and an external host hitting any node's NodePort, are refused.'

### T2: Policy API, service key, and descriptors as outbound authority (High; tiers: structural, manual)
- Mechanism:
  - A user-kind or fleet key, or an arbitrary place or organisation selector, widens policy.
  - Mixed-revision reads produce an incoherent policy.
  - The service key reaches an upstream, a redirect, or a log.
  - A compromised or misconfigured policy server, or an organisation admin, sets a descriptor with `target_url`, `trusted`, or `registry_private_cidrs`. This pushes the enforcer toward link-local or metadata addresses, the cluster control plane, or its own listener (a routing loop).
- Asset: service-key secrecy, organisation isolation, egress confinement.
- Location: probation-server service_policy.rs, src/managed/service_policy.rs, the upstream transport.
- Design evidence: 02 'Proposed scoped policy retrieval'; 03 ServiceScope and RegistryDescriptor; evidence/design-service-policy-api.md.
- Mitigation:
  - Require database kind=service.
  - Derive the organisation server-side and read in one transaction.
  - Use a dedicated transport and client for the policy server, with a type-level split from registry traffic. Never put the key in registry request headers.
  - The enforcer applies a local, non-descriptor-overridable denylist to every outbound target: loopback, link-local and metadata addresses, its own listener, and cluster control-plane ranges. `registry_private_cidrs` may only narrow what is allowed, or must be bounded by operator-local config.
  - Only a configured descriptor may be reached as an outbound registry.
- Verification property:
  - 'The service key cannot reach any registry request.'
  - 'A snapshot from a user-kind or foreign-organisation key is refused.'
  - 'A descriptor naming a denylisted target is rejected before activation.'
  - 'No descriptor value can make the enforcer connect to itself.'
- Note: this tension needs an explicit statement. 02 asserts the historical rule that no config relaxes private-address checks, while the descriptor carries `registry_private_cidrs`. See D5.

### T3: Remembered policy, refusal persistence, and snapshot-validity semantics (High; tiers: structural, manual, decision)
- Mechanism:
  - Previous-file recovery, a late in-flight reply from an earlier config generation, or cache restore resurrects refused authority.
  - A forged or misrouted 401 or 403 durably locks out the service. An attacker on the path, or an operator error, causes denial of service.
  - An unrecognized-ecosystem snapshot from a newer server (version skew) is rejected. The design does not say whether that counts as a refusal or a transient fault.
  - The design also does not say whether a 404 for a removed registry affects only that registry or the whole snapshot.
  - There is no stated path to recover from a durable refusal after the server re-enables the key.
- Asset: policy correctness and availability.
- Location: src/managed/service_policy.rs and cache.
- Design evidence: 02 'Persist remembered policy'; 03 enforcer validation paragraph; C19/C20.
- Mitigation:
  - Bind the envelope to server identity, key hash, mode, and registry set.
  - Persist the refusal marker before acting on it, covering both primary and previous-file recovery. If persistence fails, admission stays closed.
  - Fence config generations on every activation.
  - Treat refusal only on an authenticated HTTPS response from the bound server. Treat validation failure (skew, bounds, unsupported tag) as retain-last-good with degraded readiness and an alert, not a refusal.
  - Define the registry-404 scope as that registry only.
  - Define explicit recovery: a config key change or a documented operator action.
- Verification property:
  - 'After a refusal, no restart or recovery path admits.'
  - 'A late reply from a prior generation cannot activate.'
  - 'An unsupported-tag snapshot never clears or creates a refusal.'
  - 'A cold or mismatched cache cannot admit.'
  - Outage with a matching cache continues serving under C19/C20.
- Decision: D3.

### T4: FIX-16-A publication gate (High; tiers: structural, decision, manual)
- Mechanism:
  - A legacy managed request evaluates a stale admission-time policy at release. FIX-16-A is the correction.
  - The gate itself can fail in these ways:
    - Generation and prepared-result binding is incomplete, so a captured grant releases another file.
    - A std RwLock has platform-dependent fairness. A nested read in the same thread, or a writer waiting, can deadlock. Poisoning makes the service permanently unavailable. Blocking waits run on async worker threads.
    - OSV results, and the standalone blocklist/policy publication, are not under the managed gate. OSV is complete before authorization but is not generation-bound, so an OSV update landing between preparation and handoff is not ordered.
    - Metadata and render caches that omit registry identity or policy generation serve stale candidates.
- Asset: zero payload bytes after a refusal publication.
- Location: src/artifacts/mod.rs, stream.rs, the policy publication gate, http/artifact_routes.rs and registry_routes.rs, service_registry.rs.
- Design evidence: 03 FIX-16-A and its matrix; evidence/artifact-flow-correctness.md findings 4 and 5.
- Mitigation:
  - Make AuthorizedResponse non-cloneable and bound to reference/content, registry, and authority/config generation.
  - The same critical section covers verification and handoff. No await and no I/O inside it.
  - Forbid nested acquisition. Fix the lock ordering against other locks.
  - Poison means refuse closed, and readiness must show it.
  - Put every cache key under registry plus generation.
  - Either include the OSV snapshot generation in the gate's check, or record it as a named accepted limitation with an owner (D4).
  - Do not treat the detached `Authorized` witness or a call-order check as a proof.
- Verification property: 'A policy or refusal publication ordered before final authorization yields zero artifact payload bytes (cold and warm, HEAD/range, legacy, selected, and common routes). A publication after accepted handoff does not cut the stream. An unchanged policy delivers the exact bytes.'
- Witness: the Slice 16 matrix in tests/managed_delivery_authority.rs, plus a cross-thread publication test at the gate boundary. Failure observed before the fix, with no timing sleeps.

### T5: Shared cache against caller upstream-credential authorization (High; tier: decision)
- Mechanism:
  - A caller with package-manager credentials fetches an artifact from a registry that requires authorization.
  - The shared content and metadata cache then serves the same bytes to any admitted caller that has no credentials (C1021 provides no login).
  - This silently bypasses upstream read authorization. It matters most in the cluster, where C1022 says Kubernetes permissions govern private-registry credentials.
- Asset: confidentiality of upstream-authorized content.
- Location: store/artifact cache key, reference binding.
- Design evidence: 02 Store row ('relevant credential authorization scope', 'cross-caller tests'); 03 states no mechanism.
- Mitigation:
  - Option A (preferred): do not populate or serve the shared cache from credential-bearing read responses.
  - Option B: key the cache by registry plus a one-way credential-scope fingerprint, never storing the credential.
  - Option C: revalidate with the caller's credential upstream before release.
  - Whichever is chosen, refusals are never cached across scopes. This does not change C1024 forwarding, publishing, or credentials, or create a public/private mode.
- Verification property: 'Bytes obtained under credential A are never delivered to a request lacking an equivalent upstream authorization.'
- Decision: D2.

### T6: Per-adapter identity and age confusion, plus migration tag confusion (High; tiers: structural, manual)
- Mechanism:
  - Collisions or aliases break blocks:
    - Maven case and classifier.
    - Cargo hyphen/underscore/case aliases.
    - Go escaped (!) paths.
    - NuGet version normalization.
    - Conan `_`/`_` placeholder and revisions.
    - RubyGems platform-ambiguous filenames.
    - OCI tag against digest.
  - A new variant resets first-seen, or inherits an unrelated date:
    - A Conan recipe date aging a new binary.
    - A RubyGems date for the wrong platform.
    - A NuGet unlisted sentinel.
    - An OCI config build time standing in for publication time.
    - A Maven directory age.
  - A truncated log label becomes storage identity.
  - Migration: the server's unknown-tag-to-Npm fallback maps an unseen ecosystem to npm. A rubygems block would then act on npm packages, and an exception would loosen an npm block. A rollback or old reader then hides the new rows.
- Asset: block and exception correctness.
- Location: crates/probation-policy names.rs and lib.rs, 0014 migration, per-family modules.
- Design evidence: 03 protocol and origin contracts (identity table), 'Configuration, data and platform contract', and evidence/design-protocol-contracts.md.
- Mitigation:
  - Per-family canonical identity with the selected registry in the key. An ambiguous identity refuses instead of guessing.
  - Age comes only from a matching authoritative date or committed first-seen.
  - Raw request, stored identity, and log truncation are separate.
  - Explicit refusal on an unknown tag before any new row is written.
  - Incompatible old writers and readers are stopped. Rollback uses a compatible binary or a backup, not deletion.
- Verification property:
  - 'Distinct artifacts never share a policy key; aliases of one artifact always do.'
  - 'A new variant never inherits another variant's age.'
  - 'An old binary refuses new-ecosystem rows rather than mapping them to npm.'
  - Old rows are unchanged after upgrade.
- Witness: per-family fixtures and a reopen test.

### T7: Per-adapter origin, redirect, token, parser, and fail-open filtering (High; tiers: structural, manual)
- Mechanism:
  - Metadata-driven URLs enlarge egress authority:
    - NuGet resource URLs.
    - Cargo dl/api.
    - Go sumdb and proxy.
    - Maven repository fallback.
    - OCI token realm from an upstream WWW-Authenticate header.
  - Credentials follow a redirect or a realm to an off-origin host.
  - GOPROXY comma/pipe, or any other fallback, retries the origin after a refusal.
  - Hostile bytes cause exhaustion:
    - Ruby Marshal.
    - Maven XML external entity or DTD.
    - zlib/gzip bombs.
    - Deep or huge indexes.
    - Slow bodies.
  - Parser or filter failure returns the unfiltered upstream bytes (fail-open).
- Asset: egress confinement, caller credentials, zero bytes after denial, availability.
- Design evidence: 03 origin sentence, 'Candidate discovery', and the RubyGems paragraph.
- Mitigation:
  - Each family declares its allowed origins as parsed scheme/host/port/path in the registry descriptor or fixed public-source descriptor. Resource URLs and realms outside it are rejected.
  - Redirects are rechecked hop by hop.
  - Credential forwarding is operation-specific and redirect-scoped.
  - Typed bounded parsers with no entity or DTD resolution and no code execution. Size, depth, expansion, and time bounds are set per family.
  - Malformed or unsupported shapes refuse. The fail-closed rule that 03 states for RubyGems must be applied to every family explicitly.
  - After a refusal there is no alternate remote or origin.
- Verification property:
  - 'Every outbound request's parsed origin is in the declared set.'
  - 'A credential never leaves its registry and realm.'
  - 'Metadata that cannot be filtered is refused, not passed through.'
  - Hostile corpora finish within bounded memory and time.
- Witness: per-family origin traces from native clients and adversarial fixtures.

### T8: Cluster/containerd routing, no-fallback, and node trust (High; tiers: manual, decision)
- Mechanism:
  - A node runtime is not routed through the enforcer, or a registry-specific host override or mirror routes around it.
  - The runtime retries the origin on a denial or on service outage.
  - Pod NetworkPolicy is mistaken for host-runtime egress control.
  - The bootstrap image pull depends on the enforcer itself.
  - An arbitrary `ns` namespace requests an unconfigured registry.
  - Storage failover, or a second replica, allows two store owners.
  - Cached images skip the enforcer, which the design accepts as having no execution-time revocation.
- Asset: refusal effectiveness and store integrity.
- Location: deploy/kubernetes, node runtime configuration, the OCI router.
- Design evidence: 02 'Concrete deployment and compatibility proposal'; C1022, C1023; evidence/research-cluster-image-routing.md.
- Mitigation:
  - Use explicit server with pull and resolve capability on every pulling node, reconciling all registry-specific overrides.
  - Host egress allowlist for the runtime.
  - Preload the bootstrap image before enforcement.
  - Resolve the `ns` value only to a permitted configured registry, or use the explicit default OCI registry, otherwise refuse.
  - One Recreate Deployment with a ReadWriteOncePod volume on fenced storage.
  - State the cached-image limit in operations documentation.
- Verification property:
  - 'With a healthy origin, a denied or service-down fresh tag or digest pull yields zero direct runtime-to-origin requests.'
  - 'An unapproved node is refused.'
  - 'An unconfigured `ns` is refused.'
  - 'Two store owners never coexist.'
- Witness: the pinned-runtime run (Slice 26). The routing is a documented candidate, not runtime-verified (C1023).

## Required decisions (non-blocking; a named owner is needed before row closure)
- D1: choose and verify the cluster actual-peer mechanism, namely externalTrafficPolicy Local or equivalent source preservation (T1). Slice 26.
- D2: choose Option A, B, or C for credential-bearing reads and the shared cache (T5). Slice 16, before the cache/store row closes.
- D3: define what counts as an explicit refusal (authenticated response from the bound server only), registry-404 scope, validation-failure handling, and the recovery path from a durable refusal (T3).
- D4: include the OSV generation in the FIX-16-A check, or accept the OSV/blocklist ordering limit with a named owner and explicit approval (T4). Not accepted here.
- D5: state how `registry_private_cidrs` and `target_url` are bounded by enforcer-local policy (T2).

## Omitted threats: 4
Resource exhaustion and policy-update starvation; decision-log injection and identity/secret exclusion; service-key file permissions and credential leakage into logs; accepted residuals (local administrator, C30; native caches and installed code, C23). All four have mitigations in the design: bounded semaphores, secret-excluded sinks, service-owned permissions, and the C30 boundary. They are less likely to change the design than T1-T8.

## Limitations
- Absent source: every source behavior is proposed. FIX-16-A, the gate, and all adapters are unimplemented, and the Slice 16 test matrix is planned.
- The cluster routing candidate and the native OS behavior are unverified at runtime. Hosted native lanes do not replace Desktop-capable machines.
- The accepted limits remain: delayed revocation under C19/C20, cached images, and the local administrator. They are not findings.
- No SMTC source-analysis legs were run, and no packet gap was found. Evidence read: 01 context via the arch/program clarification tables, 02, 03 lines 1-181, 04 rows 16-27, and the five evidence files above.
