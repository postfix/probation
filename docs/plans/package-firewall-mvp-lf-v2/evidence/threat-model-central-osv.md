# Central OSV threat model (C1030, row 30, sf-threat-model, 2026-11-17)

Verdict: UNKNOWN. Blocking finding: B1 (credential for /osv undefined and contradicts C1021 and the sync auth class). Evidence tier: manual design review of the packet plus read-only reading of existing code (src/osv/mod.rs, src/osv/batcher.rs, src/lib.rs App::start, crates/probation-server/src/sync.rs). Source claims about row 30 code are proposed, not verified. This report extends evidence/threat-model-shared-service-r2.md (MODELED) and does not change it. C1024 and C1029 are honored.

## Scope
New threats from: the policy server's osv.dev-compatible POST /osv/v1/querybatch (crates/probation-server/src/osv.rs), and managed or shared-service endpoints that route OSV lookups through it by changing only the OsvClient base URL and adding a credential.

## Entry points
- POST /osv/v1/querybatch on the policy server (body: queries[]).
- Endpoint to server HTTPS call from OsvClient's batcher (credential header, base URL derived from [management] or [service_policy]).
- Server to api.osv.dev (fixed host) upstream client and shared cache.
- AppDeps::osv_base_url test seam; App::start OSV wiring (src/lib.rs lines 304-327).

## Trust boundaries
1. Endpoint to server route (credential kind, host, TLS, redirects).
2. Request body to upstream query (shape, size, ecosystem, host choice).
3. Server to api.osv.dev (egress budget, answer integrity).
4. Shared cache across tenants and credentials.
5. Server answer to endpoint verdict, then to C1029 generation and FIX-16-A gate.
6. Managed config to actual OSV network path (no direct fallback).
7. OSV route budget to the policy sync routes on the same server.

## Assets
- OSV protection is not silently lost.
- Credential secrecy (fleet token, service key).
- api.osv.dev egress quota and reputation.
- Confidentiality of which packages (possibly private names) each tenant queries.
- Verdict integrity (no forged or misaligned MAL- matches).
- Policy-sync availability (revocation propagation, C19/C20).

## Threats (eight displayed, omitted 0)

### T9-1: Wrong or undefined credential class on /osv (BLOCKING B1; High; tier: decision)
- Mechanism: see B1. The sync authenticator accepts only `fwt_` tokens, with source-CIDR checks. The design says the service key may also call it, but C1021 limits that key to policy retrieval. An implementer either widens the key's authority silently, or the shared-service mode gets permanent 401 and fails open.
- Also: if both kinds are accepted, the per-credential limit and the source-CIDR admission must exist for both. The service key has no `allowed_source_cidrs` today.
- Asset: credential scope; OSV availability in shared-service mode.
- Location: crates/probation-server/src/osv.rs, sync.rs (`firewall`), service_policy.rs key lookup.
- Mitigation: decide (a) amend C1021 and add a service-kind-only extractor for /osv (kind=service, live, org-scoped, read-only), or (b) a separate OSV credential. The route accepts a closed set of credential kinds, and user-kind keys are refused. State the admission (source CIDR or the listener allowlist) for each kind.
- Verification property: "the /osv handler runs only for a live firewall token or live service-kind key; user-kind, revoked, wrong-kind and missing credentials get 401 before any cache read or upstream call". Test: osv_route_requires_authentication, extended with those four cases plus a service-key positive case.
- Owner: row 30; the C1021 amendment needs the user.

### T9-2: Credential sent to the wrong host, over plaintext, or on redirect (High; tiers: structural, manual)
- Mechanism:
  - The base URL is derived from config plus "/osv". `AppDeps::osv_base_url` wins when set, and the injected `reqwest::Client` carries whatever redirect and proxy policy it was built with.
  - Plain reqwest strips only a fixed set of sensitive headers on cross-host redirects. A custom header name is not stripped.
  - An http:// server_url, or a redirect from a compromised or misconfigured server, delivers the fleet token or service key to another host.
  - If the OSV client is built on the same client as the policy client, the key crosses boundaries (T2).
- Asset: fleet token and service key secrecy.
- Location: src/lib.rs OSV wiring, src/config.rs derivation, src/osv/batcher.rs send.
- Mitigation:
  - Attach the credential only when the target origin (scheme, host, port) equals the configured server origin, decided once at construction.
  - Require https for a managed base URL. Only the test seam may be plain http, and the credential is never attached there.
  - Use a dedicated OSV client with redirects disabled (Policy::none) and mark the header sensitive.
  - Never reuse the registry transport or the policy client.
  - Build the URL by pushing path segments, not by string concatenation or Url::join (a base path without a trailing slash silently drops "/osv").
- Verification property: "the credential never appears on a request whose origin differs from the configured server origin, including after a 3xx". Tests to add: osv_credential_not_sent_on_redirect, osv_base_url_requires_https_in_managed_mode, osv_test_seam_never_carries_credential.
- Owner: row 30.

### T9-3: Relay, SSRF and query-shape abuse (Medium; tier: structural)
- Mechanism:
  - "osv.dev-compatible" invites passing the body through. osv.dev's schema also accepts `commit`, `package.purl`, `page_token`, a missing `version` (returns every vuln for the package), and arbitrary ecosystems.
  - Passed through, that turns the route into a general relay: unbounded result sizes, cache-key explosion, and an unbounded key space.
  - The host cannot be chosen by the body (the design's own invariant). The remaining risk is a future `purl` or URL-shaped field.
- Asset: egress quota, memory, host integrity.
- Location: crates/probation-server/src/osv.rs request parsing.
- Mitigation:
  - A typed request with `deny_unknown_fields`.
  - Only package.name, package.ecosystem and a required version are accepted.
  - The ecosystem is an allowlist (npm, PyPI now; each later family only when its OSV mapping is delivered).
  - Length and charset bounds per field.
  - Maximum batch size ≥ the client's OSV_BATCH_RECORDS (256) and ≤ 1000. A 2 MiB-class body cap must not be inherited from sync, so set a smaller one.
  - Count the body limit before parsing.
  - Server upstream reads use a counted, capped loop (not `response.bytes()`) and a bounded serde depth.
  - The server re-renders its own minimal answer (MAL- ids only, bounded count) and never streams upstream bytes through.
- Verification property: "no request field, header or query parameter reaches the upstream host, path or query beyond the validated name, ecosystem and version; the only upstream host is api.osv.dev". Tests to add: osv_route_rejects_unknown_fields_commit_purl_page_token_and_versionless; osv_route_rejects_unlisted_ecosystem; osv_upstream_response_is_size_capped.
- Owner: row 30.

### T9-4: Amplification toward api.osv.dev, rate-limit starvation and cache exhaustion (High; tiers: structural, decision)
- Mechanism:
  - The existing per-firewall limit counts requests (FIREWALL_TOKEN_RATE_PER_SECOND = 200, sync.rs:38), not queries. One request carries up to 1000 unique cache-missing keys. A valid credential holder can drive about 200k upstream keys a second, getting the whole fleet's server IP throttled or banned by osv.dev (a fleet-wide fail-open).
  - If /osv reuses the same per-firewall window as lookup, layers and changes (sync.rs:231-259), an OSV burst makes `changes` return 429 and delays revocation propagation (C19/C20).
  - `firewall()` runs a database query before the rate check, so an invalid-token flood costs one database round trip each.
  - Cache exhaustion: unique garbage keys fill a bounded LRU and evict real entries, and negative entries evict MAL matches. An eviction combined with an upstream failure is then a downgrade.
  - One tenant draining a single global upstream budget starves all tenants.
- Asset: osv.dev egress standing, policy-sync availability, the cache, fairness.
- Location: crates/probation-server/src/osv.rs (OsvLimits, OsvState), sync.rs rate table.
- Mitigation:
  - A separate OSV budget that never shares the sync window. Charge cache-missing keys, not requests, per credential, and give each credential a fair share of a global upstream key budget.
  - A bounded global upstream concurrency, plus honoring upstream 429 or Retry-After with a circuit breaker. Do not retry in a loop.
  - A pre-auth failure throttle (per source address), or a short positive auth cache.
  - A cache bounded by entries and bytes, with key validation (T9-3), with matched entries kept preferentially (a segmented or protected set), and stale-if-error for matched entries.
  - Cache hits do not draw on the upstream budget.
- Verification property: "a credential cannot cause more upstream keys per interval than its budget, however the keys are batched; an OSV flood never changes the status of a sync route for the same credential; garbage keys cannot evict a live matched entry". Tests: osv_batch_limits_refuse_oversize_and_rate_limited extended with a key-budget case; osv_flood_does_not_429_sync_routes; osv_garbage_keys_do_not_evict_matched; osv_upstream_429_opens_breaker.
- Owner: row 30. Decision D-OSV3: the numeric budgets (owner row 30 implementer, approved with the row).

### T9-5: Cache poisoning and a malicious or misaligned answer (High; tiers: structural, manual)
- Mechanism:
  - The server builds upstream batches from several tenants' keys. If results are mapped to keys by index and the upstream answers a different count, or the order differs, tenant A's verdict is stored under tenant B's key.
  - One tenant's malformed query makes osv.dev reject the whole combined batch (4xx). If every key in it is then cached as no-match, other tenants' keys are poisoned (fail-open by batch-mate).
  - Failure results cached with the same TTL as confirmed answers hold a downgrade open past the outage.
  - TTL stacking: client negative TTL (30 s, OSV_NEGATIVE_TTL) plus an unspecified server TTL lengthens the window before a newly published MAL- package is denied beyond today's.
  - A compromised server, or a TLS-stripped path, can hide a MAL- match (equivalent to fail-open) or fabricate one (denial of service of a chosen package). Fabrication is inherent to the trust in the server, which already holds policy authority. It is accepted as such, with the transport controls of T9-2.
  - The cache is filled only from upstream, never from request bodies; the design must state this.
- Asset: verdict integrity, freshness.
- Location: crates/probation-server/src/osv.rs (batch assembly, cache), src/osv/batcher.rs (client side).
- Mitigation:
  - Store a result only after `results.len() == queries.len()`; on mismatch store nothing.
  - On an upstream 4xx for a combined batch, split and retry per key (or per tenant sub-batch) so a bad key fails alone.
  - Never cache a failure as a no-match (or only for a tiny TTL ≤ the client's 30 s). Failures are not stored in the confirmed-answer cache.
  - The server no-match TTL is ≤ OSV_NEGATIVE_TTL, stated as a design value. The matched TTL is ≥ the client's.
  - The endpoint adds a response body cap and keeps its length check.
- Verification property: "a stored verdict always comes from the upstream result whose index equals the key's index in a length-validated response; one tenant's invalid query never changes another tenant's answer; no request body writes the cache". Tests: osv_misaligned_upstream_response_stores_nothing; osv_bad_key_in_mixed_batch_does_not_fail_other_keys; osv_failure_not_cached_as_confirmed_no_match; response_shape_matches_osv_dev_golden.
- Owner: row 30. Accepted residual: a compromised policy server can forge OSV answers (same trust as policy; named owner: the policy-server operator).

### T9-6: Cross-tenant disclosure of queried package names (Medium; tier: decision)
- Mechanism:
  - The shared cache is keyed (ecosystem, name, version) only (T9 row). A tenant that probes `acme-internal-x@1.0.0` can tell from latency or from coalescing that another tenant asked recently. That confirms another tenant's private package names (C1024 allows private registries).
  - The server now collects every tenant's queries, so logs, metrics and error bodies that echo keys give the operator and any log reader the cross-tenant list.
  - Names of private packages are also forwarded to api.osv.dev. This already happens today per endpoint. It is not new, but it is now aggregated.
  - Coalescing: a waiter cancelled or failed for tenant A must not cancel or fail the in-flight call for tenant B.
- Asset: confidentiality of tenant package inventories.
- Location: crates/probation-server/src/osv.rs, logging.
- Mitigation:
  - Option A (preferred): keep matched entries shared (public MAL data) and scope no-match entries per organisation, or per credential.
  - Option B: keep one shared cache and record a named, approved accepted risk for the timing oracle.
  - Either way, no per-key logging. Counters are aggregate only. Error bodies never echo queries.
  - The coalesced upstream call outlives any single waiter.
- Verification property: "no observable response field or status distinguishes a key another tenant queried from one nobody queried (Option A), and no log line or metric label contains a queried name or version". Tests to add: osv_cache_miss_and_hit_indistinguishable_across_orgs (Option A), osv_logs_contain_no_query_keys, osv_cancelled_waiter_does_not_fail_coalesced_peer.
- Decision D-OSV2: choose A or B (not yet stated in the design; named owner needed before row 30 closes).

### T9-7: Fail-open downgrade made invisible (High; tiers: structural, manual)
- Mechanism:
  - Every failure (401, 403, 404, 413, 429, 5xx, timeout, bad body, length mismatch) answers no-match. That is the accepted C3/C14 policy.
  - But `flush` records an HTTP 4xx as "reached" (batcher.rs:181-186: `err.status().is_some_and(|s| !s.is_server_error())`). That rule was right for api.osv.dev. Against the server, a revoked or wrong-kind token (401/403), a rate limit (429) and an oversize batch (413) show OSV as healthy while every lookup fails open.
  - The server answers `{}` for an upstream failure, so the endpoint also sees a healthy 200.
  - Skew: if the server's batch cap is below the client's 256 batch, every full batch fails permanently.
- Asset: truthful readiness and decision records; OSV protection.
- Location: src/osv/batcher.rs (reached computation), src/managed/report.rs UpstreamHealth, crates/probation-server/src/osv.rs.
- Mitigation:
  - In managed mode only a 2xx counts as reached; 401, 403, 404, 413 and 429 count as not reached.
  - The server marks a degraded answer, for example with a response header the batcher reads. Do not use 5xx, which the design reserves for non-upstream faults.
  - Server health counts upstream failures.
  - Server batch cap ≥ OSV_BATCH_RECORDS, enforced by a shared constant or test.
  - The fail-open meaning is unchanged (no deny), and C3/C14 stays as accepted.
- Verification property: "an endpoint whose /osv call returns anything other than a non-degraded 2xx reports OSV as not reached in its upstream health, and its fail-open answer is never cached longer than OSV_NEGATIVE_TTL". Tests: osv_unauthorized_or_limited_marks_upstream_unreached; server_upstream_failure_answers_no_match_and_counts (existing, extended to assert the degraded marker); osv_server_batch_cap_not_below_client_batch.
- Owner: row 30.

### T9-8: Managed endpoint silently falling back to direct api.osv.dev (High; tiers: structural, manual)
- Mechanism:
  - `App::start` today calls `OsvClient::new` (fixed api.osv.dev) whenever `osv_base_url` is None. A managed configuration whose derivation fails, or an unset base URL in a new code path, takes that arm and leaks every query directly.
  - The injected `osv_client` and `unreachable_client()` must not mask this in tests.
  - The proposed test `managed_endpoint_sends_no_request_to_osv_dev` runs only while server queries succeed. It would not catch a fallback on server error.
  - Environment proxy variables are outside this threat.
- Asset: the "managed endpoints make no api.osv.dev calls" invariant; tenant privacy.
- Location: src/lib.rs OSV match arm, src/config.rs, src/osv/mod.rs.
- Mitigation:
  - In managed or shared-service mode the `None` arm is unreachable: config validation yields a base URL, or startup fails.
  - `OsvClient::new` (the fixed-host constructor) is callable only from the standalone arm, structurally (a type or a cfg), and has no managed caller.
  - There is no configuration key, environment variable, or retry that selects direct OSV on a server error.
- Verification property: "in managed and shared-service mode no code path constructs or sends to the api.osv.dev endpoint, including when the server returns 401, 429, 5xx, times out, or is unreachable". Tests: managed_endpoint_sends_no_request_to_osv_dev extended with the failure cases (server 401, 429, 500, refused connection, timeout); managed_config_has_no_direct_osv_key; standalone_still_queries_osv_dev_directly; a structural check that the managed arm cannot call the fixed constructor.
- Owner: row 30.

## Decisions required
- D-OSV1 (B1, blocking): credential for /osv (T9-1). Owner: user (C1021 amendment) then row 30.
- D-OSV2: cache scope for no-match entries, or accepted timing oracle with named owner (T9-6). Before row 30 closes.
- D-OSV3: numeric budgets, TTLs (no-match ≤ 30 s), batch cap, body cap (T9-3, T9-4, T9-5). With row 30.

## Limitations
- Absent source: every row 30 behavior is proposed. Existing code was read only to ground the mechanisms.
- Model gap: the design states no molecule or model covers the route (03 "Model note"); the named runtime tests are the only witnesses.
- Whether the policy server's existing route stack can host the new auth classes was not examined beyond sync.rs. The policy-snapshot route's service-key lookup was not read.
- Accepted: C3/C14 fail-open on upstream outage, and compromised-policy-server forgery (same trust as policy).
- No SMTC source analysis was run. No document or code was changed.

## Resolution (main agent, 2026-11-17; appended after the sub-agent report above, which is unchanged)

- B1 / D-OSV1 resolved by the user: `/osv/v1/querybatch` accepts a live firewall token or a live service-kind key; C1021 is amended; user-kind, revoked and missing credentials get 401.
- D-OSV2 resolved by the user: one shared cache; a cache hit showing that some user or org asked is not treated as a risk (T9-6 dropped); no per-key logging stays.
- D-OSV3 set in 03: server degraded deadline 300 ms, managed client timeout floor 400 ms, stale matched window default 24 h (floor 1 h, ceiling 7 d); other budgets set by row 30 and approved with it.
- C1031 (user): known matches survive a server outage via stale-if-error; no direct fallback.
- T9-2 to T9-8 requirements and tests are carried into 03 "Central OSV lookup". Resulting status: no blocking finding remains; verdict MODELED with the decisions above.
- Persisted matches file (C1031, added after the sub-agent report): a local file under the endpoint data directory. Threats: tampering or a corrupt file hiding matches (an attacker with local write already controls the endpoint; same trust as the policy cache), oversize or malformed content blocking startup, and information exposure. Controls: size and entry bounds on load and write, owner-only mode, atomic replace, corrupt or oversize loads empty with a health warning and never blocks startup, no secrets stored (only ecosystem, name, version, expiry). Witness: `osv_matches_file_corrupt_loads_empty_and_does_not_block_startup`.
