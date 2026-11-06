# Slice 3 security review

Review kind: security  
Verdict: UNKNOWN  
Bounded manual implementation audit: no concrete vulnerability found in the inspected local-service publishing and unpublish paths. No blocking code finding.  
Subject: base=8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59; frozen manifest `.scratch/slice3/current-subject.json` SHA-256 `200b3c7c4b5271f0ec00b848512020de0f0f5b4afbcc53ee982cd265387fafbb`.

The strict verdict reflects an unproved deciding property, not a discovered defect: the required protocol analysis cannot establish that every reachable service reference DELETE is preceded by successful, exact-identity marker consumption and current destination authorization. The relevant send is `src/http/service_unpublish.rs:103`; the source at lines 94–102 and executable race/refusal tests support that ordering, but the required analyzer reports Stub/Lossy coverage and does not establish it. Likewise, the sink inventory did not provide the relevant action/credential sink for a supported taint trace. This review does not ask for global completeness; these are limits on the scoped guard/credential claims.

## Subject binding

Base resolved with `git rev-parse --verify 8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59^{commit}`. Each file was hashed separately with `sha256sum -- <path>` before analysis and again before this report. Initial hashes matched the initial packet. The parent subsequently rebound the frozen subject: only `src/store/action_leases.rs` changed, from `ecfd0afb22ca054302d06dcd1825494f3845d75d1b55e2d0b61a887a99b04c29` to the value below. SMTC read of lines 126–140 confirmed the expected expensive-test ignore annotation. Final hashes match all 13 manifest entries.

| Path | Verified current SHA-256 |
|---|---|
| src/http/mod.rs | 7037ca2ce12a320a7780d56e1d6f6ed31c4a965988f2c0b88eabf50aa795dd5a |
| src/http/registry_routes.rs | c8517acd7eb33f93b48b15a91842c6610669b2e0481870626d0ca68e2c5f744b |
| src/http/service_registry.rs | 60a29c429bc434a7f02e399e8d995d591de5ff0a3749e405833ff49afddfb748 |
| src/http/service_unpublish.rs | 0c49a83b5d1e54edef99a5da501bf246156acb0f2c70907325a0cfac59143301 |
| src/http/unpublish_reference.rs | f6c3fdf0cbfcbaea88cc207a1bdaab9a14f2b0bb5edb6ae04dedf8f066dd72ca |
| src/store/action_leases.rs | 3954dee041bf31dd476a5394b41312794ac823a58ada9a20a5dedda8a2c9caa5 |
| tests/service_unpublish.rs | 310416f5662fd72b00d066b65c78bafbef0ef79e20ebe7d55ca67daaf3eda95f |
| tests/shared_service.rs | 5f28df4ae71a5f0ccdda36965a3516bdc916e15e2c08a5b72c0a4b62a64a9a30 |
| tests/e2e/fixtures/fakes/main.mjs | 345c1b125d563ad26ccee3d36b84d6159ec6ed81e09a6b884be3f09fed04806b |
| tests/e2e/scenarios/publishing-npm-actions.mjs | 1e518f5ec1b9a6420506aa889cba6f2a4b2bad3e44b35cb0d9076df5a0e12d89 |
| tests/e2e/scenarios/publishing-npm-read.mjs | 3e98e09daea01e2a2e4329bd43a6c2dbb4c5350b1b6c9271c8cd6f03c02a206b |
| tests/e2e/scenarios/publishing-npm-actions-issuer.mjs | 8ce741e58804f8107d00e2566ad3c27b8e634f9ed33112afb16cd23df5816e11 |
| tests/e2e/scenarios/publishing-full-matrix.mjs | 83eb1524009aa86056c156836f3670931b1662adf9523a2f3ed2ba3cbecfb051 |

Git raw/status checks showed ordinary 100644 modifications for tracked product files and untracked new `service_registry.rs` and `service_unpublish.rs`; no renamed/deleted product subjects. The existing dirty checkout is not represented as one clean branch delta.

## Findings and evidence

Findings: none reproduced or source-established. Omitted findings: 0.

1. **Admission and credential authority — Manual plus supplied runtime witnesses.** `service_registry.rs:19` checks peer admission, usable store, active service policy, selected registry and admission budget before dispatch. `registry_read.rs:119` attaches only the request's package-manager credential; `service_policy.rs:414` supplies no registry credential. `registry_action.rs:209` permits only enumerated login/actions and checks appropriate Bearer/Basic form. Upstream decides package authorization. No policy API key path to the action request was found.
2. **Service namespace and exact destination — Manual.** `unpublish_reference.rs:26` uses distinct service AAD, `lease_owner` uses member 0, and non-service member 0 is refused. SQL lookup/mark/consume predicates bind registry/member/reference. `artifacts/reference.rs:43` hashes package/version/filename/full URL/integrity; `compute_in_registry` adds registry identity. `service_unpublish.rs:73` rechecks registry, member, reference, filename, package validity, current policy and decrypted URL. `approve_deletion_scope` rejects other origins in service mode even if historical scopes permit bearer forwarding; exact URL/query remains sealed and only revision path segments are appended.
3. **Marker provenance, partial write and one use — Manual plus supplied runtime witnesses.** `service_unpublish.rs:28` accepts only a successful removal response with a valid revision, or a selected-origin authenticated GET proving exact package, valid revision and removed versions absent. Failed/malformed/inconsistent verification cannot commit a marker. The transactional `mark_removed` rejects disappeared/already-marked leases. `consume_marker` performs a conditional SQL UPDATE including revision, expiry and consumed=0; the caller awaits success before send. Concurrent/replay/restart and partial-write cases are exercised by the inspected focused/E2E tests.
4. **Credential-bearing transport — Manual plus selected E2E witness.** `reqwest_transport.rs:162` and `:215` select a client with redirects disabled, admit the URL before I/O, attach only explicitly supplied credential, and cap responses. The builder disables proxies and uses the guarded DNS resolver; origin construction checks literal IPs, HTTPS, credentials and prefixes. DNS answers must be public or explicitly policy-allowed CIDRs. Canonical direct tarball DELETE is refused by service classification and route handler; whole-package revision DELETE remains an explicitly authorized upstream action.
5. **Approval ownership and resource bounds — Manual plus quota witness.** Following the custom deletion-scope approval beyond the slice found `portal/registries.rs:75` calling signed-in POST, org-place and org-admin checks before a registry/org-bound SQL write. `organisation.rs:196` requires second factor and org admin; `Portal.signed_in_post` uses the existing posted-session path. The consumer uses current descriptor scopes. Lease quota updates occur transactionally; supplied actual-cap test verifies unchanged whole-row fingerprints after refusal at 20k/100k/1m limits.

The service is intentionally a shared trust domain without individual caller identity. A caller who knows a pending reference/revision can consume it with a credential the upstream rejects. The parent confirmed consume-before-I/O, including denial, as the approved at-most-once contract; it is not reported as an authorization bypass. A retry must not silently reset a consumed marker.

## Properties

| Scoped security property | Status | Evidence / receipt |
|---|---|---|
| Request-local credentials and selected-upstream authority; no route alternative bypass | unknown formally; no defect found manually | R1, R3, R5, R6; source evidence 1/4; E2E allow/deny/no-I/O cases |
| Service lease isolation, sealed exact destination, path/query/DNS/redirect restrictions | unknown formally; inspected guards agree with contract | R3, R5, R6; source evidence 2/4; E2E selected/custom/foreign/redirect cases |
| Accepted-removal provenance and failure withholding marker | unknown formally; focused cases pass | R2–R4, R6; source evidence 3 |
| Successful exact-identity consumption dominates outbound DELETE; no replay/race second send | unknown formally; atomic SQL/source and tested races support claim | R2/R3/R6/R7; precise unresolved claim stated above |
| Scope approval is recorded by authorized org admin and current scope is checked | unknown beyond inspected boundary | R3/R6/R8; source evidence 5; underlying tenancy/session implementation not fully re-audited |

## Executable evidence supplied by the implementing agent

These logs were read directly as build/test inputs; this reviewer did not rerun or produce them:

- `.scratch/slice3/green-service-removal3.log`: 2 passed, 0 failed; inspected test covers revision response, authenticated fallback, unavailable/retained/bad revision/malformed/denied/unchanged/marker-failure plus concurrent DELETE/replay/outbound counts.
- `.scratch/slice3/check-removal.log`: workspace compile finished successfully.
- `.scratch/slice3/e2e-actions-full1.log`: 1 passed, 0 failed, 0 not run, 55.0 seconds. The reviewed scenario source additionally asserts credential isolation, direct-route no I/O, native npm unpublish, durable restart/races, denied DELETE consumption, redirect refusal, selected custom signed query, and historical extra-origin refusal.
- `.scratch/slice3/quota-production.log`: actual production-cap test passed, 553.09 seconds. Parent attests only the ignore annotation changed afterward; test body unchanged.

These are bounded execution witnesses. They are not an SMTC verification certificate or a proof over untested control-flow paths.

## SMTC receipt

Repository root for every rooted command: `/home/john/go/src/github.com/postfix/probation`. Session: `sf-slice3-security-2026-11-03`. No native project-source read/search fallback was used. Native reads were limited to supplied packet/protocol and build/test logs. No raw analyzer payload is used as a clean verdict.

**R1 — entry points, run.**

```text
smtc analyze entry-points --limit 5 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

Outer ok=true; inner analyzed_clean=false/verified_clean=false; 5/23 entries shown, 2332 unresolved dispatch sites, providers js-express/rust-main, omitted test files 117. No ref. Interpretation: incomplete inventory; Axum dispatch boundary was established separately by source inspection, not inferred from inventory absence.

**R2 — protocol-site inventory, run.**

```text
smtc analyze protocol-sites --limit 20 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

Outer ok=true; 20/78 sites, truncated=true, no ref; built-in models mostly generic releases and Axum routing guards. Interpretation: candidate inventory only, no claim that async store/send ordering is modeled.

**R3 — guard ordering, run.**

```text
smtc analyze missing-guards --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

Outer ok=true; inner applicable=true, analyzed_clean=false, verified_clean=false; 7 sensitive operations, no violations; cert_fidelity=Stub, signal fidelity Lossy, heuristic graph, 2219 unresolved holes; no result truncation/ref. Interpretation: UNKNOWN, including the scoped marker-before-send obligation; absence of findings is not clean evidence.

**R4 — persistence validation, run.**

```text
smtc analyze validation-gaps --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

Outer ok=true; inner applicable=false, analyzed_clean=false, coverage=0, no modeled persistence operations; Stub/Lossy, 2219 unresolved holes, no truncation/ref. Interpretation: UNKNOWN for lease/marker persistence validation. No taint/protocol certificate was synthesized from SQL text.

**R5 — source-to-sink inventory, run.**

```text
smtc analyze sinks --limit 5 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

Outer ok=true; 5/869 sinks returned, all shown items unrelated command/test sites; nominal cert_fidelity Honest but completeness signal Lossy, 2219 unresolved holes, heuristic graph. No relevant action sink returned, no deciding ref. Taint/explain legs were not guessed against unrelated sinks. Interpretation: scoped credential-to-action safety remains formally unknown. ProposedNext: `sf-taint-trace` trace request Authorization and stored destination to `src/http/service_unpublish.rs:103 send_action`, and revision verification to marker commit, with supported relevant sink selection.

**R6 — bounded source reads, run, Manual evidence.**

The following exact commands were run; each successful read had outer ok=true, concrete content, no ref or presentation truncation. Some end ranges clamp at EOF; their complete shorter content was returned. Functions analyzed/fidelity: not applicable to file text; no safety proof inferred.

```text
smtc file read --path src/http/mod.rs --start-line 36 --end-line 155 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/mod.rs --start-line 180 --end-line 223 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/service_registry.rs --start-line 19 --end-line 148 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/service_registry.rs --start-line 167 --end-line 250 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/service_unpublish.rs --start-line 1 --end-line 110 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/registry_routes.rs --start-line 1 --end-line 100 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/registry_routes.rs --start-line 275 --end-line 350 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/registry_routes.rs --start-line 380 --end-line 505 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/registry_read.rs --start-line 1 --end-line 125 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/registry_action.rs --start-line 1 --end-line 125 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/registry_action.rs --start-line 125 --end-line 270 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/registry_action.rs --start-line 267 --end-line 345 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/unpublish_reference.rs --start-line 1 --end-line 110 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/unpublish_reference.rs --start-line 110 --end-line 210 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/unpublish_reference.rs --start-line 210 --end-line 305 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/token_packument.rs --start-line 1 --end-line 125 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/http/token_packument.rs --start-line 125 --end-line 160 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/store/action_leases.rs --start-line 1 --end-line 110 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/store/action_leases.rs --start-line 106 --end-line 145 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/store/action_leases.rs --start-line 126 --end-line 140 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/upstream/reqwest_transport.rs --start-line 89 --end-line 134 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/upstream/reqwest_transport.rs --start-line 162 --end-line 250 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/upstream/resolver.rs --start-line 1 --end-line 130 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/upstream/origins.rs --start-line 1 --end-line 100 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/upstream/origins.rs --start-line 94 --end-line 137 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/upstream/origins.rs --start-line 203 --end-line 295 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/artifacts/reference.rs --start-line 1 --end-line 120 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path src/managed/service_policy.rs --start-line 366 --end-line 425 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path tests/service_unpublish.rs --start-line 121 --end-line 230 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path tests/e2e/scenarios/publishing-npm-actions.mjs --start-line 1 --end-line 45 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path tests/e2e/scenarios/publishing-npm-actions.mjs --start-line 46 --end-line 85 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path tests/e2e/scenarios/publishing-npm-actions.mjs --start-line 86 --end-line 125 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path tests/e2e/scenarios/publishing-npm-actions.mjs --start-line 126 --end-line 165 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc file read --path tests/e2e/scenarios/publishing-npm-actions.mjs --start-line 166 --end-line 205 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

A request for `src/http/mod.rs:235–310` had outer ok=true but inner line_range_invalid (223 lines); it was not evidence and was replaced by the bounded 180–223 read. The initial 1–100 E2E read yielded ref-90 (2579 token estimate) and was narrowed to the reads above; ref was not opened. Discovery greps were sometimes truncated or zero-file matches and were used only to locate exact file reads, never as negative safety evidence.

**R7 — named consumption declaration and caller, run.**

```text
smtc search symbol --name-pattern consume_service_marker_then_send --limit 6 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc inspect symbol --handle /home/john/go/src/github.com/postfix/probation/src/http/service_unpublish.rs:93:109 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc callers --name consume_service_marker_then_send --depth 1 --limit 5 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

Search resolved exactly one declaration, start zero-based (92,0); inspect returned one-based lines 93–109. Outer ok=true throughout. Caller result identified `unsupported_artifact_delete` at zero-based line 395, one direct structural edge; 2219 unresolved dispatch sites. Tool host display truncated the verbose caller payload although the command used max-tokens 2048; the decisive source call is independently read at registry_routes.rs:396. No global caller-exhaustiveness claim.

**R8 — recorded scope approval boundary, run.**

```text
smtc search symbol --name-pattern '*delete_scope*' --limit 6 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc inspect symbol --handle /home/john/go/src/github.com/postfix/probation/crates/probation-server/src/portal/registries.rs:69:104 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc callers --name set_delete_scope --depth 1 --limit 5 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc search symbol --name-pattern admin_on --limit 6 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc inspect symbol --handle /home/john/go/src/github.com/postfix/probation/crates/probation-server/src/portal/organisation.rs:186:203 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc search symbol --name-pattern signed_in_post --limit 6 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
smtc inspect symbol --handle /home/john/go/src/github.com/postfix/probation/crates/probation-server/src/portal/mod.rs:833:836 --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-security-2026-11-03
```

Outer ok=true; named set_delete_scope/signed_in_post each resolved uniquely; admin_on exact name/path distinguished from global_admin_on and a test candidate. Inspections returned complete concrete bodies, Manual. Callers returned 0 chains with truncated ref-91 (3414 token estimate); no negative reachability conclusion was drawn. Exact-file grep located the literal POST registration at portal/mod.rs:234. This confirms the observed boundary, not exhaustive tenancy/CSRF correctness.

## Limits and disposition

Not examined: full historical certificate publishing matrix, PyPI publishing, unrelated dirty-checkout changes, broad portal/session/tenancy internals, whole-repository attacks, exhaustive transport/library verification, and deployment filesystem hardening. These are outside this bounded service delta; approval internals that could affect the reviewed custom-scope trust boundary remain explicitly unknown rather than excluded from the verdict.

Out of scope: no non-security defect asserted.

Unmodeled surfaces: no supplied threat model, so the review independently identified service HTTP peers, URI/header/body inputs, upstream metadata/action responses, policy-controlled registry/scope/CIDR descriptors, the admin deletion-scope endpoint, the local encrypted-URL key and lease/marker database, and selected upstream credential-bearing I/O.

Omitted: 0 findings; inventories omit 18 entry points, 58 protocol sites and 864 sink items. Those omitted inventories do not alone block the bounded result; the relevant guard/persistence/taint proof gaps do.

Tier: Manual source inspection with bounded external execution witnesses; one direct caller edge is Structural. No Decision-tier SMTC security certificate.

Limitations: required analyzer cannot witness the scoped async ordering or relevant persistence/sink semantics; supplied doctor input says diagnostics are unavailable due rust-analyzer didOpen failure. Compiler evidence is recorded separately. No fixes, new tests, broad suite run, secret values, or source/model/spec edits were made.

Prerequisite for a strict CLEAR under this review protocol: a supported scoped protocol/taint check (with a positive unsafe control) that witnesses current scope/marker consumption before the actual send, or an explicitly accepted verification method replacing that unavailable proof. The parent owns that checker investigation.

