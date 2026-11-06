# Slice 2 bounded security recheck — 2026-11-03

Review kind: security

Verdict: **CLEAR**, bounded to the implemented local-service npm metadata/search/audit delta and its connected security boundaries, at Manual tier with supplied focused runtime evidence. No global formal security clearance is claimed.

The fresh review identifies no open vulnerability or specific caller-visible security behavior lacking a source/runtime witness. The previous UNKNOWN conflated incomplete global analyzer coverage with the selected properties. The independent protocol and credential followups supplied with this packet, together with current source inspection and the hash-bound GREEN3 execution, close those selected properties. Global formal analysis remains UNKNOWN; it supplies no safety inference.

Subject: base=8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59; `.scratch/slice-2/final-subject.json` SHA-256 `ce808dc2eac9cae3965829109cd5e3de443eb90b4e412d2d34d7896c27bfc7a6`. Git resolves that base as HEAD. The isolated `slice-source.diff` and supplied baseline distinguish this delta in the dirty checkout; Git reports modifications for registry_routes and the two E2E paths. No source/test edits were made by this review.

| Current path | SHA-256, independently matched before and after inspection |
|---|---|
| src/http/service_registry.rs | 554b70a6d61e8f653667083fe36065fb0d619af791a95a616e066dd5b229f31c |
| src/http/registry_routes.rs | 7d9f4c3cc285f3fc9ac064529cb45e684ed142eaa5b3ac34046287bdfd160bb0 |
| tests/shared_service.rs | 0c2bb3b79851551bc17d3d7b16bf3ad22ee192b0fcdd41248558969252af52ba |
| tests/e2e/fixtures/fakes/main.mjs | d1a8f760f5ebed4a89e04d899fe48ab56be07cad119387480d3cca59dd0d9586 |
| tests/e2e/scenarios/publishing-npm-read.mjs | ff6951112437c06cdfec740e3b55042cf309e855d9006afdee0fea5cb331a2cc |

Findings: none confirmed; no remaining open scoped property.

## Properties

1. **Route authority and policy handoff: closed (Manual).** `service_registry.rs:19-154` checks the actual peer allowlist, healthy storage, active snapshot, selected registry/ecosystem membership and request admission before dispatch. Exact bulk/quick literals alone admit POST; only search admits a query; other npm action routes refuse. `registry_routes.rs:26-76` admits a permit/principal before the token branch and rechecks the principal before response conversion. The OriginalUri check retains the selected `/registry/npm/` prefix; legacy aliases and Basic credentials retain the ordinary policy path. The outer generation authorization precedes response release. Independent protocol followup confirms these connected paths. SMTC receipt R1/R2; supplied runtime R6.
2. **Credential destination and request isolation: closed (Manual plus supplied runtime).** `registry_read.rs:55-137` constructs the current service principal and attaches only this request's bounded Basic/Bearer value. The independent credential followup confirms the fresh principal starts with no read authorization. `token_packument.rs:19-154` accepts canonical GET/Bearer, builds a selected-origin URL, fetches directly, validates package identity, bounds/rebuilds the response, and does not commit metadata. The middleware query refusal makes its write-lease branch unreachable in this service slice. `reqwest_transport.rs:50-140,189-240` admits the destination, disables token-packument redirects and caps the result; named reads use the selected origin and same-origin redirect policy. `npm/mod.rs:232-252,670-830` refreshes service reads before cache use, propagates upstream credential refusal and uses request-reference commit. The independent credential followup additionally inspected that commit's `persist_metadata=false` branch. GREEN3 exercises owner/denied/anonymous reads sequentially, concurrently and after restart, plus redirect and hidden-artifact refusal. SMTC receipt R2/R3/R4; supplied runtime R6.
3. **Search/audit disclosure: closed (Manual plus supplied runtime).** `registry_routes.rs:445-681` uses fixed endpoint mappings and rebuilds search results using only the advertised version present in policy-filtered metadata. `audit_filter.rs:29-210` looks up policy-visible versions, intersects advisory ranges, and emits fixed safe fields rather than upstream free text/URLs. Malformed quick vulnerability reports refuse. Final principal and outer generation checks apply to the prepared bytes. GREEN3 and the supplied prior review establish the sentinels, denied advertised-version, nonempty bulk/quick and native npm assertions. SMTC receipt R1/R2/R5; supplied runtime R6.
4. **Resource bounds and permit lifetime: closed (Manual plus supplied runtime).** The named-read permit precedes bounded `to_bytes` and upstream work; the 30-second timeout covers fetch/filter/recheck and the owned permit is dropped after success, error or timeout. Output collection and rebuilt search/audit results are capped. Audit lookup/concurrency/comparison limits are preserved. The GREEN3 scenario sets exactly one active permit, verifies M+1 input causes no upstream request, rejects oversized output, and exercises deadline/permit recovery. Independent protocol followup and the previous inspected header-limit witness support the connected unchanged middleware. SMTC receipt R2/R3/R5; supplied runtime R6.

## SMTC receipt

Stable session: `sf-slice2-security-recheck-2026-11-03`; root `/home/john/go/src/github.com/postfix/probation`. Each current source command used exact shared shapes and the suffix `--format json --max-tokens 2048 --session-id sf-slice2-security-recheck-2026-11-03`. No secret values were used. Hash/base checks ran before the first project-evidence command.

| ID | Operation / argv operands (shared root and suffix above) | Status and interpretation |
|---|---|---|
| R1 | `smtc file read --root <root> --path src/http/service_registry.rs --start-line 19 --end-line 154 <suffix>` | run; outer ok=true, inner current source; untruncated, no refs. Manual route/handoff witness. Initial whole-file read returned truncated ref-80 (2,563 estimated tokens); narrowed instead of relying on it. |
| R2 | `smtc file read --root <root> --path src/http/registry_routes.rs --start-line <start> --end-line <end> <suffix>` for 26-86,445-545,545-681 | run; outer ok=true, current source; all untruncated, no refs. Manual admission, filtering, bounds and recheck witnesses. |
| R3 | Same `file read` shape for registry_read.rs:55-137, token_packument.rs:19-154, upstream/reqwest_transport.rs:50-125,122-140,165-195,195-295 | run; outer ok=true, current source; untruncated, no refs. Manual request credential and selected destination witnesses. Function-count/fidelity labels do not apply to literal source reads; no graph completeness inferred. |
| R4 | Same `file read` shape for npm/mod.rs:232-252,670-773,773-830 | run; outer ok=true, current source; untruncated, no refs. Manual cache/refetch/refusal/commit selection witnesses. |
| R5 | Same `file read` shape for audit_filter.rs:29-125,125-215; http/mod.rs:135-153; tests/e2e/scenarios/publishing-npm-read.mjs:250-320 | run; outer ok=true; untruncated, no refs. Audit second range clamps at EOF210. Manual fixed-field/bound/runtime-assertion witnesses. Test grep with pattern `concurrent\|restart\|sentinel\|permit\|limit\|timeout\|deadline\|malformed\|denied\|gzip`, path restricted to that scenario, max-results20 returned truncated=true/max_results_hit=true; locator only, never absence evidence. |
| R6 | Native task-input reads: previous security report, prerequisite round-2 clarification, slice-2 execution report, `.scratch/slice-2/e2e-green3.log`, `green3-subject-binding.txt`; independent protocol/credential facts supplied in packet | run; GREEN3 log reports 1 passed/0 failed; binding reports all five final hashes unchanged and exact manifest digest. These are supplied execution/followup evidence, not tests rerun here or SMTC proof. |
| R7 | Prior `sf-slice2-security-2026-11-03` receipt: sinks; protocol-sites; missing-guards; validation-gaps; lifecycle, and supplied doctor outcome | unsupported for deciding global proof: Lossy/Stub, unresolved dispatch, validation coverage0, lifecycle functions0/skipped44; no passing negative inference. Already diagnosed, not retried. Prior exact argv and outer/inner details remain in `slice-2-security.md`. This recheck closes selected literal-path properties by the explicit Manual alternative and focused execution, not by these results. |

Up to five deciding items: verified frozen subject; exact route/method/query mapping; selected-origin request-local credential and cache path; fixed-field policy-visible filtering and bounded lifetime; matching GREEN3 execution. Omitted deciding items: 0.

Not examined: full-repository entry-point inventory and global IFDS/guard/lifecycle proof (unavailable and not asserted); later publishing/account actions, PyPI feature changes, portal approval/issuance internals, database/TLS/dependency internals (outside this bounded delta). Relevant route admission, selected transport, cache isolation and final handoff were followed beyond changed paths.

Out of scope: none identified. Unmodeled surfaces: not assessed against a threat model; none was supplied or received. Omitted findings: 0.

Limitations: Manual review plus supplied focused runtime evidence is not a universal or formal proof. Only the five changed files are hash-bound; connected unchanged source was read at current bytes. The prior global analyzer limitations and separately ongoing molecule/source-verifier repair remain unresolved and must not be represented as passing by this verdict. This security result does not mark the slice complete or waive that independent delivery requirement.

Skipped: heavy suite reruns and unrelated repository surfaces. Risk: global formal/source-verifier capability gaps remain; no concrete open scoped security behavior was identified.
