# Slice 2 independent security review

Review kind: security

Verdict: UNKNOWN

The bounded manual review found no confirmed security vulnerability in the implemented local-service npm routing delta. Matching runtime evidence supports the intended boundaries. The required automated security properties remain unknown because their deciding recipes report incomplete coverage; this is not a formal or global security clearance.

Subject: base=8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59; frozen manifest `.scratch/slice-2/final-subject.json` SHA-256 `ce808dc2eac9cae3965829109cd5e3de443eb90b4e412d2d34d7896c27bfc7a6`.

| Current path | SHA-256 verified before and after review |
|---|---|
| src/http/service_registry.rs | 554b70a6d61e8f653667083fe36065fb0d619af791a95a616e066dd5b229f31c |
| src/http/registry_routes.rs | 7d9f4c3cc285f3fc9ac064529cb45e684ed142eaa5b3ac34046287bdfd160bb0 |
| tests/shared_service.rs | 0c2bb3b79851551bc17d3d7b16bf3ad22ee192b0fcdd41248558969252af52ba |
| tests/e2e/fixtures/fakes/main.mjs | d1a8f760f5ebed4a89e04d899fe48ab56be07cad119387480d3cca59dd0d9586 |
| tests/e2e/scenarios/publishing-npm-read.mjs | ff6951112437c06cdfec740e3b55042cf309e855d9006afdee0fea5cb331a2cc |

Git resolved the base commit. Git raw delta reports regular-file modifications for registry_routes and the two E2E files; the frozen baseline/delta identifies service_registry and shared_service changes in this dirty checkout. Review used the supplied isolated delta, not all changes since Git base.

Findings: none confirmed.

Properties:

1. **Authority and alternate routes: unknown automated; manual witnesses support closure.** `service_registry.rs:19-154` preserves socket peer allowlisting, usable storage, snapshot membership, request admission and generation-based final handoff. POST is admitted only for the two literal npm audit endpoints; non-search queries and unnamed npm action routes refuse before dispatch. `registry_routes.rs:26-76` restricts the new token exception to an original selected npm URL with admitted Bearer authorization. Legacy, version and artifact routes retain ordinary policy paths. Receipt R1/R2/R4/R5.
2. **Credential destination and private metadata isolation: unknown automated; manual witnesses support closure.** `token_packument.rs:19-154` requires canonical GET and Bearer input, builds the selected origin URL, performs a fresh transport call, validates the returned package identity and rewrites tarballs. This function does not persist metadata; the write-lease branch is unreachable through the changed query gate. `reqwest_transport.rs:94-116,215-240` disables redirects for this token request, admits the URL and caps response bytes. Ordinary service metadata at `npm/mod.rs:232-245` always refetches before consuming shared cache; upstream denial at lines 761-762 refuses. These selected reads establish a manual witness, not complete taint proof. Receipt R1/R3/R6.
3. **Search/audit disclosure: manual closed for inspected mappings; automated provenance unknown.** `registry_routes.rs:445-681` selects fixed named upstream routes, obtains the selected principal, rebuilds search hits only from the advertised version in policy-filtered metadata and rechecks authority. `audit_filter.rs:29-210` obtains currently policy-visible versions, intersects advisory ranges and rebuilds fixed safe fields, discarding arbitrary upstream advisory text/URLs/metadata; malformed quick vulnerability reports fail closed. Receipt R1/R3/R6.
4. **Bounds and permit lifetime: unknown automated; manual/runtime witnesses support closure.** Headers are bounded by `http/mod.rs:141-149`; named requests cap input/output with metadata limits and one 30-second timeout covering fetch/filter, and drop the owned permit after completion/error. Audit filtering caps distinct lookups (1,024), concurrency (16) and comparisons (8,192). Runtime tests exercise refusal and timeout permit release. Receipt R1/R7.

Up to five deciding evidence items:

- Frozen manifest/current hashes were verified at start and end; base exists. No product or test source was changed by this review.
- SMTC exact current source reads covered service_registry 1-155; registry_routes 1-150,260-400,445-681; registry_read 1-137; token_packument 1-154; audit_filter 1-210; http/mod 25-160; reqwest_transport 50-125,195-295; npm/mod 232-252,670-773.
- SMTC search/inspect resolved `serve_token_packument` at zero-based (35,0), handle `/home/john/go/src/github.com/postfix/probation/src/http/token_packument.rs:36:45`; callers reported the registry package route with structural confidence, while exposing 2,182 unresolved workspace dispatch sites.
- Supplied `.scratch/slice-2/e2e-green3.log` reports the matching scenario PASS, 1 passed / 0 failed; `green3-subject-binding.txt` binds all five final hashes. Inspected scenario assertions include denied/absent/concurrent/restarted token isolation, legacy/version/artifact denial, redirect refusal, filtered search/audit sentinels, comparison/lookup caps, malformed responses, unsupported routes and deadline permit release. This review did not rerun the suite.
- Supplied `.scratch/slice-2/shared-service-green-2.log` reports 4 passed / 0 failed including selected/legacy authority changes, raw scoped tarball selection and publication handoff.

Tier: Manual for scoped security conclusions; Structural for the reported caller edge. No executable security certificate was claimed.

## SMTC receipt

Stable session: `sf-slice2-security-2026-11-03`. Root: `/home/john/go/src/github.com/postfix/probation`. All question-specific commands used `--root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice2-security-2026-11-03` (suffix abbreviated as `<flags>` below). No secret values were passed. Source reading/search was performed only with SMTC; native reads were limited to supplied task/runtime artifacts and Git/hash state.

| ID | Operation / redacted argv | Execution and status | Fidelity, completeness and interpretation |
|---|---|---|---|
| R1 | `smtc file read --path <path> --start-line <start> --end-line <end> <flags>` for the exact source ranges listed above; `smtc file grep --pattern <routing/credential/bound identifier> --path-include <connected source/test path> --max-results 20 <flags>` | run; outer ok=true; reads returned current source | Manual evidence. Initial whole service file and a 111-line E2E range returned refs/truncated; narrowed to bounded ranges. Source reads used for conclusions were inline/untruncated; clamped at EOF where declared. One upstream glob matched zero files and was corrected to `src/upstream/**`; no absence inference. Shared-service broad grep truncated and was used only for candidate location. |
| R2 | `smtc inspect file --path src/http/registry_routes.rs --limit 5 <flags>` | run; outer ok=true; 5 declarations, ref-67, truncated | Inventory locator only, not deciding negative evidence. Followed by bounded reads. |
| R3 | `smtc analyze sinks --limit 5 <flags>` | run; outer ok=true; 5/856 sinks, unrelated test commands | cert_fidelity=Honest but signal=Lossy, call graph Heuristic, 2,182 unresolved holes, completeness aggregator absent. This cannot establish scoped credential flow. No unrelated test sink was traced merely to manufacture evidence. |
| R4 | `smtc analyze protocol-sites --limit 20 <flags>` | run; outer ok=true; 20/78 sites; truncated | Partial workspace locator. Does not establish all relevant guarded routes. |
| R5 | `smtc analyze missing-guards <flags>`; `smtc analyze validation-gaps <flags>` | run; outer ok=true; inner analyzed_clean=false / verified_clean=false | Missing guards: Stub/Lossy, 7 sensitive operations, 2,182 unresolved holes. Validation gaps: Stub/Lossy, coverage=0, no persistence operations modeled. Neither weak negative closes the relevant property. |
| R6 | `smtc search symbol --name-pattern serve_token_packument --limit 6 <flags>`; `smtc inspect symbol --handle /home/john/go/src/github.com/postfix/probation/src/http/token_packument.rs:36:45 <flags>`; `smtc callers --name serve_token_packument --depth 1 --limit 5 <flags>` | run; outer ok=true; one unambiguous declaration/body/caller | Structural caller edge; caller parse health 2 files / 0 error nodes / 0 dropped statements; 2,182 unresolved workspace dispatch sites. Caller output was large and host-truncated; manually inspected route body supplies the deciding call witness. Not a complete negative caller proof. |
| R7 | `smtc analyze lifecycle <flags>` | run; outer ok=true; inner analyzed_clean=false / verified_clean=false | 0 functions analyzed, 44 skipped, lifecycle_mapping_incomplete. This cannot establish scoped permit safety. |

Not examined: publishing/account actions, PyPI features, portal/control-plane issuance and synchronization internals, and unrelated workspace entry points; outside this bounded npm routing delta. Relevant selected-origin transport, ordinary cache admission, policy filtering and middleware crossings were followed beyond changed files.

Out of scope: none identified.

Unmodeled surfaces: not assessed against a design threat model; none was received or relied upon, as required by the packet.

Omitted: 0 confirmed findings; unrelated inventory items omitted as reported in R3/R4.

Limitations: required source-to-sink and ordering/lifecycle recipes lack deciding coverage for relevant security properties. Runtime logs are supplied execution evidence, not a fresh run by this reviewer. Connected unchanged source was inspected as current bytes but only the five subject files were hash-bound. Diagnostics/compile repair was independently ongoing; no compiler/model proof claim is made.

proposedNext: `sf-protocol-check check In service_registry::respond -> registry_routes::{package,named_read}, do network allowlist, selected-registry membership, active permit, body bound, principal recheck and publication generation checks cover every newly admitted npm GET/POST route before upstream I/O or response release?`

proposedNext: `sf-taint-trace Trace downstream Authorization from registry_read::service_principal and registry_routes::package/named_read to ReqwestTransport::{fetch_token_packument,fetch_named_read}; prove it reaches only the selected registry and never becomes shared cached metadata or downstream disclosure.`

Skipped: a heavy suite rerun and unrelated full-repository audit. Risk: no confirmed vulnerability, but the required executable security analysis remains incomplete.
