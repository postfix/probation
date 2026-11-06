Review kind: qa
Verdict: VERIFIED
Goal: Approved active publishing-proxy Slice 2: preserve npm canonical token metadata and safe audit behavior through the local shared service (04-slices.md:10; 01-product.md C35/C37/C38).
Overall assessment: The frozen slice meets its approved scope. No blocking finding remains. Installed model/source checks and required runtime evidence pass within their stated scopes; the three absent Slice 3 obligations are permitted PENDING.
Subject: base=8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59; manifest=.scratch/slice-2/final-subject.json, SHA-256 ce808dc2eac9cae3965829109cd5e3de443eb90b4e412d2d34d7896c27bfc7a6.

The base resolves to HEAD. The five current-file hashes and five baseline-copy hashes matched before review; all five current hashes matched again immediately before this report. The isolated delta SHA-256 is 98a33dc01e8b99d16ff61970797b503d5a04e1a55278c964eba4aeea30fdc4e5. Git identifies three tracked modified files (mode 100644) and two pre-existing untracked files; the manifest/baseline binds the task delta within the shared dirty checkout. No unrelated change is accepted by this verdict.

| Current path | Verified SHA-256 |
|---|---|
| src/http/service_registry.rs | 554b70a6d61e8f653667083fe36065fb0d619af791a95a616e066dd5b229f31c |
| src/http/registry_routes.rs | 7d9f4c3cc285f3fc9ac064529cb45e684ed142eaa5b3ac34046287bdfd160bb0 |
| tests/shared_service.rs | 0c2bb3b79851551bc17d3d7b16bf3ad22ee192b0fcdd41248558969252af52ba |
| tests/e2e/fixtures/fakes/main.mjs | d1a8f760f5ebed4a89e04d899fe48ab56be07cad119387480d3cca59dd0d9586 |
| tests/e2e/scenarios/publishing-npm-read.mjs | ff6951112437c06cdfec740e3b55042cf309e855d9006afdee0fea5cb331a2cc |

Detailed findings

- Completeness: no issue found. The selected route preserves the request body and reaches the reused token/audit handlers. Canonical selected Bearer metadata has the approved exception; ordinary, legacy, version and artifact reads retain policy filtering. Pending publishing actions remain refused.
- Code quality: no material issue found. Current independent slice-2-code-review.md is SHIP. The implementation reuses existing admission, token parsing, filtering, selected transport and response-recheck seams without a new dependency or abstraction.
- Testing: no required gap found. The public scenario contains independent allow/deny, isolation, safe-field and error assertions, rather than deriving expectations from implementation helpers. The TDD record witnesses accepted hidden metadata returning 403 before the product change and GREEN3 afterward; later strengthening assertions have no separate chronological RED claim. Intermediate failures are retained and explained. Adversarial PASS suggests optional stronger overlap/body-equality/scoped-route controls; these are not demonstrated failures or required revisions.
- Security and performance: bounded slice-2-security-recheck.md is CLEAR; no open scoped vulnerability. Exact route admission, request-local selected-origin credentials, policy-visible fixed-field audit output, byte/work limits and timeout/permit recovery have source and executed witnesses. Global formal security analysis remains UNKNOWN and is not used as a clean negative.
- Documentation: no blocking drift found in the affected active contracts, slice/TDD evidence, or updated installed-validation account. Earlier capability failures are explicitly historical and superseded by new receipts. No intent clarification is needed.

Requirement checks

- [VERIFIED] C35 canonical selected token-packument behavior; active design token-packument row and Slice 2 witness.
  evidence: registry_routes.rs:26-76 checks OriginalUri plus admitted Bearer authorization, calls serve_token_packument with this request's registry/name/method/query/headers, and rechecks authority. token_packument.rs:36-45 applies the canonical guard before the selected-upstream operation. GREEN3 scenario:48-108 observes accepted 200, denied/anonymous 403, ordinary version/legacy/artifact refusal, query/redirect refusal, concurrent credential separation and restart separation.
  scope: selected local npm metadata path and its ordinary-read boundaries.
  evidence type: decision (observed HTTP/npm cases), structural (canonical guard/source control), manual (branch/value inspection).
  limitations: concurrent probes do not force a barrier-controlled overlapping cold window; no arbitrary interleaving proof is claimed.
- [VERIFIED] C37 reduced policy-safe bulk/quick output; active design read/audit contract.
  evidence: named_read forwards the bounded body and encoding to the fixed selected endpoint, passes returned bytes through filter_audit_response, then rechecks authority. Audit filtering parses and validates, awaits policy-visible advisories, and renders fixed fields. GREEN3 scenario:165-256 observes nonempty gzip forwarding, safe nonempty bulk/quick signals, omission of hidden packages/versions/arbitrary text, malformed report refusal, work-cap refusal and actual npm advisory reporting.
  scope: both named audit routes and connected filtering/rendering.
  evidence type: decision plus structural and manual.
  limitations: body-length/encoding witness detects dropped bodies but does not independently establish byte-for-byte forwarding; the direct payload assignment is the inspected value-path witness.
- [VERIFIED] C38 upstream bulk-unsupported behavior without synthetic quick fallback.
  evidence: GREEN3 scenario:256-268 observes npm's bulk 404 error, unchanged quick-call count, then successful explicit quick POST. named_read preserves upstream 404 as NotFound and has no bulk-to-quick fallback.
  scope: selected npm 11.21.1 bulk/quick behavior.
  evidence type: decision plus manual.
  limitations: other npm versions are not established by this executed scenario.
- [VERIFIED] Selected-route compatibility and bounded failure/resource behavior required by active Slice 2/design.
  evidence: service_registry.rs:19-154 preserves body/selected identity and permits only exact audit POSTs and selected search queries; GREEN3:274-358 observes unknown-route zero I/O, numeric legacy reachability, request/response/header/artifact bounds, forbidden action/query zero I/O, 30-second audit deadline and subsequent successful ping with exactly one active permit.
  scope: changed local dispatch and connected named read failure paths; unchanged foundational Slice 1 guarantees remain prerequisite evidence.
  evidence type: decision plus manual.
  limitations: no whole-program resource-lifecycle proof.
- [VERIFIED] Required model/source obligations and executable regression checks.
  evidence: installed molecule-check reports PASS/findings []; installed molecule-verify --slice 2 archive run-9PMQUc has six present production checks PASS, six detecting unsafe controls, zero UNKNOWN/FAIL, and only three absent service_unpublish.rs obligations due Slice 3 PENDING. All 27 archive binding hashes match current files via sha256sum, one path per command. Each production/control attribution records selectedUnresolved=0; globalUnresolved=[152] is retained explicitly. Token and audit mutations remove their named guard/filter while retaining the operation; production yields zero findings and mutations yield the expected one finding. The other four pairs likewise produce zero/one findings. Source checks prove encoded selected call order and attribution, with route/value behavior separately inspected/executed above.
  scope: version-1 active model and current declared source obligations, not arbitrary source correctness or future unpublish implementation.
  evidence type: structural for model/spec results; decision for executed Cargo and runtime checks.
  limitations: contract-to-spec meanings remain reviewed premises; unrelated unresolved dispatches establish no global safety result.

Affected-document checks

- [CURRENT] 04-slices.md:10 and 03-program-design.md:32-34 active npm read/audit/token promises: required paths exist and inspected handlers plus GREEN3 implement the selected caller outcomes.
- [CURRENT] 01-product.md:51,53,54 C35/C37/C38: exact exception, safe audit disclosure and upstream error/no-fabrication behavior match current branch/value paths and observed cases.
- [CURRENT] evidence/tdd-slice-2.md:5-13: RED/GREEN identity, behavioral failure and execution counts match retained logs/JUnit; no claim that every strengthening assertion was independently developed test-first.
- [CURRENT] evidence/slice-2.md:64-78: historical blocker distinction, reviewed verifier hash, installed release, zero drift and fresh source/model results match examined artifacts. The recorded emergency installer evaluation-matrix skip is a tooling limitation, not a product-client pass.

Checks run and inspected

- Independently ran Git base/status/mode checks and sha256sum for the manifest, five current files, five baseline copies, isolated patch, reviewed tooling source/tests and final tooling logs; all expected hashes match. Independently checked all 27 captured bindings for both run-tsDHc6 and installed run-9PMQUc; no mismatch.
- Independently inspected runtime logs/JUnit: GREEN3 1 passed, 0 failed, 0 skipped; workspace 53 success summaries totaling 782 passed, 0 failed, 21 ignored; cargo check completed successfully; focused shared-service 4 passed. These expensive project runs were supplied current evidence and were not repeated.
- Independently inspected installed tool hash 487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea, full mandatory installer terminal PASS, drift 299 entries/0 drifted, installed-model.json, installed-source.json, and all 12 production/control stdout/attribution artifacts. The coordinator executed the fresh installed commands from this repository with CPU 0-1/nice19 and disk-backed scratch.
- Exact installed Router: /home/john/.local/share/software-factory/releases/7e8fca647076e63b75952e8850dc78c21a23861bafb9ac4ce8e6a9fdbc51cb83/skills-codex/sf-start/scripts/router; commands: molecule-check --plan-root docs/plans/publishing-proxy; molecule-verify --plan-root docs/plans/publishing-proxy --slice 2. Receipts: .scratch/verifier-repair/installed-model.json, installed-source.json, drift.log, install-emergency-repin.log.

SMTC receipt

Root=/home/john/go/src/github.com/postfix/probation; session=sf-slice2-verification-2026-11-03. Every local question recipe used --root <root> --format json --max-tokens 2048 --session-id <session>, except rootless ref show, which used only its exact id/session. No native source search/read fallback was used.

| Operation and argv operands | Status, fidelity/completeness, interpretation |
|---|---|
| smtc freshness <suffix> | run; outer ok=true; status not_built, file_count=0, possibly_stale=null. No freshness or whole-graph completeness inference; exact file hashes/current source reads and archived execution bind deciding evidence. |
| smtc search symbol --name-pattern <name> --limit 6 <suffix> | run; named_read, serve_token_packument, filter_audit_response resolved production declarations. Qualified service_registry::respond/registry_routes::package/registry_routes::named_read returned zero because names are stored unqualified; bare respond/package searches were truncated/ambiguous and were not used to choose a graph identity. A literal anchored filter name returned SEARCH-METACHAR/zero; bare filter_audit_response then uniquely resolved. No absence inference. |
| smtc inspect symbol --handle <resolved absolute path:range> <suffix> | run; token_packument.rs:36:45 and audit_filter.rs:29:45 return current untruncated bodies. registry_routes.rs:445:681 returned truncated ref-84 (3030 tokens); exact ref show ref-84 returned full body. Manual source evidence, no compile proof. Search span line35 became display line36 for token; line28 became29 for audit; no edit coordinates used. |
| smtc callers --name serve_token_packument --depth 1 --limit 5 <suffix> | run; outer ok=true, one exact structural package caller edge with this request's arguments; parse health files1/error0/dropped0, unresolved_dispatch_sites2182. Positive local connection only; no complete caller inventory inferred. |
| smtc file read --path <affected source/design/review/test file> [--start-line N --end-line M] <suffix> | run; current literal source/contract evidence. Bounded ranges inspected service_registry19-152, registry_routes26-86, audit_filter46-123, scenario45-112/165-240/240-334/334-380 and affected active docs/reviews. EOF ranges clamp explicitly. Initial long 04-slices read ref-81 estimated9267 was not opened; narrowed to active1-18. Slice evidence ref-82 estimated3358 and security ref-83 estimated2330 were opened with exact rootless ref show. file find *slice-2* max20 was truncated and used only as locator. |
| smtc file grep --pattern 'C35\|C37\|C38' --path-include docs/plans/publishing-proxy/01-product.md --max-results 20 <suffix> | run; outer ok=true, four untruncated matches identify exact active requirements. Manual text evidence only. |
| installed Router molecule-verify --plan-root docs/plans/publishing-proxy --slice 2 (supplied executed receipt run-9PMQUc) | run; six source PASS and six detecting controls; selected completeness as above; three future PENDING only. Structural tier; no global formal proof. |
| prior exact SMTC diagnostics, doctor and Cargo fallback supplied in slice-2.md | unsupported diagnostics: outer ok=true, inner internal_error/incomplete rust-analyzer stopped; doctor HEALTHY retry remained unavailable. Cargo compiler/runtime evidence supplies the executable check; unavailable diagnostics are not represented as a pass. |

Deciding evidence: frozen/current subject; connected canonical request-local metadata behavior; safe audit/error/bound behavior; matching runtime/compiler results; installed model/source/control results. Omitted deciding items: 0.

Limitations: 21 workspace tests remain ignored; global formal security analysis remains UNKNOWN. Mandatory tooling install suite passed; its documented emergency provider evaluation matrix was skipped. Later publishing/unpublish, PyPI migration and native OS/client release acceptance are outside this slice. No product source was edited by this review.

Next steps: ready for Slice 2 acceptance/completion under the existing coordinator workflow.

Skipped repeated expensive runtime suites; existing current hash-bound runs were inspected. The verdict establishes approved Slice 2 scope, not blanket production readiness.
