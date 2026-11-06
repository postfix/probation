Review kind: code-review
Verdict: FIX FIRST
Question: Can the frozen 30-file shared-service prerequisite be accepted for code quality?
Reviewing: uncommitted tracked changes and all eight new files in subject.json, base 8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59.

Blocking review-protocol finding: new regression/acceptance tests lack individual historical RED evidence. This is an evidence finding, not proof those tests are ineffective.
Material probe targets: failed creation of a refusal tombstone can leave restart recovery eligible; raw scoped npm tarball aliases are rewritten into a route shape absent from the selected router. Neither has an executable reproducer in this review.

The source stayed unchanged. The policy/credential separation and final response handoff are coherent in the inspected paths. No demonstrated credential leak or stale-generation payload release was found. The current E2E run is pending, and the supplied Structural proof does not settle the two probe targets.

Defects:

[MAJOR] Required per-test RED provenance is incomplete — tests/service_policy_cache.rs:181
Violated property: the review protocol explicitly requires a supplied `tdd:` RED line for each test in the diff.
Failure: `malformed_snapshots_cannot_replace_remembered_authority`, publication unit controls, the additional managed-delivery matrix tests and E2E scenario were added without individual historical RED evidence in the packet. Parent confirms that chronology does not exist for the extra positive/acceptance controls. Core fixes do have honest RED/GREEN evidence; the post-implementation E2E baseline is honestly labeled and is not a historical RED.
Evidence: packet comparison, parent clarification, SMTC symbol inspection of the malformed-snapshot and publication tests; tier: Manual.
Smallest fix: preserve the historical limitation and obtain the required review-policy disposition; for regression properties still needing falsification, record honest current defect-removal controls. Do not fabricate chronology, relabel positive fail-all controls as failed regressions, or delete useful positive checks to satisfy this rule. Current mutation controls would strengthen effectiveness evidence but cannot retroactively prove test-first chronology.

[MAJOR, needs confirmation] Refusal persistence failure may resurrect a remembered grant — src/managed/service_policy.rs:413
Violated property: explicit refusal survives restart and previous-file recovery.
Failure candidate: `refuse` clears RAM, then `write_atomically` can fail at `NamedTempFile::new_in` before creating REFUSED. Existing SNAPSHOT/PREVIOUS are untouched. A later `load_with_clock` sees no REFUSED and loads the old grant; startup sync failure is ignored to support remembered outages. The existing persistence-failure control creates a directory at REFUSED, which already makes the loader refuse, so it does not test this case.
Evidence: inspected ServicePolicy.refuse, ServicePolicy.load_with_clock, write_atomically; slice has exact sync_once→refuse and gate edges, with text-confirmed persistence/load branches. Tier: Manual for the filesystem failure consequence; Structural for the call connection. Runtime filesystem probe not run.
Smallest fix/probe: activate a grant, make the data directory non-writable as the service UID while keeping snapshots readable, return401, confirm RAM closes, then reload while the server is unavailable. Require the persisted cache eligibility to remain closed. The correction needs a durable invalidation state established before an explicit refusal can be lost; merely clearing RAM or returning an error is insufficient. Exact durability design requires this failure probe and an explicit storage-failure assumption.

[MAJOR, needs confirmation] Raw scoped npm tarball alias has no selected route — src/http/service_registry.rs:121
Violated property: supported legacy npm paths remain usable when selecting the sole service registry.
Failure candidate: `/npm/@scope/pkg/-/pkg-1.0.0.tgz` becomes `/registry/npm/3/@scope/pkg/-/pkg-1.0.0.tgz`. The selected router registers only `/registry/npm/{registry}/{package}/-/{filename}`. Its original legacy sibling explicitly registers `/npm/{scope}/{package}/-/{filename}` and joins the scope/package. The rewritten raw scoped shape has no selected sibling, so a legacy lockfile request appears to404. Current shared alias tests use unscoped names.
Evidence: inspected classify_selected_registry and serve_npm_upstream_scoped; complete router table read at src/http/mod.rs:61-129; exact respond→classifier edge. Tier: Manual for route-matching outcome; Structural for classifier connection. No runtime route probe.
Smallest fix/probe: run GET/HEAD against raw scoped and percent-encoded scoped aliases with valid metadata/artifact. Preserve the selected registry while normalizing a raw scoped package into the existing single package capture, or provide the corresponding selected scoped route. Test before choosing the smaller correction.

Conventions (repository standards set empty; supplied AGENTS instructions applied):
- No breaches established. Five required find patterns returned no repository standards files. Context7 was not used. No build, package cache, or large temporary output was created in /tmp. Toolchain formatting is outside this review.

Simplifications:
- No deletion/replacement recommendation is established. The small async validate_policy_snapshot wrapper looks locally redundant, but it is a named ordered-obligation seam. Its search found one product declaration and four fixture declarations; blast-radius returned an ambiguous five-candidate result. Removing it is unconfirmed and could break the approved proof contract. Replacement unverified; proposedNext: sf-impact change validate_policy_snapshot if this seam is reconsidered.

Additional nonblocking analysis limit:
- Managed.ask_server publishes every cache insertion through the global generation, so an unrelated cold key lookup can invalidate another request's prepared response. This is source-established conservatism, not a confirmed contract defect: the approved evidence explicitly includes lookup publication. A paused-artifact A / cold-authentication B probe would quantify resulting503s before changing that design. Do not weaken its guard without preserving revocation ordering.

Reviewed (changed units plus connected context; all30 subject paths):
- crates/probation-policy/src/api.rs — service snapshot and descriptor wire types.
- crates/probation-server/src/lib.rs — route registration.
- crates/probation-server/src/service_policy.rs — complete new endpoint, service scope, snapshot transaction, rate control, descriptors.
- crates/probation-server/src/sync.rs — shared snapshot and lookup implementations.
- crates/probation-server/tests/service_policy_api.rs — full scoped API test.
- src/artifacts/download.rs — per-waiter mode handling and nearby pin/publication logic.
- src/artifacts/mod.rs — artifact checks, upstream membership, authority receipt.
- src/artifacts/stream.rs — authority-bearing constructors and response conversion.
- src/config.rs — configuration validation changes and atomic writer.
- src/http/health.rs — readiness.
- src/http/logging.rs — real socket peer context.
- src/http/mod.rs — complete router table and middleware placement.
- src/http/registry_action.rs — extracted canonical-tarball/revision predicates and enclosing classifier.
- src/http/registry_read.rs — complete admission/recheck/credential helper.
- src/http/registry_routes.rs — changed package branch and connected artifact/version rechecks.
- src/http/service_registry.rs — complete new middleware, classifier and DELETE refusal unit test.
- src/lib.rs — App construction, initial sync, blocklist exclusion, connect-info integration.
- src/managed/cache.rs — changed principal fixture.
- src/managed/mod.rs — all changed hunks, authentication/ask paths, publication sites, account rate limiter.
- src/managed/service_policy.rs — complete new module and unit tests.
- src/managed/sync.rs — changed publication dispatch and complete applying/retirement paths.
- src/npm/mod.rs — changed request-local refresh, serving/reuse conditions, refreshed response construction.
- src/pypi/mod.rs — changed request-local refresh, serving/reuse conditions, refreshed response construction.
- src/store/mod.rs — changed command transport and complete transactional refresh/reference carry-forward context.
- src/tasks/mod.rs — background task lifecycle integration.
- tests/authorization_read_once.rs — exact inventory addition and scanner context; established scanner implementation not reaudited.
- tests/e2e/scenarios/service-policy.mjs — complete new scenario.
- tests/managed_delivery_authority.rs — complete new tests and shared helper.
- tests/service_policy_cache.rs — complete new tests.
- tests/shared_service.rs — complete new tests and credential transport.
- Neighbor: src/http/artifact_routes.rs scoped legacy handler inspected. src/http/pypi_routes.rs and src/upstream/reqwest_transport.rs fingerprinted for possible follow-up, but not inspected in this bounded pass. Their full sink/security analysis remains with the security reviewer.

Unchanged during review: yes. All30 actual SHA256 values matched subject.json before and after. Git status list was unchanged; HEAD equals the supplied base. `git diff HEAD -- <all30paths>` had SHA256 5c520ed5f3b7991095b71c9c3b6c8980c989d76da90dccfdcbf99d402161a953 and48343 bytes both times. New files were read separately through SMTC.
Supporting fingerprints unchanged: artifact_routes.rs=e051742fcf9b1b692f16428588ef1af78126f03be380893c04dc557c67681d42; pypi_routes.rs=9423275fd175c5922735ecb355981d143dc740d928eb9b6ff5fb205c275de052; reqwest_transport.rs=08cbadb340daf7a6237c874435b7ef3b521210fa1a5ab977712ffbf87c11a43d; prerequisite-slice-16.md=dc2e200aa6e80d7f0fc44fdb18b20d02f1bfe54aa12bd62ca8b2cc0cae5d1348.
Deleted: none.
Checked clean within inspected scope: numeric/boundary validation except the scoped-route candidate; ownership/cleanup/cancellation; shared-state lock ordering and termination except the noted coverage limits; input-driven bounds and obvious credential separation; maintenance coupling except the preserved simplification candidate; approved scope (including405 writes and existing metadata HEAD404). Errors/partial failure, compatibility and tests are covered by the findings above. Conventions clean; simplifications unresolved/advisory only.
Omitted:0 defect findings,0 convention findings,0 established simplifications. This is not whole-repository coverage.
Limitations: no fresh executable tests, compiler checks or filesystem/HTTP probes run by this reviewer, per coordinator request to avoid concurrent broad builds. Supplied778-pass workspace and24-pass regressions are accepted as supplied evidence, not rerun. Existing structural certificates establish their stated ordering properties only. Current E2E is pending. Full transitive credential sinks, exhaustive race interleavings and native storage-fault semantics were not established. No SHIP claim follows from this report.

SMTC receipt

Repository root R=/home/john/go/src/github.com/postfix/probation; stable session S=sf-prerequisite-code-review-2026-11-03. All commands below use literal `smtc`, `--root R --format json --max-tokens 2048 --session-id S` in the order shown by the shared recipe. No pipes/redirections/wrappers or native source-read fallback were used. Exact path parameters are the repository-relative paths listed above; no secrets were passed. Common status for completed reads: run; outer ok=true; no inner refusal; complete selected text; fidelity=Manual, functions analyzed=not asserted; no truncation except the explicitly named narrowed reads.

- Standards operation: `smtc file find --root R --pattern <P> --max-results 20 --format json --max-tokens 2048 --session-id S`, P individually AGENTS.md, CLAUDE.md, CONTRIBUTING*, CODING_STANDARDS*, docs/codebase-overview.md. All run/ok,0 matches, not truncated. The unrelated exploratory `*rate*` find was truncated at20 and not used for a negative conclusion.
- Source reading operation: `smtc file read --root R --path <P> --start-line <A> --end-line <B> --format json --max-tokens 2048 --session-id S`. Selected ranges are recorded in the conversation receipts. Complete new-file reads: managed/service_policy1-150,151-300,301-450,451-620; server/service_policy1-180; http/service_registry1-180,181-350; service_policy_api1-160; service_policy_cache1-160,160-310; shared_service1-150,151-225,226-300,301-430,431-570,570-730; managed_delivery_authority1-150,140-280,280-410,410-500; E2E1-100. Changed existing units and neighbors were read in bounded ranges as listed under Reviewed. Clamped ranges ended at EOF and are complete, not truncations.
- Read recovery: shared_service151-300 produced ref-17/2060 estimated tokens; narrowed to151-225 and226-300. Evidence document1-100 produced ref-19/2695; narrowed to1-14 and15-31. No large ref was opened. An aggregated tool-display response was shortened; deciding test portions were reread individually in the bounded ranges above.
- Declaration resolution: `smtc search symbol --root R --name-pattern <P> --limit 6 --format json --max-tokens 2048 --session-id S`. Product matches resolved for `*refuse`→ServicePolicy.refuse (among four explicitly disambiguated path matches), write_atomically, handoff_binds_gate_generation_and_exact_owned_response, malformed_snapshots_cannot_replace_remembered_authority, *ask_server, *load_with_clock, *poisoned_publication_gate_refuses_final_authorization, *RateLimits, *classify_selected_registry, *serve_npm_upstream_scoped. Run/ok, complete final bounded matches. Initial `refuse` substring truncated at6/89; `^refuse$` warned metacharacters are literal; `ServicePolicy::refuse` returned0. None was treated as absence; `*refuse` resolved the target. validate_policy_snapshot and its trailing-match search returned five product/fixture candidates, preserved as ambiguous for impact.
- Declaration inspection: `smtc inspect symbol --root R --handle <H> --format json --max-tokens 2048 --session-id S`. H values: src/config.rs:1207:1227; src/managed/service_policy.rs:407:415,162:212,418:426,503:539,542:554; tests/service_policy_cache.rs:181:230; src/managed/mod.rs:548:675,1099:1102; src/http/service_registry.rs:69:125; src/http/artifact_routes.rs:92:110, each prefixed by R/. All run, outer/inner ok, complete source body, Manual evidence; no compiler certificate implied. Search coordinates are zero-based; handles/body lines retain tool-returned one-based text positions.
- Path inspection: `smtc review slice --root R --function ServicePolicy.refuse --direction both --format json --max-tokens 2048 --session-id S`, and the same for classify_selected_registry. Both run/ok, unambiguous single owner, complete8/5 entries respectively. Structural tier. Exact sync_once→refuse and respond→classifier edges are usable; heuristic unrelated publish/join/path/parse edges are not asserted as real connections. Functions analyzed not reported.
- Impact: `smtc review blast-radius --root R --symbol ServicePolicy.refuse --reverse --include-resolution --format json --max-tokens 2048 --session-id S`: run/outer ok; ref-21 estimated16293 tokens exceeds4096, deliberately unopened; incomplete impact evidence, no safety verdict.
- Simplification impact: same blast-radius recipe with validate_policy_snapshot: run/outer ok; inner five-candidate disambiguation, no resolved impact; no deletion recommendation. Additional wrapper callers/callees checks irrelevant until product/fixture impact identity is settled; proposedNext sf-impact change validate_policy_snapshot.

Skipped: fresh builds, runtime probes, complete transitive sink review and pending E2E acceptance. Risk: the two source-grounded failure paths remain unresolved until reproduced or refuted.
