Review kind: code-review
Verdict: FIX FIRST
Question: Does the isolated active Slice 3 change preserve npm publishing/unpublish behavior and durable selected-origin deletion safety?
Reviewing: 13 paths bound by `.scratch/slice3/current-subject.json`; isolated against the pre-task baseline, not the broad dirty HEAD diff.

Defects:
- [MAJOR] Encoded scoped package names fail service admission — `src/http/service_registry.rs:124` (also line 208).
  Violated property: npm scoped package compatibility and the active Slice 3 whole-package/version-unpublish outcomes.
  Failure: `GET /registry/npm/3/@scope%2fname?write=true` is rejected before the token-packument handler; `DELETE /registry/npm/3/@scope%2fname/-rev/1` is likewise rejected before selected-upstream authorization. npm's encoded scoped spelling is a valid route component.
  Evidence: production-parser executable `.scratch/slice3/code-review-scoped.rs` directly includes `src/npm/name.rs`; both `%2f` and `%2F` return `Err(IncompleteScope)`, while decoded `@scope/name` succeeds. SMTC inspection shows `request.uri().path()` passed unmodified into `PackageName::parse_route`; a false preflight predicate makes the query branch return NotFound. The DELETE classifier makes the same raw-subject call. Tier: Decision for parser behavior, Manual/Structural for its route connection; full HTTP reproduction is delegated to the implementer.
  Smallest fix: decode the package component exactly once at the classifier boundary, preserving malformed-encoding and path checks; cover both write preflight and whole-package DELETE. Regression expectation: scoped native npm version unpublish succeeds; encoded whole-package DELETE preserves upstream allow/deny; direct tarball and malformed routes still send zero requests.
- [MAJOR — test-process evidence only] New quota acceptance test lacks a recorded RED — `src/store/action_leases.rs:133`.
  Violated property: review protocol requires a matching supplied `tdd:` red line for a new test in the diff.
  Failure: the three supplied RED lines cover publish, write preflight and service removal, not this new production-quota test. This does not establish a quota implementation defect: production `commit_with_limits` is reused unchanged.
  Evidence: isolated patch plus test symbol inspection; engineering evidence explicitly describes later acceptance strengthening without independently observed RED. Tier: Manual.
  Smallest correction: retain this as honest acceptance characterization, with a baseline run documenting the already-existing behavior if needed; resolve its process classification with the coordinator. A newly manufactured failure cannot establish historical TDD and correct quota code should not be broken merely to obtain a red result.

Conventions (repository standards set empty):
- No files found for `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING*`, `CODING_STANDARDS*`, or `docs/codebase-overview.md`. Applied the supplied AGENTS instructions and active plan; no convention breach found. Formatter/type-checker rules were not manually reviewed.

Simplifications:
- None recommended. The service marker helpers correspond to the approved deciding boundaries. The unused-by-current-caller optional package binding is an approved guard and is not recommended for deletion. No safe deletion claim is made from incomplete dispatch blast-radius evidence.

Deciding observations:
1. Owner zero separates the local store namespace from positive historical membership identities; `npm-service-unpublish` AEAD associated data differs from historical member data. Selected-origin enforcement precedes URL advertisement and DELETE consumption.
2. Accepted revision PUT obtains a valid response revision, or authenticated selected-origin GET checks the package, absent leased versions and resulting revision. Denied/unchanged/unverifiable results do not commit; marker persistence errors return PARTIAL_WRITE_UNCERTAIN.
3. Store `consume_marker` is a conditional UPDATE on registry/owner/reference/revision/expiry/unconsumed state. Consumption precedes transport, including denied or redirected upstream outcomes. Transactional marker commits reject disappeared references.
4. Production send_action and token-packument transport select the requested origin, admit the URL, disable redirects and cap response bytes. The service API key is not an argument in the reviewed action path.
5. Current quota witness exercises the literal production limits and compares every stored column plus row count. Larger seeded aggregate states do not prove historical commit reachability. Supplied six-test, compilation and first action-E2E passes are separate evidence, not substitutes for the scoped-package regression.

Subject and stability:
- Manifest SHA256: `200b3c7c4b5271f0ec00b848512020de0f0f5b4afbcc53ee982cd265387fafbb`.
- Base and final HEAD: `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`.
- All 13 manifest hashes matched before reading and at final check. Same scoped Git status; final HEAD diff 82,863 bytes, SHA256 `c3a4f1df75db5499ac52daaa30863860d1614d8fdbda4b461e72f3af0a579cbc`.
- Baseline reconstruction used HEAD plus the supplied pre-task working-tree patch, with supplied original service_registry/shared_service files. Isolated patches are in `.scratch/slice3/code-review-baseline/`.
- Supporting hashes stayed unchanged: registry_action `b2a03eec5a66e9135da3bcffc930e91dbc8365446c0aa179723ae283f34d4ebf`; token_packument `31176bfad7f228496bfb78060a679b8c0e7540be74f52a8a0e684406516c2ab2`; registry_read `83188bf11ce0d0a0f5258042f037ba1277d7b45568807438aa382e16f1ce3730`; reqwest_transport `08cbadb340daf7a6237c874435b7ef3b521210fa1a5ab977712ffbf87c11a43d`; origins `cbbdacdf0d6312b58c2138da515497536642bb1ba22136b929d446b30fb50c30`; npm/name `0ee2e167ddc40df63176ae101744d23e2e7edcb3d5183e8f4631c8c0e6bb19a9`.

SMTC receipt:
Every command used root `/home/john/go/src/github.com/postfix/probation`, `--format json --max-tokens 2048 --session-id sf-slice3-code-2026-11-03`. The following is an argv ledger: append that suffix to the literal command forms below, substituting each listed argument; no shell pipelines, redirection or wrappers were used for SMTC.

| Operation / argv before common suffix | Status | Fidelity / completeness and interpretation |
|---|---|---|
| `smtc file find --pattern <pattern> --max-results 20` for the five standards patterns above | run; outer ok, no inner error | Text discovery, zero standards matches, untruncated. |
| `smtc file find --pattern 'src/upstream/*' --max-results 20`; same for `src/npm/name.rs` | run; outer ok, no inner error | Four upstream files and one npm name file located, complete. An earlier guessed transport.rs fingerprint path was absent; discovery identified reqwest_transport.rs before content inspection. |
| `smtc file read --path <path> --start-line <a> --end-line <b>` | run; outer ok, no inner error | Manual source evidence, no functions-analyzed claim. Paths/ranges below. |
| `smtc search symbol --name-pattern <symbol> --limit 6` followed by `smtc inspect symbol --handle <absolute-path:start:end>` | run; outer ok, no inner error | Unique declarations inspected for all deciding symbols listed below; no hidden source truncation. consume_service_marker substring returned two candidates; no merged identity or result relied on that search. |
| `smtc review blast-radius --symbol <symbol> --reverse --include-resolution` | run; outer ok, no inner error | prepare_leases: 3 affected; forward_revision_put: 5; approve_deletion_scope: 15; complete Structural/Exact mixed edges. dispatch_npm_delete_route: truncated ref-94, 16,334 estimated tokens; not opened and not used to authorize a simplification. |
| `smtc review slice --function classify_selected_registry --direction both` | run; outer ok, no inner error | 11 entries, untruncated. Exact respond caller; several Structural candidate method edges are overinclusive, so parser executable and inspected body decide the defect. This is not a CFG certificate. |
| `smtc file grep --pattern <regex> --path-include <path> --max-results 20` | run; outer ok, no inner error | Located transport send/token methods, origin url_for, npm parse_route/upstream_segment, action admission/revision helpers and read admission. Transport redirect matches hit limit; narrowed deciding bodies were then read. Two initial repository-wide searches hit limit and were not used as negative evidence. |

Read ranges: service_registry 1–120 and 121–260; service_unpublish 1–109; unpublish_reference 24–150, 190–253 plus inspected forward_revision_put 254–283; store/action_leases 1–69,70–127,128–180; registry_routes 290–410; http/mod 50–130; registry_action 1–165 and 208–340; token_packument 1–110; registry_read 100–137; reqwest_transport 162–244; origins 207–248; npm/name 1–80,79–150; tests/service_unpublish 1–151; shared_service 599–640; fakes/main 107–159; action scenario 1–55 plus full isolated 163-line diff; read scenario 50–65 plus all changed hunks; issuer 1–9; full-matrix 1–45. Active plan row was read at 04-slices 1–16 and design 35–62. Broad initial plan read ref-92 exceeded 4,096 tokens and was narrowed; store read ref-93 was narrowed into two complete ranges. Initial broad HEAD diff output was truncated; all task-local hunks were then isolated and read separately.

Unique symbol inspections: record_successful_service_removal (service_unpublish 23–26), resolve_removed_revision_from_put_or_authenticated_get (28–55), commit_service_removal_marker (57–64), check_service_reference (73–86), consume_service_marker_then_send (93–109), forward_revision_put (unpublish_reference 254–283), lease_aad (26–31), lease_owner (33–38), approve_deletion_scope (110–130), prepare_leases (132–148), restore_revision_links (194–227), classify_selected_registry (service_registry 66–148), classify_direct_or_whole_package_delete (175–215), dispatch_npm_delete_route (217–223), production_service_registry_global_quota_plus_one_preserves_every_row (action_leases 133–173).

Unchanged during review: yes, through the final manifest/Git checks before this report.
Reviewed: all 13 manifest paths listed above; connected registry_action, token_packument, registry_read, reqwest_transport, origins and npm/name deciding units. Deleted: none.
Checked clean: errors/rollback/partial failure; ownership/cleanup/cancellation/lifecycle; shared-state ordering/races/deadlocks/termination; input-driven bounds/obvious security defects; maintainability; scope creep; conventions. Correctness/boundaries/types/compatibility and tests have the findings above. No additional material suspicion was retained. Simplifications: none evidenced for recommendation.
Omitted: 0 defects; 0 conventions; 0 simplifications. Detailed unchanged historical bodies and ten extra blast-radius edges are omitted from this bounded report.
Limitations: no full HTTP scoped repro in this review; parser witness plus actual route body establish the rejection. Supplied Cargo/E2E runs were not repeated. Rust diagnostics remain unavailable after supplied HEALTHY doctor verdict (didOpen/service stopped); no SMTC diagnostic pass is claimed. Supplied classifier CFG failure and qualified send_action unsafe-control expectation mismatches remain blockers owned by verification; no specs were weakened. Final broad workspace/E2E outcomes were pending in the packet. Native OS conformance and historical quota-state reachability were not checked.

Skipped broad reruns and historical certificate re-audit; scoped npm unpublish remains broken until the classifier fix and regression pass.
