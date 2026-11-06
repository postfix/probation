Review kind: code-review
Verdict: SHIP
Question: Has the scoped-name admission defect from the prior FIX FIRST review been repaired without weakening validation or selected-registry identity?
Reviewing: targeted recheck of the scoped-name correction, its dependency edge and regression coverage, bound to the 15-path current manifest. This is a product-code verdict, not whole-slice certification.

Defects:
- None remaining in the scoped correction. Prior scoped-name MAJOR is resolved.

Historical process finding (still open, not a product defect):
- [MAJOR — test-process evidence only] `src/store/action_leases.rs:133`: the quota acceptance test still has no observed historical RED. The prior finding's evidence and the packet explicitly agree. Its passing acceptance characterization does not repair that historical gap; production quota code was reused unchanged. Tier: Manual. No new RED is claimed or requested, and no quota implementation change is recommended. Coordinator owns process disposition.

Resolved finding:
- `src/http/service_registry.rs:124,175–177,214`: the middleware validates a once-percent-decoded UTF-8 copy through the existing PackageName validator while preserving URI bytes for the downstream router. The decoder itself is permissive about malformed percent sequences, but the existing validator rejects remaining `%`, so the composition rejects malformed/double encodings. Invalid UTF-8, controls, backslashes, extra separators and leading-dot components remain refused.
- Old failure is recorded in `.scratch/slice3/red-scoped-action.log`: the HTTP regression returned 404 instead of 200 for `@scope%2fexample`. Current `.scratch/slice3/green-scoped-focused.log` records that exact regression passing, with all 7 focused tests passing, and `.scratch/slice3/check-scoped.log` records workspace compilation success. Tier: Decision for supplied executable results, Manual/Structural for inspected route connections. These logs were read, not rerun.
- Three valid encoded spellings reach the selected origin with the expected canonical package, developer credential and GET/DELETE method. Seven malformed spellings each fail both HTTP routes without outbound calls. The test asserts HTTP behavior and the external transport boundary; it does not recompute expected URLs using the implementation under test.
- Native npm scenario now covers scoped publish, deprecate, version unpublish and whole-package unpublish. Its post-fix execution was still pending in the supplied evidence; no native post-fix PASS is claimed here.
- Cargo adds a direct edge to the already-locked exact `percent-encoding` 2.3.2. No package-version or lock-resolution change is present. The helper has two current callers, both inspected classifier boundaries, and serves the approved validation need.

Conventions (prior standards set empty):
- None. Prior full review found no AGENTS.md, CLAUDE.md, CONTRIBUTING*, CODING_STANDARDS* or docs/codebase-overview.md. Its clean conventions lens is retained under targeted-recheck rules, with supplied AGENTS instructions applied. No new convention breach was found in the correction.

Simplifications:
- None recommended. The small private helper shares the necessary URI-boundary validation in both classifiers; no speculative abstraction or safe deletion candidate was identified. No blast-radius evidence is claimed for a deletion or replacement.

Subject and stability:
- Manifest `.scratch/slice3/current-subject.json`: SHA256 `a082c4e5f25600783ae8233174c53c4ce17b9ac3e791e6d3fc9ed323dc0afe13`; all 15 hashes matched before source inspection and after review.
- Base and final HEAD: `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`. Same scoped Git status and byte-identical HEAD diff; SHA256 `7faa038db7ee131848060f428d9e3e2408aaac786976a85c7dbf2289722a8e0d` (`.scratch/slice3/recheck-initial.diff`). The broad pre-existing dirty checkout is not treated as new scope.
- Supporting source fingerprints stayed unchanged: npm/name `0ee2e167ddc40df63176ae101744d23e2e7edcb3d5183e8f4631c8c0e6bb19a9`; registry_action `b2a03eec5a66e9135da3bcffc930e91dbc8365446c0aa179723ae283f34d4ebf`.
- Prior full review is retained for unchanged behavior and previously clean lenses. No new claim is made that its broad inspection was repeated.

SMTC receipt:
All listed operations used absolute root `/home/john/go/src/github.com/postfix/probation`, format JSON, max-tokens 2048, and session `sf-code-recheck-2026-11-03`. The exact argv templates below use those literal values as `ROOT` and `SESSION` only to shorten this receipt; substitute them without a shell wrapper. Every executed leg below was `run`, outer `ok:true`, with no inner error. Reads/searches are Manual evidence, not function-analysis proof.

| Operation / exact argv template | Arguments and completeness | Interpretation |
|---|---|---|
| `smtc file read --root ROOT --path PATH --start-line A --end-line B --format json --max-tokens 2048 --session-id SESSION` | service_registry.rs 1:180,180:340; tests/service_unpublish.rs 100:225; tests/e2e/scenarios/publishing-npm-actions.mjs 80:140; tests/shared_service.rs 200:300,295:370,590:680; registry_routes.rs 1:140,285:410; registry_action.rs 1:120; npm/name.rs 1:170. Source paths are under src/http except explicit tests and npm paths. All deciding narrowed content complete; ranges past EOF clamped. | Changed guard and classifiers, HTTP tests, raw scoped tarball/denial neighbors, extraction and forwarding boundaries inspected. |
| Same `file read` argv | docs/plans/publishing-proxy/evidence/slice-3-code-review.md 1:32,32:61; slice-3-engineering.md 1:24,25:40; slice-3-cert.md 1:26. | Prior lens bounds, executable evidence scope, and separate certification limits. |
| `smtc file read --root ROOT --path PATH --format json --max-tokens 2048 --session-id SESSION` | Initial prior-review read and engineering read were truncated to refs `ref-96` (2951 tokens) and `ref-97` (2535 tokens). Both narrowed into the complete ranges above; neither ref opened. | Initial summaries were not used as deciding content. The first prior-review input read preceded its fingerprint; it returned only a summary/ref, and deciding content was read after its hash was recorded. |
| `smtc search symbol --root ROOT --name-pattern NAME --limit 6 --format json --max-tokens 2048 --session-id SESSION` | parse_uri_package; classify_selected_registry; classify_direct_or_whole_package_delete; scoped_action_routes_decode_once_and_preserve_selected_identity. Each resolved uniquely, untruncated. | Zero-based positions respectively 174:0,65:0,179:0,111:0; read/inspect locations are one-based. |
| `smtc inspect symbol --root ROOT --handle HANDLE --format json --max-tokens 2048 --session-id SESSION` | Absolute handles: src/http/service_registry.rs:175:178, :66:148, :180:222; tests/service_unpublish.rs:112:132. All complete. | Bodies inspected for all four resolved deciding declarations. |
| `smtc file grep --root ROOT --pattern PATTERN --path-include PATH --max-results 20 --format json --max-tokens 2048 --session-id SESSION` | `scoped_action_routes|percent_encoding|scoped.*unpublish|decode_package`, tests/**: 2 matches; `PackageName::parse_route|Path\(|whole_package|delete_package`, src/http/registry_action.rs: 3 matches. Both untruncated. | Candidate locations only; no negative callgraph inference. |
| `smtc review slice --root ROOT --function parse_uri_package --direction both --format json --max-tokens 2048 --session-id SESSION` | Unique resolution; 4 entries; no truncation. Exact callers are the two inspected classifiers. Callee candidates are Structural and overinclude PyPI parse_route. | Inspected body establishes actual npm validator call; graph does not certify parser safety. |

Diagnostics: unsupported/unavailable per supplied HEALTHY-doctor result and exact retry in engineering evidence (`smtc diagnostics --root /home/john/go/src/github.com/postfix/probation --path src/http/service_registry.rs --format json --max-tokens 2048 --session-id sf-slice3-2026-11-03`: outer ok, inner internal_error, incomplete, didOpen/service stopped). Not rerun; no SMTC diagnostic PASS claimed. Native source-search/read fallback was not used. Git state, input manifest, and compiler/test logs are external task evidence.

Unchanged during review: yes, all 15 subject files and two freshly inspected supporting source files.
Reviewed: fresh correction units in src/http/service_registry.rs; tests/service_unpublish.rs; tests/e2e/scenarios/publishing-npm-actions.mjs; Cargo.toml; Cargo.lock. Fresh connected reads: src/http/registry_routes.rs, src/http/registry_action.rs, src/npm/name.rs, tests/shared_service.rs. Retained prior review coverage: src/http/mod.rs, src/http/service_unpublish.rs, src/http/unpublish_reference.rs, src/store/action_leases.rs, tests/e2e/fixtures/fakes/main.mjs, tests/e2e/scenarios/publishing-npm-read.mjs, tests/e2e/scenarios/publishing-npm-actions-issuer.mjs, tests/e2e/scenarios/publishing-full-matrix.mjs. Deleted: none.
Checked clean: correctness/totality/boundaries/types/numerics; errors/rollback/partial failure; ownership/cleanup/cancellation/lifecycle; shared-state ordering/races/deadlocks/termination; preconditions/postconditions/invariants/compatibility/side effects; input bounds/obvious security defects; maintainability; scope creep; current scoped regression behavior; conventions; simplifications. Unaffected clean lenses are inherited from the prior full review. Historical quota test-process evidence remains open as stated above.
Omitted: 0 defect findings; 0 convention findings; 0 simplification findings.
Limitations: targeted recheck, not a fresh whole-slice audit. Supplied executable logs establish the scoped regression and compilation; broad/native post-fix checks were not repeated or claimed complete. The three unpublish ordered specs are separately certified Structural PASS with expected unsafe-control failures; classifier CFG and model operation-summary attribution still block whole certification and are not resolved by this code verdict.

Skipped broad test reruns and certificate re-audit. Remaining risks are the explicit quota process-evidence gap and separate whole-slice verification limits, not an identified defect in the scoped fix.
