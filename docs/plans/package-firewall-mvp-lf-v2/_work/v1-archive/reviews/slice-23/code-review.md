# Code review: slice 23 (Conan 2)
Verdict: FIX FIRST
Scope: uncommitted slice 23 on branch slice5-native-ci at 1e1418b: src/conan/{mod,coords,serve}.rs, src/http/conan_routes.rs, the shared wiring (registry_read, service_registry, credential_read, names.rs, osv), the tests the evidence names, and the two tests that switched their unknown tag. Requirements: 04-slices.md row 23 (line 36), 03 family table row Conan2 (line 322), LS-F4/F6/F7/F12, evidence/slice-23.md incl. "Spec changes needed", evidence/tdd-slice-23.md, reviews of slices 20 and 21 (finding titles), pass-product-goal.md (ruling 2026-11-09, full parity, no backlog).
Summary: the protocol shape (ping, search, revisions/latest, files, upload/delete, login) is correct and the lessons of 17-21 are mostly applied. One blocking confirmed defect: the 512-list judging cap in searches is not "withhold until later requests settle them". It is a permanent loss of every result past the first 512, and the evidence/docs claim the opposite. C23-1 blocks. C23-2 to C23-6 are non-blocking. C23-7 and C23-8 are spec and test hygiene.

## Findings

C23-1 — high — parity loss (withhold of valid input) / false claim — searches never judge a result past the first 512
Location: src/conan/serve.rs:945-968 (`judge_parents`, `take(wanted)` at 947, `out = vec![false; wanted]` at 963), callers 1004 (reference search) and 1033 (binary search); const at :51; claim at evidence/slice-23.md "Not done" bullet 2, docs/operations.md:1852, comment serve.rs:942-944.
Requirement/rule: pass-product-goal ruling 2026-11-09 (full parity, no withhold of valid inputs, no backlog); row 23 "no valid input refused before the cap" (LS-F7).
Failure or cost: `judge_parents` always takes the FIRST 512 parents of the remote's own document order. Nothing consults earlier work: `list_units` (:613) always fetches the list (only the 5 s `raw` share, :709) and the unit table is never read to skip a parent; `Cell.lists` (declared :103, written :681-686) is never read anywhere (grep: no read), so "every list read is remembered" is false. `allowed` is `vec![false; wanted]`, and `refs.iter().zip(allowed)` (:1005) drops everything beyond `wanted`. Example: `conan search '*' -r svc` / `conan list '*'` against ConanCenter (about 4,000+ references per the evidence) or any custom remote lists the same first 512 forever; results 513.. never appear no matter how many requests follow. The same applies to a recipe revision with more than 512 package ids (binary search silently omits binaries, so the client reports "no binary" and builds from source). A transient upstream error on one list also drops that entry with a 200 (`judge_parents` :952-957), so a binary search can answer 200 with a binary missing and the client silently picks another or builds. Each over-cap search additionally costs 512 upstream fetches plus 512 row-gated commits again, uselessly, per request. No test exercises more than 7 results (grep of tests/conan_*.rs for 512/JUDGE_CAP: none), so the cap is untested.
Evidence: code trace above; tests/conan_registry.rs:292-308 uses 7 results; no test with more than the cap.
Correction (what full parity needs): (1) remove the fixed prefix cut. Judge every result up to the existing MAX_ENTRIES document bound. (2) Make judging cumulative so it converges and costs once: a bounded process table of verdicts keyed (registry, origin, rref or package id) holding allowed/held plus an expiry (the earliest instant a held unit can age in, never longer than a short TTL, dropped on policy fingerprint or OSV change); consult it and the already-stored anchor dates (`list_project_publications_in`) before any upstream list, so a reference with a stored, aged anchor needs no fetch. (3) Decouple the work from the 120 s request deadline: run the judging as a shared background task per (registry, document) whose results are kept in the table, so a deadline or a client disconnect does not discard progress; the request awaits it up to the deadline and a first huge `q=*` answers 504 (retry-safe, converging) rather than a silently truncated 200. (4) A failed list read must fail the search (502/504), not drop the entry with a 200. Inherent cost: a first `q=*` of N references needs N list reads (about N/4 round trips with 4 per-registry places); that is the price of exact answers and is why (2)/(3) matter. Cost of the fix: one more bounded table and a background task per document; the dead `Cell.lists` can be deleted. Until then, correct the evidence/docs sentence, which currently misdescribes the behavior.
Blocking: yes. Binding product rule; the stated residual is a permanent loss, not a delay.

C23-2 — medium — correctness/availability — `resolve` never refreshes `checked`; every file request after the TTL refetches and re-judges the whole list
Location: src/conan/serve.rs:818-839 with :537 and :654-660.
Requirement/rule: PERF/bounds lessons of slices 20-21 (no repeated computation/IO per file).
Failure or cost: `Known.checked` is set only inside `record`, which runs only for units that are `wanted` (new, undated or later-dated). For a dated, unchanged unit `list_units` leaves the old `checked`, so once `exists_ttl` has passed (5 s in service mode) `resolve` re-enters `list_units` on every file request: one upstream list fetch, one `list_project_publications_in` (all rows of the project name), a pins query and one `evaluate_scoped` per listed revision (a 2,100-revision list: 2,100 evaluations) for each of the six files of a package install. Under credential-bearing reads (throwaway cell) this is always the case.
Evidence: trace. Not run (no probe built).
Correction: in `list_units`, after reading the list, stamp `checked = mono` for every listed unit already in the table (and in `resolve` when the unit is listed). Cost: a few lines. Closure: a test that downloads two files of one revision 10 s apart in service mode and asserts one list fetch per TTL window.
Blocking: no.

C23-3 — medium — probable client break (needs a real-client check) — held revision lists answer 403 to the client's own upload existence check
Location: src/conan/serve.rs:795-813 (`nothing_allowed`), used by the same routes `conan upload` reads; tests/e2e/scenarios/publishing-conan-service.mjs uploads once into an empty registry.
Requirement/rule: row 23 write forwarding and no-backlog full parity of `conan upload`.
Failure or cost: PLAUSIBLE. Multi-platform CI uploads the second binary of a recipe revision that is already on the registry and still inside its cooldown. The client first reads the recipe's revisions/latest; with every revision held the firewall answers 403 with the hold, which the Conan client raises as a permission error instead of the 404 it treats as "not there", so the second upload fails. The e2e only tests a first upload to an empty remote and a 403 from the upstream.
Evidence/check: run the real client: upload hello/1.0 (young revision, cooldown on), then `conan upload` a second package id of the same recipe revision through `/registry/conan/{id}`; expected: second upload succeeds. If it fails, the fix is for the upload path (a request carrying the caller's own credential on a registry the caller publishes to) to see the unfiltered revision list, which needs a decision on whose reads are exempt (a policy question for the user, not mine).
Blocking: no (unverified); owner: implementer to run the check.

C23-4 — low — parity (withhold of valid input) — file names of a revision outside `[A-Za-z0-9._+=-]`, more than four segments, or with a dot-leading segment vanish from the file list and 404
Location: src/conan/coords.rs:89-95 (`file_ok`), serve.rs:925 (names filtered), coords.rs:136-139.
Requirement/rule: no 400/404 of valid input; Conan 2 metadata files (`metadata/...`) take client-chosen names.
Failure or cost: a package that uploads `metadata/logs/linux x86/build log.txt` or a nested/dot-prefixed metadata path loses that file from `files` and gets 404 on download; the client then treats the revision as incomplete or skips metadata silently. Real remotes accept more than this charset.
Correction: accept any file name the remote lists that is a canonical relative path (no empty/`.`/`..`, no control, percent-encoded on output, a byte bound) and raise the segment bound; cost: wider URL builder, plus a test with a space and a 6-segment name.
Blocking: no.

C23-5 — low — policy identity — user/channel are not part of the policy name
Location: serve.rs:382-387, :432-441 (`candidate(&rref.name, &rref.version, ...)`), evidence "Identity".
Requirement/rule: row 23 "Full user/channel/recipe/package revision identity".
Failure or cost: PLAUSIBLE. Unit keys, rows and URLs carry user/channel, but policy, a blocklist entry, an exception and the OSV key see only name+version. An exception that releases `zlib 1.3.1` early also releases `zlib/1.3.1@anyone/anything` in a custom remote that allows open uploads; an OSV hit on `zlib/1.2.11` blocks the user's own `zlib/1.2.11@acme/stable`. The shared policy schema has no field for it, so this is a decision, not a quick fix.
Check/question: the user decides whether name or name@user/channel is the policy identity for Conan (03 line 267 says name only); record it either way. Blocking: no.

C23-6 — low — dead state
Location: serve.rs:103 (`Cell.lists`), :55 (`MAX_LISTS`), :681-686.
Failure or cost: written and size-bounded but never read; the comment promises a search reuse that does not exist (see C23-1). Delete or use it (C23-1 correction 2). Blocking: no.

C23-7 — low — spec/test hygiene — row 23 trailing sentence contradicts the 2026-11-18 decision; tests switched to `oci` as the unknown tag
Location: 04-slices.md:36 (end of the row 23 cell: "`osv_skipped_for_private_registry_in_conan` (a non-ConanCenter remote with default scope sends no OSV query)"); 00-status.md approval record 2026-11-18 (a) and 03 LS-F12/line 1631/1689; crates/probation-server/tests/ecosystem_tags.rs:70-86; src/policy/blocklist.rs:689.
Failure or cost: the sentence is stale and conflicts with the same cell's earlier text (default custom remote is Public, only an operator-set Private is not queried); the code and tests follow the decision (`osv_skipped_for_private_registry_in_conan` uses Private; `conan_osv_query_follows_effective_scope` covers default Public, src/osv/mod.rs:1131-1160). The implementer already lists the correction in "Spec changes needed"; it is correct and should be applied (the coordinator owns 04). On the tag switch: assertions are unchanged and the refusal is preserved, but `oci` is row 24's own family and migration 0014's CHECK admits only the nine tags, so the DB-insert test in ecosystem_tags.rs has no unknown tag left after row 24 and will fail then (nothing remains to switch to). The blocklist unit test takes any JSON string, so it should use a tag that never becomes a variant (for example `"swift"`), not `oci`. Row 24 needs a different technique for the DB case (a raw-JSON snapshot, or dropping the CHECK inside the test).
Blocking: no. Record the row 24 consequence in the plan.

C23-8 — low — spec mismatch already declared
Location: 03 line 267 (name `[a-z0-9_.+-]`, ConanCenter only) vs coords/names.rs:303-308 (`[A-Za-z0-9_][A-Za-z0-9_+.-]*`, 200 bytes).
Failure or cost: none in behavior. The widening is right: the Conan 2 client accepts upper case and a leading `_`, so the table would refuse valid names (ConanCenter itself is lower case). Apply the evidence's spec change. Note the client also enforces a 2-character minimum; accepting one character is harmless.
Blocking: no.

## Requirement coverage
| Requirement and source | Implementation/connection | Expected -> observed | Check and limits | Status |
|---|---|---|---|---|
| Ping, `v1/ping` only of the v1 tree (row 23, evidence) | coords.rs:113, conan_routes.rs Parsed::Ping | local 200 with `revisions`; every other v1 path 404 | unit test one_path_is_one_identity; static read | MET |
| Search recipes and packages (Conan 2 REST) | serve_search, serve_package_search | judged per reference or package id | traced; no test over 7 results | NOT MET (C23-1) |
| Latest, revision lists and times | serve_revisions, list_units, newest_allowed | filtered, rebuilt, `time` kept | tests listed in evidence; static read | MET |
| Recipe/package file lists and downloads | serve_files, reference_for_file, ensure_fresh_project_in | names rebuilt, each file gated by its revision | static read; C23-4 for odd names | MET with C23-4 |
| Upload PUT/DELETE, check_credentials, authenticate | conan_routes.rs:151-226, serve_auth, publish_target, spool owner | caller's own Authorization only, 401 challenge first | static read; re-upload case unverified | UNKNOWN for CI re-upload (C23-3) |
| package_id and prev identity; unit keys | serve.rs:321-326, coords.rs | rrev and prev are separate units, user/channel in keys | static read | MET (policy identity C23-5) |
| name/version/user/channel charset | names.rs:303 | widened, matches client | static read | MET |
| Revision dating; new binary on old recipe | list_units/record, anchor row `conanmanifest.txt` | own time, only later | static read | MET |
| Conan 1 tree not routed | coords.rs:113-122 | only v1/ping | unit test | MET |
| Fail-closed unknown tags; FIX-16-A; C1028; osv_scope; route classes; spool owner; archive origin; bounded tables; hard atomic row bound; shared cells/TTL/deadlines; strict bounded decoding; blocked ids before upstream; URL rewriting completeness | applied as in 19-21 | consistent with template | static read only | MET at read level |
| Row 23 trailing OSV sentence vs 2026-11-18 | code follows decision; sentence stale | contradiction in 04 | text compare | spec fix needed (C23-7) |

## Conventions and simplifications
Only C23-6 (dead `Cell.lists`) and the `ponytail:` note at serve.rs:533 apply; nothing else of note.

## Uncertainties
- C23-3 (real client re-upload during cooldown).
- C23-5 (policy identity ignores user/channel).
- Conan 2 `v2/conans/{ref}/search` without `revisions/{rrev}` (an older binary-search spelling) is routed as 404; I could not check the client source locally (no network use). Check the shipped client 2.21.0 `rest_client_v2.search_packages` URL builder.
- Row-bound-induced withholding (serve.rs:665-677, test conan_registry.rs:412-433) of a recipe with more than five times `max_references_per_project` revisions/files is a deliberate hard bound inherited from slices 20-21; I did not re-judge it.

## Verification and limits
- Read only: no build or test was run (static review; no cargo, no scratch directory created, nothing to delete).
- Evidence read, not re-run: evidence/slice-23.md, tdd-slice-23.md (24 `tdd:` lines present; the "red not observed" lines are honest and not blocking; mutation probes M1-M19 as recorded, none for the 512 cap).
- Files read in full: src/conan/coords.rs, src/conan/serve.rs, src/http/conan_routes.rs; read in part: src/http/registry_read.rs, service_registry.rs, credential_read.rs diffs, names.rs, src/lib.rs `osv_scope`, tests/conan_registry.rs (search tests), tests/e2e/scenarios/publishing-conan-service.mjs, ecosystem_tags.rs and blocklist.rs diffs, 03/04/00-status lines cited.
- Not reviewed: the other 60+ changed files of the working tree (docs, portal, templates, fleet, Docker/e2e fakes), E2E fakes, migration 0021 text, native lane. Fingerprints not taken; the tree is uncommitted and I did not change it. Unchanged during review: could not check beyond the single read pass.

## Next steps
1. Fix C23-1 (judge all results, cumulative verdict table, background judging, fail the search on a failed list) and add a test with more than 512 results and one failed list; correct the "settles later" sentences in evidence, docs/operations.md:1852 and serve.rs:942-944 in the same change.
2. Run the real-client re-upload check of C23-3.
3. Fix C23-2 (refresh `checked`), C23-4 (file-name charset), delete `Cell.lists`.
4. Coordinator: apply the "Spec changes needed" (incl. row 23 OSV sentence), decide C23-5, and plan row 24's unknown-tag test technique (C23-7); switch the blocklist unit test off `oci`.
