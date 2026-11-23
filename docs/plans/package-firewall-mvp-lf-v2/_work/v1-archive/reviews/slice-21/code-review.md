# Code review
Verdict: FIX FIRST
Scope: uncommitted slice 21 (Maven) on branch slice5-native-ci at 2dcf030 (79 changed or new paths). Read in full: src/maven/{coords,meta,xml,serve}.rs, src/http/maven_routes.rs, migration 0020, names.rs, blocklist.rs, osv wiring, download.rs and artifacts/mod.rs hunks, logging, service_registry, credential_read, the test diffs that replaced `maven` by `conan`, evidence/slice-21.md and tdd-slice-21.md. Authoritative: 03-program-design.md (family row Maven, LS-F4/F6/F7/F12), 04-slices.md row 21, the lessons of reviews slice-17..20.
Reviewer procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md. Read-only; the only file written is this report.
Summary: one blocking medium finding (S21-1, per-project row bound is soft: anchor rows are written before the bound is checked), one medium resource finding (S21-2, quadratic CPU on hostile documents inside async handlers), one confirmed test-judge failure that is pre-existing from slice 20 (S21-3), and low parity gaps (S21-4..S21-8). No protocol-correctness defect found in coordinates, metadata filtering, rebuilt checksums, .asc handling, catalog, snapshots, deploy challenge. The "Ecosystem::ALL.len()" claim and the maven-to-conan test changes are sound.

## Findings

S21-1 — medium — resource bound (lazy rows bounded per project) — anchor rows are committed before the row bound is checked
Location: src/maven/serve.rs:447-473 (`resolve` -> `record`, commit at 422-429), :489 (call), :490-516 (bound check at 507-511 only when `existing` is none), :538-547 (`ensure_fresh_project_in` also calls `resolve`).
Requirement/rule: evidence/slice-21.md "a project holds at most five times `max_references_per_project` reference rows (past it a file of one more unit is a 503)"; lesson of slices 19/20 (bounded lazy rows per project).
Failure or cost: `reference_for_file` first calls `resolve`, which commits the unit's POM anchor row unconditionally. For a request for the POM itself the row now exists, so `existing` is Some and the whole gate block (decision, bound, existence probe) is skipped. For any other file the anchor row stays even when the same request is then refused with 503 (the existing test's comment counts that row: tests/maven_registry.rs:443-467). So the bound stops file rows only; every distinct unit whose POM the registry answers adds one row without limit. A tenant-controlled registry answering 200 for any `.../{n}/lib-{n}.pom` lets a client grow `artifact_references` for one project forever; on Central it is bounded only by the real version count.
Evidence: code trace; the test at 443-467 asserts only `1.1.pom` (already has a row) and never requests a POM of a new unit after the bound, so it cannot catch this. Not executed (no probe build); trace is direct.
Correction: check the bound (count >= ROWS_FACTOR * max) inside `resolve` before `record` when the anchor row does not exist, answer `Overloaded`; add a test that GETs the POM of a fresh version at the bound and expects 503 with the row count unchanged. Cost: one count query per unit not in the table (the same query already runs at :507).
Blocking: yes (named lesson, unbounded persistent growth from tenant-controlled input).

S21-2 — medium — resource/DoS — quadratic scans of hostile documents run synchronously in the handler
Location: src/maven/serve.rs:765 and :772 (`builds.contains`), :778 (`decision_of` = `position`), :793 (`rev().find(allowed)` calling `position` each step), :942-947 (`removed.iter().any` for every `<repository>`).
Requirement/rule: LS-F7 bounded inputs; "per-registry fairness"; slice 19/20 lessons on bounded work per request.
Failure or cost: entry bounds are 100,000 (5 x max_references_per_project) for metadata and 500,000 for the catalog, far above any real document. A registry-owner serves a 15 MB snapshot-level document with 100,000 distinct `snapshotVersions` builds: `builds.contains` is O(B^2) (about 5e9 string compares), then each entry calls `decision_of` (O(B)) and `allowed` inside `newest` (O(B) per step) for another about 1e10. Likewise a 60 MB catalog of 500,000 archetypes that are cut (invalid names) each with a `<repository>` costs about 1.2e11 compares at :942-947. This is CPU work with no await, so `tokio::time::timeout(DOCUMENT_DEADLINE)` (maven_routes.rs:69-76) cannot interrupt it and it pins a worker thread for tens of seconds to minutes; repeatable by every request of that registry.
Evidence: code trace and the stated bounds; not measured.
Correction: use a HashMap<token, index> for builds and decisions and a sorted/interval check (edits are produced in document order) for the repository-inside-cut test; or lower the snapshot and catalog entry bounds to a few times the real maxima. Cost: small.
Blocking: no (needs a hostile registry owner), but fix with S21-1.

S21-3 — medium — test judge — tests/e2e/native/run_tests.py fails; cause is slice 20, not slice 21
Location: tests/e2e/native/nuget-fake.test.mjs:91 (`console.log("nuget-fake ok")`).
Requirement/rule: run_tests.py judge (success_pattern, line 26-28 of run_tests.py) requires the last line `nuget-fake.test: ok`.
Failure or cost: `python3 tests/e2e/native/run_tests.py` exits 1 with 2 finding lines for nuget-fake.test.mjs (success line not last). The file is unchanged since commit 2dcf030 (slice 20; `git status` shows it clean), so this is pre-existing and real: any CI that runs the judge fails. Slice 21's own maven-fake.test.mjs prints `maven-fake.test: ok` and passes (25 asserts, registered in expected-asserts.json).
Evidence: I ran `python3 tests/e2e/native/run_tests.py` in a capped scope (NATIVE_TEST_SCRATCH on disk): every other file ok, `run_tests: 2 finding(s)` (one file), exit 1, node v20.19.6. I could not reproduce the author's "22 findings": on this host it is 1 file / 2 lines, so the other 20 are not caused by slices 20/21 on this tree (probably the author's environment; not reproducible from the kept evidence).
Correction: change line 91 to `console.log("nuget-fake.test: ok")`. Closure: the run above reports 0 findings.
Blocking: no for slice 21 (attribute to slice 20), yes for any gate that runs run_tests.py.

S21-4 — low — parity (withhold of valid input) — a version without a POM never appears in artifact metadata
Location: src/maven/serve.rs:611-612 (`Ok(None) => {}`), :627-631.
Failure or cost: a hosted repository holding `lib-1.0.jar` without `lib-1.0.pom` (deploy of a bare file) lists 1.0 in its metadata, but the firewall cuts it from every listing forever (no date, no first-seen row) until someone requests a file of it directly. Range, LATEST and RELEASE resolution then skip it. Real Central always has the POM, so this only affects private repositories.
Correction: for a listed version whose POM is 404, record an anchor-less first-seen row (or treat it as Undated with first-seen now), so it ages normally. Cost: one more row per such version, subject to S21-1.
Blocking: no.

S21-5 — low — parity — snapshot with a held newest build and metadata that lists only the newest build is a 403
Location: src/maven/serve.rs:789-806 (documented in evidence "Not done").
Failure or cost: Sonatype and many Nexus repositories list only the newest build per extension in `snapshotVersions`; with a cooldown longer than the deploy interval the newest build is always young, so `mvn` resolving `X-SNAPSHOT` gets 403 even though older allowed builds exist by exact name. For a CI that deploys every few minutes this makes snapshots unusable under any cooldown above that interval. It follows the cooldown rule, so it is a decision, not a bug; flagged because the product rule is "no withhold of valid input".
Correction (optional): none without a directory listing; record as a consequence for the user rather than a defect.
Blocking: no.

S21-6 — low — parity — DELETE of a version directory is a 404
Location: src/maven/coords.rs:248 (trailing slash refused), src/http/maven_routes.rs:137-142.
Failure or cost: Nexus and Artifactory operators clean up with `DELETE .../lib/1.0/`; only single layout files can be deleted through the firewall. `mvn deploy` is unaffected.
Blocking: no.

S21-7 — low — strictness — comments containing `&`, and non-UTF-8 documents, make a valid document a 502
Location: src/maven/xml.rs:149-153 (`check_text` runs entity validation over a comment, so `<!-- R&D -->` is `Entity`), :112 and meta.rs:86 (a document declared `encoding="ISO-8859-1"` with high bytes is `NotUtf8`).
Failure or cost: a private Nexus catalog or hand-edited metadata with an ampersand in a comment or Latin-1 text is refused, where XML allows both. Central's documents have neither (measured per evidence), so only private registries are affected.
Correction: check comments with `check_text_raw` only; accept ISO-8859-1 declared documents by refusing only undeclared non-UTF-8.
Blocking: no.

S21-8 — low — correctness — first of two same-named singleton elements passes unfiltered
Location: src/maven/meta.rs:115-120, 131-132 (`meta.latest = leaf()` keeps the last).
Failure or cost: a document with two `<latest>` or `<release>` elements gets only the last rewritten. Only a registry owner can produce it, and that owner could serve any list; low. Cheapest fix: refuse the document (502) on a repeated singleton.
Blocking: no.

## Requirement coverage
| Requirement and source | Implementation/connection | Expected -> observed | Check and limits | Status |
|---|---|---|---|---|
| Identity: case-exact `groupId:artifactId`, one spelling per path (LS-F6, 03 row Maven) | coords.rs 167-285, names.rs valid_maven_name, blocklist.rs Maven arm | one canonical path; dot in a group directory, empty/dot/encoded segments, query -> 404 before upstream | unit tests coords.rs 327-400, maven_names.rs, maven_registry `paths_that_are_not...`; read the parser: rebuilt URL equals parsed segments | MET |
| Metadata filtering (artifact, plugin group, snapshot) with latest/release/pointer moved, unknown content byte-identical | meta.rs cut/apply, serve.rs 674-809 | withheld versions cut; latest/release fall back to newest allowed; empty -> elements removed | maven_registry tests, native mvn (supplied, not re-run) | MET |
| Rebuilt md5/sha1/sha256/sha512; .asc only when unchanged | serve.rs 876-888 | checksum of served bytes; .asc (and its sums) relayed only if unchanged, else 404 | read; two-request skew (document and sidecar fetched separately when a version ages between them) is inherent and low | MET |
| Files of a version gated, sidecars included, classifier/extension, .module | coords.rs split_file, serve.rs 483-531 | every file judged by its unit; held files not fetched | tests `every_file_of_an_allowed_version...`; S21-1 for rows | MET except bound (S21-1) |
| Dating by POM Last-Modified, else first-seen, never directory age | serve.rs 304-310, 375-473 | max-merge; undated waits first-seen | measured on Central per evidence; unit test 994-1000 | MET |
| Snapshots unique and legacy | coords.rs split_file, serve.rs 747-809 | builds are units; literal -SNAPSHOT is its own unit | tests 258-296; legacy redeploy pinned (documented limit); S21-5 | MET with stated limits |
| archetype-catalog filtered, `<repository>` URLs removed | serve.rs 914-961 | blocked entries and foreign repo URLs cut | test 309; S21-2 | MET |
| Strict bounded XML (03: DTD/entities disabled) | xml.rs | DOCTYPE/entity/PI refused, depth 24, no recursion | unit tests 295-345; S21-7 | MET |
| Deploy PUT/DELETE, 401 Basic challenge, caller's own credential, shared spool, status allow-list | maven_routes.rs 123-192 | challenge before any read; own Authorization to registry origin; public registry needs maven_publish_url | tests/maven_service_write.rs; S21-6 | MET |
| Blocked ids refused before upstream (files, metadata, plugin group, catalog) | serve.rs 358-368, 594 | local refusal, no fetch | tests 182-201 | MET |
| C1028, F12 osv_scope, route table, readmit layer | credential_read, service_registry, maven_routes 107-117 | request-scoped reads use throwaway cells; scope tests present | supplied evidence | MET (supplied) |
| Bounded tables, refresh places, per-project row bound | serve.rs 63-82, 176-207 | 128 cells, 8 raw docs, 256 gates, 4/16 places | tests 236 (tables), 412 (places); row bound see S21-1 | NOT MET for rows |
| Spec 03 "Maven ... external entities/DTD disabled" | refusal instead of ignoring | stricter than spec; no valid document uses DTD | accepted | MET |

## Conventions and simplifications
- "Blocklist table size from `Ecosystem::ALL.len()`" (src/policy/blocklist.rs:61, 51-52, 120-121, 235-236): true and correct. `ALL` has 7 entries and `ecosystem_index` maps Maven to 6 (src/policy/mod.rs:26), so no out-of-range index. There is no compile-time check that `ecosystem_index` stays below `ALL.len()`; the exhaustive match makes a missing arm a compile error, which is enough. No finding.
- Tests changed from `maven` to `conan`: src/policy/blocklist.rs (`rejects_unsupported_algorithm...`) and crates/probation-server/tests/ecosystem_tags.rs. Both assert "unknown tag is refused/503, never read as npm"; `maven` is now known, so a different unknown tag is the correct way to keep the assertion. Assertions are unchanged in strength. tests/service_policy_cache.rs and tests/shared_service.rs already used `Maven2` for the unknown tag, unaffected. A positive Maven record decode is covered by the new `snapshot_names_a_maven_registry_and_a_maven_block` test. No finding.
- The `Maven => unreachable!` arms in tests/shared_service.rs only keep matches exhaustive; no assertion removed.
- `resolve` reads a whole POM (up to 16 MiB) to learn its Last-Modified, once per file request for credentialed reads (nothing cached by design). Acceptable under C1028; optional: a HEAD would do if the transport offered one.

## Uncertainties
- Hosted repositories that allow release redeploy (Nexus "allow redeploy") get a permanent changed-bytes refusal after the first download pins a file (documented). If product wants those repositories, a decision on pin reset is needed; owner: user.
- Mirror `Last-Modified` stamped at cache time (Artifactory, Nexus proxies) only lengthens holds (documented, fail closed). Not testable here.
- The 20 other run_tests.py findings the author saw: not reproduced (see S21-3).

## Verification and limits
- Run: `python3 tests/e2e/native/run_tests.py` inside `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`, scratch under /home/john/go/src/github.com/postfix/.probation-scratch/native (deleted afterwards). Result: 1 failing file (nuget-fake.test.mjs), exit 1, all other files ok including maven-fake.test.mjs.
- Not re-run: cargo build/tests, native mvn lane, E2E stack, Postgres tests (relied on supplied evidence/tdd-slice-21.md: 883 root tests, 231 server tests, clippy clean). TDD lines: 29 `tdd:` lines (20 `red not observed`, acknowledged in the evidence, not blocking).
- Fingerprints (sha256 prefix): coords.rs 00ae389baf82a966, meta.rs e0af2250a426dda7, serve.rs 8440e8613e1064a2, xml.rs 2c84b47c5dd1f665, maven_routes.rs 4ea7f4772c565bdf.
- Unchanged during review: yes (no edits to the subject; 79 status lines before and after).
- Lenses with no finding: URL rewriting (POM `<repositories>` stay the client's mirror to settle, documented; catalog `<repository>` removed), write forwarding credential handling, readmit layer, migration 0020 (found by constraint content like 0017/0018), config/OSV scope.
- Out of scope: security audit (use lf-security-review), Gradle (none planned).

## Next steps
1. Fix S21-1 (bound check before anchor commit) with the failing test first; fix S21-2 together.
2. Fix nuget-fake last line (S21-3) in slice 20's file; rerun run_tests.py to 0 findings.
3. Decide S21-4 to S21-8 (low; S21-4 and S21-7 are the ones that withhold valid private-registry input and fall under the full-parity rule).
