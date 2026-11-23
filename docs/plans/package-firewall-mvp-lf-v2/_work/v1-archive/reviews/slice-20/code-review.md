# Code review
Verdict: PASS with advisory findings (no confirmed blocker; 0 critical, 0 high, 4 medium/low confirmed, 3 uncertainties)
Scope: uncommitted slice 20 (NuGet) on branch slice5-native-ci at d32778b (`git status` 85 entries, unchanged during review). Reviewed in full: src/nuget/{doc,serve,mod}.rs, src/http/nuget_routes.rs, the NuGet diffs of src/http/{mod,service_registry,registry_read,credential_read,logging}.rs, src/artifacts/{mod,download}.rs, src/upstream/{mod,origins,reqwest_transport}.rs, src/osv/{mod,batcher}.rs, src/policy/*, src/managed/{report,service_policy}.rs, src/{lib,config}.rs, crates/probation-policy/src/{lib,names,osv_key,api}.rs, crates/probation-server/src/{fleet,service_policy}.rs and portal/*, migration 0018, tests/nuget_{registry,service_read,service_write}.rs, crates/probation-policy/tests/nuget_names.rs (skimmed: tests/nuget_native.rs, tests/common/nuget.rs, E2E fakes and scenarios).
Requirement sources: docs/plans/package-firewall-mvp-lf/04-slices.md row 20; 03-program-design.md (family table "NuGet v3" line 316, LS-F4/F6/F7/F12, C1028); evidence/slice-20.md and evidence/tdd-slice-20.md; lessons from reviews/slice-18 and slice-19 code reviews (headings only).

## Findings

S20-1 — medium — resource bound — registration is rebuilt uncached, fully inline, with no aggregate cap
Location: src/nuget/serve.rs:431-469 (`fetch_registration`), 797 (`serve_registration_index` always `refresh_with_docs`), src/nuget/serve.rs:63 (`MAX_PAGES = 256`), 50 (`DOC_FLOOR_CAP` 16 MiB per document).
Requirement/rule: LS-F7 bounded inputs; "bounded tables"/strict decoding with caps lesson (slices 17-19).
Failure or cost: every `GET v3/registration/{id}/index.json` fetches the flat index plus every registration page again (no TTL, the project is refreshed from it and committed to the store), collects all pages as parsed `serde_json::Value` in one `Vec`, and returns one inline document. Per-document cap is 16 MiB but nothing caps the sum: 256 pages x 16 MiB decoded, times the JSON tree overhead, is a multi-GB allocation per request from a hostile private registry (the registry is operator-trusted, so this is a resource-bound defect, not an exploit by an anonymous party). On the real registry, awssdk.core (1,524 versions, 24 pages at about 670 kB each, evidence) means about 16 MB uncompressed response and 25 upstream fetches per request, and `dotnet list package --outdated` / VS ask registration for every package. The firewall also never compresses the response.
Evidence: code trace; `a_large_registration_is_not_refused_before_its_cap` covers a 4,000-version document, not the page count or the sum. No test for `MAX_PAGES` exceeded.
Correction: cap the sum of decoded page bytes (for example `index_cap`), and either use the project TTL for the registration documents or re-link pages (decision 1 in the evidence already names the alternative). Cost: a little code and one more cache cell. Closure: a test with 257 linked pages gives 502, and a second request within the TTL makes no upstream calls.
Blocking: no.

S20-2 — low — PERF-01 — search and autocomplete ask the registry about blocked ids
Location: src/nuget/serve.rs:861-875 (`allowed_for`), 887-928.
Requirement/rule: slice 18/19 lesson, "a blocked id or version is refused before any upstream call" (witness Q17 covers only the flat, registration and file routes).
Failure or cost: `locally_blocked` is called by the flat, registration, leaf and file routes only. For a search result whose id is blocked, `allowed_for` runs `current_project` (flat plus registration, 25+ upstream calls for a big package) and `judge`, and only then drops it. A search for a blocked name with 50 hits spends up to 50 projects of upstream traffic; `?id=` autocomplete of a blocked id does the same.
Evidence: `grep locally_blocked src/nuget/serve.rs` shows lines 773, 789, 814, 995 only.
Correction: call `locally_blocked`/`name_is_blocked` on each id before `current_project` in `allowed_for`. Cost: two lines. Closure: a search test with a blocked id asserts zero calls to that id's flat container.
Blocking: no.

S20-3 — low — test — guards weaker than their names
Location: tests/nuget_registry.rs:463-478 (`upstream_documents_that_are_not_what_the_protocol_names...`).
Failure or cost: the last assertion is `versions_of(&body).is_empty() || !contains("x.y")`. It passes when the body lists nothing at all, so it cannot detect "an entry that is no NuGet version is dropped, a repeat kept once" (the comment's claim) or the loss of valid entries: a regression that returned an empty list would pass. No test exceeds `MAX_PAGES` (256), `MAX_RESOURCES` (512), the 16-file vulnerability index, the 64-certificate signature index, the 64-entry service-index table or the 256-entry shared-project table, although evidence/slice-20.md lists these bounds as delivered. The slice 17-19 lesson was to pin each table bound. The tdd record has 19 "red not observed" lines of 50; the probes Q1-Q20 mitigate this for the route code but not for these bounds.
Correction: assert exact `["1.0.0","2.0.0"]` (with 1.0.0.0 folded) and add one test per bound. Cost: small tests. Blocking: no.

S20-4 — low — validation — ids "." and ".." are valid NuGet names
Location: crates/probation-policy/src/names.rs (NuGet arm of `valid_name`), src/http/nuget_routes.rs:40-42, serve.rs:361-363.
Failure or cost: `valid_name(NuGet, "..")` is true. Routes are still safe (`OriginSet::url_below` refuses `.`/`..` and the request ends 404 or 502 after the service-index fetch and an `absent` cache entry), and a policy block for ".." is accepted. Cargo/Go validators reject dot-only elements. Reject dot-only ids (and ids that start or end with `.`, which nuget.org refuses) in `valid_name`. Cost: one condition. Blocking: no.

## Uncertainties

U20-1 (plausible) — a package with more than 5,000 versions (`max_references_per_project / 4`) gets 502 on every route, so none of its versions can be restored (serve.rs:510-513, tested at exactly 5,000/5,001). The LS-F7 claim "no valid input refused" is backed by 12 sampled packages (largest 1,524 versions). Deciding check: the real maximum version count on nuget.org (nightly-build packages exist); raise the reference bound or filter to the newest N rather than refusing the project.

U20-2 (plausible) — search forwards only `q, skip, take, prerelease, semVerLevel, packageType` (serve.rs:838). Visual Studio also sends `supportedFramework`; it is silently dropped (framework filtering lost, not a safety issue), and `take` is clamped to 50 and results are removed after upstream paging, so a client that pages by its own `take` (for example 100) skips results and `totalHits` still counts withheld versions. Deciding check: real VS traffic; the feature-parity ruling means this is to be built if found.

U20-3 (plausible) — registration leaves keep upstream `catalogEntry.@id` and `dependencyGroups[].dependencies[].registration` (decision 4). These are identifiers no restore reads, but VS/other clients that follow a dependency's `registration` link would go to the registry directly and bypass the firewall. Deciding check: a client that follows it; rewriting `registration` to a firewall route is cheap. Also unverified: whether nuget.org's flat container serves a `license` file next to `readme`/`icon` (not served here).

## Requirement coverage
| Requirement | Implementation / connection | Check and limits | Status |
|---|---|---|---|
| Service index URLs rewritten, unconfigured origins rejected | doc.rs:91-184, serve.rs:326 `admit` per resource kind; routes advertise only served resources | 3 tests plus native; https-only RepositorySignatures (real dotnet finding) | MET |
| Flat container and registration filtered, page/link consistent | serve.rs:771-808, doc.rs:340-370 (counts, lower/upper recomputed, empty page dropped) | tests incl. linked pages; inline-only by decision 1; see S20-1 | MET |
| Normalised versions, lower-case id, one identity | names.rs `nuget_version`, routes parse strictly (404 before upstream), proptest idempotence | nuget_names 5 + proptests; see S20-4 | MET |
| Unlisted sentinel dates -> first-seen | doc.rs:228-231, serve.rs:398-403 | Q2/Q3 killed | MET |
| Four files per version, digest pin integrity, single-source restore | serve.rs:372-392, 991-1003, artifacts membership | tests + real dotnet 8.0.416 lane | MET |
| osv_ecosystem_mapping NuGet, F12 cases, osv_scope | batcher.rs, osv/mod.rs, `app.osv_scope` in judge | I ran nothing beyond the three suites below | MET (evidence reused) |
| C1028 credential-bearing read, path-embedded forms | credential_read.rs NUGET rules, `cache_token` gates in `resources`/`current_project`/absent cache | `..._nuget` and `..._end_to_end` | MET |
| FIX-16-A re-admission | `selected` rechecks principal (incl. archive origin, read authorization), `readmit::refusal` | added to the all-families test | MET |
| Write forwarding with caller's own key, bounded | nuget_routes.rs:209-281; 401 before lookup, 413 before upstream, service key never forwarded, publish target confined to the registry origin (`publish_target`) | write suite 6 ok; unlist/relist verbs covered | MET |
| Archive origin, migration 0018, fail-closed tags | download.rs, origins.rs, 0018, server `UnknownEcosystem` path | server tests per evidence (Postgres); not re-run | MET (evidence reused) |
| Bounded tables / strict decoding | caps present in code | tests missing for most bounds (S20-3) | MET with gaps |
| Search/autocomplete, vulnerability and signature documents | serve.rs:887-984 | confined to what the registry's current index names; see S20-2, U20-2 | MET |

## Conventions and simplifications
`ensure_fresh_project_in` and `reference_for_file` both check `in_flat` (equivalent mutant Q5, a deliberate second guard). `Entry.listed` is stored but never used by any decision (dead state; harmless, keep only if a later row needs it). Document routes answer HEAD with 405 by design (tested). `serve_vulnerability_file` reads up to 128 MiB and copies it with `body.to_vec()` (two copies; real file is under 1 MiB).

## Verification and limits
Run (scope `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`, in-repo `target/`, no /tmp): `cargo test -j 8 --features probation/test-support --test nuget_registry --test nuget_service_read --test nuget_service_write`: 27, 7, 6 passed. Not re-run: nuget_native (real dotnet), probation-policy tests, server tests (Postgres), E2E, clippy; their results are taken from evidence/tdd-slice-20.md (supplied, not independently verified). No scratch copies were made; my log file under .probation-scratch was deleted.
Test-first history: tdd-slice-20.md carries 31 `tdd:` lines and 19 `red not observed`; the missing reds were compensated by 20 mutation probes (19 killed, 1 equivalent); gaps listed in S20-3.
Fingerprints (sha256 prefix): src/nuget/doc.rs 917413a8, src/nuget/serve.rs faea18e1, src/http/nuget_routes.rs 0bbf23e3, names.rs 14332955; HEAD d32778b. Unchanged during review: yes (status count 85 before and after).
No lens skipped except the live-registry and cross-platform lanes (not available here).

## Next steps
Optional before commit: S20-2 (two lines) and S20-4 (one line) are cheap; S20-1 and S20-3 should be accepted or fixed before the security review, and U20-1 needs a real-registry version-count check. No finding blocks the slice.
