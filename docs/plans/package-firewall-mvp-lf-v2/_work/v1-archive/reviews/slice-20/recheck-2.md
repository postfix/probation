# Recheck 2: slice 20 (NuGet) recheck-1 fix round, security lens

Verdict: PASS (no blocking finding; 6 non-blocking residuals N1-N6)
Scope: uncommitted tree at d32778b (103 status entries, unchanged during review). Read: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md, reviews/slice-20/recheck-1.md, evidence/slice-20.md and tdd-slice-20.md (Recheck-1 round), src/nuget/serve.rs, src/nuget/doc.rs, src/http/spool.rs, src/http/limits.rs, src/http/nuget_routes.rs, store commit_project_refresh, tests/nuget_registry.rs (R1 tests), tests/nuget_service_read.rs (R4), tests/nuget_service_write.rs (R3 test names).
Run (capped scope, `-j 8`): `cargo test --features probation/test-support --test nuget_registry --test nuget_service_read --test nuget_service_write`: 40 + 12 + 12 passed. Not re-run: Postgres suites, native dotnet, E2E, clippy, mutation probes P1-P14 (taken from evidence). Scratch log deleted.

## Status of recheck-1 items

| ID | Status |
|---|---|
| R1 | Fixed and guarded in default mode; shared-service undated corner is fail-closed but untested (N2). |
| R2 | Fixed: `take` passed on exactly, up to 1,000 ids judged 8 at a time under the 60 s deadline (504 on overrun), VulnerabilityInfo advertised over http. Residual N5. |
| R3 | Fixed: budget 2x cap, 413 for declared/streamed overflow, bytes reserved as they arrive, 60 s idle plus 15 min total, `Content-Length: 0` takes no place, RAII release on every path. Residual N4. |
| R4 | Fixed (4 per registry of 16; lock order own then global, both inside the 30 s wait; guarded by `one_registry_holding_its_refresh_places_does_not_starve_another`). Residual N6. |
| R5 | Fixed: `under_prefix` on vulnerability `@id` and certificate `contentUrl`; the service-index cell key now includes the prefix. Key half has no test (as stated in evidence). |
| U-1 | Fixed (readmeUrl mapped; test). |

## R1 analysis (the focus)

- No policy bypass for versions outside the row window. Every version stays in the stored project and is judged (flat index, registration, leaf, search, autocomplete) with no rows needed. A file request goes `reference_for_file` -> lazy 4-row upsert -> the normal artifact pipeline, which judges from the row (publication, first seen, pins). A version must be `in_flat` and valid, so rows exist only for versions the registry lists. FIX-16-A publication gate unchanged: dated versions use the registration date; the lazy upsert carries `publication_micros` of the entry.
- Undated versions: `stamp_first_seen` gives every undated entry `seen` = (stored payload seen) else (committed row first-seen) else now, for every entry with or without rows; `publication_of` uses committed first-seen, then `entry.seen`. Never earlier than the first refresh that saw it. A young undated version cannot be served early.
- Shared-service mode (`persist_metadata=false`): the payload is not stored, so `previous` is empty and an undated old version without rows is re-stamped `now` at every refresh (hold restarts; fail-closed). Its lazy row takes `entry.seen` of the cached refresh, committed first-seen is never replaced (store `carried_forward`), so after one file request the clock keeps running. Not early in any path I traced. See N2.
- Lazy commit does not clobber the stored project: `commit_request_references_in` skips REPLACE_PROJECT and does not move the generation; rows idempotent, pins/first-seen carried.
- Per-request row creation: at most 4 rows per request, idempotent (`get_reference` check), only for listed versions. See N1 for the aggregate.
- Page route `v3/registration/{id}/page/{lower}/{upper}.json`: `lower/upper` must be the exact normalised spelling and must equal a bound of a page in the registry's freshly fetched index; the URL fetched is the registry's own link, re-admitted (`admit_page_link`: same host, under the id's registration directory, `.json`, no query). No client text reaches an upstream URL or a rendered `@id` except through `Url::path_segments_mut().push` (encoded). Only versions named on that page are judged (`subset`); a version the stored project does not know is not shown. Credential-bearing reads share nothing: raw/shared/doc tables are read and written only with a cache token (C1028), the page route uses none of them. Inline pages stay inline.

## Findings (all non-blocking)

N1 - medium - resource bound - lazy rows are not bounded by `max_references_per_project`
Location: src/nuget/serve.rs `reference_for_file` (lazy upsert, ~1294-1310); `stamp_first_seen`/`refresh_with_docs` `list_project_first_seen_in` load all rows.
Scenario: a client (any caller that can read the registry) requests the `.nupkg`/`.nuspec` of every old listed version of a large project; each creates 4 rows before the policy decision (also for Hold/Deny versions, which cost no upstream download). A project of 200,000 flat versions (MAX_FLAT_VERSIONS) grows to 800,000 rows, 40x the configured bound; every later refresh/load of that project reads all of them. The rows are bounded by what the registry really lists, so this is not unbounded input growth, and a real nuget.org project is far below it.
Correction: create the lazy rows only after the decision allows (or Hold, which needs the row's first-seen), and/or cap lazy rows per project (for example 4 x `max_references_per_project`) answering 503/404 past it. Cost: one count query or a cheap per-project counter. Blocking: no (needs 5,000+ real versions and many requests; no policy effect).

N2 - low - gap - shared-service undated old versions: untested and not listed until asked
Location: tests/nuget_registry.rs `an_undated_version_beyond_the_row_window_...` runs in standalone mode only.
In shared-service mode the stamp is not carried between refreshes (payload not persisted), so such a version (no date, more than 5,000 versions, not requested) is never listed by the flat index and its hold restarts at each refresh until someone requests one of its files once. Fail-closed; no early service. Add a shared-service test pinning "not served early, served after cooldown following one file request". Blocking: no.

N3 - low - amplification - the page route is unshared and takes no refresh place
Location: `serve_registration_page` calls `fetch_registration_index` then `fetch_page_leaves` on every request (no raw share, no gate, no `REFRESHES` place). One request = 2 upstream fetches; a client walking 94 pages makes 94 extra index fetches; a loop of page requests is bounded only by the request permits. Correction: take the 5 s raw share for the index when credential-free. Blocking: no.

N4 - low - isolation/availability - spool places and budget are global
Location: src/http/spool.rs, src/http/limits.rs. Eight places shared by all tenants and five families; a caller admitted by the firewall (the spool runs after admission) who sends 1 byte every 59 s holds a place for 15 minutes, so eight such connections refuse every publish with 503. Budget = 2x artifact cap means two concurrent uploads totalling more than 2x fail the second with 503 after its bytes were read. Closure conditions of R3 (1.5x accepted, stalled declaration holds little, abort frees place, empty `Content-Length: 0` takes no place) are met; a chunked empty body still takes a place until its end. Correction (optional): per-registry/principal place share, minimum-rate rule. Blocking: no (needs a valid key; bounded 15 min).

N5 - low - behaviour - a per-id refresh failure hides that result instead of failing the search
Location: `allowed_for` (`result.ok()` -> `None`). Only the 60 s deadline gives 504; an id whose project refresh fails (its own 504, 502) silently drops from the results. Fail-closed (nothing leaks), but the recheck-1 design asked for "fail, not skipped". Blocking: no.

N6 - low - fairness - the public registry (id 0) has one share of 4 places for all users
A take=1000 search holds the four places for up to 60 s and other cold public reads wait up to 30 s then 504. Optional: smaller per-request search parallelism for the public id. Blocking: no.

## Regression check (earlier rounds)

S20-1..4, U20-2/3, F1-F6 re-verified by reading and by the 64 passing tests: raw/shared/docs share only with a cache token; per-project gate then place order, no wait inside a place; service-index prefix and key; `supportedFramework` allow-list; same-host URL scrubbing; vulnerability/signature caps; spool callers keep the file alive to the end of each handler and recheck policy after the body. Nothing regressed.

## Next steps
Accept R1-R5. Schedule N1 (cap lazy rows) and N2 (shared-service test); N3-N6 optional hardening.
