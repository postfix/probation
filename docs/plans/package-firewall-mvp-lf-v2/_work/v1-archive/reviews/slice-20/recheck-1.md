# Recheck 1: slice 20 (NuGet) fix round, security lens

Verdict: FIX FIRST (3 blocking: R1, R2, R3; 2 non-blocking medium/low: R4, R5; 2 uncertainties)
Scope: uncommitted tree at d32778b (103 status entries before and after, unchanged), fix round of reviews/slice-20/{code-review,security-review}.md. Read: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md, evidence/slice-20.md, evidence/tdd-slice-20.md (Fix round), both prior reviews, src/http/spool.rs, src/http/limits.rs, the five spool callers, src/nuget/{serve,doc}.rs, src/http/nuget_routes.rs, credential_read.rs, migration 0019, service_policy/portal prefix code.
Fingerprints (sha256 prefix): spool.rs a04bd59f, serve.rs e5d4fc62, doc.rs 2a98279e, nuget_routes.rs ec24b5df.
Run (capped scope, in-repo target): `cargo test -j 8 --features probation/test-support --test nuget_registry --test nuget_service_read --test nuget_service_write --test cargo_service_write`: 5 + 38 + 10 + 8 passed. Not re-run: Postgres server suites, native dotnet, E2E, clippy (taken from evidence).

## Finding status

| ID | Status |
|---|---|
| S20-1 | Fixed and guarded (5 s raw share, single flight, 16 places, page-sum cap, 257-page refusal; C1028 test in shared service). Residual: R4. |
| S20-2 | Fixed and guarded (`allowed_for` and `?id=`). |
| S20-3 | Fixed and guarded (bound tests added; vacuous assertion now exact). |
| S20-4 | Fixed and guarded. |
| U20-1 | NOT closed as a parity matter: R1. |
| U20-2 | `supportedFramework` fixed; `take` > 100 is a regression: R2. |
| U20-3 | Fixed for same-host URLs and dependency links; one uncertainty (U-1). |
| F1 | Fixed (amplification bounded); see R4 for the new shared-pool side effect. |
| F2 | Closed for anonymous disk-fill, but the bound itself regresses publish: R3. |
| F3 | Fixed for service-index resources; two credentialed fetches escape the prefix: R5. |
| F4, F5, F6 | F4 fixed and guarded; F5 fixed and guarded; F6 fixed but by withholding a feature: R2. |

## Findings

R1 - high - product rule (parity loss) - versions beyond 5,000 are withheld, not served
Location: src/nuget/serve.rs:555-562 (`entries_of`, `out.drain(..out.len() - max)`), 275-279 `max_versions`, `reference_for_file` (serve.rs:1099-1100).
Rule: pass-product-goal.md ruling 2026-11-09 (full parity, no backlog, never ask whether to drop or defer) and "never recommend a loss as the default".
Failure: a project with 5,001+ versions (nightly/CI feeds on Azure Artifacts, Artifactory, GitHub Packages) serves the highest-sorted 5,000. `GET v3-flatcontainer/{id}/{old}/{id}.{old}.nupkg` is 404, the flat index and registration omit the old versions, and a lock-file or `PackageReference Version="[1.0.0]"` restore of an old version fails with NU1101/NU1102 where the registry alone would succeed. The order is the flat container's (semver ascending), so "newest" means highest-sorted, not newest-published. The only trace is a `tracing::warn!`. Evidence section "Decisions for the user" item 4 asks the user to choose, which the rule forbids.
Evidence: source trace; `a_project_over_the_reference_bound_keeps_its_newest_versions` pins the withholding (5,001 -> 5,000).
Full-parity design (no config dependence): the stored payload keeps every version (flat list is bounded at 200,000; a few bytes each) with its date. Reference rows (4 per version) are the 20,000-row bound, so create them for the newest N plus lazily for any version that is requested: `reference_for_file` confirms the version is in the stored list, judges it alone (one `evaluate_scoped`), and upserts only that version's 4 rows (and first-seen when undated) before serving; ensure_fresh_project_in membership uses the stored list, not the rows. Flat index: judge and list every version (judging is in-memory policy plus the OSV batcher; it needs no rows). Registration: re-link pages instead of inlining (NuGet-native): the index lists page descriptors with `lower`/`upper`/`count` and `@id` pointing at a firewall route `v3/registration/{id}/page/{lower}/{upper}.json` rendered from the cached `RegRaw`, so no response holds 200,000 leaves. Cost: one route, one lazy-upsert path, tests at 5,001 and 20,001 versions with an exact pin of the oldest. Closure: restore of version 1 of a 6,000-version fake succeeds through the firewall, and a young version still waits.
Blocking: yes.

R2 - medium - product rule (parity loss) - `take` > 100 is a 400; `VulnerabilityInfo` is not advertised over http
Location: src/nuget/serve.rs:826-828 (`query_pairs`), `SEARCH_TAKE_CAP`; doc.rs service-index render (F6), evidence "Decisions" items 2 and 3.
Failure: (a) `dotnet package search --take 200` (the option is a plain integer, documented without a client-side cap) and any tool that pages search with take 101..1000 get 400 through the firewall where nuget.org answers (nuget.org accepts takes well above 100; I could not measure the exact ceiling here, so this is from the documented search API, not a probe). VS and the default CLI use 20 to 30, so the common path is fine; the loss is for explicit larger takes. (b) With `allowInsecureConnections` a dev setup over a plain-http firewall URL loses NuGet audit data entirely; the fix round makes this default with the opt-in only as a "decision for the user".
Full-parity design: (a) forward `take` up to the registry's own ceiling (1,000) and judge all returned ids through `allowed_for` in chunks of `SEARCH_PARALLEL` under the existing 60 s deadline, using the project share and the refresh pool; results not judged before the deadline fail the request (504) instead of being skipped, so nothing is silently dropped and no 400 appears. (b) advertise `VulnerabilityInfo` over http when a config key `nuget_advertise_audit_over_http` (default false, documented) is set, or always and rely on the client refusing http audit sources; either is a build, not a question.
Blocking: yes (removal by default without the user's explicit yes).

R3 - medium - regression - the shared spool refuses uploads that worked and lets one junk request starve publishing
Location: src/http/limits.rs (`spool_budget` = `max(max_artifact_bytes, 64 MiB)`), src/http/spool.rs:34-45, callers' caps (pypi_routes.rs:351, cargo_routes.rs:270, nuget_routes.rs:229 use 2x `max_artifact_bytes`).
Failure scenarios (CONFIRMED by source):
1. Budget (1x) is below the per-upload cap (2x) for PyPI, Cargo and NuGet. A legitimate upload with `Content-Length` in (1x, 2x] used to be accepted; `reservation.grow(declared)` now fails and the answer is 503 `OVERLOADED` with `Retry-After: 5`, forever (a retry never fits). A chunked upload of the same size fails mid-stream with the same 503 after its bytes were already spooled. It should be 413 (over what the service holds) or fit.
2. Two legitimate large uploads at once (any family) now serialise: the second gets 503. Before, concurrency was bounded only by disk.
3. Availability: a declared `Content-Length` of one byte under the budget reserves the whole budget at once, before any byte arrives. One junk-keyed connection per family-agnostic slot (8 connections, `BODY_DEADLINE` 15 minutes total, not idle) holds every place; one connection holding the whole budget blocks every other publish on all five families for up to 15 minutes, repeatably. The anonymous disk-fill is closed, but it is replaced by an anonymous publish outage. Also a plain unlist/relist `DELETE`/`POST` with an empty body takes a place and a temp file, so it is refused while eight uploads crawl.
Evidence: `the_spool_places_and_bytes_are_bounded_and_returned` and `uploads_past_the_spool_places_are_refused_not_queued` pin places and bytes arithmetic only; no test sends a declared length above the budget, a chunked overflow, an aborted upload that must free its place, or the 15-minute deadline (RAII makes release correct by reading: `slot` and `reservation` are locals dropped on every early return, on the timeout branch and on future drop, and the caller keeps `spool` alive to the end of its scope, so no leak was found).
Correction: set the budget to at least the largest single cap (`2 x max_artifact_bytes`, or the cap each caller passes) and answer 413 for a declared length above the budget; reserve a declared length progressively (as bytes arrive, capped at the declared value) or reserve at most a small first chunk, so a stalled declaration holds little; add an idle timeout (for example 60 s without a chunk) next to the total deadline; skip the spool (no place, no file) when the body is empty. Cost: a few lines and tests. Closure: a 1.5x upload succeeds; a stalled upload that declared the whole budget lets a second upload of 1 MiB through; abort frees the place (`spool_slot()` is `Some` again).
Blocking: yes (the focus item "no regression of publish behaviour" fails for the (1x, 2x] band, and the availability hole is new).

R4 - medium - isolation - the 16 refresh places are process-wide and shared across tenants
Location: src/nuget/serve.rs:176-181 (`REFRESHES`), 600 (`refresh.acquire` with 30 s wait).
Failure: any caller who can start 16 slow refreshes holds every place: an org admin whose private registry answers slowly (their own registry is operator-chosen and each refresh is up to 60 s), or any authenticated caller sending 16 credential-bearing reads (not coalesced, C1028) of large packages. Every other tenant's cache-missing NuGet reads then wait 30 s and fail with 504. Single flight and the 5 s share do not help ids no one has fetched. No deadlock was found: lock order is gate then place, place holders never wait for a gate, the registration route drops its gate before `current_project`, and every wait has a timeout and is cancel-safe (guards are owned and dropped with the future).
Correction: add a per-registry sub-limit (for example 4 of the 16 per `registry_id`; the public id 0 its own share) so one registry cannot take all places. Cost: a small map of semaphores or a per-key counter. Closure: with registry A holding 4 stalled refreshes, registry B's read still completes.
Blocking: no (availability, no data exposure; but fix before multi-tenant exposure).

R5 - low - hardening - F3 prefix is not applied to two credentialed fetches
Location: src/nuget/serve.rs `serve_vulnerability_file` (the `origins.set.admit(&url, origins.index)` after `parse_vulnerability_index`) and `serve_signature_certificate` (`admit(&url, ...)` for `contentUrl`). `under_prefix` is applied only to service-index resources (`fetch_resources`).
Failure: the vulnerability index and signature index are documents of the registry that name further URLs; those URLs are fetched with the registry's stored read credential (`fetch` sends `read_authorization`) and may lie anywhere on the host, outside the prefix that F3 added to confine exactly this. A hostile or compromised index document inside the prefix can steer the credential to another tenant's path of the same host. The same two points also keep an F3 prefix change unapplied for up to 60 s (`SERVICE_INDEX_TTL`; the cell key ignores the prefix); minor.
Correction: add `&& origins.under_prefix(&url)` to both admits (and a test: a vulnerability `@id` outside the prefix gives 502, nothing fetched). Cost: two conditions. Blocking: no.

## Uncertainties

U-1 (plausible) - doc.rs `rewrite_leaf`/`scrub_url`: every string of `catalogEntry` on the registry's host becomes `v3/catalog/...` (404), except `packageContent` and `iconUrl`. If a registry names `readmeUrl` (nuget.org catalog entries carry one on api.nuget.org flat-container paths, from memory, not measured here), it is turned into an unserved route although the firewall serves `.../{id}/{version}/readme`. Check: a captured nuget.org leaf; fix: map a flat-container readme URL like `icon_url`. Other-host URLs (licenses, project pages, www.nuget.org) stay by design and cannot be used by restore.
U-2 (plausible) - R3's budget default depends on the real default of `max_artifact_bytes`; the bands above hold for any value, only the sizes change.

## Answers to the focus questions

(a) Spool: releases are correct on error, abort, timeout and TooLarge by RAII; ninth upload is refused (`try_acquire`, 503, never queued); policy recheck after the body is preserved in all five callers (the spool lives to the end of each handler); declared length above the caller cap is 413 before a place is taken; anonymous disk-fill is bounded by the budget. Regressions: R3.
(b) Shares: C1028 holds (raw, docs and project cells are read and filled only when `cache_token` is `Some`; the shared-service test covers it); per-project gate has no deadlock or cancel hazard; 60 s deadline covers gate wait (30) plus place wait (30) exactly. Cross-tenant starvation: R4.
(c) U20-1: judged under R1.
(d) U20-3: registration index, leaves, dependency links, search (`@id`, `registration`, `versions[].@id`, `iconUrl`, `@context.@base`), service index and the vulnerability/signature indexes carry no registry-host URL except same-host values deliberately scrubbed; residual U-1 only.
(e) F3: migration 0019 is additive with a CHECK tying it to NuGet with a target; descriptor, snapshot, activation validation, portal route and `Principal` plumbing are consistent and tested; gap R5.
(f) F4 hash check, F5 status allow-list and nosniff are correct and guarded; the allow-list maps a registry 500/503 to 502 (the registry's message is lost; acceptable). F6 and `take` > 100: R2.

## Next steps
Fix R1, R2, R3 (blocking) and R5; schedule R4; settle U-1 with one captured leaf. Closure checks are named per finding. After the fix, a fresh reviewer should recheck the shared spool across the five forwarders.
