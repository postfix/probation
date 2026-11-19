# Recheck 1: slice 17 (RubyGems) fix round

Verdict: FIX FIRST (2 high/medium new defects; all 16 prior findings otherwise closed).
Subject: uncommitted tree on slice5-native-ci, HEAD e3226bf; sha256 prefixes serve.rs 7f51efe2, marshal.rs f0add637, inflate.rs 75a1bbd9, info.rs 6a1192a0, rubygems_routes.rs 4cb0bee9.
Checks run (capped scope, target dir under .probation-scratch, deleted after): `cargo test` of rubygems_marshal, rubygems_info, rubygems_registry, rubygems_service_write, rubygems_native, rubygems_marshal_property, credential_bearing_reads: all pass (7 binaries, 0 failed). Policy-crate gem_version test not re-run. E2E ignored as instructed. One read-only WebFetch of rubygems.org controller source (timeframe_versions).

## Prior findings

| ID | Status | Basis |
|---|---|---|
| F1 | PARTLY: fixed against the fakes, NOT against the real registry (see N1); Upstream(0) substitute is gone, service mode works, tests exist | serve.rs recent_versions; native tests pass |
| F2 | OPEN (E2E in progress elsewhere, ignored per instruction) | |
| F3 / SR17-3 | FIXED, guarded (bufread decoder, exact slice accounting; marshal tests pass) | inflate.rs |
| F4 | FIXED, guarded (record_decision + test) | serve.rs serve_info |
| F5 | FIXED (selects, keys.html, docs, fleet.rs); client-bundle snippets in place | grep |
| F6 / SR17-2 | MOSTLY: 60 s cache keyed (registry, file, policy fingerprint, origin), never for request-scoped reads, limiter 2, container length refused before collection, 160 B node. Residual N4, N5 | |
| F7 | FIXED (positive control moved to the index cache) | |
| F8 | FIXED for native tests (loud skip); registry/marshal tests still hard-fail without Ruby (documented) | |
| F9 / SR17-6 | FIXED (Ruby-exact equality, digit-string segments, 42-spelling check vs real Ruby) | |
| F10 | FIXED (names validated; versions column documented, second run and update tested) | |
| SR17-1 | FIXED, guarded (more than 3 splits refused before any fetch; fetching stops at 2nd match; test counts /info calls) | |
| SR17-4 | FIXED for policy/blocklist/OSV keys, BUT introduces N2 | |
| SR17-5 | FIXED for dates (see N1 for the real-registry gap); OSV for unindexed tuples still not asked (accepted by implementer, needs user yes) | |

## New findings

N1 high, correctness (spec 03 line 333/363, real registry): the dated window reads page 1 only.
src/rubygems/serve.rs recent_versions. rubygems.org's `timeframe_versions` controller paginates (`Version.created_between(from,to).page(@page)`; 7-day cap bounds the time range, not the count; default page size is the site's, about 30). The code fetches no `page=` beyond the first and treats "absent from the list" as "published before the window". A real week holds thousands of versions, so almost every young version is absent from page 1 and is dated `bound` (older than the cooldown) and LISTED. Result: the F1 failure (resolver picks young latest, gemspec/gem 404, `gem install` fails) persists on rubygems.org; the age gate on the legacy index fails open (delivery stays gated by info/gemspec/gem, so it is a listing and availability defect, not artifact delivery). All fakes return one short array for every window, so tests cannot see it. Fix: page until an empty page (bounded, e.g. page cap and byte cap) and fail closed (return None, tuples unlisted) if the cap is hit; add a fake that serves page N by `page=` query. Closure: a test with more entries than one page where a young version sits on page 2 is not listed. Page size and the `page` parameter name were not verified against a live call (read-only WebFetch of source only); confirm once.

N2 high, regression from the SR17-4 fix: gems with uppercase in their real name cannot be downloaded (static trace, not executed; no test uses a mixed-case gem file).
reference_of stores `ArtifactReference.name` lower-cased, while the reference id and file name use the client's spelling (`RedCloth-4.3.2.gem`). The artifact path (artifacts/mod.rs:211) calls `ensure_fresh_project_in(row.reference.name)` with the LOWER name, which rebuilds ids with `gem_filename("redcloth")` = `redcloth-4.3.2.gem`; the id differs from the stored one, `advertised.contains` is false, answer 404. rubygems.org files are case-exact (evidence in fix round: `Rack-` 403), so real mixed-case gems (RedCloth, ZenTest, Ascii85, CFPropertyList, ...) fail through the firewall; a lowercase spelling gets 403 upstream. Fix: build filename/upstream_url from the spelling the index/client used consistently, or store the original-case name in the reference and lower-case only for policy keys; or have ensure_fresh_project_in resolve by stored filename. Closure: registry test installing `Mixed-1.0.gem` end to end (info, gem file, quick gemspec).

N3 medium, resource/DoS: `recent_versions` holds a global `tokio::Mutex` (all registries) across up to 6 sequential upstream fetches, each bounded only by transport timeout, while the caller also holds one of 2 heavy permits. A slow or hostile tenant-selected origin stalls every other registry's index builds. Failures are not cached, so a registry without the API is re-probed on every uncached index build. Fix: per-key single flight, short negative cache, total deadline.

N4 low-medium, unbudgeted memory: each timeframe response may be up to `max_metadata_bytes` (64 MiB) and is parsed with `serde_json::Value` (several times the size) and into `dated` with no entry cap, inside the heavy permit, up to 6 times. Cap bytes (e.g. 8 MiB) and entries.

N5 low: the recent cache is read and written by request-scoped (credential-bearing) reads and is keyed (registry_id, window) only, unlike the index cache (gated by `cache_token`, keyed by origin). The data is the registry's own configured-credential fetch, so no caller secret enters it, but it breaks the C1028 rule that such reads never touch shared caches, and an origin change within 60 s serves the old origin's dates. Gate by cache_token and add the origin to the key; extend the credential test to the recent list.

N6 low: no single flight on the filtered index: after the limiter the cache is not re-checked, so N cold concurrent requests do N fetches and N filter passes (sequentially, 2 at a time). The new test only checks agreement, not one fetch (F6's closure sentence is met only for sequential requests). Re-check the cache after acquiring the permit.

N7 low: `windows > 6` (freeze over 42 days) returns None, which un-lists every unindexed tuple (fail-closed but a silent empty-ish index for such a policy). Document or paginate further. Also `judged` is keyed by lower name, so project rows `Rack` and `rack` overwrite each other's `present/refused` sets (last wins); distinct-case rows also let any admitted client create one stored project row per case spelling (pre-existing, now known to be reachable on rubygems.org).

N8 low, parity: `gem push` forwards only `Authorization`; rubygems.org MFA uses the `OTP` header, which is dropped, so push/yank to MFA-protected accounts fail. Check whether PyPI-parity is the intended bar; otherwise forward a small allow-list (`OTP`). Otherwise write path is sound: 401 before admission, bare key length-bounded, origin from the registry config only, url_for admission, 413 by Content-Length and by streamed count, recheck of origin/CIDR/policy before send, tempfile in data_dir.

## Other checks (no finding)
- SSRF/origin: timeframe fetch uses the same OriginSet/url_for/MetadataRequest (origin, private CIDRs) as other reads; query built with query_pairs_mut.
- Upstream report: `upstreams.rubygems` Option with serde default and skip_serializing_if; set only after first call; a 404 counts as reached (record_upstream), so a registry lacking timeframe_versions does not show unreachable.
- Container pre-refusal and 160 B charge: tests and property run pass; limits apply only in keep mode, so gemspec validation is unaffected.
- Acceptance still needed from user (implementer lists): dated window instead of first-seen store, 160 B vs 64 B, marshal-rs deviation, OSV not asked for unindexed tuples.
