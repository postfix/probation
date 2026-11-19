# TDD record, slice 17 (RubyGems; local, uncommitted)

Capped command form: `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900 cargo ... -j 8`.

tdd: osv_ecosystem_mapping_per_family_rubygems (tests/osv_ecosystem_mapping.rs) — red: error[E0599]: no variant, associated function, or constant named `RubyGems` found for enum `Ecosystem` (compile red, as designed) — green: see below
tdd: migration_0014_accepts_the_nine_selected_tags_and_no_others (crates/probation-server/tests/ecosystem_tags.rs) — red: registries must accept `maven`: ... violates check constraint "registries_ecosystem_check" — green: `cargo test -p probation-server --test ecosystem_tags` passed (0014_ten_ecosystems.sql)
tdd: snapshot_names_a_rubygems_registry — red: assertion failed, the serde spelling `RubyGems` absent because the server snapshot match had no rubygems arm (first attempt compared the tag instead of the wire spelling; the test was corrected) — green: same command passed
tdd: unknown_tag_rows_are_an_explicit_decode_refusal_never_npm — red: the whole test file was red at the 0014 constraint (a `maven` block could not be inserted before the migration), so the npm-fallback behaviour itself was not observed red; the fallback `Ecosystem::from_tag(text).unwrap_or(Ecosystem::Npm)` was removed (StoreError::UnknownEcosystem) and the test asserts 503. red not observed for the fallback in isolation
tdd: LS-F13/LS-F7 codec tests (tests/rubygems_marshal.rs, 20 tests: quick_gemspec_real_fixtures_validate, marshal_filter_real_slice_is_loaded_by_ruby_with_the_denied_tuples_gone, marshal_filter_keeping_everything_preserves_every_tuple, marshal_filter_output_is_rerendered_not_spliced, marshal_filter_refuses_unknown_type_tag, marshal_filter_refuses_other_classes_and_malformed_shapes, marshal_filter_depth_and_object_caps, marshal_filter_memory_budget_refuses, marshal_filter_bad_link_refused, marshal_filter_length_prefix_no_prealloc, marshal_filter_symbol_and_link_tables_count_against_budget, quick_gemspec_hostile_class_refused, quick_gemspec_hostile_class_in_nested_stream_refused, quick_gemspec_nested_payload_counts_against_budgets, quick_gemspec_time_payload_not_parsed_as_stream, quick_gemspec_nested_depth_is_cumulative, quick_gemspec_nested_header_and_tables_checked, quick_gemspec_non_stream_payload_refused, quick_gemspec_bounds_and_memory_budget, gzip_ratio_and_size_cap_refuse_bomb) — red not observed as a test-first red: the module and its tests were written in one cycle; first run 15 passed / 5 failed, all five failures were test-construction mistakes (my builder's `long` encoded values over 255 wrongly, a truncated forward-link stream, an 8 MiB zero zlib that hits the ratio cap before the size cap) fixed in the tests, not in the codec — green: `cargo test --test rubygems_marshal` 20 passed. The guards are proven instead by mutation probes (marshal.rs backed up, restored by trap, cmp-verified after):
  probe P1 depth check off -> FAILED marshal_filter_depth_and_object_caps, quick_gemspec_bounds_and_memory_budget, quick_gemspec_nested_depth_is_cumulative
  probe P2 class allow-list off for `o:` -> FAILED quick_gemspec_hostile_class_in_nested_stream_refused, quick_gemspec_non_stream_payload_refused, marshal_filter_refuses_other_classes_and_malformed_shapes, quick_gemspec_hostile_class_refused
  probe P3 nested stream recursion off -> FAILED quick_gemspec_hostile_class_in_nested_stream_refused, quick_gemspec_nested_header_and_tables_checked, quick_gemspec_nested_payload_counts_against_budgets, quick_gemspec_nested_depth_is_cumulative
  probe P4 `o:` not registered in the object table -> FAILED quick_gemspec_real_fixtures_validate (link numbering)
  probe P5 object/link table slots not charged (after the test budget was tightened, first run survived) -> FAILED marshal_filter_symbol_and_link_tables_count_against_budget
  probe P6 Time payload length unchecked -> FAILED quick_gemspec_time_payload_not_parsed_as_stream
  probe P7 nested depth restarted at 0 (not cumulative) -> FAILED quick_gemspec_nested_depth_is_cumulative
  probe P8 symbol table not charged (after tightening, first run survived) -> FAILED marshal_filter_symbol_and_link_tables_count_against_budget
  probe P9 length-prefix pre-check off -> SURVIVED, an equivalent mutant: the reader grows a Vec element by element and fails at the first missing byte, so the pre-check is a fast path, not the no-preallocation guarantee; `marshal_filter_length_prefix_no_prealloc` still asserts the Truncated outcome and a 2 s bound.
tdd: osv_key_rubygems_charset_is_ls_f6 (crates/probation-policy/tests/osv_key.rs, plus the RubyGems arm of osv_key_valid_names_pass_for_every_family) — red: the whole test target did not compile (`error[E0004]: non-exhaustive patterns: Ecosystem::RubyGems not covered` after the variant was added, `osv_key` had no RubyGems arm) — green: `cargo test -p probation-policy --test osv_key` passed
tdd: osv_ecosystem_mapping_per_family_rubygems — green: `cargo test --test osv_ecosystem_mapping` passed (3 tests) with Ecosystem::RubyGems, tag `rubygems`, ALL entry and mapping arm `Some("RubyGems")`
tdd: credential_bearing_read_never_enters_shared_caches_rubygems (tests/credential_bearing_reads.rs) — red not observed as a test-first red (FamilyReadRules::RUBYGEMS was added in the same cycle); allow-list guards proven by probes X3 and X4 below and by the real client run that first failed on `keep-alive` — green: `cargo test --test credential_bearing_reads` 8 passed
tdd: rubygems_native_clients_send_only_allow_listed_headers (tests/rubygems_native.rs) — red: `assertion failed: a native client header is off the allow-list: /rubygems/versions {"accept-encoding": ..., "keep-alive": "30", ...}` (real RubyGems 3.6.7 sends `Keep-Alive: 30`; the family allow-list gained `keep-alive` with that stated reason) — green: `cargo test --test rubygems_native` passed
tdd: native_bundler_installs_the_eligible_version_through_the_compact_index — red: Bundler 2.5.22 `NoMethodError: undefined method '+' for nil` in compact_index_client/parser.rb:74 `parse_version_checksum` (my first /versions rendering dropped the third column; Bundler requires it, uses it only to decide whether its cached info is current) -> /versions is passed through unchanged — green: same command passed (`demo (1.0.0)` locked, young 2.0.0 withheld)
tdd: native_gem_install_resolves_only_what_the_firewall_lists — red: `gem install: bad response Not Found 404 (Gem::RemoteFetcher::FetchError)` at fetch_spec (the legacy index listed the young 2.0.0 of a gem this instance had not indexed, then its quick gemspec was refused by the identity gate); the test now warms the compact index first (see "Known gaps") — green: same command passed (`demo (1.0.0)` installed, 2.0.0 not offered)
tdd: info_* / gem_file_* / quick_gemspec_* / versions_and_names_* / specs_index_* (tests/rubygems_registry.rs, 12 tests) — red not observed as a test-first red (serve.rs and the routes were written in the same cycle); first run 11 of 11 passed; guards proven by probes M1..M5, X1, X2 (below) — green: `cargo test --test rubygems_registry` 12 passed
tdd: info_* (tests/rubygems_info.rs, 4 tests) — red not observed (module and tests together); first run 3 of 4 passed, the failure was a test assumption (a version absent from the 24-line real slice) corrected in the test — green: `cargo test --test rubygems_info` 4 passed
tdd: osv_skipped_for_private_registry_in_rubygems, osv_public_mirror_with_explicit_scope_is_queried (src/osv/mod.rs tests, F12 cases of row 17) — red not observed (effective_scope already had the generic rule; the RubyGems fixed sources `rubygems.org`, `index.rubygems.org` were added in the same cycle) — green: `cargo test --lib osv_` 14 passed
tdd: credential_bearing_read_never_enters_shared_caches_rubygems_end_to_end (C1028 through the row 28 seam, shared-service mode, info + gem file + allow-listed read cached) — red not observed — green: `cargo test --test credential_bearing_reads` 8 passed

Mutation probes (file backed up before, restored by trap, cmp-verified; every run under the capped scope):
  M1 registry `created_at` ignored in publication_of -> FAILED 5 of 11 rubygems_registry tests
  M2 refused entries not filtered from `info` -> FAILED info_judges_each_platform_by_its_own_date, info_without_a_registry_date_waits_on_the_committed_first_seen_time, info_hides_blocked_versions_and_packages, info_withholds_young_versions_and_keeps_every_other_line_byte_for_byte
  M3 two index entries for one file name accepted -> FAILED gem_file_names_that_fit_two_index_entries_refuse_instead_of_guessing
  M4 quick gemspec validation skipped -> FAILED quick_gemspec_is_identity_gated_and_refuses_hostile_classes
  M5 quick gemspec identity gate off -> FAILED quick_gemspec_is_identity_gated_and_refuses_hostile_classes
  X1 judgement of indexed gems off in the tuple index -> FAILED specs_index_is_filtered_by_blocks_and_by_what_the_instance_has_indexed
  X2 blocks-only judgement off in the tuple index -> FAILED the same test
  X3 `keep-alive` not on the RubyGems allow-list -> FAILED rubygems_native_clients_send_only_allow_listed_headers
  X4 service-mode selection of the RubyGems family rules removed -> first run SURVIVED (the end-to-end test could not tell the rule sets apart); the test gained the allow-listed `keep-alive` gem read that must enter the content store, then X4 -> FAILED credential_bearing_read_never_enters_shared_caches_rubygems_end_to_end
  Y1 (server) `policy::ecosystem_of` restored to `unwrap_or(Ecosystem::Npm)` (the pre-row fallback) -> FAILED unknown_tag_rows_are_an_explicit_decode_refusal_never_npm (the real red of that test, observed by probe; policy.rs restored and cmp-verified)

## Verification (every command under `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`, cargo -j 8)
- `cargo clippy --workspace --all-targets -- -D warnings`: clean. Same with `--features probation/test-support`: clean.
- Root test binaries, one `cargo test --test X` at a time (50 files in tests/): all 50 passed (first full pass had one failure, `listener_admission::route_inventory_equals_classified_table`, because the new routes were not in the classified table; the 16 RubyGems rows were added and it passed; the whole sequence was then rerun after the last source change and passed 50 of 50).
- `cargo test -p probation-policy`: 5 targets, all passed.
- `cargo test -p probation-server -- --test-threads 4` against Postgres 16 (container on 127.0.0.1:55432, data directory under .probation-scratch, removed afterwards): 15 + 34 + 30 + 1 + 3 + 1 + 52 + 8 + 40 + 3 + 6 + 5 + 6 + 4 + 1 passed, 0 failed (includes ecosystem_tags 3 and service_policy_api 5).
- `cargo test --lib osv_`: 14 passed. The full `cargo test --lib` was NOT run (known osv and managed::client hangs from slice 28/30).
- `cargo test --test rubygems_marshal -- --ignored real_corpus_measurement` with PROBATION_RUBYGEMS_CORPUS pointing at the downloaded corpus: passed, numbers in rubygems-corpus.md.
- E2E-rubygems: NOT built, NOT run (see slice-17.md "Known gaps" 2).

## Fix round 2026-11-19
tdd: gzip_ratio_and_size_cap_refuse_bomb (zlib trailing bytes: 1, 16 and 40,000 bytes after the stream) — red: `panicked at tests/rubygems_marshal.rs:474` (the old `read::ZlibDecoder` swallowed the tail into its BufReader) — green: `cargo test --test rubygems_marshal` 23 passed after `bufread::ZlibDecoder`
tdd: gem_version_equality_matches_ruby_on_awkward_spellings, gem_version_segments_of_any_length_compare_without_limit (crates/probation-policy/tests/gem_version.rs, against real Ruby) — red: `Ruby says "1.0.a" != "1.0.A"` and the 60-digit segment case — green: `cargo test -p probation-policy --test gem_version` 2 passed
tdd: gem_names_are_judged_case_insensitively_so_a_spelling_cannot_dodge_a_block (tests/rubygems_registry.rs) — red: `Rack is the blocked gem` left: the unfiltered 1.0.0 line — green: `cargo test --test rubygems_registry` passed
tdd: marshal_filter_refuses_oversized_in_flight_containers_before_collecting_children — red: `Truncated` returned only after 200,000 children were collected (assertion at rubygems_marshal.rs:529) — green: Shape refusal before any child; marshal_filter_charges_retained_values_at_real_size: red not observed (already above 300 B per tuple)
tdd: marshal_filter_symbol_and_link_tables_count_against_budget — re-pointed at the gemspec reader because the tuple reader now refuses the long containers it used; mutation probes P5b/P8b of the first round re-ran green->red before the change, not repeated after
tdd: native_gem_install_of_an_unseen_gem_* (standalone and service), native_bundler_*_shared_service, second-run Bundler — red (first-round evidence): `gem install: bad response Not Found 404 (Gem::RemoteFetcher::FetchError)` when the unwarmed index listed the young latest; green after the dated index: `cargo test --test rubygems_native` 5 passed
tdd: gem_file_name_fan_out_is_bounded_before_any_upstream_call, names_are_validated_and_a_filtered_index_is_built_once_per_window — red not observed (written with the code); probes below
tdd: shared_service_forwards_gem_push_and_yank_with_the_callers_own_key_only — red: `left: (401, ...AUTHENTICATION_REQUIRED... "a valid API key is required")` (the shared principal check demanded Bearer or Basic) — green after RubyGems accepts its bare key; the listener route-table test first failed `DELETE ... got 405` (npm delete dispatch) and passed once the dispatch left RubyGems alone
tdd: rubygems_fully_refused_listing_records_one_decision (tests/managed_mode.rs) — red: `no RubyGems decision was recorded` (first attempt waited on sync delivery; the queue is read directly) — green: `cargo test --test managed_mode rubygems` passed
tdd: rubygems_reachability_is_additive_in_both_directions — red not observed — green: `cargo test -p probation-policy --test report_compat` 3 passed
tdd: tests/rubygems_marshal_property.rs (3 properties) — red not observed (no panic found); no mutation probe was run against it

Probes of this round (restored, cmp-verified):
  Z1 credential-bearing reads allowed to share the index cache -> FAILED credential_bearing_read_never_enters_shared_caches_rubygems_end_to_end
  Z2 recent-versions dates ignored -> FAILED both native `gem install` tests (unseen gem)
  Z3 name fan-out bound raised to 300 (first run SURVIVED because the hostile name was filtered by length; the test now uses 30 digit-led splits) -> FAILED gem_file_name_fan_out_is_bounded_before_any_upstream_call
  Z4 decision record disabled -> FAILED rubygems_fully_refused_listing_records_one_decision

Verification of the fix round (capped scopes, -j 8): clippy workspace `-D warnings` clean in both feature sets; every root test binary run one at a time (55 files incl. the new rubygems_service_write, rubygems_marshal_property): all passed; the one failure of the sequence, `authorization_read_once` (the source scan found the new `forward_write` read of the caller's Authorization), got its reviewed-site entry and passed 4 of 4; `cargo test -p probation-policy` passed (gem_version 2, report_compat 3); `cargo test -p probation-server -- --test-threads 4` against Postgres 16 passed in full; `cargo test --lib osv_` 14 passed. The first `cargo check` of the round ran once outside the capped scope by mistake (a plain `timeout 600 cargo check`); nothing else did. E2E-rubygems NOT built or run.

## Recheck fix round 2026-11-19 (N1-N8)
tdd: shared_service_forwards_gem_push_and_yank_with_the_callers_own_key_only (N8, OTP + Content-Type asserted) — red: `left: (None, Some("application/octet-stream")) right: (Some("123456"), ...)` (the field existed, the route sent None) — green after the route forwards `OTP`
tdd: young_versions_beyond_the_first_page_are_withheld (N1; fake pages by `page=`) — red: assertion failed (page-1-only code listed the young nokogiri 1.2.0 java from page 2) — green: 3 page requests, tuple withheld
tdd: an_endless_recent_list_fails_closed (N1 cap) — red: `bounded: 1 page requests` (no paging) — green: stops at the page cap, nothing unindexed listed
tdd: an_oversized_recent_page_fails_closed (N4) — red: `assert!(tuples_of(..).is_empty())` (64 MiB cap parsed a 5 MiB page) — green with the 2 MiB page cap
tdd: a_failed_recent_list_is_remembered_briefly (N3) — red: `the failure is cached left: 2 right: 1` — green
tdd: cold_concurrent_index_requests_share_one_build (N6, gate on the recent fetch) — red: `one upstream fetch and one filter pass left: 6 right: 1` — green: 1 fetch, 1 recent list
tdd: mixed_case_gems_download_and_spellings_share_one_project_row (N2, N7, standalone: info, quick gemspec, gem file, second spelling, one project row) — red: 404 on the quick gemspec/gem of `RedCloth` — green
tdd: rubygems_mixed_case_gem_is_delivered_in_service_mode (N2, service) — red not observed separately (written with the fix; probe M1 below fails it)
tdd: rubygems_recent_versions_cache_is_never_read_or_filled_by_a_credential_bearing_read (N5, with positive control: two plain reads of two index files, one list; two credential-bearing, two) — red not observed separately; probe M2 fails it
tdd: a_freeze_beyond_the_recent_horizon_lists_no_unindexed_tuple (N7, behaviour kept) — red not applicable (already fail closed); guard
Fake change (tests/common/mod.rs): `{path}?page=N` / `{path}?page=*` answers; a plain path is page 1 and later pages are `[]`.

Probes of this round (restored, sha256 cmp-verified):
  M1 artifact membership uses the lower-case name again -> FAILED rubygems_mixed_case_gem_is_delivered_in_service_mode
  M2 recent cache used by credential-bearing reads -> FAILED rubygems_recent_versions_cache_is_never_read_or_filled_by_a_credential_bearing_read
  M3 no per-index flight lock -> FAILED cold_concurrent_index_requests_share_one_build
  M4 per-spelling revalidation off -> FAILED mixed_case_gems_download_and_spellings_share_one_project_row
  M5 paging stops after page 1 -> FAILED young_versions_beyond_the_first_page_are_withheld, an_endless_recent_list_fails_closed
  M6 failure cache TTL 0 -> FAILED a_failed_recent_list_is_remembered_briefly
  M7 page byte cap 64 MiB -> FAILED an_oversized_recent_page_fails_closed
Verification gap: see the end of the recheck fix round in slice-17.md (full root run, policy and server tests not completed; the stuck build is process 1703381 `cargo test -j 8 --no-run --tests`, started outside the capped scope by mistake).

tdd: rubygems_slow_recent_list_of_one_registry_does_not_stall_another (N3, two registries, one recent fetch held) — green; red observed under probe M8
  M8 recent cell keyed globally (registry and origin ignored) -> FAILED rubygems_slow_recent_list_of_one_registry_does_not_stall_another (20 s timeout), restored, sha256-verified
Verification gap closed: see the end of the recheck fix round in slice-17.md.

## Recheck-2 fix round 2026-11-19
tdd: case_spellings_per_gem_are_capped (R1) — red: statuses `[200 x10]` — green
tdd: a_slow_crawl_is_stamped_when_it_ends (R2, clock advanced past the cache lifetime while the crawl is gated) — red: `left: 2 right: 1` — green
tdd: a_dropped_request_does_not_drop_the_crawl (R2) — red: `left: 2 right: 1` — green
tdd: a_recent_crawl_over_its_deadline_fails_closed (R5) — red: the unwired setter left the request waiting (10 s test timeout) — green with the deadline field wired
tdd: rubygems_credential_bearing_index_reads_crawl_at_most_two_at_a_time (R3) — red under probe (limit 100), not observed before the code (written with it)
tdd: a_recent_list_over_the_row_cap_fails_closed, otp_is_forwarded_only_within_its_bounds (R5) — guards of existing code: red observed only under probes
Probes (restored, sha256 cmp-verified):
  P1 per-private-gate limit 100 -> FAILED rubygems_credential_bearing_index_reads_crawl_at_most_two_at_a_time
  P2 MAX_SPELLINGS 400 -> FAILED case_spellings_per_gem_are_capped
  P3 stamp taken before the crawl -> FAILED a_slow_crawl_is_stamped_when_it_ends
  P4 crawl inline (no spawned task) -> FAILED a_dropped_request_does_not_drop_the_crawl
  P5 deadline constant instead of the field -> FAILED a_recent_crawl_over_its_deadline_fails_closed
  P6 row cap 600,000 -> FAILED a_recent_list_over_the_row_cap_fails_closed
  P7 OTP cap 640 -> FAILED otp_is_forwarded_only_within_its_bounds
