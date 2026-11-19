# TDD evidence, slice 21 (Maven)

Procedure followed: /home/john/.claude/skills/lf-start/agents/implement/AGENT.md (red -> green cycles, `tdd:` lines). Inputs read: docs/plans/package-firewall-mvp-lf/{00-status,03-program-design,04-slices}.md (row 21, the Maven lines of the family table, LS-F4/F6/F7/F12, the OSV mapping), evidence/slice-17..20.md, tdd-slice-17..20.md and reviews/slice-17..20/*.md (lessons applied up front, listed in slice-21.md), /home/john/.claude/rules/pass-product-goal.md (full parity, no backlog), the NuGet and Go sources as the template.

Seams: the HTTP surface of the firewall (`/maven/...`, `/registry/maven/{id}/...`) against an in-process fake repository (`FakeRegistry`, the repository's `Last-Modified` carried by `FakeAnswer::Dated`) and a clock the test moves; the real `mvn` 3.9.16 in the pinned client container against the firewall on a real port; the strict XML scanner, the layout parser and the metadata cutter as pure functions (unit tests); the policy crate's names and OSV key; the server crate's snapshot, constraint and portal. Independent oracles: Maven Central's own documents (measured 2026-11-19: the shape of `maven-metadata.xml`, the plugin group's, `archetype-catalog.xml`, `Last-Modified` on POM, JAR and checksum files), the real client, hex digests of fixed inputs (`abc`), and the repository layout as Maven itself writes it.

Ordering note (as in slices 19 and 20): the strict scanner, the layout parser and the cutter were written together with their unit tests, the integration tests together with the serving flow they witness, so most cycles read "red not observed"; the mutation probes below are the witness that each test fails when the behaviour it names is undone. Real failures observed on first runs are copied.

## Cycles

tdd: osv_ecosystem_mapping_per_family_maven (tests/osv_ecosystem_mapping.rs) — red: after `Ecosystem::Maven` was added the first `cargo check --workspace --all-targets` failed with `error[E0004]: non-exhaustive patterns: `Ecosystem::Maven` not covered` in 8 library matches (download.rs x4, artifacts/mod.rs, logging.rs, osv/mod.rs, blocklist.rs) and in the tests that loop families (shared_service, managed_mode, managed_delivery_authority, osv_key) — each got its arm — green: `cargo test --test osv_ecosystem_mapping` passed
tdd: maven_names_are_group_and_artifact_with_one_colon_and_case_kept, a_maven_version_has_no_canonical_form_so_only_the_exact_spelling_matches (crates/probation-policy/tests/maven_names.rs), maven_keys_are_group_and_artifact_with_one_colon (osv_key.rs) — red not observed — green: `cargo test -p probation-policy` passed
tdd: a_metadata_document_is_scanned..., declarations_entities_and_instructions_are_refused, nesting_is_bounded_without_recursion, numeric_references_decode (src/maven/xml.rs) — red not observed — green: `cargo test --lib maven::xml` passed; probe M8 KILLS the declaration test
tdd: files_of_a_release_version_parse..., snapshot_builds_resolve_to_their_timestamp_and_number, metadata_paths_are_artifact_group_or_snapshot_level, one_path_is_one_identity, checksums_are_the_repositorys_own_hex (src/maven/coords.rs) — red not observed — green: `cargo test --lib maven::coords` passed; probe M9 KILLS one_path_is_one_identity
tdd: an_artifact_document_is_read_and_a_version_is_cut_with_its_line, plugins_snapshots_and_catalogs_are_read, the_wrong_root_an_entity_and_too_many_entries_are_refused (src/maven/meta.rs) — red not observed — green
tdd: every test of tests/maven_registry.rs, first run (17 of 18 failed) — red: `thread panicked at src/policy/blocklist.rs:310:9: index out of bounds: the len is 6 but the index is 6` (the blocklist's per-family tables were a constant 6; a seventh family indexed past them: the table is now `Ecosystem::ALL.len()`) — green: the 18 passed after the fixes below
tdd: every_file_of_an_allowed_version_is_served_exactly_and_every_file_of_a_held_one_is_refused_unfetched — red: `assertion left == right failed: a held version's files are never fetched  left: 2 right: 0` (a new file of a held version was probed for existence BEFORE the policy decided: the decision now comes first and makes no row and no probe) — green; probe M6 KILLS it
tdd: a_snapshot_build_ages_by_its_own_date_and_the_pointer_falls_back_to_the_newest_allowed_build — red: `left: 1 right: 0` (the same probe, for the held snapshot build's jar) — green after the same fix; probes M10 and M17 KILL it
tdd: paths_that_are_not_one_canonical_spelling_are_404_before_any_upstream_call — red: `/maven/org/demo/lib/%2e%2e/lib/1.0/lib-1.0.jar left: 200 right: 404` (the CLIENT normalised the encoded dots away, so the request was the canonical path: a test error, not a product one; the encoded forms are now sent raw with `raw_get_status` and are 404; `%2F` is the same identity as `/` and is no longer asserted to be refused) — green
tdd: a_made_up_file_name_of_a_real_version_is_a_404_and_makes_no_reference — red: the test HUNG (it held an `Arc<App>` across `server.shutdown()`, which waits for the last owner; the lesson of slice 20) — green after dropping it; probe M5 KILLS it
tdd: metadata_withholds_young_versions_names_the_newest_allowed_and_rebuilds_every_checksum, unchanged_metadata_is_byte_identical_and_its_signature_is_the_repositorys, a_version_that_ages_is_listed_once_its_cooldown_has_passed, when_every_version_is_withheld_latest_and_release_go... — red not observed — green; probes M1, M2, M3, M7 KILL the first
tdd: a_blocked_package_or_version_is_refused_before_any_upstream_call_and_case_is_identity, a_version_with_no_date_waits_on_its_first_seen_time, changed_bytes_of_a_pinned_file_are_refused_once_the_stored_copy_is_gone (jar, pom, checksum), range_and_head_work_..., a_standalone_firewall_has_no_deploy_route — red not observed — green; probe M4 KILLS the first
tdd: plugin_group_metadata_lists_no_plugin_a_policy_blocks, the_archetype_catalog_drops_what_a_policy_blocks (now also an entry's own `<repository>` URL), a_document_with_a_doctype_or_an_entity_is_a_502_and_never_expanded_or_fetched — red not observed — green; probes M15 and M16 KILL the first two
tdd: a_large_listing_is_not_refused_before_its_cap_and_the_dating_fan_out_settles_across_requests (2,100 versions: 2,048 dated on the first request, all on the second, none asked for on the third) — red not observed — green
tdd: one_registry_never_holds_more_than_its_refresh_places (six listings, four in flight, all complete) — red not observed — green; probe M14 KILLS it
tdd: a_project_at_its_row_bound_refuses_the_file_of_one_more_version_and_keeps_serving_the_rest — red not observed — green; probe M18 KILLS it
tdd: tests/maven_service_read.rs (7: a selected registry's own layout through both roots, the credential travels to the registry only, a credentialed read shares nothing, 401/403/502/404, the archive origin travels with the jar only, read-only verbs, bounded tables) — red not observed — green; probe M11 KILLS the sharing test
tdd: tests/maven_service_write.rs (6: challenge then forward with the caller's credential, the registry's answer relayed as text with a known status, layout/size/verb refusals, the public registry's deploy URL, standalone has no route, the shared spool bound) — red not observed — green; probes M12 and M13 KILL the first and the fourth
tdd: native_mvn_takes_the_newest_allowed_version_of_a_range_and_the_pin_of_a_held_one_fails, native_mvn_resolves_a_snapshot_to_the_newest_allowed_build, mvn_native_client_sends_only_allow_listed_headers (tests/maven_native.rs; the real mvn 3.9.16, Java 21.0.12.1) — red not observed (first run green; the headers it sends are `accept-encoding, cache-control, connection, host, pragma, user-agent`) — green: `cargo test --test maven_native` passed (3)
tdd: credential_bearing_read_never_enters_shared_caches_maven, credential_bearing_read_never_enters_shared_caches_maven_end_to_end, a_publication_between_authorisation_and_release_is_admitted_again_for_every_family (+ Maven) — red not observed — green
tdd: osv_skipped_for_private_registry_in_maven, osv_public_mirror_with_explicit_scope_is_queried_in_maven (src/osv/mod.rs) — red not observed — green
tdd: maven_key_route_authenticates_every_read_and_refuses_a_blocked_coordinate_locally (tests/managed_mode.rs) — red not observed — green
tdd: every_class_w_route_refuses_without_credential_and_makes_no_upstream_call, route_inventory_equals_classified_table (tests/listener_admission.rs, two Maven rows) — red not observed — green
tdd: no_config_key_or_env_var_relaxes_origins — red: `maven_upstream_url = https://registry.example/prefix must be refused` (the test's "origin only" list named the two Maven keys; they are an origin AND a path prefix like `go_artifacts_url`: moved to their own test) — green
tdd: the_maven_origins_carry_a_path_prefix_and_a_url_cannot_walk_out_of_it — red: `https://nexus.example/../repo` and `%2e%2e` were ACCEPTED by the configuration (the `url` crate resolves dot segments when it parses, so the value is `/repo`: no escape exists; the two cases were wrong and are removed) — green
tdd: the_tree_as_built_uses_authorization_only_at_reviewed_sites and its two siblings (tests/authorization_read_once.rs) — red: 3 of 4 failed (`hits outside the allowlist`: src/http/maven_routes.rs `fn credential` reads the caller's `Authorization`; the one reviewed site was added to `ALLOWED`) — green
tdd: unknown_tag_rows_are_an_explicit_decode_refusal_never_npm (crates/probation-server/tests/ecosystem_tags.rs), rejects_unsupported_algorithm_and_malformed_records (src/policy/blocklist.rs) — red: both used `maven` as their example of an unknown ecosystem tag (`left: 200 right: 503`; a `Err(MalformedRecord)` became Ok): `maven` is known from this row on, both now use `conan`, the assertions are unchanged — green
tdd: snapshot_names_a_maven_registry_and_a_maven_block, snapshot_carries_the_archive_origin_of_a_maven_registry_and_the_constraint_still_refuses_the_rest, settings_push_accepts_https_maven_origins_and_refuses_the_rest, t_registry_form_adds_a_maven_registry_with_an_optional_archive_origin_and_the_block_form_offers_maven, maven_setup_points_at_the_key_route — red not observed — green (Postgres 16 for the server ones)
tdd: archive_origin_is_checked_like_a_target_and_only_a_cargo_registry_with_a_target_may_carry_one (+ Maven), maven_reachability_is_additive_in_both_directions, a_maven_tracker_is_reported_only_after_its_first_call_and_follows_the_same_rule, maven_paths_log_their_coordinate_and_version — red not observed — green

## Mutation probes (fresh backup, sha256 compared before and after, capped scope; harness in /home/john/go/src/github.com/postfix/.probation-scratch/probes/probes.py, `run` and `restore` are separate commands)
M1 withheld versions stay listed (the allow test of `filter_artifact` always true): KILLED by `metadata_withholds_young_versions_...`
M2 a metadata checksum computed from the repository's bytes: KILLED by the same test
M3 a repository signature relayed for a document whose bytes changed: first run SURVIVED (the fake had no `.asc`, so the relay was a 404 too: an equivalent answer); the test now registers the repository's `.asc` and `.asc.sha1` and the probe is KILLED
M4 no local block check before the upstream is asked: KILLED by `a_blocked_package_or_version_is_refused_before_any_upstream_call...`
M5 a made-up file name makes a row (no existence probe): KILLED by `a_made_up_file_name_...`
M6 a held unit's file is probed before the policy decides: KILLED by `every_file_of_an_allowed_version_...`
M7 `Last-Modified` ignored (every unit undated): KILLED by `metadata_withholds_...`
M8 a DOCTYPE accepted by the scanner: KILLED by `declarations_entities_and_instructions_are_refused`
M9 a dot accepted in a group directory: KILLED by `one_path_is_one_identity`
M10 the snapshot pointer not moved to the newest allowed build: KILLED by `a_snapshot_build_ages_by_its_own_date...`
M11 a credentialed read reads the shared document cell: KILLED by `a_credentialed_read_shares_nothing_and_a_credential_free_one_shares_for_a_moment`
M12 a write with no credential proceeds to the registry: KILLED by `a_deploy_is_challenged_then_forwarded_...`
M13 the public registry always has a deploy URL: KILLED by `the_public_registrys_deploy_url_is_the_configured_one_and_otherwise_there_is_none`
M14 per-registry refresh places 4 -> 16: KILLED by `one_registry_never_holds_more_than_its_refresh_places`
M15 an archetype's own `<repository>` URL kept: KILLED by `the_archetype_catalog_drops_what_a_policy_blocks`
M16 a blocked plugin stays listed: KILLED by `plugin_group_metadata_lists_no_plugin_a_policy_blocks`
M17 a snapshot build aged by the directory version's POM: KILLED by `a_snapshot_build_ages_by_its_own_date...`
M18 the project row bound not enforced: KILLED by `a_project_at_its_row_bound_...`
All 18 are KILLED in the final run (the harness counts a probe as killed only when the build succeeded and a test failed: a probe that does not compile is reported as such, none did). Every probe line ends `restored sha256 OK` (the restore is a separate command from the one that ran the mutated code, with a `trap` as well) and the file's sha256 after equals the one before. The first batch also KILLED 17 of 18 under a looser classification; the batch above is the final one.

## Remaining stubs and limits
The packet has no "Remaining stubs and limits" entry. Stubs, mocks and hardcoded values this slice leaves: the in-process `FakeRegistry` (a transport substitute: it establishes the firewall's behaviour against documents shaped like Central's, not Central's own behaviour; the shapes and sizes were measured live on 2026-11-19), `tests/e2e/fixtures/fakes/maven.mjs` (the E2E stand-in for Maven Central, checked by native/maven-fake.test.mjs), the placeholder origin `https://maven-publish.invalid` that stands for "no deploy URL configured" in `OriginSet` (read only by `maven_publish_configured`; never contacted), and the plugin seed in the client image (fetched from real Central at image build time). Replaced by this slice: none.

## Verification
All under `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900..3000`, `cargo -j 8`; builds and tests with CARGO_TARGET_DIR in /home/john/go/src/github.com/postfix/.probation-scratch/target (on disk, never /tmp); scratch deleted afterwards.
- `cargo clippy --workspace --all-targets -- -D warnings` and with `--features probation/test-support`: clean after the last source edit.
- `cargo test -p probation-policy`: all ok (12 + 3 + 3 + 2 + 4 + 2 + 7 + 9 + 13 + 7 + 1 tests in 11 result lines, including maven_names 2, osv_key, report_compat).
- Root test binaries, built together with `cargo test --no-run --tests` and then RUN one at a time (each its own capped scope): 67 of 67 ok, 883 tests (maven_registry 20, maven_native 3 with the real mvn 3.9.16, maven_service_read 7, maven_service_write 6, credential_bearing_reads 23, listener_admission 16, managed_mode 19, origin_guard 36, authorization_read_once 4). The first pass of those 67 ran 37 binaries and then stopped: something deleted `target/debug` of the repository while it ran (exit 127, the executables were gone; not a product failure), so the target moved to the scratch directory and the remaining 30 ran there, all ok. maven_registry and its siblings were run once more after the last test edit (20, 7, 6, 3 ok).
- Full `cargo test --lib`: 263 passed, 2 ignored (the two ignored are the ones recorded in slice 19).
- `cargo test -p probation-server --no-fail-fast -- --test-threads 4` against Postgres 16 (podman container probation-s21-pg on 127.0.0.1:55434 with max_connections=500 and fsync off, data directory on disk under .probation-scratch/pgdata21, removed with `podman unshare rm -rf`): 231 passed, 0 failed, including the four new ecosystem_tags tests, the Maven portal test and the certificate script test.
- Node: `node tests/e2e/native/maven-fake.test.mjs` (25 asserts, registered in expected-asserts.json, judged by run_tests.py's own `run_one`: holds), and go-fake, cargo-fake, rubygems-fake, nuget-fake ok. FINDING outside this slice: `python3 tests/e2e/native/run_tests.py` as a whole reports 22 findings on this host, among them `nuget-fake.test.mjs`, whose last line is `nuget-fake ok` and not the `nuget-fake.test: ok` the judge requires (slice 20 recorded run_tests.py as not run); the Maven file prints the required line.
- E2E on freshly built images (`docker build --build-arg CARGO_BUILD_JOBS=8 -t localhost/probation:e2e -f Dockerfile .` and `-t localhost/probation-server:e2e -f crates/probation-server/Dockerfile .` from the final tree; client image `localhost/probation-e2e-client:maven3.9.16` from tests/e2e/compose/clients/maven.Dockerfile; the .NET, Go, Cargo and Ruby clients built by the stack): `E2E_PREBUILT=1 E2E_COMPOSE_CMD=podman-compose E2E_WORK=<scratch> node tests/e2e/harness/run.mjs --only E2E-maven --only E2E-publishing-maven-service --only E2E-nuget --only E2E-go --only E2E-cargo --only E2E-rubygems --only E2E-publishing-nuget-service --only E2E-publishing-cargo-service --only E2E-publishing-rubygems-service --only E2E-011`: 9 passed, 1 failed at the first pass (E2E-maven 25.7 s, nuget 35.6 s, go 38.7 s, cargo 23.7 s, rubygems 14.4 s, publishing-nuget-service 34.6 s, publishing-rubygems-service 28.8 s, 011 73.7 s, publishing-cargo-service in the same set); the failure was real and found by the real client: E2E-publishing-maven-service ran `mvn deploy:deploy-file` with a settings file that had no mirror, so Maven looked for the seeded deploy plugin under the repository id `central` while it had been fetched under `probation` ("present, but unavailable ... Name or service not known"). The scenario's settings now carry the same mirror id, and the scenario passed on rerun alone (34.6 s). So 10 of 10 scenarios pass on the final images (the deploy scenario on a second run of the same images; no product code changed in between).
- Cleanup: the Postgres container, the product images (probation:e2e, probation-server:e2e), the client and fakes images the stack built, the Maven client image and the pulled Maven base image removed; the scratch target directory, E2E work directory, the probe harness and the Postgres data directory deleted.
- NOT run: Gradle (the plan lists none), previous-release binaries, `check_workflow.test.py`, the browser E2E scenarios (E2E-002 and E2E-003: no UI code outside two templates and the select lists changed, covered by the server's portal tests), a live-registry test (the live Central was only read with curl for the measurements).

## Fix round (reviews/slice-21; same capped scopes, scratch and target under /home/john/go/src/github.com/postfix/.probation-scratch)

Ordering: the code and its tests were written together for the shared seams (`Transport::probe_file`, `spool::owner_of`, the row-bound helper), so most cycles are "red not observed"; the probes below are the witness. Real failures observed are copied.

tdd: the_pom_of_a_fresh_version_past_the_row_bound_is_a_503_and_makes_no_row (S21-1) — red not observed (the test was written against the fixed code; its first form asserted a 503 at the fifth anchor, which was my arithmetic, not the code) — green; probe F1 KILLS it
tdd: a_hostile_snapshot_document_and_catalog_of_a_hundred_thousand_entries_are_answered_fast (S21-2) — red not observed — green; probes F2 and F3
tdd: a_listed_version_with_no_pom_ages_from_its_first_seen_time (S21-4) — red not observed — green; probe F4
tdd: a_comment_may_hold_an_ampersand_and_latin1_documents_are_transcoded (xml unit), comments_with_ampersands_and_latin1_documents_are_read (S21-7) — red: the first HTTP test asked a second time for a document whose version had meanwhile become young (`status` was the unchanged original: the unit table already knew the version: a test design error, the changed case now uses a second artifact) — green; probes F5, F6, F7
tdd: documents_no_strict_reader_would_read_as_one_thing_are_refused (meta unit), ambiguous_metadata_is_refused_not_passed_on (F3, S21-8) — red not observed — green; probes F8, F9, F10
tdd: a_delete_of_a_directory_is_forwarded, a_directory_of_the_layout_is_an_artifact_or_a_version_directory (S21-6) — red: `left: 201 right: 404` for `/maven/org/../lib/1.0/` (the client normalised it to `/maven/lib/1.0/`, which is a valid directory: a test error, now `org/de.mo/...`) — green; probe F16
tdd: catalog_requests_queue_without_blocking_metadata_and_share_one_fetch, the_archetype_catalog_is_shared_for_credential_free_reads_only (F1) — red not observed — green; probes F11, F12
tdd: a_classifier_added_to_an_old_version_waits_its_own_cooldown (F5) — red: `left: 200 right: 403`: the probe returned no date because `Limited`, the wrapper every transport sits in (src/upstream/mod.rs), did not forward the new `probe_file` (the default implementation answered with no validators): a real defect of the new operation, found by this test, fixed by forwarding it — green; probes F13 and F19
tdd: a_gradle_module_file_naming_another_host_is_refused (F4) — red not observed — green; probe F14
tdd: a_download_that_disagrees_with_the_registrys_checksum_file_is_refused_and_not_pinned (F6) — red not observed — green; probe F15
tdd: trickling_uploads_of_one_credential_do_not_block_another_credential, a_trickle_below_the_minimum_rate_is_cut_after_the_grace_period (F2) — red not observed — green; probes F17, F18; the nuget spool tests (which keep one credential) pass unchanged
tdd: nuget_fake (tests/e2e/native/nuget-fake.test.mjs, S21-3) — red: `python3 tests/e2e/native/run_tests.py` judged `nuget-fake ok` not to be the required last line — green: it prints `nuget-fake.test: ok`

Mutation probes of the round (fresh backup, sha256 compared before and after, `run` and `restore` separate commands plus a `trap`, harness in .probation-scratch/probes2, deleted afterwards):
F1 the row bound not checked before the anchor row is committed: KILLED by `the_pom_of_a_fresh_version_past_the_row_bound_...`
F2 snapshot builds deduplicated by a linear scan: first run SURVIVED (a 90 s bound was far too loose: the fixed code needs 5.8 s for 100,000 builds); with the bound at 30 s KILLED by `a_hostile_snapshot_document_and_catalog_...`
F3 catalog `<repository>` checked against the removed entries by a linear scan: first run SURVIVED for the same reason; the catalog bound is now 5 s (the fixed code 0.56 s) and the probe is KILLED
F4 a listed version with no POM cut for ever: first run SURVIVED (the test asked for the jar between the two listings, which itself made the first-seen row); the test no longer touches a file in between and the probe is KILLED
F5 an ampersand in a comment is an entity error: KILLED (xml unit test)
F6 ISO-8859-1 not accepted: KILLED (xml unit test and `comments_with_ampersands_and_latin1_documents_are_read`)
F7 an unchanged transcoded document served transcoded: KILLED by `comments_with_ampersands_and_latin1_documents_are_read`
F8 a repeated singleton accepted: KILLED (meta unit test)
F9 plugins beside versions accepted: KILLED (meta unit test)
F10 archetype repositories not bounded: KILLED (meta unit test)
F11 the catalog not shared: KILLED by `catalog_requests_queue_without_blocking_metadata_and_share_one_fetch`
F12 a credentialed read shares the catalog: KILLED by `the_archetype_catalog_is_shared_for_credential_free_reads_only`
F13 a file's own date ignored: KILLED by `a_classifier_added_to_an_old_version_waits_its_own_cooldown`
F14 a `.module` naming another host served: KILLED by `a_gradle_module_file_naming_another_host_is_refused`
F15 first download not checked against the registry's `.sha1`: KILLED by `a_download_that_disagrees_with_the_registrys_checksum_file...`
F16 a directory DELETE loses its trailing slash: KILLED by `a_delete_of_a_directory_is_forwarded`
F17 spool places counted by the service key only: KILLED by `trickling_uploads_of_one_credential_do_not_block_another_credential`
F18 no minimum upload rate: KILLED by `a_trickle_below_the_minimum_rate_is_cut_after_the_grace_period`
F19 the upstream limiter does not forward `probe_file`: KILLED by `a_classifier_added_to_an_old_version_waits_its_own_cooldown`
All 19 KILLED in the final classification (a probe that does not compile is reported as such; none did); every `restore` ran as its own command, printed `restored sha256 OK` and the file's sha256 after equals the one before.

Verification of the round:
All under `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout ...`, `cargo -j 8`, with CARGO_TARGET_DIR on disk in the scratch directory (never /tmp, never the repository's own target, which something deleted mid-run last time); scratch deleted afterwards.
- clippy `--workspace --all-targets -- -D warnings` in both feature sets: clean after the last source edit (the first pass of this round found `nonminimal_bool`, five `needless_borrow`, a `MutexGuard` held across an await in my test and an `iter().copied().collect()`: fixed).
- probation-policy: all ok. Full `cargo test --lib`: 266 passed, 2 ignored.
- Root test binaries, built together and RUN one at a time (each its own capped scope): 67 of 67 ok, 896 tests (maven_registry 29, maven_service_read 8, maven_service_write 9, maven_native 3 with the real mvn, authorization_read_once 4 after the two new reviewed `Authorization` sites: the spool's per-credential hash and the `probe_file` header read). The first pass of this round found that very test red (3 of 4 failed on the two new sites) and the two clippy items above, which is why the whole set was run a second time on the final tree.
- `python3 tests/e2e/native/run_tests.py`: `run_tests: 27 test files hold`, exit 0 (nuget-fake prints `nuget-fake.test: ok`; the 22 findings of the previous round were this one file plus the host's own state).
- `cargo test -p probation-server --no-fail-fast -- --test-threads 4` against Postgres 16 (podman container on 127.0.0.1:55434, on-disk data directory in the scratch, removed with `podman unshare rm -rf`): 231 passed, 0 failed.
- E2E on freshly built images (both product images and the Maven client image rebuilt from the final tree, then `E2E_PREBUILT=1 ... run.mjs --only E2E-maven --only E2E-publishing-maven-service --only E2E-nuget --only E2E-go --only E2E-cargo --only E2E-rubygems --only E2E-publishing-nuget-service --only E2E-publishing-cargo-service --only E2E-publishing-rubygems-service --only E2E-011`): 10 passed, 0 failed (E2E-maven 32.3 s, publishing-maven-service 34.6 s, nuget 34.7 s, go 32.3 s, cargo 23.7 s, rubygems 15.8 s, publishing-nuget 35.0 s, publishing-rubygems 31.6 s, publishing-cargo 90.7 s, 011 74.0 s).
- Cleanup: the Postgres container, the product and client images, the pulled base image, the scratch target, E2E work, probe harness and data directories removed.

## Recheck-1 round (reviews/slice-21/recheck-1.md; same capped scopes, scratch and target on disk under .probation-scratch)

tdd: junk_credentials_under_one_key_do_not_multiply_its_places, all_six_forwarders_count_their_spool_places_per_credential_and_per_key (R1) — red: the earlier `trickling_uploads_of_one_credential_do_not_block_another_credential` itself failed (`left: 503 right: 201`) once the key cap existed, because it asserted exactly the behaviour the review called a defect; it was rewritten to assert the key share and that another key still gets a place — green; probe R1a KILLS the junk test
tdd: a_slow_start_is_allowed_a_mid_body_stall_is_not_and_the_deadline_follows_the_declared_length (R1 deadline, R5) — red: `the first chunk gets its own, longer wait` (my first form used a grace of 0 against the new floor of 16 KiB/s: the test, not the code; a 10 s grace) — green; probes R1b, R1c, R5 KILL it
tdd: an_absent_checksum_file_answered_403_is_no_check_and_a_present_wrong_one_still_blocks (R2) — red not observed — green; probe R2 KILLS it
tdd: a_file_with_a_later_date_than_its_unit_is_not_written_again_on_every_get (R3) — red: probe R3 SURVIVED the first form (it counted all store commands against a loose bound); it now compares the commands of a GET of the later-dated file with a plain file's — green; probe R3 KILLS it
tdd: a_slow_private_catalog_does_not_keep_another_registrys_catalog_waiting (R4) — red not observed — green; probe R4 KILLS it
tdd: simultaneous_first_requests_never_overshoot_the_row_bound (atomic row bound) — red: its first form asserted 200 for the admitted five, but they fail to download a POM from the gated fake (502): the assertion is now "not 503" — green; probe R6 KILLS it

Mutation probes of the round (backup, sha256 before = after, `run` and `restore` separate commands): R1a, R1b, R1c, R2, R3, R4, R5, R6: all 8 KILLED, every restore `sha256 OK`.

Verification of the round:
All under capped `systemd-run --user --scope` scopes, `cargo -j 8`, CARGO_TARGET_DIR on disk in the scratch directory; scratch deleted afterwards.
- clippy `--workspace --all-targets -D warnings`, both feature sets: clean after the last edit (the first pass of the round found one `type_complexity` on the new row-gate table, now a type alias; the maven tests, authorization_read_once, both clippy runs and the Maven lib tests were rerun after that alias).
- probation-policy ok; full `cargo test --lib`: 266 passed, 2 ignored.
- Root test binaries, built together and run one at a time: 67 of 67 ok, 903 tests (maven_registry 32, maven_service_read 9, maven_service_write 12, maven_native 3 with the real mvn, authorization_read_once 4).
- `python3 tests/e2e/native/run_tests.py` run WITHOUT NATIVE_TEST_SCRATCH (the script now defaults to a disk directory next to the repository): `run_tests: 27 test files hold`, exit 0.
- `cargo test -p probation-server --no-fail-fast -- --test-threads 4` on Postgres 16 (podman, on-disk data directory, removed with `podman unshare rm -rf`): 231 passed, 0 failed.
- E2E on freshly built images (both product images and the Maven client image rebuilt from the tree before the type alias): 10 passed, 0 failed (E2E-maven 32.8 s, publishing-maven-service 39.8 s, nuget 40.2 s, go 32.3 s, cargo 23.3 s, rubygems 9.9 s, publishing-nuget 35.2 s, publishing-rubygems 31.6 s, publishing-cargo 95.6 s, 011 74.0 s). The only source edit after the images was that type alias (no behaviour).
- Cleanup: Postgres container, product and client images, the pulled base image, scratch target, E2E work, probe harness and data directories removed.

## Recheck-2 round (reviews/slice-21/recheck-2.md; same capped scopes, scratch and target on disk under .probation-scratch)

Honest note on order: the implementation and the closure tests were written together in this round and the tests were run green; red was not observed on the old code by running it. The kill evidence is the mutation probes below (each probe reverts one decision and the named test fails), the same standard as the earlier rounds where red was "not observed".

tdd: junk_credentials_from_one_address_take_that_addresss_share_and_another_address_still_deploys (N1 service mode) — red not observed — green; probe P1 KILLS it
tdd: one_credential_from_many_addresses_holds_its_share_only (credential count) — red not observed — green; probe P7 KILLS it
tdd: a_forwarded_for_header_names_the_client_only_from_a_listed_proxy (N1, trusted proxy) — red not observed — green; unit `in_service_mode_the_address_is_the_peer_unless_a_listed_proxy_names_the_client` and probe P6 KILL a trust-everything proxy
tdd: in_certificate_mode_one_account_cannot_take_the_places_or_bytes_of_another (N1 certificate mode, unit test in src/http/spool.rs) — red not observed — green; probe P2 KILLS it
tdd: one_owner_never_holds_more_than_half_of_the_spool_budget, the_spool_places_and_bytes_are_bounded_and_returned (N2) — red not observed — green; probes P3 and P8 KILL them
tdd: the_rate_clock_starts_at_the_first_chunk_and_a_burst_does_not_license_a_trickle (N3 and trickle-hold) — red not observed — green; probes P4 (window check off: the trickle runs to the end of its stream, 14.7 s) and P5 (clock from the body start: the 2.5 s first chunk is "too slow") KILL it
tdd: existing tests adapted, not weakened: the nuget budget tests (`a_stalled_declaration...`, `two_large_uploads...`, `two_uploads_over_the_budget...`) now respect one owner's half; `all_six_forwarders_count_their_spool_places_per_real_identity_and_credential` replaces the key-id form; authorization_read_once's reviewed site moved to `fn owner_in`; `explicit_service_policy_config_accepts...` gained the `trusted_proxies` cases

Mutation probes of the round (harness .probation-scratch/probes2/probe.py, `run` and `restore` separate commands, sha256 of spool.rs and limits.rs identical before and after): P1 address ignored, P2 account ignored, P3 and P8 byte share off, P4 window floor off, P5 clock from body start, P6 every peer a trusted proxy, P7 credential count folded into the key count: all 8 KILLED, every restore `True`, final `sha256sum -c` OK.

Verification of the round (capped `systemd-run --user --scope`, CARGO_TARGET_DIR on disk in the scratch directory, deleted afterwards):
- clippy `--all-targets -D warnings`, both feature sets: clean (after boxing `Spooled::Body`, which `large_enum_variant` asked for, and one `needless_borrow`).
- probation-policy 12 ok; full `cargo test --lib`: 268 passed, 2 ignored.
- Root test binaries built together and run one at a time: 67 of 67 ok, 1236 tests. `artifacts_concurrency::blocklist_commit_is_not_delayed_by_a_large_project_refresh` failed once while the E2E stack and the image builds loaded the host (timing test, untouched by this round) and passed 15 of 15 on a rerun on the idle host.
- `python3 tests/e2e/native/run_tests.py` without any environment variable: `run_tests: 27 test files hold`.
- `cargo test -p probation-server --no-fail-fast -- --test-threads 4` on Postgres 16 (podman, on-disk data directory): 231 passed, 0 failed.
- E2E on freshly built images (both product images built from the final tree; clients rebuilt by the harness): 10 passed, 0 failed (maven 27.8 s, publishing-maven-service 32.0 s, nuget 44.5 s, go 37.6 s, cargo 24.0 s, rubygems 34.3 s, publishing-nuget 34.4 s, publishing-rubygems 29.6 s, publishing-cargo 89.6 s, 011 73.4 s).
- Cleanup: Postgres container, product and client images, scratch target, E2E work, probe harness and data directories removed.

## Recheck-3 round (reviews/slice-21/recheck-3.md; same capped scopes, scratch and target on disk under .probation-scratch)

tdd: an_ipv6_client_is_counted_by_its_64_and_a_mapped_address_as_ipv4 (R3-1) — red not observed (written with the change) — green; probe Q1 (full 128 bits) KILLS it
tdd: the_spool_budget_holds_four_times_the_artifact_cap_so_an_owners_half_takes_a_body_with_its_envelope (R3-3) — red not observed — green; probe Q2 (budget back to 2 x) KILLS it
tdd: one_owners_two_big_uploads_take_turns_and_both_complete (R3-4) — red not observed — green; probe Q3 (no turn taken) KILLS it (30.4 s: both wait out the budget wait, one is refused)
tdd: our_own_wait_for_budget_is_not_the_clients_slowness (R3-5) — red not observed — green; probe Q4 (wait not subtracted) KILLS it
tdd: the_credential_is_a_second_dimension_capped_apart_from_the_account (R3-6) — red not observed — green; probe Q5 (credential count folded into the key count) KILLS it
tdd: R3-2 warning and R3-1 documentation: no assertion on the log line (once-per-process flag); config.sample.toml and docs are the change

Honest note: as in the recheck-2 round the tests were written with the change, so the evidence of effect is the probes, not an observed red. Mutation probes (harness .probation-scratch/probes3/probe.py, `run` and `restore` separate commands, sha256 of spool.rs and limits.rs identical before and after): Q1 to Q5, 5 of 5 KILLED, every restore `True`, final `sha256sum -c` OK.

Verification of the round (capped scopes, scratch target on disk, deleted afterwards):
- clippy `--all-targets -D warnings`, both feature sets: clean.
- probation-policy ok; full `cargo test --lib`: 270 passed, 2 ignored.
- Root binaries built together and run one at a time: 67 of 67 run. The first sweep found two failures that were MY edit of config.sample.toml (the word "proxy" in the sample fails origin_guard `no_config_key_or_env_var_relaxes_origins`, and a commented block after the `[management]` section fails managed_mode `t_config_management_required`, which uncomments everything after it); the sample was reworded and the block moved before the `[management]` section, then every binary that reads the sample was rerun: all ok.
- `python3 tests/e2e/native/run_tests.py` with no environment variable: `27 test files hold`.
- probation-server on Postgres 16 (podman, on-disk data directory): 231 passed, 0 failed.
- E2E on freshly built images (rebuilt after the last source and sample change): 10 passed, 0 failed (011 73.9 s, cargo 23.3, go 33.2, maven 32.3, nuget 35.4, rubygems 14.7, publishing-cargo 90.7, publishing-maven 33.5, publishing-nuget 33.9, publishing-rubygems 29.6).
- Cleanup: Postgres container, images, scratch target, E2E work, probe harness and data directories removed.
