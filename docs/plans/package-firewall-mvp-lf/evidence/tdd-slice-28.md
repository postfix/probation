# Slice 28 TDD record (partial: see slice-28.md for what is delivered and what is not)

All commands ran as `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900 cargo ... -j 8` with the repo's own `target/` (disk). No kills (no 137/143).
Stub rule: `ServicePolicy::reset_revision_floor` was first compiled as a no-op stub so the reds below fail by assertion, not by compile error.

## Cycle 1: LS-F8 monotonic revision floor, reset command, LS-F1 (404 is not a refusal) - tests/service_policy_cache.rs
tdd: activation_rejects_older_revision_same_binding | red: panicked at tests/service_policy_cache.rs:420 (older revision was activated) | green: `cargo test --test service_policy_cache` 15/15
tdd: activation_equal_revision_different_policy_digest_is_rejected | red: assertion failed: policy.sync_once().await.is_err() | green: same run
tdd: activation_floor_reset_by_operator_command | red: assertion failed: policy.sync_once().await.is_err() (floor not enforced at baseline) | green: same run
tdd: snapshot_404_is_not_an_authority_refusal | red: panicked at :510 (404 created a refusal) | green: same run
tdd: activation_equal_revision_identical_digest_is_accepted, activation_equal_revision_registry_edit_is_accepted, activation_equal_revision_rate_change_is_accepted, activation_after_key_rotation_starts_without_floor, floor_reset_never_clears_a_refusal | red not observed (accept-path guards; they pass at baseline and keep passing)
Implementation: `ServicePolicySnapshot::policy_digest` (crates/probation-policy/src/api.rs), `ActiveRevision` floor in the saved envelope (additive optional field), check inside the fetch step so a rejection clears the checking marker and retains the last good snapshot, `ServicePolicy::reset_revision_floor` + `revision-floor-reset` marker consumed at the next poll.

## Cycle 2: operator command - tests/service_policy_cache.rs
tdd: reset_revision_floor_command_leaves_the_marker_and_requires_service_policy | red: `error: unrecognized subcommand 'reset-revision-floor'` | green: `cargo test --test service_policy_cache` 16/16 (src/main.rs ResetRevisionFloor)

## Cycle 3: LS-F7 bounds (client side of the snapshot) - tests/service_policy_cache.rs
tdd: activation_rejects_snapshot_over_each_bound | red: panicked at tests/service_policy_cache.rs:593 "257 registries" (limit was 1000) | green: 17/17 (registries 256, cidrs 64, rules/layer 10000, string 2048, nesting 16, chain 16; at-limit accepted, one over refused, never a refusal). The 100,000 per-snapshot rule bound is implemented but unreachable with 3 layers x 10,000, so it has no test.

## Cycle 4: LS-F3 unknown ecosystem tag - tests/service_policy_cache.rs
Stubs `unavailable_registries`/`rules_skipped_unknown_ecosystem` compiled first.
tdd: activation_unknown_ecosystem_degrades_only_that_registry | red: panicked at :645 (whole snapshot rejected: sync_once returned Err on the `Maven2` tag) | green: 20/20
tdd: activation_mixed_version_snapshot_keeps_known_denies | red: panicked at :656 (same cause) | green: 20/20
tdd: activation_structural_error_still_rejects_whole_snapshot | red not observed (guard: version 2 was already rejected)

## Cycle 5: LS-F9 / D5 denylist - tests/service_connector.rs (new), tests/service_policy_cache.rs
`src/http/service_connector.rs` compiled first as a permissive stub.
tdd: descriptor_rejects_userinfo_and_ip_spellings, descriptor_ipv4_mapped_ipv6_is_denied, denylist_includes_extended_metadata_addresses, denylist_unwraps_ipv4_compatible_nat64_6to4, denylist_embedded_forms_reach_fixpoint, denylist_names_the_listener_and_control_plane, connector_refuses_hostname_resolving_to_denied_address, connector_all_resolved_addresses_must_pass | red: assertion failures at tests/service_connector.rs:18,44,53,70,81,93,101,107 | green: `cargo test --features test-support --test service_connector` 9/9
tdd: connector_refuses_rebinding_between_resolutions | red not observed (the stub also resolved once; kept as the one-resolution guard)
tdd: descriptor_naming_loopback_or_link_local_is_rejected_before_activation, descriptor_naming_the_enforcers_own_listener_is_rejected | red: panicked at tests/service_policy_cache.rs:690 and :706 (loopback target accepted through its own private CIDR; own listener accepted) | green: `--test service_policy_cache` 22/22 (check_target inside snapshot validation; `with_listener` wired in src/lib.rs)

## Cycle 6: LS-F10 listener admission - tests/listener_admission.rs (new)
Stub module `src/http/listener_admission.rs` (always true) compiled first.
tdd: listener_host_duplicate_headers_refused, listener_host_trailing_dot_and_default_port_equal, listener_absolute_form_authority_mismatch_refused, listener_http2_authority_vs_host_mismatch_refused, listener_ipv6_literal_and_idn_host_equal_canonical, peer_admission_uses_the_actual_peer_and_ipv4_mapped_normalisation, listener_cidr_prefix_floor_boundaries | red: panicked at tests/listener_admission.rs:20,31,41,52,59,76,90 | green: `cargo test --test listener_admission` 7/7 (CIDR floor /8 and /32 in src/config.rs; respond() uses peer_admitted and a Host check for CIDR-admitted non-loopback peers)

## Cycle 7: LS-F15 config - tests/service_policy_cache.rs
tdd: config_server_url_rejects_path_query_userinfo_fragment_and_http | red: panicked at :738 (a path was accepted) | green: 25/25
tdd: config_service_key_trims_single_trailing_newline | red: panicked at :763 (two trailing newlines, a trailing space were accepted: trim() trimmed all whitespace) | green: 25/25
tdd: config_service_key_rejects_control_non_ascii_and_overlong | red not observed (the fixed 36-byte format check already refused these; kept, message never echoes the key)

## Cycle 8: LS-F4 classify_read (C1028 detection) - tests/credential_bearing_reads.rs (new)
Permissive stub `src/http/credential_read.rs` compiled first.
tdd: credential_bearing_read_never_enters_shared_caches (detection half) | red: panicked at tests/credential_bearing_reads.rs:36 (Authorization read was cache-eligible) | green: 1/1 (Authorization, Proxy-Authorization, Cookie, X-NuGet-ApiKey, X-JFrog-Art-Api, X-Probe-Unknown, repeated/mixed-case, ?token=, ?api_key=, URL userinfo, extra pseudo-header; header-only allow-list control stays eligible). NOT wired into any adapter or cache yet (see slice-28.md).

## Cycle 9: LS-F12 server side - crates/probation-server/tests/service_policy_api.rs (Postgres 16 in a podman container, data dir on disk)
Stub `set_osv_scope` (returns false) compiled first.
tdd: osv_scope_migration_additive_and_reopens_old_rows | red: left [] right [("YES", None)] (no column) | green: 4/4 after migrations/0015_registry_osv_scope.sql
tdd: osv_scope_api_sets_and_clears | red: panicked at :207 (setter was a stub) | green: 4/4
tdd: revision_moves_with_every_digest_field | red not observed (layer edits already bump change_counter). Covers layer rule kinds only (block package/version, freeze, osv, allow switches, exception; platform and org layers). Chain, account and key org-membership cases NOT covered (no production mutation path found for a service key); if one is found not to bump, that field must leave the digest (LS-F8).
Wire field `osv_scope: Option<OsvScope>` (serde default, omitted when None) in crates/probation-policy/src/api.rs; portal route and form `/org/{org}/registries/{id}/osv-scope` added WITHOUT a test (portal sessions not exercised).

## Cycle 10: LS-F16 temp files - tests/credential_temp.rs (new)
Permissive stub `src/http/credential_temp.rs` compiled first.
tdd: 10 tests (no_default_request_cap_streams_large_body, optional_request_cap_refuses_413_without_retry_after, total_cap_refuses_503_with_retry_after, single_request_over_total_refuses_413_without_retry_after, enospc_refuses_503_without_retry_after, startup_sweep_skips_locked_subdirectories, startup_sweep_removes_orphans, symlinked_parent_refused, removed_on_abort_and_on_completion, refusal_happens_before_first_body_byte) | red: assertions at tests/credential_temp.rs:40,47,61,71,82,92,103,112,121,137 | green: 10/10. Module is NOT yet used by any adapter.

## Cycle 11: order guard
tdd: managed::order_guards::tests::activation_order_checks_shape_then_floor | red not observed (extraction refactor; behaviour covered by cycle 1 and 4 tests that stayed green)

## Existing test adapted
tests/shared_service.rs shared_http_cold_warm_selected_and_legacy_authority_changes published a policy change at an unchanged revision, which LS-F8 now rejects. The fixture now bumps `revision` (a real server moves it with every change). No assertion was weakened.

# Second implement pass (coordinator order: full parity, no backlog)

## Cycle 12: C1028 end to end - tests/credential_bearing_reads.rs
Test fixture: a registry whose metadata is public and whose artifact needs `Bearer allowed`.
tdd: credential_bearing_artifact_never_enters_the_shared_content_cache | red: panicked at tests/credential_bearing_reads.rs:152 "a credential-bearing body never enters the shared content store" (the verified body was published to content/), and, before that assertion was made real, `left: 200 right: 403` "bytes fetched under credential A are never served without it" (a credential-less caller was served the warm bytes) | green: 2/2 after: logging request_scoped flag + `classify_read` in `service_registry::respond`; `download::fetch_request_scoped` (request-owned file from `credential_temp`, no content store, no single-flight, identity-only pins); `PinnedFile::request_scoped`; `ApiError::PayloadTooLarge`; service-mode upstream 401/403 on artifacts now map to 401/403 like metadata; service-mode `absent` refusal cache writes removed.
Covers npm (A fetch, no-credential refusal, credential B judged by upstream, unlisted header `x-probe-unknown` forces its own upstream request, control: two eligible reads cost one transfer, temp dir empty after) and PyPI (credentialed wheel request leaves the shared store unchanged; the credential is not sent to the separate files host by design).
Metadata paths were already request-scoped in service mode (`current_project` refreshes every time, `commit_request_references_in` persists identity only, selected-registry routes are never rendered-cached); the only shared write left was the npm/PyPI `absent` refusal mark, now skipped in service mode.

## Cycle 13: LS-F9 connector - tests/service_connector.rs (+6)
Stubs `ReqwestTransport::with_denylist` and `OriginSet::with_denylist` (no-ops) compiled first.
tdd: redirect_to_denied_address_is_refused | red: panicked at tests/service_connector.rs:166 "127.0.0.1" (CIDR exemption still allowed it) | green: 15/15
tdd: connector_refuses_hostname_resolving_to_denied_address_at_connect | red: `Transport("error sending request for url (https://localhost:9/pkg)")` (the resolver let `localhost` through under the registry's own CIDRs) | green: 15/15 (Denylist consulted by `GuardedResolver` before the CIDR exemption, by `OriginSet::allows_address` for the connected peer on every hop; applied in `ReqwestTransport::selected_within` to every selected registry when `[service_policy]` is configured, src/main.rs)
tdd: standalone_loopback_target_still_allowed, service_fixture_loopback_via_seam_only, connector_ignores_proxy_environment | red not observed (controls/guards: loopback stays dialable without the denylist; `Denylist::only` is test-support only; proxy variables are ignored because `base_builder` calls `.no_proxy()`, checked in a child process with HTTP_PROXY/HTTPS_PROXY/ALL_PROXY set to a dead port)
Config keys `control_plane_cidrs`, `credential_temp_max_request_bytes`, `credential_temp_max_total_bytes` (tests/service_policy_cache.rs `config_control_plane_and_credential_temp_keys`: written after the code, red not observed).

## Cycle 14: LS-F3 readiness - tests/shared_service.rs
tdd: readiness_reports_policy_gate_and_degraded_registries | red: `left: Null right: true` (`/health/ready` had no body) | green: shared_service 5/5. Service-mode readiness returns JSON {policy_active, gate_poisoned, degraded_registries, policy_rules_skipped_unknown_ecosystem, credential_temp_bytes}; status rule unchanged plus a poisoned gate refuses. `UpstreamHealth::policy_rules_skipped_unknown_ecosystem` is set through `ServicePolicy::with_health` (no `load` signature change was needed).

## Cycle 15: HTTP-level listener - tests/listener_admission.rs (+4)
tdd: upstream_write_without_credential_is_refused | red: `POST /registry/pypi/4/ from 10.1.2.3 left: 404 right: 401` (the registry-shape check ran before the credential check) | green: 11/11 after moving the Authorization check first in `pypi_routes::selected_upload`
tdd: forged_x_forwarded_for_cannot_admit_a_foreign_peer, listener_host_checked_at_the_http_boundary | red not observed (the peer check was already on the real peer; Host check added in pass 1)
tdd: route_inventory_equals_classified_table | red: mutation probe, a temporary `.route("/extra", ...)` in src/http/mod.rs made it FAIL (left contained /extra); file restored byte for byte (verified `grep -c '"/extra"'` = 0). The test reads the router source (`package_router`) and compares paths and verbs with the R/W/X table in the test.

## Cycle 16: server guard, revision chain case, portal
tdd: crates/probation-server order_guards::tests::snapshot_order_checks_standing_before_budget | red not observed (extraction); `require_live_service_scope` now returns a `Standing`, the handler calls `snapshot_order` before `load_policy_snapshot`.
tdd: revision_moves_with_every_digest_field (group-chain case added) | real red by mutation probe: `insert_change` in crates/probation-server/src/policy.rs made a no-op; the test failed with "platform block of a package: revision 0 must exceed 0"; file restored (git diff empty). Account, org and key id cannot change for a live service key (a deleted group revokes its keys), so no case exists for them.
tdd: portal t_registry_osv_scope_form_sets_clears_and_is_listed (crates/probation-server/tests/portal_places.rs) | real red by mutation probe: the handler's `"private"` mapped to None failed with `left: None right: Some("private")`; restored (grep count 1) | green 1/1.

## LS-F7 compressed fixtures (measured 2026-11-18, real public registries, one GET each)
npm typescript packument: 2,034,864 B compressed, 15,949,929 B inflated (7.8:1); aws-sdk 1,217,406 to 10,595,791. PyPI simple JSON: botocore 650,905 to 2,617,960 (4:1); numpy 483,591 to 2,876,128; boto3 554,375 to 2,242,414. Repository fixtures: tests/fixtures/npm/representative-100-versions.json 133,876 raw, 13,326 gzip -9. The delivered `max_metadata_bytes` default is 64 MiB after decompression, above the 15.9 MiB maximum (4x headroom), so no valid input is refused and no new cap was added (LS-F7: delivered paths gain no new refusal). Row 27 re-checks at acceptance.

# Review-fix pass (reviews/slice-28/code-review.md and security-review.md, FIX FIRST)

## Cycle 17: S28-1 type seam - tests/credential_bearing_reads.rs
`GatedCache` (src/store/cache.rs) wraps the project, rendered and absent caches: reads are free, every insert takes `&CacheToken`; the only mint points are `classify_read`, `cache_token(app)` (None for a request-scoped read in service mode) and `CacheToken::for_tests` (test-support). Eight npm/PyPI insert sites updated.
tdd: credential_bearing_metadata_read_never_enters_shared_caches (carriers: Authorization, Cookie, X-NuGet-ApiKey, X-JFrog-Art-Api, unlisted header; npm packument and PyPI simple route; project, absent and rendered caches asserted empty) | red: mutation probe (cache_token always Some and the npm service-mode early return removed) failed with `cookie: project snapshot cache is empty`; both files restored (grep count 0) | green: credential_bearing_reads 4/4.
Note on the review's "control that an allow-list-only request populates the cache": in service mode the metadata path never reads or fills the project cache (every read revalidates upstream with the caller's own credential before any cached byte is used, src/npm/mod.rs current_project), because a credential-less caller must not be served a private registry's metadata from a cache. So an eligible read leaves the caches empty too; the control is therefore the type seam itself (the inserts are unreachable without a token) and the artifact control (two eligible reads, one transfer).

## Cycle 18: R28-1 / S28-2 own listener - tests/service_connector.rs, tests/service_policy_cache.rs
Stubs (`denies_endpoint` = `denies`, `resolve_checked_on` = `resolve_checked`) compiled first.
tdd: listener_wildcard_bind_denies_own_interface_address_with_listener_port | red: `own address on the listener port` | green: service_connector 18/18
tdd: endpoint_denial_uses_address_and_port | red: `assert!(wild.denies_endpoint(own, 8080))` | green
tdd: hostname_resolving_to_own_listener_endpoint_is_refused_with_its_port | red: `matches!(resolve_checked_on(..), Err(Denied))` | green
Implementation: `Denylist::denies_endpoint(ip, port)` (a wildcard listener owns every local address, found by binding a UDP socket to it; mapped and embedded spellings unwrapped); `GuardedResolver` carries the dialled origin's port; `OriginSet::allows_endpoint(peer)` (address and port of the connected peer); activation resolves descriptor hostnames (2 s bound, async) and refuses a denied answer.
tdd: descriptor_hostname_resolving_to_a_denied_address_is_rejected_at_activation | red: mutation probe (call to `check_hostnames` removed) failed at tests/service_policy_cache.rs:792; restored (grep count 1) | green 28/28. (A DNS lookup in a test leaves a blocking thread that delays runtime shutdown; the bounds test now uses an IP-literal target.)

## Cycle 19: R28-2 (USER DECISION) Host check for every peer
tdd: loopback_peer_host_checked, dns_rebinding_host_refused_on_loopback | red: `left: 404 right: 400` (a loopback peer with `Host: evil.example.test` was served) | green: listener_admission 16/16
tdd: local_names_accepted | red: `a loopback name needs the listener's own port` (127.0.0.1:1 was accepted) | green
Accepted Host values: `public_url` host, plus `127.0.0.1`, `[::1]`, `localhost`, each with the listener's actual bound port (`App::bound`, set after the bind). Proposed sentence for 03 (an approved Gate document, so not edited here): "The Host check applies to every peer including loopback; accepted values are the public_url host and 127.0.0.1, [::1] and localhost, each with the listener's own port."

## Cycle 20: R28-3, R28-4, R28-5, R28-6
- R28-3 (behaviour-preserving refactor, existing tests cover): SHA-1 updated in the streaming loop; no re-read; writes go through `TempFile::write_blocking` on the blocking pool. credential_bearing_reads and artifacts_verification stay green. Red not applicable.
- R28-4: tdd: every_class_w_route_refuses_without_credential_and_makes_no_upstream_call | red: first runs failed on real behaviour (`PUT .../-/unpublish` 404, `DELETE ...-rev` 405/404); the table now encodes it: named actions need a credential (401), direct tarball and artifact-reference DELETE are never forwarded (405/404), npm login stays credential-free | green (16/16). It drives the class column.
- R28-5: tdd: artifact_upstream_401_and_403_have_their_own_codes | red: not observable as a new failure because the old mapping returned 401 AUTHENTICATION_REQUIRED and 403 BLOCKED; the test asserts the new codes UPSTREAM_AUTHENTICATION_REQUIRED and UPSTREAM_DENIED, so it fails against the old mapping by construction | green. Proposed 03 sentence: "In shared-service mode an upstream 401 or 403 on an artifact is reported as UPSTREAM_AUTHENTICATION_REQUIRED or UPSTREAM_DENIED (never a policy BLOCKED)."
- R28-6: the detection test now uses `FamilyReadRules::NPM`. The pseudo-header branch is library-level only (the listener is HTTP/1; note for 03).

## Cycle 21: S28-3, R28-8, S28-5b, R28-7, missing row items
tdd: credential_temp_loose_parent_is_tightened | red: `got 777` | green credential_temp 13/13 (an existing parent with group/other bits is chmod 0700)
tdd: credential_temp_sweep_does_not_follow_a_symlinked_lock | red: failed (the sweep opened the symlink target) | green (a symlinked lock is skipped, target untouched)
tdd: credential_temp_sweep_removes_old_lockless_directory_and_keeps_a_fresh_one | red: failed (lock-less directory never removed) | green (older than 60 s removed, fresh kept)
S28-5b: `selected_upload` checks the credential before `admit_pypi`. Red waiver: the 401 is already returned for known registries (upstream_write_without_credential_is_refused stays green); the reorder only changes which error wins when admission would also fail, which no deterministic test can force without breaking storage health (tests/pypi_service_upload.rs and listener_admission stay green).
tdd: unknown_ecosystem_degraded_state_survives_restart | red: `left: [] right: [RegistryId(4)]` | green service_policy_cache 28/28 (additive `unavailable` and `skipped` fields in the envelope)
tdd: common_route_policy_change_refuses_before_release (tests/managed_delivery_authority.rs, FIX-16-A on the common route: deny published and confirmed while a cold artifact request is in flight refuses, zero bytes; unchanged control delivers) | red not observed: the guarantee was built and mutation-probed in slice 16 (tests/managed_release_wiring.rs); waiver recorded | green
tdd: osv_scope_migration_refuses_unknown_values_and_rolls_back (Postgres) | red not observed: guards the CHECK constraint written with the migration; waiver | green service_policy_api 5/5
S28-6: server_url must be https with certificate validation: tests/service_policy_cache.rs config_server_url_rejects_path_query_userinfo_fragment_and_http asserts `http://policy.example.test` is refused (verified present, it passed in pass 1).
S28-4: no default temp-file byte cap added (user no-loss rule); `credential_temp_max_*` stay optional and documented in docs/configuration.md.
R28-9: operator doc for `reset-revision-floor` added to docs/operations.md (section "Resetting the shared-service revision floor") and the shared-service keys to docs/configuration.md.

## Waivers for the earlier 'red not observed' tests (code review list)
config_service_key_rejects_control_non_ascii_and_overlong: the fixed 36-byte `prb_` format check refuses every spelling it forbids, so the lexical rule has no input of its own that the old code accepted; kept as the contract test. forged_x_forwarded_for_*: guard (the peer check never read forwarding headers); the rebinding Host tests above are the new reds. listener_host_checked_at_the_http_boundary: guard for the CIDR peer; the loopback cases are new reds. snapshot_order_*: extraction of an existing ordering, unit test of the guard. connector_refuses_rebinding_between_resolutions: guard, the stub also resolved once. Accept-path guards of cycle 1: they pin latest-wins of registries and rate at equal revision and passed by design.

# Final small-fix pass (code-review-r2 PASS, security-review-r2 CLEAR)

tdd: metadata_upstream_401_and_403_have_their_own_codes (tests/credential_bearing_reads.rs: npm packument, PyPI index, developer-token packument and a named read, 401 and 403 each) | red: `left: (401, "AUTHENTICATION_REQUIRED") right: (401, "UPSTREAM_AUTHENTICATION_REQUIRED")` | green: the four sites (src/npm/mod.rs, src/pypi/mod.rs, src/http/token_packument.rs, src/http/registry_routes.rs) map to UpstreamUnauthenticated / UpstreamDenied, statuses unchanged (N1)
tdd: cache_token_fails_closed_without_a_request_context_in_service_mode | red: `assert!(cache_token(&server.app()).is_none())` failed | green: `cache_token` returns None in service mode outside a request (new `logging::in_request`); standalone keeps its token (N2)
N3: comment on the deliberately ungated `references` cache in src/store/cache.rs (identity only, no body or caller-credentialed document).
tdd: readiness_detail_is_only_for_admitted_peers (tests/listener_admission.rs) | red: a peer outside allowed_peer_cidrs received the JSON detail | green: status code identical for every peer (orchestrator probes unchanged), JSON detail only for loopback and allowed CIDR peers (S28-7)
tdd: listen_port_zero_is_refused_under_service_policy (tests/service_policy_cache.rs) | red: `Config { listen: 127.0.0.1:0 ... }` accepted | green: `listen` must name a fixed port with [service_policy]; a random port stays allowed without it (S28-8)
tdd: content_store::an_open_during_eviction_is_refused_and_a_second_eviction_stands_aside (flake) | red: with the hold compiled as a no-op stub, `the first eviction reached the hold: Elapsed(())` | green: deterministic via `ContentStore::hold_next_eviction` (test-support): the first eviction notifies `reached` after claiming its key and waits for `release` before removing the file; the second eviction and the open run in exactly that window; 8 consecutive runs 12/12 under host load. Root cause of the old flake: tokio::join! does not poll in argument order, so the old comment's assumption was wrong.
Evidence text: the stale "loopback peers are exempt" statements in evidence/slice-28.md now say every peer is checked.
