# Slice 16 (FIX-16-A) baseline fail-first evidence

Baseline: detached worktree of HEAD 8d9f5e3 (original committed code) with only
tests/managed_delivery_authority.rs and tests/authorization_read_once.rs copied from the main tree.
Commands: `cargo test --test <name> -j 8 --no-fail-fast`, CARGO_TARGET_DIR on disk, wrapped in systemd-run scope (TasksMax=512, MemoryMax=16G, timeout 900). All four targets compiled and ran; no timeouts, no exit 137/143.

## Results

| Target / test | Baseline | First failing assertion |
|---|---|---|
| managed_delivery_authority / managed_cold_policy_change_refuses_before_release | assertion failure | tests/managed_delivery_authority.rs:114 "a deny published before artifact release must govern the request: <verified package bytes>" |
| managed_delivery_authority / managed_http_cold_and_warm_changes_refuse_for_both_ecosystems | assertion failure | :268 "HTTP Npm warm=false http_deny" |
| managed_delivery_authority / same_revision_authority_payload_invalidates_prepared_response | assertion failure | :365 "Npm warm=true same_revision GET must govern final handoff" |
| managed_delivery_authority / cold_and_warm_current_authority_applies_to_head_range_and_get | assertion failure | :365 "Npm warm=false deny GET must govern final handoff" |
| managed_delivery_authority / accepted_stream_survives_later_authority_refusal_for_both_ecosystems | PASSED | (see below) |
| authorization_read_once / the_tree_as_built_uses_authorization_only_at_reviewed_sites | assertion failure | tests/authorization_read_once.rs:611 "hits outside the allowlist" (allowlist entries found 0, expected 1: see below) |
| authorization_read_once / harmless_edits_keep_the_scan_passing | assertion failure | :844 "a fn above RawConfig" (same stale-allowlist entries) |
| authorization_read_once / a_comment_naming_the_header_is_not_a_hit | assertion failure | :913 (same stale-allowlist entries) |
| authorization_read_once / each_mutated_copy_fails_and_names_the_extra_hit | PASSED | n/a |

Controls (unchanged, committed tests): blocklist_revocation 8/8 passed; artifacts_verification 16/16 passed.

## Compile errors / missing symbols

None. Both new test files compile against HEAD: they drive only the public HTTP router and existing management update/sync interfaces. No gate, barrier hook or OSV-generation symbol is referenced by these tests, so no stubs are needed for compilation. (The PolicyPublicationGate, barrier constructor seam and osv_generation are not exercised by this file; they belong to later tests, not this baseline.)

## Passing at baseline (must be rewritten or justified)

1. accepted_stream_survives_later_authority_refusal_for_both_ecosystems: passes on today's code. It asserts the non-retroactive boundary (an already accepted stream is not cancelled), which current behaviour already satisfies. It is a preserve-behaviour regression guard, not a fail-first test; it cannot prove FIX-16-A and needs a variant that fails first (e.g. refusal published just before the final check must refuse) or an explicit "guard, not red" classification.
2. each_mutated_copy_fails_and_names_the_extra_hit (authorization_read_once): passes at baseline; it mutates copies and expects failure, which holds regardless of the allowlist state. Same classification: guard.

## Notes on authorization_read_once failures

The 3 failures are not caused by missing FIX-16-A behaviour. The test's allowlist expects 3 sites that do not exist in HEAD source (they exist only in the uncommitted prototype source):
- src/http/registry_read.rs: `get(axum::http::header::AUTHORIZATION)` in `fn service_principal`
- src/managed/mod.rs: `get(AUTHORIZATION)` in `fn place_invalidation_cannot_stamp_an_old_admission_with_new_authority`
- src/managed/mod.rs: `insert(AUTHORIZATION, HeaderValue::from_static("Bearer prb_0123..."))` in the same test fn

So they fail by assertion at baseline because the allowlist is ahead of the code; they will pass once the prototype source (registry_read.rs service_principal, managed place_invalidation test) lands. They are not independent evidence for the FIX-16-A gate.

All four managed_delivery_authority failures are at the delivery boundary (npm; cold and warm; HEAD/range/GET), confirming the admission-time policy snapshot is released after a later deny or same-revision authority change.

Worktree and target directory removed after the run.
