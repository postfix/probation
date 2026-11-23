# Slice 16 evidence — FIX-16-A

Checks (all pass): managed_delivery_authority 5/5; authorization_read_once 4/4; blocklist_revocation 8/8; artifacts_verification 16/16; managed_release_wiring 6/6; lib publication_tests 6/6; osv generation test 1/1; molecule-check PASS.

Reviews: code-review=SHIP (4 MINOR; tautological assertion fixed, wiring test added); security=CLEAR; adversarial=PASS (6 tests kept as tests/managed_release_wiring.rs); qa=VERIFIED.

Known, not caused by this slice (identical on a clean HEAD worktree): `cargo test --lib` fails managed::client::tests::redirects_are_not_followed_and_the_environment_proxy_is_ignored and 6 osv::tests::* and two osv tests hang >60s; clippy -D warnings errors in src/http/service_unpublish.rs and src/managed/cache.rs.

Clarifications:
- C-S16-1 | resolved 2026-11-18 | A failed lookup (full/timed-out enqueue, failed or short batch) is no OSV answer and is no longer cached, so it can never overwrite a live match (deny->allow). User decision: nothing is cached without a response. Fix: src/osv/mod.rs `check` no longer puts on enqueue failure; src/osv/batcher.rs puts only when the batch produced answers. The test a_failed_lookup_fails_open_and_caches_nothing replaces a_failed_lookup_fails_open_and_is_not_retried_at_once (red: 1 request instead of 2; green after fix). osv lib tests 31/31, wiring 6/6, authority 5/5, read_once 4/4, verification 16/16. Cost: a down OSV is asked again on each cache miss (batched), no 30s back-off. NOT re-reviewed by the review agents after this change.
- C-S16-2 | resolved | Design text allows one OSV re-evaluation before refusing; code refuses on first generation change. Design test table accepts "re-evaluated or refused".
- C-S16-3 | resolved | Row 16 file list names src/lib.rs, src/osv/batcher.rs and http route files that did not change; counter lives in OsvCache (src/osv/mod.rs). Plan text only.
- C-S16-4 | resolved | Standalone mode (no managed/service policy) has no gate by design.

Full `cargo test --lib` stays flaky under parallel load on clean HEAD and with this change (different tests fail per run; osv::batcher::tests::batcher_flushes_on_record_count_cap hangs >60s). managed::client::tests::redirects_are_not_followed... sets HTTP_PROXY process-wide and never removes it; a drop guard did not stop the flakiness. Cause not found.
