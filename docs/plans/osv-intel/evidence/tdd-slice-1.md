# TDD evidence: Slice 1 (OSV vulnerability intelligence)

Witness commands: `cargo test --lib osv:: policy:: config::` and `cargo test --test config_validation`.

Baseline red, shared by every test below that lives in a new file: `src/osv` did not
exist, so `cargo test --lib osv:: policy:: config::` failed to compile
(`error[E0433]: failed to resolve: use of undeclared crate or module osv`) before any
of `src/osv/mod.rs` / `src/osv/batcher.rs` existed. Tests added to already-compiling
files (`src/policy/mod.rs`, `tests/config_validation.rs`, `src/artifacts/mod.rs`) each
failed to compile individually against the pre-slice signatures (`policy::evaluate`
took 4 arguments, `DenyReason` had no `BlockedByOsv` variant, `Config` had no
`osv_cache_ttl_seconds`/`osv_request_timeout_ms` fields) before their corresponding
production change landed.

```
tdd: policy::osv_matched_true_denies_before_digest_check — red: error[E0061]: this function takes 4 arguments but 5 were supplied — green: cargo test --lib -- policy::tests::osv_matched_true_denies_before_digest_check passed
tdd: policy::evaluate_never_lets_osv_unblock_a_producer_deny — red: same signature mismatch as above — green: cargo test --lib -- policy::tests::evaluate_never_lets_osv_unblock_a_producer_deny passed
tdd: policy::check_order_is_unavailable_deny_hold_allow (extended) — red: same signature mismatch, plus `DenyReason::BlockedByOsv` did not exist — green: cargo test --lib -- policy::tests::check_order_is_unavailable_deny_hold_allow passed
tdd: osv::evaluate_skips_osv_when_producer_already_denies — red: E0433 module osv unresolved — green: cargo test --lib -- osv::tests::evaluate_skips_osv_when_producer_already_denies passed
tdd: osv::evaluate_calls_osv_only_when_producer_would_allow — red: E0433 module osv unresolved — green: cargo test --lib -- osv::tests::evaluate_calls_osv_only_when_producer_would_allow passed
tdd: osv::check_returns_cached_answer_without_a_batcher_round_trip — red: E0433 module osv unresolved — green: cargo test --lib -- osv::tests::check_returns_cached_answer_without_a_batcher_round_trip passed
tdd: osv::check_fails_open_on_batcher_timeout — red: E0433 module osv unresolved — green: cargo test --lib -- osv::tests::check_fails_open_on_batcher_timeout passed
tdd: osv::check_writes_negative_ttl_on_failure — red: E0433 module osv unresolved — green: cargo test --lib -- osv::tests::check_writes_negative_ttl_on_failure passed
tdd: osv::check_fails_open_on_full_channel — red: E0433 module osv unresolved; first green attempt then panicked ("Closed(..)") because the test helper dropped its mpsc::Receiver before the send it was guarding — green: cargo test --lib -- osv::tests::check_fails_open_on_full_channel passed
tdd: osv::batcher::batcher_flushes_on_record_count_cap — red: E0433 module osv unresolved — green: cargo test --lib -- osv::batcher::tests::batcher_flushes_on_record_count_cap passed
tdd: osv::batcher::batcher_flushes_on_interval — red: E0433 module osv unresolved — green: cargo test --lib -- osv::batcher::tests::batcher_flushes_on_interval passed
tdd: osv::batcher::batcher_never_blocks_past_timeout_on_a_hung_connection — red: E0433 module osv unresolved — green: cargo test --lib -- osv::batcher::tests::batcher_never_blocks_past_timeout_on_a_hung_connection passed
tdd: osv::batcher::batcher_fails_open_the_whole_batch_on_length_mismatch — red: E0433 module osv unresolved — green: cargo test --lib -- osv::batcher::tests::batcher_fails_open_the_whole_batch_on_length_mismatch passed
tdd: osv::batcher::batcher_drains_after_shutdown_signal — red: E0433 module osv unresolved — green: cargo test --lib -- osv::batcher::tests::batcher_drains_after_shutdown_signal passed
tdd: osv::osv_client_new_spawns_one_batcher_task — red: E0433 module osv unresolved — green: cargo test --lib -- osv::tests::osv_client_new_spawns_one_batcher_task passed
tdd: osv::app_start_constructs_one_osv_client_and_spawns_its_batcher — red: E0433 module osv unresolved, plus AppDeps had no osv field — green: cargo test --lib -- osv::tests::app_start_constructs_one_osv_client_and_spawns_its_batcher passed
tdd: osv::running_shutdown_joins_the_batcher_task — red: E0433 module osv unresolved — green: cargo test --lib -- osv::tests::running_shutdown_joins_the_batcher_task passed
tdd: artifacts::deny_reason_maps_blocked_by_osv_in_artifacts_mod — red: error[E0004]: non-exhaustive patterns: DenyReason::BlockedByOsv not covered — green: cargo test --lib -- artifacts::tests::deny_reason_maps_blocked_by_osv_in_artifacts_mod passed
tdd: npm::deny_reason_maps_blocked_by_osv_in_npm_mod — red: test did not exist (no #[cfg(test)] mod tests in src/npm/mod.rs yet); the match arm it checks had already been added as a build-green fix, so this test's own red was "test not found" rather than a compile error — green: cargo test --lib -- npm::tests::deny_reason_maps_blocked_by_osv_in_npm_mod passed (added after team-lead review flagged the gap against Test plan row 226)
tdd: config_validation::every_invalid_config_fixture_is_refused_with_its_reason (osv_cache_ttl_seconds, osv_request_timeout_ms rows) — red: fixture files did not exist / Config had no such keys to reject — green: cargo test --test config_validation -- every_invalid_config_fixture_is_refused_with_its_reason passed
tdd: config_validation::deleting_any_sample_key_is_reported_as_that_key_missing (osv keys added to WITH_DEFAULTS) — red: sample key count assertion failed (17 != 19) before config.sample.toml carried the two new keys — green: cargo test --test config_validation -- deleting_any_sample_key_is_reported_as_that_key_missing passed
```

Post-implementation fix (sf-adversarial-testing verdict FIX): `OsvClient::resolve`
wrapped only the enqueue (`tx.send`) in `tokio::time::timeout(OSV_ENQUEUE_TIMEOUT, ..)`;
the subsequent `reply_rx.await` had no bound of its own, so a solitary `check` call —
nothing else filling the batch toward `OSV_BATCH_RECORDS` — waited on the batcher's
`OSV_BATCH_INTERVAL` (2s) flush cadence rather than on `request_timeout` (contradicting
both `check`'s own doc comment and the design's C12c/C14 promise). Fixed by wrapping
`reply_rx.await` in `tokio::time::timeout(self.request_timeout, reply_rx)`, added
`request_timeout: Duration` to `OsvClient`, and both `spawn_with`/`offline` set it.

```
tdd: osv::check_bounds_a_solitary_lookup_to_request_timeout_not_the_batch_interval — red: with reply_rx.await unbounded, a solitary lookup against a hung collector took ~OSV_BATCH_INTERVAL (2s), failing the assertion elapsed < OSV_BATCH_INTERVAL / 10 (request_timeout 20ms) — green: cargo test --lib -- osv::tests::check_bounds_a_solitary_lookup_to_request_timeout_not_the_batch_interval passed (~20-30ms)
```

`osv::check_fails_open_on_batcher_timeout` was also extended with a timing assertion
(`elapsed < OSV_BATCH_INTERVAL`) for the same regression, now passing in tens of
milliseconds rather than ~2s.

Post-implementation fix (code review, MAJOR): D3 promised "`Running::shutdown`'s
existing join-then-drain sequence already covers" the osv batcher, but `AppDeps.osv`
was a caller-built, already-spawned `osv::OsvClient` with its own independent
`CancellationToken` that `Running::shutdown` never touched — the batcher was
orphaned, not joined, on every shutdown (production and test alike). Root cause: I
had wrongly assumed no `CancellationToken` exists early enough inside `App::start`
for `osv::OsvClient::new` to use, when in fact `drain` — the token `delivery::build`
already uses for exactly this purpose — is created well before `AppDeps` is even
consumed. Fixed by reverting `AppDeps.osv: osv::OsvClient` to `AppDeps.osv_client:
reqwest::Client` (the one ingredient the design's own call-stack row named) and
having `App::start` call `osv::OsvClient::new(deps.osv_client, .., drain.clone())`
itself, pushing the returned handle into `delivery_tasks` before `tasks::spawn` —
now D3 holds exactly as written, with no new field on `AppDeps`/`Running` beyond
that one. Test hermeticity (no real network from the test suite) is preserved by a
new `osv::unreachable_client()` (test-support only): a `reqwest::Client` built with
`.resolve("api.osv.dev", <address nothing listens on>)`, so the batcher's fixed
production endpoint still resolves, connects, and is refused instantly and locally —
`OsvClient::new` itself needed no URL parameter added. `app_start_constructs_one_osv
_client_and_spawns_its_batcher` and `running_shutdown_joins_the_batcher_task` were
rewritten to actually exercise `App::start`/`Running::shutdown` (previously neither
touched `App`/`Running`/`AppDeps` despite their names, per code review). One
downstream fixture needed updating: `tests/decision_log_delivery.rs`'s
`tp3_default_config_opens_nothing` asserted `background_task_count() == 2`
(pre-Slice-1 baseline); the osv batcher is now always spawned regardless of sink
configuration, so the baseline is 3 — updated with a comment explaining why.

Minor (code review, non-blocking): `osv_matched_false_is_indistinguishable_from_
todays_behavior` — named in `03-program-design.md`'s Checks list but never written
as its own test (the property was only covered indirectly, by all 23 existing
`policy::evaluate` call sites passing `osv_matched: false`). Added as a dedicated
test in `src/policy/mod.rs`: one representative case per pre-slice `Decision` shape
(`Deny`, `Hold`, `Allow`, `Unavailable`), each asserting exactly the result its own
tier's dedicated test above already established.

Full witness command output:

```
$ cargo test --lib -- osv:: policy:: config::
test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 81 filtered out

$ cargo test --test config_validation
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`cargo test --workspace` (full suite, run once at the end): all green, no regressions
outside this slice's own files — one incidental fix was needed in
`src/osv/mod.rs`'s own `app_start_constructs_one_osv_client_and_spawns_its_batcher`
test, which had used `OriginSet::for_tests` and tripped
`origin_guard.rs::no_config_key_or_env_var_relaxes_origins` (a security invariant that
`for_tests` is named only in its own defining file); switched to
`OriginSet::production()`, which the test's `NoopTransport` never dials out through
either way.
