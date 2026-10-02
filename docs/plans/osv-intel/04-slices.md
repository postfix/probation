# Slices: OSV vulnerability intelligence

## Clarifications and decisions

| ID | Class | Status | Owning Gate | Target Gate | Question or disposition | Selected value or policy | Decision source |
|---|---|---|---|---|---|---|---|
None — checked for incoming deferrals and unresolved choices.

| Slice | Outcome | Dependencies | Exact files | Direct witness | Test prerequisites | Temporary artifacts | Reviews | Visible review triggers |
|---|---|---|---|---|---|---|---|---|
| 1 | A real request through `artifacts::serve_artifact` gets OSV-checked end to end — `osv::OsvClient` batches a live `POST /v1/querybatch` (fake transport in tests), caches the answer, and `policy::evaluate`'s new `osv_matched` tier denies a matched candidate at the correct order. Details: [Slice 1](#slice-1-interfaces) | none — first slice | `src/osv/mod.rs` (new), `src/osv/batcher.rs` (new), `src/policy/mod.rs`, `src/policy/blocklist.rs`, `src/lib.rs`, `src/config.rs`, `src/artifacts/mod.rs`, `src/main.rs`, `tests/config_validation.rs`, `config.sample.toml`, `tests/common/mod.rs`, `tests/persistence_recovery.rs`, `tests/decision_log_delivery.rs` | `cargo test --lib osv:: policy:: config::` and `cargo test --test config_validation` -> all PASS (fails today: `src/osv` does not exist); once implementation lands, `sf-spec-authoring` runs for each of the five invariants `03-program-design.md`'s `## Invariants & spec dispositions` marks `deferred to slice 1: source absent` (OR-only merge C1; OSV-absence/timeout never-fail-closed C3/C14; bounded-channel/enqueue-timeout fail-open C12a; `results`/`queries` length-check C12b; timeout-wrapped outbound call C12c) — on `KEEP`, sf-verify-cert verdict (run as `smtc`) against the written spec path and control root docs/plans/osv-intel/controls/unsafe/ must show the unsafe control firing outside the product root and zero findings scanning `src/osv/` as the product root, and that disposition line rewrites to the `KEEP:` form before this slice is considered witnessed | `cargo` on PATH; no fixtures beyond the new INVALID_CONFIGS rows this slice adds to `tests/config_validation.rs`; `smtc` on PATH for the sf-verify-cert verdict spec witnesses above, once authored | fake/no-op `OsvClient` construction path in `tests/common/mod.rs` (not removed — it is the established test-fake convention, D2 Least-confident-decision 2) | qa, code-review, security | none |
| 2 | The same OSV check now covers every production decision point — npm and PyPI per-version resolution and the artifact download path — so a version blocked by OSV is denied everywhere a version can be requested, not only through `serve_artifact`. Details: [Slice 2](#slice-2-interfaces) | `osv::evaluate` and `OsvClient` from Slice 1, unchanged | `src/npm/mod.rs`, `src/pypi/mod.rs`, `src/artifacts/download.rs` | `cargo test --lib npm:: pypi:: artifacts::download` and existing `cargo test --test decision_log_delivery` -> all PASS (fails today: these call sites still call `policy::evaluate` directly, so a version OSV blocks is allowed) | `cargo` on PATH; no new fixtures | none | qa, code-review, adversarial | none |
| 3 | A real `npm install` against a listening instance is refused because OSV — not the operator's own blocklist snapshot — flags the resolved version, proving Slices 1-2's `osv::evaluate` wrapper actually blocks an OR-only real client end to end, with a negative case showing an OSV-clear resolution still succeeds. Details: [Slice 3](#slice-3-interfaces) | `osv::evaluate`, `TestServer` (Slices 1-2, unchanged) | `tests/e2e_npm.rs` | `cargo test --test e2e_npm -- --ignored osv` -> `ok. 2 passed; 0 failed` for `npm_install_is_refused_on_an_osv_malicious_package_match` and `npm_install_succeeds_when_osv_does_not_flag_the_resolved_version` | `cargo`, `npm` on PATH (real client, per the existing e2e harness convention) | a `wiremock::MockServer` standing in for `https://api.osv.dev`, torn down at test end; no production fixtures | code-review | none |
| 4 | Operators can turn OSV enforcement on/off/diagnostic-only via `osv_mode`, defaulting to today's `enforce` behavior: `off` skips the check entirely, `enforce` denies exactly as today, `diagnostic` allows but logs the match — none of Slices 1-3's behavior changes when the key is absent. Details: [Slice 4](#slice-4-interfaces) | `osv::evaluate`, `OsvClient` (Slices 1-2, D5's `mode` field added); `RequestContext`/`record_cache` (`http::logging`, D7's seam added alongside) | `src/osv/mod.rs`, `src/config.rs`, `src/lib.rs`, `src/http/logging.rs`, `tests/config_validation.rs`, `tests/decision_log_delivery.rs`, `config.sample.toml`, `docs/operations.md` | `cargo test --lib osv:: config:: http::logging::` and `cargo test --test config_validation` and `cargo test --test decision_log_delivery` -> all PASS (fails today: `OsvMode` does not exist, `osv_mode` is not a config key, `record_osv_diagnostic_match` does not exist) | `cargo` on PATH; no fixtures beyond the new INVALID_CONFIGS row this slice adds to `tests/config_validation.rs` (an unrecognized osv_mode value, C18b), mirroring Slice 1's own osv_cache_ttl_seconds/osv_request_timeout_ms fixture rows | none — `osv_mode`'s absence keeps every existing test's behavior unchanged (default `Enforce`); the 6 existing `src/osv/mod.rs` test sites (D5, Gate 3 `## Files`) get a `mode: OsvMode::Enforce` argument added, not removed later | qa, code-review, security | none |

## Slice interface details

### Slice 1 interfaces

Uses: `reqwest::Client`, `tokio::sync::{mpsc, oneshot}`, `tokio_util::sync::CancellationToken` (existing dependency, `delivery/siem.rs`'s pattern), `tasks::spawn`'s existing `Vec<JoinHandle<()>>` join point (D3).

Changes: adds `osv::OsvClient::new`, `osv::OsvClient::check`, `osv::evaluate`, `osv::batcher::run` (all new, per `03-program-design.md`'s `### osv` and `### osv::batcher` sections); `policy::evaluate` gains the `osv_matched: bool` parameter and `DenyReason` gains `BlockedByOsv` (interface changed, not compatible — every caller updates in this slice or Slice 2); `App`/`AppDeps` gain the `osv` field; `Config` gains `osv_cache_ttl_seconds`/`osv_request_timeout_ms`; `artifacts::mod.rs`'s private `evaluate` wrapper becomes `async` and its 3 `serve_artifact` callers gain `.await`.

Design: `03-program-design.md` `### osv`, `### osv::batcher`, `### policy::evaluate`, `### policy::DenyReason`, `### App / AppDeps`, `### config`; D1-D4; the `## Threat model` table (G1/G2/G3, C12a/b/c, C14).

Acceptance: the Test plan rows for `osv_client_new_spawns_one_batcher_task`, `check_returns_cached_answer_without_a_batcher_round_trip`, `check_fails_open_on_batcher_timeout`, `check_fails_open_on_full_channel`, `check_writes_negative_ttl_on_failure`, `evaluate_skips_osv_when_producer_already_denies`, `evaluate_calls_osv_only_when_producer_would_allow`, `evaluate_never_lets_osv_unblock_a_producer_deny`, `osv_matched_true_denies_before_digest_check`, `osv_matched_false_is_indistinguishable_from_todays_behavior`, `check_order_is_unavailable_deny_hold_allow` (extended), `batcher_flushes_on_record_count_cap`, `batcher_flushes_on_interval`, `batcher_never_blocks_past_timeout_on_a_hung_connection`, `batcher_fails_open_the_whole_batch_on_length_mismatch`, `batcher_drains_after_shutdown_signal`, `deny_reason_maps_blocked_by_osv_in_artifacts_mod`, `every_invalid_config_fixture_is_refused_with_its_reason`, `deleting_any_sample_key_is_reported_as_that_key_missing`, `app_start_constructs_one_osv_client_and_spawns_its_batcher`, `running_shutdown_joins_the_batcher_task`. `sf-tdd` implements each red-then-green, one at a time, at the seam `03-program-design.md` names.

Temporary behavior: `tests/common/mod.rs`'s fake `OsvClient` is not temporary — it is the lasting test convention every later test and Slice 2 reuses; nothing here is removed later.

### Slice 2 interfaces

Uses: `osv::evaluate` (Slice 1, unchanged signature); `policy::DenyReason::BlockedByOsv` (Slice 1).

Changes: `npm::resolve`'s per-version `policy::evaluate` call (line 305) becomes `osv::evaluate(...).await`; `pypi::resolve`'s per-file call (line 318) becomes `osv::evaluate(...).await` (no `deny_reason` change here — D1, none exists); `npm::mod.rs`'s `deny_reason` (line 749) gains the `BlockedByOsv` arm; `artifacts::download.rs::transfer`'s single call (line 343) becomes `osv::evaluate(...).await`.

Design: `03-program-design.md` `## Call stack` rows for `npm::resolve`, `pypi::resolve`, `artifacts::download.rs::transfer`; D1.

Acceptance: `deny_reason_maps_blocked_by_osv_in_npm_mod`; existing npm/PyPI/download integration suites continue to pass with every call site routed through `osv::evaluate`, demonstrating the wrapper's OSV-blind-first ordering holds at every production seam (C15 completed).

Temporary behavior: none.

### Slice 3 interfaces

Uses: `TestServer::start_with_upstream_and_osv` (existing test seam wiring a real `reqwest::Client` and OSV base URL, mirroring `start_with_upstream`); `wiremock::MockServer` answering `POST /v1/querybatch` the same shape `osv::batcher`'s own unit tests use.

Changes: adds `Harness::start_for_with_osv`/`Harness::start_full` (test-only harness constructors in `tests/e2e_npm.rs`) and one `osv_flags` mock-server helper; no production code changes.

Design: no new design — exercises Slice 1's `03-program-design.md` `### osv`/`### osv::batcher` OR-only merge (C1) and Slice 2's per-call-site wiring against a real client, over the loopback HTTP server the existing e2e harness already starts.

Acceptance: `npm_install_is_refused_on_an_osv_malicious_package_match` (empty blocklist, OSV flags the pinned version — the refusal is OSV-only, not the blocklist) and `npm_install_succeeds_when_osv_does_not_flag_the_resolved_version` (the negative control: OSV would flag a held version, but the cooldown fallback resolves to an OSV-clear one, which succeeds) — both `#[ignore]`d per the existing e2e convention (real npm client).

Temporary behavior: `config.osv_request_timeout_ms` is widened to 4000ms only when the harness is started with a real OSV base URL, because the sample config's 500ms default is shorter than `OSV_BATCH_INTERVAL` (2s) and a solitary lookup never fills the batch — this is production's actual behavior on a single-package install, not a test-only quirk, and is documented at the widen site in `tests/e2e_npm.rs`.

sf-red-team: not triggered — Slice 3 adds only test harness code exercising Slices 1-2's already-modeled behavior; no new architecture, uncertainty, or security surface.

### Slice 4 interfaces

Uses: `OsvClient::new`/`spawn_with` (Slices 1-2, D5 adds the `mode` parameter); `RequestContext`/`record_cache` (`http::logging`'s existing task-local seam, D7 adds `record_osv_diagnostic_match` alongside it); `public_url`'s existing string-then-validate `config.rs` idiom and `osv_cache_ttl_seconds`'s existing `Option<u64>`/`None`-defaults-inline idiom (D6).

Changes: `pub enum OsvMode { Enforce, Diagnostic, Off }` (new, `src/osv/mod.rs`); `OsvClient` gains `mode: OsvMode`, `new`/`spawn_with` each gain a `mode: OsvMode` parameter (interface change — the 6 existing test call/literal sites Gate 3's `## Files` names all gain `mode: OsvMode::Enforce`); `osv::evaluate`'s body gains the three-way mode branch (D5) — its own signature is unchanged; `Config`/`RawConfig` gain `osv_mode`, `OPTIONAL_KEYS` gains the key, `validate()` gains the match arm (D6); `RequestContext` gains `osv_diagnostic_match: AtomicBool`, `http::logging` gains `record_osv_diagnostic_match()` and `OSV_DIAGNOSTIC_REASON`, `decide()`'s no-`ApiError` branch reads the new field (D7); `docs/operations.md` gains a bullet under `## 4. The blocklist` naming the three values and T2's accepted no-distinct-metric limitation.

Design: `03-program-design.md` D5, D6, D7, D8; the `osv`, `config`, `http::logging` `## Modules and interfaces` sections; the two new `## Call stack` rows; `evidence/threat-model-3.md` (MODELED, this slice implements its G1/T1/T2 closures verbatim).

Acceptance: the Test plan rows for `evaluate_off_mode_never_calls_check`, `evaluate_enforce_mode_denies_on_match`, `evaluate_diagnostic_mode_allows_on_match`, `evaluate_diagnostic_mode_allows_without_match`, `osv_mode_defaults_to_enforce_when_absent`, `every_invalid_config_fixture_is_refused_with_its_reason` (3rd row), `record_osv_diagnostic_match_sets_the_reason_without_changing_result` (in `tests/decision_log_delivery.rs`, alongside its existing file-sink NDJSON-content tests — the natural home for asserting a delivered record's exact `result`/`reason` fields), `record_osv_diagnostic_match_outside_a_request_is_a_no_op`. `sf-tdd` implements each red-then-green, one at a time, at the seam `03-program-design.md` names; the mode-branching tests build a real `OsvClient` via `spawn_with` against a `counting_server` (`src/osv/batcher.rs`'s existing local-mock-server pattern), never a hand-duplicated fake (Gate 3 F3).

Temporary behavior: none — `osv_mode`'s default (`Enforce`) is the permanent, lasting behavior for every deployment that never sets the key.

sf-red-team: not triggered — Gate 2's `sf-red-team` already reviewed the `osv_mode` design (FIX FIRST, closed by C17c) and Gate 3's D5-D8 pin exactly that design in concrete types; this slice implements what both reviews already covered, introducing no new architecture, uncertainty, or security surface.
