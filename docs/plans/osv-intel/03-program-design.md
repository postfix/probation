# Program Design: OSV vulnerability intelligence

## Clarifications and decisions

| ID | Class | Status | Owning Gate | Target Gate | Question or disposition | Selected value or policy | Decision source |
|---|---|---|---|---|---|---|---|
| D1 | current-Gate decision | resolved | 3 | none | Gate 2's Fit table assumed a "pypi equivalent" of `src/npm/mod.rs`'s `deny_reason` (src/npm/mod.rs:749-756) exists for the `DenyReason` match site. Does it? | No. `src/pypi/` has no `deny_reason` function and no exhaustive match over `DenyReason` anywhere. `pypi::resolve()` (src/pypi/mod.rs:285-358) never converts `Decision::Deny(reason)` to a string — it only pattern-matches `Decision::Hold` (folding `eligible_at_micros` into `next_release`) and pushes every other `Decision`, including `Deny`, unchanged into the returned `decisions: Vec<Decision>`. The exhaustive `DenyReason` match exists in exactly two places, both needing a `BlockedByOsv` arm: `src/artifacts/mod.rs:320-327` and `src/npm/mod.rs:749-757`. | `sf-impact`, `sf-codebase-intel` (this Gate) |
| D2 | current-Gate decision | resolved | 3 | none | `sf-impact` found `policy::evaluate` is called from 4 production sites, not uniformly "once or twice per request": `src/npm/mod.rs:305` and `src/pypi/mod.rs:318` call it once per version/file entry inside a `for` loop; `src/artifacts/mod.rs:199` (a private wrapper) is itself called 3 times from `serve_artifact` (lines 100, 108, 137); `src/artifacts/download.rs:343` calls it once. Does C15's "call evaluate twice, OSV-blind then real" logic get duplicated at every one of these sites? | No — C15's two-phase dance (call `policy::evaluate(..., osv_matched: false)`; only if that result is `Allow`, resolve OSV via `osv::OsvClient::check` and call `policy::evaluate` again with the real value) is written exactly once, as a new async wrapper `osv::evaluate(...)`, and every one of the 4 production call sites replaces its direct `policy::evaluate(...)` call with `osv::evaluate(&app.osv, ...).await`. This keeps the loops in npm/pypi `resolve()` and `serve_artifact`'s 3 checkpoints correct by construction (each entry/checkpoint gets its own correctly-cached OSV answer, C13) without hand-duplicating the dance at each site. `policy::evaluate` itself stays pure and still takes the plain `osv_matched: bool` (C15's Gate 2 signature is unchanged); only its callers change. | architect decision, this Gate, following `sf-codebase-design`'s "one adapter means a hypothetical seam, two means a real one" — 4 real call sites justify one shared wrapper over 4 hand-copies |
| D3 | current-Gate decision | resolved | 3 | none | How is `osv::batcher::run` spawned onto the shared `CancellationToken` without changing `tasks::spawn`'s signature? | It is not spawned by `tasks::spawn` — it follows the `delivery` sinks' existing pattern exactly: `App::start` spawns it directly (alongside constructing `osv::OsvClient`) and pushes its `JoinHandle` into the same `Vec<JoinHandle<()>>` already passed to `tasks::spawn`'s `delivery` parameter (src/tasks/mod.rs:29-46 `handles.extend(delivery)`). No new parameter, no signature change; `Running::shutdown`'s existing join-then-drain sequence already covers it. | architect decision, this Gate, grounded in `sf-repo-view`'s `src/tasks/mod.rs` and `src/delivery/mod.rs` construction evidence |
| D4 | current-Gate decision | resolved | 3 | none | Exact config key names and defaults for C13's cache TTL and C14's per-check timeout. | `osv_cache_ttl_seconds: NonZeroU64` (default 300 — 5 minutes, `OPTIONAL_KEYS`, present in `config.sample.toml` and `WITH_DEFAULTS` per the `max_references_per_project`/`metadata_max_age_seconds` convention) and `osv_request_timeout_ms: NonZeroU64` (default 500, `OPTIONAL_KEYS`, same convention). Negative-TTL (C14's failure-path cache entry) and the batcher's flush count-cap/interval and channel capacity are not configurable — they mirror `delivery/siem.rs`'s `BATCH_RECORDS`/`BATCH_INTERVAL` as fixed `const`s (`OSV_BATCH_RECORDS`, `OSV_BATCH_INTERVAL`, `OSV_NEGATIVE_TTL`, `OSV_CHANNEL_CAPACITY`, `OSV_ENQUEUE_TIMEOUT`), since none of the existing batching precedent (`siem.rs`) makes its own cadence configurable. | architect decision, this Gate, following `src/delivery/siem.rs`'s existing constant convention |
| D5 | current-Gate decision | resolved | 3 | none | Gate 2 reopened with C16-C18b (`osv_mode: enforce/diagnostic/off`). Where does `OsvMode` live, and how does `osv::evaluate` become mode-aware without D2's 4 call sites each having to branch on mode themselves? | `pub enum OsvMode { Enforce, Diagnostic, Off }` (`Copy, Clone, PartialEq, Eq, Debug`) in `src/osv/mod.rs`, alongside `OsvClient`. `OsvClient` gains a `mode: OsvMode` field, set once and never changed after (matches `threat-model-3.md`'s finding that no reload/hot-swap path exists). Slices 1-2 already built `OsvClient::new(client, cache_ttl, request_timeout, shutdown)` as a thin wrapper that pins the production URL and delegates to `pub(crate) fn spawn_with(client, url, cache_ttl, request_timeout, shutdown)` (`src/osv/mod.rs:119-150`), which builds the actual `OsvClient` struct literal and spawns the batcher; `spawn_with` is also called directly by `App::start`'s `deps.osv_base_url: Some(url)` match arm (`src/lib.rs:196-209`) for the test-server-pointed case. Both functions gain a `mode: OsvMode` parameter — `new` just forwards it to `spawn_with`, which stores it on the struct literal. `osv::evaluate`'s own signature is unchanged (D2's whole point survives this reopen): internally it reads `osv.mode` and branches once, inside the one wrapper, instead of duplicating a mode check at each of the 4 call sites. `Off`: returns `policy::evaluate(..., osv_matched: false)` directly, `OsvClient::check` is never called (C18's short-circuit). `Enforce`: D2's existing two-phase dance, unchanged. `Diagnostic`: the same two-phase dance runs (so C13's cache and C12's batcher still see every request), but the second `policy::evaluate` call always passes `osv_matched: false`; if the real check answered `true`, `osv::evaluate` calls `crate::http::logging::record_osv_diagnostic_match()` (D7) before returning. This stays inside the wrapper rather than following `record_cache`/`record_ecosystem`'s route-handler-owned-call precedent, because the diagnostic condition (mode + the two-phase dance's real answer) is entirely internal to `osv::evaluate` already — pushing it back out to 4 call sites would just be copying the wrapper's own state for no reason. | architect decision, this Gate, extending D2 under the same "one wrapper, real call sites justify it" reasoning, grounded in `src/osv/mod.rs:119-150` and `src/lib.rs:196-209`'s existing `new`/`spawn_with` split and both call sites |
| D6 | current-Gate decision | resolved | 3 | none | Exact `config.rs` shape for `osv_mode` (C18/C18b: string, validated, hard-fail on an unrecognized value, default `enforce`). | Follows `public_url`'s existing string-then-validate idiom for validation (`src/config.rs:219-236`, `invalid(key, reason)`), and D4's own already-implemented optional-key convention for the default — not a serde default attribute (`config.rs` uses none anywhere): `RawConfig.osv_mode: Option<String>`, added to `OPTIONAL_KEYS`; `validate()` gets a new arm shaped exactly like `osv_cache_ttl_seconds`'s existing one (`src/config.rs:393-396`): `osv_mode: match self.osv_mode { Some(value) => match value.to_lowercase().as_str() { "enforce" => osv::OsvMode::Enforce, "diagnostic" => osv::OsvMode::Diagnostic, "off" => osv::OsvMode::Off, _ => return Err(invalid("osv_mode", format!("must be one of enforce, diagnostic, off, got {value:?}"))) }, None => osv::OsvMode::Enforce }` (C18b's hard-fail, no silent fallback; `None` gets the default inline, matching `DEFAULT_OSV_CACHE_TTL_SECONDS`'s pattern, not a `DEFAULT_OSV_MODE` constant since the default is a fieldless enum variant, not a numeric literal worth naming separately). `Config.osv_mode: osv::OsvMode`, imported the same way `config.rs` already imports `crate::delivery` for `delivery::SomeType` (`src/config.rs:16`) — no new import convention. | architect decision, this Gate, grounded in `src/config.rs:1-16,219-236,393-399`'s existing validated-string-key and optional-numeric-key idioms |
| D7 | current-Gate decision | resolved | 3 | none | Exact `http::logging` shape for C17b/C17c's diagnostic-match logging seam. | `RequestContext` (`src/http/logging.rs:100-106`) gains `osv_diagnostic_match: AtomicBool`, initialized `false` alongside `cache`/`ecosystem` in `decide()`'s context construction (line ~173). A new `pub fn record_osv_diagnostic_match()` mirrors `record_cache`'s exact shape (`CONTEXT.try_with(\|context\| context.osv_diagnostic_match.store(true, Ordering::Relaxed))`, silently a no-op outside a request — the same tolerance `record_cache` already has, which is what lets `osv::evaluate`'s own `#[cfg(test)] mod tests` call it unconditionally without a request context). A new `pub(crate) const OSV_DIAGNOSTIC_REASON: &str = "the request would be blocked by a known OSV malicious-package advisory (diagnostic mode: not enforced)"` (C17c). `decide()`'s `None` (no-`ApiError`) branch (line ~191) becomes: `if context.osv_diagnostic_match.load(Ordering::Relaxed) { ("ALLOWED", OSV_DIAGNOSTIC_REASON.to_owned()) } else { ("ALLOWED", "the request was served".to_owned()) }`. | architect decision, this Gate, grounded in `src/http/logging.rs:100-134,189-193`'s existing `RequestContext`/`record_cache`/`decide()` shapes |
| D8 | current-Gate decision | resolved | 3 | none | Does this Gate's `osv_mode` design introduce any new entry point, trust boundary, or asset beyond Gate 2's `threat-model-3.md` (MODELED)? | No. D5-D7 are concrete Rust types/call shapes implementing exactly what C16-C18b already decided and `sf-threat-model`/`sf-red-team` already reviewed at Gate 2 — `OsvMode`'s three variants, the `RequestContext` seam, and the hard-fail validation are pinned here, not redesigned. No new external call, no new config surface beyond the one `osv_mode` key C18 already named, no change to what crosses the OSV/decision-log trust boundary. This Gate's mandatory Security trigger (untrusted OSV response feeding a decision) is unchanged from Gate 2/the original Gate 3 approval; `sf-threat-model` is not re-dispatched for a pure type/shape pinning that introduces nothing new to model. | architect decision, this Gate, non-regression check against `docs/plans/osv-intel/evidence/threat-model-3.md` |

## Files

- `src/osv/mod.rs` (new; further changed this reopen, D5) — `OsvClient` (cache + batcher sender) and the `osv::evaluate` wrapper (D2) that every production call site uses. D5 adds `mode: OsvMode` to the `OsvClient` struct and to both `new`/`spawn_with`; this module's own `#[cfg(test)] mod tests` (already built by Slices 1-2) has 6 existing call/literal sites that break and need `mode: OsvMode::Enforce` added (the neutral, today's-behavior default — none of these 6 tests are about mode): 4 constructor calls — `check_fails_open_on_batcher_timeout` (line 464, `spawn_with`), `check_bounds_a_solitary_lookup_to_request_timeout_not_the_batch_interval` (line 502, `spawn_with`), `check_writes_negative_ttl_on_failure` (line 531, `spawn_with`), `osv_client_new_spawns_one_batcher_task` (line 568, `new`) — plus 2 direct `OsvClient { .. }` struct literals that bypass both constructors entirely: the `client_with_capacity` test helper (line 276-281) and the inline literal in `check_fails_open_on_full_channel` (line 421-426).
- `src/osv/batcher.rs` (new) — the batching background task, mirroring `src/delivery/siem.rs`'s `run`/flush shape (C12), with the timeout-wrapped outbound call (C12c) and length-checked pairing (C12b) `siem.rs` does not need.
- `src/policy/mod.rs` (changed) — `evaluate` gains `osv_matched: bool`; `DenyReason` gains `BlockedByOsv`; `check_order_is_unavailable_deny_hold_allow` is extended, not replaced; its 23 unit-test call sites (`mod tests`, lines 210-480) each gain the new argument.
- `src/policy/blocklist.rs` (changed) — 3 unit-test call sites in `mod tests` (lines 540, 840, 851) each gain the new argument.
- `src/lib.rs` (changed) — `AppDeps` and `App` each gain an `osv: osv::OsvClient` field; `App::start` constructs it and spawns `osv::batcher::run`, pushing its handle into the `delivery` vec before calling `tasks::spawn` (D3).
- `src/config.rs` (changed) — `osv_cache_ttl_seconds`, `osv_request_timeout_ms` added to `OPTIONAL_KEYS`, `RawConfig`, `Config`, and `validate()` (D4). This reopen adds a third key, `osv_mode`, to the same four places (D6) — `OPTIONAL_KEYS` (line 179-198), `RawConfig.osv_mode: Option<String>` (near line 142-143), `Config.osv_mode: osv::OsvMode` (near line 74-78), and a new `validate()` match arm (near line 393-399).
- `src/artifacts/mod.rs` (changed) — `deny_reason` (line 320) gains a `BlockedByOsv` arm; the private `evaluate` wrapper (lines 192-210) becomes `async` and calls `osv::evaluate` instead of `policy::evaluate` directly; its 3 callers in `serve_artifact` (lines 100, 108, 137) each gain `.await`.
- `src/npm/mod.rs` (changed) — `deny_reason` (line 749) gains a `BlockedByOsv` arm; the per-entry `policy::evaluate` call in `resolve()` (line 305) becomes `osv::evaluate(...).await`.
- `src/pypi/mod.rs` (changed) — the per-entry `policy::evaluate` call in `resolve()` (line 318) becomes `osv::evaluate(...).await`; no `deny_reason` change (D1 — none exists here).
- `src/artifacts/download.rs` (changed) — its single `policy::evaluate` call (line 343) becomes `osv::evaluate(...).await`.
- `src/main.rs` (changed) — `serve()` constructs the production `osv::OsvClient` (real `reqwest`-backed transport) and adds it to the `AppDeps` literal (lines 137-142).
- `tests/config_validation.rs` (changed) — new `INVALID_CONFIGS` fixture rows for both original keys (mirroring the `zero_blocklist_poll_seconds.toml` pattern) and both keys added to `WITH_DEFAULTS`. This reopen adds a third `INVALID_CONFIGS` row (`invalid_osv_mode.toml`, an unrecognized `osv_mode` string, C18b) and `osv_mode` to `WITH_DEFAULTS`.
- `config.sample.toml` (changed) — both original keys added with their default values (bumps the asserted sample-key count). This reopen adds `osv_mode = "enforce"` (bumps the count again).
- `tests/common/mod.rs` (changed) — the shared `start()` test helper (lines 471-475) gains a fake/no-op OSV client so integration tests never touch the real OSV endpoint, mirroring the existing `Transport` fake convention.
- `tests/persistence_recovery.rs`, `tests/decision_log_delivery.rs` (changed) — 3 direct `AppDeps` literals (persistence_recovery.rs:349-353; decision_log_delivery.rs:413-417, 971-975) each supply a fake OSV client.
- `src/http/logging.rs` (changed, D7) — `RequestContext` gains `osv_diagnostic_match: AtomicBool`; new `record_osv_diagnostic_match()` and `OSV_DIAGNOSTIC_REASON` constant; `decide()`'s no-`ApiError` branch reads the new field.
- `docs/operations.md` (changed, D5/F2) — a new bullet under an operations section (no OSV section exists yet; added alongside the blocklist docs, `## 4. The blocklist`) naming the three `osv_mode` values and recording T2's accepted limitation verbatim: `diagnostic` mode is monitor-only, with no counter/metric distinct from ordinary allowed traffic — the NDJSON `reason` field (`OSV_DIAGNOSTIC_REASON`) is the only signal, so an operator watching for it should grep/alert on that string, not a dedicated metric.

## Modules and interfaces

Programming entry point: none — an added await at each existing decision point plus one new background batching task.

### `osv` (`src/osv/mod.rs`; proposed)

Purpose: answer "does OSV block (ecosystem, name, version)?", cheaply on repeat, without ever blocking a request past a short bound.

Provides: `OsvClient::check`, `osv::evaluate` (the shared C15 two-phase wrapper, D2).

Owns: the short-TTL result cache (C13); the batcher's `mpsc::Sender` handle.

Public types and values:
- `pub struct OsvClient` — opaque; holds `tx: mpsc::Sender<OsvRequest>`, `cache: OsvCache` (an internally-locked `HashMap<(Ecosystem, String, String), CacheEntry>`, `CacheEntry { matched: bool, expires_at: Instant }`), and `mode: OsvMode` (D5).
- `type OsvRequest = ((Ecosystem, String, String), oneshot::Sender<bool>)` — one queued lookup and its reply channel.
- `pub enum OsvMode { Enforce, Diagnostic, Off }` (D5) — `Copy, Clone, PartialEq, Eq, Debug`; read only by `osv::evaluate`, set once at construction, never mutated.

Callers and visibility: `pub`, re-exported from `src/lib.rs` like every other top-level module; called from `osv::evaluate` (internal) and from `App::start`/`src/main.rs` for construction.

#### `OsvClient::new` (existing, Slice 1; changed, D5)

Declaration: `pub fn new(client: reqwest::Client, cache_ttl: Duration, request_timeout: Duration, mode: OsvMode, shutdown: CancellationToken) -> (OsvClient, tokio::task::JoinHandle<()>)`

Accepts: an already-built `reqwest::Client` (production: real; tests: a client pointed at a mock/no-op transport, mirroring `Transport`'s fake convention), the two D4 durations, the new D5/D6 enforcement mode (config-derived, fixed for the client's lifetime), and the shared shutdown token.

Returns: the client handle plus the spawned batcher's `JoinHandle`, so the caller (`App::start`) can push the handle into the same `Vec<JoinHandle<()>>` `tasks::spawn` already joins (D3).

Rejects: none — construction cannot fail.

Effects: pins the production OSV URL (`OSV_QUERYBATCH_URL`) and delegates to `spawn_with` below, forwarding `mode` unchanged.

Caller obligations: call exactly once per `App`; keep the returned `OsvClient` alive for the process lifetime (its `tx` must stay open until shutdown).

Uses: `OsvClient::spawn_with`.

Caller example:
```rust
let (osv, osv_handle) = OsvClient::new(reqwest_client, cache_ttl, request_timeout, mode, shutdown.clone());
delivery_handles.push(osv_handle);
let tasks = tasks::spawn(Arc::clone(&app), shutdown, watcher, delivery_handles);
```

Checks: `osv_client_new_spawns_one_batcher_task`.

#### `OsvClient::spawn_with` (existing, Slice 1; changed, D5)

Declaration: `pub(crate) fn spawn_with(client: reqwest::Client, url: Url, cache_ttl: Duration, request_timeout: Duration, mode: OsvMode, shutdown: CancellationToken) -> (OsvClient, tokio::task::JoinHandle<()>)`

Accepts: `new`'s parameters plus an explicit endpoint `url` (tests point this at a local mock server, `src/osv/batcher.rs`'s `counting_server` pattern).

Returns: same shape as `new`.

Rejects: none.

Effects: builds the `OsvClient` struct literal (now storing `mode`) and spawns `osv::batcher::run` once, exactly as before this reopen — only the added field changes.

Caller obligations: `App::start`'s `deps.osv_base_url: Some(url)` match arm (`src/lib.rs:196-209`) calls this directly and must now also pass `deps.config.osv_mode`; `new`'s `None` arm gets `mode` via `new`'s own new parameter. Both `src/lib.rs` match arms change, not only one — this is the caller-impact D2's `sf-impact` precedent requires naming explicitly (F1).

Uses: `osv::batcher::run`.

Checks: `osv_client_new_spawns_one_batcher_task` (covers both paths via `new`; `spawn_with`'s direct callers are exercised by every existing test that already uses it to point at a local server).

#### `OsvClient::check` (proposed)

Declaration: `pub async fn check(&self, ecosystem: Ecosystem, name: &str, version: &str) -> bool`

Accepts: the exact (ecosystem, name, version) to judge; no preconditions.

Returns: `true` only on a confirmed OSV `MAL-*` match; `false` for no match, a cache miss that fails open, a full/timed-out enqueue (C12a), a batch failure or length mismatch (C12b/C14), or an outbound timeout (C12c) — every failure path answers `false`, never blocks past `request_timeout`, and is counted (mirrors `SinkCounters`).

Rejects: none — this function cannot fail; every failure mode degrades to `false`.

Effects: on a cache miss, enqueues into the batcher and populates the cache with the answer (normal TTL on a real answer, `OSV_NEGATIVE_TTL` on any failure path) before returning.

Caller obligations: none beyond normal async calling convention; safe to call concurrently and repeatedly for the same key (cache absorbs repeats, C13).

Uses: the batcher via `tx.send`, bounded by `OSV_ENQUEUE_TIMEOUT` (C12a); the reply `oneshot`, bounded by `request_timeout` (C14).

Caller example:
```rust
let matched = app.osv.check(candidate.ecosystem, candidate.name, candidate.version).await;
```

Checks: `check_returns_cached_answer_without_a_batcher_round_trip`, `check_fails_open_on_batcher_timeout`, `check_fails_open_on_full_channel`, `check_writes_negative_ttl_on_failure`.

#### `osv::evaluate` (proposed)

Declaration: `pub async fn evaluate(osv: &OsvClient, snapshot: Option<&BlocklistSnapshot>, now_utc_micros: i64, cooldown_seconds: u64, candidate: &Candidate<'_>) -> Decision`

Accepts: exactly `policy::evaluate`'s existing 4 parameters, plus the `OsvClient` handle.

Returns: the final `Decision` for this candidate, with C15's OSV-blind-first ordering already applied, gated by `osv.mode` (D5).

Rejects: none.

Effects: calls `policy::evaluate(snapshot, now_utc_micros, cooldown_seconds, candidate, osv_matched: false)`; if that result is not `Allow`, returns it unchanged, no OSV call (C15). If it is `Allow` and `osv.mode == Off`, returns it unchanged, no OSV call (C18/D5). If it is `Allow` and `osv.mode` is `Enforce` or `Diagnostic`, calls `osv.check(...)`: under `Enforce`, calls `policy::evaluate` a second time with the real value and returns that. Under `Diagnostic`, calls `policy::evaluate` a second time with `osv_matched: false` (never denies); if the real check was `true`, also calls `crate::http::logging::record_osv_diagnostic_match()` (D7) before returning the (always-`Allow`-or-unaffected) result.

Caller obligations: replaces every direct production call to `policy::evaluate` (D2); unit tests of the pure decision logic keep calling `policy::evaluate` directly.

Uses: `policy::evaluate` (twice, conditionally); `OsvClient::check`; `crate::http::logging::record_osv_diagnostic_match()` (conditionally, D5/D7).

Caller example:
```rust
let decision = osv::evaluate(&app.osv, Some(&snapshot), now, app.config.cooldown_seconds, &candidate).await;
```

Checks: `evaluate_skips_osv_when_producer_already_denies`, `evaluate_calls_osv_only_when_producer_would_allow`, `evaluate_never_lets_osv_unblock_a_producer_deny` (C1 non-regression), `evaluate_off_mode_never_calls_check`, `evaluate_enforce_mode_denies_on_match`, `evaluate_diagnostic_mode_allows_on_match`, `evaluate_diagnostic_mode_allows_without_match`. The `record_osv_diagnostic_match()` side effect these last two trigger is not asserted here: `RequestContext`/`CONTEXT` are private to `http::logging` with no test accessor, and this function is not the public seam that effect is observable through anyway — `record_osv_diagnostic_match_sets_the_reason_without_changing_result` (Test plan) proves it through the actual public seam, the delivered decision-log record, via a real request.

### `osv::batcher` (`src/osv/batcher.rs`; proposed)

Purpose: coalesce concurrent OSV lookups into `POST /v1/querybatch` calls without ever blocking on a hung outbound connection.

Provides: the background loop `osv::batcher::run`.

Owns: its own flush cadence and in-flight batch (transient, no persistence, C7).

Public types and values: none exported beyond `run`; `OsvRequest` is defined and owned by `osv` (parent module).

Callers and visibility: `pub(super)`, matching `delivery/siem.rs`'s visibility; spawned once by `OsvClient::new`.

#### `osv::batcher::run` (proposed)

Declaration: `pub(super) async fn run(client: reqwest::Client, url: Url, mut rx: mpsc::Receiver<OsvRequest>, request_timeout: Duration, shutdown: CancellationToken)`

Accepts: the OSV HTTP client and endpoint URL, the request queue, the outbound-call timeout bound (reused from C14/D4's `osv_request_timeout_ms`, satisfying C12c), and the shared shutdown token.

Returns: nothing — runs until the channel closes or shutdown fires.

Rejects: none.

Effects: mirrors `delivery/siem.rs::run`'s `loop { tokio::select! { rx.recv(), sleep_until(deadline), shutdown.cancelled() } }` shape (accumulate → flush on `OSV_BATCH_RECORDS` count-cap or `OSV_BATCH_INTERVAL` interval, whichever first); each flush issues one `POST /v1/querybatch` wrapped in `tokio::time::timeout(request_timeout, ...)` (C12c — never awaited unbounded, unlike `siem.rs`'s send); on a successful, on-time response, checks `results.len() == queries.len()` before any positional pairing (C12b) — a mismatch, a timeout, a non-2xx, or a transport error answers every waiter in that flush with `false` over its `oneshot` (C14), the same fail-open path for every failure kind, so `OsvClient::check` needs only one failure branch.

Caller obligations: exactly one instance per process; the caller (`OsvClient::new`) owns keeping `rx`'s matching `tx` alive.

Uses: `reqwest::Client::post`; `tokio::time::timeout`; `tokio::select!`.

Caller example: not called directly by application code — spawned once, see `OsvClient::new`.

Checks: `batcher_flushes_on_record_count_cap`, `batcher_flushes_on_interval`, `batcher_never_blocks_past_timeout_on_a_hung_connection` (C12c, closes threat-model G1), `batcher_fails_open_the_whole_batch_on_length_mismatch` (C12b, closes G3), `batcher_drains_after_shutdown_signal`.

### `policy::evaluate` (`src/policy/mod.rs`; changed)

Declaration: `pub fn evaluate(snapshot: Option<&BlocklistSnapshot>, now_utc_micros: i64, cooldown_seconds: u64, candidate: &Candidate<'_>, osv_matched: bool) -> Decision`

Accepts: its existing 4 parameters unchanged, plus `osv_matched: bool` — the caller-resolved answer to "does OSV block this exact version" (never resolved inside this pure function, C15).

Returns: `Decision`, unchanged shape; `osv_matched: true` denies at the same tier as the existing producer package/version checks, before the digest check (Gate 2 Fit table); `false` contributes no block.

Rejects: none — pure, total function, same as today.

Effects: none — still no I/O, no clock read (only `now_utc_micros` is used).

Caller obligations: every production caller now goes through `osv::evaluate` (D2), never calls this directly with a resolved OSV answer inline; unit tests call it directly with a literal `osv_matched` value.

Uses: none new.

Caller example:
```rust
let decision = policy::evaluate(Some(&snapshot), now, cooldown, &candidate, osv_matched);
```

Checks: `check_order_is_unavailable_deny_hold_allow` (extended with an `osv_matched` case, not replaced), `osv_matched_true_denies_before_digest_check`, `osv_matched_false_is_indistinguishable_from_todays_behavior`.

### `policy::DenyReason` (`src/policy/mod.rs`; changed)

Declaration: `pub enum DenyReason { BlockedPackage, BlockedVersion, BlockedDigest, MalformedTimestamp, FutureTimestamp, NoTimestamp, BlockedByOsv }`

Provides: one new variant, `Copy`, exhaustive (D1 — exactly 2 match sites need a new arm: `src/artifacts/mod.rs:320`, `src/npm/mod.rs:749`).

Checks: `deny_reason_maps_blocked_by_osv_in_artifacts_mod`, `deny_reason_maps_blocked_by_osv_in_npm_mod` (both `const fn`, exhaustive-match compile checks doubling as unit tests).

### `App` / `AppDeps` (`src/lib.rs`; changed)

Declaration: `AppDeps` gains `pub osv: osv::OsvClient`; `App` gains `osv: osv::OsvClient` (private, matching `policy`/`store`'s privacy, since it is reached only through `osv::evaluate` call sites that already hold `&App`).

Accepts / Effects: `App::start` (src/lib.rs:134) constructs `osv::OsvClient::new(...)` alongside its existing `delivery::Sinks` construction, pushes the returned batcher handle into the same `Vec<JoinHandle<()>>` passed to `tasks::spawn` (D3), and stores the client on `App`.

Caller obligations: all 5 `AppDeps` struct-literal construction sites (`src/main.rs:137`, `tests/common/mod.rs:471`, `tests/persistence_recovery.rs:349`, `tests/decision_log_delivery.rs:413`, `tests/decision_log_delivery.rs:971`) must supply a value — production a real client, tests a fake/no-op one (no existing convention for this yet; established here, mirroring `Transport`'s fake).

Checks: `app_start_constructs_one_osv_client_and_spawns_its_batcher`, `running_shutdown_joins_the_batcher_task`.

### `config` (`src/config.rs`; changed)

Declaration: `Config` gains `osv_cache_ttl_seconds: NonZeroU64`, `osv_request_timeout_ms: NonZeroU64`, `osv_mode: osv::OsvMode` (D6); all three added to `OPTIONAL_KEYS`, `RawConfig` (with serde default functions), and `validate()`. The two durations use the nonzero-conversion pattern shared with every other duration/count field; `osv_mode` uses the string-then-match-then-`invalid()` pattern shared with `public_url` (D6).

Checks: `every_invalid_config_fixture_is_refused_with_its_reason` (extended with 3 new `INVALID_CONFIGS` rows: zero TTL, zero timeout, unrecognized `osv_mode`), `deleting_any_sample_key_is_reported_as_that_key_missing` (all three keys added to `WITH_DEFAULTS`, sample key count bumped), `osv_mode_defaults_to_enforce_when_absent`.

### `http::logging` (`src/http/logging.rs`; changed, D7)

Declaration: `RequestContext` gains `osv_diagnostic_match: AtomicBool`; new `pub fn record_osv_diagnostic_match()` and `pub(crate) const OSV_DIAGNOSTIC_REASON: &str`.

Accepts / Effects: `record_osv_diagnostic_match()` sets the task-local flag, mirroring `record_cache`'s exact shape and its silent-no-op-outside-a-request tolerance. `decide()`'s no-`ApiError` branch reads the flag and substitutes `OSV_DIAGNOSTIC_REASON` for the default `"the request was served"` reason when set; `result` is unaffected either way (`"ALLOWED"`).

Caller obligations: called only from `osv::evaluate` (D5), under `osv_mode: diagnostic` and a real OSV match; no other caller.

Checks: `record_osv_diagnostic_match_sets_the_reason_without_changing_result`, `record_osv_diagnostic_match_outside_a_request_is_a_no_op` (mirrors `record_cache`'s existing outside-a-request tolerance).

## Call stack

| Caller -> operation | Value/state passed | Why accepted | Result/failure handling |
|---|---|---|---|
| `App::start` (`deps.osv_base_url: None` arm) -> `osv::OsvClient::new` | production `reqwest::Client`, D4 durations, `deps.config.osv_mode` (D5), shared `shutdown` token | one-time process construction, same point as `delivery::Sinks`; production/default path | returns client + batcher handle; handle pushed into `tasks::spawn`'s `delivery` vec (D3) |
| `App::start` (`deps.osv_base_url: Some(url)` arm) -> `osv::OsvClient::spawn_with` | test `reqwest::Client`, explicit `url`, D4 durations, `deps.config.osv_mode` (D5), shared `shutdown` token | the test-server-pointed construction path (`src/lib.rs:196-209`); both match arms now pass `mode` (F1) | same as `new`'s row |
| `npm::resolve` (per version, loop) -> `osv::evaluate` | current `snapshot`, `now`, `cooldown_seconds`, this loop iteration's `Candidate` | producer snapshot alone would decide `Allow` or not, per-version (Gate 2 flow step 1-2) | `Decision` folded into this version's response entry, same as today's `policy::evaluate` result |
| `pypi::resolve` (per file, loop) -> `osv::evaluate` | same shape, PyPI `Candidate` | same as npm | pushed into `decisions: Vec<Decision>` unchanged (D1 — no reason-string step here) |
| `artifacts::mod.rs`'s private `evaluate` wrapper (3 call sites in `serve_artifact`) -> `osv::evaluate` | wrapper's existing `app, snapshot, now, row, pinned` reshaped into `osv::evaluate`'s params | each of the 3 checkpoints (pre-upstream-check, post-check, final pre-response, SPEC §9) needs the same final decision | wrapper becomes `async`; its 3 callers each gain `.await`; on `Deny(BlockedByOsv)`, `deny_reason` (line 320) renders the string |
| `artifacts::download.rs::transfer` -> `osv::evaluate` | its existing single-call arguments | one decision point per transfer | unchanged control flow, now `.await`ed |
| `osv::evaluate` -> `OsvClient::check` | `(ecosystem, name, version)` | only called when the OSV-blind `policy::evaluate` result is `Allow` and `osv.mode != Off` (C15/C18, D5) | boolean folded into the second `policy::evaluate` call's `osv_matched`, real under `Enforce`, forced `false` under `Diagnostic` |
| `osv::evaluate` -> `crate::http::logging::record_osv_diagnostic_match` | none (marker call) | `osv.mode == Diagnostic` and the real check answered `true` (D5/D7/C17b/C17c) | sets `RequestContext.osv_diagnostic_match`; `decide()` later reads it, never changes `result` |
| `OsvClient::check` -> `osv::batcher` (via `mpsc::Sender`) | `(key, oneshot::Sender<bool>)` | cache miss | enqueue-timeout fail-open (C12a) if the channel is full; otherwise awaits the `oneshot`, bounded by `request_timeout` (C14) |
| `osv::batcher::run` -> `POST /v1/querybatch` | one query per distinct key in the current flush | flush fired (count-cap or interval) | `tokio::time::timeout`-wrapped (C12c); success pairs `results[i]`/`queries[i]` after a length check (C12b); any failure answers every waiter `false` |

## Test plan

| API promise | Caller and input/state | Expected observable result | Planned check and evidence kind |
|---|---|---|---|
| `policy::evaluate` denies at the producer tier when `osv_matched: true` and no other block applies | unit, `Candidate` otherwise clean, `osv_matched: true` | `Decision::Deny(DenyReason::BlockedByOsv)` | `osv_matched_true_denies_before_digest_check`; example; execution |
| `policy::evaluate` never lets `osv_matched: false` unblock a producer deny (C1) | unit, snapshot blocks the package, `osv_matched: false` | `Decision::Deny(DenyReason::BlockedPackage)` (producer reason wins, unaffected) | `evaluate_never_lets_osv_unblock_a_producer_deny`; example; execution |
| Decision order stays `Unavailable -> Deny(package) -> Deny(version) -> Deny(digest) -> Deny(timestamp) -> Hold -> Allow`, OSV interleaved at the producer package/version tier | unit, one case per tier plus one OSV-only case | fixed order holds, extended not replaced | `check_order_is_unavailable_deny_hold_allow` (extended); example; execution |
| `osv::evaluate` skips the OSV call entirely when the OSV-blind decision is not `Allow` | unit/integration, fake `OsvClient` that panics if `check` is called, producer-blocked candidate | `Decision` matches the OSV-blind result; fake never invoked | `evaluate_skips_osv_when_producer_already_denies`; example; execution |
| `osv::evaluate` resolves OSV only when the OSV-blind decision would be `Allow` (C15) | unit/integration, fake `OsvClient` returning a known answer, clean candidate | second `policy::evaluate` call uses the fake's answer | `evaluate_calls_osv_only_when_producer_would_allow`; example; execution |
| `OsvClient::check` answers from cache without a network round trip on a repeat within the TTL (C13) | unit, fake transport that panics on a second call, two `check` calls for the same key | second call returns the cached value, fake invoked once | `check_returns_cached_answer_without_a_batcher_round_trip`; example; execution |
| `OsvClient::check` fails open (returns `false`) and writes a negative-TTL cache entry on any batcher failure (C14) | unit, fake transport returning an error/timeout/malformed response | `false`, counted, negative-TTL entry written | `check_fails_open_on_batcher_timeout`; example; execution |
| `OsvClient::check` fails open on a full/timed-out enqueue (C12a) | unit, channel pre-filled to capacity | `false` within `OSV_ENQUEUE_TIMEOUT`, never blocks | `check_fails_open_on_full_channel`; example; execution |
| `osv::batcher::run` flushes on record-count cap or interval, whichever first | unit/property, queue N requests then advance a `TestClock`-equivalent timer | one `POST` per flush trigger | `batcher_flushes_on_record_count_cap`, `batcher_flushes_on_interval`; example; execution |
| `osv::batcher::run`'s outbound call never blocks the loop past `request_timeout` (C12c, closes threat-model G1) | unit, fake transport that hangs forever | flush completes at the timeout bound; loop returns to draining `rx` immediately after | `batcher_never_blocks_past_timeout_on_a_hung_connection`; example; execution |
| `osv::batcher::run` fails the whole batch open on a `results`/`queries` length mismatch (C12b, closes G3), never panics | unit, fake transport returning a short/long `results` array | every waiter in that flush gets `false`; no panic | `batcher_fails_open_the_whole_batch_on_length_mismatch`; example; execution |
| A `DenyReason::BlockedByOsv` decision renders a human reason string at both existing match sites | unit, one call to each `deny_reason` (artifacts, npm) with `BlockedByOsv` | non-empty `&'static str`, compiles (exhaustive match forces this) | `deny_reason_maps_blocked_by_osv_in_artifacts_mod`, `deny_reason_maps_blocked_by_osv_in_npm_mod`; example; typecheck+execution |
| `osv_cache_ttl_seconds`/`osv_request_timeout_ms` reject a zero value with a named reason | integration, `Config::load` against a new invalid fixture per key | `ConfigError::Invalid { key, .. }` naming the exact key | `every_invalid_config_fixture_is_refused_with_its_reason` (2 new rows); example; execution |
| Both new config keys are optional with a stated default | integration, delete each key from the sample config in turn | `Config::load` succeeds, default value applied | `deleting_any_sample_key_is_reported_as_that_key_missing` (both keys added to `WITH_DEFAULTS`); example; execution |
| `osv::evaluate` under `osv_mode: off` never calls `OsvClient::check` (C18) | unit, real `OsvClient` built via `spawn_with` (D5) against a `counting_server` (`src/osv/batcher.rs`'s pattern, F3) that panics/asserts zero requests, `mode: Off`, clean candidate | `Decision` matches the OSV-blind result; server sees zero requests | `evaluate_off_mode_never_calls_check`; example; execution |
| `osv::evaluate` under `osv_mode: enforce` denies on a real OSV match, unchanged from today | unit, real `OsvClient` via `spawn_with` against a `counting_server` returning a match, `mode: Enforce` | `Decision::Deny(BlockedByOsv)` | `evaluate_enforce_mode_denies_on_match`; example; execution |
| `osv::evaluate` under `osv_mode: diagnostic` allows even on a real OSV match | unit, real `OsvClient` via `spawn_with` against a `counting_server` returning a match, `mode: Diagnostic` | `Decision::Allow` (never denies, C17) | `evaluate_diagnostic_mode_allows_on_match`; example; execution |
| `osv::evaluate` under `osv_mode: diagnostic` with no OSV match also allows | unit, real `OsvClient` via `spawn_with` against a `counting_server` returning no match, `mode: Diagnostic` | `Decision::Allow` | `evaluate_diagnostic_mode_allows_without_match`; example; execution |
| `osv_mode` rejects an unrecognized value with a named reason (C18b) | integration, `Config::load` against a new invalid fixture | `ConfigError::Invalid { key: "osv_mode", .. }` | `every_invalid_config_fixture_is_refused_with_its_reason` (3rd new row); example; execution |
| `osv_mode` defaults to `enforce` when absent | integration, delete the key from the sample config | `Config::load` succeeds, `Config.osv_mode == OsvMode::Enforce` | `osv_mode_defaults_to_enforce_when_absent`; example; execution |
| `record_osv_diagnostic_match` sets only `reason`, never `result` (C17b/C17c) | integration/e2e, a request whose `decide()` middleware runs with the flag set | delivered `Decision.result == "ALLOWED"`, `Decision.reason == OSV_DIAGNOSTIC_REASON` | `record_osv_diagnostic_match_sets_the_reason_without_changing_result`; example; execution |
| `record_osv_diagnostic_match` outside a request is a no-op, same as `record_cache` | unit, call it with no task-local `CONTEXT` in scope | no panic, no observable effect | `record_osv_diagnostic_match_outside_a_request_is_a_no_op`; example; execution |

`sf-tdd` implements these rows one at a time at the named seam.

## Invariants & spec dispositions

- SPEC §5 decision order is fixed and OSV is interleaved, not appended — existing check: `src/policy/mod.rs`: `check_order_is_unavailable_deny_hold_allow`.
- OR-only merge: no OSV outcome may unblock what the producer's snapshot blocks (C1) — REJECT: `ordered_obligation` (guard = calls to `evaluate`, operation = calls to `check`) validated correctly on disposable controls but against the real product root (`src/osv/`) found 4 findings, all inside `#[cfg(test)] mod tests` where unit tests deliberately call `OsvClient::check` directly, not through `osv::evaluate`; the dominance check is intraprocedural and has no test-path exclude, so the spec would perpetually flag its own test suite — existing check: `src/policy/mod.rs`'s `evaluate_never_lets_osv_unblock_a_producer_deny` covers this invariant instead.
- OSV absence/timeout never produces `Decision::Unavailable` or otherwise fail-closed (C3/C14) — REJECT: `Decision::Unavailable` is a fieldless-variant bare path expression, never a call expression; every supported SMTC shape's operation/sink matcher only matches call expressions, so a spec targeting it would be vacuously true, not a real check — existing check: `src/osv/mod.rs`'s `check_fails_open_on_batcher_timeout`/`check_fails_open_on_full_channel`/`check_writes_negative_ttl_on_failure` cover this invariant instead.
- Bounded channel + enqueue-timeout fail-open on a full batcher queue (C12a) — KEEP: `.smtc/analyzers/enqueue-timeout-guard.yaml`; controls `docs/plans/osv-intel/controls/{unsafe,safe}/`; slice 1. First attempt (`must_dominate: true`) returned `analysis_failed` — `sf-smtc-doctor` found this was a spec-schema placement bug, not an engine limit: statement-order dominance genuinely cannot resolve a guard and operation sharing one statement, but the schema's default `relation: {}` (same-function co-occurrence) resolves it correctly and non-vacuously. `sf-verify-cert` confirmed SOUND: 0 findings scanning the real product root `src/osv/mod.rs` (non-vacuous — the 1 real `self.tx.send(...)` site is correctly recognized as guarded), unsafe control fires, safe control clean. Product root is `src/osv/mod.rs`, not the whole `src/osv/` directory — `send` is too generic a name and `src/osv/batcher.rs` independently defines an unrelated `send` plus test-module `tx.send`/`reply.send` sites that are C12c's territory, not C12a's; scanning the full directory pulls in that noise (confirmed: 7 unrelated findings, all in `batcher.rs`, none in `mod.rs`) without changing what the spec actually proves.
- `results[i]`/`queries[i]` length-equality check before any positional pairing (C12b) — REJECT: the guard is an equality comparison (`response.results.len() == keys.len()`) and the protected operation is a subscript/index expression, not a call; no supported SMTC shape matches a non-call guard or a non-call protected operation — existing check: `src/osv/batcher.rs`'s `batcher_fails_open_the_whole_batch_on_length_mismatch` covers this invariant instead.
- Outbound `POST /v1/querybatch` is timeout-wrapped, never awaited unbounded (C12c) — KEEP: `.smtc/analyzers/outbound-timeout-guard.yaml`; controls `docs/plans/osv-intel/controls/{unsafe,safe}/`; slice 1. Same fix as C12a (`relation: {}`). `sf-verify-cert` confirmed SOUND against product root `src/osv/batcher.rs`, but not at a literal zero: 7 findings at lines 195, 286, 325, 360, 398, 399, 427, with the real invariant site (line 149, `timeout(request_timeout, send(client, url, &body))` in `flush`) correctly absent in every run. `ordered_obligation`'s `relation: {}` has no call-graph transitivity, and the daemon's `calls:` schema (`name`/`receiver_type`/`package` only, confirmed no predicate can select-or-exclude a receiverless free-function call) cannot disambiguate `flush`'s already-guarded inner `client.post(..).send()` primitive or the unrelated test-module `tx.send`/`reply.send`/`waiter.send` sites from the guarded target. The spec's own header documents the pass condition as this exact 7-line set with line 149 absent, following this repository's existing precedent for the identical schema limitation in `.smtc/analyzers/consumer-identity-extension-read.yaml` (independently read and confirmed by `sf-verify-cert`, not taken on the author's claim) — any deviation from that exact set is the re-validation signal, not evidence the spec is unsound.
- `Decision`'s `BYTES_PER_RECORD` heap-footprint ceiling is not invalidated by the new `DenyReason` variant (Copy, no new String/Vec field) — one-off: `src/delivery/mod.rs`'s compile-time `const _: () = assert!(...)` already re-checks this on every build; no separate spec needed since the variant is `Copy` and the ceiling derivation is unchanged.

## Threat model

Trigger: this Gate's mandatory Security trigger applies unchanged from Gate 2 — untrusted, internet-fetched
OSV responses feed a production block decision. Scope, entry points, trust boundaries, assets, and the
mechanism (`osv::OsvClient::check` -> cache C13 -> `osv::batcher` mpsc/oneshot C12 -> `POST
api.osv.dev/v1/querybatch` -> `policy::evaluate`'s `osv_matched` tier -> decision log) are exactly Gate 2's
model (`evidence/threat-model-2.md`, MODELED); this Gate introduces no new entry point, trust boundary, or
asset, only the module/interface shapes above. Gate 2's model closed G1/G2/G3 as mechanism commitments
(C12a/b/c) and explicitly deferred their exact numeric values to this Gate as "a Gate 3 config deferral, not
a mechanism gap," binding any chosen values to three properties: **bounded**, **short**, and **no looser
than C14's bound**. This Gate pins those values and checks each against its property:

| ID | Property | Concrete mechanism (this Gate) | Value | Property check |
|---|---|---|---|---|
| G1/C12c | outbound call never blocks the batcher past a bound | `tokio::time::timeout(osv_request_timeout_ms, POST /v1/querybatch)` | `osv_request_timeout_ms` (D4, default 500ms) | Short — sits inside C14's own "a few hundred ms" bound by construction, since it *is* C14's bound (one config value serves both C12c's outbound-call timeout and C14's per-waiter reply timeout, D2/D4 — no second, potentially-looser knob to drift out of sync). |
| G2/C12a | channel is bounded; a full channel fails open, never blocks | `mpsc::channel(OSV_CHANNEL_CAPACITY)` sized against the flush cap; `tx.send(...)` wrapped in `tokio::time::timeout(OSV_ENQUEUE_TIMEOUT, ...)` | `OSV_CHANNEL_CAPACITY = 1024` (4x `OSV_BATCH_RECORDS = 256`, mirroring `delivery/siem.rs`'s `BATCH_RECORDS` headroom convention); `OSV_ENQUEUE_TIMEOUT = 50ms` | Bounded (fixed-capacity channel, not unbounded growth) and short (50ms, an order of magnitude under the 500ms reply bound, so a full channel fails open well before a caller would notice a latency hit). |
| G3/C12b | a `results`/`queries` length mismatch never panics or silently truncates | `results.len() == queries.len()` checked before any positional pairing; mismatch takes the whole-batch fail-open path (same code path as any other batch failure, C14) | no numeric value — a structural check, unaffected by the numeric deferral | N/A — already closed by mechanism alone (Gate 2), reconfirmed unchanged by this Gate's design (`osv::batcher::run`'s contract above). |
| C14 (failure caching) | a struggling OSV endpoint is not re-hammered by repeat requests during an outage | a fixed negative-TTL cache entry written on any failure path | `OSV_NEGATIVE_TTL = 30s` (an order of magnitude under `osv_cache_ttl_seconds`'s 300s default, D4) | Short relative to the normal TTL, bounded (fixed constant, not configurable, so it cannot silently grow past what C14 intends). |

Confirmed non-gaps (unchanged from Gate 2, re-checked against this Gate's concrete design): T1 (a
wholesale-erroneous OSV match, accepted by C4's Gate 1 trust policy) and T5 (oversized response body,
bounded by OSV's documented cap) — neither is affected by pinning the numeric values above. C1 (OR-only
merge), C3 (never fail-closed), C5 (no provider abstraction), and C15 (OSV-blind-first ordering, implemented
here as D2's `osv::evaluate` wrapper) all still hold; D2 does not change what data crosses the trust boundary,
only how many call sites route through it.

Limitations: this challenges the plan only, using Gate 2's already-MODELED entry points/assets and this
Gate's own numeric choices; it does not independently re-derive the trust boundary. Post-implementation
`sf-security-review` independently reviews the actual `osv::batcher.rs`/`osv/mod.rs` source once written
(Gate 4).

Accountable accept: `OSV_CHANNEL_CAPACITY`/`OSV_ENQUEUE_TIMEOUT`/`OSV_NEGATIVE_TTL` are fixed `const`s, not
config keys (D4) — accepted by the architect (this Gate) on the same rationale as `delivery/siem.rs`'s
existing `BATCH_RECORDS`/`BATCH_INTERVAL` precedent: no operator-tuning need has been shown for a firstcut,
and a fixed value that satisfies the bound is simpler than exposing a knob nothing yet needs.

Reopened 2026-09-29 (following Gate 2's second re-steer, `osv_mode`): D5-D8 pin the exact Rust types and
call shapes for C16-C18b, already threat-modeled and red-teamed at Gate 2 (`evidence/threat-model-3.md`,
MODELED; `sf-red-team` FIX FIRST closed by C17c). D8 is this Gate's own non-regression check: nothing in
D5 (`OsvMode`, `OsvClient.mode`), D6 (`config.rs`'s validated string), or D7 (`RequestContext`'s new field)
introduces an entry point, trust boundary, or asset Gate 2 did not already model — `osv::evaluate`'s
signature is unchanged for every caller (D2/D5), `policy::evaluate` stays pure and mode-unaware, and the
diagnostic-log mechanism is the exact `RequestContext` seam C17b named, now given concrete field/function
names. No new `sf-threat-model` dispatch: there is nothing new to model, only to name.

## Least confident decisions

1. **D2's shared `osv::evaluate` wrapper** is this Gate's biggest departure from Gate 2's literal Fit table (which implied hand-writing the two-phase dance at each call site). The wrapper is smaller and more locality-preserving, but it means `serve_artifact`'s 3 checkpoints and npm/pypi's per-entry loop calls all now pay a potential OSV round trip at 4-6x the call volume Gate 2's architecture estimated — C13's cache is what keeps this cheap in practice; if the cache TTL (D4, 300s default) proves too short under real traffic patterns, that volume assumption should be revisited before tuning it in production.
2. **No fake-OSV-client convention exists yet** (`tests/common/mod.rs`'s `start()` helper and 3 direct `AppDeps` literals need one invented from scratch, unlike `Transport`/`Clock` which already have established fakes) — worth a second look once Slice 1's tests reveal whether a trait-based fake or a plain "always returns false" stub is enough, given `SPEC.md:59`/C5 rule out a `Provider`-style abstraction.
3. **`osv_request_timeout_ms` default of 500ms (D4)** is an architect's estimate, not sourced from OSV's documented SLA (`evidence/research-1.md` found none) — cheap to change later since it is a single config default, but worth confirming against real OSV latency once Slice 1 is live.
4. **`osv_mode` has no hot-reload path (D5)** — changing it requires a process restart, same as every other config value in this codebase (no config file is watched/re-read after startup). `threat-model-3.md` treated this as a closed, not-a-gap finding, but it is worth confirming operators are comfortable with a restart to move between `enforce`/`diagnostic`/`off` before this ships, since a diagnostic-mode rollout is exactly the kind of thing an operator might want to flip quickly under a live incident.

## Repository evidence

- `docs/plans/osv-intel/evidence/repository-structure.md` — Gate 2's whole-repo briefing (module ownership, conventions, invariants, landmines).
- `sf-repo-view` (this Gate, 11 dispatches): `src/policy/mod.rs`, `src/lib.rs`, `src/config.rs`, `src/artifacts/mod.rs`, `src/npm/mod.rs`, `src/pypi/` (deny_reason absence), `tests/config_validation.rs`, `src/main.rs`, `src/tasks/mod.rs`, `src/delivery/siem.rs` (the batcher's mirror template), `src/artifacts/download.rs` (the `transfer` function and its exact `policy::evaluate` call site, lines 339-355) — full declaration lists and exact code shapes grounding every `## Modules and interfaces` entry above.
- `src/policy/blocklist.rs`, `tests/common/mod.rs`, `tests/persistence_recovery.rs`, `tests/decision_log_delivery.rs` — not independently `sf-repo-view`'d; already grounded by the `sf-impact` dispatch below (exact construction/call sites with line numbers), which is a stronger evidence kind (caller enumeration, not just declaration listing) for these mechanical test-fixture edits.
- `config.sample.toml` — not triggered: a data fixture, not source; its shape (which keys are present vs. covered by `WITH_DEFAULTS`) is grounded by `tests/config_validation.rs`'s `sf-repo-view` result above.
- `sf-impact` (this Gate, 3 dispatches): `policy::evaluate`'s 4 production + 26 unit-test call sites (grounds D2 and the `## Files`/`## Call stack` per-site list); `DenyReason`'s exactly-2 exhaustive match sites (grounds D1); `App`/`AppDeps`'s 5 construction sites and single `App` literal (grounds the `## Files` test-fixture list and D2's fake-client note).
- `sf-codebase-intel` (this Gate): `pypi::resolve()`'s `Decision::Deny` handling — confirms D1 (no reason-string conversion happens there).
- `docs/plans/osv-intel/02-architecture.md` — approved Gate 2 architecture (C1-C15), the basis every Gate 3 decision above extends or corrects.
- `docs/plans/osv-intel/evidence/threat-model-2.md` — Gate 2's MODELED threat model (G1/G2/G3 closed by C12a/b/c); this Gate's `osv::batcher::run` design directly implements those closures (see Test plan rows citing G1/G3).
- `docs/plans/osv-intel/evidence/threat-model-3.md` — Gate 2's second reopen, `osv_mode`'s MODELED threat model (G1/T1/T2 closed by C17b/C18b); D5-D8 pin its concrete implementation.
- Direct reads grounding D5-D8: `src/config.rs:1-16,219-236` (`public_url`'s string-then-validate idiom, the `invalid()` helper, existing cross-module import of `crate::delivery`); `src/http/logging.rs:82-134,189-193` (`RequestContext`, `record_cache`'s exact shape and its outside-a-request tolerance, `decide()`'s `result`/`reason` derivation); `src/osv/mod.rs:95-155` (`OsvClient`'s fields, the existing `new`/`spawn_with` split, `spawn_with`'s doc comment naming `App::start` as its only other caller besides this module's own tests); `src/lib.rs:196-209` (both `App::start` match arms that call `new`/`spawn_with` — the complete caller enumeration for D5's added `mode` parameter, in place of a separate `sf-impact` dispatch since both call sites are already fully visible in one function); `src/osv/batcher.rs:244-275` (`counting_server`, the local-mock-server test pattern D5's new mode-branching tests use in place of `evaluate_with_fake`'s hand-duplicated logic, F3); `src/osv/mod.rs`'s `#[cfg(test)] mod tests` (grepped for every `spawn_with(`/`OsvClient::new(` call plus every direct `OsvClient {` struct literal: 6 existing sites total — 4 constructor calls at lines 464, 502, 531, 568, and 2 direct struct literals at lines 276-281 (`client_with_capacity`) and 421-426 (`check_fails_open_on_full_channel`, which bypasses both constructors to hold a channel slot open) — the complete enumeration for D5's `mode` field/parameter, F5 — no other file constructs an `OsvClient` directly; `tests/common/mod.rs`, `tests/persistence_recovery.rs`, `tests/decision_log_delivery.rs`, `tests/e2e_npm.rs` all go through `AppDeps`'s `osv_base_url`/`osv_client` fields and `App::start`, already covered by the `src/lib.rs:196-209` call-stack rows, not a separate construction site); `docs/operations.md` (grepped for any existing OSV/enforce/diagnostic text — none found; Gate 3 QA's own direct read independently confirmed the same, F2).

sf-red-team: not triggered — no new concrete uncertainty, consequential assumption, or hard bar beyond what Gate 2's `sf-threat-model` (MODELED, both passes) already covers; this Gate's decisions (D1-D4) are grounded corrections/refinements from direct repository evidence, not new architectural risk, and the mandatory Gate 3 Security trigger (untrusted external input crossing a trust boundary) was already the reason Gate 2 ran `sf-threat-model` twice — nothing in this Gate's grounding surfaced a boundary that model does not already cover.

sf-red-team (reopen, D5-D8): not re-triggered either. `sf-red-team` already reviewed the `osv_mode` design at
Gate 2 (FIX FIRST -> closed by C17c) after `sf-threat-model` returned MODELED; D5-D8 implement exactly that
already-reviewed design in this codebase's concrete types, introducing no decision Gate 2's Red Team pass
did not already see. Grounded directly against current source: `src/config.rs:1-16,219-236` (D6),
`src/http/logging.rs:100-134,189-193` (D7), confirming both are mechanical pinnings, not new design.
