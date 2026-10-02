# Gate 3 source analysis — rated-load-guard

Seven read-only dispatches, 2026-09-24, against branch `package-firewall-mvp`. Three
`sf-repo-view` declaration inventories for the files `## Files` names that Gate 2 grounding did
not already enumerate, and four `sf-impact` analyses for the contract-changing symbols — the
fourth, §7, dispatched later in response to `sf-red-team` finding 4. Every line number is
one-based as the source shows it.

`evidence/repository-structure.md` (Gate 2, `sf-repo-view`, ORIENTED) already enumerates the
declarations of `src/delivery/mod.rs`, `src/delivery/file.rs`, `src/delivery/siem.rs`,
`src/http/health.rs` and `src/config.rs`; those five files were not re-dispatched.

---

## 1. `src/http/mod.rs` — `sf-repo-view`, ORIENTED

99 lines, 12 top-level declarations: 7 `pub mod` lines (`:3-9`), `pub fn router(app: Arc<App>)
-> Router` (`:39-75`), and four private `async fn` — `unknown_route` (`:77`),
`unsupported_method` (`:83`), `unsupported_npm_api` (`:89`), `no_store` (`:94-99`). No
`#[cfg(test)]` module, no types, no constants.

- **Route registration is 13 literal `.route(...)` calls.** No loop, no `fold`, no
  `macro_rules!`, no proc-macro, no `include!`. The chain opens `Router::new()` at `:40` and
  closes `.with_state(app)` at `:74`, so the returned type is state-erased and every handler
  added inside the chain type-checks against state `Arc<App>`.
- **The two health lines, verbatim**, so a third is written to match byte for byte:

```
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
```

  Eight leading spaces, double-quoted path, `, `, `get(health::<fn>)`, no trailing comma. The
  health block is contiguous at `:41-42`; the next route is `:43`.

**Design consequence:** the `/health/delivery` registration is one literal line inserted after
`:42`, in that exact shape. No other change to this file.

---

## 2. `src/lib.rs` — `sf-repo-view`, ORIENTED (file-scoped)

372 lines. `App` (`:55-83`) carries `pub(crate) delivery: delivery::Sinks` at **`:82`**,
produced at `:161` by `let (delivery, delivery_tasks) = delivery::build(&deps.config,
drain.clone())?;` and moved into the struct literal at `:173`. `delivery_tasks` goes to
`tasks::spawn` at `:195` and lives on `Running.tasks`, not on `App`.

`App` has no public constructor and is never returned directly: `pub async fn start(deps:
AppDeps) -> Result<Running, StartupError>` (`:127`) returns `Running` (`:223-231`), and callers
reach the app through `Running::app(&self) -> &Arc<App>` (`:294`).

**The `test-support` precedent is already in this file, twice:**

| Line | Item |
|---|---|
| `:114-116` | `#[cfg(feature = "test-support")] pub fn delivery_is_empty(&self) -> bool` on `impl App`, body `self.delivery.is_empty()`. Its doc (`:107-113`) states the rationale: "`Sinks` is crate-internal precisely so that a consumer of this crate cannot reach the delivery path." |
| `:300-302` | `#[cfg(feature = "test-support")] pub fn background_task_count(&self) -> usize` on `impl Running`. |

**Design consequence:** the C33 monotonic-drop-total accessor is a third method in exactly this
shape — `#[cfg(feature = "test-support")] pub fn …(&self) -> …` on `impl App`, delegating to a
`Sinks` method, beside `delivery_is_empty` at `:114`. It invents no new seam and widens no
visibility beyond the two that already exist here.

Shutdown order, `Running::shutdown` (`:310-333`): `shutdown.cancel()` (`:311`), await the server
join (`:312`), `flush_summary` (`:321`), `drain.cancel()` (`:322`), `tasks.join()` (`:324`),
`flush_drop_tail` (`:326`), `drop(self.app)` (`:327`), await `store_task` (`:328-330`). The
measurement path's "shut the App down before reading the tally" (C28, C32) is therefore
`Running::shutdown().await`, after which the sink tasks have joined at `:324`.

---

## 3. `src/http/logging.rs` — `sf-repo-view`, ORIENTED

499 lines, 39 declarations. Confirms every Gate 2 anchor (`decide` `:150`, `Decision` `:207`,
`tracing::info!` `:224`, `offer` `:243`, `summarise` `:245`/`:357`, `close_window` `:415`,
`emit` `:440`, `RequestSummary` `:451`, `set_summary_window` `:461`). Three findings matter to
the design:

**(a) `Decision.method` is unbounded today — the C22 gap, exactly as stated.**

```rust
210:        method: method.to_string(),
```

`method` is bound at `:153` from `request.method().clone()`, an `axum::http::Method`. `loggable`
is **not** applied. It is applied only inside `Target::of` (`:301`, `:302`, `:307`, `:312`,
`:313`), so `package` and `version` arrive already bounded at `:212-213` while `method` does not.

**(b) `loggable` bounds *chars* and then expands them.** Full body, `:322-326`:

```rust
fn loggable(segment: Option<&str>) -> Option<String> {
    let segment = segment.filter(|segment| !segment.is_empty())?;
    let bounded: String = segment.chars().take(MAX_LOGGED_TARGET).collect();
    Some(format!("{bounded:?}"))
}
```

`MAX_LOGGED_TARGET = 256` (`:51`) counts Unicode scalar values, so 256 chars is up to 1 KiB of
UTF-8 — and the `{:?}` escape wrapper expands further: a control character becomes `\n` (2
chars) or `\u{...}` (up to 10). The in-file test at `:489-494` asserts only `len() <=
MAX_LOGGED_TARGET + 2` against ASCII input, so the non-ASCII and escape-heavy byte ceiling is
untested.

**Design consequence for `BYTES_PER_RECORD` (C29, C37):** the per-field ceiling is not
`256 × 4`. It is `(256 chars × 4 bytes) + escape expansion + the 2 quote characters`, and the
derivation must state the escape term or the constant is not a ceiling. A `String` bounded this
way also carries its heap capacity, not its length.

**(c) `flush_summary` (`:384`) and `flush_drop_tail` (`:399`)** are each called from exactly one
site, both in `Running::shutdown`: `src/lib.rs:321` and `src/lib.rs:326`. `close_window`
(`:421`) and `flush_drop_tail` (`:400`) are the only two `sinks.drops()` reads in the
repository.

---

## 4. `QUEUE_CAPACITY` — `sf-impact`, WIDE

**Three references, all inside `delivery::build`:** the declaration
`const QUEUE_CAPACITY: usize = 4096;` (`src/delivery/mod.rs:37`) and the two
`mpsc::channel(QUEUE_CAPACITY)` calls at `:214` (file) and `:250` (SIEM). No test, bench or
fixture names the constant. `build` (`:203`) already takes `config: &Config`, so **no caller
signature and no call site changes.**

Reverse graph: 3 direct callers, 12 transitive dependents across 5 modules, terminating at
`main` (`src/main.rs:54`) and `serve` (`:121`) — a process entry point, hence WIDE.

**The cost lands in one existing test, which the design must handle.** `TP-7`
(`tests/decision_log_delivery.rs:693`) depends on 4096 being *smaller* than its load:

| Line | Site | Assumption |
|---|---|---|
| `:688` | doc comment "the SIEM sink's 4096-record queue" | prose that becomes false |
| `:690` | `const OVERFLOW_REQUESTS: usize = 5_000;` | 5,000 exceeds capacity |
| `:709` | `for _ in 1..OVERFLOW_REQUESTS` | the load generator |
| `:730` | `.any(\|summary\| summary["dropped_siem"].as_u64() > Some(0))` | **the assertion that fails** once capacity exceeds 5,000 |
| `:737` | `.all(\|summary\| summary["dropped_file"].as_u64() == Some(0))` | the file sink absorbs all 5,000 — fails if a budget shrinks that queue |

The C13 default budget (5 minutes of collector outage at the rated load) makes the queue far
larger than 5,000 records, so TP-7 stops testing overflow and `:730` fails. TP-7 must pin its
own small `siem_queue_max_bytes` so it keeps testing overflow independently of the default.

Also capacity-sensitive through `sample_config()`, all requiring capacity > 0 because
`mpsc::channel(0)` panics inside `build` on the startup path (the C23 rule): `tp2`
(`tests/decision_log_delivery.rs:107`), `tp1` (`:60`), `tp10` (`:251`), `tp15b` (`:1033`).

**Cleared, do not touch:** `const CAP: u64 = 4_096` at `tests/decision_log_delivery.rs:108`,
`:158`, `:479` is `log_file_max_bytes`, a *byte* cap, coincidentally 4096.
`src/delivery/file.rs:233` `const QUEUED: u64 = 10_000` with its own channel at `:234` belongs
to `tp19`, which calls `file::run` directly and never goes through `build`.
`src/store/mod.rs:595` is a different subsystem. **No bench depends on 4096.**

---

## 5. Widening `Sink.drops` — `sf-impact`, WIDE by graph rule, 3 files in practice

`Sinks::drops()` has 2 direct callers (`src/http/logging.rs:400`, `:421`), 14 transitive
dependents across 5 modules, and **no caller in `tests/`** — it is `pub(crate)`, so integration
tests cannot reach it.

**No caller breaks.** `&Arc<AtomicU64>` deref-coerces to `&AtomicU64`, so every existing call
site keeps its shape (`file.rs:43`, `:47`; `siem.rs:68`, `:74`, `:84`, `:88`). If the accessor
keeps returning the existing `Drops` value type, the widening is source-local to three files.

Every position naming `AtomicU64` in the delivery path:

| File | Lines |
|---|---|
| `src/delivery/mod.rs` | `:20` import · `:109` field `Sink.drops` · `:115` `push` increment · `:155`, `:159` the two `swap(0)` resets · `:215`, `:251` construction · `:221`, `:258` `Arc::clone` into the tasks · `:223`, `:260` struct literals |
| `src/delivery/file.rs` | `:10` import · `:36` `run` param · `:43`, `:47` call sites · `:65` `drain` param · `:75` increment · `:103` `append` param · `:105`, `:142` increments · `:151` `open` param · `:181` increment · **`:249`, `:251`, `:260` the `#[cfg(test)]` `tp19` test** |
| `src/delivery/siem.rs` | `:10` import · `:51` `run` param · `:68`, `:74`, `:84`, `:88` call sites · `:97` increment · `:118` `send` param · `:134` `Unsent` literal · `:197` `struct Unsent<'a>` · `:199` field · `:212` `Drop for Unsent` increment |

**Two snags the analysis turned up:**

1. **`Drops` is taken.** `pub(crate) struct Drops { pub file: u64, pub siem: u64 }` already
   exists at `src/delivery/mod.rs:100-103` and is the return type of `Sinks::drops()`. The
   widened per-sink struct needs a different name; `evidence/threat-model.md:48` proposes
   `Drops` and must not be followed literally.
2. **The reset is the point.** `swap(0)` at `:155` and `:159` is the only reset. The monotonic
   total must be a separate atomic read with `load`, never folded into the swapped field, and
   the shed marker needs its own read path.

`tp19` (`src/delivery/file.rs:228-263`) constructs a bare `AtomicU64` at `:249` and reads it at
`:260`; it is the one existing test the widening touches.

---

## 6. Adding the two config keys — `sf-impact`, PARTIAL

**Exactly one compile-breaking site in the repository:** the single exhaustive
`Ok(Config { … })` literal at `src/config.rs:302-340`. The analogue field is
`log_file_max_bytes` at `:336`. No other `Config { … }` literal exists anywhere in `src/`,
`tests/` or `benches/` — every other site loads TOML and mutates fields, so it is run-time
affected only and compiles unchanged. **No bench constructs a `Config`**; all three pull
`#[path = "../tests/common/mod.rs"] mod common;` and call `config_with_open_blocklist`.

`RawConfig` is never literal-constructed: serde builds it at `src/config.rs:161`. With
`#[serde(deny_unknown_fields)]` (`:83`), a key registered in `OPTIONAL_KEYS` but missing from
`RawConfig` is a run-time `ConfigError::Syntax`, not a compile error.

**Minimum change set, six edits in `src/config.rs` plus the sample:** `RawConfig` field
(near `:105`), `Config` field (near `:51`), `OPTIONAL_KEYS` entry (`:145-153`), the default
const (near `:78`), the default-and-validation arm in `validate` (the `log_file_max_bytes`
pattern at `:239-250`), the field in the `Ok(Config { … })` literal (`:336`) — plus a
commented sample block and the `docs/operations.md:442` key table.

**No existing config test changes, because C5 ships both keys commented out.**
`tests/config_validation.rs:171` asserts `keys.len() == 17`, counting non-comment lines of
`config.sample.toml`; the four existing optional delivery keys already live there commented out
(`config.sample.toml:44`, `:47`, `:55`, `:59`, `:73`), which is why the count is 17. It fails
`17 != 19` only if either new key ships as a live line. `WITH_DEFAULTS`
(`tests/config_validation.rs:174`), read by `deleting_any_sample_key_is_reported_as_that_key_missing`
(`:160-191`), has the same condition. Following the `log_file_max_bytes` precedent keeps both
green. **These two lines are the only enumeration of the key set in the whole suite.**

`tests/origin_guard.rs:297-303` enumerates six *forbidden* key names and asserts the sample
carries none; no collision with `log_queue_max_bytes` or `siem_queue_max_bytes`, no change.

---

## Tier and limitations

| Analysis | Tier | Limitation |
|---|---|---|
| §1 `src/http/mod.rs` | Structural + Manual | Handler bodies are out of scope. |
| §2 `src/lib.rs` | Structural | `inspect file --limit 5` truncated; re-run at `--limit 60` for the complete 30-declaration set. No `verify` leg, so nothing is Decision-tier. |
| §3 `src/http/logging.rs` | Structural (inventory) + Manual (the three quoted specifics) | `inspect file --limit 60` returned a 4,127-token ref, over the 4,096 open threshold; the list was reconstructed from contiguous bounded reads of 1-499 instead. |
| §4 `QUEUE_CAPACITY` | Structural (census, reverse graph) + Manual (value assumptions) | `smtc callers` and `blast-radius` cannot resolve a Rust `const` — both returned `matched: 0`, a tool limit and not evidence of zero dependents. Substituted with range-based `review impact` over the two `channel` sites. The 4096-dependence of the tests is inference from their text; only `cargo test` proves which flip. |
| §5 `Sink.drops` | Structural (caller list) + Manual (per-line type inventory) | `review impact` on the field range returned `total_impacted: 0` — field-level dependents are not modelled, so the type inventory rests on bounded grep and reads. |
| §6 config keys | **Manual** | The call graph carries no struct-type edges, so both graph legs returned no dependents. Five greps hit their 20-result bound, all on load-then-mutate helpers that cannot break at compile time: the one-site compile-time list is the trustworthy half; the run-time tail is a floor, not a census. |

`meta.dirty_build: true` on every leg across all six analyses — the analysis snapshot is ahead
of the last build because `docs/plans/rated-load-guard/` is uncommitted. `parse_health` reported
0 error nodes and 0 dropped statements, and no source file is dirty, so the line numbers are
fresh. No leg was refused, and no native workspace search substituted for an SMTC recipe.

---

## 7. `siem::send` and `Unsent` under the C31 hold — `sf-impact`, PARTIAL (graph legs unusable), sizing WIDE

Dispatched 2026-09-24 in response to `sf-red-team` finding 4. Graded PARTIAL on protocol: both
`review impact` legs returned refs over the 4,096-token bound (9,077 and 9,395) and
`review blast-radius` could not be pinned, because the bare name `send` collides with
`reqwest::RequestBuilder::send`, `mpsc::Sender::send` and `store::send` and `blast-radius` has no
`--file` flag. The affected-test answer is complete, graded Manual/Structural from bounded grep
and file reads. **No test breaks at compile time** — `send`, `Unsent`, `BACKOFF`,
`DRAIN_DEADLINE` and `BATCH_RECORDS` are all private to `src/delivery/siem.rs`, and `Unsent`
appears nowhere in `tests/` or elsewhere in `src/`. Every breakage is behavioural.

### The mechanism that decides every prediction

`src/lib.rs:321-326` is the hinge:

```rust
http::logging::flush_summary(&self.app.delivery, self.app.clock.as_ref());  // :321 reads AND RESETS
self.drain.cancel();                                                        // :322
self.tasks.join().await;                                                    // :324
http::logging::flush_drop_tail(&self.app.delivery);                         // :326 sinks gone -> console only
```

A drop counted **before** shutdown lands in the `request_summary` record written to the file
sink. A drop counted **during the drain window** reaches only the `flush_drop_tail` console warn.
Today `Unsent::drop` fires at send-failure time, during normal running, so it lands in the file.
Holding the batch relocates that accounting — to `Sink::push` overflow (still pre-shutdown, still
in the file) or to the drain tally (console only). **That relocation, not the hold itself, is
what breaks tests.**

### Affected tests, all in `tests/decision_log_delivery.rs`

| Line | Test | Collector | Predicted outcome |
|---|---|---|---|
| 693 | `tp7_drop_is_counted_and_read_back_from_file` | wedged | Passes — but **can HANG** |
| 835 | `tp9_redirect_is_not_followed` | 302 rejecting | **FAILS at run time** |
| 900 | `tp11a_credential_absent_from_runtime_output` | 400 rejecting | Passes, slower; **can HANG** |
| 1003 | `tp15_shutdown_bounded_against_wedged_collector` | wedged | **Passes** if the hold stays inside the drain timeout |
| 1033 | `tp15b_drain_cutoff_records_are_counted` | silent | **Bimodal** — see below |

**tp9 is the certain breakage.** One request, 2.5 s sleep, shutdown. Today the batch timer fires
at 2 s, the 302 is non-retryable so `send` breaks immediately and `Unsent::drop` counts well
before `flush_summary` — so the count reaches the file summary. Under the hold, one request never
fills the queue, `Sink::push` never sheds, and nothing is counted before `flush_summary`; the held
batch is accounted only at the drain tally, which reaches the console. The assertion at `:889`
(`dropped_siem > 0`, "the unfollowed batch is counted as lost rather than quietly forgotten")
fails. Its other two assertions hold. **This is a designed consequence of C31, not a repair**, and
it needs a disposition.

**tp7 and tp11a can hang.** Neither has a test-level timeout; `tp7`'s `server.shutdown().await`
at `:719` has none either. The two `send` call sites at `:68` (batch-full) and `:74` (batch-timer)
are **outside any timeout**. An unbounded retry reached from either never returns to the
`select!`, so `drain.cancelled()` at `:76` is never polled, `tasks.join()` never returns, and the
test hangs forever with nothing to convert it into a failure. This is the worst outcome in the
suite, and it is exactly what C46's cancellation-aware sleep prevents.

**tp15 passes and is the safety net.** The drain arm wraps everything in
`timeout(DRAIN_DEADLINE, …)` at `:80`, so a hold living inside `send` still returns in ~5 s and
its `< 10 s` assertion holds. tp15 carries the **only** test-level timeout among the collector
tests — 20 s with `expect("HANG: shutdown did not return…")` — so it converts an out-of-timeout
hold into a bounded failure rather than a hang. **Do not weaken it.**

**tp15b discriminates between the two hold designs.** Today `batch.drain(..)` empties the batch
before the first await, so the tally at `:95-97` sees nothing and only `Unsent::drop` supplies the
count. Sub-case (a), never drain and serialize by reference: records stay reachable from `run`'s
`batch`, the drain tally counts them, tp15b passes by a different mechanism. Sub-case (b), keep
`batch.drain(..)` and restore on the normal return path: cancellation at an await never runs the
restore, and with `Unsent` gone nothing counts — tp15b fails, reproducing verbatim the slice-2
blocker `docs/plans/decision-log-delivery/00-status.md` records as found and fixed. **tp15b stays
green only if records stay reachable from `run`'s `batch`, or an equivalent RAII guard is
retained.** C46 retains `Unsent` armed with `batch` still drained, which is the second of those.

**Not affected:** `tp20` (`:620`) and `tp8` (`:747`) use 200-OK collectors. One watch item: tp8
asserts `received.len() == 1`, so any redesign changing *when* `send` is called breaks it even
against a healthy collector. `tp11b` (`:951`) never starts a server; `tests/config_validation.rs`
`tp5b` and `tp6` parse config only.

### Call sites and `Unsent` uses — complete, all in `src/delivery/siem.rs`

`send` ×4: `:68` batch-full (**outside any timeout**), `:74` batch-timer (**outside any
timeout**), `:84` drain-arm `try_recv` loop (inside `timeout`), `:88` drain-arm final partial
batch (inside `timeout`).

`Unsent` ×5, zero elsewhere in the repository: `:134` construction (the only one), `:151`
`delivered()` disarm on the 2xx return, `:197-200` struct, `:203-207` impl, `:209-215`
`impl Drop` — the counting site.

**Packet correction:** the construction is at `:134`, not `:136`; the "records exist nowhere
else" comment is `:128-133`, not `:130-135`.

### Limitations

The reverse call graph gave no usable evidence: `send` is a bare-name collision, `callers`
returned `reqwest`/`mpsc`/`store` sites keyed to `siem.rs` even when file-pinned with
`matched: 1` — a name-based identity merge that was discarded — and `blast-radius` cannot be
file-pinned. The call-site and `Unsent` lists are Manual but exhaustive: both greps completed
without hitting `max_results`. Predicted outcomes are reasoned from current bytes plus the
`src/lib.rs` shutdown ordering, **not executed**; no test was run. tp15b's outcome is genuinely
bimodal and is settled by C46's choice, not by this analysis.
