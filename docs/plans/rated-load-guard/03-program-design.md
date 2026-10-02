# Program Design: Rated load guard

## Clarifications and decisions

| ID | Class | Status | Owning Gate | Target Gate | Question or disposition | Selected value or policy | Decision source |
|---|---|---|---|---|---|---|---|
| C87 | user clarification | resolved | 3 | none | **Reopens Gate 3.** `## Threat model` accepts G3-T6 on the premise that stdout is the complete trail (C26). That premise is false: `main.rs:58-63` builds the subscriber from `EnvFilter::try_from_default_env()`, and `EnvFilter`'s default INFO directive is discarded as soon as `RUST_LOG` holds any valid directive — so `RUST_LOG=hyper=debug`, `RUST_LOG=warn`, or a set-but-empty `RUST_LOG` silences every decision line on stdout while `offer` (`logging.rs:242`) keeps delivering to the file and SIEM sinks unfiltered. Reproduced against `target/debug/package-firewall`: unset and `RUST_LOG=info` give 2170 bytes of stdout with the decision line present; `RUST_LOG=hyper=debug` and `RUST_LOG=` give 0 bytes; the NDJSON sink takes 2 records in all four. `docs/operations.md:427` tells operators to set that variable. Which disposition? | **Pin the audit target: `RUST_LOG` no longer reaches the decision log.** `src/main.rs` appends `add_directive("package_firewall::http::logging=info")` after parsing the operator's filter, so whatever they set governs every other target and never this one. This restores the premise G3-T6 was accepted under, rather than re-deciding an accepted risk under worse facts; no other mitigation in `## Threat model` changes. Rejected: accepting it and weakening C26 to "stdout is complete unless filtered", which leaves the documented alerting advice pointing at a silent failure; and moving the complete-trail role to the file sink, which is optional configuration and so cannot be the trail by default. Carries a check that sets a foreign `RUST_LOG` and asserts the decision line still appears — the shape `sf-adversarial-testing` supplied as `rl24b`. | user answer, Gate 3 grilling Q5, ADR candidate |
| C89 | current-Gate decision | resolved | 3 | none | Was: the configured file sink becomes the system of record whenever `log_file_path` is set. Withdrawn 2026-09-25 as scope this plan did not plan (user instruction, YAGNI). `sf-red-team` B3/B4 had also shown it rests on a key that is absent by default and reverses C87's own stated rejection. `log_file_path` keeps exactly the meaning it already shipped with. | withdrawn (not built) | withdrawn; cited by `sf-red-team` rounds 1-2 |
| C91 | current-Gate decision | resolved | 3 | none | Was: `Summary` gains a `lost_total` field so a dropped summary loses only its window count. Withdrawn 2026-09-25 for the same reason, and `sf-red-team` B5 showed it only moved the loss one record later. G3-T12 is addressed by C87 instead, at no cost. | withdrawn (not built) | withdrawn; cited by `sf-red-team` rounds 1-2 |
| C90 | research fact | resolved | 3 | none | `sf-threat-model` flagged as **must-verify, not verified**: can a `RUST_LOG` directive still out-specify C87's pinned `add_directive`? | **Yes, by span- or field-qualified directives on the same target, and C87 still beats every form reproduced.** `add_directive`'s own documentation: “If a filter directive is inserted that matches exactly the same spans and events as a previous filter, but sets a different level for those spans and events, the previous directive is overwritten” — so the pin overwrites `RUST_LOG=package_firewall::http::logging=warn`, and a bare `warn`/`off`/`hyper=debug` never matches this target at all. But `impl Ord for Directive` orders by target length, then `in_span.is_some()`, then `fields.len()`, `.reverse()`d — most specific first — so a **field-qualified** directive on the same target, `package_firewall::http::logging[{request_id}]=off`, carries one more field than the pin, sorts ahead of it and wins — and by the same ordering a **span-qualified** directive does too, which is why the citing rows say “span- or field-qualified”. The honest claim is therefore “no level or target directive silences the decision log”, **not** “no value of `RUST_LOG` silences it”. `rl24b` asserts the forms the pin does beat and does not claim the stronger property. | `ctx7` `/websites/rs_tracing-subscriber`, fetched 2026-09-25: `docs.rs/tracing-subscriber/latest/src/tracing_subscriber/filter/env/mod.rs.html` (`add_directive`'s overwrite rule) and `.../filter/env/directive.rs.html` (`impl Ord for Directive`) |
| C93 | user clarification | resolved | 3 | none | **C92's cost was not known when it was decided, and `sf-red-team` round 2 priced it.** (a) `tracing_appender` is **not** a direct dependency — `Cargo.toml` `[dependencies]` carries `tracing` and `tracing-subscriber` only — so C92 adds a new **runtime** dependency, against approved Gate 2 `## External`: “None. No third-party API, no webhook, **no new dependency**.” C55 reconciled `proptest` only because it is dev-only and nothing ships; that argument does not extend to a runtime crate. (b) `non_blocking` is **lossy by default** — `NonBlocking::write` is a `try_send` that discards on a full channel — so the console can drop decision lines, which **reopens G3-T12**, the threat C87 closes at no cost and which was witnessed 2026-09-25 (178 sink records + 222 reported drops = 400 requests). (c) the blocking it prevents is **pre-existing shipped behaviour**, never modelled; approved Gate 1 C7 governs the delivery **queue**, not the console write, so it was never covered by “delivery never slows a request”. C87 does narrow the escape from it by removing the `RUST_LOG=warn` lever. Keep C92 or withdraw it? | **Withdraw it.** The plan's net addition to `src/main.rs` returns to C87's single pinned directive. The trade was a witnessed closure (G3-T12) and an approved dependency rule against a blocking scenario nobody has demonstrated. **G3-T14 returns to accepted**, with its residual stated plainly: a slow console consumer can block `tracing::info!` inside `decide`, this is pre-existing shipped behaviour, and C87 narrows the escape from it by removing the `RUST_LOG=warn` lever. An operator whose console consumer is slow can still redirect stdout to a file. Rejected: `tracing_appender::non_blocking`, which costs a runtime dependency against Gate 2 `## External` and reopens G3-T12 by making the console lossy. | user answer, Gate 3 grilling Q10 |
| C92 | current-Gate decision | resolved | 3 | none | Was: wrap stdout in `tracing_appender::non_blocking` so a slow console consumer cannot block the request path. Withdrawn 2026-09-25 by C93 once `sf-red-team` round 2 priced it: a new runtime dependency against approved Gate 2 `## External`, and a lossy-by-default writer that reopens G3-T12. Its premise — that approved Gate 1 C7 forbids this — was also over-broad: C7 governs the delivery queue, not the console write. | withdrawn (not built) | withdrawn; see C93 |
| C88 | user clarification | resolved | 3 | none | Two more ways the stdout trail goes incomplete, neither listed in `## Threat model`, both found by `sf-security-review` on slice 2. **F2:** `tracing_subscriber::fmt` discards writer I/O errors and Rust sets `SIGPIPE` to `SIG_IGN`, so if stdout is a pipe whose reader died — a restarted log shipper — every decision line is discarded with no counter and no alarm, while the sinks deliver normally. **F3:** no panic-catching layer exists anywhere in `src/http/`, so a handler panic unwinds through `next.run(request)` (`logging.rs:177`) and skips `tracing::info!`, `offer` and `summarise` alike — no stdout line, no sink record, no counter. Neither has a demonstrated reachable trigger. Does C26's completeness claim get mitigations, or named exceptions? | **Both accepted and named; no new middleware or counter.** C26 is weakened from "stdout is the complete trail" to "stdout carries every decided request, except where the console writer itself fails (G3-T10), the handler never returns (G3-T11), the host log transport truncates it (G3-T13), or a span- or field-qualified `RUST_LOG` directive out-specifies the pin (C90)" — **four** exceptions, not the two this row first named — and `## Threat model` gains a row for three of them (G3-T10, G3-T11, G3-T13); the fourth, C90's span- or field-qualified directive, is a stated residual inside G3-T9 rather than a row of its own, status **accepted**, with that sentence as the mitigation. The deciding reason is reachability: F1 was closed in code because `docs/operations.md:427` invites the very action that triggers it. **Reason corrected 2026-09-25 (`sf-gate-qa` G3QA-24):** this row first said F2 “needs a crashed reader on the console pipe”. That is wrong — ENOSPC on a redirected stdout discards identically and needs no attacker, which is why G3-T10 is rated High. **The acceptance stands** on the narrower ground the user has now given twice: no counter or dependency is added for a failure nobody has demonstrated (Q6, and Q10 for the same shape). F3 has no reachable panic witness in first-party code. Rejected: `tower_http::catch_panic::CatchPanicLayer` inside `decide` and a stdout write-failure counter, both real work against surfaces neither `sf-security-review` nor `sf-adversarial-testing` could trigger. | user answer, Gate 3 grilling Q6 |
| C35 | user clarification | resolved | 2 | none | How long `/health/delivery` stays `503` after the last lost record. A signal that clears instantly is unalertable; one that latches forever is useless. Constrained by C24: no clock read may enter `Sink::push`, so the reader holds the timestamp. | **A fixed 60-second quiet period: `503` while a record was lost within the last 60 s, `200` once 60 s pass with no new loss.** 60 s matches the existing summary window (`SUMMARY_MILLIS = 60_000`, `src/http/logging.rs:54`), so the alarm covers exactly the window the summary record already reports `dropped_file` / `dropped_siem` for, and no probe interval an operator would plausibly pick steps over a shedding event. A fixed constant, not a configuration key. The handler holds the timestamp per C24: it reads the monotonic total and the clock and updates a last-seen-total / last-change pair. Unlike `Sinks::drops()` (C16), that update is idempotent — two concurrent probers converge on the same values instead of stealing from each other — so the signal supports any number of readers. | user answer, Gate 3 grilling Q1 |
| C36 | user clarification | resolved | 2 | none | Whether `log_queue_max_bytes` and `siem_queue_max_bytes` get a sanity upper bound. `NonZeroU64` with no ceiling accepts `u64::MAX`, the process starts normally because tokio's mpsc does not preallocate, and the failure is deferred to an OOM during a collector outage (threat T8). | **Yes: a fixed per-sink ceiling of 4 GiB, refused at load as `ConfigError::Invalid`, in the same validation arm as C23's lower bound.** One comparison and one message in the shape every other bad value already uses (`src/config.rs:230-235`), far above any honest budget — at `BYTES_PER_RECORD` = 32,768 that is 131,072 records, about 655 s of outage at the 200 rps reference load and about 2 s at the measured ceiling N (Gate 2 C13 as amended, C39; the earlier "about 4 million records, hours of outage" assumed 1 KiB per record and is withdrawn) — and far below a value that wedges a host. It also closes the 32-bit `Semaphore::MAX_PERMITS` band C39 found, so both `mpsc::channel` panic paths are refused by `config` rather than reached at `src/lib.rs:161`. Rejected: cross-checking against `memory_cache_max_bytes`, which would couple the queue budget to the metadata cache and surprise an operator who legitimately wants a large queue and a small cache. | user answer, Gate 3 grilling Q2, ADR candidate |
| C39 | research fact | resolved | 3 | none | Does `mpsc::channel` have an upper capacity limit, as well as the zero-capacity panic C23 names? | Yes. `tokio::sync::mpsc::channel(buffer)` "Panics if the buffer capacity is 0 or exceeds the maximum allowed capacity (`Semaphore::MAX_PERMITS`)" — so there are **two** panic paths on the startup path at `src/lib.rs:161`, not one. Reachability differs by target: `Semaphore::MAX_PERMITS` is `usize::MAX >> 3`, so on a 64-bit build `u64::MAX ÷ BYTES_PER_RECORD` stays far below it for any `BYTES_PER_RECORD ≥ 8` and the upper panic is unreachable; on a 32-bit build the limit is about 5.4 × 10⁸ records, and C23's `usize::try_from` rejects anything above `u32::MAX` records, leaving a reachable band between them. The primary T8 risk therefore remains the deferred OOM rather than a startup panic, and this fact narrows but does not by itself decide C36. | `ctx7` → tokio `sync::mpsc::channel`, https://docs.rs/tokio/latest/tokio/sync/mpsc/fn.channel.html, fetched 2026-09-24 |
| C40 | current-Gate decision | resolved | 3 | none | The name of the widened per-sink shared state. `evidence/threat-model.md:48` proposes `Drops`, but that name is taken. | **`SinkCounters`.** `pub(crate) struct Drops { pub file: u64, pub siem: u64 }` already exists at `src/delivery/mod.rs:100-103` and is the by-value return type of `Sinks::drops()`; reusing the name would collide. `SinkCounters` is the per-sink shared state behind the `Arc` — one instance per sink, carrying the window counter and the monotonic total — while `Drops` stays exactly what it is, the two-field snapshot the summary record reads. All four of its items are `pub(super)`: `new`, `lose`, `take_window`, `total`. | `sf-impact` snag 1, `evidence/gate3-analysis.md` §5 |
| C41 | current-Gate decision | resolved | 3 | none | Which existing tests this feature's premise changes. The first draft claimed one; `sf-red-team` finding 4 showed the claim was false and `sf-impact` then enumerated six. | **Six existing tests are affected, each with its own disposition, and only one is edited.** `tp7` (`:693`): **edited** — it pins its own small `siem_queue_max_bytes`, because the C13 default makes the queue far larger than its `OVERFLOW_REQUESTS = 5_000` and its `:730` assertion would stop testing overflow; its `:688` doc comment and the figure are updated to match. `tp19` (`src/delivery/file.rs:228`): **retyped only** — `AtomicU64` becomes `SinkCounters` at `:249`, `:251`, `:260`; behaviour and assertion unchanged. `tp9` (`:835`): **untouched**, kept green by C56. `tp11a` (`:900`): **untouched** — no drop or timing assertion; it only runs slower, and C46 removes its hang exposure. `tp15` (`:1003`): **untouched and must not be weakened** — it carries the only test-level timeout among the collector tests (20 s, `expect("HANG: shutdown did not return…")`), making it the suite's sole converter of a hang into a bounded failure. `tp15b` (`:1033`): **untouched**, kept green because C46 retains the `Unsent` guard rather than restoring a drained batch. Rejected: choosing a default budget small enough to keep `tp7` overflowing, which contradicts approved C13. | `sf-red-team` finding 4; `sf-impact`, `evidence/gate3-analysis.md` §4 and §7 |
| C56 | user clarification | resolved | 3 | none | Under the C31 hold, is a **non-retryable** rejection still discarded and counted immediately? `tp9_redirect_is_not_followed` (`:835`) asserts at `:889` that a 302-rejected batch is "counted as lost rather than quietly forgotten". Today `Unsent::drop` counts it at ~2 s, before `flush_summary`, so it reaches the file summary; under an unconditional hold one request never fills the queue, nothing is counted before shutdown, and the batch reaches only the console drain tail — the assertion fails. C31's text chose exactly that: "a non-retryable rejection means the hold may never end". | **The hold applies only to retryable failures. A non-retryable rejection (302/400/401/403) still discards and counts immediately, as today.** This narrows C31's literal text, deliberately: C31's purpose is surviving a collector *outage* — maintenance or a restart — which is retryable by definition, and holding for a collector that will never accept the batch buys no tolerance at all. It merely fills the queue until it sheds, converting a clean immediate count into a delayed one, and keeps re-presenting a rejected credential for the life of the process (`src/delivery/siem.rs:145-147`). `tp9` stays green untouched and `siem_queue_max_bytes` still means what C6 says for the case it was bought for. Rejected: keeping C31 literal and amending `tp9` to read the drain tail as `tp15b` does — it works, but edits a shipped assertion to accommodate a behaviour change rather than the reverse. | user answer, Gate 3 grilling Q4, ADR candidate |
| C42 | current-Gate decision | resolved | 3 | none | Where the load driver lives, given that both a `benches/` target and a `tests/` target must call the same loop (`02-architecture.md` `## Fit`) and both are external consumers of the crate. | **`tests/common/mod.rs`**, reached from the bench by `#[path = "../tests/common/mod.rs"] mod common;` — the pattern all three existing benches already use (`benches/artifact_throughput.rs:25`). The driver is then ordinary harness code needing no library surface at all, and the crate's only new `test-support` item stays the single accessor C32 narrowed it to. Rejected: a `pub mod` in the library behind `test-support`, which would widen the crate's gated surface for something the existing bench/test-sharing precedent already carries. | `sf-repo-view`, `evidence/gate3-analysis.md` §6; C19, C25, C32 |
| C43 | current-Gate decision | resolved | 3 | none | What `/health/delivery` reports when no sink is configured at all. | **`200`.** With `Sinks` empty, `offer` is `(None, None) => {}` (`src/delivery/mod.rs:141`) and no record can be lost, so nothing is being shed and the signal is truthful. It is not an error state: running with no durable sink is a supported configuration in which stdout is the whole trail, which is what the C26 operator warning already says. | Gate 3 design, grounded `src/delivery/mod.rs:141` |
| C45 | current-Gate decision | resolved | 3 | none | How the loss-site invariant is enforced, given that an analyzer spec cannot express it. | **`SinkCounters` is defined in its own module, `src/delivery/counters.rs`, rather than in `src/delivery/mod.rs`.** `mod.rs:13-14` declares `mod file;` and `mod siem;`, so `file` and `siem` are *child* modules of `delivery` and can reach a private field of a type defined in `mod.rs` — which is the only reason the invariant is breakable. Defining `SinkCounters` in `counters` puts `window` and `total` out of reach of every other module — `file` and `siem` as siblings, `mod.rs` as parent alike — so **no raw `fetch_add` on a sink counter compiles outside `counters`**. The invariant rustc enforces is therefore "a loss cannot be *recorded* except through `lose`", not "nothing else mutates": `take_window` is `pub(super)` and so also callable from the sink modules, but it resets a counter and cannot record a loss, so it is not a bypass. Decision tier via rustc instead of a structural check that degrades silently, a smaller diff than the spec, and it covers the eighth loss site and every future one with no maintenance. | `sf-spec-authoring` REJECT, 2026-09-24; corrected per `sf-gate-qa` G3QA-4 and G3QA-14 |
| C46 | current-Gate decision | resolved | 3 | none | The C31 hold's termination and cancellation contract, which the first draft left unstated. `send` is awaited inside the `tokio::select!` arms at `src/delivery/siem.rs:68` and `:74`; an unbounded retry loop inside it never returns to that `select!`, so the `drain.cancelled()` arm at `:76` is never polled and `Running::shutdown` blocks forever at `src/lib.rs:324` while the collector is down. | **The hold is cancellation-aware, implemented exactly one way, and its retry interval is capped at the last `BACKOFF` entry (2 s).** The backoff sleep at `src/delivery/siem.rs:181` is `select!`ed against `drain.cancelled()` inside `send`, which gains the token as a parameter (C62); `batch` stays drained as it is today, and `Unsent` stays armed as the mechanism that counts held records. The `timeout(DRAIN_DEADLINE)` at `:80` then bounds shutdown as it does today. The cap stops a bare `loop { send }` from hot-spinning a tokio worker and from presenting the credential in a tight indefinite loop (`:145-147`); the hold covers retryable failures only (C56). **One serialized `body`** — not `batch`, which `send` empties at `:122` before its first await at `:149`, so it is empty for the whole hold — is stated in the operator documentation as a **persistent** addend for the length of the outage, not the transient one C29 described. Witnessed by `rl23` and `rl23b`. **Rejected: keeping the undelivered batch as task state and returning to the outer `select!` between attempts.** The `received = rx.recv()` arm at `:61-72` is unconditional — only the timer arm at `:73` carries `if !batch.is_empty()` — so a task that returns to its `select!` keeps draining its queue throughout the outage. The queue never accumulates, which is the whole of C31, and `rl10` fails while `rl23` and `rl23b` both pass. | `sf-threat-model` G3-T4 and G3-T5, `evidence/threat-model-gate3.md`; corrected per `sf-red-team` round 2 finding 4 and `sf-gate-qa` G3QA-17, G3QA-18 |
| C47 | current-Gate decision | resolved | 3 | none | Where the `is_shedding` watch pair lives, and whether two relaxed atomics are sufficient for it. | **One pair on `Sinks` for the whole process, with ordered stores.** Not one per sink, because a single `503` covers both (C9). `last_change_micros` is stored **before** `last_total`, `last_total` is stored `Release` and loaded `Acquire`: with both relaxed, one prober can store `last_total` and be preempted, and a second prober then reads `total == last_total` with a stale timestamp and answers `200` while records are being destroyed. The staleness test additionally requires the delta to be **non-negative**, so a backwards wall-clock step such as an NTP correction cannot latch `503` for the size of the step. Witnessed by `rl16` and `rl16c`. | `sf-threat-model` G3-T1 and omitted item (a), `evidence/threat-model-gate3.md` |
| C48 | current-Gate decision | resolved | 3 | none | How many sinks the load driver configures, given that `lost_total()` sums both. | **Exactly one.** At least one, because an empty `Sinks` makes `offer` a no-op (`src/delivery/mod.rs:141`) and every zero-drops assertion vacuous (C28). At most one, because a record offered to both sinks and dropped by both is counted twice in the sum, which would make `offered − delivered == dropped` fail on a healthy run — turning the feature's headline reconciliation into a flake. | `sf-threat-model` omitted item (c), `evidence/threat-model-gate3.md` |
| C66 | current-Gate decision | resolved | 3 | none | C46's row offered two permitted implementations of the hold while its `send` subsection permitted one and rejected the other. Reported by `sf-red-team` round 2, repaired in the subsection, and **not** repaired in the row — the recurring failure of this gate. | **C46's row now states the single permitted implementation and carries the rejection in its own Rejected clause.** Gate 4 slices cite decision rows, not module prose, so a row offering the rejected option is the one an implementer would build from: a SIEM sink whose queue never accumulates during an outage, failing `rl10` and undelivering C31/C6's premise while `rl23` and `rl23b` both pass. | `sf-gate-qa` G3QA-17, `gate-3-qa.md` |
| C67 | current-Gate decision | resolved | 3 | none | C65 pinned "a queue budget small enough that a pipeline slower than `F` fills it within `D`" — unsatisfiable for a pipeline at `F − ε` — and claimed a 4× regression trips limb 1, which is arithmetically false: with `F = R/4`, a 4× regression gives `P = F`, so the queue grows at `F − P = 0` and never fills. Neither `B` nor `D` had a value anywhere in the gate. | **`D = 5 s`, `B = F × (D/2) × BYTES_PER_RECORD`, and each limb's detection role stated separately.** Limb 1 trips when the delivery pipeline sustains less than `F/2`, since the queue grows at `F − P` and `B` holds `F × D/2` of offer. Limb 2 trips when the request path cannot sustain `F`, because the loop is closed and `offered` then falls short. Limb 3 trips when the counters disagree with the destination. C65 had the roles inverted, calling limb 1 the collapse detector when limb 2 is the request-path detector and limb 1 the pipeline one. | `sf-gate-qa` G3QA-20, `gate-3-qa.md` |
| C68 | current-Gate decision | resolved | 3 | none | C46 said the backoff sleep is `select!`ed against `drain.cancelled()` but never said what the cancellation branch **does**. At the drain call sites `siem.rs:84` and `:88` the token is already cancelled, so "skip the sleep and retry" spins for the whole 5 s drain window — the hot-spin C46 forbids — while "return" silently voids the drain path's `BACKOFF` ladder. `rl23`, `rl23b` and `tp15` all pass either way, so it was a hidden implementation decision. | **On cancellation `send` returns without a further attempt**, leaving the batch to `Unsent::drop` (`:212`), which counts it. The consequence is named rather than left implicit: during drain the `BACKOFF` ladder does not run and each `send` call makes exactly one delivery attempt. That is the right behaviour when flushing at shutdown, and it changes little — today's ladder sums to about 2.6 s of sleeping inside a 5 s budget shared by every remaining batch. | `sf-gate-qa` G3QA-19, `gate-3-qa.md` |
| C69 | current-Gate decision | resolved | 3 | none | `build_decision` was declared `method: &str` returning a `Decision` whose `method` is a `String`, "with `loggable` applied inside" — but `loggable` returns `Option<String>` and filters an empty segment to `None` (`src/http/logging.rs:322-326`, `:323`). The mapping was unstated, and `rl16b` generates the empty method and asserted every input comes back escaped. | **`method: loggable(Some(method)).unwrap_or_default()`, the same shape `package` and `version` already use at `:212-213`.** An empty method therefore maps to `String::new()`, unescaped, exactly as an absent package does — and `rl16b` asserts that case explicitly rather than asserting a blanket "escaped exactly as `package` is", which was false for the one input it deliberately generates. | `sf-gate-qa` G3QA-21, `gate-3-qa.md` |
| C62 | current-Gate decision | resolved | 3 | none | C46 required the backoff sleep to be `select!`ed against `drain.cancelled()` **inside `send`**, while the `send` subsection froze the signature as "unchanged". `send` (`src/delivery/siem.rs:113-119`) takes no token; `drain` is a local of `run` (`:50`) passed to none of its four call sites. | **`send` gains `drain: &CancellationToken`, and all four call sites pass `&drain`.** Freezing the signature made C46's one permitted implementation `E0425: cannot find value 'drain' in this scope` at `:181` — and the implementer's likely escape is the retry loop that never observes cancellation, which is exactly the High-severity G3-T4 implementation `rl23` exists to reject and the one that hangs `tp7` and `tp11a`. The rejection of the task-state alternative is re-derived from the `rx.recv()` guard argument alone (`:61-72` is unconditional; only the timer arm at `:73` carries `if !batch.is_empty()`), which stands without reference to the signature. | `sf-red-team` round 2 finding 1, [evidence/red-team-gate3-round2.md](evidence/red-team-gate3-round2.md) |
| C63 | current-Gate decision | resolved | 3 | none | With the literal extracted into `build_decision`, `decide` was still shown applying `loggable` to `method` at `:210` **and** `build_decision` applying it again inside. | **`loggable` is applied in exactly one place, inside `build_decision`; `decide` applies no bound.** `loggable` is `format!("{bounded:?}")` (`:322-326`) and is not idempotent, so two applications emit every record's `method` as `"\"GET\""` — a SPEC §11 field-value regression that ships green, because `rl16b` and `rl22` call `build_decision` directly and see one application, the existing suite asserts only key presence (`DECISION_FIELDS`, `tests/decision_log_delivery.rs:36-48`), and **no test in the repository asserts the `method` value at all**. | `sf-red-team` round 2 finding 2, [evidence/red-team-gate3-round2.md](evidence/red-team-gate3-round2.md) |
| C64 | current-Gate decision | resolved | 3 | none | The `SinkCounters` change did not compile at three of its own call sites, and named one binding two ways. | **Three corrections.** `Sinks::drops` is **changed**, not unchanged: its `sink.drops.swap(0, …)` (`src/delivery/mod.rs:155`, `:159`) is `E0616` once `window` is private, and becomes `sink.counters.take_window()`. The binding is renamed `drops` → `counters` in one pass across every field, parameter and body, since the frozen signatures said `drops` while every rewritten body said `counters` — `E0425` at all eight loss sites. `tp19`'s read at `src/delivery/file.rs:260` becomes `counters.total()`, as `SinkCounters` exposes no `load`. These are compile errors rather than silent defects, which is C45 working as intended. | `sf-red-team` round 2 finding 6, [evidence/red-team-gate3-round2.md](evidence/red-team-gate3-round2.md) |
| C65 | current-Gate decision | resolved | 3 | none | `rl18`'s throughput limb carried no throughput information. With `drive_rated_load` pacing the offer at `target_rate`, `offered ≈ F × D` by construction, so limb 1 (`dropped == 0`) and limb 3 (exact reconciliation) together entail limb 2 (`delivered >= F × D`); and C60's `4 × D` deadline multiplied with `F`'s own 4× headroom, detecting nothing until a ~16× collapse. | **Pin a small queue budget in the floor test, and cut the deadline to `D + 30 s`.** The driver is confirmed closed-loop: `target_rate` paces the offer, `achieved` reports what it sustained. Pinning a budget stops a short run fitting entirely inside the C13 default queue, where a dead sink drops nothing — the same device `tp7` uses (C41) — and cutting the deadline stops the two 4× margins compounding. **This row's own sizing rule and margin claim were wrong and are superseded by C67**: "small enough that a pipeline slower than `F` fills it" is unsatisfiable at `F − ε`, and with `F = R/4` a 4× regression gives `P = F`, so the queue grows at `F − P = 0` and never fills. C67 supplies `D`, `B`, and each limb's actual detection role. | `sf-red-team` round 2 finding 5, [evidence/red-team-gate3-round2.md](evidence/red-team-gate3-round2.md); superseded in part by `sf-gate-qa` G3QA-20 |
| C61 | current-Gate decision | resolved | 3 | none | `rl6` drove a "capacity conversion" that was declared nowhere — prose inside `build`, a function that also probes and opens the log file — and was sited in `tests/`, where `mod delivery` being `pub(crate)` (`src/lib.rs:13`) means it can name neither `BYTES_PER_RECORD` nor `build`. It could not compile, and no reviewer had checked it: it appears in neither `sf-red-team`'s findings nor its clean list. | **Name the arithmetic: `delivery::capacity_for(budget) -> Result<usize, CapacityError>`, total over its whole input domain, called by both `config` (to decide its lower budget rule) and `build`.** The property is sited in-crate like `rl22` and `rl16b`. Being total is what makes it a seam: it returns `Err` for the inputs `config` refuses rather than panicking, so a property can sweep the full `u64` range. It also removes the per-target claim `rl6` could not observe — `MAX_SAFE_CAPACITY` is `Semaphore::MAX_PERMITS` for the target actually compiled, so the property holds wherever it runs instead of asserting something about an absent target. | `sf-gate-qa` G3QA-12, `gate-3-qa.md` |
| C57 | current-Gate decision | resolved | 3 | none | C51 moved `rl22`'s property onto `logging::decide`'s inputs, but `decide` cannot be the seam: it is axum middleware taking `State`, `Request` and `Next`; `axum::middleware::Next` has no public constructor; and `decide` never yields the `Decision` at all — the literal is inline at `src/http/logging.rs:207` and moves straight into `offer` at `:243`. The row's observable had no observation point. | **Extract the record literal into a pure `build_decision(...) -> Decision` in `src/http/logging.rs`, called by `decide` in place of the inline literal.** The property then generates method and path strings, runs them through `Target::of` and `build_decision`, and measures the returned record's **heap footprint** — `size_of::<Decision>()` plus each `String`'s capacity, never serialized size, which approved C29 states is a different quantity. Behaviour is unchanged; the extraction exists to give the record-building step a seam it does not have today. This is the third attempt at `rl22` and the first with a callable observation point. | `sf-gate-qa` G3QA-1, `gate-3-qa.md` |
| C58 | research fact | resolved | 3 | none | C50 supersedes approved `02-architecture.md` C34 without saying so. C34 fixes `delivered` as distinct `request_id` values **excluding** `RequestSummary` lines, with the equality `offered − delivered == dropped`; C50 counts summaries **in** and uses `(offered + 1) − delivered == dropped`. | **Reconciled here rather than by reopening Gate 2**, the C38 and C55 precedent, and stated explicitly rather than left implicit. C34's intent holds exactly — `delivered` must be an *independent* observation at the destination so the equality is a real assertion and not an arithmetic identity. What changes is only the bookkeeping: C34's exclusion clause was written believing `lost_total()` counted decided records alone, but both `Record` variants reach the same counter through `Sink::push`, so excluding summaries from `delivered` while leaving them in `dropped` makes the equality false against a correct implementation. Counting both kinds and adding the one shutdown summary restores C34's own intent. C34 is a research fact, so this needs a row and not a user answer. Correction carried into C53: C28 approved two limbs and C34 supplied the third. | `sf-gate-qa` G3QA-5, `gate-3-qa.md` |
| C59 | current-Gate decision | resolved | 3 | none | `rl23` carries High-severity G3-T4 but named no test-level timeout, so against the implementation it exists to reject — a hold that never polls `drain.cancelled()` — `shutdown().await` never returns and the row **hangs instead of failing**. G3-T5's cadence property had no carrier at all. | **`rl23` wraps `shutdown()` in `tokio::time::timeout(Duration::from_secs(20), …).expect("HANG: …")`, the exact guard `tp15` already uses (`tests/decision_log_delivery.rs:1003-1026`), and a new `rl23b` observes the hold's POST cadence at the collector.** The document had already established this failure mode twice — C41 calls `tp15` the suite's sole hang-to-failure converter, and `evidence/gate3-analysis.md` §7 records that `tp7` and `tp11a` hang rather than fail — and then failed to apply it to the sole carrier of a High threat. | `sf-gate-qa` G3QA-2 and G3QA-7(a), `gate-3-qa.md` |
| C60 | current-Gate decision | resolved | 3 | none | C53 claimed the floor test's deadline and headroom "are stated in the row"; neither appeared anywhere, leaving C11's required generous deadline unstated on exactly the limb C11 names as dangerous. | **`delivered >= F × D` is asserted within a wall-clock deadline of `4 × D`, and `F` is chosen at no more than one quarter of the debug-build rate the measuring slice observes.** Both numbers are now in the `rl18` row itself rather than promised by it. The 4× deadline and the 4× headroom are deliberately generous against the `tests/artifacts_concurrency.rs:991` scar, where a 500 ms margin calibrated to debug timing fails under `--release`; a genuine collapse of the delivery pipeline still misses a floor set four times below the observed rate. | `sf-gate-qa` G3QA-8, `gate-3-qa.md` |
| C55 | user clarification | resolved | 3 | none | C49 adds `proptest`, but approved `02-architecture.md` `## External` reads in full: "None. No third-party API, no webhook, **no new dependency**." C49 argued the dependency against the criterion precedent and never mentioned the approved sentence it reverses. Reconcile here, or reopen Gate 2? | **Reconciled here rather than by reopening Gate 2**, the way C38 reconciled C31 against Gate 1's Non-goal. `## External`'s subject is runtime external surface — its own template line is "third-party APIs, env var NAMES (never values), webhooks" — and the sentence's intent holds exactly: this feature still reaches no third-party API, registers no webhook and adds no runtime dependency. `proptest` is a `[dev-dependencies]` entry in a crate that is `publish = false` (`Cargo.toml:8`), compiled only into test and bench binaries, so nothing ships and no runtime surface changes. The `Cargo.toml` row of `## Files` names the dependency and the committed `proptest-regressions/` explicitly, so the contradiction is recorded rather than silent. Rejected: reopening Gate 2 for a test-only dependency, a full gate cycle for no change to the architecture; and dropping property tests to keep the sentence literal, which costs `rl22` its ability to falsify High-severity G3-T3. | user answer, Gate 3 grilling Q3 |
| C50 | current-Gate decision | resolved | 3 | none | `rl17`'s reconciliation `offered − delivered == dropped` cannot hold: `Record` has two variants and both reach the same counter through `Sink::push`, so a dropped `RequestSummary` raises `dropped` while raising neither `offered` (requests issued) nor a decided-record tally — and `rl17` runs a deliberately small queue, which is exactly when a summary is dropped. | **The driver pins the summary window past the run, counts both record kinds at the destination, reconciles `(offered + 1) − delivered == dropped`, and asserts the drain deadline was not hit.** The window is pinned through the existing `set_summary_window` seam (`src/http/logging.rs:461`) so the only summary offered is the one `flush_summary` emits at shutdown (`src/lib.rs:321`) — hence exactly `+ 1`. The drain-deadline assertion is required because `src/delivery/file.rs:60-61` documents that counter as "may be one high and is never low", which no exact equality can survive. Rejected: loosening the equality to `>=`, which returns the feature's headline reconciliation to the arithmetic identity C34 exists to prevent. | `sf-red-team` finding 1, `evidence/red-team-gate3.md` |
| C51 | current-Gate decision | resolved | 3 | none | `rl22` as first written could not pass. `Decision` is a `pub(crate)` struct with public `String` fields, so a `Decision` whose `method` is a 1 MiB `String` is freely constructible and "no constructible `Decision` exceeds `BYTES_PER_RECORD`" is false for every finite constant — proptest would shrink to a counterexample on the first run. `Decision` is also `pub(crate)`, so a `tests/`-resident property could not name the type. | **The property is stated over `logging::decide`'s inputs, not over `Decision` values, and lives in an in-crate `#[cfg(test)]` module.** The ceiling exists only because `decide` applies `loggable` on the way in, so the invariant that is actually true is "every record `decide` produces fits", and that is what the property generates for: arbitrary HTTP method, package, version and consumer. Siting it in-crate also solves the visibility problem. `reason` is excluded from generation and added to the C37 derivation as a constant instead: `sf-threat-model` verified every `ApiError` arm supplies a `&'static str` (`src/http/error.rs:35`, `:38`, `:136-172`), so its ceiling is the longest of that fixed set. | `sf-red-team` finding 2, `evidence/red-team-gate3.md` |
| C52 | current-Gate decision | resolved | 3 | none | Four rows could not fail or failed against correct code: `rl11`'s input does not exist, `rl7` claimed eight drivable sites, `rl16` cannot discriminate on x86-64, and `rl16c` as written went red against a correct implementation. | **Each is restated honestly rather than left as false coverage.** `rl11` and `rl16` become **structural** evidence read at the seam, not execution: `serde_json::to_string` cannot fail on an all-`String`/integer `Decision`, and x86-64's TSO model does not reorder the relaxed stores C47's ordering contract forbids, so a racing test stays green against the implementation it exists to reject. `rl7` drives the **six** reachable sites; the two serialize branches (`file.rs:105`, the new `siem.rs` one) are unreachable by construction. `rl16c` gains the interleaved probe it needs — without one, the post-step probe is itself the first since the loss and correctly stamps `now`. | `sf-red-team` finding 5, `evidence/red-team-gate3.md` |
| C53 | current-Gate decision | resolved | 3 | none | `rl18` carried two of the three approved assertions for the floor test, relocating the third to `rl17` — a different test with a different configuration. The three are not all C28's: **`02-architecture.md` C28 says the test "gains a second limb", and C34 supplies the third** (correction per `sf-gate-qa` G3QA-15). | **All three limbs return to `rl18`**, with the third in its C50 form. Without it the floor cannot fail for the case C3 requires: a run that over-delivers relative to `F × duration` while losing records at an uncounted site passes with `dropped == 0` and `delivered >= F × duration`. The deadline `F` is asserted within, and the headroom `F` is chosen with, are stated in the row — C11 requires a generous deadline precisely because the surviving throughput limb is a debug-build timing assertion, the shape `tests/artifacts_concurrency.rs:991` already scarred this repository with. | `sf-red-team` finding 6, `evidence/red-team-gate3.md` |
| C54 | current-Gate decision | resolved | 3 | none | C48 says the driver configures exactly one sink but never says **which** one the bench uses, while `rl19`'s rotation rule implies the file sink and C13's tolerance `M` describes a SIEM collector outage. | **The bench configures the file sink.** It is local, reaches no network, has no collector to wedge and is therefore reproducible on the named reference hardware — the property a published figure needs. The rated figure `N` is a property of the request path, not of a particular sink, and the tolerance `M` is then derived arithmetically per sink as `budget ÷ BYTES_PER_RECORD ÷ N`. `docs/operations.md` states that the SIEM tolerance is derived this way rather than measured against a live collector, so no reader mistakes it for an observed collector-outage figure. | `sf-red-team` question 3, `evidence/red-team-gate3.md` |
| C49 | current-Gate decision | resolved | 3 | none | Whether any Gate 3 test-plan row is a property test under `sf-tdd`, and whether `proptest` is added as a dev-dependency to a repository that carries exactly two and deliberately dropped criterion (`Cargo.toml:77-82`). | **Three rows are properties and `proptest` is added.** `sf-tdd` makes a property test mandatory — not optional — when the promise is a roundtrip, invariant, metamorphic or oracle and the language is in its supported table; Rust is, with `proptest` as the default and `proptest-regressions/` as the committed replay evidence. `rl22` (no constructible `Decision` exceeds `BYTES_PER_RECORD`), `rl16b` (every method string is bounded) and `rl6` (no `u64` budget panics or yields a bad capacity) each state an invariant over a whole domain, and the first carries the High-severity G3-T3 — a hand-picked worst-case record proves only that the one record the author thought of fits. The dependency is the real cost: it is the third `[dev-dependency]` in a repository disciplined about them. It is accepted because criterion was dropped for being unable to express its targets, whereas `proptest` expresses these three exactly. Every other row stays an example test with a literal expected value, as `sf-tdd` prescribes. | user challenge, 2026-09-24; `sf-tdd` `properties.md` supported-languages table |
| C44 | research fact | resolved | 3 | none | Is "256 chars is up to 1 KiB in UTF-8" (C29) the complete per-field ceiling for a `loggable`-bounded string? | No — it omits the escape expansion. `loggable` (`src/http/logging.rs:322-326`) takes 256 **chars** and then returns `format!("{bounded:?}")`, so the `Debug` escaping runs *after* the bound: a control character becomes `\n` (2 chars) or `\u{...}` (up to 10), and two quote characters are added. The ceiling for one bounded field is therefore `(MAX_LOGGED_TARGET chars × 4 bytes × worst-case escape expansion) + 2`, and a `String` contributes its heap **capacity**, not its length. C37's required derivation must carry the expansion term or `BYTES_PER_RECORD` is a mean wearing a ceiling's clothes. | `sf-repo-view`, `evidence/gate3-analysis.md` §3(b) |

## Files

| File | New or changed | Why it lives there |
|---|---|---|
| `src/config.rs` | change | Declares and validates both budgets. The only exhaustive `Config` literal in the repository is here (`:302-340`), so this is the one file that breaks at compile time (`evidence/gate3-analysis.md` §6). Six edits: two `RawConfig` fields, two `Config` fields, two `OPTIONAL_KEYS` entries, the default and ceiling constants, the validation arm, and two fields in the `Ok(Config { … })` literal. |
| `src/delivery/mod.rs` | change | Owns the queue construction, so it owns the byte→record conversion and `BYTES_PER_RECORD`. Declares `mod counters;` and holds `Arc<SinkCounters>` on `Sink` in place of `Arc<AtomicU64>` (`:109`). |
| `src/delivery/counters.rs` | **new** | Defines `SinkCounters`. It is a separate module precisely so that `file` and `siem`, which are sibling child modules of `delivery`, cannot reach the `window` and `total` fields and must call `lose` — the compile-time enforcement of the loss-site invariant (C45). |
| `src/delivery/file.rs` | change | Four of the eight loss sites are here; each must do all three writes. |
| `src/delivery/siem.rs` | change | Two of the eight loss sites (`:97`, `:212`), plus the eighth site overall — the serialize-failure branch that has no counter today (C27) — so three in this file. Also the hold-while-unreachable change (C31, C46, C56) and `send`'s new `drain` parameter (C62). |
| `src/http/health.rs` | change | Serves the shedding signal. A third handler in the same 39-line module, the same bare-`StatusCode` shape as `live` and `ready`. |
| `src/http/mod.rs` | change | One literal `.route(...)` line after `:42`, in the byte-exact shape of the two health lines above it. |
| `src/http/logging.rs` | change | The `Decision` literal at `:207-222` is extracted into a pure `build_decision` (C57), which applies `loggable` to `method` — the last unbounded record field (C22), bounded in exactly one place (C63). Without it `BYTES_PER_RECORD` is not a ceiling. Also gains the in-crate `#[cfg(test)]` property module for `rl22` and `rl16b`. |
| `src/lib.rs` | change | One `#[cfg(feature = "test-support")]` accessor on `impl App`, beside `delivery_is_empty` (`:114`). The crate's only new gated item. |
| `src/main.rs` | change | **New at the slice-2 reopen (C87).** One line appended to the `EnvFilter` built at `:58-63`, pinning the audit target so no level or target `RUST_LOG` directive can silence the decision log (G3-T9, scoped by C90). The only change to this file. |
| `config.sample.toml` | change | Both keys, commented out beside their sink's other keys — the `log_file_max_bytes` precedent, which is what keeps `tests/config_validation.rs:171` and `:174` green. |
| `tests/common/mod.rs` | change | Holds the load driver (C42), so the bench and the floor test run the identical loop and cannot drift. |
| `tests/delivery_rated_load.rs` | **new** | The floor test, asserted by `cargo test` (C14). |
| `benches/delivery_rated_load.rs` | **new** | The ten-minute sustained run producing the rated figure and the `BYTES_PER_RECORD` derivation. `harness = false` with its own `main`, following the three existing benches (C19). |
| `Cargo.toml` | change | One `[[bench]]` entry with `harness = false`, matching `:23-33`, **and `proptest` as a third `[dev-dependencies]` entry** (C49, C55). It is compiled only into test and bench binaries and the crate is `publish = false` (`:8`), so no runtime surface changes — which is the reconciliation C55 records against Gate 2 `## External`. |
| `proptest-regressions/` | **new** | Committed replay files for the three property rows, as `sf-tdd` requires: a failing property writes its shrunk counterexample here and replays it on the next run. |
| `tests/decision_log_delivery.rs` | change | **`tp7` only** pins its own `siem_queue_max_bytes` (C41). Five further tests in this file are affected and none is edited: `tp9`, `tp11a`, `tp15` and `tp15b` stay green under C46 and C56, and `tp15` must not be weakened — it carries the suite's only hang-to-failure timeout. |
| `docs/operations.md` | change | Publishes the four numbers, the reference hardware, the `BYTES_PER_RECORD` derivation, the additive-memory statement, the upgrade note, and the four documentary security items that exist nowhere else (restated and widened at the slice-2 reopen; slice 7 enumerates them) (C25, C26, C29, C30, C37, C38). **Added at the slice-2 reopen:** **slice 7 carries all of these** (see `04-slices.md` `### Slice 7 interfaces`). The C26 statement is restated as “stdout carries every decided request, except where the console writer itself fails (G3-T10), the handler never returns (G3-T11), the host log transport truncates it (G3-T13), or a span- or field-qualified `RUST_LOG` directive out-specifies the pin (C90)”, naming its four exceptions (C88): G3-T10, G3-T11, G3-T13, and C90's span- or field-qualified directive; the `RUST_LOG` guidance at `:427` gains a sentence that the decision log is pinned and not silenceable by any level or target directive, the scope C90 fixes (C87); and the decision-line sample at `:414-419` is corrected by **slice 2**, which caused the drift, from `"method":"GET"` to `"method":"\"GET\""`, which is what the tree ships after slice 2 — verified on both stdout and the NDJSON sink. |

## Modules and interfaces

Programming entry point: **none.** `mod delivery` stays `pub(crate)` (`src/lib.rs:13`) and this
feature adds no public Rust API. The single new gated item is one accessor on `App`, in the shape
of the two that already exist (`src/lib.rs:114`, `:300`).

### `delivery` (`src/delivery/mod.rs`) — existing, changed

Purpose: owns where a decision record goes once it exists, and now also how much memory each
sink's queue may hold and whether records are currently being lost.

Provides: unchanged non-blocking `offer` for the request path; a read-and-reset window snapshot
for the summary record; a monotonic total for the measurement harness; a shedding answer for the
health route.

Owns: `BYTES_PER_RECORD`, the default and ceiling budget constants, the shed quiet period,
`SinkCounters`, and the byte→record conversion. Both window counters keep today's semantics.

Public types and values:

```rust
/// A conservative ceiling on one record's heap footprint, in bytes.
/// Derivation published by the bench and in docs/operations.md (C29, C37, C44).
pub(crate) const BYTES_PER_RECORD: u64;

/// The per-field ceiling BYTES_PER_RECORD's derivation sums, for each
/// `loggable`-bounded String: MAX_LOGGED_TARGET chars x 4 bytes of UTF-8
/// x the worst-case Debug escape expansion, + 2 quote characters (C44).
/// `reason` is excluded: every ApiError arm supplies a &'static str, so its
/// ceiling is the longest of that fixed set (C51).
pub(crate) const FIELD_CEILING_BYTES: u64;

/// Per-sink default budget: the smallest whole MiB buying >= 5 minutes of
/// collector outage at the 200 rps reference load, ceil(300 x 200 x
/// BYTES_PER_RECORD) = 1,875 MiB (C13 as amended, C39). Not derived from the
/// measured ceiling N, which no honest budget could cover. Literal set by the bench slice.
pub(crate) const DEFAULT_QUEUE_MAX_BYTES: u64;

/// Per-sink ceiling, refused above this at config load (C36).
pub(crate) const MAX_QUEUE_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// How long /health/delivery reports 503 after the last loss (C35).
pub(crate) const SHED_QUIET: Duration = Duration::from_secs(60);

/// Shared per-sink state behind the Arc cloned into each sink task.
/// Replaces the bare `Arc<AtomicU64>` at src/delivery/mod.rs:109 (C21, C33, C40).
/// Defined in src/delivery/counters.rs, NOT in mod.rs, so that the sibling
/// modules `file` and `siem` cannot reach these fields and must call `lose` (C45).
pub(super) struct SinkCounters {
    window: AtomicU64,   // private to `counters`; reset only via take_window()
    total: AtomicU64,    // private to `counters`; monotonic, never reset
}

impl SinkCounters {
    pub(super) fn new() -> SinkCounters;        // both fields zero
    pub(super) fn lose(&self, n: u64);          // the ONLY increment path
    pub(super) fn take_window(&self) -> u64;    // swap(0), for Sinks::drops()
    pub(super) fn total(&self) -> u64;          // load, for Sinks::lost_total()
}
```

Every item is `pub(super)`, which from `counters` means visible throughout `delivery` and its
descendants — `mod.rs`, `file` and `siem` alike. **A constructor is required and was missing**
(`gate-3-qa.md` G3QA-13): the fields are private to `counters`, so by this design's own reasoning
`mod.rs` cannot write the struct literal it needs at `src/delivery/mod.rs:214-215` and `:251`,
and `tp19` cannot replace `AtomicU64::new(0)` at `src/delivery/file.rs:249`. `SinkCounters::new()`
is what both call.

`src/delivery/mod.rs` gains `mod counters;` beside the existing `mod file;` / `mod siem;`
(`:13-14`).

**The binding is renamed `drops` → `counters` everywhere, in one pass** (C64). The field is
`drops` today (`mod.rs:109`) and every signature this design freezes inherited that name — 
`file::run(drops: Arc<SinkCounters>)`, `Unsent<'a> { drops: &'a SinkCounters }` — while every
body it writes says `counters.lose(n)`. Two names for one binding is `E0425` at all eight loss
sites. `Sink.counters`, `run(.., counters: Arc<SinkCounters>)`,
`Unsent<'a> { count: u64, counters: &'a SinkCounters }`. The three now-unused
`use std::sync::atomic::{AtomicU64, …}` imports (`mod.rs:20`, `file.rs:10`, `siem.rs:10`) drop
`AtomicU64`; `Ordering` stays where it is still used.

**What the module move does and does not enforce** (C45, corrected by `gate-3-qa.md` G3QA-4).
The fields are private to `counters`, so **no code outside that module can perform a raw
`fetch_add`** — which is exactly the bypass the loss-site invariant forbids. That much is a
compile error, and it is the whole of the enforcement.

It is *not* true that `lose` is the only mutator that compiles. `Sinks::drops()` lives in
`mod.rs`, and a **parent** module has no more access to a child's private fields than a sibling
does, so `take_window` must be at least `pub(super)` — which also makes it reachable from `file`
and `siem`. That is acceptable: `take_window` resets a counter, it cannot *record a loss*, so a
loss site still has no way to account for a lost record except by calling `lose`. The invariant
the compiler enforces is therefore "**a loss cannot be recorded except through `lose`**", not
"nothing else mutates".

`Drops` (`src/delivery/mod.rs:100`) is unchanged and keeps its meaning: the two-field snapshot the
summary record reads.

Callers and visibility: `pub(crate)` throughout. `http::logging` reads the window snapshot,
`http::health` reads the shedding answer, `App` exposes the monotonic total behind
`#[cfg(feature = "test-support")]`.

#### `SinkCounters::lose(&self, n: u64)` — proposed

Declaration: `pub(super) fn lose(&self, n: u64)`

Accepts: `n`, the number of records lost at this site, `n >= 1`.

Returns: nothing.

Rejects: nothing; infallible by construction.

Effects: increments `window` and `total` by `n`, both `Ordering::Relaxed`. This single call **is**
the loss-site discipline: a site that calls it cannot do two of the three things and miss the
third. The shed marker needs no separate write, because the marker is derived from `total` by the
reader (C35) rather than stored.

Caller obligations: call exactly once per loss, with the true count. No lock, allocation, syscall
or clock read is permitted inside (C24), which this body satisfies with two relaxed atomic adds.

Uses: nothing.

Caller example — the queue-full site, `src/delivery/mod.rs:113-118` after the change:

```rust
fn push(&self, record: Record) {
    if self.tx.try_send(record).is_err() {
        self.counters.lose(1);
    }
}
```

Checks: `rl7`, `rl8`, `rl9`, `rl11`.

#### `Sinks::drops(&self) -> Drops` — existing, **changed** (C64)

Declaration: `pub(crate) fn drops(&self) -> Drops` — unchanged signature and unchanged meaning,
but the **body changes**: `sink.drops.swap(0, Ordering::Relaxed)` (`src/delivery/mod.rs:155`,
`:159`) reaches into the atomic directly, which is `E0616` once `window` is private to
`counters`. It becomes `sink.counters.take_window()`.

Accepts: `&self`.

Returns: the per-sink counts since the last call, then zeroes them — identical semantics to
today, now expressed through `take_window()`.

Rejects: nothing.

Effects: resets `window` via `take_window()`. Never touches `total`.

Caller obligations: **exactly two consumers, and only one of them reaches a sink.** `close_window` (`:421` at HEAD, `:465` in the working tree) builds the `Summary`, which goes to the sinks and the console; `flush_drop_tail` (`:400` / `:444`) writes `tracing::warn!` and reaches **the console only**, so it is the sole carrier of drain-window losses — the fact that makes G3-T10 and G3-T12 bite. Neither the health route
(C16) nor the measurement driver (C33) may call it; a second concurrent caller silently steals a
window's counts (`src/delivery/mod.rs:148-149`). Its two call sites are `src/http/logging.rs:400`
and `:421` at HEAD `734d22d`, which slices 1-2 shift to `:444` and `:465` (baseline note under
`## Invariants`).

Uses: nothing.

Checks: `rl8`, `rl9`.

#### `Sinks::lost_total(&self) -> u64` — proposed

Declaration: `pub(crate) fn lost_total(&self) -> u64`

Accepts: `&self`.

Returns: the sum of both sinks' monotonic `total` counters, `Ordering::Relaxed`. Never resets.
This is what makes `offered − delivered == dropped` a real assertion over a whole run rather than
over the last summary window (C33, C34).

Rejects: nothing.

Effects: none. Any number of concurrent callers is safe, which is the property `drops()` lacks.

Caller obligations: none.

Uses: nothing.

Checks: `rl9`, `rl17`.

#### `Sinks::is_shedding(&self, now_utc_micros: i64) -> bool` — proposed

Declaration: `pub(crate) fn is_shedding(&self, now_utc_micros: i64) -> bool`

Accepts: `now_utc_micros`, the caller's clock reading in microseconds since the Unix epoch — the
same value `src/http/health.rs:31` already obtains from `app.clock.now_utc_micros()`. The clock
read stays with the caller so it never enters `Sink::push` (C24).

Returns: `true` while a record was lost within the last `SHED_QUIET`, `false` otherwise. With no
sink configured it returns `false`, because no record can be lost (C43).

Rejects: nothing.

Effects: updates the watch pair. **The pair lives on `Sinks`, exactly one instance for the
process — not one per sink** (C47), because one `503` covers both sinks (C9). It is
`last_change_micros: AtomicI64` initialised to `i64::MIN`, and `last_total: AtomicU64`
initialised to `0`.

The two stores are **ordered, not both relaxed** (C47). `is_shedding` reads `lost_total()`, and
when it differs from `last_total` it stores `last_change_micros` **first**, then stores
`last_total` with `Ordering::Release`; the load of `last_total` is `Ordering::Acquire`. That
ordering is what makes the pair safe for concurrent probers: a prober observing
`total == last_total` is guaranteed to see the timestamp that accompanied it. With both stores
relaxed, prober A could store `last_total` and be preempted, and prober B would then read
`total == last_total` with a stale `last_change_micros` and answer `200` while records were being
destroyed.

The staleness test is `now_utc_micros.saturating_sub(last_change_micros)`, and the answer is
`true` when that delta is **both non-negative and less than `SHED_QUIET`**. The non-negative
condition matters: a backwards wall-clock step, such as an NTP correction, makes the delta
negative, and a bare `< SHED_QUIET` test would latch `503` for the whole size of the step
(C47). `i64::MIN` cannot overflow under `saturating_sub`, so a process that has never lost a
record answers `false`.

Caller obligations: none. Any number of alerting systems may probe this route (C35): unlike
`drops()`, concurrent callers converge on the same values rather than stealing from each other.

Uses: nothing.

Caller example — `src/http/health.rs`, the new handler:

```rust
pub async fn delivery(State(app): State<Arc<App>>) -> StatusCode {
    if app.delivery.is_shedding(app.clock.now_utc_micros()) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}
```

Checks: `rl12`, `rl13`, `rl14`, `rl15`, `rl16`.

#### `delivery::build(config, drain)` — existing, changed

Declaration: unchanged —
`pub(crate) fn build(config: &Config, drain: CancellationToken) -> Result<(Sinks, Vec<JoinHandle<()>>), StartupError>`

Accepts: unchanged. `build` already takes `&Config` (`src/delivery/mod.rs:203`), so **no caller and
no call site changes** (`evidence/gate3-analysis.md` §4).

Returns: unchanged.

Rejects: unchanged. It does **not** gain a capacity error: `config` has already refused any budget
that would produce a bad capacity (C23, C36), so by the time `build` runs the arithmetic cannot
fail.

Effects: each `mpsc::channel(QUEUE_CAPACITY)` (`:214`, `:250`) becomes
`mpsc::channel(capacity_for(budget).expect("config validated"))`. `const QUEUE_CAPACITY` (`:37`)
is deleted; it has no other reference anywhere in the repository.

Caller obligations: unchanged — `App::start` passes the validated `Config` it already holds.

Uses: `config.log_queue_max_bytes`, `config.siem_queue_max_bytes`, `capacity_for`.

Checks: `rl1`.

#### `delivery::capacity_for` — proposed (C61)

Declaration (C61, corrected per `sf-red-team` round 2 finding 3):

```rust
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CapacityError {
    TooSmall,   // quotient is 0 -> mpsc::channel(0) panics
    TooLarge,   // quotient exceeds MAX_SAFE_CAPACITY, or usize::try_from fails
}

/// Semaphore::MAX_PERMITS for the target actually compiled.
pub(crate) const MAX_SAFE_CAPACITY: usize;

pub(crate) fn capacity_for(budget: u64) -> Result<usize, CapacityError>;
```

Accepts: **any `u64`, including `0`** — not `NonZeroU64`. A property cannot hand `0` to a
`NonZeroU64` parameter, and `0` is C23's original `mpsc::channel(0)` panic input, so a
`NonZeroU64` signature would exclude from the sweep the very value the function exists to
refuse. `build` passes `config.log_queue_max_bytes.get()`.

`CapacityError` derives `Debug` so `build`'s `.expect("config validated")` compiles, and
`PartialEq`/`Eq` so the property can assert **which** arm it got rather than merely that it
erred.

Returns: `budget / BYTES_PER_RECORD` as a `usize` when that value is `1..=MAX_SAFE_CAPACITY`.

Rejects: `Err(CapacityError::TooSmall)` when the quotient is `0`, and
`Err(CapacityError::TooLarge)` when it exceeds `MAX_SAFE_CAPACITY` — the two inputs on which
`mpsc::channel` panics (C39). The conversion uses `usize::try_from`, never `as usize` (C23), so
a 32-bit target cannot truncate a large budget into a small capacity; `try_from` failing is
itself `TooLarge`.

Effects: none. Pure arithmetic, which is what makes it a property's seam.

Caller obligations: `build` calls it on an already-validated `Config`, so the `Err` arms are
unreachable there and `.expect` is honest. `config` calls the same function to decide its
**lower** rule — "must hold at least one record" — so that bound and the division can never
disagree (C23). Its **upper** rule is a different quantity and stays separate: `MAX_QUEUE_MAX_BYTES`
is a 4 GiB *byte* ceiling (C36), while `MAX_SAFE_CAPACITY` is a *capacity* bound; with the byte
ceiling in force, `TooLarge` is unreachable from config's accepted range on either target, and it
exists to keep `capacity_for` total rather than to enforce a config rule.

**This function did not exist in the previous revision** — the arithmetic was prose inside
`build`, a function that also probes and opens the log file, so `rl6` had nothing to call and
was sited in `tests/` where `pub(crate)` made it uncompilable (`gate-3-qa.md` G3QA-12). Naming
it also removes the per-target claim `rl6` could not observe: `MAX_SAFE_CAPACITY` is
`Semaphore::MAX_PERMITS` for the target actually compiled, so the property holds on whichever
target runs it rather than asserting something about a target that is not present.

Uses: `BYTES_PER_RECORD`, `MAX_SAFE_CAPACITY`.

Checks: `rl2`, `rl3`, `rl6`.

### `delivery::file` (`src/delivery/file.rs`) — existing, changed

Purpose: unchanged — writes records to the log file and rotates it.

Provides: unchanged.

Owns: four of the eight loss sites.

Public types and values: unchanged. `run`'s `drops: Arc<AtomicU64>` parameter (`:36`) becomes
`Arc<SinkCounters>`, and the `&AtomicU64` parameters of `drain` (`:65`), `Writer::append`
(`:103`) and `Writer::open` (`:151`) become `&SinkCounters`. Every call site keeps its shape,
because `&Arc<T>` deref-coerces (`evidence/gate3-analysis.md` §5).

#### The four loss sites — existing, changed

Declaration: unchanged signatures.

Effects: each of `:75` (drain deadline cut off `rx.len() + 1` records), `:105` (record would not
serialize), `:142` (write or flush error) and `:181` (file could not be opened) replaces its
`drops.fetch_add(n, Ordering::Relaxed)` with `counters.lose(n)`. The counts are unchanged; what
changes is that each now also advances the monotonic total and therefore the shed marker. The
`:181` case is the one Gate 2 threat T1 named: an unopenable log file destroys 100% of the trail
while the queue never fills, and after this change it raises `503`.

Caller obligations: unchanged.

Uses: `SinkCounters::lose`. It **cannot** reach `window` or `total` directly, because
`SinkCounters` is defined in the sibling module `counters` (C45).

Checks: `rl7`, `rl13`.

#### `tp19_file_drain_deadline_counts_cut_off_records` — existing, changed

The one existing test the widening touches, with three named replacements (C64):
`AtomicU64::new(0)` at `:249` → `SinkCounters::new()`; `&drops` at `:251` coerces unchanged;
and `drops.load(Ordering::Relaxed)` at `:260` → `counters.total()`, since `SinkCounters` exposes
no `load`. It reaches all three through `use super::*` at `file.rs:224`, which makes the
`#[cfg(test)]` module a descendant of `file` and so inside `pub(in crate::delivery)`. Behaviour
and assertion are unchanged.

Checks: `rl21`.

### `delivery::siem` (`src/delivery/siem.rs`) — existing, changed

Purpose: unchanged — batches records and posts them to the collector. **This module carries the
largest behavioural change in the feature (C31) and the eighth loss site (C27).**

Provides: unchanged.

Owns: three loss sites after C27, and the hold.

Public types and values: unchanged; the `drops` parameter types change as in `file.rs`, including
`struct Unsent<'a> { count: u64, drops: &'a SinkCounters }` (`:197-199`).

#### The three existing loss sites — existing, changed

Each of `:97` (drain deadline cut off `batch.len() + rx.len()`) and `:212` (`Unsent::drop`, the
whole undelivered batch, up to 256 records) replaces its `drops.fetch_add(n, Ordering::Relaxed)`
with `counters.lose(n)`, and `Unsent`'s field is renamed with the rest (C64). The counts are
unchanged. Stated explicitly because the previous revision gave `siem.rs` only the type change
and left the conversion of these two sites implied.

Checks: `rl7`, `rl23`.

#### The eighth loss site — proposed

Declaration: unchanged.

Effects: inside `send`'s `batch.drain(..)` loop (`:113-135`), the branch
`if let Ok(line) = serde_json::to_string(&record)` silently discards a record that will not
serialize, while the surrounding `Unsent` still reports the batch delivered — no counter runs at
all today. It gains `counters.lose(1)`, exactly as the file sink already counts the identical
case at `src/delivery/file.rs:105` (C27). Serde failure on a `Decision` is close to unreachable,
so this is a correctness-of-invariant fix rather than a live defect.

Checks: `rl11`.

#### `send` — existing, changed: the hold (C31)

Declaration: **changed** (C62) — it gains the cancellation token it must observe:

```rust
async fn send(
    client: &Client,
    url: &Url,
    auth: Option<&(HeaderName, HeaderValue)>,
    batch: &mut Vec<Record>,
    counters: &SinkCounters,
    drain: &CancellationToken,        // NEW
)
```

Today's signature (`:113-119`) takes no token, and `drain` is a local binding of `run` (`:50`)
passed to none of `send`'s four call sites (`:68`, `:74`, `:84`, `:88`). Freezing the signature
while requiring the sleep at `:181` to be selected against `drain.cancelled()` is
`E0425: cannot find value 'drain' in this scope` — the implementer would then either add the
parameter anyway or, worse, keep the signature and write the retry loop that never observes
cancellation, which is precisely the High-severity G3-T4 implementation `rl23` exists to reject
and the one that hangs `tp7` and `tp11a`. All four call sites pass `&drain`.

Accepts: as above.

Returns: unchanged.

Rejects: unchanged.

Effects: while the collector is unreachable, the batch is **held rather than discarded**, so the
queue accumulates and overflow drops at `Sink::push` where they are counted and visible — instead
of `Unsent::drop` (`:209-213`) destroying the batch after the `BACKOFF` table
(`[100ms, 500ms, 2s]`, `:30`) exhausts at roughly 7 seconds. This is what makes
`siem_queue_max_bytes` mean what C6 says it means.

Caller obligations — **three, and the first is why this subsection exists:**

1. **The hold must be cancellation-aware, and it holds *inside* `send`** (C46). `send` is awaited
   inside the arm *bodies* at `:68` and `:74`, outside the `select!`'s own polling, so an
   unbounded retry loop inside `send` never returns to that `select!` and the `drain.cancelled()`
   arm at `:76` is never polled. `Running::shutdown` cancels drain and then joins the sink tasks
   at `src/lib.rs:324` with no timeout of its own, so the graceful SIGTERM stop added in `734d22d`
   would never complete while the collector is down — precisely the incident during which an
   operator restarts the firewall. Today that path is bounded only because `BACKOFF.get(attempt)`
   exhausts.

   **The hold is implemented one way only: the backoff sleep at `:181` is `select!`ed against
   `drain.cancelled()` inside `send`, and `batch` is still drained as it is today.** The
   alternative of keeping the undelivered batch as task state and returning to the outer
   `select!` between attempts is **rejected on its own merits**: the `received = rx.recv()` arm
   at `:61-72` is unconditional — only the timer arm at `:73` carries `if !batch.is_empty()` — so
   a task that returns to the `select!` keeps draining its queue throughout the outage. The queue
   never accumulates, and that is the whole of C31.

   **The cancellation-aware sleep is also what stops two existing tests hanging the suite.** Of
   the four `send` call sites, `:84` and `:88` sit inside the drain arm's
   `timeout(DRAIN_DEADLINE, …)`, but `:68` (batch-full) and `:74` (batch-timer) are **outside any
   timeout**. A retry loop reached from either that does not observe cancellation never returns
   to the `select!`, so `tasks.join()` never returns — and `tp7` (`tests/decision_log_delivery.rs:693`)
   and `tp11a` (`:900`) have no test-level timeout, so they hang forever rather than failing
   (`evidence/gate3-analysis.md` §7).

   **On cancellation, `send` returns without a further attempt** (C68), leaving the undelivered
   batch to `Unsent::drop` at `:212`, which counts it. The branch has to be stated, because at
   the drain call sites `:84` and `:88` the token is *already* cancelled — they sit inside the
   `:80` `timeout(DRAIN_DEADLINE)` within the `drain.cancelled()` arm — so "skip the sleep and
   retry" would spin for the whole 5 s drain window, which is the G3-T5 hot-spin this same
   decision forbids. **The consequence is deliberate: during drain the `BACKOFF` ladder does not
   run, and each `send` call makes exactly one delivery attempt.** That is the right behaviour
   when flushing at shutdown, and it changes little in practice — today's ladder sums to ~2.6 s
   of sleeping inside a 5 s budget shared by every remaining batch.

   With the sleep selected against cancellation, the existing `timeout(DRAIN_DEADLINE)` at `:80`
   bounds shutdown exactly as it does today — `timeout` drops the inner future at an await point,
   so even an unbounded retry inside the drain block is cut at 5 s.

   **`Unsent` remains the mechanism that counts records held at cancellation, and it stays
   armed.** Because `batch` is drained before the first await, the drain tally at `:95`
   (`batch.len() + rx.len()`) is blind to the in-flight batch; only `Unsent`'s `Drop` at
   `:209-215` counts it. An implementation that instead stopped draining `batch` while leaving
   `Unsent` armed would **double-count every held record** — once by `Unsent::drop`, once at
   `:95` — which would pass `rl23` while breaking `rl17` and `rl18` with `dropped` too high.

   Retaining `Unsent` is also what keeps `tp15b_drain_cutoff_records_are_counted`
   (`tests/decision_log_delivery.rs:1033`) green. That test discriminates between the two
   possible hold designs: keeping `batch.drain(..)` and restoring the batch on the normal return
   path would lose the count entirely at an await-point cancellation, reproducing the slice-2
   blocker `docs/plans/decision-log-delivery/00-status.md` records as found and fixed. Records
   must stay reachable from `run`'s `batch`, or an equivalent RAII guard must be retained; this
   design retains the guard (`evidence/gate3-analysis.md` §7).
2. **The hold covers retryable failures only, and its retry interval is capped at the last
   `BACKOFF` entry, 2 s** (C46, C56). A non-retryable rejection — 302, 400, `401`/`403` (`:164`)
   — still discards and counts immediately, exactly as today, because holding for a collector
   that will never accept the batch buys no outage tolerance and would keep re-presenting a
   rejected credential (`:145-147`) for the life of the process. For the retryable case a bare
   `loop { send }` would hot-spin a tokio worker, so the interval settles at the last backoff
   entry; retrying forever at that interval adds no new constant.
3. **The held bytes are stated as a persistent addend, not a transient one.** During a hold the
   task holds **one serialized `body`** — not `batch`, which is empty because `send` drained it
   before its first await — resident for the whole outage and outside the per-sink queue budget.
   C29 named this addend when it was transient; C31 makes it last as long as the outage, and
   `docs/operations.md` must say so.

Uses: `SinkCounters::lose`, the existing `BACKOFF` table, the existing drain token.

Checks: `rl10`, `rl10b`, `rl11`, `rl23`, `rl23b`.

### `config` (`src/config.rs`) — existing, changed

Purpose: declares both budgets and owns every rejection rule for them, so that no bad value
reaches `mpsc::channel` — which panics on both a zero and an over-large buffer (C39), and a panic
is the one failure mode this module exists to avoid.

Provides: two validated budgets on `Config`.

Owns: the default value, the ceiling, the "must hold at least one record" rule, and the "refused
without its sink" rule.

Public types and values:

```rust
pub struct Config {
    // … existing fields unchanged …
    pub log_queue_max_bytes: NonZeroU64,   // near :51, beside log_file_max_bytes :52
    pub siem_queue_max_bytes: NonZeroU64,  // beside siem_auth_header :59
}
```

Both are `NonZeroU64` on `Config` and `Option<u64>` on `RawConfig` (near `:105`), the exact shape
of `log_file_max_bytes`. Both join `OPTIONAL_KEYS` (`:145-153`).

Callers and visibility: `pub`, as the rest of `Config`. Read only by `delivery::build`.

#### `RawConfig::validate` — existing, changed

Declaration: unchanged.

Accepts: unchanged.

Returns: unchanged — `Ok(Config { … })` at `:302-340`, now naming both new fields.

Rejects, four rules per key, all `ConfigError::Invalid` via the existing `invalid("<key>", …)`
helper (`:372`), in the arm shaped like `:239-250`:

| Condition | Message names |
|---|---|
| set while its sink is off (`log_queue_max_bytes` without `log_file_path`; `siem_queue_max_bytes` without `siem_url`) | the key and its sink key, matching `:239-244` |
| `0` | the key, matching every other `NonZeroU64` |
| `< BYTES_PER_RECORD` — integer division would yield capacity `0` and `mpsc::channel(0)` panics (C23, C39) | the key and `BYTES_PER_RECORD`, so the operator learns the real minimum |
| `> MAX_QUEUE_MAX_BYTES` (4 GiB) (C36, C39) | the key and the ceiling |

Effects: applies `DEFAULT_QUEUE_MAX_BYTES` **whenever the key is absent, regardless of whether
its sink is on**, inside `validate` — the `Option`-shaped mechanism `log_file_max_bytes` already
uses (`:245-250`). The two rules are independent: the default fills an absent key, and the
"refused without its sink" rule rejects a key that is *present* without its sink. Conditioning
the default on the sink would contradict `rl5`, which loads the shipped `config.sample.toml` —
where both sinks are commented out (`:44`, `:54`) — and expects both budgets to equal the default
(`gate-3-qa.md` G3QA-16).

Caller obligations: none beyond today's.

Uses: `delivery::BYTES_PER_RECORD` and `delivery::MAX_QUEUE_MAX_BYTES`, imported rather than
duplicated, so the bound and the division can never disagree (C23).

Checks: `rl2`, `rl3`, `rl4`, `rl5`.

### `http::health` (`src/http/health.rs`) — existing, changed

Purpose: serves the shedding signal.

Provides: `GET /health/delivery`.

Owns: nothing. It reads `delivery` state and the clock, and no serving decision consults it
(C8, T4).

Callers and visibility: `pub async fn`, registered by `http::router`.

#### `health::delivery` — proposed

Declaration: `pub async fn delivery(State(app): State<Arc<App>>) -> StatusCode`

Accepts: the `Arc<App>` state, exactly as `ready` does (`src/http/health.rs:30`).

Returns: `200` when records are not being shed, `503` when they are. Bare status code, no body —
the shape of both existing handlers, so the module still declares no response-body type.
`Cache-Control: no-store` comes from the existing layer (`src/http/mod.rs:94`).

Rejects: nothing.

Effects: updates the watch pair inside `is_shedding`. No serving decision changes.

Caller obligations: **this is an alerting signal, never a probe target** — `/health/ready` is the
probe, and it stays green while shedding (C8, C26). The obligation is documentary and its carrier
is `docs/operations.md`.

Uses: `Sinks::is_shedding` and `Clock::now_utc_micros`.

Caller example: the registration, one literal line after `src/http/mod.rs:42`, in the byte-exact
shape of the two above it:

```rust
        .route("/health/delivery", get(health::delivery))
```

Checks: `rl12`, `rl13`, `rl14`, `rl15`, `rl16`.

### `http::logging` (`src/http/logging.rs`) — existing, changed

Purpose: unchanged. One field gains the bound that makes `BYTES_PER_RECORD` a ceiling.

#### `decide` — existing, changed

Declaration: unchanged —
`pub async fn decide(State(app): State<Arc<App>>, request: Request, next: Next) -> Response`
(`:150`).

Effects: the fourteen-field `Decision` literal at `:207-222` is replaced by a call to
`build_decision` below, passing `method.as_str()`. **`decide` applies no bound itself** (C63):
the `loggable` call that closes the C22 gap lives inside `build_decision` and nowhere else.
`loggable` is `format!("{bounded:?}")` (`:322-326`) and is **not idempotent**, so applying it in
both places would emit every record's `method` as `"\"GET\""` — and nothing planned would catch
it, because `rl16b` and `rl22` call `build_decision` directly and see one application, while the
existing suite asserts only key presence (`DECISION_FIELDS`, `tests/decision_log_delivery.rs:36-48`)
and no test in the repository asserts the `method` **value**.

Caller obligations: unchanged. The `tracing::info!` at `:224` must keep running **before**
`offer` at `:243`; that ordering is what keeps stdout complete when the durable sinks are lossy,
and no change may reverse it.

Checks: `rl24`.

#### `build_decision` — proposed (C57)

Declaration:

```rust
fn build_decision(
    timestamp: String,
    request_id: String,
    method: &str,                  // NOT &Method — see below
    ecosystem: &'static str,       // the handler override, NOT target.ecosystem
    target: Target,                // supplies package and version only
    reason: String,                // NOT &'static str — ApiError::reason returns String
    // remaining parameters correspond one-to-one to the `Decision` fields at
    // src/delivery/mod.rs:55-72, with their declared types taken verbatim:
    // status, result, blocklist_revision, cache, duration_micros, bytes, consumer
) -> Decision
```

Accepts: exactly what the fourteen-field `Decision` literal at `:207-222` is built from today.
**Three parameters differ from the shape the literal might suggest, and each was a blocker when
it was got wrong** (`gate-3-qa.md` G3QA-10, G3QA-11):

- **`method: &str`, not `&Method`.** `decide` binds `request.method().clone()` at `:153`, but
  `http::Method` admits only RFC 7230 token bytes, so a property taking `&Method` cannot
  construct the empty, multi-byte or control-character inputs that are the falsifying half of
  `rl22`'s domain. `decide` passes `method.as_str()`; the seam takes the string.
- **`ecosystem` is an explicit parameter, not read off `target`.** `decide` computes it at
  `:197-201` from `context.ecosystem`, which **overrides** `target.ecosystem`. A seam deriving it
  from `target` would silently drop the handler override, and "behaviour is unchanged" would be
  false.
- **`reason: String`, not `&'static str`.** `ApiError::reason(&self) -> String`
  (`src/http/error.rs:136`) and the `None` arm at `logging.rs:195` is `"…".to_owned()`. C51's
  claim that every arm supplies a `&'static str` is true of the *values* (`error.rs:138-171` are
  all constants) but not of the type, which is what a signature must match.

Returns: the `Decision`. `method` is built as

```rust
        method: loggable(Some(method)).unwrap_or_default(),
```

which is the same shape `package` and `version` already use at `:212-213`
(`target.package.unwrap_or_default()`). The `unwrap_or_default()` is required and was missing:
`loggable` is `fn loggable(segment: Option<&str>) -> Option<String>` (`:322-326`) and filters an
empty segment to `None` at `:323`, while `Decision.method` is a `String`
(`src/delivery/mod.rs:57`). So an empty method maps to `String::new()` — unescaped, exactly as an
absent package already does — and `rl16b` asserts that, rather than asserting every generated
input comes back quoted (C69).

Rejects: nothing.

Effects: none — it is a pure constructor. It exists so that the record-building step has a seam,
which it does not have today: the literal is inline at `:207` and moves straight into
`offer(...)` at `:243`, so nothing can observe a constructed `Decision` (`gate-3-qa.md` G3QA-1).

Caller obligations: `decide` calls it in place of the inline literal and passes the same values;
behaviour is unchanged.

Uses: `loggable`.

**This is the observation point `rl22` needs.** `decide` itself cannot be the seam: it is axum
middleware taking `State`, `Request` and `Next`, `axum::middleware::Next` has no public
constructor, and `decide` never yields the `Decision` at all. An in-crate `#[cfg(test)]` property
generates arbitrary method and path strings, calls `Target::of` and then `build_decision`, and
measures the returned record. The measurement is **heap footprint**, not serialized size —
approved C29 states the two differ — computed as `size_of::<Decision>()` plus each `String`'s
capacity. Siting is confirmed reachable: an in-crate `#[cfg(test)]` module in `logging.rs` can
name the private `Target` and `loggable` and the `pub(crate) Decision`.

Caller obligations: `decide` is the only caller and applies no bound of its own (C63) —
`loggable` runs here, once.

Uses: `loggable`.

Checks: `rl22`, `rl16b`.

### `main` (`src/main.rs`) — existing, changed

Purpose: unchanged. The console subscriber stops letting `RUST_LOG` reach the audit target (C87, G3-T9).

Effects: the `EnvFilter` built at `:58-63` gains one appended directive. The operator's filter is
still parsed and still governs every other target; only the decision log's target is pinned:

```rust
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
                .add_directive("package_firewall::http::logging=info".parse().expect("static directive")),
        )
```

The target string is the module path `tracing` attaches to the `info!` at `src/http/logging.rs:223`,
which the shipped summary line already prints as `"target":"package_firewall::http::logging"` — so it
is read off observed output, not assumed. `add_directive` overrides whatever the operator set for
that one target and nothing else — **with the scope C90 fixes**: it wins against a level or
target directive naming the same target, but a span- or field-qualified directive on that target
sorts ahead of it and still wins. That residual is stated in G3-T9 and is the fourth exception in
the restated C26 statement.

Rejects: nothing. An unparseable `RUST_LOG` still falls back to `info` exactly as today.

Caller obligations: none. This is process setup, before any request is served.

Checks: `rl24b`.

### Load driver (`tests/common/mod.rs`) — proposed

Purpose: runs the measurement protocol once, so the bench and the floor test cannot drift (C42).

Provides: one function both targets call.

Owns: the measurement protocol.

Public types and values:

```rust
pub struct RatedLoadResult {
    pub offered: u64,     // requests issued
    pub delivered: u64,   // distinct request_id values observed at the destination
    pub dropped: u64,     // App's monotonic total, read after shutdown
    pub achieved: f64,    // offered / elapsed seconds
}

pub async fn drive_rated_load(
    config: Config,       // at least one sink configured
    target_rate: u32,     // records per second offered
    duration: Duration,
) -> RatedLoadResult;
```

Callers and visibility: `pub` within the test harness. Reached from the bench by
`#[path = "../tests/common/mod.rs"] mod common;`, as all three existing benches already do.

#### `drive_rated_load` — proposed

Accepts: a `Config` with **exactly one sink configured** (C48); a target rate; a duration. At
least one is required because an empty `Sinks` makes `offer` a no-op (`src/delivery/mod.rs:141`)
and every zero-drops assertion vacuous (C28). At most one is required because `lost_total()` sums
both sinks, so a record that both sinks drop counts twice and `offered − delivered == dropped`
fails on a healthy run.

Returns: `RatedLoadResult`, three independent measurements plus the achieved rate.

Rejects: panics if the file sink rotated — `Writer::roll_over` (`src/delivery/file.rs:205`)
renames to `<path>.1` and destroys the previous generation, so a rotated run is **void, not
under-counted** (C34). The harness sizes `log_file_max_bytes` for the whole run and asserts
`<path>.1` does not exist.

Effects: starts an `App`, **paces** the offer at `target_rate` — the loop is closed, so `offered`
is a count the driver issues and `achieved` reports what it managed to sustain (C65) — driving
HTTP `GET /health/live` for the duration —
the cheapest route in the service, touching no upstream, no store and no artifact, yet still
emitting exactly one decision record because `logging::decide` is the outermost layer
(`src/http/mod.rs:70-73`) and `Target::of` gives `/health/*` the ecosystem `"health"`
(`src/http/logging.rs:272-279`). So the achieved figure genuinely is requests per second (C2,
C32).

Caller obligations: **read the tally only after `Running::shutdown().await` returns.** Shutdown
cancels drain at `src/lib.rs:322` and joins the sink tasks at `:324`; the late loss sites
(`src/delivery/file.rs:75`, `src/delivery/siem.rs:97`, `:212`) fire during that drain, so a tally
read earlier reports zero for a run that lost its entire tail (C28).

Uses: `App::start`, `Running::shutdown`, and the one `test-support` accessor for the monotonic
total. Never `Sinks::drops()` (C33) — the App consumes that itself on every window close
(`src/http/logging.rs:421`) and at shutdown (`:400`).

`delivered` is counted at the destination, never derived from the firewall's own counters: the
SIEM collector receives batches of up to `BATCH_RECORDS = 256` and `send` re-posts `body.clone()`
on retry, so raw arrivals over-count. Distinct `request_id` values are counted among
`RequestDecided` records, and `RequestSummary` records are counted separately (C50).

**Both kinds must be counted, because `lost_total()` counts both** (C50). `Sinks::offer` carries
`Record::RequestDecided` and `Record::RequestSummary` through the same `Sink::push` and the same
counter, so a dropped summary raises `dropped` while raising neither `offered` (requests issued)
nor a `RequestDecided` tally. Since `rl17` deliberately runs a small queue — exactly the state in
which a summary is dropped — `offered − delivered == dropped` would be off by at least one
against a correct implementation. The driver therefore:

- sets a summary window longer than the run through the existing
  `http::logging::set_summary_window` seam (`src/http/logging.rs:461`), so no window closes
  mid-run and the only `RequestSummary` offered is the single one `Running::shutdown` emits via
  `flush_summary` (`src/lib.rs:321`). **That seam writes the process-global
  `static SUMMARY_MILLIS` (`:54`), which every test in the binary shares and `cargo test` runs in
  parallel threads — so no test in `tests/delivery_rated_load.rs` may set a short window** (C65);
- counts `delivered` as distinct decided `request_id`s **plus** summary records observed;
- reconciles `(offered + 1) − delivered == dropped`, the `+ 1` being that one shutdown summary;
- asserts the drain deadline was **not** hit, because `src/delivery/file.rs:60-61` documents the
  drain counter as deliberately imprecise — "the count may be one high and is never low" — so a
  run that hits the deadline cannot support an exact equality.

With `delivered` observed this way, the equality is a real assertion rather than an arithmetic
identity, and it is exact rather than approximate.

Checks: `rl17`, `rl18`, `rl19`, `rl20`.

#### `App::delivery_lost_total` — proposed, `#[cfg(feature = "test-support")]`

Declaration:

```rust
    #[cfg(feature = "test-support")]
    pub fn delivery_lost_total(&self) -> u64 {
        self.delivery.lost_total()
    }
```

Accepts: `&self`.

Returns: the monotonic non-resetting total across both sinks.

Rejects: nothing.

Effects: none.

Caller obligations: read after shutdown (above).

Uses: `Sinks::lost_total`.

This is the crate's **only** new gated item. It sits on `impl App` beside `delivery_is_empty`
(`src/lib.rs:114-116`), whose doc already states the rationale: `Sinks` is crate-internal
precisely so a consumer cannot reach the delivery path. It is an accessor returning a `u64`, not a
`Sinks` constructor and not `Record` construction, which is what removed the record-forgery
surface of threat T7 (C32).

Checks: `rl9`, `rl17`.

## Call stack

| Caller -> operation | Value/state passed | Why accepted | Result/failure handling |
|---|---|---|---|
| `main::serve` (`src/main.rs:123`) -> `Config::load` | the operator's TOML | — | `ConfigError::Invalid` names the offending key and the process refuses to start; no panic reaches `mpsc::channel` |
| `RawConfig::validate` -> the four rejection rules | `Option<u64>` per key | serde parsed it; `check_keys` (`:357`) already accepted the name | any rule failing returns `invalid("<key>", …)`; otherwise the default is applied and a `NonZeroU64` lands on `Config` |
| `App::start` (`src/lib.rs:161`) -> `delivery::build` | `&Config`, drain token | `Config` is validated, so both budgets are within `[BYTES_PER_RECORD, 4 GiB]` | capacity arithmetic cannot fail; `build` returns today's `Result` for today's reasons only |
| `delivery::build` -> `mpsc::channel` | `usize::try_from(budget / BYTES_PER_RECORD)` | C23 and C36 guarantee `1 <= capacity` and, on both targets, `capacity < Semaphore::MAX_PERMITS` (C39) | neither panic path is reachable |
| `http::logging::decide` (`:243`) -> `Sinks::offer` | one `Record` | unchanged; `offer` is non-`async`, lock-free, infallible | queue full -> `SinkCounters::lose(1)`; the request is never slowed or failed (C7) |
| each of the 8 loss sites -> `SinkCounters::lose(n)` | the true count lost | the site knows its own count | window and total both advance; the marker follows from the total |
| `http::logging::close_window` (`:465`) -> `Sinks::drops` | `&Sinks` | **one of two consumers** (the other is `flush_drop_tail`, `:444`, console-only), inside the `COUNTERS` mutex | `dropped_file` / `dropped_siem`; `window` resets, `total` does not, |
| `http::health::delivery` -> `Sinks::is_shedding` | `app.clock.now_utc_micros()` | the handler already reads the clock (`src/http/health.rs:31`) | `true` -> `503`, `false` -> `200`; `/health/ready` is unaffected |
| `drive_rated_load` -> `Running::shutdown` then `App::delivery_lost_total` | — | shutdown joined the sink tasks at `src/lib.rs:324`, so late losses are included | the three measurements reconcile, or the assertion fails |

## Test plan

| API promise | Caller and input/state | Expected observable result | Planned check and evidence kind |
|---|---|---|---|
| `build` sizes each queue from its budget | `Config` with `siem_queue_max_bytes` set small | the sink overflows at the capacity the budget implies, not at 4096 | `rl1`; execution |
| budget below one record is refused | `Config::from_toml_str` with `log_queue_max_bytes = 1` | `ConfigError::Invalid` naming the key; **no panic** | `rl2`; execution |
| budget above the ceiling is refused | `log_queue_max_bytes = 5 GiB` | `ConfigError::Invalid` naming the key and the ceiling | `rl3`; execution |
| **no `u64` budget can panic or yield a bad capacity** | **generated `u64` values across the whole range, `0` included**, passed to `delivery::capacity_for` (C61) in an **in-crate `#[cfg(test)]` module** — `mod delivery` is `pub(crate)` (`src/lib.rs:13`), so a `tests/`-resident property can name neither the constants nor the function | every value returns either `Err(TooSmall)` for a quotient of `0`, `Err(TooLarge)` above `MAX_SAFE_CAPACITY`, or an `Ok` capacity in `1..=MAX_SAFE_CAPACITY` — the property asserts **which** arm, so neither panicking input can reach `mpsc::channel` | `rl6`; **property (invariant), `proptest`**; execution |
| budget without its sink is refused | `siem_queue_max_bytes` set, `siem_url` absent | `ConfigError::Invalid`, same shape as `log_file_max_bytes` today | `rl4`; execution |
| unset budget takes the default | the shipped `config.sample.toml` | loads; both budgets equal `DEFAULT_QUEUE_MAX_BYTES` | `rl5`; execution |
| every drivable loss site increments the window counter | each of the **six drivable** sites in turn (C52): `mod.rs:115`, `file.rs:75`, `:142`, `:181`, `siem.rs:97`, `:212` | `dropped_file` / `dropped_siem` rise on the summary record | `rl7`; execution |
| `drops()` keeps read-and-reset semantics | two successive summary windows | the second window reports only its own losses | `rl8`; execution |
| the monotonic total is never reset | a run spanning several summary windows | `delivery_lost_total()` is non-decreasing and exceeds any single window | `rl9`; execution |
| the SIEM sink holds its queue while the collector is unreachable (C31) | wedged collector, sustained offer | records accumulate in the queue and are delivered on recovery; loss begins at the queue, not after ~7 s | `rl10`; execution |
| a non-retryable rejection still discards and counts immediately (C56) | a collector answering `302`, then `401` | the batch is counted at `Unsent::drop` before shutdown and appears on the summary record, not only on the console drain tail — the hold does not engage | `rl10b`; execution |
| the SIEM serialize-failure branch is counted (C27) | **not drivable** — `Decision` is all `String` / `&'static str` / integer / `Option<IpAddr>`, so `serde_json::to_string` cannot fail on it; the `decision-log-delivery` plan already recorded this as "impossible for the current all-String/u64/&static str record types" | the branch calls `lose(1)` and is unreachable, exactly as `src/delivery/file.rs:105` already is | `rl11`; **structural, not execution** (C52) — read at the seam, the correctness-of-invariant fix C27 describes, not a live defect |
| `/health/delivery` is `200` when nothing is shed | fresh `App`, some traffic, no loss; and an `App` with no sink at all (C43) | `200` in both | `rl12`; execution |
| `/health/delivery` is `503` within the quiet period | force a loss, probe immediately | `503` | `rl13`; execution |
| `/health/delivery` clears after the quiet period | force a loss, advance `TestClock` past 60 s, probe | `200` | `rl14`; execution |
| `/health/ready` stays green while shedding | force sustained loss, probe both routes | `/health/ready` `200`, `/health/delivery` `503` | `rl15`; execution |
| the signal never reads `200` during active loss | the ordering contract of C47, read at the seam | `last_change_micros` is stored before `last_total`, `last_total` is stored `Release` and loaded `Acquire` | `rl16`; **structural, not execution** (C52) — a racing integration test cannot discriminate here, because x86-64 does not reorder the relaxed stores the contract exists to forbid, so such a test stays green against the implementation it exists to reject |
| a backwards clock step does not latch the signal | force a loss, **probe once** so the watch pair is stamped, then step `TestClock` backwards past that timestamp and probe again | the second probe returns `200`, not a `503` latched for the size of the step | `rl16c`; execution — the interleaved first probe is required, or the second probe is itself the first since the loss and correctly stamps `now` (C52) |
| `Decision.method` is bounded | **generated** method **strings** — long, multi-byte, control-character-bearing, empty — passed to `build_decision`'s `method: &str` (C57); `&Method` could not express this domain | a non-empty method comes back quoted and escaped exactly as `package` does; an **empty** one comes back as `String::new()`, since `loggable` filters it to `None` and `unwrap_or_default()` applies (C69); and in every case the field's heap size is `<= FIELD_CEILING_BYTES` | `rl16b`; **property (invariant), `proptest`**; execution |
| the three measurements reconcile | a driver run with a deliberately small queue and **exactly one sink** configured (C48), summary window pinned past the run | **`(offered + 1) − delivered == dropped`** (C50) — `delivered` counted at the destination over both record kinds, the `+ 1` being the single shutdown `flush_summary` record — **and** the drain deadline asserted not hit, since `src/delivery/file.rs:60-61` documents that counter as "may be one high and is never low" | `rl17`; execution |
| the floor holds on every `cargo test` | `tests/delivery_rated_load.rs` **paced at `F`** for **`D` = 5 s**, exactly one sink configured, queue budget pinned at **`B = F × (D/2) × BYTES_PER_RECORD`** — 2.5 s of offer (C67) | **all three approved limbs** (C53), read after shutdown, the whole run completing within `D + 30 s`. Each limb detects a different thing (C67): **limb 1, zero drops**, fails when the *delivery pipeline* sustains less than `F/2`, because the queue grows at `F − P` and `B` holds `F × D/2`; **limb 2, `delivered >= F × D`**, fails when the *request path* cannot sustain `F` at all, since the closed loop then leaves `offered < F × D`; **limb 3, `(offered + 1) − delivered == dropped`**, fails when the counters disagree with the destination. `F` is one quarter of the debug rate the measuring slice observes (C60) | `rl18`; execution |
| a rotated file-sink run is void | driver run with `log_file_max_bytes` too small | the run panics naming rotation, rather than reporting a low `delivered` | `rl19`; execution |
| the bench produces the published numbers | `cargo bench --bench delivery_rated_load` | ten minutes sustained; prints the rated figure, the tolerance, and the `BYTES_PER_RECORD` derivation; fails nothing | `rl20`; execution |
| existing delivery behaviour is unchanged | the whole existing suite | `cargo test` passes with TP-7 amended per C41 and `tp19` retyped per C64, and nothing else changed | `rl21`; execution |
| **`BYTES_PER_RECORD` is a ceiling, not a mean** | **generated method and path strings** — multi-byte and escape-expanding — passed through `Target::of` into `build_decision` (C57), in an in-crate `#[cfg(test)]` module | every returned `Decision`'s **heap footprint** — `size_of::<Decision>()` plus each `String`'s capacity, not its serialized size (C29) — is `<= BYTES_PER_RECORD`, and the bench's printed derivation states the same figure | `rl22`; **property (invariant)** — red evidence is the seed and shrunk counterexample; execution |
| shutdown completes while the collector is unreachable | wedged collector, records held per C31, then `Running::shutdown()` wrapped in `tokio::time::timeout(Duration::from_secs(20), …).expect("HANG: shutdown did not return")` — the exact guard `tp15` uses at `tests/decision_log_delivery.rs:1003-1026` (C59) | returns within `DRAIN_DEADLINE`; records still held are counted through `lose`. **Without its own timeout this row hangs instead of failing** against the non-cancellation-aware implementation it exists to reject, leaving High-severity G3-T4 with no witness that can fail | `rl23`; execution |
| the hold does not hot-spin | wedged collector, hold engaged, POSTs observed at the collector over a window | the interval between attempts is `>= 2 s`, the last `BACKOFF` entry — carrying G3-T5's cadence property, which `rl23` does not observe (C59) | `rl23b`; execution |
| a dropped record is still on stdout | force a sink loss, capture stdout | the record appears on stdout although the sink lost it — `tracing::info!` (`src/http/logging.rs:223`) still runs before `offer` (`:242`) | `rl24`; execution |
| **no level or target `RUST_LOG` directive an operator sets can silence the decision log** — the scope C90 fixes; `rl24b` does not claim the stronger property | **the built binary, run as a subprocess** with a foreign `RUST_LOG` set, plus one decided request and a configured file sink. It must be the binary and not an in-process subscriber: `Cargo.toml` declares `[lib] path = src/lib.rs` and a separate `[[bin]] path = src/main.rs`, so a `tests/`-resident test links the library and can never fail against the pin in `main.rs` (`sf-red-team` B2). This is the shape the main agent already reproduced by hand against `target/debug/package-firewall serve` | the record is on the console **and** in the sink; today the console is empty and the sink has it, so the row is red against the tree as it stands | `rl24b`; execution |
| the shedding signal discloses nothing | probe `/health/delivery` in both states | the response body is empty for `200` and for `503`, and carries `Cache-Control: no-store` | `rl25`; execution |

`sf-tdd` implements these rows one at a time at the named seam.

**Three rows are properties, not examples** (C49). `sf-tdd` requires a property test when the
promise is a roundtrip, invariant, metamorphic or oracle and the language is in its table; Rust is,
with `proptest` as the default library and the `proptest-regressions/` file as the replay
evidence. `rl22`, `rl16b` and `rl6` each state an invariant over a whole domain — every
constructible `Decision`, every method string, every `u64` budget — so each is written with
generated input, and its red evidence is the seed and the shrunk counterexample rather than a
literal failure line. The remaining rows are example or integration tests with literal expected
values, which is what `sf-tdd` prescribes for them.

Gate 4 carries `proptest` in the `Test prerequisites` cell of every slice whose witness runs one
of those three rows. `rl22` and `rl16b` are sited in in-crate `#[cfg(test)]` modules (C51),
because `delivery::Decision` is `pub(crate)` and a `tests/`-resident property cannot name it.

**Two rows are structural rather than execution** and say so in their own cells: `rl11`, whose
input cannot exist, and `rl16`, which cannot discriminate on this platform (C52). Separately, two
invariants are enforced at compile time rather than by any row — the loss-site routing (C45) and
the `usize::try_from` conversion. Structural evidence is named as such so Gate 4 does not promise
a runtime witness that cannot exist; the cost is stated plainly in `## Threat model`, where
G3-T1 is recorded as having **no executable witness**.

## Invariants & spec dispositions

- **Every site that loses a record routes through `SinkCounters::lose`** (load-bearing, repeated
  across 8 sites in 3 files) — **no spec: not expressible**, and covered at compile time instead.
  `sf-spec-authoring` returned REJECT after establishing by experiment that the three exclusion
  levers the analyzer schema advertises are all inert for this rule: `scope.files` is silently
  ignored (an unsafe control scoped to a non-existent path still returned all 4 findings, with no
  scope-filter step in the trace), `where` does not bind identifiers (`in_method == "lose"`
  behaves exactly like `false`, and an unknown identifier exactly like `true`), and `in_method`
  has no negation. The only formulation that decides is an allowlist of loss-site method names,
  whose failure mode is a silent false negative on any new or renamed site — a spec that reports
  clean while the invariant is broken. **Instead `SinkCounters` is defined in its own module,
  `src/delivery/counters.rs` (C45), which puts `window` and `total` out of reach of every other
  module — `file` and `siem` as siblings, and `mod.rs` as parent alike — so no raw `fetch_add`
  compiles anywhere outside `counters`.** The enforced invariant is precisely "a loss cannot be
  recorded except through `lose`"; `take_window` is `pub(super)` and therefore also callable from
  the sink modules, but it resets a counter and cannot record a loss, so it is not a bypass.
  Decision tier for that invariant, and it covers the eighth site and every future site with no
  maintenance.
- **`Sinks::drops()` has exactly two consumers, and only one of them reaches a sink**
  (load-bearing) — no spec: an existing check owns the risk. **Corrected at the slice-2 reopen:**
  this invariant previously read "exactly one consumer, the App's own summary path" and cited
  `src/http/logging.rs:400` and `:421`. **The line numbers were right; the characterisation was
  wrong.** An earlier draft of this reopen called them stale, which silently contradicted approved
  Gate 4 **C78**; that claim is withdrawn. The call sites are `close_window` (`:421` at HEAD, `:465`
  in the working tree), whose `Summary` goes to the sinks and to the console, and `flush_drop_tail`
  (`:400` / `:444`), whose `tracing::warn!` reaches **the console only** — as
  that function's own doc comment says: "this last line reaches the console only — stated rather
  than hidden".

  **Baseline note.** Anchors in this document are against HEAD `734d22d`, as approved C78 fixes them.
  Slices 1 and 2 are uncommitted and shift **two** files: `src/http/logging.rs` by roughly 44 lines and `src/delivery/mod.rs` by roughly 102 lines (`fn drops` `:150` HEAD / `:252` tree; `Decision` `:54` / `:156`). Every other `delivery/mod.rs` citation in this document is HEAD and lands, so the reopen's
  own rows (C87, G3-T9 to G3-T15, `rl24`, `rl24b`, `### main`, and `## Call stack` row 7) cite the working tree they were read from —
  the tree slice 2 ships. Equivalences: `info!` `:224` HEAD / `:223` tree; `offer` `:243` / `:242`;
  `loggable` `:322` / `:366`; `drops()` `:400`, `:421` / `:444`, `:465`.

  The second consumer is therefore the sole carrier of drain-window losses, which is
  what makes it a casualty of G3-T10 and part of G3-T12. The method is `pub(crate)`, so `tests/`
  cannot reach it at all, and the two in-crate readers the design adds (`lost_total`, `is_shedding`)
  do not call it. `rl8` and `rl9` witness
  the semantics directly.
- **No lock, allocation, syscall or clock read in `Sink::push`** (load-bearing, C24) — no spec:
  the same module move covers the mechanism. `lose` is two relaxed atomic adds and the clock read
  lives with the health handler by construction, since `is_shedding` takes `now_utc_micros` as a
  parameter rather than reading a clock it does not hold.
- **The capacity conversion uses `usize::try_from`, never `as usize`** (one-off, C23) — no spec:
  it is a single expression at a single site, and `rl6` witnesses the rejection it protects.

Limitation worth carrying beyond this plan: `scope.files` being silently ignored means **any**
analyzer spec written around file scoping enforces nothing while appearing correct. Established
on `structural_pattern` only; `taint_query` was not checked.

## Threat model

`sf-threat-model`. **Two runs, two artifacts.** Pre-reopen: 2026-09-24, verdict **MODELED**, 8 threats — [evidence/threat-model-gate3.md](evidence/threat-model-gate3.md). Slice-2 reopen: 2026-09-25, verdict **UNKNOWN** (B1-B5), which proposed G3-T13 to G3-T15 and rejected the first G3-T12 mitigation — [evidence/threat-model-gate3-reopen.md](evidence/threat-model-gate3-reopen.md). The reopen's other dispatches are [evidence/security-review-slice-2.md](evidence/security-review-slice-2.md) (the review that reopened this gate), [evidence/red-team-gate3-reopen.md](evidence/red-team-gate3-reopen.md) (rounds 1 and 2, distinct from the pre-reopen rounds) and [evidence/reproduction-2026-09-25.md](evidence/reproduction-2026-09-25.md) (the executed runs behind C87 and G3-T12). It was required because
`evidence/threat-model.md` recorded `TRIGGER-CHECK: Yes` for two controls this design names — the
shedding signal as an audit-trail-loss detection control, and `BYTES_PER_RECORD` as a
memory-bound control.

**Scope:** the ten surfaces this design introduces. **Entry points:** `GET /health/delivery`,
unauthenticated and now a *writer* of process state; every other route through `Sinks::offer`
into a queue that is now operator-sized; the two budget keys; **the SIEM collector's HTTP
response**, which Gate 2 did not list and which post-C31 influences queue occupancy and sink-task
lifetime; and the `test-support` accessor. **Trust boundaries:** unauthenticated peer ⇄ process
state; operator config → host memory; **external collector → sink-task control flow and process
shutdown** (new); hot path → observer tasks across relaxed atomics; `pub(crate) delivery` → test
binaries. **Assets:** the audit trail's completeness; the truthfulness of the alarm over it;
package-serving availability (C7, C8 rank it first); host memory and the honesty of the published
budget; orderly shutdown during an incident; the SIEM credential, which nothing here moves.

| ID | Property | Mechanism | Asset | Location | Sev | Mitigation | Verification | Tier | Carrier |
|---|---|---|---|---|---|---|---|---|---|
| G3-T1 | TOCTOU on a detection control | two relaxed stores in the watch pair let one prober read `200` with a stale timestamp while records are destroyed | the alarm's truthfulness | `Sinks::is_shedding` | Medium | **C47** — ordered stores, `Release`/`Acquire`, pair owned by `Sinks` | `last_change_micros` is stored before `last_total`; `last_total` is `Release`/`Acquire` | **structural** — and this threat has **no executable witness**, stated plainly (C52, `gate-3-qa.md` G3QA-6): x86-64's TSO model does not exhibit the reordering, so no racing test on this platform can discriminate | `rl16`, structural |
| G3-T2 | noninterference between loss and alarm | every other module could write `SinkCounters`' atomics directly and bypass `lose` | the trail and its alarm | the eight loss sites | Medium (High over time) | **C45** — `SinkCounters` in its own module; no other module, parent or sibling, can name the fields | **no raw `fetch_add` on a sink counter compiles outside `counters`**, so a loss cannot be recorded except through `lose` (`take_window` is `pub(super)` but cannot record a loss) | **decision** (compile error) | compile-time + `rl7` |
| G3-T3 | memory-bound control | the constant is deferred to a report-only bench; C44 makes the honest per-field ceiling larger than C29 assumed, so the published budget can hold several times more bytes than promised — and the queue is fillable by an unauthenticated flood | host memory; the honesty of the published tolerance | `BYTES_PER_RECORD` | **High** | a property test that generates records and falsifies the ceiling | no constructible `Decision` exceeds `BYTES_PER_RECORD` | decision | **`rl22`** |
| G3-T4 | external dependency isolated from process lifecycle | C31's hold is awaited inside `select!`; an unbounded retry never polls `drain.cancelled()`, so `Running::shutdown` blocks forever at `src/lib.rs:324` while the collector is down | availability; the ability to restart during an incident | `src/delivery/siem.rs` | **High** | **C46** — cancellation-aware hold; `timeout(DRAIN_DEADLINE)` bounds shutdown as today | `shutdown()` returns within `DRAIN_DEADLINE` with the collector unreachable, **asserted under its own 20 s test timeout** so the rejected implementation fails rather than hangs (C59) | structural | **`rl23`** |
| G3-T5 | resource and ambient authority at an external boundary | unspecified hold cadence hot-spins a worker and re-presents the credential indefinitely; **one serialized `body`** sits outside the published budget for the whole outage (not the batch, which `send` drains before its first await — C46) | host memory; the credential's standing | `src/delivery/siem.rs` | Medium | **C46** — hold covers retryable failures only (C56), cadence capped at the last `BACKOFF` entry; held body published as a persistent addend | POST interval ≥ 2 s during a hold; resident bytes never exceed `siem_queue_max_bytes` + one serialized body | decision | **`rl23b`** for cadence (C59) + docs row for the memory statement |
| G3-T6 | disclosure enabling repudiation | flood the cheapest route, poll until `503`, then issue the fetch you want absent — sharper post-C31 | the trail's answer to "who took this package" | the new handler | Medium | **accepted** — bodyless response, `no_store`, and the C26 statement that stdout carries every decided request. **Re-examined after slice 2 (C87, C88):** this acceptance rested on a premise that was false — see G3-T9, now closed in code — and its named exceptions are now four: G3-T10, G3-T11, G3-T13 and C90's span- or field-qualified directive (C88) | a dropped record is still on stdout; the body is empty in both states | manual | **`rl24`, `rl25`** |
| G3-T7 | privilege crossing by misconfiguration | an operator wires a `/health/` route into an LB and hands any client that can drive drops a lever to drain the pool | fleet serving availability | registration; docs | Medium | structural half satisfied (no serving decision reads the state); documentary half is the C26 deliverable | `/health/ready` stays `200` throughout a shedding event | structural | `rl15` + docs row |
| G3-T8 | resource exhaustion via operator input | ceiling is per sink so two sinks accept 8 GiB, with no host-memory cross-check; and a flood can now pin the whole budget rather than 2 × 4096 records | host memory, transitively serving | `RawConfig::validate` | Medium (**up** from Low) | **accepted** — keep the ceiling, restated in records now the constant is measured: 131,072 per sink. Severity stays Medium: the default a flood can pin rises from 64 MiB to 1,875 MiB per sink (3,750 MiB with both sinks, additive to `memory_cache_max_bytes`), bounded by the ceiling and accepted knowingly at Gate 2 (C39) | no accepted config yields a budget above the ceiling or below one record | decision | `rl2`, `rl3`, `rl6` |
| G3-T9 | detection control disabled by ordinary configuration | `main.rs:58-63` builds the subscriber from `EnvFilter::try_from_default_env()`, whose default INFO directive is discarded the moment `RUST_LOG` holds any valid directive — so `RUST_LOG=warn`, `RUST_LOG=hyper=debug` or a set-but-empty `RUST_LOG` silences every decision line while `offer` (`logging.rs:242`) keeps delivering unfiltered. `docs/operations.md:427` tells operators to set that variable | the audit trail's completeness — and the premise G3-T6 was **accepted** under | `src/main.rs` | **High** | **C87** — `add_directive("package_firewall::http::logging=info")` appended after the operator's filter, so `RUST_LOG` governs every other target and never the audit target | a foreign `RUST_LOG` is set and the decision line still reaches stdout. **Scoped by C90:** the property is “no level or target directive silences the audit target” — `rl24b` covers the bare-level, foreign-target and same-target level forms. A **span- or field-qualified** directive on the same target still out-specifies the pin and is a stated residual, not a covered case | decision | **`rl24b`** |
| G3-T10 | detection control fails silently | `tracing_subscriber::fmt` discards writer I/O errors and Rust sets `SIGPIPE` to `SIG_IGN`, so a console pipe whose reader died — a restarted log shipper — discards every decision line with no counter and no alarm, while the sinks deliver normally | the audit trail's completeness | `src/main.rs`, the console writer | **High** (**up** from Medium) | **accepted** (**C88**) — named as an exception in the C26 statement rather than mitigated; unlike the sink path there is no `drops` equivalent for stdout, and stdout truncation is the residual: C87 rejected making the file sink the trail by default precisely because it is optional configuration, so nothing here promises a durable trail the operator has not configured | none — accepted without a witness. **Reachability corrected:** the first draft said this needs “a crashed reader on the console pipe”. That is wrong — ENOSPC on a redirected stdout discards identically, needs no attacker, and is amplified by the decision lines themselves | manual | docs row (C26) |
| G3-T11 | control never runs | no panic-catching layer exists in `src/http/`, so a handler panic unwinds through `next.run(request)` (`logging.rs:177`) and skips `tracing::info!`, `offer` and `summarise` alike — no stdout line, no sink record, no counter, and symmetric so it does not even show as a drop. **Corrected:** the crate sets no `panic = "abort"` profile, so the default hook does print a trace to **stderr** — it is not wholly silent, but stderr is not the trail | the audit trail's completeness | `decide` | Medium | **accepted** (**C88**) — named as an exception in the C26 statement; `tower_http::catch_panic::CatchPanicLayer` rejected — but on **absence of a witness, not on cost**: `tower-http` is already a dependency and the layer is a feature flag plus one `.layer()` line below `decide`. The cost argument is withdrawn | none — **no reachable panic witness exists in the repository**, stated plainly | manual | docs row (C26) |
| G3-T12 | loss evidence destroyed by its own reader | `Sinks::drops()` is a destructive `swap(0, Relaxed)` (`delivery/mod.rs:150` at HEAD, `:252` in the working tree); its counts go into a `Summary` offered to the same queues, where `Sink::push` discards on a full queue — **self-amplifying**, because the condition that produces the loss is the condition that discards the record carrying its count. It has **two** consumers, not one: `close_window` (`src/http/logging.rs:465`) and `flush_drop_tail` (`:444`), and the second publishes drain-window losses to the console **only** (`tracing::warn!`, no sink), so G3-T10 destroys that copy too | the truthfulness of the alarm over the trail | `Sinks::drops`, `Summary`, `flush_drop_tail` | Medium | **closed by C87, at no additional cost.** `emit` (`src/http/logging.rs:484-496`) writes the window's `dropped_file` / `dropped_siem` to the console with `tracing::info!` **before** `sinks.offer(Record::RequestSummary(..))` — the same ordering C78 pins for the decision line. A full queue discarding the `Summary` therefore cannot destroy its counts: the console already carries them. The genuine hole was never the destructive `swap(0)`; it was `RUST_LOG` silencing the console, which is G3-T9, and C87's pin closes both. `flush_drop_tail`'s `tracing::warn!` (`:446`; `:444` is its `drops()` call) is on the same target and the pin is `=info`, so it is covered too. **Two earlier drafts of this row were wrong**: the first claimed a monotonic `SinkCounters.total` mitigated it (that field does not exist in `src/`); the second added `lost_total` to `Summary` as C91, which `sf-red-team` B5 correctly showed only moves the loss one record later. Both withdrawn — no field, no counter, no new work | the summary line carrying a non-zero `dropped_file` reaches the console in a run whose queue overflowed. **Witnessed 2026-09-25** against `target/debug/package-firewall serve` with `log_queue_max_bytes = 32768` (one record) and 400 concurrent requests: the sink took 178 decision records, the stdout summary line reported `dropped_file: 222`, and 178 + 222 = 400 — the loss count reached the console while the queue was overflowing | **manual** — the run witnesses `emit`'s ordering, not C87's pin, because it predates it; the tier is manual, not decision | — no test-plan row asserts a summary line with a non-zero `dropped_file`; the closure rests on the ordering plus the reproduction above |
| G3-T13 | attacker-set volume against a control the operator can no longer throttle | the decision line is one per request and the host log transport applies its own limits. **Observed 2026-09-25:** the audit trail shares stdout with operational diagnostics — a run writes the decision line, the summary, `listening`, `shutting down` and two blocklist `ERROR`s all to stdout, with **stderr empty (0 bytes)** — so the trail competes with diagnostics for whatever limit the host applies. Splitting the streams would weaken this threat and costs a layer split in `main.rs`; **not taken** (YAGNI, user instruction 2026-09-25), recorded so the option is not lost (journald `RateLimitBurst`, kubelet rotation); after C87 the operator's only remaining volume levers are redirecting stdout, which destroys the trail wholesale, or restarting — while an unauthenticated peer sets the rate | the audit trail's completeness | `src/main.rs` subscriber ⇔ host transport; `docs/operations.md` §8 | **High** | **accepted** — stdout truncation is the residual and nothing here promises a durable trail the operator has not configured — C87 rejected making the file sink the trail by default, precisely because it is optional configuration; `docs/operations.md` names the host transport as an exception to the C26 statement. No host-side configuration requirement is published (YAGNI): this repository cannot know an operator's collector limits | the published rated figure and the host collector's documented acceptance rate are stated together, so an operator can see whether their transport can carry the load | manual (docs) | docs row (C26) |
| G3-T14 | availability lost to a detection control in the request path | `fmt`'s default writer is `io::stdout()`, so a slow or blocked console consumer blocks `tracing::info!` (`src/http/logging.rs:223`) **inside** `decide`, before `offer` — and C87 removed the `RUST_LOG=warn` lever that previously let an operator drop the write | package-serving availability, which C7/C8 rank **first** | `src/main.rs` + `src/http/logging.rs:223` | Medium (High where stdout is a pipe to a sidecar) | **accepted** (C93) — pre-existing shipped behaviour, never modelled before this reopen. C87 narrows the escape from it by removing the `RUST_LOG=warn` lever; an operator whose console consumer is slow can redirect stdout to a file. **Two earlier drafts were wrong here:** the first accepted it as “fail-closed, the posture the rest of this plan takes”, which is backwards; the second mitigated it with `tracing_appender::non_blocking` (C92), which costs a runtime dependency and reopens G3-T12. Both withdrawn | none — accepted without a witness, stated plainly | manual | — |
| G3-T15 | an untrusted reader starts the detection control's own quiet window | `SHED_QUIET` runs from the **first probe after the loss**, not from the loss, because the reader holds the timestamp (C24, C35). `/health/delivery` is unauthenticated, so a peer that causes loss and immediately probes starts the 60 s window itself, and an operator polling at exactly 60 s can land on the `delta == SHED_QUIET` boundary and read `200` | the alarm's truthfulness | `Sinks::is_shedding`, `src/http/health.rs` | Low-Medium | **documentary, carried by slice 7** — `docs/operations.md` states that a `/health/delivery` probe interval must be strictly shorter than `SHED_QUIET`; it is item (iv) of that slice's restated security sentences. **Text defect recorded, not corrected here:** C35 reads “`503` while a record was lost within the last 60 s”, which is not what the design implements — it is 60 s from the first probe that observed the loss. C35 is an approved Gate 2 row; slice 5 owns `is_shedding` and its wording, and corrects both there | force a loss, probe as the attacker, advance the `TestClock` to the documented interval, probe as the operator, expect `503` | structural | slice 7 (the documented interval), with slice 5's `rl16c` covering the clock step; no test-plan row is added here |

**Omitted: 5.** (Counted before the slice-2 reopen; G3-T9 to G3-T15 were added after, and G3-T12 is one of the surfaces this count had not named.) Two are resolved here — a backwards clock step latching `503` (**C47**, witnessed
by `rl16c`) and `lost_total()` double-counting a record both sinks drop (**C48**). One is
accepted: a partially-accepted, re-posted SIEM batch can be counted both delivered and lost,
because `Unsent` counts whole batches by existing design — which is why `rl17` reconciles against
a small queue rather than a wedged collector. The other two are Low or cost-only.

**Gate 2 T1–T8 dispositions:** T5, T6 and T7 are **closed**; T1 and T4 are **mitigated**; T2 is
mitigated in mechanism but was open in value until `rl22`; T3 stays **open and accepted**; T8 is
mitigated with its residual carried at raised severity as G3-T8.

**Accepted risks and their owners.** The 4 GiB ceiling with no host-memory cross-check is owned by
**the user**, accepted at Gate 3 grilling Q2. The unauthenticated confirmation oracle is owned by
**the user**, accepted at Gate 2 grilling Q4. The double-counted partially-accepted batch is
carried here for visibility at this gate. The indefinite SIEM hold was **not** accepted: the Gate 2
Q8 answer covered only *where* records are lost, not shutdown cancellation or retry cadence, so
G3-T4 and G3-T5 are fixed by C46 rather than accepted.

**Added at the slice-2 reopen.** **Four** further risks are accepted, all owned by **the user**: G3-T10 and G3-T11 at Gate 3 grilling **Q6** (C88), G3-T13 at Q6 as well once C89 was withdrawn, and G3-T14 at **Q10** (C93). G3-T12 is not among them — it is closed by C87:
- **G3-T10**, console writes discarded unobserved, and **G3-T13**, the host log transport truncating stdout — both accepted and named in the C26 statement. No new counter, warning or host-side requirement is added for either (YAGNI): an operator who needs a durable trail already has `log_file_path`, which this plan did not invent and does not change.
- **G3-T11**, a handler panic leaving no decision record — accepted as **cheap but unwitnessed**, not as expensive or unreachable. `tower-http` is already a dependency and `catch_panic` is a feature flag plus one `.layer()` line, so the cost argument is withdrawn; what stands is that no reachable panic witness exists in first-party code, while attacker-controlled strings do reach three third-party parsers. Revisit if any panic is ever observed in `decide`.
- **G3-T14**, a slow console consumer blocking the request path — accepted (C93). Pre-existing and outside Gate 1 C7, which governs the delivery queue rather than the console write. No new dependency is taken for it.

## Least confident decisions

1. **`BYTES_PER_RECORD` as a single constant.** C15 chose one conservative high number over
   byte-accounting the queue. C44 now shows the per-field ceiling is larger and more awkward than
   C29 assumed — chars, then escape expansion, then heap capacity — so a genuinely conservative
   constant may be several KiB, which makes the C13 default budget large. `rl22` makes the
   constant falsifiable rather than asserted, which is the important half; what remains uncertain
   is whether the honest number is one an operator will accept. If it is absurd, the alternative
   is to publish the budget against a *typical* record and say plainly it is not a hard memory
   bound — which C22 explicitly rejected. Most likely of all these to need revisiting once the
   bench measures real records.
2. **Deriving the shed marker from the monotonic total rather than storing a flag.** It removes a
   write from the loss path and makes the state reader-owned as C24 demands, but it means the
   signal's truthfulness depends entirely on every loss site calling `lose`. C45 closes the way
   that dependency could be broken — a sibling module cannot touch the fields — so what remains is
   the weaker risk that a future loss site increments nothing at all, which no mechanism here
   catches.
3. **Amending `tp7` (C41), and the five tests around it.** `tp7` is an existing, passing, shipped
   test whose premise this feature removes; pinning its own budget is the minimal repair, but it
   is still a change to a test that guards real behaviour. The wider worry is that the first
   draft claimed `tp7` was the *only* affected test and was wrong by five — the impact analysis
   found `tp9`, `tp11a`, `tp15` and `tp15b` all on this path, two of which could have hung the
   suite. C46 and C56 keep all five green without edits, but that is a prediction from reading
   bytes, not an executed run. The tracer slice should run `cargo test --test decision_log_delivery`
   early and treat any of the five going red as a design question, not a test to adjust.
4. **`/health/delivery` covering both sinks with one status.** An operator whose file sink is
   healthy and whose SIEM collector is wedged sees the same `503` as one losing everything. C9
   rejected a per-sink JSON body because the summary record already publishes `dropped_file` /
   `dropped_siem`. If operators find the single bit too coarse in practice, the fix is two routes,
   not a body.
5. **The 4 GiB ceiling (C36).** Chosen as obviously-too-large rather than measured. If
   `BYTES_PER_RECORD` lands high, 4 GiB buys fewer records than the "hours of outage" the row
   claimed. It did: 131,072 records, about 655 s at 200 rps and about 2 s at N, restated in C36. G3-T8 also raises the
   residual severity from Low to Medium on a point worth stating plainly: after this feature an
   unauthenticated flood can pin the operator's whole budget, where today it pins at most
   2 × 4096 records.
6. **Adding `proptest` (C49).** `sf-tdd` makes it mandatory for the three invariant rows, and the
   dependency earns its place on `rl22` alone. But it is the third `[dev-dependency]` in a
   repository that carries two and deliberately dropped criterion, so it is a genuine reversal of
   that discipline — justified here because criterion was dropped for being unable to express its
   targets, while `proptest` expresses these exactly.
7. **The C31 hold, now that C46 has had to bound it.** The hold was accepted at Gate 2 as a
   question of *where* records are lost. Implementing it turns out to touch task cancellation,
   shutdown, retry cadence and credential presentation — four things that acceptance did not
   consider. It is still the right call, but it is the largest behavioural change in the feature
   and it lives in the file with the least prior test coverage.

## Repository evidence

- [evidence/gate3-analysis.md](evidence/gate3-analysis.md) — seven read-only dispatches,
  2026-09-24: `sf-repo-view` on `src/http/mod.rs`, `src/lib.rs` and `src/http/logging.rs` (all
  ORIENTED), and `sf-impact` on `QUEUE_CAPACITY` (WIDE), on the `Sink.drops` widening (WIDE by
  graph rule, three files in practice), on the two new configuration keys (PARTIAL), and — §7,
  dispatched in response to `sf-red-team` finding 4 — on `siem::send` and `Unsent` under the C31
  hold (PARTIAL on protocol, sizing WIDE). Grounds C40, C41, C42, C44, C46, C56, the `## Files`
  table, and every line citation in `## Modules and interfaces`. §7 is the evidence that two
  existing tests could hang the suite rather than fail, and that `tp15` is its only hang-to-failure
  converter.
- [evidence/repository-structure.md](evidence/repository-structure.md) — `sf-repo-view`,
  2026-09-23, ORIENTED. Gate 2 grounding; still current for `src/delivery/`, `src/config.rs` and
  `src/http/health.rs`, which Gate 3 did not re-dispatch.
- [evidence/red-team-gate3-round2.md](evidence/red-team-gate3-round2.md) — `sf-red-team`,
  2026-09-24, **second pass**, verdict NEEDS REVISION, 6 findings (3 blockers, 3 major). Scoped
  to the material the first pass never saw: C46's restatement, C50–C61, the `build_decision`,
  `capacity_for` and `SinkCounters` blocks, the two `delivery` module subsections, and ten test
  rows. Grounds C62, C63, C64, C65 and the C61 correction. It recorded a protocol deviation —
  most source reads used native tools rather than SMTC — which `sf-gate-qa` round 3 closed by
  re-deriving all six findings from source through SMTC and confirming every cited line lands.
- [evidence/red-team-gate3.md](evidence/red-team-gate3.md) — `sf-red-team`, 2026-09-24, first
  pass, verdict NEEDS REVISION, 6 findings (3 blockers, 3 major). Every design citation it checked landed
  exactly. Grounds C50 through C54 and the C46 restatement. Its one finding left open — the Gate 2 `## External` contradiction — was resolved by the user as C55.
- [evidence/threat-model-gate3.md](evidence/threat-model-gate3.md) — `sf-threat-model`,
  2026-09-24, verdict MODELED, 8 retained threats (2 High, 6 Medium) plus 5 omitted, with an
  explicit disposition for each of the Gate 2 threats T1–T8. Grounds `## Threat model`, C46, C47
  and C48. Dispatched against the draft **before** C45–C48 were recorded, so its G3-T1 and G3-T2
  findings are what those rows resolve; it reached the `src/delivery/counters.rs` fix for G3-T2
  independently of `sf-spec-authoring`, which proposed the identical move.
- [evidence/threat-model.md](evidence/threat-model.md) — `sf-threat-model`, 2026-09-23, MODELED,
  8 threats. Its `TRIGGER-CHECK` is **Yes**, which is why `## Threat model` above is required at
  this gate.
- [evidence/red-team-gate2.md](evidence/red-team-gate2.md) — `sf-red-team`, 2026-09-23.
- [gate-2-qa.md](gate-2-qa.md) — `sf-gate-qa`, 2026-09-24, three rounds.
- tokio `sync::mpsc::channel` — https://docs.rs/tokio/latest/tokio/sync/mpsc/fn.channel.html,
  fetched 2026-09-24 via `ctx7`. Grounds C39.
- Editor diagnostics reporting `E0063` across `src/delivery/`, `src/http/logging.rs` and three
  test files reappeared on 2026-09-24, identical to the set `02-architecture.md:225` recorded on
  2026-09-23 as stale rust-analyzer index state rather than a broken tree. Unchanged assessment;
  the Gate 4 tracer slice re-establishes build health with `cargo check --all-targets` before any
  product write.

**Added at the slice-2 reopen, 2026-09-25.**

- [evidence/security-review-slice-2.md](evidence/security-review-slice-2.md) — `sf-security-review`,
  verdict **FIX FIRST**. F1 reopened this gate. Its two subject hashes are exact against the current
  working tree.
- [evidence/threat-model-gate3-reopen.md](evidence/threat-model-gate3-reopen.md) — `sf-threat-model`,
  verdict **UNKNOWN** (B1-B5). Proposed G3-T13 to G3-T15; rejected the first G3-T12 mitigation. A
  second run, distinct from the 2026-09-24 **MODELED** file above.
- [evidence/red-team-gate3-reopen.md](evidence/red-team-gate3-reopen.md) — `sf-red-team`, two rounds,
  both **NEEDS REVISION**. Round 1 B1-B6 withdrew C89 and C91; round 2 withdrew C92. Distinct from
  `red-team-gate3.md` and `red-team-gate3-round2.md`, which are the pre-reopen rounds.
- [evidence/reproduction-2026-09-25.md](evidence/reproduction-2026-09-25.md) — the executed runs
  against `target/debug/package-firewall serve` behind C87 and the G3-T12 closure, plus the recorded
  stdout/stderr split that was **not** acted on.
- `tracing-subscriber` `EnvFilter` — https://docs.rs/tracing-subscriber/latest/src/tracing_subscriber/filter/env/mod.rs.html
  (`add_directive`'s same-target overwrite rule) and
  https://docs.rs/tracing-subscriber/latest/src/tracing_subscriber/filter/env/directive.rs.html
  (`impl Ord for Directive`, ordering by target length, then span, then field count, reversed),
  fetched 2026-09-25 via `ctx7`. Grounds **C90**.
- `tracing-appender` `non_blocking` — https://github.com/tokio-rs/tracing/blob/main/tracing-appender/README.md,
  fetched 2026-09-25 via `ctx7`. Grounds the withdrawal of C92: the writer is lossy by default, and
  `NonBlocking::error_counter()` does expose `dropped_lines()`, contrary to what an earlier draft claimed.
