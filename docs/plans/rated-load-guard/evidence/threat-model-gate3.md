# Threat model — Gate 3, rated-load-guard

Source: `sf-threat-model`, 2026-09-24. Verdict: **MODELED**. Design-only and read-only: every
threat is against `03-program-design.md` plus the existing source lines it cites. Dispatched
against the draft **before** C45, C46, C47 and C48 were recorded; the disposition column below
states which findings those rows now carry.

This model exists because `evidence/threat-model.md` (Gate 2) recorded `TRIGGER-CHECK: Yes` —
the shedding signal is an audit-trail-loss detection control and `BYTES_PER_RECORD` is a
memory-bound control, so both had to be modelled again in depth once the design named them.

---

## One design claim checked and confirmed

C22 asserts `Decision.method` is the **last** unbounded record field. True. `Decision`
(`src/delivery/mod.rs:53-73`) has six `String` fields: `timestamp` is fixed-width RFC 3339,
`request_id` is internally generated, `package` and `version` arrive `loggable`-bounded, and
`reason` is a constant in every arm — `ApiError::Blocked { reason: &'static str }`
(`src/http/error.rs:35`), `InvalidInput(&'static str)` (`:38`), and a literal in every other arm
(`:136-172`). Bounding `method` at `src/http/logging.rs:210` closes the field set, so the
remaining T2 risk is entirely about the *value* of `BYTES_PER_RECORD`, not about another field.

## Scope, entry points, trust boundaries, assets

**Scope:** the ten surfaces the design introduces — the two budget keys and their four rejection
rules; `BYTES_PER_RECORD` as a memory bound under C44; `SinkCounters::lose` and the eight loss
sites; the derived shed marker; `Sinks::is_shedding` and its watch pair; `GET /health/delivery`
unauthenticated on the serving listener; the `test-support` accessor; the C31 SIEM hold; and the
load driver.

**Entry points**

| Entry point | Actor | Authentication | New at Gate 3? |
|---|---|---|---|
| `GET /health/delivery` | any peer reaching `listen` | none | yes — and it is a **writer** of process state (the watch pair), not only a reader |
| every other route → `logging::decide` → `Sinks::offer` (`src/http/logging.rs:243`) | any peer | none | unchanged shape, but the queue it fills is now operator-sized up to 4 GiB |
| `log_queue_max_bytes` / `siem_queue_max_bytes` in TOML | operator | filesystem | yes |
| **the SIEM collector's HTTP response** (`src/delivery/siem.rs:149-173`) | the collector, or anyone who can interrupt the path to it | outbound credential only | **yes, and Gate 2 did not list it.** Post-C31 the collector's answer decides whether the SIEM task consumes its queue at all, so an external party now influences queue occupancy and sink-task lifetime |
| `App::delivery_lost_total` under `test-support` | a `tests/` or `benches/` binary in this repo | Cargo feature, default-off, `publish = false` | narrowed from Gate 2 |

**Trust boundaries:** (1) unauthenticated network peer ⇄ process state — the same actor fills the
queues and both reads *and mutates* the watch pair; (2) operator config → host memory, now up to
4 GiB × 2 sinks; (3) **external collector → sink-task control flow and process shutdown** (new,
C31); (4) hot path (`Sink::push`, non-`async`, lock-free) → observer tasks across relaxed
atomics; (5) `pub(crate) delivery` → test and bench binaries, now only a `u64` accessor.

**Assets:** the audit trail's completeness; **the truthfulness of the alarm that reports its
incompleteness**; package-serving availability for the fleet (C7 and C8 rank this first); host
memory and the honesty of the published byte budget; orderly shutdown and restart during an
incident (newly at risk); the SIEM credential (`OSPREY_SIEM_AUTH`, `src/delivery/mod.rs:179`),
still out of reach — nothing in this design places it on `Config` or in a body.

---

## Retained threats

| ID | Property | Mechanism | Asset | Location | Sev | Mitigation | Verification property | Tier | Carrier |
|---|---|---|---|---|---|---|---|---|---|
| G3-T1 | TOCTOU on a detection control | `is_shedding` stores `last_total` and `last_change_micros` as two separate relaxed atomics. Prober A stores `last_total` and is preempted; prober B reads `total == last_total` with a stale timestamp and answers `200` while records are destroyed. The endpoint is unauthenticated, so the race can be widened by hammering it. The draft also gave the pair no declared home. | the alarm's truthfulness | `Sinks::is_shedding` | Medium | **Resolved by C47**: pair owned by `Sinks`, `last_change_micros` stored first, `last_total` stored `Release` / loaded `Acquire` | no probe returns `200` once any probe has observed the loss increment that made the process shed | decision | `rl16`, **restated** to fail on the interleaving rather than only on convergence |
| G3-T2 | noninterference between loss and alarm (Gate 2 T1 residual) | `SinkCounters` declared in `mod.rs` leaves its private atomics reachable from `delivery::file` and `delivery::siem`, which are descendant modules — exactly where seven of the eight loss sites live. A site incrementing a field directly makes the alarm lie and breaks the reconciliation. | the audit trail and its alarm | `SinkCounters`; the eight sites | Medium (High over the module's lifetime) | **Resolved by C45**, reached independently: define `SinkCounters` in `src/delivery/counters.rs` so siblings cannot name the fields and `lose` is the only mutator that compiles | no mutating atomic op on a sink counter exists in `src/delivery/` outside `SinkCounters`' own module | structural → **decision** after C45 | compile-time; `rl7` covers the eight known sites behaviourally |
| G3-T3 | attacker-controlled complexity / memory-bound control (Gate 2 T2 residual) | The constant's literal is deferred to the bench, and the only row touching the derivation fails nothing. C44 shows the honest per-field ceiling is `256 chars × 4 bytes × escape expansion + 2`, on `String` **capacity**. If the bench reports a mean or drops the expansion term, the operator's stated budget holds several times more bytes than promised — and that queue is fillable by an unauthenticated flood, since the cheapest route still emits one record. This is exactly the documented false guarantee C22 rejected. | host memory; the honesty of the published tolerance | `BYTES_PER_RECORD`; the bench; `docs/operations.md` | **High** | **Carrier added: `rl22`** — construct a worst-case `Decision` in-process and assert its heap footprint ≤ `BYTES_PER_RECORD`, with the bench's printed derivation checked against the same figure | no `Decision` this process can construct has a heap footprint greater than `BYTES_PER_RECORD` | decision | **`rl22`** (was none) |
| G3-T4 | availability / external dependency isolated from process lifecycle | C31's hold is awaited inside `tokio::select!` (`src/delivery/siem.rs:68`, `:74`); an unbounded retry never returns to poll the `drain.cancelled()` arm at `:76`, so `Running::shutdown` blocks forever at `src/lib.rs:324`. The graceful SIGTERM stop added in `734d22d` never completes while the collector is down — the exact incident during which an operator restarts. Today the path is bounded only because `BACKOFF` exhausts at ~7 s. | process availability; the operator's ability to restart during an incident | `send` and the `select!` at `:59-102` | **High** | **Resolved by C46**: the hold is cancellation-aware, so `timeout(DRAIN_DEADLINE)` at `:80` bounds shutdown as today | with the collector unreachable, `Running::shutdown().await` returns within `DRAIN_DEADLINE`, and held records are counted through `lose` | structural | **`rl23`** (was none) |
| G3-T5 | resource and ambient authority at an external boundary | The hold's cadence is unspecified. A bare `loop { send }` hot-spins a tokio worker; for a non-retryable `401`/`403` (`:164`) the hold may never end, making an indefinite authenticated-failure loop that presents the credential on every attempt (`:145-147`) — collector-side lockout and alarm flood. Separately the held `batch` (up to 256) plus one serialized `body` are resident for the whole outage, outside the budget the operator was sold; C29 named this addend as transient, C31 makes it persistent. | host memory beyond the published budget; the credential's standing at the collector | `src/delivery/siem.rs:139-183`; `docs/operations.md` | Medium | **Resolved by C46**: interval capped at the last `BACKOFF` entry (no new constant); the docs row states the held bytes as a persistent addend | during a hold the interval between POSTs is ≥ the last `BACKOFF` entry, and resident bytes never exceed `siem_queue_max_bytes + BATCH_RECORDS × BYTES_PER_RECORD + one body` | decision | **`rl23`** for cadence; docs row for the memory statement |
| G3-T6 | information disclosure enabling repudiation (Gate 2 T3, carried) | The same unauthenticated actor floods the cheapest route to fill the queues and polls `/health/delivery` until it reads `503`, confirming the durable sinks are discarding before issuing the fetch it wants absent. Post-C31 the SIEM half is *sharper*: forcing the hold no longer means waiting out a 7 s retry window. | the trail's answer to "which machines took this package" | the new handler; registration after `src/http/mod.rs:42` | Medium | **Accepted.** Bodyless response (C9, C43), `no_store` (`src/http/mod.rs:94`), and the C26 docs deliverable that stdout remains the complete trail | a record dropped by a sink is still on stdout — `offer` never moves above `tracing::info!` — and the response body is empty for every outcome | manual | **`rl24`, `rl25`** (was none) |
| G3-T7 | availability / privilege crossing by misconfiguration (Gate 2 T4, carried) | The route sits under `/health/` beside two genuine probe targets; an operator wiring it into an LB or Kubernetes readiness check hands any client that can drive drops a lever to remove every instance from the pool. | package-serving availability for the fleet | registration; `docs/operations.md`, `README.md` | Medium | Structural half satisfied — `http::health` owns nothing, no serving decision consults the state, `ready` untouched. Documentary half is the C26 named deliverable | no serving decision reads the shedding state; `/health/ready` returns `200` throughout a sustained shedding event | structural | `rl15` + docs row |
| G3-T8 | resource exhaustion via operator-authored input (Gate 2 T8, mostly closed) | C36 closes the `u64::MAX` path and the 32-bit `MAX_PERMITS` band. Residual: the ceiling is per sink, so two sinks accept 8 GiB; C36 rejected any host-memory cross-check; and the "about 4 million records" rationale assumes ~1 KiB per record, which G3-T3 and C44 make unlikely. The change in attacker reach is real: today a flood pins at most 2 × 4096 records, after this feature it pins the operator's whole budget, and C31 guarantees the SIEM queue reaches it during any outage. | host memory, transitively serving availability | `RawConfig::validate`; `MAX_QUEUE_MAX_BYTES` | Medium (**up** from Low) | **Accepted.** Keep the ceiling; restate it in **records** as well as bytes in `docs/operations.md` once `BYTES_PER_RECORD` is measured. If `4 GiB ÷ BYTES_PER_RECORD` stops matching the "hours of outage" claim, the number is restated rather than the claim | no accepted configuration yields a per-sink budget above `MAX_QUEUE_MAX_BYTES` or below `BYTES_PER_RECORD`, and the published ceiling is expressed in records at the measured constant | decision | `rl2`, `rl3`, `rl6`; records-restatement on the docs row |

**Omitted: 5.** (a) A backwards wall-clock step makes `now.saturating_sub(last_change)` negative,
which is `< SHED_QUIET`, latching `503` for the size of the step — **resolved by C47**, which
requires a non-negative delta, witnessed by `rl16c`. (b) A SIEM batch the collector partially
accepted and then re-posted can be both delivered and counted lost, since `Unsent` counts whole
batches (`src/delivery/siem.rs:209-215`) — a false `503` and a flaky `rl17`; **open, accepted**,
and the reason `rl17` runs with a deliberately small queue rather than a wedged collector.
(c) `lost_total()` sums both sinks, so a record both sinks drop counts twice and the
reconciliation fails on a healthy run — **resolved by C48**, one sink in the driver.
(d) Gate 2 T7's residual: the accessor returns a `u64` and constructs nothing — Low, controlled.
(e) The driver in `tests/common/mod.rs` compiles into all 19 integration binaries — cost, not
exposure.

---

## Gate 2 threats T1–T8, disposed against this design

| Gate 2 | Disposition |
|---|---|
| **T1** shedding blind to non-backpressure loss sites (High) | **Mitigated.** `lose` at all eight sites plus a marker derived from `total` means the unopenable-log-file case (`src/delivery/file.rs:181`) now raises `503`; C31 converts the non-retryable-SIEM case from fast-fail into backpressure that sheds at `push` where it is counted — better than Gate 2 assumed. Residuals carried as G3-T2 and G3-T1, both now resolved by C45 and C47. |
| **T2** `Decision.method` unbounded (Medium) | **Mitigated in mechanism, open in value.** The `loggable` edit closes the field set (verified above). But C44 makes the ceiling larger than C29 assumed and the constant was deferred to a report-only bench, so the bound was unverified: G3-T3, raised to **High**, now carried by `rl22`. |
| **T3** unauthenticated confirmation oracle (Medium) | **Open, accepted.** Every existing control preserved plus the C26 docs deliverables. Slightly worse post-C31. Carried as G3-T6, now witnessed by `rl24` and `rl25`. |
| **T4** `/health/` route wired into an LB (Medium) | **Mitigated.** Structural half explicit in the design and carried by `rl15`; documentary half a named C26 deliverable. Carried as G3-T7 at reduced residual. |
| **T5** budget below one record → `mpsc::channel(0)` panic (Medium) | **Closed.** Four rejection rules against the imported `BYTES_PER_RECORD`, `usize::try_from` not `as`, and C39's second panic path closed by the ceiling. `build` gains no new error because nothing can fail by the time it runs. Carriers `rl2`, `rl3`, `rl4`, `rl6`. |
| **T6** lock or clock read in `Sink::push` (Medium) | **Closed.** `lose(n)` is two relaxed adds; the clock read stays with the handler because `is_shedding` takes `now_utc_micros` as a parameter; the marker is derived, so the loss path gained no third write. Its verification property is structural with no test row — accepted: the code shape is the carrier and post-implementation Security re-reads source. |
| **T7** driver becomes public API and can forge records (Low) | **Closed / narrowed.** C42 puts the driver in `tests/common/mod.rs` with no library surface; C32 narrows the gated item to `App::delivery_lost_total() -> u64`. No `Sinks` constructor, no `Record` construction. |
| **T8** no upper bound on the budget keys (Low) | **Mitigated, residual accepted.** C36's ceiling closes the deferred-OOM and the 32-bit band. Residual carried as G3-T8 at **Medium** — severity went *up*, because the feature multiplies the memory an unauthenticated flood can pin, from ~8192 records to the whole budget. |

## Accepted risks and their owners

| # | Accepted risk | Rationale | Owner |
|---|---|---|---|
| 1 | The 4 GiB per-sink ceiling with no host-memory cross-check (C36, G3-T8) | Coupling the queue budget to `memory_cache_max_bytes` would surprise an operator who legitimately wants a large queue and a small cache | **The user**, at Gate 3 grilling Q2, 2026-09-24 |
| 2 | The unauthenticated confirmation oracle (C9, C26, G3-T6) | The record stream survives on stdout, and per-sink detail is already published on the summary record | **The user**, at Gate 2 grilling Q4, 2026-09-23 |
| 3 | A partially-accepted, re-posted SIEM batch counted both delivered and lost (omitted item (b)) | `Unsent` counts whole batches by existing design (`src/delivery/siem.rs:107-112`, rationale in place since the MVP); the reconciliation row `rl17` avoids it by using a small queue rather than a wedged collector | **The user**, carried here for visibility at the Gate 3 decision |

The indefinite SIEM hold was **not** accepted as such: the user's Gate 2 grilling Q8 answer
considered only *where* records are lost, not shutdown cancellation or retry cadence, so G3-T4
and G3-T5 are consequences that acceptance did not cover. They are fixed by C46 rather than
accepted.

## Limitations

- Proposed code does not exist; every threat is against the design plus the existing lines it
  cites. Missing implementation was never treated as an unknown surface.
- The model was produced against the draft **before** C45–C48 were recorded. Its two structural
  findings that those rows resolve (G3-T2, G3-T1) were reached independently of the
  `sf-spec-authoring` result, which proposed the identical module move for G3-T2.
- The design's largest structural weakness at the time of the model: `## Modules and interfaces`
  had no subsection for `src/delivery/file.rs` or `src/delivery/siem.rs`, although those two
  files carry seven of the eight loss sites and the whole C31 hold. G3-T4 and G3-T5 exist
  because that contract was unwritten. Both subsections have since been added.
- Hyper's ceiling on a request-line method token was not determined, and does not matter: after
  the `loggable` edit the field is bounded in-process regardless.
- The verification properties for G3-T2 and G3-T6 are inspection-checkable structural
  invariants; G3-T2's is now a compile error under C45, and G3-T6's gained executable rows.
