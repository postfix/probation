# Red team — Gate 3 round 2, rated-load-guard

Source: `sf-red-team`, 2026-09-24, second pass. Verdict: **NEEDS REVISION**, six findings, three
blockers. Independent, read-only. Scope was the material the first pass never saw: C46's
restatement, C50–C61, the `build_decision` and `capacity_for` subsections, the `SinkCounters`
block, the `delivery::file` and `delivery::siem` subsections, and rows `rl6`, `rl10b`, `rl16`,
`rl16b`, `rl16c`, `rl17`, `rl18`, `rl22`, `rl23`, `rl23b`.

Subject: `03-program-design.md` =
`0f99e5c1522488f73536a0f349e7e0f0c4eedcd7d639f32ddbbd658d9a27f92b`.

## Findings and dispositions

| # | Finding | Rank | Disposition |
|---|---|---|---|
| 1 | **C46's one permitted hold cannot compile.** The `send` subsection froze the signature as unchanged while requiring the sleep at `siem.rs:181` to be `select!`ed against `drain.cancelled()` inside `send`. `send` (`:113-119`) takes no token; `drain` is a local of `run` (`:50`) passed to none of its four call sites — `E0425`. The implementer's likely escape is the retry loop that never observes cancellation: the High-severity G3-T4 implementation `rl23` exists to reject, and the one that hangs `tp7` and `tp11a`. | blocker | **Fixed, C62** |
| 2 | **`loggable` applied to `method` twice.** `decide`'s `:210` edit and `build_decision` both applied it; `loggable` is `format!("{bounded:?}")` and is not idempotent, so every record would emit `method` as `"\"GET\""`. No planned check could fail: the two property rows call `build_decision` directly and see one application, `DECISION_FIELDS` (`tests/decision_log_delivery.rs:36-48`) is a 12-key presence list, and **no test in the repository asserts the `method` value** — every other `method` hit is a `wiremock` matcher. | blocker | **Fixed, C63** |
| 3 | **`rl6` could not pass its declared domain.** `capacity_for(budget: NonZeroU64)` cannot receive `0`, which is C23's original `mpsc::channel(0)` panic input — the very value the function exists to refuse. `CapacityError` and `MAX_SAFE_CAPACITY` were declared nowhere, so `build`'s `.expect` and the property's arm assertion had no types to compile against. | blocker | **Fixed, C61 corrected** |
| 4 | **C46's row still offered the implementation its own subsection rejects.** Gate 4 slices cite decision rows, not module prose; an implementer taking the second option ships a SIEM sink whose queue never accumulates, so `rl10` fails and C31/C6's premise is undelivered, while `rl23` and `rl23b` both pass. | major | **Not fixed in round 2; fixed now, C66** — re-reported as `sf-gate-qa` G3QA-17 |
| 5 | **`rl18`'s throughput limb was entailed by its other two.** With the offer paced at `F`, `offered ≈ F × D` by construction, so zero-drops plus the exact reconciliation force `delivered == offered + 1`. The `4 × D` deadline compounded with `F`'s own 4× headroom, detecting nothing below a ~16× collapse. | major | **Half fixed by C65; completed now, C67** — re-reported as G3QA-20 |
| 6 | **`SinkCounters` broke three of its own call sites and named the binding two ways.** `Sinks::drops`'s `swap(0, …)` on a now-private field is `E0616`; every rewritten loss-site body said `counters` while every frozen signature said `drops` — `E0425` at all eight sites; `tp19:260`'s `drops.load(…)` had no `SinkCounters` equivalent. | major | **Fixed, C64** |

## Checked clean

Risk order — C59 and C46 move the hold's cancellation and cadence risk to `rl23`/`rl23b` in the
same slice that introduces it, and `## Least confident` #7 names the file's thin coverage.
Sizing — the new material adds one seam per row it serves.

`build_decision`'s parameter list was verified as the first one that survives the source:
fourteen fields at `src/http/logging.rs:207-222`; `ecosystem: &'static str`
(`src/delivery/mod.rs:58`) confirms the explicit-parameter decision, since `decide` computes it
at `logging.rs:198-202` from `context.ecosystem` overriding `target.ecosystem`; `reason: String`
(`:63`) confirms the correction, since `ApiError::reason(&self) -> String`
(`src/http/error.rs:136`) and the `None` arm at `logging.rs:194` is `"…".to_owned()`;
`consumer: Option<IpAddr>` (`:72`). `Target` (`logging.rs:261-265`) holds `Option<String>`, so
`target: Target` by value compiles and the ecosystem override is resolved before the move.

`rl17` was confirmed able to fail and to pass: the `+1` is right because `flush_summary`
(`src/lib.rs:321`) runs after the server joins and before `drain.cancel()` (`:322`) and
`tasks.join()` (`:324`), so exactly one `RequestSummary` is offered; and the seam is reachable
because `set_summary_window` is `#[cfg(feature = "test-support")] pub fn` at `logging.rs:461`
inside `pub mod http` / `pub mod logging`, with dev-dependencies turning the feature on.

## Limitations

- **Protocol deviation, recorded:** one SMTC leg ran; the remaining source reads used native
  tools without a host refusal or an `sf-smtc-doctor` verdict to justify the fallback. Tier for
  those legs is Manual rather than SMTC-backed. `sf-gate-qa` round 3 subsequently re-derived all
  six findings from source through SMTC and confirmed every line they rely on lands exactly, so
  the accuracy is independently established; only the original tier was reduced.
- `BYTES_PER_RECORD`, `FIELD_CEILING_BYTES`, `DEFAULT_QUEUE_MAX_BYTES` and `F`/`D`/`M` are all
  deferred to the bench slice, so every claim about the ceiling's honesty is unfalsifiable at
  this gate by construction.
- `Semaphore::MAX_PERMITS` was taken from the design's own `ctx7` citation rather than re-fetched.
- Below the bar and not raised as findings at the time, both since addressed: `rl17`/`rl18`'s
  exact `+ 1` rests on the process-global `SUMMARY_MILLIS` (`logging.rs:54`), shared by every
  test in a binary `cargo test` runs in parallel threads (now an obligation in C65); and the
  `## Files` row for `siem.rs` read as nine loss sites rather than eight.
