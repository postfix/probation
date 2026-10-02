# Gate 2 — Architecture: Rated load guard

## What problem do we have?

The firewall promises it does not lose decision records below its rated load, but no number
anywhere says what that load is, and an operator has no lever when their traffic exceeds it. So an
operator cannot size a deployment — they do not know whether 200 requests a second is comfortable
or already shedding — and when their collector goes down for maintenance they cannot tell whether
records are held or dropped after a few seconds. Today's fixed 4096 records per sink
(`src/delivery/mod.rs:37`) is roughly 20 seconds at 200 records per second, and the operator cannot
change it.

## How will we solve it?

Measure the number, publish it with the outage tolerance it implies, assert a floor on
`cargo test` so a collapse cannot ship unnoticed, and turn the fixed queue capacity into two
configurable per-sink memory budgets.

| Requirement | Module that fulfils it |
|---|---|
| An operator raises either sink's queue budget by configuration | `config` (`src/config.rs`) — `log_queue_max_bytes` and `siem_queue_max_bytes`, both `NonZeroU64`, both optional, each refused when its sink is off (C5) |
| A byte budget becomes a queue capacity | `delivery` (`src/delivery/mod.rs`) — divide by `BYTES_PER_RECORD` once, at the two existing `mpsc::channel` calls; `QUEUE_CAPACITY` stops being the capacity (C15) |
| The published budget is a true memory bound | `http::logging` (`src/http/logging.rs`) — `Decision.method` bounded with the existing `loggable` / `MAX_LOGGED_TARGET` (C22) |
| A default deployment survives a collector outage | `delivery` (`src/delivery/siem.rs`) — the SIEM sink holds its queue while the collector is unreachable instead of discarding the batch (C31) |
| An operator sees that records are being shed, without reading logs | `http::health` (`src/http/health.rs`) — `GET /health/delivery`, bare status code, `200` / `503` (C9); one route line in `http` (`src/http/mod.rs:42`) |
| Every record loss reaches both the alarm and the measurement | `delivery` (`mod.rs`, `file.rs`, `siem.rs`) — every loss site increments the window counter, increments the monotonic total, and marks the shedding state (`## Flow` step 4) |
| One measurement loop, so bench and test cannot drift | delivery load driver — drives real HTTP at `/health/live` against a started `App` with a sink configured (C32) |
| The rated figure and the bytes-per-record constant | `benches/delivery_rated_load.rs` — `harness = false`, the product's ten minutes sustained, reports numbers and fails nothing (C30) |
| A collapse fails a run | `tests/delivery_rated_load.rs` — asserted by `cargo test`, because this repository has no CI at all (C14) |
| Operators read the numbers and the two security warnings | `docs/operations.md`, `config.sample.toml`, `README.md` — the published items and two named operator warnings |

```text
src/
├── config.rs                    # the two budget keys and their rejection rules
├── delivery/
│   ├── mod.rs                   # budget → capacity, shed marker, monotonic drop total
│   ├── file.rs                  # the loss-site discipline at its four sites
│   └── siem.rs                  # holds its queue while the collector is unreachable
└── http/
    ├── health.rs                # GET /health/delivery
    ├── logging.rs               # bounds Decision.method
    └── mod.rs                   # one route line
benches/delivery_rated_load.rs   # the rated figure, ten minutes sustained
tests/delivery_rated_load.rs     # the floor, on cargo test
```

Two values are set by policy rather than by a literal chosen now: the default per-sink budget is
the smallest whole MiB that buys at least 5 minutes of collector outage at the rated load, in the
same family as the existing 256 MiB `memory_cache_max_bytes` (C13); and the floor is its own
published absolute rate `F`, asserted as **zero drops while offering `F` records per second** and
never as achieved throughput, because `cargo test` builds debug (C11, C14).

**Two deliberate scope additions**, both accepted rather than narrowed away: C22 bounds
`Decision.method` in `src/http/logging.rs`, slightly outside this plan's stated scope, so the
budget means what the product says it means; C31 changes SIEM delivery behaviour so the budget
buys the outage tolerance the approved Success metric promises.

Both came from review, and both changed the design. The threat model found that marking the state
in `Sink::push` alone would report `200` while an unopenable log file or a rotated SIEM credential
destroyed 100% of the audit trail — those sites drain at full speed, so the queue never fills (T1).
The red team found that no budget of any size buys collector-outage tolerance on the SIEM sink,
because `send` retries `BACKOFF` and `Unsent::drop` discards the batch at roughly 7 seconds while
the receiver keeps draining (finding 2).

## How will we confirm it is solved?

All checks below are **planned**; no code exists yet.

| Scenario | Expected result | Check |
|---|---|---|
| The delivery pipeline collapses | `cargo test` fails the run | `tests/delivery_rated_load.rs`, against a configured sink: zero drops at `F`, `delivered ≥ F × duration`, and `offered − delivered == dropped` (C28, C34) |
| Rated load is measured | A figure on named reference hardware, ten minutes sustained | `benches/delivery_rated_load.rs`, which prints and fails nothing (C30) |
| Offered load exceeds the queue's capacity | Records dropped and counted as today; serving neither slowed nor failed; `/health/ready` green; `/health/delivery` `503` | `## Program behavior` Failures |
| A log file cannot be opened, or a credential is rotated | `/health/delivery` reports `503` rather than green | every loss site marks the shedding state — eight sites, seven counting today plus the SIEM serialize-failure branch (`## Flow` step 4, C21, C27) |
| A budget too small to hold one record | Rejected at config load as `Invalid`; no `mpsc::channel(0)` panic | validated in `config` against the same constant, using `usize::try_from` (C23) |
| A budget key set while its sink is off | Rejected at load | the existing `log_file_max_bytes` rule (C5) |

`delivered` is counted independently, as distinct `request_id` values observed at the destination
among `RequestDecided` records, so `offered − delivered == dropped` is a real assertion rather than
an arithmetic identity; a run in which `Writer::roll_over` rotated the log file is void, not
under-counted (C34).

Recommendation: approve. Every product outcome has one owning module, both deliberate scope
additions keep approved promises rather than retreating from them, and the four checks that decide
the feature are named with the code each failure lands in.

Limits:

- **Deferred to Gate 3 as inventory rows, not settled here:** C35, how long `/health/delivery`
  stays `503` after the last drop (constrained by C24 — the clock read stays out of `Sink::push`);
  and C36, whether the two budget keys get a sanity ceiling (threat T8).
- The threat model's `TRIGGER-CHECK` is **Yes**: the shedding signal and `BYTES_PER_RECORD` are
  security controls in their own right and must be modelled again in depth at Gate 3.
- The `sf-red-team` verdict stands against a **pre-correction** document. All 7 findings were
  resolved afterwards, but nothing in the corrected text has been adversarially reviewed — four
  successive Gate QA rounds are its only independent reviews.
- `01-product.md` still enumerates two unconditional changes where C31 makes three. C38 reconciles
  this inside Gate 2, with an operator-facing upgrade note as the carrier; Gate 1 is not reopened.
- Three non-blocking observations carried to Gate 3, none of which changes a selected value: C34
  writes the record filter as `event == "RequestDecided"` where the wire tag is `request_decided`
  (`Record` carries `rename_all = "snake_case"`); `## Flow` says the floor test "asserts both
  limbs" where the owning `## Fit` row names three; `## Repository evidence` says "Two rounds" then
  recites three.
- Gate QA also records two cases where an observed `delivered` could legitimately differ from
  `offered − dropped` without an uncounted loss — with **both** sinks configured the reconciliation
  must be taken per sink, and a driver request that fails in transport produces no decision record.
  Both are Gate 3 mechanism, not Gate 2 shape.

Status: Gate 1 (Product) approved 2026-09-23. `sf-gate-qa` round 4 returned **READY** with 0
blocking findings.

Sources: `02-architecture.md` (the Gate document); `01-product.md`;
`evidence/repository-structure.md` (`sf-repo-view`, ORIENTED); `evidence/threat-model.md`
(`sf-threat-model`, MODELED, 8 threats); `evidence/red-team-gate2.md` (`sf-red-team`, FIX FIRST,
7 findings, all resolved); `gate-2-qa.md` (`sf-gate-qa`, READY).

Approve Gate 2, or what should change?
