## What problem do we have?
Gate 2 was reopened (C13 amended, C39 added): the default queue budget now comes from a stated 200 rps reference load, 1,875 MiB per sink, not from the measured ceiling N (about 65,202/s). Gate 3 still described the old world in four places. Its 4 GiB ceiling (C36) was justified as "hours of outage", and its risk rows (G3-T8, accepted-risk 5) still spoke of a 64 MiB default.
## How will we solve it?
Only four places in `03-program-design.md` change; the rest was approved-quality READY on 2026-09-25 and is unchanged.

```text
DEFAULT_QUEUE_MAX_BYTES doc comment: ceil(300 x 200 x BYTES_PER_RECORD) = 1,875 MiB
C36  4 GiB ceiling = 131,072 records (at 32,768 B): ~655 s at 200 rps, ~2 s at N
G3-T8 (Medium, kept): default a flood can pin 64 MiB -> 1,875 MiB per sink,
      3,750 MiB with both sinks, additive to memory_cache_max_bytes
Accepted-risk 5: same restatement, in records
```

Code shape per package, as the document declares it (unchanged by this reopen):

```text
delivery/mod.rs   BYTES_PER_RECORD, FIELD_CEILING_BYTES, DEFAULT_QUEUE_MAX_BYTES,
                  MAX_QUEUE_MAX_BYTES (4 GiB), SHED_QUIET (60 s), capacity_for(u64),
                  Sinks::{drops, lost_total, is_shedding}, build (sizes queues)
delivery/counters.rs (new)  SinkCounters::{new, lose, take_window, total}
delivery/file.rs  4 loss sites -> counters.lose(n)
delivery/siem.rs  3 loss sites + hold; send(.., drain: &CancellationToken)
config.rs         two NonZeroU64 budgets; 4 rejection rules per key
http/health.rs    delivery() -> 200 | 503, bare status
http/logging.rs   build_decision(..) -> Decision; loggable applied once
main.rs           EnvFilter + add_directive("package_firewall::http::logging=info")
tests/common      drive_rated_load(config, target_rate, duration) -> RatedLoadResult
```

| Behavior | Test | Guards |
|---|---|---|
| bad budgets refused | rl2, rl3, rl4 | error: 0, 1 byte, 5 GiB, key without sink |
| no u64 budget panics | rl6 (property) | boundary: capacity_for is total |
| record within BYTES_PER_RECORD | rl22, rl16b (properties) | security/perf: G3-T3 memory bound |
| hold stops on shutdown | rl23, rl23b | security: G3-T4/T5 no hang, no hot-spin |
| 503 signal, ordering, clock step | rl12-rl16c | core: alarm truthful |
| three counts reconcile; floor holds | rl17, rl18 | performance: no loss at F |
| RUST_LOG cannot silence audit line | rl24, rl24b | security: G3-T9 |

Security and performance: bounded per-record memory and a 4 GiB per-sink ceiling; cancellation-aware, capped-cadence hold; pinned audit log target; bodyless health route. DRY and separation: one loss path (`SinkCounters::lose`, compiler-enforced by its own module), one bounding site (`build_decision`), one load driver shared by bench and test.
## How will we confirm it is solved?
Planned, not yet observed for the new default:
- 4 GiB / 32,768 B = 131,072 records; / 200 = ~655 s; / 65,202 = ~2 s -> stated in C36 and G3-T8 -> `gate-3-qa.md` recomputed all of these and they check.
- Floor test `tests/delivery_rated_load.rs` (rl18) and bench `benches/delivery_rated_load.rs` (rl20) -> re-run after Gate 4 is re-approved (slice 7).
Recommendation: Approve. The restatement is arithmetic only, matches Gate 2 as amended, and adds no module, boundary or input.
Limits: QA read the four amended places plus a consistency sweep, not all 1,207 lines; unchanged sections rely on the prior READY. Red Team was not re-run. The larger default a flood can pin (1,875 MiB per sink) is accepted knowingly, as at Gate 2. Gate 4 text (C76, slice 7, slice-1 64 MiB notes) still needs a matching update after this approval.
Status: Gate 3 reopened 2026-09-26; `sf-gate-qa` READY (`gate-3-qa.md`); router verify READY (16 files). Slices 1-6 stay done. Gate 4 pending.
Sources: `03-program-design.md` (C36, `DEFAULT_QUEUE_MAX_BYTES`, G3-T8, Least confident 5), `gate-3-qa.md`, `show-me-gate2-reapproval.md`, `evidence/tdd-slice-7.md`
Approve Gate 3, or what should change?
