## What problem do we have?
Gate 2 is reopened for one change (C13 amended, C39 added). C13 sized the default queue budget from "the rated load", meaning the measured ceiling `N`. The slice 7 ten-minute release run measured `N` ≈ 65,202 records/s and `BYTES_PER_RECORD` = 32,768, so the formula gives about 611,267 MiB (~597 GiB). That is roughly 150 times the 4 GiB ceiling of Gate 3 C36, so it cannot be satisfied (`evidence/tdd-slice-7.md`).
## How will we solve it?
The default budget is derived from a stated reference load of 200 requests per second instead of `N`:

```text
DEFAULT_QUEUE_MAX_BYTES = ceil(5 min x 200 x 32,768 B) in whole MiB = 1,875 MiB per sink
                                                    (60,000 records x 32,768 B)
```

| Quantity | At 200 rps | At N (65,202/s) |
|---|---|---|
| Default 1,875 MiB per sink | 300 s of collector outage | about 0.9 s |
| 4 GiB ceiling (Gate 3 C36) | about 655 s | about 2 s |
| Rejected: keep 64 MiB (2,048 records) | about 10 s | about 31 ms |

- Memory cost: 1,875 MiB per sink, 3,750 MiB with both sinks on, additive to `memory_cache_max_bytes`. That is 7.5 times the top of slice 1's 60-250 MiB band, because `BYTES_PER_RECORD` is a worst-case ceiling (C29), not a mean. The earlier claim "same family as the 256 MiB cache" is withdrawn. The operator docs must state the memory beside the default.
- The promise is now: no record lost at or below the stated reference load, and at most `N` on the named reference hardware. `N` is published as the machine's ceiling, not as the promise. An operator whose traffic nears `N` must raise the budget, and the docs say so.
- Not changed: the headline promise (zero records lost at `N`, sustained ten minutes, on named reference hardware), which the bench and the floor test witness.
- Rejected: raising or dropping the 4 GiB ceiling, which reopens C36 and leaves the budget unbounded.

Gate 1 reading (your choice): Gate 1's C6, C10, C13 and the Success metric tie the tolerance to the measured `N`. Gate 2 reads "rated load" for `M` as the 200 rps reference load and does not edit Gate 1 (C39, the same approach as C38). If you want Gate 1's own sentences amended so "rated load" names the reference load, that is a Gate 1 reopen.

Corrections carried into later Gates (each is reopened as pending and needs its own re-approval; slices 1-6 stay done):

```text
Gate 3: 03-program-design.md:103-104 (constant's doc comment); C36 "hours of outage"
        -> about 655 s at 200 rps, about 2 s at N; severity of G3-T8 vs larger default
Gate 4: C76 and slice 7 text (N no longer the multiplicand; 60-250 MiB band;
        slice-1 provisional 64 MiB notes)
```
## How will we confirm it is solved?
Planned, not yet observed for the new default:
- 1,875 MiB / 32,768 B = 60,000 records; 60,000 / 200 = 300 s; 60,000 / 65,202 = 0.92 s -> stated in the docs -> `gate-2-qa.md` round 5 recomputed these figures and they check.
- Bench `benches/delivery_rated_load.rs` -> prints `N`, `BYTES_PER_RECORD` derivation and the default's tolerance -> re-run after Gates 3 and 4 are re-approved (slice 7).
- Floor test `tests/delivery_rated_load.rs` -> zero drops, `delivered >= F x duration`, `offered - delivered == dropped` (C28, C34) -> `cargo test`.

Recommendation: Approve. The 200 rps reference load is your own choice, and the default fits inside the 4 GiB ceiling with the tolerance stated honestly at both loads.
Limits: `sf-red-team` not triggered for this revision; the raised memory an unauthenticated flood can pin during a collector wedge (64 MiB to 1,875 MiB per sink, 3,750 MiB with both) is accepted knowingly, bounded by the 4 GiB ceiling and restated at Gate 3. Gate QA notes that Gate 1 C6 also says "at the rated load" and is not in C39's list; the same reading applies. Bookkeeping in the `## Repository evidence` gate-2-qa bullet is stale (not a decision source). Source code was not re-inspected in round 5.
Status: Gate 2 reopened 2026-09-26; `sf-gate-qa` round 5 READY (`gate-2-qa.md`); router verify READY. Gates 3 and 4 pending re-approval.
Sources: `02-architecture.md` (C13, C39, last line), `gate-2-qa.md`, `evidence/tdd-slice-7.md`
Approve Gate 2, or what should change?
