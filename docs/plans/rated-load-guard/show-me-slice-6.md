## Delivered
The SIEM sink now holds its undelivered batch through a collector outage instead of discarding it after the ~7 s retry ladder, so loss begins at the operator's queue budget and is counted there. `run`'s signature, `Unsent`, `offer` and `Sinks::drops` are unchanged; only the private `send` changes.

```diff
 src/delivery/siem.rs
-  send(...)                      // 5 params; ladder exhausts, Unsent::drop counts the batch
+  send(..., drain: &CancellationToken)   // 6th param; all four call sites pass &drain
+  retryable (5xx, 429, transport): retry, interval capped at last BACKOFF entry (2 s)
+  backoff sleep is select!ed against drain.cancelled(); on cancel return, Unsent stays armed
   302/400/401/403: still discard and count immediately
 tests/decision_log_delivery.rs
+  prompt_503_collector(), decided_ids_received(), rl10, rl10b, rl23, rl23b
+  AuthEnv taken before each test's timeout
```

Mechanical churn: the `siem.rs` module header was reworded (the ladder is no longer finite).

## Proof
| Promise | Witness | Observed |
|---|---|---|
| rl10: records accumulate and are delivered on recovery | red: `left 20, right 0` (lost_total after 9 s outage) | green: 503 collector, 20+20 records, reset to 200, all 40 delivered |
| rl23: shutdown returns against a wedged collector | red: `HANG: shutdown did not return / no held records counted within 10 s` | green: 30 records counted within 10 s, shutdown under its 20 s timeout |
| rl23b: the hold does not hot-spin | red: 4 arrivals, then give up | green: >= 5 arrivals, gaps after the first three >= 1.95 s |
| rl10b: 302/401 counted immediately | not red, regression guard (C56) | green: lost_total 1 then 2, exactly 2 requests |

Commands: `cargo check --all-targets` exit 0; `cargo test --test decision_log_delivery` -> `ok. 31 passed`, 0 failed (~86 s), including rl10 rl10b rl23 rl23b and tp7 tp9 tp11a tp15 tp15b unedited. Run three times by the main agent; the first failed rl23b (the 60 s timeout also covered the AuthEnv lock wait), fixed, then green. Reviews: code-review=SHIP, security=CLEAR, adversarial=PASS on recheck, qa=VERIFIED.
Evidence limit: rl10b and the rl10/rl10b timeout change were never observed red (see `evidence/tdd-slice-6.md`).

## Limits
- C97, accepted by the user: an in-flight request runs to the 3 s request timeout before the 5 s drain deadline starts, so shutdown against a hung collector takes at most about 8 s (shorter than the ~7 s ladder plus drain before the hold). Counting stays exact (266 of 266). No code change; slice 7 documents it in `docs/operations.md`.
- Security MINOR: an indefinitely failing collector receives the credential every 2 s until shutdown, inherent to hold-not-drop.
- Slice 7 also documents the persistent held-body addend (one serialized batch outside the queue budget, C29/C31).

## Next
Slice 7: the bench, the published numbers, and the final default budget literal.

## Recommendation
Continue to slice 7. All four slice-6 acceptance rows are witnessed and the one adversarial finding is accepted and carried to a documentary deliverable.

Status: Gates 1-4 approved; slices 1-6 complete; slice 7 pending.
Sources: 00-status.md (slice 6 proof line); evidence/slice-6.md; evidence/tdd-slice-6.md; 04-slices.md (slice 6 row, Slice 6 interfaces, C97)
Continue to slice 7, or re-steer?
