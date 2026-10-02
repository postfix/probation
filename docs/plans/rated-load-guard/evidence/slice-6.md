# Slice 6 evidence: the SIEM sink holds its batch

## Diff summary
- `src/delivery/siem.rs`: `send` gains `drain: &CancellationToken`; all four call sites pass `&drain`. Retryable failures (5xx, 429, transport) retry with the interval capped at the last `BACKOFF` entry (2 s); the backoff sleep is `select!`ed against `drain.cancelled()` and returns without a further attempt, leaving `Unsent` armed. 302/400/401/403 still discard and count immediately. Module header reworded (the ladder is no longer finite).
- `tests/decision_log_delivery.rs`: `prompt_503_collector()`, `decided_ids_received()`, `rl10`, `rl10b`, `rl23`, `rl23b`. `AuthEnv` is taken before each test's timeout so the timeout does not cover the lock wait.

## Witness
`cargo check --all-targets` exit 0; `cargo test --test decision_log_delivery`: 31 passed, 0 failed (~86 s), including rl10, rl10b, rl23, rl23b and tp7, tp9, tp11a, tp15, tp15b. Main-agent run, three times; the first run failed rl23b (lock wait inside its timeout), fixed and rerun green.

## tdd lines
See `evidence/tdd-slice-6.md` (six lines).

## Review verdicts
- code-review: SHIP. MINOR: header comment stale (fixed); serialize-failure double count is unreachable and belongs to slice 3's site.
- security: CLEAR. No unmodeled surface. MINOR: an indefinitely failing collector receives the credential every 2 s until shutdown, inherent to hold-not-drop.
- adversarial: PASS on recheck. First run FIX (an in-flight request overruns the 5 s drain deadline by up to 3 s), accepted by the user as C97, no code change.
- qa (sf-verification): VERIFIED.

## Carried to slice 7 (documentary, C97)
`docs/operations.md` states: shutdown against a hung collector is bounded by the 3 s request timeout plus the 5 s drain deadline, at most about 8 s; and the persistent held-body addend (one serialized batch outside the queue budget, C29/C31).
