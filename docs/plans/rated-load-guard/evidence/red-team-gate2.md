# Red team review — Gate 2, rated-load-guard

Source: sf-red-team, 2026-09-23.

```text
Review kind: red-team
Verdict: NEEDS REVISION
Review: independent
Subject: architecture docs/plans/rated-load-guard/02-architecture.md=72d2c0e495fb650f77c938e45ecebdb1f5b0f610d49955f1b56d3c59ffd7e137; 01-product.md=ebaa8593a9dd505c0f2b153ec04fbfcd86471c42d63f5411c12bcd0f3771f70b; evidence/repository-structure.md=f95a8fa35128c0bf47a1c25b8f9a576a019343c0882b8e66f0337f2b11d10ff4; evidence/threat-model.md=6edf27a4f343d3a6ba819f319030f1a7e65e7ed764f9f4c81a27a84eb64e7413
Bottom line: Three of the plan's load-bearing numbers — the default budget, the outage tolerance, and the CI floor — are derived from a rate that is not the arrival rate, and the headline "survives a collector outage of M minutes" is defeated by the SIEM sink's existing retry-then-drop path that this plan does not touch.
```

Note on subject hashes: these are the document states the reviewer read. `02-architecture.md` has
since been corrected for findings 5, 6 and 7 and re-reviewed; the hash above is the pre-correction
state.

## Findings

**1. BLOCKER · hard bar · C13 + C17 · the default budget computes to GiB, not MiB.**
`5 min × rated rate × BYTES_PER_RECORD`, where the rated rate is `Sinks::offer` measured in
isolation (C17, `## Flow` measurement path) — an in-process `try_send`
(`src/delivery/mod.rs:113-118`) that outruns the real request path by orders of magnitude, because
the per-request `tracing::info!` (`src/http/logging.rs:224`) and the process-global `COUNTERS`
mutex (`:347`) are not in the driver. At any offer rate above ~1,750 rec/s the default exceeds
256 MiB per sink, falsifying C13's own "same family as the existing 256 MiB" and C12's "raise it
modestly". Fix: derive the default from an arrival rate (`max_active_requests`-bounded, or the
Problem section's 200 rps), not from the offer ceiling; publish M against the same rate. This also
answers C2's "operator reads the figure as requests per second" — the offer figure is not that
number.

**2. BLOCKER · coverage · 01-product Success metric (derived) · no budget buys collector-outage
tolerance on the SIEM sink.** With the collector down, `send` retries `BACKOFF`
`[100ms, 500ms, 2s]` then `Unsent::drop` counts the whole batch (`src/delivery/siem.rs:209-213`);
the receiver keeps draining. The queue never accumulates: loss starts at ~7 s and continues
regardless of `siem_queue_max_bytes`. The Problem section's maintenance case and C10's M are
undelivered for the sink they name. Fix: name a hold-the-queue behaviour (stop consuming while the
collector is unreachable) as in-scope, or restrict the published M to the file sink and say so.

**3. BLOCKER · verifiability · C11, Fit row `tests/delivery_rated_load.rs` · the floor test cannot
fail on a collapse.** "Zero drops while offering `F`/s" is absorbed by the queue: with the C13
default the test's total offered records fit in the buffer, so a sink task that is alive but 100×
slow drops nothing and passes — precisely the collapse C3 requires to fail. Second limb: the
architecture never says the driver configures a sink; with `Sinks` empty, `offer` is
`(None, None) => {}` (`src/delivery/mod.rs:141`) and zero drops is vacuous. Third: the driver's
promised `delivered` tally has no source — nothing in `delivery` counts deliveries. Fix: assert
`delivered ≥ F × duration` after draining and joining the sink task, against a named sink.

**4. MAJOR · foundations · C15/C22 · `BYTES_PER_RECORD` has no stated derivation.** T2's
verification property is *serialized* size; C13/C15 use the constant as a *heap* bound. They differ
(`size_of::<Record>()` per queue slot, `String` capacities, `loggable`'s 256-**chars** = up to
1 KiB). C15's "conservative high" admits a mean. Also outside the budget: the SIEM task holds
`batch` (256 records) plus a serialized `body` of the same batch (`src/delivery/siem.rs:113-135`).
Fix: state the derivation and add the batch addend.

**5. MAJOR · security · threat model T3 and T4 · both mitigations are purely documentary and no
deliverable in the architecture carries them.** The docs row of `## Fit` commits
`docs/operations.md`, `config.sample.toml` and `README.md` to publishing exactly four things: the
rated figure, the floor, the default budget and the tolerance. Two required sentences are absent
from that list and from `## Constraints`. First, T3's residual mitigation — that stdout remains the
complete trail and a `503` on `/health/delivery` means the durable sinks are lossy, not the record
stream. The architecture instead carries only the ordering invariant "a record dropped by a sink
must remain on stdout", which preserves the mechanism but tells no operator to capture stdout; the
mitigation is worth nothing to a deployment whose durable trail is the file sink alone, and that is
the default shape a new operator reaches, since `log_file_path` is the first delivery key in the
sample. Second, T4's countermeasure — that `/health/delivery` is an alerting signal and must never
be a load-balancer or Kubernetes readiness or liveness probe target, `/health/ready` being the
probe. C9 chose the name for that reason and the threat model says explicitly that the
documentation has to finish the job the name starts; nothing in this architecture does.
Consequence: the accepted mitigation for a fleet-wide serving outage driven by an unauthenticated
party exists only in the threat model. Smallest fix: add both sentences to the docs row as named
deliverables, at the point `docs/operations.md` introduces the route.

**6. MINOR · security · `## Flow` step 4 · an eighth record-loss site increments no drop counter,
so neither the marker nor T1's verification property can see it.** In `siem::send`, the batch is
serialized under `if let Ok(line) = serde_json::to_string(&record)` inside `batch.drain(..)`
(`src/delivery/siem.rs:113-135`); a record that fails to serialize is discarded there and the
surrounding `Unsent` still reports the batch delivered, so no `fetch_add` runs. The file sink
counts the identical case at `src/delivery/file.rs:105`. T1's stated invariant — no `fetch_add` on
a drop counter without setting the shedding state — is grep-checkable but structurally blind to a
site that has no `fetch_add` at all. Serde failure on `Decision` is close to unreachable, which is
why this is MINOR. Smallest fix: state the invariant as "every site that loses a record", and count
that branch as the file sink already does.

**7. MAJOR · coverage · 01-product Success metric and C1 · no deliverable carries the run's
duration or the reference hardware.** The metric is "zero records lost at N records per second,
sustained for ten minutes, on named reference hardware"; the architecture's bench runs "a fixed
duration" (`## Flow`, measurement path) and the docs row publishes four numbers, none of them the
hardware. A figure from a 10-second run on an unnamed machine satisfies the architecture and not
the product. Smallest fix: name the ten minutes in the bench row and the hardware in the docs row.

## Dispositions for items that produced no finding

**(a) Panicked or exited sink task: HOLDS, and the worry is unfounded.** When a sink task panics or
returns, its `mpsc::Receiver` is dropped and the channel closes. `Sink::push` uses `try_send`,
whose `Err` covers closed as well as full, and both fall into the same branch
(`src/delivery/mod.rs:113-118`, confirmed by the grounding at evidence §2). So the very next
`offer` increments the counter and, under C21, sets the marker. Detection is immediate on the next
served request, and no separate liveness check is needed. The only loss the design still cannot see
is finding 6.

**(b) T3's stdout mitigation under a file-sink-only deployment: DOES NOT survive** — raised as
finding 5, first limb.

**(c) `Sinks::drops()` read-and-reset: HOLDS, no conflict.** The floor test drives its own `Sinks`
built through the `test-support` seam, a different instance from the one `App` holds, so
`close_window` (`src/http/logging.rs:421`) and `flush_drop_tail` (`:400`) cannot steal its counts
and it cannot steal theirs. `drops()` is `pub(crate)` and a `tests/*.rs` binary is an external
consumer, so the tally must be returned by the driver rather than read by the test. One ordering
hazard, folded into finding 3: reading the tally before cancelling drain and joining the task
misses the late sites (`file.rs:75`, `siem.rs:97`, `siem.rs:212`), so a run that lost its whole
tail still reports zero drops.

**(d)** One further undelivered product outcome — raised as finding 7.

VERDICT-LINE: FIX FIRST
