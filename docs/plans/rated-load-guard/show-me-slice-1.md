# Slice 1 complete — operator-sized delivery queues

## Delivered

An operator writes `siem_queue_max_bytes` (or `log_queue_max_bytes`) in their TOML, the process
starts, and that sink's queue holds `budget ÷ BYTES_PER_RECORD` records instead of the fixed 4096 —
while a budget too small, too large, or set without its sink is refused at config load with the key
named.

529 insertions, 8 deletions against base `734d22d`:

```
 Cargo.lock                     |  77 +
 Cargo.toml                     |   4 +
 config.sample.toml             |  12 +
 src/config.rs                  |  78 +
 src/delivery/mod.rs            | 168 ++-
 tests/config_validation.rs     | 131 +
 tests/decision_log_delivery.rs |  67 +-
```

Plus `proptest-regressions/delivery/mod.txt`, holding `rl6`'s shrunk counterexample replay seed.

- `src/delivery/mod.rs` — `FIELD_CEILING_BYTES`, `BYTES_PER_RECORD`, `DEFAULT_QUEUE_MAX_BYTES`,
  `MAX_QUEUE_MAX_BYTES`, `MAX_SAFE_CAPACITY`, `CapacityError`, `capacity_for`; both `mpsc::channel`
  sites size from the budget; `const QUEUE_CAPACITY` deleted.
- `src/config.rs` — two `RawConfig` fields, two `Config` fields (`NonZeroU64`), two `OPTIONAL_KEYS`
  entries, a `queue_budget` helper carrying all four rejection rules. It imports `delivery` rather
  than restating any number, and derives its lower bound by calling `capacity_for`, so the refusal
  and the division cannot disagree.
- `config.sample.toml` — both keys commented out (C71); the parsed key count stays 17.
- Tests: `rl2`–`rl5` in `tests/config_validation.rs`, `rl1` in `tests/decision_log_delivery.rs`,
  `rl6` in a new in-crate `#[cfg(test)]` module. `tp7` amended to pin its own small budget (C41);
  no other existing test edited.

**Signatures unchanged**: `Sinks::offer`, `Sink::push`, `Sinks::drops` and `delivery::build`.

**And the number this slice existed to produce**: `BYTES_PER_RECORD` came out **32 KiB**, against the
roughly 1 KiB per record Gate 4 assumed when it wrote C76. That is the substantive news, and what
the question below is about.

## Proof

Promise: a budget-sized queue overflows at the budget's capacity, not at 4096. Witness, run by the
main agent and not only by Engineering:

```
cargo check --all-targets                                                → exit 0
cargo test --lib --test config_validation --test decision_log_delivery
  test result: ok. 85 passed; 0 failed    (--lib, incl. rl6)
  test result: ok. 25 passed; 0 failed    (config_validation, rl2–rl5)
  test result: ok. 18 passed; 0 failed    (decision_log_delivery, rl1 + amended tp7)
```

Each row was red first. `rl1`'s red is the discriminating one: a budget of eight records overflowed
within 512 requests, and the old fixed queue reported `"dropped_file": 0, "dropped_siem": 0` over
those same 512 — so the test is not tautological. Full red lines in `evidence/tdd-slice-1.md`.

**Stage limit cleared.** The five tests the plan predicted green from reading bytes — `tp7`, `tp9`,
`tp11a`, `tp15`, `tp15b` — all ran and all passed. No design question arose from that limb.

**Reviews: no behavioural defect in any round.** code-review said SHIP at round 1; three rounds ran
in total; every finding in every round was comment accuracy on shipped constants, one manifest
version and one untracked file. No BLOCKER, no MAJOR. All findings were applied. Stated honestly:
round 3 was closed by applying the two reviewers' own prescribed wording *without* a fourth review
round, after the router's loop check raised `security -> engineering : rework x3`. One security
finding (F1) was accepted and not fixed, as the approved design in `03-program-design.md` specifies.

## Limits

`BYTES_PER_RECORD` at 32 KiB has three consequences, none of them resolvable by a reviewer, and all
three are the user's decision:

1. **The derivation may be 4× too conservative.** `FIELD_CEILING_BYTES` implements C44 faithfully as
   `256 chars × 4 UTF-8 bytes × 10-byte escape expansion + 2` = 10242. But those are alternatives per
   character, not factors: `\u{10ffff}` is ten bytes *instead of* four, not ten times four. The
   honest ceiling is `256 × 10 + 2` = **2562**, which would put `BYTES_PER_RECORD` near 16 KiB.
   Changing it is a Gate 3 change to C44 — and C80 pins the constant as final from this slice,
   because slice 4 derives its `B` from it.
2. **The provisional default is smaller than what it replaces.** 64 MiB ÷ 32 KiB = 2048 records
   ≈ **10 s** of collector outage at 200 rps, against **~20 s** from the fixed 4096-record queue.
   Approved C12 requires the default be materially *longer* than today's ~20 s. Halving
   `BYTES_PER_RECORD` restores parity but does not improve on it.
3. **The default-sizing rule collides with the ceiling.** C13's five-minute formula lands at
   1.831 GiB at 200 rps and 0.92–3.66 GiB across 100–400 rps, crossing the 4 GiB per-sink
   `MAX_QUEUE_MAX_BYTES` at **436.9 rps** — so the two rules are compatible over a narrower range of
   rated figures than Gate 3 assumed.

Carried forward as planned: `DEFAULT_QUEUE_MAX_BYTES` stays the provisional 64 MiB literal until
slice 7 replaces it (C76). Until slice 2 lands, `Decision.method` is unbounded, so a queue may hold
more resident bytes than the operator's budget states (C77) — code review measured a 415,000-byte
method token producing a `method` field 12.7× `BYTES_PER_RECORD`, root-caused to hyper 1.11.1's
417,792-byte head buffer. No budget number is published before slice 7.

## Next

Slice 2 of 7: bound every record's `method` with the same `loggable` idiom the other target fields
use, so `BYTES_PER_RECORD` becomes a real ceiling rather than a mean — which closes C77. Slices 2–7
are pending. Consequence 1 above, if acted on, is a Gate 3 reopening and lands *before* slice 4
rather than after it.

## Recommendation

The slice itself is complete, witnessed and sound; nothing in the work warrants a re-steer. What
happens next is not decided by this result: the three sizing consequences are the user's call, and
this presentation does not pick among them. Note only that consequence 1 has a deadline — C80 makes
`BYTES_PER_RECORD` final from this slice because slice 4 computes its `B` from it.

Gate 4 approved; slice 1 of 7 complete with its proof line recorded in `00-status.md`; slices 2–7
pending.

Sources: `evidence/slice-1.md` (diff, witness, review verdicts, open question);
`evidence/tdd-slice-1.md` (red/green lines); `04-slices.md` slice 1 row and `### Slice 1 interfaces`
(C41, C44, C71, C76, C77, C80); `00-status.md`.

Slice 1 is complete and witnessed, and `BYTES_PER_RECORD` came out 32 KiB against the ~1 KiB Gate 4 assumed — which leaves the provisional default holding ~10 s of collector outage where today's fixed queue holds ~20 s: do you want to continue to slice 2 and leave all three sizing consequences to slice 7, correct C44's derivation now by reopening Gate 3, or raise the provisional default now so the interim default is not a regression?
