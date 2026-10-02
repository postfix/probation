# Slice 1 evidence — tracer bullet: operator-sized delivery queues

Outcome delivered: an operator writes `siem_queue_max_bytes` (or `log_queue_max_bytes`) in their
TOML, the process starts, and that sink's queue holds `budget ÷ BYTES_PER_RECORD` records instead
of the fixed 4096 — while a budget too small, too large, or set without its sink is refused at
config load with the key named.

## Diff summary

Against base `734d22d` on branch `package-firewall-mvp`, 529 insertions and 8 deletions:

```
 Cargo.lock                     |  77 +
 Cargo.toml                     |   4 +
 config.sample.toml             |  12 +
 src/config.rs                  |  78 +
 src/delivery/mod.rs            | 168 ++-
 tests/config_validation.rs     | 131 +
 tests/decision_log_delivery.rs |  67 +-
```

Plus `proptest-regressions/delivery/mod.txt`, staged and uncommitted, holding `rl6`'s shrunk
counterexample replay seed.

- `src/delivery/mod.rs` — `FIELD_CEILING_BYTES`, `BYTES_PER_RECORD`, `DEFAULT_QUEUE_MAX_BYTES`,
  `MAX_QUEUE_MAX_BYTES`, `MAX_SAFE_CAPACITY`, `CapacityError`, `capacity_for`; both
  `mpsc::channel` sites size from the budget; `const QUEUE_CAPACITY` deleted; new
  `#[cfg(test)] mod tests` holding `rl6`. `Sinks::offer`, `Sink::push`, `Sinks::drops` and
  `build`'s signature unchanged.
- `src/config.rs` — two `RawConfig` fields, two `Config` fields (`NonZeroU64`), two
  `OPTIONAL_KEYS` entries, a `queue_budget` helper carrying all four rejection rules, both fields
  in the `Ok(Config { … })` literal. Imports `delivery` rather than restating any number, and
  derives its lower bound by calling `capacity_for`, so the refusal and the division cannot
  disagree.
- `config.sample.toml` — both keys commented out beside their sink's other keys (C71); the parsed
  key count stays 17 and the deletion sweep is untouched.
- `tests/config_validation.rs` — `rl2`–`rl5`.
- `tests/decision_log_delivery.rs` — `rl1` added; `tp7` amended to pin its own small
  `siem_queue_max_bytes` (C41). No other existing test edited.
- `Cargo.toml` — `proptest = "1.11.0"` as the third dev-dependency, matching the lock.

## Witness

Command, run by the main agent, not only by Engineering:

```
cargo check --all-targets
cargo test --lib --test config_validation --test decision_log_delivery
```

Observed:

```
=== check exit: 0 ===
test result: ok. 85 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
=== test exit: 0 ===
```

All six rows ran: `rl1` in the delivery suite, `rl2`–`rl5` in `config_validation`, and
`delivery::tests::rl6_no_budget_panics_or_yields_a_bad_capacity` under `--lib`.

**Stage limit cleared.** The five existing tests the plan predicted green from reading bytes
rather than from a run — `tp7`, `tp9`, `tp11a`, `tp15`, `tp15b` — all ran and all passed. Only
`tp7` was edited, as C41 requires. No design question arose from this limb.

## TDD lines

Copied from `evidence/tdd-slice-1.md`:

```text
tdd: rl6_no_budget_panics_or_yields_a_bad_capacity — red: Test failed: not yet implemented: capacity_for. minimal failing input: budget = 0 (proptest-regressions/delivery/mod.txt: cc ad401550571791245a9d03ac27d014e6d816ada0684a0ac18aabf3c1ff3f502e # shrinks to budget = 0) — green: cargo test --lib passed
tdd: rl5_absent_budgets_take_the_default — red: assertion `left == right` failed: the shipped default is a memory budget, the same shape as cache_max_bytes / left: 1 / right: 67108864 — green: cargo test --test config_validation passed
tdd: rl2_budget_below_one_record_is_refused — red: the refusal names the key an operator can fix, got `unknown key `log_queue_max_bytes`` — green: cargo test --test config_validation passed
tdd: rl3_budget_above_the_ceiling_is_refused — red: five gibibytes of queue for one sink is refused: Config { … log_queue_max_bytes: 5368709120 … } — green: cargo test --test config_validation passed
tdd: rl4_budget_without_its_sink_is_refused — red: a queue budget with no collector to feed is refused: Config { … siem_url: None, … siem_queue_max_bytes: 1048576 } — green: cargo test --test config_validation passed
tdd: rl1_queue_capacity_follows_the_budget — red: a budget of eight records overflows within 512 requests; a queue still sized at a fixed 4096 would report none of it: [Object {… "dropped_file": Number(0), "dropped_siem": Number(0), "requests": Number(512) …}] — green: cargo test --test decision_log_delivery passed
```

## Review verdicts

The slice row names two reviews. Both ran three times against fresh isolated subagents.

| Round | code-review | security |
|---|---|---|
| 1 | SHIP, 3 MINOR | FIX FIRST, 4 MINOR |
| 2 | FIX FIRST, 2 MINOR | FIX FIRST, 1 MINOR |
| 3 | FIX FIRST, 1 MINOR | FIX FIRST, 1 MINOR |

No round produced a BLOCKER or a MAJOR. Every finding across all three rounds was
comment-accuracy on shipped constants, one manifest version, and one untracked file — no
behavioural or correctness defect was found in any round.

**Verified sound and not reopened**, across the rounds: `capacity_for` takes `u64`, is total, and
uses `usize::try_from` rather than `as usize`; `MAX_SAFE_CAPACITY` is correct against tokio
1.53.1's own asserts; `src/config.rs` duplicates no constant; default-when-absent and
refused-without-its-sink are independent rules; `QUEUE_CAPACITY` has no remaining reference;
`build`'s signature is unchanged with exactly three `capacity_for` call sites; both sample keys
are commented out; `tests/decision_log_delivery.rs` carries exactly the two allowed changes; and
the tests are not tautological — `rl1`'s red shows `dropped_siem: 0` over 512 requests, which is
the old 4096-record queue absorbing everything.

**Findings resolved:**

- The `method` derivation row, the 8 GiB resident-queue claim and its test-doc echo were stated
  in the present tense while `Decision.method` is unbounded until slice 2. All now conditioned on
  slice 2. Code review measured the gap on the running binary: a 415,000-byte method token was
  accepted and produced a record whose `method` field was 12.7× `BYTES_PER_RECORD`, offered to
  both queues. Root cause is hyper 1.11.1's 417,792-byte head buffer plus `http::Method`'s
  unbounded extension arm.
- The `DEFAULT_QUEUE_MAX_BYTES` band contradicted its own formula. Rederived from the shipped
  constants and independently verified: 1.831 GiB at 200 rps, 0.92–3.66 GiB across 100–400 rps,
  ceiling crossing at 436.9 rps.
- `Decision`'s `&'static str` count corrected from two to three.
- The const assert restated a literal instead of reading the struct. It now reads
  `size_of::<Decision>() as u64`, and a second tight assert `size_of::<Decision>() <= 256` was
  added. Verified live by positive control: `<= 240` compiles, `<= 239` produces `E0080`.
- `proptest` manifest version aligned with the lock at 1.11.0.
- `proptest-regressions/delivery/mod.txt` staged, so the replay evidence ships.

**Accepted, not fixed.** Security F1: `capacity_for(...).expect("config validated")` at both
`build` sites encodes its precondition as a convention rather than a type, so a library consumer
hand-building a `Config` would abort instead of receiving a `StartupError`. This is the approved
design — `03-program-design.md` `#### delivery::build` specifies that exact expression and records
that the `Err` arms are unreachable from a validated `Config` — and it is not operator-reachable
in the shipped binary, whose only `Config` constructor is `Config::load` (`src/main.rs:123`). The
round-3 security auditor independently agreed with the acceptance.

**Round 3 closed without a fourth review, deliberately.** Both round-3 findings were the same
item: the tight assert's comment claimed "one added field of any kind trips this", which is false
because the 256-byte allowance leaves 16 bytes of slack and the struct has 5 bytes of tail
padding. Security measured the class on a field-identical replica — `+bool` 240, `+u64` 248,
`+Box<str>` / `+Arc<str>` / `+&'static str` 256, all passing; only `+String` at 264 trips — and
code review confirmed the padding figure with `-Zprint-type-sizes` on the real crate. Both
prescribed the same correction, which was applied verbatim. The router's loop check raised
`security -> engineering : rework x3` at this point. Per the playbook's rule that a third round of
findings naming no decision is where reviewing stops, the prescribed text was applied and the
paragraph closed rather than dispatched for a fourth round on the same sentence. The correction is
the reviewers' own measured wording, so a further review of it would be reviewing their own text.

## Temporary artifacts carried forward

`DEFAULT_QUEUE_MAX_BYTES` remains the provisional 64 MiB literal (C76); slice 7 replaces it. Until
slice 2 lands, `Decision.method` is unbounded, so a queue may hold more resident bytes than the
operator's budget states (C77) — measured above at 12.7× per record in the worst case observed.
No budget number is published before slice 7.

## Open question this slice produced, for the user

Slice 1 was named as the first slice to produce a real `BYTES_PER_RECORD`. It came out **32 KiB**,
against the roughly 1 KiB per record Gate 4 assumed when it wrote C76. Three consequences, none
resolvable by a reviewer:

1. **The derivation may be 4× too conservative.** `FIELD_CEILING_BYTES` implements C44 faithfully
   as `256 chars × 4 UTF-8 bytes × 10-byte escape expansion + 2`. Those are alternatives per
   character, not factors: `\u{10ffff}` is ten bytes *instead of* four. The honest ceiling is
   `256 × 10 + 2 = 2562`, which would put `BYTES_PER_RECORD` near 16 KiB. Changing it is a Gate 3
   change to C44, and C80 pins the constant as final from this slice because slice 4 derives its
   `B` from it.
2. **The provisional default is smaller than what it replaces.** 64 MiB ÷ 32 KiB = 2048 records
   ≈ 10 s of collector outage at 200 rps, against ~20 s from the fixed 4096-record queue. Approved
   C12 requires the default be materially longer than today's ~20 s. Halving `BYTES_PER_RECORD`
   restores parity but does not improve on it.
3. **The default-sizing rule collides with the ceiling.** C13's five-minute formula exceeds the
   4 GiB per-sink `MAX_QUEUE_MAX_BYTES` above roughly 437 rps, so the two rules are compatible over
   a narrower range of rated figures than Gate 3 assumed.
