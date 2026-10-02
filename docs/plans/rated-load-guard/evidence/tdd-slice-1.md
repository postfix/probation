# TDD evidence — slice 1 (rated load guard)

One line per Gate 3 test-plan row, in the order the cycles ran. Each red was observed
against the tree as it stood before that cycle's product change.

```text
tdd: rl6_no_budget_panics_or_yields_a_bad_capacity — red: Test failed: not yet implemented: capacity_for. minimal failing input: budget = 0 (proptest-regressions/delivery/mod.txt: cc ad401550571791245a9d03ac27d014e6d816ada0684a0ac18aabf3c1ff3f502e # shrinks to budget = 0) — green: cargo test --lib passed
tdd: rl5_absent_budgets_take_the_default — red: assertion `left == right` failed: the shipped default is a memory budget, the same shape as cache_max_bytes / left: 1 / right: 67108864 — green: cargo test --test config_validation passed
tdd: rl2_budget_below_one_record_is_refused — red: the refusal names the key an operator can fix, got `unknown key `log_queue_max_bytes`` — green: cargo test --test config_validation passed
tdd: rl3_budget_above_the_ceiling_is_refused — red: five gibibytes of queue for one sink is refused: Config { … log_queue_max_bytes: 5368709120 … } — green: cargo test --test config_validation passed
tdd: rl4_budget_without_its_sink_is_refused — red: a queue budget with no collector to feed is refused: Config { … siem_url: None, … siem_queue_max_bytes: 1048576 } — green: cargo test --test config_validation passed
tdd: rl1_queue_capacity_follows_the_budget — red: a budget of eight records overflows within 512 requests; a queue still sized at a fixed 4096 would report none of it: [Object {… "dropped_file": Number(0), "dropped_siem": Number(0), "requests": Number(512) …}] — green: cargo test --test decision_log_delivery passed
```

Notes on the reds:

- `rl6` first failed to compile (`E0425: cannot find function capacity_for`). Per
  `sf-tdd`, the declarations the seam names were added with a `todo!()` body and the
  run repeated; the line above is that second run, and the stub is not green.
- `rl5` first failed to compile (`E0609: no field log_queue_max_bytes on type Config`).
  The two `Config` fields were added with a placeholder value and no default logic,
  and the line above is that second run.
- `rl2`, `rl3`, `rl4` and `rl1` each failed against compiling code, on the behaviour
  the row names rather than on a missing declaration.
