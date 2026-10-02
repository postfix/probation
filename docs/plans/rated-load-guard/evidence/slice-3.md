# Slice 3 evidence — all eight loss sites account through `SinkCounters::lose`

Date: 2026-09-25. Git base `734d22d` plus the working tree (slices 1-2 uncommitted).

## Diff summary

- `src/delivery/counters.rs` (new): `SinkCounters { window, total }`, fields private; `pub(super)` `new`, `lose`, `take_window`, `total`.
- `src/delivery/mod.rs`: `mod counters;`, `Sink.drops` -> `Sink.counters: Arc<SinkCounters>`, `Sinks::drops` uses `take_window()`, new `Sinks::lost_total()`, `Sink::push` calls `lose(1)`. Tests `rl7` (queue-full) and `rl8`.
- `src/delivery/file.rs`: four loss sites call `counters.lose(n)`; `tp19` retyped; three `rl7` tests.
- `src/delivery/siem.rs`: three sites plus the eighth (serialize-failure branch, first counter) call `lose`; new test module with two `rl7` tests.
- `src/lib.rs`: `#[cfg(feature = "test-support")] App::delivery_lost_total`.
- `tests/decision_log_delivery.rs`: `rl9`.

Subject hashes: counters.rs `8b401c2b`, file.rs `f5fbd4ca`, mod.rs `2795b2d3`, siem.rs `4daafef2`, lib.rs `1b9eef65`, decision_log_delivery.rs `80c3e180`.

## Direct witness (run by the main agent)

- `cargo check --all-targets` -> exit 0 (`Finished dev profile`).
- `cargo test --lib --test decision_log_delivery` -> lib `test result: ok. 94 passed; 0 failed`; integration `test result: ok. 21 passed; 0 failed` (92.53 s, `rl9` ~90 s of it). Includes `rl7_*` (six), `rl8_the_second_window_reports_only_its_own_losses`, `rl9_the_monotonic_total_is_never_reset`, `tp19_file_drain_deadline_counts_cut_off_records`.
- C82 compile-time half: engineering saw `E0616 field window of struct SinkCounters is private` on a raw `counters.window.fetch_add` in `file.rs`, reverted; `sf-verification` re-witnessed it in a scratch copy: `error[E0616]: field 'window' of struct 'SinkCounters' is private --> src/delivery/file.rs:105:22`.
- `rl11` structural: `src/delivery/siem.rs` `send()` `else { counters.lose(1); }` (~:126-128).

## tdd lines

See `evidence/tdd-slice-3.md` (`rl9` red E0599 then green; `rl8` and six `rl7` tests are regression guards, each mutated red and restored; `tp19`, `rl11`, `C82`).

## Review verdicts

- code-review: SHIP. No blocking findings. MINOR 1: `siem.rs:71` `None => break` drops a partial batch uncounted; no production path found (last `App` dropped only after the task joins). MINOR 2: `siem.rs:120-136` serialize failure counts 1, then `Unsent::drop` counts the whole batch again; unreachable (`Decision` cannot fail serde). Neither fixed.
- adversarial: PASS. No defects; attacks on the eight sites' counts, `window`/`total` divergence, field reach, overflow and feature gating all held.
- qa (sf-verification): VERIFIED. Structural claims are Manual tier because the SMTC index was `not_built`; compile and test claims are Decision tier.

## Limitations carried forward

- `rl7`/`rl8` read `take_window()`/`drops()`, not `dropped_file`/`dropped_siem` off a delivered summary record; `tp7` and `rl1` cover that end to end for the queue-full site.
- `rl9` sets the process-global `set_summary_window(100ms)` and restores 60 s; safe today because SIEM-sink tests serialise on `SIEM_AUTH_LOCK`. It takes ~90 s.
- The write-error `rl7` test uses `/dev/full` (Linux only).
- The `Unsent::drop` test builds `Unsent` directly, not through `send`.
- The full `cargo test` suite was not run in this slice; `rl21` belongs to slice 7.
- The two MINOR findings above stay open as unreachable-branch notes.
