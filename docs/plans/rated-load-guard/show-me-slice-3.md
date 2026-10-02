## Delivered

All eight loss sites now count through one call, `SinkCounters::lose`, which advances a summary `window` and a monotonic `total`. Both fields are private to `src/delivery/counters.rs`. Signatures are unchanged for `Sink::push`, `Sinks::drops` and `delivery::build`; the only new public item is the `test-support`-gated `App::delivery_lost_total`.

```diff
+ src/delivery/counters.rs   SinkCounters { window, total } private;
+                            pub(super) new, lose, take_window, total
  src/delivery/mod.rs        mod counters;  Sink.drops -> Sink.counters: Arc<SinkCounters>
                             Sinks::drops uses take_window();  + Sinks::lost_total()
  src/delivery/file.rs       four sites -> counters.lose(n); tp19 retyped (SinkCounters::new(), counters.total())
  src/delivery/siem.rs       three sites + the eighth (serialize-failure branch, first counter) -> lose
  src/lib.rs                 + #[cfg(feature = "test-support")] App::delivery_lost_total
  tests/decision_log_delivery.rs  + rl9
```

## Proof

- Compiler refuses a bypass (C82) -> raw `counters.window.fetch_add` in `src/delivery/file.rs`, then reverted -> `error[E0616]: field 'window' of struct 'SinkCounters' is private --> src/delivery/file.rs:105:22` (re-witnessed by sf-verification in a scratch copy).
- Monotonic total (`rl9`) -> red `E0599 no method delivery_lost_total on Arc<App>`, now `rl9_the_monotonic_total_is_never_reset` ok.
- Counts unchanged (`rl7` x6, `rl8`) -> regression guards that pass against the pre-change path, not new evidence. Each was mutated red (for example `no lose in push -> left 0, right 1`; `take_window uses load instead of swap(0) -> left: 4, right: 1`) and restored.
- `tp19` retyped in place, ok. `rl11` is structural: `siem.rs` `send()` `else { counters.lose(1); }` (~:126-128).
- Commands: `cargo check --all-targets` -> exit 0. `cargo test --lib --test decision_log_delivery` -> lib `ok. 94 passed; 0 failed`; integration `ok. 21 passed; 0 failed` (92.53 s, `rl9` ~90 s).
- Reviews: code-review=SHIP, adversarial=PASS, qa=VERIFIED (structural claims Manual tier: SMTC index `not_built`).

## Limits

- Two MINOR code-review findings left open, both unreachable in production: `siem.rs:71` `None => break` drops a partial batch uncounted; `siem.rs:120-136` serialize failure counts 1, then `Unsent::drop` counts the batch again.
- `rl7`/`rl8` read `take_window()`/`drops()`, not a delivered summary record; `tp7` and `rl1` cover that end to end for the queue-full site.
- `rl9` takes ~90 s and sets the process-global summary window (100ms, restored to 60 s); safe today because SIEM-sink tests serialise on `SIEM_AUTH_LOCK`.
- The write-error `rl7` test uses `/dev/full` (Linux only); the `Unsent::drop` test builds `Unsent` directly, not through `send`.
- Full `cargo test` not run here; `rl21` belongs to slice 7.
- The compile-time half rests on the E0616 negative control, not on a green build.

## Next

Slice 4: the closed-loop load driver and the `cargo test` floor. It reads `App::delivery_lost_total` after shutdown. Slices 4-7 are pending.

## Recommendation

Continue to slice 4: no blocking review finding, both open findings are unreachable, and slice 4 depends on the accessor this slice delivered.

Status: slice 3 of 7 complete; Gates 1-4 approved; slices 1-3 done.
Sources: docs/plans/rated-load-guard/04-slices.md (row 3, Slice 3 interfaces), evidence/slice-3.md, evidence/tdd-slice-3.md, 00-status.md
Continue to slice 4, or re-steer?
