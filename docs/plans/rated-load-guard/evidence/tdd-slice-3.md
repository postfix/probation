tdd: rl9 | red: E0599 no method `delivery_lost_total` on Arc<App> | green: rl9_the_monotonic_total_is_never_reset ok | src/lib.rs, src/delivery/{counters,mod,file,siem}.rs
tdd: rl11 | structural, no test: src/delivery/siem.rs send() `else { counters.lose(1); }` in the batch.drain loop
tdd: tp19 | retyped in place: SinkCounters::new(), &counters, counters.total() | ok
tdd: C82 | raw counters.window.fetch_add in file.rs -> E0616 field `window` of struct `SinkCounters` is private; reverted, cargo check --all-targets exit 0
tdd: rl8 | rl8_the_second_window_reports_only_its_own_losses (src/delivery/mod.rs tests) | regression guard, passes against the pre-change path | mutation: take_window uses load instead of swap(0) -> red `left: 4, right: 1` (not 4: first window was reset); restored
tdd: rl7 | six in-crate tests, regression guard, pass against the pre-change path; each mutated by deleting its one `lose` call, red, restored:
tdd: rl7 mod.rs push | rl7_queue_full_counts_in_the_window | mutation: no lose in push -> left 0, right 1
tdd: rl7 file drain deadline | rl7_file_drain_deadline_counts_in_the_window | mutation: no lose at the drain cut -> `counters.take_window() > 0` failed
tdd: rl7 file write error | rl7_file_write_error_counts_in_the_window (/dev/full) | mutation -> left 0, right 1
tdd: rl7 file unopenable | rl7_file_unopenable_counts_in_the_window | mutation -> left 0, right 1
tdd: rl7 siem drain deadline | rl7_siem_drain_deadline_and_unsent_count_in_the_window (silent TCP collector, 300 queued) | mutation: no lose at the deadline site -> left 256, right 300
tdd: rl7 siem Unsent::drop | rl7_unsent_counts_an_undelivered_batch (Unsent driven directly, not through send) | mutation -> left 0, right 5
