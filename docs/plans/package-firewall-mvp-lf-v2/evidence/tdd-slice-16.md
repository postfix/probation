# Slice 16 (FIX-16-A) TDD record (complete)

Finding: at HEAD 6c4b7fc the prototype gate already existed in src/managed/service_policy.rs; baseline red evidence is in baseline-slice-16.md. Delivered: gate moved to src/managed/publication_gate.rs (service_policy.rs re-exports it), respond_order, osv_generation (C1029), barrier/poison/pending-writer tests, wiring in artifacts/mod.rs + stream.rs.

tdd: osv::tests::generation_advances_only_on_a_new_match | red: compile error E0599 no method `generation` on OsvCache | green: 24/24 osv lib tests pass after OsvCache.generation + bump in put (matched && no live match)
tdd: publication_gate::tests::{osv_generation_change_refuses_before_release, respond_order_refuses_after_publication_and_when_poisoned, final_boundary_barrier_drives_cross_thread_publication, pending_writer_does_not_deadlock_read_or_handoff} | red: compile errors E0425/E0599 (respond_order, AuthorityReceipt::new, with_osv, with_receipt, is_poisoned, set_barrier missing) | green: 5 new gate tests + 2 moved pass in the standalone module (7/7); wired afterwards

tdd: tests/managed_release_wiring.rs (6 tests) | red: mutation dropping `authority.with_osv(..)` in src/artifacts/mod.rs makes osv_flip_after_prepare_refuses_cold_and_warm_all_methods FAIL (file restored, cmp identical) | green: 6/6 pass with real wiring
tdd: osv::tests::a_failed_lookup_fails_open_and_caches_nothing | red: left 1 right 2 (failure was cached, OSV asked once) | green: passes after removing failure writes in check and batcher; 31/31 osv lib tests
