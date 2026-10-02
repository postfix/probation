tdd: rl12 | red: 404 on /health/delivery (no route) | green: rl12_delivery_is_200_when_nothing_is_shed ok (no-sink App and file-sink App with traffic, no loss) | tests/decision_log_delivery.rs
tdd: rl13 | red: left 404, right 503 | green: rl13_delivery_is_503_right_after_a_loss ok (gated SIEM collector, 5000 requests, lost_total > 0) | tests/decision_log_delivery.rs
tdd: rl14 | red: left 404, right 503 | green: rl14_delivery_recovers_after_sixty_quiet_seconds ok (probe 503, collector released and queue drained, +61 s, probe 200) | tests/decision_log_delivery.rs
tdd: rl15 | red: /health/delivery 404, ready 200 | green: rl15_readiness_stays_green_while_delivery_sheds ok (ready 200, delivery 503) | tests/decision_log_delivery.rs
tdd: rl16c | red: left 404, right 503 | green: rl16c_a_backwards_clock_step_does_not_latch_503 ok | also red under mutation `since < SHED_QUIET` (no non-negative bound): left 503, right 200 | tests/decision_log_delivery.rs
tdd: rl25 | red: left 404, right 503 ("shedding" limb) | green: rl25_delivery_has_no_body_and_is_not_cacheable ok (empty body and Cache-Control: no-store in both 503 and 200) | tests/decision_log_delivery.rs
tdd: rl14 lower bound | red under mutation SHED_QUIET = 1 s: left 200, right 503 at +59 s (restored to 60 s) | green: rl14 ok (503 at +59 s, 200 at +61 s) | tests/decision_log_delivery.rs
tdd: rl13/rl15 gate release | not a behaviour change: `gate.send_replace(true)` before `server.shutdown()` so shutdown does not drain against a wedged collector | tests stay green, run time measured below | tests/decision_log_delivery.rs
