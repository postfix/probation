# Slice 2 evidence — every record's `method` bounded; RUST_LOG pin

## Diff summary
- `src/http/logging.rs`: new pure `build_decision`, applies `loggable` to `method` once (C63, C69); `decide` calls it and still emits `tracing::info!` before `offer` (C78). Landed in the first pass of this slice (rl16b, rl22, rl24).
- `src/main.rs`: `.add_directive("package_firewall::http::logging=info".parse().expect("static directive"))` appended to the console `EnvFilter` (C87, closes G3-T9). No other edit.
- `tests/decision_log_delivery.rs`: `rl24`; `rl24b` plus helper `serve_once_with_rust_log` and a `ServedChild` kill-on-drop guard (added after review).
- `docs/operations.md`: the decision-line sample's `"method":"GET"` is now `"method":"\"GET\""`, confirmed against a real line from the built binary.
- `proptest-regressions/http/logging.txt`: seeds for rl16b and rl22.

## Direct witness (run by the main agent, final bytes)
- `cargo check --all-targets` → exit 0, no warnings.
- `cargo test --lib --test decision_log_delivery` → `test result: ok. 87 passed` (lib) and `test result: ok. 20 passed` (integration); rl16b, rl22, rl24, rl24b `ok`.
- `pgrep -fc '^…/target/debug/package-firewall serve'` → 0 after the run.

## TDD lines
See `evidence/tdd-slice-2.md` (rl16b, rl22, rl24, rl24b, rl24b_child_reaped_on_failure), one per cycle with its observed red.

## Review verdicts
- code-review: SHIP (one MINOR: rl24b leaked the served child on a failed assert) → fixed with `ServedChild`; fresh re-review of the correction: SHIP, no findings.
- security: CLEAR on scopes 1, 2, 4; same MINOR as above, fixed. No unmodeled surface.
- adversarial: PASS. 15 `RUST_LOG` values × with/without file sink, 8 hostile requests each: 7 decision lines on stdout every run, methods bounded to 256 chars + quotes.

## Limitations and notes for the user
- Observation, not a defect against this slice's promise: a request line whose method has a non-ASCII byte is rejected by hyper before the router and produces no decision record. Outside `decide`'s coverage; a separate slice if wanted.
- The quoted `method` is a wire-format change for any SIEM parser matching an unquoted `GET` (slice 7's upgrade note is the place to say so).
- Adversarial ran a debug build on loopback only: no full/closed stdout pipe, slow sink under load, SIEM sink or HTTP/2.
- Stale `unused_mut` diagnostic seen once at `tests/decision_log_delivery.rs:1463`; `cargo check --all-targets` reports no warnings.
- Accepted exceptions unchanged: G3-T10, G3-T11, G3-T13 and the span/field-qualified directive (C88, C90).
