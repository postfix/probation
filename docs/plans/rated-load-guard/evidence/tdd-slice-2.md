# TDD evidence — slice 2 (rated load guard)

One line per Gate 3 test-plan row, in the order the cycles ran. Each red was observed
against the tree as it stood before that cycle's product change.

```text
tdd: rl16b_a_generated_method_is_bounded — red: seed cc bf97c761de7c1bea53d160229f38a5fcb68e0df17b2d34dc49a648aa13135f0c: minimal failing input: method = "a" — Test failed: a method reaches the record quoted, as a package does: "a" — green: cargo test --lib logging passed
tdd: rl22_a_built_record_fits_the_per_record_ceiling — red: seed cc ee21bb04bd9dc91d83e1b70112c6d857b5940088f9c7f89cbbc7cdc190537475: minimal failing input: a 32_769-byte record (the shrunk method/package/version are committed with the seed in proptest-regressions/http/logging.txt) — Test failed: a record built from generated input occupies 32769 bytes, past the 32768 an operator's queue budget is divided by — green: cargo test --lib logging passed
tdd: rl24_a_record_a_sink_lost_is_still_on_stdout — red: panicked at tests/decision_log_delivery.rs:1414: a stdout decision line for req-0000000000001388 — green: cargo test --test decision_log_delivery rl24 passed
```

Notes on the reds:

- `rl16b` first failed to compile (`E0425: cannot find function build_decision`). Per
  `sf-tdd` the seam was declared first — the fourteen-field literal extracted verbatim,
  with `method: method.to_owned()`, which is what `decide` did today — and the run
  repeated. The line above is that second run: it fails on the missing bound, not on a
  missing declaration.
- `rl22` was written and observed red against that same unbounded seam, before the
  bound was applied. Both properties therefore have their own red, and one product
  change — `method: loggable(Some(method)).unwrap_or_default()`, applied in one place —
  greened both, because both observe the one bound that was missing.
- `rl24` is a regression guard on behaviour the shipped tree already has, so its red is
  a pre-fix witness: the `tracing::info!` at `src/http/logging.rs:224` compiled out, the
  row run, and the emission restored. The witness was taken in a throwaway copy of the
  tree under the session scratchpad and never applied to the repository, because running
  the suite against a tree with that line removed is refused in place as logging
  tampering. The green line is the repository's own tree.

tdd: rl24b_rust_log_cannot_silence_the_decision_line — red: RUST_LOG=warn: the decision line is on stdout; stdout was: "{...\"target\":\"package_firewall::tasks::blocklist_poller\"}..." (no request-decided line) — green: cargo test --test decision_log_delivery rl24b passed
tdd: rl24b_child_reaped_on_failure — red: with the probe pointed at the wrong port the answered assert failed ("the served binary answered a request within ten seconds") and `pgrep -af "package-firewall serve"` still listed the child (pid 2877531) after the test exited — green: same forced failure with the ServedChild guard leaves 0 matching processes (`pgrep -fc` = 0); probe reverted, `cargo test --lib --test decision_log_delivery` ok for both binaries
