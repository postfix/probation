## Delivered
Every decision record's `method` now goes through `loggable`, once, so `BYTES_PER_RECORD` is a ceiling on a record rather than a mean. `RUST_LOG` can no longer silence the decision line. `decide`'s signature is unchanged, and `tracing::info!` still runs before `offer`.

```diff
 src/http/logging.rs
-  Decision { ...fourteen fields..., method: method.to_owned(), ... }
+  build_decision(...)  // pure; method: loggable(Some(method)).unwrap_or_default()
 src/main.rs                       (EnvFilter, one line)
+  .add_directive("package_firewall::http::logging=info".parse().expect("static directive"))
 docs/operations.md                (decision-line sample)
-  "method":"GET"
+  "method":"\"GET\""
 tests/decision_log_delivery.rs    rl24, rl24b, serve_once_with_rust_log, ServedChild
 proptest-regressions/http/logging.txt   seeds for rl16b, rl22
```

## Proof
- `rl16b` -> proptest -> red: `a method reaches the record quoted, as a package does: "a"`; green.
- `rl22` -> proptest -> red: `a record built from generated input occupies 32769 bytes, past the 32768 an operator's queue budget is divided by`; green.
- `rl24` -> sink-lost record still on the captured INFO stream -> green. It guards existing behaviour, so its red was taken in a throwaway copy with `tracing::info!` removed: `a stdout decision line for req-0000000000001388`.
- `rl24b` -> built binary with a foreign `RUST_LOG` -> red: `RUST_LOG=warn: the decision line is on stdout` (no request-decided line); green.
- `rl24b_child_reaped_on_failure` -> `pgrep -fc` was 0 with the `ServedChild` guard.
- Run by the main agent on the final bytes:
  - `cargo check --all-targets`: exit 0, no warnings.
  - `cargo test --lib --test decision_log_delivery`: `ok. 87 passed` (lib) and `ok. 20 passed` (integration).
- Reviews: code-review SHIP (one MINOR, fixed, re-review SHIP); security CLEAR; adversarial PASS (15 `RUST_LOG` values, 7 decision lines on stdout every run, methods bounded to 256 chars plus quotes).
- Evidence limit: adversarial ran a debug build on loopback only. It did not cover a full or closed stdout pipe, a slow sink under load, the SIEM sink or HTTP/2.

## Limits
- A request line with a non-ASCII method byte is rejected by hyper before the router, so it gets no decision record. It is outside `decide`'s coverage; a separate slice if wanted.
- The quoted `method` is a wire-format change for any SIEM parser matching an unquoted `GET`. Slice 7's upgrade note is the place to say so.
- Accepted exceptions unchanged: G3-T10, G3-T11, G3-T13 and the span- or field-qualified directive (C88, C90).

## Next
Slice 3: all eight loss sites account through `SinkCounters::lose`, plus a monotonic total. Slices 4-7 follow.

## Recommendation
Continue to slice 3. The slice's promise is witnessed with observed reds and a green run, and all three reviews passed. The three limits above are recorded, and none blocks slice 3.

Status: slice 2 complete; proof line recorded in `00-status.md`; slices 3, 4, 5, 6, 7 remain.
Sources: `04-slices.md` row 2 and "Slice 2 interfaces"; `evidence/slice-2.md`; `evidence/tdd-slice-2.md`; `00-status.md`.
Continue to slice 3, or re-steer?
