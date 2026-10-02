# sf-security-review — slice 2 (2026-09-25)

Verdict: **FIX FIRST**. Dispatched after slice 2's witness went green; this review reopened Gate 3.

Subject: `src/http/logging.rs`=2cd850594600c8d587fa34f4cbe0157c45cd9758a85103071c9bb6388f415004,
`tests/decision_log_delivery.rs`=e366bd8c630bb882934ee2054b71685481c79d484e594127d2526f53f9a1b8de,
uncommitted working tree on `package-firewall-mvp`.

## Findings

- **F1 · MAJOR — `RUST_LOG` deletes the audit trail from stdout while the sinks keep delivering.**
  `main.rs:58-63` builds the subscriber from `EnvFilter::try_from_default_env()`. Its `unwrap_or_else`
  fallback fires only when `RUST_LOG` is *unset*; when set, `EnvFilter`'s `FromStr` applies its
  `LevelFilter::ERROR` default only if the string is empty or wholly invalid, so one valid directive
  suppresses it. `docs/operations.md:427` tells operators to set that variable. `offer`
  (`logging.rs:242`) is unfiltered, so records still reach the file and SIEM sinks.
  → **C87**, and the reason Gate 3 reopened: it invalidated the premise G3-T6 was *accepted* under.
- **F2 · MINOR — stdout write failure is unobserved.** `tracing_subscriber::fmt` discards writer I/O
  errors and Rust sets `SIGPIPE` to `SIG_IGN`. → **G3-T10**, accepted (C88).
- **F3 · MINOR — no panic-catching layer.** A handler panic unwinds through `next.run(request)`
  (`logging.rs:177`), skipping `info!`, `offer` and `summarise`. → **G3-T11**, accepted (C88).

## Unmodelled surfaces

F1, F2 and F3 fall outside every `## Threat model` row. F1 reopens planning: it does not change a
mitigation, it invalidates the premise an accepted risk was accepted under.

## Constraint verdicts

Hostile method bound: **closed** — `http::Method::from_bytes` has no length cap, so a ~400 KiB method
token reached the record before this slice; after it, ≤ 258 bytes. Log injection: **closed**. Memory:
**closed** — the derivation is complete over `Decision` now that `method` is bounded. Trail integrity:
**open** (F1-F3).
