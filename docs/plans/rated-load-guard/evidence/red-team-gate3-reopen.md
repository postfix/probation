# sf-red-team — Gate 3 reopen, rounds 1 and 2 (2026-09-25)

Distinct from `red-team-gate3.md` and `red-team-gate3-round2.md`, which are the **pre-reopen** rounds
(scope C46, C50-C61, grounding C62-C67). These two rounds review the slice-2 reopen only.

## Round 1 — NEEDS REVISION

- **B1 · BLOCKER** — G3-T14's fail-closed acceptance reverses APPROVED Gate 1 **C7** ("package serving
  is never slowed or failed — Rejected: making the request wait for queue space") and **C8**, and the
  shipped `docs/operations.md:450` sentence. **Verified by the main agent against both files.**
- **B2 · BLOCKER** — `rl24b` cannot fail against `src/main.rs`: `Cargo.toml` declares `[lib]
  path = src/lib.rs` and a separate `[[bin]] path = src/main.rs`, so a `tests/`-resident test links the
  library. **Verified.** → `rl24b` respecified as a subprocess test.
- **B3 · BLOCKER** — C89's file sink is absent by default (`log_file_path` is `Option<PathBuf>`), so it
  converts two High threats to "documentary" by pointing at unenforced configuration.
- **B4 · MAJOR** — C89 adopts what C87 explicitly rejected, unstated; C88 says "two exceptions" where
  there are four.
- **B5 · MAJOR** — C91 has no carrier, changes a serialized record, and its value is a two-sink sum.
- **B6 · MAJOR** — the `#### Sinks::drops` interface section still carried the text the corrected
  invariant calls wrong.

Disposition: B1 → C92 (later withdrawn). B2 → respecified. B3/B4 → **C89 withdrawn**. B5 → **C91
withdrawn**, G3-T12 closed by C87 instead. B6 → corrected.

## Round 2 — NEEDS REVISION

- **BLOCKER** — `### main` and the `## Files` row specified only C87, never C92.
- **BLOCKER** — `tracing_appender::non_blocking` is **lossy by default** (`try_send`, discards on a full
  channel), so G3-T14's verification ("no decision line is discarded") is unsatisfiable and contradicts
  C92's own answer.
- **BLOCKER** — C92 reopens G3-T12: `flush_drop_tail`'s console-only `warn!` goes into a lossy channel,
  and `WorkerGuard::drop` abandons the flush after ~1.1 s.
- **MAJOR** — G3-T13 still rests on withdrawn C89.
- **MAJOR** — C92's rated-figure claim is false: `rl18`/`rl20` link the library and never execute
  `src/main.rs`, the same `[lib]`/`[[bin]]` argument accepted for B2.
- **MAJOR** — `tracing-appender` is not a direct dependency (**verified**: `[dependencies]` carries
  `tracing` and `tracing-subscriber` only), and a `WorkerGuard` bound inside the builder chain drops
  before the first request.
- Also corrected a false research claim: `NonBlocking::error_counter()` → `dropped_lines()` does exist.

Disposition: **C92 withdrawn (C93)**. The reopen's net addition returns to one line in `src/main.rs`
and one test. G3-T13 corrected; the false claims withdrawn in place.
