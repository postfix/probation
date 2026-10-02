# sf-threat-model — Gate 3 reopen (2026-09-25)

Verdict: **UNKNOWN**. Supersedes nothing: `threat-model-gate3.md` (2026-09-24, MODELED, 8 threats) is
the pre-reopen model and remains valid for the rows it covers.

Scope: the audit-trail asset and the controls over it after the slice-2 reopen — C87's pinned
directive, C88's two accepted exceptions, and the alarm.

## Blocking findings

- **B1** — the draft G3-T12 row claimed the threat was already mitigated by a monotonic
  `SinkCounters.total`. False twice over: `lost_total` appears nowhere in `src/` (it is a slice-3
  proposal), and a running total does not reconstruct a destroyed *window* count. **Verified by the
  main agent and withdrawn.**
- **B2** — C87 creates two boundaries no row covers → proposed **G3-T13** (host log transport) and
  **G3-T14** (synchronous console write in the request path). Both added.
- **B3** — G3-T10 is under-scoped: ENOSPC on a redirected stdout discards identically and needs no
  attacker, so "needs a crashed reader on the console pipe" is wrong. Severity raised to High.
- **B4** — `## Invariants` claimed `Sinks::drops()` has one consumer. It has two: `close_window`
  (`logging.rs:465`) and `flush_drop_tail` (`:444`), the second console-only. **Verified and corrected.**
- **B5** — G3-T10 and G3-T11 carried no entry in `## Accepted risks and their owners`. Added.

Also proposed **G3-T15** (the shed alarm's quiet window is startable by an unauthenticated peer).

## Must-verify, not verified

Whether a field-qualified `RUST_LOG` directive out-specifies C87's `add_directive`. No shell was
available in the dispatch. **Settled afterwards as C90** from the library's own source documentation.

## Limitation

Line citations across `## Modules and interfaces` are on a mixed baseline; slice 2 had already landed
`build_decision` in the working tree.
