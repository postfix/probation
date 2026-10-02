# Gate 3 — Program design: Rated load guard (re-presented after the slice-2 reopen)

## What problem do we have?

`sf-security-review` on slice 2 returned **FIX FIRST**. F1, MAJOR: `src/main.rs:58-63` builds the
subscriber from `EnvFilter::try_from_default_env()`, and `EnvFilter`'s default INFO directive is
discarded as soon as `RUST_LOG` holds any valid directive — so any value an operator sets silences
every decision line on stdout, while `offer` (`logging.rs:242`) keeps delivering to the file and
SIEM sinks unfiltered. `docs/operations.md:427` tells operators to set that variable.

Reproduced against `target/debug/package-firewall serve`, one `GET /npm/left-pad/1.3.0` per run:

| `RUST_LOG` | stdout | NDJSON sink |
|---|---|---|
| unset | 2170 bytes, decision line present | 2 records |
| `info` | 2170 bytes, decision line present | 2 records |
| `hyper=debug` | **0 bytes** | 2 records |
| set but empty (what a systemd unit or compose file produces from an unset variable) | **0 bytes** | 2 records |

This reopened the gate rather than changing a mitigation: it invalidated the premise threat
**G3-T6 was *accepted* under** — C26's "stdout is the complete trail".

## How will we solve it?

**The entire net addition to the approved plan is one line, one test, and one line of documentation.**
No new dependency, no new module, no new counter, no new middleware.

1. `src/main.rs` — the only change to this file (C87). The operator's filter is still parsed and
   still governs every other target; only the decision log's target is pinned:

```rust
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
                .add_directive("package_firewall::http::logging=info".parse().expect("static directive")),
        )
```

   The target string is the module path `tracing` attaches to the `info!` at
   `src/http/logging.rs:223`, read off the shipped summary line's
   `"target":"package_firewall::http::logging"`, not assumed.

2. `rl24b` — one test, run as a **subprocess** against the built binary with a foreign `RUST_LOG`
   (`Cargo.toml` declares `[lib] path = src/lib.rs` and a separate `[[bin]] path = src/main.rs`, so
   a `tests/`-resident test links the library and could never fail against the pin).

3. `docs/operations.md:414-419` — the decision-line sample still shows `"method":"GET"` where slice 2
   now ships `"method":"\"GET\""`. Owned by **slice 2**, which caused the drift.

**Withdrawn as scope the plan did not plan** (YAGNI, user instruction 2026-09-25) — each tombstoned
with the finding that killed it:

| Withdrawn | Was | Killed by |
|---|---|---|
| **C89** | the configured file sink becomes the system of record whenever `log_file_path` is set | `sf-red-team` B3/B4 — it rests on a key absent by default and reverses C87's own stated rejection |
| **C91** | `Summary` gains a `lost_total` field | `sf-red-team` B5 — it only moves the loss one record later; G3-T12 is closed by C87 instead |
| **C92** | wrap stdout in `tracing_appender::non_blocking` | C93 — a new **runtime** dependency against approved Gate 2 `## External` ("no new dependency"), and a **lossy-by-default** writer (`try_send`) that reopens G3-T12 |

**What you decided in this reopen:** Q5 pinned the audit target (**C87**); Q6 accepted G3-T10 and
G3-T11 as **named exceptions** in the C26 statement rather than mitigating them (**C88**); Q10
withdrew C92 once its cost was priced (**C93**), returning G3-T14 to accepted.

C26 now reads: stdout carries every decided request, **except** where the console writer itself fails
(G3-T10), the handler never returns (G3-T11), the host log transport truncates it (G3-T13), or a
span- or field-qualified `RUST_LOG` directive out-specifies the pin (**C90**) — four exceptions.

Security practice: the audit target's level is now process-set, not environment-set. DRY and
separation: `loggable` is applied in exactly one place (`build_decision`, C63), and the pin is
process setup in `main` — no request-path code changes, so no performance claim moves.

## How will we confirm it is solved?

| Scenario | Expected result | Check |
|---|---|---|
| the built binary run as a subprocess with a foreign `RUST_LOG`, one decided request, file sink configured | the record is on the console **and** in the sink; today the console is empty and the sink has it | `rl24b` — **planned**, red against the tree as it stands |
| a sink loses a record | the record is still on stdout — `tracing::info!` (`:223`) runs before `offer` (`:242`) | `rl24` — **planned** |
| a full queue destroys its own window's loss count (G3-T12) | the summary line carrying a non-zero `dropped_file` reaches the console | **observed** 2026-09-25: one-record queue (`log_queue_max_bytes = 32768`), 400 concurrent requests → sink took **178** records, stdout summary reported **`dropped_file: 222`**, 178 + 222 = **400**. Tier **manual**: the run witnesses `emit`'s ordering, not C87's pin, because it predates it |

**G3-T12 is closed by C87 at no additional cost** — `emit` writes the drop counts with
`tracing::info!` before `sinks.offer(..)`, so the console already carries them.

Threats that are **accepted, each with the verification its own row states** — none is "all good":

| Threat | Sev | Disposition | What verifies it |
|---|---|---|---|
| G3-T1 TOCTOU on the watch pair | Medium | C47, ordered stores | structural — **no executable witness** on x86-64 (TSO); `rl16` |
| G3-T6 confirmation oracle | Medium | accepted (user, Gate 2 Q4); its named exceptions are now four | `rl24`, `rl25` |
| G3-T8 4 GiB ceiling, no host-memory cross-check | Medium (up from Low) | accepted (user, Gate 3 Q2) | `rl2`, `rl3`, `rl6` |
| G3-T10 console writes discarded unobserved | **High** (up) | accepted (C88, Q6) — ENOSPC on a redirected stdout discards identically and needs no attacker | **none — accepted without a witness**; docs row (C26) |
| G3-T11 handler panic leaves no record | Medium | accepted (C88, Q6) as **cheap but unwitnessed** — the `CatchPanicLayer` cost argument is withdrawn | **none — no reachable panic witness** in first-party code |
| G3-T13 host log transport truncates stdout | **High** | accepted (C88, Q6); splitting stdout/stderr recorded and **not taken** (YAGNI) | docs row; no host-side requirement published |
| G3-T14 slow console consumer blocks `info!` inside `decide` | Medium (High where stdout is a pipe to a sidecar) | accepted (C93, Q10) — pre-existing shipped behaviour, outside Gate 1 C7, which governs the delivery queue | **none — accepted without a witness** |
| G3-T15 an untrusted peer starts the 60 s quiet window | Low-Medium | documentary, carried by slice 7 item (iv) | structural; slice 5's `rl16c` covers the clock step |

Recommendation: **approve.** The reopen's deciding fact was reproduced before it was designed for,
the fix is one line closing a High threat, and every expansion that was priced turned out to cost
more than it bought and was withdrawn rather than carried.

Limits: **C87's pin is scoped by C90** — no *level or target* `RUST_LOG` directive can silence the
decision log, but a span- or field-qualified directive on that target sorts ahead of the pin and
still wins; that is a stated residual, not a covered case, and `rl24b` does not claim the stronger
property. Seven rows above are accepted, and three of them state **no witness at all** — G3-T10,
G3-T11 and G3-T14; G3-T1, the eighth row, is mitigated but has no executable witness either. The G3-T12 closure rests on the ordering plus
the manual reproduction — no test-plan row asserts a summary line with a non-zero `dropped_file`.
Slice 2's code is written and green but **not checked off**, and cannot be until Gates 3 and 4 are
re-approved.

Status: `sf-gate-qa` returned **READY** on round 7 with **no blocking findings** (`gate-3-qa.md`),
plus two non-blocking observations it routes rather than fixes: **N1**, two stale cross-document line
anchors in `04-slices.md` C79 that still resolve by content and are Gate 4's to fix, and **N2**, a
knowingly imprecise `Returns:` line on `is_shedding` that G3-T15 records and assigns to slice 5.
`router gate-qa verify --gate 3` returned `{"verdict":"READY","files":14}`. Slice 2's code is written
and green (87 lib tests, 19 integration). Gate 4 is pending re-approval; `00-status.md` records
Gate 3 as in progress, generation 7, reopened.

Sources: `03-program-design.md` (C87–C93, `## Files` `src/main.rs`, `### main`, `## Test plan`
`rl24`/`rl24b`, `## Threat model` G3-T6, G3-T9–G3-T15); `04-slices.md` slice 2 row and interfaces,
slice 7 item (ii)-(iv); `gate-3-qa.md`; `evidence/security-review-slice-2.md`,
`evidence/threat-model-gate3-reopen.md`, `evidence/red-team-gate3-reopen.md`,
`evidence/reproduction-2026-09-25.md`.

Approve Gate 3, or what should change?
