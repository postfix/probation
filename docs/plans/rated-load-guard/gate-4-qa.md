# Gate 4 QA
## Verdict
READY

## Questions and findings

none. Round 7, fresh, after the revision answering G4QA-16. No user question, no blocking finding.

- G4QA-16 resolved. C95 (`04-slices.md:22`) now says only `src/main.rs` is unchanged since HEAD `734d22d`; `src/config.rs` anchors are HEAD anchors shifted by slice 1's uncommitted edits; `src/http/logging.rs` is shifted by slice 2 work in progress; `build_decision` at `src/http/logging.rs:266` and any other slice 2 anchor read from the tree are working-tree anchors. Checked against the tree: `git diff HEAD --stat` shows `src/main.rs` and `docs/operations.md` unmodified, `src/config.rs` +78 (hunks at `:16`, `:66`, `:89`, `:121`, `:167`, `:169`, `:270`, `:362`, `:410`), `src/http/logging.rs` +184; `fn build_decision` is at `src/http/logging.rs:266` in the working tree and absent at HEAD, where `impl Target` / `fn of` sit at `:267-268` (C72's `Target::of :268`). The sentence is now true.
- G4QA-9 to G4QA-15 were confirmed in the prior round; the text they rest on is unchanged in this revision.

## Checked dimensions

- Subject completeness and freshness: `04-slices.md`, `01`-`03` and 11 relied-on evidence files tracked before reading; the helper refuses `gate-4-qa.md` as a source (generated report), so the prior report was read as context only and nothing relied on it as evidence. Result: complete.
- Clarification inventory: Gate 4 rows C70-C82, C86, C94, C95 each have a stable ID, class, status resolved, owner 4, target none, selected value and decision source; incoming deferrals keep their IDs; no open choice or Engineering-targeted deferral. Result: pass.
- Vertical slices and order: seven slices with outcome, dependencies, exact files, witness, prerequisites, temporary artifacts, reviews and triggers; none depends on withdrawn C89/C91/C92. Result: pass.
- Direct witnesses that fail today: each slice names why its witness is red today; slice 2 says only `rl24b` is red, consistent with `evidence/tdd-slice-2.md` and `evidence/reproduction-2026-09-25.md`. Result: pass.
- Implementation-verification labels concealing an unselected value: none; provisional 64 MiB and `F` carry named removal points (C76). Result: pass.
- Red Team: `evidence/red-team-gate4.md` findings resolved in C78-C82; the closing line records why C94 and C95 need no new round. Result: pass.
- Citations: baseline declared by C95 and true. Result: pass.
- Gates 1-3 dimensions: not applicable.

## Limitations

- The six `clarification-row` findings in approved `03-program-design.md` (withdrawn rows C89, C91, C92) are known, belong to Gate 3 and are out of scope.
- `00-status.md` and `gate-4-qa.md` are machine state or generated and were not relied on.
- Nothing was executed; source claims were checked with `git diff HEAD` stat/hunk headers and grep. `smtc` was not used: the subject is plan text and the checks needed only line positions (manual tier).
- `rl24b` is not written; its red-today claim rests on its absence plus the manual reproduction.
