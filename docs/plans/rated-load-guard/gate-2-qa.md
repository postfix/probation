# Gate 2 QA
## Verdict
READY

## Questions and findings
Round 5: all three round-4 findings are resolved; nothing else in 02-architecture.md contradicts C39.
- G2QA-16 resolved. C39 now states an explicit reconciliation with Gate 1 C13, Gate 1 C10 and the Success metric. The headline promise is unchanged; M is published at the 200 rps reference load (300 s); about 0.9 s at N is stated plainly; the Gate 1 reopen is offered to the user at presentation. That choice is the user's, so it is not a QUESTIONS. Arithmetic checked: 1,875 MiB / 32,768 B = 60,000 records; 60,000 / 200 = 300 s; 60,000 / 65,202 = 0.92 s.
- G2QA-17 resolved. 64 MiB = 2,048 records, about 31 ms at N (31.4) and about 10 s at 200 rps (10.24). The 4 GiB ceiling figures also check (about 655 s at 200 rps, about 2 s at N). The 611,267 MiB / 597 GiB / 150x figures and the 7.5x band ratio check.
- G2QA-18 resolved. The `sf-red-team: not triggered` line names the 64 MiB to 1,875 MiB (3,750 MiB with both sinks) increase and the reasons it is accepted: the user saw the figure, the 4 GiB Gate 3 C36 ceiling holds, the memory is documented as additive, and severity is restated at Gate 3.
- Capability 1 of Program behavior now says the tolerance is computed from the stated 200 rps reference load and the constant (C39), not produced by the benchmark. It is consistent with C39, C13 and C15.
- Non-blocking note, no revision required: Gate 1 C6 also says "at the rated load" and is not in C39's list of Gate 1 sentences. The same reading applies, and C39's general statement (M published at the reference load) covers it. Optionally add "C6" to the list.
## Checked dimensions
- Subject completeness, regular paths, freshness: ok. The six files are tracked; the seal rechecks them.
- Clarification inventory: stable IDs, class, status, owner, target, source all present. C35 and C36 remain deferred to Gate 3 under their IDs. Gate 1 deferrals C5, C9, C11 and C13 are imported and resolved. Ok.
- Gate 2 grounded fit, interfaces, flow, constraints: ok. No target-Gate choice is left open.
- C39 against the rest of the document: C13, C15, the Fit rows, the Flow and the Constraints are consistent, with no residual "N as multiplicand" text.
- Red Team: the not-triggered reason is complete (G2QA-18). The earlier red team's findings are recorded as resolved.
- Gate 1 unchanged (approved upstream): C39 no longer claims it is unchanged and instead documents a reading.
- Gates 3 and 4: not applicable, except that the carried corrections are listed in C39.
## Limitations
- Bookkeeping in `## Repository evidence` (the gate-2-qa.md bullet still describes rounds 1 to 3 and "requires a fourth review") is stale. It is not a decision source; refresh it at the next edit.
- Arithmetic was recomputed from figures stated in the documents and `evidence/tdd-slice-7.md`. Source code was not re-inspected this round, since the repairs are prose-only.
- No SMTC leg was run; the repairs are documentary.
