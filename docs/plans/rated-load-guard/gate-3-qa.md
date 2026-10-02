# Gate 3 QA
## Verdict
READY
## Questions and findings
Re-review of the 2026-09-26 amendment (Gate 2 re-approved, C13 amended, C39 added). No blocking findings. Non-blocking observations:
- N1 (Gate 3, cosmetic): residual-risk item 1 (~line 1101) says the constant "may be several KiB"; it landed at 32 KiB (C39). Still true as a prediction, so not stale; not required.
- N2 (Gate 4, out of scope): `04-slices.md` still says slice 1's provisional default is 64 MiB and "cannot be computed until the bench reports the rated figure" (lines 50, 118, 124); `Changes` for slice 7 speaks of `M` derived from `N`. These need Gate 4 re-approval to follow C13/C39 (stated 200 rps, 1,875 MiB). Not reviewed here.
## Checked dimensions
- Subject completeness and freshness: 03, 01, 02, `show-me-gate2-reapproval.md`, `evidence/tdd-slice-7.md` and the ten listed evidence files all tracked (16 files) and read/grepped. Result: ok.
- Arithmetic: 4 GiB / 32,768 = 131,072 records; / 200 = 655.36 s (~655 s); / 65,202 = 2.01 s (~2 s); 1,875 MiB = 1,966,080,000 B = 60,000 records = 300 s at 200 rps = ceil(300 x 200 x 32,768) exactly, whole MiB; two sinks = 3,750 MiB; 64 MiB = 2,048 records. All correct.
- Consistency with 02 C13 (as amended) and C39: default = smallest whole MiB for 5 min at stated 200 rps, 1,875 MiB per sink, inside 4 GiB ceiling, additive to `memory_cache_max_bytes`, N published as machine ceiling. The four amended places in 03 (DEFAULT_QUEUE_MAX_BYTES doc comment line 103-107, C36 line 15, G3-T8 line 1065, accepted-risk 5 lines 1126-1131) match. G3-T8 severity Medium kept, matches 02 line 230 not-triggered note.
- Stale claims: every remaining "hours of outage" occurrence (C36, accepted-risk 5) is an explicit withdrawal/historical quote; no live "rated load" claim in 03. Remaining "rated" hits are identifiers (`RatedLoadResult`, `drive_rated_load`, `delivery_rated_load`) and "rated figure" meaning N, consistent with C39's reconciliation. C13 references at C54 and residual risk 1 remain accurate.
- Rest of document vs amended default: `capacity_for`/validate arms (floor BYTES_PER_RECORD, ceiling 4 GiB), `rl5` (both budgets equal the default), `rl18` (pinned B, independent of default), `rl20` bench, and G3-T3/T5 read consistently.
- Clarification inventory, Gate 3 design/test/invariant/repository-evidence dimensions: unchanged by this amendment; prior READY (2026-09-25) findings not reopened; Red Team not triggered for this revision (recorded in 02 line 230, arithmetic-only restatement, no new module/boundary/input).
- Gate 1, 2, 4-specific dimensions: not applicable.
## Limitations
Review scoped to the four amended places plus consistency sweep by grep and targeted reads, not a full re-read of all 1,207 lines; unchanged sections rely on the prior READY. Gate 4 out of scope. No SMTC leg was needed (documents only).
