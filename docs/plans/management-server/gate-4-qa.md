# Design QA
## Verdict
READY

## Overall assessment
This is a fresh review after commit 09d5f4a, which fixes AD1. `after-restore` now sets `value := greatest(value, now_us) + 1`, then `pruned_through := value`. Under the two stated assumptions, the counter is never more than one revision ahead of the clock. The clock never steps back, and changes arrive at fewer than one per microsecond. Each run therefore lands strictly above every revision issued before it, and that includes these cases:
- a backup restored twice;
- a backup taken right after an earlier `after-restore`;
- a backup that predates an earlier `after-restore`.

Because `pruned_through` equals `value`, every pre-restore cursor resets. Cursors below the new value reset by the floor rule, and any cursor ahead of it resets by the C126 rule. The planned test now restores twice a backup taken right after an earlier `after-restore`, the case AD1 named. `git diff 861441d 09d5f4a` changes the same sentence in 02, 03 C129 and 04 slice 8, plus one test row. It adds no contradiction.

`router check` reports no findings, and `molecule-check` is PASS. Source verification is PASS for 9 obligations. The 3 slice-4 obligations are PENDING because their source is absent on this branch. Everything approved before stays approved. There are no blocking findings. Note N2 below is optional.

## Questions and findings
None blocking.

**N2: non-blocking wording note (C129 clock).** Locations: 02 line 82, 03 C129 (line 26) and 04 slice 8 (line 98). The bound needs the clock that `after-restore` reads never to step backwards between runs. The text names only a rollback caused by a database restore; an NTP step backwards would matter in the same way, by up to the size of the step. The text also does not say which clock is read: Postgres `clock_timestamp()` in the transaction, or the CLI host's clock. If the author wants it exact, name the clock and state the assumption as "never steps backwards across runs". This does not affect readiness: the stated scope already covers the intended operations, and the residual is limited to the size of a clock step.

## What was checked
- **Inputs and dispatch.**
  - `router check`: no findings. The last history entry is `hand -> qa`.
  - `gate-qa prepare --gate design`: PREPARED.
  - Tracked and read: 01–04, molecule-flow.json, molecule-contracts.json, evidence/slice-3.md to slice-7.md, red-team.md and tdd-slice-3.md.
  - Reviewed `git diff 861441d 09d5f4a` (02, 03 and 04; 4 lines changed).
- **AD1: resolved.**
  - Clock bound: after a run at clock T, `value` is T + 1. Later writes add fewer than one revision per microsecond, so every revision issued before a later restore at T2 is at most T2.
  - The next run sets at least T2 + 1. That is strictly higher, whichever backup is restored, so two runs can no longer produce the same N.
  - With `pruned_through := value`, the reset rule (`since < pruned_through` or `since > value`) resets every cursor issued before the restore.
  - Headroom: epoch microseconds are about 2^50.6, far below 2^63. This is consistent with the C126 rule that a cursor of i64::MAX gets a reset.
  - The invariant `pruned_through ≤ value` holds, so a firewall that has adopted `value` is not reset again on every sync.
  - The test row exercises the formerly failing case and keeps the prune-after-restore case (AC1).
- **Earlier findings stay resolved.**
  - AC1: the prune job never lowers `pruned_through`, in 04 slice 4, 03 T-sync-api-contract and C129, and the test covers it.
  - AC3: an invitation re-admits a removed login only if it was created after the removal (`created_at` after `removed_at`), in 02, C130, 04 slice 6 and T-portal-sso-removed-not-rejoined.
  - N1: fixed.
  - AB1–AB4 and the user answers ABQ1/ABQ2 (C129 and C130) stay resolved, as reviewed in the two earlier rounds.
- **Clarification inventory.** C126–C130 each have an ID, class, status, owner, selected policy and a user source. No open questions remain.
- **Molecule model.**
  - `router molecule-check`: PASS. The model and sidecar are unchanged in 09d5f4a. `assumptions[6]` ("holds once the operator has run … after-restore") is accurate.
  - Source verification (from preparation): 9 obligations PASS, with every control detected.
  - `authorize-may-edit-first`, `save-edit-audit-before-commit` and `save-edit-change-before-commit` are PENDING; slice 4 delivers their source. Full `molecule-verify` was not run because obligations are PENDING.
  - Each `bySlice` precedes its consumers.
- **Design and contracts (sf-codebase-design).** The `after-restore` CLI seam keeps a one-statement contract with stated invariants: a monotonic counter, `pruned_through = value` after a run, and `pruned_through ≤ value`. The sync interface and the firewall are unchanged.
- **Test plan (sf-tdd).** T-ops-after-restore-resets-fleet tests through the public seams: the CLI, the sync API and two real firewalls with Postgres. Each of its three cases has an expected result that tells the behaviour apart from the AC1 and AD1 defects.
- **Security coverage.** The T7 row and the "Revocations not skipped (C20, T7)" row cite C129 and its test. T31 is preserved because the command has no API route. Other rows are unchanged.
- **Delivery order.** C129 lands in slice 8, after the slice 3 firewall reset and the slice 4 server; nothing earlier relies on it. C130 lands in slice 6. Witness counts match the tests named.
- **Repository evidence and § Invariants.** Unchanged by 09d5f4a. The line prefixes remain valid.

## Limitations
- The slice 4–7 implementations are on worktree branches outside the tracked roots. Statements about them come from the evidence files.
- The 3 slice-4 source obligations remain PENDING on this branch.
- The C129 bound rests on the stated clock and write-rate assumptions; those are premises, not something checked.

## Next steps
The main agent presents the reopened design (C126–C130 and the fixes from rounds AB, AC and AD) to the user and records the approval. N2 is optional wording the author may apply before presenting; any edit to 02–04 would then need a fresh review.
