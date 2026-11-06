# Slice 3 test sensitivity repair

Scope: new isolated negative-control experiments for the production quota witness and correctly sealed foreign-reference HTTP witness. Main product, tests, approved models and specifications remain unchanged. This report does not alter the chronological TDD record or claim the original tests ran RED before implementation.

## Subject and isolation

`.scratch/slice3-repair/tests/before-manifest.json` freezes 548 source/test/benchmark and active-plan non-evidence files plus Cargo manifests and toolchain configuration. The experiment copies source into `.scratch/slice3-repair/tests/workspace`; only that disposable copy is mutated. `experiment.py` and the generated fixture/mutation diffs make the transformations reviewable. The authoritative experiments use their own Cargo target directory under the authorized scratch directory, with two compiler jobs/test threads and two CPU cores. Temporary files and logs also remain on disk there. The prior 15-file review manifest and actual production-limit GREEN remain the baseline.

## Experiments

Authoritative isolated-target execution is complete. All controls selected the expected nonzero test counts and the intended failures were observed. Two earlier shared-cache invocations selected zero tests and are excluded; Cargo metadata confirmed the copied source selection, while touching copied `src/lib.rs` forced recompilation and produced the expected three passing probes. That successful diagnostic run is preserved separately but is not the authoritative control pair. The coordinator required a separate target directory to remove artifact-identity ambiguity.

Quota hypothesis: the witness assertions detect loss of the quota refusal branch for each member/service, registry and global count query. For speed, the isolated fixture splits the original literal-threshold loop into three independent tests (`sensitivity_member`, `sensitivity_registry`, `sensitivity_global`) and changes only cardinalities and matching limit values to 3, 5 and 7. Production `commit`, its three queries, shared limit branch, transaction, full row-hash comparison and absent-candidate assertions remain in use. The fault disables only `if count >= limit { return Err(StoreError::Busy); }`. This reduced fixture proves branch sensitivity, not a RED run of the original million-row literal fixture. The original exact-threshold GREEN is separately recorded in `slice-3-engineering.md` and `.scratch/slice3/quota-production.log`.

Foreign-reference hypothesis: the existing HTTP witness detects removal of selected-origin approval even when store lookup, service seal, reference identity and removal marker are valid and legacy `forward_bearer=true` allows the foreign origin. The fault disables only the service selected-origin guard in `approve_deletion_scope`; the existing test is unchanged. The fake transport makes the experiment local without sending credentials to an external service.

## Process distinction

A new mutation-killing experiment is acceptance sensitivity evidence. It cannot reconstruct an unobserved pre-implementation RED or cure that historical fact. No `tdd:` line is rewritten or upgraded. Parent-owned fresh review determines the disposition of this transparent process limitation.

## SMTC receipt

Session `sf-slice3-sensitivity-2026-11-03`, absolute repository root `/home/john/go/src/github.com/postfix/probation`: `search symbol` then `inspect symbol` resolved both named witnesses; `file read` inspected quota commit/count enforcement and deletion-scope approval; bounded `file grep` located the selected-origin guard. Each returned outer `ok:true`, complete untruncated content and no diagnostics. These are manual source-grounding evidence, not compiler or exhaustive safety certificates. No production defect or product patch is claimed.

## Observed results

| Experiment | Selected | Result | Deciding observation |
|---|---:|---|---|
| quota-green | 3 | PASS | All three count-query boundary probes refuse quota+1 and retain original row-hash assertions. |
| quota-mutant | 3 | Expected FAIL | All three fail their exact `3+1`, `5+1`, `7+1 must refuse through production quota code` assertion after only the quota branch is disabled. |
| quota-restored | 3 | PASS | Restoring the quota branch restores all three outcomes. |
| foreign-mutant | 1 | Expected FAIL | With only the selected-origin guard disabled, the existing transport assertion detects `Some("foreign.invalid")` instead of `Some("npm.invalid")`. The resulting client incomplete-message error is secondary to that deliberate wrong-origin assertion, not an infrastructure failure. |
| foreign-restored | 1 | PASS | Restored source returns the selected-origin refusal, sends nothing, and retains the valid marker. |

Exact logs and matching `*-subject.json` receipts are under `.scratch/slice3-repair/tests/`, with names matching the experiment column. Cargo used the explicit copied manifest, working directory and isolated target. Commands were `cargo test --offline --lib sensitivity_ -- --ignored --nocapture` for the three quota variants and `cargo test --offline --test service_unpublish sealed_foreign_reference_with_valid_marker_refuses_before_send -- --exact --nocapture` for the unchanged foreign test.

`.scratch/slice3-repair/tests/terminal-receipt.json` confirms zero drift across all 548 frozen files and all 15 reviewed subject files. The two copied production files were restored byte-for-byte to the main workspace. All command processes ended. No main source, test, approved model or specification changed in these experiments.

Disposition requested from fresh review: judge these as explicit regression/acceptance controls with demonstrated sensitivity, retain missing historical RED as an honest chronology limitation, and do not confuse it with an untested protection or fabricate a past failure.
