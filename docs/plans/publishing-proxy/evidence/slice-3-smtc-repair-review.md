Review kind: code-review
Verdict: SHIP
Question: Does the isolated ordered-obligation repair preserve refusal, bind call locations to current source, and prevent the reproduced false clean results?
Reviewing: staged `crates/smtc-spec/src/eval.rs`, its exact patch against the clean external base, and the connected generic locator/CFG/hash contracts.

This verdict approves the bounded repair at the hashes below. It is not an SMTC release-wide soundness certificate or approval of the separate Factory receiver-resolution repair.

Defects: none remaining in the reviewed repair.

Conventions (`CLAUDE.md`, `CONTRIBUTING.md`, `docs/standing-rules.md`, relevant `docs/test-conventions.md` sections): none. Tool-enforced formatting rules were not manually reviewed. Recorded source-level tests are supplemented by a matched CLI/daemon command probe; no release-wide capability claim is made.

Simplifications: none recommended. The locator preserves the existing generic lookup and adds exact typed-call recovery; both finding branches use the diagnostic helper. No speculative interface, configuration, dependency, or export was added.

Deciding evidence:

1. Exact call location: `ordered_call_site` joins the actual typed instruction's block/index to exactly one byte sidecar, checks `start < end <= source.len()`, and derives its line from source bytes. Multiple matching occurrences and missing/duplicate/invalid identities refuse. Source bytes are cached only after their FNV-1a identity matches the indexed source hash and the CFG path equals the operation path. The former whole-block/unique-name fallback was removed.
2. Evaluation order: same-block proof compares typed instruction indexes only after verifying that both instruction owners equal the blocks used for dominance. Same-line refusal remains. `guard(operation())`, its multiline form, and the form with a preceding unrelated call cannot return clean. Existing CFG validity, indexed caller/source checks, and unresolved-guard refusal remain.
3. Review-found defects have executable regressions. `partial-identity-red.log` reproduced borrowing a guarded sibling when an operation sidecar was absent; `omitted-call-red.log` reproduced borrowing a later same-named call when an earlier operation was omitted; `nested-red.log` reproduced accepting an operation evaluated before its surrounding guard. Final `spec-suite-bound.log`: 123 passed, zero failed/ignored. The tests assert public evaluator results; the real-engine decorator only injects the relevant incomplete carrier.
4. Actual controls: `bound-summary.json` records four safe/unsafe pairs, each safe result with zero findings and each unsafe result with one expected finding. The raw qualified-send finding retains `callee_qualified_name`, caller, file, line, receiver, and source hash. `native-matched-reference-unsafe.json` independently exercises the CLI/daemon seam: outer `ok:true`, one expected finding, no diagnostics/refs, `workspace_cache_hit:false`, request `req-1092296-1793728420694-0`.
5. Preserved-invariant sensitivity is distinct from historical RED: changing only the existing same-line refusal to `if false && ...` produced exactly one failed test in `same-line-mutation-red.log`; restoring byte-identical final source produced exactly one pass in `same-line-restored-green.log`. This is mutation RED/restored GREEN, not a claimed old bug.

All logs above are under `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/`.

TDD bindings:

| Added test | RED/sensitivity evidence | Final result |
|---|---|---|
| `ordered_rust_question_mark_branch_call_locations` | `tdd: cfg-final-red.log` — old locator rejected the safe branch | PASS; includes awaited, missing, sibling, reversed cases |
| `ordered_diagnostic_preserves_qualified_callee_and_caller_filter` | `tdd: diagnostic-red5.log` — old summary omitted short spelling | PASS |
| `ordered_refuses_partial_call_identity_instead_of_wrong_branch_proof` | `tdd: partial-identity-red.log` — intermediate repair falsely accepted incomplete identity | PASS |
| `ordered_guard_argument_operation_is_not_guarded` | `tdd: nested-red.log` — prior same-block line comparison falsely accepted nested argument | PASS, all three forms |
| `ordered_refuses_omitted_earlier_same_named_call` | `tdd: omitted-call-red.log` — intermediate unique-name/block-span fallback falsely accepted | PASS |
| `ordered_call_location_refuses_same_line_calls` | `tdd: same-line-mutation-red.log` — preserved refusal deliberately disabled | Restored PASS |

Subject and provenance:

- Repository root: `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/smtc-source`.
- Base: `/home/john/go/src/github.com/agenthands/show-me-the-code`, clean HEAD `fb784663b4d825fca7d5ff3f7b7b91a0ea03e315`; base eval.rs SHA256 `74419bc4db9abb3e331cf3cfe3ed98696c715680c8c57944b2852cb8582f78ea`.
- Final eval.rs SHA256: `412b7b79ea024e6988f6699cbe7c3686954c294d3f2de1976f2ddcb90bfa42a1`.
- Final patch SHA256: `0f12d1a52d746040cffe9585d8e572662146f34c26e9a352c49b683acf2aebf8` (419-line patch, `smtc-eval.patch`).
- Generic locator file SHA256: `866e4f2e013f860c1da020f16f57651bc1f78466b186811a445b122196a9c7ab`.
- IR carrier file SHA256: `633d151eabe6034256a1d9b8ff3ce45328843ebe3210d0cf434007b91ab43ea2`.
- Engine hash contract file SHA256: `5d7bc3212d1ae4d7fd5d1a621f0e00246f9e645eadc1f654979ec31f7f7013bf`.
- Matched CLI SHA256: `9969701fbf93856d0ad2bb2b8076c731b2ca04ed01590125ad5f2f6c7d384c1f`.
- Matched daemon SHA256: `b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3`.
- Actual-control library runner SHA256: `4fa2ef3a20432dba744a3d8179af6e9123832f221f52fff6f02bf659ad12ec5c`.
- Staging is a Git archive nested inside the product repository. Review used `git diff --no-index -- <clean-base-eval> <staged-eval>` and source fingerprints, rather than treating the parent repository's empty staged-path status as a patch inventory. Base status was repeated and remained clean.
- Initial packet hash mismatch was returned before content inspection; corrected packets were explicitly rebound. Earlier changing candidates were not approved. Following the final sensitivity mutation, the exact final hash was restored, the helper was reinspected through SMTC, and final fingerprints matched again.

SMTC receipt:

Use the following literal expansions for this receipt: `R=/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/smtc-source`, `S=sf-smtc-repair-review-2026-11-03`. Each ordinary command below ended with `--format json --max-tokens 2048 --session-id S`; no pipes, wrappers or output redirection were used. Source-inspection tier is Manual; executable tests prove their individual outcomes, and analyzer control results are Structural, not program-wide safety certificates.

| Operation / argv (R and S expanded as above) | Status / completeness / interpretation |
|---|---|
| `smtc search symbol --root R --name-pattern NAME --limit 6` for `ordered_call_site`, `ordered_call_block`, `unguarded_operation_summary`, `eval_ordered_obligation`, the six added tests, `find_block_for_line`, `ControlFlowGraph` | run; outer true, no inner refusal; resolved declarations, untruncated; no semantic function-count claim |
| `smtc inspect symbol --root R --handle HANDLE` for resolved helpers/tests/connected declarations | run; outer true, no inner refusal; complete body text. Final handles include eval.rs `392:433`, `435:443`, `461:757`, `1789:1810`, `2036:2059`. Generic locator `crates/smtc-protocol-check/src/lib.rs:170:213`; carrier `crates/ir-ast/src/lib.rs:1371:1458` |
| `smtc file read --root R --path crates/smtc-spec/src/eval.rs --start-line 528 --end-line 672` | run; outer true, no inner refusal, untruncated; final hash/path binding, caller checks, owner-equality and instruction ordering inspected |
| `smtc file read --root R --path crates/smtc-spec/src/eval.rs --start-line 1621 --end-line 1725` on the earlier fingerprint, plus exact final patch inspection | run; outer true, untruncated; real-engine fault-injection seam inspected; final changes add omission of one instruction and reindex its sidecars |
| `smtc file read --root R --path crates/ir-ast/src/lib.rs --start-line 1173 --end-line 1207` | run; outer true, untruncated; distinguishes call-step spans from typed call sidecars |
| `smtc file find --root R --pattern PATTERN --max-results 20` for `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING*`, `CODING_STANDARDS*`, `docs/codebase-overview.md`; `smtc file read` for hits | run; outer true, no inner refusal; only CLAUDE/CONTRIBUTING matched. Standing rules read in bounded ranges; applicable test-convention sections read in bounded ranges |
| `smtc ref show ref-121 --session-id S`; `smtc ref show ref-122 --session-id S` | run; outer true, complete evaluator bodies for prior candidates (3,323 and 3,548 estimated tokens). Final evaluator inspection emitted ref-123 (3,763); final changed region was narrowed/read instead. Large refs above 4,096 were not opened |
| Worker-supplied `smtc inspect symbol --root /home/john/go/src/github.com/agenthands/show-me-the-code --handle /home/john/go/src/github.com/agenthands/show-me-the-code/crates/engine/src/lib.rs:7977:7985 --format json --max-tokens 2048 --session-id sf-slice3-tooling-repair` | run; supplied request `req-1017741-1793728079872-0`, outer true, nine complete lines/no refs; FNV-1a offset/XOR/wrapping multiplier match final evaluator. Stage/base engine file hashes match |
| `smtc review impact --root R --file crates/smtc-spec/src/eval.rs --start-line 391 --end-line 439 --format json --max-tokens 2048 --session-id S` | unavailable; outer false, error `timeout` at 100000ms daemon deadline; no semantic impact result. Supplementary leg only; parent accepted bounded exact-diff/private-helper evidence. No whole-program impact claim; `proposedNext: sf-smtc-doctor health` if that graph evidence is later required |
| Final restored `smtc inspect symbol --root R --handle R/crates/smtc-spec/src/eval.rs:392:433 --format json --max-tokens 2048 --session-id S` | run; outer true, no inner refusal, complete; request `req-1117722-1793728543618-0`; identical final helper after mutation restoration |

No native source-reading fallback was used. Native Git/fingerprint commands and build/test logs are subject and execution evidence. This review reused evidence across Defects, Conventions and Simplifications; no deletion recommendation requires an unresolved blast-radius leg.

Unchanged during review: yes for the final restored-hash recheck; earlier iterations and the disclosed sensitivity mutation were explicitly superseded. Final eval/patch/support hashes match the approved snapshot.
Reviewed: the sole changed production/test file `crates/smtc-spec/src/eval.rs` (three locator/summary helpers, enclosing ordered evaluator, six added tests and `CfgProvider` fault injection); supporting `find_block_for_line`, `BasicBlock`/`ControlFlowGraph`, and the pinned engine content-hash contract. Deleted: none.
Checked clean: correctness/totality/boundaries/types/numeric behavior; errors/partial failure; ownership/cleanup/cancellation/lifecycle; shared-state/order/races/deadlock/termination within the repair; pre/postconditions/invariants/compatibility/side effects; input bounds/obvious security defects; maintainability; behavioral tests; authorized scope; applicable conventions and simplifications.
Omitted: zero findings in each block.
Limitations: broad semantic-impact query timed out; no full-engine or daemon suite, performance benchmark, or installation was performed by this reviewer. Four pairs ran through the actual library runner and one unsafe case through the matched CLI/daemon; final product verification remains the parent's task. Receiver-to-same-named-free-function resolution remains a separate Factory concern and is not excused by short diagnostics. Missing evidence is still refusal; this verdict does not upgrade structural analysis to a general proof of runtime safety.
