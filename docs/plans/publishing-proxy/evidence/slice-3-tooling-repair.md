# Slice 3 tooling repair — reviewed and installed SMTC evidence

Status: independently reviewed eval-only repair is persisted and installed as a matched release pair. A fresh installed daemon passes all four unchanged production specs and all four unsafe controls. Full engine/daemon testing is not green: 36 failing cases reproduce on the exact pre-repair baseline, and five diagnostics cases pass in isolation on both baseline and repaired source but remain unresolved in the full-suite context. No whole-SMTC release-green or slice-completion claim is made here.

## Frozen subjects and ownership

All 15 product files match `.scratch/slice3/current-subject.json` (manifest SHA-256 `a85bfdde9de40508ce3c512087d59461037b0710b125f2382359832d66e201b9`). All 28 source/design/spec bindings captured by `run-nwGNeA/bindings.json` still match. No product, approved model/spec, or status bytes were changed. Receipt: `.scratch/slice3-repair/tooling/repair-receipt.json`.

Factory source is `/home/john/go/src/github.com/agenthands/software-factory`, HEAD `0ead3ed78a94fc3368d4df6ae85289d77e6f4eb1`; its receiver-attribution repair is assigned separately. Latest installed release `f59e03f3dcd4b86acea2ac5592fb003f43fb70e93c119232253962732d34d693` reproduces the original six PASS / three UNKNOWN result. Its `molecule-source.mjs` SHA-256 is `487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea`.

SMTC source owner is `/home/john/go/src/github.com/agenthands/show-me-the-code`, HEAD `fb784663b4d825fca7d5ff3f7b7b91a0ea03e315`. A `git archive HEAD` copy is staged at `.scratch/slice3-repair/tooling/smtc-source`; original unrelated dirty files are untouched. Only staged `crates/smtc-spec/src/eval.rs` differs from that archive. Its scratch-only `examples/slice3_spec.rs` is a direct library runner, excluded from the deployable repair. Recursive manifests are `smtc-before.sha256` and `smtc-after.sha256`.

| Bound artifact | SHA-256 |
|---|---|
| Original eval.rs precondition | `74419bc4db9abb3e331cf3cfe3ed98696c715680c8c57944b2852cb8582f78ea` |
| Final staged eval.rs | `412b7b79ea024e6988f6699cbe7c3686954c294d3f2de1976f2ddcb90bfa42a1` |
| `smtc-eval.patch` | `0f12d1a52d746040cffe9585d8e572662146f34c26e9a352c49b683acf2aebf8` |
| Candidate CLI | `9969701fbf93856d0ad2bb2b8076c731b2ca04ed01590125ad5f2f6c7d384c1f` |
| Candidate daemon | `b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3` |
| Direct library runner | `4fa2ef3a20432dba744a3d8179af6e9123832f221f52fff6f02bf659ad12ec5c` |

## Mechanism and final change

The minimal Rust fixture `if delete { guard()?; operation()?; }` reproduces the classifier error. The lowered CFG gives multiple blocks the same broad span, so the generic line locator refuses. Actual typed call byte identities remain available. The repair keeps that public generic locator unchanged and adds a private ordered-call lookup joining the selected call spelling and source line to its typed instruction and unique byte-span sidecar. Same-line duplicate occurrences and incomplete matching-call identities remain unresolved.

The evaluator reads source bytes once per cached CFG and checks the indexed FNV-1a content identity and file path before interpreting byte offsets. It derives exact line locations from those bytes rather than assuming a uniquely named remaining CFG call represents every source occurrence. The algorithm matches pinned `crates/engine/src/lib.rs:7977` (`simple_hash`); that file's SHA-256 is `5d7bc3212d1ae4d7fd5d1a621f0e00246f9e645eadc1f654979ec31f7f7013bf` in both original and staged trees. The existing source-change/ABA tests remain green.

Within the same block, guard completion must precede the operation's actual instruction index, with both precise sites belonging to that block. This also repairs the existing false-clean result for multiline `guard(operation())`. Tests cover same-line, multiline, and a preceding unrelated call. The existing same-line guard/order refusal remains.

Unsafe summaries now name the short operation and explicitly retain the full callee, for example `Operation 'send_action' lacks required guard (callee: app.transport.send_action)`. Structured `callee_qualified_name`, caller, location and severity remain intact. This is a diagnostic producer repair; no recorded finding, approved expectation or specification is normalized or edited. Global receiver/declaration identity remains Factory's separate obligation.

## Deciding checks

All build/test commands use disk-backed `TMPDIR=.scratch/slice3-repair/tooling/tmp`, `CARGO_TARGET_DIR=.scratch/slice3-repair/tooling/target` and `CARGO_BUILD_JOBS=2`. Full logs are retained under the tooling directory.

1. `cargo test -p smtc-spec --offline`: PASS, 123 passed / 0 failed / 0 ignored (`spec-suite-bound.log`). Includes source-change/ABA, all seven branch cases, nested-order controls, incomplete identity, omitted earlier occurrence, qualified diagnostic/caller filtering and same-line refusal.
2. `cargo check -p smtc-spec --offline`: PASS (`spec-check-final.log`). `cargo build --bin smtc --bin smtc-daemon --offline`: PASS (`matched-build.log`). These are the matched **debug target pair**, not an installed release.
3. Exact approved specs on full current product source and retained unchanged unsafe roots: all four safe legs complete with zero findings; all four unsafe legs complete with exactly one detecting finding. `bound-summary.json` binds the runner hash; `bound-<spec>-<safe|unsafe>.json` and `.stderr` retain raw outputs. Specs: `npm-delete-routes-classify-before-dispatch`, `service-unpublish-reference-before-send`, `service-unpublish-marker-before-delete`, `service-removal-marker-after-put`.
4. Native matched CLI/daemon unsafe reference spec: PASS detecting one finding at `service_unpublish.rs:103`; `native-matched-reference-unsafe.json`, zero-byte `.stderr`. Full qualified callee survives and the approved short substring is present. Fresh isolated runtime is `.scratch/slice3-repair/tooling/d2`; final binaries are under `target/debug/`. Initial matched run request `req-1065743-1793728302302-0` returned `daemon_reused=false`, no diagnostics or refs. The saved replay uses the same pair. A prior installed-CLI/candidate-daemon mix emitted build-mismatch stderr and is not counted as proof.
5. Product/approved-artifact hashes remain unchanged, final staged eval.rs restored byte-identically after sensitivity mutation, and candidate binary hashes remain unchanged. See `repair-receipt.json` and the manifests.

These are structural call-order properties with detecting controls. They do not replace runtime requirements for exact destination/value binding, authorization, persistence, atomicity, replay, or quotas. No exported formal certificate or general cross-language capability grade is claimed.

## Honest TDD chronology

```text
tdd: cfg-branch-location — RED cfg-final-red.log (old evaluator: operation block unresolved at fixture line 6); GREEN spec-suite-bound.log, ordered_rust_question_mark_branch_call_locations (safe, missing, sibling, reversed and awaited cases); actual classifier safe/control pair PASS.
tdd: qualified-diagnostic — RED diagnostic-red5.log (approved short substring absent from qualified summary); GREEN spec-suite-bound.log, ordered_diagnostic_preserves_qualified_callee_and_caller_filter; both actual send controls detect while preserving qualified identity.
tdd: partial-call-identity — candidate-hardening RED partial-identity-red.log (missing operation metadata borrowed guarded sibling); GREEN spec-suite-bound.log, ordered_refuses_partial_call_identity_instead_of_wrong_branch_proof. This RED targets an intermediate candidate, not historical product code.
tdd: omitted-earlier-occurrence — candidate-hardening RED omitted-call-red.log (earlier unguarded same-name call omitted by CFG); GREEN spec-suite-bound.log, ordered_refuses_omitted_earlier_same_named_call. Exact source byte binding replaces the unsafe uniqueness fallback.
tdd: nested-guard-argument — RED nested-red.log (operation argument falsely treated as guarded); GREEN spec-suite-bound.log, ordered_guard_argument_operation_is_not_guarded (same-line, multiline and preceding unrelated call).
tdd: same-line-refusal — characterization sensitivity MUTATION RED same-line-mutation-red.log (exactly 1 failed after disabling only existing same-line refusal); restored GREEN same-line-restored-green.log (exactly 1 passed). Final source restored to SHA 412b7b79...; this is not claimed as a historical bug RED.
```

Intermediate fixture errors, compile errors, and two rejected candidate designs remain in raw logs and are not counted as final evidence. The final current-source/control pairs supersede earlier candidate failures. The separate same-name receiver/free-function misattribution witness remains in `diagnostic-probe/lib.rs` and `diagnostic-red4.log`; Factory must reject or correctly resolve that false edge.

## Installed-release reproduction and SMTC receipt

The latest installed Factory `molecule-verify --plan-root docs/plans/publishing-proxy --slice 3` first hit child-process IPC refusal (`current-router.log`, archive `run-KFDZjo`). The escalated local-IPC rerun completed (`current-router-ipc.log`, archive `.scratch/state/software-factory/contract-evidence/repo-cc718bf594b6832a/run-nwGNeA`) with six production/control PASS pairs and the original three UNKNOWN gaps. This proves the new installed Factory release alone did not solve them.

Stable discovery session: `sf-slice3-tooling-repair`. SMTC search/inspect/read/grep/CFG grounded the repairs; the minimal fixture produced complete CFG evidence. Large production CFG refs above 4,096 estimated tokens were not opened. Pinned hash-function inspection: `smtc inspect symbol --root /home/john/go/src/github.com/agenthands/show-me-the-code --handle /home/john/go/src/github.com/agenthands/show-me-the-code/crates/engine/src/lib.rs:7977:7985 --format json --max-tokens 2048 --session-id sf-slice3-tooling-repair`; request `req-1017741-1793728079872-0`, outer ok=true, complete 9 lines, no refs or diagnostics. Native candidate receipt session: `sf-slice3-tooling-bound`; full argv/env are retained in `native-matched-command.json`.

## Safe persistence boundary

Smallest external source write is original `crates/smtc-spec/src/eval.rs`, guarded by the original and reviewed hashes above. Preserve all unrelated dirty files. Do not copy the debug candidate binaries into the shared installation: this archive excludes pre-existing local autostart/cmd changes in the original checkout.

Owner `CLAUDE.md` requires a matched release build (`cargo build --release -p smtc-cmd -p smtc-daemon --bins`), replacement of both CLI and daemon, and fresh-daemon PID/hash evidence for installed verification. The process floor is `bash scripts/check.sh`; skips/unavailable are not green. Engine/daemon tests run serially (`cargo test -p smtc-engine -p smtc-daemon -- --test-threads=1`). Deployment and daemon coordination require the coordinator's reviewed external escalation. The explicit two-CPU session constraint overrides the owner's general all-CPU preference.

Current persistence/check results are recorded below. Full workspace-wide release acceptance and final Slice 3 approval remain outside this repair report. The isolated candidate stays available; a scoped installed-pair claim requires exact fresh-daemon controls and final Factory verification.

## Reviewed persistence progress

Independent review: `slice-3-smtc-repair-review.md`, SHIP for final eval.rs SHA `412b7b79...` and patch SHA `0f12d1a5...`. Scoped external auto-review authorized applying only that reviewed file. `deployment-before.json` records 8,123 nonignored source files and pre-existing dirty status; immediately after apply, only `crates/smtc-spec/src/eval.rs` differed.

Original-checkout process floor `bash scripts/check.sh`: PASS (`deploy-floor.log`), including formatting, skill corpora/scorer, scoped clippy, dependency bans, capability/parity drift and catalog fail-closed probes. The initial required serial suite attempt is retained in `deploy-engine-daemon-tests.log`; complete campaign and installation results follow below.

The original-checkout checks reuse scratch build outputs, so the immutable reviewed debug pair is now preserved under `.scratch/slice3-repair/tooling/candidate-bin/`. Their hashes remain exactly `9969701f...` / `b508569e...`; runtime `d2` PID 1065745 still serves that reviewed daemon. The daemon image was preserved from `/proc/1065745/exe` after a deployment-check build replaced `target/debug/smtc-daemon`; the copied image's full SHA-256 matches the original receipt. Do not confuse subsequent build-output binaries with the frozen candidate pair.

Deployment environment correction: the first serial run stopped in all 10 `analyze_handlers` cases because long `TMPDIR` made the generated Unix socket path exceed Linux's path limit; the daemon used TCP and fixtures required `socket_path`. No source logic changed. Parent approved shorter disk-backed `.scratch/s3t`; the exact failing test file then passed 10/10 (`deploy-analyze-handlers-shorttmp.log`). The required full serial suite rerun is captured separately in `deploy-engine-daemon-shorttmp.log`; the original failure remains in `deploy-engine-daemon-tests.log`. A subsequent 8,123-file baseline comparison still showed only reviewed `eval.rs` changed, SHA `412b7b79ea024e6988f6699cbe7c3686954c294d3f2de1976f2ddcb90bfa42a1`.

Required serial suite unresolved: corrected-environment run passed 293 tests, failed 1, and reported 1 existing ignored test before stopping in `callable_identity_jvm_native_cli::rust_forward_taint_attributes_the_flow_to_the_unsafe_sibling_only` at assertion line 741. Exact isolated current run reproduced the failure (0 passed / 1 failed, 0.22 s). An isolated copy of all 8,123 pre-repair nonignored source files, including every pre-existing local change, was hash-compared to `deployment-before.json` and matched exactly; the identical isolated test also failed (0 passed / 1 failed, 0.25 s). Both returned zero forward taint paths with Stub fidelity for the real `read_untrusted` to `execute_query` flow inside `UnsafeHandler.handle`. This is a demonstrated pre-existing defect, not a passing check or waived requirement. Receipts: `deployment-baseline-failure.json`, `deploy-taint-isolated.log`, `deploy-taint-baseline.log`, `taint-baseline-manifest.json`. No taint implementation or assertion has been edited. Release build/install remains gated.

Bounded baseline taint diagnosis (no patch): fresh scratch variants renamed either colliding method or removed the safe sibling; all still returned zero paths. Explicit `--source-pattern read_untrusted` and a simplified source body also returned zero. Changing only `execute_query(&data)` to `execute_query(data)` restored one path (`taint-variant-summary.json`, `taint-narrow-summary.json`). SMTC reads bind the cause to `cfg/src/rust.rs:1522`: immutable references currently lower to `Operand::Unknown` via `ValueAllocator::unlowered`; the IFDS sink predicate accepts a tainted argument only through `value_id()`, which Unknown lacks. The scalar conservatism is intentional, so no copy shortcut was applied. An explicit borrow dependency carrier was considered and abandoned before any edit after coordinator scope correction: this unrelated taint defect is not an approved Slice 3 guarantee.

Scope correction: owner process rules require recording the complete serial suite outcome and forbid claiming whole-SMTC release green when it fails; they do not require repairing every pre-existing unrelated language/taint defect before a scoped reviewed evaluator installation. The coordinator authorized continuing a matched release build/install only for eval SHA `412b7b79...`, preserving all failing checks, exact baseline comparisons, and scoped spec/native-control evidence. No tests/assertions, borrow IR, product code, models, or approved specs were changed.

Complete serial engine/daemon campaign: `cargo test -p smtc-engine -p smtc-daemon --offline --no-fail-fast -- --test-threads=1` exited 101, with 2,733 passed, 41 failed, and 114 existing ignored tests across 427 result-bearing test binaries/doc-test groups; 22 targets failed. Full log `deploy-engine-daemon-complete.log` SHA-256 `706a9eeb3cd8e883cc1ea6eb26127cdec21e7ec42c5e78009377526653af492a`; machine summary `deploy-suite-summary.json` lists every failed target. These results are not whole-SMTC release green. No ignore or assertion was added or altered. Exact-name baseline comparisons for all 41 failing tests are running with individual result-count checks, recorded in `baseline-selected-cases.json` and `baseline-failure-comparison/results.jsonl`.

Matching release build started from the original preserved dirty checkout with reviewed eval `412b7b79...`, one Cargo build job alongside one-job baseline comparison. `deploy-release-build.log` captures the standard `cargo build --release -p smtc-cmd -p smtc-daemon --bins --offline`. The first escalation request expired during automatic approval review before execution; its explicitly permitted single retry succeeded. No install/restart occurred at this point.

## Final scoped installation and verification

The standard matched release build passed in 3m04s (`deploy-release-build.log`). Original checkout delta is still exactly `crates/smtc-spec/src/eval.rs` across all 8,123 baseline source files; its reviewed SHA is `412b7b79ea024e6988f6699cbe7c3686954c294d3f2de1976f2ddcb90bfa42a1`, patch SHA `0f12d1a52d746040cffe9585d8e572662146f34c26e9a352c49b683acf2aebf8`. All pre-existing dirty bytes remain intact. Final receipt `deployment-final-receipt.json` also rechecks all 15 product files and all 28 archived source/model/spec bindings unchanged.

Both release executables were installed under `~/.local/bin` after automatic approval of the concrete reviewed scope, old/new hash preconditions, and a coordinated shared-caller pause. The prior pair is preserved at `.scratch/slice3-repair/tooling/installed-backup/`. Installed CLI SHA `fbde1a91373107ccee46a79201a1f084b40ddf7f5763007aff9d458687512bc4` is byte-identical to its rebuilt predecessor; installed daemon SHA is `2d149b7d5cced35398796ec48e9a8b99a44a5a6dc7ea8433a24879d8716344f5`. The old daemon SHA was `0f6e125f0aaaef1d56bd0d0a258151d6a6750e2ea845bb61470c4ad6a166ee52`. `installed-pair-receipt.json` records both installed and backup hashes.

Only identified shared daemon PID 1666734 was gracefully drained, after validating its daemon ID and executable hash; its process image disappeared before replacement. Fresh shared PID 1884231 (`d-1884231-1793731949068`) serves the exact new daemon hash verified through `/proc/1884231/exe`. The first installed spec request `req-1884230-1793731949066-0` reported `daemon_reused=false`. Isolated review daemon `d2` remains PID 1065745 with original candidate image SHA `b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3`; it was not stopped or replaced. Receipts: `shared-stop-receipt.json`, `installed-daemon-receipt.json`.

Installed native controls (`installed-probe-summary.json`, per-case JSON and zero-byte stderr) all pass with nonempty operation matches; safe cases also require nonempty guards:

| Unchanged spec | Production findings | Unsafe findings | Result |
|---|---:|---:|---|
| npm-delete-routes-classify-before-dispatch | 0 | 1 | PASS |
| service-unpublish-reference-before-send | 0 | 1 | PASS |
| service-unpublish-marker-before-delete | 0 | 1 | PASS |
| service-removal-marker-after-put | 0 | 1 | PASS |

All 41 full-suite failures received exact-name baseline comparisons, each proving exactly one test executed. Thirty-six failed at the same assertion location on the byte-identical pre-repair source baseline. Five diagnostics cases passed in isolation on baseline and were then compiled and run on repaired current source; all five also passed there, each with a one-test count. They are `python_verify_diagnostics_agree_on_warm_file`, `python_clean_file_reports_confident_incomplete_false`, `python_type_error_is_surfaced_deterministically`, `ts_clean_file_reports_confident_incomplete_false`, and `ts_type_error_is_surfaced_not_false_clean`. Their full-suite/context-sensitive failures remain unresolved; these isolated passes do not prove a pre-existing defect or an evaluator regression. Comparison receipts: `baseline-comparison-summary.json`, `baseline-compiled-artifacts.json`, `current-isolation-summary.json`; raw logs and exact argv are preserved. The interrupted repeated-build comparator's partial case is retained but excluded from completed results; its owned processes were verified gone before compile-once execution.

Scope verdict: the reviewed evaluator fix, process floor, spec suite (123 passed), matching release build, and all eight installed structural controls pass. The full engine/daemon suite remains recorded as 2,733 passed / 41 failed / 114 pre-existing ignored, and no whole-SMTC release-green claim is made. Factory source attribution and final all-nine obligation verification remain the coordinator's separate reviewed task.
