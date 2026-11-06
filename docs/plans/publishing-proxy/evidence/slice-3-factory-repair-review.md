Review kind: code-review
Verdict: FIX FIRST
Question: Does the frozen Factory repair preserve fail-closed receiver attribution and reject incomplete or misleading receipts?
Reviewing: staged `scripts/molecule-source.mjs`, its test import, and new `scripts/molecule-receiver.test.mjs`; supplied patch, not installed code.

Defects:

- [MAJOR] Tuple match patterns bypass receiver shadowing checks — scripts/molecule-source.mjs:691. A different receiver type is attributed to the original parameter's trait.
- [MAJOR] Comment text is accepted as a receipt declaration — scripts/molecule-source.mjs:610. A real overriding extension trait can be misclassified as a harmless struct.
- [MAJOR] Missing receiver metadata bypasses captured binding — scripts/molecule-source.mjs:811. An exact-confidence edge naming an unrelated trait/key is accepted when its receiver field is omitted.

Do not install source `deb3d232d8bde2242e0250ee88a4370dbb3a317c39423c3358a840ea840f74b0`. The existing final-byte suite passes but does not cover these false-PASS controls.

## Deciding evidence and smallest fixes

1. **Tuple match shadowing.** Violated property: the selected receiver must be the parameter whose field/trait closure was captured. With `fn save(app: &Arc<App>, other: &crate::OtherApp)` and `match (other,) { (app,) => { app.transport.send_action(); } }`, where `OtherApp.transport` is `Arc<dyn OtherTransport>`, the verifier returns PASS and archives `callee_name: Transport.send_action`, `callee_key: src/upstream.rs#22-46`. The original `app` parameter is unused; rustc successfully compiled the captured fixture (four unused-code warnings). The guard-removal control also passes its expected detection, so safe/unsafe pairing does not cure the wrong identity. Evidence tier: Structural attribution plus executable reproducer; compiler Decision evidence establishes that the fixture is valid Rust, not the verifier's semantic correctness. Smallest fix: conservatively reject unsupported match/pattern binding constructs containing the receiver, or all match syntax in this narrow supported subset, until lexical binding is established. Add this different-type tuple-pattern negative control and related struct/ref patterns; preserve the ordinary positive case. Reassignment/shadowing must not be inferred safe merely from a missing `let` match.

2. **Comment declaration spoof.** Violated property: receipt spans identify actual declarations in the captured file, not independently parsed substrings. The captured extension file is `/* pub struct Extension; */\npub trait Extension { fn send_action(&self) {} }\nimpl<T: ?Sized> Extension for std::sync::Arc<T> {}\n`. The receipt selects bytes 3..24, kind `struct`, name `Extension`, with correct hashes. The current code parses this selected substring independently and only checks brace depth in the full masked file, so it accepts a nonexistent struct and returns PASS. Actual import-to-declaration linkage remains an explicitly reviewed premise; this finding does not demand rustc resolution, but the machine check claiming that a declaration exists is false even before linkage review. Evidence tier: Structural plus executable reproducer. Smallest fix: anchor start/end to a real declaration in the fully masked/parsed source and reject spans inside comments/strings, partial or concatenated declarations, and nonmatching full-file tokens. Add comment and string-span negative controls using correct hashes.

3. **Omitted receiver metadata.** Violated property: incomplete graph metadata cannot bypass required receiver/type/trait binding. A wrapper runs the real matched SMTC and changes only caller edges: deletes `call_site.receiver`, sets confidence to `exact`, callee name to `Other.send_action`, and key to `src/unrelated.rs#0-10`. The verifier returns PASS for production and its unsafe control. `attributeSites` gates both the binding attempt and required-binding rejection on receiver metadata being non-null; exact confidence then passes its generic identity check. Evidence tier: Structural plus executable protocol-negative control. Smallest fix: determine receiver syntax from the captured source expression and require matching receiver metadata and captured qualified identity for every receiver call; an omitted/null receiver must not become a free-function path. Add missing/null receiver controls with unrelated qualified names and keys, while preserving valid free-function behavior.

## Checks and artifacts

Root `R`: `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source`.

- Node24 `scripts/molecule-source.test.mjs`: exit 0, existing source-verifier regression suite plus 5 receiver positives and 35 receiver negatives. Log `R/.scratch/review-final-suite.log`; receiver fixture `R/.scratch/tmp/receiver-test-AZvVlH`. Initial sandbox attempt failed before meaningful execution; escalated local-daemon run succeeded.
- Additional read-only verifier probes: `R/.scratch/review-probes.mjs`; final log `R/.scratch/review-probes-final.log`, exit 0. Baseline PASS; target supertrait collision UNKNOWN; same-type tuple shadow PASS; different-type tuple shadow false PASS; comment declaration false PASS; missing receiver/wrong exact trait false PASS. No source or test files were modified.
- Final probe evidence root: `R/.scratch/tmp/review-receiver-uvcC2l`. Deciding runs: `evidence/tuple-match-foreign-shadow/run-kxnveZ`, `evidence/comment-spoofed-declaration/run-E0Opc7`, `evidence/missing-receiver-exact-wrong-trait/run-cxcK1V`. Each includes exact commands, complete analyzer outputs, selected attribution, production and mutation results, captured sources and receipt bindings.
- Earlier identical tuple fixture successfully compiled with `rustc --edition=2021 --crate-type=lib --emit=metadata --out-dir R/.scratch R/.scratch/tmp/review-receiver-nRFuaS/evidence/tuple-match-foreign-shadow/run-rU3FqE/1/source/src/lib.rs` (exit 0). Earlier false-PASS controls recorded in `R/.scratch/review-probes.log`.
- SMTC `verify` candidate source: 0 errors, 0 warnings, `incomplete:false`, one file. This static check does not establish receiver soundness.

Test environment: `/home/john/.nvm/versions/node/v24.19.0/bin/node`; PATH starts with that Node directory and `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/target/debug`; isolated `SMTC_RUNTIME_DIR=/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/d2`, matching `SMTC_DAEMON_BIN=.../target/debug/smtc-daemon`; worker/concurrency/cache/Rayon counts 2; `TMPDIR=R/.scratch/tmp`. Executed commands: `node scripts/molecule-source.test.mjs` and `node .scratch/review-probes.mjs`, with output captured to the logs above. Direct sandbox IPC was refused; approved elevated test invocations accessed the existing daemon. No installation occurred.

## Subject and fingerprints

Before/after source, tests, receipt and patch fingerprints match:

| Subject | SHA256 |
|---|---|
| scripts/molecule-source.mjs | deb3d232d8bde2242e0250ee88a4370dbb3a317c39423c3358a840ea840f74b0 |
| scripts/molecule-source.test.mjs | c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d |
| scripts/molecule-receiver.test.mjs | 0c9442fb7123045aac31b8c7f22ac0ad380cab3b04c61b0e94f04dc68f9f7759 |
| .scratch/product-receiver-scope.json | 64b7712c3634743aaa102277e1ad5f3cd5c57670867051f6cc09d73c9dd0ce11 |
| ../factory-binding.patch | 3bcd90873427f551d60e9bd1678ced52cf2dbf8cfa5188953e1df33f41f3e169 |

Baseline original Factory source was fingerprinted `487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea`; staged diff is 209 insertions/19 deletions in the source, plus the test import and new test file. Scoped Git status is empty because the staging directory is ignored within the parent repository; reviewed identity is established by supplied patch and exact fingerprints, not that empty status. No staged standalone Git repository was assumed.

Supporting fingerprints recorded before inspection: molecule-source.test-support.mjs `a13246adca8fefdc4c81e6f0926d81f68a867861f8bdf0fdd3581760ef0ee2dd`; parallel-contracts.test.mjs `c22e49126ca3d44bca099c0bb554282d74b8151218cdeb889883bad0b0970dda`; molecule-yaml.mjs `d4110073df1de5a08ef2d7dff06b94c41f576f0ca0eb1316347a480edac89f43`; molecule-flow.mjs `8514c59399ee2a5d9ec193cb1779fad910f876efe9341fe44c9d277b11027772`; .scratch/check-product.mjs `339935d5be99f1a0a9e5075de75de6351ddaa8760f26e9d45a5630206aec0e93`.

Conventions (standards files read: none found in staged root): none confirmed. SMTC searches for AGENTS.md, CLAUDE.md, CONTRIBUTING*, CODING_STANDARDS*, docs/codebase-overview.md returned no matches; the supplied AGENTS instructions and active Ponytail instructions were followed. The ignored staging copy limits claims about standards in the external full checkout.

Simplifications: none recommended. Conservatively rejecting unsupported receiver shapes is the smallest correction to finding 1; there is no evidence justifying a general Rust resolver or new abstraction. No deletion/replacement recommendation is made without blast-radius evidence.

## SMTC receipt

Session `S=sf-factory-repair-review-2026-11-03`. Common literal suffix for entries below: `--root R --format json --max-tokens 2048 --session-id S`; R and S expand to the absolute root/session above. Each command was invoked directly, without shell redirection or pipes.

- `file find` for each of the five standards patterns, `--max-results 20`: run; outer ok true, inner successful, complete/not truncated, 0 matches; Manual location evidence only.
- `file read --path scripts/molecule-source.mjs` with ranges 1..100, 422..466, 467..514, 554..587, 739..789, 871..910, 911..938, 939..978, 979..1040: run; outer ok true, full bounded contents, no refs; Manual code evidence. `file grep` function/receiver inventory reached max-results 20 and was truncated; used only for locating declarations, never as a clean result.
- `search symbol --name-pattern N --limit 6` and `inspect symbol --handle R/scripts/molecule-source.mjs:L:E` for rustImports 515:553, receiverScopes 591:668, rustReceiverFiles 672:738, attributeSites 790:841, verifySourceContracts 871:1040: run; all searches resolved exactly one declaration, complete. First four inspections returned complete bodies. verifySourceContracts inspection returned ref-129, estimate 4521 tokens, not opened; narrowed file reads cover its changed implementation and control execution. Names resolved before findings; zero-based search positions mapped to one-based displayed lines.
- `file read` new receiver test ranges 1..45, 46..85, 86..125, existing source test 1..50, test-support 1..35, check-product 1..50: run; successful Manual source evidence. Initial receiver read 1..100 was summarized into ref-124 and replaced with narrow reads; EOF clamps on receiver 86..125 and check-product concern nonexistent trailing lines only. Existing test-file diff showed only the new receiver-suite import.
- `review slice --function rustReceiverFiles --direction both`: run; outer ok true, resolution matched 1/ambiguous false, 19 entries, not truncated. Exact callers include exactRustReceiver and verifySourceContracts; structural same-name callees `read`/`replace` point into unrelated files and were not accepted as value-provenance proof. Structural, not dispatch certification.
- `review blast-radius --symbol verifySourceContracts --reverse --include-resolution`: run; outer ok true, summarized/truncated ref-130, estimate 8891 tokens, not opened. Scope limitations preserved; no safe-deletion conclusion follows.
- `verify --path scripts/molecule-source.mjs`: run; outer ok true, inner 0 errors/0 warnings, incomplete false, one workspace file, no refs. Decision-tier static verification only.
- Focused verifier subprocess SMTC evidence: run with matched isolated CLI/daemon; exact argv archived under every deciding run's `*-command.json` and `command.json`; complete positive production and detecting mutation output accompanies each false PASS. Initial sandbox invocation returned daemon_unavailable because IPC was denied; rerun with approved IPC succeeded. This refusal did not require native source-read fallback; project inspection remained SMTC-backed.

Unchanged during review: yes for frozen candidate source, changed tests, patch and product receipt; checked before/after. Original candidate files were never edited.
Reviewed: all changed code in rustImports/rustImportFiles, receiverScopes, rustReceiverFiles, exactRustReceiver, attributeSites, verifySourceContracts capture/run/drift/quotas, CLI option handling; added test import and complete new receiver suite. Inspected neighbors rustCode, topLevelItem, completeReport, operationSpec, exactRustImport, validSpan, resolveSubject, validateGraph and source-test setup/support; preserved existing free-function regression suite ran successfully. Deleted: none.
Checked clean: errors/partial failure and rollback; cleanup/lifecycle within changed scope; synchronous ordering/shared-state handling within changed scope; arithmetic/resource bounds and quota additions had no confirmed issue; no added repeated business rule or misleading representation defect beyond findings above; tests had supplied RED evidence and meaningful existing safe/unsafe controls; no confirmed goal scope creep. Correctness/boundaries/types, preconditions/invariants/compatibility/side effects and input-driven security defects are covered by findings 1–3. Conventions and simplifications: no confirmed findings.
Omitted: defects 0; conventions 0; simplifications 0.
Limitations: full product nine-obligation rerun and full Factory npm test/typecheck were not run after blocking findings; no installed-release/drift review; blast-radius output is incomplete; no arbitrary Rust dispatch/compiler proof or broad trust-boundary audit. The product receipt's external linkage premise was not re-reviewed after the decisive false-PASS controls. The original actual product PASS on older bytes does not justify installing this candidate.

Remaining work: fix the three controls, rerun this exact probe plus existing suite on fresh hashes, then full product safe/unsafe obligations, standard Factory checks and independent targeted recheck before installation. Candidate ownership is released; no further source changes or review test processes remain active.
