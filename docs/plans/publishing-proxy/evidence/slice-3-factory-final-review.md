Review kind: code-review
Verdict: FIX FIRST
Question: Does the final Unicode macro repair close the previous false-PASS findings while preserving fail-closed receiver attribution?
Reviewing: targeted recheck of frozen scripts/molecule-source.mjs, scripts/molecule-source.test.mjs and scripts/molecule-receiver.test.mjs; supplied patch, not installed code.

Defects:

[MAJOR] Rust whitespace bypasses the shared macro guard — scripts/molecule-source.mjs:454.
Violated property: unsupported imported-trait macro expansion must remain UNKNOWN, including valid whitespace between the bang and delimiter.
Failure: a truthful hash-bound Extension trait with a macro invocation containing U+0085 after its bang is accepted; the verifier returns PASS and attributes the call to Transport.send_action although Rust dispatches to Extension.send_action.
Evidence: fresh final-byte verifier probe, successful rustc compilation of its fixture, and executable dispatch witness; tier: Structural attribution plus Decision evidence for the compiled witness, not a general compiler-resolution certificate.
Smallest fix: make the shared guard cover Rust token whitespace, or conservatively refuse unsupported whitespace before attribution. Add the real U+0085 macro control and require UNKNOWN; retain masking positives and ordinary receiver PASS. Do not treat JavaScript \s as Rust whitespace.

Do not install candidate 4f32d7d316ed7177717665aa8ddf346e1e10dbab475dcf719ff133231c57309b. All four original findings now reject, but this directly connected lexical boundary remains a confirmed false PASS.

## Deciding witness

Root R: /home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source.
Tool base B: /home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling.

The current shared predicate is `/!\s*[(\[{]/.test(code)`. Rust accepts U+0085 as whitespace; JavaScript's \s does not match it. The fully masked trait retains that character between the bang and opening parenthesis. The fixture is equivalent to the following, where <U+0085> denotes the actual character, not literal text:

```text
macro_rules! 注入 { () => { fn send_action(&self) {} }; }
pub trait Extension { 注入!<U+0085>(); }
impl<T: ?Sized> Extension for std::sync::Arc<T> {}
```

The caller explicitly imports crate::extension::Extension. The receipt selects the complete actual Extension declaration using correct UTF-8 byte offsets and hashes. This does not challenge the reviewed import-linkage premise or rely on a forged declaration.

Focused harness: R/.scratch/final-review-nel-macro.mjs, SHA256 75af0bded3e1e6d2e13fd9b5cfb9176fd5cd39e202045732f44d43616f4b94a4. It copies the prior reviewed harness, changing only the invocation to contain U+0085 and its test label. Run with the preserved candidate-bin/runtime environment below:

`node .scratch/final-review-nel-macro.mjs`

Results: baseline PASS; unicode-nel-macro-extension incorrectly PASS. Raw evidence: R/.scratch/tmp/review-receiver-QGz1Ak/evidence/unicode-nel-macro-extension/run-Bk9YdN. Production 1/attribution.json and guard-removal control 2/attribution.json both bind receiver app.transport to Transport.send_action, key src/upstream.rs#22-46, with Structural confidence. The unsafe control succeeds, so production/control pairing does not cure the wrong operation identity.

The exact generated fixture compiled successfully:

`rustc --edition=2021 --crate-type=lib --emit=metadata --out-dir R/.scratch R/.scratch/tmp/review-receiver-QGz1Ak/src/lib.rs`

Exit0, four unused-code warnings. Extension fixture SHA256: 70ccc8d579dd31ceb4468620323678c6db71864306e1817301d90b6fc385c6cd.

Independent runtime witness R/.scratch/final-review-nel-dispatch.rs uses the same Arc/dyn-trait/macro/blanket-impl shape. Transport.send_action panics; macro-generated Extension.send_action prints its name. Compiling with `rustc --edition=2021 --crate-name final_review_nel_dispatch -o R/.scratch/final-review-nel-dispatch R/.scratch/final-review-nel-dispatch.rs` succeeded with one unused-method warning. Execution exited0 and printed `Extension.send_action`.
Source SHA256: 2778633f8589ea8ca834c4e979c7697c6bc702a4690e986720d5b3eb5ea0e8a0.
Executable SHA256: 88b73ddc7162ac68c35291b762bf54ab52b8176265491e164be5b8feaac16e7d.

## Prior findings and positive controls

All prior findings have a current-byte pass/fail check, using the old failures recorded in the supplied review reports:

1. Unicode identifier macro without exceptional whitespace: original unchanged probe now returns UNKNOWN, “Imported trait has unsupported attributes or macros”; baseline PASS. Fixture R/.scratch/tmp/review-receiver-Mh0HaA.
2. Foreign tuple receiver shadowing: unchanged prior probe returns UNKNOWN. Same-type tuple and target-supertrait negatives also reject.
3. Comment-spoofed declaration: unchanged prior probe returns UNKNOWN, “Imported declaration does not match a unique full-file token span.”
4. Missing receiver metadata with unrelated exact trait/key: unchanged prior probe returns UNKNOWN, “Receiver call lacks a captured type and trait binding.” Prior-probe results: R/.scratch/tmp/review-receiver-zwWa1H/results.json; baseline PASS.

Fresh `node scripts/molecule-receiver.test.mjs` exited0 on final bytes: 11 positive and68 negative checks, fixture R/.scratch/tmp/receiver-test-ZV9zuM. ASCII/Unicode/raw/qualified names, comment-separated invocation tokens, parentheses/brackets/braces all reject. Macro-looking nested comments, quoted strings and raw strings PASS. Raw overriding method r#send_action rejects. Existing receiver identity, declaration spans, drift and CLI cases pass their expected assertions. This suite does not cover U+0085.

SMTC verify request req-1741440-1793730891450-0:0 errors,0 warnings, incomplete:false, one workspace file. This establishes static verification only.

The supplied integrated source-suite log was inspected and records PASS, including the same receiver controls. Supplied final product result B/factory-unicode-product-result.json records all9 unchanged obligations PASS with18 production/control runs under R/.scratch/product-evidence/run-xLuaYz. B/factory-unicode-product-before.json and factory-unicode-product-after.json compare equal,104 entries. Those existing checks do not cover the newly demonstrated macro boundary; they were not rerun during this focused review.

## Subject binding

Before/after fingerprints match:

| Subject | SHA256 |
|---|---|
| scripts/molecule-source.mjs | 4f32d7d316ed7177717665aa8ddf346e1e10dbab475dcf719ff133231c57309b |
| scripts/molecule-source.test.mjs | c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d |
| scripts/molecule-receiver.test.mjs | f3b2f1a80ffdb5df06445d6eb5d103f6e99d14aa58ddcb25defce5c8bc1963c5 |
| .scratch/product-receiver-scope.json | cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9 |
| ../factory-binding.patch | c043999d286bc60c6c3b3741dffb175c9370208192f3bd22a44cdc1f48b6f797 |
| .scratch/recheck-unicode-macro.mjs | 0847931ee970dea664001c90f4c931dc01d6bbcc0a64a5487a605f4bbcef2cab |
| .scratch/review-probes.mjs | fc1e3fb9b24e2be33c9336332182305ec6ccc74ef6af2f6f688029aa7967211f |

Scoped Git status and diff HEAD were empty before/after: staging is ignored by its parent repository, so hashes and supplied patch bind the subject. The initial unscoped Git inventory included unrelated parent files and is not the review scope.

Preserved candidate-bin/smtc SHA256 9969701fbf93856d0ad2bb2b8076c731b2ca04ed01590125ad5f2f6c7d384c1f; candidate-bin/smtc-daemon SHA256 b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3. Deciding tests used Node24.19.0, PATH starting with B/candidate-bin and Node24 bin, SMTC_RUNTIME_DIR=B/d2, SMTC_DAEMON_BIN=B/candidate-bin/smtc-daemon, worker/concurrency/cache/Rayon limits2, TMPDIR=R/.scratch/tmp. No mutable target/debug tool was used.

Conventions (inherited clean standards set: none found in staging root; supplied AGENTS and Ponytail rules): none confirmed in the correction.

Simplifications: none recommended. The local shared predicate addresses the right seam; its lexical coverage is the defect above. No deletion/replacement recommendation or blast-radius claim is made.

## SMTC receipt

Session S: sf-factory-final-review-2026-11-03. The following command templates expand R and S exactly as defined above. All deciding commands invoked preserved B/candidate-bin/smtc directly with the isolated environment. Common suffix: `--format json --max-tokens 2048 --session-id S`. No pipes, redirection or shell wrapper were used.

- Discovery `smtc search symbol --root R --name-pattern hasRustMacroInvocation --limit 6 <suffix>`: run, outer ok:true, inner0 matches, complete/no refs. Initial guessed-name discovery on default CLI; irrelevant to deciding evidence.
- `B/candidate-bin/smtc file grep --root R --pattern 'Macro|macroInvocation' --path-include scripts/molecule-source.mjs --max-results 20 <suffix>`: first refused by sandbox IPC, outer ok:false/daemon_unavailable, no analysis. Identical approved escalated invocation then run, outer ok:true, five matches, complete/no refs. No native source-read fallback. This was a host IPC refusal, not unsupported language.
- `search symbol --root R --name-pattern N --limit 6 <suffix>`, N=hasRustMacroTokens,rustCode,receiverScopes,rustReceiverFiles,attributeSites,exactRustImport,rustIifeCaller,exactRustReceiver: run, outer ok:true, one exact declaration each, complete/no refs. Zero-based search positions converted once to one-based handles.
- `inspect symbol --root R --handle R/scripts/molecule-source.mjs:H <suffix>`, H=453:455,422:449,597:687,691:768,819:877,778:794,457:484,769:776: run, outer ok:true. Complete bodies except receiverScopes, summarized to ref-1 (2214 estimated tokens); narrowed file reads597..642 and643..687 supplied complete deciding text, ref not opened. Manual source-body evidence; no semantic safety inference from inspection alone.
- `file read --root R --path scripts/molecule-source.mjs --start-line A --end-line B <suffix>`, ranges450..480,597..642,643..687: run, outer ok:true, complete/nonclamped/no refs.
- Same file-read recipe for scripts/molecule-receiver.test.mjs ranges1..45,85..140,138..161: run, outer ok:true, complete/nonclamped/no refs. Changed regression and adjacent harness inspected; unchanged remainder inherited from prior complete review.
- Same file-read recipe for .scratch/recheck-unicode-macro.mjs and .scratch/review-probes.mjs ranges1..60: run, outer ok:true, full files36/45 lines, EOF clamped/no refs. Unicode harness subsequently read whole via shared recipe to produce the separate scratch probe; complete/no refs.
- `verify --root R --path scripts/molecule-source.mjs <suffix>`: run, outer ok:true; inner0 errors/0 warnings/incomplete:false/one file; no refs. Static verification only.
- Focused verifier subprocess analyzer commands: run using preserved matched CLI/daemon; archived command/output artifacts in the stated evidence runs. Structural attribution; real execution established baseline PASS and adverse PASS/UNKNOWN outcomes. Exact witness scope, not blanket Rust dispatch proof.

Unchanged during review: yes; candidate source, both tests, receipt, patch and prior probes checked before/after. No shared code/test/receipt edits.
Reviewed: changed hasRustMacroTokens and its four guard owners (receiverScopes, rustIifeCaller, exactRustImport, attributeSites); connected rustCode, rustReceiverFiles, exactRustReceiver; receiver-test delta and harness; unchanged source-suite integration and prior complete test review inherited. Supplied patch, final logs and104-entry manifests inspected.
Deleted: none.
Checked clean: prior four regressions; targeted errors/partial-failure behavior, cleanup/lifecycle/cancellation, shared-state/ordering/races/termination, numeric/resource bounds, maintainability and tests within this correction. Correctness/types/boundaries, invariants/compatibility and input-driven safety have the confirmed finding above. Scope remains the approved repair; no scope-creep finding. Conventions and simplifications clean within targeted scope.
Omitted: defects0; conventions0; simplifications0.
Limitations: import-to-ultimate-declaration/reexport linkage remains an explicit reviewed hash-bound Structural premise, not a compiler certificate. Prior clean capture/provenance/quota paths are inherited; no wider Rust capability audit. Full Factory typecheck/npm test, installation, installed-source drift and full product reruns were not performed here.

Remaining work: repair/regress the whitespace boundary, rerun exact final-byte source/product controls and fresh targeted review, then parent-owned safe patch application, full Factory checks, durable receipt publication, installation and installed drift verification. Reviewer processes are finished; only own scratch witnesses and this report were authored.

