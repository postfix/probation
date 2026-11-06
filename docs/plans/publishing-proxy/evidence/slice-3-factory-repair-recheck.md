Review kind: code-review
Verdict: FIX FIRST
Question: Does the final frozen Factory repair close the three prior false-PASS controls while conservatively rejecting unsupported receiver and receipt syntax?
Reviewing: targeted recheck of scripts/molecule-source.mjs, scripts/molecule-source.test.mjs and scripts/molecule-receiver.test.mjs; frozen supplied patch, not installed code.

Defects:

[MAJOR] Unicode trait macros bypass the receipt safety check — scripts/molecule-source.mjs:630.
Violated property: unsupported imported-trait macros must remain UNKNOWN; receipt classification must not hide an overriding method.
Failure: a valid, hash-bound trait containing `注入!();` is accepted as harmless even though that macro introduces `send_action`. The verifier returns PASS and attributes the selected call to Transport.send_action instead of the Extension method selected by Rust.
Evidence: fresh negative control and valid-Rust compile; runtime dispatch witness prints Extension.send_action; tier: Structural attribution plus executable reproducer (Decision for the compiled witness, not a general dispatch certificate).
Smallest fix: reject unsupported macro invocation punctuation in the imported trait independently of the identifier alphabet; preserve fail-closed attribute handling. Add this macro-expanded overriding-trait control and require UNKNOWN, retaining the ordinary positive case. Do not add a Unicode-name whitelist.

Do not install candidate ba93be1872215a0a94e7f948192008f6b4b52d1aa450b38e255a7d496daa2d6e. The previous three findings are closed, but this new false PASS blocks this candidate.

## Deciding evidence

Root R: /home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source.

Fresh focused probe: R/.scratch/recheck-unicode-macro.mjs, SHA256 0847931ee970dea664001c90f4c931dc01d6bbcc0a64a5487a605f4bbcef2cab. This preserves the prior review harness/model/spec/control and adds this real source fixture:

```rust
macro_rules! 注入 { () => { fn send_action(&self) {} }; }
pub trait Extension { 注入!(); }
impl<T: ?Sized> Extension for std::sync::Arc<T> {}
```

The caller explicitly imports crate::extension::Extension. The receipt truthfully selects the full top-level Extension trait with correct UTF-8 byte offsets and source hashes. There is no fake import linkage or comment span. The baseline returns PASS; unicode-macro-extension incorrectly returns PASS.

Raw evidence: R/.scratch/tmp/review-receiver-ngR4dP/evidence/unicode-macro-extension/run-B73Ktz. Both 1/attribution.json (production) and 2/attribution.json (guard-removal control) record caller save, receiver app.transport, callee Transport.send_action, key src/upstream.rs#22-46. The safe/unsafe analyzer pairing still succeeds, demonstrating why pairing does not cure wrong operation identity. Exact analyzer commands and outputs are archived in that run.

`rustc --edition=2021 --crate-type=lib --emit=metadata --out-dir R/.scratch R/.scratch/tmp/review-receiver-ngR4dP/src/lib.rs` exited0 with four unused-code warnings. A small independent runtime witness, R/.scratch/recheck-unicode-dispatch.rs, uses the same Arc/dyn-trait/Unicode-macro/blanket-impl shape, makes Transport.send_action panic, and makes Extension.send_action print its name. Compiled with `rustc --edition=2021 --crate-name recheck_unicode_dispatch -o R/.scratch/recheck-unicode-dispatch R/.scratch/recheck-unicode-dispatch.rs`; execution exited0 and printed `Extension.send_action`. Thus the witness establishes actual competing-method dispatch, not only syntactic acceptance.

The imported-trait check uses an ASCII-only identifier suffix before `!`. The selected caller check already includes Unicode code points, but the macro lives in the captured imported declaration, so that caller check does not cover it. The later `fn send_action` text check cannot see a macro-generated method.

Runtime witness source SHA256: 7587d1acbf82d42768d4c177e5b6653a407c69e3fd7cc3106461ec0a76e7b936; compiled executable SHA256: 77b3dfe1e82e43a39be96d1c72e3d0be2b58acb0fc27a1a95623e98bb0e52ffe. Valid-Rust fixture extension.rs SHA256: 889f0abd2cd2a21f6d24144b308452d87c17a0b30c72fa69a4f2201a396e2660; action.rs SHA256: 8937d81c3ebbf4c71cada4ac9936ade6d01cd94f012fe54920f40c109a4e7083. No separate procedural-attribute bypass was demonstrated; none is asserted.

## Prior findings rechecked

Unchanged prior probe R/.scratch/review-probes.mjs, SHA256 fc1e3fb9b24e2be33c9336332182305ec6ccc74ef6af2f6f688029aa7967211f, reran on final bytes.

- Tuple foreign receiver: prior false PASS; now UNKNOWN. Same-type tuple and target-supertrait controls also UNKNOWN.
- Comment declaration spoof: prior false PASS; now UNKNOWN with “Imported declaration does not match a unique full-file token span.”
- Missing receiver metadata with exact unrelated callee/key: prior false PASS; now UNKNOWN with “Receiver call lacks a captured type and trait binding.”
- Ordinary receiver baseline: PASS, including required guard-removal detection.

Raw recheck results: R/.scratch/tmp/review-receiver-oTUCTe/results.json; baseline run-JmYasx, foreign tuple run-mX4RBC, missing receiver run-cTxPIh. Comment-span rejection occurs before evidence-run creation. Old-byte failures remain grounded in slice-3-factory-repair-review.md and its recorded reproductions.

The complete new receiver test file was inspected. It executes the real analyzer before mutating JSON; .cjs wrappers avoid the earlier execution error. New source controls cover binding patterns, comments/strings/raw strings/macro token arguments, complete/partial tuple declarations, UTF-8 prefixes, null/omitted receiver metadata, truncated receiver prefixes, live source drift and receipt CLI behavior. Those controls do not include a Unicode-named macro inside the actual selected trait declaration. No code/tests were edited.

## Exact subject checks

Before and after hashes match:

| Subject | SHA256 |
|---|---|
| scripts/molecule-source.mjs | ba93be1872215a0a94e7f948192008f6b4b52d1aa450b38e255a7d496daa2d6e |
| scripts/molecule-source.test.mjs | c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d |
| scripts/molecule-receiver.test.mjs | bed122c17995a531dfc6572a33bde1c07ba72b67a5b4c20db7831c5b18a238a6 |
| .scratch/product-receiver-scope.json | cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9 |
| ../factory-binding.patch | fce50a941faff63e732544d7d0906211d703860f83f607a23a0c19e47191bfa5 |

Scoped git status and git diff HEAD were empty before/after because this staging copy is ignored within its parent repository. The supplied patch and fingerprints establish identity; empty Git output is not evidence of a standalone clean checkout.

Original external Factory source still hashes 487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea. Preserved candidate-bin/smtc and smtc-daemon hashes match the packet: 9969701fbf93856d0ad2bb2b8076c731b2ca04ed01590125ad5f2f6c7d384c1f and b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3.

## Checks and boundaries

Focused probes used Node24.19.0, PATH starting with ../candidate-bin and the Node bin directory, SMTC_RUNTIME_DIR=../d2, SMTC_DAEMON_BIN=../candidate-bin/smtc-daemon, worker/concurrency/cache/Rayon values2, and TMPDIR=R/.scratch/tmp. Initial sandbox execution could not access daemon IPC and produced non-deciding UNKNOWN results; approved elevated reruns successfully executed the matched daemon. No native code-read fallback was used.

SMTC verify on scripts/molecule-source.mjs returned0 errors/0 warnings, incomplete:false, one file, request req-1607293-1793730042775-0. This is static source verification, not proof of receipt soundness.

The packet's final full suite, all9 product obligations/18 source-control runs, 104 unchanged product hashes and corrected ReferenceId end1210 are recorded inputs. This targeted recheck did not rerun those broad checks after discovering the blocking negative control. They do not cover this newly demonstrated behavior. Import-to-ultimate-declaration/reexport linkage remains the explicitly reviewed hash-bound Structural premise; no general Rust compiler-resolution claim is made.

Conventions (prior standards set: none found in staging root; supplied AGENTS and Ponytail rules): none confirmed. The previous review recorded this lens clean; no changed standard is supplied.

Simplifications: none recommended. A conservative punctuation guard is a bounded local correction; no new resolver, abstraction or deletion is proposed. Prior simplifications lens remains clean within this targeted scope.

## SMTC receipt

Session S: sf-factory-repair-recheck-2026-11-03. Every recipe used absolute R above and `--format json --max-tokens 2048 --session-id S` unless stated otherwise. Commands were invoked directly, without pipes or redirection.

- `search symbol --root R --name-pattern N --limit 6`, N=receiverScopes, rustReceiverFiles, attributeSites, rustCode, exactRustReceiver: run; outer ok:true, successful inner results, one declaration each, complete/not truncated, no refs. Resolved source positions are zero-based; displayed lines/handles one-based. An initial combined literal pattern with pipes returned0 and SEARCH-METACHAR; it was used only as failed discovery, then replaced with separate exact names.
- `inspect symbol --root R --handle H`, H=R/scripts/molecule-source.mjs:591:681, :685:762, :813:871, :422:449, :763:770: run; outer ok:true. All but receiverScopes contain complete bodies. receiverScopes summarized to ref-134, token estimate2218; narrowed complete file reads591..635 and636..681 supplied deciding text instead of opening the ref. Fidelity: Manual body evidence, no semantic safety inference from inspection alone.
- `file read --root R --path scripts/molecule-source.mjs --start-line A --end-line B`, ranges591..635,636..681,764..785: run; outer ok:true, complete/nonclamped, no refs. Complete receipt classification/provenance and receiver identity neighbors inspected.
- `file read --root R --path scripts/molecule-receiver.test.mjs --start-line A --end-line B`, ranges1..38,39..74,75..110,111..145,146..177: run; outer ok:true, complete/nonclamped, no refs. Complete changed harness inspection.
- `file read --root R --path .scratch/review-probes.mjs`: run; outer ok:true,45 lines complete/no refs; prior probe inspected and reused unchanged.
- `verify --root R --path scripts/molecule-source.mjs`: run; outer ok:true, inner0 errors/0 warnings, incomplete:false, one workspace file, no refs. Decision tier for static verification only.
- Focused verifier subprocess analyzer recipes: run; matched CLI/daemon, production and mutation commands archived under the deciding run's command JSON files, Structural attribution and executable negative control. Initial sandbox refusal was excluded from deciding results; approved IPC rerun passed baseline. No unsupported command or language leg remains decisive.

Unchanged during review: yes; candidate source, both tests, patch, receipt and prior probe fingerprints checked before/after; scoped Git commands repeated.
Reviewed: targeted corrections in receiverScopes declaration validation, rustReceiverFiles lexical binding/scope guards, exactRustReceiver, attributeSites; risk-bearing rustCode and exactRustImport neighbors; complete molecule-receiver.test.mjs and source-suite import diff. Prior clean capture/provenance/drift/quota paths remain bounded by the original review and were not independently re-proven.
Deleted: none.
Checked clean: prior three regressions; targeted cleanup/lifecycle, errors/partial-failure behavior, shared-state/ordering, numeric/resource bounds, maintained compatibility and tests within rechecked scope. Correctness/types/boundaries, invariants and input-driven safety are covered by the confirmed Unicode macro finding. Conventions and simplifications: no confirmed findings. Approved goal remains unchanged; no scope-creep finding.
Omitted: defects0; conventions0; simplifications0.
Limitations: no broad Rust resolver proof; no renewed full product/import-linkage review after blocker; no full Factory npm/typecheck suite, installation or installed drift check. Supplied previous clean lenses bound this targeted recheck; no whole-repository approval.

Remaining work: fix and regress this Unicode macro control; rerun final-byte focused and full source suites and product obligations; fresh recheck on new exact hashes; then parent-owned safe patch application, full Factory checks, installation and installed-source drift verification. No shared installation occurred. Reviewer source ownership remains read-only; scratch probes and this report are the only authored files.

