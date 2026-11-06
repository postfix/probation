Review kind: code-review
Verdict: SHIP
Question: Does the frozen Rust token-whitespace repair close the prior receiver-attribution false PASS findings, and does the explicit receipt reach final completion validation?
Reviewing: targeted recheck of staged scripts/molecule-source.mjs, scripts/molecule-source.test.mjs and scripts/molecule-receiver.test.mjs, plus connected receipt validation/completion paths; supplied patch, not an installed release.

Defects: none confirmed; no unresolved material defect suspicion in this bounded correction.

The prior NEL macro false PASS, NEL method override false PASS, Unicode macro false PASS, tuple-match receiver shadow, comment-spoofed declaration and missing-receiver metadata failures now fail closed. Ordinary receiver, harmless imported trait and masking controls still PASS. Real router completion without the required receipt is refused without changing status; the same completion with the explicit environment receipt succeeds. This is bounded Structural attribution with an explicitly reviewed import-linkage premise, not general Rust dispatch proof.

Conventions (inherited prior clean standards set: none found in staging root; supplied AGENTS.md and Ponytail rules): none confirmed. No changed standard was supplied.

Simplifications: none recommended. The shared normalization addresses the demonstrated lexical seam, and the environment input reuses existing receipt validation/capture. No deletion/replacement recommendation or unproven blast-radius claim is made.

## Exact subject

R = /home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source
B = /home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling
Q = /home/john/go/src/github.com/postfix/probation/.scratch/slice3-factory-lexical-review
S = sf-factory-lexical-2026-11-03

These hashes matched the packet before content inspection and remained unchanged at the final check:

| Subject relative to R | SHA256 |
|---|---|
| scripts/molecule-source.mjs | 04335552b9bb06a707d252f4afd0b6a880b349da8c0b2f1336c541f5b5a6270e |
| scripts/molecule-source.test.mjs | c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d |
| scripts/molecule-receiver.test.mjs | 449fa9e533728dd4025df58925d5a4ae18caff7a17dc1bb77ff9e24a71cc36e9 |
| ../factory-binding.patch | b91a78b5eaf0d83cbfbf2c69524be4721c94d703e6fa84948ca63fa4cba73ac5 |
| .scratch/product-receiver-scope.json | cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9 |
| .scratch/review-probes.mjs | fc1e3fb9b24e2be33c9336332182305ec6ccc74ef6af2f6f688029aa7967211f |
| .scratch/final-review-nel-macro.mjs | 75af0bded3e1e6d2e13fd9b5cfb9176fd5cd39e202045732f44d43616f4b94a4 |
| .scratch/check-receipt-completion.mjs | 6435b69eb98f4e652a31f5b815239a86875c78d7d0545cf2eaa15d3408219272 |
| scripts/router | 267f6b2147e0f735e021c4ad169b271d7ed76e7730c788f39c08774d8a401a5d |
| scripts/router.ts | eea55d90a4eb79e03b5a4c121052e662f498d90feb6eaf06fcec3e6f920d3667 |
| scripts/gate-qa.mjs | b2bd3715a87883a55564c251b37585ba75950db3bf419187468751fc2b6082ae |
| scripts/parallel-execution.mjs | fe9efd3118702e7a513fef8ec76ed93e6b603534aa1215b93efe7b074ecbccec |

The packet's suggested factory-receiver-binding.patch filename was absent; the supplied implementation evidence identifies factory-binding.patch, whose hash matches exactly. No missing code was substituted. scripts/router.mts was absent; the inspected shell dispatcher explicitly falls back to the present router.ts.

Scoped git status --short --untracked-files=all and git diff HEAD for the three candidate files were empty before/after. This staging tree is ignored by the parent repository: fingerprints and the supplied patch bind the reviewed bytes, not an assertion that this is a standalone clean checkout.

## Deciding evidence

1. **Fresh complete receiver suite:** Node24.19.0 scripts/molecule-receiver.test.mjs exited0, 17 positive and103 negative checks. Fixture Q/tmp/receiver-test-KovkMK. All eleven Rust Pattern_White_Space code points reject both imported macro and overriding-method cases. NEL/LRM/RLM receiver shadowing and exact declaration controls reject or pass as intended; comment/string/raw-string macro text remains harmless. CLI/environment malformed, missing, empty and conflicting receipt inputs return UNKNOWN. These are public verifier/CLI outcomes using the real candidate analyzer, including deliberate corrupted external analyzer-response controls; no implementation call-count assertions.

2. **Unchanged previous reproducers:** R/.scratch/final-review-nel-macro.mjs returned baseline PASS and unicode-nel-macro-extension UNKNOWN, “Imported trait has unsupported attributes or macros.” Fixture Q/tmp/review-receiver-h1o8X4. R/.scratch/review-probes.mjs returned baseline PASS; target-supertrait, same/foreign tuple shadow, comment-spoofed declaration and missing-receiver-exact-wrong-trait all UNKNOWN. Fixture Q/tmp/review-receiver-J9GQcC. The existing suite also checks Unicode macro without exceptional whitespace and fn<NEL>send_action; both UNKNOWN. Old-byte failures are recorded in the three supplied prior reviews and factory-whitespace-method-red.log.

3. **Independent discriminating probes:** Q/independent-probes.mjs, SHA256 99858b7745a565fa14dd6702acd66de0a83f8d4ce7466dfd1edc6c0ddf5a7b15. Baseline and a supplementary Unicode comment before the target trait PASS. A truthful imported trait combining all eleven whitespace characters between tokens and a supplementary Unicode prefix PASS when harmless; the corresponding macro and overriding-method cases return UNKNOWN. Nested block comments and raw/quoted strings containing the same macro/method-looking text PASS. Final results Q/tmp/review-receiver-PygOrV/results.json, SHA256 41e58a9ecda9aaea85c3b943cc8a93f14dd9c5bcce8b12736b406ef945618476. Two broader harmless probes with all eleven characters inside the target method/callsite are UNKNOWN because SMTC reports analysis_failed: “workspace source parse is incomplete; source population not established.” The first target-method expectation was initially PASS, failed, and was revised to record this conservative unsupported case; it is not counted as supported-language coverage or concealed as a clean parse. No false PASS was found.

4. **Independent real completion route:** ran the unchanged R/.scratch/check-receipt-completion.mjs against Q/tmp/receiver-test-KovkMK. Dispatch, Gate4 prepare/seal/bind/approve and completion with explicit receipt all exited0. Completion without receipt exited4/SOURCE_CONTRACT_REQUIRED, and the harness confirmed status bytes were unchanged. Final status contains the completed slice only after the successful verified write. Results Q/tmp/receiver-test-KovkMK/completion-route-results.json, SHA256 b7431196fe0ad55cc04df1892e9fd1117497a83c68b4726b0fd7b8502582f73b. This synthetic fixture is not product approval.

5. **Static check and supplied exact-byte integration:** fresh SMTC verify request req-1923250-1793732126855-0 returned0 errors,0 warnings,incomplete:false,one workspace file. The inspected final integrated source-suite log B/factory-whitespace-full-suite.log records molecule-source PASS plus the same receiver controls, SHA256 bc8f0b9ea5fe08b8c4c050cace7eac5adee1e8aceacc1581eea1e66c57a0437d. Supplied B/factory-whitespace-product-result.json records all9 unchanged obligations PASS with18 production/control runs under R/.scratch/product-evidence/run-VxwxQp. Before/after product manifests compare byte-identical with104 entries, hash e8a66fe82e3e6b1f6c33869f97e73894411411827d284c11e27a0f9fabe9f682. These supplied broad runs were not redundantly rerun.

Tier: Structural for source attribution and inspected integration; executable deciding evidence for the exact fresh verifier/CLI controls; SMTC verify is Decision evidence for its static check only. No compiler certificate for dispatch is claimed.

## Why the correction is bounded

rustCode normalizes after comment/string/character masking. Pattern_White_Space consists here of BMP code points; replacing each non-LF code point with one ASCII space preserves UTF-16 length, and LF is preserved. Byte boundaries are still computed against the original text, not the normalized string. The fresh supplementary-prefix and mixed-whitespace receipt cases exercise that mapping. Masked text remains masked.

All four macro guard owners receive masked/normalized text: imported trait declarations, IIFE bodies, exact-import caller owners and selected caller owners. rustReceiverFiles uses the same normalized source for method checks and pre-call binding guards. The change therefore closes the direct fn<NEL>send_action override as well as the original bang/delimiter bypass. Existing conservative refusals remain: unsupported macros, raw/unsupported attributes, ambiguous scope binding and missing/conflicting receiver metadata are not treated as exact identities.

At verifySourceContracts, an explicitly present SF_RUST_RECEIVER_SCOPES_FILE conflicts with either explicit receipt input, including an identical explicit path. The env-selected file follows the same JSON/schema/hash/provenance capture as an options-selected file. Its original bytes join receiverInputs.files, its hash/archive appear in receiver-scope/bindings.json, and end-of-run drift checks re-read it. Empty path, missing file and malformed JSON cannot fall through to a successful default.

The inspected route is completeSlice → saveStatus → saveStatusInternal → validateSliceContracts → sourceResult → verifySourceContracts. The source check precedes the temporary status write/rename. Gate checking uses the same sourceResult/verifier boundary. The independent real-router witness resolves this route without relying on a complete semantic caller graph. The inspected parallel publication caller also invokes the shared verifier directly; no parallel native-host conformance claim or wider parallel execution review is made.

The durable product receipt is /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/evidence/slice-3-rust-receiver-scopes.json, SHA256 cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9. The all9 archive's receiver-scope/bindings.json binds this exact path/hash. The receipt binds20 imports and the previously reviewed axum0.8.9 → axum-core0.5.6 IntoResponse declaration, plus package manifests/lock metadata and reexport source bytes. Import-to-ultimate-declaration linkage is retained as the explicit hash-bound Structural premise from the earlier review, not mechanically upgraded into a general compiler-resolution proof. This review checks propagation and unchanged receipt identity; it does not silently re-establish all external import paths.

## RED provenance

The refreshed implementation packet contains:

- tdd: Rust token-whitespace attribution — red: scope-macro-syntax-unicode-nel actual PASS !== expected UNKNOWN; scope-nel-method-override actual PASS !== expected UNKNOWN — green: receiver suite and final integrated source suite passed.
- tdd: receipt input reaches completion verifier — red: scope-env actual UNKNOWN !== expected PASS — green: receiver suite and real scratch gate/complete-slice route passed.

Inspected B/factory-whitespace-method-red.log (SHA256 c521a732b0a9459816125ac4d2b6cce2db052d8a79054e18b194f50323d8153b) records the old fn<NEL>send_action false PASS. Inspected B/factory-receipt-env-red.log (SHA256 4ff28df5f75c64a1c9867c384a2be8e0bd356340a1f56392842ea5fb134aa7ff) records scope-env UNKNOWN before environment support. Additional alphabet/masking/boundary checks are regression breadth, not claims that previously safe cases failed.

## SMTC receipt

Every direct SMTC command used absolute B/candidate-bin/smtc with BOTH:
SMTC_RUNTIME_DIR=B/d2
SMTC_DAEMON_BIN=B/candidate-bin/smtc-daemon

For the templates below, R/B/S expand exactly as above. Common suffix is --format json --max-tokens 2048 --session-id S. No pipe, redirection, shell wrapper or chained command was appended to an SMTC recipe. No native code-read/search fallback was used.

- file read --root R --path scripts/molecule-source.mjs --start-line 1 --end-line 100 <suffix>: refused; outer ok:false, daemon_unavailable, host sandbox denied IPC (“Operation not permitted”), no inner analysis/functions/refs. No verdict derived. Approved escalated reads using the identical pinned daemon environment then succeeded; no shared daemon was touched.
- search symbol --root R --name-pattern N --limit 6 <suffix>, N=rustCode,verifySourceContracts,receiverScopes,rustReceiverFiles,hasRustMacroTokens,rustIifeCaller,exactRustImport,attributeSites: run; outer ok:true, one unambiguous declaration each, complete/not truncated/no refs. Positions resolved once; inspect handles carry one-based display ranges.
- inspect symbol --root R --handle R/scripts/molecule-source.mjs:H <suffix>, H=422:452,910:1084,600:690,694:771,456:458,460:487,781:797,822:880: run; outer ok:true. Bodies complete except verifySourceContracts ref-2 (4649 tokens) and receiverScopes ref-3 (2214 tokens). Neither ref opened. Deciding ranges were narrowed with file read instead. Fidelity: selected source bodies/Manual evidence, no semantic safety inference from body inspection alone.
- file read --root R --path scripts/molecule-source.mjs --start-line A --end-line B <suffix>, ranges410..465,600..644,645..690,910..950,951..991,1051..1084: run; outer ok:true, complete/nonclamped/no refs. The middle unchanged analyzer execution/control loop is bounded by the prior clean review; no new completeness claim for its unrelated behavior.
- file read --root R --path scripts/molecule-receiver.test.mjs --start-line A --end-line B <suffix>, ranges1..45,46..88,89..130,131..175,176..220,221..250: run; outer ok:true; complete, final range EOF-clamped at242, no refs. Whole current receiver harness inspected.
- file read for .scratch/review-probes.mjs (1..60), .scratch/final-review-nel-macro.mjs (1..60 and whole file), .scratch/check-receipt-completion.mjs (1..50): run; outer ok:true, full45/37/37-line files, only EOF clamping, no refs. These exact existing probes were independently executed into Q-owned fixtures.
- file read for scripts/router (1..80), scripts/router.ts (1190..1240,1241..1308,1519..1544), scripts/gate-qa.mjs (112..144,252..288,329..351), scripts/parallel-execution.mjs (150..179): run; outer ok:true, complete/no refs except ordinary EOF clamping of the66-line shell router. Manual route evidence, reinforced by the executable completion witness.
- file grep --root R --pattern verifySourceContracts --path-include 'scripts/*' --max-results 20 <suffix>: run; outer ok:true,14 matches/87 files, complete/no refs. Initial path-include scripts scanned0 files and supplied no negative evidence.
- file grep --root R --pattern 'molecule-source|verifySource|source-contract' --path-include 'scripts/*.mjs' --max-results 20 <suffix>: run; outer ok:true but20-result cap/truncated. Used only for discovery; deciding follow-ups narrowed to router.ts and gate-qa.mjs. router.mts lookup scanned0 files; shell router explicitly selected router.ts.
- Narrow file grep on router.ts ('molecule-source|verifySource|completeSlice|saveStatus', then 'SOURCE_CONTRACT|sourceContract|source-contract|gate-qa'), gate-qa.mjs ('validateSliceContracts|sourceResult') and molecule-source.test.mjs ('molecule-receiver'): run; outer ok:true, complete/no refs, textual candidate locations only.
- callers --root R --name verifySourceContracts --depth 1 --limit 5 <suffix>: run but UNKNOWN; outer ok:false, error timeout after100000ms daemon deadline, no graph/functions/ref. No caller-graph completeness inference. Exact path reads and the executable router route were used for the bounded receipt-propagation question; no daemon restart attempted.
- verify --root R --path scripts/molecule-source.mjs <suffix>: run; outer ok:true, inner0errors/0warnings/incomplete:false/one workspace file, no truncation/ref. Request req-1923250-1793732126855-0; static verification only.
- Fresh verifier subprocess analyzer commands: run against matched pinned CLI/daemon. Artifacts are under the Q fixtures cited above. Mixed all11 target/call-site inventory returns outer ok:false/analysis_failed (“source parse is incomplete”); interpretation UNKNOWN, not clean support. All other stated deciding outcomes are the actual result.json/CLI outcomes.

All fresh executable checks used Node /home/john/.nvm/versions/node/v24.19.0/bin/node, PATH beginning B/candidate-bin and that Node directory, the pinned daemon variables, worker/concurrency/cache/Rayon limits2 and TMPDIR=Q/tmp on disk. Tests did not use the mutable shared daemon or install anything.

Unchanged during review: yes; candidate files, supplied patch, receipt, prior reproducers, completion harness and inspected route neighbors have matching before/after hashes; scoped Git checks repeated.
Reviewed: the targeted rustCode correction and all four macro guard owners; receiverScopes, rustReceiverFiles, attributeSites and verifySourceContracts receipt boundary/capture/drift; complete molecule-receiver.test.mjs; unchanged molecule-source.test.mjs receiver integration; router shell/completeSlice/saveStatus path, gate source validation, parallel shared-verifier caller; exact prior and completion harnesses. Earlier clean capture/provenance/quota behavior is inherited from the prior bounded reviews.
Deleted: none.
Checked clean: correctness/totality/boundary/type/numeric behavior within the corrected supported subset; errors/rollback/partial failure; ownership/cleanup/cancellation/lifecycle; shared state/ordering/races/deadlocks/termination; preconditions/postconditions/invariants/compatibility/side effects; input bounds and obvious implementation security; maintainability; regression tests and supplied RED provenance. Approved scope remains the repair and receipt route; no scope-creep finding. Conventions and simplifications clean within this targeted scope.
Omitted: defects0; conventions0; simplifications0.
Limitations: broader SMTC caller graph timed out; unusual target/call-site whitespace can remain unsupported/UNKNOWN. Import linkage remains a reviewed hash-bound Structural premise. No general Rust resolver/compiler dispatch certificate, whole-Factory review, full npm/typecheck, installation or installed-source drift check. Supplied all9 integration evidence was inspected rather than redundantly rerun.
All reviewer tool processes are terminal. Source/product/model/spec files were read-only; only Q scratch artifacts and this exclusively assigned report were authored. Report/scratch write ownership is released.

Skipped full Factory installation and broad repository checks; parent retains those steps. Remaining risk is the documented supported-subset/Structural evidence boundary, not an unresolved confirmed false PASS in this correction.

