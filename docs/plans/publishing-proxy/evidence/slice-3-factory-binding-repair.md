# Installed Factory repair: verified, zero drift

The reviewed receiver attribution repair is installed in immutable release **`2ae901dc66af5637abceac7201f74c2511ebfe98c9fd76a9250fe661d0f4673c`**. The final standard `npm run install:emergency` completed with exit0 after normal typecheck and the complete npm suite, ending in `router Slice 12 CLI smokes: PASS`. `npm run drift` completed with **299 entries,0 drifted** for that exact release. The prescribed emergency path skips the provider evaluation matrix; no additional test or assertion was skipped.

Immutable router:

```text
/home/john/.local/share/software-factory/releases/2ae901dc66af5637abceac7201f74c2511ebfe98c9fd76a9250fe661d0f4673c/skills-codex/sf-start/scripts/router
```

Installed `molecule-source.mjs` is SHA256 `04335552b9bb06a707d252f4afd0b6a880b349da8c0b2f1336c541f5b5a6270e`, equal to the independently reviewed implementation. Final receiver test SHA256 is `5b82018c420ffbe745dc058da01c508afd5d54a994b6a6338c719dd87869e4a5` after the independently reviewed three-newline EOF trim. The source-suite integration remainsc10ff73c. The mechanical103 case pins use snapshot `f435d012b4a78e9d2e880e5cbd0aaed2af65116f1ba460a6d77e086b2d3d1b4c`; all58 zero and5 special pins were preserved. All106 frozen Factory hashes and exact changed-file scope match; `git diff --check` passes. The new test has intent-to-add metadata only; no contents are staged and no commit was made by this worker.

## Installed product proof

The immutable installed router, installed SMTC CLI `fbde1a91373107ccee46a79201a1f084b40ddf7f5763007aff9d458687512bc4` and daemon `2d149b7d5cced35398796ec48e9a8b99a44a5a6dc7ea8433a24879d8716344f5`, with default runtime and candidate runtime variables cleared, returned **PASS for all9 unchanged obligations and all9 unsafe controls** (18 runs), exit0, stderr0.

Archive: `/home/john/go/src/github.com/postfix/probation/.scratch/state/software-factory/contract-evidence/repo-cc718bf594b6832a/run-xKUiUa`.

Both service-reference-before-delete and service-marker-before-delete production/control attribution records identify `Transport.send_action`, key `src/upstream/mod.rs#1739-1876` (runs11–14). All104 product Rust source/model/sidecar/spec hashes remain unchanged. These are Structural SMTC source obligations with unsafe-control sensitivity, not arbitrary functional correctness or a general compiler method-resolution certificate. The explicit reviewed import/reexport premise remains fully hash-bound in the captured receipt/source closure.

Durable receipt input: `docs/plans/publishing-proxy/evidence/slice-3-rust-receiver-scopes.json`, SHA256 `cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9`. Use it per invocation through `SF_RUST_RECEIVER_SCOPES_FILE`; it is also consumed by the completion/save-status/gate verification source boundary. The real scratch complete-slice proof is recorded below. This worker did not complete or otherwise write the product slice status.

Example installed verification from product root, with candidate runtime settings cleared:

```sh
env -u SMTC_RUNTIME_DIR -u SMTC_DAEMON_BIN \
  SF_NODE=/home/john/.nvm/versions/node/v24.19.0/bin/node \
  PATH=/home/john/.local/bin:/home/john/.nvm/versions/node/v24.19.0/bin:/usr/local/bin:/usr/bin:/bin \
  SF_RUST_RECEIVER_SCOPES_FILE=/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/evidence/slice-3-rust-receiver-scopes.json \
  /home/john/.local/share/software-factory/releases/2ae901dc66af5637abceac7201f74c2511ebfe98c9fd76a9250fe661d0f4673c/skills-codex/sf-start/scripts/router \
  molecule-verify --plan-root docs/plans/publishing-proxy --slice 3
```

For parent-owned completion, use that same per-invocation environment and immutable router with normal `complete-slice` arguments, the freshly read status hash and actual required review verdicts. Do not combine the environment input with a receipt CLI option; conflict rejection is intentional.

## Decisive receipts

All tooling paths below are under `.scratch/slice3-repair/tooling/`.

- Compact final receipt: `factory-deployment-receipt.json`, SHA256 `c282876264dc536fb11b5619cc98a1a6ecd55181162366e690bd44ab6c88e075`.
- Final normal fullcheck/install log: `factory-deploy-install-final.log`, SHA256 `955a0cc90fed0a65084e2e60387ba8561fde1ce1f78f8a95d88afbd8e27ff48c`.
- Drift log: `factory-deploy-drift.log`, SHA256 `0e03e7df271a2797ef98d79cda342d1686105ece4efa89f324ac58d5409fefd2`.
- Installed source/control result: `factory-installed-product-result.json`, SHA256 `cf71378613ec8a673a32884e90a24da90450549c5d256a2cc87718eba3cdce0e`; `factory-installed-product-stderr.log` is empty.
- Product before/after hashes: `factory-installed-product-before.json`, `factory-installed-product-after.json`. Factory frozen scope: `factory-final-change-manifest.json`, SHA256 `473fc922d4bfc48c24fae3e6b3f9d0161aa9c1d103d204f6f8f3deb7e3c93f1c`.
- Independent lexical SHIP: `evidence/slice-3-factory-lexical-recheck.md`, SHA256 `b52c1f7d8835fa28e3667f12110729edafae98a040fe0da1e0e946644dcfaa9e`; independent mechanical pin/EOF SHIP: `evidence/slice-3-factory-pin-recheck.md`, SHA256 `009f0596e9774486f99f0e6d18f5c4b49b220295877bd5d0603c19b7153552d3` (both paths relative to plan).

Two earlier installer failures remain preserved, not reclassified as passes: `factory-deploy-install.log` (baseline host-test timing race, causally reproduced on pristine source) and `factory-deploy-install-retry.log` (stale generated snapshot pins). The diagnosis, unchanged assertions, authorized environment correction, exact mechanical pin update and focused checks are retained in the historical sections and receipts below. The final full installer gate passed with those assertions intact.

All worker test/install processes have completed. Exclusive writer ownership is released. Final product QA and completion remain parent-owned; no further source repair is pending in this packet.

---

# Historical repair and deployment record

# Mechanical snapshot re-pin and EOF-only correction pending review

The authorized normal-priority installer retry passed the formerly failing host-stop assertion and the receiver/source suites. It then stopped before promotion at `skill-evals.test.ts:2154`: fake-provider canary refused stale snapshot manifest `4e694e59a8832e2f8b200c231e0e5df74abb10bbcfe10ba817b6912326e50cb8`. The full log is `factory-deploy-install-retry.log`; no assertion was bypassed.

Factory AGENTS.md25–33 explicitly prescribes replacing the dominant repository snapshot pin for this exact failure, leaving zero and fixture-root pins unchanged. Parent authorized that mechanical scope expansion and a reversible `git add -N -- scripts/molecule-receiver.test.mjs` so the new reviewed test is included by `git ls-files` in future snapshots. No file contents were staged; product Git index was untouched. Index before/after receipt is `factory-index-intent-to-add.json`.

The dominant old pin `ab3cecd72324d6196538c672be33a58d13d1ac17e434ee329e8e672b8111d7a3` occurred in exactly103 case files. Pristine original HEAD's snapshot is `3f697870a7e84d724f03d680768c3b1ea5d6681e2895e6af8dd05a97d67c0759`, so those pins were already stale at pristine HEAD. Complete current/pristine manifests show only the three reviewed source/test differences; this is not a mode/permission difference. Snapshot provenance is in `factory-snapshot-manifests.json` and `factory-snapshot-differences.json`.

Intent-to-add made Git's whitespace check see three redundant EOF newline bytes in the previously untracked receiver test. Parent authorized removing only those bytes, preserving its final newline and every nonblank byte. Its new hash is `5b82018c420ffbe745dc058da01c508afd5d54a994b6a6338c719dd87869e4a5`; source verifier04335552 and source-suite integrationc10ff73c are unchanged. Exact formatting receipt: `factory-test-eof-trim.json`.

Final snapshot pin: `f435d012b4a78e9d2e880e5cbd0aaed2af65116f1ba460a6d77e086b2d3d1b4c`. Exactly103 matching manifest fields now use it. All58 zero pins, all5 other non-dominant occurrences, and every nonpin byte remain unchanged. Case backups, before/after hashes and inventory are in `factory-case-repin-receipt.json`; pin-only patch SHA256 `ccd4c4de355813faf2ff4bc755a496fdabf83e3853219efa235c9e0d399140ae`. The source3 patch after EOF trim is `b47fb69a065aaf7bc4120b90ec228c2916d39417ff207d72775e79fc9ace1256`. `factory-final-change-manifest.json` freezes all106 changed files; no subsequent source/pin edits while independent review runs.

Focused receiver test passed (`factory-repin-receiver.log`), full `git diff --check` passed, and the post-repin snapshot still equalsf435d012. The exact `scripts/skill-evals.test.ts` file containing the fake-provider canary passed (exit0, `factory-repin-skill-evals.log`); there is no individual-canary selector. No third full installer campaign has started. Parent requires focused checks and fresh independent pin/EOF SHIP before that campaign. Installed Factory remains oldf59e03 until actual promotion succeeds.

All artifact paths above are under `.scratch/slice3-repair/tooling/`. No product source/model/spec or guarantee changed.

---

# Installer diagnosis and authorized single standard-priority retry

The unchanged focused `parallel-host.test.mjs` passed on both the reviewed checkout and a pristine clone of original HEAD0ead3ed7 under the same Node24, installed SMTC pair, dependencies and nice10 environment. The host test/host adapter/store/coordinator files are byte-identical across those checkouts; the receiver repair is not invoked by the failing PauseRun/stop branch.

A diagnostic preload on pristine HEAD delayed only the controller for1500ms after reading the readiness assertion input, leaving all repository source and assertions unchanged. It reproduced the exact original failure at line400 (`Observation` instead of `Stopping`). The captured terminal record had exitCode0, stopped:false, quiescent:true: the worker's fixed1000ms lifetime elapsed before stop, which legitimately returned its terminal observation. This proves baseline timing sensitivity. It does not prove nice10 was the sole cause of the original scheduler delay; the failed live fixture was cleaned up. The previously retained LrosNt fixture is an earlier deliberate malformed-terminal control, not that failed live worker.

Exact evidence and hashes: `.scratch/slice3-repair/tooling/factory-installer-diagnosis.json`, logs `factory-host-focused-current.log`, `factory-host-focused-pristine.log`, `factory-host-delay-pristine.log`, trace `factory-host-delay-trace.jsonl`, and diagnostic-only `host-delay-probe.cjs`. No source or test repair was made.

Parent authorized one retry of the ordinary `npm run install:emergency` command without the worker-added nice10 wrapper, with no concurrent build. The first failure is preserved. The same full gate/assertions remain; no extra skips. A repeated failure stops for a separately reviewed fixture repair rather than a retry loop.

---

# Deployment attempt: full-suite blocker before promotion

Independent lexical review returned SHIP in `slice-3-factory-lexical-recheck.md`, SHA256 `b52c1f7d8835fa28e3667f12110729edafae98a040fe0da1e0e946644dcfaa9e`. Parent authorized deployment. The hashguard applied exactly the three frozen reviewed files to original Factory HEAD0ead3ed7; backups and exact applied hashes are retained under `.scratch/slice3-repair/tooling/`.

The single prescribed `npm run install:emergency` campaign passed typechecking, then **failed the ordinary full npm suite** at `scripts/parallel-host.test.mjs:400`: expected `Stopping`, observed `Observation`; exit1. Log: `.scratch/slice3-repair/tooling/factory-deploy-install.log`. Last preceding successful case: `V08 accepted pause parks saved launch: PASS`. The test also reported retained fixture `/home/john/go/src/github.com/agenthands/software-factory/log/p4-host-LrosNt`, quiescent=false; its lifecycle is not claimed clean.

**No promotion occurred.** Installed Factory current remains `f59e03f3dcd4b86acea2ac5592fb003f43fb70e93c119232253962732d34d693`. Source diff remains precisely the three reviewed files with unchanged04335552/c10ff73c/449fa9e5 hashes. No test suppression, broad repair or rerun was attempted. Zero drift and installed all9 are pending and are not claimed. Installer process is terminal; retained test-fixture processes have not been independently audited or terminated.

Machine-readable receipt: `.scratch/slice3-repair/tooling/factory-deployment-receipt.json`. All104 product/model/spec hashes remain unchanged (`factory-deployment-failure-product-after.json`). Parent and final sf-verification were notified. Investigation of this required full-suite blocker is a separate parent-directed decision; do not bypass the install gate.

---

# Current candidate after Rust-whitespace FIX FIRST

**Frozen for fresh independent review; not installed.** The report `slice-3-factory-final-review.md` remains unchanged at SHA256 `7494be4adc6fe4e0580579eaa4932ebb0f821458fb5cf52f36fb7f582b255353`. Historical candidates and reviews below are not installation clearance.

## Frozen subject

- `scripts/molecule-source.mjs`: `04335552b9bb06a707d252f4afd0b6a880b349da8c0b2f1336c541f5b5a6270e`
- `scripts/molecule-source.test.mjs`: `c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d`
- `scripts/molecule-receiver.test.mjs`: `449fa9e533728dd4025df58925d5a4ae18caff7a17dc1bb77ff9e24a71cc36e9`
- `patch`: `b91a78b5eaf0d83cbfbf2c69524be4721c94d703e6fa84948ca63fa4cba73ac5`
- `receipt`: `cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9`

Source paths are under `.scratch/slice3-repair/tooling/factory-source`; patch is `.scratch/slice3-repair/tooling/factory-binding.patch`. The exact receipt is also published unchanged at `docs/plans/publishing-proxy/evidence/slice-3-rust-receiver-scopes.json`. `factory-candidate-hashes.json` and the deployment apply script bind these same bytes.

## Common lexical cause and repair

JavaScript `\s` is not Rust token whitespace. The unchanged reviewer NEL macro probe reproduced false PASS. A related new control also reproduced false PASS for an imported overriding method spelled `fn<U+0085>send_action`: a macro-only fix would leave the same lexical defect in the method check.

The single shared `rustCode` masker now normalizes Unicode `Pattern_White_Space` to ASCII spaces after masking comments/literals, preserving LF and UTF-16 positions. Every downstream import, declaration, scope, method and macro check therefore sees consistent Rust token whitespace. Byte spans still derive from corresponding positions in the original unmodified UTF-8 source. No source bytes or source hashes are normalized. Installed Rust reference `share/doc/rust/html/reference/whitespace.html` explicitly lists the eleven characters and names the Pattern_White_Space property; no external lookup or Unicode-name whitelist was used.

Controls cover all eleven Rust whitespace characters (TAB, LF, VT, FF, CR, space, NEL, LRM, RLM, line separator, paragraph separator) in both macro invocations and direct overriding method declarations. NEL/LRM/RLM also cover shadowing and complete receipt declaration boundaries, with harmless declaration positives preserving exact byte spans. Comments, strings and raw strings remain masked, including macro-looking NEL/LRM/RLM text. This is still a bounded lexical source check, not a general Rust resolver.

## Completion receipt integration

Parent authorized one minimal environment input at the existing `verifySourceContracts` boundary: `SF_RUST_RECEIVER_SCOPES_FILE`. It follows the same validated, hash-captured receipt path as the explicit file option. Empty values, missing files, malformed JSON, or conflicts with either explicit receipt option are UNKNOWN. The environment is per invocation; no global setting is persisted. No router/gate module edits were necessary.

The actual call path is `completeSlice -> saveStatus -> validateSliceContracts -> verifySourceContracts`. Gate verification also calls that same source verifier. Existing options did not carry the molecule-verify CLI flag into completion, so the env-route test was RED before this interface was added. The real scratch router fixture proves it is carried through gate preparation/sealing/binding/approval and completion, not only through molecule-verify.

Supported parent-owned completion shape, after final reviews and with a fresh status hash:

```sh
SF_RUST_RECEIVER_SCOPES_FILE=/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/evidence/slice-3-rust-receiver-scopes.json /home/john/.codex/skills/sf-start/scripts/router complete-slice --plan-root docs/plans/publishing-proxy --expected-sha256 <current-status-sha256> --slice 3 --witness <actual-witness> --result PASS --review qa=VERIFIED
```

Use the parent's actual required review arguments. `complete-slice` does not accept a receipt CLI flag. Do not combine this environment input with explicit receipt options or molecule-verify's `--rust-receiver-scopes` flag; conflicting sources are rejected even if identical.

## Deciding final-byte evidence

Paths below start at `.scratch/slice3-repair/tooling/` unless specified otherwise.

- RED reviewer reproduction `factory-whitespace-red.log`: baseline PASS and NEL macro false PASS; fixture `factory-source/.scratch/tmp/review-receiver-bie3Ru`.
- RED regression `factory-whitespace-test-red.log`: `scope-macro-syntax-unicode-nel`, actual PASS, expected UNKNOWN, exit1. Related method RED `factory-whitespace-method-red.log`: `scope-nel-method-override`, actual PASS, expected UNKNOWN, exit1. Shared normalization GREEN in `factory-whitespace-test-green.log` and final full suite.
- Receipt environment RED `factory-receipt-env-red.log`: `scope-env`, actual UNKNOWN, expected PASS, exit1. GREEN `factory-receipt-env-green.log`, including invalid/missing/empty/conflicting inputs.
- Final full `node scripts/molecule-source.test.mjs`: exit0; existing source-contract suite PASS plus **17 positive and103 negative receiver controls**. Log `factory-whitespace-full-suite.log`, fixture `factory-source/.scratch/tmp/receiver-test-fR9Ay2`.
- Final unchanged reviewer probes: `factory-whitespace-green.log` (NEL macro UNKNOWN), `factory-whitespace-unicode-control.log` (Unicode macro UNKNOWN), and `factory-whitespace-prior-controls.log` (all prior adverse probes UNKNOWN). Their ordinary baselines PASS.
- **All9 unchanged actual product obligations PASS,18 production/control runs**, exercising the new environment route with the durable published receipt: `factory-whitespace-product-result.json`; empty `factory-whitespace-product-stderr.log`; raw archive `factory-source/.scratch/product-evidence/run-VxwxQp`. Both deletion obligations' production/control sites bind `Transport.send_action`, key `src/upstream/mod.rs#1739-1876`, runs11–14. Caller: `factory-source/.scratch/check-product-env.mjs` with explicit `SF_RUST_RECEIVER_SCOPES_FILE` to the published receipt.
- **Real scratch completion route PASS:** `factory-completion-route.log`, exact command/results `factory-source/.scratch/tmp/receiver-test-H3E72S/completion-route-results.json`; harness `factory-source/.scratch/check-receipt-completion.mjs`. Gate prepare/seal/bind/approve exit0. Completion without receipt exits4 with SOURCE_CONTRACT_REQUIRED and preserves exact status bytes; same completion with receipt exits0 and records the synthetic Slice1 proof. Initial harness assumed refusal exit1, corrected to actual router exit4; no implementation change was needed. This fixture is explicitly synthetic and is not product approval or product completion.
- Final `node --check`: PASS. Static SMTC verify request `req-1809918-1793731684916-0`:0 errors,0 warnings,incomplete false,1 file. Static evidence only.
- All104 product Rust source/model/sidecar/spec hashes unchanged: `factory-whitespace-product-before.json` and `factory-whitespace-product-after.json`. No approved expectation changed.

`tdd: Rust token-whitespace attribution — red: scope-macro-syntax-unicode-nel actual PASS !== expected UNKNOWN; scope-nel-method-override actual PASS !== expected UNKNOWN — green: receiver suite and final integrated source suite passed`

`tdd: receipt input reaches completion verifier — red: scope-env actual UNKNOWN !== expected PASS — green: receiver suite and real scratch gate/complete-slice route passed`

Additional whitespace/shadow/declaration controls that already rejected before this change are breadth checks; no separate pre-fix failure is claimed for them.

## Frozen runtime and deployment boundary

Deciding tests used the same preserved reviewed SMTC CLI9969701f/daemonb508569e pair, explicit runtime `d2`, Node24.19.0, thread/concurrency/cache/Rayon limits2, and disk-backed staged TMPDIR. No source edits occurred after freezing source04335552/test449fa9e5 and running these final checks. Import-to-declaration/reexport linkage remains the explicit reviewed hash-bound Structural premise; no compiler dispatch certificate is claimed.

`factory-apply-reviewed.py` now guards the frozen hashes above and still passes its dry-run against clean original Factory HEAD0ead3ed7 and old source487daee2/testd09d8528/new-test absence. It has not been invoked with --apply. `factory-deployment-plan.md` now prescribes exactly one `npm run install:emergency` campaign, whose built-in typecheck and complete npm test gate promotion, then `npm run drift` requiring zero. The provider evaluation matrix is skipped by that standard agent install path only; no additional skips. Parent will provide newly installed matching repaired SMTC provenance before the final installed-router all9 rerun. No installed or original Factory source has changed in this worker packet.

All worker verification processes have completed. Candidate writer ownership is released; only this report/deployment preparation was updated after source freeze. Fresh independent SHIP is still required before external apply/install.

---

# Historical third candidate (superseded after Rust-whitespace review)

**Fresh independent review required; not installed.** The Unicode macro false PASS reported in `slice-3-factory-repair-recheck.md` is reproduced and repaired. That review remains unchanged at SHA256 `7a018263784c96abebb8aa1a3430d845c301432bb2524655f88b57eeafbace7b`. All prior review reports and the historical sections below remain historical evidence, not clearance of this candidate.

## Exact frozen subject

- `scripts/molecule-source.mjs`: `4f32d7d316ed7177717665aa8ddf346e1e10dbab475dcf719ff133231c57309b`
- `scripts/molecule-source.test.mjs`: `c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d`
- `scripts/molecule-receiver.test.mjs`: `f3b2f1a80ffdb5df06445d6eb5d103f6e99d14aa58ddcb25defce5c8bc1963c5`
- `patch`: `c043999d286bc60c6c3b3741dffb175c9370208192f3bd22a44cdc1f48b6f797`
- `receipt`: `cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9`

Paths are relative to the staged Factory root `.scratch/slice3-repair/tooling/factory-source`, except patch `.scratch/slice3-repair/tooling/factory-binding.patch`. The receipt remains `.scratch/product-receiver-scope.json` inside the staged root. The machine-readable packet is `.scratch/slice3-repair/tooling/factory-candidate-hashes.json`. Source test integration is unchanged in this pass; implementation and receiver regression bytes changed.

## Causal change and retained boundary

The imported-trait check required an ASCII identifier suffix before macro invocation punctuation. Thus a fully captured, correctly hash-bound trait containing `注入!();` evaded the macro rejection and hid an overriding `send_action` method. The unchanged reviewer reproducer returned baseline PASS and Unicode extension PASS before editing.

A private shared predicate now checks masked Rust code for `!` followed by an opening parenthesis, bracket or brace, independent of identifier spelling. All four existing macro checks use it (receipt traits, IIFE bodies, exact-import owners and selected caller owners). It deliberately also refuses ambiguous unary-negation syntax followed by a delimiter; this is a supported-subset limitation, not relaxed attribution. Whole-file masking continues to remove comments and quoted/raw strings before checking. The existing known async_trait policy and unsupported-attribute refusal are unchanged.

New seam controls cover ASCII/Unicode/raw identifier and qualified macro names; comment-separated tokens; all three delimiter forms; and comment, string and raw-string text that must not be mistaken for live macro syntax. The explicit raw overriding method `fn r#send_action` is UNKNOWN under the existing unsupported-raw-identifier/attribute syntax policy; no parser expansion was necessary.

Source closure, exact receiver/type/trait/key matching, full declaration spans, pinned receipt provenance, drift checks and quotas remain unchanged. Import-to-declaration/reexport linkage remains the explicitly reviewed hash-bound Structural premise, not a compiler method-resolution certificate. Product/model/spec expectations are unchanged.

## Deciding evidence on final bytes

All paths below start at `.scratch/slice3-repair/tooling/` unless absolute.

- RED unchanged reviewer probe: `factory-unicode-red.log`; fixture `factory-source/.scratch/tmp/review-receiver-IFSYLg`; baseline PASS and Unicode macro extension false PASS.
- RED new regression before source edit: `factory-unicode-test-red.log`; assertion `scope-unicode-trait-macro`, actual `PASS`, expected `UNKNOWN`, exit1. The initial single-file green run is `factory-unicode-test-green.log`.
- GREEN unchanged reviewer probe on final source: `factory-unicode-green.log`; baseline PASS, Unicode extension UNKNOWN with “Imported trait has unsupported attributes or macros.” Fixture `factory-source/.scratch/tmp/review-receiver-9WvDOi`.
- Prior three review defects remain closed on final source: `factory-unicode-prior-controls.log`; baseline PASS and all five negative probes UNKNOWN. Fixture `factory-source/.scratch/tmp/review-receiver-0IOFng`.
- Final complete `node scripts/molecule-source.test.mjs`: exit0, existing source-contract suite PASS plus **11 positive and 68 negative receiver/scope controls**. Log `factory-unicode-full-suite.log`; fixture `factory-source/.scratch/tmp/receiver-test-QR3iHy`. Includes `scope-raw-method-override: UNKNOWN`, known async_trait positive, and CLI receipt checks.
- Final source `node --check`: PASS. SMTC verify request `req-1693246-1793730435211-0`:0 errors,0 warnings,incomplete false,1 workspace file. This is static verification only.
- **All9 unchanged product obligations PASS,18 production/control runs**: `factory-unicode-product-result.json`, empty `factory-unicode-product-stderr.log`; full capture `factory-source/.scratch/product-evidence/run-xLuaYz`. Both service-reference-before-delete and service-marker-before-delete production/control attribution record `Transport.send_action`, key `src/upstream/mod.rs#1739-1876` (runs11–14).
- All104 product Rust source/model/sidecar/spec hashes match before/after: `factory-unicode-product-before.json` and `factory-unicode-product-after.json`. Original Factory shipped source still SHA256 `487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea`.

`tdd: Unicode imported-trait macro — red: scope-unicode-trait-macro actual PASS !== expected UNKNOWN (exit1) — green: node scripts/molecule-receiver.test.mjs passed; final integrated source suite passed (factory-unicode-test-red.log, factory-unicode-test-green.log, factory-unicode-full-suite.log)`

Additional alphabet/masking and raw-method cases are regression breadth checks; no separate red is claimed for behavior already rejected before this fix.

## Runtime and handoff

All deciding tests used preserved `candidate-bin/smtc` SHA256 `9969701fbf93856d0ad2bb2b8076c731b2ca04ed01590125ad5f2f6c7d384c1f`, daemon SHA256 `b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3`, explicit runtime `d2`, Node24.19.0, worker/concurrency/cache/Rayon limits2, and disk-backed TMPDIR under staged `.scratch/tmp`. The first source search accidentally omitted isolated runtime environment and reported a default-runtime daemon build mismatch/restart; parent was notified immediately. That search is not deciding test evidence. All later inspections/tests used explicit isolation and approved IPC escalation.

The unchanged full9 API caller is `factory-source/.scratch/check-product.mjs`. The reproducible router receipt interface and deployment commands remain in the historical boundary section below. This pass did not install anything or change the original Factory checkout. Parent owns fresh review, safe patch application with current dirty-state preconditions, full Factory typecheck/npm tests, installation, durable receipt publication and zero installed drift. All worker test processes completed; exclusive writer ownership is released with this packet.

---

# Historical second candidate (superseded after Unicode macro review)

**Fresh independent review required; not installed.** The three confirmed defects in `slice-3-factory-repair-review.md` are repaired in the staged candidate below. The prior review remains unchanged at SHA256 `8d87e512cd9e470115dda21d862d25522bc15a994ec7c1f14352dcbbc113f063`. The historical candidate/evidence appendix below is superseded by this section.

## Exact frozen scope

- `scripts/molecule-source.mjs`: `ba93be1872215a0a94e7f948192008f6b4b52d1aa450b38e255a7d496daa2d6e`
- `scripts/molecule-source.test.mjs`: `c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d`
- `scripts/molecule-receiver.test.mjs`: `bed122c17995a531dfc6572a33bde1c07ba72b67a5b4c20db7831c5b18a238a6`

Patch `.scratch/slice3-repair/tooling/factory-binding.patch`, SHA256 `fce50a941faff63e732544d7d0906211d703860f83f607a23a0c19e47191bfa5`. Complete exact hash packet: `.scratch/slice3-repair/tooling/factory-candidate-hashes.json`.

Receipt `.scratch/slice3-repair/tooling/factory-source/.scratch/product-receiver-scope.json`, SHA256 `cdbb06b40f1fb08fe59e623d68700161dfea63f2b0a26b600b8e4728a84f9ec9`. Stricter span validation found the old receipt ended ReferenceId at byte1204 inside its array field; the corrected exact tuple-struct end is1210. No source/dependency bytes changed. The scratch receipt generator now handles nested parentheses/brackets rather than treating an array-field semicolon as the declaration end. This receipt correction is part of the fresh review subject; no approved model, sidecar, spec or expectation string changed.

## Causal fixes

1. **Receiver binding scopes:** before any selected receiver call, refuse match/for scopes and local item declarations; reject receiver-binding let patterns and closure parameter shapes outside a simple nonreceiver identifier list. This intentionally supports a narrow subset, not a general Rust binding resolver. Actual product map_err closures and ordinary receiver calls remain supported. Tuple/ref/enum match, for, if-let, while-let, destructured/ref let and closure patterns remain UNKNOWN.
2. **Full-file receipt declarations:** use the fully masked source, validate UTF-8 byte boundaries, build balanced delimiter depth/pairs, require a unique top-level declaration token matching exact name/kind/start, and require the complete declaration's exact end. Comments, quoted/raw strings, macro token arguments, inner-token starts, partial and concatenated spans cannot invent declarations. Positive controls cover full tuple structs and UTF-8 prefixes.
3. **Lexical receiver requirement:** derive free/receiver syntax from the fully masked captured call-site span. Missing/null/wrong graph receiver metadata cannot bypass binding, including exact-confidence edges. Reject truncated qualified prefixes and source/graph identity mismatches. Captured receiver/type/trait/key matching remains mandatory for receiver syntax.

Source closure/receipt validation, package provenance, unsafe controls, source drift checks and capture/evidence quotas remain intact. Import-to-ultimate-declaration/reexport linkage remains an explicit reviewed hash-bound premise; no compiler dispatch certificate is claimed.

## Final-byte checks

- RED reproduction before edits: `.scratch/slice3-repair/tooling/factory-review-red.log` on deb3d232: foreign tuple receiver, comment-spoofed declaration and omitted-receiver/wrong-exact-identity all incorrectly PASS.
- GREEN unchanged reviewer probes on final `ba93be1872215a0a94e7f948192008f6b4b52d1aa450b38e255a7d496daa2d6e`: `.scratch/slice3-repair/tooling/factory-review-green.log`. Baseline PASS; all five adverse probes UNKNOWN, including the three major findings. Raw fixture `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source/.scratch/tmp/review-receiver-B2V4NL`.
- Full `scripts/molecule-source.test.mjs` on final bytes: exit0, existing source-verifier suite plus **8 positive and58 negative receiver/scope checks**. Log `.scratch/slice3-repair/tooling/factory-review-full-suite.log`; fixture `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source/.scratch/tmp/receiver-test-Ur8THg`. The CommonJS graph-mutating wrappers use `.cjs`, and the metadata controls execute the real analyzer before altering its JSON.
- **All9 unchanged product obligations PASS on the same final source bytes and corrected receipt**,18 production/control runs. Result `.scratch/slice3-repair/tooling/factory-review-product-result.json`; raw captured evidence `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source/.scratch/product-evidence/run-XFMJdF`. Both service deletion guard obligations retain exact expected findings and captured Transport.send_action identity.
- `node --check scripts/molecule-source.mjs`: PASS. SMTC verify request `req-1446220-1793729538689-0`:0 errors,0 warnings, incomplete false, one file; this is static source verification only.
- All104 product Rust source/model/sidecar/spec hashes remain unchanged in `.scratch/slice3-repair/tooling/factory-product-before.json` and `.scratch/slice3-repair/tooling/factory-product-after.json`.

## Reproduction and deployment boundary

Use preserved matched tools in `.scratch/slice3-repair/tooling/candidate-bin`, **not mutable target/debug**. CLI SHA256 `9969701fbf93856d0ad2bb2b8076c731b2ca04ed01590125ad5f2f6c7d384c1f`, daemon SHA256 `b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3`. Runtime `SMTC_RUNTIME_DIR=/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/d2`; daemon environment points to candidate-bin/smtc-daemon. CLI PATH starts with candidate-bin and Node24.19.0, worker/concurrency/cache/Rayon limits2, TMPDIR is the staged `.scratch/tmp` directory on disk. The exact API caller `.scratch/slice3-repair/tooling/factory-source/.scratch/check-product.mjs` now selects candidate-bin/smtc and rustReceiverScopesFile explicitly.

Reproducible router CLI after review (with those environment settings and disk-backed XDG_STATE_HOME):

```sh
.scratch/slice3-repair/tooling/factory-source/scripts/router molecule-verify --plan-root docs/plans/publishing-proxy --slice 3 --rust-receiver-scopes .scratch/slice3-repair/tooling/factory-source/.scratch/product-receiver-scope.json
```

The actual all9 run used the API caller, while the optional receipt CLI is covered by the full regression suite. Parent owns durable receipt publication, fresh independent review, safe apply to the originally clean Factory HEAD0ead3ed78a94fc3368d4df6ae85289d77e6f4eb1, full Factory typecheck/npm test/install and zero installed drift. No original Factory checkout or installed release was edited by this worker; recheck their state before apply.

`tdd: receiver-shadowing | RED foreign tuple receiver falsePASS | GREEN unsupported binding scopes UNKNOWN + ordinary positive PASS | evidence: factory-review-red.log, factory-review-full-suite.log`

`tdd: receipt-declaration-span | RED comment snippet falsePASS | GREEN unique complete full-file declaration tokens + comment/string/raw/macro/partial negatives | evidence: factory-review-red.log, factory-review-full-suite.log`

`tdd: missing-receiver-metadata | RED exact-edge metadata omission falsePASS | GREEN lexical receiver requirement rejects missing/null/conflicting metadata | evidence: factory-review-red.log, factory-review-full-suite.log`

`tdd: final-slice3-source-obligations | PASS9/9 with approved unsafe controls on ba93be1872215a0a94e7f948192008f6b4b52d1aa450b38e255a7d496daa2d6e | tier: Structural + reviewed import-linkage premise | evidence: /home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source/.scratch/product-evidence/run-XFMJdF`

Ownership released after this report: no subagents, no remaining test/build/verification process, no pending source edits. Current candidate bytes are frozen for re-review. Full Factory repository/install/drift checks were not run in the partial staging copy.

---

# Historical first implementation packet (superseded)

# Factory receiver binding repair candidate

Status: reviewed-test candidate41a1c6 passed targeted regression and all nine unchanged product structural obligations. The final staged candidate adds resource-only receipt capture limits/accounting afterward and requires a fresh integrated/product rerun. Independent review, full Factory repository typecheck/test, installation and installed drift verification remain required. No installed release or original Factory checkout was modified.

## Causal evidence

Baseline Factory HEAD `0ead3ed78a94fc3368d4df6ae85289d77e6f4eb1`, original molecule-source SHA256 `487daee2c1c1ba209a4876f821a8f26f85d3c8783c457402aa977e6d66167bea`.

The minimal real-SMTC fixture failed with `SOURCE_SUBJECT_UNRESOLVED: Receiver call does not identify the selected free function.` (`factory-receiver-red.log`). The direct-import closure omitted the receiver trait, and the bare-name caller query misattributed a receiver to a same-named free function. The candidate captures the parameter's struct, dyn-trait field, and exact trait method span, queries the qualified method, and independently checks caller, receiver, method and byte-key identity. Each run adds only its own dependency closure, avoiding contamination of unrelated free-function queries.

An adversarial imported extension trait exposed a second causal issue: lexical `Arc<dyn Trait>` alone does not establish dispatch (`factory-extension-red.log`: incorrect PASS). The final candidate rejects every additional import unless a complete reviewed source-scope receipt binds its declaration. Imported traits with same-name methods, supertraits, unsupported attributes or macros are rejected. Unknown/local shadowing and unverified imports remain UNKNOWN.

## Interface and scope receipt

Existing API accepts `rustReceiverScopes` (receipt array) or `rustReceiverScopesFile` (one JSON input file), exclusively. The existing router forwards the new final optional CLI pair `--rust-receiver-scopes <receipt JSON file>` to molecule-source.mjs; no router source changes are required.

Receipt schema: source/sourceSha256/symbol; exact owning specs with SHA256; repository Cargo.lock with SHA256; package name/version/checksum and manifest binding; import path, declaration file/name/kind/byte span, optional concrete ultimate declaration for a type alias, and reexport source bindings. Every non-std extra import must be covered. The verifier checks actual declaration text, source/spec/lock hashes and pinned package metadata, archives all supplied bytes and the original receipt file, and rechecks them after verification. Wrong hashes, wrong scope/import/declaration, unresolved aliases, missing coverage and live source drift fail closed.

**Reviewed premise:** import-to-ultimate-declaration/reexport linkage is a hash-bound source-review premise. This is Structural source attribution, not a rustc dispatch certificate. The receipt does not accept a caller-supplied boolean asserting safety. For the actual external trait, axum0.8.9 reexports axum-core0.5.6 `IntoResponse`; its captured trait has only `into_response`, with no supertrait. The receipt binds all20 additional imports, including non-trait declarations and the Response alias's ultimate struct.

Exact receipt: `.scratch/slice3-repair/tooling/factory-source/.scratch/product-receiver-scope.json`
SHA256: `64b7712c3634743aaa102277e1ad5f3cd5c57670867051f6cc09d73c9dd0ce11`.

## Final evidence boundary

Full9 PASS and final integrated suite evidence were produced on source SHA256 `41a1c6f7124026cc56fce2223997b91adb2f38c6f3acd94769449f4e298f2762`. Immediately before ownership freeze, a resource-only hardening change capped scope capture at256 files/32MiB, bounded package/import/reexport arrays, and included captured receiver bytes in the existing evidence quota reservation. This avoids bypassing existing quota guarantees. Final source passed `node --check`; **integrated/full9 checks must rerun on final hash below**. No behavioral PASS is claimed for untested bytes. Parent requested immediate release for independent review; no processes remain active from this worker.

## Changed deployment paths and hashes

- `scripts/molecule-source.mjs`: `deb3d232d8bde2242e0250ee88a4370dbb3a317c39423c3358a840ea840f74b0`
- `scripts/molecule-source.test.mjs`: `c10ff73c51b2d954424824d5f0eb98d4afabf66a6690895af3e98c690c6a8e4d`
- `scripts/molecule-receiver.test.mjs`: `0c9442fb7123045aac31b8c7f22ac0ad380cab3b04c61b0e94f04dc68f9f7759`

Patch: `.scratch/slice3-repair/tooling/factory-binding.patch`, SHA256 `3bcd90873427f551d60e9bd1678ced52cf2dbf8cfa5188953e1df33f41f3e169`.
Full staged code is under `.scratch/slice3-repair/tooling/factory-source`; original Factory checkout remains clean.

## Checks and exact evidence scope

- `node --check scripts/molecule-source.mjs`: PASS (JavaScript syntax).
- Node24 `scripts/molecule-source.test.mjs`: PASS, including the existing full source-verifier regression file and new receiver suite. Log `.scratch/slice3-repair/tooling/factory-source-suite.log`. New suite:5 positive checks and35 negative checks. Five graph mutation controls were separately inspected to confirm complete altered graph output, not an execution error. The initial extensionless CommonJS test wrapper failed before execution; it was corrected to `.cjs`, and all final checks reran.
- Complete unchanged publishing-proxy source contract suite: **PASS,9/9** using matched isolated SMTC candidate CLI/daemon and the exact receipt. Result `.scratch/slice3-repair/tooling/factory-product-candidate-result.json`; raw evidence `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source/.scratch/product-evidence/run-ySwl7Q`.18 source/control runs. Both receiver obligations' production/control sites bind `Transport.send_action` to `src/upstream/mod.rs#1739-1876`; all approved expectation strings were preserved.
- Product before/after manifest: all104 captured Rust source, model, sidecar and spec hashes unchanged. `.scratch/slice3-repair/tooling/factory-product-before.json` and `.scratch/slice3-repair/tooling/factory-product-after.json`.
- Original staged scope manifest: `.scratch/slice3-repair/tooling/factory-before.sha256`. Final candidate exact hashes: `.scratch/slice3-repair/tooling/factory-candidate-hashes.json`.

Matched SMTC CLI SHA256 `9969701fbf93856d0ad2bb2b8076c731b2ca04ed01590125ad5f2f6c7d384c1f`; daemon SHA256 `b508569eabb482ed35abb881ca7078bdf44a96c04fd90eb99ff6242a16aac9b3`. Both reside in `.scratch/slice3-repair/tooling/target/debug`; isolated runtime `.scratch/slice3-repair/tooling/d2`. Installed CLI against the candidate daemon produced mismatch diagnostics and was correctly rejected; that run is not passing evidence.

Reproduction caller: `.scratch/slice3-repair/tooling/factory-source/.scratch/check-product.mjs`. Set `SMTC_RUNTIME_DIR=/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/d2`, `SMTC_DAEMON_BIN=/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/target/debug/smtc-daemon`, `SMTC_DAEMON_WORKER_THREADS=2`, `SMTC_DAEMON_MAX_CONCURRENT=2`, `SMTC_WORKSPACE_CACHE=2`, `RAYON_NUM_THREADS=2`, and disk-backed `TMPDIR=/home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source/.scratch/tmp`; run with `/home/john/.nvm/versions/node/v24.19.0/bin/node`. Caller explicitly selects the matching candidate CLI and input receipt file. Parent should persist the receipt under plan evidence after independent review; its absolute external source paths are intentional pinned local provenance.

## SMTC receipt

- `search symbol` rustImportFiles on Factory root: successful, one declaration, complete; `inspect symbol` resolved handle scripts/molecule-source.mjs:515:584 returned the exact source.
- `review slice` rustImportFiles backward: complete; callers exactRustImport and verifySourceContracts, both Exact structural graph evidence.
- `review slice` Transport.send_action backward on product root: complete; actual consume_service_marker_then_send caller Structural.
- `file read` actual caller/struct/trait and pinned IntoResponse declaration: complete bounded source evidence (one requested EOF range clamped; no completeness claim relies on the omitted nonexistent lines).
- `verify` staged molecule-source.mjs:0 errors/0 warnings, complete, one file. This does not certify Rust dispatch or the full Factory repository.

## Dispatcher lines

`tdd: factory-receiver-attribution | RED baseline receiver/free-function mismatch | GREEN exact captured trait binding + unsafe control | evidence: factory-receiver-red.log, factory-source-suite.log`

`tdd: factory-receiver-extension-scope | RED imported extension trait incorrectly passed | GREEN missing/overriding/unverified scope rejected and pinned safe scope accepted | evidence: factory-extension-red.log, factory-source-suite.log`

`tdd: slice3-receiver-obligations | PASS production plus approved unsafe controls for service-reference-before-delete and service-marker-before-delete | scope: Structural, reviewed hash-bound import premise | evidence: /home/john/go/src/github.com/postfix/probation/.scratch/slice3-repair/tooling/factory-source/.scratch/product-evidence/run-ySwl7Q`

Not run: full Factory npm test/typecheck/release installation/drift; the isolated copy lacks the full checkout environment. Parent coordinates these after independent review. No arbitrary functional correctness or compiler dispatch proof is claimed.

## Production CLI reproduction after review

From the product root, use the matching CLI on PATH and matching daemon/runtime environment recorded above, plus `SF_NODE=/home/john/.nvm/versions/node/v24.19.0/bin/node`:

```sh
.scratch/slice3-repair/tooling/factory-source/scripts/router molecule-verify --plan-root docs/plans/publishing-proxy --slice 3 --rust-receiver-scopes .scratch/slice3-repair/tooling/factory-source/.scratch/product-receiver-scope.json
```

The API full9 invocation and CLI receipt round-trip were executed separately; the exact full-product CLI invocation above is a reproduction command, not an already-run claim. Configure XDG_STATE_HOME/TMPDIR on disk before running.

Ownership released: no descendant agents were spawned, no owned test/build process remains running, and this worker will not edit candidate files after handoff. Parent owns review, safe apply, standard `npm run typecheck`, `npm test`, full installation checks, installed drift check, reruns and durable receipt publication. Original Factory checkout precondition at release: clean HEAD0ead3ed78a94fc3368d4df6ae85289d77e6f4eb1. Preserve unrelated later edits and recheck hashes before applying.
