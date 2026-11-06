Review kind: adversarial
Verdict: UNKNOWN
Review: independent
Question: Do the frozen Slice 3 implementation and retained witnesses adequately cover service-reference lifecycle, revision recovery, destination/credential confinement, route ambiguity, replay/restart/concurrency, and quotas?
Summary: No source-established defect found; one explicitly required adversarial destination witness is missing from the reviewed subject.
Tier: Manual. Source and test bodies inspected through SMTC; supplied execution summaries are attributed evidence, not rerun evidence.

## Findings

1. **Required witness gap — existing extra-origin service reference.** The active Slice 3 row requires a forged extra-origin reference to refuse before I/O without forwarding the developer credential. `tests/e2e/scenarios/publishing-npm-actions.mjs:66` supplies a random unknown reference, which stops at lease lookup; lines 155–160 test extra-origin preflight refusal. Neither reaches the DELETE destination check with a successfully decrypted existing service lease and matching removal marker. The complete `tests/service_unpublish.rs` body also lacks this case. `src/http/service_unpublish.rs:71` checks the stored reference and `src/http/unpublish_reference.rs:115` explicitly rejects extra origins, so this is a test gap, not evidence of a bypass. A regression removing that DELETE check could survive the present controls. Route this missing acceptance witness to implementation/verification; do not classify it as a product defect.

## Evidence

- Active contract: `docs/plans/publishing-proxy/04-slices.md:11` and `03-program-design.md:39` require selected-origin confinement, accepted-removal provenance, fallback, one-use persistence, and quota boundaries.
- `src/http/service_unpublish.rs:29` rejects denied/empty removal, malformed response/revision and inconsistent fallback; the selected authenticated GET confirms every removed version absent. `tests/service_unpublish.rs:148` exercises revision/fallback/timeout/retained/bad-revision/malformed/denied/unchanged/marker-failure paths with exact DELETE counts.
- `src/http/service_unpublish.rs:93` validates the lease and destination before atomically consuming the marker and sending. `src/store/action_leases.rs:119` binds consumption to registry/owner/reference/revision/expiry. E2E lines 93–108 assert wrong-revision refusal, one-winner races, exact selected URL/credential, and replay refusal across restart; lines 126–139 cover upstream denial and redirect consumption.
- `tests/service_unpublish.rs:112` positively checks three equivalent scoped encodings and rejects seven malformed/double-encoded forms with no extra transport calls. E2E lines 58–69 distinguish whole-package, canonical tarball and unknown-reference DELETE. Lines 140–160 check signed-query sealing, selected custom paths across restart, and extra-origin preflight refusal.
- `src/store/action_leases.rs:155` seeds literal production thresholds and compares every stored column/count after production commit refuses quota+1; `src/http/unpublish_reference.rs:132` awaits lease commit before preparation returns. Supplied engineering evidence records its dedicated 553.09-second PASS. This review accepts that scoped runtime/source combination; it does not invent a historical RED or claim the ignored fixture ran in the routine suite.

## Proposed tests — not executed by this review

1. **Required:** Create a real service-owned lease with correctly sealed destination `https://foreign.example/extra/pkg.tgz`, a matching valid removal revision, and a current historical extra-origin scope with `forward_bearer=true`. Submit its local reference DELETE with a valid developer Bearer. Expect local refusal, zero `send_action` calls to every origin, and no credential delivery. Also prove the fixture passes lease lookup and decryption (or supply an otherwise identical selected-origin positive control). This isolates DELETE's current selected-origin guard instead of merely testing missing-reference refusal.
2. **Optional strengthening:** Lease three versions, remove two in one accepted revision PUT and retain the third. Expect both removed references to consume independently once at the resulting revision, retained version to refuse, and no wrong-revision sends. This catches accidental first-version-only verification or broad marking. Existing single-version and store controls cover the approved core case.
3. **Optional strengthening:** Prepare and mark a selected custom-path reference, revoke its scope before DELETE, then send the request. Expect zero transport calls. This directly witnesses the current scope recheck already visible in the source.
4. **Optional strengthening:** Repeat service HTTP reference DELETE just before and exactly at lease expiry using the test clock. Expect the live marker usable once before expiry and refusal at expiry. Existing store tests cover the exact boundary; this would strengthen service wiring coverage.

## Subject and stability

Base: `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`. Manifest `.scratch/slice3/current-subject.json` SHA-256 `a082c4e5f25600783ae8233174c53c4ce17b9ac3e791e6d3fc9ed323dc0afe13`. All 15 supplied raw-file SHA-256 values matched before inspection and immediately before report creation, using one `sha256sum -- PATH` command per file. This report applies to those frozen bytes; a subsequent implementation test requires recheck.

| Path | Verified SHA-256 |
|---|---|
| src/http/mod.rs | 7037ca2ce12a320a7780d56e1d6f6ed31c4a965988f2c0b88eabf50aa795dd5a |
| src/http/registry_routes.rs | c8517acd7eb33f93b48b15a91842c6610669b2e0481870626d0ca68e2c5f744b |
| src/http/service_registry.rs | 8a54071e78ef30ca831956ce3b602d21aff3b9f7a15067aa23f529af171ee367 |
| src/http/service_unpublish.rs | 0c49a83b5d1e54edef99a5da501bf246156acb0f2c70907325a0cfac59143301 |
| src/http/unpublish_reference.rs | f6c3fdf0cbfcbaea88cc207a1bdaab9a14f2b0bb5edb6ae04dedf8f066dd72ca |
| src/store/action_leases.rs | 3954dee041bf31dd476a5394b41312794ac823a58ada9a20a5dedda8a2c9caa5 |
| tests/service_unpublish.rs | f2008c80f8409ae6b9ad9f9d23d892ff21c3d9c7130aaa743413f0ff8d1ed576 |
| tests/shared_service.rs | 5f28df4ae71a5f0ccdda36965a3516bdc916e15e2c08a5b72c0a4b62a64a9a30 |
| tests/e2e/fixtures/fakes/main.mjs | 345c1b125d563ad26ccee3d36b84d6159ec6ed81e09a6b884be3f09fed04806b |
| tests/e2e/scenarios/publishing-npm-actions.mjs | 6a7f75e2f42282e11d5d5fdf5ee2f3fc7183e0718b5b04d9a41c60ae00ed6f67 |
| tests/e2e/scenarios/publishing-npm-read.mjs | 3e98e09daea01e2a2e4329bd43a6c2dbb4c5350b1b6c9271c8cd6f03c02a206b |
| tests/e2e/scenarios/publishing-npm-actions-issuer.mjs | 8ce741e58804f8107d00e2566ad3c27b8e634f9ed33112afb16cd23df5816e11 |
| tests/e2e/scenarios/publishing-full-matrix.mjs | 83eb1524009aa86056c156836f3670931b1662adf9523a2f3ed2ba3cbecfb051 |
| Cargo.toml | 14f7305afa06210ce73103e5c13a46252fd29d3d58dc9c5fec4fb2d642ef72f7 |
| Cargo.lock | d4dae800c073cb0363b1d016d06efe55bd09d888caca15d1f24ed5d78cb9db58 |

Git name-status identified modifications to the tracked manifest paths; the two service modules and two integration test files are untracked additions. Scoped Git diff summary showed no mode/rename changes. The pre-existing dirty checkout is not treated as newly authored scope.

## SMTC receipt

All executed project-evidence legs below used root `/home/john/go/src/github.com/postfix/probation`, JSON format, max-tokens 2048 and session `sf-slice3-adversarial-2026-11-03`. Exact argv templates substitute these literal ROOT/SESSION values; no wrappers, pipes or redirects were used. Reads/searches have text fidelity; functions analyzed: not applicable; they do not establish semantic graph certification.

| Operation and exact argv template | Executed arguments / status | Interpretation |
|---|---|---|
| `smtc file read --root ROOT --path PATH --start-line A --end-line B --format json --max-tokens 2048 --session-id SESSION` | `04-slices.md` 1:25; `03-program-design.md` 1:20,26:60; evidence `slice-3-engineering.md` 1:40,1:24; `tdd-slice-3.md` 1:40; `slice-3-code-recheck.md` 1:40. All under docs/plans/publishing-proxy. run; outer ok:true; no inner errors. Engineering 1:40 truncated to ref-99 (2535 tokens), narrowed to complete deciding 1:24. | Approved boundary and attributed prior results. |
| Same read argv | src/http/service_unpublish.rs 1:150; tests/service_unpublish.rs 1:110,111:230; src/http/service_registry.rs 150:250; src/http/registry_action.rs 35:130,130:220; src/http/unpublish_reference.rs 1:110,110:210,210:300,300:420. run; outer ok:true; inner complete; EOF ranges clamped. | Complete service removal/test bodies and relevant destination/route guards. |
| Same read argv | tests/e2e/scenarios/publishing-npm-actions.mjs 1:135 then narrowed 1:65,66:130,131:195; src/store/action_leases.rs 1:135 then narrowed 1:75,76:155,155:235. run; outer ok:true; initial refs ref-100/ref-101 (2326/3385 tokens), narrowed reads complete; no refs opened. | Adversarial assertions, atomic marker operations and quota fixture. |
| Same read argv | tests/shared_service.rs 1:70,590:690,830:950. run; outer ok:true; complete. | Additional shared HTTP credential/route controls; no service action transport override here. |
| `smtc file grep --root ROOT --pattern REGEX --path-include PATH --max-results 20 --format json --max-tokens 2048 --session-id SESSION` | `forg|extra.origin|scope|quota` in tests/shared_service.rs (truncated at 20; narrowed reads above); `forg|extra.origin|service` in src/http/unpublish_reference.rs (10 complete); `forged.*(lease|origin)|seal.*(forge|origin)|unapproved|scope.*remov|scope.*recheck` in tests/* (0 complete); `npm-service-unpublish|forged|seal_url` and `quota|20001|20_001|20_000` in tests/*unpublish* (0 complete). run; outer ok:true, no inner errors. | Candidate location only; negative searches are not used alone as absence proof. Full active service test and active E2E bodies inspected. |
| `smtc file read --root ROOT --path docs/plans/publishing-proxy/04-slices.md --format json --max-tokens 2048 --session-id SESSION` | run; outer ok:true, truncated ref-98 estimated 9267 tokens. Ref not opened; narrowed 1:25 above. | Initial summary not deciding evidence. |
| Same ranged read argv | tests/service_unpublish.rs 231:360. refused; outer ok:true; inner line_range_invalid, actual length 178. | Speculative over-EOF request, irrelevant; complete file already read in 1:110,111:230. No unavailable operation or native fallback. |

Changed paths: no source/test changes; only this authorized report.
Out of scope: whole-certificate CFG/qualified-operation summary blockers and historical quota RED absence remain coordinator-owned; no new code-review defect or whole-slice delivery verdict is asserted.
Limitations: No tests, native E2E, million-row fixture, DNS suite or certificates rerun. Post-scoped-fix native E2E was pending in supplied evidence. No broad taint/control-flow claim is made from text reads.
Omitted: 0 findings; routine inspected evidence grouped into five deciding items above.

Skipped additional execution and optional strengthening tests; the required existing-foreign-reference witness must be supplied before this adversarial review can pass.
