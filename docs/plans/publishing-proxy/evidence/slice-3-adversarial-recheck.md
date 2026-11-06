Review kind: adversarial
Verdict: PASS
Review: independent
Question: Does the new forged foreign-reference witness reach successful lookup/decryption with a valid removal marker, then exercise actual selected-origin refusal before transport?
Summary: Yes; the new regression closes the sole required witness gap in slice-3-adversarial.md for the bound subject.
Tier: Manual source inspection, supported by supplied successful execution logs; no new verify/certificate claim.

## Findings

None. The prior required witness gap is closed. This bounded PASS does not resolve unrelated whole-slice proof blockers.

## Evidence

1. `tests/service_unpublish.rs:89` configures the historical foreign deletion scope with `forward_bearer=true`. The regression at line 140 starts a real service HTTP server, obtains a valid owner-0 lease through successful write preflight, computes the foreign ArtifactReference ID, encrypts the foreign URL with the service key and matching authenticated data, persists it, and marks revision 2 removed.
2. `tests/service_unpublish.rs:168` submits HTTP DELETE with Bearer owner and revision 2. Its assertions require status 400 and the exact selected-registry-origin error. `src/http/service_unpublish.rs:73` performs successful lease lookup and identity validation before `open_url`, and only then invokes destination approval. `src/http/unpublish_reference.rs:75` decrypts the sealed URL; line 115 returns the asserted origin-specific error. Lookup failure or decryption failure cannot satisfy this witness.
3. The regression asserts unchanged transport trace length and successful subsequent consumption of the revision-2 marker. `src/store/action_leases.rs:119` requires matching registry/owner/reference/revision, unexpired lease and unconsumed state for that consumption. Thus the fixture carries a usable marker, and the HTTP refusal precedes its consumption. `src/http/service_unpublish.rs:93` checks the destination before consuming or sending. The fake transport also asserts selected origin and developer credential on action calls, so an attempted foreign action cannot silently pass this regression.
4. Supplied `.scratch/slice3/foreign-reference-focused2.log` records the exact new regression passing plus the existing three service-unpublish tests: 4 passed, 0 failed, 0 ignored. This is recorded execution evidence, not a rerun by this reviewer.
5. Supplied `.scratch/slice3/e2e-final2.log` records native publishing-npm-actions acceptance: 1 passed, 0 failed, 0 not run. This supports the surrounding HTTP flow; the focused Rust test is the deciding forged-state witness.

## Proposed tests — not executed by this review

No additional required tests. The previously proposed foreign-reference input is now retained and recorded passing: a correctly sealed foreign URL, valid owner-0 lease, valid revision-2 marker, legacy foreign scope allowing bearer forwarding, and valid developer Bearer must produce the origin-specific 400, no transport call, and an unconsumed marker. This would fail if destination validation were bypassed or if the fixture stopped at missing lease/decryption instead. The prior report's optional multi-version, scope-revocation, and exact-expiry strengthening tests remain optional and were not executed.

## Subject and stability

Base: `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`.
Manifest: `.scratch/slice3/current-subject.json`, SHA-256 `a85bfdde9de40508ce3c512087d59461037b0710b125f2382359832d66e201b9`.
All 15 current-file hashes matched before source inspection and immediately before report creation, using one `sha256sum -- PATH` per command. The manifest hash also matched twice. Git name-status/summary showed modifications and no mode/rename changes; Git status identified the two service modules and two service integration tests as untracked additions. This does not attribute pre-existing checkout changes to this review.

| Path | Verified SHA-256 |
|---|---|
| src/http/mod.rs | 7037ca2ce12a320a7780d56e1d6f6ed31c4a965988f2c0b88eabf50aa795dd5a |
| src/http/registry_routes.rs | c8517acd7eb33f93b48b15a91842c6610669b2e0481870626d0ca68e2c5f744b |
| src/http/service_registry.rs | 8a54071e78ef30ca831956ce3b602d21aff3b9f7a15067aa23f529af171ee367 |
| src/http/service_unpublish.rs | 0c49a83b5d1e54edef99a5da501bf246156acb0f2c70907325a0cfac59143301 |
| src/http/unpublish_reference.rs | f6c3fdf0cbfcbaea88cc207a1bdaab9a14f2b0bb5edb6ae04dedf8f066dd72ca |
| src/store/action_leases.rs | 3954dee041bf31dd476a5394b41312794ac823a58ada9a20a5dedda8a2c9caa5 |
| tests/service_unpublish.rs | 94778444524df053928c784513bb3bf6d93a701fa0fd5edad7a5aab12e223152 |
| tests/shared_service.rs | 5f28df4ae71a5f0ccdda36965a3516bdc916e15e2c08a5b72c0a4b62a64a9a30 |
| tests/e2e/fixtures/fakes/main.mjs | 345c1b125d563ad26ccee3d36b84d6159ec6ed81e09a6b884be3f09fed04806b |
| tests/e2e/scenarios/publishing-npm-actions.mjs | 6a7f75e2f42282e11d5d5fdf5ee2f3fc7183e0718b5b04d9a41c60ae00ed6f67 |
| tests/e2e/scenarios/publishing-npm-read.mjs | 3e98e09daea01e2a2e4329bd43a6c2dbb4c5350b1b6c9271c8cd6f03c02a206b |
| tests/e2e/scenarios/publishing-npm-actions-issuer.mjs | 8ce741e58804f8107d00e2566ad3c27b8e634f9ed33112afb16cd23df5816e11 |
| tests/e2e/scenarios/publishing-full-matrix.mjs | 83eb1524009aa86056c156836f3670931b1662adf9523a2f3ed2ba3cbecfb051 |
| Cargo.toml | 14f7305afa06210ce73103e5c13a46252fd29d3d58dc9c5fec4fb2d642ef72f7 |
| Cargo.lock | d4dae800c073cb0363b1d016d06efe55bd09d888caca15d1f24ed5d78cb9db58 |

## SMTC receipt

Every executed project-evidence operation used the exact command template:

`smtc file read --root /home/john/go/src/github.com/postfix/probation --path PATH --start-line A --end-line B --format json --max-tokens 2048 --session-id sf-slice3-adversarial-recheck-2026-11-03`

| PATH and A:B | Status and fidelity | Interpretation |
|---|---|---|
| tests/service_unpublish.rs 1:100 | run; outer ok:true; inner complete; text fidelity; functions analyzed N/A; no truncation/ref | Transport assertions and foreign forwarding scope. |
| tests/service_unpublish.rs 175:310 | run; outer ok:true; inner complete; EOF-clamped to 221; text fidelity; functions analyzed N/A; no truncation/ref | Existing positive lifecycle tests, complementary control. |
| src/http/service_unpublish.rs 60:145 | run; outer ok:true; inner complete; EOF-clamped to 109; text fidelity; functions analyzed N/A; no truncation/ref | Lookup/decrypt/approval ordering precedes marker consumption and transport. |
| tests/service_unpublish.rs 100:175 | run; outer ok:true; inner complete; text fidelity; functions analyzed N/A; no truncation/ref | Complete retained forged-state regression and setup. |
| src/http/unpublish_reference.rs 70:132 | run; outer ok:true; inner complete; text fidelity; functions analyzed N/A; no truncation/ref | Successful decryption leads to exact extra-origin refusal. |
| src/http/unpublish_reference.rs 40:70 | run; outer ok:true; inner complete; text fidelity; functions analyzed N/A; no truncation/ref | Service data key and encryption construction. |
| src/store/action_leases.rs 85:133 | run; outer ok:true; inner complete; text fidelity; functions analyzed N/A; no truncation/ref | Marker validity and atomic consumption predicate. |

No unsupported/refused commands, native source fallback, diagnostic claims, or semantic graph claims. Task-supplied manifest, prior report and execution logs were read as task/external evidence.

Changed paths: no source/test changes; only this explicitly authorized report.
Out of scope: Global classifier proof and operation-summary text blockers remain separate; this is not a whole-slice delivery verdict.
Limitations: Supplied focused/native execution logs were inspected but not regenerated. No full suite, diagnostic/certificate, optional strengthening tests or mutation run performed. Fixed fixture nonce is confined to isolated test state, not a production sealing change.
Omitted: 0 findings; evidence grouped into five deciding items.

Skipped suite repetition and optional tests; unrelated global proof blockers remain unresolved by this bounded PASS.
