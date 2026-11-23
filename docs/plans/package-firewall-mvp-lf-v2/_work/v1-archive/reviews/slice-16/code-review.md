# Code review
Verdict: PASS
Scope: Slice 16 (FIX-16-A, C1029 osv_generation, C-S16-1) in the dirty tree on HEAD 6c4b7fc (branch slice5-native-ci). Files: src/osv/{mod,batcher}.rs, src/artifacts/{mod,stream}.rs, src/managed/{mod,service_policy,publication_gate}.rs, tests/managed_release_wiring.rs. Read-only. Requirements: 04-slices.md row 16, 03-program-design.md (C1029 contract, lines 121-123; test table line 192), evidence/slice-16.md, tdd-slice-16.md, baseline-slice-16.md.
Summary: No blocking findings. Two low non-blocking observations (L1, L2). The baseline failures are pre-existing and unrelated to slice 16. They do not block slice 28, but slice 28 must fix the clippy errors because it edits both files.

## Findings
None blocking.

L1 — low — process — C-S16-1 behaviour change was not re-reviewed
Location: src/osv/mod.rs `check` (enqueue-failure put removed), src/osv/batcher.rs:216-224 (`if matches.is_some()`).
Requirement/rule: C1029 and the C3/C14 fail-open rule in 02-architecture.md line 34 ("short negative TTL, fail-open C3/C14 stay"). User decision 2026-11-18: nothing is cached without an OSV response.
Failure or cost: A failed or short batch now caches nothing. A down OSV is queried again on every cache miss, with no 30s back-off. Requests stay bounded by the batcher queue and enqueue timeout. The code matches the user decision, and the gain is that a failure can no longer overwrite a live match (deny to allow).
Evidence: a_failed_lookup_fails_open_and_caches_nothing passes. tdd-slice-16.md records red then green. evidence/slice-16.md and migration.md say it was not re-reviewed by the security, adversarial or code-review agents.
Correction: Have the row-16 security and adversarial reviews cover this one hunk. The load-amplification cost is accepted by the user. Optionally record it in operations notes.
Blocking: no. The change is small and correct, and the review gap is a process item.

L2 — low — plan text drift (already recorded as C-S16-2 and C-S16-3)
Location: 04-slices.md row 16 file list, and 03-program-design.md line 123.
Failure or cost: The row lists src/lib.rs, src/http/*routes and "src/osv/batcher.rs (counter)", but the counter lives in OsvCache and the batcher is only the caller of `put`. The design says "re-evaluated or refused, bounded at two preparations", while the code refuses on the first generation change. The test table allows "refused". Behaviour is the conservative choice and still satisfies the spec.
Correction: Fix the plan text at the next plan edit. No code change.
Blocking: no.

## Requirement coverage
| Requirement and source | Implementation/connection | Expected -> observed | Check and limits | Status |
|---|---|---|---|---|
| R1 Gate moved to publication_gate.rs; service_policy.rs re-exports (row 16) | publication_gate.rs holds PolicyPublicationGate, PreparedResponse, AuthorityReceipt and respond_order. service_policy.rs `pub use`s them. | One ordering point. No duplicate types. | Compiles. Callers in managed/mod.rs and artifacts/stream.rs use the new paths. | MET |
| R2 Synchronous respond_order guard on release (row 16, design "no await") | stream.rs `into_response` calls `respond_order(gate, prepared)`. Authorize and `release_verified_response` run while the read guard is held. No await or I/O inside. | Gate generation, gate identity and OSV generation are checked in one critical section, then handoff under the guard. | managed_delivery_authority 5/5 (red on baseline, per baseline-slice-16.md). Gate unit tests 7/7 (poison, barrier, pending-writer, publication ordering). | MET |
| R3 Cold and warm, all methods, current authority before release | Authorized::under_authority attaches the receipt for HEAD, range and GET paths. All paths end in ArtifactResponse::into_response. | A deny or same-revision change before release refuses with zero bytes. | managed_delivery_authority and managed_release_wiring 6/6. The wiring test goes red when `with_osv` is dropped (mutation recorded in tdd-slice-16.md). | MET |
| R4 C1029 osv_generation: bump rule | OsvCache::put bumps only when `matched` and no live match existed before (absent, expired or false). Counter is an Arc<AtomicU64>. The batcher is the only production writer of `put`. | Only an allow-to-deny change advances it. | generation_advances_only_on_a_new_match passes (absent, false, re-store, other key). Expiry and re-match bumps conservatively; harmless (refuses, never releases a stale allow). | MET |
| R5 Generation read BEFORE evaluation; checked inside the gate | artifacts/mod.rs reads `generation()` and `seen` before `evaluate`. `with_osv` stamps the receipt. authorize compares `counter == seen` under the read guard. | A flip during or after evaluation is seen. A bump between the read and the evaluate refuses spuriously, which is safe. | osv_generation_change_refuses_before_release (unchanged delivers, changed refuses). Wiring test refuses cold and warm. | MET |
| R6 Refusal result (503 PolicyUnavailable) | `unwrap_or_else(PolicyUnavailable)` | 503, not a stale allow | Covered by the wiring tests | MET |
| R7 Accepted stream is not cancelled (non-retroactive) | Guard applies only at handoff. | accepted_stream_survives_later_authority_refusal passes. | Preserve-guard, not red (baseline notes this). | MET |
| R8 record_would_block/OSV recording outside the guard | `record_would_block` is awaited before `under_authority`, before the guard is taken. | No await under the lock. | Code read. | MET |
| R9 Standalone mode has no gate (C-S16-4) | `principal.authority` is None, so no stamp, no guard. | Behaviour unchanged. | blocklist_revocation 8/8, artifacts_verification 16/16, osv_enforcement 4/4. | MET |
| R10 Test seam absent from release builds | Barrier field and `set_barrier` are `cfg(any(test, feature = "test-support"))`. `authorize` only calls it under that cfg. | No production hook. | Code read. I did not build with `--release` to confirm the feature gating. | MET (limit: not release-built) |
| R11 No-sleep proof | Gate tests order with channels. Wiring tests were not run in a loop. | Deterministic | Code read. | MET |
| R12 C-S16-1: no cache without an OSV answer | check() has no put on enqueue failure. The batcher puts only when `matches.is_some()`. | A failure cannot overwrite a live match. | a_failed_lookup_fails_open_and_caches_nothing. | MET (see L1) |
| R13 Row 16 caller-visible tests (managed_release_wiring) | tests/managed_release_wiring.rs, 6 tests | Pass | 6/6 | MET |

## Conventions and simplifications
- `service_policy.rs` now holds only policy logic plus a 2-line re-export. This is smaller and easier for slice 28 to edit.
- `PolicyPublicationGate::authorize_current_policy` is a method that delegates to the free function. It is a small duplicate surface, kept so existing callers keep compiling. Optional to remove later.
- Clippy on the changed files: no warnings in any slice-16 file (see Verification).

## Uncertainties
- Flaky `cargo test --lib` (managed::client and osv tests). Cause not found by the implementer. A plausible mechanism seen in code: src/managed/client.rs:844-845 does `std::env::set_var("HTTP_PROXY"/"http_proxy")` process-wide and never removes it. Any reqwest client built afterwards in the same test process, such as the osv tests' clients, then goes through a dead proxy. That would give hangs or failures that differ per run. This is unverified. Check: run the osv tests with those env vars unset, and the managed::client test alone. Owner: row 28 (it touches the managed layer). No effect on slice 16.
- I did not run the full `cargo test --lib`, and did not rebuild a clean-HEAD worktree. Pre-existing status rests on the evidence below.

## Verification and limits
Commands run in the repo, in `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout ...`. No scratch copies, no CPU burners.
- `cargo test --test managed_delivery_authority --test authorization_read_once --test blocklist_revocation --test artifacts_verification --test managed_release_wiring`: 5, 4, 8, 16 and 6 pass.
- `cargo test --lib -- osv:: publication_gate`: 30 passed, in both the default and `--test-threads=1` runs.
- `cargo test --test osv_enforcement`: 4/4.
- `cargo clippy --all-targets -- -D warnings`: fails with 4 errors, in src/http/service_unpublish.rs (lines 24, 97, 101: needless borrow) and src/managed/cache.rs:31 (large enum variant). Without `-D warnings` the only warnings are those plus src/store/action_leases.rs:169. None of those three files is in the dirty tree (git status shows them unmodified), so they are pre-existing on HEAD. No diagnostic points at any slice-16 file.
- Baseline-failure assessment:
  - Clippy errors: pre-existing and unrelated. The files are unmodified, and evidence/slice-16.md reports the same on a clean HEAD worktree. Row 28 lists src/http/service_unpublish.rs and src/managed/cache.rs in its file list, so it will edit them. If row 28's gate includes clippy `-D warnings`, row 28 must fix these 4 errors, and a lint-only commit is cleanest. This does not block starting row 28.
  - Flaky lib tests (osv, managed::client): pre-existing per the clean-HEAD run. The slice-16 osv tests pass in isolation and serially. Row 28's listed commands do not run `cargo test --lib`, so the flakiness does not block row 28. It will make any lib-wide gate untrustworthy until the HTTP_PROXY leak (see Uncertainties) is fixed.
  - action_leases.rs:169 warning is also pre-existing and unmodified.
- Supplied evidence relied on, not re-run: baseline-slice-16.md red results for managed_delivery_authority and authorization_read_once. The review-agent outcomes (code-review=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED) predate C-S16-1.
- Subject fingerprints (first 16 hex of sha256): osv/mod.rs b3ee4e2fce0f5332; osv/batcher.rs a0ad6f2260ae2a0d; managed/publication_gate.rs fb19b8f0fc03a316; artifacts/mod.rs 5365e69e42062fce; artifacts/stream.rs a910c16a7fab035f; managed/service_policy.rs 828726d084b6b047; managed/mod.rs 1b8804eafb02e4a2; tests/managed_release_wiring.rs 550be0b222218077. Base: HEAD 6c4b7fc plus the dirty tree.
- Unchanged during review: yes. No source edits were made. My test and clippy runs only updated the ordinary target/ directory.
- Lenses with no finding: correctness, caller compatibility, removed behaviour (the moved tests and the old inline tests are present in publication_gate.rs), security (the guard cannot be bypassed on the artifact path; poisoning refuses), efficiency (one atomic load under the guard). Not applicable: the docs/conventions lens beyond the plan-text drift in L2.
- Unreviewed: http route files that call into ArtifactResponse (they are unchanged), and the registry/metadata release paths. Row 16 scopes only artifact release.

## Next steps
1. Accept slice 16 within this scope.
2. Include the C-S16-1 hunk (L1) in the row-16 security and adversarial confirmation, since those reviews predate it.
3. Fix the plan text in 04-slices.md row 16 (L2).
4. Slice 28: fix the 4 clippy errors in service_unpublish.rs and cache.rs, and investigate the HTTP_PROXY set_var leak if a lib-wide test gate is used.
