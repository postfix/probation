# Design QA
## Verdict
READY

## Overall assessment
This is the fourth review of the combined design, reopened for C123. It covers 01-product.md (approved scope), 02-architecture.md, 03-program-design.md, 04-slices.md, molecule-flow.json, molecule-contracts.json, the `managed-*` analyzer specs and controls, read together as one decision. The round-3 findings are fixed. AA1: the T-edit-parent-chain row in 03 § Test plan now tells a correct parent chain apart from a sibling group's chain or an organisation-only chain, and it checks the returned stored layer. AA2: the slice 2 witness for T-resolve-empty-platform now requires `test result: ok. 1 passed`, so it fails before the test exists. The C123 disposition entry now sits at the end of 03 § Review dispositions. Nothing blocks. The machine checks give these results: `router check` reports no findings; `molecule-check` returns PASS; source verification passes for the 3 obligations whose source exists, with every control detected; the other 9 obligations are PENDING on absent sources, each assigned to the slice that creates it. The C123 SMTC query returns exactly one site on the current tree. Decisions that were already approved and are not affected by C123 stay approved.

## Questions and findings
None.

AA1 is resolved. 03 § Test plan, row "parent chain for edits", now sets up a user U in group G, where G has `shorter_freeze` off, next to a sibling group G2 in the same organisation, where it is on. The row asserts three things:
- `PolicyStore::parent_policy` returns `resolve` of [Platform], [Platform, Org] and [Platform, Org, G].
- For each place, the returned stored layer equals that place's own stored layer.
- `check_edit` with U's parent refuses a new shorter freeze (`NotAllowedByParent { ShorterFreeze }`) and accepts a re-save of U's unchanged kept 1-day freeze (C47).

If the implementation picked G2 or stopped at the organisation, the parent's `allow.shorter_freeze` would be on and the refusal assertion would fail. If it returned the wrong current layer, the stored-layer assertion would fail. The slice 4 `policy_edit` witness still names 8 tests, and the count matches its list.

AA2 is resolved. Slice 2's direct witness reads `cargo test -p probation-policy --lib tests::t_resolve_empty_platform` prints `test result: ok. 1 passed`. Today the filter matches no test and prints `0 passed`, so the witness fails before the test is written.

## What was checked
- **Evidence and clarifications.** I read all of 01–04 and the molecule files. I also read evidence/smtc-argument-matching.md, evidence/red-team.md § "C123 re-review", evidence/slice-1.md, evidence/slice-2.md and controls/managed-contracts.json. All design inventories (C2, C34, C35, C86, C95–C125, C108) are resolved and each names its decision source. C123, C124 and C125 each record the user's answer and date. Nothing open is deferred to Engineering. Result: pass.
- **Architecture and interfaces (sf-codebase-design).** I checked 02 § Fit and § Flow and 03 § Modules and interfaces. `PolicyStore::parent_policy` is a deep seam: the portal, the automation push and the bootstrap CLI all get both the parent `EffectivePolicy` and the current stored layer from this one function, so chain selection is decided in one place and tested at that interface. C123 changes no caller-visible guarantee. "Exactly one `Authorization` read, and only the hash leaves" stays the same promise; only its check changed. Result: pass.
- **Contracts, flows and model.** `router molecule-check`: PASS (3 flows: `managed-request`, `policy-edit`, `sync-changes`). Required outcomes still trace to C8, C13, C19, C20, C25, C30, C55, C66, C72, C81, C92, C96 and C120. No obligation was deleted or weakened in this round. Result: pass.
- **Source obligations.** Preparation's `sourceVerification` is PENDING, which means no failures. Three obligations PASS on existing source with zero production findings, and every control produces findings:
  - `authenticate-checks-retired-first` (src/managed/mod.rs, slice 2): 3/3 operations guarded; controls `retired-check-removed` and `retired-check-after-lookup` each give 3 findings.
  - `decide-exceptions-first` (src/policy/effective.rs, slice 1): 2 controls, each detected.
  - `check-edit-loosening-search-first` (crates/probation-policy/src/edit.rs, slice 1): 2 controls, each detected.

  Nine obligations are PENDING on absent sources: slice 3 for src/managed/sync.rs and activity.rs, slice 4 for crates/probation-server tenancy.rs and policy.rs. Each `bySlice` matches the slice's Source evidence line in 04. I did not run the full `molecule-verify` because PENDING obligations remain. Result: pass for planning.
- **Security coverage (T19 re-model, C123).** I checked 03 § Threat model, § Security coverage and § Invariants. The T19 row is now a token-allowlist test, the C123 SMTC query and T-key-canary, with T19a–h assigned and no new risk acceptance. The premise in evidence/smtc-argument-matching.md still holds: on the current tree, `smtc callers --name get|get_all --callsites-matching '*AUTHORIZATION' --argument-index 0|1` over absolute `src` and `crates/probation-policy/src` returns exactly one site, `headers.get(AUTHORIZATION)` in src/managed/mod.rs. A grep of current source agrees with the pinned allowlist: `AUTHORIZATION` appears only in src/managed/mod.rs and in the src/config.rs default, and `siem_auth_header` only in src/config.rs and src/delivery/mod.rs. The line format in § Invariants & spec dispositions is valid (KEEP, UNKNOWN, existing check, one-off, deferred to slice 4). Result: pass.
- **Test plan (sf-tdd).** Each changed row names its seam, its input and an assertion that tells correct behaviour from a defect. T-edit-parent-chain tests at the public `parent_policy`/`check_edit` interface with literal outcomes. Its `resolve` comparison is not tautological, because the property under test is which chain is selected, not how the merge works. T-resolve-empty-platform pins C125's fail-open default with literal values (freeze 0, OSV Off, no source layer). Result: pass.
- **Delivery.** Slice order still delivers each guarantee before anything relies on it: shared rules (1), then the managed firewall against a fake server (2–3), then the real server (4), the portal (5–7) and finally E2E (8). Each witness names exact counts and a reason it fails today. The C123 test and query are in the Recheck of slices 2–8. Slice 2's Temporary behavior is explicit. Result: pass.
- **Repository evidence.** 03 § Repository evidence still assesses the effect on existing callers, with links. Result: pass.

## Limitations
- Model PASS covers the finite declared model only. Source PASS covers the encoded call-order properties on existing source only. Neither proves arbitrary implementation behaviour.
- Nine source obligations remain PENDING until slices 3 and 4 create their sources.
- Slice 2 is implemented but not committed or reviewed. `tests/authorization_read_once.rs` and `tests/key_canary.rs` do not exist yet. Their pinned allowlist and canary results are slice 2 delivery evidence and were not assessed here.
- The C123 SMTC query result depends on the current SMTC build, which is marked as a dirty build. Each Recheck must run it again.

## Next steps
The main agent presents the reopened combined design to the user for approval and records that approval. Slice 2 delivery resumes only after that.
