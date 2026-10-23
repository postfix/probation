# Status: Probation management server and self-service portal

- Gate 1 — Product: APPROVED 2026-10-20
- Gate 2 — Architecture: APPROVED 2026-10-21
- Gate 3 — Program Design: APPROVED 2026-10-23
- Gate 4 — Slice plan: APPROVED 2026-10-23

## Factory settings

- presentation: auto

## Loop signal

{"generation":12,"boundary":{"kind":"slice","number":6},"reopened":false,"history":[]}

## Gate 1 progress

- [x] Create 00-status.md
  Result: docs/plans/management-server/00-status.md created from the template.
- [x] Select the plan with router resume
  Result: router resume returned no findings; position Gate 1.
- [x] Create the product clarification inventory
  Result: 01-product.md `## Clarifications and decisions` created.
- [x] Resolve user decisions
  Result: grilling Q1–Q31 recorded as C1–C33 in 01-product.md; 0 open; C2 deferred to Gate 2.
- [x] Review UI mockups with the user
  Result: 9 mockups in mockups/ approved (C74); mockup review raised C34–C35 (deferred to Gate 2) and C36–C73 (resolved).
- [x] Complete 01-product.md
  Result: 01-product.md — Problem, Success metric, Non-goals, Announcement, Screens written from C1–C74.
- [x] Obtain QA READY
  Result: docs/plans/management-server/gate-1-qa.md — READY after five rounds (Q1–Q13 answered as C75–C94, F1–F5 fixed); gate-qa verify returned READY.
- [x] Present and record user approval
  Result: approved by the user 2026-10-20; presentation docs/plans/management-server/show-me-gate-1.md.

## Gate 2 progress

- [x] Check whether existing architecture and evidence can be reused
  Result: no earlier architecture for this feature; repository evidence was missing, so it was gathered fresh.
- [x] Create or update the architecture and carry deferred questions
  Result: 02-architecture.md created; C2, C34, C35 and C86 imported under their original IDs.
- [x] Gather repository evidence
  Result: evidence/repository-structure.md (sf-repo-view): routes, policy evaluation, caches, config, Decision record, analyzers.
- [x] Save findings and resolve architecture decisions
  Result: Gate 2 grilling Q50–Q55 resolved C2, C34, C35, C86 and C95–C102; `grep -c '| open |' 02-architecture.md` = 0.
- [x] Complete 02-architecture.md
  Result: all template sections written; router check has no findings; molecule-check PASS (3 flows, 16 required outcomes).
- [x] Record architecture assumptions and review triggers
  Result: assumptions in molecule-flow.json; review triggers in 02-architecture.md § Constraints (Decision record size, header-read analyzer, restart on settings push, C83 budget).
- [x] Complete architecture section of the combined design
  Result: 02-architecture.md complete after threat-model (B1–B3) and red-team (F1–F6) fixes; router check no findings.
- [x] Carry contracts and obligations into program design
  Result: molecule-flow.json operations carried into 03 § Modules and interfaces; molecule-contracts.json has 12 contracts, each assigned to a slice.

## Gate 3 progress

- [x] Create or update the design from its template
  Result: 03-program-design.md written from the template; C103–C116 recorded (C113–C116 from grilling Q56).
- [x] Gather design evidence
  Result: evidence/repository-structure.md plus red-team source checks (config.rs REQUIRED_KEYS, health.rs ready, Dockerfile).
- [x] Record effects on callers, dependencies, and planned checks
  Result: 03 § Call stack and § Files; caches, download single flight and Decision record changes named with their checks.
- [x] Define interfaces, behavior, invariants, and test cases
  Result: 03 § Modules and interfaces, § Program behavior, § Invariants & spec dispositions (12 KEEP), § Test plan.
- [x] Validate analyzer specs or assign their authoring to slices
  Result: 12 .smtc/analyzers/managed-*.yaml specs authored (sf-spec-authoring), PENDING until source; T19 spec assigned to slice 2.
  Reopened 2026-10-22 (slice 2 delivery): the T19 spec cannot be built; this SMTC build ignores argument constraints in specs (sf-spec-authoring UNKNOWN, sf-smtc-doctor UNSUPPORTED). User chose C123: cargo test T-authorization-read-once plus the `smtc callers --callsites-matching AUTHORIZATION` query in every Recheck. 03 (C123, § Invariants, T19 threat row, § Security coverage, § Test plan, H5) and 04 (slice 2 files and acceptance, Recheck of slices 2–8) updated. Rework: fresh design QA (`--gate design`) and the user's design approval.
  Result (2026-10-22): no T19 spec; C123 checks (T-authorization-read-once, T-key-canary/T-key-canary-sync, C123 SMTC query) assigned to slices 2–3 and rechecked in 2–8; premise in evidence/smtc-argument-matching.md.
- [x] Define security coverage and resolve required planning reviews
  Reopened 2026-10-22: the T19 coverage row changed under C123; the guarantee is unchanged. Rework: Design QA checks the changed row.
  Result (2026-10-22): sf-threat-model MODELED (T19a–h, 03 § Threat model); sf-red-team NEEDS REVISION, 6 findings fixed (evidence/red-team.md § C123 re-review); C124 and C125 recorded; § Security coverage updated.
  Result: sf-threat-model T1–T30 with B1–B3 fixed; acceptances A1–A7 accepted by the user 2026-10-21 (C116); 03 § Security coverage.
- [x] Complete contracts and flows for the combined design
  Result: molecule-check PASS (3 flows); molecule-contracts.json 12 contracts.
- [x] Carry guarantees and checks into delivery slices
  Result: 04-slices.md lists each contract and test by slice.

## Gate 4 progress

- [x] Write the slice plan
  Result: 04-slices.md, 8 slices (C108).
- [x] Define slice behavior and dependencies
  Result: each slice row names its behavior, dependencies and files.
- [x] Define checks
  Result: each slice witness fails before implementation (red-team F5 fixed).
  Reopened 2026-10-22: slice 2–8 Recheck lines changed from the T19 spec run to the C123 test plus SMTC query.
  Result (2026-10-22): slice 2 witness adds authorization_read_once and key_canary; slice 3 witness adds key_canary 2 passed; slice 4 adds T-edit-parent-chain; slice 7 T-blocklist-roundtrip covers `reason`.
- [x] Validate prerequisites
  Result: tools cargo, docker, npm, npx, bash; test-only fixtures named per slice.
- [x] Complete required combined design reviews
  Result: sf-threat-model and sf-red-team findings fixed in 02, 03, 04; user decisions Q56 recorded as C113–C116.
- [ ] Obtain QA READY
  Reopened 2026-10-23: C126 (only the ahead firewall resets), C127 (taken org name revealed, accepted like A3) and C128 (removed members stay removed under SSO) were added to 03 as user decisions during delivery without design re-approval; the router refused slice 3 completion (SOURCE_CONTRACT_REQUIRED). Rework: fresh `--gate design` QA, then user approval.
  C126–C130 rounds: QUESTIONS (ABQ1 → C129 operator after-restore; ABQ2 → C130 only admin removal blocks SSO re-join, erased with the login; AB1–AB4 fixed, 485f724), REVISE (AC1–AC3, N1 fixed, 861441d), REVISE (AD1: +1 not +2^32, 09d5f4a), READY — gate-4-qa.md. User approved 2026-10-23 (show-me-design.html); gate-qa approve --gate design APPROVED.
  Reopened 2026-10-22 for C123; fresh `--gate design` QA required.
  C123 round 1: QUESTIONS — docs/plans/management-server/gate-4-qa.md. Blocker: YQ1 (user question: C47 "not in effect" vs slice-1 deviation 2). Revisions Y1–Y6 pending. Next: ask YQ1, fix Y1–Y6, request fresh QA.
  YQ1 answered by the user (24 h) as C124; Y1–Y6 fixed in 03 and 04; N1 saved as evidence/smtc-argument-matching.md; router check no findings, molecule-check PASS. Round 2 requested.
  C123 round 2: REVISE — gate-4-qa.md (Z1–Z3, no user decision). Fixed: T-edit-parent-chain in § Test plan with `PolicyStore::parent_policy` and the slice 4 policy_edit witness (8 passed); C125 seeding claim removed and T-resolve-empty-platform added (slice 2); stale status lines in 02/03 fixed; review disposition added. router check no findings, molecule-check PASS. Round 3 requested.
  C123 round 3: REVISE — gate-4-qa.md (AA1, AA2, no user decision). Fixed: T-edit-parent-chain rewritten with sibling groups G/G2 and a stored-layer assertion; the slice 2 T-resolve-empty-platform witness requires `1 passed`; the disposition entry moved to the end of § Review dispositions. router check no findings, molecule-check PASS. Round 4 requested.
  User approved round 4 (2026-10-22). C123 round 4: READY — docs/plans/management-server/gate-4-qa.md; gate-qa verify --gate design returned READY.
  Round 1: UNKNOWN — docs/plans/management-server/gate-4-qa.md. Blockers: E1 (red-team report not saved), Q1 (C106 vs C16, user question), F1–F10 revisions.
  Revisions: red-team report saved (evidence/red-team.md); Q57 accepted C106; F1–F10 fixed in 02, 03, 04, molecule-flow.json, contracts (03 § Review dispositions); router check no findings, molecule-check PASS. Round 2 requested.
  Round 2: REVISE — gate-4-qa.md (R1–R9). Fixed in 01 (C16 note), 02, 03, 04, molecule-flow.json and the sync reference shape (03 § Review dispositions); router check no findings, molecule-check PASS. Round 3 requested.
  Round 3: REVISE — gate-4-qa.md (D1–D7, no user decision). Fixed in 03 and 04 (03 § Review dispositions); router check no findings, molecule-check PASS. Round limit reached: round 4 needs the user's permission.
  User approved round 4 (Q58, 2026-10-21). Pre-review sweep (5 lenses, 2 skeptics each): 41 confirmed findings fixed in 02, 03, 04, molecule-flow.json and reference shapes; router check no findings, molecule-check PASS. User answered Q59 = A (publish probation-policy too), recorded as C117. Round 4 requested.
  Round 4: REVISE — gate-4-qa.md (G1–G10, no user decision). Fixed; research note evidence/research-cargo-workspace-publish.md. Second pre-review sweep (6 lenses, 2 skeptics each): 63 confirmed, fixed. Synthetic molecule-verify 12/12 PASS; existing analyzers zero findings on reference src/managed (evidence/analyzer-roots.md). router check no findings, molecule-check PASS. User answered Q60 = A (C118) and approved round 5 (Q61, 2026-10-21). Round 5 requested.
  Round 5: REVISE — gate-4-qa.md (H1–H7), fixed. Third pre-review sweep: 52 confirmed, fixed (03 § Review dispositions); synthetic molecule-verify 12/12 PASS; router check no findings, molecule-check PASS. User answered Q62–Q65 (C120–C122) and approved round 6 (Q66, 2026-10-21). Round 6 requested.
  Round 6: REVISE — gate-4-qa.md (J1–J7, no user decision), fixed; synthetic molecule-verify 12/12 PASS; router check no findings, molecule-check PASS. User approved round 7 (Q67, 2026-10-21). Round 7 requested.
  Round 7: REVISE — gate-4-qa.md (K1–K3, no user decision), fixed; synthetic molecule-verify 12/12 PASS; router check no findings, molecule-check PASS. User approved round 8 (Q68, 2026-10-21). Round 8 requested.
  Round 8: REVISE — gate-4-qa.md (L1–L4, no user decision), fixed; synthetic molecule-verify 12/12 PASS; router check no findings, molecule-check PASS. User approved round 9 (Q69, 2026-10-21). Round 9 requested.
  Round 9: REVISE — gate-4-qa.md (M1–M2, no user decision), fixed; router check no findings, molecule-check PASS. User approved round 10 (Q70, 2026-10-21). Round 10 requested.
  Round 10: REVISE — gate-4-qa.md (N1–N2, test-plan only, no user decision), fixed; router check no findings, molecule-check PASS. User approved round 11 (Q71, 2026-10-21). Round 11 requested.
  Round 11: REVISE — gate-4-qa.md (P1 only, no user decision), fixed; router check no findings, molecule-check PASS. User approved round 12 (Q72, 2026-10-21). Round 12 requested.
  Round 12: REVISE — gate-4-qa.md (S1: 00-status.md ## Slices still had template rows; design itself passed every check). Slices 1–8 declared. User approved round 13 (Q73, 2026-10-21). Round 13 requested.
  Round 13: REVISE — gate-4-qa.md (V1 delivery order), fixed. Delivery-order sweep: 11 confirmed and fixed; second pass 0 confirmed. router check no findings, molecule-check PASS. User approved round 14 (Q74, 2026-10-21). Round 14 requested.
  Round 14: REVISE — gate-4-qa.md (W1 + 4 notes), fixed. Propagation/temporary-behaviour check: 5 found, fixed. router check no findings, molecule-check PASS. User approved round 15 (Q75, 2026-10-21). Round 15 requested.
  Pre-review sweep: 14 confirmed, fixed (03 § Review dispositions); router check no findings, molecule-check PASS.
  Result: Round 15 READY — docs/plans/management-server/gate-4-qa.md (notes N1–N4 non-blocking, left unchanged); gate-qa verify returned READY.
- [ ] Present and record user approval
  Reopened 2026-10-23 for C126–C128.
  Reopened 2026-10-22 for C123; the design needs the user's approval again.
  Result: reopened design (C123, C124, C125) approved by the user 2026-10-22; presentation docs/plans/management-server/show-me-design.md; gate-qa approve --gate design returned APPROVED.
  Result: design approved by the user 2026-10-21; presentation docs/plans/management-server/show-me-design.md; gate-qa approve --gate design returned APPROVED.

## Slices

- [x] Slice 1 — tracer bullet: a standalone firewall decides through `decide(&CompiledPolicy, …)` with identical results; `probation-policy` merges layers and checks edits
  - proof: cargo test -p probation-policy; cargo test -p probation-policy --doc; cargo test --lib policy::effective::tests; cargo test --workspace; cargo bench --bench warm_metadata --bench artifact_throughput -- --assert; cargo clippy --workspace --all-targets -- -D warnings; docker build .; cargo package --workspace --locked; cargo llvm-cov --locked --summary-only --fail-under-lines 98; router molecule-check; router molecule-verify --slice 1 -> probation-policy ok. 8 passed (7 approved + D3 C9 should_panic from review) + doctest ok. 1 passed; effective tests ok. 4 passed; workspace 33 suites ok, 0 failed; benches 9/9 SPEC §12 PASS (warm denial p95 1.411 ms); clippy clean; docker build exit 0; package probation-policy+probation only; llvm-cov 98.46% lines; molecule-check PASS; molecule-verify slice-1 contracts PASS (4/4 controls), later slices SOURCE_PENDING; evidence/slice-1.md; reviews: qa=VERIFIED, code-review=SHIP, adversarial=PASS
- [x] Slice 2 — a managed firewall serves each request under its own key's policy from a fake server and refuses missing or unknown keys
  - proof: cargo test --test managed_mode; cargo test -p probation-policy --lib tests::t_resolve_empty_platform; cargo test --test authorization_read_once; cargo test --test key_canary; cargo bench --bench warm_metadata --bench artifact_throughput -- --managed; cargo test --workspace; clippy -D warnings; fmt --check; cargo llvm-cov --fail-under-lines 98; docker build .; router molecule-check; router molecule-verify --slice 2; C123 smtc callers query -> managed_mode ok. 10 passed; t_resolve_empty_platform ok. 1 passed; authorization_read_once ok. 4 passed; key_canary ok. 1 passed; --managed overhead PASS, throughput PASS on reruns (89.4% once at load 18.45, then 110.7/109.6/99.1%; S2-4); workspace 36 ok; clippy/fmt clean; llvm-cov 98.46%; docker exit 0; molecule-check PASS; authenticate-checks-retired-first PASS (2/2 controls); C123 query exactly 1 site; evidence/slice-2.md; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
- [x] Slice 3 — a managed firewall syncs, enforces the network lock and readiness, serves stale during outages, ships activity and applies settings pushes
  - proof: cargo test --test key_canary; cargo test --test managed_sync; cargo test --test origin_guard; cargo test --test managed_mode; cargo test --test authorization_read_once; cargo test --workspace; router molecule-verify --slice 3; C123 smtc callers query; analyzers at documented roots -> key_canary ok. 2 passed; managed_sync ok. 33 passed (S3-11); origin_guard 26; managed_mode 10; authorization_read_once 4; workspace all ok; molecule-verify slice 1-3 obligations 9/9 PASS; C123 exactly 1 site; analyzers pass (outbound-timeout-guard pin refreshed, 02de667); evidence/slice-3.md; final verification on 08b6d69; reviews: qa=VERIFIED
- [x] Slice 4 — `probation-server` on Postgres answers the real sync API; keys and layers via the bootstrap CLI, edited atomically with audit
  - proof: docker compose -f docker-compose.test.yml up -d postgres; cargo test -p probation-server --test sync_api; --test policy_edit; --test tenancy; --test propagation -- --nocapture; cargo test -p probation-server --doc; cargo test --workspace; clippy; fmt; cargo package --workspace --exclude probation-server --locked; router molecule-verify --slice 4; analyzers at crates/probation-server -> sync_api ok. 6 passed; policy_edit ok. 8 passed; tenancy ok. 3 passed; propagation ok. 3 passed (edits p99 5.002 s, revocations p99 4.954 s <= 10 s interval); doctest ok. 1 passed; workspace 609 passed 0 failed; clippy/fmt clean; package probation + probation-policy only; molecule-verify slice 4 PASS 12/12; analyzers 0 findings; evidence/slice-4.md; final verification on 7d9dda9; reviews: qa=VERIFIED
- [x] Slice 5 — people sign up, verify, sign in (password, OAuth, SSO), link methods, use TOTP, delete and restore in the portal
  - proof: cargo test -p probation-server --test accounts; cargo test --workspace; clippy -D warnings; fmt --check; router molecule-check; router molecule-verify --slice 5; 4 analyzers; C123 smtc callers query; node crates/probation-server/tests/a11y/axe.mjs --slice 5; post-merge cargo test -p probation-server on management-server b2ebbe3 -> accounts ok. 29 passed; workspace 634 passed 0 failed 21 ignored; clippy/fmt clean; molecule-check PASS; molecule-verify slice 5 PASS 12/12; analyzers 0 findings at crates/probation-server and pass conditions at documented roots; C123 exactly 1 site; A11Y slice 5: 22 pages, 0 problems; mutants R4 N1 N2 N5 killed; F4 SSO org check added at a6009c8 (accounts 29 passed); after merge on b2ebbe3: accounts 29, policy_edit 8, propagation 3, sync_api 6, tenancy 3, lib 3, doctest 1 all ok; S5-7 TOTP reset moved to slice 6 (04, 485f724); evidence/slice-5.md; reviews: qa=VERIFIED
- [ ] Slice 6 — org admins, group admins and users manage members, groups, invitations, keys, policy, activity, audit, ranges and org deletion in the portal
- [ ] Slice 7 — global admins manage organisations, personal accounts, platform policy, ranges, limits, the fleet, blocklist import/export and retention
- [ ] Slice 8 — scripted sign-up to `npm install` in under 10 minutes; propagation, overhead and accessibility measured; both images build

## Notes for a fresh session

- Scope is fully recorded in 01-product.md rows C1–C94; the chat added nothing beyond them.
- Gate 2 must import and resolve the deferred rows C2, C34, C35, C86 under their original IDs.
- The user is not a native English speaker: keep questions short and concrete, with a scenario.
- The user prefers batching small, conventional details into one numbered list with recommendations (C36).

## Source contract evidence

Required for this plan.
