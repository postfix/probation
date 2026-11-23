# Migration: Package Firewall MVP (SF) → Light Factory
Result: DECISIONS ANSWERED 2026-11-18 (1 and 4 still in progress, see "Decisions needed")
Source: /home/john/go/src/github.com/postfix/probation/docs/plans/package-firewall-mvp/ ; SF separate-gate plan (Gates 1,2,3,4 with a 2026-11-17 combined design approval for 2-4), loop generation 41; workspace revision 6c4b7fc30ab1ccda2ed61e0f8224a0c5d0ab9693 on branch slice5-native-ci, DIRTY
Source snapshot: below
Destination: /home/john/go/src/github.com/postfix/probation/docs/plans/package-firewall-mvp-lf/
Worker/publication state: see below

## Source snapshot (sha256, taken 2026-11-18 ~13:10 local, rechecked at end)
| Path (under docs/plans/package-firewall-mvp/) | sha256 |
|---|---|
| 00-status.md | 5eb1b2358c6f472421078fe1316126bca86ea8ab747affa604accd019396d102 |
| 01-product.md | 609f0355a9ec3390e28f3c315d10e6e7980e3dfdc13f53815f382bfe368dca1f |
| 02-architecture.md | f9593d34dd42246112bf2adb8a48d8b8534af9a7b04c8032d9ea2dcaf6df0e31 |
| 03-program-design.md | 6cdec52905215acf050e2f560e0b9980f50d7444b189549eba523cd81c4c2959 |
| 04-slices.md | 583553f0561b2f88d8031b8418f467793b0d3332c496d44a65aae630fa0e4181 |
| gate-1-qa.md | 8184a2f4f8d437121a31a0fb7535e6ddc378d541298ecc9c08c4806d259323bb |
| gate-4-qa.md | 2a158e8f45bc6d28fd8115d8d490fe3a036c1c0d1b6fca1fdafbd51fd96caf73 |
| molecule-contracts.json | fd75a849b984835558514c9d83f2cf6d9b0cfaa530cae1dcc4d941df7c69bde5 |
| molecule-flow.json | db6ba7f77a54d0cb530b5cf95367a1834991b5cb3e0a8c9b9b624be3f5b5eb51 |
| external: /home/john/go/src/github.com/postfix/probation/SPEC.md | 4cda91fb248a65d7382529099d9fb800e1babd1e35d267998ca99299a7c5d002 |
| external: .scratch/scope-review-inputs.json (Gate 1 review input) | a47f3eed6e3e9cc94760e896c86538bf19120904378819248fedbb9cad0c4e44 |
Other source files (evidence/*, specs/*, show-me-*, .gate-*-review.json) were copied/hashed byte-identical (diff -r clean for evidence/ and specs/). Source format: SF with .gate-N-review.json seals (version 1), molecule-flow/contracts, router "loop signal"; no sf-migrate-v2 marker in the source itself.
Source files modified in the dirty tree (not by this migration): 00-status.md, 02, 03, 04, gate-4-qa.md; untracked: evidence/{slice-16,tdd-slice-16,research-osv-ecosystems,threat-model-central-osv}.md, show-me-design-central-osv.html, show-me-slice-16.html. The 2026-11-17 design revision itself therefore exists ONLY in the uncommitted tree.

## Workspace baseline (recorded, untouched)
HEAD 6c4b7fc30ab1ccda2ed61e0f8224a0c5d0ab9693; `git diff -- src docs` sha256 0823bc6e96fc2695f253533208bf7a3909a359aa60b0d9d21af9b7d5f9ee1f73; 22 status lines.
Modified: docs/plans/{management-server/03-program-design.md (+C131), osv-intel/02-architecture.md (+C2008), package-firewall-mvp/{00-status,02,03,04,gate-4-qa}.md}, src/artifacts/{mod,stream}.rs, src/managed/{mod,service_policy}.rs, src/osv/{batcher,mod}.rs.
Untracked: docs/plans/package-firewall-mvp-v2/, evidence/{research-osv-ecosystems,slice-16,tdd-slice-16,threat-model-central-osv}.md, show-me-design-central-osv.html, show-me-slice-16.html, src/managed/publication_gate.rs, tests/managed_release_wiring.rs.
Slice 16 source file hashes (first 16 hex) and mtimes: artifacts/mod.rs 5365e69e42062fce (11-17 21:22); artifacts/stream.rs a910c16a7fab035f; managed/mod.rs 1b8804eafb02e4a2; managed/service_policy.rs 828726d084b6b047; managed/publication_gate.rs fb19b8f0fc03a316; osv/batcher.rs a0ad6f2260ae2a0d and osv/mod.rs b3ee4e2fce0f5332 (both 11-17 23:53, i.e. C-S16-1); tests/managed_release_wiring.rs 550be0b222218077; evidence/slice-16.md written 11-18 00:10.

## Worker and publication state
- Source status records no worker or agent identities (searched 00-status.md). Coordinator reported none running.
- Host observation 2026-11-18 13:08 EET: no cargo/rustc processes; claude CLI processes exist in other directories (CodeStruct, falcoids, show-me-the-code, home) and one in the probation workspace (pts/2, started 13:03; consistent with this session); none attributable to an SF worker of this plan. Not proof of termination; no handles to cancel.
- git worktrees (11 listed): probation (this), .probation-scratch/fix16-merge-wt on fix16a-combined f40000b "FIX-16-A: publication gate seams and OSV generation (C1029)" 2026-11-09 clean, probation-e2e*, probation-fix-fw, probation-fix-srv, probation/.claude/worktrees/agent-a7e4fb06992c9981c (8f5bc84, slice 5). fix16a-combined is an earlier FIX-16-A prototype branch; its relation to the uncommitted slice 16 work is not stated in the plan (see Decision 1).
- Publication: nothing committed, pushed or opened for slice 16 or the 2026-11-17 design. Slices 1-15 are in HEAD history (code for slices 14/15 verified present). No PR/merge state recorded in the source for slices 16+.

## Obligation mapping
| Source ID/location | Meaning or required check | Successor owner/location | State | Gap or disposition |
|---|---|---|---|---|
| 01-product.md (all, C1001-C1029 clarifications, nine families, RubyGems critical, CPAN omitted, Linux/macOS/Windows client, Linux-only server, credentials stay in package managers) | Gate 1 scope | 01-product.md (byte-identical copy) | carried | none. No mockup directory exists in the source ("no new GUI"); Screens section keeps source wording |
| 01-product.md "Domain model and reviewed decision sources" (line 183) | domain model | none separate; 01-domain.md NOT written | gap | Source has only a 1-paragraph "existing domain language suffices"; no model-domain output, no authoritative glossary file found (searched GLOSSARY*, docs/glossary*, CONTEXT*). Recorded as a Gate 1 gap, not an invented model (Decision 5) |
| 02-architecture.md C1003,C1018-C1029 (shared service, one policy/service, host-restricted access, trust approved nodes, FIX-16-A, C1028 D2, C1029 D4); C1030/C1031 central OSV (lines 26-39); Fit/Endpoints/Data/Flow/External (106-199) | Gate 2 contracts | 02-architecture.md (byte-identical) | carried | LF template headings present; extra SF sections retained |
| 03-program-design.md Files/Types/Call stack/Test plan/Invariants/Threat model/Red Team/Least confident (lines 379-1270); revisions 1306, 1448 | Gate 3 contracts and test plan | 03-program-design.md (byte-identical) | carried | LF template headings present; LangSec spec review (LF Gate 3 stage) was not run, SF used Red Team + threat models + Design QA instead (Decision 4) |
| molecule-flow.json, molecule-contracts.json (bySlice 16/28) | structured flow/contracts, "molecule-check PASS" | copied, linked as evidence | carried as evidence | molecule-check/verify are SF tools; not re-runnable here; verify of slice 28 order_guards obligations was PENDING (files absent) |
| specs/service-policy-admission/* (4 analyzer specs, fixtures) | guard-order analyzers owned by rows 16/28 | specs/ copied | carried | row 16 witness reported as delivered; row 28 specs (server-snapshot, managed-activation) PENDING source |
| 04-slices.md rows 1-30; "Direct witness", "Test prerequisites", "Visible review triggers" columns | LF slice packet fields: Behavior=Outcome; Dependencies; Owned files=Exact files; Tests=Direct witness+prerequisites; Demonstration=Direct witness; Review=Visible review triggers; Delivery=none stated (local); Stubs=Temporary artifacts | 04-slices.md (byte-identical, SF table form) | carried | Per-slice "Implementation packet" is built from the row at dispatch time; 04 line 19-21 still says "current unapproved ... proposal" (stale wording; hash is the approved one, see Decision 3b) |
| Security/adversarial/code review requirements per row (04 lines 41-43: rows 16,28,29,17-24,26 security+adversarial; 25 platform security; 27 recheck) | required controls | 04-slices.md + this record | retained | LF runs security-review conditionally; these SF-mandated reviews are KEPT as plan-required (not waived) |
| Slices 1-15 proofs | historical completion | provenance/sf-00-status.md, show-me-slice-*.md in source | historical | current-source match not re-verified; see baseline below |
| Slice 16 | FIX-16-A | evidence/slice-16.md, tdd-slice-16.md, baseline-slice-16.md, show-me-slice-16.html | completed, uncommitted | prerequisite guarantee unverified, Decision 1 |
| Slices 28,29,30,17-21,23-27 | remaining | 04-slices.md rows; 00-status.md | pending | none |
| C-S16-1..4 (slice 16 clarifications) | C-S16-1 user decision 2026-11-18: nothing cached without an OSV response | evidence/slice-16.md | resolved decision, recorded | not re-reviewed |
| C1030/C1031 amendments to other plans (osv-intel C2008, management-server C131) | cross-plan | those plans (dirty, out of scope) | external dependency | recorded; not migrated |
| Loop signal, factory setting presentation: auto, router history | SF runtime | provenance/sf-00-status.md | provenance only | not copied into LF actions |
| SF 00-status Gate 2 progress rows [ ] "Complete 02-architecture.md" etc. | SF bookkeeping reset on reopen | n/a | inconsistent with header APPROVED 2026-11-17 | superseded by header + sealed review; recorded (Decision 3a) |

## Approval provenance
| Light Factory gate | Source user approval and subject | Equivalence evidence | Destination fingerprint | Carried or unresolved |
|---|---|---|---|---|
| 1 Product | APPROVED 2026-11-02, user approved nine-family/RubyGems-critical scope (SF note, bound presentation show-me-gate1-rubygems-nine.md sha ee7d0c35...; Gate 1 review 4b45d1f9 sealed READY) | 01-product.md bytes identical; review subject hash 609f0355... equals current | 609f0355a9ec3390e28f3c315d10e6e7980e3dfdc13f53815f382bfe368dca1f | Carried. Gap: no accepted domain model (Decision 5) |
| 2 Architecture | APPROVED 2026-11-17, combined design approval after central-OSV re-steer (Design QA READY pass 8, review 1cd372e4 sealed, presentation show-me-design-central-osv.html sha 84a63138...) | subject hashes of 01-04 + evidence match; all three docs covered by one approval; no content change on copy | f9593d34dd42246112bf2adb8a48d8b8534af9a7b04c8032d9ea2dcaf6df0e31 | Carried. The user approval itself is recorded only by the SF status ("user approved 2026-11-17") and is not independently verifiable from documents (gate-4-qa.md says so); accepted on the main agent's record. Earlier 2026-11-04 approvals are historical/superseded |
| 3 Program Design | same | same | 6cdec52905215acf050e2f560e0b9980f50d7444b189549eba523cd81c4c2959 | Carried; LangSec review not run (Decision 4) |
| 4 Slice plan | same | same | 583553f0561b2f88d8031b8418f467793b0d3332c496d44a65aae630fa0e4181 | Carried; approves "build in order" for remaining rows; no batch or publication authority was approved |
Stale: none of the four gates is marked stale. One review input is stale-by-design: .gate-4-review.json lists src/managed/publication_gate.rs at sha 701c28c61764 (planned/prototype state); current file fb19b8f0fc03 (delivered slice 16). Expected change from implementation, not a design change; the design hashes still match. Gate 1 review also lists an older 02-architecture.md hash (6cb8ddd2e83b), from 2026-11-02, superseded by later approvals.

## Completed baseline and remaining work
Completed: slices 1-16 (IDs 1..9, 11, 12, 13, 10, 14, 15, 16; SF build order 9->11->12->13->10 then 14, 15, 16; there is no 22). Original evidence in provenance/sf-00-status.md proof lines and show-me-slice-*.md (source dir).
Identity match: slices 1-15 proofs are historical (SF notes the dirty tree and HEAD differ from the proof moment). I verified only that slice 14/15 code exists in HEAD. Not re-run (user constraint: avoid builds). Slice 16 evidence times (11-18 00:10) post-date all slice-16 source files (latest 11-17 23:53) so the recorded results describe the current files; but C-S16-1 was not re-reviewed, and the evidence records `cargo test --lib` failures/flakiness and clippy -D warnings errors in src/http/service_unpublish.rs and src/managed/cache.rs that are identical on clean HEAD. Earlier slice proofs required clippy -D warnings clean, so the global "clippy clean" guarantee dependents (slice 28 owns src/managed/cache.rs and service_policy.rs) assumed is currently UNVERIFIED/false.
Remaining order: 28 -> 29 and 30 (both need 28; independent of each other but both feed later rows) -> 17 (needs 28, 30) -> 18,19,20,21,23,24 -> 25 (28,29,18-21,23,24) -> 26 (24,25,29) -> 27 (17-21,23-26,30).
Batch: none (dependent chain; rows 18-24 may become a candidate tranche only after 17 and only if 5+ independent separately mergeable units exist, and they are 6 rows sharing one mapping file, so likely not).

## Execution-policy differences
- Removed runtime enforcement: SF router, loop signal, `gate-qa` seals and `molecule-check`/`molecule-verify` are not enforced; their last results are historical evidence (molecule-check PASS; verify PENDING for row-28 sources). Analyzer specs under specs/ remain runnable inputs only if SMTC/SF tools are available. Decision 6.
- Review coverage: LF has no Red Team/threat-model/Design-QA gate stages; SF used them for Gates 2-4 and they are retained as evidence. LF Gate 3 LangSec is not retroactively satisfied (Decision 4).
- Required controls retained: per-row code review, independent verification, security and adversarial reviews listed in 04-slices.md are kept as plan requirements; not waived.
- Publication authority: none granted by the SF plan beyond local delivery; LF does not add any. Slice 16 and the design docs are uncommitted; committing needs the user's explicit instruction.
- Recovery guarantees: SF checkpoint/resume projection is gone; this status file and migration.md are the recovery record.
- No unsupported obligations beyond the above.

## Decisions needed
User answers 2026-11-18 (original questions kept in the git-less history of this file's first version; summary below).
1. Slice 16 acceptance: IN PROGRESS. User wants a code review first; report at reviews/slice-16/code-review.md (pending). Slice 16 stays 'complete, review pending' until it returns clean. Commit, fix16a-combined worktree and baseline-failure questions stay open and are not authorized.
2. package-firewall-mvp-v2: RESOLVED. SUPERSEDED by this LF plan; one-line SUPERSEDED note added at the top of its 00-status.md; nothing else touched.
3. Source inconsistencies: RESOLVED. User confirms the 2026-11-17 approval covered exactly the four document hashes recorded in 00-status.md.
4. LangSec: IN PROGRESS. Gate 3 stays approved. A review-langsec pass runs for information only; report at reviews/gate-3/langsec.md (pending); the user reviews its findings.
5. Domain model: RESOLVED, accepted waiver. User omits 01-domain.md ('we already have all the specs').
6. Check tooling: RESOLVED. molecule-check/molecule-verify/specs analyzers are replaced by independent code-review per slice (user decision).

Gate to slice 28: slice 16 code review returns clean and the user has reviewed the LangSec findings.

## Validation
- Source unchanged by migration: all source file hashes above rechecked after writing (see final line); no source file was written.
- Destination: 01-04, molecule-*.json, gate-*-qa.md, evidence/, specs/ byte-identical (cmp/diff -r); relative links inside 01-04 resolve to evidence/ and specs/ in the destination. Links to ../management-server/..., ../osv-intel/..., ../package-firewall-mvp/ (show-me-* history, SPEC.md at repo root, .scratch) are retained as EXTERNAL dependencies on the source/other plans; show-me-* files other than the three bound presentations were not copied.
- Decision IDs unchanged (C1003, C1018-C1031, D2-D5, C-S16-*). Dependency order checked from 04-slices.md rows. Completed-code claims: only HEAD presence of slice 14/15 code and file mtimes vs evidence time were checked.
- Commands run: ls, stat, sha256sum, cmp, diff -r, git status/diff/log/worktree/grep (read-only), cp into the new destination directory, ps/pgrep. No builds, tests, or load; nothing in /tmp.
- Limits: tests not re-run; user approval of 2026-11-17 not independently verifiable; other claude sessions cannot be ruled out as concurrent writers to the shared dirty tree.

## Next action
After the slice 16 code review (reviews/slice-16/code-review.md) returns clean and the user has reviewed the LangSec findings (reviews/gate-3/langsec.md), dispatch `implement` for Slice 28 from its 04-slices.md row, local result only (no commit/push/PR authority), followed by 29 and 30.
