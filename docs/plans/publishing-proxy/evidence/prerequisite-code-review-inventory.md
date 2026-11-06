Review kind: code-review
Verdict: SHIP
Question: Does the exact fixture-inventory repair close the sole remaining round-2 defect without changing the reviewed product or weakening its scanner?
Reviewing: targeted recheck, round 2 to final round 4; tests/authorization_read_once.rs and its unchanged race fixture. Prior independent review coverage is retained for the other 29 manifest paths.

The inventory defect is closed. Exactly two count-1 ALLOWED tuples were added, and the supplied focused scanner execution passes all four tests, including the mutation negative control. This is a bounded code-review verdict, not delivery completion or whole-program proof.

Defects:
- None remaining in this targeted recheck. Round-2 MAJOR inventory finding: PASS. The old full-suite run failed three inventory tests; final round-4 scanner passes 4/0/0. The intermediate round-3 tuple retained a space that the scanner removes; final round 4 correctly uses the normalized key below. No scanner logic changed to obtain this result.

Deciding evidence (Manual source/fingerprint evidence plus supplied executable check):
1. Base resolves to `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`. Round-4 manifest SHA256 `4551649c2a115004aacd7048c9ef8d9d53da97b2d2b820357ae7f19f3d94a9ed`; all 30 current hashes match before and after review. Round-2 and round-4 path sets and base are identical; all 29 other paths retain their round-2 hash.
2. The round-2 inventory snapshot matches its manifest SHA256 `2c90f5e849cb69aca998a6bcdb09c61b62b3b9830bb5cc09363d46996a2b7797`. Complete `git diff --no-index` against final inventory shows only the following additions at lines 42–43. Final inventory SHA256 `dc00d9284647cc77046b4eacf5f453890fda375626cb9b27e3d4996c5037829c`.

```rust
("src/managed/mod.rs", "fn place_invalidation_cannot_stamp_an_old_admission_with_new_authority", "insert(AUTHORIZATION,HeaderValue::from_static(\"Bearerprb_01234567890123456789012345678901\"))", 1),
("src/managed/mod.rs", "fn place_invalidation_cannot_stamp_an_old_admission_with_new_authority", "get(AUTHORIZATION)", 1),
```

3. Resolved and inspected the complete fixture at `src/managed/mod.rs:1227–1272`: its local HeaderMap inserts the fixed synthetic `Bearer prb_01234567890123456789012345678901` and reads it to compute the cache key. The real header still contains its required space. This file remains SHA256 `55f5228ef1b3c0c919ce422bbfd05857fc353f983cfe4c3201f8eb90208ce339`. The unchanged `squeeze` implementation removes whitespace, including the literal's space, which explains the exact inventory key.
4. The complete two-line-only diff preserves scanner implementation, ROOTS, all prior tuple counts, exact multiset comparisons and all negative controls. No broad exemption, cfg(test) exclusion or matching relaxation was added. The prior four product-defect closures and their risk-bearing-neighbor coverage remain bound to identical bytes through the round-2 manifest and report.
5. Supplied runner result, inspected directly: `.scratch/prerequisite-checks/review-inventory-green-4.log`, SHA256 `b8631b3e18a68a3c7f4c27167f81f41f5c7f13c64ca148925ea5e0571fcd494a`: four passed, zero failed/ignored; runner reports exit 0. Passing tests cover real-tree inventory, mutation rejection, harmless edits and comments. This reviewer ran no tests or builds.

Conventions (inherited empty repository standards set; supplied AGENTS instructions):
- None. This targeted recheck retains the prior standards discovery and clean conventions result. No toolchain-formatting opinion is added.

Simplifications:
- None recommended for this two-entry maintenance change. Retain the prior unconfirmed advisory concerning `validate_policy_snapshot` removal; no deletion or replacement safety is asserted. If removal is later proposed: `sf-impact change validate_policy_snapshot`.

Unchanged during review: yes, for the final frozen round-4 subject. Scoped Git status SHA256 `7348666cde20822212a7ad483b3b644ed9265f0819310453a75e7ba95e378542` (873 bytes) and `git diff HEAD` SHA256 `c2af1a01a6c5781520685018634e8e15c5e8564eeb0693fb9b8c0c2452fa12f4` (53898 bytes) match before/after; all 30 file hashes match. The announced round-3 correction preceded the final subject binding.
Reviewed: freshly, the ALLOWED additions and scanner front end/normalization in tests/authorization_read_once.rs, plus the complete race fixture in src/managed/mod.rs. For every other path listed in subject-round-4.json, retain the unchanged subject-round-2.json coverage documented in prerequisite-code-review-round-2.md; this is not a repeated 30-file audit. Deleted: none.
Checked clean in the bounded difference, retaining prior clean lenses: correctness/totality/boundaries/types/numeric behavior; errors/rollback/partial failure; ownership/cleanup/cancellation/lifecycle; shared-state ordering/races/deadlocks/termination; preconditions/postconditions/invariants/compatibility/side effects; input bounds and obvious security defects; maintenance coupling; tests and approved scope; conventions. Simplifications retain only the advisory limitation above. Accepted historical TDD disposition remains unchanged; this repair adds inventory data, no test logic or product behavior.
Omitted: 0 defects, 0 conventions, 0 established simplifications.
Limitations: Manual selected-source evidence and exact hash/diff binding, with explicitly supplied runtime evidence. Full workspace, current-image E2E and renewed source-proof results remain coordinator-owned acceptance work. No new exhaustive concurrency, transitive credential-flow, native-storage or whole-program claim.

SMTC receipt

Root R=`/home/john/go/src/github.com/postfix/probation`; session S=`sf-prerequisite-inventory-review-2026-11-03`. Ordinary argv below expands R/S and always includes `--root R --format json --max-tokens 2048 --session-id S`. All legs ran with outer ok=true, no inner refusal or diagnostics. File/inspection results do not report fidelity or functions-analyzed; they support Manual inspection only, not a semantic safety negative.

- `smtc file read --root R --path .scratch/prerequisite-review/subject-round-3.json --format json --max-tokens 2048 --session-id S`: run; complete 35 lines, no refs/truncation; initial supplied-subject binding before announced correction.
- `smtc file read --root R --path docs/plans/publishing-proxy/evidence/prerequisite-code-review-round-2.md --format json --max-tokens 2048 --session-id S`: run; truncated into ref-36 (3680 estimated tokens); not used as complete evidence. Narrowed with identical argv plus `--start-line A --end-line B` for 1–30, 31–49, 50–63; all ranges complete, no refs/truncation. Establishes prior sole blocker, clean lenses, retained scope and limitations.
- `smtc file read --root R --path tests/authorization_read_once.rs --start-line A --end-line B --format json --max-tokens 2048 --session-id S`: run for 1–65, 75–155, 330–345; complete, no refs/truncation. Establishes exact additions, unchanged exact-count implementation and normalization.
- `smtc search symbol --root R --name-pattern '*place_invalidation_cannot_stamp_an_old_admission_with_new_authority' --limit 6 --format json --max-tokens 2048 --session-id S`: run; exactly one declaration, no truncation/ref. Zero-based start (1226,4), handle R/src/managed/mod.rs:1227:1272; locator only.
- `smtc inspect symbol --root R --handle R/src/managed/mod.rs:1227:1272 --format json --max-tokens 2048 --session-id S`: run; complete 46-line fixture, no refs/truncation. Establishes the two synthetic HeaderMap sites. No callers/blast-radius operation needed: no shared contract or candidate deletion changed.

Skipped: fresh builds/tests and a repeated whole-subject audit; full workspace/E2E/source-proof acceptance remains pending independently of this code-review SHIP.
Risk: the scanner remains the existing token scanner, not a semantic authorization-safety proof.
