# Slice 1 evidence — standalone decides through `decide(&CompiledPolicy, …)`; `probation-policy` merges layers and checks edits

Date: 2026-10-21. Base: 23e8822 (`main`), uncommitted working tree.
Prerequisite C122: `probation-policy` 0.0.0 placeholder published on crates.io, owner `postfix` (checked through the crates.io API before dispatch).

## Changed files
Modified: `Cargo.toml`, `Cargo.lock`, `Dockerfile`, `.github/workflows/{rust,release}.yml`, `benches/{warm_metadata,artifact_throughput}.rs`, `src/lib.rs`, `src/policy/{mod.rs,blocklist.rs}`, `src/pypi/{mod.rs,name.rs}`, `src/npm/mod.rs`, `src/artifacts/{mod.rs,download.rs}`, `src/osv/mod.rs`.
New: `crates/probation-policy/{Cargo.toml,src/lib.rs,src/edit.rs,src/names.rs}`, `src/policy/effective.rs`.
Outside the slice file list: `.smtc/analyzers/outbound-timeout-guard.yaml`, header only. See Security coverage.

## Direct witness (main-agent rerun on the final tree)
| Command | Observed |
|---|---|
| `cargo test -p probation-policy` | `test result: ok. 8 passed` (approved text: 7; see Deviations) |
| `cargo test -p probation-policy --doc` | `test result: ok. 1 passed` (compile_fail, E0624) |
| `cargo test --lib policy::effective::tests` | `test result: ok. 4 passed; … 145 filtered out` |
| `cargo test --workspace` | 33 `test result: ok`, 0 FAILED |
| `cargo bench --bench warm_metadata --bench artifact_throughput -- --assert` | exit 0, 9/9 `SPEC §12 … PASS`. Final-tree run (sf-verification): warm metadata p95 0.115 ms, warm denial p95 1.411 ms ≤ 2 ms, 115167 responses/s, artifact ttfb +0.112–0.166 ms, throughput 111–112 %. Earlier pre-rework run: denial p95 1.886 ms |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| `cargo fmt --all --check` | clean |
| `docker build .` | exit 0 on the final tree (image 000862e2ecad) |
| `cargo package --workspace --locked --allow-dirty` | `probation-policy` and `probation` only; no `probation-server` (`--allow-dirty` because nothing is committed) |
| `cargo llvm-cov --locked --summary-only --fail-under-lines 98` | exit 0, 98.46 % lines |
| `router molecule-check` | PASS |
| `router molecule-verify --slice 1` | `decide-exceptions-first` PASS, `check-edit-loosening-search-first` PASS, all 4 controls detected; exit 1 only because 10 obligations for slices 2–4 are SOURCE_PENDING |

Rework touched `crates/probation-policy/src/{lib.rs,edit.rs}` and `src/policy/effective.rs` (`decide`/`attribute`, on the request path). The benches and `docker build` were rerun on the final tree.
Warm denial p95 is close to its limit. The implementer's alternating base-commit reruns on this host measured slice 1.20/1.23 ms against base 1.43/1.42 ms, so there is no regression, but `--assert` may be flaky on a busy machine.

## TDD
`evidence/tdd-slice-1.md`: 12 initial `tdd:` lines, 14 under `## Rework`, 5 under `## Rework 2`.

## Contract and flow changes
None to the approved model. `molecule-flow.json` and `molecule-contracts.json` are unchanged.

## Security coverage
- Unchanged baseline: client-data-reaches-delivery-sink PASS, consumer-identity-extension-read PASS (1 finding, its documented pass), enqueue-timeout-guard PASS.
- outbound-timeout-guard: the first run was UNKNOWN. The finding count no longer matched the header (10 against 7) because `src/osv/batcher.rs` changed in 01b94d7 (2026-10-19), before this slice.
  - sf-spec-authoring: KEEP. It changed the header only (count, line numbers, trace shape) and left the matching rules byte-identical.
  - sf-verify-cert: PASS. The unsafe control still fires.
- Slice obligations: managed-decide-exceptions-first PASS and managed-check-edit-loosening-first PASS. Every control fires with `caller_function` = `decide` / `check_edit`.
- No new findings or gaps.

## Reviews
| Review | Verdict | Resolution |
|---|---|---|
| code-review | SHIP, 3 minor | Attribution tests, `check_edit` branch tests and a place-kind guard were added in rework. |
| adversarial | FIX | D1 duplicate-target re-save (C47), D2 `would_block` only on Allow (C81), D3 C9 chain shapes: fixed in rework. |
| code-review (after fix) | SHIP | All 7 resolved; 9 mutants killed. |
| adversarial (after fix) | FIX | F1: [Platform, Org, User] rejected (C10). G1: whole→exact narrowing refused. G3: generators missed Personal and [P,O,U]. Fixed in rework 2. |
| adversarial (after rework 2) | PASS | 40,000-case `rules_for` oracle: 0 loosenings, 0 over-refusals. |
| qa (sf-verification) | VERIFIED | Every witness was rerun independently, including the benches. C12, C107 and C110 are unchanged. Every production decision goes through `policy::effective::decide`. All 8 deviations keep the approved guarantees. |

## Deviations from the design text (guarantees kept)
1. `CandidateRules::layer_behind` lives in the firewall as the private `attribute()` in `src/policy/effective.rs`. The shared crate cannot name the firewall's `Decision` and `Candidate`.
2. C47 kept-but-not-in-effect values stay in `EffectivePolicy.chain`, and the `rules_for` merge drops them. Under an exception lift this is stricter than excluding them in `resolve`. Because they can change decisions, the fingerprint includes them (C103). Pinned by C6 in `tdd-slice-1.md`.
3. Merge defaults: with no unlifted value, freeze is 0 and OSV is Off. Standalone always sets both values.
4. `OsvClient` has no mode. `osv::evaluate` reads the policy's OSV setting, and Enforce/Diagnostic/Off compile to On/LogOnly/Off.
5. `decide` has `#[rustfmt::skip]` so the SMTC control lines stay verbatim.
6. `Block` has no `reason` field (C119).
7. The place-kind check is the first statement of `check_edit`, not inside `find_invalid`, because the `find_loosening` call line is a fixed control string.
8. `check_edit` accepts narrowing a stored whole-package exception to an exact version for freeze and OSV lifts, but not for the block lift: under C106 an exact version also lifts file blocks. This follows design §check_edit "adds or widens". Design line 674's "C106 is a `decide` rule" does not mention this edit-side consequence.
9. The `probation-policy` witness count is 8, not 7. The extra test is the D3 `#[should_panic]` C9 test; every other review assertion went into existing tests.
10. P-check-edit-agrees-with-resolve runs 2048 cases.

## Clarifications
| ID | Status | Note |
|---|---|---|
| S1-1 | planned: T-edit-parent-chain in slice 4 (03 § Test plan, 2026-10-22) | `check_edit` does not check that `parent` is the chain above `target`. The server must pass [Platform] for Personal and [Platform, Org] for an ungrouped User. A slice-4 test should pin this. |
| S1-2 | resolved 2026-10-22 (user, see evidence/slice-2.md S2-1) | In managed mode a platform layer that leaves OSV `None` fails open to Off (merge default). The server or platform seed should always set platform freeze and OSV, or record this default. |
| S1-3 | accepted | The `check_edit` tests do not pin PyPI/npm spelling variants. Mutants on `same_package` and `same_version` survive the crate suite but could only cause over-refusal, never loosening. Add spelling rows when slice 4 exercises `save_edit`. |
| S1-4 | accepted | Fingerprints differ for "2.0" and "2.0.0", which only splits the render cache. Control characters in versions are accepted, matching today's blocklist-file validation. |
| S1-5 | resolved 2026-10-22: C124 (user chose 24 h; label "not in effect while a stricter rule above applies") | Deviation 2 is visible in the product. A stored looser value that the portal labels "not in effect" (C47) still applies, as a stricter value, to a package whose upper rules an exception lifts (C6 test: Group 1-day freeze). Record the deviation in 03-program-design.md (`EffectivePolicy.chain`, `CandidateRules`) and settle the label wording before slice 6 (T-portal-not-in-effect). |
| S1-6 | planned: `Block.reason` in slice 7, fingerprint unchanged without reasons (03 § Test plan C80/C86, 2026-10-22) | `Block` has no `reason`, but today's blocklist records carry one. A lossless T-blocklist-roundtrip (C86/C119) needs a field on the shared `Block`, which changes the fingerprint encoding. Decide before slice 7. |
| S1-7 | fixed in 03 on 2026-10-22 (design reopen) | Design-text drift to correct when design is next opened: check_edit's declaration says `find_loosening` runs first, but the place-kind guard (deviation 7) now runs first; the `EffectivePolicy.chain` comment says C47 values are excluded; `CandidateRules::layer_behind` is described as public API; line 674 says C106 is a `decide` rule only, but it also limits `check_edit` (deviation 8). |
| S1-8 | optional | README.md:114-115 `cargo test` and `cargo clippy` don't cover the new crate. Adding `--workspace` would, as CI now does. |
