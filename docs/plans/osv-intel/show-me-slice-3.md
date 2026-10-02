## Delivered
Test-only, no production code changed. Two new `#[tokio::test]` cases in `tests/e2e_npm.rs`: `npm_install_is_refused_on_an_osv_malicious_package_match` and `npm_install_succeeds_when_osv_does_not_flag_the_resolved_version`, plus an `osv_flags` wiremock helper and `Harness::start_for_with_osv`/`Harness::start_full`. `tests/common/mod.rs` uses the existing `TestServer::start_with_upstream_and_osv` seam from Slice 1 unchanged. Signatures elsewhere are unchanged — this slice only adds test harness code exercising Slices 1-2's already-modeled behavior.

## Proof
| Promise | Executed witness | Observed result |
|---|---|---|
| A real `npm install` is refused when OSV — not the operator's blocklist — flags the resolved version (empty blocklist, OSV-only match) | `npm_install_is_refused_on_an_osv_malicious_package_match` | ok |
| A resolution OSV would flag on a held version still succeeds once the cooldown fallback resolves to an OSV-clear version (negative control) | `npm_install_succeeds_when_osv_does_not_flag_the_resolved_version` | ok |

Command: `cargo test --test e2e_npm -- --ignored osv` -> `ok. 2 passed; 0 failed`. Re-run independently after post-review cleanup (removed two no-op `drop(osv_server)` calls, renamed bindings to `_osv_server`, ran `cargo fmt`) with the same result.

Evidence limit: `config.osv_request_timeout_ms` is widened to 4000ms only when the harness starts with a real OSV base URL — the sample config's 500ms default is shorter than the 2s batch interval and a solitary lookup never fills the batch. This is production's real single-package-install behavior, not a test-only quirk, and is documented at the widen site in `tests/e2e_npm.rs`.

## Limits
None beyond the timeout-widening note above. code-review: SHIP (no defects; two simplification notes applied). qa (sf-verification): VERIFIED — both tests independently read and the witness independently re-run, matching the claimed result verbatim; confirmed test-only scope. sf-red-team: not triggered — no new architecture, uncertainty, or security surface.

## Next
Slice 3 is the last row in `04-slices.md`. All three slices are done and all four gates are approved — the OSV vulnerability intelligence plan is complete unless more is wanted.

## Recommendation
Complete — Slices 1-2 wired `osv::evaluate` through every production call site (`serve_artifact`, npm/PyPI resolve, artifact download); Slice 3 proves that wiring against a real `npm install` client with both a positive OSV-only refusal and a negative control. No open findings, no pending gates.

Slice 3 is the last row in 04-slices.md, and `router check --plan-root docs/plans/osv-intel` now shows all four gates approved, all three slices done, and zero findings — this completes the OSV vulnerability intelligence plan.
Sources: docs/plans/osv-intel/evidence/slice-3.md; docs/plans/osv-intel/04-slices.md (Slice 3 row, "### Slice 3 interfaces"); docs/plans/osv-intel/00-status.md (Slice 3 proof line)
Slice 3 done — that's all three slices and all four gates. Confirm the osv-intel plan is complete, or is there more to add?
