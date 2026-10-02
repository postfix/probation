# Slice 3 evidence — e2e OSV-only refusal

## Diff summary
Test-only. No production code changed.
- `tests/e2e_npm.rs`: two new `#[tokio::test]` cases (`npm_install_is_refused_on_an_osv_malicious_package_match`,
  `npm_install_succeeds_when_osv_does_not_flag_the_resolved_version`), an `osv_flags` wiremock helper,
  and `Harness::start_for_with_osv`/`start_full`.
- `tests/common/mod.rs`: uses the existing `TestServer::start_with_upstream_and_osv` seam (Slice 1); no changes
  attributable to this slice.

Post-review cleanup: removed two no-op `drop(osv_server)` calls (renamed the bindings to `_osv_server` to keep
the mock server alive for the test's duration without an unused-variable warning), then ran `cargo fmt`.

## Witness
```
cargo test --test e2e_npm -- --ignored osv
```
```
running 2 tests
test npm_install_is_refused_on_an_osv_malicious_package_match ... ok
test npm_install_succeeds_when_osv_does_not_flag_the_resolved_version ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out
```
Re-run independently after the post-review cleanup with the same result.

## Reviews
- code-review: SHIP — no defects; two simplification notes (no-op `drop`, `cargo fmt`) applied.
- qa (sf-verification): VERIFIED — both tests independently read and the witness independently re-run,
  matching the claimed result verbatim; confirmed test-only scope (no production files touched).

## Notes
Slices 1-2 stand unchanged. No `02-architecture.md`/`03-program-design.md` change. Red Team not triggered
(test-only addition, no new architecture or trust boundary).
