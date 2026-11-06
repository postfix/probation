# Slice 2 TDD — local-service npm reads

The previous certificate-era TDD evidence is preserved byte-for-byte from baseline HEAD in [tdd-slice-2-certificate-history.md](tdd-slice-2-certificate-history.md); it is not active-slice acceptance evidence.

Approved executable seam: `node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read`, the active Slice 2 row in `04-slices.md`. The historical certificate scenario was migrated to the managed local service. This is one vertical compatibility cycle through the public HTTP/npm interface.

RED observed against unchanged Slice 1 product: `E2E FAIL E2E-publishing-npm-read: Error: accepted token sees hidden packument without a write: 403 {"error":"BLOCKED","reason":"the package is blocked","request_id":"req-0000000000000003"}`. Exit 1; 0 passed, 1 failed, 0 notrun; JUnit 1 test, 1 failure, 0 skipped. Log `.scratch/slice-2/e2e-red.log`; JUnit `.scratch/publishing-slice2/e2e-red/out/junit.xml`.

The runner verified all 24 baseline product hashes and both exact Slice 1 image IDs before using `--skip-build` for RED. Added assertions after RED strengthen concurrent denied-token/restart coverage and verify a nonempty gzip audit body reaches upstream; they have no separate chronological RED claim.

GREEN: `.scratch/slice-2/e2e-green3.log`; exit 0, 1 passed, 0 failed, 0 notrun; JUnit 1 test, 0 failures, 0 skipped at `.scratch/publishing-slice2/e2e-green3/out/junit.xml`. Scenario runtime 105.3 seconds after 10-second setup. The product/fixture images were rebuilt for the first GREEN attempt, then reused only after exact current hash/image binding for fixture-only corrections. Failed intermediate attempts and their causal diagnostics are retained in `slice-2.md`.

tdd: E2E-publishing-npm-read — red: accepted token sees hidden packument without a write: 403 {"error":"BLOCKED","reason":"the package is blocked","request_id":"req-0000000000000003"} — green: node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read --skip-build passed
