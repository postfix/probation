# Historical certificate-based delivery before local-client re-steer

Saved 2026-11-02 before reopening the completed plan. Earlier approvals and proofs apply to the delivered certificate-based source, not the new API-key policy/local-client design. Existing evidence/slice-1.md through slice-5.md remain unchanged.

# Status: Transparent package publishing

- Gate 1 — Product: APPROVED 2026-10-27
- Gate 2 — Architecture: APPROVED 2026-10-29
- Gate 3 — Program Design: APPROVED 2026-10-29
- Gate 4 — Slice plan: APPROVED 2026-10-29

## Slices

- [x] Slice 1 — Probation certificate setup and npm install
  - proof: test -f tests/e2e/scenarios/publishing-certificate-npm.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-certificate-npm -> 1 passed, 0 failed, 0 not run; cargo check PASS; model PASS; seven due source controls PASS; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 2 — enterprise certificates and registry isolation
  - proof: test -f tests/e2e/scenarios/publishing-enterprise-registry.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-enterprise-registry -> 1 passed, 0 failed, 0 not run; cargo check PASS; model PASS; nine due source controls PASS; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 3 — complete guarded npm reads
  - proof: test -f tests/e2e/scenarios/publishing-npm-read.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read -> 1 passed, 0 failed, 0 not run; cargo check PASS; model PASS; 13 due source controls PASS; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
  - rework: token packument artifact links and reads need fresh source and runtime proof after the design revision; historical proof remains in evidence/slice-3.md.
- [x] Slice 4 — npm publishing and administration
  - proof: TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-actions -> 1 passed, 0 failed, 0 not run; final source model and 21 source controls PASS; full Rust workspace 760 passed, 0 failed, 21 ignored; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
- [x] Slice 5 — Python and uv workflows
  - proof: test -f tests/e2e/scenarios/publishing-full-matrix.mjs && node tests/e2e/harness/run.mjs --only E2E-publishing-full-matrix -> 19/19 runners passed; 123/123 row-mode cases observed; JUnit 1 passed, 0 failed, 0 skipped; focused private-CIDR withdrawal regression passed; cargo check PASS; finite model PASS; 21/21 source controls PASS; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
