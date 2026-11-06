# Active Slice 4 — PyPI publishing and uv workflows

Status: implemented and independently VERIFIED; completion recorded with `router complete-slice` (see the Factory status). Presentation and the user's continuation decision remain. Do not start Slice 5 before that decision.

Historical certificate-based Slice 4 evidence is preserved byte-for-byte in [slice-4-certificate-history.md](slice-4-certificate-history.md). Those approvals do not certify this local-service slice. Detailed engineering record: [slice-4-engineering.md](slice-4-engineering.md); TDD record: [tdd-slice-4.md](tdd-slice-4.md).

## Outcome

PyPI uploads (Twine Basic and Bearer) go through the local service at exactly `POST /registry/pypi/<id>/` (no query), are forwarded with the caller's package-manager credential only to the exact selected registry, and the upstream status and body stay authoritative. The firewall's policy API key never reaches the registry. Unknown IDs, unrelated Python POST paths, query-bearing uploads and non-POST methods are refused locally with zero upstream I/O. A managed-policy outage or revoked service key refuses the upload with no upstream write. Declared and chunked B+1 uploads are refused with 413 before upstream I/O. Uploads over 1 MiB get the 15-minute lifetime instead of the 30-second metadata deadline.

Changed paths: `src/http/service_registry.rs`, `src/managed/mod.rs` (atomic generation check and rate charge in `admit_certificate`, at most three asks), `src/upstream/reqwest_transport.rs` (`UPLOAD_BODY_BYTES`, `selected_within`), `tests/pypi_service_upload.rs`, `tests/e2e/scenarios/publishing-python-service.mjs`, `publishing-full-matrix.mjs`, `publishing-npm-read.mjs` (`historicalNpmRead`), `tests/e2e/fixtures/fakes/pypi.mjs`, `main.mjs`, and the evidence files.

## Checks (final tree, all exit 0)

- Direct witness `node tests/e2e/harness/run.mjs --only E2E-publishing-full-matrix`: PASS, 1 passed / 0 failed / 0 not run, 2,846.9 s, `.scratch/slice4/matrix4.log` (SHA-256 `9769cd16289c11e4da74ae7f559736d8bb35424d17a18c67d5af8bfe17a52fa4`). Runs against fakes, not real PyPI.
- `cargo test --offline --workspace -j 8`: 792 passed / 0 failed / 22 ignored, `cargo-test-workspace-final2.log`.
- `router molecule-check`: PASS, zero findings. `router molecule-verify --slice 4`: PASS, 9/9 checks with a control each (`molecule-verify-final3.log`); scope is encoded call order only.
- `E2E-publishing-python-service` alone: PASS (6 uploads, 64.8 s, `service-green2.log`), including the 2 MiB upload to a registry that answers after 33 s.
- `tdd:` lines (RED then GREEN) for the classifier (405→200), certificate admission race (503 at identities 1329/815/59, plus unit REDs for the retry), matrix accounting (N07/X05/X07) and the large-upload deadline (504→200) are in `tdd-slice-4.md`.

## Reviews

- Code review: SHIP (six admission mutants and classifier mutants all killed by tests).
- Security: CLEAR (stale-policy admission closed, no double charge, credentials confined to the selected origin, policy key never at the registry).
- Adversarial: one major defect (30 s total deadline on large uploads) found, fixed and covered by an e2e probe; other findings are the limits below.
- Implementation verification (`sf-verification`): VERIFIED, no blocking findings.
- Contract/flow and security-coverage changes: none to `molecule-flow.json`/`molecule-contracts.json` or the specs; no approved assertion weakened.

## Accepted limits (user decision 2026-11-04: record as open, no code change in Slice 4)

1. Upload size/time: spool cap is 2×max_artifact_bytes + max_metadata_bytes before the upstream credential check, with no read-idle or total timeout on the client leg and no write-idle timer upstream (a stalled client or upstream holds a permit; upstream sends are bounded by 15 minutes). Severity: major availability, admitted peers only.
2. Post-write 503: in service mode a policy snapshot change (any revision bump) after the upstream write is committed returns 503 "no valid blocklist is loaded"; a retry hits upstream's "file exists". The pre-send recheck remains fail-closed. Severity: minor.
3. One URL per registry: uploads POST to the registry's configured URL; a registry whose upload endpoint differs from its Simple URL (pypi.org → upload.pypi.org/legacy/) is unsupported.
4. Advisory: reqwest `Authorization` not marked sensitive; fake PyPI accepts `Bearer e2e-owner` and labels only Bearer `prb_*` as `policy-key`; case-sensitive auth scheme parsing; unthrottled `tracing::warn!` during a management outage; unknown-key lookups bump the publication generation and can void certificate admissions on a firewall serving both traffic kinds (fail-closed 503); `admit_certificate` ignores `self.retired`; 401 vs 404 registry-ID enumeration for local peers; no in-repo https unit test of the real `send_action`; `python-service` has no matrix witness rows (only the zero-assertion guard).
