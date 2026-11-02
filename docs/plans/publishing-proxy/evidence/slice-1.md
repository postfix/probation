# Slice 1 evidence — Probation certificate setup and npm install

## Delivered caller outcome

A signed-in member receives an own-account certificate bundle and installs an allowed npm package through the certificate firewall. The selected E2E also refuses a missing, foreign, revoked or disabled certificate, a removed member, wrong routes, management outage and changed group policy before returning a held response. Self-service-off stops new bundles while existing certificate reads continue. The single configured registry remains the approved temporary limit for Slice 1.

## Direct checks

| Check | Observed result | Limit |
|---|---|---|
| `test -f tests/e2e/scenarios/publishing-certificate-npm.mjs && node tests/e2e/harness/run.mjs --only E2E-publishing-certificate-npm` | Final selected run: 1 passed, 0 failed, 0 not run; exit 0. | Pinned npm, fake SSO and issuer, local TLS gateway and fake origin. |
| `cargo check --workspace` | Passed after the request-path fix. | Type check. |
| `cargo test --workspace --offline --quiet` | Passed after the request-path fix; ordinary ignored tests stayed ignored. | Includes repository tests; timing-only ignored tests are outside this witness. |
| `cargo fmt --all -- --check`; `node --check` on changed E2E files; `git diff --check` | Passed. | Formatting and syntax only. |
| `router molecule-check --plan-root docs/plans/publishing-proxy` | PASS for the twelve declared finite flows. | Model contracts and assumptions are premises, not source proof. |
| `router molecule-verify --plan-root docs/plans/publishing-proxy --slice 1` | Seven due Slice 1 source checks and unsafe controls PASS with Structural fidelity; five absent sources assigned to Slices 2–4 PENDING. Evidence: `/home/john/.local/state/software-factory/contract-evidence/run-Rf9eId`. | Exact member/registry SQL values and runtime response behavior need independent review and E2E. |

The original request-path code charged two active-request permits and two rate units for a read. A new E2E check failed with one permit before the fix and passed afterward. The revised path keeps one permit and rate charge while rechecking live certificate, network lock and policy before bytes. A security review found that certificate network checks used the socket peer behind a trusted proxy; the fix applies the existing trusted-proxy client resolution while keeping TLS identity tied to the socket handshake. The E2E checks trusted forwarded client refusal and rejects untrusted spoofed forwarding.

The [TDD record](tdd-slice-1.md) includes the original pre-implementation 404, one-permit red/green, the temporary final-recheck bypass that returned an unsafe HTTP 200 during a held read, and the unrelated-503 control rejected by the exact `POLICY_UNAVAILABLE` assertion. The final E2E pass followed restoration of production source byte for byte.

## Reviews

| Review | Verdict | Deciding result |
|---|---|---|
| Code | SHIP | Double-charge defect closed; final test requires exact policy error, and bounded fake hold releases on cleanup. |
| Security | CLEAR for implemented Slice 1 path | Portal SSO/CSRF and private-key handling, TLS peer, trusted client address, current member/registry query and read recheck inspected; no finding. The generic SMTC guard analyzer is unsupported on this Rust workspace and was not used as clean evidence. |
| Adversarial | PASS | In-flight policy negative control and final E2E close the stale-success gap. Parseable invalid-leaf variants remain proposed tests; enterprise status belongs to Slice 2. |
| Implementation verification | VERIFIED | Independent source and E2E reruns confirmed own-account bundle, exact member/registry SQL predicates, one permit/rate unit, trusted client address, held-response refusal and seven due source controls. |

## Temporary material

The project scan found only the committed TLS fixture under `tests/fixtures/tls/` and disposable E2E keys/tokens under `target/e2e/`. After final verification, `target/e2e/` was removed. A repeat key/certificate/config path scan found only the committed TLS fixture. No generated key, bundle or npm config appears as a worktree change.

## Selected URL namespace revalidation (2026-10-27)

The selected npm base, setup bundle and rendered artifact links now use `/registry/npm/<id>/`. Selected read, ping, search and audit route registrations use that base; legacy `/npm/...` no longer treats a numeric first segment as a registry ID. This revalidation changes the Slice 1 route witness only; audit response filtering and actions remain for later slices.

| Check | Observed result | Evidence scope |
|---|---|---|
| `test -f tests/e2e/scenarios/publishing-certificate-npm.mjs && node tests/e2e/harness/run.mjs --only E2E-publishing-certificate-npm` | RED on unchanged product source at `setup bundle selects the distinct npm registry namespace`: 0 passed, 1 failed, 0 not run, exit 1. GREEN after change: 1 passed, 0 failed, 0 not run, exit 0. | Signed-in bundle and real npm install, `/npm/123/1.0.0`, its legacy tarball, selected `/registry/npm/<id>/123`, and the existing certificate, group, outage, and refusal controls. [TDD record](tdd-slice-1.md). |
| `TMPDIR="$PWD/.scratch/tmp" cargo check --workspace` | PASS, exit 0. | Workspace type check. |
| `cargo test --workspace --offline --quiet` | Sandbox attempt stopped with local socket bind `PermissionDenied` (154 passed, 1 ignored before failure). Elevated attempt passed earlier groups, then 34 `probation-server --test accounts` tests failed at `tests/common/mod.rs:108` with Postgres `PoolTimedOut`; exit 101. | Full Rust suite remains incomplete because its test Postgres was unavailable; no route assertion failure was reported. |
| `node --check tests/e2e/scenarios/publishing-certificate-npm.mjs`; `git diff --check` on touched tracked source | PASS. | Syntax and whitespace only. `cargo fmt --all -- --check` fails across pre-existing concurrent unformatted source; no broad formatting rewrite was made. |
| Pinned `router molecule-check --plan-root docs/plans/publishing-proxy` | PASS, exit 0, no findings. | Declared finite model only. |
| Pinned `router molecule-verify --plan-root docs/plans/publishing-proxy --slice 1` | Overall PENDING, exit 1: all seven due Slice 1 structural obligations PASS; three future-source checks PENDING (one Slice 3, two Slice 4). Raw evidence: `/home/john/.local/state/software-factory/contract-evidence/run-6mnD3o`. | Structural source and mutation controls; exact URL values and runtime behavior are established by E2E, not by this check. |

The first E2E attempt required Podman runtime access outside the sandbox; after escalation it reached the behavioral red and later green. The first source-verify attempt could not write the tool's evidence directory outside the workspace; the elevated rerun produced the result above. The broader npm-read E2E still has old selected URL literals and belongs to Slice 3 revalidation.

### Scoped selected version review fix

Code and adversarial review identified a selected scoped-version route error: Axum decoded `@e2e%2Fscoped` to `@e2e/scoped`, then the version handler appended `/1.0.0` as though the path named an unencoded scope/package pair. The focused E2E red returned HTTP 400 `INVALID_INPUT` on `GET /registry/npm/<id>/@e2e%2Fscoped/1.0.0`. The handler now treats a leading `@` as an unencoded scope only when that decoded segment contains no slash, matching the legacy parser rule.

After the fix, the focused E2E passed 1/1 with zero failures and zero not run. It checked the exact scoped name/version, a selected-registry artifact link and readable tarball, and a group-blocked scoped version returning 403. `cargo check --workspace`, E2E JavaScript syntax, and scoped `git diff --check` passed. The pinned `molecule-check` passed. The pinned `molecule-verify --slice 1` returned overall PENDING because the same three future Slice 3/4 sources remain absent; all seven due Slice 1 structural checks passed with raw evidence at `/home/john/.local/state/software-factory/contract-evidence/run-IjXC7d`. These checks establish declared model consistency and structural source order; the E2E establishes the URL/value behavior. The full Rust suite was not rerun after this one-condition fix because the prior run in this revalidation could not reach a complete result without test Postgres.

### Final certificate-route matrix and reviews

The selected package, encoded scoped version, and selected artifact routes each returned HTTP 401 with a missing, foreign, or revoked certificate. Each three-request group left the fake upstream request count unchanged. The final focused E2E command, `test -f tests/e2e/scenarios/publishing-certificate-npm.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-certificate-npm`, passed independently twice after that matrix was added: 1 passed, 0 failed, 0 not run in each run. The second run was made by implementation QA. JavaScript syntax and scoped diff checks passed. The matrix was a test-only addition with no behavioral red; product source and the TDD record did not change after the scoped-version fix.

| Review | Final verdict | Deciding result |
|---|---|---|
| Code | SHIP | Fresh review checked the scoped-version fix, selected URL propagation, and legacy numeric paths; no remaining defect. |
| Security | CLEAR for the Slice 1 certificate-route gap | Fresh bounded review inspected admission and the nine-request refusal/zero-upstream matrix. The broad SMTC missing-guards analysis remains Stub/Lossy and supplies no clean proof. |
| Adversarial | PASS | Fresh review confirmed the encoded scoped-version defect was closed and found no further selected/legacy URL boundary defect. |
| Implementation verification | VERIFIED | Independent E2E, `cargo check --workspace`, model check, seven due source obligations and mutation controls, URL wiring, and evidence correspondence passed. Raw source evidence: `/home/john/.local/state/software-factory/contract-evidence/run-UUEjEX`. |

The final source verifier remains overall PENDING solely for the three absent Slice 3/4 sources. SMTC compile verification was incomplete (`lsp_not_quiescent`); `cargo check --workspace` passed. The broad Rust suite remains incomplete because its test Postgres timed out during the earlier revalidation attempt.
