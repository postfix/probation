# Slice 3 TDD evidence

## Review bounds: audit comparison work

tdd: selected audit rejects over-budget advisory-version work — red: `E2E FAIL E2E-publishing-npm-read: Error: 8,220 advisory-version comparisons refuse within the audit deadline` (pre-fix selected scenario, 52.4 s) — green: selected pinned npm-read E2E passed (1 passed, 0 failed, 0 not run; 219.7 s)

The red used the pinned npm 11.21.1 selected-registry scenario with isolated Podman project `probation-s3-bounds-red`, disk-backed `.scratch/s3-bounds-red`, and a same-package advisory response with 137 entries against 60 visible versions. The new 8,192-comparison limit is checked before the synchronous range-matching loop; `cargo check --quiet` passed after this change.

## Review bounds: rebuilt search output

tdd: selected search refuses a rebuilt response larger than M — red: `E2E FAIL E2E-publishing-npm-read: Error: search rebuilt from bounded packuments refuses a response larger than M` (partial-fix selected scenario, 56.3 s) — green: selected pinned npm-read E2E passed (1 passed, 0 failed, 0 not run; 219.7 s)

The second red used isolated Podman project `probation-s3-search-red`, disk-backed `.scratch/s3-search-red`, 8 allowed search hits with 700-byte descriptions and M=4096. Each upstream packument fit M, but their combined response exceeded M. The route now checks serialized response length before sending. `cargo check --quiet` passed after both source changes; `rustfmt --edition 2024` touched only the two owned Rust files. The workspace-wide `cargo fmt --check` found extensive pre-existing formatting differences outside this assignment and was not applied globally.

The final selected npm-read E2E green was run by the coordinator against a fresh product image and pinned npm 11.21.1 client. It passed 1/1 in 219.7 seconds. A local fake measurement gave 1,427 bytes for one bounded-search packument and 6,511 bytes for the eight-hit rebuilt search response, showing that the M=4096 assertion exercises the final response bound.

Seam: certificate-protected selected npm registry URL. The E2E image for the red run was built from pre-Slice-3 product source; the command began before product edits and the failing handler returned the old group-filtered result.

## Canonical developer-token packument

Red command (isolated Podman project):

```sh
env TMPDIR="$PWD/.scratch/e2e-npm-read-red-s3/tmp" CONTAINERS_CONF="$PWD/.scratch/containers-slirp.conf" CONTAINERS_STORAGE_CONF="$PWD/.scratch/podman-slice2-storage.conf" E2E_COMPOSE_CMD=podman-compose E2E_PROJECT=probation-npm-read-red-s3 E2E_NET=11.229.0 E2E_BRIDGE_PORT=18422 E2E_WORK="$PWD/.scratch/e2e-npm-read-red-s3" E2E_OUT="$PWD/.scratch/e2e-npm-read-red-s3/out" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read
```

Result: exit 1; `publishing-npm-read.mjs:42` accepted token saw 403 `BLOCKED` for a group-hidden packument, expected 200. Stack started and scenario ran. Project teardown left no containers for `probation-npm-read-red-s3`.

tdd: accepted developer token reads a hidden canonical packument — red: accepted token got 403 BLOCKED, expected 200 at publishing-npm-read.mjs:42 — green: final npm 11.21.1 selected E2E, 1 passed, 0 failed

## Named reads and client isolation

The expanded scenario ran with `--skip-build` against the prior firewall image `810958b226a4` (created 13:40:13 UTC before the named-route edits). It passed token A/none/denied sequential and concurrent checks, a second certificate, restart isolation, and hidden artifact refusal, then failed at `publishing-npm-read.mjs:87`: `named search filters group-hidden package even with no token`. The isolated project `probation-npm-read-expanded-red-s3` was torn down.

tdd: named search filters hidden packages on the selected URL — red: named search filters group-hidden package even with no token at publishing-npm-read.mjs:87 — green: final npm 11.21.1 selected E2E, 1 passed, 0 failed

Green3 used a fresh firewall image and passed the selected scenario in 36.6 seconds. It covered token A/none/denied, two certificate clients sequentially and concurrently, restart, hidden artifact refusal, selected npm install/view/whoami/ping/audit, search, unknown route, and client-only network topology. Subsequent review found the shared `client-npm` fixture was pinned to npm 12.2.1, while this plan requires 11.21.1. Green3 is useful behavioral diagnosis but is **not acceptance evidence for pinned npm 11.21.1**. The fixture now pins 11.21.1 and the scenario asserts that version before setup.

## Bounds and enterprise extensions

The bound checks were added after the original red/green cycles; they are direct acceptance controls, not a separately observed red cycle. Diag3 against the fresh green4 product image observed M+1 metadata → 502, A+1 artifact → 502, six-hop redirect → 502, and a 64 KiB+1 request header → 431 with no upstream lookup. A prior bound run observed a 30-second stalled upstream response → 504 and then ping → 200 with the single request permit released. Its next fake-control log request hit a stale harness keep-alive tunnel, so the stall assertion moved to the scenario end. Diag3 proceeded through selected-registry collision, remove/re-add, management outage and enterprise certificate admission, then exposed missing npm client certificate settings for the replacement registry URL. Diag4 ran `npm audit --json --registry=https://fw1.e2e.test/npm/2/` with npm 12.2.1 after the fake selected upstream returned bulk POST 404. It exited nonzero with `audit endpoint returned an error` and did not call quick. That is a version-mismatched diagnostic, not a claim about npm 11.21.1; the corrected fixture must be rerun before resolving N04.

tdd: bounds and enterprise read controls — red: not separately observed; appended after the canonical and named-read red cycles — green: final npm 11.21.1 selected E2E, 1 passed, 0 failed

Green6 used a freshly built npm 11.21.1 client and passed the selected scenario in 114.8 seconds (1 passed, 0 failed). The scenario asserted the exact client version and covered both certificate providers, selected registry collision/remove/re-add, named reads, gzip audit forwarding, all four bounds, and isolation. Product/fixture edits landed while its build was starting, so this is a diagnostic pass with ambiguous image capture. The final exact witness will use a fresh build after the source and fixture freeze.

## Open N04 clarification

The npm 11.21.1 client image is `27e06833efccb2615915b55b22f7349bffb37257aa3b53d446a9a56abbe6a63f` (`npm --version` returned `11.21.1`). Its installed `/usr/local/lib/node_modules/npm/node_modules/@npmcli/arborist/lib/audit-report.js` `#getReport` posts `/-/npm/v1/security/advisories/bulk` with `gzip: true` at lines 334–340; lines 343–347 catch a failed bulk request, record `this.error`, and return `null`. That function contains no quick request. Read-only image inspection used `--network none` and is captured in `.scratch/e2e-npm-read-green7-s3/npm-audit-getreport.log`. In the npm 11.21.1 E2E, `npm audit --json --registry=https://fw1.e2e.test/npm/2/` against fake bulk POST 404 exited nonzero and reported 404. The final test compared fake quick-request counts before and after that CLI call and found no automatic quick request, then exercised quick POST directly. **Open:** approved N04 says “quick fallback after upstream unsupported bulk”; pinned npm does not issue that fallback automatically. The direct quick route is present, but this is not equivalent to automatic CLI fallback.

## Final selected witness

Exact guarded command: `test -f tests/e2e/scenarios/publishing-npm-read.mjs && env TMPDIR="$PWD/.scratch/e2e-npm-read-final-s3/tmp" CONTAINERS_CONF="$PWD/.scratch/containers-slirp.conf" CONTAINERS_STORAGE_CONF="$PWD/.scratch/podman-slice2-storage.conf" E2E_COMPOSE_CMD=podman-compose E2E_PROJECT=probation-npm-read-final-s3 E2E_NET=11.242.0 E2E_BRIDGE_PORT=18435 E2E_WORK="$PWD/.scratch/e2e-npm-read-final-s3" E2E_OUT="$PWD/.scratch/e2e-npm-read-final-s3/out" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read`.

Result: exit 0; fresh image; stack up in 9 seconds; selected scenario passed in 146.7 seconds, 1 passed, 0 failed. The scenario asserted npm 11.21.1, no quick request between the CLI's bulk-404 and the explicit quick POST, the M+1/A+1 fault log, exactly six artifact redirect responses, 431 before upstream, 30-second idle permit release, two certificate providers, selected-registry collision/remove/re-add, management outage, wrong organization, revocation and disable. Project-filtered Podman teardown left no containers. Log: `.scratch/e2e-npm-read-final-s3/run.log`; JUnit: `.scratch/e2e-npm-read-final-s3/out/junit.xml`.

## Authorization inventory regression

The first full `cargo test --workspace` reached `tests/authorization_read_once.rs` and failed three of its four tests. Its exact allowlist had no entries for five reviewed Slice 3 uses: token route classification, canonical token guard, named whoami token read, and the two selected-upstream token sends. The production paths were already guarded and exercised by the selected E2E; the test's old “exactly one read” comment no longer described the approved behavior. The allowlist now names these five exact file/function/call sites, and still rejects any extra occurrence or count change. The focused rerun passed 4/4; the next full run reached database-backed tests and failed because the prerequisite test Postgres was absent at `127.0.0.1:55432` (`PoolTimedOut`). A sandboxed focused rerun also failed at test setup when local loopback binds were denied (`Operation not permitted`); the same five binaries passed 111/111 with loopback permission. With isolated test Postgres accepting connections and loopback binds allowed, `cargo test --workspace` passed exit 0: 49 test-result groups, 748 passed, 0 failed. The isolated Postgres Compose project was torn down and its project-filtered container list was empty. Log: `.scratch/postgres-slice3-final/cargo-test-workspace.log`.

tdd: Authorization inventory covers approved token-read sites — red: `cargo test --workspace` failed 3/4 `authorization_read_once` tests with five unallowlisted Slice 3 sites — green: focused 4/4 passed; isolated-Postgres full workspace passed 748/748

## Prior-slice read-route regression

The selected Slice 1 E2E ran under the new npm 11.21.1 client-only topology and reached `publishing-certificate-npm.mjs:156`, where it expected selected `GET /-/ping` to be an unknown 4xx route. Slice 3 intentionally serves selected ping and returned 200. Its earlier setup/topology checks passed; the isolated project tore down. The stale assertion now probes `/-/unknown`, retaining the no-upstream assertion. A first rerun then reached a second old-topology assumption at line 219: its direct trusted-proxy probe expected `client-npm` on the backend subnet, but that client now has only an isolated `clients` address. The regression now temporarily connects the client to this project's backend only around the two direct trusted-proxy checks and disconnects it in `finally`. Its next selected run, `probation-slice1-network-final-s3`, reused the frozen product image and passed 1/1 in 68.5 seconds; isolated teardown left no project containers. Log: `.scratch/e2e-slice1-network-final-s3/run.log`.

tdd: prior Slice 1 unknown route remains refused — red: selected Slice 1 E2E got 200 for now-supported `/-/ping` at line 156, expected 4xx — green: selected Slice 1 E2E passed 1/1 in 68.5 seconds with `/-/unknown` and temporary backend-network test connection

## Search deadline and vetted-result controls

With the product image built before the total-search-deadline fix (`--skip-build`), the expanded selected scenario reached two cold search packuments. Each fake response delayed 20 seconds; `max_active_requests` was one. The request completed without the required single 30-second deadline and failed `publishing-npm-read.mjs:413` (`cold search has one 30-second total deadline`) after 168.0 seconds of scenario time. The isolated `probation-npm-search-red-s3` project tore down with zero containers. A separate adversarial run against the unchanged pre-fix product image advertised allowed old version 1.0.0 while carrying `private-denied-latest` in description, maintainers and keywords from blocked latest version 2.0.0. It failed `publishing-npm-read.mjs:131` (`search rebuilds an allowed advertised hit without denied-version upstream fields`) after 37.4 seconds; isolated `probation-npm-search-taint-red-s3` tore down empty. Both are behavioral reds, not missing-file failures.

tdd: named search has one 30-second total deadline and releases its permit — red: old product image failed `cold search has one 30-second total deadline` after two delayed cold packuments — green: fresh-image selected E2E passed 1/1 in 176.4 seconds
tdd: named search returns only vetted fields from an allowed version — red: pre-fix selected E2E leaked `private-denied-latest` in allowed-advertised-version search hit at line 131 — green: fresh-image selected E2E passed 1/1 in 176.4 seconds

The search-fix green used the exact `test -f tests/e2e/scenarios/publishing-npm-read.mjs && env ... node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read` guard with isolated project `probation-npm-read-search-green-s3`, network `11.245.0.0/24`, bridge port `18438`, and disk-backed `.scratch/e2e-npm-read-search-green-s3`. Fresh product image and npm 11.21.1 client; stack up in 35 seconds; scenario exit 0, 1 passed/0 failed in 176.4 seconds. Project-filtered Podman teardown left no containers. Log: `.scratch/e2e-npm-read-search-green-s3/run.log`.

## Credential-bearing packument redirect

The approved program design requires a token-bearing packument redirect to refuse. The new selected E2E control installed a one-shot, same-origin 302 from the hidden canonical packument back to itself and compared upstream request logs. With `--skip-build` against the unchanged product image from the search-fix green, isolated project `probation-token-redirect-red-s3` failed at `publishing-npm-read.mjs:71` after 31.0 seconds: the fake saw a first GET returning 302 with `credential: developer-owner`, then a second GET returning 200 with the **same developer credential**. Its project-filtered teardown was empty. The source fix makes the credential-bearing token fetch use a no-redirect client; ordinary metadata and artifact redirect behavior is unchanged. The exact guarded selected command (`test -f tests/e2e/scenarios/publishing-npm-read.mjs && env ... node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read`) used fresh images, isolated project `probation-token-redirect-green-s3`, subnet `11.249.0.0/24`, bridge port `18442`, disk-backed `.scratch/e2e-token-redirect-green-s3`, and passed 1/1 in 187.2 seconds. The direct control observed one credential-bearing 302 request and a client 502. Project-filtered teardown was empty. Log: `.scratch/e2e-token-redirect-green-s3/run.log`.

tdd: credential-bearing canonical packument redirect refuses without a second secret send — red: pre-fix same-origin 302 produced a second GET carrying developer-owner at publishing-npm-read.mjs:71 — green: fresh-image selected E2E passed 1/1 in 187.2 seconds with one credential-bearing 302 and client 502

## Open audit response policy gap

The existing audit fake returned only empty JSON, so it could not test the approved group-policy rule for audit. A new one-shot fake JSON fault supplied nonempty response shapes for both selected audit endpoints: bulk `{ packageName: [advisory] }` and quick `{ advisories: { id: { module_name, ... } }, metadata: ... }`. Each response included a group-hidden package advisory; a permitted package advisory carried the `private-denied-audit` sentinel in its title and the hidden package name in its URL. The added assertion requires both responses to retain the permitted advisory while excluding hidden metadata.

The red ran with `--skip-build` against the unchanged product image using disk-backed `.scratch/e2e-audit-policy-red-s3`, isolated project `probation-audit-policy-red-s3`, subnet `11.250.0.0/24` and bridge port `18443`. Both POSTs returned 200 with the original JSON unchanged. The scenario failed at `publishing-npm-read.mjs:195` after 51.2 seconds and printed both leaking response objects. Project-filtered Podman teardown was empty; log: `.scratch/e2e-audit-policy-red-s3/run.log`. No production fix is applied while the audit-result fidelity decision is open.

tdd: bulk and quick audit responses retain only current-group-visible facts — red: unchanged product echoed hidden package, sentinel title/URL and quick metadata in both 200 responses at publishing-npm-read.mjs:195 — green: pending product decision and implementation

## Approved reduced advisory implementation

The combined design approval accepted reduced safe advisories and proxy-only upstream behavior; it supersedes the preceding pending-decision line. The first post-approval red run used the migrated selected URL and unchanged product source. It failed at `publishing-npm-read.mjs:195`, printing the hidden package, sentinel title/URL and quick metadata in both responses. The focused green run against the new response filter passed `E2E-publishing-npm-read`: 1 passed, 0 failed, 0 not run in 186.6 seconds. The selected URL, npm 11 nonempty vulnerability, hidden version, malformed range, 1,025-name cap and bulk-404 controls were in this run. A later final run adds M+1 audit input/output and audit timeout controls.

tdd: reduced group-safe bulk and quick audit advisories — red: E2E FAIL E2E-publishing-npm-read: bulk and quick audit exclude group-hidden metadata; unchanged source returned hidden package, sentinel title/URL and quick metadata — green: `TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read` passed (1 passed, 0 failed, 0 not run; 186.6 s)

The final exact command included audit M+1 input and output refusals, a 30-second audit deadline with permit release, and the prior safe-advisory controls. Its first run confirmed firewall 504 after 30.003 seconds and a following 200 ping, then a fake-control socket hang-up occurred when the scenario installed its next fault. Moving that delay control to the end of the scenario avoided the fake-control race. The final exact command passed 1 passed, 0 failed, 0 not run in 207.0 seconds.

tdd: bounded audit input, output and total deadline — red: red not observed for these added bound controls; the preceding raw-response leak was the behavioral red for this audit route — green: `test -f tests/e2e/scenarios/publishing-npm-read.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read` passed (1 passed, 0 failed, 0 not run; 207.0 s)

## Quick mixed-report regression

Independent review identified a false-clean Quick shape: `{ "advisories": {}, "vulnerabilities": { "visible": { "severity": "high" } } }`. A focused E2E control was inserted before changing the parser. The unchanged parser returned 200, and the exact selected E2E failed at `publishing-npm-read.mjs:205`: `mixed quick advisory and nonempty vulnerability reports refuse instead of claiming clean` (0 passed, 1 failed, 0 not run; 52.0 seconds). A second control sends `vulnerabilities: []` alongside empty `advisories` and requires 502. The parser now checks the `vulnerabilities` value regardless of whether `advisories` is present, while preserving the existing empty-v2 Quick response.

tdd: mixed Quick audit reports refuse instead of returning false clean — red: E2E FAIL E2E-publishing-npm-read: mixed quick advisory and nonempty vulnerability reports refuse instead of claiming clean at publishing-npm-read.mjs:205 (unchanged parser returned 200; 0 passed, 1 failed, 0 not run) — green: `test -f tests/e2e/scenarios/publishing-npm-read.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read` passed (1 passed, 0 failed, 0 not run; 217.8 s)

tdd: selected audit POST admission matrix — red: red not observed; this test-only security control added no product change — green: `test -f tests/e2e/scenarios/publishing-npm-read.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read` passed (1 passed, 0 failed, 0 not run; 222.5 s)
