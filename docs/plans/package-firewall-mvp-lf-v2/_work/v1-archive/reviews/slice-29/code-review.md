# Code review: slice 29 (native-driver seam + containerd explicit-server probe)
Verdict: UNKNOWN (no confirmed blocker; row-29 closure is incomplete for host reasons, plus 3 non-blocking test-strength gaps)
Scope: row 29 of 04-slices.md (+rule at line 50), 03-program-design.md T8/C1023/C1018, evidence/spike-native-cluster.md. Files: tests/e2e/harness/{client-host.mjs,client-host.test.mjs,service-setup.mjs,run.mjs,helpers.mjs}, tests/e2e/scenarios/{service-native-smoke,service-cluster-probe}.mjs, tests/e2e/README.md. Dirty tree, uncommitted (src/ and crates/ ignored).
Summary: the seam does what the rule asks (loud failure, no container fallback in the intended flows, enforced counts). The probe is meaningful (recording proxy, positive control). Weaknesses: F1 vacuous pass in the paused-service check, F2 weak native refusal assertion, F3 container fallback possible for scenarios that call h.client directly, F4 the row-24 flip is a prose comment only. No blockers.

## Findings
F1 — medium — test strength — paused-service "no fallback" assertion can pass vacuously
Location: tests/e2e/scenarios/service-cluster-probe.mjs:171
Requirement: spike finding 3 (no origin fallback with the service down).
Failure: `proxy.connects.slice(before).every(...)` is true for an empty slice. If ctr made zero connections while paused (a failure before dialing, or ctr killed by the 40 s timer at :168), the check passes without having observed anything.
Evidence: code read. The evidence file says the observed result was a TLS handshake timeout, so the real run likely had a connect, but the assertion does not require it.
Correction: also `h.expect(proxy.connects.length > before, ...)` and assert the stderr names a service connect/handshake error rather than a bare timeout kill.
Blocking: no.

F2 — low/medium — test strength — native refusal assertion accepts any failure
Location: tests/e2e/scenarios/service-native-smoke.mjs:41
Failure: `r.status !== 0` for the blocklisted npm install is also true for a proxy, TLS or CA failure, so the "refused by policy" claim is not distinguished from a broken lane. There is no native pip refusal case.
Correction: assert the service's refusal marker in `r.stderr` (E403/blocked, as service-policy.mjs does for containers) and that the package never reached the fake upstream.
Blocking: no.

F3 — low/medium — no-container-fallback guard is only partial
Location: tests/e2e/harness/helpers.mjs:159-168, run.mjs:117-124
Failure: only `h.npm` and `h.pip` switch under `--client-host native`. A scenario that declares `native` but also calls `h.client(...)` directly (or any other tool) silently runs it in a client container, while the run still counts as native. Today's only native scenario uses just npm and pip, so no current defect.
Also: `--client-host native` without `--only` selects every suite scenario. The scenarios without `meta.native` are only rejected after the whole stack has run (`checkNativeCounts`, run.mjs:149), not before. That is loud, but wasteful.
Correction: reject non-native scenarios at selection time (next to the needNative check, run.mjs:64) and make `h.client` throw when `h.clientHost.kind === "native"`.
Blocking: no. Becomes relevant at rows 25 and 27.

F4 — low — marking of the row-24 flip
Location: service-cluster-probe.mjs:58, 152, 161
The 404 and `exit !== 0` expectations are explained in prose ("this changes at row 24", "before row 24"). That is clear to a reader, but nothing greppable or failing reminds row 24 to flip them. Also :159 matches any HEAD/404 line in the whole container log (>=1), so an unrelated earlier request could satisfy it.
Correction: a single `// ROW24-FLIP:` tag on every row-28-only expectation, and name row 24's task to remove the tags. Also scope the log read to lines after the pull.
Blocking: no.

F5 — low — evidence/records
Counts are enforced in-process (run.mjs:149-153) but JUnit (run.mjs:156-168) does not carry client-use counts or a native flag. The rule at 04-slices.md:50 asks for "zero skipped required cases in JUnit/results". `skipped` is emitted correctly and the exit code is 1 on incomplete, so this is only a gap for external verification. Add `used` to the testcase properties.

## Requirement coverage
| Requirement | Implementation | Expected -> observed | Check and limits | Status |
|---|---|---|---|---|
| Absent native lane fails, never skips or uses containers (row 29 closure; 04:50) | client-host.mjs:19-26; run.mjs:37-40, 64-71 (before any stack) | exit 1 listing every reason; no stack work | `node tests/e2e/harness/client-host.test.mjs`: "all checks passed", run by me. It covers missing NATIVE_PLATFORM, pin failures, bad flag value, smoke without flag, and "no starting the stack". Real `checkClients` path covered only by the evidence-file run | MET |
| Native uses no container clients | helpers.mjs seam for npm/pip only | npm/pip native | F3: other client paths unguarded | MET for the smoke, partial as a general guarantee |
| Expected scenario/client counts, zero skipped | client-host.mjs:30-43; run.mjs:149-153 | fails if missing scenario, unused client, undeclared scenario | unit-tested with synthetic results (:23-28). `used` counts calls, not successes (scenario errors fail separately). Not in JUnit (F5) | MET (in-process) |
| Seam added at the existing client seam, not a new harness | helpers.mjs, run.mjs | one seam | reads as required | MET |
| Native smoke on npm/PyPI service on Windows/macOS/pinned Linux | service-native-smoke.mjs | pass on each OS | never run on a pinned lane. Only an unpinned throwaway witness on Linux (evidence), explicitly not lane evidence | NOT MET (blocked, see below) |
| containerd explicit-server routing probe vs row-28 service | service-cluster-probe.mjs | routing, no fallback, control | run once per evidence: 1 passed (13.0 s). I did not rerun (no containers permitted). Resolve/HEAD step only | MET at probe scope |
| Probe assertions meaningful | recording proxy (:81-105), control (:176-181), pinned-commit check (:112) | proxy only tunnels to the service, so a fallback is recorded; control proves the recorder works | F1 vacuity; 404 marking F4 | MET with F1/F4 |
| evidence/spike-native-cluster.md recorded | present | present, with limits and blocked lanes listed honestly | | MET |
| Row closure "qa=VERIFIED; security=CLEAR" | reviews/slice-29 | | this is the code review only; the qa and security records are not mine | UNKNOWN |

## Unmet vs blocked
Blocked by host (cannot be done on this Linux box):
- Pinned native Linux run: needs node 24.22.1, npm 11.21.1, python 3.15.1, pip 26.2.2, twine 7.0.0, uv 0.13.5 and NATIVE_PLATFORM=linux-x64 (host has node 20.19.6 / npm 11.16.0 / python 3.13.5 / pip 25.1.1). This is a provisioning gap on this host, not a code gap; a CI runner with setup actions or a pinned container-less toolchain satisfies it.
- macOS (darwin-arm64) and Windows (win32-x64) smoke runs: need those runners. Untested code on them: the Windows npm shim via `launch()` and backslash paths in `.npmrc`/`pip.conf` (`cafile=`/`cert=` written raw at service-native-smoke.mjs:32-33), plus `E2E_BRIDGE_HOST`.
- Real node (CRI/kubelet `config_path`): row 26.
Buildable now (unmet or improvable):
- F1 to F5 above (small edits).
- Topology point the evidence leaves open: compose publishes the bridge on `127.0.0.1` only (tests/e2e/compose/compose.yml `ports: 127.0.0.1:${E2E_BRIDGE_PORT}`), so `E2E_BRIDGE_HOST` pointing to a remote Linux stack cannot work as the evidence implies; it needs a bind-address option or a tunnel. Decide at rows 25/27, but record it in 03 now.
- A GitHub Actions job that runs the native smoke and the probe on the pinned lanes (row 25/27 own CI per C1018, so not strictly row 29).
- Probe cases the evidence lists as not covered and that are buildable on Linux now: a 403 (denying) service instead of a paused one needs row 24 routes (not buildable); an unprivileged `config_path` registry-config check without a node is partly buildable.

## Spike conclusion ("nothing invalidates router/lifecycle design")
Supported for what was observed: containerd with `server = service` sends the HEAD to the service with the original repo path and `ns=docker.io`, does not contact the origin when it gets 404 or when the service is paused, and the control run shows the recorder detects fallback. That backs the shared-router / explicit-server premise of T8/C1023 at the resolve step only, on containerd 2.2.0 run unprivileged. It does not test: authentication challenges and credential isolation, blob and child-manifest paths, a denying 403, a real CRI/kubelet node, or cached-image launches (all listed as limits in the evidence). It also says nothing about Windows/macOS lifecycle. So the claim is reasonable as "no contrary evidence for the router design"; "nothing invalidates ... lifecycle design" is not backed by anything in this spike and should be worded as untested until rows 25/26. 03 T8 should keep "routing is a documented candidate" for the unexercised parts (it currently says candidate until row 29/26).

## Conventions and simplifications
Small and consistent with the existing harness (single seam, plain node test script like native/*.test.mjs). `parseClientHost`/`requireNativeLane` are not over-built. The new test is not in native/expected-asserts.json (assertion floors, row 29 run on that mechanism via run_tests?): check whether native/*.test floors apply to harness/*.test.mjs; I did not verify the CI wiring, so client-host.test.mjs may not run in CI yet.

## Uncertainties
- U1: client-host.test.mjs may not be wired into the CI node-test list or assertion floors (not checked; owner: row 25).
- U2: Windows path escaping in generated .npmrc/pip.conf (needs a Windows run).

## Verification and limits
Ran: `node tests/e2e/harness/client-host.test.mjs` -> "client-host: all checks passed". Read all listed files in full, the row 29 text and the evidence file. Did not run the containers, the probe, or the native smoke (no pinned lane; instructions excluded containers). Supplied evidence (probe run, driver witness) is relied on as reported, not reproduced.
Files are untracked/dirty; sources hashed not recorded beyond this snapshot. Unchanged during review: I modified only this report; I did not recheck the git status after the run.
Lenses with no finding: security (probe proxy only tunnels the service name and binds 127.0.0.1; no credentials handled), efficiency.

## Next steps
1. Fix F1 and F2 (a few lines each) and tag row-24 flips (F4).
2. Add the native guard in F3 before row 25 builds on the seam.
3. Record the bridge-bind topology and soften the lifecycle claim in the spike conclusion.
4. Run the pinned Linux/macOS/Windows smoke on CI lanes (rows 25/27) to close the blocked items.
