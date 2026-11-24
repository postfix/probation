# Slice 31 (v2 Slice 30) evidence: execution of the authored lanes

Branch `slice5-native-ci`, local HEAD `ec49bac` (plan docs only ahead of origin), origin `057459e` (the commit the hosted runs used). Nothing committed or pushed by this slice. Decision basis: D25 (hosted runs authorized, local Linux first; no tag push), D26. Every claim is EXECUTED (command and result quoted) or AUTHORED, NOT EXECUTED. **D1 is NOT closed**: no cluster lane has run (see "Why native-service.yml and cluster.yml did not run").

Host: Debian 13, rootless podman 5.4.2 with `podman-compose` (no Docker Compose, no root, no nft, no Kubernetes). Every command ran in `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout <cap>`; scratch, target dir, E2E work dirs, Postgres data under `/home/john/go/src/github.com/postfix/.probation-scratch/s30`; compose project `probation-s30l`, subnet 11.230.0.0/24, bridge port 18230, Postgres 16 container `probation-s30-pg` port 55436. Tools installed in the scratch tree: actionlint 1.7.7, kubeconform 0.7.0 (go install), kubectl v1.36.5 (sha256 checked against cluster.yml's pin).

## Local Linux lanes (run first, per D25)

| Lane | Command | Exit | Result |
|---|---|---|---|
| clippy | `cargo clippy --workspace --all-targets --locked -j 8 -- -D warnings` | 0 | clean |
| tests | `cargo test --workspace --locked -j 8` (Postgres 16) | 0 | 122 result lines, 1,823 passed, 0 failed, 31 ignored |
| transport bench | `cargo bench --locked --bench transport_hot_paths -- --assert` | 0 | 36 PASS, 0 FAIL |
| SPEC section 12 benches | `cargo bench --locked --bench warm_metadata|artifact_throughput|blocklist_swap -- --assert` | 0, 0, 0 | warm metadata p95 0.088 ms, 127,021 resp/s; policy denial p95 1.340 ms; artifact +0.100 / +0.093 / +0.111 ms, 106.0 / 106.0 / 105.5 percent of baseline; no NOT MET |
| static native harness tests | `python3 tests/e2e/native/run_tests.py` | 0 (twice: before and after the lane fixes below) | `run_tests: 31 test files hold` |
| check_kubernetes | `python3 tests/e2e/native/check_kubernetes.py`; `.test.py` | 0, 0 | ok; 86 checks hold (79 mutations) |
| kubeconform | `kubectl kustomize deploy/kubernetes` then `kubeconform -strict -summary -kubernetes-version 1.36.0` with pvc.yaml | 0 | 12 resources, 12 valid |
| shell syntax | `sh -n` on the three node scripts | 0 | ok |
| actionlint | `actionlint` (1.7.7) | 1, then 0 | the only findings: runner labels `macos-26` and `macos-15-intel` unknown to the 1.7.7 label table (real labels); `actionlint -ignore 'label "macos-(26|15-intel)" is unknown'` exits 0 |
| release E2E (podman-compose), invocation 1 | `node tests/e2e/harness/run.mjs --suite release` | 124 (my 14,000 s cap) | 35 of 58 passed; 12 failed; stopped inside E2E-publishing-npm-read |
| release E2E, invocation 2 (failed and not-run scenarios, `E2E_PREBUILT=1`, matrix excluded) | same with `--only` list | 130 (interrupted by me) | passed: E2E-portal-members-browser, E2E-publishing-certificate-npm, PBT-smoke; failed: see below |

Release E2E detail (podman-compose; JUnit "no skipped" is not met because the run did not complete):

- Passed in invocation 1 (35): E2E-001, 002, 003, 004, 006, 008, 010, 011, 012, 013, 015, 016, 017, 018, 019, 020, A11Y-axe, cargo, conan, go, maven, nuget, oci, rubygems, portal-areas-browser, portal-login-deletion-browser, publishing-cargo-service, -certificate-scale (organisation-issuer admissions 10,000, no 401 this time), -conan-service, -maven-service, -native-linux, -npm-actions, -npm-read-issuer, -portal-ui, -private-read. E2E-012 passed here (it failed 4 of 4 in slice 27).
- The three "mail not delivered within 65 s" scenarios (E2E-portal-members-browser, -publishing-certificate-npm, -publishing-enterprise-registry) failed in the long shared stack at host load average 0.3 (so not host load), then members-browser and certificate-npm passed on a fresh stack (90.8 s, 318.5 s); enterprise-registry failed again (`fw1 ready ... TLS handshake timed out`).
- Failures that share one cause: E2E-publishing-full-matrix (runner 15 of 20, `npm-actions-issuer`: `fw1 ready: not within 60000 ms (TLS handshake fw1.e2e.test:443 timed out)`), -npm-actions-issuer, -python, -python-issuer, -sso-python, -uv, -uv-issuer (pip/uv `Read timed out` against `fw1.e2e.test`), E2E-005, E2E-007, E2E-009, E2E-014 (502 UPSTREAM_FAILURE in 6.2 s, the 5 s bound). The gateway log of those runs says `connect() failed (113: Host is unreachable) while connecting to upstream ... 11.230.0.5:8080 / 11.230.0.9:8080 / 11.230.0.15:8080`: the nginx gateway container cannot reach the firewall containers' addresses on the podman bridge after a firewall container is recreated or restarted. That is a podman-compose / netavark behaviour (slice 27 recorded `No route to host` and `IPAM error` from the same stack), the firewall itself logged no request for the failing pip calls. It is not shown to be a product defect, and it cannot be separated from the host without `docker compose`: an unresolved issue of this lane, not a pass.
- Not run in the final state: E2E-publishing-npm-read (killed by my cap in invocation 1; failed in invocation 2 after the network degraded), -nuget-service, -oci-service, -pypi-cidr-race, -python-service, -rubygems-service, E2E-service-policy, E2E-signup-to-install. Their last results are slice 27 round 4 (passed).
- `release-native` and `release-cluster` were not re-run (slice 18 ran both locally on 2026-11-23: `_work/slices/slice-18-local-linux.md`).

## Hosted lanes (per D25)

Dispatch used `gh workflow run <file> --ref slice5-native-ci`. Runs executed the origin commit `057459e`, which does not hold this slice's uncommitted fixes.

| Lane (workflow / job) | Trigger | Run URL | Expected (runbook, slice-27.md) | Actual | State |
|---|---|---|---|---|---|
| native-clients.yml `native` linux-x64 | workflow_dispatch | https://github.com/postfix/probation/actions/runs/45436763112 (job 138596585779) | every OS job green | success | EXECUTED, passed |
| native-clients.yml `native` darwin-arm64 | same | same run (job 138596585398) | green | FAILURE: `twine upload ... SSLCertVerificationError ... Missing Authority Key Identifier` (the test CA leaf certificate has no AKI; macOS openssl is LibreSSL; Python 3.13+ verifies strictly), then every Twine/uv assertion | EXECUTED, failed; fix authored locally (below) |
| native-clients.yml `native` win32-x64 | same | same run (job 138596585246) | green | FAILURE: `probation exited 1 ... invalid service_policy.service_key_file: requires a private regular file` although the harness ran `icacls /inheritance:r /grant:r` on the key | EXECUTED, failed; cause not isolated (see finding W1) |
| native-clients.yml `real-server` (cloudflared tunnel) | same | same run (job 138596585502) | green | FAILURE: `win32-x64: the native probation never fetched the snapshot` (only win32-x64 is named by the check: a consequence of the Windows failure) | EXECUTED, failed |
| native-clients.yml `linux-managed` | same | same run (job 138596584763) | green | RESULT PENDING when this was written: the job was still inside `E2E-publishing-full-matrix` (about 70 minutes in); GitHub gives no log of a running job | PENDING |
| e2e.yml `nightly` (docker compose, ubuntu) | workflow_dispatch suite=nightly | https://github.com/postfix/probation/actions/runs/45436770587 (job 138596600689) | the docker compose answer to finding 4a | FAILURE after 25 scenarios: 23 passed (E2E-001, 002, 003, 004, 006, 011, 012, 013, 017, 018, 019, 020, cargo, conan, go, maven, nuget, oci, rubygems, portal-areas, portal-login-deletion, portal-members-browser, publishing-portal-ui) then E2E-A11Y-axe FAILED (slice 6: 6 problems on `/keys` and `/keys/service`: axe `scrollable-region-focusable` on two `pre` blocks, and the first Tab stop is not the skip link); E2E-005 passed; the next fresh stack aborted the run: `fw2 ready: not within 60000 ms` (stack.mjs firewallReady) | EXECUTED, failed |
| native-service.yml (service-linux, service-macos x2, service-windows, tools, tools-host, tools-linux, docker-engine) | workflow_dispatch | none: `gh workflow run native-service.yml` returned HTTP 404 | green on every OS | NOT RUN | AUTHORED, NOT EXECUTED |
| cluster.yml (static, netns, e2e-service-cluster, kind, cri-node) and D1 | workflow_dispatch | none: HTTP 404 | five jobs; first green run is first evidence for D1 | NOT RUN | AUTHORED, NOT EXECUTED |
| rust.yml `static-link` (3 targets) | pull_request to main only; no dispatch trigger | none | green | NOT RUN | AUTHORED, NOT EXECUTED |
| release.yml `test`, `e2e`, `build`, `attest`, cosign, draft release, bench step | `v*.*.*` tag push only; tag push NOT authorized (D25) | none | see runbook | NOT RUN | AUTHORED, NOT EXECUTED |

### Why native-service.yml and cluster.yml did not run

GitHub lists only workflows it has registered: `gh workflow list --all` shows E2E, Native call probe, Native package clients, Release, Rust and Dependabot. `native-service.yml` and `cluster.yml` exist on `slice5-native-ci` but are not on `main` and no push or pull_request run ever registered them (native-service.yml has only `workflow_call` and `workflow_dispatch`; cluster.yml has `pull_request` on its path list, `schedule` and `workflow_dispatch`, and no PR exists for the branch). A `workflow_dispatch` of a workflow that is not on the default branch is refused with 404. Two ways to run them need an action D25 does not grant: (a) open a pull request `slice5-native-ci` to `main` (fires cluster.yml's `pull_request` trigger and rust.yml `static-link` and e2e.yml `pr`; native-service.yml has no PR trigger and would need one added), or (b) merge the workflow files to `main`.

## Lane fixes made locally (not committed, not pushed; they could not be exercised on a hosted runner)

1. `tests/e2e/fixtures/make-ca.sh`: the CA gets `subjectKeyIdentifier=hash`, the leaf gets `subjectKeyIdentifier=hash` and `authorityKeyIdentifier=keyid:always`. Local witness: OpenSSL 3 `x509 -ext authorityKeyIdentifier,subjectKeyIdentifier` shows both; `openssl verify -x509_strict -CAfile ca.pem cert.pem` prints OK; `node tests/e2e/native/ca-script.test.mjs` passes. Targets the macOS failure; not proven on macOS.
2. `tests/e2e/native/stack.mjs` (`keyFileWarnings`) and `stack.test.mjs`: on Windows the harness now prints the key file's SDDL and the account SID next to the existing "not verified" line, so the next hosted run names why `is_shared` says the file is not private. `node tests/e2e/native/stack.test.mjs`: ok.

### Finding W1 (Windows key-file check): possible product defect, not fixed here

`src/key_acl.rs` compares SDDL trustees with literal SIDs (`S-1-5-18`, `S-1-5-32-544`, the process user SID) and the two-letter aliases `SY`, `BA`. `ConvertSecurityDescriptorToStringSecurityDescriptorW` prints well-known SIDs as aliases (for a built-in account such as RID 500 it prints `LA`; other aliases exist), so a key file granted to the runner's own account can read as "outside" the allowed set. This is a hypothesis from reading the code; no hosted run has printed the SDDL yet (fix 2 above makes the next run print it). Product source is out of scope for this slice: if the SDDL confirms it, it needs its own `code-tdd` slice.

## Findings from evidence/slice-27.md, current state

| Item | Current state with evidence |
|---|---|
| Finding 2: the two SPEC section 12 benches | RESOLVED on this host: `warm_metadata`, `artifact_throughput`, `blocklist_swap` `-- --assert` exit 0 with no NOT MET (table above). Slice 27 round 3 and 4 had the same result; the slice 27 round 0 failure was the host. |
| Finding 3: shared-service npm metadata revalidation cost | DECIDED and built in slice 27 round 4 (owner decision): the 5 s share serves credential-free metadata reads only; artifact requests always revalidate. The `transport_hot_paths` bench asserts the bounds (36 PASS). The wording for C1028 is still a spec change (item 0 below). |
| Finding 4a: the six release scenarios that failed on podman-compose | NOT SETTLED. Locally E2E-012 passed this time; E2E-009 and E2E-014 failed again, certificate-scale and full-matrix did not reproduce the 401 (certificate-scale passed), and a new set (python, uv, issuer, sso, E2E-005, E2E-007, matrix runner 15) fails with the gateway `Host is unreachable` signature. The hosted docker compose run (e2e.yml `nightly`, run 45436770587) did not discriminate: it stopped after 25 scenarios when a fresh stack's `fw2` did not become ready in 60 s, so the hosted lane shows a firewall-readiness failure on docker too (cause not isolated), and none of the slice 27 six (009, 014, full-matrix, certificate-scale, native-linux) ran there. A separate hosted-only finding: E2E-A11Y-axe fails on the current hosted Chromium (portal `pre` blocks need keyboard access, first Tab stop not the skip link; product templates, not fixed here), while it passed locally with the older cached Chromium. |
| Finding 1 / the success criterion (all nine transports on all 3 client OSes) | NOT MET: macOS and Windows native publishing failed on hosted runners (above); the `tools` lanes did not run. |
| Spec changes 0 to 6 | UNCHANGED, still the plan owner's; the spec is not edited. Item 1 (three E2E runs, `--client-host native` split) and 2 (hosted criterion wording): confirmed by this run: native-clients ran `native` on three OSes as a separate workflow. Item 6 (00-status NEXT ACTION): the hosted runs above are the first executions; D1 stays open. |

## D1 verdict

D1 stays OPEN. The kind and cri-node jobs, the NodePort source-address check, the no-upstream-fallback kubelet path, ReadWriteOncePod, NetworkPolicy/Cilium and multi-node lanes have not run: cluster.yml could not be dispatched (404). Nothing in this file claims otherwise.

## Pending

`linux-managed` (job 138596584763 of run 45436763112, steps E2E-service-policy, npm-read, npm-actions, python-service, full-matrix, native-linux) was still running at the hand-off. Read its result with `gh run view 45436763112 --json jobs`; it is not claimed here.

## Cleanup

Compose project `probation-s30l`: containers, volumes and networks removed (checked with `podman ps -a`, `podman network ls`, `podman volume ls`). Postgres container `probation-s30-pg` and the scratch tree `.probation-scratch/s30` remain until the hand-off is accepted.

## Result of run 45436763112 (native-clients on 057459e), final

Read with `gh run view 45436763112 --json jobs`: `linux-managed` (job 138596584763) = **success**; linux-x64 success; win32-x64, darwin-arm64 and real-server failure (rows above). Run conclusion: failure.

## Hosted round 2 (commit a1ec43c)

Three dispatches on `slice5-native-ci` at `a1ec43c` (D25/D27), 2026-11-24 18:02 UTC: `gh workflow run native-service.yml|cluster.yml|native-clients.yml --ref slice5-native-ci`. All three registered (the 404 of round 1 is gone since `da7f499` put the two workflow files on main). The runs hold none of the lane fixes of "Round 2 lane fixes" below (authored after, not pushed). Logs read with `gh api repos/postfix/probation/actions/jobs/<id>/logs`; the cluster artifact `cri-node` read with `gh run download`.

| Run / job | Job id | Expected (runbook) | Actual | State |
|---|---|---|---|---|
| native-service https://github.com/postfix/probation/actions/runs/45455094825 `docker-engine` | 138662277632 | green | success (pinned Docker Engine 29.9.2 daemon pulls through the OCI routes) | EXECUTED, passed |
| same `service-linux` | 138662278346 | green | FAIL: `E2E-service-native` install: `chown: invalid group: 'root:probation-e2e-10281'` (system scope, root, real `useradd`) | EXECUTED, failed (lane/script defect L5) |
| same `service-macos aarch64-apple-darwin` | 138662278222 | green | FAIL: `install-service.sh ... the release attestation of .../probation does not verify (gh attestation verify ...)`: the CI-built package has no attestation | EXECUTED, failed (lane defect L3) |
| same `service-macos x86_64-apple-darwin` | 138662278424 | green | same attestation refusal | EXECUTED, failed (L3) |
| same `service-windows` | 138662278828 | green | FAIL at "The packaged exe imports only system libraries": `the binary imports non-system libraries: bcryptprimitives.dll` (a Windows system DLL missing from the allow-list regex); the lifecycle steps after it did not run | EXECUTED, failed (lane defect L4) |
| same `tools linux-x64` | 138662278497 | green | FAIL at "Verify the pinned tool versions": `dotnet: want 8.0.416, got 11.0.100` (the runner image's SDK 11 sits in the same dotnet root; the muxer takes the highest) | EXECUTED, failed (L2) |
| same `tools darwin-arm64` | 138662278491 | green | same dotnet pin failure | EXECUTED, failed (L2) |
| same `tools win32-x64` | 138662278639 | green | same dotnet pin failure | EXECUTED, failed (L2) |
| same `tools-linux` (Maven, Conan, podman OCI) | 138662278605 | green | Maven and Conan passed; `oci_native`: 3 of 4 failed, `Error: the specified runroot is longer than 50 characters` (podman's `--runroot` is `<workspace parent>/.probation-scratch/native-oci/.tmpXXXXXX/...`, over podman's 50-character limit on the hosted path `/home/runner/work/probation/...`) | EXECUTED, failed (test-source defect L6, `tests/oci_native.rs`, outside my allowlist) |
| same `tools-host linux-x64` | 138662278685 | green | success | EXECUTED, passed |
| same `tools-host darwin-arm64` | 138662278797 | green | Conan: 2 passed, 1 failed: `seeding with the real client failed: ... Connection to 127.0.0.1 timed out. (connect timeout=30)` to the loopback recorder on port 49298; the other two Conan tests passed in the same job; cause not isolated | EXECUTED, failed (unexplained, not fixed) |
| same `tools-host win32-x64` | 138662278734 | green | Conan: 3 failed. `bash` resolves to System32's WSL launcher: `Windows Subsystem for Linux has no installed distributions` | EXECUTED, failed (L7) |
| cluster https://github.com/postfix/probation/actions/runs/45455102110 `static` | 138662299654 | green | success | EXECUTED, passed |
| same `netns` | 138662299120 | green | success (its assertion counts are the lane's own: 1, 1, 0 + the deliberate "no assertion ran" negative control, then ok) | EXECUTED, passed |
| same `e2e-service-cluster` | 138662299534 | green | FAIL: `E2E-service-cluster-probe` passed; `E2E-service-cluster`: `the shipped pod starts ...: docker: unknown command: docker kube` (the stack engine on the hosted runner is docker, `kube play` is podman) | EXECUTED, failed (L1) |
| same `kind` (calico) | 138662299661 | green; phase A, phase B, negative control, no-upstream-fallback | FAIL before any assertion: `kind load` => `ERROR: unknown containerd config version: 4 (supported versions: 2 and 3)`; `lane aborted with status 1 after 0 assertion(s)` (kind v0.31.0 with node image v1.36.4, which kind v0.33.0 published) | EXECUTED, failed (L8) |
| same `cri-node` | 138662299442 | green | 5 of 6 assertions ok (control pull from the registry, install-node.sh, install-firewall.sh, the same PullImage fails and names the endpoint with no fallback, registry image absent); FAIL `verify-node.sh passes`: `the drop-in changes more than the registry config_path ... (first differences: < time="..." level=warning msg="Configuration migrated from version 2 ..." t="10.9µs" > time=... t="10.48µs"`: containerd's own log lines (timestamps, durations) are in the dump the verifier diffs (artifact `cri-node`, `expect.log`) | EXECUTED, failed (product-script defect in `deploy/`, L9) |
| native-clients https://github.com/postfix/probation/actions/runs/45455108402 `native linux-x64` | 138662322306 | green | success | EXECUTED, passed |
| same `native darwin-arm64` | 138662322601 | green | success: `native publishing passed: 75 checks on darwin-arm64` (the key-identifier fix of `a1ec43c` is proven on macOS) | EXECUTED, passed |
| same `native win32-x64` | 138662322146 | green | FAIL as in round 1: `probation exited 1: ... invalid service_policy.service_key_file: requires a private regular file`. Diagnostic printed (below) | EXECUTED, failed |
| same `real-server` | 138662321727 | green | FAIL: `win32-x64: the native probation never fetched the snapshot (no unlabelled request from 172.206.245.226)` (consequence of the Windows failure; linux-x64 and darwin-arm64 are not named) | EXECUTED, failed |
| same `linux-managed` | 138662322362 | green | success: E2E-service-policy, -npm-read, -npm-actions, -python-service, -full-matrix (2,375.3 s), -native-linux, `6 passed, 0 failed, 0 not run (suite pr)` | EXECUTED, passed |

### Windows: the new key-file diagnostic and W1

The two lines the harness printed (job 138662322146):

```
warning: the ACL of C:\Users\RUNNER~1\AppData\Local\Temp\native-publish-wqCGpf\stack\service.key is not verified: Probation checks key file permissions with POSIX modes only
warning: the ACL of C:\Users\RUNNER~1\AppData\Local\Temp\native-publish-wqCGpf\stack\service.key as the runner sees it: USER=S-1-5-21-3414932011-3134797172-3625386099-500 Get-Acl : The 'Get-Acl' command was found in the module 'Microsoft.PowerShell.Security', but the module could not be loaded. ...
```

The SDDL itself was NOT printed (Get-Acl could not load its module from that shell), so W1 is neither confirmed nor refuted. What the SID line shows: the runner's account is `S-1-5-21-...-500`, RID 500, the built-in local Administrator. `ConvertSecurityDescriptorToStringSecurityDescriptorW` prints that account as the alias `LA`, not as a literal SID, and `src/key_acl.rs` compares against literal SIDs plus `SY`/`BA` only: this is the precondition W1 needed and it holds, but the proof (an `LA` or other alias in the DACL) is still missing. Fix authored (L10): the diagnostic reads the descriptor through .NET (`FileInfo.GetAccessControl().GetSecurityDescriptorSddlForm`), so the next Windows run prints the SDDL.

### D1 verdict (round 2)

D1 stays **OPEN**. Executed green: cluster `static` and `netns`. Not executed green: `kind` (phase A, phase B, negative control, and the lane's no-upstream-fallback on the kubelet path never ran: 0 assertions, aborted at `kind load`), `cri-node` (the no-upstream-fallback CRI pull assertion passed, but the job failed on `verify-node.sh`, so the job is red), `e2e-service-cluster`. D1 closes only on a green `kind` and `cri-node` job.

### Round 2 lane fixes (authored here, tested locally where a check exists; NOT committed, NOT pushed, NOT exercised on a hosted runner)

| # | Defect | Fix | Local check |
|---|---|---|---|
| L1 | `E2E-service-cluster` pod smoke used the stack engine (docker) for `kube play` | `tests/e2e/scenarios/service-cluster.mjs`: the pod smoke uses `podman`; `cluster.yml` e2e-service-cluster gets a step `docker save localhost/probation:e2e | podman load` | `node --check`; actionlint 0 |
| L2 | dotnet pin: runner SDK 11 wins | `native-service.yml` `tools`: step `dotnet new globaljson --sdk-version $PIN_DOTNET --roll-forward disable` into the parent of the workspace's parent (covers the checkout and `$RUNNER_TEMP`); the cargo test step sets TMPDIR/TEMP/TMP to `runner.temp` so the tests' directories sit under it | actionlint 0; check_workflow (below) |
| L3 | CI package has no attestation | `tests/e2e/native/service-lifecycle.mjs` `installVerifyFlags`: `--no-verify` / `-NoVerify` when `E2E_SERVICE_UNATTESTED` is set; both service-lifecycle-run steps of `native-service.yml` set it. Windows `-NoVerify` also skips the SHA256SUMS check of the installer (what `-NoVerify` means in `install-service.ps1`); the hash check of that package is therefore not exercised by this lane | `service-lifecycle.test.mjs` |
| L4 | `bcryptprimitives.dll` is a Windows system library | added to the allow-list regex in `native-service.yml` | actionlint 0 |
| L5 | `chown root:<service-name>`: no such group on the hosted runner | `scripts/install-service.sh`: `useradd --system --user-group` (a same-named group is made explicitly; locally USERGROUPS_ENAB already did) | `bash -n`; NO check can run (needs a real root `useradd`); cause on the hosted image not proven |
| L7 | Windows `bash` is the WSL launcher | `native-service.yml` tools-host: a step puts `C:\Program Files\Git\bin` first on PATH (no `if:`: check_workflow forbids it, the step tests `$RUNNER_OS` in the script) | actionlint 0; check_workflow |
| L8 | kind v0.31.0 cannot `kind load` into containerd config v4 | `cluster.yml`: kind v0.33.0 (the release that published the pinned node image v1.36.4), sha256 `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d` (the release's asset digest, and `sha256sum` of the downloaded file agree) | actionlint 0 |
| L9 | `verify-node.sh` diffed containerd's log lines | `deploy/kubernetes/node/verify-node.sh`: lines starting `time="` are dropped from both comparison files | test below |
| L10 | Windows SDDL diagnostic printed nothing | `tests/e2e/native/stack.mjs` `aclScript` (.NET call) | `stack.test.mjs` |

Not fixed, reported: L6 (`tests/oci_native.rs` hard-codes the engine's storage under `<workspace parent>/.probation-scratch/native-oci/.tmpXXXXXX`, a path over podman's 50-character runroot limit on the hosted workspace; a fix needs an environment override or a shorter base in that test file, which is outside this slice's owned paths); the macOS `tools-host` Conan loopback timeout; W1's product question (`src/key_acl.rs`); E2E-A11Y-axe (round 1).

tdd: log_lines_of_containerd_in_the_dump_do_not_count_as_a_changed_configuration (tests/node_scripts.rs) — red: `FAIL: the drop-in changes more than the registry config_path of .../n402/etc/containerd/config.toml (first differences: < time="1795543896753827072" level=warning ...` — green: `cargo test --locked --test node_scripts` passed (25 passed, 0 failed)
tdd: service-lifecycle.test.mjs installVerifyFlags — red: `SyntaxError: The requested module './service-lifecycle.mjs' does not provide an export named 'installVerifyFlags'` — green: `node tests/e2e/native/service-lifecycle.test.mjs` passed (`service-lifecycle.test: ok`)
tdd: stack.test.mjs aclScript — red: `SyntaxError: The requested module './stack.mjs' does not provide an export named 'aclScript'` (observed by stashing stack.mjs) — green: `NATIVE_TEST_SCRATCH=... node tests/e2e/native/stack.test.mjs` passed
verification: `python3 tests/e2e/native/run_tests.py` => `run_tests: 31 test files hold` (final state of all edits except none after); `actionlint -ignore 'label "macos-(26|15-intel)" is unknown'` on all workflows => exit 0; `sh -n`/`bash -n` on the touched shell scripts => ok. `cargo test --test node_scripts` hangs when stdin is an open pipe (a stub `kubectl` runs `cat`); run it with `</dev/null`.
