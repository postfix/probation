# Slice 29 spike: native-driver seam and containerd routing probe — 2026-11-18

Local only; no commit. Rows 03/04/00-status are untouched and nothing is marked complete.

## Delivered

| Path | What |
|---|---|
| tests/e2e/harness/client-host.mjs | The seam: `parseClientHost`, `requireNativeLane` (preflight through native/clients.mjs and pins.json), `nativeClients` (host npm/pip through the bridge CONNECT proxy and the e2e CA), `checkNativeCounts` |
| tests/e2e/harness/run.mjs, helpers.mjs | `--client-host container\|native`; `h.npm`/`h.pip` delegate at the one existing client seam when native; `h.caFile`; counts and JUnit |
| tests/e2e/harness/service-setup.mjs | Starts the row-28 common service (peer CIDR admission) for both scenarios |
| tests/e2e/native/client-host.test.mjs | Rules test, in the established native test list (`native/expected-asserts.json` floor 28, run by `native/run_tests.py`) |
| tests/e2e/compose/compose.yml | Bridge bind address option `E2E_BRIDGE_BIND` (default 127.0.0.1, unchanged; tested) |
| tests/e2e/scenarios/service-native-smoke.mjs | `E2E-service-native-smoke` (declares `clientHost: "native"`, `native: {npm: 2, pip: 1}`) |
| tests/e2e/scenarios/service-cluster-probe.mjs | `E2E-service-cluster-probe` |
| tests/e2e/README.md | Section "Native client host and the cluster probe" |

Rules enforced (tested): an unprovisioned native lane exits 1 before any container exists and lists every reason; the native smoke without the flag exits 1 ("requires --client-host native"); a bad value exits 1; a native run fails unless every selected scenario ran, declares native clients and used each at least its declared count. No path runs containers under `--client-host native` and nothing is skipped.

## TDD cycles

- client-host.test.mjs — red: `ERR_MODULE_NOT_FOUND ... harness/client-host.mjs` (before the module existed) — green: `node tests/e2e/harness/client-host.test.mjs` printed `client-host: all checks passed`.
- E2E-service-cluster-probe — red: `e2e: --only names no scenario: "E2E-service-cluster-probe-missing"` (the absent-ID path; the scenario file did not exist). Then three honest probe reds while building it, each fixed in the scenario: (1) `spawnSync` froze the in-process recording proxy (`context deadline exceeded`, empty connect log); (2) the service's request log carries no path, so path evidence was moved to the runtime's debug log; (3) gateway has no access log. Green: `e2e: 1 passed, 0 failed, 0 not run` (command below).
- E2E-service-native-smoke — red not observed as a live run: it cannot run on this host (see blocked lanes). Driver witness below.

## Results (real runs)

Fail-loudly, this Linux host:

```
$ node tests/e2e/harness/run.mjs --only E2E-service-native-smoke --client-host native
e2e: native client lane is not provisioned:
  NATIVE_PLATFORM is not set                                  (exit 1)
$ NATIVE_PLATFORM=linux-x64 node ... --client-host native
  node: want 24.22.1, the running node is 20.19.6 / npm: want 11.21.1, got 11.16.0 / python: want 3.15.1, got 3.13.5
  pip: want 26.2.2, got 25.1.1 / twine: want 7.0.0, got missing / uv: want 0.13.5, got 0.12.1 ...   (exit 1)
$ node ... --only E2E-service-native-smoke
e2e: E2E-service-native-smoke requires --client-host native (it never runs in containers)   (exit 1)
```

Containerd probe: `E2E_WORK=<scratch> E2E_PREBUILT=1 systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 3000 node tests/e2e/harness/run.mjs --only E2E-service-cluster-probe` -> `E2E-service-cluster-probe passed in 13.0 s`, `1 passed, 0 failed, 0 not run`. First run built the images: stack up in 341 s.

Runtime: containerd v2.2.0 commit 1c4457e00facac03ce1d75f7b6777a7a851e5c41 (the pinned pair member), started UNPRIVILEGED (own root/state/socket, uid/gid of the user, CRI, overlayfs, erofs, blockfile, nri disabled), `ctr content fetch --hosts-dir` (resolve and pull into the content store; no snapshotter or root). hosts.toml: `server = "https://fw-standalone.e2e.test"`, `capabilities = ["pull","resolve"]`, `ca = <e2e CA>`. Every runtime connection goes through a recording CONNECT proxy that tunnels only to the service name.

Findings (all observed):

1. Routing works. A pull of `docker.io/library/alpine:latest` made exactly one request, `HEAD https://fw-standalone.e2e.test/v2/library/alpine/manifests/latest?ns=docker.io`: the service as server, the original repository path, and the original registry preserved as `ns=docker.io` (C1023's documented candidate is now runtime-verified for the resolve step).
2. Row 28 has no OCI route: the service answered 404 `NOT_FOUND` (its log: one `HEAD`, status 404, `no such route or resource`) and containerd reported `not found`. This is the expected recorded answer until row 24 delivers OCI routes; the probe's assertions that depend on it (`exit !== 0`, 404) must be flipped when row 24 lands.
3. No fallback to the origin: the proxy saw only `fw-standalone.e2e.test:443` for the routed pull, and also with the service paused (the request failed with `TLS handshake timeout`; no other destination attempted). With the service as `server`, containerd does not try registry-1.docker.io.
4. Positive control: the identical run with a hosts.toml without `server` attempted `registry-1.docker.io:443` (refused by the recorder), so the recorder does detect a fallback.
5. Conclusion, worded to what was observed: no evidence contradicts the shared-router / explicit-server premise of T8/C1023 at the resolve step, on containerd 2.2.0 run unprivileged. The lifecycle design (rows 25/26: macOS/Windows service lifecycle, node and cluster behaviour) is UNTESTED by this spike and stays so until rows 25 and 26; 03 T8 keeps "routing is a documented candidate" for everything the probe did not exercise.

Not covered by the probe (limits): CRI/kubelet `config_path` path and a real node (row 26 owns the Kubernetes 1.36.5 witness); authentication behaviour (Basic/Bearer challenges and credential isolation need row 24's OCI routes); a service that denies (403) rather than a paused one; image blob/child paths; cached-image launches.

Native smoke driver witness (NOT lane evidence): a throwaway runner in the scratch directory ran the smoke scenario against the live stack with the host's UNPINNED tools (node 20.19.6, npm 11.16.0, pip 25.1.1) through `nativeClients`: `witness passed; client use {"npm":2,"pip":1}` — native npm install, native pip install and the blocklisted-package refusal through the service via the bridge proxy. This shows the seam works end to end on Linux; it does not satisfy the pinned-lane requirement.

## Blocked lanes

| Lane | State | What it needs |
|---|---|---|
| Native Linux (ubuntu-24.04 x64), pinned | blocked on this host | node 24.22.1, npm 11.21.1, python 3.15.1, pip 26.2.2, twine 7.0.0, uv 0.13.5 on PATH (native/pins.json), `NATIVE_PLATFORM=linux-x64`, Docker/Compose-compatible engine for the stack |
| Native macOS (macos-26 arm64) | not run (host is Linux) | a macOS runner with the same pins, `NATIVE_PLATFORM=darwin-arm64`, a Linux stack endpoint: the stack is Linux containers, so the runner needs a container VM or a remote Linux stack, and `E2E_BRIDGE_HOST` pointing at its published bridge port (the seam reads it; untested on macOS) |
| Native Windows (windows-2025 x64) | not run (host is Linux) | the same on `NATIVE_PLATFORM=win32-x64`; the npm shim goes through `launch()` in native/spawn-args.mjs (untested here); stack on a Linux endpoint as above |
| containerd on a real node (CRI, kubelet) | not run | Kubernetes 1.36.5 node with the pinned containerd and root; row 26 |

Topology: the seam reaches the stack through the bridge proxy, which only tunnels e2e-network addresses. A runner on another machine needs `E2E_BRIDGE_BIND` (stack host) and `E2E_BRIDGE_HOST` (runner); never run against a public interface. The CI topology itself is for rows 25/27 to record in 03.

## Cleanup

Scratch work dir, unprivileged containerd state, compose project, volumes and the images built for the run were removed.
