# TDD record, slice 26 (one cluster endpoint with approved-node trust and no upstream fallback)

Two rounds are recorded: the first round below built a StatefulSet and was reviewed (reviews/slice-26/); the "Fix round" at the end answers those reviews with the approved Recreate Deployment and the other changes. Where the first round's cycles name files that no longer exist (statefulset.yaml, configmap.yaml) the fix round's cycles are the current ones.

Procedure: /home/john/.claude/skills/agents/implement/AGENT.md (the path named in the task, /home/john/.claude/skills/lf-start/agents/implement/AGENT.md, does not exist; this is the file that does). Inputs read: 00-status.md, 03-program-design.md (the shared-service platform contract with D1 and the node-trust sentence, coverage rows T1, T8 and D1, item (p) points 14 and 16, item (q)), 04-slices.md row 26, evidence/spike-native-cluster.md, reviews/slice-29/code-review.md, evidence/slice-24.md, evidence/slice-25.md (shape of the Lanes table and the checks), evidence/design-deployment-contract.md, evidence/research-native-supervision.md, tests/e2e/scenarios/service-cluster-probe.mjs and harness/service-setup.mjs, docs/operations.md (OCI and shared-service parts), docs/configuration.md.

Baseline: starting commit `45f4ab8d69b80964821c1093f52b6868d1ab7de0` on branch `slice5-native-ci`, working tree clean (`git status --short --untracked-files=all` empty). Nothing is committed.

Owned paths (the write allowlist, from the row): deploy/kubernetes/ (and node/), tests/e2e/scenarios/service-cluster.mjs, the harness module it shares with the probe, the node runtime and egress set-up, docs/operations.md, plus their tests: tests/cluster_peer.rs, tests/node_scripts.rs, tests/e2e/native/check_kubernetes.py and .test.py, tests/e2e/fixtures/{kube-play,node-egress}/, tests/e2e/README.md, CHANGELOG.md, tests/e2e/native/expected-asserts.json. The Rust service itself is NOT changed: `allowed_peer_cidrs` and the admission order of row 28 already are the approved-node mechanism; this slice proves them over real TCP and in the shipped configuration.

Seams: (1) the `probation` binary as a process (`check-config`, `serve`) started from the SHIPPED ConfigMap; (2) the manifests as files (static contract, kubeconform, `podman kube play`); (3) install-node.sh and verify-node.sh as commands; (4) the real containerd 2.2.0 and the shared service in the e2e stack; (5) egress.nft loaded into a throwaway network namespace.

Honesty about order: the manifests and the checker were written before their test, so for the static contract the "red" of each property is its mutation, not an absent file; every other cycle below states what was actually observed. Reds that were observed while building (not manufactured) are listed first in each cycle.

## Cycles

tdd: check_kubernetes (the static contract, 53 mutations) — red: `FINDING S-REPLICAS: replicas must be 1 (one store owner), found None` (the checker against a deployment with no manifests; six `FINDING` lines, first `N-PSS`) — green: `python3 tests/e2e/native/check_kubernetes.test.py` printed `check_kubernetes.test: 55 checks hold (53 mutations each caught by its named finding)`. Each mutation edits one line of a copy and requires its named finding id; red not observed for the mutations as a separate step (they pass at once because the checker already contained the rule); the probes below break the SHIPPED files instead.

tdd: shipped_configmap_is_what_the_binary_accepts — red: `/…/config.toml: missing key `max_blocklist_bytes`` (REAL defect: the first ConfigMap omitted a key the product requires; found only because the test runs `probation check-config` on the shipped text) — green: `cargo test --test cluster_peer shipped` 1 passed after adding the key. The negative half (no TLS, no approved node, `0.0.0.0/0`, a /7) is refused by the same parser: red not observed (existing behavior), pinned.

tdd: real_tcp_peers_in_a_network_namespace (6 checks over real TCP from chosen source addresses: approved admitted, unapproved refused on 5 routes, forged X-Forwarded-For/X-Real-IP/Forwarded refused, probes answered from any peer with the pod address as Host, a source-rewriting forwarder admits the external host, the pod's loopback admitted) — red: `the service exited early: exit status 1` (the same missing `max_blocklist_bytes`, seen through the real binary) — green: `cargo test --test cluster_peer -- --include-ignored` 2 passed. Characterization of row 28's mechanism at the TCP level: red not observed for the six checks themselves; mutations P1, P2 and P5 kill it.

tdd: node_scripts (4 tests: installer output and idempotence, 8 refusals plus a foreign hosts file kept, 13 verifier failures plus the same-endpoint override accepted, online checks) — red: `containerd: flag provided but not defined: -c` (verify-node.sh used `containerd config dump -c`; the first version of the same test, written as a Node test, failed on it) — green: `cargo test --test node_scripts` 4 passed. The Node version of this test was dropped after `python3 tests/e2e/native/run_tests.py` failed `check_workflow.test.py`, `crlf.test.py` and `encoding.test.py` with `run_tests.py SKIP_ON must be exactly {"win32": {"clients.test.mjs", "rendezvous-cli.test.mjs"}}` (it needed a Windows skip, which that checker pins); the Rust port is `#![cfg(unix)]` like tests/service_scripts.rs. Red not observed for the port (ported behavior); mutations P6, P7, P7b kill it.

tdd: egress.nft (the node egress ruleset, run in a throwaway network namespace) — red: `10.77.0.40:6443 CLOSED` and `10.77.0.50:8080 CLOSED` after loading the rules (a bug of the first test: the one-shot listeners had been used up by the "before" probe; not a bug of the ruleset) — green: listeners made persistent, then `SYNTAX ok; after OPEN 10.77.0.20:30443; after CLOSED 10.77.0.20:443; after CLOSED 10.77.0.30:443; after CLOSED 10.77.0.30:30443; after OPEN 10.77.0.40:6443; after OPEN 10.77.0.50:8080; RELOAD ok`. Wired into E2E-service-cluster step 8 (fixtures/node-egress).

tdd: podman kube play of the shipped pod (init container, security context, mounts) — red 1: `cp: cannot open '/secrets/service-key/service-key' for reading: Permission denied` (podman has no fsGroup: render.py makes the Secret files readable, the way a kubelet with fsGroup does) — red 2: `invalid `service_policy.service_key_file`: cannot be read` (podman gives each container its own tmpfs for a Memory emptyDir; render.py uses a shared volume, Kubernetes shares the in-memory one) — green: pod up, `listening 0.0.0.0:8443`, `/health/live` 200, run as `999:999` with a read-only root file system. The unstaged variant: `invalid `service_policy.service_key_file`: requires a private regular file` (the refusal the init container exists to avoid).

tdd: E2E-service-cluster — red: `containerd serves: not within 30000 ms` (first run of the refactored probe: the unix socket path of the ttrpc listener was 107 bytes, which containerd refuses: `failed to create unix socket`; shortened in harness/containerd-node.mjs) — red: `the origin is healthy: a client that goes to it directly gets the image (1) … lookup registry-1.docker.io … no such host` (client containers have no alias for the fake hub; replaced by pulling another repository through the service while the blocked one is refused) — red: `after the service is back the same pull succeeds: … 403 Forbidden` (my scenario pulled the digest it had blocked earlier: a digest block holds in every repository, which is the product's documented behavior; the scenario now uses another image) — red: `ERR getaddrinfo ENOTFOUND firewall-standalone`, then `ERR connect ENETUNREACH 11.220.0.8:8080` (client containers are not on the service's network; the unapproved node is the fakes container) — green: `node tests/e2e/harness/run.mjs --only E2E-service-cluster` printed `E2E-service-cluster passed in 83.8 s`, `1 passed, 0 failed, 0 not run`.

tdd: E2E-service-cluster-probe after the refactor onto harness/containerd-node.mjs — red: `containerd serves: not within 30000 ms` (same socket path) — green: `E2E-service-cluster-probe passed in 13.2 s` (it passed in 16.5 s before the refactor).

tdd: kubeconform schema validation — red not observed (the manifests were valid at first use); positive control: a `replica: 1` typo gives `additional properties 'replica' not allowed` and exit 1. Green: `kubeconform -strict -kubernetes-version 1.36.0 -skip Kustomization deploy/kubernetes/*.yaml` printed `Summary: 10 resources found in 8 files - Valid: 9, Invalid: 0, Errors: 0, Skipped: 1`.

## Mutation probes (each: backup with sha256, one edit, narrow test, restore in a SEPARATE command, sha256 verified; helper `probe.sh` in the scratch directory)

| Probe | File and edit | Result |
|---|---|---|
| P1 | src/http/listener_admission.rs `peer_admitted`: `… || true` (admit everyone) | cluster_peer netns test FAILED (`an unapproved source is refused: 503 …`); listener_admission 3 tests FAILED. Restored, sha256 f94392b7… verified |
| P2 | same file: also admit RFC 1918 peers | cluster_peer netns test FAILED (the external 10.77.0.3 admitted); listener_admission 1 test FAILED (peer_admission_uses_the_actual_peer…). Restored, verified |
| P3 | deploy/kubernetes/service.yaml: `externalTrafficPolicy: Cluster` | `FINDING SVC-ETP`; kubeconform still says Valid (the schema cannot know). Restored, sha256 2fd5e2e0… verified |
| P4 | statefulset.yaml: claim `ReadWriteOnce` | `FINDING S-RWOP`; kubeconform Valid. Restored, sha256 1c934d2b… verified |
| P5 | configmap.yaml: `allowed_peer_cidrs = ["0.0.0.0/0"]` | cluster_peer shipped-config test FAILED (the binary refuses it); `FINDING CFG-CIDR`, `NP-NODES`; kubeconform Valid. Restored, sha256 12c5c375… verified |
| P6 | node/install-node.sh: the `server =` line left out | node_scripts 3 of 4 FAILED. Restored, sha256 2b2aff5d… verified |
| P7 | node/verify-node.sh: the per-registry override finding replaced by `true` | node_scripts verifier test FAILED. Restored, sha256 4ee5d157… verified |
| P7b | verify-node.sh: the host-table check replaced by `true` | node_scripts verifier test FAILED. Restored, verified |
| P8 | node/egress.nft: the final `reject` rule removed | in the namespace every target `OPEN` after loading; the fixture's output was compared with the map step 8 asserts, the scenario itself was not rerun with this mutation. Restored, sha256 1210d563… verified |
| P8b | egress.nft: `ip daddr $service4 accept` (any port) | `after OPEN 10.77.0.20:443` (not the map step 8 asserts; the scenario was not rerun with it). Restored, verified |
| P9 | statefulset.yaml: init command reduced to a plain `cp` | `FINDING K-KEYSTAGE`; `podman kube play`: `requires a private regular file`. Restored, sha256 1c934d2b… verified |
| P10 | install-node.sh (as P6) run through `E2E-service-cluster` | the scenario FAILED at `verify-node.sh accepts the installed node against the real containerd: FAIL: … does not name the server`. Restored, sha256 2b2aff5d… verified |

No probe was killed by a timeout or a signal; every restore was a separate command and `git status` afterwards listed only this slice's files.
Surviving probes: none of the twelve. Not probed (stated, not claimed): the scenario's own assertions on the recording proxy (a mutation of `recordingProxy` to allow the origin was not run; the control step 6 shows the recorder does see the origin without `server`), the pod-smoke assertions, and `render.py`.

## Checks (final tree)

See evidence/slice-26.md, "Final checks" (same run; the tdd-specific results are above).

## The stale build (a mistake of mine, caught, and what it changed)

My probe helper restored a mutated source file with `cp -p`, which keeps the OLD modification time, so cargo did not rebuild: the first full pass over the root test binaries (47 binaries in) ran against the build of mutation P2 (`peer_admitted` admitting RFC 1918 peers) and `listener_admission` failed with exactly P2's signature (15 passed, 1 failed) although the source file's sha256 was already verified equal to the original. Detected by that failure; the pass was discarded. The helper now touches the file after restoring; the sources were touched and rebuilt, `listener_admission` 16 passed, and ALL results quoted in evidence/slice-26.md "Final checks" are from after that fix (the clippy runs that preceded it were repeated too). Probes P3 to P10 touch no Rust source and are unaffected; P1 and P2 results were taken right after their own `apply`, which does rebuild.


# Fix round (answering reviews/slice-26/code-review.md and security-review.md)

Same procedure (/home/john/.claude/skills/agents/implement/AGENT.md). Baseline: `45f4ab8`, the tree at the end of the first round (uncommitted). Scratch under `.probation-scratch/s26b` (own target directory), deleted at the end.

## Cycles

tdd: oci_service `the_ns_a_client_sends_selects_the_registry_whose_host_it_names_and_an_unserved_ns_is_refused` and `the_docker_hub_names_are_one_registry_that_has_no_target` — red: `assertion left == right failed: the registry whose host is ns  left: 404 right: 200` and `docker.io: another registry's ns  left: 200 right: 404` — green: `cargo test --test oci_service` 51 passed (src/http/service_registry.rs: `oci_ns`, `oci_hosts`, `only_registry`). A first attempt to edit with an inline python heredoc did not apply (a tool hook swallowed it); the red above was re-observed before the edit was made by file.

tdd: oci_service `the_challenge_realm_keeps_the_ns_so_the_token_request_selects_the_same_registry` — red: `the realm names the registry the client meant: Bearer realm="https://packages.example.org/v2/token",service="probation",...` then, after the realm change, `assertion left == right failed: {"errors":[{"code":"NAME_UNKNOWN",...  left: 404 right: 200` (the token endpoint rejected the `ns` key) — green: 51 passed (oci_routes.rs `ns_of` and the realm query; serve.rs `token_scopes` accepts a shape-checked `ns`).

tdd: lock tests (`the_longest_mount_point_decides_the_type`, `network_and_fuse_types_are_refused_and_local_ones_are_not`, `a_data_directory_on_a_network_mount_is_refused_with_the_type_named`, `a_local_directory_is_accepted_and_the_switch_always_accepts`) — red not observed (written with the implementation); killed by P14 and P14c; the wiring in `App::start` and the config key are not covered by a test that can mount NFS here (stated). Clippy red: `identity_op: this operation has no effect  src/store/lock.rs:79 i + 3 < bytes.len() + 0` — green: clippy `-D warnings` exit 0 in all three sets.

tdd: check_kubernetes.test, exact finding sets (70 mutations, plus `--deployable`, plus an empty deployment) — red: the first run of the rewritten test, collecting mismatches: `a ClusterIP service ['SVC-PORT','SVC-TYPE'] vs ['SVC-TYPE']`, `a second Service ... SVC-PORT vs SVC-SELECTOR`, `a Secret in the manifests ['K-KIND','K-LIST'] vs ['K-KIND']`, `the claim in the kustomization ... + K-KIND`, `public_url without a port ... + SVC-PORT vs only CFG-PUBLIC` (my expectations were wrong; the checker's sets were right) and `FileNotFoundError ... empty/config.toml` (the checker crashed on a deployment with no config.toml: fixed) — green: `check_kubernetes.test: 73 checks hold (70 mutations, each producing exactly its named findings)`. The three holes the review found are now mutations that pass only through new checks: `a second ingress rule with no from` (NP-INGRESS), `an egress rule with no to` (NP-EGRESS), `loadBalancerSourceRanges` and `a headless clusterIP` (SVC-EXTRA), `a second Service` (SVC-ONE). Probe P27 removes the from-less check and the test fails (`mutation 'a second ingress rule with no from': expected exactly ['NP-INGRESS'], got []`).

tdd: node_scripts (9 tests: every file the installer writes, the imports line added once with a backup and rolled back, 14 refusals plus IPv6 and foreign files, legacy directories, 18 verifier failures, the service-pool check, the preload, online and egress classes, the firewall installer) — red: `install-node: a registry is mapped twice` for a single mapping (a `wc -l` of text with no trailing newline) and, for `--endpoint $'https://ok.example\nskip_verify = true'`, `the reason is named: install-node: quotes, backslashes and spaces are not accepted` (the control-character check was ineffective: command substitution strips a trailing newline; the review's F9 reproduced) — green: `cargo test --test node_scripts` 9 passed.

tdd: preload against the real containerd 2.2.0 (prototype) — red: `ctr: unknown service containerd.services.transfer.v1.Transfer` (no transfer plugin without a snapshotter), then `ctr images import --local --index-name REF` registered an INDEX of another digest (`sha256:75f2dd16...` instead of the manifest's `577b279f...`) and tried to unpack (`snapshotter not loaded: overlayfs`) — green: `--local --no-unpack --digests --base-name <repository>` gives `repository@sha256:577b279f...` of the manifest's own digest; `verify-node.sh --service-pool` prints `verify-node: ok`.

tdd: node firewall (install-firewall.sh, egress.nft, ingress.nft in a throwaway namespace) — red: an observation, not a failure: with the DNS reject removed (P28) TCP/53 stayed closed (the final TCP reset covers it), so the first fixture could not kill that mutation; UDP/53 was then added to the fixture (busybox nc gave both CLOSED before the rules: `udp-before CLOSED 10.77.0.53:53`; socat gave `OPEN`) — green: `udp-after OPEN 10.77.0.53:53; udp-after CLOSED 10.77.0.54:53`, `ingress OPEN 10.77.0.2`, `ingress CLOSED 10.77.0.3`, `ROLLBACK ok`; P28 and P29 now kill.

tdd: E2E-service-cluster, rewritten (two registries, per-registry routes and `?ns=`, credentials, legacy layout, CA pinning, preload, firewall) — red: `install-node.sh maps it: ... _default/hosts.toml exists and was not written by this script` (my legacy fixture wrote a hosts file by hand) — green: `E2E-service-cluster passed in 133.3 s`; the earlier runs of the first round are in the first-round section.

tdd: check_workflow.py cluster.yml rules and 22 mutations — red: `cluster.yml is not plain YAML: mapping values are not allowed here` (`run: python -m pip install --only-binary=:all: ...`, an unquoted colon) and `BYPASS: cluster.yml a download with no hash check` (the check accepted one hash for two downloads) — green: `check_workflow.test: 199 bypasses all fail, known-good passes`; `actionlint` on cluster.yml: no finding.

tdd: cluster_peer / listener tests after the config.toml move — red not observed (the shipped file is read from deploy/kubernetes/config.toml now); `#![cfg(unix)]` added.

## Mutation probes of the fix round (backup with sha256, one edit, narrow test, restore in a SEPARATE command that TOUCHES the file and verifies the sha256)

| Probe | File and edit | Result |
|---|---|---|
| P11 | service_registry.rs: Docker Hub's `docker.io` name removed | oci_service `the_docker_hub_names...` FAILED. Restored, sha256 eb096b4d... verified |
| P12 | the `ns` selection replaced by the old single-registry rule | both ns tests FAILED. Restored, verified |
| P13 | oci_routes.rs: the realm no longer carries the ns | the realm test FAILED. Restored, sha256 994f19ac... verified |
| P14, P14c | lock.rs: `fuse` no longer a network type; the refusal judged never | `network_and_fuse_types...` and `a_data_directory_on_a_network_mount...` FAILED. Restored, verified |
| P14b | lib.rs: the allow flag always true | NOT killed (no test can mount a network file system here; stated) |
| P15 | install-node.sh: the imports line never added to an existing config | node_scripts imports test FAILED |
| P16 | verify-node.sh: the legacy certificate check removed | node_scripts verifier test FAILED |
| P17 | verify-node.sh: the CA pin check removed | FAILED |
| P18 | install-node.sh: the preload digest check removed | preload test FAILED |
| P19 | verify-node.sh: a timeout counted as a closed egress | online test FAILED |
| P20 | install-firewall.sh: the list validation made a no-op | firewall installer test FAILED |
| P22 | service.yaml: `externalTrafficPolicy: Cluster` | `FINDING SVC-ETP`; kubeconform still `Valid` |
| P23 | deployment.yaml: strategy RollingUpdate | `FINDING S-RECREATE` |
| P24 | admission-policy.yaml: the policy allows Cluster | `FINDING VAP-ETP` |
| P25 | kustomization.yaml lists pvc.yaml | `K-LIST`, `K-PVC`, `K-KIND` |
| P26 | cluster.yml: no pipefail | `FAIL cluster.yml: defaults.run.shell must set pipefail` |
| P27 | check_kubernetes.py: the from-less ingress check removed | check_kubernetes.test FAILED (exact-set mismatch) |
| P28 | egress.nft: the DNS reject removed | `udp-after OPEN 10.77.0.54:53` (the fixture, and so the scenario's step 8, fails) |
| P29 | ingress.nft: the final drop removed | `ingress OPEN 10.77.0.3` (the fixture fails) |

A meaningless control (P21: an extra ignored flag added to install-node.sh) survived by design and is not a claim. Not probed: the scenario's recording proxy, the pod-smoke assertions, `render.py`, `run-kind-lane.sh` (not run), and the new e2e steps by mutation of the shipped scripts through the scenario itself (the scenario was not rerun with a mutated script in this round; the first round's P10 did that for the old installer).

Final checks of the fix round: evidence/slice-26.md, "Final checks" (same run).


# Recheck-1 round (answering reviews/slice-26/recheck-1.md)

Scratch `.probation-scratch/s26c` (own target directory), deleted at the end. Baseline: `45f4ab8` plus the uncommitted tree of the fix round.

## Cycles

tdd: network_filesystem (4 `App::start` tests through the `test-support` seam `store::lock::set_filesystem_probe`) — red: the first run, `Some(DataDir(Directory { path: "/var/lib/probation/state", source: PermissionDenied }))` (my test did not point `data_dir` at its temporary directory; test bug) then green: `cargo test --test network_filesystem` 4 passed. The refusal of nfs4, the switch and the fail-closed case were not observed red as such (the seam was written with them); P33, P34 and P34b kill them (fail open, always allow, negated flag).

tdd: service_registry `a_percent_encoded_ns_with_a_port_names_the_registry` — red not observed (written with the decode); P38 (the raw reading) kills it.

tdd: node_scripts, new and changed (13 tests): the drop-in speaks the main file's schema (v2, v3, three refusals), rollback removes only the inserted line, the SSL_CERT_DIR line and the empty directory, the baseline comparison, the firewall unit order and `fib daddr type local`, `verify-node.sh --firewall`, the kind lane script's control flow — red: the whole file after the installer change reported the old expectations (`the service CA is the only root` and the old systemd drop-in text), fixed; green: `cargo test --test node_scripts` 13 passed. The first run of each new test passed at once (the code was written with it): P30 to P32, P35, P37, P39, P40 show they fail when their line is broken.

tdd: E2E-service-cluster, the new steps — reds in order: (1) `verify-node.sh --prove-pin` hung for 20 minutes (the probe's ctr waited for an answer to a HEAD from `openssl s_server -www`; I killed the stuck ctr by pid, which then produced `connect: connection refused` from the killed server: an artefact) — fixed with `timeout 15`; (2) `mount source ... err: operation not permitted` from the CRI image service's native snapshotter — fixed by starting that daemon in a user and mount namespace (`unshare --user --map-root-user --mount`); (3) the CRI image listing truncates digests (`577b279fbb757`) — `--no-trunc` — green: `E2E-service-cluster passed in 147.4 s` with the configSchemas control (the old drop-in turns SystemdCgroup off), the populated-directory pin test and the CRI pulls.

tdd: check_kubernetes (the R12 and R9 gaps) — red: the three mutations the review described passed the checker before the new rules (`check_kubernetes: ok` on a VAP without UPDATE, a loosened type expression, a Role with `patch deployments`); green: `check_kubernetes.test: 82 checks hold (76 mutations ...)`, including the guide-versus-lane apply-order check. P41 removes the UPDATE rule from the checker and the test fails (`expected exactly ['VAP-ETP'], got []`).

tdd: cluster.yml (crictl install, comments) — green: `check_workflow.test: 199 bypasses all fail`; actionlint clean.

## Mutation probes of this round (backup with sha256, one edit, narrow test, restore in a SEPARATE command that touches the file and verifies the sha256)

| Probe | File and edit | Result |
|---|---|---|
| P30 | install-node.sh: the SSL_CERT_DIR line removed from the drop-in | node_scripts: 5 tests FAILED (installer output, verifier cases, pool, online, firewall) |
| P31 | install-node.sh: a version-2 main file gets the version-3 section | the schema test FAILED |
| P32 | run-kind-lane.sh: the trap keeps no status (the old `exit "$failed"` shape) | the lane control-flow test FAILED |
| P33 | lock.rs: an unclassifiable file system accepted | network_filesystem FAILED |
| P34 | lib.rs: the allow flag always true | network_filesystem 2 FAILED (the old P14b, now killed) |
| P34b | lib.rs: the allow flag negated | 3 FAILED |
| P35 | ingress.nft: one rule without `fib daddr type local` | the firewall ordering test FAILED |
| P37 | install-node.sh: rollback restores the whole backup | the rollback test FAILED |
| P38 | service_registry.rs: `ns` read raw | the encoded-port unit test FAILED |
| P39 | verify-node.sh: the baseline comparison off | the verifier test FAILED |
| P40 | verify-node.sh: a non-empty pinned directory accepted | the verifier test FAILED |
| P41 | check_kubernetes.py: UPDATE no longer required of the VAP | check_kubernetes.test FAILED |

Not probed: the new scenario steps by mutating the shipped scripts and rerunning E2E-service-cluster (the scenario was not rerun with a mutated script this round), `run-kind-lane.sh`'s assertions (never run), render.py.

Final checks of this round: evidence/slice-26.md, "Final checks of the recheck-1 round" (same run).


# Recheck-2 round (answering reviews/slice-26/recheck-2.md)

Scratch `.probation-scratch/s26d` (own target directory), deleted at the end. Baseline: `45f4ab8` plus the uncommitted tree of the previous rounds.

## Cycles

tdd: oci_service flake (`FakeOci::hold_next_blob`, the cancel seam) — red: the two load-flaky tests of the earlier rounds failed under load; green: 20 of 20 runs alone passed; P62 kills it when the cancellation is unobserved.

tdd: the M1 firewall unit and `verify-node.sh` step 4a, install/verify/rollback/lane-lib/RBAC lint tests (node_scripts 19, check_kubernetes.test 85 checks with 79 mutations) — each new test was written with its code; P42 to P61 show every one fails when its line is broken (below).

tdd: E2E-service-cluster after step 4a — red: `v2: verify-node.sh ... accepts it: FAIL: systemd's effective environment of containerd is SSL_CERT_FILE='unset' ... FAIL: cannot read /proc/2315/environ (run this as root)` (the scenario's verify-node.sh read this host's real systemd and containerd); green: the scenario's `fakeHost()` stand-in, `E2E-service-cluster passed in 145.5 s`.

## Mutation probes (backup with sha256, one edit, narrow test, restore with copy + touch, sha256 verified by the probe script and again afterwards against the backups: all 21 files identical)

| Probe | Edit | Result |
|---|---|---|
| P42 | service_registry.rs: the first matching registry wins for `ns` | KILLED (exit 101) |
| P43 | lock.rs: an unclassified file system passes | KILLED |
| P44 | lock.rs: virtiofs dropped from the network list | KILLED |
| P45 | firewall unit: not `PartOf` containerd | KILLED |
| P46 | firewall unit: `ExecStop` not tolerant (no `-`) | KILLED |
| P47 | verify-node.sh: systemd's effective environment unchecked | KILLED |
| P48 | verify-node.sh: the running daemon's environment unchecked | KILLED |
| P49 | verify-node.sh: the first assignment wins instead of the last | KILLED |
| P50 | verify-node.sh: the roots directory mode unchecked | KILLED |
| P51 | install-node.sh: no check that the roots directory is empty | KILLED |
| P52 | install-node.sh: an old containerd accepted | KILLED |
| P53 | verify-node.sh: an old containerd accepted | KILLED |
| P54 | install-node.sh: `_default` always removed on rollback | KILLED |
| P55 | verify-node.sh: the baseline taken from a stale file | KILLED |
| P56 | install-node.sh: the import line checked late | KILLED |
| P57 | lane-lib.sh: the helper always refuses | KILLED |
| P58 | lane-lib.sh: an empty run passes | KILLED |
| P59 | lane-lib.sh: any source accepted | KILLED |
| P60 | check_kubernetes.py: Role access to secrets unchecked | KILLED (exact-set mismatch) |
| P61 | check_kubernetes.py: Role access to configmaps unchecked | KILLED |
| P62 | tests/common/oci.rs: the flake seam's cancel unobserved | KILLED |

Every probe ended with `restored sha256 ok`. Not probed: the scenario's `fakeHost()` stand-in and the kind lane assertions (never run).

## Runs that do not count

The first E2E batch overlapped the probes (they mutate repo files while images build) and failed at `compose run server migrate: exit status 126`; the second collided with a duplicate launch of the same batch (same compose project, work directory and network: `IPAM error: requested ip address 11.220.0.12 is already allocated`). Both were discarded, their images and volume removed by ID; the authoritative runs are in evidence/slice-26.md, "Recheck-2 round".


# Recheck-3 round (answering reviews/slice-26/recheck-3.md)

Scratch `.probation-scratch/s26e`, deleted at the end. Baseline: `45f4ab8` plus the uncommitted tree.

## Cycles

tdd: the_firewall_installer_starts_the_unit_and_checks_it_is_active_with_both_tables_loaded — red: the test failed on the first run of node_scripts (the installer loaded with `nft -f`, never `systemctl enable`/`restart`, no `--load`); green: `cargo test --test node_scripts` 24 passed.
tdd: the_firewall_check_of_the_verifier_needs_the_unit_active_as_well_as_the_tables — red: FAILED (no `is-active` check); green: same run.
tdd: a_commented_out_imports_line_is_not_taken_for_the_import — red: FAILED (the install wrote nothing: the commented line was taken for the import); green after anchoring the match.
tdd: the_verifier_writes_nothing_next_to_the_containerd_config — red: FAILED (a read-only configuration directory made the verifier fail: `cannot write next to`); green after the private temporary directory and trap.
tdd: rollback_deletes_a_stale_backup_of_an_older_install_and_never_restores_it — red not observed (a characterization of existing `rm -f`; it replaces a vacuous assertion).
tdd: the_kind_lane_assertion_helpers_... (`denied`, the restore trap with a stub kubectl) and check_kubernetes.test (phase A) — red: observed only for check_kubernetes.test (`AssertionError: phase A must not delete only probation-ingress`, before the doc was corrected); the node_scripts lane tests were written before the lane-lib code and were first run green; probes P63 to P67 and P76b show each fails when its line is broken.
tdd: a_registry_targeting_any_docker_hub_host_answers_to_every_hub_name — red not observed separately (written with the fix); P75 kills it.
Checks: `cargo test --lib service_registry` 4 passed; the E2E of the five scenarios (evidence/slice-26.md, "Recheck-3 round").

## Mutation probes (probe.py: backup with sha256, one edit, narrow test, restore with copy + touch, sha256 verified; run BEFORE the E2E, nothing overlapping)

| Probe | Edit | Result |
|---|---|---|
| P63 | lane-lib.sh: `denied` back to `kubectl ... \| grep -q` | KILLED (lane helper test) |
| P64 | lane-lib.sh: `finish` does not restore the lifted policies | KILLED |
| P65 | lane-lib.sh: `lift_ingress_policy` does not set the flag | KILLED |
| P66 | lane-lib.sh: `restore_policies` without `apply -k` | KILLED |
| P67 | lane-lib.sh: `restore_policies` keeps the flag (restores twice) | KILLED |
| P68 | install-firewall.sh: no `systemctl restart` | KILLED |
| P69 | install-firewall.sh: no `is-active` check | KILLED |
| P70 | install-firewall.sh: a direct `nft -f` load | KILLED |
| P71 | install-firewall.sh: no table check | KILLED |
| P72 | verify-node.sh: `--firewall` without `is-active` | KILLED |
| P73 | install-node.sh: `imports` matched anywhere in the file | KILLED |
| P74 | verify-node.sh: the baseline copy next to the config | KILLED |
| P75 | service_registry.rs: only `registry-1.docker.io` aliased | KILLED |
| P76 | operations.md: one occurrence of the policy name changed | SURVIVED (a weak probe: the name occurs elsewhere in the guide; not a claim) |
| P76b | operations.md: the guide tells the reader to delete only `probation-ingress` | KILLED (check_kubernetes.test) |

Every restore: `restored sha256 ok`. Not probed: the lane's phase A control flow beyond the helpers (never run), the Calico patch snippet (run once against the real manifest).

