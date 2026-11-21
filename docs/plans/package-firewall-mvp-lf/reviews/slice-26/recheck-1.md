# Slice 26 recheck 1 (security lens, read-only)

Subject: uncommitted slice 26 after the fix round, branch `slice5-native-ci` at `45f4ab8`. No code was edited. Scratch: `/home/john/go/src/github.com/postfix/.probation-scratch/r26` (deleted at the end). No node script was run against the real /etc, containerd or nftables (disposable config trees and `containerd config dump` only; no containers started).

**Verdict: FAIL.** Four blocking findings (R1 to R4), the first two reproduced here, one of them (R1) a security claim that is false on Debian/Ubuntu-style nodes.

## What ran here (all in `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`)

| Check | Result |
|---|---|
| cluster_peer `--include-ignored` | 2 passed |
| node_scripts | 9 passed |
| listener_admission | 16 passed |
| oci_service | 53 passed (316 s) |
| oci_registry | 18 passed |
| authorization_read_once | 4 passed |
| lib `lock` | 26 passed (incl. 4 network_filesystem_tests) |
| check_kubernetes.test.py | 73 checks hold (70 mutations) |
| check_workflow.test.py | 199 bypasses all fail |
| 17 extra mutations of my own on check_kubernetes.py | 14 caught; 3 gaps (R12) |
| E2E service-cluster, kind, cri-node, containerd/ctr node runs | NOT re-run by me (needs the image stack); the evidence's E2E claims are taken as stated, not re-verified |

No regression found in slices 17 to 26 in the suites above.

## Blocking

**R1 (High, security) The CA pin does not pin on a node that has a certificate directory. Sec F1 is NOT fixed.**
`deploy/kubernetes/node/install-node.sh:185-191`, `verify-node.sh:121-124`, `docs/operations.md:2083`, evidence F1.
The installer sets only `SSL_CERT_FILE=<service CA>` and states containerd then trusts "ONLY the service CA". Go's `loadSystemRoots` (`/usr/local/go/src/crypto/x509/root_unix.go:32`) replaces the file list from `SSL_CERT_FILE` but still reads the default certificate DIRECTORIES (`/etc/ssl/certs`, `/etc/pki/tls/certs`) unless `SSL_CERT_DIR` is set. Reproduced with a 10-line Go program on this Debian host: default pool 149 roots; `SSL_CERT_FILE=ca.pem` 150 roots (all system CAs still trusted, plus ours); `SSL_CERT_FILE=ca.pem SSL_CERT_DIR=/nonexistent` 1 root. Failure scenario: an attacker who redirects the endpoint name and holds a public-CA certificate for it answers the node's pulls with arbitrary images, exactly the attack F1 described, while `verify-node.sh` reports ok. The e2e "reproduction" passes because the harness's containerd runs where no certificate directory exists; it proves only the file half.
Fix: the same systemd drop-in also sets `SSL_CERT_DIR` to a directory that holds only the service CA (or a nonexistent path); `verify-node.sh` requires both lines; test the effective trust set against a pool that has a directory source (the Go program above is enough), and put the second CA into a directory source in `E2E-service-cluster`. Correct the sentence at operations.md:2083 ("the ONLY root set") until then.

**R2 (High) `install-node.sh` corrupts the CRI configuration of a node whose main config is `version = 2`.**
`install-node.sh:158-162` always writes the drop-in as `version = 3`. With a version 2 main file, containerd 2.2.0 lets the imported `version` win and ignores the main file's v2 CRI sections. Reproduced with `containerd --config etc/config.toml config dump` (v2 main with `SystemdCgroup = true`, `sandbox_image = pause:3.9`, `config_path = certs.d:docker/certs.d`): control (main alone) keeps `SystemdCgroup = true`, `pause:3.9`; with the installed drop-in the dump shows `version = 3`, `SystemdCgroup = false`, `sandbox = pause:3.10.1`, six "Ignoring unknown key in TOML for plugin io.containerd.grpc.v1.cri" warnings. Scenario: the first restart of containerd on a kubeadm node that was upgraded from 1.7 (v2 config) switches runc to the cgroupfs driver while the kubelet uses systemd, and every pod fails to start. `verify-node.sh` only reads `config_path`, which looks right, so it passes. All tests use `version = 3` (`tests/node_scripts.rs:180-200`, `service-cluster.mjs:207`, `containerd-node.mjs:69`).
Verified fix: write the drop-in with no `version` line and, for a v2 main file, the section `[plugins."io.containerd.grpc.v1.cri".registry] config_path = '<dir>'` (dump keeps SystemdCgroup, pause image and sets the path; a v3 section without a version line is NOT applied to a v2 main file). Detect the main file's `version`, refuse an unknown one, add a v2 case to node_scripts and a real-containerd dump comparison (baseline vs after, only `config_path` may differ) to verify-node.

**R3 (High) `run-kind-lane.sh` exits 0 when the script aborts. The `kind` and `cri-node` jobs can go green without running anything.**
`tests/e2e/cluster/run-kind-lane.sh:11,28-29`: `set -e` plus `trap finish EXIT` where `finish` ends with `exit "$failed"`; an abort (a failing `kind create`, `docker build`, `kubectl apply -k`, a VAP race in the negative control at line 138-139) runs the trap, which replaces the exit status by `$failed`, still 0. Reproduced with a 6-line script (`exit=0`). This is the false pass the lane exists to avoid, and a first hosted run would "pass" vacuously. Fix: in `finish` capture `rc=$?` first and `exit $(( rc != 0 ? rc : failed ))`; add a test that a crashing step makes the script non-zero (the check_workflow tests do not look inside the script).

**R4 (blocking by the stated rule) The network-filesystem refusal is wired by reading but not provably.**
`src/lib.rs:331-332` calls `store::lock::refuse_network_filesystem(&deps.config.data_dir, deps.config.allow_network_data_dir)` before `open_and_recover`; it is the only production entry (the other `App::start` call sites are `src/lib.rs:657-676` and a test in `src/osv/mod.rs:1454`), and the config key is plumbed (`src/config.rs`). I found no bypass. But P14b is right: an always-allow edit of that line, or a negated `allow`, survives every test; the 4 new tests exercise only `judge_filesystem`, `is_network_filesystem` and `filesystem_type` on text. Fix: a seam, e.g. `AppDeps { fs_type_probe: Option<Box<dyn Fn(&Path) -> Option<String> + Send + Sync>> }` (test-support only) or make `refuse_network_filesystem` take the mountinfo text from `deps`; add two `App::start` tests: a probe returning `nfs4` makes `start` return `StartupError::DataDir(Lock(NetworkFilesystem{..}))` and starts nothing; the same with `allow_network_data_dir = true` starts. Notes (Low): an unreadable `/proc/self/mountinfo` fails open (`lock.rs` `else { return Ok(()) }`); the table lacks gfs2, ocfs2, gpfs, beegfs, virtiofs (not statfs f_type based: it is the mountinfo type string, which operations.md:2143 states correctly); tmpfs and overlay are correctly allowed, `fuseblk` deliberately allowed.

## Medium

**R5 The D1 procedure contradicts the shipped NetworkPolicy; the kind lane cannot pass as authored.**
`networkpolicy.yaml:31-40` lets in only the approved node addresses, so under an enforcing CNI an unapproved node, an external host and a pod are DROPPED before the service (timeout, empty body), yet `operations.md:2093-2098` and `run-kind-lane.sh:131-133` require the body `NETWORK_NOT_ALLOWED`. The negative control (`run-kind-lane.sh:139-141`, doc 2103) probes the pool node (worker 1, IP1) after switching to `Cluster`: the source becomes IP1 (or the tunnel address), which is neither in `allowed_peer_cidrs` (only IP2) nor in the policy, so the control stays "refused" or times out: it cannot turn green. Probing an approved non-pool node under Cluster is what would show the SNAT admission. Operations.md:2105 says the kind lane "is these checks"; it is not runnable as written. Decide: require the body only with the NetworkPolicy lifted for the check, or accept a timeout as refusal for the policy layer plus a body check with the policy removed; make the control probe an approved node address.

**R6 The documented apply order cannot work.** `operations.md:2057-2064`: `kubectl -n probation create secret ...` and `kubectl apply -f pvc.yaml` come before anything creates the namespace (namespace.yaml is only inside the kustomization). Literal execution fails at the first command. The lane script has the right order (`run-kind-lane.sh:105-114`: namespace, secrets, pvc, `apply -k`). `kubectl apply -k` itself does not create the PVC (correct, by design; it must not be pruned), delete safety is as documented.

**R7 Overstated `cri-node`.** `.github/workflows/cluster.yml:167-168` says "then a pod pulled through the CRI plugin ... and an unmapped registry refused"; the evidence (Lane 18) says "its pod-pull assertions are listed and one is explicitly skipped". `run-kind-lane.sh:68-80` has NO pod pull and no registry: three `expect` lines (installer runs, verifier offline, `install-firewall.sh --no-load`) and one `skipped`. It passes `--ca /etc/ssl/certs/ca-certificates.crt` (pins nothing). The job name `cri-node` promises more than it tests; it also builds and loads the full image for nothing. Lane 18 and the comment must say "installer/verifier smoke on a kind node; CRI pull not attempted".

**R8 Weak assertions in the kind lane.** (a) Lines 106, 115, 116, 148 are `! cmd | grep -q created/patched/.`: any failure (API timeout, image pull, syntax) passes, and the VAP checks right after `apply -k` can race the policy becoming active (a patch that succeeds leaves the Service on Cluster for all later D1 steps). Require the denial text (`denied request`, `violates PodSecurity`). (b) Line 149 is named "the eviction API refuses (429)" but only reads `.spec.minAvailable`. (c) The fence check (lines 164-166) holds trivially: the control plane does not replace a pod of a node for about 5 minutes, the check waits 90 s. (d) The RWOP step is skipped unless `RWOP_STORAGE_CLASS` is set; the skip is printed honestly, but with kind's default class the PVC may never bind (the doc says its provisioner is not RWOP), so the default lane likely stalls at `rollout status` before any D1 check: unverified either way. Also unverified: Calico's pool CIDR against the kind `podSubnet` 10.244.0.0/16 (the manifest is applied unedited).

**R9 The optional operator Role grants an exec-equivalent.** `optional/operator-role.yaml:17-19` allows `patch`/`update` on `deployments`: adding a sidecar (or changing the command) to the service pod gives a process on the pod's loopback, which the service always admits, i.e. an approved node, the exact reason the comment gives for excluding `pods/exec`. restricted Pod Security does not prevent a sidecar. Either narrow it (`patch` of `deployments` only through a controller, `resourceNames`, or document it as node-equivalent) and state the equivalence in operations.md:2077; the checker does not flag it (R12).

**R10 `egress.nft` and the unit, lockout and claim accuracy.** No SSH lockout: inbound sessions are `established`, loopback and ICMP/UDP are untouched, IPv6 mirrors IPv4. But: (a) `operations.md:2115` labels `--dns4 <cluster resolver>`; the reject at `egress.nft:32` also refuses the host's own upstream resolver (systemd-resolved forwarding, DHCP resolver, VPC resolver), so the node cannot resolve the endpoint name unless the operator lists it, and the doc example steers to the wrong address. (b) The doc says "Pod traffic is forwarded and not affected"; `hostNetwork` pods (CNI agents, CSI node plugins, log shippers, kube-proxy) emit via OUTPUT and are restricted by the same rules (also after the output-hook DNAT, so an API server outside `cluster4` is refused for them as for the kubelet). (c) `probation-node-firewall.service:5-7` orders only before `network-pre.target`, kubelet and containerd; Debian's `nftables.service` begins with `flush ruleset` and is not ordered against it, so at boot the tables can be wiped silently (fail-open egress). Add `After=nftables.service` (or `Before` it plus a re-assert) and a verify-node check that both tables exist. (d) `--rollback` is safe (tables deleted, no flush), but with `--root` it leaves loaded tables by design; it does not `daemon-reload` after removing the unit.

**R11 `ingress.nft:17-19` matches forwarded traffic, not only locally destined.** `tcp dport 30443 ... drop` at prerouting/raw also drops a pod's connection through this node to any host's port 30443 (e.g. a pod on an approved node reaching the endpoint) before masquerade, contradicting the doc's "a pod on an approved node (admitted when the CNI masquerades)". Add `fib daddr type local` to the three rules.

**R12 check_kubernetes.py gaps (my mutations).** Removing `UPDATE` from the VAP `operations` passes (`kubectl edit` to Cluster would no longer be refused); loosening the type expression to `in ['NodePort','LoadBalancer']` passes; a Role granting `patch deployments` passes. The 70 shipped mutations are real (exact finding sets), these are not among them. Rules caught: expression `!= 'Cluster'`, Warn action, wrong namespace, Ignore failure policy, name check removed, replicas 2, RollingUpdate, RWO, pvc in kustomization, suffix disabled, Cluster policy, privilege escalation, hostNetwork, unequal images; `--deployable` refuses the placeholder digest in both containers.

**R13 Rollback can overwrite later edits.** `install-node.sh:85-86,175`: the backup is taken once and restored whole by `--rollback`; edits an operator made to `config.toml` after the install (new runtime options) are lost; also a stale backup left by a failed run is reused. Remove only the marker line, or compare before restoring.

## Low

- `?ns=` is compared raw: containerd/Docker may send `ns=host%3A5000` (percent-encoded colon); `src/http/service_registry.rs` `oci_ns` and `oci_routes.rs` `ns_of` do not decode, so a registry with a port fails closed (404), never crosses registries. Add a test with an encoded port.
- Behavior change to state in release notes: a single-registry setup now refuses a client `ns` that is not the registry's host (a Docker Hub mirror host configured as the only registry now 404s for `ns=docker.io`). Tests assert it; the spec-change list mentions it. Cross-registry confusion is closed: the registry id comes from the selected route, same-named repositories are separate; the token realm keeps `ns` (tested).
- `install-node.sh:177-181` inserts `imports` after the first `version =` line even if that line is inside a table when no top-level `version` exists.
- `operations.md:2117` "there is no second server to try" is unqualified; the proven scope is `ctr` against containerd 2.2.0 (line 2109 says so, the closing section covers the CRI). The `auth` per-registry suggestion at 2139 is unverified. D1 is stated OPEN (2039, 2167), private-registry claims are limited to `ctr --user` (2139): both honest.
- `networkpolicy.yaml:29` refers to `configmap.yaml`; the file is `config.toml`.

## Per-finding status (earlier round)

| Finding | Status |
|---|---|
| H1 preload / sec F3 | Fixed and tested with real ctr (digest check, refusal, store). CRI/kubelet use not run: stays AUTHORED. |
| H2 multi-registry | Fixed in code and tests (R: encoded `ns` Low). |
| H3 D1 procedure | NOT fixed: the written check contradicts the NetworkPolicy and the control probes the wrong node (R5). |
| H4 CI | Partly: cluster.yml is sound (SHA pins, `contents: read`, `bash -eo pipefail`, no `pull_request_target`, hashed downloads, honest comments except R7), but the `kind`/`cri-node` script is false-green on abort (R3). |
| M1, M6, M7 | Fixed as designed (Recreate over RWOP claim outside the kustomization, hash-suffixed ConfigMap rolls the pod). Rendered-object validity only by kubeconform. |
| M2 imports line | Works for v3; breaks v2 (R2). |
| M3, M4 | Authored; checker gaps R12. |
| M5 | Honest (ctr `--user` only). |
| M8, sec F7 to F10 | Installer/verifier validation fine; firewall points R10, R11. |
| sec F1 | NOT fixed (R1). |
| sec F2 legacy certs.d | Fixed (refused by both scripts, reproduced earlier). |
| sec F11 | Classifier tested; wiring untested (R4). |
| sec F13 | Fixed (digest pin, 127.0.0.1 bind). |

## Honesty check of lanes

The Lanes table is accurate except: Lane 14/18 wording for `cri-node` (R7); Lane 8 "CA pinning: reproduced and rejected with it" is true only for the file source (R1); Lane 15 to 21 are correctly AUTHORED, NOT EXECUTED. VAP/VAPB: the CEL expressions are correct on reading (a second name, a non-NodePort type, a missing or non-Local `externalTrafficPolicy` and `externalIPs` each refused; binding `Deny`, namespace selector `kubernetes.io/metadata.name: probation`, UPDATE included); enforcement on a cluster is not run.

## To clear this recheck

R1 to R4 fixed with tests, R5 to R8 and R10 to R11 corrected or documented, R12 gaps closed in the checker with mutations, then a recheck of R1/R2 against containerd 2.2.0 with a certificate directory and a v2 main config.
