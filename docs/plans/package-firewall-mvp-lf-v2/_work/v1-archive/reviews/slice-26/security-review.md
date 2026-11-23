# Slice 26 security review: cluster endpoint, approved-node trust, no upstream fallback

Scope: the uncommitted slice 26 tree at `45f4ab8` (branch `slice5-native-ci`): `deploy/kubernetes/`, `deploy/kubernetes/node/`, `tests/cluster_peer.rs`, `tests/node_scripts.rs`, `tests/e2e/scenarios/service-cluster.mjs`, `tests/e2e/harness/containerd-node.mjs`, `tests/e2e/native/check_kubernetes.py`, `tests/e2e/fixtures/{kube-play,node-egress}`, `docs/operations.md` section 21. Read-only: no code was edited. Also read: `src/http/listener_admission.rs` (`peer_admitted`), `src/store/lock.rs`.

Method: reading plus two small experiments against the pinned `containerd`/`ctr` 2.2.0 in a disposable root (own containerd, own loopback TLS server, throwaway CAs; scratch under `.probation-scratch/s26-secrev`, deleted). No Kubernetes was available, so every kube-proxy, CNI, CSI and kubelet statement below is analysis, not observation, and is labelled "unverified".

Result: no Critical or High finding. 4 Medium, 9 Low/Info. The two Medium findings on the node runtime (F1, F2) were reproduced.

## Findings

### F1 Medium: the service CA is added to the system roots, not pinned (reproduced)

`deploy/kubernetes/node/install-node.sh:51-54` writes `ca = ".../probation-ca.pem"` in `_default/hosts.toml`. Section 21 says "the CA that signed it is the one file `install-node.sh` distributes", and `verify-node.sh:79` proves the endpoint answers with `curl --cacert "$ca"`.

Observed with containerd 2.2.0 `ctr content fetch --hosts-dir` (the same hosts-directory resolver the CRI plugin uses): the server's certificate was signed by CA1; `hosts.toml` named only `ca = CA2`.
- With CA1 absent from the system pool: `x509: certificate signed by unknown authority`.
- With CA1 in the system pool (`SSL_CERT_FILE=ca1.pem`): the TLS handshake succeeded and the request reached the server (404).
So `ca` appends to the system pool. Any certificate for the endpoint name from any CA the node trusts (public CAs, an enterprise root in the OS bundle) is accepted by the runtime.

Exploit: an attacker who can redirect the endpoint name (DNS or ARP/route hijack on the node network, a compromised internal DNS) and obtains a certificate for that name from any trusted CA (an internal PKI that issues to many teams; a public CA when the name is public) answers the node's pulls with arbitrary images. That is a complete bypass of the firewall for those pulls. `verify-node.sh --online` cannot detect it, because `curl --cacert` replaces the roots, so the check gives false assurance about pinning.

Mitigation: say the truth in section 21 (the CA is additive); require an endpoint name that no public CA can certify and a private PKI whose root is not in the node bundle; and make the runtime trust only the service CA: a containerd systemd drop-in `Environment=SSL_CERT_FILE=<certs-dir>/_default/probation-ca.pem` (Go honours it; re-run the experiment above as the acceptance check). Have `verify-node.sh` check the drop-in or the unit's environment.

### F2 Medium: the verifier skips per-registry directories that have no `hosts.toml`; containerd then goes to the origin (reproduced)

`verify-node.sh:58`: `[ -e "$dir/hosts.toml" ] || continue`. `install-node.sh:38-40` only inspects `_default/hosts.toml`.

Observed: `_default/hosts.toml` with `server` pointing at a dead endpoint, plus `certs.d/localhost:18999/ca.crt` and no `hosts.toml`: `ctr content fetch localhost:18999/foo/bar:latest` connected to the origin itself on 18999 (the legacy certificate-directory layout configures the registry's own address). A dead `server` would have failed the fetch, so the per-registry directory wins.

Exploit: not an attacker action, a misconfiguration the acceptance gate misses. A node with an old Docker-style `/etc/containerd/certs.d/docker.io/ca.crt` (or any `<registry>/*.crt|*.cert|*.key` left from a private-registry setup) passes `verify-node.sh` and `check_kubernetes.py` and still pulls that registry directly. The claim "no upstream fallback" is false for that registry, and the egress rule is the only remaining backstop.

Mitigation: in step 2 flag every non-`_default` directory that is not a valid endpoint-only `hosts.toml` (any directory without `hosts.toml` is a finding; also flag `*.crt`, `*.cert`, `*.key` files). Have `install-node.sh` refuse the same.

### F3 Medium: the service's own image cannot be pulled on a configured node (undocumented bootstrap)

`statefulset.yaml:60,82` (`imagePullPolicy: IfNotPresent`), `operations.md` section 21 "The service pool and the approved nodes", "Planned replacement, fencing and node loss".

If a service-pool node is an approved node (the natural case: its address is in `allowed_peer_cidrs`, and `service4` in `egress.nft` lists the pool), its containerd resolves the service image through the service, which is down or not yet started. After a node loss, a rollout to another pool node, or a first install, the pod sits in `ImagePullBackOff` with nothing to repair it. Nothing says: pre-load the image on every pool node (`ctr images pull` from the origin before installing, or an image pre-pull step), keep pool nodes outside the egress rule, or serve the service image from a registry that is not routed through the service.

Exploit scenario: an outage during the documented node-loss procedure (step 4, "wait for Ready on another pool node") cannot finish. The operator's quickest recovery is removing `config_path`/`egress.nft` on that node, after which the node pulls everything from origins and stays that way. Fail-closed turns into an unplanned bypass.

Mitigation: add a pre-load requirement and a verify step ("the service image digest is present in the node's content store") to section 21 and `verify-node.sh`; state explicitly whether pool nodes get the node configuration.

### F4 Medium: D1 rests on one mechanism with no backstop (unverified in a cluster)

`service.yaml:14` is the only guard. Section 21 says so: kube-proxy behaviour was not run (lane 12 open).

1. If `externalTrafficPolicy` becomes `Cluster` (a `kubectl edit`, a Helm overlay, a kustomize patch, a second Service object), every host that reaches any node's NodePort is admitted as that node. `check_kubernetes.py` runs only on the repository copy; nothing in the cluster rejects the change (no ValidatingAdmissionPolicy is shipped).
2. `check_kubernetes.py` does `one("Service")` for every `SVC-*` check (first Service only) and never counts Services: a second Service in the directory (a `LoadBalancer` with `Cluster` policy, or a Service with `externalIPs`) selecting the same pod is accepted and `K-LIST` lists it as expected. False assurance in the static check.
3. A node with a public address exposes NodePort 30443 to the internet; the service's source check is the only gate. Neither cloud security group nor host input rule restriction of 30443 to the approved addresses is shipped or documented (the egress file exists, an ingress counterpart does not). With F4.1 or any D1 failure this is the difference between "refused" and "admitted".
4. The NetworkPolicy ingress ipBlocks do not help in the failure case: under `Cluster` policy the source IS an approved node address.

Mitigation: ship the backstop: a ValidatingAdmissionPolicy that denies `externalTrafficPolicy != Local` on the `probation` Service, and a documented cloud security group or `nft` input rule limiting 30443 to the approved addresses; make `check_kubernetes.py` assert exactly one Service and iterate all Services.

### F5 Low: who counts as an "approved node" is wider than section 21 says, and the narrower reading is also unverified

`src/http/listener_admission.rs:44-47` admits loopback and any peer in the list.
- Loopback: any holder of `pods/portforward`, `pods/exec` or `pods/ephemeralcontainers` in namespace `probation` reaches the endpoint from 127.0.0.1 inside the pod and is admitted (`kubectl port-forward` connects from the pod's loopback). Section 21 never mentions it. Impact is bounded (an admitted peer gets policy-judged pulls, not a policy bypass), but RBAC on that namespace becomes part of the trust boundary and the guide should say so.
- hostNetwork pods and any host process on an approved node arrive as the node address (admitted). The restricted Pod Security level is enforced only in the `probation` namespace; `kube-system` and others may run hostNetwork pods. Accepted by C1022 ("every workload on an approved node can use the service"), but the sentence is also only true for ordinary pods when the CNI masquerades pod traffic to the NodePort address; with no masquerade a pod appears as its pod IP and is refused. The D1 checks in section 21 test only an unapproved node and an external host. Add a pod on an approved node and a hostNetwork pod as expected results, so the actual behaviour of the cluster is recorded (unverified).
- Hairpin and ClusterIP: the Service also has a ClusterIP. A pod calling ClusterIP:8443 or its own node's NodePort may or may not be SNATed depending on kube-proxy `masqueradeAll`, `clusterCIDR` and the CNI. Add both calls to the D1 check list (expected: refused unless the CNI SNATs to an approved node address, in which case the pod is that node).

### F6 Low: NAT, balancer and L2 limits of source-address trust are not stated

Section 21 "One cluster endpoint, DNS and TLS" says a balancer must pass the peer through, but not what to do when it cannot. An operator who sees refusals behind an SNAT balancer or NAT gateway will add the balancer's address to `allowed_peer_cidrs` and the NetworkPolicy, which admits everything behind it. State: never list a balancer, NAT gateway or proxy address; nodes behind a shared NAT cannot be separately approved. Also state that source-address trust assumes the node network prevents address spoofing (cloud anti-spoof, no shared L2 with untrusted hosts); an attacker on the same L2 segment who can ARP-poison can complete the TLS handshake as an approved node. `trusted_proxies` is correctly ignored for admission (`peer_admitted` takes the TCP peer only; `tests/cluster_peer.rs` shows forged `X-Forwarded-For`, `X-Real-IP`, `Forwarded` change nothing), but `check_kubernetes.py` does not assert `[service_policy] trusted_proxies` stays absent. It only affects spool owner accounting (`src/http/spool.rs:62`), yet add `CFG-PROXIES`.

### F7 Low: `egress.nft` gaps (reasoning; the shipped checks ran in a netns)

`deploy/kubernetes/node/egress.nft:20-31`.
- TCP only: a node-originated DNS fallback over TCP/53 to a resolver outside `cluster4` (a public or cloud link-local resolver) is reset; large answers fail intermittently. UDP is untouched on purpose (header, line 8), which also leaves DNS-tunnel exfiltration open.
- No `ct state invalid drop` before the final reject; harmless for new connections, noted for completeness.
- IPv6: the `inet` table plus `meta l4proto tcp` covers v6 (a registry over IPv6 or NAT64 `64:ff9b::/96` is rejected). There is no `service6` rule, so an AAAA-only endpoint is unreachable (availability only).
- `cluster4` (all of 10/8, 172.16/12, 192.168/16) is accepted on every port, so listing the service address with a port restriction is moot on private networks, and 169.254.169.254 is closed for TCP unless the operator lists it (good, but the guide should name it: kubelet credential providers on cloud nodes need it).
- Not persisted; the guide says "keep it in the node's boot configuration" without a mechanism. Pod traffic is forwarded and unaffected by design; a pod with `CAP_NET_ADMIN` and hostNetwork could delete the table (node root defeats everything; the PSS-restricted namespace is the only gate).

### F8 Low: NetworkPolicy egress is broader than the service needs

`deploy/kubernetes/networkpolicy.yaml:63-75`: any public address on 443. A compromised or SSRF-driven service process can reach any public host and exfiltrate the service key or the data. IPv4 `except` omits `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4` and the cluster's own node and API-server public addresses (a managed control plane is usually on public 443; no token is mounted, but anonymous endpoints answer). The DNS rule allows the whole kube-dns upstream (tunnelling) and excludes NodeLocal DNSCache (169.254.20.10 is inside the excluded range), an availability trap. Cloud metadata `169.254.169.254` IS excluded for IPv4. IPv6 egress is denied (no v6 ipBlock). Suggest a FQDN-aware policy where the CNI supports it, listing the upstream hosts; document the rest as accepted.

### F9 Low: installer input validation accepts newlines (reproduced)

`install-node.sh:33-35` validates the endpoint with `printf | grep -Eq`, which passes when ANY line matches. `--endpoint "$(printf 'https://ok.example\nskip_verify = true')"` exits 0 and writes a `hosts.toml` whose `server` string spans two lines (invalid TOML; containerd refuses it; the verifier's exact `grep -qxF` also fails). No injection is possible because quotes and backslashes are rejected, so it is a fail-closed breakage, but a provisioning system that feeds an untrusted hostname into root's script should get a clear error: reject any value containing a newline (`case $endpoint in *"$(printf '\n')"*)`). The `--ca` path is only read. Temporary files use a predictable suffix (`$1.tmp.$$`) inside root-owned directories (`/etc/containerd/certs.d`); not exploitable unless a lower-privilege user can write there. The final instruction line also echoes the multi-line value unquoted.

### F10 Low: false-assurance details in the verifier and static check

- `verify-node.sh:83`: `--check-egress` treats every curl failure (no DNS, no route, a local proxy variable, a captive portal) as "origin unreachable"; a node with no internet at all passes. It tests three registries over TCP/443 only; `HTTPS_PROXY` in root's environment changes the result.
- `verify-node.sh:36`: `host=${host%%:*}` breaks for a bracketed IPv6 endpoint (availability only).
- `check_kubernetes.py`: `C-IMAGE` accepts the 64-zero placeholder (it matches `[0-9a-f]{64}`), so the static contract passes on a file that cannot start. The runtime outcome is correctly fail-closed (`registry.example.invalid` never resolves; `ImagePullBackOff`), but the check should reject all-zero digests and `.invalid` hosts so `apply` of unedited manifests is caught before the cluster. `imagePullPolicy` is not checked.
- Ingress ipBlocks wider than /32 are caught only through the equality with `allowed_peer_cidrs` (and `CFG-NODE-CIDR`); fine today.

### F11 Low: store lock on network file systems is advisory and not detected at start

`src/store/lock.rs:45-52` takes an `flock`. Section 21 correctly says never use a shared network file system, but `ReadWriteOncePod` does not stop two nodes from mounting a node-loss force-deleted volume on a CSI that implements it above shared storage (NFS/EFS/CephFS). The step-1 requirement in "Planned replacement, fencing and node loss" (establish the node is down) is the whole fence; step 2's `out-of-service` taint force-detaches without checking. This is documented honestly; recommend (not required) a start-up refusal on a data directory whose file system type is `nfs*`/`cifs`/`fuse.*`, and a hard warning in step 3 that `--force --grace-period=0` on a live partitioned node creates two writers on shared storage. The documented timing is unverified (lane 11).

### F12 Info: tag memo and the cached boundary

A tag is judged by the digest it names now, with the registry's tag-to-digest answer remembered up to 30 s (documented, measured 29.3 to 29.5 s). The memo holds the registry's answer, not the policy verdict, so a digest block reaches the tag path in about one policy sync (1.2 s measured, one run) and the staleness window affects only a tag moved by the registry. The staleness runs in the safe direction for an upstream attacker (old allowed digest) and delays an upstream fix by up to 30 s. Acceptable and documented. Cached images stay on nodes (C1023); documented with `crictl rmi`.

### F13 Info: test harness

- `tests/e2e/fixtures/node-egress/Dockerfile` uses `alpine:3.22` (moving tag) and `apk add` at test time: a supply-chain input to a test that runs with `--cap-add NET_ADMIN` (rootless podman; the capability is scoped to the container's own netns, volumes are read-only; `service-cluster.mjs:246`). Pin the digest.
- `render.py` publishes `hostPort 18443` on all host interfaces with `allowed_peer_cidrs = ["10.0.0.0/8"]` for the duration of the smoke test (test-only key `prb_aaaa...`): any host on a 10.x LAN reaches a throwaway service. Bind it to 127.0.0.1.
- `containerd-node.mjs` runs containerd unprivileged on a per-run directory and a loopback-only recording proxy whose `connects` list is the evidence for "no origin fallback"; it returns 403 for any CONNECT outside the service host. Sound. Its `rmSync(dir, recursive)` is on a caller-supplied path; keep callers on the e2e work directory.
- `tests/node_scripts.rs` uses fake `containerd`/`curl`/`getent` in a tempdir (small, in /tmp). `tests/cluster_peer.rs` uses `unshare --user --map-root-user --net`; no host effect.

## Checked and found sound

- Pod Security restricted: `runAsNonRoot`, numeric UID, `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, read-only root file system on both containers; only configMap, secret, emptyDir and PVC volumes; no hostPath/hostNetwork/hostPort. (Admission by a real cluster not run; kubeconform schema valid.)
- ServiceAccount token off at both levels; no Role, ClusterRole or binding anywhere (`K-KIND` forbids them).
- Service key: not in env, arguments, image layers or logs; mounted only in the init container; staged 0600 into a memory-backed emptyDir; the service refuses a non-private file. The key is readable by the service's UID by design. No secrets, private keys or key-shaped strings in the new files (searched).
- Placeholder digest on `registry.example.invalid` fails closed.
- Retain policy, `ReadWriteOncePod`, single replica, `OrderedReady`, PDB, 60 s grace are consistent with the stated fence.
- Forged forwarding headers do not influence admission (code and `cluster_peer.rs`); `/health/*` answers all peers but returns readiness detail only to admitted ones.
- containerd: `server` in `_default` with no `[host]` tables, plain-https regex in the installer, `skip_verify`/`override_path`/`http://` refused by the verifier, one `config_path` checked through `containerd config dump`. The `ca` field is per host configuration and does not add the service CA for other registries (all registries go to the one server).

## Verification status

Reproduced here: F1, F2, F9. Not runnable here and therefore analysis only: F3 (needs a cluster), F4 (kube-proxy, CNI), F5 hostNetwork/hairpin behaviour, F7/F8 on a real node and CNI, F11.
