#!/usr/bin/env bash
# The cluster lanes of .github/workflows/cluster.yml (jobs `kind` and `cri-node`). Executed on hosted runners by cluster.yml (evidence/slice-31.md,
# run 45977663713 on 7e75aec: LANE=cluster 25/25 with Calico, LANE=cri 6/6); its control flow is also tested with stub tools (tests/node_scripts.rs),
# and its helpers by tests/e2e/native/lane_probe.test.py. NOT RUN YET (hosted run pending), added after that run: the Cilium leg (CNI=cilium), and in
# LANE=cri the kubelet's own pull with no fallback, a pod started from a preloaded image, the kubelet's pull-secret matching against a private
# registry, the same pull THROUGH the Probation endpoint (LANE=cluster, registry-lib.sh: the harness's policy server next to kind, policy-server.mjs), and the
# systemd propagation of nftables.service to the firewall unit. Read docs/plans/package-firewall-mvp-lf/evidence/slice-26.md, "Lanes".
#
#   LANE=cluster (default)  kind with a control plane and four workers (workers 1 and 4 = the service pool, worker 2 = the approved node,
#                           worker 3 = an unapproved node) and Calico (CNI=calico, default) or Cilium (CNI=cilium) without encapsulation (the
#                           nodes share one subnet): admission, D1 (with its negative control, which asserts the source address the service
#                           sees), NetworkPolicy, the PDB, the rollout and the fence. With Cilium also the label-based policy of
#                           optional/cilium-networkpolicy.yaml (fromNodes). Then the pull secret through the service: the service is pointed at
#                           the policy server, worker 2's runtime at the endpoint, and a pod on worker 2 pulls the private registry's image with a
#                           pull secret (runs), with none or another server's (refused); the registry never sees worker 2 or the service key.
#   LANE=cri                one kind node. Before the installer: a control `crictl pull` of a public registry, and the kubelet's pull-secret matching
#                           against a private registry (a pod with a matching secret runs; with none, or with a secret of another server, it
#                           does not). Then the SHIPPED install-node.sh (with the service image preloaded by digest) / verify-node.sh /
#                           install-firewall.sh on the node's own containerd, a restart, and the same `crictl pull` (the CRI PullImage) AND a pod
#                           whose pull is the kubelet's own, which must go to the endpoint, fail there, and never reach the registry; a pod of the
#                           preloaded image that runs although nothing can be pulled. Last: the firewall loaded for real and a restart, a reload
#                           and a stop of nftables.service, which the firewall unit must follow.
#
# Every assertion is `expect NAME COMMAND...` (lane-lib.sh, whose helpers have a stub-driven self-test in tests/node_scripts.rs). The script ends non-zero when a step aborts (its own status is kept), when an assertion
# failed, or when no assertion ran at all: a lane that did nothing must not be green.
set -euo pipefail

LANE=${LANE:-cluster}
CNI=${CNI:-calico}
WORK_DIR=${WORK_DIR:?WORK_DIR is required}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
NODE_IMAGE=${KIND_NODE_IMAGE:?KIND_NODE_IMAGE is required}
CLUSTER=probation-$LANE
ENDPOINT_NAME=probation.kind.test
NODEPORT=30443
mkdir -p "$WORK_DIR/logs"
# shellcheck source=lane-lib.sh
. "$(dirname "$0")/lane-lib.sh"
# shellcheck source=registry-lib.sh
. "$(dirname "$0")/registry-lib.sh"
trap finish EXIT

# ---- the cluster ----
if [ "$LANE" = cluster ]; then
  cat > "$WORK_DIR/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 10.244.0.0/16
nodes:
  - role: control-plane
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: JoinConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "probation.example/service-node=true"
  - role: worker
  - role: worker
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: JoinConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "probation.example/service-node=true"
EOF
else
  printf 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n  - role: control-plane\n' > "$WORK_DIR/kind.yaml"
fi
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$WORK_DIR/kind.yaml" --wait 0s

if [ "$LANE" = cri ]; then
  # ---- LANE=cri ----
  NODE=$CLUSTER-control-plane
  # (not pause:3.10, the node's own sandbox image: a kind node ships it, so the control must pull an image the node does not hold)
  REF=registry.k8s.io/pause:3.9
  wait_cri "$NODE" || fail "the node's CRI did not answer"
  kubectl wait --for=condition=Ready node --all --timeout=300s
  expect "control: before the installer the node's CRI pulls $REF from its registry" docker exec "$NODE" crictl pull "$REF"
  docker exec "$NODE" crictl rmi "$REF" >/dev/null 2>&1 || true

  # ---- the kubelet's pull-secret matching, against a private registry (BEFORE the installer: afterwards every registry goes to the endpoint, and
  # verify-node.sh refuses a per-registry directory of its own). The registry is on the kind network behind TLS and basic auth; the node's
  # containerd reaches it through a plain hosts.toml. The pods' pulls are the KUBELET's: it picks the secret whose server matches the image's host.
  private_registry_up
  docker exec "$NODE" sh -c "echo '$REGIP private.kind.test' >> /etc/hosts"
  docker exec "$NODE" mkdir -p "/etc/containerd/certs.d/$PRIVATE"
  docker exec -i "$NODE" sh -c "cat > '/etc/containerd/certs.d/$PRIVATE/ca.crt'" < "$WORK_DIR/registry/reg.crt"
  printf 'server = "https://%s"\n\n[host."https://%s"]\n  capabilities = ["pull", "resolve"]\n  ca = "ca.crt"\n' "$PRIVATE" "$PRIVATE" | docker exec -i "$NODE" sh -c "cat > '/etc/containerd/certs.d/$PRIVATE/hosts.toml'"
  expect "the kind node's containerd reads registry hosts from /etc/containerd/certs.d" docker exec "$NODE" sh -c "crictl info | grep -q /etc/containerd/certs.d"
  kubectl create secret docker-registry private-pull --docker-server="$PRIVATE" --docker-username=puller --docker-password="$PULL_PW"
  kubectl create secret docker-registry other-server-pull --docker-server=other.kind.test:5000 --docker-username=puller --docker-password="$PULL_PW"
  lane_pod secret-ok "$PRIV_IMAGE" Always private-pull
  lane_pod secret-none "$PRIV_IMAGE" Always
  lane_pod secret-other "$PRIV_IMAGE" Always other-server-pull
  AUTH_FAILED='Failed to pull image.*(401|unauthorized|authoriz|authenticat|credential)'
  expect "pull secret: a pod whose imagePullSecrets name the registry's own server ($PRIVATE) runs" wait_until 150 pod_phase_is default secret-ok Running
  expect "pull secret: the registry saw the pull with the secret's user (puller), not an anonymous one" bash -c "docker logs $REG 2>&1 | grep -Eq 'auth.user.name=\"?puller'"
  expect "pull secret: the same image with NO pull secret is refused for authorization (the kubelet sends no credential)" wait_until 150 pod_event_matches default secret-none "$AUTH_FAILED"
  expect "pull secret: a pod with a secret of ANOTHER server (other.kind.test:5000) is refused the same way (matching is by the image's host)" wait_until 150 pod_event_matches default secret-other "$AUTH_FAILED"
  expect "pull secret: the pod with no secret does not run" not pod_phase_is default secret-none Running
  expect "pull secret: the pod with the other server's secret does not run" not pod_phase_is default secret-other Running
  kubectl delete pod secret-ok secret-none secret-other --ignore-not-found --wait=false
  docker exec "$NODE" rm -rf "/etc/containerd/certs.d/$PRIVATE"
  docker rm -f "$REG" >/dev/null

  # ---- the node: the installer, with the service's own image preloaded BY DIGEST (the kubelet's use of a preloaded image is checked below) ----
  # An OCI archive of ONE platform's manifest (skopeo picks it from the index), named repository@<that manifest's digest> by install-node.sh. The
  # repository is one that does not exist on registry.k8s.io: a pod of it can only run if the preload is what the kubelet uses.
  skopeo copy --override-os linux --override-arch amd64 "docker://$BUSYBOX" "oci-archive:$WORK_DIR/preload.tar:1"
  PRELOAD_DIGEST=$(python3 - "$WORK_DIR/preload.tar" <<'PY'
import json, sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    member = next(m for m in t.getmembers() if m.name.lstrip("./") == "index.json")
    print(json.load(t.extractfile(member))["manifests"][0]["digest"])
PY
)
  case $PRELOAD_DIGEST in sha256:????????????????????????????????????????????????????????????????) ;; *) fail "the preload archive names no manifest digest: $PRELOAD_DIGEST" ;; esac
  PRELOAD_REF=registry.k8s.io/probation-lane/preloaded@$PRELOAD_DIGEST
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK_DIR/ca.key" -out "$WORK_DIR/ca.pem" -subj "/CN=probation-kind-ca" -days 2
  docker cp "$ROOT/deploy/kubernetes/node" "$NODE:/opt/probation-node"
  docker cp "$WORK_DIR/ca.pem" "$NODE:/opt/probation-ca.pem"
  docker cp "$WORK_DIR/preload.tar" "$NODE:/opt/probation-preload.tar"
  NODEIP=$(node_ip "$NODE")
  FIREWALL_ARGS="--service4 $NODEIP --service-port $NODEPORT --cluster4 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 --dns4 $NODEIP --approved4 $NODEIP"
  expect "install-node.sh runs on the node's real containerd config and preloads the image by digest" docker exec "$NODE" sh /opt/probation-node/install-node.sh --endpoint "https://$ENDPOINT_NAME:$NODEPORT" --ca /opt/probation-ca.pem --registry registry.k8s.io=1 --preload-image /opt/probation-preload.tar --image-ref "${PRELOAD_REF}"
  # shellcheck disable=SC2086 # FIREWALL_ARGS is a word list of the installer's own flags
  expect "install-firewall.sh renders and passes nft -c" docker exec "$NODE" sh /opt/probation-node/install-firewall.sh --root /tmp/fw $FIREWALL_ARGS
  docker exec "$NODE" systemctl daemon-reload
  docker exec "$NODE" systemctl restart containerd
  wait_cri "$NODE" || fail "the node's CRI did not come back after the restart"
  # After the restart: the verifier reads the effective environment of the RUNNING containerd (systemd's and /proc/<pid>/environ).
  expect "verify-node.sh passes (real containerd config dump, the running daemon's environment)" docker exec "$NODE" sh /opt/probation-node/verify-node.sh --endpoint "https://$ENDPOINT_NAME:$NODEPORT"
  # The endpoint name does not resolve here: the pull must FAIL AT THE ENDPOINT. If the runtime fell back to registry.k8s.io it would succeed.
  expect "the same PullImage now fails and names the endpoint (no fallback to the registry)" bash -c "out=\$(docker exec $NODE crictl pull $REF 2>&1) && exit 1; printf '%s' \"\$out\" | grep -q '$ENDPOINT_NAME'"
  expect "the registry's image $REF is not on the node (a kind node holds its own control-plane images, so only this one is checked)" bash -c "! docker exec $NODE crictl inspecti $REF"

  # ---- the kubelet's own pull, and its use of a preloaded image ----
  # The kubelet calls PullImage itself (imagePullPolicy Always): it must go through config_path to the endpoint, fail there, and leave no image behind.
  lane_pod nofallback "$REF" Always
  expect "kubelet pull: the pod's own pull of $REF fails at the endpoint (the event names $ENDPOINT_NAME): no fallback to the registry" wait_until 150 pod_event_matches default nofallback "Failed to pull image.*$ENDPOINT_NAME"
  expect "kubelet pull: the pod is not running" not pod_phase_is default nofallback Running
  expect "kubelet pull: $REF is still not on the node (the pull left nothing behind)" bash -c "! docker exec $NODE crictl inspecti $REF"
  # IfNotPresent and a digest the node holds (the preload): no pull is needed. The repository does not exist on registry.k8s.io and the endpoint does
  # not resolve, so a pull could not have succeeded: Running with the event "already present on machine" shows the kubelet used the preload.
  lane_pod preloaded "$PRELOAD_REF" IfNotPresent
  expect "kubelet preload: a pod of $PRELOAD_REF (IfNotPresent) reaches Running although nothing can be pulled" wait_until 150 pod_phase_is default preloaded Running
  expect "kubelet preload: the kubelet found the image already present on the node (no pull)" pod_event_matches default preloaded 'already present on machine'

  # ---- systemd propagation of nftables.service to the firewall unit ----
  # LAST: nftables.service's `flush ruleset` also clears the node's kube-proxy rules. The firewall is loaded for real here (no --root), the unit must be
  # active (PartOf= and ReloadPropagatedFrom= only reach an active unit), and a marker table that is NOT ours proves that each action really flushed
  # the rule set: ours must be back (restart, reload) or gone (stop) while the marker is gone.
  docker exec "$NODE" systemctl cat nftables.service >/dev/null 2>&1 || fail "the kind node has no nftables.service: the propagation to the firewall unit cannot be exercised"
  # shellcheck disable=SC2086
  expect "install-firewall.sh loads both tables for real and starts probation-node-firewall.service" docker exec "$NODE" sh /opt/probation-node/install-firewall.sh $FIREWALL_ARGS
  expect "verify-node.sh --firewall: both tables are loaded and the unit is active" docker exec "$NODE" sh /opt/probation-node/verify-node.sh --endpoint "https://$ENDPOINT_NAME:$NODEPORT" --firewall
  docker exec "$NODE" nft add table inet probation_lane_marker
  docker exec "$NODE" systemctl restart nftables.service
  expect "nftables.service restart: the rule set was flushed (the marker table is gone)" wait_until 30 nft_table_absent "$NODE" probation_lane_marker
  expect "nftables.service restart: probation-node-firewall.service followed it and both tables are loaded again" wait_until 30 fw_loaded "$NODE"
  expect "nftables.service restart: the firewall unit is active again" wait_until 30 docker exec "$NODE" systemctl is-active --quiet probation-node-firewall.service
  docker exec "$NODE" nft add table inet probation_lane_marker
  docker exec "$NODE" systemctl reload nftables.service
  expect "nftables.service reload: the rule set was flushed (the marker table is gone)" wait_until 30 nft_table_absent "$NODE" probation_lane_marker
  expect "nftables.service reload: both tables are loaded again (ReloadPropagatedFrom and ExecReload)" wait_until 30 fw_loaded "$NODE"
  docker exec "$NODE" systemctl stop nftables.service
  expect "nftables.service stop: both tables are gone (docs/operations.md: a stop of nftables.service removes the node firewall)" wait_until 30 fw_gone "$NODE"
  expect "nftables.service stop: the firewall unit stopped with it" wait_until 30 not docker exec "$NODE" systemctl is-active --quiet probation-node-firewall.service
  exit 0
fi

# ---- LANE=cluster ----
if [ "$CNI" = cilium ]; then
  # Cilium (the cilium CLI is pinned and checked by the workflow). kube-proxy stays: it applies externalTrafficPolicy, which is what D1 rests on, so
  # kubeProxyReplacement is off. Native routing over the nodes' shared subnet (the equivalent of Calico's CrossSubnet) keeps the source address kube-proxy
  # leaves, so the negative control can OBSERVE it. policyCIDRMatchMode=nodes lets networkpolicy.yaml's ipBlock of a node address match that node
  # (docs/operations.md, "NetworkPolicy is not host control"); nodeSelectorLabels lets optional/cilium-networkpolicy.yaml select nodes by label.
  cilium install --version "${CILIUM_VERSION:?CILIUM_VERSION is required}" --set kubeProxyReplacement=false --set routingMode=native --set ipv4NativeRoutingCIDR=10.244.0.0/16 --set autoDirectNodeRoutes=true --set ipam.mode=kubernetes --set policyCIDRMatchMode=nodes --set nodeSelectorLabels=true
  cilium status --wait --wait-duration 10m
elif [ "$CNI" = calico ]; then
  curl -fsSL -o "$WORK_DIR/calico.yaml" "https://raw.githubusercontent.com/projectcalico/calico/v3.31.0/manifests/calico.yaml"
  echo "$CALICO_SHA256  $WORK_DIR/calico.yaml" | sha256sum --check
  # The checked manifest, then two changes: the pool CIDR is the cluster's pod subnet (Calico's default 192.168.0.0/16 is not, which changes kube-proxy's
  # masquerade decisions for pod traffic), and no IP-in-IP encapsulation between nodes of one subnet (`CrossSubnet`: kind's nodes share a subnet), so kube-proxy's
  # Cluster-mode masquerade uses the node's own address and the negative control below can ASSERT the source address it sees (it does not assume it).
  python3 - "$WORK_DIR/calico.yaml" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
new, n = re.subn(r'(- name: CALICO_IPV4POOL_IPIP\n\s+value: )"Always"', r'\1"CrossSubnet"', text)
if n != 1:
    sys.exit("the Calico manifest has no CALICO_IPV4POOL_IPIP=Always to change")
# the manifest ships the pool CIDR commented out (`# - name: CALICO_IPV4POOL_CIDR` / `#   value: "192.168.0.0/16"`): enable it with the pod subnet
new, n = re.subn(r'# - name: CALICO_IPV4POOL_CIDR\n(\s*)#\s+value: "[^"]*"', lambda m: '- name: CALICO_IPV4POOL_CIDR\n' + m.group(1) + '  value: "10.244.0.0/16"', new)
if n != 1:
    sys.exit("the Calico manifest has no commented CALICO_IPV4POOL_CIDR to set to the pod subnet")
open(sys.argv[1], "w").write(new)
PY
  kubectl apply -f "$WORK_DIR/calico.yaml"
else
  fail "unknown CNI $CNI (calico or cilium)"
fi
kubectl wait --for=condition=Ready nodes --all --timeout=300s
if [ "$CNI" = cilium ]; then
  expect "Cilium: policy-cidr-match-mode is nodes (an ipBlock of a node address matches that node)" bash -c "[ \"\$(kubectl -n kube-system get configmap cilium-config -o jsonpath='{.data.policy-cidr-match-mode}')\" = nodes ]"
  expect "Cilium: node selector labels are enabled (fromNodes can select nodes)" bash -c "[ \"\$(kubectl -n kube-system get configmap cilium-config -o jsonpath='{.data.enable-node-selector-labels}')\" = true ]"
fi
kubectl taint nodes -l probation.example/service-node=true probation.example/service=true:NoSchedule
W1=$CLUSTER-worker; W2=$CLUSTER-worker2; W3=$CLUSTER-worker3; W4=$CLUSTER-worker4
IP1=$(node_ip "$W1"); IP2=$(node_ip "$W2"); IP3=$(node_ip "$W3")
kubectl label node "$W2" probation.example/approved-node=true --overwrite

# The image: built from this checkout and loaded into the nodes (a tag here, not a digest: the kind lane does not test digest pinning).
docker build -t localhost/probation:kind "$ROOT"
kind load docker-image localhost/probation:kind --name "$CLUSTER"

# A storage class that enforces ReadWriteOncePod: kind's default provisioner is not CSI. Installed from the driver's pinned release, or the lane
# fails (it never runs the ownership and fence checks against storage that cannot enforce them).
# The driver's snapshotter sidecar needs the VolumeSnapshot CRDs, which kind does not ship (hosted run: "no matches for kind VolumeSnapshotClass").
# They come from external-snapshotter at its pinned release, the checked-out commit verified. The snapshot-controller is not installed: this lane takes
# no snapshots, it only needs the API types to exist.
git clone --depth 1 --branch v8.2.0 https://github.com/kubernetes-csi/external-snapshotter "$WORK_DIR/snapshotter"
[ "$(git -C "$WORK_DIR/snapshotter" rev-parse HEAD)" = 0f215370c7ca3eeef4ab7028824d3bc66e1f63bd ] || fail "external-snapshotter v8.2.0 is not the pinned commit"
kubectl apply -k "$WORK_DIR/snapshotter/client/config/crd"
kubectl wait --for=condition=Established --timeout=60s crd/volumesnapshotclasses.snapshot.storage.k8s.io crd/volumesnapshots.snapshot.storage.k8s.io crd/volumesnapshotcontents.snapshot.storage.k8s.io
git clone --depth 1 --branch v1.17.0 https://github.com/kubernetes-csi/csi-driver-host-path "$WORK_DIR/csi"
[ "$(git -C "$WORK_DIR/csi" rev-parse HEAD)" = 8b88d04ec388312df1b910bf1cb48926c63c2660 ] || fail "csi-driver-host-path v1.17.0 is not the pinned commit"
( cd "$WORK_DIR/csi" && bash deploy/kubernetes-latest/deploy.sh )
# The driver's plugin is a single pod and its volumes are node-local to the node it runs on: it runs on the pool node that holds the service (worker 1),
# which carries the pool taint, so the pod, its claim and the volume are on one node. (Worker 4 is the second pool node of the fence check.)
kubectl patch statefulset csi-hostpathplugin --type merge -p "{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$W1\"},\"tolerations\":[{\"key\":\"probation.example/service\",\"operator\":\"Equal\",\"value\":\"true\",\"effect\":\"NoSchedule\"}]}}}}"
kubectl rollout status statefulset/csi-hostpathplugin --timeout=300s
kubectl apply -f "$WORK_DIR/csi/examples/csi-storageclass.yaml"
RWOP_CLASS=csi-hostpath-sc
kubectl get storageclass "$RWOP_CLASS" >/dev/null || fail "no ReadWriteOncePod-capable storage class $RWOP_CLASS: the ownership and fence checks cannot run"

# The manifests with this cluster's values: one approved node (worker 2), the endpoint name, a locally loaded image.
cp -r "$ROOT/deploy/kubernetes" "$WORK_DIR/k"
python3 - "$WORK_DIR/k" "$IP2" "$ENDPOINT_NAME" "$RWOP_CLASS" <<'PY'
import pathlib, re, sys
k, ip, name, cls = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
cfg = (k / "config.toml").read_text()
cfg = re.sub(r"allowed_peer_cidrs = \[.*\]", f'allowed_peer_cidrs = ["{ip}/32"]', cfg).replace("probation.cluster.example", name)
(k / "config.toml").write_text(cfg)
policy = (k / "networkpolicy.yaml").read_text()
policy = re.sub(r"(- from:\n)(?:\s+- ipBlock:\n\s+cidr: [^\n]+\n)+", lambda m: m.group(1) + f"        - ipBlock:\n            cidr: {ip}/32\n", policy)
(k / "networkpolicy.yaml").write_text(policy)
dep = (k / "deployment.yaml").read_text().replace("registry.example.invalid/probation/probation@sha256:" + "0" * 64, "localhost/probation:kind").replace("imagePullPolicy: IfNotPresent", "imagePullPolicy: Never")
# no policy server in this lane: readiness would never be true, so the pod is ready when it is live (the peer decision comes first).
dep = dep.replace("path: /health/ready", "path: /health/live")
(k / "deployment.yaml").write_text(dep)
pvc = (k / "pvc.yaml").read_text().replace("spec:\n  accessModes", f"spec:\n  storageClassName: {cls}\n  accessModes", 1)
(k / "pvc.yaml").write_text(pvc)
PY

# Apply in the order the guide gives: namespace, Secrets, claim, the rest.
kubectl apply -f "$WORK_DIR/k/namespace.yaml"
expect "namespace: a privileged pod is refused by Pod Security" bash -c "kubectl -n probation run bad --image=localhost/probation:kind --privileged --restart=Never --dry-run=server 2>&1 | grep -q 'violates PodSecurity'"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK_DIR/tls.key" -out "$WORK_DIR/tls.crt" -subj "/CN=$ENDPOINT_NAME" -addext "subjectAltName=DNS:$ENDPOINT_NAME" -days 2
kubectl -n probation create secret tls probation-tls --cert="$WORK_DIR/tls.crt" --key="$WORK_DIR/tls.key"
printf 'prb_%s\n' "$(openssl rand -hex 16)" > "$WORK_DIR/service-key"
kubectl -n probation create secret generic probation-service-key --from-file=service-key="$WORK_DIR/service-key"
kubectl apply -f "$WORK_DIR/k/pvc.yaml"
kubectl apply -k "$WORK_DIR/k"
kubectl -n probation rollout status deployment/probation --timeout=300s

# The admission backstop must be ACTIVE before anything relies on it: poll a server-side dry run until it is denied (bounded), then require the reason.
# (`denied` is in lane-lib.sh: it captures kubectl's output first, kubectl exits 1 on a denial.)
for _ in $(seq 1 30); do denied && break; sleep 2; done
expect "admission: externalTrafficPolicy Cluster is refused by the policy (named in the denial)" denied
expect "admission: a second Service is refused by the policy" bash -c "kubectl -n probation create service nodeport second --tcp=80:80 --dry-run=server 2>&1 | grep -q 'probation-one-local-service'"

# ---- D1 ----
# A probe pins the endpoint NAME to one node address (TLS and the Host check pass) and prints the body. Where it runs decides what it can prove:
#   * from a host or hostNetwork pod of an UNAPPROVED node, or from the runner, with the NetworkPolicy of the namespace in force, an enforcing
#     CNI drops the packet BEFORE the service: the answer is a TIMEOUT (curl exit 28), which says "some layer dropped it" and proves nothing about D1;
#   * the same probe with the ingress NetworkPolicy removed reaches the service, which answers NETWORK_NOT_ALLOWED: that body proves the
#     service saw the caller's OWN source address (kube-proxy kept it) and judged it: the discriminating check;
#   * the negative control switches to Cluster. It first ASKS the service which source address it sees for an outsider that comes in through the
#     UNAPPROVED worker 3's NodePort (the refusal names it) and requires that to be worker 3's own address (kube-proxy's masquerade is by that node's
#     address); only then does it probe the APPROVED node's NodePort from outside: the same masquerade gives worker 2's address, which is in
#     allowed_peer_cidrs, and the service ADMITS the outsider. The SNAT address is observed, not assumed: on a CNI that masquerades with another address
#     the first assertion fails and says so.
probe() { # probe FROM ADDRESS
  local from=$1 address=$2
  local cmd="curl -sk --max-time 10 --resolve $ENDPOINT_NAME:$NODEPORT:$address https://$ENDPOINT_NAME:$NODEPORT/v2/"
  case $from in
    runner) bash -c "$cmd" ;;
    node:*) docker exec "${from#node:}" sh -c "$cmd" ;;
    hostpod3) kubectl run "probe-$RANDOM" -n default --rm -i --quiet --restart=Never --image=docker.io/curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 --overrides="{\"spec\":{\"hostNetwork\":true,\"nodeName\":\"$W3\"}}" -- sh -c "$cmd" ;;
    pod3) kubectl run "probe-$RANDOM" -n default --rm -i --quiet --restart=Never --image=docker.io/curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 --overrides="{\"spec\":{\"nodeName\":\"$W3\"}}" -- sh -c "$cmd" ;;
  esac
}
# Phase B, the NetworkPolicy in force: an unapproved source never gets an answer from the service (dropped, or refused by it); the approved node does.
expect "NetworkPolicy layer: the runner gets no answer from the service" dropped_or_refused runner "$IP1"
expect "NetworkPolicy layer: an unapproved node's host gets no answer" dropped_or_refused "node:$W3" "$IP1"
expect "NetworkPolicy layer: a hostNetwork pod on the unapproved node gets no answer" dropped_or_refused hostpod3 "$IP1"
expect "NetworkPolicy layer: a pod on the unapproved node gets no answer" dropped_or_refused pod3 "$IP1"
expect "the approved node is admitted with the policy in force" admitted "node:$W2" "$IP1"

# Phase A, the ingress layer lifted so the service itself decides: the D1 check. The namespace has a default-deny policy for every pod AND
# probation-ingress, so deleting probation-ingress alone would leave the pod unreachable for everyone; a temporary policy that allows all ingress
# to the service pod is added instead (policies add up). lane-lib.sh's finish restores everything on any exit.
lift_ingress_policy
# Until the CNI has programmed the new policy, the outsider still gets no answer: poll (bounded) for the service's own refusal instead of sleeping.
for _ in $(seq 1 45); do refused_by_service runner "$IP1" && break; sleep 2; done
expect "D1: an external host (the runner) is refused BY THE SERVICE with its own source address" refused_by_service runner "$IP1"
expect "D1: the unapproved worker 3 host is refused by the service" refused_by_service "node:$W3" "$IP1"
expect "D1: a hostNetwork pod on the unapproved worker 3 is refused by the service" refused_by_service hostpod3 "$IP1"
expect "D1: a pod on the unapproved worker 3 is refused by the service" refused_by_service pod3 "$IP1"
expect "D1: the approved worker 2 is admitted" admitted "node:$W2" "$IP1"
expect "D1 (Local): the approved node's own NodePort has no endpoint, so the outsider gets no answer there" dropped runner "$IP2"
# The negative control: lift the admission policy for this one change and switch to Cluster.
kubectl delete validatingadmissionpolicybinding probation-one-local-service
# The API server's admission cache can still hold the binding for a moment and deny the patch: poll (bounded), then one unguarded patch so a
# denial that persists aborts the lane.
for _ in $(seq 1 30); do kubectl -n probation patch svc probation --type merge -p '{"spec":{"externalTrafficPolicy":"Cluster"}}' && break; sleep 2; done
kubectl -n probation patch svc probation --type merge -p '{"spec":{"externalTrafficPolicy":"Cluster"}}'
# First what the service SEES: an outsider through the UNAPPROVED worker 3's NodePort is masqueraded by kube-proxy; the refusal names the source.
# The premise of the control (the source is the forwarding node's own address) is asserted from that, never assumed.
for _ in $(seq 1 45); do [ -n "$(source_seen runner "$IP3")" ] && break; sleep 2; done
echo "source address the service saw for an outsider through worker 3 (Cluster): $(source_seen runner "$IP3")"
expect "D1 negative control, premise: with Cluster the service sees the forwarding node's own address ($IP3), not the outsider's" source_is "$IP3" runner "$IP3"
# Then the approved node's NodePort (the endpoint is on worker 1): the masquerade gives worker 2's address, which is in allowed_peer_cidrs.
for _ in $(seq 1 45); do admitted runner "$IP2" && break; sleep 2; done
expect "D1 negative control: with Cluster the outsider IS admitted through the approved node's NodePort (the check discriminates)" admitted runner "$IP2"
restore_policies
for _ in $(seq 1 30); do denied && break; sleep 2; done
# The temporary allow-all policy is gone and `apply -k` restored Local and the binding: the outsider is DROPPED again (no answer), as in phase B.
for _ in $(seq 1 45); do dropped runner "$IP1" && break; sleep 2; done
expect "D1 restored: the ingress policy is back and the outsider gets no answer again" dropped runner "$IP1"
expect "D1 restored: the approved node is admitted again" admitted "node:$W2" "$IP1"

# ---- Cilium: the label-based policy (optional/cilium-networkpolicy.yaml, `fromNodes`) ----
# Everything above ran with networkpolicy.yaml's ipBlock, matched against nodes by policyCIDRMatchMode=nodes. Here the ipBlock rule is taken away so that
# the namespace's default-deny is all that remains (the control: not even the approved node is answered), then the shipped CiliumNetworkPolicy is applied:
# the node LABELLED approved (worker 2) is admitted, the unlabelled worker 3 and the runner get no answer. Then the policies of the kustomization are restored.
if [ "$CNI" = cilium ]; then
  remove_ipblock_policy
  wait_until 90 dropped "node:$W2" "$IP1" || true
  expect "Cilium control: with the ipBlock policy deleted (default-deny only) the approved node gets no answer" dropped "node:$W2" "$IP1"
  kubectl apply -f "$ROOT/deploy/kubernetes/optional/cilium-networkpolicy.yaml"
  wait_until 90 admitted "node:$W2" "$IP1" || true
  expect "Cilium fromNodes: the node labelled approved-node=true (worker 2) is admitted" admitted "node:$W2" "$IP1"
  expect "Cilium fromNodes: the unlabelled worker 3 host gets no answer" dropped "node:$W3" "$IP1"
  expect "Cilium fromNodes: the runner (outside the cluster) gets no answer" dropped runner "$IP1"
  kubectl delete -f "$ROOT/deploy/kubernetes/optional/cilium-networkpolicy.yaml"
  kubectl apply -k "$WORK_DIR/k"
  wait_until 90 admitted "node:$W2" "$IP1" || true
  expect "Cilium: with the CiliumNetworkPolicy removed and probation-ingress restored the approved node is admitted again" admitted "node:$W2" "$IP1"
fi

# ---- the kubelet's pull secret THROUGH the Probation endpoint (registry-lib.sh) ----
pull_through_service

# ---- the rest ----
POD=$(kubectl -n probation get pod -l app.kubernetes.io/name=probation -o jsonpath='{.items[0].metadata.name}')
expect "PDB: the eviction API answers 429 (the budget refuses)" bash -c "printf '%s' '{\"apiVersion\":\"policy/v1\",\"kind\":\"Eviction\",\"metadata\":{\"name\":\"$POD\",\"namespace\":\"probation\"}}' | kubectl create --raw /api/v1/namespaces/probation/pods/$POD/eviction -f - 2>&1 | grep -q 'disruption budget'"
# A pod that is admitted by the namespace's restricted Pod Security level, tolerates the pool taint and selects the pool nodes: the claim's
# ReadWriteOncePod mode is then the one reason it cannot be scheduled, and the scheduler's event says so.
expect "ReadWriteOncePod: a second pod on the claim stays Pending with the RWOP event" bash -c "kubectl -n probation apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: second}
spec:
  nodeSelector: {probation.example/service-node: 'true'}
  tolerations: [{key: probation.example/service, operator: Equal, value: 'true', effect: NoSchedule}]
  securityContext: {runAsNonRoot: true, runAsUser: 100, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: s
      image: docker.io/curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69
      command: [sleep, '600']
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts: [{name: d, mountPath: /d}]
  volumes: [{name: d, persistentVolumeClaim: {claimName: probation-data}}]
EOF
for _ in \$(seq 1 40); do kubectl -n probation get events --field-selector involvedObject.name=second -o jsonpath='{range .items[*]}{.reason}: {.message}{\"\\n\"}{end}' 2>&1 | grep -q 'FailedScheduling:.*ReadWriteOncePod access mode' && exit 0; sleep 3; done; exit 1"
kubectl -n probation delete pod second --ignore-not-found
before=$(kubectl -n probation get pods -l app.kubernetes.io/name=probation -o name | wc -l)
kubectl -n probation rollout restart deployment/probation
( for _ in $(seq 1 60); do kubectl -n probation get pods -l app.kubernetes.io/name=probation --field-selector=status.phase=Running -o name | wc -l; sleep 2; done ) > "$WORK_DIR/logs/running-count.log" &
watcher=$!
kubectl -n probation rollout status deployment/probation --timeout=300s
wait "$watcher" || true
expect "rollout: never two running pods at once (Recreate)" bash -c "! grep -qE '^[2-9]' '$WORK_DIR/logs/running-count.log'"
echo "pods before the rollout: $before"
# The fence: take the pool node off the network. The Deployment replaces the pod only after the node's pods are evicted (about five minutes);
# the replacement must then stay Pending on the claim while the old pod object still exists. Bounded waits on the real conditions.
OLD=$(kubectl -n probation get pod -l app.kubernetes.io/name=probation -o jsonpath='{.items[0].metadata.name}')
docker network disconnect kind "$W1"
second_pod_exists() { [ "$(kubectl -n probation get pods -l app.kubernetes.io/name=probation -o name | wc -l)" -ge 2 ]; }
for _ in $(seq 1 120); do second_pod_exists && break; sleep 5; done
expect "fence: a replacement pod appears once the node is lost" second_pod_exists
expect "fence: the old pod object still exists" kubectl -n probation get pod "$OLD"
sleep 60
expect "fence: the replacement is not Running while the old pod is not confirmed gone (RWOP)" bash -c "[ \$(kubectl -n probation get pods -l app.kubernetes.io/name=probation --field-selector=status.phase=Running -o name | grep -vc $OLD) -eq 0 ]"
# The pool has a second node (worker 4), so the node selector is not what holds the replacement back; the scheduler's event names the claim.
NEW=$(kubectl -n probation get pods -l app.kubernetes.io/name=probation -o name | { grep -v "$OLD" || true; } | sed -n 1p | cut -d/ -f2)
expect "fence: the replacement is held back by the ReadWriteOncePod claim (the scheduler's event), with a second pool node available" bash -c "kubectl get node $W4 >/dev/null && kubectl -n probation get events --field-selector involvedObject.name=$NEW -o jsonpath='{range .items[*]}{.reason}: {.message}{\"\\n\"}{end}' | grep -q 'FailedScheduling:.*ReadWriteOncePod access mode'"
docker network connect kind "$W1"
echo "the safe force-delete procedure is the guide's (docs/operations.md, 'Node loss'); this lane stops here"
