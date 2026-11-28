# Sourced by run-kind-lane.sh (and by tests/node_scripts.rs, with stub tools): the private registry the pull-secret checks use, the pods of the kubelet's own
# pulls, and `pull_through_service`, the kubelet's pull secret THROUGH the Probation endpoint of the cluster lane. Needs lane-lib.sh. NOT RUN YET on a
# hosted runner (hosted run pending).
# Public images, pinned by digest: the one the private registry is filled with, the registry itself, the cri lane's preload, and htpasswd (bcrypt, which
# the registry requires). The preload must NOT be the private registry's image: the kubelet (KubeletEnsureSecretPulledImages, on by default since 1.35)
# re-verifies, by pulling, an image it once pulled with a pull secret before a pod without that secret may use it (hosted run 46132781149).
BUSYBOX=docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
REGISTRY_IMAGE=docker.io/library/registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
PRELOAD_IMAGE=docker.io/library/registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
HTPASSWD_IMAGE=docker.io/library/httpd:2.4.66-alpine@sha256:968c8b4098fcecb473762b45f6c541a3b2b2cfab2caccb1edbd2cece071ef160
REG=$CLUSTER-private-registry
PRIVATE=private.kind.test:5000
PRIV_IMAGE=$PRIVATE/private/app:1
registry_up() { [ "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:5000/v2/)" = 401 ]; }
# A private registry (registry:2) on the kind network behind TLS and basic auth (user `puller`, the password in PULL_PW), filled with $PRIV_IMAGE (busybox).
# Its certificate (CN and SAN private.kind.test, localhost) is an end-entity certificate, $WORK_DIR/registry/reg.crt, under a lane CA,
# $WORK_DIR/registry/ca/ca.crt, which is what clients trust. Not one self-signed certificate: `openssl req -x509` marks it CA:TRUE, and the
# service's rustls refuses a CA presented by a server (CaUsedAsEndEntity, every pull through the service 502, hosted run 46132781149).
# Sets PULL_PW and REGIP; finish removes the container.
private_registry_up() {
  command -v skopeo >/dev/null || fail "skopeo is required (it fills the private registry and builds the preload archive)"
  PULL_PW=$(openssl rand -hex 12)
  mkdir -p "$WORK_DIR/registry/ca"
  # (the CA key is not in ca/: skopeo's cert dir takes a .key there for a client certificate)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK_DIR/registry/ca.key" -out "$WORK_DIR/registry/ca/ca.crt" -subj "/CN=probation lane registry CA" -addext "keyUsage=critical,keyCertSign,cRLSign" -days 2
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK_DIR/registry/reg.key" -out "$WORK_DIR/registry/reg.csr" -subj "/CN=private.kind.test"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:private.kind.test,DNS:localhost,IP:127.0.0.1\n' > "$WORK_DIR/registry/reg.ext"
  openssl x509 -req -in "$WORK_DIR/registry/reg.csr" -CA "$WORK_DIR/registry/ca/ca.crt" -CAkey "$WORK_DIR/registry/ca.key" -set_serial "0x$(openssl rand -hex 8)" -extfile "$WORK_DIR/registry/reg.ext" -out "$WORK_DIR/registry/reg.crt" -days 2
  docker run --rm --entrypoint htpasswd "$HTPASSWD_IMAGE" -Bbn puller "$PULL_PW" > "$WORK_DIR/registry/htpasswd"
  docker run -d --name "$REG" --network kind -p 127.0.0.1:5000:5000 -v "$WORK_DIR/registry:/auth:ro" -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 -e REGISTRY_HTTP_TLS_CERTIFICATE=/auth/reg.crt -e REGISTRY_HTTP_TLS_KEY=/auth/reg.key -e REGISTRY_AUTH=htpasswd -e REGISTRY_AUTH_HTPASSWD_REALM=probation-lane -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd "$REGISTRY_IMAGE" >/dev/null
  wait_until 60 registry_up || fail "the private registry did not come up (it must answer 401 without a credential)"
  skopeo copy --override-os linux --override-arch amd64 --dest-creds "puller:$PULL_PW" --dest-cert-dir "$WORK_DIR/registry/ca" "docker://$BUSYBOX" docker://localhost:5000/private/app:1
  REGIP=$(node_ip "$REG")
}

# A pod of the default namespace, for the kubelet's own pulls: on the node LANE_POD_NODE when set, else wherever the scheduler puts it.
lane_pod() { # lane_pod NAME IMAGE PULL_POLICY [PULL_SECRET]
  local secrets="" node=""
  [ -z "${4:-}" ] || secrets="imagePullSecrets: [{name: $4}]"
  [ -z "${LANE_POD_NODE:-}" ] || node="nodeName: $LANE_POD_NODE"
  kubectl apply -f - <<POD
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: default}
spec:
  tolerations: [{key: node-role.kubernetes.io/control-plane, operator: Exists, effect: NoSchedule}]
  $secrets
  $node
  containers:
    - name: c
      image: $2
      imagePullPolicy: $3
      command: [sleep, "3600"]
POD
}

# The policy server's own helpers: the JSON `policy-server.mjs up` wrote, the users and the peers the registry's log shows.
policy_value() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$POLICY" "$1"; }
registry_log() { docker logs "$REG" 2>&1; }
registry_users() { registry_log | grep -o 'auth\.user\.name="\?[A-Za-z0-9_]*' | sed 's/.*=//; s/"//' | sort -u; }
registry_users_are() { [ "$(registry_users)" = "$1" ]; }
registry_saw_user_from() { registry_log | grep "auth\.user\.name=\"\?$1" | grep -q "remoteaddr=\"\?$2:"; } # registry_saw_user_from USER ADDRESS
registry_saw_address() { registry_log | grep -q "remoteaddr=\"\?$1:"; }
registry_never_saw() { ! registry_log | grep -qF -- "$1"; }
# The service answers on the registry's route (401 or 200 once the policy has synced; before that the route is unknown).
registry_route() { # registry_route NODE ENDPOINT_ADDRESS REGISTRY_ID
  local code
  code=$(docker exec "$1" curl -sk -o /dev/null -w '%{http_code}' --resolve "$ENDPOINT_NAME:$NODEPORT:$2" "https://$ENDPOINT_NAME:$NODEPORT/registry/oci/$3/v2/") || return 1
  [ "$code" = 200 ] || [ "$code" = 401 ]
}

# The cluster lane's pull-secret check THROUGH the service. Needs: WORK_DIR ROOT W1 W2 IP1 IP2 ENDPOINT_NAME NODEPORT and a running service
# (`$WORK_DIR/k` is the manifest copy the lane applied). It
#   * starts the private registry on the kind network and the harness's policy server (policy-server.mjs: the e2e compose stack, an organisation with a
#     registry whose target is the private registry, an operator-approved private address, a service key), connected to the kind network;
#   * points the service at that policy server (config, key, CA bundle, host aliases, egress), which rolls the Deployment;
#   * installs the node scripts on worker 2 (the approved node) mapping the registry to the policy server's registry, so its kubelet pulls THROUGH the
#     endpoint on worker 1.
pull_through_service() {
  POLICY=$WORK_DIR/policy.json
  POLICY_STACK=$WORK_DIR/policy-stack
  private_registry_up
  node "$ROOT/tests/e2e/cluster/policy-server.mjs" up --work "$POLICY_STACK" --registry-host "$PRIVATE" --registry-cidr "$REGIP/32" --out "$POLICY"
  local registry_id service_key gateway gwip
  registry_id=$(policy_value registryId); service_key=$(policy_value serviceKey); gateway=$(policy_value gateway)
  docker network connect kind "$gateway"
  gwip=$(node_ip "$gateway")
  # Everything the service needs to reach the policy server (sync.e2e.test, the gateway's address) and the registry (private.kind.test, its address)
  # and to trust them: the e2e CA and the registry's CA, added to the system roots. Lane-only changes of the manifest copy.
  cat /etc/ssl/certs/ca-certificates.crt "$(policy_value ca)" "$WORK_DIR/registry/ca/ca.crt" > "$WORK_DIR/ca-bundle.pem"
  kubectl -n probation create secret generic probation-ca-bundle --from-file=ca-bundle.pem="$WORK_DIR/ca-bundle.pem"
  printf '%s\n' "$service_key" > "$WORK_DIR/service-key.policy"
  kubectl -n probation create secret generic probation-service-key --from-file=service-key="$WORK_DIR/service-key.policy" --dry-run=client -o yaml | kubectl apply -f -
  python3 - "$WORK_DIR/k" "$gwip" "$REGIP" <<'PY'
import pathlib, sys
k, gateway, registry = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def edit(name, old, new):
    path = k / name
    text = path.read_text()
    if text.count(old) != 1:
        sys.exit(f"{name}: expected exactly one {old!r}")
    path.write_text(text.replace(old, new))
edit("config.toml", 'server_url = "https://policy.example.org"', 'server_url = "https://sync.e2e.test"\nsync_interval_seconds = 5')
edit("deployment.yaml", "      enableServiceLinks: false\n",
     f"      enableServiceLinks: false\n      hostAliases:\n        - ip: {gateway}\n          hostnames: [sync.e2e.test]\n        - ip: {registry}\n          hostnames: [private.kind.test]\n")
edit("deployment.yaml", '          args: ["serve", "--config", "/etc/probation/config.toml"]\n',
     '          args: ["serve", "--config", "/etc/probation/config.toml"]\n          env:\n            - name: SSL_CERT_FILE\n              value: /etc/probation/ca-bundle/ca-bundle.pem\n')
edit("deployment.yaml", "            - name: tmp\n              mountPath: /tmp\n",
     "            - name: tmp\n              mountPath: /tmp\n            - name: ca-bundle\n              mountPath: /etc/probation/ca-bundle\n              readOnly: true\n")
edit("deployment.yaml", "            sizeLimit: 256Mi\n",
     "            sizeLimit: 256Mi\n        - name: ca-bundle\n          secret:\n            secretName: probation-ca-bundle\n")
edit("networkpolicy.yaml", "    # The policy server. Replace with its address",
     f"    # (lane) the policy server's gateway and the private registry, on the kind network\n    - to:\n        - ipBlock:\n            cidr: {gateway}/32\n        - ipBlock:\n            cidr: {registry}/32\n      ports:\n        - protocol: TCP\n          port: 443\n        - protocol: TCP\n          port: 5000\n    # The policy server. Replace with its address")
PY
  kubectl apply -k "$WORK_DIR/k"
  kubectl -n probation rollout status deployment/probation --timeout=300s
  # Worker 2 is the approved node: its runtime goes to the endpoint on worker 1 (the endpoint has no pod on worker 2, so the name is pinned to worker 1).
  docker exec "$W2" sh -c "echo '$IP1 $ENDPOINT_NAME' >> /etc/hosts"
  docker cp "$ROOT/deploy/kubernetes/node" "$W2:/opt/probation-node"
  docker cp "$WORK_DIR/tls.crt" "$W2:/opt/probation-ca.pem"
  expect "through the service: install-node.sh on worker 2 maps $PRIVATE to the policy server's registry $registry_id" docker exec "$W2" sh /opt/probation-node/install-node.sh --endpoint "https://$ENDPOINT_NAME:$NODEPORT" --ca /opt/probation-ca.pem --registry "$PRIVATE=$registry_id"
  docker exec "$W2" systemctl daemon-reload
  docker exec "$W2" systemctl restart containerd
  wait_cri "$W2" || fail "the CRI of worker 2 did not come back after the restart"
  expect "through the service: the service synced the policy and serves the registry route (401 without a credential)" wait_until 180 registry_route "$W2" "$IP1" "$registry_id"
  kubectl create secret docker-registry private-pull --docker-server="$PRIVATE" --docker-username=puller --docker-password="$PULL_PW"
  kubectl create secret docker-registry other-server-pull --docker-server=other.kind.test:5000 --docker-username=puller --docker-password="$PULL_PW"
  export LANE_POD_NODE=$W2
  lane_pod svc-secret-ok "$PRIV_IMAGE" Always private-pull
  lane_pod svc-secret-none "$PRIV_IMAGE" Always
  lane_pod svc-secret-other "$PRIV_IMAGE" Always other-server-pull
  unset LANE_POD_NODE
  local auth_failed='Failed to pull image.*(401|unauthorized|authoriz|authenticat|credential)'
  expect "through the service: a pod on worker 2 whose imagePullSecrets name $PRIVATE is pulled through the endpoint and runs" wait_until 180 pod_phase_is default svc-secret-ok Running
  expect "through the service: the registry saw the credential of the pull secret (user puller) from worker 1, where the service runs" registry_saw_user_from puller "$IP1"
  expect "through the service: the registry never saw worker 2 (its kubelet did not go to the registry itself)" not registry_saw_address "$IP2"
  expect "through the service: the registry saw only the user puller, never the service key's user" registry_users_are puller
  expect "through the service: the service key itself never reached the registry" registry_never_saw "$service_key"
  expect "through the service: the same image with NO pull secret is refused for authorization" wait_until 180 pod_event_matches default svc-secret-none "$auth_failed"
  expect "through the service: a secret of ANOTHER server (other.kind.test:5000) is refused the same way (matching is by the image's host)" wait_until 180 pod_event_matches default svc-secret-other "$auth_failed"
  expect "through the service: the pod with no secret does not run" not pod_phase_is default svc-secret-none Running
  expect "through the service: the pod with the other server's secret does not run" not pod_phase_is default svc-secret-other Running
  # The service pod of this block is replaced by the later rollout and the registry is removed by finish: keep their logs now.
  kubectl -n probation logs deployment/probation --all-containers --timestamps > "$WORK_DIR/logs/through-service-probation.log" 2>&1 || true
  registry_log > "$WORK_DIR/logs/private-registry.log" || true
  kubectl delete pod svc-secret-ok svc-secret-none svc-secret-other --ignore-not-found --wait=false
}
