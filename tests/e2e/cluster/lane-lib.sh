# Sourced by run-kind-lane.sh (and by tests/node_scripts.rs, which drives these functions with a stub `probe`): the assertion bookkeeping
# and the assertions over what a probe prints. AUTHORED, NOT EXECUTED against a cluster; the functions' own decisions are tested with stubs.
#
# `probe FROM ADDRESS` (defined by the lane) prints the body the service answered, and fails (curl's status) when nothing answered.
# Each helper captures the output first: `probe | grep -q` under `pipefail` would turn grep's early exit (SIGPIPE) into a failure.
ran=0
failed=0
expect() { # expect NAME COMMAND...: the command's exit status decides
  local name=$1; shift
  ran=$((ran + 1))
  if "$@" >>"$WORK_DIR/logs/expect.log" 2>&1; then echo "ok   $name"; else echo "FAIL $name"; failed=1; fi
}
fail() { echo "FAIL $*"; exit 1; }
finish() {
  local rc=$?  # the status of whatever ended the script: kept, never replaced by $failed
  # Whatever ended the lane, the policies it lifted are put back first (the cluster is deleted next, but an operator who runs the lane against a
  # cluster of their own with a keep-flag, or a `kind` that fails to delete, must not be left with an open ingress).
  [ -z "${POLICIES_LIFTED:-}" ] || restore_policies >/dev/null 2>&1 || true
  kind export logs "$WORK_DIR/logs/kind" --name "$CLUSTER" >/dev/null 2>&1 || true
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  if [ "$rc" -ne 0 ]; then echo "lane aborted with status $rc after $ran assertion(s)"; exit "$rc"; fi
  echo "assertions ran: $ran, failed: $failed"
  if [ "$ran" -eq 0 ]; then echo "FAIL no assertion ran"; exit 3; fi
  exit "$failed"
}
# The service itself refused the caller, naming its own view of the address.
refused_by_service() { local out; out=$(probe "$@" || true); grep -q NETWORK_NOT_ALLOWED <<<"$out"; }
# The service answered and did not refuse the caller.
admitted() { local out; out=$(probe "$@") && [ -n "$out" ] && ! grep -q NETWORK_NOT_ALLOWED <<<"$out"; }
# Nothing answered at all (a layer in front dropped the packet).
dropped() { local out; out=$(probe "$@" || true); [ -z "$out" ]; }
dropped_or_refused() { local out; out=$(probe "$@" || true); [ -z "$out" ] || grep -q NETWORK_NOT_ALLOWED <<<"$out"; }
# The address the service says it saw: the refusal names it ("this API key may not be used from ADDRESS").
source_seen() { local out; out=$(probe "$@" || true); sed -n 's/.*may not be used from \([0-9A-Fa-f:.]*\).*/\1/p' <<<"$out" | sed -n 1p; }
source_is() { local want=$1; shift; [ "$(source_seen "$@")" = "$want" ]; }
# Bounded wait for a node's CRI (a kind node's containerd) to answer.
wait_cri() { local i; for i in $(seq 1 60); do docker exec "$1" crictl info >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

# The admission backstop refuses a switch to Cluster. kubectl EXITS 1 with the policy's name when it denies, so the output is captured first: a
# `kubectl ... | grep -q` under pipefail takes that exit status and is never true (recheck-3 M-2).
denied() {
  local out
  out=$(kubectl -n probation patch svc probation --type merge -p '{"spec":{"externalTrafficPolicy":"Cluster"}}' --dry-run=server 2>&1 || true)
  grep -q 'probation-one-local-service' <<<"$out"
}
# D1 phase A: the namespace's default-deny (podSelector {}, Ingress and Egress) and probation-ingress would drop an unapproved caller BEFORE the
# service. NetworkPolicies add up, so a temporary policy that allows ALL ingress to the service pod lifts the ingress layer (deleting only
# probation-ingress leaves default-deny in force and nobody reaches the pod). restore_policies puts back everything phase A and the negative
# control changed (the temporary policy goes, `apply -k` restores externalTrafficPolicy Local and the admission binding); finish calls it.
lift_ingress_policy() {
  POLICIES_LIFTED=1
  kubectl -n probation apply -f - <<'POLICY'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: phase-a-allow-ingress, namespace: probation}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/name: probation}}
  policyTypes: [Ingress]
  ingress: [{}]
POLICY
}
restore_policies() {
  kubectl -n probation delete networkpolicy phase-a-allow-ingress --ignore-not-found
  kubectl apply -k "$WORK_DIR/k"
  POLICIES_LIFTED=
}
