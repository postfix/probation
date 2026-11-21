#!/usr/bin/env python3
"""The static contract of deploy/kubernetes holds for the shipped manifests, and each property fails when its line is broken:
every mutation below edits ONE thing in a copy of the manifests and the checker must report EXACTLY the named set of finding ids (an
unexpected extra finding fails the test as much as a missing one), and the shipped copy must report none.
python3 tests/e2e/native/check_kubernetes.test.py"""
import importlib.util, os, pathlib, shutil, sys, tempfile
for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(errors="backslashreplace")

here = pathlib.Path(__file__).resolve().parent
root = here.parents[2]
spec = importlib.util.spec_from_file_location("check_kubernetes", here / "check_kubernetes.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
shipped = root / "deploy" / "kubernetes"

D = "deployment.yaml"
POD_SECURITY = "            allowPrivilegeEscalation: false\n            readOnlyRootFilesystem: true\n            capabilities:\n              drop: [\"ALL\"]\n          resources:\n            requests:\n              cpu: 500m"
NODES = '"192.0.2.11/32", "192.0.2.12/32", "192.0.2.13/32"'
DIGEST = "registry.example.invalid/probation/probation@sha256:" + "0" * 64
DEPLOY = "NOT-IN-TEMPLATE"

# (name, file, old text, new text, the exact set of finding ids). `old` must occur exactly once in the file.
MUTATIONS = [
    ("externalTrafficPolicy Cluster", "service.yaml", "externalTrafficPolicy: Local", "externalTrafficPolicy: Cluster", {"SVC-ETP"}),
    ("externalTrafficPolicy removed", "service.yaml", "  externalTrafficPolicy: Local\n", "", {"SVC-ETP"}),
    ("a ClusterIP service", "service.yaml", "type: NodePort", "type: ClusterIP", {"SVC-TYPE"}),
    ("externalIPs", "service.yaml", "  sessionAffinity: None\n", "  sessionAffinity: None\n  externalIPs: [\"203.0.113.9\"]\n", {"SVC-EXTRA"}),
    ("loadBalancerSourceRanges", "service.yaml", "  sessionAffinity: None\n", "  sessionAffinity: None\n  loadBalancerSourceRanges: [\"0.0.0.0/0\"]\n", {"SVC-EXTRA"}),
    ("a headless clusterIP", "service.yaml", "  sessionAffinity: None\n", "  sessionAffinity: None\n  clusterIP: None\n", {"SVC-EXTRA"}),
    ("a second Service", "service.yaml", "---NEVER---", "", None),  # handled below (needs an appended document)
    ("nodePort differs from public_url", "service.yaml", "nodePort: 30443", "nodePort: 30444", {"SVC-PORT"}),
    ("two replicas", D, "replicas: 1", "replicas: 2", {"S-REPLICAS"}),
    ("a RollingUpdate", D, "    type: Recreate\n", "    type: RollingUpdate\n", {"S-RECREATE"}),
    ("ReadWriteOnce claim", "pvc.yaml", 'accessModes: ["ReadWriteOncePod"]', 'accessModes: ["ReadWriteOnce"]', {"S-RWOP"}),
    ("ReadWriteMany claim", "pvc.yaml", 'accessModes: ["ReadWriteOncePod"]', 'accessModes: ["ReadWriteMany"]', {"S-RWOP"}),
    ("a claim without storage", "pvc.yaml", "    requests:\n      storage: 200Gi\n", "    requests: {}\n", {"S-STORAGE"}),
    ("the pod mounts another claim", D, "claimName: probation-data", "claimName: other", {"S-CLAIM"}),
    ("short grace period", D, "terminationGracePeriodSeconds: 60", "terminationGracePeriodSeconds: 10", {"S-GRACE"}),
    ("no node selector", D, '      nodeSelector:\n        probation.example/service-node: "true"\n', "", {"P-NODES"}),
    ("runs as root", D, "runAsUser: 999", "runAsUser: 0", {"P-NONROOT"}),
    ("runAsNonRoot off", D, "runAsNonRoot: true", "runAsNonRoot: false", {"P-NONROOT"}),
    ("no seccomp profile", D, "        seccompProfile:\n          type: RuntimeDefault\n", "", {"P-SECCOMP"}),
    ("host network", D, "      enableServiceLinks: false\n", "      enableServiceLinks: false\n      hostNetwork: true\n", {"P-HOST"}),
    ("a hostPath volume", D, "        - name: tmp\n          emptyDir:", "        - name: host\n          hostPath:\n            path: /\n        - name: tmp\n          emptyDir:", {"P-HOSTPATH"}),
    ("service account token mounted", D, "      automountServiceAccountToken: false\n", "", {"P-TOKEN"}),
    ("privilege escalation allowed", D, POD_SECURITY, POD_SECURITY.replace("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true"), {"C-ESCALATION"}),
    ("writable root file system", D, POD_SECURITY, POD_SECURITY.replace("readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false"), {"C-READONLY"}),
    ("capabilities not dropped", D, POD_SECURITY, POD_SECURITY.replace('drop: ["ALL"]', 'add: ["NET_ADMIN"]'), {"C-CAPS"}),
    ("an image tag instead of a digest (both)", D, DIGEST, "registry.example.invalid/probation/probation:latest", {"C-IMAGE"}),
    ("an all-zero digest on a real host", D, "registry.example.invalid/probation/probation@sha256:" + "0" * 64 + "\n          imagePullPolicy: IfNotPresent\n          args", "ghcr.io/example/probation@sha256:" + "0" * 64 + "\n          imagePullPolicy: IfNotPresent\n          args", {"C-IMAGE", "C-IMAGE-SAME"}),
    ("the init container on another digest", D, DIGEST + "\n          imagePullPolicy: IfNotPresent\n          command", "registry.example.invalid/probation/probation@sha256:" + "1" * 64 + "\n          imagePullPolicy: IfNotPresent\n          command", {"C-IMAGE-SAME"}),
    ("no memory limit", D, "            limits:\n              memory: 4Gi\n", "", {"C-RESOURCES"}),
    ("a literal secret in the environment", D, "          args: [\"serve\"", "          env:\n            - name: SERVICE_KEY\n              value: hunter2hunter2\n          args: [\"serve\"", {"C-ENV"}),
    ("a host port", D, "              containerPort: 8443\n", "              containerPort: 8443\n              hostPort: 8443\n", {"C-HOSTPORT"}),
    ("liveness over a different path", D, "              path: /health/live\n              port: https\n              scheme: HTTPS\n            periodSeconds: 10", "              path: /health/ready\n              port: https\n              scheme: HTTPS\n            periodSeconds: 10", {"C-PROBE"}),
    ("the service key copied group-readable", D, "chmod 0600 /run/probation/service.key", "chmod 0640 /run/probation/service.key", {"K-KEYSTAGE"}),
    ("the key staged without a umask", D, "umask 077; ", "", {"K-KEYSTAGE"}),
    ("the service key on disk", D, "        - name: runtime\n          emptyDir:\n            medium: Memory\n            sizeLimit: 1Mi", "        - name: runtime\n          emptyDir:\n            sizeLimit: 1Mi", {"K-KEYVOL"}),
    ("the TLS Secret not referenced", D, "            secretName: probation-tls\n", "            secretName: \"\"\n", {"K-SECRETREF"}),
    ("the config volume names a fixed ConfigMap", D, "            name: probation-config\n", "            name: probation-config-fixed\n", {"K-CONFIG-VOL"}),
    ("a Secret in the manifests", "kustomization.yaml", "  - pdb.yaml\n", "  - pdb.yaml\n  - secret.yaml\n", {"K-KIND"}),
    ("a manifest not in the kustomization", "kustomization.yaml", "  - pdb.yaml\n", "", {"K-LIST", "PDB", "PDB-SELECTOR"}),
    ("the claim in the kustomization", "kustomization.yaml", "  - pdb.yaml\n", "  - pdb.yaml\n  - pvc.yaml\n", {"K-LIST", "K-PVC", "K-KIND"}),
    ("the config name without a hash suffix", "kustomization.yaml", "configMapGenerator:\n", "generatorOptions:\n  disableNameSuffixHash: true\nconfigMapGenerator:\n", {"K-CONFIG-ROLL"}),
    ("no generator", "kustomization.yaml", "configMapGenerator:\n  - name: probation-config\n    files:\n      - config.toml\n", "", {"K-CONFIG-ROLL", "K-CONFIG-VOL"}),
    ("the namespace stops enforcing restricted", "namespace.yaml", "pod-security.kubernetes.io/enforce: restricted", "pod-security.kubernetes.io/enforce: baseline", {"N-PSS"}),
    ("the service account mounts a token", "serviceaccount.yaml", "automountServiceAccountToken: false", "automountServiceAccountToken: true", {"SA-TOKEN"}),
    ("plain http public_url", "config.toml", 'public_url = "https://', 'public_url = "http://', {"CFG-PUBLIC"}),
    ("public_url without a port", "config.toml", ":30443\"", "\"", {"CFG-PUBLIC"}),
    ("no TLS", "config.toml", 'tls_cert_path = "/etc/probation/tls/tls.crt"\n', "", {"CFG-TLS"}),
    ("loopback listener", "config.toml", 'listen = "0.0.0.0:8443"', 'listen = "127.0.0.1:8443"', {"CFG-LISTEN"}),
    ("data directory off the claim", "config.toml", 'data_dir = "/var/lib/probation"', 'data_dir = "/tmp/probation"', {"CFG-DATA"}),
    ("a blocklist file in service mode", "config.toml", "cooldown_seconds = 86400\n", "blocklist_file = \"/etc/probation/blocklist.json\"\ncooldown_seconds = 86400\n", {"CFG-MODE"}),
    ("trusted proxies listed", "config.toml", 'service_key_file = "/run/probation/service.key"', 'service_key_file = "/run/probation/service.key"\ntrusted_proxies = ["10.0.0.0/8"]', {"CFG-PROXIES"}),
    ("a network file system allowed", "config.toml", "cooldown_seconds = 86400\n", "allow_network_data_dir = true\ncooldown_seconds = 86400\n", {"CFG-NETFS"}),
    ("a whole subnet approved", "config.toml", NODES, '"192.0.2.0/24"', {"CFG-NODE-CIDR", "NP-NODES"}),
    ("the whole internet approved", "config.toml", NODES, '"0.0.0.0/0"', {"CFG-CIDR", "NP-NODES"}),
    ("no approved node", "config.toml", "[" + NODES + "]", "[]", {"CFG-CIDR", "NP-NODES"}),
    ("approved nodes differ from the network policy", "networkpolicy.yaml", "cidr: 192.0.2.13/32", "cidr: 192.0.2.99/32", {"NP-NODES"}),
    ("no default deny", "networkpolicy.yaml", "  policyTypes: [\"Ingress\", \"Egress\"]\n", "  policyTypes: [\"Ingress\"]\n", {"NP-DENY"}),
    ("ingress from a pod selector", "networkpolicy.yaml", "    - from:\n        - ipBlock:\n            cidr: 192.0.2.11/32\n", "    - from:\n        - podSelector: {}\n        - ipBlock:\n            cidr: 192.0.2.11/32\n", {"NP-INGRESS"}),
    ("a second ingress rule with no from", "networkpolicy.yaml", "  policyTypes: [\"Ingress\"]\n  ingress:\n", "  policyTypes: [\"Ingress\"]\n  ingress:\n    - ports:\n        - protocol: TCP\n          port: 8443\n", {"NP-INGRESS"}),
    ("ingress on another port", "networkpolicy.yaml", "        - protocol: TCP\n          port: 8443\n", "        - protocol: TCP\n          port: 9999\n", {"NP-INGRESS-PORT"}),
    ("an egress rule with no to", "networkpolicy.yaml", "  egress:\n    # Cluster DNS", "  egress:\n    - ports:\n        - protocol: TCP\n          port: 53\n    # Cluster DNS", {"NP-EGRESS"}),
    ("egress on every port", "networkpolicy.yaml", "      ports:\n        - protocol: TCP\n          port: 443\n    # The policy server.", "    # The policy server.", {"NP-EGRESS-PORT"}),
    ("egress to private ranges", "networkpolicy.yaml", "              - 10.0.0.0/8\n", "", {"NP-EGRESS-PRIVATE"}),
    ("a disruption budget that allows eviction", "pdb.yaml", "minAvailable: 1", "minAvailable: 0", {"PDB"}),
    ("a disruption budget for another pod", "pdb.yaml", "      app.kubernetes.io/name: probation", "      app.kubernetes.io/name: other", {"PDB-SELECTOR"}),
    ("the admission policy allows Cluster", "admission-policy.yaml", "object.spec.externalTrafficPolicy == 'Local'", "object.spec.externalTrafficPolicy == 'Cluster'", {"VAP-ETP"}),
    ("the admission policy fails open", "admission-policy.yaml", "failurePolicy: Fail", "failurePolicy: Ignore", {"VAP-ETP"}),
    ("the admission binding only warns", "admission-policy.yaml", 'validationActions: ["Deny"]', 'validationActions: ["Warn"]', {"VAP-BINDING"}),
    ("the admission policy no longer covers UPDATE", "admission-policy.yaml", 'operations: ["CREATE", "UPDATE"]', 'operations: ["CREATE"]', {"VAP-ETP"}),
    ("the admission policy admits LoadBalancer too", "admission-policy.yaml", "object.spec.type == 'NodePort'", "object.spec.type in ['NodePort', 'LoadBalancer']", {"VAP-ETP"}),
    ("the admission policy drops the externalIPs rule", "admission-policy.yaml", '    - expression: "!has(object.spec.externalIPs) || size(object.spec.externalIPs) == 0"\n      message: "the probation Service has no externalIPs"\n', "", {"VAP-ETP"}),
    ("an operator role that may patch the Deployment", "optional/operator-role.yaml", '    resources: ["deployments"]\n    verbs: ["get", "list", "watch"]', '    resources: ["deployments"]\n    verbs: ["get", "list", "watch", "patch"]', {"RBAC-WORKLOAD"}),
    ("an operator role that may create pods", "optional/operator-role.yaml", '    resources: ["pods"]\n    verbs: ["delete"]', '    resources: ["pods"]\n    verbs: ["delete", "create"]', {"RBAC-WORKLOAD"}),
    ("an operator role that may escalate", "optional/operator-role.yaml", '    resources: ["persistentvolumeclaims"]\n    verbs: ["get", "list", "watch"]', '    resources: ["persistentvolumeclaims"]\n    verbs: ["get", "list", "watch", "escalate"]', {"RBAC-WORKLOAD"}),
    ("an operator role that may read secrets", "optional/operator-role.yaml", '    resources: ["persistentvolumeclaims"]\n    verbs: ["get", "list", "watch"]', '    resources: ["persistentvolumeclaims", "secrets"]\n    verbs: ["get", "list", "watch"]', {"RBAC-CONFIG"}),
    ("an operator role that may edit a configmap", "optional/operator-role.yaml", '    resources: ["persistentvolumeclaims"]\n    verbs: ["get", "list", "watch"]', '    resources: ["persistentvolumeclaims", "configmaps"]\n    verbs: ["get", "list", "watch", "patch"]', {"RBAC-CONFIG"}),
    ("an operator role that may delete a network policy", "optional/operator-role.yaml", '    resources: ["persistentvolumeclaims"]\n    verbs: ["get", "list", "watch"]', '    resources: ["persistentvolumeclaims", "networkpolicies"]\n    verbs: ["get", "list", "watch", "delete"]', {"RBAC-CONFIG"}),
    ("an operator role that may port-forward", "optional/operator-role.yaml", '    resources: ["pods", "pods/log", "events"]', '    resources: ["pods", "pods/log", "pods/portforward", "events"]', {"RBAC-LOOPBACK"}),
    ("an operator role with a wildcard", "optional/operator-role.yaml", '    resources: ["persistentvolumeclaims"]', '    resources: ["*"]', {"RBAC-LOOPBACK"}),
]


def ids(findings):
    return {f.split(":", 1)[0].split(" ", 1)[1] for f in findings}


def main():
    checks = 0
    base = checker.check(shipped)
    assert base == [], "the shipped manifests must satisfy the contract:\n" + "\n".join(base)
    checks += 1
    deployable = checker.check(shipped, deployable=True)
    assert ids(deployable) == {"C-IMAGE"} and len(deployable) == 2, f"--deployable refuses exactly the placeholder (both containers): {deployable}"
    checks += 1
    with tempfile.TemporaryDirectory(dir=os.environ.get("NATIVE_TEST_SCRATCH")) as scratch:
        scratch = pathlib.Path(scratch)
        # A directory with no manifests is not a pass: the kustomization is required to exist and to list what it holds.
        empty = scratch / "empty"
        empty.mkdir()
        (empty / "kustomization.yaml").write_text("resources: []\n", encoding="utf-8")
        found = ids(checker.check(empty))
        assert {"S-REPLICAS", "SVC-ONE", "VAP-ETP", "K-CONFIG-ROLL"} <= found, f"an empty deployment must not satisfy the contract: {found}"
        checks += 1
        for index, (name, file, old, new, expected) in enumerate(MUTATIONS):
            copy = scratch / f"m{index}"
            shutil.copytree(shipped, copy)
            if name == "a Secret in the manifests":
                (copy / "secret.yaml").write_text("apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n", encoding="utf-8")
                expected = {"K-KIND"}
            if name == "a second Service":
                svc = (copy / "service.yaml").read_text(encoding="utf-8")
                (copy / "service.yaml").write_text(svc + "---\n" + svc.replace("name: probation", "name: second").replace("externalTrafficPolicy: Local", "externalTrafficPolicy: Cluster"), encoding="utf-8")
                expected = {"SVC-ONE", "SVC-ETP", "SVC-SELECTOR"}
            else:
                path = copy / file
                text = path.read_text(encoding="utf-8")
                assert text.count(old) == 1 or (old == DIGEST and text.count(old) == 2), f"mutation {name!r}: the text to change occurs {text.count(old)} times in {file}"
                path.write_text(text.replace(old, new), encoding="utf-8")
            found = checker.check(copy)
            assert ids(found) == expected, f"mutation {name!r}: expected exactly {sorted(expected)}, got {sorted(ids(found))}:\n" + "\n".join(found)
            checks += 1
    # The apply order of the guide is the order of the kind lane script: namespace, the two Secrets, the claim, the kustomization.
    guide = (root / "docs/operations.md").read_text(encoding="utf-8")
    block = guide[guide.index("Apply in THIS order"):]
    block = block[block.index("```\n") + 4:block.index("\n```", block.index("```\n") + 4)]
    lane = (root / "tests/e2e/cluster/run-kind-lane.sh").read_text(encoding="utf-8")
    steps = [("namespace.yaml", "kubectl apply -f"), ("create secret tls", None), ("create secret generic", None), ("pvc.yaml", "kubectl apply -f"), ("apply -k", None)]
    def order(text):
        positions = []
        for needle, _ in steps:
            at = [m for m in range(len(text)) if text.startswith(needle, m)]
            assert at, f"{needle!r} is missing"
            positions.append(at[-1] if needle == "apply -k" and text is lane else at[0])
        return positions
    guide_order, lane_order = order(block), order(lane[lane.index("# Apply in the order"):])
    assert guide_order == sorted(guide_order), f"the guide applies in the wrong order: {guide_order}"
    assert lane_order == sorted(lane_order), f"the lane script applies in the wrong order: {lane_order}"
    assert block.index("namespace.yaml") < block.index("create secret"), "the namespace exists before a Secret is created in it"
    # D1 phase A (recheck-3 M-3): deleting only probation-ingress leaves the namespace's default-deny in force, so neither the guide nor the lane may
    # say so; both name the temporary allow-all policy that lifts the ingress layer, and the lane's EXIT trap (finish) restores it.
    lib = (root / "tests/e2e/cluster/lane-lib.sh").read_text(encoding="utf-8")
    assert "delete networkpolicy probation-ingress" not in guide and "delete networkpolicy probation-ingress" not in lane, "phase A must not delete only probation-ingress"
    assert "phase-a-allow-ingress" in guide and "phase-a-allow-ingress" in lib and "lift_ingress_policy" in lane, "guide, lib and lane name the same temporary policy"
    assert "restore_policies" in lib[lib.index("finish()"):lib.index("refused_by_service()")], "finish restores the lifted policies on any exit"
    deny = (root / "deploy/kubernetes/networkpolicy.yaml").read_text(encoding="utf-8")
    assert "name: default-deny" in deny, "the premise of the phase A text: a namespace default-deny exists"
    checks += 4
    print(f"check_kubernetes.test: {checks} checks hold ({len(MUTATIONS)} mutations, each producing exactly its named findings)")


if __name__ == "__main__":
    main()
