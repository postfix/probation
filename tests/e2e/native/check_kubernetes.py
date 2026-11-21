#!/usr/bin/env python3
"""Static contract of deploy/kubernetes (slice 26): every property the cluster row requires, read from the manifests themselves.

    python3 tests/e2e/native/check_kubernetes.py [--dir deploy/kubernetes] [--deployable]

Prints one `FINDING <id>: <what>` line per violated property and exits 1; exits 0 and prints `check_kubernetes: ok` when all hold.
The shipped tree carries a placeholder image digest (64 zeros on registry.example.invalid) and passes WITHOUT --deployable;
`--deployable` is the check an operator (and the kind job) runs after setting the real digest: it refuses the placeholder.
This reads YAML and TOML only. It proves the files say the right thing; it does not prove a cluster behaves that way (see
docs/plans/package-firewall-mvp-lf/evidence/slice-26.md, "Lanes"). Schema validity against the Kubernetes API is kubeconform's job.
"""
import argparse, ipaddress, pathlib, re, sys, tomllib
import yaml

here = pathlib.Path(__file__).resolve().parent
ALLOWED_KINDS = {"Namespace", "ServiceAccount", "Service", "NetworkPolicy", "PodDisruptionBudget", "Deployment",
                 "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8"]
SECRET_SHAPES = [r"prb_[A-Za-z0-9]{32}", r"-----BEGIN [A-Z ]*PRIVATE KEY", r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*[\"']?[A-Za-z0-9+/_-]{12,}"]
PLACEHOLDER = re.compile(r"^registry\.example\.invalid/.*@sha256:0{64}$")
FORBIDDEN_SUBRESOURCES = {"pods/exec", "pods/portforward", "pods/ephemeralcontainers", "pods/attach", "pods/proxy", "services/proxy", "nodes/proxy"}


def load(directory):
    """(kustomization, [(file, document)]) with the documents of every resource file the kustomization lists."""
    kustomization = yaml.safe_load((directory / "kustomization.yaml").read_text(encoding="utf-8"))
    docs = []
    for name in kustomization.get("resources", []):
        text = (directory / name).read_text(encoding="utf-8")
        docs += [(name, d) for d in yaml.safe_load_all(text) if d]
    return kustomization, docs


def containers(pod):
    return [("init:" + c["name"], c) for c in pod.get("initContainers", [])] + [(c["name"], c) for c in pod.get("containers", [])]


def check(directory, deployable=False):
    out = []
    add = lambda ident, text: out.append(f"FINDING {ident}: {text}")
    kustomization, docs = load(directory)

    listed = set(kustomization.get("resources", []))
    present = {p.name for p in directory.glob("*.yaml")} - {"kustomization.yaml", "pvc.yaml"}
    if listed != present:
        add("K-LIST", f"kustomization.yaml lists {sorted(listed)} but the directory holds {sorted(present)}")
    if "pvc.yaml" in listed or not (directory / "pvc.yaml").exists():
        add("K-PVC", "pvc.yaml must exist and must NOT be listed in the kustomization (so `kubectl delete -k` and pruning never delete the data)")
    kinds = [d.get("kind") for _, d in docs]
    for kind in sorted(set(kinds) - ALLOWED_KINDS):
        add("K-KIND", f"{kind} is not a resource of this deployment (a Secret, Role, binding or second workload kind must not ship here)")
    blob = "\n".join(p.read_text(encoding="utf-8") for p in sorted(directory.glob("*.yaml")) + [directory / "config.toml"] if p.exists())
    for shape in SECRET_SHAPES:
        if re.search(shape, blob):
            add("K-SECRET", f"a manifest carries something shaped like a secret ({shape})")

    by_kind = lambda kind: [d for _, d in docs if d.get("kind") == kind]
    one = lambda kind: (by_kind(kind) or [{}])[0]

    # Namespace: the restricted Pod Security Standard is enforced.
    labels = one("Namespace").get("metadata", {}).get("labels", {})
    for mode in ("enforce", "audit", "warn"):
        if labels.get(f"pod-security.kubernetes.io/{mode}") != "restricted":
            add("N-PSS", f"the namespace does not set pod-security.kubernetes.io/{mode}: restricted")

    # ServiceAccount: no token, no grants.
    if one("ServiceAccount").get("automountServiceAccountToken") is not False:
        add("SA-TOKEN", "the ServiceAccount must set automountServiceAccountToken: false")

    # The generated ConfigMap carries a hash of its content, so a changed file rolls the pod.
    generators = kustomization.get("configMapGenerator", [])
    options = kustomization.get("generatorOptions", {})
    if len(generators) != 1 or generators[0].get("files") != ["config.toml"] or options.get("disableNameSuffixHash") or generators[0].get("options", {}).get("disableNameSuffixHash"):
        add("K-CONFIG-ROLL", "the config must come from one configMapGenerator over config.toml WITH the hash suffix (editing it must roll the Deployment)")
    if "ConfigMap" in kinds:
        add("K-KIND", "a ConfigMap file must not ship: the generator owns it")

    deployment = one("Deployment")
    spec = deployment.get("spec", {})
    pod = spec.get("template", {}).get("spec", {})
    # One active store owner (02-architecture.md: a Recreate Deployment over a ReadWriteOncePod claim).
    if len(by_kind("Deployment")) != 1 or "StatefulSet" in kinds or "DaemonSet" in kinds:
        add("S-ONE", "exactly one Deployment is required (no StatefulSet or DaemonSet)")
    if spec.get("replicas") != 1:
        add("S-REPLICAS", f"replicas must be 1 (one store owner), found {spec.get('replicas')!r}")
    if spec.get("strategy", {}).get("type") != "Recreate" or spec.get("strategy", {}).get("rollingUpdate"):
        add("S-RECREATE", "strategy must be Recreate (the old pod is gone before the new one starts)")
    claim = {}
    try:
        claim = yaml.safe_load((directory / "pvc.yaml").read_text(encoding="utf-8")) or {}
    except OSError:
        pass
    if claim.get("kind") != "PersistentVolumeClaim" or claim.get("spec", {}).get("accessModes") != ["ReadWriteOncePod"]:
        add("S-RWOP", "pvc.yaml must be one PersistentVolumeClaim with accessModes [ReadWriteOncePod]")
    if not claim.get("spec", {}).get("resources", {}).get("requests", {}).get("storage"):
        add("S-STORAGE", "the claim requests no storage")
    claim_volumes = [v for v in pod.get("volumes", []) if v.get("persistentVolumeClaim")]
    if len(claim_volumes) != 1 or claim_volumes[0]["persistentVolumeClaim"].get("claimName") != claim.get("metadata", {}).get("name"):
        add("S-CLAIM", "the pod must mount exactly the claim of pvc.yaml (by name)")
    if pod.get("terminationGracePeriodSeconds", 30) < 45:
        add("S-GRACE", "terminationGracePeriodSeconds must cover the 30 s drain and the 5 s log drain (at least 45)")

    # Pod: restricted, no host access, pinned image, probes, node selection.
    sc = pod.get("securityContext", {})
    if sc.get("runAsNonRoot") is not True or not isinstance(sc.get("runAsUser"), int) or sc.get("runAsUser", 0) == 0:
        add("P-NONROOT", "the pod must set runAsNonRoot: true and a numeric non-zero runAsUser (the image's user is a name)")
    if (sc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
        add("P-SECCOMP", "the pod must set seccompProfile RuntimeDefault")
    if pod.get("automountServiceAccountToken") is not False:
        add("P-TOKEN", "the pod must set automountServiceAccountToken: false")
    if pod.get("serviceAccountName") != one("ServiceAccount").get("metadata", {}).get("name"):
        add("P-SA", "the pod does not use the shipped ServiceAccount")
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(key):
            add("P-HOST", f"{key} must not be set")
    if any("hostPath" in v for v in pod.get("volumes", [])):
        add("P-HOSTPATH", "no hostPath volume is allowed")
    if not pod.get("nodeSelector") or not any(t.get("effect") == "NoSchedule" for t in pod.get("tolerations", [])):
        add("P-NODES", "the pod must select the service pool with a nodeSelector and tolerate its NoSchedule taint")
    images = set()
    for name, c in containers(pod):
        csc = c.get("securityContext", {})
        if csc.get("allowPrivilegeEscalation") is not False:
            add("C-ESCALATION", f"{name}: allowPrivilegeEscalation must be false")
        if csc.get("readOnlyRootFilesystem") is not True:
            add("C-READONLY", f"{name}: readOnlyRootFilesystem must be true")
        if csc.get("capabilities", {}).get("drop") != ["ALL"] or csc.get("capabilities", {}).get("add") or csc.get("privileged"):
            add("C-CAPS", f"{name}: capabilities must drop ALL, add none, and the container must not be privileged")
        image = c.get("image", "")
        images.add(image)
        if not re.search(r"@sha256:[0-9a-f]{64}$", image):
            add("C-IMAGE", f"{name}: the image must be pinned by sha256 digest, found {image!r}")
        elif deployable and (re.search(r"@sha256:0{64}$", image) or ".invalid/" in image):
            add("C-IMAGE", f"{name}: the placeholder image {image!r} is not deployable (set the digest of a real build)")
        elif not deployable and re.search(r"@sha256:0{64}$", image) and not PLACEHOLDER.match(image):
            add("C-IMAGE", f"{name}: an all-zero digest is accepted only as the registry.example.invalid placeholder")
        if not c.get("resources", {}).get("requests") or not c.get("resources", {}).get("limits", {}).get("memory"):
            add("C-RESOURCES", f"{name}: requests and a memory limit are required")
        if any(p.get("hostPort") for p in c.get("ports", [])):
            add("C-HOSTPORT", f"{name}: no hostPort")
        for env in c.get("env", []):
            if "value" in env and re.search(r"(?i)key|token|secret|password", env["name"]):
                add("C-ENV", f"{name}: env {env['name']} carries a literal value")
    if len(images) != 1:
        add("C-IMAGE-SAME", f"the init container and the service must run the identical image (two hand-edited lines drift): {sorted(images)}")
    main = (pod.get("containers") or [{}])[0]
    for probe, path in (("startupProbe", "/health/live"), ("livenessProbe", "/health/live"), ("readinessProbe", "/health/ready")):
        get = main.get(probe, {}).get("httpGet", {})
        if get.get("path") != path or get.get("scheme") != "HTTPS":
            add("C-PROBE", f"{probe} must be an HTTPS GET of {path}")

    # The service key: staged private by an init container into the in-memory volume the config names.
    try:
        config = tomllib.loads((directory / "config.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        config = {}
        add("CFG-PARSE", "config.toml must exist and be valid TOML")
    mounts = {m["name"]: m["mountPath"] for m in main.get("volumeMounts", [])}
    volumes = {v["name"]: v for v in pod.get("volumes", [])}
    key_file = config.get("service_policy", {}).get("service_key_file", "")
    stage = next((c for n, c in containers(pod) if n == "init:stage-service-key"), None)
    runtime_mount = mounts.get("runtime")
    if not stage or "umask 077" not in " ".join(stage.get("command", [])) or "chmod 0600 " + key_file not in " ".join(stage.get("command", [])):
        add("K-KEYSTAGE", "an init container must copy the service key to service_key_file with umask 077 and chmod 0600 (fsGroup makes Secret files group-readable and the service refuses that)")
    if not runtime_mount or not key_file.startswith(runtime_mount + "/") or volumes.get("runtime", {}).get("emptyDir", {}).get("medium") != "Memory":
        add("K-KEYVOL", "service_key_file must live on an in-memory emptyDir mounted into the service container")
    for secret in ("service-key", "tls"):
        if not volumes.get(secret, {}).get("secret", {}).get("secretName"):
            add("K-SECRETREF", f"the {secret} volume must reference a Secret by name")
    generator_name = (generators[0] if generators else {}).get("name")
    if volumes.get("config", {}).get("configMap", {}).get("name") != generator_name:
        add("K-CONFIG-VOL", "the config volume must name the generated ConfigMap")

    # The service's own configuration (config.toml).
    listen = config.get("listen", "")
    port = int(listen.rsplit(":", 1)[-1]) if ":" in listen else 0
    public = config.get("public_url", "")
    m = re.fullmatch(r"https://[^/:@?#]+:(\d+)", public)
    if not m:
        add("CFG-PUBLIC", f"public_url must be an https origin with an explicit port, found {public!r}")
    if not listen.startswith("0.0.0.0:") or (main.get("ports") or [{}])[0].get("containerPort") != port:
        add("CFG-LISTEN", "listen must be 0.0.0.0:<containerPort> (a pod address is not known in advance)")
    if not config.get("tls_cert_path") or not config.get("tls_key_path"):
        add("CFG-TLS", "a non-loopback listener requires tls_cert_path and tls_key_path")
    elif not all(p.startswith(mounts.get("tls", "\0") + "/") for p in (config["tls_cert_path"], config["tls_key_path"])):
        add("CFG-TLSMOUNT", "the TLS paths must lie in the tls Secret mount")
    if config.get("data_dir") != mounts.get("data"):
        add("CFG-DATA", "data_dir must be the mount of the data claim")
    if "blocklist_file" in config or "management" in config or "service_policy" not in config:
        add("CFG-MODE", "the cluster endpoint is a shared service: [service_policy] only, no blocklist_file and no [management]")
    if config.get("service_policy", {}).get("trusted_proxies"):
        add("CFG-PROXIES", "[service_policy] trusted_proxies must stay empty: nothing in front of this listener may speak for a client")
    if config.get("allow_network_data_dir"):
        add("CFG-NETFS", "allow_network_data_dir must not be set: the store's lock is not reliable on a network file system")
    cidrs = config.get("allowed_peer_cidrs", [])
    nets = []
    for text in cidrs:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            add("CFG-CIDR", f"allowed_peer_cidrs entry {text!r} is no CIDR")
            continue
        nets.append(net)
        if net.prefixlen < (8 if net.version == 4 else 32):
            add("CFG-CIDR", f"allowed_peer_cidrs entry {text} is wider than the service accepts (/8 IPv4, /32 IPv6)")
        elif net.prefixlen < (32 if net.version == 4 else 128):
            add("CFG-NODE-CIDR", f"allowed_peer_cidrs entry {text} is a range, not one approved node address: list each approved node as a single address")
    if not cidrs:
        add("CFG-CIDR", "allowed_peer_cidrs must list the approved nodes")

    # The one endpoint: exactly one Service, a NodePort with source-address preservation (D1).
    services = by_kind("Service")
    if len(services) != 1:
        add("SVC-ONE", f"exactly one Service is allowed (a second way in defeats D1), found {len(services)}")
    for service in services:
        svc = service.get("spec", {})
        if svc.get("type") != "NodePort":
            add("SVC-TYPE", "the endpoint is a NodePort")
        if svc.get("externalTrafficPolicy") != "Local":
            add("SVC-ETP", "externalTrafficPolicy must be Local: with Cluster the node's own address replaces the caller's and every host that reaches a NodePort looks approved (D1)")
        if any(k in svc for k in ("externalIPs", "loadBalancerIP", "loadBalancerSourceRanges", "clusterIP", "loadBalancerClass")):
            add("SVC-EXTRA", "no externalIPs, loadBalancerIP, loadBalancerSourceRanges, loadBalancerClass or fixed clusterIP")
        ports = svc.get("ports", [])
        if len(ports) != 1 or ports[0].get("targetPort") != (main.get("ports") or [{}])[0].get("name") or (m and ports[0].get("nodePort") != int(m.group(1))):
            add("SVC-PORT", "one port, targeting the container's named port, with nodePort equal to the port of public_url")
        if svc.get("selector") != spec.get("template", {}).get("metadata", {}).get("labels"):
            add("SVC-SELECTOR", "the Service selector must equal the pod labels")
        if not 30000 <= (ports[0].get("nodePort", 0) if ports else 0) <= 32767:
            add("SVC-NODEPORT", "nodePort must lie in the default 30000-32767 range")

    # The admission backstop for D1: every rule of the policy, verbatim, on CREATE and UPDATE of Services, failing closed.
    policy = one("ValidatingAdmissionPolicy").get("spec", {})
    expressions = {v.get("expression", "") for v in policy.get("validations", [])}
    required = {"object.metadata.name == 'probation'", "object.spec.type == 'NodePort'",
                "has(object.spec.externalTrafficPolicy) && object.spec.externalTrafficPolicy == 'Local'",
                "!has(object.spec.externalIPs) || size(object.spec.externalIPs) == 0"}
    rules = policy.get("matchConstraints", {}).get("resourceRules", [])
    covers = any(set(r.get("operations", [])) >= {"CREATE", "UPDATE"} and r.get("resources") == ["services"] for r in rules)
    if not required <= expressions or expressions - required or policy.get("failurePolicy") != "Fail" or not covers:
        add("VAP-ETP", "the ValidatingAdmissionPolicy (failurePolicy Fail, CREATE and UPDATE of services) must carry exactly the four rules: only the Service `probation`, a NodePort, externalTrafficPolicy Local, no externalIPs")
    binding = one("ValidatingAdmissionPolicyBinding").get("spec", {})
    if binding.get("validationActions") != ["Deny"] or binding.get("matchResources", {}).get("namespaceSelector", {}).get("matchLabels", {}).get("kubernetes.io/metadata.name") != "probation":
        add("VAP-BINDING", "the admission policy must be bound with validationActions [Deny] to the probation namespace")

    # NetworkPolicy: default deny, then the approved nodes in, the registries and DNS out; every rule bounded in peer and port.
    policies = by_kind("NetworkPolicy")
    deny = [p for p in policies if p["spec"].get("podSelector") == {} and set(p["spec"].get("policyTypes", [])) == {"Ingress", "Egress"} and not p["spec"].get("ingress") and not p["spec"].get("egress")]
    if not deny:
        add("NP-DENY", "a default-deny NetworkPolicy (empty podSelector, Ingress and Egress, no rules) is required")
    ingress_blocks = []
    for p in policies:
        for rule in p["spec"].get("ingress", []):
            if not rule.get("from"):
                add("NP-INGRESS", "an ingress rule without `from` admits every source")
            for peer in rule.get("from", []):
                block = peer.get("ipBlock")
                if not block:
                    add("NP-INGRESS", "an ingress rule admits something other than node addresses (only ipBlock peers are allowed)")
                    continue
                net = ipaddress.ip_network(block["cidr"], strict=False)
                ingress_blocks.append(net)
                if net.prefixlen < 8 or block.get("except"):
                    add("NP-INGRESS", f"ingress ipBlock {block['cidr']} is too wide")
            for pt in rule.get("ports", []):
                if pt.get("port") != port or pt.get("protocol") != "TCP":
                    add("NP-INGRESS-PORT", f"ingress allows {pt}, not just TCP {port}")
            if not rule.get("ports"):
                add("NP-INGRESS-PORT", "an ingress rule without ports admits every port")
        for rule in p["spec"].get("egress", []):
            if not rule.get("to"):
                add("NP-EGRESS", "an egress rule without `to` admits every destination")
            for pt in rule.get("ports", []):
                if pt.get("port") not in (53, 443):
                    add("NP-EGRESS-PORT", f"egress allows port {pt.get('port')}, only DNS (53) and https (443) are needed")
            if not rule.get("ports"):
                add("NP-EGRESS-PORT", "an egress rule without ports admits every port")
            for peer in rule.get("to", []):
                block = peer.get("ipBlock")
                if block and ipaddress.ip_network(block["cidr"], strict=False).prefixlen < 8:
                    excepted = {str(ipaddress.ip_network(e, strict=False)) for e in block.get("except", [])}
                    missing = [r for r in PRIVATE_RANGES if r not in excepted]
                    if missing:
                        add("NP-EGRESS-PRIVATE", f"an egress rule to {block['cidr']} does not except {missing}")
    if sorted(map(str, ingress_blocks)) != sorted(map(str, nets)):
        add("NP-NODES", "the ipBlocks of the ingress policy must equal allowed_peer_cidrs of config.toml")

    # PodDisruptionBudget.
    pdb = one("PodDisruptionBudget").get("spec", {})
    if pdb.get("minAvailable") != 1 and pdb.get("maxUnavailable") != 0:
        add("PDB", "the PodDisruptionBudget must refuse a voluntary eviction of the single pod (minAvailable 1)")
    if pdb.get("selector", {}).get("matchLabels") != spec.get("selector", {}).get("matchLabels"):
        add("PDB-SELECTOR", "the PodDisruptionBudget selector must equal the Deployment selector")

    # optional/: guidance files. A Role there must never grant what reaches the service from the pod's own loopback address (exec, port-forward...)
    # or what can put a process there (a change to a workload or a pod: a patched Deployment gets a sidecar on the loopback: an approved node).
    workloads = {"deployments", "statefulsets", "daemonsets", "replicasets", "replicationcontrollers", "jobs", "cronjobs", "pods", "deployments/scale"}
    writes = {"create", "update", "patch", "delete", "deletecollection", "*"}
    for path in sorted((directory / "optional").glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if (doc or {}).get("kind") in ("Role", "ClusterRole"):
                for rule in doc.get("rules", []):
                    granted = set(rule.get("resources", []))
                    verbs = set(rule.get("verbs", []))
                    if granted & FORBIDDEN_SUBRESOURCES or "*" in granted or "pods/*" in granted:
                        add("RBAC-LOOPBACK", f"{path.name}: grants {sorted(granted & (FORBIDDEN_SUBRESOURCES | {'*', 'pods/*'}))}: a loopback connection through the pod is admitted by the service")
                    if verbs & {"escalate", "bind", "impersonate"}:
                        add("RBAC-WORKLOAD", f"{path.name}: grants {sorted(verbs & {'escalate', 'bind', 'impersonate'})}")
                    mutating = verbs & writes
                    # deleting a pod is the documented fence step and only recreates the same spec; every other write to a workload can add a sidecar
                    allowed_delete = granted == {"pods"} and mutating <= {"delete"}
                    # What the service reads or is protected by: a changed ConfigMap changes `allowed_peer_cidrs` at the next pod restart (the Role may
                    # delete pods), a changed NetworkPolicy or Service reopens the pod, and a Secret holds the service key and the TLS key.
                    if granted & {"secrets"}:
                        add("RBAC-CONFIG", f"{path.name}: {sorted(verbs)} on secrets: the service key and the TLS key are in them")
                    if granted & {"configmaps", "networkpolicies", "services", "serviceaccounts"} and mutating:
                        add("RBAC-CONFIG", f"{path.name}: {sorted(mutating)} on {sorted(granted & {'configmaps', 'networkpolicies', 'services', 'serviceaccounts'})} changes who the service admits (allowed_peer_cidrs, the policies around the pod)")
                    if granted & workloads and mutating and not allowed_delete:
                        add("RBAC-WORKLOAD", f"{path.name}: {sorted(mutating)} on {sorted(granted & workloads)} lets its holder change what runs next to the service: its pod's loopback is admitted, so that is node-equivalent")
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=str(here.parents[2] / "deploy" / "kubernetes"))
    parser.add_argument("--deployable", action="store_true")
    args = parser.parse_args()
    findings = check(pathlib.Path(args.dir), args.deployable)
    print("\n".join(findings) if findings else "check_kubernetes: ok")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
