#!/usr/bin/env python3
"""Turns the pod of deploy/kubernetes/deployment.yaml into a Pod that `podman kube play` can run, to see the SHIPPED pod spec (init
container, security context, mounts, command line, read-only root file system) start the real image. Test-only changes, all listed
here and nowhere else: the image is the locally built one, the claim becomes a PVC object, the Secrets and the ConfigMap are created
(the real ones are the operator's), a hostPort is added so the host can reach the pod, the probes are dropped (the scenario polls), and
the in-memory staging volume is an ordinary shared one (podman gives each container its own tmpfs), the Secret files are world-readable (podman has no fsGroup to let the pod's user read them), the approved-node list is a test range.

    render.py OUT.yaml --image IMG --tls-cert PEM --tls-key PEM --host-port 18443 [--no-stage]

--no-stage drops the init container and mounts the service key Secret (a group- or world-readable file, what a kubelet leaves behind with fsGroup) straight
where the service reads it: the service must refuse to start with it."""
import argparse, json, pathlib
import yaml

root = pathlib.Path(__file__).resolve().parents[4]
p = argparse.ArgumentParser()
p.add_argument("out")
p.add_argument("--image", required=True)
p.add_argument("--tls-cert", required=True)
p.add_argument("--tls-key", required=True)
p.add_argument("--host-port", type=int, required=True)
p.add_argument("--no-stage", action="store_true")
a = p.parse_args()

k = root / "deploy" / "kubernetes"
dep = yaml.safe_load((k / "deployment.yaml").read_text())
config = (k / "config.toml").read_text()
spec = json.loads(json.dumps(dep["spec"]["template"]["spec"]))
for c in spec.get("initContainers", []) + spec["containers"]:
    c["image"] = a.image
    c["imagePullPolicy"] = "Never"
    for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
        c.pop(probe, None)
spec["containers"][0]["ports"][0]["hostPort"] = a.host_port
spec["containers"][0]["ports"][0]["hostIP"] = "127.0.0.1"  # reachable from this host only
for key in ("nodeSelector", "tolerations", "serviceAccountName", "automountServiceAccountToken", "enableServiceLinks", "terminationGracePeriodSeconds"):
    spec.pop(key, None)
spec["securityContext"].pop("fsGroup", None)  # podman has no fsGroup
spec["securityContext"].pop("fsGroupChangePolicy", None)
for v in spec["volumes"]:
    if v["name"] == "config":
        v["configMap"] = {"name": "probation-config", "defaultMode": 0o444}  # the generated, hash-suffixed name is a kustomize matter
    if v.get("persistentVolumeClaim"):
        v["persistentVolumeClaim"]["claimName"] = "probation-data"
for v in spec["volumes"]:
    if "secret" in v:  # a kubelet with fsGroup makes the pod's user able to read a Secret file; podman has no fsGroup, so the mode says it
        v["secret"]["defaultMode"] = 0o444
for v in spec["volumes"]:
    if v["name"] == "runtime" and "emptyDir" in v:  # podman makes a Memory emptyDir a tmpfs PER CONTAINER; a shared volume is what Kubernetes gives
        v["emptyDir"].pop("medium", None)
if a.no_stage:
    spec["initContainers"] = []
    for v in spec["volumes"]:
        if v["name"] == "runtime":
            v.pop("emptyDir")
            v["secret"] = {"secretName": "probation-service-key", "defaultMode": 0o444, "items": [{"key": "service-key", "path": "service.key"}]}
old = 'allowed_peer_cidrs = ["192.0.2.11/32", "192.0.2.12/32", "192.0.2.13/32"]'
assert old in config, "the shipped approved-node line changed"
config = config.replace(old, 'allowed_peer_cidrs = ["10.0.0.0/8"]')
docs = [
    {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "probation-config"}, "data": {"config.toml": config}},
    {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "probation-tls"}, "type": "kubernetes.io/tls",
     "stringData": {"tls.crt": pathlib.Path(a.tls_cert).read_text(), "tls.key": pathlib.Path(a.tls_key).read_text()}},
    {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "probation-service-key"}, "stringData": {"service-key": "prb_" + "a" * 32 + "\n"}},
    {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "probation-data"},
     "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}},
    {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "probation-smoke", "labels": {"app.kubernetes.io/name": "probation"}}, "spec": spec},
]
pathlib.Path(a.out).write_text(yaml.safe_dump_all(docs))
