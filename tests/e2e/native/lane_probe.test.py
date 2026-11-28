#!/usr/bin/env python3
"""The kind lane's real `probe` function (extracted from cluster/run-kind-lane.sh, run under its `set -euo pipefail`) with a stub `curl`.
Round 5 (hosted): `local from=$1 address=$2 cmd="... $address ..."` expanded $address before it was assigned, `probe` died with
`address: unbound variable`, and every dropped_or_refused NetworkPolicy assertion passed because "no output" counted as "dropped". A probe that
cannot run must not count as a drop; a curl timeout (28) must.   python3 tests/e2e/native/lane_probe.test.py"""
import os, pathlib, re, subprocess, sys, tempfile
for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(errors="backslashreplace")

if sys.platform == "win32":  # the lane is a bash script for Linux hosts; the check is not run there
    print("lane_probe.test: 0 probe runs (skipped on win32)")
    sys.exit(0)

here = pathlib.Path(__file__).resolve().parent
lane = (here.parent / "cluster" / "run-kind-lane.sh").read_text(encoding="utf-8").replace("\r\n", "\n")
lib = here.parent / "cluster" / "lane-lib.sh"
match = re.search(r"^probe\(\) \{.*?^\}\n", lane, re.S | re.M)
assert match, "run-kind-lane.sh defines probe()"
checks = 0


def run(call, curl_out, curl_rc):
    global checks
    checks += 1
    with tempfile.TemporaryDirectory(dir=os.environ.get("NATIVE_TEST_SCRATCH")) as d:
        stub = pathlib.Path(d) / "curl"
        stub.write_text('#!/bin/sh\necho "$*" > "$CURL_LOG"\nprintf \'%s\' "$CURL_OUT"\nexit "$CURL_RC"\n', encoding="utf-8")
        stub.chmod(0o755)
        script = f"set -euo pipefail\nENDPOINT_NAME=ep.test NODEPORT=30443\n. '{lib}'\n{match.group(0)}\n{call}"
        env = {**os.environ, "PATH": f"{d}:{os.environ['PATH']}", "CURL_OUT": curl_out, "CURL_RC": str(curl_rc), "CURL_LOG": str(pathlib.Path(d) / "log")}
        r = subprocess.run(["bash", "-c", script], capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=60)
        log = (pathlib.Path(d) / "log").read_text(encoding="utf-8") if (pathlib.Path(d) / "log").exists() else ""
    return r, log


refusal = '{"error":"NETWORK_NOT_ALLOWED"}'
r, log = run("probe runner 10.0.0.1", "body", 0)
assert r.returncode == 0 and r.stdout == "body", f"probe runs and prints the answer: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
assert "--resolve ep.test:30443:10.0.0.1" in log, f"curl pins the endpoint name to the address: {log!r}"
for helper in ("dropped", "dropped_or_refused"):
    r, _ = run(f"{helper} runner 10.0.0.1", "", 28)
    assert r.returncode == 0, f"{helper}: a curl timeout is a drop: {r.stderr!r}"
    r, _ = run(f"{helper} runner 10.0.0.1", "", 2)
    assert r.returncode != 0, f"{helper}: a probe that cannot run (curl status 2) is not a drop"
    # security-1-3: curl exit 0 is an HTTP answer, even with an empty body; it is never "nothing answered"
    r, _ = run(f"{helper} runner 10.0.0.1", "", 0)
    assert r.returncode != 0, f"{helper}: an empty HTTP answer (curl status 0) is not a drop"
r, _ = run("dropped_or_refused runner 10.0.0.1", refusal, 0)
assert r.returncode == 0, f"dropped_or_refused: the service's refusal passes: {r.stderr!r}"
# The inline "D1 (Local)" check of the lane uses the same helper: no private copy of the rule that curl 0 + empty body counts as a drop.
d1_local = next(l for l in lane.splitlines() if "D1 (Local)" in l)
assert 'dropped runner "$IP2"' in d1_local and "|| true" not in d1_local, f"D1 (Local) goes through dropped(): {d1_local!r}"
assert checks == 8, checks


# The pod and firewall helpers of the cri lane (kubelet pull path, pull-secret matching, nftables propagation), driven with stub kubectl and docker:
# each must say yes for the property and no for its absence, and no when the tool itself failed.
helper_runs = 0


def helper(call, **stubs):
    global helper_runs
    helper_runs += 1
    with tempfile.TemporaryDirectory(dir=os.environ.get("NATIVE_TEST_SCRATCH")) as d:
        for name, body in stubs.items():
            path = pathlib.Path(d) / name
            path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
            path.chmod(0o755)
        script = f"set -euo pipefail\n. '{lib}'\n{call}"
        env = {**os.environ, "PATH": f"{d}:{os.environ['PATH']}", "POLL_SECONDS": "0.05", "STATE": str(pathlib.Path(d) / "state")}
        return subprocess.run(["bash", "-c", script], capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=60)


pull_failed = "Failed: Failed to pull image \"registry.k8s.io/pause:3.9\": dial tcp: lookup probation.kind.test: no such host\nBackOff: Back-off pulling image"
pulled = "Pulled: Container image \"x@sha256:00\" already present on machine"
for out, want, why in ((pull_failed, 0, "the pull failure naming the endpoint"), (pulled, 1, "an unrelated event"), ("", 1, "no event at all")):
    r = helper("pod_event_matches default p 'Failed to pull image.*probation[.]kind[.]test'", kubectl=f"printf '%s\\n' '{out}'")
    assert (r.returncode == 0) == (want == 0), f"pod_event_matches on {why}: rc={r.returncode} {r.stderr!r}"
r = helper("pod_event_matches default p 'Failed to pull image'", kubectl="echo 'Failed to pull image' >&2; exit 1")
assert r.returncode != 0, "pod_event_matches: a failing kubectl is not a match (its error text is not an event)"
for out, want in (("Running", 0), ("Pending", 1), ("", 1)):
    r = helper("pod_phase_is default p Running", kubectl=f"printf '%s' '{out}'")
    assert (r.returncode == 0) == (want == 0), f"pod_phase_is Running on {out!r}: rc={r.returncode}"
r = helper("wait_until 2 test -e \"$STATE\"", kubectl="exit 0")
assert r.returncode != 0, "wait_until: a condition that never holds fails after its budget"
r = helper("(sleep 0.2; touch \"$STATE\") & wait_until 10 test -e \"$STATE\"", kubectl="exit 0")
assert r.returncode == 0, f"wait_until: a condition that becomes true is seen: {r.stderr!r}"
# nftables: a table is present or absent as `nft list table` says; the firewall is loaded only when BOTH tables are, gone only when NEITHER is.
nft = 'case "$*" in *probation_node_ingress*) exit "$INGRESS";; *probation_node_egress*) exit "$EGRESS";; *probation_lane_marker*) exit "$MARKER";; esac; exit 0'
for egress, ingress, loaded, gone in ((0, 0, True, False), (0, 1, False, False), (1, 0, False, False), (1, 1, False, True)):
    for fn, want in (("fw_loaded", loaded), ("fw_gone", gone)):
        r = helper(f"INGRESS={ingress} EGRESS={egress} {fn} node1", docker=nft.replace('"$INGRESS"', str(ingress)).replace('"$EGRESS"', str(egress)))
        assert (r.returncode == 0) == want, f"{fn} with egress rc {egress}, ingress rc {ingress}: rc={r.returncode} {r.stderr!r}"
for rc in (0, 1):
    r = helper("not docker exec node1 true", docker=f"exit {rc}")
    assert (r.returncode == 0) == (rc != 0), f"not inverts a command that exits {rc}"
for rc, present in ((0, True), (1, False)):
    r = helper("nft_table_present node1 probation_lane_marker", docker=f"exit {rc}")
    assert (r.returncode == 0) == present, f"nft_table_present on `nft list table` rc {rc}"
    r = helper("nft_table_absent node1 probation_lane_marker", docker=f"exit {rc}")
    assert (r.returncode == 0) != present, f"nft_table_absent on `nft list table` rc {rc}"
print(f"lane_probe.test: {checks} probe runs hold, {helper_runs} helper runs hold")
