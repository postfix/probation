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
r, _ = run("dropped_or_refused runner 10.0.0.1", refusal, 0)
assert r.returncode == 0, f"dropped_or_refused: the service's refusal passes: {r.stderr!r}"
assert checks == 6, checks
print(f"lane_probe.test: {checks} probe runs hold")
