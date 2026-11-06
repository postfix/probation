#!/usr/bin/env python3
"""A Windows checkout may turn every line ending into CRLF (core.autocrlf). None of the checks may change their
verdict: the workflow checker and the Dockerfile test accept CRLF copies of their inputs, and .gitattributes keeps
scripts and requirements files LF in the first place.   python3 tests/e2e/native/crlf.test.py"""
import os, pathlib, subprocess, sys, tempfile

here = pathlib.Path(__file__).resolve().parent
root = here.parents[2]
scratch = os.environ.get("NATIVE_TEST_SCRATCH")


def crlf(src, dst):
    data = src.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    dst.write_bytes(data)
    assert b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b""), dst


with tempfile.TemporaryDirectory(dir=scratch) as d:
    d = pathlib.Path(d)
    names = {
        "wf.yml": root / ".github/workflows/native-clients.yml", "release.yml": root / ".github/workflows/release.yml",
        "ci.txt": here / "ci-requirements.txt", "chk.txt": here / "checker-requirements.txt",
        "native.txt": root / "tests/e2e/compose/clients/native-requirements.txt", "tunnel.json": here / "tunnel.json", "pins.json": here / "pins.json",
    }
    for name, src in names.items():
        crlf(src, d / name)
    r = subprocess.run([sys.executable, str(here / "check_workflow.py"), "--file", str(d / "wf.yml"), "--release", str(d / "release.yml"),
                        "--ci-requirements", str(d / "ci.txt"), "--checker-requirements", str(d / "chk.txt"), "--native-requirements", str(d / "native.txt"),
                        "--tunnel", str(d / "tunnel.json"), "--pins", str(d / "pins.json")], capture_output=True, text=True)
    assert r.returncode == 0, f"the workflow checker must pass on CRLF copies:\n{r.stdout}{r.stderr}"
    # The Dockerfile test reads the image definition and its requirements from NATIVE_CLIENTS_DIR.
    clients = d / "clients"
    clients.mkdir()
    crlf(root / "tests/e2e/compose/clients/native.Dockerfile", clients / "native.Dockerfile")
    crlf(root / "tests/e2e/compose/clients/native-requirements.txt", clients / "native-requirements.txt")
    r = subprocess.run(["node", str(here / "dockerfile.test.mjs")], capture_output=True, text=True, env={**os.environ, "NATIVE_CLIENTS_DIR": str(clients)})
    assert r.returncode == 0 and r.stdout.strip().endswith("dockerfile.test: ok"), f"dockerfile.test must pass on CRLF copies:\n{r.stdout}{r.stderr}"

# .gitattributes keeps what bash and the parsers read LF.
need = ["tests/e2e/fixtures/make-ca.sh", "tests/e2e/native/ci-requirements.txt", "tests/e2e/native/checker-requirements.txt",
        "tests/e2e/compose/clients/native-requirements.txt", "tests/e2e/compose/clients/native.Dockerfile", ".github/workflows/native-clients.yml",
        "tests/e2e/native/run_tests.py", "tests/e2e/native/rendezvous.mjs", "config.sample.toml"]
r = subprocess.run(["git", "check-attr", "eol", "--"] + need, cwd=root, capture_output=True, text=True)
assert r.returncode == 0, r.stderr
not_lf = [line for line in r.stdout.splitlines() if not line.endswith(": eol: lf")]
assert not not_lf, f".gitattributes must set eol=lf for: {not_lf}"
print(f"crlf.test: {len(names) + 2} inputs hold with CRLF line endings, {len(need)} files pinned to LF")
