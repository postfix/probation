#!/usr/bin/env python3
"""Runs every tests/e2e/native/*.test.* file and judges it by what it DID, not by what it says:
exit code 0, its own success line as the very last line of stdout, no BYPASS/CRASH/FAIL line, and for
JavaScript tests at least the recorded minimum number of assertion calls (count-asserts.mjs). Two
canaries run first: check_workflow.test.py must FAIL against a checker that always exits 0, and the
judge itself must reject a silent, a failing and a non-asserting test.   python3 tests/e2e/native/run_tests.py
"""
import json, os, pathlib, re, subprocess, sys, tempfile

here = pathlib.Path(__file__).resolve().parent
SKIP_ON = {"win32": {"clients.test.mjs", "rendezvous-cli.test.mjs"}}  # their fakes are POSIX shell scripts
BAD_LINE = re.compile(r"^(BYPASS|CRASH|FAIL)\b")


def count_import():
    """The --import specifier of the assertion counter: a file URL, because node rejects a Windows path."""
    return (here / "count-asserts.mjs").as_uri()


def success_pattern(path):
    stem = path.name.split(".test.")[0]
    return re.compile(rf"^{re.escape(stem)}\.test: " + (r"ok$" if path.suffix == ".mjs" else r".+$"))


def judge(path, code, stdout, count, minimum):
    """The findings for one finished test run; empty means it holds."""
    findings = []
    lines = [line.rstrip() for line in stdout.splitlines() if line.strip()]
    if code != 0:
        findings.append(f"{path.name} exited {code}")
    if not lines or not success_pattern(path).match(lines[-1]):
        findings.append(f"{path.name}: its success line is not the last line of output (last: {lines[-1][:80] if lines else 'nothing'!r})")
    findings += [f"{path.name}: output line {line[:80]!r}" for line in lines if BAD_LINE.match(line)]
    if path.suffix == ".mjs" and (count is None or count < minimum):
        findings.append(f"{path.name}: {count} assertion calls, expected at least {minimum}")
    return findings


def run_one(path, minimum, extra_env=None):
    env = {**os.environ, **(extra_env or {})}
    if path.suffix == ".mjs":
        with tempfile.TemporaryDirectory(dir=os.environ.get("NATIVE_TEST_SCRATCH")) as d:
            counts = pathlib.Path(d) / "count"
            env["NATIVE_ASSERT_COUNT_FILE"] = str(counts)
            r = subprocess.run(["node", "--import", count_import(), str(path)], capture_output=True, text=True, env=env, timeout=900)
            count = int(counts.read_text()) if counts.exists() else None
    else:
        r = subprocess.run([sys.executable, str(path)], capture_output=True, text=True, env=env, timeout=900)
        count = None
    findings = judge(path, r.returncode, r.stdout, count, minimum)
    if findings:  # a hosted failure is diagnosed from this log: the test's own stderr and the tail of its stdout
        tail = lambda text: "\n".join(text.rstrip().splitlines()[-40:])
        findings.append(f"{path.name} stderr:\n{tail(r.stderr) or '(empty)'}\n{path.name} stdout tail:\n{tail(r.stdout) or '(empty)'}")
    return findings


def stub_checker_canary():
    """True if check_workflow.test.py correctly fails when the checker always exits 0."""
    with tempfile.TemporaryDirectory(dir=os.environ.get("NATIVE_TEST_SCRATCH")) as d:
        stub = pathlib.Path(d) / "stub_checker.py"
        stub.write_text("import sys\nsys.exit(0)\n")
        r = subprocess.run([sys.executable, str(here / "check_workflow.test.py")], capture_output=True, text=True,
                           env={**os.environ, "NATIVE_CHECKER": str(stub)}, timeout=900)
    return r.returncode != 0


def judge_canary():
    p = here / "x.test.mjs"
    cases = [
        (judge(p, 0, "output\n", 5, 1), "no success line"),
        (judge(p, 1, "x.test: ok\n", 5, 1), "a failing exit"),
        (judge(p, 0, "x.test: ok\n", 0, 1), "no assertions"),
        (judge(p, 0, "BYPASS: y\nx.test: ok\n", 5, 1), "a BYPASS line"),
    ]
    return [what for findings, what in cases if not findings]


def main():
    skipped = SKIP_ON.get(sys.platform, set())
    if not stub_checker_canary():
        print("FAIL canary: check_workflow.test.py passed against a checker that always exits 0")
        return 1
    missed = judge_canary()
    if missed:
        print(f"FAIL canary: the judge accepted {missed}")
        return 1
    expected = json.loads((here / "expected-asserts.json").read_text())
    tests = sorted(here.glob("*.test.*"))
    failures = []
    for path in tests:
        if path.name in skipped:
            print(f"SKIPPED on {sys.platform}: {path.name} (POSIX shell fakes)")
            continue
        if path.suffix == ".mjs" and path.name not in expected:
            failures.append(f"{path.name} has no entry in expected-asserts.json")
            continue
        findings = run_one(path, expected.get(path.name, 0))
        print(f"{'ok  ' if not findings else 'FAIL'} {path.name}" + "".join(f"\n     {f}" for f in findings))
        failures += findings
    if failures:
        print(f"run_tests: {len(failures)} finding(s)")
        return 1
    print(f"run_tests: {len(tests) - len(skipped & {t.name for t in tests})} test files hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
