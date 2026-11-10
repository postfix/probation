#!/usr/bin/env python3
"""Tests of the test runner itself (run_tests.py): the verified bypasses of a test file must be
rejected, a good one accepted, and the stub-checker canary must trip.
python3 tests/e2e/native/run_tests.test.py"""
import os, pathlib, sys, tempfile
for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(errors="backslashreplace")  # a console that cannot show a character (cp1252) must not crash the script

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import run_tests  # noqa: E402  (main is guarded)

scratch = os.environ.get("NATIVE_TEST_SCRATCH")
rejected = 0
with tempfile.TemporaryDirectory(dir=scratch) as d:
    d = pathlib.Path(d)

    def js(name, body):
        path = d / f"{name}.test.mjs"
        path.write_text(body, encoding="utf-8")
        return path

    def py(name, body):
        path = d / f"{name}.test.py"
        path.write_text(body, encoding="utf-8")
        return path

    ok_js = js("good", 'import assert from "node:assert/strict";\nassert.equal(1, 1);\nconsole.log("good.test: ok");\n')
    assert run_tests.run_one(ok_js, minimum=1) == [], "a good test is accepted"
    bypasses = {
        # the failing assertion is commented out; exit 0 and the success line remain, but nothing was asserted
        "comment-wrapped body": js("wrapped", 'import assert from "node:assert/strict";\n/*\nassert.equal(1, 2);\n*/\nconsole.log("wrapped.test: ok");\n'),
        # destructured exit: exits 0 before the failing assertion and before the success line
        "destructured exit(0)": js("destructured", 'import assert from "node:assert/strict";\nconst { exit } = process;\nexit(0);\nassert.equal(1, 2);\nconsole.log("destructured.test: ok");\n'),
        # a failing assertion that is awaited nowhere: exit code is non-zero
        "a failing assertion": js("failing", 'import assert from "node:assert/strict";\nassert.equal(1, 2);\nconsole.log("failing.test: ok");\n'),
        # the success line is missing
        "no success line": js("silent", 'import assert from "node:assert/strict";\nassert.equal(1, 1);\n'),
        # the success line is not last
        "output after the success line": js("trailing", 'import assert from "node:assert/strict";\nassert.equal(1, 1);\nconsole.log("trailing.test: ok");\nconsole.log("more");\n'),
        # `if failed:` changed to `pass`: a BYPASS line is printed but the exit is 0 and the success line is there
        "if failed changed to pass": py("passed", 'failed = ["x"]\nprint("BYPASS (checker passed): x")\nif failed:\n    pass\nprint("passed.test: 1 bypasses all fail")\n'),
    }
    for name, path in bypasses.items():
        findings = run_tests.run_one(path, minimum=1)
        assert findings, f"{name} must be rejected"
        rejected += 1
    # A failing test's own stderr and stdout tail are in the findings, so a hosted failure can be diagnosed from the log.
    crash = js("crashing", 'import assert from "node:assert/strict";\nconsole.log("progress-marker");\nconsole.error("stderr-marker boom");\nprocess.exitCode = 1;\n')
    shown = "\n".join(run_tests.run_one(crash, minimum=0))
    assert "stderr-marker boom" in shown and "progress-marker" in shown, shown
    py_ok = py("fine", 'print("fine.test: 3 bypasses all fail")\n')
    assert run_tests.run_one(py_ok, minimum=0) == [], "a good python test is accepted"

# A Windows path is not a valid --import specifier for node; a file URL is.
assert run_tests.count_import().startswith("file:///"), run_tests.count_import()
assert run_tests.count_import().endswith("/count-asserts.mjs")
rejected += 0

# main() itself: one failing .test.mjs among passing ones must exit 1; all passing exits 0; a registered file that
# vanished, an unregistered file, and a Python test whose own count fell below its pin are each findings.
import io, json, contextlib  # noqa: E402


def main_over(files, expected):
    real_canary, run_tests.stub_checker_canary = run_tests.stub_checker_canary, lambda: True  # the canary has its own test below
    with tempfile.TemporaryDirectory(dir=scratch) as t:
        t = pathlib.Path(t)
        for name, body in files.items():
            (t / name).write_text(body, encoding="utf-8")
        (t / "expected-asserts.json").write_text(json.dumps(expected), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                code = run_tests.main(t)
            finally:
                run_tests.stub_checker_canary = real_canary
        return code, out.getvalue()


GOOD = 'import assert from "node:assert/strict";\nassert.equal(1, 1);\nconsole.log("a.test: ok");\n'
BAD = 'import assert from "node:assert/strict";\nassert.equal(1, 1);\nprocess.exitCode = 1;\nconsole.log("b.test: ok");\n'
PY = 'print("p.test: 5 bypasses all fail")\n'
code, out = main_over({"a.test.mjs": GOOD, "p.test.py": PY}, {"a.test.mjs": 1, "p.test.py": 5})
assert code == 0, out
for what, (files, expected) in {
    "a failing test file": ({"a.test.mjs": GOOD, "b.test.mjs": BAD, "p.test.py": PY}, {"a.test.mjs": 1, "b.test.mjs": 1, "p.test.py": 5}),
    "a registered test file deleted": ({"a.test.mjs": GOOD}, {"a.test.mjs": 1, "p.test.py": 5}),
    "a test file with no registration": ({"a.test.mjs": GOOD, "p.test.py": PY}, {"a.test.mjs": 1}),
    "a Python test whose count halved": ({"a.test.mjs": GOOD, "p.test.py": PY}, {"a.test.mjs": 1, "p.test.py": 10}),
}.items():
    code, out = main_over(files, expected)
    assert code == 1, f"{what} must exit 1: {out}"
    rejected += 1
# judge: a Python test that reports fewer checks than pinned is rejected
assert run_tests.judge(here / "p.test.py", 0, "p.test: 3 bypasses all fail\n", 3, 50), "a halved Python count"
assert not run_tests.judge(here / "p.test.py", 0, "p.test: 50 bypasses all fail\n", 50, 50)

# The canary: a checker that always exits 0 must make check_workflow.test.py fail.
assert run_tests.stub_checker_canary(), "check_workflow.test.py passed against a checker that always exits 0"
rejected += 1
print(f"run_tests.test: {rejected} bypasses rejected, good tests accepted")
