#!/usr/bin/env python3
"""Tests of the test runner itself (run_tests.py): the verified bypasses of a test file must be
rejected, a good one accepted, and the stub-checker canary must trip.
python3 tests/e2e/native/run_tests.test.py"""
import os, pathlib, sys, tempfile

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import run_tests  # noqa: E402  (main is guarded)

scratch = os.environ.get("NATIVE_TEST_SCRATCH")
rejected = 0
with tempfile.TemporaryDirectory(dir=scratch) as d:
    d = pathlib.Path(d)

    def js(name, body):
        path = d / f"{name}.test.mjs"
        path.write_text(body)
        return path

    def py(name, body):
        path = d / f"{name}.test.py"
        path.write_text(body)
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
    py_ok = py("fine", 'print("fine.test: 3 bypasses all fail")\n')
    assert run_tests.run_one(py_ok, minimum=0) == [], "a good python test is accepted"

# A Windows path is not a valid --import specifier for node; a file URL is.
assert run_tests.count_import().startswith("file:///"), run_tests.count_import()
assert run_tests.count_import().endswith("/count-asserts.mjs")
rejected += 0

# The canary: a checker that always exits 0 must make check_workflow.test.py fail.
assert run_tests.stub_checker_canary(), "check_workflow.test.py passed against a checker that always exits 0"
rejected += 1
print(f"run_tests.test: {rejected} bypasses rejected, good tests accepted")
