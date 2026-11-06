#!/usr/bin/env python3
"""The native Python scripts must not depend on the console or the locale encoding: a Windows runner's default is cp1252,
which cannot write the look-alike letters of the checker's mutations (hosted run 42215710972). The mutation test runs
under an ASCII-only default encoding and ASCII-only strict stdio and must still pass.   python3 tests/e2e/native/encoding.test.py"""
import os, pathlib, subprocess, sys
for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(errors="backslashreplace")  # a console that cannot show a character (cp1252) must not crash the script

here = pathlib.Path(__file__).resolve().parent
env = {**os.environ, "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0", "LC_ALL": "C", "PYTHONIOENCODING": "ascii:strict"}
for script in ("check_workflow.test.py", "crlf.test.py"):
    r = subprocess.run([sys.executable, str(here / script)], capture_output=True, encoding="utf-8", errors="replace", env=env)
    assert r.returncode == 0, f"{script} must pass with an ASCII default encoding:\n{r.stdout[-600:]}\n{r.stderr[-1200:]}"
print("encoding.test: 2 scripts pass under an ASCII-only default encoding")
