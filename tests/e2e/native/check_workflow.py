#!/usr/bin/env python3
"""Structure check for .github/workflows/native-clients.yml (publishing-proxy Slice 5).

The workflow is compared with a canonical description, not searched for substrings: the
native matrix is exactly the three pinned runners, every step of both jobs is exactly the
expected one (so no `if`, `|| true`, `; exit 0`, echo or comment can stand in for a
command), and every PIN_* is tied to what the steps install. Anything else fails.
  python3 tests/e2e/native/check_workflow.py [--file PATH]
Mutation tests: check_workflow.test.py.
"""
import json, pathlib, re, sys
for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(errors="backslashreplace")  # a console that cannot show a character (cp1252) must not crash the script
import yaml


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses what makes a workflow read differently from how it parses:
    duplicate keys (the last silently wins), anchors, aliases and merge keys."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.YAMLError(f"merge key `<<` at line {key_node.start_mark.line + 1}")
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.YAMLError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
            seen.add(key)
        return super().construct_mapping(node, deep)


def load_strict(text):
    for event in yaml.parse(text, Loader=StrictLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise yaml.YAMLError("anchors and aliases are not allowed")
    return yaml.load(text, Loader=StrictLoader)

def option(flag, default):
    return pathlib.Path(sys.argv[sys.argv.index(flag) + 1]) if flag in sys.argv else default


root = pathlib.Path(__file__).resolve().parents[3]
pins_path = root / "tests/e2e/native/pins.json"
if "--pins" in sys.argv:
    pins_path = pathlib.Path(sys.argv[sys.argv.index("--pins") + 1])
pins = json.loads(pins_path.read_text(encoding="utf-8"))
path = root / ".github/workflows/native-clients.yml"
if "--file" in sys.argv:
    path = pathlib.Path(sys.argv[sys.argv.index("--file") + 1])
release_path = root / ".github/workflows/release.yml"
if "--release" in sys.argv:
    release_path = pathlib.Path(sys.argv[sys.argv.index("--release") + 1])
raw = path.read_bytes()
text = path.read_text(encoding="utf-8")
bad = []
# C5: printable ASCII and line breaks only (no look-alike letters, zero-width or bidi characters),
# and no explicit YAML tags.
for label, content in (("native-clients.yml", raw), ("release.yml", release_path.read_bytes())):
    odd = sorted({chr(b) if b < 128 else f"0x{b:02x}" for b in content if not (0x20 <= b <= 0x7E or b in (0x0A, 0x0D))})
    if odd:
        bad.append(f"{label} holds characters outside printable ASCII: {odd[:6]}")
    if re.search(rb"(^|[\s:\[,{])!!?[A-Za-z]", content, re.M):
        bad.append(f"{label} uses an explicit YAML tag (!tag or !!tag)")
try:
    wf = load_strict(text)
    release_wf = load_strict(release_path.read_text(encoding="utf-8"))
except yaml.YAMLError as error:
    print(f"FAIL workflow is not plain YAML: {error}")
    sys.exit(1)

CHECKOUT = {"uses": "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "with": {"persist-credentials": False}}
SETUP_NODE = {"uses": "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "with": {"node-version": "${{ env.PIN_NODE }}"}}
SETUP_PYTHON = {"uses": "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065", "with": {"python-version": "${{ env.PIN_PYTHON }}"}}
UPLOAD = {"uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "if": "always()",
          "with": {"name": "native-linux-managed", "path": "target/e2e/out", "if-no-files-found": "ignore"}}

EXPECTED_ENV = {
    "PIN_NODE": pins["node"], "PIN_NPM": pins["npm"], "PIN_PYTHON": pins["python"], "PIN_PIP": pins["pip"],
    "PIN_TWINE": pins["twine"], "PIN_UV": pins["uv"], "NATIVE_PLATFORM": "${{ matrix.platform }}", "CARGO_TERM_COLOR": "always",
    "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8",
}
UNIT_TESTS = '''export NATIVE_TEST_SCRATCH="$RUNNER_TEMP/native-tests"
mkdir -p "$NATIVE_TEST_SCRATCH"
"$CHECK_PYTHON" tests/e2e/native/run_tests.py'''
UPLOAD_SHA = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
CHECK_ENV = {"CHECK_PYTHON": "${{ steps.checker_python.outputs.python-path }}"}
NATIVE_STEPS = [
    CHECKOUT, SETUP_NODE, SETUP_PYTHON,
    {"name": "Python for the workflow checker", "id": "checker_python", "uses": "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
     "with": {"python-version": "3.13", "update-environment": False}},
    {"name": "Install the workflow checker's parser", "shell": "bash", "env": CHECK_ENV,
     "run": '"$CHECK_PYTHON" -m pip install --only-binary=:all: --require-hashes -r tests/e2e/native/checker-requirements.txt'},
    {"name": "Install pinned clients", "shell": "bash", "run": 'npm install --global "npm@$PIN_NPM"\npython -m pip install --only-binary=:all: --require-hashes -r tests/e2e/native/ci-requirements.txt\n'},
    {"name": "Verify this workflow's structure", "shell": "bash", "env": CHECK_ENV, "run": '"$CHECK_PYTHON" tests/e2e/native/check_workflow.py'},
    {"name": "Show the shell and openssl the CA script uses", "shell": "bash",
     "run": 'bash --version | head -1\ncommand -v openssl\nopenssl version\nbash -x tests/e2e/fixtures/make-ca.sh "$RUNNER_TEMP/ca-probe" 2>&1 | tail -60\n'},
    {"name": "Install the harness dependencies", "run": "npm ci --prefix tests/e2e --no-audit --no-fund"},
    {"name": "Run the native harness unit tests", "shell": "bash", "env": CHECK_ENV, "run": UNIT_TESTS},
    {"name": "Verify exact client versions", "run": "node tests/e2e/native/clients.mjs"},
    {"name": "Provide OpenSSL's libcrypto for the OCSP code", "shell": "bash", "run": "node tests/e2e/native/openssl-setup.mjs apply"},
    {"name": "Build the native service", "env": {"AWS_LC_SYS_USE_SYSTEM": "0"}, "run": "cargo build --locked --bin probation"},
    {"name": "Allow the low loopback port", "shell": "bash", "run": 'if [ "$RUNNER_OS" = Linux ]; then sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0; fi\n'},
    {"name": "Wait for the real server's handshake", "shell": "bash", "env": {"GH_TOKEN": "${{ github.token }}"},
     "run": 'node tests/e2e/native/rendezvous.mjs client-wait --repo "$GITHUB_REPOSITORY" --run-id "$GITHUB_RUN_ID" --out "$RUNNER_TEMP/handshake" --timeout-min 50'},
    {"name": "Probe the tunnel as this job", "shell": "bash", "run": 'node tests/e2e/native/rendezvous.mjs client-probe --label "$NATIVE_PLATFORM"'},
    {"name": "Native npm and Python publishing", "run": "node tests/e2e/native/publishing.mjs"},
    {"name": "Record this job's completion", "if": "always()", "shell": "bash",
     "run": 'node tests/e2e/native/rendezvous.mjs done --label "$NATIVE_PLATFORM" --status "${{ job.status }}" --out "$RUNNER_TEMP/done"'},
    {"name": "Upload the completion record", "if": "always()", "uses": UPLOAD_SHA,
     "with": {"name": "native-done-${{ matrix.platform }}", "path": "${{ runner.temp }}/done/done.json", "retention-days": 1}},
]
RV = "node tests/e2e/native/rendezvous.mjs"
REAL_SERVER_STEPS = [
    CHECKOUT,
    {"run": "npm ci --prefix tests/e2e --no-audit --no-fund"},
    {"name": "Fetch cloudflared (pinned, checksum-verified)", "run": 'node tests/e2e/native/cloudflared.mjs fetch "$RUNNER_TEMP/cloudflared"'},
    {"name": "Start the real stack and its tunnel", "shell": "bash",
     "run": 'mkdir -p "$RUNNER_TEMP/remote"\nexport E2E_REMOTE_DIR="$RUNNER_TEMP/remote"\nnohup node tests/e2e/harness/run.mjs --only E2E-publishing-native-remote > "$E2E_REMOTE_DIR/harness.log" 2>&1 &\necho $! > "$E2E_REMOTE_DIR/harness.pid"\n'},
    {"name": "Wait for the tunnel and mask it", "run": f'{RV} server-wait-ready --dir "$RUNNER_TEMP/remote" --timeout-min 35'},
    {"name": "Make sure a handshake exists", "if": "always()", "run": f'{RV} server-ensure-handshake --dir "$RUNNER_TEMP/remote"'},
    {"name": "Publish the handshake", "if": "always()", "uses": UPLOAD_SHA,
     "with": {"name": "native-handshake", "path": "${{ runner.temp }}/remote/handshake.json", "retention-days": 1, "if-no-files-found": "error"}},
    {"name": "Wait for the native jobs", "if": "always()", "shell": "bash", "env": {"GH_TOKEN": "${{ github.token }}"},
     "run": f'{RV} server-wait-done --dir "$RUNNER_TEMP/remote" --expect linux-x64,darwin-arm64,win32-x64 --repo "$GITHUB_REPOSITORY" --run-id "$GITHUB_RUN_ID" --timeout-min 55'},
    {"name": "Release the scenario and check what the native jobs did", "if": "always()", "run": f'{RV} server-release --dir "$RUNNER_TEMP/remote" --timeout-min 10'},
    {"name": "Tear down the tunnel and the stack", "if": "always()", "run": f'{RV} server-teardown --dir "$RUNNER_TEMP/remote"'},
    {"name": "Keep the logs", "if": "always()", "uses": UPLOAD_SHA,
     "with": {"name": "native-real-server-logs", "path": "${{ runner.temp }}/remote/harness.log\ntarget/e2e/out\n", "retention-days": 3, "if-no-files-found": "ignore"}},
]
LINUX_SCENARIOS = ["E2E-service-policy", "E2E-publishing-npm-read", "E2E-publishing-npm-actions", "E2E-publishing-python-service",
                   "E2E-publishing-full-matrix", "E2E-publishing-native-linux"]
LINUX_STEPS = [
    CHECKOUT,
    {"run": "npm ci --prefix tests/e2e --no-audit --no-fund"},
    {"run": "npx --prefix tests/e2e playwright install --with-deps chromium"},
    {"run": "node tests/e2e/native/run-ids.test.mjs"},
    {"run": "node tests/e2e/harness/run.mjs " + " ".join(f"--only {s}" for s in LINUX_SCENARIOS)},
    UPLOAD,
]


# pins.json: exact versions, never a range, `latest` or a wildcard; the runners are the three known.
for tool in ("node", "npm", "python", "pip", "twine", "uv"):
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(pins.get(tool, ""))):
        bad.append(f"pins.json: {tool} must be an exact x.y.z version, got {pins.get(tool)!r}")


def need(ok, msg):
    if not ok:
        bad.append(msg)


def norm_run(step):
    return dict(step)


def same(a, b):
    """Equality that does not read 0 as false or 1 as true."""
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def same_steps(actual, expected, label):
    need(isinstance(actual, list) and len(actual) == len(expected), f"{label}: expected {len(expected)} steps, found {len(actual) if isinstance(actual, list) else actual!r}")
    if not isinstance(actual, list):
        return
    for i, (a, e) in enumerate(zip(actual, expected)):
        a, e = norm_run(a), norm_run(e)
        # Exact text: a run split over lines is several commands in most shells, so no
        # whitespace is normalised; only the final newline of a block scalar is ignored.
        if isinstance(a.get("run"), str) and isinstance(e.get("run"), str):
            a["run"], e["run"] = a["run"].strip(), e["run"].strip()
        need(same(a, e), f"{label} step {i + 1} is not the expected step: found {json.dumps(a)[:200]}, expected {json.dumps(e)[:200]}")


# Top level.
need(set(wf) == {"name", True, "permissions", "jobs"}, f"unexpected top-level keys {sorted(map(str, wf))}")
need(wf.get("permissions") == {"contents": "read", "actions": "read"}, "top-level permissions must be exactly contents: read and actions: read (the handshake is read from this run's artifacts)")
on = wf.get(True, {})
BASE_TRIGGERS = {"workflow_call", "workflow_dispatch", "schedule"}
need(set(on) in (BASE_TRIGGERS, BASE_TRIGGERS | {"push"}), f"unexpected triggers {sorted(on)}")
# The one temporary exception: a push of exactly the branch that carries this work, no tags, paths or patterns.
need("push" not in on or same(on["push"], {"branches": ["slice5-native-ci"]}), f"the push trigger may only be `branches: [slice5-native-ci]`, found {on.get('push')!r}")
need(on.get("workflow_call") in ({}, None), "workflow_call must declare no secrets or inputs")
need(on.get("workflow_dispatch") in ({}, None), "workflow_dispatch must declare no inputs")
need(on.get("schedule") == [{"cron": "23 4 * * *"}], "unexpected schedule")
jobs = wf.get("jobs", {})
need(set(jobs) == {"native-clients", "linux-managed", "real-server"}, f"unexpected jobs {sorted(jobs)}")

# Native matrix job.
native = jobs.get("native-clients", {})
need(set(native) == {"name", "strategy", "runs-on", "timeout-minutes", "env", "steps"}, f"native-clients has unexpected keys {sorted(native)}")
need(native.get("name") == "native ${{ matrix.platform }}", "unexpected job name")
need(native.get("runs-on") == "${{ matrix.runner }}", "native job must run on matrix.runner")
need(native.get("timeout-minutes") == 100, "unexpected timeout")
strategy = native.get("strategy", {})
need(set(strategy) == {"fail-fast", "matrix"}, f"unexpected strategy keys {sorted(strategy)}")
need(strategy.get("fail-fast") is False, "native matrix must set fail-fast: false so every OS reports")
matrix = strategy.get("matrix", {})
need(set(matrix) == {"include"}, f"matrix may only have include (found {sorted(matrix)})")
include = matrix.get("include", [])
want = [{"runner": r["runner"], "platform": r["platform"]} for r in pins["runners"]]
need(include == want, f"matrix.include {include} != pinned {want}")
need(same(native.get("env"), EXPECTED_ENV), f"job env differs from the pinned environment: {native.get('env')}")
same_steps(native.get("steps"), NATIVE_STEPS, "native-clients")

# Linux managed job.
linux = jobs.get("linux-managed", {})
need(set(linux) == {"runs-on", "timeout-minutes", "steps"}, f"linux-managed has unexpected keys {sorted(linux)}")
need(linux.get("runs-on") == "ubuntu-24.04", "linux-managed must run on ubuntu-24.04")
need(linux.get("timeout-minutes") == 120, "unexpected timeout")
same_steps(linux.get("steps"), LINUX_STEPS, "linux-managed")

# The real-server job: a hard timeout that covers its bounded waits (35 + 55 + 10 minutes), nothing conditional
# but the always() steps, no `needs` (a job cannot need one that is still running: the jobs rendezvous
# through artifacts), and exactly the canonical steps.
real = jobs.get("real-server", {})
need(set(real) == {"runs-on", "timeout-minutes", "steps"}, f"real-server has unexpected keys {sorted(real)}")
need(real.get("runs-on") == "ubuntu-24.04", "real-server must run on ubuntu-24.04")
need(real.get("timeout-minutes") == 110, "real-server must have the hard timeout of 110 minutes")
same_steps(real.get("steps"), REAL_SERVER_STEPS, "real-server")

# The tunnel binary is pinned in tunnel.json: an exact release, the official asset, a SHA-256; and the rendezvous
# commands print their masks before they write or export anything.
tunnel_path = option("--tunnel", root / "tests/e2e/native/tunnel.json")
tunnel = json.loads(tunnel_path.read_text(encoding="utf-8")).get("cloudflared", {})
need(re.fullmatch(r"\d{4}\.\d+\.\d+", str(tunnel.get("version", ""))), f"tunnel.json: cloudflared version must be an exact release, got {tunnel.get('version')!r}")
need(re.fullmatch(r"[0-9a-f]{64}", str(tunnel.get("sha256", ""))), "tunnel.json: cloudflared sha256 must be a 64-digit hex digest")
need(tunnel.get("asset") == "cloudflared-linux-amd64", f"tunnel.json: cloudflared asset must be cloudflared-linux-amd64, got {tunnel.get('asset')!r}")
rendezvous = option("--rendezvous", root / "tests/e2e/native/rendezvous.mjs").read_text(encoding="utf-8")
client_wait = rendezvous[rendezvous.index('command === "client-wait"'):rendezvous.index('command === "client-probe"')]
need(client_wait.index("maskLines(handshake)") < client_wait.index("writeFileSync(keyFile") < client_wait.index("appendFileSync(process.env.GITHUB_ENV"),
     "rendezvous.mjs client-wait must print the masks before it writes the key file or the environment")
need("maskLines(handshake)" in rendezvous[rendezvous.index('command === "server-wait-ready"'):rendezvous.index('command === "server-ensure-handshake"')], "rendezvous.mjs server-wait-ready must print the masks")
need("parseHandshake(" in client_wait, "rendezvous.mjs client-wait must validate the handshake before using it")
fetcher = option("--cloudflared-js", root / "tests/e2e/native/cloudflared.mjs").read_text(encoding="utf-8")
need("expected: pin.sha256" in fetcher and "downloadUrl(pin)" in fetcher, "cloudflared.mjs must download the pinned version and verify the pinned checksum")

# release.yml: the gate. `native` calls this workflow with nothing conditional, and both
# `release` and `publish` wait for it.
release = release_wf["jobs"]
need(release.get("native") == {"needs": "test", "permissions": {"contents": "read", "actions": "read"}, "uses": "./.github/workflows/native-clients.yml"},
     f"release.yml's native job must be exactly a call of native-clients.yml after test (no if, secrets or with): {release.get('native')}")
for gated in ("release", "publish"):
    needs = release.get(gated, {}).get("needs")
    needs = [needs] if isinstance(needs, str) else (needs or [])
    need("native" in needs, f"release.yml's {gated} job must need native (needs: {needs})")
need("e2e" in (release.get("release", {}).get("needs") or []), "release.yml's release job must need e2e directly")

# H1: every job. No continue-on-error anywhere, no `|| true`, no `if` except the upload-artifact
# `always()` steps; and any job that writes, uses an environment or secrets, or runs a publishing
# command must transitively need both native and e2e.
def needed(job_name, seen=None):
    seen = set() if seen is None else seen
    needs = release.get(job_name, {}).get("needs") or []
    for dep in ([needs] if isinstance(needs, str) else needs):
        if dep not in seen:
            seen.add(dep)
            needed(dep, seen)
    return seen


PUBLISHING = re.compile(r"cargo publish|gh release|docker push|docker login|npm publish|twine upload|gh api|ghcr\.io")
for job_name, job in release.items():
    need("continue-on-error" not in job, f"release.yml job {job_name} must not continue-on-error")
    need("if" not in job, f"release.yml job {job_name} must have no `if` (found {job.get('if')!r}): `always()` or `!cancelled()` would run it past a failed gate")
    perms = job.get("permissions") or {}
    # security-events: write only uploads code-scanning results (codeql); everything else that writes publishes.
    writes = isinstance(perms, str) and "write" in perms or isinstance(perms, dict) and any("write" in str(v) for k, v in perms.items() if k != "security-events")
    job_text = json.dumps(job)
    sensitive = writes or "environment" in job or "secrets" in job_text or bool(PUBLISHING.search(job_text))
    for step in job.get("steps", []) or []:
        need("continue-on-error" not in step, f"release.yml job {job_name} has a step with continue-on-error")
        if "if" in step:
            exempt = str(step.get("if")) == "always()" and str(step.get("uses", "")).startswith("actions/upload-artifact@")
            need(exempt, f"release.yml job {job_name} has a step `if: {step['if']}` (only upload-artifact steps may use always())")
        need(not re.search(r"\|\|\s*(true|:)\b|\|\|\s*exit\s+0|;\s*exit\s+0\s*$", str(step.get("run", "")), re.M), f"release.yml job {job_name} hides a failure with || true or exit 0")
    if sensitive:
        chain = needed(job_name)
        need({"native", "e2e"} <= chain, f"release.yml job {job_name} writes, publishes or uses secrets or an environment, so it must transitively need native and e2e (it needs {sorted(chain)})")

# Every scenario ID the workflow names exists: in the scenario files, and (where the harness
# dependencies are installed) as `run.mjs --list --only <id>` says.
def scenario_ids():
    """IDs declared by a real `export const meta` at the start of a line, comments removed
    first (a meta inside a block comment declares nothing)."""
    folder = root / "tests/e2e/scenarios"
    if "--scenarios-dir" in sys.argv:
        folder = pathlib.Path(sys.argv[sys.argv.index("--scenarios-dir") + 1])
    ids = set()
    for scenario in folder.glob("*.mjs"):
        code = re.sub(r"/\*.*?\*/", "", scenario.read_text(encoding="utf-8"), flags=re.S)
        code = re.sub(r"^[ \t]*//.*$", "", code, flags=re.M)
        ids.update(re.findall(r'^export const meta = \{[^}]*?\bid: "([^"]+)"', code, re.M | re.S))
    return ids


def verify_ids(wanted):
    known = scenario_ids()
    problems = [f"scenario ID {w} exists in no tests/e2e/scenarios file" for w in wanted if w not in known]
    if not problems and "--scenarios-dir" not in sys.argv and (root / "tests/e2e/node_modules").exists():
        import subprocess
        for w in wanted:
            r = subprocess.run(["node", str(root / "tests/e2e/harness/run.mjs"), "--list", "--only", w], capture_output=True, encoding="utf-8", errors="replace")
            if r.returncode != 0 or w not in r.stdout:
                problems.append(f"run.mjs --list --only {w} failed: {r.stderr.strip()[:200]}")
    return problems


if "--verify-ids" in sys.argv:
    problems = verify_ids(sys.argv[sys.argv.index("--verify-ids") + 1:])
    print("\n".join(f"FAIL {p}" for p in problems) or "scenario IDs exist")
    sys.exit(1 if problems else 0)
named = re.findall(r"--only (\S+)", " ".join(str(step.get("run", "")) for step in linux.get("steps", [])))
need(len(named) >= 1, "linux-managed names no scenario")
for problem in verify_ids(named):
    need(False, problem)

# The hash-pinned requirements the workflow installs from hold exactly the pinned versions, every
# requirement pinned with ==, with a sha256 hash, and nothing else.
def requirement_findings(requirements_text, label, want_extra=(), tools=True):
    findings = []
    logical = re.sub(r"\\\n", " ", requirements_text)
    names = {}
    for line in logical.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)(?:\s*;[^-]*?)?((?:\s+--hash=sha256:[0-9a-f]{64})+)", line)
        if not match:
            findings.append(f"{label}: not an exact, hashed requirement: {line[:80]}")
            continue
        names[match.group(1).lower()] = match.group(2)
    for tool in (("pip", "twine", "uv") if tools else ()):
        if names.get(tool) != pins[tool]:
            findings.append(f"{label}: {tool} is {names.get(tool)!r}, PIN is {pins[tool]}")
    for extra in want_extra:
        if names.get(extra) is None:
            findings.append(f"{label}: {extra} is not pinned")
    return findings


for problem in requirement_findings(option("--ci-requirements", root / "tests/e2e/native/ci-requirements.txt").read_text(encoding="utf-8"), "ci-requirements.txt"):
    need(False, problem)
for problem in requirement_findings(option("--checker-requirements", root / "tests/e2e/native/checker-requirements.txt").read_text(encoding="utf-8"), "checker-requirements.txt", want_extra=("pyyaml",), tools=False):
    need(False, problem)
for problem in requirement_findings(option("--native-requirements", root / "tests/e2e/compose/clients/native-requirements.txt").read_text(encoding="utf-8"), "native-requirements.txt"):
    need(False, problem)

# Every *.test.* file is run by the one wrapper step (the canonical "Run the native harness unit
# tests" step): the wrapper must discover them all, and judge them by behaviour.
wrapper = option("--run-tests", root / "tests/e2e/native/run_tests.py").read_text(encoding="utf-8")
need('sorted(here.glob("*.test.*"))' in wrapper, "run_tests.py must discover every *.test.* file with here.glob(\"*.test.*\")")
need("if not stub_checker_canary():" in wrapper and "judge_canary()" in wrapper, "run_tests.py must run both canaries before the tests")
need("--import" in wrapper and "count-asserts.mjs" in wrapper and "expected-asserts.json" in wrapper, "run_tests.py must count assertion calls of the JavaScript tests")

# Whole-file rules (comments and strings included).
for line in re.findall(r"uses:\s*(\S+)", text):
    need(re.search(r"@[0-9a-f]{40}$", line) is not None, f"action not pinned to a commit SHA: {line}")
for forbidden in ["continue-on-error", "client_cert", "TWINE_CERT", "TWINE_CLIENT_CERT", "--cert", "NPM_TOKEN", "PYPI_TOKEN", "TWINE_PASSWORD",
                  "NODE_TLS_REJECT_UNAUTHORIZED", "NATIVE_PINS_FILE", "curl ", "wget ", "Invoke-WebRequest", "releases/latest", "E2E_TUNNEL", "NATIVE_RENDEZVOUS", "secrets.", "vars.", "NATIVE_E2E", "secrets:"]:
    need(forbidden not in text, f"workflow must not contain {forbidden}")

if bad:
    print("\n".join(f"FAIL {b}" for b in bad))
    sys.exit(1)
print("native-clients.yml structure OK")
