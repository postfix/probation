#!/usr/bin/env python3
"""Mutation tests for check_workflow.py: every bypass the review listed must fail the
checker, and the unmutated workflow must pass.  python3 tests/e2e/native/check_workflow.test.py
"""
import json, os, pathlib, subprocess, sys, tempfile

here = pathlib.Path(__file__).resolve().parent
root = here.parents[2]
good = (root / ".github/workflows/native-clients.yml").read_text()
checker = pathlib.Path(os.environ.get("NATIVE_CHECKER", here / "check_workflow.py"))  # a stub makes the canary in run_tests.py trip
scratch = os.environ.get("NATIVE_TEST_SCRATCH")  # small text files only; unset uses the system temp dir


good_release = (root / ".github/workflows/release.yml").read_text()


def check(text, release=None):
    with tempfile.TemporaryDirectory(dir=scratch) as d:
        path = pathlib.Path(d) / "wf.yml"
        path.write_text(text)
        command = [sys.executable, str(checker), "--file", str(path)]
        if release is not None:
            rel = pathlib.Path(d) / "release.yml"
            rel.write_text(release)
            command += ["--release", str(rel)]
        r = subprocess.run(command, capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr


def sub(old, new, count=1):
    assert old in good, f"mutation anchor missing: {old!r}"
    return good.replace(old, new, count)


mutations = {
    "matrix.exclude": sub("    runs-on: ${{ matrix.runner }}\n", "", 1).replace("            platform: win32-x64\n", "            platform: win32-x64\n        exclude:\n          - runner: windows-2025\n    runs-on: ${{ matrix.runner }}\n", 1),
    "job-level if": sub("    name: native ${{ matrix.platform }}\n", "    name: native ${{ matrix.platform }}\n    if: false\n"),
    "job-level permissions": sub("    timeout-minutes: 100\n", "    timeout-minutes: 100\n    permissions:\n      contents: write\n"),
    "|| true": sub("run: node tests/e2e/native/publishing.mjs", "run: node tests/e2e/native/publishing.mjs || true"),
    "; exit 0": sub("run: node tests/e2e/native/publishing.mjs", "run: node tests/e2e/native/publishing.mjs; exit 0"),
    "echo satisfying a substring": sub("run: node tests/e2e/native/clients.mjs", "run: echo node tests/e2e/native/clients.mjs"),
    "comment satisfying a substring": sub("run: cargo build --locked --bin probation", "run: true # cargo build --locked --bin probation"),
    "extra include entry": sub("          - runner: windows-2025\n            platform: win32-x64\n", "          - runner: windows-2025\n            platform: win32-x64\n          - runner: ubuntu-22.04\n            platform: linux-x64\n"),
    "duplicate include entry": sub("          - runner: macos-26\n            platform: darwin-arm64\n", "          - runner: macos-26\n            platform: darwin-arm64\n          - runner: macos-26\n            platform: darwin-arm64\n"),
    "linux-managed step if false": sub("      - run: >\n          node tests/e2e/harness/run.mjs", "      - if: false\n        run: >\n          node tests/e2e/harness/run.mjs"),
    "step continue-on-error": sub("        run: node tests/e2e/native/clients.mjs", "        run: node tests/e2e/native/clients.mjs\n        continue-on-error: true"),
    "step-level env override": sub("      - name: Verify exact client versions\n", "      - name: Verify exact client versions\n        env:\n          NATIVE_PLATFORM: linux-x64\n"),
    "job env pin changed": sub('PIN_UV: "0.13.5"', 'PIN_UV: "0.13.4"'),
    "tools installed without --require-hashes (SEC3)": sub("python -m pip install --only-binary=:all: --require-hashes -r tests/e2e/native/ci-requirements.txt", "python -m pip install twine==7.0.0 uv==0.13.5 pip==26.2.2"),
    "tools installed from another file (SEC3)": sub("-r tests/e2e/native/ci-requirements.txt", "-r tests/e2e/native/other.txt"),
    "an extra unhashed install (SEC3)": sub('-r tests/e2e/native/ci-requirements.txt\n', '-r tests/e2e/native/ci-requirements.txt\n          python -m pip install requests\n'),
    "structure step installs pyyaml unhashed (SEC3)": sub('"$CHECK_PYTHON" tests/e2e/native/check_workflow.py', 'python -m pip install "pyyaml==6.0.2" && python tests/e2e/native/check_workflow.py', 1),
    "npm installed at another version": sub('"npm@$PIN_NPM"', '"npm@10.0.0"'),
    "node-version not tied to the pin": sub("node-version: ${{ env.PIN_NODE }}", 'node-version: "20"'),
    "python-version not tied to the pin": sub("python-version: ${{ env.PIN_PYTHON }}", 'python-version: "3.13"'),
    "preflight step removed": sub("      - name: Verify exact client versions\n        run: node tests/e2e/native/clients.mjs\n", ""),
    "publishing before preflight": sub("      - name: Verify exact client versions\n        run: node tests/e2e/native/clients.mjs\n", "").replace("      - name: Native npm and Python publishing\n        run: node tests/e2e/native/publishing.mjs\n", "      - name: Native npm and Python publishing\n        run: node tests/e2e/native/publishing.mjs\n      - name: Verify exact client versions\n        run: node tests/e2e/native/clients.mjs\n"),
    "unpinned action": sub("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0", "actions/setup-node@v4"),
    "workflow-level permission widened": sub("permissions:\n  contents: read\n", "permissions:\n  contents: write\n"),
    "linux-managed scenario dropped": sub("          --only E2E-publishing-native-linux\n", ""),
    "extra job": good + "\n  extra:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo hi\n",
    "fail-fast true": sub("fail-fast: false", "fail-fast: true"),
    "unit-test step removed (C7)": sub(good[good.index("      - name: Run the native harness unit tests"):good.index("      - name: Verify exact client versions")], ""),
    "unit-test step swallows failures (H2)": sub("run_tests.py\n", "run_tests.py || true\n"),
    "unit-test step runs another script (H2)": sub("run_tests.py", "run_tests.py.bak"),
    "unit-test scratch outside the job temp dir (C7)": sub('"$RUNNER_TEMP/native-tests"', '"/tmp/native-tests"', 2),
    "ID-check step removed (C1)": sub("      - run: node tests/e2e/native/run-ids.test.mjs\n", ""),
    "duplicate key, bad run then good run (G10)": sub("        run: cargo build --locked --bin probation\n".replace("        run", "        run") if False else "run: cargo build --locked --bin probation", "run: exit 0\n        run: cargo build --locked --bin probation"),
    "anchor on a step value (G10)": sub("CARGO_TERM_COLOR: always", "CARGO_TERM_COLOR: &c always"),
    "alias in the workflow (G10)": sub("      CARGO_TERM_COLOR: always\n", "      CARGO_TERM_COLOR: always\n      OTHER: *c\n").replace("CARGO_TERM_COLOR: always\n    steps", "CARGO_TERM_COLOR: &c always\n    steps", 1),
    "merge key on a step (G10)": sub("      - name: Build the native service\n", "      - name: Build the native service\n        <<: {if: false}\n"),
    "newline-split run on a default shell (G10)": sub("run: node tests/e2e/native/clients.mjs", "run: |\n          node\n          tests/e2e/native/clients.mjs"),
    "non-ASCII character in the workflow (C5)": sub("name: Build the native service", "name: Build the nativе service"),
    "zero where a boolean is expected (C5)": sub("persist-credentials: false", "persist-credentials: 0", 1),
    "explicit !! tag (C5)": sub("persist-credentials: false", "persist-credentials: !!bool false", 1),
    "zero-width space in a run (C5)": sub("run: cargo build --locked --bin probation", "run: cargo build --locked --bin probation\u200b"),
    "checker python step removed (PYYAML)": sub(good[good.index("      - name: Python for the workflow checker"):good.index("      - name: Install the workflow checker's parser")], ""),
    "checker installs PyYAML with wheels optional (PYYAML)": sub("--only-binary=:all: --require-hashes -r tests/e2e/native/checker-requirements.txt", "--require-hashes -r tests/e2e/native/checker-requirements.txt"),
    "client tools without --only-binary (PYYAML)": sub("python -m pip install --only-binary=:all: --require-hashes -r tests/e2e/native/ci-requirements.txt", "python -m pip install --require-hashes -r tests/e2e/native/ci-requirements.txt"),
    # --- the real-server handshake (tunnel) shape
    "teardown without always()": sub("      - name: Tear down the tunnel and the stack\n        if: always()\n", "      - name: Tear down the tunnel and the stack\n"),
    "release without always()": sub("      - name: Release the scenario and check what the native jobs did\n        if: always()\n", "      - name: Release the scenario and check what the native jobs did\n"),
    "wait-done without always()": sub("      - name: Wait for the native jobs\n        if: always()\n", "      - name: Wait for the native jobs\n"),
    "handshake upload without always()": sub("      - name: Publish the handshake\n        if: always()\n", "      - name: Publish the handshake\n"),
    "handshake upload ignores a missing file": sub("          if-no-files-found: error\n", "          if-no-files-found: ignore\n"),
    "ensure-handshake step removed": sub("      - name: Make sure a handshake exists\n        if: always()\n        run: node tests/e2e/native/rendezvous.mjs server-ensure-handshake --dir \"$RUNNER_TEMP/remote\"\n", ""),
    "completion record without always()": sub("      - name: Record this job's completion\n        if: always()\n", "      - name: Record this job's completion\n"),
    "completion upload without always()": sub("      - name: Upload the completion record\n        if: always()\n", "      - name: Upload the completion record\n"),
    "real-server without the hard timeout": sub("    timeout-minutes: 110\n", ""),
    "real-server with a longer timeout": sub("    timeout-minutes: 110\n", "    timeout-minutes: 360\n"),
    "unbounded wait for the native jobs": sub("--expect linux-x64,darwin-arm64,win32-x64 --repo \"$GITHUB_REPOSITORY\" --run-id \"$GITHUB_RUN_ID\" --timeout-min 55", "--expect linux-x64,darwin-arm64,win32-x64 --repo \"$GITHUB_REPOSITORY\" --run-id \"$GITHUB_RUN_ID\" --timeout-min 5000"),
    "client waits for the handshake forever": sub("--out \"$RUNNER_TEMP/handshake\" --timeout-min 50", "--out \"$RUNNER_TEMP/handshake\" --timeout-min 5000"),
    "cloudflared fetched with curl": sub("run: node tests/e2e/native/cloudflared.mjs fetch \"$RUNNER_TEMP/cloudflared\"", "run: curl -L -o \"$RUNNER_TEMP/cloudflared\" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && chmod +x \"$RUNNER_TEMP/cloudflared\""),
    "cloudflared fetch step removed": sub("      - name: Fetch cloudflared (pinned, checksum-verified)\n        run: node tests/e2e/native/cloudflared.mjs fetch \"$RUNNER_TEMP/cloudflared\"\n", ""),
    "masking step replaced": sub("run: node tests/e2e/native/rendezvous.mjs server-wait-ready --dir \"$RUNNER_TEMP/remote\" --timeout-min 35", "run: sleep 60"),
    "needs added to the real-server job": sub("  real-server:\n    runs-on: ubuntu-24.04\n", "  real-server:\n    needs: native-clients\n    runs-on: ubuntu-24.04\n"),
    "needs added to the native job": sub("    runs-on: ${{ matrix.runner }}\n", "    needs: real-server\n    runs-on: ${{ matrix.runner }}\n"),
    "actions: read dropped": sub("  contents: read\n  actions: read\n", "  contents: read\n"),
    "actions: write": sub("  contents: read\n  actions: read\n", "  contents: read\n  actions: write\n"),
    "a repository secret for the tunnel": sub("          GH_TOKEN: ${{ github.token }}\n        run: node tests/e2e/native/rendezvous.mjs server-wait-done", "          GH_TOKEN: ${{ secrets.TUNNEL_TOKEN }}\n        run: node tests/e2e/native/rendezvous.mjs server-wait-done"),
    "stub tunnel switched on": sub("          export E2E_REMOTE_DIR=\"$RUNNER_TEMP/remote\"\n", "          export E2E_REMOTE_DIR=\"$RUNNER_TEMP/remote\"\n          export E2E_TUNNEL=stub\n"),
    "renamed scenario ID (C1)": sub("--only E2E-publishing-native-linux", "--only E2E-publishing-native-linx"),
}

release_mutations = {
    "native job without the actions: read grant": good_release.replace("    permissions:\n      contents: read\n      actions: read\n    uses: ./.github/workflows/native-clients.yml\n", "    uses: ./.github/workflows/native-clients.yml\n", 1),
    "native job with actions: write": good_release.replace("      actions: read\n    uses: ./.github/workflows/native-clients.yml", "      actions: write\n    uses: ./.github/workflows/native-clients.yml", 1),
    "if always() on release (D1)": good_release.replace("  release:\n    needs: [build, e2e, native]\n", "  release:\n    needs: [build, e2e, native]\n    if: always()\n", 1),
    "if !cancelled() on publish (D1)": good_release.replace("  publish:\n    needs: [release, e2e, native]\n", "  publish:\n    needs: [release, e2e, native]\n    if: ${{ !cancelled() }}\n", 1),
    "empty needs on the native job (D1)": good_release.replace("  native:\n    needs: test\n", "  native:\n    needs: []\n", 1),
    "if always() on the test job (D1)": good_release.replace("  test:\n    runs-on: ubuntu-latest\n", "  test:\n    if: always()\n    runs-on: ubuntu-latest\n", 1),
    "if always() under images (H1)": good_release.replace("  images:\n    needs: [release, e2e]\n", "  images:\n    needs: [release, e2e]\n    if: always()\n", 1),
    "images needs only e2e (H1)": good_release.replace("  images:\n    needs: [release, e2e]\n", "  images:\n    needs: [e2e]\n", 1),
    "continue-on-error on the e2e run.mjs step (H1)": good_release.replace("      - run: node tests/e2e/harness/run.mjs --suite release\n", "      - run: node tests/e2e/harness/run.mjs --suite release\n        continue-on-error: true\n", 1),
    "release needs build and native only (H1)": good_release.replace("  release:\n    needs: [build, e2e, native]\n", "  release:\n    needs: [build, native]\n", 1),
    "an extra job running cargo publish with no needs (H1)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo publish --workspace\n        env:\n          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}\n",
    "an extra job pushing images with no needs (H1)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker push ghcr.io/x/y:z\n",
    "|| true in a release step (H1)": good_release.replace("      - run: cargo package --workspace --exclude probation-server --locked\n", "      - run: cargo package --workspace --exclude probation-server --locked || true\n", 1),
    "step if outside the upload-artifact exception (H1)": good_release.replace("      - run: cargo publish --workspace --locked --no-verify\n", "      - if: always()\n        run: cargo publish --workspace --locked --no-verify\n", 1),
    "continue-on-error on a job (H1)": good_release.replace("  codeql:\n    needs: test\n", "  codeql:\n    needs: test\n    continue-on-error: true\n", 1),
    "if always() on the e2e job (D1)": good_release.replace("  e2e:\n    needs: test\n", "  e2e:\n    needs: test\n    if: always()\n", 1),
    "release job no longer needs native (C6)": good_release.replace("needs: [build, e2e, native]", "needs: [build, e2e]", 1),
    "publish job no longer needs native (C6)": good_release.replace("needs: [release, e2e, native]", "needs: [release, e2e]", 1),
    "job-level if on the native job (C6)": good_release.replace("  native:\n    needs: test\n", "  native:\n    needs: test\n    if: false\n", 1),
    "native job passes secrets (C6)": good_release.replace("    uses: ./.github/workflows/native-clients.yml\n", "    uses: ./.github/workflows/native-clients.yml\n    secrets: inherit\n", 1),
    "native job removed (C6)": good_release.replace(good_release[good_release.index("  native:\n"):good_release.index("  codeql:")], "", 1),
}
ids_check = subprocess.run([sys.executable, str(checker), "--verify-ids", "E2E-publishing-native-linux", "E2E-no-such-scenario"], capture_output=True, text=True)
assert ids_check.returncode == 1 and "E2E-no-such-scenario" in ids_check.stdout and "native-linux" not in ids_check.stdout.replace("E2E-publishing-native-linux exists", ""), f"--verify-ids must name only the unknown ID: {ids_check.stdout}"

code, out = check(good)
assert code == 0, f"the known-good workflow must pass: {out}"
failed = []
for name, text in mutations.items():
    assert text != good, f"{name}: mutation changed nothing"
    code, out = check(text)
    if code == 0:
        failed.append(name)
        print(f"BYPASS (checker passed): {name}")
    elif "FAIL " not in out or "Traceback" in out:
        failed.append(name)
        print(f"CRASH (not a clean FAIL): {name}: {out[-300:]}")
for name, release_text in release_mutations.items():
    assert release_text != good_release, f"{name}: mutation changed nothing"
    code, out = check(good, release_text)
    if code == 0:
        failed.append(name)
        print(f"BYPASS (checker passed): {name}")
    elif "FAIL " not in out or "Traceback" in out:
        failed.append(name)
        print(f"CRASH (not a clean FAIL): {name}: {out[-300:]}")
def run_checker(*extra):
    r = subprocess.run([sys.executable, str(checker), *extra], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


with tempfile.TemporaryDirectory(dir=scratch) as d:
    d = pathlib.Path(d)
    # The tunnel pin and the code that obeys it.
    good_tunnel = json.loads((here / "tunnel.json").read_text())
    for name, change in {"version latest": {"version": "latest"}, "a short sha": {"sha256": "abc123"}, "a non-hex sha": {"sha256": "z" * 64}, "the deb asset": {"asset": "cloudflared-linux-amd64.deb"}, "a floating version": {"version": "2026.10"}}.items():
        (d / "tunnel.json").write_text(json.dumps({"cloudflared": {**good_tunnel["cloudflared"], **change}}))
        code, out = run_checker("--tunnel", str(d / "tunnel.json"))
        if code == 0:
            failed.append(f"tunnel.json: {name}")
            print(f"BYPASS: tunnel.json {name}")
    rendezvous_text = (here / "rendezvous.mjs").read_text()
    cloudflared_text = (here / "cloudflared.mjs").read_text()
    code_mutations = {
        "masks printed after the key is written": ("--rendezvous", rendezvous_text.replace("console.log(maskLines(handshake).join(\"\\n\"));\n    const keyFile", "const keyFile", 1).replace("writeFileSync(keyFile, `${handshake.key}\\n`, { mode: 0o600 });", "writeFileSync(keyFile, `${handshake.key}\\n`, { mode: 0o600 });\n    console.log(maskLines(handshake).join(\"\\n\"));", 1)),
        "handshake not validated": ("--rendezvous", rendezvous_text.replace("const handshake = parseHandshake(readFileSync(join(out, \"handshake.json\"), \"utf8\"));", "const handshake = JSON.parse(readFileSync(join(out, \"handshake.json\"), \"utf8\"));", 1)),
        "server does not print masks": ("--rendezvous", rendezvous_text.replace("console.log(maskLines(handshake).join(\"\\n\"));\n      console.log(\"handshake ready\");", "console.log(\"handshake ready\");", 1)),
        "checksum not enforced": ("--cloudflared-js", cloudflared_text.replace("expected: pin.sha256", "expected: ''")),
        "download not from the pinned URL": ("--cloudflared-js", cloudflared_text.replace("downloadUrl(pin)", "pin.source")),
    }
    for name, (option_name, text) in code_mutations.items():
        assert text != (rendezvous_text if option_name == "--rendezvous" else cloudflared_text), name
        (d / "mutated.mjs").write_text(text)
        code, out = run_checker(option_name, str(d / "mutated.mjs"))
        if code == 0:
            failed.append(f"code: {name}")
            print(f"BYPASS: {name}")
    # SEC3: the hashed requirements must pin exactly the PIN_* versions, every line with a hash.
    good_requirements = (here / "ci-requirements.txt").read_text()
    bad_requirements = {
        "twine at another version": good_requirements.replace("\ntwine==7.0.0 ", "\ntwine==6.0.0 ", 1),
        "uv at another version": good_requirements.replace("\nuv==0.13.5 ", "\nuv==0.13.4 ", 1),
        "pip at another version": good_requirements.replace("\npip==26.2.2 ", "\npip==25.1.1 ", 1),
        "a requirement without hashes": good_requirements + "\nrequests==2.34.2\n",
        "twine removed": "\n".join(l for l in good_requirements.split("\n") if "twine" not in l),
        "an unpinned requirement": good_requirements + "\nexamplepkg>=1.0 \\\n    --hash=sha256:" + "0" * 64 + "\n",
    }
    for name, text in bad_requirements.items():
        assert text != good_requirements, name
        (d / "req.txt").write_text(text)
        code, out = run_checker("--ci-requirements", str(d / "req.txt"))
        if code == 0:
            failed.append(f"ci-requirements: {name}")
            print(f"BYPASS: ci-requirements {name}")
    good_checker = (here / "checker-requirements.txt").read_text()
    for name, text in {"pyyaml removed": "# nothing\n", "pyyaml without hashes": "pyyaml==6.0.3\n", "pyyaml with a range": "pyyaml>=6 \\\n    --hash=sha256:" + "0" * 64 + "\n"}.items():
        (d / "chk.txt").write_text(text)
        code, out = run_checker("--checker-requirements", str(d / "chk.txt"))
        if code == 0:
            failed.append(f"checker-requirements: {name}")
            print(f"BYPASS: checker-requirements {name}")
    # H2: the wrapper must still discover every test, run both canaries and count assertions.
    wrapper_text = (here / "run_tests.py").read_text()
    for name, text in {"fixed test list": wrapper_text.replace('sorted(here.glob("*.test.*"))', '[here / "assertions.test.mjs"]'),
                       "no stub canary": wrapper_text.replace("if not stub_checker_canary():", "if False:"),
                       "no assertion counting": wrapper_text.replace("count-asserts.mjs", "gone.mjs")}.items():
        (d / "wrapper.py").write_text(text)
        code, out = run_checker("--run-tests", str(d / "wrapper.py"))
        if code == 0:
            failed.append(f"run_tests.py: {name}")
            print(f"BYPASS: run_tests.py {name}")
    # G10: pins.json with a range, `latest` or a wildcard.
    import json
    real_pins = json.loads((here / "pins.json").read_text())
    for tool, bad_value in [("node", "latest"), ("npm", "*"), ("python", "3.15"), ("uv", "^0.13.5"), ("pip", "26.2.x")]:
        pins = dict(real_pins, **{tool: bad_value})
        (d / "pins.json").write_text(json.dumps(pins))
        code, out = run_checker("--pins", str(d / "pins.json"))
        if code == 0 or tool not in out:
            failed.append(f"pins.json {tool}={bad_value}")
            print(f"BYPASS: pins.json {tool}={bad_value}: {out[-200:]}")
    # G10: a scenario meta inside a block comment declares nothing.
    scenarios = d / "scenarios"
    scenarios.mkdir()
    (scenarios / "a.mjs").write_text('/*\nexport const meta = { id: "E2E-service-policy", suites: [] };\n*/\nexport const meta = { id: "E2E-other", suites: [] };\n')
    code, out = run_checker("--scenarios-dir", str(scenarios), "--verify-ids", "E2E-service-policy")
    if code == 0:
        failed.append("scenario meta in a block comment")
        print("BYPASS: a meta in a block comment passed verify_ids")
    code, out = run_checker("--scenarios-dir", str(scenarios), "--verify-ids", "E2E-other")
    if code != 0:
        failed.append("real scenario meta not found")
        print(f"a real meta must be found: {out}")
if failed:
    sys.exit(1)
print(f"check_workflow.test: {len(mutations) + len(release_mutations)} bypasses all fail, known-good passes")
