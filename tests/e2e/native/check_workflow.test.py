#!/usr/bin/env python3
"""Mutation tests for check_workflow.py: every bypass the review listed must fail the
checker, and the unmutated workflow must pass.  python3 tests/e2e/native/check_workflow.test.py
"""
import json, os, pathlib, subprocess, sys, tempfile
for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(errors="backslashreplace")  # a console that cannot show a character (cp1252) must not crash the script

here = pathlib.Path(__file__).resolve().parent
root = here.parents[2]
good = (root / ".github/workflows/native-clients.yml").read_text(encoding="utf-8")
PUSH = "  workflow_dispatch:\n  push:\n"
checker = pathlib.Path(os.environ.get("NATIVE_CHECKER", here / "check_workflow.py"))  # a stub makes the canary in run_tests.py trip
scratch = os.environ.get("NATIVE_TEST_SCRATCH")  # small text files only; unset uses the system temp dir


good_release = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")


def check(text, release=None):
    with tempfile.TemporaryDirectory(dir=scratch) as d:
        path = pathlib.Path(d) / "wf.yml"
        path.write_text(text, encoding="utf-8")
        command = [sys.executable, str(checker), "--file", str(path)]
        if release is not None:
            rel = pathlib.Path(d) / "release.yml"
            rel.write_text(release, encoding="utf-8")
            command += ["--release", str(rel)]
        r = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace")
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
    "unbounded wait for the native jobs": sub("--expect linux-x64,darwin-arm64,win32-x64 --repo \"$GITHUB_REPOSITORY\" --run-id \"$GITHUB_RUN_ID\" --attempt \"$GITHUB_RUN_ATTEMPT\" --timeout-min 55", "--expect linux-x64,darwin-arm64,win32-x64 --repo \"$GITHUB_REPOSITORY\" --run-id \"$GITHUB_RUN_ID\" --attempt \"$GITHUB_RUN_ATTEMPT\" --timeout-min 5000"),
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
    # --- triggers: no push of any form is permitted
    "push on a branch": sub("  workflow_dispatch:\n", PUSH + "    branches: [main]\n"),
    "push on every branch": sub("  workflow_dispatch:\n", PUSH + "    branches: ['**']\n"),
    "push with tags": sub("  workflow_dispatch:\n", PUSH + "    tags: ['v*']\n"),
    "push with paths": sub("  workflow_dispatch:\n", PUSH + "    paths: ['docs/**']\n"),
    "push with branches-ignore": sub("  workflow_dispatch:\n", PUSH + "    branches-ignore: [x]\n"),
    "bare push": sub("  workflow_dispatch:\n", PUSH),
    "pull_request": sub("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"),
    "pull_request_target": sub("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request_target:\n"),
    "Python UTF-8 mode dropped from the job env": sub('      PYTHONUTF8: "1"\n', ""),
    "Python IO encoding dropped from the job env": sub("      PYTHONIOENCODING: utf-8\n", ""),
    "native build may adopt a system AWS-LC (env dropped)": sub('        env:\n          AWS_LC_SYS_USE_SYSTEM: "0"\n        run: cargo build', "        run: cargo build"),
    "native build requires a system AWS-LC": sub('AWS_LC_SYS_USE_SYSTEM: "0"', 'AWS_LC_SYS_USE_SYSTEM: "1"'),
    "native build with a Homebrew install step": sub("      - name: Build the native service\n", "      - name: Install openssl\n        run: brew install openssl@3\n      - name: Build the native service\n"),
    "OpenSSL step removed": sub("      - name: Provide OpenSSL's libcrypto for the OCSP code\n        shell: bash\n        run: node tests/e2e/native/openssl-setup.mjs apply\n", ""),
    "OpenSSL installed by an unpinned download": sub("        run: node tests/e2e/native/openssl-setup.mjs apply\n", "        run: curl -sSL https://example.invalid/openssl.sh | sh\n"),
    "OpenSSL step after the build": sub("      - name: Provide OpenSSL's libcrypto for the OCSP code\n        shell: bash\n        run: node tests/e2e/native/openssl-setup.mjs apply\n", "").replace("      - name: Wait for the real server's handshake\n", "      - name: Provide OpenSSL's libcrypto for the OCSP code\n        shell: bash\n        run: node tests/e2e/native/openssl-setup.mjs apply\n      - name: Wait for the real server's handshake\n", 1),
    "Playwright browser install dropped from linux-managed": sub("      - run: npx --prefix tests/e2e playwright install --with-deps chromium\n", ""),
    "Playwright install without the system libraries": sub("playwright install --with-deps chromium", "playwright install chromium"),
    "CA diagnostic step back": sub("      - name: Install the harness dependencies\n", "      - name: Show the shell\n        shell: bash\n        run: bash -x tests/e2e/fixtures/make-ca.sh \"$RUNNER_TEMP/ca-probe\" 2>&1 | tail -60\n      - name: Install the harness dependencies\n"),
    "GH_TOKEN in the build step env": sub('        env:\n          AWS_LC_SYS_USE_SYSTEM: "0"\n', '        env:\n          AWS_LC_SYS_USE_SYSTEM: "0"\n          GH_TOKEN: ${{ github.token }}\n'),
    "GH_TOKEN in the job env": sub('      PYTHONUTF8: "1"\n', '      PYTHONUTF8: "1"\n      GH_TOKEN: ${{ github.token }}\n'),
    "GH_TOKEN in the unit test step": sub('      - name: Run the native harness unit tests\n        shell: bash\n        env:\n', '      - name: Run the native harness unit tests\n        shell: bash\n        env:\n          GH_TOKEN: ${{ github.token }}\n'),
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
    '|| echo in a release step (F5)': good_release.replace('      - run: cargo package --workspace --exclude probation-server --locked\n', '      - run: cargo package --workspace --exclude probation-server --locked || echo ignored\n', 1),
    '|| /bin/true in a release step (F5)': good_release.replace('      - run: cargo package --workspace --exclude probation-server --locked\n', '      - run: cargo package --workspace --exclude probation-server --locked || /bin/true\n', 1),
    '|| : at the end of a release step (F5)': good_release.replace('      - run: cargo package --workspace --exclude probation-server --locked\n', '      - run: cargo package --workspace --exclude probation-server --locked || :\n', 1),
    'set +e in a release step (F5)': good_release.replace('      - run: cargo package --workspace --exclude probation-server --locked\n', '      - run: |\n          set +e\n          cargo package --workspace --exclude probation-server --locked\n', 1),
    '; true in a release step (F5)': good_release.replace('      - run: cargo package --workspace --exclude probation-server --locked\n', '      - run: cargo package --workspace --exclude probation-server --locked; true\n', 1),
    "an extra job running git push with no needs (F5)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git push origin HEAD:refs/tags/v9\n",
    "an extra job using build-push-action with no needs (F5)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/build-push-action@0000000000000000000000000000000000000000\n",
    "an extra job running buildx --push with no needs (F5)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker buildx build --push -t x/y .\n",
    "|| true in a release step (H1)": good_release.replace("      - run: cargo package --workspace --exclude probation-server --locked\n", "      - run: cargo package --workspace --exclude probation-server --locked || true\n", 1),
    "step if outside the upload-artifact exception (H1)": good_release.replace("      - run: cargo publish --workspace --locked --no-verify\n", "      - if: always()\n        run: cargo publish --workspace --locked --no-verify\n", 1),
    "continue-on-error on a job (H1)": good_release.replace("  codeql:\n    needs: test\n", "  codeql:\n    needs: test\n    continue-on-error: true\n", 1),
    "if always() on the e2e job (D1)": good_release.replace("  e2e:\n    needs: test\n", "  e2e:\n    needs: test\n    if: always()\n", 1),
    "release job no longer needs native (C6)": good_release.replace("needs: [build, e2e, native]", "needs: [build, e2e]", 1),
    "publish job no longer needs native (C6)": good_release.replace("needs: [release, e2e, native]", "needs: [release, e2e]", 1),
    "job-level if on the native job (C6)": good_release.replace("  native:\n    needs: test\n", "  native:\n    needs: test\n    if: false\n", 1),
    "native job passes secrets (C6)": good_release.replace("    uses: ./.github/workflows/native-clients.yml\n", "    uses: ./.github/workflows/native-clients.yml\n    secrets: inherit\n", 1),
    "native job removed (C6)": good_release.replace(good_release[good_release.index("  native:\n"):good_release.index("  codeql:")], "", 1),
    "the transport hot-path bench removed from the release test job (slice 27)": good_release.replace("      - run: cargo bench --locked --bench transport_hot_paths -- --assert\n", "", 1),
    "the transport hot-path bench without --assert (slice 27)": good_release.replace("cargo bench --locked --bench transport_hot_paths -- --assert", "cargo bench --locked --bench transport_hot_paths", 1),
    "the workspace tests removed from the release test job (slice 27)": good_release.replace("      - run: cargo test --workspace --locked\n", "", 1),
    "the transport hot-path bench with --list appended (slice 27 fix round)": good_release.replace("cargo bench --locked --bench transport_hot_paths -- --assert", "cargo bench --locked --bench transport_hot_paths -- --assert --list", 1),
    "the workspace tests built but not run (--no-run, slice 27 fix round)": good_release.replace("      - run: cargo test --workspace --locked\n", "      - run: cargo test --workspace --locked --no-run\n", 1),
    "the tag name interpolated into the Package script (slice 27 fix round)": good_release.replace('VERSION="$REF_NAME"', 'VERSION="${{ github.ref_name }}"', 1),
    "the event payload interpolated into a run script (slice 27 fix round)": good_release.replace("      - run: cargo test --workspace --locked\n", "      - run: cargo test --workspace --locked\n      - run: echo ${{ github.event.head_commit.message }}\n", 1),
    "id-token: write on the test job (RC1-5)": good_release.replace("  test:\n    runs-on: ubuntu-latest\n", "  test:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n", 1),
    "the release is published immediately, not as a draft (RC2-9)": good_release.replace("--verify-tag --draft --generate-notes", "--verify-tag --generate-notes", 1),
    "the bundle is named another way (RC2-9)": good_release.replace('--bundle "$name.sigstore.json"', '--bundle "$name.sig.json"'),
    "a Windows release build without the static feature (RC1-2)": good_release.replace(" --target x86_64-pc-windows-msvc --features static-openssl", " --target x86_64-pc-windows-msvc", 1),
    "top-level permissions contents: write (F5r2)": good_release.replace("permissions:\n  contents: read\n\nenv:", "permissions:\n  contents: write\n\nenv:", 1),
    "test job with a write grant and no native/e2e chain (F5r2)": good_release.replace("  test:\n    runs-on: ubuntu-latest\n", "  test:\n    runs-on: ubuntu-latest\n    permissions:\n      packages: write\n", 1),
    "build job with id-token: write (F5r2)": good_release.replace("  build:\n    needs: [codeql, native-service, build-windows]\n", "  build:\n    needs: [codeql, native-service, build-windows]\n    permissions:\n      id-token: write\n", 1),
    "release no longer gated by the native service lanes (slice 25)": good_release.replace("    needs: [codeql, native-service, build-windows]\n", "    needs: [codeql, build-windows]\n").replace("    needs: [codeql, native-service]\n", "    needs: codeql\n"),
    "native-service job removed (slice 25)": good_release.replace(good_release[good_release.index("  native-service:\n"):good_release.index("  codeql:")], "", 1),
    "cargo test piped without pipefail (F5r2)": good_release.replace("      - run: cargo test --workspace --locked\n", "      - run: cargo test --workspace --locked | cat\n", 1),
    "cargo test inside an if (F5r2)": good_release.replace("      - run: cargo test --workspace --locked\n", "      - run: if cargo test --workspace --locked; then echo ok; fi\n", 1),
    "cargo test with a trailing & (F5r2)": good_release.replace("      - run: cargo test --workspace --locked\n", "      - run: cargo test --workspace --locked &\n", 1),
    "stray job: npm  publish (two spaces) (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm  publish\n",
    "stray job: uv publish (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: uv publish\n",
    "stray job: cargo release publish (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo release publish\n",
    "stray job: npm run publish (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm run publish\n",
    "stray job: gh workflow run (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh workflow run x.yml\n",
    "stray job: crane push (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: crane push a b\n",
    "stray job: skopeo copy (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - run: skopeo copy a b\n",
    "stray job: docker/login-action (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/login-action@0000000000000000000000000000000000000000\n",
    "stray job: softprops/action-gh-release (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: softprops/action-gh-release@0000000000000000000000000000000000000000\n",
    "stray job: pypa/gh-action-pypi-publish (F5r2)": good_release + "\n  stray:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: pypa/gh-action-pypi-publish@0000000000000000000000000000000000000000\n",
}
failed = []
extra_checks = []  # the mutations of the loops below, counted into the final line (run_tests pins the total)
good_service = (root / ".github/workflows/native-service.yml").read_text(encoding="utf-8")


def check_service(text):
    with tempfile.TemporaryDirectory(dir=scratch) as d:
        path = pathlib.Path(d) / "native-service.yml"
        path.write_text(text, encoding="utf-8")
        r = subprocess.run([sys.executable, str(checker), "--native-service", str(path)], capture_output=True, encoding="utf-8", errors="replace")
        return r.returncode, r.stdout + r.stderr


def swap(old, new):
    assert old in good_service, f"mutation anchor missing: {old!r}"
    return good_service.replace(old, new, 1)


service_mutations = {
    "native-service: no pipefail (defaults.run.shell removed) (slice 25)": swap("defaults:\n  run:\n    shell: bash\n", ""),
    "native-service: pull_request_target trigger": swap("on:\n  workflow_call:\n", "on:\n  pull_request_target:\n  workflow_call:\n"),
    "native-service: a push trigger": swap("on:\n  workflow_call:\n", "on:\n  push:\n  workflow_call:\n"),
    "native-service: write permission": swap("permissions:\n  contents: read\n\n# bash", "permissions:\n  contents: write\n\n# bash"),
    "native-service: unpinned action": swap("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0", "actions/setup-node@v4"),
    "native-service: || true on the cargo test": swap("-- --nocapture --test-threads=1 2>&1 | tee \"$RUNNER_TEMP/docker-engine.log\"", "-- --nocapture --test-threads=1 2>&1 | tee \"$RUNNER_TEMP/docker-engine.log\" || true"),
    "native-service: continue-on-error on a step": swap("      - name: Install and start the pinned Docker Engine\n", "      - name: Install and start the pinned Docker Engine\n        continue-on-error: true\n"),
    "native-service: a job-level if": swap("  docker-engine:\n    runs-on: ubuntu-24.04\n", "  docker-engine:\n    if: false\n    runs-on: ubuntu-24.04\n"),
    "native-service: Conan installed without the hash-locked file (slice 25)": swap("python -m pip install --require-hashes -r tests/e2e/native/conan-requirements.txt", 'python -m pip install "conan==2.21.0"'),
    "native-service: the lifecycle lane switches the installer's verification off again (D28)": swap('E2E_SERVICE_SIGNER_WORKFLOW: .github/workflows/native-service.yml\n        run: |\n          pkg=$(echo "$RUNNER_TEMP"/pkg/probation-*)\n          sudo', 'E2E_SERVICE_UNATTESTED: "1"\n        run: |\n          pkg=$(echo "$RUNNER_TEMP"/pkg/probation-*)\n          sudo'),
    "native-service: the attestation step is dropped from a lane that installs the package (D28)": swap("      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2\n        with:\n          subject-path: ${{ steps.pkg.outputs.subject }}\n", ""),
    "native-service: id-token on a job that does not attest": swap("  docker-engine:\n    runs-on: ubuntu-24.04\n", "  docker-engine:\n    permissions:\n      contents: read\n      id-token: write\n    runs-on: ubuntu-24.04\n"),
    "native-service: tools-host without the explicit Rust toolchain install (run 45840170035)": swap("      - name: Install the pinned Rust toolchain\n        run: |\n          rustup toolchain install 1.96.0 --profile minimal --component clippy,rustfmt\n          cargo --version\n      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0\n        with:\n          node-version: ${{ env.PIN_NODE }}\n      - uses: actions/setup-java", "      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0\n        with:\n          node-version: ${{ env.PIN_NODE }}\n      - uses: actions/setup-java"),
    "native-service: the Rust install pins another toolchain": swap("rustup toolchain install 1.96.0 --profile minimal", "rustup toolchain install stable --profile minimal"),
    "native-service: another step runs past a failure with !cancelled()": swap("      - name: Verify the pinned tool versions\n", "      - name: Verify the pinned tool versions\n        if: ${{ !cancelled() }}\n"),
    "native-service: the credential-reads step with always()": swap("        if: ${{ !cancelled() }}\n        shell: bash\n        env:\n          TMPDIR: ${{ runner.temp }}\n          TEMP: ${{ runner.temp }}\n          TMP: ${{ runner.temp }}\n        run: |\n          if [ \"$RUNNER_OS\" = Linux ]", "        if: always()\n        shell: bash\n        env:\n          TMPDIR: ${{ runner.temp }}\n          TEMP: ${{ runner.temp }}\n          TMP: ${{ runner.temp }}\n        run: |\n          if [ \"$RUNNER_OS\" = Linux ]"),
    "native-service: the credential-reads step hides a failure (|| true)": swap("--test-threads=1 2>&1 | tee \"$RUNNER_TEMP/credential-temp.log\"", "--test-threads=1 2>&1 | tee \"$RUNNER_TEMP/credential-temp.log\" || true"),
    "native-service: the credential-reads step dropped (renamed, no if)": swap("      - name: Windows and macOS credential-reads folder checks\n        if: ${{ !cancelled() }}\n", "      - name: Credential checks\n"),
    "native-service: a second credential-reads step in tools": swap("      - name: Verify the pinned tool versions\n", "      - name: Windows and macOS credential-reads folder checks\n        if: ${{ !cancelled() }}\n"),
    "native-service: the credential-reads allowance used outside tools": swap("      - name: Install and start the pinned Docker Engine\n", "      - name: Windows and macOS credential-reads folder checks\n        if: ${{ !cancelled() }}\n"),
    "native-service: a secret": swap("env:\n  CARGO_TERM_COLOR: always\n", "env:\n  CARGO_TERM_COLOR: always\n  TOKEN: ${{ secrets.X }}\n"),
}
with tempfile.TemporaryDirectory(dir=scratch) as d:
    bad_setup = pathlib.Path(d) / "openssl-setup.mjs"
    bad_setup.write_text((here / "openssl-setup.mjs").read_text(encoding="utf-8").replace("x64-windows-static-md", "x64-windows-static"), encoding="utf-8")
    r = subprocess.run([sys.executable, str(checker), "--openssl-setup", str(bad_setup)], capture_output=True, encoding="utf-8", errors="replace")
    extra_checks.append("the plain x64-windows-static triplet (RC1-2)")
    if r.returncode == 0:
        failed.append("the plain x64-windows-static triplet (RC1-2)")
        print("BYPASS (checker passed): the plain x64-windows-static triplet")
code, out = check_service(good_service)
assert code == 0, f"the known-good native-service.yml must pass: {out}"
for name, text in service_mutations.items():
    assert text != good_service, f"{name}: mutation changed nothing"
    extra_checks.append(name)
    code, out = check_service(text)
    if code == 0:
        failed.append(name)
        print(f"BYPASS (checker passed): {name}")

# The call probe was temporary: its presence is rejected, its absence is the permanent shape.
probe_mutations = {"native-call-probe.yml present": None}
with tempfile.TemporaryDirectory(dir=scratch) as d:
    probe_file = pathlib.Path(d) / "probe.yml"
    probe_file.write_text("name: Native call probe\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(checker), "--probe", str(probe_file)], capture_output=True, encoding="utf-8", errors="replace")
    assert r.returncode != 0 and "FAIL " in r.stdout + r.stderr and "Traceback" not in r.stdout + r.stderr, f"a present probe must fail cleanly: {r.stdout}{r.stderr}"
r = subprocess.run([sys.executable, str(checker), "--probe", str(here / "no-such-probe.yml")], capture_output=True, encoding="utf-8", errors="replace")
assert r.returncode == 0, f"without the probe the workflow must pass: {r.stdout}{r.stderr}"
# Under workflow_call github.run_id is the CALLER's id: every artifact wait and upload of the called workflow must key on it
# (never a fixed run), so the direct run and the probe's run cannot read each other's handshake or completion records.
for name, text in {"wait-done on another run": sub('--repo "$GITHUB_REPOSITORY" --run-id "$GITHUB_RUN_ID" --attempt "$GITHUB_RUN_ATTEMPT" --timeout-min 55', '--repo "$GITHUB_REPOSITORY" --run-id 1 --attempt "$GITHUB_RUN_ATTEMPT" --timeout-min 55'),
                   "client-wait on another run": sub('--run-id "$GITHUB_RUN_ID" --attempt "$GITHUB_RUN_ATTEMPT" --out', '--run-id 1 --attempt "$GITHUB_RUN_ATTEMPT" --out'),
                   "client-wait without the attempt": sub(' --attempt "$GITHUB_RUN_ATTEMPT" --out', ' --out'),
                   "wait-done without the attempt": sub(' --attempt "$GITHUB_RUN_ATTEMPT" --timeout-min 55', ' --timeout-min 55'),
                   "handshake upload without the attempt": sub("name: native-handshake-${{ github.run_attempt }}", "name: native-handshake"),
                   "done upload without the attempt": sub("name: native-done-${{ matrix.platform }}-${{ github.run_attempt }}", "name: native-done-${{ matrix.platform }}"),
                   "logs upload without the attempt": sub("name: native-real-server-logs-${{ github.run_attempt }}", "name: native-real-server-logs")}.items():
    extra_checks.append(name)
    code, out = check(text)
    if code == 0:
        failed.append(name)
        print(f"BYPASS (checker passed): {name}")
ids_check = subprocess.run([sys.executable, str(checker), "--verify-ids", "E2E-publishing-native-linux", "E2E-no-such-scenario"], capture_output=True, encoding="utf-8", errors="replace")
assert ids_check.returncode == 1 and "E2E-no-such-scenario" in ids_check.stdout and "native-linux" not in ids_check.stdout.replace("E2E-publishing-native-linux exists", ""), f"--verify-ids must name only the unknown ID: {ids_check.stdout}"

code, out = check(good)
assert code == 0, f"the known-good workflow must pass: {out}"
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
    r = subprocess.run([sys.executable, str(checker), *extra], capture_output=True, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout + r.stderr


with tempfile.TemporaryDirectory(dir=scratch) as d:
    d = pathlib.Path(d)
    # The tunnel pin and the code that obeys it.
    good_tunnel = json.loads((here / "tunnel.json").read_text(encoding="utf-8"))
    for name, change in {"version latest": {"version": "latest"}, "a short sha": {"sha256": "abc123"}, "a non-hex sha": {"sha256": "z" * 64}, "the deb asset": {"asset": "cloudflared-linux-amd64.deb"}, "a floating version": {"version": "2026.10"}}.items():
        (d / "tunnel.json").write_text(json.dumps({"cloudflared": {**good_tunnel["cloudflared"], **change}}), encoding="utf-8")
        code, out = run_checker("--tunnel", str(d / "tunnel.json"))
        if code == 0:
            failed.append(f"tunnel.json: {name}")
            print(f"BYPASS: tunnel.json {name}")
    rendezvous_text = (here / "rendezvous.mjs").read_text(encoding="utf-8")
    cloudflared_text = (here / "cloudflared.mjs").read_text(encoding="utf-8")
    code_mutations = {
        "masks printed after the key is written": ("--rendezvous", rendezvous_text.replace("console.log(maskLines(handshake).join(\"\\n\"));\n    const keyFile", "const keyFile", 1).replace("writeFileSync(keyFile, `${handshake.key}\\n`, { mode: 0o600 });", "writeFileSync(keyFile, `${handshake.key}\\n`, { mode: 0o600 });\n    console.log(maskLines(handshake).join(\"\\n\"));", 1)),
        "handshake not validated": ("--rendezvous", rendezvous_text.replace("const handshake = parseHandshake(readFileSync(join(out, \"handshake.json\"), \"utf8\"));", "const handshake = JSON.parse(readFileSync(join(out, \"handshake.json\"), \"utf8\"));", 1)),
        "server does not print masks": ("--rendezvous", rendezvous_text.replace("console.log(maskLines(handshake).join(\"\\n\"));\n      console.log(\"handshake ready\");", "console.log(\"handshake ready\");", 1)),
        "checksum not enforced": ("--cloudflared-js", cloudflared_text.replace("expected: pin.sha256", "expected: ''")),
        "download not from the pinned URL": ("--cloudflared-js", cloudflared_text.replace("downloadUrl(pin)", "pin.source")),
    }
    for name, (option_name, text) in code_mutations.items():
        assert text != (rendezvous_text if option_name == "--rendezvous" else cloudflared_text), name
        (d / "mutated.mjs").write_text(text, encoding="utf-8")
        code, out = run_checker(option_name, str(d / "mutated.mjs"))
        if code == 0:
            failed.append(f"code: {name}")
            print(f"BYPASS: {name}")
    # SEC3: the hashed requirements must pin exactly the PIN_* versions, every line with a hash.
    good_requirements = (here / "ci-requirements.txt").read_text(encoding="utf-8")
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
        (d / "req.txt").write_text(text, encoding="utf-8")
        code, out = run_checker("--ci-requirements", str(d / "req.txt"))
        if code == 0:
            failed.append(f"ci-requirements: {name}")
            print(f"BYPASS: ci-requirements {name}")
    good_checker = (here / "checker-requirements.txt").read_text(encoding="utf-8")
    for name, text in {"pyyaml removed": "# nothing\n", "pyyaml without hashes": "pyyaml==6.0.3\n", "pyyaml with a range": "pyyaml>=6 \\\n    --hash=sha256:" + "0" * 64 + "\n"}.items():
        (d / "chk.txt").write_text(text, encoding="utf-8")
        code, out = run_checker("--checker-requirements", str(d / "chk.txt"))
        if code == 0:
            failed.append(f"checker-requirements: {name}")
            print(f"BYPASS: checker-requirements {name}")
    # H2: the wrapper must still discover every test, run both canaries and count assertions.
    wrapper_text = (here / "run_tests.py").read_text(encoding="utf-8")
    def wrap(old, new):
        assert old in wrapper_text, old
        return wrapper_text.replace(old, new, 1)
    for name, text in {"fixed test list": wrapper_text.replace('sorted(directory.glob("*.test.*"))', '[here / "assertions.test.mjs"]'),
                       "no stub canary": wrapper_text.replace("if not stub_checker_canary():", "if False:"),
                       "no assertion counting": wrapper_text.replace("count-asserts.mjs", "gone.mjs"),
                       "decoy: if False and the canary in a comment": wrap("if not stub_checker_canary():", "if False and not stub_checker_canary():  # if not stub_checker_canary():"),
                       "decoy: missed emptied, judge_canary() in a comment": wrap("missed = judge_canary()", "missed = []  # judge_canary()"),
                       "decoy: glob only in a comment": wrap('tests = sorted(directory.glob("*.test.*"))', 'tests = [here / "assertions.test.mjs"]  # sorted(here.glob("*.test.*"))'),
                       "decoy: glob in a string": wrap('tests = sorted(directory.glob("*.test.*"))', 'tests = [here / "assertions.test.mjs"]; _ = \'sorted(here.glob("*.test.*"))\''),
                       "failures never fail the run": wrap("    if failures:\n", "    if False:\n"),
                       "failures never collected": wrap("        failures += findings\n", "        pass\n"),
                       "the canary result ignored": wrap("        return 1\n    missed", "        pass\n    missed"),
                       "main always returns 0": wrap('finding(s)")\n        return 1', 'finding(s)")\n        return 0'),
                       "the exit status dropped": wrap("sys.exit(main())", "main()"),
                       "SKIP_ON widened (F9)": wrap('"rendezvous-cli.test.mjs"}}', '"rendezvous-cli.test.mjs", "stack.test.mjs", "pf.test.mjs"}}'),
                       "SKIP_ON on another platform (F9)": wrap('SKIP_ON = {"win32"', 'SKIP_ON = {"linux": {"stack.test.mjs"}, "win32"'),
                       "findings reset before aggregation (F9)": wrap("        failures += findings\n", "        findings = []\n        failures += findings\n"),
                       "findings reassigned after run_one (F9)": wrap("        print(f\"{'ok  '", "        findings = findings[:0]\n        print(f\"{'ok  '"),
                       "the registry not read": wrap('(directory / "expected-asserts.json").read_text(encoding="utf-8")', '"{}"')}.items():
        extra_checks.append(name)
        (d / "wrapper.py").write_text(text, encoding="utf-8")
        code, out = run_checker("--run-tests", str(d / "wrapper.py"))
        if code == 0:
            failed.append(f"run_tests.py: {name}")
            print(f"BYPASS: run_tests.py {name}")
    # F9: expected-asserts.json may not lower a floor, nor drop an entry (a deleted test deleted with its registration).
    real_expected = json.loads((here / "expected-asserts.json").read_text(encoding="utf-8"))
    some = next(iter(real_expected))
    lowered = dict(real_expected, **{some: real_expected[some] - 1})
    dropped = {k: v for k, v in real_expected.items() if k != some}
    for name, table in {"a floor lowered": lowered, "an entry deleted": dropped}.items():
        extra_checks.append(name)
        (d / "expected.json").write_text(json.dumps(table), encoding="utf-8")
        code, out = run_checker("--expected", str(d / "expected.json"))
        if code == 0:
            failed.append(f"expected-asserts.json: {name}")
            print(f"BYPASS: expected-asserts.json {name}")
    # G10: pins.json with a range, `latest` or a wildcard.
    import json
    real_pins = json.loads((here / "pins.json").read_text(encoding="utf-8"))
    for tool, bad_value in [("node", "latest"), ("npm", "*"), ("python", "3.15"), ("uv", "^0.13.5"), ("pip", "26.2.x")]:
        pins = dict(real_pins, **{tool: bad_value})
        (d / "pins.json").write_text(json.dumps(pins), encoding="utf-8")
        code, out = run_checker("--pins", str(d / "pins.json"))
        if code == 0 or tool not in out:
            failed.append(f"pins.json {tool}={bad_value}")
            print(f"BYPASS: pins.json {tool}={bad_value}: {out[-200:]}")
    # Slice 26: cluster.yml is held to the same rules (pins, least privilege, pipefail, hashed downloads, the job set).
    good_cluster = (root / ".github/workflows/cluster.yml").read_text(encoding="utf-8")
    def csub(old, new, count=1):
        assert old in good_cluster, f"cluster mutation anchor missing: {old!r}"
        return good_cluster.replace(old, new, count)
    cluster_mutations = {
        "pull_request_target": csub("on:\n  pull_request:\n", "on:\n  pull_request_target:\n  pull_request:\n"),
        "workflow_run trigger": csub("  workflow_dispatch:\n\npermissions", "  workflow_dispatch:\n  workflow_run:\n    workflows: [Rust]\n\npermissions"),
        "an unfiltered pull_request": csub("    paths:\n      - deploy/kubernetes/**\n      - src/http/**\n      - src/oci/**\n      - tests/e2e/**\n      - tests/cluster_peer.rs\n      - tests/node_scripts.rs\n      - .github/workflows/cluster.yml\n      - docs/operations.md\n", ""),
        "write permissions": csub("permissions:\n  contents: read\n\ndefaults", "permissions:\n  contents: write\n\ndefaults"),
        "a job-level permission": csub("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    permissions:\n      contents: write\n"),
        "no pipefail": csub("shell: bash -eo pipefail {0}", "shell: bash -e {0}"),
        "an unpinned action": csub("actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0", "actions/setup-python@v5", 1),
        "checkout keeps credentials": csub("        with:\n          persist-credentials: false\n", "", 1),
        "a download with no hash check": csub('          echo "$KUBECTL_SHA256  $RUNNER_TEMP/bin/kubectl" | sha256sum --check\n', "", 1),
        "a pipe into a shell": csub('          chmod +x "$RUNNER_TEMP/bin/kubectl"\n          curl', '          curl -fsSL https://example.test/x | sh\n          curl', 1),
        "|| true on a check": csub("      - run: python tests/e2e/native/check_kubernetes.py\n", "      - run: python tests/e2e/native/check_kubernetes.py || true\n"),
        "a step that may be skipped": csub("      - run: python tests/e2e/native/check_kubernetes.py\n", "      - if: github.event_name == 'schedule'\n        run: python tests/e2e/native/check_kubernetes.py\n"),
        "continue-on-error": csub("    timeout-minutes: 40\n", "    timeout-minutes: 40\n    continue-on-error: true\n"),
        "no timeout": csub("    timeout-minutes: 40\n", ""),
        "the kind job removed": good_cluster[:good_cluster.index("  # NOT RUN BY ANYBODY YET. kind with")] + good_cluster[good_cluster.index("  # NOT RUN BY ANYBODY YET. One kind node"):],
        "an extra job": good_cluster + "\n  extra:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0\n        with:\n          persist-credentials: false\n      - run: echo hi\n",
        "the sysctl step removed": csub("      # ubuntu-24.04 restricts unprivileged user namespaces; the real-TCP peer test (tests/cluster_peer.rs) needs them.\n      - run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n      - run: cargo test --locked --test cluster_peer", "      - run: cargo test --locked --test cluster_peer"),
        "the ignored test not included": csub("cluster_peer -- --include-ignored", "cluster_peer"),
        "kubeconform not strict": csub("kubeconform -strict -summary", "kubeconform -summary"),
        "one scenario dropped": csub("--only E2E-service-cluster-probe --only E2E-service-cluster", "--only E2E-service-cluster"),
        "a secret": csub("      - run: sh -n deploy/kubernetes/node/install-node.sh", "      - run: echo ${{ secrets.TOKEN }}\n      - run: sh -n deploy/kubernetes/node/install-node.sh"),
        "curl -k": csub('curl -fsSL -o "$RUNNER_TEMP/kubeconform.tgz"', 'curl -k -fsSL -o "$RUNNER_TEMP/kubeconform.tgz"'),
    }
    for name, text in cluster_mutations.items():
        extra_checks.append(f"cluster.yml: {name}")
        (d / "cluster.yml").write_text(text, encoding="utf-8")
        code, out = run_checker("--cluster", str(d / "cluster.yml"))
        if code == 0:
            failed.append(f"cluster.yml: {name}")
            print(f"BYPASS: cluster.yml {name}")
    (d / "cluster.yml").write_text(good_cluster, encoding="utf-8")
    code, out = run_checker("--cluster", str(d / "cluster.yml"))
    if code != 0:
        failed.append("the known-good cluster.yml")
        print(f"the known-good cluster.yml must pass: {out}")
    # G10: a scenario meta inside a block comment declares nothing.
    scenarios = d / "scenarios"
    scenarios.mkdir()
    (scenarios / "a.mjs").write_text('/*\nexport const meta = { id: "E2E-service-policy", suites: [] };\n*/\nexport const meta = { id: "E2E-other", suites: [] };\n', encoding="utf-8")
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
print(f"check_workflow.test: {len(mutations) + len(release_mutations) + len(probe_mutations) + len(extra_checks)} bypasses all fail, known-good passes")
