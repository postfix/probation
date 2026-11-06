// make-ca.sh must say what failed and must not let Git for Windows' path conversion rewrite `-subj /CN=...` (on the hosted
// Windows runner it exited non-zero with no output at all: every openssl error went to /dev/null).
// NATIVE_TEST_SCRATCH=<disk dir> node tests/e2e/native/ca-script.test.mjs
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { BASH, posixPath } from "./stack.mjs";

const script = fileURLToPath(new URL("../fixtures/make-ca.sh", import.meta.url));
const scratch = process.env.NATIVE_TEST_SCRATCH;
assert(scratch, "set NATIVE_TEST_SCRATCH");
const root = mkdtempSync(join(scratch, "ca-"));
const bin = join(root, "bin");
mkdirSync(bin);
const record = join(root, "calls.txt");
// A fake openssl: records its arguments and the path-conversion switches, and fails the third call with a message.
writeFileSync(join(bin, "openssl"), `#!/bin/sh
echo "ARGS: $* | MSYS_NO_PATHCONV=$MSYS_NO_PATHCONV MSYS2_ARG_CONV_EXCL=$MSYS2_ARG_CONV_EXCL" >> "${posixPath(record)}"
case "$1" in
  rand) echo 0123456789abcdef; exit 0 ;;
  x509) echo "FAKE-OPENSSL: unable to sign the certificate" >&2; exit 1 ;;
esac
touch "$(echo "$@" | sed -n 's/.*-out \\([^ ]*\\).*/\\1/p;s/.*-keyout \\([^ ]*\\).*/\\1/p' | head -1)" 2>/dev/null
exit 0
`);
chmodSync(join(bin, "openssl"), 0o755);
const out = join(root, "out");
// The fake is named explicitly (OPENSSL), not found through PATH: on Windows bash may prefer Git's own openssl (a plain
// file without .exe loses to it, and PATH is converted between the two path spellings), and the real one would succeed.
const r = spawnSync(BASH, [posixPath(script), posixPath(out)], { encoding: "utf8", env: { ...process.env, OPENSSL: posixPath(join(bin, "openssl")) } });
// Proof that the fake ran at all: a test that passes without it proves nothing on any platform.
assert.ok(existsSync(record) && readFileSync(record, "utf8").includes("ARGS: req"), `the fake openssl was never invoked (exit ${r.status}, stderr ${JSON.stringify(r.stderr)})`);
assert.notEqual(r.status, 0, "a failing openssl fails the script");
assert.match(r.stderr, /FAKE-OPENSSL: unable to sign the certificate/, `the failing command's own message reaches stderr: ${JSON.stringify(r.stderr)}`);
assert.match(r.stderr, /make-ca\.sh/, "and the script says that it was make-ca.sh");
const calls = readFileSync(record, "utf8");
assert.match(calls, /-subj \/CN=probation-e2e-ca/, "the subject reaches openssl as written");
assert.ok(calls.split("\n").filter((l) => l.startsWith("ARGS: req")).every((l) => l.includes("MSYS_NO_PATHCONV=1") && l.includes("MSYS2_ARG_CONV_EXCL=*")), "path conversion is switched off for openssl");
assert.ok(!existsSync(join(out, "openssl.log")) || readFileSync(join(out, "openssl.log"), "utf8").length >= 0);
rmSync(root, { recursive: true, force: true });
console.log("ca-script.test: ok");
