// Small scope checks on shared files (C8, C9, C10). node tests/e2e/native/scope.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

// C8: the signed-delete redaction covers only the two approved destinations (host and path
// prefix each, the second only with the signed query: the historical matrix run asserts its unsigned
// /custom/case row unredacted), never "any URL containing sig=". The original single destination alone cannot
// hold: E2E-publishing-npm-actions asserts the redacted row of its /custom/case destination.
const fakes = read("../fixtures/fakes/main.mjs");
const definition = fakes.slice(fakes.indexOf("const signedDelete ="), fakes.indexOf(";", fakes.indexOf("const signedDelete =")) + 1).replace(/\s+/g, " ");
assert.equal(definition,
  'const signedDelete = (host === "registry-b.e2e.test" && req.url.startsWith("/extra/case/")) || (host === "registry.npmjs.org" && req.url.startsWith("/custom/case/") && req.url.includes("?sig="));');
assert.ok(!/includes\("sig="\)/.test(fakes.slice(fakes.indexOf("const signedDelete"), fakes.indexOf("const entry"))));

// C9: client-native is built and started for the native scenario only.
const stack = read("../harness/stack.mjs");
assert.ok(!/const CLIENTS = \[[^\]]*client-native/.test(stack), "client-native is not in every harness stack");
const scenario = read("../scenarios/publishing-native-linux.mjs");
assert.match(scenario, /compose\(\["build", "client-native"\]\)/, "the native scenario builds it");
assert.match(scenario, /start\("client-native"\)/, "and starts it");

// Windows: a dynamic import needs a file URL, never a drive-letter path; the CA script needs forward slashes under Git bash.
assert.match(read("../harness/run.mjs"), /import\(pathToFileURL\(join\(dir, file\)\)\.href\)/, "run.mjs imports scenarios by file URL");

// Test fakes that are scripts name a real executable as interpreter (macOS cannot run a script through another script): only
// /bin/sh, or the pyinterp symlink to it, in every test file.
{
  const { readdirSync } = await import("node:fs");
  const dir = fileURLToPath(new URL("./", import.meta.url));
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".test.mjs") && f !== "scope.test.mjs")) {
    for (const [, interpreter] of readFileSync(`${dir}${file}`, "utf8").matchAll(/`#!([^\n`\\]+)/g)) {
      assert.match(interpreter, /^(\/bin\/sh|\$\{interpreter\})$/, `${file}: unexpected fake interpreter ${interpreter}`);
    }
  }
}

// C10: `until` has no unused label.
assert.match(read("./publishing.mjs"), /const until = async \(check\) =>/);
// CI acceptance uses the real server: in GitHub Actions publishing.mjs refuses the in-process snapshot fixture.
{
  const r = spawnSync(process.execPath, [fileURLToPath(new URL("./publishing.mjs", import.meta.url))], { encoding: "utf8", env: { PATH: process.env.PATH, GITHUB_ACTIONS: "true", NATIVE_PLATFORM: "linux-x64" } });
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /real policy server/);
}
console.log("scope.test: ok");
