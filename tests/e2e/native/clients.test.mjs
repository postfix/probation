// Red/green check for clients.mjs using fake client executables on PATH (POSIX only).
// NATIVE_TEST_SCRATCH=<disk dir> node tests/e2e/native/clients.test.mjs
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { inside } from "./clients.mjs";

const script = fileURLToPath(new URL("./clients.mjs", import.meta.url));
const scratchRoot = process.env.NATIVE_TEST_SCRATCH;
assert(scratchRoot, "set NATIVE_TEST_SCRATCH to a disk directory (not /tmp)");
// macOS temp directories live under /var, a symlink to /private/var: every fake is built through a symlinked parent, so the
// provenance checks meet paths whose real path differs from the spelled one on every platform (not only on macOS).
mkdirSync(join(scratchRoot, "real"), { recursive: true });
try { symlinkSync(join(scratchRoot, "real"), join(scratchRoot, "link"), "dir"); } catch (error) { if (error.code !== "EEXIST") throw error; }
const scratch = process.platform === "win32" ? scratchRoot : join(scratchRoot, "link");
assert.notEqual(realpathSync(scratch), scratch, "the fakes live behind a symlink");
const platform = `${process.platform}-${process.arch}`;
const good = {
  node: `v${process.versions.node}`, npm: "11.21.1", python: "Python 3.15.1", pip: "pip 26.2.2 from @PREFIX@/lib/python3.15/site-packages/pip (python 3.15)",
  twine: "twine version 7.0.0 (importlib-metadata: 1)", uv: "uv 0.13.5 (abc 2026-01-01)", uvPython: "Python 3.15.1",
};

/// `change`: field -> output text (or null to omit the tool); `stderr`: tools that print on stderr.
function run({ change = {}, stderr = [], env = {}, pinsChange = {}, shadow = null } = {}) {
  const dir = mkdtempSync(join(scratch, "clients-"));
  const prefix = join(dir, "prefix");
  const bin = join(prefix, "bin");
  mkdirSync(bin, { recursive: true });
  const out = Object.fromEntries(Object.entries({ ...good, ...change }).map(([k, v]) => [k, typeof v === "string" ? v.replaceAll("@PREFIX@", prefix) : v]));
  const script_ = (name, body) => { writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`); chmodSync(join(bin, name), 0o755); };
  const say = (tool, text) => (stderr.includes(tool) ? `echo '${text}' >&2` : `echo '${text}'`);
  if (out.node !== null) script_("node", say("node", out.node));
  if (out.npm !== null) script_("npm", say("npm", out.npm));
  // The fake python also answers the sys.prefix probe and runs as the interpreter of a twine script.
  if (out.python !== null) {
    script_("python", `case "$1" in
  -m) ${out.pip === null ? "exit 1" : say("pip", out.pip)} ;;
  -c) echo '${prefix}'; echo '${join(bin, "python")}' ;;
  */twine) ${say("twine", out.twine ?? "")} ;;
  *) ${say("python", out.python)} ;;
esac`);
  }
  // A real twine script starts with its interpreter's path; the fake one names the fake python.
  if (out.twine !== null) {
    const interpreter = change.twineInterpreter ?? join(bin, "python");
    writeFileSync(join(bin, "twine"), `#!${interpreter}\n`);
    chmodSync(join(bin, "twine"), 0o755);
    if (change.twineInterpreter) writeFileSync(join(bin, "twine"), `#!${interpreter}\n${say("twine", out.twine)}\n`);
  }
  if (out.uv !== null) {
    const elsewhere = change.uvPythonOutside ? join(dir, "elsewhere") : bin;
    mkdirSync(elsewhere, { recursive: true });
    writeFileSync(join(elsewhere, "uvpython"), `#!/bin/sh\n${say("uvpython", out.uvPython)}\n`);
    chmodSync(join(elsewhere, "uvpython"), 0o755);
    script_("uv", `if [ "$1" = "python" ]; then echo ${join(elsewhere, "uvpython")}; else ${say("uv", out.uv)}; fi`);
  }
  if (shadow) {
    const early = join(dir, "early");
    mkdirSync(early);
    writeFileSync(join(early, shadow.tool), `#!/bin/sh\necho '${shadow.text}'\n`);
    chmodSync(join(early, shadow.tool), 0o755);
  }
  const pins = { node: process.versions.node, npm: "11.21.1", python: "3.15.1", pip: "26.2.2", twine: "7.0.0", uv: "0.13.5", ...pinsChange };
  writeFileSync(join(dir, "pins.json"), JSON.stringify(pins));
  const path = shadow ? `${join(dir, "early")}:${bin}` : bin;
  if (shadow?.tool === "python-scripts") rmSync(join(dir, "early"), { recursive: true, force: true });
  const result = spawnSync(process.execPath, [script], {
    env: { PATH: path, NATIVE_PINS_FILE: join(dir, "pins.json"), ...("NATIVE_PLATFORM" in env ? env : { NATIVE_PLATFORM: platform, ...env }) },
    encoding: "utf8",
  });
  rmSync(dir, { recursive: true, force: true });
  return result;
}
const fails = (what, options, pattern) => {
  const r = run(options);
  assert.notEqual(r.status, 0, `${what} must fail: ${r.stdout}`);
  if (pattern) assert.match(r.stdout, pattern, what);
};

// inside(): symlinked parents, paths that do not exist yet, siblings with a shared name prefix and `..` traversal.
{
  const prefix = join(scratch, "pfx");
  mkdirSync(join(prefix, "bin"), { recursive: true });
  assert.ok(inside(join(prefix, "bin"), prefix), "an existing directory inside");
  assert.ok(inside(join(prefix, "lib", "site-packages", "pip"), prefix), "a path that does not exist yet, below a symlinked parent");
  assert.ok(inside(join(realpathSync(scratch), "pfx", "lib", "x"), prefix), "spelled through the real path, prefix through the link");
  assert.ok(!inside(`${prefix}-evil/bin`, prefix), "a sibling sharing the name prefix");
  assert.ok(!inside(join(prefix, "..", "elsewhere"), prefix), "a .. traversal");
  assert.ok(!inside("/definitely/elsewhere/pip", prefix));
}
const ok = run();
assert.equal(ok.status, 0, `all pinned clients must pass: ${ok.stdout}${ok.stderr}`);
const report = JSON.parse(ok.stdout);
for (const tool of ["node", "npm", "python", "twine", "uv"]) assert.match(report.observed.paths[tool], /\/bin\/|\/early\//, `${tool}'s resolved path is recorded`);
assert.equal(report.observed.uvPython, "3.15.1", "the interpreter uv would use is probed");

fails("a wrong twine version", { change: { twine: "twine version 6.9.9" } });
fails("a missing uv", { change: { uv: null } });
fails("a missing npm", { change: { npm: null } });
fails("a missing twine", { change: { twine: null } });
fails("a missing pip", { change: { pip: null } });
fails("a wrong pip", { change: { pip: "pip 25.1.1 from /x (python 3.15)" } });
fails("a wrong python", { change: { python: "Python 3.13.0" } });
fails("a prerelease python", { change: { python: "Python 3.15.1rc1" } });
fails("a longer python patch", { change: { python: "Python 3.15.10" } });
fails("a wrong prefix line (uv)", { change: { uv: "xuv 0.13.5 (abc)" } });
fails("a wrong prefix line (python)", { change: { python: "Pythonic 3.15.1" } });
fails("a wrong prefix line (twine)", { change: { twine: "mytwine version 7.0.0" } });
fails("an npm line with extra words", { change: { npm: "npm 11.21.1" } });
// A pin that differs from whatever node runs the test (a hosted runner may well run the pinned one).
const otherNode = `${Number(process.versions.node.split(".")[0]) + 1}.0.0`;
assert.notEqual(otherNode, process.versions.node);
fails("a wrong node pin", { pinsChange: { node: otherNode } }, /node/);
fails("a node on PATH that is not the pinned one", { change: { node: "v20.0.0" } }, /node on PATH/);
fails("a shadowing npm earlier on PATH", { shadow: { tool: "npm", text: "10.0.0" } }, /npm/);
// C1: a shadow that prints the right version is still the wrong binary: npm must sit beside the node
// on PATH, and uv inside the pinned python's prefix.
fails("a shadowing npm that prints the pinned version", { shadow: { tool: "npm", text: "11.21.1" } }, /npm: .* is not beside the node/);
fails("a shadowing uv that prints the pinned version", { shadow: { tool: "uv", text: "uv 0.13.5 (shadow)" } }, /uv: .* outside the python prefix/);
fails("a shadowing node earlier on PATH", { shadow: { tool: "node", text: "v20.0.0" } }, /node on PATH/);
fails("the wrong interpreter for uv", { change: { uvPython: "Python 3.14.0" } }, /uv's python/);
fails("an unset NATIVE_PLATFORM", { env: { NATIVE_PLATFORM: undefined } }, /NATIVE_PLATFORM/);
fails("a wrong NATIVE_PLATFORM", { env: { NATIVE_PLATFORM: "freebsd-x64" } }, /platform/);
// G9: every tool belongs to the pinned python.
fails("a twine script that runs under a different interpreter", { change: { twineInterpreter: "/bin/sh" } }, /twine/);
fails("a uv whose python find is outside the python prefix", { change: { uvPythonOutside: true } }, /uv's python/);
fails("a pip whose path is outside the python prefix", { change: { pip: "pip 26.2.2 from /elsewhere/site-packages/pip (python 3.15)" } }, /pip/);
fails("a pip running another python version", { change: { pip: "pip 26.2.2 from @PREFIX@/lib/site-packages/pip (python 3.13)" } }, /pip/);
assert.equal(run({ stderr: ["twine", "uv", "npm"] }).status, 0, "versions printed on stderr are read");
console.log("clients.test: ok");
