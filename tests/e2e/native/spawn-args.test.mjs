// C4: the argument builder keeps every argument intact, on every platform.
// node tests/e2e/native/spawn-args.test.mjs
import assert from "node:assert/strict";
import { launch, taskkillArgs, winCommandLine } from "./spawn-args.mjs";

// A reference splitter with the Microsoft C runtime rules (what a program started by
// cmd.exe sees as argv): quotes group, a backslash run before a quote is halved.
function splitWindows(line) {
  const out = [];
  let current = "", inQuote = false, started = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "\\") {
      let n = 0;
      while (line[i] === "\\") { n++; i++; }
      if (line[i] === '"') { current += "\\".repeat(Math.floor(n / 2)); if (n % 2) { current += '"'; } else { i--; } }
      else { current += "\\".repeat(n); i--; }
      started = true;
    } else if (c === '"') { inQuote = !inQuote; started = true; }
    else if (/\s/.test(c) && !inQuote) { if (started) out.push(current); current = ""; started = false; }
    else { current += c; started = true; }
  }
  if (started) out.push(current);
  return out;
}

const bash = "C:\\Program Files\\Git\\bin\\bash.exe";
const args = ["C:\\a b\\make-ca.sh", "C:/work dir", "native deprecation", "a&b", "", "x^y", "(p)", "semi;colon", "tab\there", "back\\slash", "trail\\", "C:\\a b\\"];
const line = winCommandLine(bash, args);
assert.deepEqual(splitWindows(line), [bash, ...args], `the command with spaces and every argument survive: ${line}`);
const [file, argv, options] = launch(bash, args, { cwd: "x" }, "win32");
assert.equal(file, "cmd.exe");
assert.deepEqual(argv.slice(0, 4), ["/d", "/v:off", "/s", "/c"], "delayed expansion is off, so ! cannot expand");
assert.equal(argv[4], `"${line}"`, "one verbatim command line, wrapped for /s");
assert.equal(options.windowsVerbatimArguments, true);
assert.equal(options.cwd, "x");
for (const bad of ["%PATH%", 'say "hi"', "a\nb", "a\rb"]) assert.throws(() => winCommandLine("npm", [bad]), /unsafe/);
assert.throws(() => winCommandLine("C:\\Program Files\\100%\\x.exe", []), /unsafe/);

// Elsewhere the arguments go straight through, untouched.
for (const platform of ["linux", "darwin"]) {
  const direct = launch("bash", args, { cwd: "y" }, platform);
  assert.deepEqual(direct, ["bash", args, { cwd: "y" }], `${platform}: no shell, no re-quoting`);
}

// M1: a timeout on Windows must kill the whole tree (cmd.exe starts the real program), not only the shell.
assert.deepEqual(taskkillArgs(4242, "win32"), ["taskkill", ["/T", "/F", "/PID", "4242"]]);
assert.equal(taskkillArgs(4242, "linux"), null, "elsewhere the child is killed directly");
for (const bad of ["4242 & calc", -1, 1.5, "x", undefined]) assert.throws(() => taskkillArgs(bad, "win32"), /pid/);
// Real programs (bash.exe, certutil, icacls, sudo, openssl) do not need the cmd.exe wrapper that .cmd shims do.
const [direct, directArgv] = launch(bash, ["a b"], {}, "win32", { shim: false });
assert.equal(direct, bash);
assert.deepEqual(directArgv, ["a b"]);
console.log("spawn-args.test: ok");
