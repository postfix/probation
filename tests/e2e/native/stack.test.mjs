// Cleanup, gating and quoting of stack.mjs. node tests/e2e/native/stack.test.mjs
// NATIVE_TEST_SCRATCH must name a disk directory (not /tmp).
import assert from "node:assert/strict";
import { lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync, chmodSync } from "node:fs";
import net from "node:net";
import { join } from "node:path";
import { HANDLED_SIGNALS, composeTrustBundle, describeFailure, notReadyReport, posixPath, run, startStack, winCommandLine, writeHostsAtomically, keyFileWarnings } from "./stack.mjs";

const scratch = process.env.NATIVE_TEST_SCRATCH;
assert(scratch, "set NATIVE_TEST_SCRATCH");
const free = () => new Promise((resolve) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
// pypi.org resolves to a public address until the hosts line is written, then to loopback.
const resolvesAfterTheHostsLine = () => { let calls = 0; return async () => (calls++ === 0 ? "203.0.113.9" : "127.0.0.1"); };
const refused = (port) => new Promise((resolve) => { const c = net.connect(port, "127.0.0.1"); c.on("connect", () => { c.destroy(); resolve(false); }); c.on("error", () => resolve(true)); });

// S1: a throw after trust() and the hosts mapping restores both and closes every server.
{
  const dir = mkdtempSync(join(scratch, "stack-"));
  const hostsFile = join(dir, "hosts");
  const original = "127.0.0.1 localhost\n";
  writeFileSync(hostsFile, original);
  const events = [];
  const npmPort = await free();
  const pypiPort = await free();
  // A "binary" that exits at once makes the readiness wait fail after trust and mapping.
  await assert.rejects(startStack({
    binary: process.execPath, work: join(dir, "work"), npmPort, pypiPort,
    hooks: { trust: () => { events.push("trust"); return () => events.push("untrust"); }, lookup: resolvesAfterTheHostsLine(), hostsFile, mapHosts: true },
  }), /probation exited/);
  assert.deepEqual(events, ["trust", "untrust"], "the CA store is restored");
  assert.equal(readFileSync(hostsFile, "utf8"), original, "the hosts mapping is removed");
  assert.ok(await refused(npmPort) && await refused(pypiPort), "every fake server is closed");
  rmSync(dir, { recursive: true, force: true });
}

// The service's trust file: the run's own CA, a real server's CA if given, and on Linux (where SSL_CERT_FILE replaces
// the system roots) the system roots when the policy server sits behind a public certificate (the tunnel).
{
  const read = (path) => (path === "/etc/ssl/certs/ca-certificates.crt" ? "SYSTEM-ROOTS" : null);
  assert.equal(composeTrustBundle({ nativePem: "NATIVE", platform: "linux", read }), "NATIVE");
  assert.equal(composeTrustBundle({ nativePem: "NATIVE", extraPem: "SERVER-CA", platform: "linux", read }), "NATIVE\nSERVER-CA");
  assert.equal(composeTrustBundle({ nativePem: "NATIVE", publicTrust: true, platform: "linux", read }), "NATIVE\nSYSTEM-ROOTS");
  assert.equal(composeTrustBundle({ nativePem: "NATIVE", publicTrust: true, platform: "darwin", read }), "NATIVE", "macOS and Windows verify against the system store");
  assert.throws(() => composeTrustBundle({ nativePem: "NATIVE", publicTrust: true, platform: "linux", read: () => null }), /system CA bundle/);
}

// Git bash reads a backslash as an escape: paths handed to bash scripts use forward slashes.
assert.equal(posixPath("C:\\Users\\runner\\work\\make-ca.sh"), "C:/Users/runner/work/make-ca.sh");
assert.equal(posixPath("/home/x/y"), "/home/x/y");

// A command that could not even start must say why (hosted Windows: "make-ca failed: " with nothing after it).
{
  const missing = run("definitely-not-a-program-xyz", ["--version"]);
  assert.equal(missing.status, -1);
  assert.match(describeFailure("tool", missing), /tool failed \(exit -1, ENOENT\)/);
  const failing = run(process.execPath, ["-e", "console.log('to-stdout'); console.error('to-stderr'); process.exit(3)"]);
  const text = describeFailure("tool", failing);
  assert.match(text, /exit 3/);
  assert.ok(text.includes("to-stdout") && text.includes("to-stderr"), text);
  assert.match(describeFailure("tool", { status: null, signal: "SIGTERM", out: "", stdout: "", stderr: "" }), /signal SIGTERM/);
}

// A service that never becomes ready must explain itself: the /health/ready answer, the START of its log (the cause is usually
// early; the tail is only repeated refusals) and what is in its data directory.
{
  const log = Array.from({ length: 200 }, (_, i) => `line-${i + 1}`).join("\n");
  const report = notReadyReport({ ready: { status: 503, body: "storage: closed" }, log, listing: [{ name: "service-policy.checking", size: 9 }, { name: "blocklist.json", size: 120 }], timeoutMs: 60000 });
  assert.match(report, /GET \/health\/ready -> 503/);
  assert.ok(report.includes("storage: closed"));
  assert.ok(report.includes("line-1\n") && report.includes("line-60\n") && !report.includes("line-61\n"), "the first 60 lines");
  assert.ok(report.includes("line-200"), "and the last lines");
  assert.ok(report.includes("service-policy.checking (9 bytes)") && report.includes("blocklist.json (120 bytes)"), "the data directory listing");
  assert.match(notReadyReport({ ready: null, log: "", listing: [], timeoutMs: 1 }), /no answer/);
}

// SEC1: a run killed hard (SIGKILL, a Windows kill) leaves its marked hosts line and trust entry; the next run
// removes both before it starts, even though the stale line makes pypi.org look like loopback.
{
  const dir = mkdtempSync(join(scratch, "stack-"));
  const hostsFile = join(dir, "hosts");
  writeFileSync(hostsFile, "127.0.0.1 localhost\n127.0.0.1 pypi.org # probation-native-e2e\n10.0.0.1 keep.example\n");
  const events = [];
  await assert.rejects(startStack({
    binary: process.execPath, work: join(dir, "work"), npmPort: await free(), pypiPort: await free(),
    hooks: { trust: () => () => {}, staleTrust: () => events.push("stale trust removed"), lookup: async () => "127.0.0.1", hostsFile, mapHosts: true },
  }), /probation exited/);
  assert.equal(readFileSync(hostsFile, "utf8"), "127.0.0.1 localhost\n10.0.0.1 keep.example\n", "the stale marked line is gone, other lines are kept");
  assert.deepEqual(events, ["stale trust removed"]);
  rmSync(dir, { recursive: true, force: true });
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"]) assert.ok(HANDLED_SIGNALS.includes(signal), `${signal} is handled`);
}

// C4: the hosts line is written but pypi.org still does not resolve to loopback (an nsswitch or resolver
// that ignores it): the run stops with a clear message and puts the file back.
{
  const dir = mkdtempSync(join(scratch, "stack-"));
  const hostsFile = join(dir, "hosts");
  writeFileSync(hostsFile, "127.0.0.1 localhost\n");
  await assert.rejects(startStack({
    binary: process.execPath, work: join(dir, "work"), npmPort: await free(), pypiPort: await free(),
    hooks: { trust: () => () => {}, staleTrust: () => {}, lookup: async () => "203.0.113.9", hostsFile, mapHosts: true },
  }), /still does not resolve to loopback after the hosts file was written.*203\.0\.113\.9/);
  assert.equal(readFileSync(hostsFile, "utf8"), "127.0.0.1 localhost\n", "the hosts file is put back");
  rmSync(dir, { recursive: true, force: true });
}

// S2: no mapping outside CI or an explicit opt-in; the hosts file is replaced atomically.
{
  const dir = mkdtempSync(join(scratch, "stack-"));
  const hostsFile = join(dir, "hosts");
  writeFileSync(hostsFile, "127.0.0.1 localhost\n");
  await assert.rejects(startStack({
    binary: process.execPath, work: join(dir, "work"), npmPort: await free(), pypiPort: await free(),
    hooks: { trust: () => () => {}, lookup: async () => "203.0.113.9", hostsFile, mapHosts: false },
  }), /pypi\.org does not resolve to loopback/);
  assert.equal(readFileSync(hostsFile, "utf8"), "127.0.0.1 localhost\n", "the hosts file was not touched");
  if (process.platform !== "win32") chmodSync(hostsFile, 0o640);
  const before = statSync(hostsFile).ino;
  writeHostsAtomically(hostsFile, "127.0.0.1 localhost\n127.0.0.1 pypi.org # x\n");
  assert.equal(readFileSync(hostsFile, "utf8"), "127.0.0.1 localhost\n127.0.0.1 pypi.org # x\n");
  assert.notEqual(statSync(hostsFile).ino, before, "replaced by rename, never truncated in place");
  if (process.platform !== "win32") assert.equal(statSync(hostsFile).mode & 0o777, 0o640, "mode kept");
  assert.deepEqual(readdirSync(dir).filter((f) => f.includes("tmp")), [], "no temporary file left");
  rmSync(dir, { recursive: true, force: true });
}

// macOS keeps /etc/hosts as a symlink to /private/etc/hosts: replacing it must change the target and keep the link.
if (process.platform !== "win32") {
  const dir = mkdtempSync(join(scratch, "stack-"));
  const target = join(dir, "real-hosts");
  const link = join(dir, "hosts");
  writeFileSync(target, "127.0.0.1 localhost\n");
  symlinkSync(target, link);
  writeHostsAtomically(link, "127.0.0.1 localhost\n127.0.0.1 pypi.org # x\n");
  assert.ok(lstatSync(link).isSymbolicLink(), "the symlink is still a symlink");
  assert.equal(readFileSync(target, "utf8"), "127.0.0.1 localhost\n127.0.0.1 pypi.org # x\n", "the target was updated");
  rmSync(dir, { recursive: true, force: true });
}

// S5: on Windows the key file's ACL is restricted and, whatever happens, the lack of a check is said.
assert.ok(keyFileWarnings({ platform: "win32", file: "C:/k", restrict: () => ({ status: 0, out: "" }) }).some((w) => /not verified/.test(w) && w.includes("C:/k")));
assert.ok(keyFileWarnings({ platform: "win32", file: "C:/k", restrict: () => ({ status: 5, out: "denied" }) }).some((w) => /could not be restricted/.test(w)));
assert.deepEqual(keyFileWarnings({ platform: "linux", file: "/k", restrict: () => assert.fail("no ACL tool on POSIX") }), []);

// A2: Windows command lines keep an argument with spaces whole and refuse what cmd would expand.
assert.equal(winCommandLine("npm", ["deprecate", "p@1.0.0", "native deprecation"]), 'npm deprecate p@1.0.0 "native deprecation"');
assert.equal(winCommandLine("npm", ["a&b"]), 'npm "a&b"');
for (const bad of ["%PATH%", 'say "hi"', "a\nb"]) assert.throws(() => winCommandLine("npm", [bad]), /unsafe/);
console.log("stack.test: ok");
