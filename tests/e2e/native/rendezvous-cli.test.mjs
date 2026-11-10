// The workflow-step commands of rendezvous.mjs against a fake `gh` (POSIX shell): the handshake download, the masks that
// come before everything, the refusal of a hostile handshake, the waits and the release. Windows runs the same commands
// against the real gh in the hosted run.
// NATIVE_TEST_SCRATCH=<disk dir> node tests/e2e/native/rendezvous-cli.test.mjs
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("./rendezvous.mjs", import.meta.url));
const scratch = process.env.NATIVE_TEST_SCRATCH;
assert(scratch, "set NATIVE_TEST_SCRATCH");
const key = "prb_" + "f".repeat(32);
const ready = { status: "ready", url: "https://calm-lake-42.trycloudflare.com", key, npmId: 4, pypiId: 5, npmPort: 43111, hiddenName: "token-private-0a1b2c3d" };

/// A fake gh: `gh api …/artifacts` lists $ARTIFACTS (comma separated names), `gh run download … --dir D` copies $HANDSHAKE_FILE.
function setup(artifacts, handshake) {
  const root = mkdtempSync(join(scratch, "cli-"));
  const bin = join(root, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "gh"), `#!/bin/sh
case "$1" in
  api) for n in $(echo "$ARTIFACTS" | tr ',' ' '); do echo "{\\"name\\":\\"$n\\",\\"id\\":1}"; done ;;
  run) dir=""; while [ $# -gt 0 ]; do [ "$1" = "--dir" ] && dir="$2"; shift; done; mkdir -p "$dir"; cp "$HANDSHAKE_FILE" "$dir/handshake.json" ;;
esac
`);
  chmodSync(join(bin, "gh"), 0o755);
  const file = join(root, "fixture.json");
  writeFileSync(file, typeof handshake === "string" ? handshake : `${JSON.stringify(handshake)}\n`);
  const env = { PATH: `${bin}:${process.env.PATH}`, ARTIFACTS: artifacts.join(","), HANDSHAKE_FILE: file, GITHUB_ENV: join(root, "env") };
  writeFileSync(env.GITHUB_ENV, "");
  return { root, env };
}
const run = (args, env) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", env, timeout: 60_000 });

// client-wait: downloads the handshake, prints the masks FIRST, keeps the key in a private file, not in the environment.
{
  const { root, env } = setup(["other", "native-handshake-2"], ready);
  const out = join(root, "hs");
  const r = run(["client-wait", "--repo", "o/r", "--run-id", "7", "--attempt", "2", "--out", out, "--timeout-min", "1"], env);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const lines = r.stdout.split("\n");
  assert.deepEqual(lines.slice(0, 3), [`::add-mask::${ready.url}`, "::add-mask::calm-lake-42.trycloudflare.com", `::add-mask::${key}`], "masks are the first output");
  assert.ok(!lines.slice(3).join("\n").includes(key) && !r.stderr.includes(key), "nothing else prints the key");
  assert.equal(readFileSync(join(out, "service.key"), "utf8"), `${key}\n`);
  assert.equal(statSync(join(out, "service.key")).mode & 0o777, 0o600);
  assert.equal(readFileSync(join(out, "handshake.json"), "utf8").trim(), "{}", "the downloaded copy with the key is overwritten");
  const github = readFileSync(env.GITHUB_ENV, "utf8");
  assert.ok(github.includes(`NATIVE_POLICY_URL=${ready.url}`) && github.includes("NATIVE_HIDDEN_NAME=token-private-0a1b2c3d") && github.includes("NATIVE_POLICY_PUBLIC_TRUST=1"));
  assert.ok(!github.includes(key), "the key never goes into GITHUB_ENV");
  rmSync(root, { recursive: true, force: true });
}
// A hostile or failed handshake: no key file, no environment, a non-zero exit.
for (const [what, handshake, pattern] of [["another host", { ...ready, url: "https://evil.example" }, /handshake/], ["a failed server job", { status: "failed", reason: "tunnel did not come up" }, /server job failed: tunnel did not come up/], ["not JSON", "<html>", /handshake/]]) {
  const { root, env } = setup(["native-handshake-2"], handshake);
  const out = join(root, "hs");
  const r = run(["client-wait", "--repo", "o/r", "--run-id", "7", "--attempt", "2", "--out", out, "--timeout-min", "1"], env);
  assert.notEqual(r.status, 0, what);
  assert.match(r.stderr, pattern, what);
  assert.ok(!existsSync(join(out, "service.key")), `${what}: no key file`);
  assert.equal(readFileSync(env.GITHUB_ENV, "utf8"), "", `${what}: no environment written`);
  assert.ok(!r.stdout.includes(key), `${what}: key not printed`);
  rmSync(root, { recursive: true, force: true });
}
// server-wait-ready: prints the masks when the scenario has written a good handshake; a dead stack process or a timeout gives a failed handshake and exit 1.
{
  const { root, env } = setup([], ready);
  const dir = join(root, "remote");
  mkdirSync(dir);
  writeFileSync(join(dir, "handshake.json"), `${JSON.stringify(ready)}\n`);
  let r = run(["server-wait-ready", "--dir", dir, "--timeout-min", "1"], env);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.split("\n")[0], `::add-mask::${ready.url}`);
  const dead = spawnSync("true");
  const dir2 = join(root, "remote2");
  mkdirSync(dir2);
  writeFileSync(join(dir2, "harness.pid"), "999999\n");
  r = run(["server-wait-ready", "--dir", dir2, "--timeout-min", "1"], env);
  assert.equal(r.status, 1);
  assert.match(readFileSync(join(dir2, "handshake.json"), "utf8"), /"status":"failed".*ended before the tunnel was up/);
  rmSync(root, { recursive: true, force: true });
  void dead;
}
// server-wait-done: nothing to wait for after a failed handshake; otherwise it ends when every job has reported.
{
  const { root, env } = setup(["native-done-linux-x64-2", "native-done-darwin-arm64-2", "native-done-win32-x64-2"], ready);
  const dir = join(root, "remote");
  mkdirSync(dir);
  writeFileSync(join(dir, "handshake.json"), `${JSON.stringify(ready)}\n`);
  let r = run(["server-wait-done", "--dir", dir, "--expect", "linux-x64,darwin-arm64,win32-x64", "--repo", "o/r", "--run-id", "7", "--attempt", "2", "--timeout-min", "1"], env);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /every native job reported/);
  // a previous attempt's done artifacts do not count for attempt 3
  r = run(["server-wait-done", "--dir", dir, "--expect", "linux-x64,darwin-arm64,win32-x64", "--repo", "o/r", "--run-id", "7", "--attempt", "3", "--timeout-min", "0.001"], env);
  assert.match(r.stdout, /still missing: native-done-linux-x64-3, native-done-darwin-arm64-3, native-done-win32-x64-3/, r.stdout);
  writeFileSync(join(dir, "handshake.json"), '{"status":"failed","reason":"x"}\n');
  r = run(["server-wait-done", "--dir", dir, "--expect", "linux-x64", "--repo", "o/r", "--run-id", "7", "--attempt", "2", "--timeout-min", "1"], { ...env, ARTIFACTS: "" });
  assert.match(r.stdout, /nothing to wait for/);
  rmSync(root, { recursive: true, force: true });
}
// server-release: writes the release flag, then passes or fails with the scenario's own result.
for (const [ok, status] of [[true, 0], [false, 1]]) {
  const { root, env } = setup([], ready);
  const dir = join(root, "remote");
  mkdirSync(dir);
  writeFileSync(join(dir, "result.json"), `${JSON.stringify({ ok, message: "m" })}\n`);
  const r = run(["server-release", "--dir", dir, "--timeout-min", "1"], env);
  assert.equal(r.status, status, `ok=${ok}: ${r.stdout}${r.stderr}`);
  assert.ok(existsSync(join(dir, "release")), "the release flag is written");
  rmSync(root, { recursive: true, force: true });
}
// server-ensure-handshake: a stack that never wrote one gets a failed handshake (so the native jobs fail fast); an existing one is kept.
{
  const { root, env } = setup([], ready);
  const dir = join(root, "remote");
  let r = run(["server-ensure-handshake", "--dir", dir], env);
  assert.equal(r.status, 0);
  assert.match(readFileSync(join(dir, "handshake.json"), "utf8"), /"status":"failed".*before the stack was up/);
  writeFileSync(join(dir, "handshake.json"), `${JSON.stringify(ready)}\n`);
  r = run(["server-ensure-handshake", "--dir", dir], env);
  assert.equal(JSON.parse(readFileSync(join(dir, "handshake.json"), "utf8")).status, "ready", "an existing handshake is not replaced");
  rmSync(root, { recursive: true, force: true });
}
// done: the completion record that is uploaded as native-done-<label>.
{
  const { root, env } = setup([], ready);
  const r = run(["done", "--label", "win32-x64", "--status", "failure", "--out", join(root, "d")], env);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(readFileSync(join(root, "d", "done.json"), "utf8")).status, "failure");
  rmSync(root, { recursive: true, force: true });
}
// client-wait: another attempt's handshake is not accepted (attempt 3 finds only native-handshake-2).
{
  const { root, env } = setup(["native-handshake-2"], ready);
  const r = run(["client-wait", "--repo", "o/r", "--run-id", "7", "--attempt", "3", "--out", join(root, "hs"), "--timeout-min", "0.001"], env);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /native-handshake-3/);
  assert.ok(!existsSync(join(root, "hs", "service.key")));
  rmSync(root, { recursive: true, force: true });
}
// client-wait/server-wait-done without --attempt refuse to guess.
{
  const { root, env } = setup(["native-handshake-2"], ready);
  const r = run(["client-wait", "--repo", "o/r", "--run-id", "7", "--out", join(root, "hs"), "--timeout-min", "0.001"], env);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /attempt/);
  rmSync(root, { recursive: true, force: true });
}
// client-probe against a TLS server that never answers: bounded by --timeout-min plus one request timeout, exits non-zero.
{
  const server = net.createServer(() => {}); // accepts the TCP connection, never answers the TLS hello
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { root, env } = setup([], ready);
  writeFileSync(join(root, "k"), `${key}\n`);
  const child = spawn(process.execPath, [cli, "client-probe", "--label", "linux-x64", "--timeout-min", "0.02", "--request-sec", "1"], { env: { ...env, NATIVE_POLICY_URL: `https://127.0.0.1:${server.address().port}`, NATIVE_SERVICE_KEY_FILE: join(root, "k") } });
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += d; });
  const started = Date.now();
  const code = await new Promise((resolve) => { const t = setTimeout(() => { child.kill("SIGKILL"); resolve("hung"); }, 20_000); child.on("close", (c) => { clearTimeout(t); resolve(c); }); });
  server.close();
  assert.equal(code, 1, `the probe must give up, got ${code}: ${stderr}`);
  assert.ok(Date.now() - started < 10_000, "and promptly");
  assert.match(stderr, /timed out/);
  rmSync(root, { recursive: true, force: true });
}
// server-teardown never signals pid 0 / negative / garbage (kill(0) would signal its own process group): run in its own group.
for (const content of ["", "0\n", "-3\n", "abc\n", "1.5\n"]) {
  const { root, env } = setup([], ready);
  const dir = join(root, "remote");
  mkdirSync(dir);
  writeFileSync(join(dir, "harness.pid"), content);
  const child = spawn(process.execPath, [cli, "server-teardown", "--dir", dir], { env, detached: true });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  const [code, signal] = await new Promise((resolve) => child.on("close", (c, sg) => resolve([c, sg])));
  assert.equal(signal, null, `pid file ${JSON.stringify(content)} made teardown signal its own group`);
  assert.equal(code, 0);
  assert.match(out, /torn down/);
  rmSync(root, { recursive: true, force: true });
}
console.log("rendezvous-cli.test: ok");
