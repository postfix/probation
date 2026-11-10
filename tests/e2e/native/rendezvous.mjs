// The handshake between the real-server job and the native jobs (native-clients.yml).
//
// GitHub jobs cannot `needs` a job that is still running, so they meet through the run's artifacts, polled
// with bounded timeouts: the real-server job uploads `native-handshake` as soon as its tunnel works; each
// native job polls for it, talks to the real server, and uploads `native-done-<platform>` when it finishes
// (success or not); the real-server job polls for those, then releases its scenario, which checks that the
// native jobs really talked to it, and tears everything down. Every wait has a deadline.
//
// The logic below takes its clock and the artifact API as parameters, so it is unit-tested with fakes
// (rendezvous.test.mjs). Only a hosted run can show that the artifact API behaves the same mid-run.
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

// Artifact names carry GITHUB_RUN_ATTEMPT: a re-run keeps the run id, so without it the re-run's upload would
// collide with the first attempt's artifact (upload-artifact v4 refuses duplicate names) and its waits would
// read the first attempt's stale handshake or done records.
const attemptOf = (attempt) => {
  if (!/^[1-9][0-9]*$/.test(String(attempt ?? ""))) throw new Error(`bad run attempt ${JSON.stringify(attempt)}`);
  return String(attempt);
};
export const handshakeArtifact = (attempt) => `native-handshake-${attemptOf(attempt)}`;
export const doneArtifact = (label, attempt) => {
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(label)) throw new Error(`bad job label ${JSON.stringify(label)}`);
  return `native-done-${label}-${attemptOf(attempt)}`;
};
/// A pid worth signalling: plain decimal digits only (no sign, exponent, hex, blanks inside), safe integer, above 1:
/// kill(0) and kill(-n) address process groups, kill(1) is init. A trailing newline (`echo $! > file`) is fine.
export const signalablePid = (text) => {
  const digits = String(text).trimEnd();
  if (!/^[1-9][0-9]*$/.test(digits)) return null;
  const pid = Number(digits);
  return Number.isSafeInteger(pid) && pid > 1 ? pid : null;
};

const realClock = { now: () => Date.now(), sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) };

/// The first truthy `check()`, polled every `intervalMs`; throws once `timeoutMs` has passed.
export async function pollUntil({ check, timeoutMs, intervalMs, now = realClock.now, sleep = realClock.sleep, what = "the condition" }) {
  const start = now();
  for (;;) {
    const value = await check();
    if (value) return value;
    if (now() - start >= timeoutMs) throw new Error(`timed out after ${timeoutMs / 1000} s waiting for ${what}`);
    await sleep(intervalMs);
  }
}

const safe = (list) => async () => { try { return await list(); } catch { return null; } }; // a listing error is retried

export async function waitForArtifact({ list, name, timeoutMs, intervalMs, now, sleep }) {
  const listing = safe(list);
  return pollUntil({ check: async () => (await listing())?.find((a) => a.name === name) ?? null, timeoutMs, intervalMs, now, sleep, what: `artifact ${name}` });
}

/// Waits for every name or the deadline; answers the names still missing (never throws, never overshoots).
export async function waitForAll({ list, names, timeoutMs, intervalMs, now = realClock.now, sleep = realClock.sleep }) {
  const listing = safe(list);
  const start = now();
  for (;;) {
    const present = new Set(((await listing()) ?? []).map((a) => a.name));
    const missing = names.filter((n) => !present.has(n));
    if (missing.length === 0 || now() - start >= timeoutMs) return { missing };
    await sleep(intervalMs);
  }
}

export const failedHandshake = (reason) => ({ status: "failed", reason: String(reason) });

/// The handshake is strict because a native job sends its throwaway key to the URL in it.
export function parseHandshake(text) {
  let h;
  try { h = JSON.parse(text); } catch { throw new Error("handshake is not JSON"); }
  if (h?.status === "failed") throw new Error(`handshake: the real server job failed: ${h.reason ?? "no reason given"}`);
  const bad = (what) => { throw new Error(`handshake: ${what}`); };
  if (h?.status !== "ready") bad(`unknown status ${JSON.stringify(h?.status)}`);
  if (typeof h.url !== "string" || !/^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/.test(h.url)) bad("the URL is not a bare https quick-tunnel origin");
  if (typeof h.key !== "string" || !/^prb_[A-Za-z0-9]{32}$/.test(h.key)) bad("the service key is malformed");
  for (const field of ["npmId", "pypiId"]) if (!Number.isSafeInteger(h[field]) || h[field] < 1 || h[field] > 2 ** 31) bad(`${field} is not a registry id`);
  if (!Number.isInteger(h.npmPort) || h.npmPort < 1024 || h.npmPort > 65535) bad("npmPort is not a high port");
  if (typeof h.hiddenName !== "string" || !/^token-private-[a-z0-9-]+$/.test(h.hiddenName)) bad("hiddenName is malformed");
  return { status: h.status, url: h.url, key: h.key, npmId: h.npmId, pypiId: h.pypiId, npmPort: h.npmPort, hiddenName: h.hiddenName };
}

/// Printed before anything else so the runner hides them in every later log line.
export const maskLines = (h) => [`::add-mask::${h.url}`, `::add-mask::${new URL(h.url).host}`, `::add-mask::${h.key}`];

export const envLines = (h, keyFile) => [
  `NATIVE_POLICY_URL=${h.url}`, `NATIVE_SERVICE_KEY_FILE=${keyFile}`, `NATIVE_NPM_REGISTRY_ID=${h.npmId}`, `NATIVE_PYPI_REGISTRY_ID=${h.pypiId}`,
  `NATIVE_NPM_PORT=${h.npmPort}`, `NATIVE_HIDDEN_NAME=${h.hiddenName}`, "NATIVE_POLICY_PUBLIC_TRUST=1",
];

// ---- command line (workflow steps) ----
function gh(args) {
  const r = spawnSync("gh", args, { encoding: "utf8", env: process.env, timeout: 120_000 });
  if (r.status !== 0) throw new Error(`gh ${args.slice(0, 2).join(" ")} failed: ${(r.stderr || r.error?.message || "").trim().slice(0, 200)}`);
  return r.stdout;
}
const artifactsOf = (repo, run) => () => JSON.parse(`[${gh(["api", `repos/${repo}/actions/runs/${run}/artifacts?per_page=100`, "--jq", ".artifacts[] | {name, id}"]).trim().split("\n").filter(Boolean).join(",")}]`);
const flag = (name, fallback) => { const i = process.argv.indexOf(`--${name}`); return i < 0 ? fallback : process.argv[i + 1]; };
const attempt = () => attemptOf(flag("attempt"));
const minutes = (name, fallback) => Number(flag(name, fallback)) * 60_000;
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

async function main(command) {
  if (command === "client-wait") {
    const [repo, run, out] = [flag("repo"), flag("run-id"), flag("out")];
    await waitForArtifact({ list: artifactsOf(repo, run), name: handshakeArtifact(attempt()), timeoutMs: minutes("timeout-min", 50), intervalMs: 15_000 });
    mkdirSync(out, { recursive: true });
    gh(["run", "download", run, "--repo", repo, "--name", handshakeArtifact(attempt()), "--dir", out]);
    const handshake = parseHandshake(readFileSync(join(out, "handshake.json"), "utf8"));
    console.log(maskLines(handshake).join("\n"));
    const keyFile = join(out, "service.key");
    writeFileSync(keyFile, `${handshake.key}\n`, { mode: 0o600 });
    writeFileSync(join(out, "handshake.json"), "{}\n"); // the copy with the key is not kept
    if (process.env.GITHUB_ENV) appendFileSync(process.env.GITHUB_ENV, `${envLines(handshake, keyFile).join("\n")}\n`);
    console.log("handshake received; the real server's tunnel and registries are known");
  } else if (command === "client-probe") {
    const [url, keyFile, label] = [process.env.NATIVE_POLICY_URL, process.env.NATIVE_SERVICE_KEY_FILE, flag("label")];
    const key = readFileSync(keyFile, "utf8").trim();
    // every request is bounded (a tunnel that accepts and never answers must not hang the step past the poll's deadline)
    const requestMs = Number(flag("request-sec", 10)) * 1000;
    const probe = () => new Promise((resolve) => {
      const req = https.get(`${url}/api/v1/policy/snapshot`, { headers: { authorization: `Bearer ${key}`, "x-native-job": label }, timeout: requestMs }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on("timeout", () => { req.destroy(); resolve(0); });
      req.on("error", () => resolve(0));
    });
    await pollUntil({ check: async () => (await probe()) === 200, timeoutMs: minutes("timeout-min", 2), intervalMs: 5_000, what: "the tunnel to answer the snapshot probe" });
    console.log(`probe as ${label}: the snapshot endpoint answered 200 through the tunnel`);
  } else if (command === "done") {
    const out = flag("out");
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "done.json"), `${JSON.stringify({ label: flag("label"), status: flag("status"), at: new Date().toISOString() })}\n`);
  } else if (command === "server-wait-ready") {
    const dir = flag("dir");
    const file = join(dir, "handshake.json");
    const pidFile = join(dir, "harness.pid");
    try {
      await pollUntil({
        check: async () => existsSync(file) || (existsSync(pidFile) && !alive(Number(readFileSync(pidFile, "utf8"))) ? (() => { throw new Error("the stack process ended before the tunnel was up"); })() : false),
        timeoutMs: minutes("timeout-min", 30), intervalMs: 3_000, what: "the real stack and its tunnel",
      });
      const handshake = parseHandshake(readFileSync(file, "utf8"));
      console.log(maskLines(handshake).join("\n"));
      console.log("handshake ready");
    } catch (error) {
      writeFileSync(file, `${JSON.stringify(failedHandshake(error.message))}\n`);
      console.error(`no handshake: ${error.message}`);
      process.exitCode = 1;
    }
  } else if (command === "server-ensure-handshake") {
    // If the stack never got as far as writing one (an early step failed), publish a failed one so the native jobs fail fast.
    const file = join(flag("dir"), "handshake.json");
    if (!existsSync(file)) {
      mkdirSync(flag("dir"), { recursive: true });
      writeFileSync(file, `${JSON.stringify(failedHandshake("the real-server job failed before the stack was up"))}\n`);
      console.log("wrote a failed handshake");
    }
  } else if (command === "server-wait-done") {
    const dir = flag("dir");
    if (existsSync(join(dir, "handshake.json")) && JSON.parse(readFileSync(join(dir, "handshake.json"), "utf8")).status !== "ready") { console.log("no handshake was published: nothing to wait for"); return; }
    const names = flag("expect").split(",").map((label) => doneArtifact(label, attempt()));
    const { missing } = await waitForAll({ list: artifactsOf(flag("repo"), flag("run-id")), names, timeoutMs: minutes("timeout-min", 50), intervalMs: 15_000 });
    console.log(missing.length ? `deadline reached; still missing: ${missing.join(", ")}` : "every native job reported");
  } else if (command === "server-release") {
    const dir = flag("dir");
    writeFileSync(join(dir, "release"), "release\n");
    const result = join(dir, "result.json");
    try {
      await pollUntil({ check: async () => existsSync(result), timeoutMs: minutes("timeout-min", 10), intervalMs: 3_000, what: "the scenario's result" });
    } catch (error) { console.error(error.message); process.exitCode = 1; }
    if (existsSync(join(dir, "harness.log"))) console.log(readFileSync(join(dir, "harness.log"), "utf8").split("\n").slice(-40).join("\n"));
    if (existsSync(result)) {
      const outcome = JSON.parse(readFileSync(result, "utf8"));
      console.log(`scenario result: ${JSON.stringify(outcome)}`);
      if (!outcome.ok) process.exitCode = 1;
    } else process.exitCode = 1;
  } else if (command === "server-teardown") {
    const dir = flag("dir");
    for (const name of ["harness.pid", "cloudflared.pid"]) {
      const file = join(dir, name);
      if (!existsSync(file)) continue;
      const pid = signalablePid(readFileSync(file, "utf8"));
      if (pid && alive(pid)) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } await realClock.sleep(3000); if (alive(pid)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } } }
    }
    console.log("torn down");
  } else {
    console.error(`unknown command ${command}`);
    process.exitCode = 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv[2]).catch((error) => { console.error(error.message); process.exit(1); });
}
