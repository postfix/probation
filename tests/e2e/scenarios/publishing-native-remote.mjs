import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { spawn } from "node:child_process";
import http from "node:http";
import https from "node:https";
import { join } from "node:path";
import { remoteSnapshotFindings } from "../native/assertions.mjs";
import { setupRealCatalog } from "../native/portal-setup.mjs";
import { SNAPSHOT_PATH, startSnapshotProxy } from "../native/snapshot-proxy.mjs";

// The real Linux policy server for the macOS, Windows and Linux native jobs (native-clients.yml). This scenario runs in
// the real-server job: it makes the throwaway catalog and key through the portal, exposes ONLY the policy snapshot
// (a filtering proxy, GET + the throwaway key) through a cloudflared quick tunnel, publishes the handshake file for the
// workflow to upload, then holds the stack up until the workflow writes `release` (the native jobs are done) or the hard
// deadline passes. It then checks that each native job really reached this server through the tunnel with the key, and
// writes result.json for the workflow to read. Run only by name (no suite).
//   E2E_REMOTE_DIR (required)  directory for handshake.json, release, result.json, cloudflared.pid
//   CLOUDFLARED                the verified cloudflared binary (cloudflared.mjs)
//   NATIVE_REMOTE_EXPECT       job labels that must have reached the server (default linux-x64,darwin-arm64,win32-x64)
//   NATIVE_REMOTE_DEADLINE_S   hard deadline for the whole wait (default 3600)
//   E2E_TUNNEL=stub            test seam: no tunnel, the proxy's own http address is the "tunnel" (local checks only)
export const meta = { id: "E2E-publishing-native-remote", title: "real policy server behind a quick tunnel for the native jobs", suites: [], stack: "own" };

const NPM_PORT = 43111;

function openTunnel(proxyPort, dir) {
  if (process.env.E2E_TUNNEL === "stub") return Promise.resolve({ url: `http://127.0.0.1:${proxyPort}`, stop() {} });
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.CLOUDFLARED, ["tunnel", "--no-autoupdate", "--protocol", "http2", "--url", `http://127.0.0.1:${proxyPort}`], { stdio: ["ignore", "pipe", "pipe"] });
    writeFileSync(join(dir, "cloudflared.pid"), `${child.pid}\n`);
    const timer = setTimeout(() => { child.kill(); reject(new Error("cloudflared printed no tunnel address in 90 s")); }, 90_000);
    const seen = (chunk) => {
      const found = chunk.toString().match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
      if (found) { clearTimeout(timer); resolve({ url: found[0], stop: () => child.kill() }); }
    };
    child.stdout.on("data", seen);
    child.stderr.on("data", seen);
    child.on("exit", (code) => { clearTimeout(timer); reject(new Error(`cloudflared exited ${code} before the tunnel was up`)); });
  });
}

const probe = (url, key, label) => new Promise((resolve) => {
  const lib = url.startsWith("https:") ? https : http;
  lib.get(`${url}${SNAPSHOT_PATH}`, { headers: { authorization: `Bearer ${key}`, "x-native-job": label } }, (res) => { res.resume(); resolve(res.statusCode); }).on("error", () => resolve(0));
});

export default async function nativeRemote(h) {
  const dir = process.env.E2E_REMOTE_DIR;
  h.expect(dir, "E2E_REMOTE_DIR names the handshake directory");
  mkdirSync(dir, { recursive: true });
  const labels = (process.env.NATIVE_REMOTE_EXPECT ?? "linux-x64,darwin-arm64,win32-x64").split(",");
  const deadline = Date.now() + Number(process.env.NATIVE_REMOTE_DEADLINE_S ?? 3600) * 1000;
  const result = (ok, message) => writeFileSync(join(dir, "result.json"), `${JSON.stringify({ ok, message })}\n`);
  let proxy, tunnel;
  try {
    const catalog = await setupRealCatalog(h, { npmPort: NPM_PORT, keyName: "native-remote-service" });
    proxy = await startSnapshotProxy({
      key: catalog.key,
      forward: async (authorization) => {
        const answer = await h.request("https://sync.e2e.test/api/v1/policy/snapshot", { headers: { authorization } });
        return { status: answer.status, contentType: answer.headers["content-type"], body: answer.bytes };
      },
    });
    tunnel = await openTunnel(proxy.port, dir);
    await h.waitFor("the tunnel answers the snapshot probe with the key", async () => (await probe(tunnel.url, catalog.key, "linux-server")) === 200, { timeout: 120_000, every: 3_000 });
    writeFileSync(join(dir, "handshake.json"), `${JSON.stringify({ status: "ready", url: tunnel.url, key: catalog.key, npmId: catalog.npmId, pypiId: catalog.pypiId, npmPort: NPM_PORT, hiddenName: catalog.hiddenName })}\n`, { mode: 0o600 });
    h.log("handshake written; waiting for the native jobs to finish");
    while (!existsSync(join(dir, "release")) && Date.now() < deadline) await h.sleep(2_000);
    const released = existsSync(join(dir, "release"));
    const findings = remoteSnapshotFindings({ entries: proxy.log, labels });
    const refused = proxy.log.filter((e) => e.status === 404 || e.status === 401).length;
    h.log(`snapshot requests seen: ${proxy.log.length} (${refused} refused); released=${released}`);
    h.expect(released, "the workflow released the scenario before the hard deadline");
    h.expect(findings.length === 0, `every native job reached the real server through the tunnel with the throwaway key: ${findings.join("; ")}`);
    result(true, `${labels.length} native jobs reached the real server; ${proxy.log.length} snapshot requests`);
  } catch (error) {
    result(false, error.message);
    throw error;
  } finally {
    tunnel?.stop();
    await proxy?.close();
  }
}
