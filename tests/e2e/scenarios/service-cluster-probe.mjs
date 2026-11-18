import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { join } from "node:path";
import { startCommonService } from "../harness/service-setup.mjs";

// Slice 29 risk spike (C1023): does containerd route an image pull for the ORIGINAL registry (docker.io) to the shared
// service when hosts.toml names the service as `server`, and does it stay there when the service refuses or is down?
// The runtime is the pinned containerd (03-program-design.md) started unprivileged with its own root/state/socket under
// the e2e work directory (disk), content-store only: `ctr content fetch` resolves and pulls without a snapshotter.
// Every connection the runtime makes goes through a recording CONNECT proxy that reaches the stack only for the
// service's own name; any other destination is refused and counted as a direct-origin attempt (fallback).
// The service has no OCI route before row 24, so a 404 from the service is the expected, recorded answer here.
// Every expectation that holds only before row 24 carries a ROW24-FLIP tag (grep it); row 24 removes or flips each one.
export const meta = {
  id: "E2E-service-cluster-probe",
  title: "containerd explicit-server routing probe against the shared service",
  suites: [],
  stack: "own",
};

const SERVICE_HOST = "fw-standalone.e2e.test";
const IMAGE = "docker.io/library/alpine:latest";

// ctr must not block this process (spawnSync would freeze the proxy that serves it).
function ctr(args, env, timeout = 120_000) {
  return new Promise((resolve) => {
    const child = spawn("ctr", args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    let killed = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, timeout);
    child.on("close", (status) => { clearTimeout(timer); resolve({ status: status ?? 1, stdout, stderr, killed }); });
  });
}

function recordingProxy(bridgePort) {
  const connects = [];
  const server = http.createServer((_, res) => res.writeHead(405).end());
  server.on("connect", (req, client, head) => {
    const target = req.url;
    connects.push(target);
    if (!target.startsWith(`${SERVICE_HOST}:`)) { client.end("HTTP/1.1 403 Forbidden\r\n\r\n"); return; }
    const bridge = net.connect(bridgePort, "127.0.0.1", () => bridge.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let answered = false;
    bridge.on("data", (chunk) => {
      if (answered) return client.write(chunk);
      answered = true;
      const at = chunk.indexOf("\r\n\r\n");
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (at + 4 < chunk.length) client.write(chunk.subarray(at + 4));
      if (head.length) bridge.write(head);
      client.on("data", (d) => bridge.write(d));
    });
    bridge.on("error", () => client.destroy());
    client.on("error", () => bridge.destroy());
    bridge.on("close", () => client.destroy());
    client.on("close", () => bridge.destroy());
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ connects, port: server.address().port, close: () => server.close() })));
}

export default async function clusterProbe(h) {
  for (const tool of ["containerd", "ctr"]) {
    h.expect(spawnSync(tool, ["--version"], { encoding: "utf8" }).status === 0, `${tool} is installed (a missing runtime fails the probe, it never skips)`);
  }
  const version = spawnSync("containerd", ["--version"], { encoding: "utf8" }).stdout;
  h.expect(version.includes("1c4457e00facac03ce1d75f7b6777a7a851e5c41"), `containerd is the pinned 2.2.0 commit: ${version.trim()}`);
  await startCommonService(h);

  const dir = join(h.stack.work, "containerd-probe");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(join(dir, "hosts", "_default"), { recursive: true });
  mkdirSync(join(dir, "hosts-none", "_default"), { recursive: true });
  const sock = join(dir, "c.sock");
  const ca = join(h.stack.work, "ca", "ca.pem");
  writeFileSync(join(dir, "config.toml"), `version = 3
root = "${dir}/root"
state = "${dir}/state"
disabled_plugins = ["io.containerd.cri.v1.runtime", "io.containerd.cri.v1.images", "io.containerd.snapshotter.v1.overlayfs", "io.containerd.snapshotter.v1.blockfile", "io.containerd.snapshotter.v1.erofs", "io.containerd.nri.v1.nri"]
[grpc]
  address = "${sock}"
  uid = ${process.getuid()}
  gid = ${process.getgid()}
[ttrpc]
  address = "${sock}.ttrpc"
  uid = ${process.getuid()}
  gid = ${process.getgid()}
`);
  // C1023's candidate: the service is the `server`, capabilities pull+resolve, the e2e CA trusted.
  writeFileSync(join(dir, "hosts", "_default", "hosts.toml"), `server = "https://${SERVICE_HOST}"\ncapabilities = ["pull", "resolve"]\nca = "${ca}"\n`);
  // Control: the same runtime without a `server` goes to the origin, which proves the recorder would see a fallback.
  writeFileSync(join(dir, "hosts-none", "_default", "hosts.toml"), `capabilities = ["pull", "resolve"]\nca = "${ca}"\n`);

  const proxy = await recordingProxy(h.stack.bridgePort);
  const daemon = spawn("containerd", ["-c", join(dir, "config.toml")], { stdio: ["ignore", "ignore", "pipe"] });
  let daemonLog = "";
  daemon.stderr.on("data", (d) => { daemonLog += d; });
  try {
    await h.waitFor("containerd serves", async () => spawnSync("ctr", ["-a", sock, "version"], { encoding: "utf8" }).status === 0, { timeout: 30_000 });
    const env = { ...process.env, HTTPS_PROXY: `http://127.0.0.1:${proxy.port}`, https_proxy: `http://127.0.0.1:${proxy.port}`, HTTP_PROXY: "", http_proxy: "", NO_PROXY: "", no_proxy: "" };
    const fetch = (hosts, timeout) => ctr(["--debug", "-a", sock, "content", "fetch", "--hosts-dir", join(dir, hosts), IMAGE], env, timeout);
    const hosts = (list) => [...new Set(list.map((t) => t.split(":")[0]))].sort();

    // The service's own request log: count of HEAD requests it decided as 404 (its log carries no path).
    const decidedHeads = () => {
      const logs = spawnSync(h.stack.engine, ["logs", h.stack.container("firewall-standalone")], { encoding: "utf8" });
      return `${logs.stdout}${logs.stderr}`.split("\n").filter((l) => l.includes('"method":"\\"HEAD\\""') && l.includes('"status":404')).length;
    };
    const headsBefore = decidedHeads();

    // 1. Routed: the pull for docker.io names the service and only the service.
    let r = await fetch("hosts");
    h.log(`routed pull: exit ${r.status}\n${r.stderr}`);
    h.expect(r.status !== 0, "row 28 has no OCI route, so the pull is refused there"); // ROW24-FLIP: row 24 serves OCI, the pull succeeds
    h.expect(r.stderr.includes(SERVICE_HOST), "the runtime talked to the service named by hosts.toml");
    h.expect(JSON.stringify(hosts(proxy.connects)) === JSON.stringify([SERVICE_HOST]), `only the service was contacted: ${hosts(proxy.connects)}`);

    // 2. The service decided exactly one HEAD for it (its request log carries no path: a 404, route unknown). The request's
    // own shape comes from the runtime's debug log: original repository path, original registry kept as ns=docker.io.
    const decided = decidedHeads() - headsBefore;
    h.log(`service decided HEAD 404 during the pull: ${decided}`);
    h.expect(decided === 1, `the service decided exactly the runtime's one HEAD (404 NOT_FOUND, no OCI route): ${decided}`); // ROW24-FLIP: row 24 answers it
    h.expect(/\/v2\/library\/alpine\/manifests\/latest\?ns=docker\.io/.test(r.stderr), "the runtime's request is /v2/library/alpine/manifests/latest?ns=docker.io");

    // 3. Service down: the origin is healthy and reachable, yet the runtime does not go there.
    const before = proxy.connects.length;
    h.stack.compose(["pause", "firewall-standalone"]);
    try {
      r = await fetch("hosts", 40_000);
      h.log(`pull with the service paused: exit ${r.status}\n${r.stderr.slice(-600)}`);
      h.expect(r.status !== 0 && !r.killed, "the pull fails while the service is down, by itself and not by the probe's timer");
      h.expect(proxy.connects.length > before, "the runtime did try to reach the service (the check below observed something)");
      h.expect(new RegExp(`${SERVICE_HOST.replaceAll(".", "\\.")}.*(handshake|timeout|EOF|refused|reset)`, "i").test(r.stderr), `the failure names the service connection: ${r.stderr.slice(-300)}`);
      h.expect(proxy.connects.slice(before).every((t) => t.startsWith(`${SERVICE_HOST}:`)), `no direct-origin attempt with the service down: ${proxy.connects.slice(before)}`);
    } finally {
      h.stack.compose(["unpause", "firewall-standalone"]);
    }

    // 4. Control: without `server` the runtime goes to the origin, and the recorder sees it.
    const mark = proxy.connects.length;
    r = await fetch("hosts-none");
    const direct = proxy.connects.slice(mark).filter((t) => !t.startsWith(`${SERVICE_HOST}:`));
    h.log(`control (no server) contacted: ${direct}`);
    h.expect(direct.some((t) => /docker\.io|docker\.com/.test(t)), "the control run attempts the origin (registry-1.docker.io), so the recorder detects fallback");
  } finally {
    daemon.kill("SIGTERM");
    proxy.close();
    await new Promise((resolve) => (daemon.exitCode === null ? daemon.once("exit", resolve) : resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}
