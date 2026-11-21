import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { join } from "node:path";

// The pinned containerd as one "node" of the e2e stack, shared by E2E-service-cluster-probe and E2E-service-cluster: started
// unprivileged with its own root, state and socket under a directory on disk (content store only: `ctr content fetch` resolves and pulls
// without a snapshotter or root), and every connection it makes goes through a recording CONNECT proxy that reaches the stack only for
// the service's own name. Any other destination is refused and counted: that is a direct-origin attempt, i.e. a fallback.

/// ctr must not block the process: a synchronous spawn would freeze the in-process proxy that serves it.
export function ctr(args, env, timeout = 120_000, command = "ctr") {
  return new Promise((resolve) => {
    const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    let killed = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, timeout);
    child.on("close", (status) => { clearTimeout(timer); resolve({ status: status ?? 1, stdout, stderr, killed }); });
  });
}

export function recordingProxy(bridgePort, serviceHost) {
  const connects = [];
  const server = http.createServer((_, res) => res.writeHead(405).end());
  server.on("connect", (req, client, head) => {
    const target = req.url;
    connects.push(target);
    if (!target.startsWith(`${serviceHost}:`)) { client.end("HTTP/1.1 403 Forbidden\r\n\r\n"); return; }
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

export function checkPinned(h) {
  for (const tool of ["containerd", "ctr"]) {
    h.expect(spawnSync(tool, ["--version"], { encoding: "utf8" }).status === 0, `${tool} is installed (a missing runtime fails the run, it never skips)`);
  }
  const version = spawnSync("containerd", ["--version"], { encoding: "utf8" }).stdout;
  h.expect(version.includes("1c4457e00facac03ce1d75f7b6777a7a851e5c41"), `containerd is the pinned 2.2.0 commit: ${version.trim()}`);
}

export function hostNames(connects) {
  return [...new Set(connects.map((t) => t.split(":")[0]))].sort();
}

/// Starts the daemon in `dir` (a fresh directory). Returns { sock, env, proxy, fetch(hostsDir, ref, timeout), stop() }.
/// `cri: true` enables the CRI plugin's IMAGE service (native snapshotter, unprivileged: crictl pull/images work; no pod runtime is used) and
/// leaves `config_path` to the installer's drop-in; `beforeStart(configFile)` runs after the main config exists and before the daemon starts
/// (the installer adds its `imports` line there); `daemonEnv` is added to the daemon's own environment (what the systemd drop-in gives it).
export async function startNode(h, dir, serviceHost, { cri = false, beforeStart, daemonEnv = {} } = {}) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  // Unix socket paths are limited to 107 bytes and containerd names the ttrpc one too: keep both short (an e2e work directory in a deep checkout is already long).
  const sock = join(dir, "c");
  const plugins = cri
    ? `disabled_plugins = ["io.containerd.snapshotter.v1.overlayfs", "io.containerd.snapshotter.v1.blockfile", "io.containerd.snapshotter.v1.erofs", "io.containerd.nri.v1.nri"]`
    : `disabled_plugins = ["io.containerd.cri.v1.runtime", "io.containerd.cri.v1.images", "io.containerd.snapshotter.v1.overlayfs", "io.containerd.snapshotter.v1.blockfile", "io.containerd.snapshotter.v1.erofs", "io.containerd.nri.v1.nri"]`;
  const criConfig = cri ? `
[plugins."io.containerd.cri.v1.images"]
  snapshotter = "native"
  [plugins."io.containerd.cri.v1.images".pinned_images]
    sandbox = "registry.invalid/pause:1"
[plugins."io.containerd.cri.v1.runtime".cni]
  conf_dir = "${dir}/cni"
[plugins."io.containerd.transfer.v1.local"]
  [[plugins."io.containerd.transfer.v1.local".unpack_config]]
    platform = "linux/amd64"
    snapshotter = "native"
    differ = ""
` : "";
  writeFileSync(join(dir, "config.toml"), `version = 3
root = "${dir}/root"
state = "${dir}/state"
${plugins}
[grpc]
  address = "${sock}"
  uid = ${cri ? 0 : process.getuid()}
  gid = ${cri ? 0 : process.getgid()}
[ttrpc]
  address = "${sock}t"
  uid = ${cri ? 0 : process.getuid()}
  gid = ${cri ? 0 : process.getgid()}
${criConfig}`);
  if (beforeStart) await beforeStart(join(dir, "config.toml"));
  const proxy = await recordingProxy(h.stack.bridgePort, serviceHost);
  const proxyEnv = { HTTPS_PROXY: `http://127.0.0.1:${proxy.port}`, https_proxy: `http://127.0.0.1:${proxy.port}`, HTTP_PROXY: "", http_proxy: "", NO_PROXY: "", no_proxy: "" };
  // The CRI image service unpacks layers with bind mounts of the native snapshotter: that needs a mount namespace, which an unprivileged user
  // gets from a user namespace in which it is root (uid 0 there is the user's own uid outside; the socket stays the user's).
  const [command, commandArgs] = cri ? ["unshare", ["--user", "--map-root-user", "--mount", "--", "containerd", "-c", join(dir, "config.toml")]] : ["containerd", ["-c", join(dir, "config.toml")]];
  const daemon = spawn(command, commandArgs, { stdio: ["ignore", "ignore", "pipe"], env: cri ? { ...process.env, ...proxyEnv, ...daemonEnv } : process.env });
  daemon.stderr.on("data", () => {});
  await h.waitFor("containerd serves", async () => spawnSync("ctr", ["-a", sock, "version"], { encoding: "utf8" }).status === 0, { timeout: 30_000 });
  const env = { ...process.env, HTTPS_PROXY: `http://127.0.0.1:${proxy.port}`, https_proxy: `http://127.0.0.1:${proxy.port}`, HTTP_PROXY: "", http_proxy: "", NO_PROXY: "", no_proxy: "" };
  return {
    sock, env, proxy,
    /// A pull into the content store. `envExtra` is added to the client's environment (a pinned SSL_CERT_FILE, a NO_PROXY for a local
    /// server), `argsExtra` goes before the reference (`--user name:password`).
    fetch: (hostsDir, ref, timeout, envExtra = {}, argsExtra = []) => ctr(["--debug", "-a", sock, "content", "fetch", "--hosts-dir", hostsDir, ...argsExtra, ref], { ...env, ...envExtra }, timeout),
    run: (args, timeout, envExtra = {}) => ctr(["-a", sock, ...args], { ...env, ...envExtra }, timeout),
    /// crictl against the CRI plugin of this daemon (only with `cri: true`): the same API the kubelet calls.
    crictl: (args, timeout = 120_000) => ctr(["--runtime-endpoint", `unix://${sock}`, "--image-endpoint", `unix://${sock}`, ...args], process.env, timeout, "crictl"),
    async stop() {
      daemon.kill("SIGTERM");
      proxy.close();
      await new Promise((resolve) => (daemon.exitCode === null ? daemon.once("exit", resolve) : resolve()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
