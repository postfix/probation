import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkPinned, hostNames, startNode } from "../harness/containerd-node.mjs";
import { startCommonService } from "../harness/service-setup.mjs";

// Slice 29 risk spike (C1023): does containerd route an image pull for the ORIGINAL registry (docker.io) to the shared
// service when hosts.toml names the service as `server`, and does it stay there when the service refuses or is down?
// The runtime is the pinned containerd (03-program-design.md) started unprivileged with its own root/state/socket under
// the e2e work directory (disk), content-store only: `ctr content fetch` resolves and pulls without a snapshotter.
// Every connection the runtime makes goes through a recording CONNECT proxy that reaches the stack only for the
// service's own name; any other destination is refused and counted as a direct-origin attempt (fallback).
// Row 24 serves OCI (the default registry is the fake Docker Hub of fixtures/fakes/oci.mjs): the routed pull succeeds, the service decides the
// runtime's HEAD of the tag, and the refusals below (the service down, no fallback to the origin) are unchanged. The service's cooldown is
// 0 here (the age of an image is when the service first saw its digest; this probe is about routing, not about the cooldown).
export const meta = {
  id: "E2E-service-cluster-probe",
  title: "containerd explicit-server routing probe against the shared service",
  suites: ["release-cluster"],
  stack: "own",
};

const SERVICE_HOST = "fw-standalone.e2e.test";
const IMAGE = "docker.io/library/alpine:latest";

export default async function clusterProbe(h) {
  checkPinned(h);
  const standalone = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(standalone, readFileSync(standalone, "utf8").replace(/^cooldown_seconds = .*$/m, "cooldown_seconds = 0"));
  await startCommonService(h);

  const dir = join(h.stack.work, "containerd-probe");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(join(dir, "hosts", "_default"), { recursive: true });
  mkdirSync(join(dir, "hosts-none", "_default"), { recursive: true });
  const ca = join(h.stack.work, "ca", "ca.pem");
  // C1023's candidate: the service is the `server`, capabilities pull+resolve, the e2e CA trusted.
  writeFileSync(join(dir, "hosts", "_default", "hosts.toml"), `server = "https://${SERVICE_HOST}"\ncapabilities = ["pull", "resolve"]\nca = "${ca}"\n`);
  // Control: the same runtime without a `server` goes to the origin, which proves the recorder would see a fallback.
  writeFileSync(join(dir, "hosts-none", "_default", "hosts.toml"), `capabilities = ["pull", "resolve"]\nca = "${ca}"\n`);

  const node = await startNode(h, join(dir, "node"), SERVICE_HOST);
  const { proxy } = node;
  try {
    const fetch = (hostsName, timeout) => node.fetch(join(dir, hostsName), IMAGE, timeout);
    const hosts = hostNames;

    // The service's own request log: count of HEAD requests it decided as 200 (its log carries the ecosystem and the repository, not the verb's path).
    const decidedHeads = () => {
      const logs = spawnSync(h.stack.engine, ["logs", h.stack.container("firewall-standalone")], { encoding: "utf8" });
      return `${logs.stdout}${logs.stderr}`.split("\n").filter((l) => l.includes('"method":"\\"HEAD\\""') && l.includes('"status":200') && l.includes("oci")).length;
    };
    const headsBefore = decidedHeads();

    // 1. Routed: the pull for docker.io names the service and only the service.
    let r = await fetch("hosts");
    h.log(`routed pull: exit ${r.status}\n${r.stderr}`);
    h.expect(r.status === 0, `row 24 serves OCI: the routed pull succeeds: ${r.stderr.slice(-300)}`);
    h.expect(r.stderr.includes(SERVICE_HOST), "the runtime talked to the service named by hosts.toml");
    h.expect(JSON.stringify(hosts(proxy.connects)) === JSON.stringify([SERVICE_HOST]), `only the service was contacted: ${hosts(proxy.connects)}`);

    // 2. The service decided the runtime's HEAD of the tag (200). The request's own shape comes from the runtime's debug log: original
    // repository path, original registry kept as ns=docker.io.
    const decided = decidedHeads() - headsBefore;
    h.log(`service decided HEAD 200 during the pull: ${decided}`);
    h.expect(decided >= 1, `the service decided the runtime's HEAD of the tag (200): ${decided}`);
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
    await node.stop();
    rmSync(dir, { recursive: true, force: true });
  }
}
