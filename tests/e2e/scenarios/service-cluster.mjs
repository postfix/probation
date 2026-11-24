// E2E-service-cluster: one cluster endpoint, approved-node trust and no upstream fallback (slice 26), as far as one Linux host can show it.
//
// What runs here: the shared service (the e2e firewall in [service_policy] mode, a real policy server, an OCI registry whose origin is the
// fake Docker Hub, blocks written in the portal), and the PINNED containerd 2.2.0 started unprivileged as the node's container runtime,
// configured by the SHIPPED node scripts (deploy/kubernetes/node/install-node.sh, verified by verify-node.sh against the real runtime's
// effective configuration). Every connection of the runtime goes through a recording proxy that reaches only the service: a connection to
// any other host is a direct-origin attempt, and the scenario asserts there is none, with the origin healthy and reachable.
//
// What does NOT run here (docs/plans/package-firewall-mvp-lf/evidence/slice-26.md, "Lanes"): a Kubernetes cluster, kube-proxy and
// externalTrafficPolicy, a CRI/kubelet pull on a node, a second node, a host firewall on a real node. The approved node here is the gateway
// address the service is told to admit; an unapproved node is another container of the network that connects to the service directly.
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import https from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkPinned, hostNames, startNode } from "../harness/containerd-node.mjs";
import { buildOciArchive } from "../harness/oci-archive.mjs";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";
import { changePlatform, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-service-cluster",
  title: "one cluster endpoint: approved and unapproved nodes, fresh tag and digest allow and deny, no origin fallback, cached boundary",
  suites: ["release-cluster"],
  stack: "own",
};

const SERVICE_HOST = "fw-standalone.e2e.test";
const NODE_SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), "../../../deploy/kubernetes/node");
// verify-node.sh also asks systemd and /proc for the environment of the RUNNING containerd (its step 4a). This host's systemd and its real
// containerd must not be read or judged, so the scenario answers as the host's systemd would after a restart: a systemctl stand-in and a /proc
// tree built from the drop-in the installer wrote (the unit's Environment lines). That the verifier rejects a stale or overridden environment
// is tested in tests/node_scripts.rs; this only keeps the real-runtime checks of the scenario independent of the host.
function fakeHost(args) {
  const sd = args[args.indexOf("--systemd-dir") + 1];
  const root = `${sd}.fakehost`;
  rmSync(root, { recursive: true, force: true });
  mkdirSync(join(root, "bin"), { recursive: true });
  mkdirSync(join(root, "proc/4242"), { recursive: true });
  let env = [];
  try {
    for (const l of readFileSync(join(sd, "containerd.service.d/probation-ca.conf"), "utf8").split("\n")) {
      const m = l.match(/^Environment="(.+)"$/);
      if (m) env.push(m[1]);
    }
  } catch { /* no drop-in: the unit has no environment, the verifier then says so */ }
  writeFileSync(join(root, "proc/4242/environ"), env.map((e) => `${e}\0`).join(""));
  writeFileSync(join(root, "bin/systemctl"), `#!/bin/sh\n[ "$1" = show ] || exit 1\ncase "$4" in LoadState) echo loaded ;; Environment) echo '${env.join(" ")}' ;; DropInPaths) echo ;; MainPID) echo 4242 ;; esac\n`, { mode: 0o755 });
  return root;
}
const sh = (script, args) => {
  if (script !== "verify-node.sh") return spawnSync("sh", [join(NODE_SCRIPTS, script), ...args], { encoding: "utf8" });
  const root = fakeHost(args);
  return spawnSync("sh", [join(NODE_SCRIPTS, script), ...args, "--proc-dir", join(root, "proc")], { encoding: "utf8", env: { ...process.env, PATH: `${join(root, "bin")}:${process.env.PATH}` } });
};

const REPO = join(dirname(fileURLToPath(import.meta.url)), "../../..");

function get(port, path, headers = {}) {
  return new Promise((resolve) => {
    const req = https.request({ host: "127.0.0.1", port, path, headers, rejectUnauthorized: false, agent: false, timeout: 5000 }, (res) => {
      let body = "";
      res.on("data", (d) => { body += d; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", () => resolve({ status: 0, body: "" }));
    req.on("timeout", () => req.destroy());
    req.end();
  });
}

// The SHIPPED pod spec (statefulset.yaml: init container, security context, mounts, arguments), run by podman against the image built
// from this repository. `podman kube play` is not Kubernetes: no fsGroup, no probes, no NetworkPolicy, no scheduler (render.py lists what it
// changes). It shows that the pod spec starts the service as the image's own user with a read-only root file system and every capability
// dropped, that the init container's staged key is accepted, and that the key as a kubelet with fsGroup would leave it is refused.
async function podSmoke(h) {
  const { expect } = h;
  const image = process.env.E2E_FIREWALL_IMAGE ?? "localhost/probation:e2e";
  const engine = "podman"; // `kube play` is a podman feature: the stack may run on docker (hosted lane), the pod smoke always runs on podman
  const render = (out, ...extra) => spawnSync("python3", ["-I", join(REPO, "tests/e2e/fixtures/kube-play/render.py"), out, "--image", image, "--tls-cert", join(REPO, "tests/fixtures/tls/cert.pem"), "--tls-key", join(REPO, "tests/fixtures/tls/key.pem"), "--host-port", "18443", ...extra], { encoding: "utf8" });
  const dir = join(h.stack.work, "pod-smoke");
  mkdirSync(dir, { recursive: true });
  const down = (file) => spawnSync(engine, ["kube", "down", file], { encoding: "utf8" });
  let r = render(join(dir, "staged.yaml"));
  expect(r.status === 0, `the pod renders: ${r.stderr}`);
  r = spawnSync(engine, ["kube", "play", join(dir, "staged.yaml")], { encoding: "utf8", timeout: 120_000 });
  try {
    expect(r.status === 0, `the shipped pod starts (init container, then the service): ${r.stdout}${r.stderr}`);
    let live;
    await h.waitFor("the pod listens", async () => (live = await get(18443, "/health/live")).status === 200, { timeout: 30_000 });
    expect(live.status === 200, "liveness answers over https with the pod's own certificate");
    const inspected = JSON.parse(spawnSync(engine, ["inspect", "probation-smoke-probation"], { encoding: "utf8" }).stdout)[0];
    expect(inspected.Config.User === "999:999", `the container runs as the image's numeric user: ${inspected.Config.User}`);
    expect(inspected.HostConfig.ReadonlyRootfs === true, "the root file system is read-only");
    expect(inspected.HostConfig.CapDrop.includes("ALL") || inspected.HostConfig.CapDrop.length > 10, `every capability is dropped: ${inspected.HostConfig.CapDrop}`);
    const admitted = await get(18443, "/v2/", { host: "probation.cluster.example:30443" });
    expect(/NETWORK_NOT_ALLOWED|POLICY_UNAVAILABLE/.test(admitted.body), `the admission path ran for a request with the public host (403 for an unlisted peer, 503 with no policy server): ${admitted.status} ${admitted.body}`);
    const wrongHost = await get(18443, "/health/live", { host: "10.244.1.7:8443" });
    expect(wrongHost.status === 200, "a probe with the pod address as Host (what the kubelet sends) is answered");
  } finally {
    down(join(dir, "staged.yaml"));
  }
  r = render(join(dir, "unstaged.yaml"), "--no-stage");
  expect(r.status === 0, `the unstaged pod renders: ${r.stderr}`);
  spawnSync(engine, ["kube", "play", join(dir, "unstaged.yaml")], { encoding: "utf8", timeout: 120_000 });
  try {
    let logs = "";
    await h.waitFor("the service names the key it refuses", async () => (logs = spawnSync(engine, ["logs", "probation-smoke-probation"], { encoding: "utf8" })).stdout.includes("requires a private regular file") || logs.stderr.includes("requires a private regular file"), { timeout: 30_000 });
    expect(true, "without the init container the group- or world-readable service key is refused: service_key_file requires a private regular file");
  } finally {
    down(join(dir, "unstaged.yaml"));
  }
}

// F1 (pinning) and F2 (legacy layout), against the real containerd 2.2.0 resolver and a local https "origin" whose certificate is signed by a
// throwaway CA that the node's system roots are made to trust (the situation of any CA a node already trusts for the endpoint's name).
async function legacyAndPinning(h, { node, ca, sh, verifyArgs }) {
  const { expect } = h;
  const dir = join(h.stack.work, "pin-legacy");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const openssl = (...args) => spawnSync("openssl", args, { encoding: "utf8" });
  const ca2 = { key: join(dir, "ca2.key"), pem: join(dir, "ca2.pem") };
  let made = openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", ca2.key, "-out", ca2.pem, "-subj", "/CN=throwaway-ca", "-days", "1");
  expect(made.status === 0, `a throwaway CA: ${made.stderr}`);
  made = openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", join(dir, "srv.key"), "-out", join(dir, "srv.csr"), "-subj", "/CN=localhost");
  writeFileSync(join(dir, "san.cnf"), "subjectAltName=DNS:localhost\n");
  made = openssl("x509", "-req", "-in", join(dir, "srv.csr"), "-CA", ca2.pem, "-CAkey", ca2.key, "-CAcreateserial", "-out", join(dir, "srv.pem"), "-days", "1", "-extfile", join(dir, "san.cnf"));
  expect(made.status === 0, `a certificate for localhost signed by it: ${made.stderr}`);
  let hits = 0;
  const server = https.createServer({ key: readFileSync(join(dir, "srv.key")), cert: readFileSync(join(dir, "srv.pem")) }, (req, res) => { hits += 1; res.writeHead(404, { "content-type": "application/json" }).end('{"errors":[{"code":"NAME_UNKNOWN"}]}'); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const local = { HTTPS_PROXY: "", https_proxy: "", NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost" };
  const bundle = join(dir, "system-roots.pem"); // "the system roots": the throwaway CA is among them, as any CA a node already trusts is
  writeFileSync(bundle, readFileSync(ca2.pem, "utf8") + readFileSync(ca, "utf8"));
  const text = (run) => `${run.stdout}\n${run.stderr}`;
  try {
    // F1. The service CA is ADDED to the roots by hosts.toml's `ca`; SSL_CERT_FILE alone does not remove the DEFAULT certificate DIRECTORIES
    // of Go (/etc/ssl/certs, /etc/pki/tls/certs), so a second CA that sits in such a directory is still trusted (R1: the file-only pin did not
    // pin). The drop-in therefore sets SSL_CERT_DIR to an empty directory too.
    const pinCerts = join(dir, "pin/certs");
    let r = sh("install-node.sh", ["--endpoint", `https://localhost:${port}`, "--ca", ca, "--certs-dir", pinCerts, "--config-dir", join(dir, "pin/etc"), "--systemd-dir", join(dir, "pin/systemd")]);
    expect(r.status === 0, `install-node.sh: ${r.stderr}`);
    const dropin = readFileSync(join(dir, "pin/systemd/containerd.service.d/probation-ca.conf"), "utf8");
    const pinFile = dropin.match(/SSL_CERT_FILE=([^"]+)"/)[1];
    const pinDir = dropin.match(/SSL_CERT_DIR=([^"]+)"/)[1];
    mkdirSync(join(dir, "system-certs"), { recursive: true }); // a populated, system-style certificate directory that trusts the second CA
    writeFileSync(join(dir, "system-certs/second-ca.pem"), readFileSync(ca2.pem));
    let before = hits;
    r = await node.fetch(pinCerts, "docker.io/x/y:z", 30_000, { ...local, SSL_CERT_FILE: pinFile, SSL_CERT_DIR: join(dir, "system-certs") });
    expect(hits > before, `control: SSL_CERT_FILE alone (a certificate directory that trusts the second CA stays in force) ACCEPTS a certificate of the second CA for the endpoint's name: ${text(r).slice(-300)}`);
    before = hits;
    r = await node.fetch(pinCerts, "docker.io/x/y:z", 30_000, { ...local, SSL_CERT_FILE: pinFile, SSL_CERT_DIR: pinDir });
    expect(hits === before && r.status !== 0 && /x509: certificate signed by unknown authority/i.test(text(r)), `pinned (the installer's SSL_CERT_FILE and its empty SSL_CERT_DIR): the second CA's certificate is rejected before any request reaches the server: hits ${before} -> ${hits}; ${text(r).slice(-300)}`);
    // The shipped verifier proves the same with its own throwaway CA (control and pinned run, ctr against the real daemon).
    const proven = sh("verify-node.sh", ["--endpoint", `https://localhost:${port}`, "--certs-dir", pinCerts, "--containerd-config", join(dir, "pin/etc/config.toml"), "--systemd-dir", join(dir, "pin/systemd"), "--prove-pin", "--containerd-address", node.sock]);
    expect(proven.status === 0 && proven.stdout.includes("verify-node: ok"), `verify-node.sh --prove-pin: the control is accepted, the pinned environment rejects the second CA, and every other check holds: ${proven.stdout}${proven.stderr}`);

    // F2. A legacy per-registry directory (a CA file, no hosts.toml) wins over _default: the runtime goes to the registry's own address.
    const legacy = join(dir, "legacy/certs");
    const first = sh("install-node.sh", ["--endpoint", "https://127.0.0.1:1", "--ca", ca, "--certs-dir", legacy, "--config-dir", join(dir, "legacy/etc"), "--systemd-dir", join(dir, "legacy/systemd")]);
    expect(first.status === 0, `install-node.sh (dead endpoint): ${first.stderr}`);
    mkdirSync(join(legacy, `localhost:${port}`), { recursive: true });
    writeFileSync(join(legacy, `localhost:${port}/ca.crt`), readFileSync(ca2.pem));
    before = hits;
    await node.fetch(legacy, `localhost:${port}/foo/bar:latest`, 30_000, { ...local, SSL_CERT_FILE: bundle });
    expect(hits > before, `reproduced: the legacy layout sent the runtime to the registry's own address (the origin saw ${hits - before} request(s)) although _default names another server`);
    const verified = sh("verify-node.sh", ["--endpoint", "https://127.0.0.1:1", "--certs-dir", legacy, "--containerd-config", join(dir, "pin/etc/config.toml"), "--systemd-dir", join(dir, "pin/systemd")]);
    expect(verified.status === 1 && verified.stdout.includes("legacy certificate file"), `verify-node.sh refuses it: ${verified.stdout}`);
    const refused = sh("install-node.sh", ["--endpoint", "https://127.0.0.1:1", "--ca", ca, "--certs-dir", legacy, "--config-dir", join(dir, "legacy/etc"), "--systemd-dir", join(dir, "legacy/systemd")]);
    expect(refused.status === 2 && refused.stderr.includes("is not mapped"), `install-node.sh refuses it: ${refused.stderr}`);
    // The mapped layout (the legacy files gone, the registry mapped): the same pull never reaches the origin; it fails against the (dead) endpoint.
    rmSync(join(legacy, `localhost:${port}`), { recursive: true });
    const mapped = sh("install-node.sh", ["--endpoint", "https://127.0.0.1:1", "--ca", ca, "--certs-dir", legacy, "--config-dir", join(dir, "legacy/etc"), "--systemd-dir", join(dir, "legacy/systemd"), "--registry", `localhost:${port}=1`]);
    expect(mapped.status === 0, `install-node.sh maps it: ${mapped.stderr}`);
    before = hits;
    r = await node.fetch(legacy, `localhost:${port}/foo/bar:latest`, 30_000, { ...local, SSL_CERT_FILE: bundle });
    expect(hits === before && r.status !== 0 && /127\.0\.0\.1:1|refused/i.test(text(r)), `no fallback: the mapped registry went to the (dead) endpoint, never to its own address (hits ${before} -> ${hits}): ${text(r).slice(-300)}`);
  } finally {
    server.close();
  }
}

// R2: the drop-in must speak the schema of the MAIN config. A real containerd 2.2.0 dumps the effective configuration of a version-2 and of a
// version-3 main file before and after the installer: the runtime's own settings stay, only the registry config_path changes. The control
// writes the OLD drop-in (its own `version = 3`) next to the version-2 main file and reproduces the corruption the installer used to cause.
function configSchemas(h, ca) {
  const { expect } = h;
  const dir = join(h.stack.work, "schemas");
  rmSync(dir, { recursive: true, force: true });
  const dump = (cfg) => spawnSync("containerd", ["--config", cfg, "config", "dump"], { encoding: "utf8" });
  const mains = {
    v2: `version = 2\n\n[plugins."io.containerd.grpc.v1.cri"]\n  sandbox_image = "registry.k8s.io/pause:3.9"\n  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]\n    SystemdCgroup = true\n  [plugins."io.containerd.grpc.v1.cri".registry]\n    config_path = "/etc/containerd/certs.d:/etc/docker/certs.d"\n`,
    v3: `version = 3\n\n[plugins.'io.containerd.cri.v1.images'.pinned_images]\n  sandbox = 'registry.k8s.io/pause:3.9'\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]\n  SystemdCgroup = true\n`,
  };
  const lines = (text) => text.split("\n").filter((l) => l.trim() && !/config_path|imports/.test(l));
  for (const [name, main] of Object.entries(mains)) {
    const d = join(dir, name);
    mkdirSync(d, { recursive: true });
    const cfg = join(d, "config.toml");
    writeFileSync(cfg, main);
    const before = dump(cfg).stdout;
    expect(before.includes("SystemdCgroup = true") && before.includes("pause:3.9"), `${name}: the baseline carries SystemdCgroup = true and the pause image`);
    const r = sh("install-node.sh", ["--endpoint", `https://${SERVICE_HOST}`, "--ca", ca, "--certs-dir", join(d, "certs.d"), "--config-dir", d, "--config-file", cfg, "--systemd-dir", join(d, "sd")]);
    expect(r.status === 0, `${name}: install-node.sh: ${r.stderr}`);
    const after = dump(cfg).stdout;
    expect(after.includes("SystemdCgroup = true") && !after.includes("SystemdCgroup = false") && after.includes("pause:3.9"), `${name}: SystemdCgroup and the sandbox image are unchanged after the installer`);
    expect(after.includes(`config_path = '${join(d, "certs.d")}'`), `${name}: the registry config_path is the installer's directory`);
    const a = new Set(lines(after));
    const gone = lines(before).filter((l) => !a.has(l));
    const b = new Set(lines(before));
    const added = lines(after).filter((l) => !b.has(l));
    expect(gone.length === 0 && added.length === 0, `${name}: nothing but config_path and imports differs (removed ${JSON.stringify(gone)}, added ${JSON.stringify(added)})`);
    const v = sh("verify-node.sh", ["--endpoint", `https://${SERVICE_HOST}`, "--certs-dir", join(d, "certs.d"), "--containerd-config", cfg, "--systemd-dir", join(d, "sd")]);
    expect(v.status === 0 && v.stdout.includes("verify-node: ok"), `${name}: verify-node.sh (which also compares the dump with the baseline) accepts it: ${v.stdout}`);
  }
  const old = join(dir, "old");
  mkdirSync(join(old, "conf.d"), { recursive: true });
  writeFileSync(join(old, "config.toml"), `${mains.v2.replace("version = 2\n", `version = 2\nimports = ["${old}/conf.d/*.toml"]\n`)}`);
  writeFileSync(join(old, "conf.d/probation.toml"), "version = 3\n\n[plugins.'io.containerd.cri.v1.images'.registry]\n  config_path = '/x'\n");
  const corrupted = dump(join(old, "config.toml")).stdout;
  expect(corrupted.includes("SystemdCgroup = false") && !corrupted.includes("SystemdCgroup = true"), "control: the old drop-in (its own version = 3) next to a version-2 main file DOES switch SystemdCgroup off");
}

// R7: the CRI plugin's image service of the real containerd 2.2.0 (the API the kubelet calls), configured by the shipped installer, pulling through
// the service only. No pod is run (no runtime here); `crictl pull` is the kubelet's PullImage call.
async function criPull(h, { ca, hubId, ghcrId, one, ghcrApp, serviceKey }) {
  const { expect } = h;
  expect(spawnSync("crictl", ["--version"], { encoding: "utf8" }).status === 0, "crictl is installed (a missing tool fails the run, it never skips)");
  const dir = join(h.stack.work, "crn");
  const pinEnv = {};
  const registries = ["--registry", `docker.io=${hubId}`, "--registry", `ghcr.io=${ghcrId}`];
  const cri = await startNode(h, dir, SERVICE_HOST, {
    cri: true,
    daemonEnv: pinEnv,
    beforeStart: async (cfg) => {
      const r = sh("install-node.sh", ["--endpoint", `https://${SERVICE_HOST}`, "--ca", ca, "--certs-dir", join(dir, "certs.d"), "--config-dir", join(dir, "etc"), "--config-file", cfg, "--systemd-dir", join(dir, "sd"), ...registries]);
      expect(r.status === 0, `install-node.sh on the CRI node: ${r.stderr}`);
      const unit = readFileSync(join(dir, "sd/containerd.service.d/probation-ca.conf"), "utf8");
      pinEnv.SSL_CERT_FILE = unit.match(/SSL_CERT_FILE=([^"]+)"/)[1];
      pinEnv.SSL_CERT_DIR = unit.match(/SSL_CERT_DIR=([^"]+)"/)[1];
    },
  });
  const out = (run) => `${run.stdout}\n${run.stderr}`;
  const hex = (digest) => digest.replace("sha256:", "");
  try {
    const verified = sh("verify-node.sh", ["--endpoint", `https://${SERVICE_HOST}`, "--certs-dir", join(dir, "certs.d"), "--containerd-config", join(dir, "config.toml"), "--systemd-dir", join(dir, "sd")]);
    expect(verified.status === 0, `verify-node.sh accepts the CRI node: ${verified.stdout}`);
    let r = await cri.crictl(["pull", "docker.io/team/app:v1"]);
    expect(r.status === 0, `the CRI PullImage of a mapped registry goes through the service: ${out(r).slice(-400)}`);
    r = await cri.crictl(["pull", "ghcr.io/team/app:v1"]);
    expect(r.status === 0, `...and so does the second registry: ${out(r).slice(-400)}`);
    const images = out(await cri.crictl(["images", "--digests", "--no-trunc"]));
    expect(images.includes(hex(one.digest)) && images.includes(hex(ghcrApp.digest)), `the CRI image store holds both images, each its own registry's digest: ${images}`);
    expect(JSON.stringify(hostNames(cri.proxy.connects)) === JSON.stringify([SERVICE_HOST]), `the CRI pulls contacted only the service: ${hostNames(cri.proxy.connects)}`);
    r = await cri.crictl(["pull", "quay.io/team/nothing:v1"], 60_000);
    expect(r.status !== 0 && /404|not found/i.test(out(r)) && cri.proxy.connects.every((t) => t.startsWith(`${SERVICE_HOST}:`)), `an unmapped registry is refused by the service through the CRI path, with no origin connection: ${out(r).slice(-300)}`);
    r = await cri.crictl(["pull", "docker.io/private/app:v1"], 60_000);
    expect(r.status !== 0, `a private image without a credential is refused through the CRI path: ${out(r).slice(-200)}`);
    r = await cri.crictl(["pull", "--creds", "e2e-owner:e2e-pass", "docker.io/private/app:v1"], 90_000);
    expect(r.status === 0, `a private image with the AuthConfig of the request is pulled through the CRI path (crictl sends no ServerAddress; the kubelet's own matching rule is not exercised): ${out(r).slice(-300)}`);
    expect(cri.proxy.connects.every((t) => t.startsWith(`${SERVICE_HOST}:`)), `still only the service: ${cri.proxy.connects}`);
    expect((await h.fakes.ociSeen()).every((x) => !String(x.authorization ?? "").includes(serviceKey)), "the service key reached no host");
  } finally {
    await cri.stop();
  }
}

export default async function cluster(h) {
  const { expect } = h;
  checkPinned(h);
  const ca = join(h.stack.work, "ca", "ca.pem");
  await podSmoke(h);
  configSchemas(h, ca);

  // ---- The service: one org policy, TWO OCI registries (the fake Docker Hub and the fake ghcr.io), the gateway is the approved node. ----
  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: true } });
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const addRegistry = async (name, target) => {
    const catalog = await admin.portal.get(`/org/${org}/registries`);
    expect((await admin.portal.post(`/org/${org}/registries`, { csrf: hidden(catalog.body, "csrf"), name, ecosystem: "oci", target_url: target })).status === 303, `${name} is added`);
    const id = (await admin.portal.get(`/org/${org}/registries`)).body.match(new RegExp(`<li>(\\d+) ${name} oci`))?.[1];
    expect(id, `${name} has an ID`);
    expect((await admin.portal.submit(`/org/${org}/registries`, `/org/${org}/registries/${id}/archive-origin`, { archive_origin: "https://production.cloudfront.docker.com/" })).status === 303, `${name}'s storage origin is declared`);
    return id;
  };
  const hubId = await addRegistry("Cluster OCI", "https://registry-1.docker.io/");
  const ghcrId = await addRegistry("Cluster GHCR", "https://ghcr.io/");
  await h.editPolicy(admin.portal, { action: "save", freeze: "0", unit: "hours", osv: "on" });
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "cluster-service", attach: "org" });
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  expect(serviceKey?.startsWith("prb_"), "the service key is issued");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${serviceKey}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  for (const id of [hubId, ghcrId]) {
    await h.waitFor(`registry ${id} is served`, async () => [200, 401].includes((await h.request(`https://${SERVICE_HOST}/registry/oci/${id}/v2/`)).status), { timeout: 30_000 });
  }

  // ---- The node: the shipped scripts configure the real runtime, with a route per registry. ----
  const work = join(h.stack.work, "cluster-node");
  const certs = join(work, "etc/certs.d");
  const systemd = join(work, "etc/systemd");
  const configFile = join(work, "etc/config.toml");
  const verifyArgs = (certsDir, config, sysd, ...more) => ["--endpoint", `https://${SERVICE_HOST}`, "--certs-dir", certsDir, "--containerd-config", config, "--systemd-dir", sysd, ...more];
  mkdirSync(work, { recursive: true });
  let r = sh("install-node.sh", ["--endpoint", `https://${SERVICE_HOST}`, "--ca", ca, "--certs-dir", certs, "--config-dir", join(work, "etc"), "--systemd-dir", systemd, "--registry", `docker.io=${hubId}`, "--registry", `ghcr.io=${ghcrId}`]);
  expect(r.status === 0, `install-node.sh: ${r.stderr}`);
  // The effective configuration is read by the real containerd 2.2.0 (`containerd config dump`): the installer's own imports line is what
  // makes the drop-in load (nothing here is written by hand).
  r = sh("verify-node.sh", verifyArgs(certs, configFile, systemd));
  expect(r.status === 0 && r.stdout.includes("verify-node: ok"), `verify-node.sh accepts the installed node against the real containerd: ${r.stdout}${r.stderr}`);
  // What the systemd drop-in would give the daemon (and CRI's pulls): the service CA is the ONLY root. The client of `ctr` does the TLS here.
  const pinned = readFileSync(join(systemd, "containerd.service.d/probation-ca.conf"), "utf8").match(/SSL_CERT_FILE=([^"]+)"/)?.[1];
  expect(pinned === join(certs, "_default/probation-ca.pem"), `the installer pins the service CA: ${pinned}`);
  const pin = { SSL_CERT_FILE: pinned };
  // The same node without the installer's config_path import, or with a legacy per-registry directory, is refused by the verifier.
  const withoutImport = join(work, "no-import.toml");
  writeFileSync(withoutImport, "version = 3\n");
  r = sh("verify-node.sh", verifyArgs(certs, withoutImport, systemd));
  expect(r.status === 1 && r.stdout.includes("probably not imported"), `verify-node.sh says what is missing when the drop-in is not imported: ${r.stdout}`);
  // The control layout (no `server`): the verifier refuses it, and the recorder below sees the runtime go to the origin with it.
  const control = join(work, "control");
  mkdirSync(join(control, "_default"), { recursive: true });
  writeFileSync(join(control, "_default/hosts.toml"), `capabilities = ["pull", "resolve"]\nca = "${ca}"\n`);
  r = sh("verify-node.sh", verifyArgs(control, configFile, systemd));
  expect(r.status === 1 && r.stdout.includes("does not name the server"), `verify-node.sh refuses a layout with no server: ${r.stdout}`);
  // The ns-only layout (no per-registry files): one `_default` endpoint serves several registries through ?ns=.
  const nsWork = join(work, "ns");
  r = sh("install-node.sh", ["--endpoint", `https://${SERVICE_HOST}`, "--ca", ca, "--certs-dir", join(nsWork, "certs.d"), "--config-dir", join(nsWork, "etc"), "--systemd-dir", join(nsWork, "systemd")]);
  expect(r.status === 0, `install-node.sh (ns only): ${r.stderr}`);
  r = sh("verify-node.sh", verifyArgs(join(nsWork, "certs.d"), join(nsWork, "etc/config.toml"), join(nsWork, "systemd")));
  expect(r.status === 0, `verify-node.sh (ns only): ${r.stdout}`);
  const nsCerts = join(nsWork, "certs.d");

  const node = await startNode(h, join(h.stack.work, "ccn"), SERVICE_HOST);
  const { proxy } = node;
  const output = (run) => `${run.stdout}\n${run.stderr}`;
  const fetch = (ref, timeout, certsDir = certs, extra = {}, args = []) => node.fetch(certsDir, ref, timeout, { ...pin, ...extra }, args);
  const names = () => hostNames(proxy.connects);
  const direct = () => proxy.connects.filter((t) => !t.startsWith(`${SERVICE_HOST}:`));
  const hub = async (path) => (await h.fakes.ociSeen()).filter((x) => x.path.includes(path)).length;
  try {
    const one = await h.fakes.publishOci({ repo: "team/app", tag: "v1", image: "hello-1" });
    const two = await h.fakes.publishOci({ repo: "team/app", tag: "v2", image: "hello-2" });
    await h.fakes.publishOci({ repo: "team/blocked", tag: "v1", image: "hello-1" });
    const ghcrApp = await h.fakes.publishOci({ repo: "team/app", tag: "v1", image: "hello-2", host: "ghcr.io" });
    const hex = (digest) => digest.replace("sha256:", "");

    // 1. Approved node, fresh tag and fresh digest: allowed, through the service only, each registry on its own route.
    r = await fetch("docker.io/team/app:v1");
    expect(r.status === 0, `a fresh tag is pulled through the service: ${r.status}\n${output(r).slice(-500)}`);
    expect(JSON.stringify(names()) === JSON.stringify([SERVICE_HOST]), `the runtime contacted only the service: ${names()}`);
    expect(new RegExp(`/registry/oci/${hubId}/v2/team/app/manifests/v1\\?ns=docker\\.io`).test(r.stderr), `docker.io went to its own route, the original registry kept as ?ns=docker.io: ${r.stderr.slice(-300)}`);
    expect(output(r).includes(hex(one.digest)), "the digest is the Hub's image");
    r = await fetch(`docker.io/team/app@${two.digest}`);
    expect(r.status === 0, `a fresh digest is pulled through the service: ${r.status}\n${output(r).slice(-500)}`);
    const got = await node.run(["content", "get", one.digest]);
    expect(got.status === 0 && got.stdout.includes("schemaVersion"), "the manifest is in the node's content store");
    expect(direct().length === 0, `no connection to anything but the service: ${direct()}`);

    // 1b. A second registry with a repository of the SAME NAME: it is its own image, never the Hub's.
    expect(ghcrApp.digest !== one.digest, "the two registries hold different images under one repository path");
    r = await fetch("ghcr.io/team/app:v1");
    expect(r.status === 0 && output(r).includes(hex(ghcrApp.digest)) && !output(r).includes(hex(one.digest)), `ghcr.io/team/app is ghcr's image, not the Hub's: ${output(r).slice(-400)}`);
    expect(new RegExp(`/registry/oci/${ghcrId}/v2/team/app/manifests/v1\\?ns=ghcr\\.io`).test(r.stderr), "ghcr.io went to its own route");
    // The ns-only layout (one _default endpoint, no per-registry files) selects the registry by ?ns= for both, with the token realm carrying the ns.
    for (const [ref, want, wrong] of [["docker.io/team/app:v1", one.digest, ghcrApp.digest], ["ghcr.io/team/app:v1", ghcrApp.digest, one.digest]]) {
      r = await fetch(ref, undefined, nsCerts);
      expect(r.status === 0 && output(r).includes(hex(want)) && !output(r).includes(hex(wrong)), `${ref} through the ns-only layout is its own registry's image: ${output(r).slice(-400)}`);
      expect(/\/v2\/team\/app\/manifests\/v1\?ns=/.test(r.stderr), "the plain /v2 root with ?ns=");
    }
    // A registry no policy registry serves is refused with no registry asked and no origin attempt, by either layout.
    const quayAsked = await hub("team/nothing");
    r = await fetch("quay.io/team/nothing:v1", 40_000, nsCerts);
    expect(r.status !== 0 && /404|not found/i.test(output(r)), `an unserved registry is refused by the service (ns-only): ${output(r).slice(-300)}`);
    r = await fetch("quay.io/team/nothing:v1", 40_000);
    expect(r.status !== 0 && /404|not found/i.test(output(r)), `an unserved registry is refused by the service (per-registry layout falls to _default): ${output(r).slice(-300)}`);
    expect((await hub("team/nothing")) === quayAsked && direct().length === 0, `nothing asked of any origin for it: ${direct()}`);

    // 1c. A private repository with the caller's own credential (what the pull-secret path sends) works through the endpoint, without it fails.
    await h.fakes.publishOci({ repo: "private/app", tag: "v1", image: "hello-1" });
    r = await fetch("docker.io/private/app:v1", 40_000);
    expect(r.status !== 0 && /401|403|unauthorized|denied/i.test(output(r)), `a private repository without a credential is refused: ${output(r).slice(-300)}`);
    r = await fetch("docker.io/private/app:v1", 60_000, certs, {}, ["--user", "e2e-owner:e2e-pass"]);
    expect(r.status === 0, `the caller's own credential is exchanged at the registry's realm and the pull succeeds: ${output(r).slice(-400)}`);
    const tokens = await h.fakes.ociTokens();
    expect(tokens.some((t) => t.basic && t.scope.includes("repository:private/app:pull")), `the registry saw the caller's Basic credential at its realm: ${JSON.stringify(tokens.slice(-3))}`);
    expect((await h.fakes.ociSeen()).every((x) => !String(x.authorization ?? "").includes(serviceKey)), "the service key never reached any host");

    // 1d. A legacy certs.d layout (a per-registry directory with a certificate and no hosts.toml) sends containerd to the registry's own address:
    // reproduced against the real resolver, refused by the verifier and the installer, and absent from the mapped layout.
    await legacyAndPinning(h, { node, ca, sh, verifyArgs });
    await criPull(h, { ca, hubId, ghcrId, one, ghcrApp, serviceKey });

    // 2. Deny with the origin healthy: a blocked repository is refused by the service, the origin serves another repository meanwhile.
    const policy = await h.policyPath(admin.portal);
    const block = async (fields) => expect((await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "oci", ...fields })).status === 303, `block ${JSON.stringify(fields)} is saved`);
    await block({ name: "team/blocked", what: "package" });
    let refused;
    await h.waitFor("the block refuses the pull", async () => { refused = await fetch("docker.io/team/blocked:v1"); return refused.status !== 0 && /403/.test(refused.stderr); }, { timeout: 40_000, every: 1000 });
    const direct1 = direct().length;
    const originAsked = await hub("team/blocked");
    r = await fetch("docker.io/team/blocked:v1");
    expect(r.status !== 0 && /403/.test(r.stderr), `a blocked repository is refused by the service (403): ${output(r).slice(-300)}`);
    expect(direct().length === direct1 && direct().length === 0, `the refused pull did not fall back to the origin: ${direct()}`);
    expect((await hub("team/blocked")) === originAsked, "the service asked the origin nothing for a blocked repository");
    await h.fakes.publishOci({ repo: "team/other", tag: "v1", image: "hello-1" });
    const otherBefore = await hub("team/other");
    r = await fetch("docker.io/team/other:v1");
    expect(r.status === 0 && (await hub("team/other")) > otherBefore, `the origin is healthy and serves another repository through the service while this one is refused: ${output(r).slice(-200)}`);

    // 3. A tag is judged by the digest it names NOW. Allowed -> blocked, and blocked -> allowed, by moving the tag at the origin.
    const flip = await h.fakes.publishOci({ repo: "team/flip", tag: "v1", image: "hello-1" });
    r = await fetch("docker.io/team/flip:v1");
    expect(r.status === 0, `the tag is allowed while its digest is: ${output(r).slice(-300)}`);
    await block({ name: "team/flip", what: "version", version: flip.digest });
    let started = Date.now();
    await h.waitFor("the digest block refuses the tag", async () => { r = await fetch("docker.io/team/flip:v1"); return r.status !== 0 && /403/.test(r.stderr); }, { timeout: 60_000, every: 1000 });
    h.log(`tag refused ${((Date.now() - started) / 1000).toFixed(1)} s after the digest block (policy sync 1 s, tag memo 30 s)`);
    r = await fetch(`docker.io/team/flip@${flip.digest}`);
    expect(r.status !== 0 && /403/.test(r.stderr), `the same digest by digest is refused too: ${output(r).slice(-300)}`);
    const moved = await h.fakes.publishOci({ repo: "team/flip", tag: "v1", image: "hello-2" });
    expect(moved.digest !== flip.digest, "the origin's tag now names another digest");
    started = Date.now();
    await h.waitFor("the moved tag is judged by its new digest", async () => { r = await fetch("docker.io/team/flip:v1"); return r.status === 0; }, { timeout: 90_000, every: 2000 });
    h.log(`moved tag pulled ${((Date.now() - started) / 1000).toFixed(1)} s after the origin moved it`);
    r = await fetch(`docker.io/team/flip@${flip.digest}`);
    expect(r.status !== 0 && /403/.test(r.stderr), "the old digest stays refused after the tag moved");
    expect(direct().length === 0, `still nothing but the service: ${direct()}`);

    // 4. The cached boundary (C1023): content already on the node is not revoked by a later block, and no later pull of it succeeds.
    const cached = await node.run(["content", "get", flip.digest]);
    expect(cached.status === 0, "a blocked digest that was pulled earlier is still in the node's content store (no execution-time revocation)");

    // 4b. Bootstrap preload (T8): the service's own image is imported by digest BEFORE anything is routed through the service, and a node
    // that holds it needs no pull. (A fixture image stands in for the service image; the import path is the shipped one.)
    const archive = buildOciArchive({ fixtures: join(REPO, "tests/e2e/fixtures/oci"), image: "hello-1", dir: join(work, "preload") });
    const serviceImage = `registry.example/probation/probation@${archive.digest}`;
    r = sh("install-node.sh", ["--endpoint", `https://${SERVICE_HOST}`, "--ca", ca, "--certs-dir", certs, "--config-dir", join(work, "etc"), "--systemd-dir", systemd, "--registry", `docker.io=${hubId}`, "--registry", `ghcr.io=${ghcrId}`, "--preload-image", archive.archive, "--image-ref", serviceImage, "--containerd-address", node.sock]);
    expect(r.status === 0 && r.stdout.includes("preloaded"), `install-node.sh preloads the service image by digest into the k8s.io store of the real containerd: ${r.stdout}${r.stderr}`);
    r = sh("verify-node.sh", verifyArgs(certs, configFile, systemd, "--service-pool", "--image-ref", serviceImage, "--containerd-address", node.sock));
    expect(r.status === 0, `verify-node.sh --service-pool finds it: ${r.stdout}`);
    r = sh("verify-node.sh", verifyArgs(certs, configFile, systemd, "--service-pool", "--image-ref", `registry.example/probation/probation@sha256:${"1".repeat(64)}`, "--containerd-address", node.sock));
    expect(r.status === 1 && r.stdout.includes("is not in the k8s.io content store"), `another digest is not there: ${r.stdout}`);

    // 5. Service down, origin healthy: every pull fails, nothing goes to the origin; the preloaded service image is still on the node.
    await h.fakes.publishOci({ repo: "team/app", tag: "v3", image: "hello-2" });
    const before = proxy.connects.length;
    h.stack.compose(["pause", "firewall-standalone"]);
    try {
      for (const ref of ["docker.io/team/app:v3", "docker.io/team/app:v2", "ghcr.io/team/app:v1"]) {
        r = await fetch(ref, 40_000);
        expect(r.status !== 0 && !r.killed, `${ref} fails while the service is down, by itself and not by the timer: ${output(r).slice(-300)}`);
      }
      expect(proxy.connects.length > before, "the runtime did try the service (so the check below observed something)");
      expect(proxy.connects.slice(before).every((t) => t.startsWith(`${SERVICE_HOST}:`)), `no direct-origin attempt with the service down: ${proxy.connects.slice(before)}`);
      const local = await node.run(["-n", "k8s.io", "images", "ls", `name==${serviceImage}`]);
      expect(local.stdout.includes(archive.digest), "with the service down the service's own image is still in the node's store: a pod using it needs no pull");
      r = await fetch(serviceImage, 40_000);
      expect(r.status !== 0, "a PULL of it still goes to the service only (and fails): the preload is what makes it unnecessary");
    } finally {
      h.stack.compose(["unpause", "firewall-standalone"]);
    }
    await h.waitFor("the service answers again", async () => [200, 401].includes((await h.request(`https://${SERVICE_HOST}/registry/oci/${hubId}/v2/`)).status), { timeout: 60_000 });
    r = await fetch("docker.io/team/app:v3");
    expect(r.status === 0, `after the service is back the same pull succeeds: ${output(r).slice(-300)}`);

    // 6. Control: the runtime configured WITHOUT `server` does go to the origin, so the recorder above would have seen a fallback.
    const mark = proxy.connects.length;
    await node.fetch(control, "docker.io/team/app:v2", undefined, {});
    expect(proxy.connects.slice(mark).some((t) => /docker\.io|docker\.com/.test(t)), "the control layout attempts the origin (registry-1.docker.io)");

    // 7. Approved and unapproved nodes at the listener. The gateway (the address the service admits) is the approved node: the runtime above
    // pulled through it. Another container of the network is an unapproved node: it reaches the service's port with its OWN source address.
    // The discriminating form of the cluster check: the endpoint NAME (so TLS and the Host check pass), pointed at one address, and the
    // refusal must be the NETWORK_NOT_ALLOWED body (a TLS failure or a Host refusal would also print a non-200).
    const probeScript = (host, port, servername) => `
      const https = require("node:https");
      const req = https.request({ host: "${host}", port: ${port}, path: "/v2/", method: "GET", servername: "${servername}", rejectUnauthorized: false, agent: false, headers: { host: "${servername}${port === 443 ? "" : ":" + port}" } }, (res) => { let b = ""; res.on("data", (d) => b += d); res.on("end", () => console.log(res.statusCode + " " + b.slice(0, 200))); });
      req.on("error", (e) => { console.log("ERR " + e.message); process.exit(1); }); req.end();`;
    const asUnapproved = (script) => h.stack.exec("fakes", ["node", "-e", script]);
    const serviceIp = Object.values(JSON.parse(spawnSync(h.stack.engine, ["inspect", h.stack.container("firewall-standalone")], { encoding: "utf8" }).stdout)[0].NetworkSettings.Networks).map((n) => n.IPAddress).find((ip) => ip.startsWith(`${h.stack.net}.`));
    expect(serviceIp, "the service container has an address on the e2e network");
    const direct403 = asUnapproved(probeScript(serviceIp, 8080, SERVICE_HOST));
    expect(/^403 /.test(direct403.stdout) && direct403.stdout.includes("NETWORK_NOT_ALLOWED"), `an unapproved node (its own source address, straight to the service port) is refused with NETWORK_NOT_ALLOWED: ${direct403.stdout}${direct403.stderr}`);
    const viaGateway = asUnapproved(probeScript(SERVICE_HOST, 443, SERVICE_HOST));
    expect(/^(200|401|404) /.test(viaGateway.stdout) && !viaGateway.stdout.includes("NETWORK_NOT_ALLOWED"), `the same host through the gateway (a hop that rewrites the source to the approved address) IS admitted: ${viaGateway.stdout}${viaGateway.stderr}`);
    h.log("approved/unapproved: direct = NETWORK_NOT_ALLOWED, through the source-rewriting gateway = admitted. This is what externalTrafficPolicy Local exists to prevent in a cluster (D1); kube-proxy itself is not run here.");

    // 8. The node firewall (deploy/kubernetes/node): rendered by the shipped install-firewall.sh, checked with nft -c, loaded into a throwaway
    // network namespace: the endpoint's port open, a registry port reset, DNS only to the listed resolver, the NodePort only for approved
    // sources, rollback.
    const fixture = join(dirname(fileURLToPath(import.meta.url)), "../fixtures/node-egress");
    const image = "localhost/probation-e2e-node-egress:nft";
    const built = spawnSync(h.stack.engine, ["build", "-q", "-t", image, fixture], { encoding: "utf8" });
    expect(built.status === 0, `the egress test image builds: ${built.stderr}`);
    const ran = spawnSync(h.stack.engine, ["run", "--rm", "--cap-add", "NET_ADMIN", "-v", `${NODE_SCRIPTS}:/node:ro`, "-v", `${fixture}/check.sh:/check.sh:ro`, image, "sh", "/check.sh"], { encoding: "utf8", timeout: 120_000 });
    expect(ran.status === 0 && ran.stdout.includes("SYNTAX ok") && ran.stdout.includes("RELOAD ok") && ran.stdout.includes("ROLLBACK ok"), `the rendered rules pass nft -c, reload and roll back: ${ran.stdout}${ran.stderr}`);
    for (const line of ["flushed OPEN 10.77.0.30:443", "flushed-ingress OPEN 10.77.0.3", "reasserted CLOSED 10.77.0.30:443", "reasserted-ingress CLOSED 10.77.0.3", "reasserted-ingress OPEN 10.77.0.2", "UNIT partof ok"]) {
      expect(ran.stdout.includes(line), `after nft flush ruleset the unit's reload path puts the tables back (${line}): ${ran.stdout}`);
    }
    const seen = Object.fromEntries([...ran.stdout.matchAll(/^(before|after) (OPEN|CLOSED) (\S+)$/gm)].map((m) => [`${m[1]} ${m[3]}`, m[2]]));
    const targets = ["10.77.0.20:30443", "10.77.0.20:443", "10.77.0.30:443", "10.77.0.30:30443", "10.77.0.40:6443", "10.77.0.50:8080", "10.77.0.53:53", "10.77.0.54:53"];
    expect(targets.every((t) => seen[`before ${t}`] === "OPEN"), `without the rules every target is reachable (the probe works): ${JSON.stringify(seen)}`);
    const wanted = { "10.77.0.20:30443": "OPEN", "10.77.0.20:443": "CLOSED", "10.77.0.30:443": "CLOSED", "10.77.0.30:30443": "CLOSED", "10.77.0.40:6443": "OPEN", "10.77.0.50:8080": "OPEN", "10.77.0.53:53": "OPEN", "10.77.0.54:53": "CLOSED" };
    expect(targets.every((t) => seen[`after ${t}`] === wanted[t]), `with the rules only the endpoint, the cluster range, the listed extra and the listed resolver are open: ${JSON.stringify(seen)}`);
    const udp = Object.fromEntries([...ran.stdout.matchAll(/^udp-(before|after) (OPEN|CLOSED) (\S+)$/gm)].map((m) => [`${m[1]} ${m[3]}`, m[2]]));
    expect(udp["before 10.77.0.53:53"] === "OPEN" && udp["before 10.77.0.54:53"] === "OPEN" && udp["after 10.77.0.53:53"] === "OPEN" && udp["after 10.77.0.54:53"] === "CLOSED", `UDP DNS reaches only the listed resolver once the rules are in: ${JSON.stringify(udp)}`);
    const ingress = Object.fromEntries([...ran.stdout.matchAll(/^ingress(-before)? (OPEN|CLOSED) (\S+) (\S+)$/gm)].map((m) => [`${m[1] ? "before " : ""}${m[3]}`, m[2]]));
    expect(ingress["before 10.77.0.3"] === "OPEN" && ingress["10.77.0.2"] === "OPEN" && ingress["10.77.0.3"] === "CLOSED", `the NodePort rule admits the approved node and drops another source: ${JSON.stringify(ingress)}`);
    spawnSync(h.stack.engine, ["rmi", "-f", image]);
  } finally {
    await node.stop();
    await restorePlatform();
  }
}
