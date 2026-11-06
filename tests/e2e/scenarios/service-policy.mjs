import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { hidden } from "../harness/net.mjs";
import { act, keyId, orgId } from "../harness/people.mjs";

export const meta = {
  id: "E2E-service-policy",
  title: "one org service policy, native npm/pip reads, remembered outage and durable refusal",
  suites: ["pr", "nightly", "release"],
  stack: "own",
};

export default async function servicePolicy(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service PyPI", ecosystem: "pypi", target_url: "https://pypi.org/",
  })).status === 303, "service org owns its PyPI registry");
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "shared-service", attach: "org" });
  h.expect(issued.status === 200, "org service key issued");
  const key = h.between(issued.body, '<code id="new-key">', "</code>");
  h.expect(key?.startsWith("prb_"), "service key exists");
  const npmName = h.unique("token-private");
  const centralDenied = h.unique("central-denied");
  const wheelName = h.unique("service-wheel");
  await h.fakes.publishNpm({ name: npmName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: centralDenied, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishPypi({ name: wheelName, version: "1.0.0", ageSeconds: 400 * 86_400, kinds: ["wheel"] });
  const root = "https://fw-standalone.e2e.test";
  const blocklistPath = join(h.stack.work, "producer", "blocklist.json");
  const localPolicy = JSON.parse(readFileSync(blocklistPath, "utf8"));
  localPolicy.revision += 1;
  localPolicy.blocked_packages.push({ ecosystem: "npm", name: npmName, version: null, reason: "standalone-only control" });
  writeFileSync(blocklistPath, JSON.stringify(localPolicy));
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  h.expect((await h.request(`${root}/npm/${npmName}/1.0.0`)).status === 403, "explicit standalone control applies local deny");
  h.expect((await h.request(`${root}/npm/${centralDenied}/1.0.0`)).status === 200, "standalone allows the future centrally denied package");
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", what: "package", name: centralDenied, version: "", reason: "central service policy control" });
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${key}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");

  h.expect((await h.request(`${root}/npm/${centralDenied}/1.0.0`)).status === 403, "service applies central deny despite permissive local policy");
  const npmrc = `registry=${root}/npm/\ncafile=/e2e/ca/ca.pem\n`;
  const pipConf = `[global]\nindex-url = ${root}/pypi/simple/\ncert = /e2e/ca/ca.pem\ndisable-pip-version-check = true\n`;
  let result = h.npm(`install ${npmName}@1.0.0 --cache "$PWD/cache" --no-audit --no-fund`, { npmrc });
  h.expect(result.status === 0, `npm without Probation login: ${result.stderr}`);
  result = h.pip(`install --no-cache-dir --target t ${wheelName}==1.0.0`, { pipConf });
  h.expect(result.status === 0, `pip without Probation login: ${result.stderr}`);
  const ownerNpmrc = `${npmrc}//fw-standalone.e2e.test/:_authToken=e2e-owner\n`;
  result = h.npm(`install ${npmName}@1.0.0 --cache "$PWD/cache" --no-audit --no-fund`, { npmrc: ownerNpmrc });
  h.expect(result.status === 0, `package-manager credential accepted independently: ${result.stderr}`);
  const denied = await h.request(`${root}/npm/${npmName}`, { headers: { authorization: "Bearer e2e-denied" } });
  h.expect(denied.status === 403, "warm allowed metadata cannot authorize a denied registry credential");
  const traces = (await h.fakes.requests("registry.npmjs.org")).filter(row => row.path.includes(npmName));
  h.expect(traces.some(row => row.credential === "developer-owner"), "selected upstream receives package-manager credential");
  h.expect(traces.every(row => ["none", "developer-owner", "developer-denied"].includes(row.credential)), "service key never reaches package upstream");
  const beforeUnknown = traces.length;
  h.expect((await h.request(`${root}/registry/npm/999999999/${npmName}`)).status === 404, "unknown registry has no fallback");
  h.expect((await h.fakes.requests("registry.npmjs.org")).filter(row => row.path.includes(npmName)).length === beforeUnknown, "unknown registry sends no upstream request");

  // Keep the fixed backend address reserved: Podman can otherwise hand a stopped
  // server's address to the recreated firewall. A paused server cannot answer polls.
  const policyServer = h.stack.container("server");
  h.stack.compose(["pause", "server"]);
  try {
    const inspected = spawnSync(h.stack.engine, ["inspect", policyServer], { encoding: "utf8" });
    h.expect(inspected.status === 0, "policy server state can be inspected");
    h.expect(JSON.parse(inspected.stdout)[0].State.Status === "paused", "policy server is actually paused during the outage");
    h.restart("firewall-standalone");
    await h.stack.firewallReady("fw-standalone");
    h.expect((await h.request(`${root}/npm/${npmName}`)).status === 200, "restart during outage retains matching remembered authority");
    h.expect((await h.request(`${root}/npm/${centralDenied}/1.0.0`)).status === 403, "central deny survives outage and restart without standalone fallback");
  } finally {
    h.stack.compose(["unpause", "server"]);
  }
  await h.waitFor("policy server recovers", async () => (await h.request("https://portal.e2e.test/signin")).status === 200, { timeout: 60_000 });
  await act(admin.portal, "/keys", `/keys/${await keyId(admin.portal, "shared-service")}/revoke`);
  await h.waitFor("explicit service refusal closes package reads", async () => (await h.request(`${root}/npm/${npmName}`)).status === 503, { timeout: 30_000 });
  h.restart("firewall-standalone");
  await h.waitFor("refusal survives restart", async () => (await h.request(`${root}/pypi/simple/${wheelName}/`)).status === 503, { timeout: 30_000 });
}
