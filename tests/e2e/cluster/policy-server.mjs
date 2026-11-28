// The policy server of the kind lane's "pull secret through the Probation endpoint" check (LANE=cluster, run-kind-lane.sh).
//
//   node tests/e2e/cluster/policy-server.mjs up   --work DIR --registry-host private.kind.test:5000 --registry-cidr 172.18.0.9/32 --out policy.json
//   node tests/e2e/cluster/policy-server.mjs down --work DIR
//
// It reuses the e2e harness (tests/e2e/harness) and does what scenarios/service-cluster.mjs does before it points a service at the stack: the
// compose stack's policy server (postgres, gateway, mail sink, bridge, the fakes the portal's sign-up needs, the server), an organisation admin with an
// authenticator, an OCI registry whose target is the private registry (a private address, so an operator approves its exact host, port and address),
// the policy that lets a fresh image through, and a service key. Nothing is re-implemented: `PolicyStack` only leaves out what this lane never uses (the
// firewalls and the client containers); the sign-up, TOTP, policy and key steps are the harness's own `helpers`.
// `up` leaves the stack running and writes {registryId, serviceKey, ca, project, gateway}; `down` removes it.
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Stack } from "../harness/stack.mjs";
import { helpers } from "../harness/helpers.mjs";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";
import { changePlatform } from "../harness/portal-steps.mjs";

const PROJECT = "probation-kind-policy";

/// The harness stack without the services this lane does not use: `start` skips the firewalls and the clients, the images of the clients are not built
/// (the server image is built by the workflow: E2E_PREBUILT), and there is no firewall to wait for.
class PolicyStack extends Stack {
  start(...services) {
    const wanted = services.filter((name) => !name.startsWith("firewall-") && !name.startsWith("client-"));
    if (wanted.length) super.start(...wanted); // `compose up` with no service names would start every service
  }

  build() {}

  async firewallReady() {}
}

const args = Object.fromEntries(process.argv.slice(3).reduce((pairs, word, at, all) => (word.startsWith("--") ? [...pairs, [word.slice(2), all[at + 1]]] : pairs), []));
const work = resolve(args.work ?? "");
const stack = new PolicyStack({ work, project: PROJECT, net: process.env.E2E_NET ?? "11.220.0", bridgePort: Number(process.env.E2E_BRIDGE_PORT ?? 18128) });

if (process.argv[2] === "down") {
  stack.down();
  process.exit(0);
}
if (process.argv[2] !== "up" || !args.work || !args["registry-host"] || !args["registry-cidr"] || !args.out) {
  console.error("usage: policy-server.mjs up --work DIR --registry-host HOST:PORT --registry-cidr CIDR --out FILE | down --work DIR");
  process.exit(2);
}

try {
  mkdirSync(work, { recursive: true });
  await stack.up();
  const h = helpers(stack, { log: (...line) => console.log("[policy-server]", ...line) });
  const { expect } = h;
  await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: true } });
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  // The private registry: a registry of the organisation whose target is the lane's registry. A private address is refused until an operator approves the
  // exact host, port and connected address (the same two steps as scenarios/publishing-enterprise-registry.mjs).
  const target = `https://${args["registry-host"]}/`;
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  const added = await admin.portal.post(`/org/${org}/registries`, { csrf: hidden(catalog.body, "csrf"), name: "Kind private", ecosystem: "oci", target_url: target });
  expect(added.status === 303, `the private registry is added: ${added.status}`);
  const registryId = (await admin.portal.get(`/org/${org}/registries`)).body.match(/<li>(\d+) Kind private oci/)?.[1];
  expect(registryId, "the private registry has an ID");
  const page = await admin.portal.get(`/org/${org}/registries`);
  const asked = await admin.portal.post(`/org/${org}/private-egress`, { csrf: hidden(page.body, "csrf"), purpose: "registry", target_url: target, cidr: args["registry-cidr"] });
  expect(asked.status === 303, `the egress request is accepted: ${asked.status}`);
  const requestId = stack.sql(`SELECT id FROM registry_private_egress WHERE org_id = ${Number(org)} AND purpose = 'registry' AND cidr = '${args["registry-cidr"]}'::cidr ORDER BY id DESC LIMIT 1`);
  const queue = await stack.operator.portal.get("/admin/private-egress");
  expect(queue.status === 200 && requestId, "the operator sees the request");
  const approved = await stack.operator.portal.post(`/admin/private-egress/${requestId}/approve`, { csrf: hidden(queue.body, "csrf") });
  expect(approved.status === 303, `the operator approves the destination: ${approved.status}`);
  await h.editPolicy(admin.portal, { action: "save", freeze: "0", unit: "hours" });
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "kind-service", attach: "org" });
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  expect(serviceKey?.startsWith("prb_"), "the service key is issued");
  const gateway = stack.container("gateway");
  writeFileSync(args.out, JSON.stringify({ registryId, serviceKey, ca: join(work, "ca", "ca.pem"), project: PROJECT, gateway }));
  console.log(`policy-server: up (registry ${registryId}, gateway ${gateway})`);
  process.exit(0);
} catch (error) {
  console.error(`policy-server: ${error.stack ?? error}`);
  try {
    await stack.collect(join(work, "logs"));
  } catch {
    // the logs are best effort
  }
  process.exit(1);
}
