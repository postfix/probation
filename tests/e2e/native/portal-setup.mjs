// The real server's catalog for the native stack, made through its portal as an administrator would: an npm registry at
// https://127.0.0.1:<npmPort>/ and a PyPI registry at https://pypi.org/, each with an operator-approved private-egress
// entry for 127.0.0.1/32, one throwaway service key, and a policy block that hides one package. Everything is created
// at run time. Used by the container scenario and by the tunnel scenario.
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export async function setupRealCatalog(h, { npmPort, keyName }) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const targets = [["Native npm", "npm", `https://127.0.0.1:${npmPort}/`], ["Native PyPI", "pypi", "https://pypi.org/"]];
  for (const [name, ecosystem, target_url] of targets) {
    const catalog = await admin.portal.get(`/org/${org}/registries`);
    const added = await admin.portal.post(`/org/${org}/registries`, { csrf: hidden(catalog.body, "csrf"), name, ecosystem, target_url });
    h.expect(added.status === 303, `${name} registry saved: ${added.status}\n${added.body}`);
  }
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  const npmId = catalog.body.match(/<li>(\d+) Native npm npm/)?.[1];
  const pypiId = catalog.body.match(/<li>(\d+) Native PyPI pypi/)?.[1];
  h.expect(npmId && pypiId, "both registries have selected IDs");
  for (const [, , target_url] of targets) {
    const page = await admin.portal.get(`/org/${org}/registries`);
    const requested = await admin.portal.post(`/org/${org}/private-egress`, { csrf: hidden(page.body, "csrf"), purpose: "registry", target_url, cidr: "127.0.0.1/32" });
    h.expect(requested.status === 303, `private egress for ${target_url} requested: ${requested.status}\n${requested.body}`);
  }
  const approvals = h.stack.sql(`SELECT id FROM registry_private_egress WHERE org_id = ${Number(org)} AND purpose = 'registry' AND cidr = '127.0.0.1/32'::cidr ORDER BY id`).split("\n").filter(Boolean);
  h.expect(approvals.length === 2, `two exact loopback approvals requested: ${approvals}`);
  for (const id of approvals) {
    const queue = await h.operator.portal.get("/admin/private-egress");
    const approved = await h.operator.portal.post(`/admin/private-egress/${id}/approve`, { csrf: hidden(queue.body, "csrf") });
    h.expect(approved.status === 303, `operator approved ${id}: ${approved.status}`);
  }
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: keyName, attach: "org" });
  h.expect(issued.status === 200, "service policy key issued");
  const key = h.between(issued.body, '<code id="new-key">', "</code>");
  const hiddenName = h.unique("token-private");
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", what: "package", name: hiddenName, version: "", reason: "native token-packument control" });
  return { admin, org, npmId: Number(npmId), pypiId: Number(pypiId), key, hiddenName };
}
