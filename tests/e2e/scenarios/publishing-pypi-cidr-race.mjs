// A paused multipart upload keeps the admitted private destination live while
// the operator withdraws its exact CIDR approval. The final body chunk must not
// cause an upstream POST after that withdrawal.
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";
import { ops } from "../harness/ops.mjs";
import { waitFor } from "../harness/stack.mjs";

export const meta = {
  id: "E2E-publishing-pypi-cidr-race",
  title: "streamed PyPI upload rechecks private destination approval",
  suites: ["release"],
  stack: "own",
};

const UPLOAD = `
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import https from "node:https";
const boundary = "e2e-pypi-private-cidr";
const body = Buffer.from([
  '--' + boundary + '\\r\\nContent-Disposition: form-data; name="name"\\r\\n\\r\\nprivate-cidr-race\\r\\n',
  '--' + boundary + '\\r\\nContent-Disposition: form-data; name="version"\\r\\n\\r\\n1.0.0\\r\\n',
  '--' + boundary + '\\r\\nContent-Disposition: form-data; name="content"; filename="private-cidr-race-1.0.0.tar.gz"\\r\\nContent-Type: application/octet-stream\\r\\n\\r\\npackage bytes\\r\\n',
  '--' + boundary + '--\\r\\n',
].join(''));
const paused = process.argv[3] === "pause";
const headers = {
  authorization: "Basic " + Buffer.from("__token__:e2e-owner").toString("base64"),
  "content-type": "multipart/form-data; boundary=" + boundary,
  "content-length": String(body.length),
};
if (paused) headers.expect = "100-continue";
const request = https.request(process.argv[2], {
  method: "POST", headers, ca: readFileSync("/e2e/ca/ca.pem"),
  cert: readFileSync(process.env.HOME + "/.config/probation/client-cert.pem"),
  key: readFileSync(process.env.HOME + "/.config/probation/client-key.pem"),
  timeout: 30_000,
}, (response) => {
  response.resume();
  response.on("end", () => console.log("STATUS=" + response.statusCode));
});
request.on("error", (error) => { console.error(error.message); process.exitCode = 2; });
request.on("timeout", () => request.destroy(new Error("streamed upload timed out")));
if (paused) {
  request.on("continue", () => {
    const cut = Math.floor(body.length / 2);
    request.write(body.subarray(0, cut));
    writeFileSync("ready", "body held after 100-continue\\n");
    const timer = setInterval(() => {
      if (!existsSync("release")) return;
      clearInterval(timer);
      request.end(body.subarray(cut));
    }, 20);
  });
  request.flushHeaders();
} else request.end(body);
`;

export default async function pypiPrivateCidrRace(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const target = "https://private-registry.e2e.test/";
  const page = await admin.portal.get(`/org/${org}/registries`);
  const added = await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(page.body, "csrf"), name: "Private Python", ecosystem: "pypi", target_url: target,
  });
  h.expect(added.status === 303, `private PyPI registry saved: ${added.status}`);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  const registry = catalog.body.match(/<li>(\d+) Private Python pypi/)?.[1];
  h.expect(registry, "private PyPI registry has a selected ID");
  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200, `private PyPI client bundle issued: ${bundle.status}`);
  const installed = h.stack.exec("client-npm", ["sh"], { input: bundle.body });
  h.expect(installed.status === 0, `private PyPI client bundle installed: ${installed.stderr}`);

  const requested = await admin.portal.post(`/org/${org}/private-egress`, {
    csrf: hidden(catalog.body, "csrf"), purpose: "registry", target_url: target, cidr: "10.77.0.2/32",
  });
  h.expect(requested.status === 303, `private PyPI CIDR request saved: ${requested.status}`);
  const approval = Number(h.stack.sql(`SELECT id FROM registry_private_egress WHERE org_id = ${Number(org)} AND purpose = 'registry' AND host = 'private-registry.e2e.test' AND cidr = '10.77.0.2/32'::cidr`));
  h.expect(Number.isInteger(approval) && approval > 0, "exact private PyPI approval ID selected");
  const queue = await h.operator.portal.get("/admin/private-egress");
  const approved = await h.operator.portal.post(`/admin/private-egress/${approval}/approve`, {
    csrf: hidden(queue.body, "csrf"),
  });
  h.expect(approved.status === 303, `operator approved exact private PyPI CIDR: ${approved.status}`);

  const url = `https://fw1.e2e.test/registry/pypi/${registry}/`;
  const dir = `/work/${h.unique("pypi-cidr-race")}`;
  const retained = h.client("client-npm", `node upload.mjs '${url}' normal`, { dir, files: { "upload.mjs": UPLOAD } });
  h.expect(retained.status === 0 && retained.stdout.includes("STATUS=200"),
    `retained private CIDR approval permits upload: ${retained.status} ${retained.stdout} ${retained.stderr}`);
  const upstream = () => h.fakes.requests("private-registry.e2e.test");
  const before = (await upstream()).filter((request) => request.method === "POST" && request.path === "/").length;
  h.expect(before === 1, `retained approval caused exactly one private PyPI upstream POST: ${before}`);

  const background = ops(h).background("client-npm", `node upload.mjs '${url}' pause`, {
    dir, files: { "upload.mjs": UPLOAD },
  });
  await waitFor("streamed PyPI upload held after admission", () =>
    h.stack.exec("client-npm", ["test", "-f", `${dir}/ready`]).status === 0,
  { timeout: 30_000, every: 100 });
  h.expect((await upstream()).filter((request) => request.method === "POST" && request.path === "/").length === before,
    "held multipart body has not reached private PyPI upstream");
  // The portal currently approves but does not expose a withdrawal route. This
  // scoped SQL deletion simulates the operator withdrawing that exact approval.
  h.stack.sql(`DELETE FROM registry_private_egress WHERE id = ${approval} AND org_id = ${Number(org)} AND purpose = 'registry' AND host = 'private-registry.e2e.test'`);
  h.expect(h.stack.sql(`SELECT count(*) FROM registry_private_egress WHERE id = ${approval}`) === "0",
    "operator's exact private CIDR approval is withdrawn while the upload body is held");
  h.stack.exec("client-npm", ["touch", `${dir}/release`]);
  const raced = await background;
  const after = (await upstream()).filter((request) => request.method === "POST" && request.path === "/").length;
  h.expect(raced.status === 0 && raced.stdout.includes("STATUS=503") && after === before,
    `withdrawn private CIDR refuses streamed upload before upstream POST: status=${raced.status} stdout=${raced.stdout} stderr=${raced.stderr} upstream=${before}->${after}`);
}
