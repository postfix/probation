import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";
import { ops } from "../harness/ops.mjs";
import { activateIssuerFor, installIssuerLeaf } from "../harness/issuer-setup.mjs";

export const meta = { id: "E2E-publishing-uv", title: "selected uv project and pip modes", suites: ["release"] };

export default async function publishingUv(h, { selfServiceDisabled = false, organizationIssued = false } = {}) {
  h.expect(!(selfServiceDisabled && organizationIssued), "uv matrix uses one certificate mode at a time");
  const version = h.stack.exec("client-uv", ["uv", "--version"]);
  h.expect(version.status === 0 && version.stdout.includes("0.13.5"), `uv pinned 0.13.5: ${version.stdout}`);
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "UV selected", ecosystem: "pypi", target_url: "https://pypi.org/",
  })).status === 303, "uv selected registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) UV selected pypi/)?.[1];
  h.expect(id, "uv registry ID");
  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200 && h.stack.exec("client-uv", ["sh"], { input: bundle.body }).status === 0, "uv certificate setup");
  if (selfServiceDisabled) {
    const issued = h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`);
    h.stack.sql(`UPDATE registry_certificate_providers SET self_service = false WHERE org_id = ${Number(org)}`);
    h.expect((await admin.portal.get("/certificates/setup")).status === 403,
      "disabled uv self-service hides a new setup bundle");
    h.expect((await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404
      && h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`) === issued,
      "disabled uv self-service issues no new certificate");
  }
  if (organizationIssued) {
    const { live } = await activateIssuerFor(h, admin, org);
    installIssuerLeaf(h, "client-uv", live);
    h.expect((await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404,
      "organization issuer creates no new uv self-service bundle");
  }
  const name = h.unique("uv-selected");
  await h.fakes.publishPypi({ name, version: "1.0.0", ageSeconds: 400 * 86_400, kinds: ["wheel"], origin: "https://pypi.org" });
  const dir = `/work/${h.unique("uv-project")}`;
  const env = `. "$HOME/.config/probation/python-env.sh"; export SSL_CERT_FILE=/e2e/ca/ca.pem UV_CACHE_DIR=$PWD/.uv-cache;`;
  const project = `[project]\nname = "uv-client-e2e"\nversion = "0.1.0"\nrequires-python = ">=3.12"\ndependencies = ["${name}==1.0.0"]\n`;
  const lock = h.client("client-uv", `${env} uv lock && uv sync`, { dir, files: { "pyproject.toml": project } });
  h.expect(lock.status === 0, `uv lock and sync: ${lock.stderr}`);
  const contents = h.stack.exec("client-uv", ["cat", `${dir}/uv.lock`]);
  h.expect(contents.status === 0 && contents.stdout.includes(`https://fw1.e2e.test/registry/pypi/${id}/`)
    && !contents.stdout.includes("PRIVATE KEY") && !contents.stdout.includes("client.pem") && !contents.stdout.includes("e2e-owner"),
    "uv.lock contains selected nonsecret URL and no credential");
  const pip = h.client("client-uv", `${env} uv venv .venv && uv pip install -p .venv ${name}==1.0.0`);
  h.expect(pip.status === 0, `uv pip install: ${pip.stderr}`);
  const history = h.stack.exec("client-uv", ["sh", "-c",
    "grep -l -E 'PRIVATE KEY|client.pem|e2e-owner' /root/.bash_history /root/.ash_history /root/.sh_history 2>/dev/null || true"]);
  h.expect(history.status === 0 && history.stdout.trim() === "", "uv shell history contains no client key or publisher token");
  const keyMarker = bundle.body.match(/-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=]{24})/)?.[1];
  h.expect(keyMarker, "uv setup bundle contains a client key for log leakage check");
  const serviceLogs = ["server", "gateway", "firewall-1", "firewall-2"].map((service) => h.stack.logs(service)).join("\n");
  h.expect(!serviceLogs.includes(keyMarker) && !serviceLogs.includes("e2e-owner"),
    "uv setup key and publisher token are absent from service logs");
  const networks = Object.keys(ops(h).inspect(ops(h).id("client-uv")).NetworkSettings.Networks);
  h.expect(networks.length === 1 && networks[0] === `${h.stack.project}_clients`, "uv uses only client network");

}
