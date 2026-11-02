import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";
import { addressOf, ops } from "../harness/ops.mjs";
import { activateIssuerFor, installIssuerLeaf } from "../harness/issuer-setup.mjs";

export const meta = { id: "E2E-publishing-python", title: "selected pip and Twine workflows", suites: ["release"] };

export default async function publishingPython(h, { selfServiceDisabled = false, organizationIssued = false } = {}) {
  h.expect(!(selfServiceDisabled && organizationIssued), "Python matrix uses one certificate mode at a time");
  for (const [service, command, version] of [["client-pip", "pip --version", "26.2.2"], ["client-twine", "twine --version", "7.0.0"]]) {
    const result = h.stack.exec(service, ["sh", "-c", command]);
    h.expect(result.status === 0 && result.stdout.includes(version), `${service} pinned ${version}: ${result.stdout} ${result.stderr}`);
  }
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  const added = await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Python selected", ecosystem: "pypi", target_url: "https://pypi.org/",
  });
  h.expect(added.status === 303, `Python registry added: ${added.status}`);
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Python selected pypi/)?.[1];
  h.expect(id, "Python registry has an ID");
  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200 && bundle.body.includes(`registry/pypi/${id}/`), "bundle names selected Python URL");
  for (const service of ["client-pip", "client-twine"]) {
    const installed = h.stack.exec(service, ["sh"], { input: bundle.body });
    h.expect(installed.status === 0, `${service} setup: ${installed.stderr}`);
  }
  if (selfServiceDisabled) {
    const issued = h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`);
    h.stack.sql(`UPDATE registry_certificate_providers SET self_service = false WHERE org_id = ${Number(org)}`);
    h.expect((await admin.portal.get("/certificates/setup")).status === 403,
      "disabled Python self-service hides a new setup bundle");
    h.expect((await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404
      && h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`) === issued,
    "disabled Python self-service issues no new certificate");
  }
  if (organizationIssued) {
    const { live } = await activateIssuerFor(h, admin, org);
    for (const service of ["client-pip", "client-twine"]) installIssuerLeaf(h, service, live);
    h.expect((await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404,
      "organization issuer creates no new Python self-service bundle");
  }
  const npmId = bundle.body.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  h.expect(npmId && npmId !== id, "npm and Python registry IDs differ");
  const admissionProbe = `import os, ssl, sys, urllib.error, urllib.request
ctx = ssl.create_default_context(cafile="/e2e/ca/ca.pem")
ctx.load_cert_chain(os.path.expanduser("~/.config/probation/client.pem"))
try:
    with urllib.request.urlopen(sys.argv[1], context=ctx) as response:
        print(response.status)
except urllib.error.HTTPError as error:
    print(error.code)
`;
  const beforeWrong = (await h.fakes.requests("pypi.org")).length;
  const wrong = h.client("client-pip", `python probe.py https://fw1.e2e.test/registry/pypi/${npmId}/simple/e2e-left/`,
    { files: { "probe.py": admissionProbe } });
  h.expect(wrong.status === 0 && wrong.stdout.trim() === "401", `npm ID cannot select Python route: ${wrong.stdout} ${wrong.stderr}`);
  h.expect((await h.fakes.requests("pypi.org")).length === beforeWrong, "wrong ecosystem refuses before upstream I/O");
  const name = h.unique("python-selected");
  await h.fakes.publishPypi({ name, version: "1.0.0", ageSeconds: 400 * 86_400, kinds: ["wheel", "sdist"], backend: "intree", origin: "https://pypi.org" });
  const env = `. "$HOME/.config/probation/python-env.sh"; export PIP_CERT=/e2e/ca/ca.pem;`;
  const versions = h.client("client-pip", `${env} pip index versions ${name} --disable-pip-version-check`);
  h.expect(versions.status === 0 && versions.stdout.includes("1.0.0"), `pip index versions: ${versions.stderr}`);
  const pipDir = `/work/${h.unique("pip-install")}`;
  const wheel = h.client("client-pip", `${env} pip install --no-deps --no-cache-dir --target site ${name}==1.0.0`, { dir: pipDir });
  h.expect(wheel.status === 0, `pip wheel install: ${wheel.stderr}`);
  const sdist = h.client("client-pip", `${env} pip install --no-deps --no-cache-dir --no-binary=:all: --no-build-isolation --target sdist-site ${name}==1.0.0`, { dir: pipDir });
  h.expect(sdist.status === 0, `pip sdist install: ${sdist.stderr}`);
  const fetchDistributions = `
import json, os, ssl, urllib.request
ctx = ssl.create_default_context(cafile="/e2e/ca/ca.pem")
ctx.load_cert_chain(os.path.expanduser("~/.config/probation/client.pem"))
request = urllib.request.Request(os.environ["PIP_INDEX_URL"] + os.environ["PROJECT"] + "/",
    headers={"Accept": "application/vnd.pypi.simple.v1+json"})
with urllib.request.urlopen(request, context=ctx) as response:
    files = json.load(response)["files"]
os.makedirs("dist", exist_ok=True)
for file in files:
    with urllib.request.urlopen(file["url"], context=ctx) as response:
        data = response.read()
    with open("dist/" + file["filename"], "wb") as output:
        output.write(data)
`;
  const twineDir = `/work/${h.unique("twine-upload")}`;
  const fetched = h.client("client-twine", `${env} PROJECT=${name} python -c '${fetchDistributions}'`, { dir: twineDir });
  h.expect(fetched.status === 0, `Twine distributions fetched through selected URL: ${fetched.stderr}`);
  const uploaded = h.client("client-twine", `${env} TWINE_USERNAME=__token__ TWINE_PASSWORD=e2e-owner TWINE_CERT=/e2e/ca/ca.pem twine upload --non-interactive dist/*`, { dir: twineDir });
  if (uploaded.status !== 0) {
    const trace = (await h.fakes.requests("pypi.org"))
      .filter((request) => request.method === "POST")
      .map(({ path, status, fault }) => ({ path, status, fault }));
    h.expect(false, `Twine wheel and sdist upload exited ${uploaded.status}: stdout=${uploaded.stdout.slice(-2000)} stderr=${uploaded.stderr.slice(-2000)} upstream=${JSON.stringify(trace)}`);
  }
  h.expect(uploaded.status === 0, "Twine wheel and sdist upload succeeded through selected URL");
  const denied = h.client("client-twine", `${env} TWINE_USERNAME=__token__ TWINE_PASSWORD=e2e-denied TWINE_CERT=/e2e/ca/ca.pem twine upload --non-interactive dist/*`, { dir: twineDir });
  h.expect(denied.status !== 0 && `${denied.stdout}\n${denied.stderr}`.includes("403"),
    `upstream denied Twine upload: stdout=${denied.stdout.slice(-2000)} stderr=${denied.stderr.slice(-2000)}`);
  const uploadTrace = await h.fakes.requests("pypi.org");
  h.expect(uploadTrace.filter((r) => r.method === "POST" && r.path === "/").length >= 3
    && uploadTrace.some((r) => r.method === "POST" && r.status === 403),
    "Twine sends two selected uploads and preserves upstream denial");
  const scan = h.client("client-pip", `! grep -R -E 'PRIVATE KEY|e2e-owner|client.pem' site sdist-site`, { dir: pipDir });
  h.expect(scan.status === 0, "Python project files do not contain client key paths or publisher token");
  const twineScan = h.client("client-twine", `! grep -R -E 'PRIVATE KEY|e2e-owner|client.pem' .`, { dir: twineDir });
  h.expect(twineScan.status === 0, "Twine project files do not contain client key paths or publisher token");
  for (const service of ["client-pip", "client-twine"]) {
    const history = h.stack.exec(service, ["sh", "-c",
      "grep -l -E 'PRIVATE KEY|client.pem|e2e-owner' /root/.bash_history /root/.ash_history /root/.sh_history 2>/dev/null || true"]);
    h.expect(history.status === 0 && history.stdout.trim() === "",
      `${service} shell history contains no client key, key path or publisher token`);
  }
  const keyMarker = bundle.body.match(/-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=]{24})/)?.[1];
  h.expect(keyMarker, "Python setup bundle contains a client key for log leakage check");
  const serviceLogs = ["server", "gateway", "firewall-1", "firewall-2"].map((service) => h.stack.logs(service)).join("\n");
  h.expect(!serviceLogs.includes(keyMarker) && !serviceLogs.includes("e2e-owner"),
    "Python setup key and publisher token are absent from service logs");
  for (const service of ["client-pip", "client-twine"]) {
    const networks = Object.keys(ops(h).inspect(ops(h).id(service)).NetworkSettings.Networks);
    h.expect(networks.length === 1 && networks[0] === `${h.stack.project}_clients`, `${service} uses only client network`);
    const directScript = `import socket
try:
    socket.create_connection(("pypi.org", 443), timeout=3)
    raise SystemExit(1)
except Exception:
    raise SystemExit(0)
`;
    const direct = h.stack.exec(service, ["python", "-c", directScript]);
    h.expect(direct.status === 0, `${service} cannot connect to upstream directly`);
  }
  const reads = await h.fakes.requests("pypi.org");
  h.expect(reads.some((r) => r.path === `/simple/${name}/`) && reads.some((r) => r.path.startsWith("/packages/")),
    "pip used selected Simple metadata and artifact bytes");
  const firewallPeer = addressOf(h.stack, "firewall-1");
  const upstreamTrace = (await h.fakes.requests()).filter((r) => ["pypi.org", "files.pythonhosted.org"].includes(r.host));
  h.expect(upstreamTrace.length > 0 && upstreamTrace.every((r) => r.peer?.replace(/^::ffff:/, "") === firewallPeer),
    `Python upstream requests came only from firewall peer ${firewallPeer}: ${JSON.stringify(upstreamTrace.map((r) => ({ host: r.host, peer: r.peer })))}`);
  h.log(`Python upstream peer ${firewallPeer}, ${upstreamTrace.length} selected requests`);
  if (!selfServiceDisabled && !organizationIssued) {
    const onlyAdmin = await h.signUp({ kind: "org" });
    await h.enableTotp(onlyAdmin);
    const onlyOrg = await orgId(onlyAdmin.portal);
    const onlyCatalog = await onlyAdmin.portal.get(`/org/${onlyOrg}/registries`);
    const onlyAdded = await onlyAdmin.portal.post(`/org/${onlyOrg}/registries`, {
      csrf: hidden(onlyCatalog.body, "csrf"), name: "PyPI only", ecosystem: "pypi", target_url: "https://pypi.org/",
    });
    h.expect(onlyAdded.status === 303, `PyPI-only registry created: ${onlyAdded.status}`);
    const npmIds = h.stack.sql(`SELECT id FROM registries WHERE org_id = ${Number(onlyOrg)} AND ecosystem = 'npm' AND removed_at IS NULL`).split("\n").filter(Boolean);
    for (const npmId of npmIds) {
      const page = await onlyAdmin.portal.get(`/org/${onlyOrg}/registries`);
      const removed = await onlyAdmin.portal.post(`/org/${onlyOrg}/registries/${npmId}/remove`, { csrf: hidden(page.body, "csrf") });
      h.expect(removed.status === 303, `PyPI-only organization removed npm registry ${npmId}: ${removed.status}`);
    }
    h.expect(h.stack.sql(`SELECT count(*) FROM registries WHERE org_id = ${Number(onlyOrg)} AND ecosystem = 'npm' AND removed_at IS NULL`) === "0",
      "PyPI-only organization has no active npm registry");
    const onlySetup = await onlyAdmin.portal.get("/certificates/setup");
    const onlyBundle = await onlyAdmin.portal.post("/certificates/setup", { csrf: hidden(onlySetup.body, "csrf") });
    h.expect(onlyBundle.status === 200 && onlyBundle.body.includes("registry/pypi/")
      && !onlyBundle.body.includes("registry=https://") && !onlyBundle.body.includes("PROBATION_NPM"),
      `PyPI-only organization receives a working bundle without npm: ${onlyBundle.status}`);
    const onlyInstall = h.stack.exec("client-pip", ["sh"], { input: onlyBundle.body });
    const onlyRead = h.client("client-pip", `${env} pip index versions ${name} --disable-pip-version-check`);
    h.expect(onlyInstall.status === 0 && onlyRead.status === 0 && onlyRead.stdout.includes("1.0.0"),
      `PyPI-only bundle admits pip through selected registry: ${onlyInstall.stderr} ${onlyRead.stderr}`);
  }
}
