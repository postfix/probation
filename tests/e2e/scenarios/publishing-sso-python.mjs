// A fake OIDC member uses the selected Python registry with the current group policy.
import { hidden } from "../harness/net.mjs";
import { act, memberId, orgId } from "../harness/people.mjs";
import { activateIssuerFor, installIssuerLeaf, issueIssuerLeafFor } from "../harness/issuer-setup.mjs";

export const meta = {
  id: "E2E-publishing-sso-python",
  title: "fake SSO member Python setup and current group policy",
  suites: ["release"],
};

const probe = `import os, ssl, sys, urllib.error, urllib.request
ctx=ssl.create_default_context(cafile="/e2e/ca/ca.pem")
ctx.load_cert_chain(os.path.expanduser("~/.config/probation/client.pem"))
try:
  with urllib.request.urlopen(sys.argv[1], context=ctx) as response: print(response.status)
except urllib.error.HTTPError as error: print(error.code)
`;

export default async function ssoPython(h, { mode = process.env.E2E_SSO_PYTHON_MODE ?? "probation-enabled" } = {}) {
  h.expect(["probation-enabled", "probation-disabled", "organization-issued"].includes(mode),
    `SSO Python certificate mode is selected: ${mode}`);
  const version = h.stack.exec("client-pip", ["pip", "--version"]);
  h.expect(version.status === 0 && version.stdout.includes("26.2.2"),
    `SSO Python pip pinned to 26.2.2: ${version.stdout} ${version.stderr}`);
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  const added = await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "SSO Python", ecosystem: "pypi", target_url: "https://pypi.org/",
  });
  h.expect(added.status === 303, `SSO Python selected registry added: ${added.status}`);
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) SSO Python pypi/)?.[1];
  h.expect(id, "SSO Python registry has an exact ID");
  const sso = await admin.portal.submit(`/org/${org}`, `/org/${org}/sso`, {
    enabled: "on", issuer: "https://idp.e2e.test", client_id: h.unique("sso-py"),
    allowed_tenant: "", client_secret: "e2e-secret",
  });
  h.expect(sso.status === 303, `SSO Python fake OIDC enabled: ${sso.status}`);
  const person = { sub: h.unique("sso-py-member"), email: `${h.unique("sso-py")}@example.com` };
  await h.fakes.oidcNext(person);
  const page = await (await h.browser()).newPage();
  await page.goto(`/o/${admin.org}`);
  h.expect(new URL(page.url()).pathname === "/account", `SSO Python member signs in: ${page.url()}`);
  const member = new h.Portal();
  for (const cookie of await page.context().cookies()) member.cookies.set(cookie.name, cookie.value);
  const memberNumber = await memberId(admin.portal, org, person.email);
  h.expect(memberNumber, "SSO Python member has a current organization membership");
  await act(admin.portal, `/org/${org}`, `/org/${org}/groups`, { name: "Python SSO readers" });
  const group = (await admin.portal.get(`/org/${org}`)).body.match(/href="\/policy\/group-(\d+)" aria-label="Policy of the Python SSO readers group"/)?.[1];
  h.expect(group, "SSO Python member group exists");
  await act(admin.portal, `/org/${org}`, `/org/members/${memberNumber}/group`, { group, role: "member" });
  const allowed = h.unique("sso-py-allowed");
  const blocked = h.unique("sso-py-blocked");
  await h.fakes.publishPypi({ name: allowed, version: "1.0.0", ageSeconds: 400 * 86_400,
    kinds: ["wheel"], backend: "intree", origin: "https://pypi.org" });
  await h.fakes.publishPypi({ name: blocked, version: "1.0.0", ageSeconds: 400 * 86_400,
    kinds: ["wheel"], backend: "intree", origin: "https://pypi.org" });
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "pypi", name: blocked,
    what: "package" }, `/policy/group-${group}`);
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: "e2e-right",
    what: "package" }, `/policy/group-${group}`);
  const setup = await member.get("/certificates/setup");
  h.expect(setup.status === 200, `SSO Python member opens own setup: ${setup.status}`);
  const bundle = await member.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200 && bundle.body.includes(`registry/pypi/${id}/`)
    && bundle.headers["cache-control"] === "no-store", "SSO Python member downloads own noncached selected setup bundle");
  const installed = h.stack.exec("client-pip", ["sh"], { input: bundle.body });
  h.expect(installed.status === 0, `SSO Python bundle installs user-local client TLS: ${installed.stderr}`);
  const npmInstalled = h.stack.exec("client-npm", ["sh"], { input: bundle.body });
  h.expect(npmInstalled.status === 0, `SSO member bundle installs selected npm and client TLS: ${npmInstalled.stderr}`);
  if (mode === "probation-disabled") {
    const count = h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`);
    h.stack.sql(`UPDATE registry_certificate_providers SET self_service = false WHERE org_id = ${Number(org)}`);
    h.expect((await member.get("/certificates/setup")).status === 403
      && (await member.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404
      && h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`) === count,
    "SSO Python disabled self-service issues no new bundle");
  }
  if (mode === "organization-issued") {
    await activateIssuerFor(h, admin, org);
    const leaf = await issueIssuerLeafFor(h, org, person.email);
    installIssuerLeaf(h, "client-pip", leaf);
    installIssuerLeaf(h, "client-npm", leaf);
    h.expect((await member.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404,
      "SSO Python organization issuer refuses a new self-service bundle");
  }
  const env = `. "$HOME/.config/probation/python-env.sh"; export PIP_CERT=/e2e/ca/ca.pem;`;
  const project = `/work/${h.unique("sso-py-project")}`;
  const allowedRun = h.client("client-pip", `${env} pip install --no-deps --no-cache-dir --target site ${allowed}==1.0.0`, { dir: project });
  h.expect(allowedRun.status === 0, `SSO Python member pip installs selected allowed bytes (${mode}): ${allowedRun.stderr}`);
  const deniedRun = h.client("client-pip", `${env} pip install --no-deps --no-cache-dir --target denied ${blocked}==1.0.0`, { dir: project });
  h.expect(deniedRun.status !== 0, `SSO Python member's current group blocks pip package (${mode}): ${deniedRun.stderr}`);
  const npmProject = `/work/${h.unique("sso-npm-project")}`;
  const npmAllowed = h.client("client-npm", "npm install e2e-left@1.0.0 --no-audit --no-fund", {
    dir: npmProject, files: { "package.json": JSON.stringify({ name: "sso-member-e2e", version: "1.0.0", private: true }) },
  });
  h.expect(npmAllowed.status === 0, `SSO member npm installs selected allowed bytes (${mode}): ${npmAllowed.stderr}`);
  const npmDenied = h.client("client-npm", "npm install e2e-right@1.0.0 --no-audit --no-fund", { dir: npmProject });
  h.expect(npmDenied.status !== 0, `SSO member's current group blocks npm package (${mode}): ${npmDenied.stderr}`);
  const npmProjectSecrets = h.stack.exec("client-npm", ["sh", "-c",
    `grep -R -l -E 'PRIVATE KEY|client-key.pem|e2e-owner' ${npmProject} || true`]);
  h.expect(npmProjectSecrets.status === 0 && npmProjectSecrets.stdout.trim() === "",
    `SSO npm project files contain no client key, key path or publisher token (${mode}): ${npmProjectSecrets.stdout}`);
  const npmHistorySecrets = h.stack.exec("client-npm", ["sh", "-c",
    "grep -l -E 'PRIVATE KEY|client-key.pem|e2e-owner' /root/.bash_history /root/.ash_history /root/.sh_history 2>/dev/null || true"]);
  h.expect(npmHistorySecrets.status === 0 && npmHistorySecrets.stdout.trim() === "",
    `SSO npm shell history contains no client key, key path or publisher token (${mode}): ${npmHistorySecrets.stdout}`);
  const projectSecrets = h.stack.exec("client-pip", ["sh", "-c",
    `grep -R -l -E 'PRIVATE KEY|client.pem|e2e-owner' ${project} || true`]);
  h.expect(projectSecrets.status === 0 && projectSecrets.stdout.trim() === "",
    `SSO Python project files contain no client key, key path or publisher token (${mode}): ${projectSecrets.stdout}`);
  const historySecrets = h.stack.exec("client-pip", ["sh", "-c",
    `grep -l -E 'PRIVATE KEY|client.pem|e2e-owner' /root/.bash_history /root/.ash_history /root/.sh_history 2>/dev/null || true`]);
  h.expect(historySecrets.status === 0 && historySecrets.stdout.trim() === "",
    `SSO Python shell history contains no client key, key path or publisher token (${mode}): ${historySecrets.stdout}`);
  const keyMarker = bundle.body.match(/-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=]{24})/)?.[1];
  h.expect(keyMarker, "SSO Python setup bundle contains a client key for log leakage check");
  const serviceLogs = ["server", "gateway", "firewall-1", "firewall-2"].map((service) => h.stack.logs(service)).join("\n");
  h.expect(!serviceLogs.includes(keyMarker) && !serviceLogs.includes("e2e-owner"),
    `SSO Python service logs contain no client key or publisher token (${mode})`);
  const url = `https://fw1.e2e.test/registry/pypi/${id}/simple/${allowed}/`;
  const status = (home = "/root") => h.client("client-pip", `HOME=${home} python probe.py '${url}'`, { files: { "probe.py": probe } });
  const own = status();
  h.expect(own.status === 0 && own.stdout.trim() === "200", `SSO Python member certificate selects own registry (${mode}): ${own.stdout} ${own.stderr}`);
  const npmId = bundle.body.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  h.expect(npmId && npmId !== id, "SSO member bundle selects a separate npm registry ID");
  const npmUrl = `https://fw1.e2e.test/registry/npm/${npmId}/e2e-left`;
  const npmProbe = `import https from "node:https";import {readFileSync} from "node:fs";
const home=process.env.HOME;const req=https.get(process.argv[2],{ca:readFileSync("/e2e/ca/ca.pem"),
cert:readFileSync(home+"/.config/probation/client-cert.pem"),key:readFileSync(home+"/.config/probation/client-key.pem")},
res=>{res.resume();res.on("end",()=>console.log(res.statusCode));});
req.on("error",e=>{console.error(e);process.exitCode=2});`;
  const npmStatus = (home = "/root") => h.client("client-npm", `HOME=${home} node sso-npm-probe.mjs '${npmUrl}'`,
    { files: { "sso-npm-probe.mjs": npmProbe } });
  const ownNpm = npmStatus();
  h.expect(ownNpm.status === 0 && ownNpm.stdout.trim() === "200",
    `SSO member npm certificate selects own registry (${mode}): ${ownNpm.stdout} ${ownNpm.stderr}`);
  const other = await h.signUp({ kind: "org" });
  const otherSetup = await other.portal.get("/certificates/setup");
  const otherBundle = await other.portal.post("/certificates/setup", { csrf: hidden(otherSetup.body, "csrf") });
  h.expect(otherBundle.status === 200 && otherBundle.body !== bundle.body,
    "different account receives its own distinct setup bundle, not the SSO member's bundle");
  const foreignHome = `/work/${h.unique("sso-py-foreign")}`;
  const foreignInstall = h.stack.exec("client-pip", ["sh", "-c", `mkdir -p ${foreignHome}; HOME=${foreignHome} sh`], { input: otherBundle.body });
  h.expect(foreignInstall.status === 0, `different account installs its own certificate: ${foreignInstall.stderr}`);
  const foreignNpmInstall = h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${foreignHome}; HOME=${foreignHome} sh`], { input: otherBundle.body });
  h.expect(foreignNpmInstall.status === 0, `different account installs its own npm certificate: ${foreignNpmInstall.stderr}`);
  const combined = h.stack.exec("client-pip", ["sh", "-c",
    `cat ${foreignHome}/.config/probation/client-cert.pem ${foreignHome}/.config/probation/client-key.pem > ${foreignHome}/.config/probation/client.pem`]);
  h.expect(combined.status === 0, `different account has its own Python client certificate: ${combined.stderr}`);
  const packageCalls = async () => (await h.fakes.requests()).filter((request) =>
    ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"].includes(request.host)).length;
  const beforeForeign = await packageCalls();
  const foreign = status(foreignHome);
  h.expect(foreign.status === 0 && foreign.stdout.trim() === "401",
    `different account cannot use SSO member's selected registry (${mode}): ${foreign.stdout} ${foreign.stderr}`);
  const foreignNpm = npmStatus(foreignHome);
  h.expect(foreignNpm.status === 0 && foreignNpm.stdout.trim() === "401",
    `different account cannot use SSO member's selected npm registry (${mode}): ${foreignNpm.stdout} ${foreignNpm.stderr}`);
  h.expect(await packageCalls() === beforeForeign,
    `different account selected npm and pip refusals made zero upstream calls (${mode})`);
  await act(admin.portal, `/org/${org}`, `/org/members/${memberNumber}/remove`);
  h.expect((await member.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status !== 200,
    "removed SSO Python member cannot download another setup bundle");
  const beforeRemoved = await packageCalls();
  const removed = status();
  h.expect(removed.status === 0 && removed.stdout.trim() === "401",
    `removed SSO Python member cannot use the selected certificate (${mode}): ${removed.stdout} ${removed.stderr}`);
  const removedNpm = npmStatus();
  h.expect(removedNpm.status === 0 && removedNpm.stdout.trim() === "401",
    `removed SSO member cannot use selected npm certificate (${mode}): ${removedNpm.stdout} ${removedNpm.stderr}`);
  h.expect(await packageCalls() === beforeRemoved,
    `removed SSO member selected npm and pip refusals made zero upstream calls (${mode})`);
  h.log(`SSO Python ${mode}: fake OIDC, member group, selected npm and pip, cross-account and removed-member refusal`);
}
