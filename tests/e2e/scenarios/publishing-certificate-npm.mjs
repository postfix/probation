// A signed-in member obtains client setup before reaching the package firewall.
import { hidden } from "../harness/net.mjs";
import { act, memberId, orgId } from "../harness/people.mjs";
import { addressOf, editConfig, ops } from "../harness/ops.mjs";

const PROBE = `
import https from "node:https";
import { readFileSync } from "node:fs";
const home = process.env.CERT_HOME;
const options = { ca: readFileSync("/e2e/ca/ca.pem"), servername: "fw1.e2e.test", headers: { "x-client-certificate": "forged-header" } };
if (process.argv[4]) options.headers["x-forwarded-for"] = process.argv[4];
if (home && home !== "none") {
  options.cert = process.env.CERT_MALFORMED ? Buffer.from("not a PEM certificate") : readFileSync(home + "/.config/probation/client-cert.pem");
  options.key = readFileSync(home + "/.config/probation/client-key.pem");
}
const req = https.request(process.argv[2], { ...options, method: process.argv[3] || "GET" }, (res) => {
  const chunks = [];
  res.on("data", (chunk) => chunks.push(chunk));
  res.on("end", () => console.log(process.env.PROBE_BODY
    ? JSON.stringify({ status: res.statusCode, body: Buffer.concat(chunks).toString() })
    : res.statusCode));
});
req.on("error", (error) => { console.error(error.code || error.message); process.exitCode = 2; });
req.end();
`;

const KEEPALIVE = `
import https from "node:https";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
const home = process.env.CERT_HOME;
const agent = new https.Agent({ keepAlive: true, maxSockets: 1, ca: readFileSync("/e2e/ca/ca.pem"),
  cert: readFileSync(home + "/.config/probation/client-cert.pem"),
  key: readFileSync(home + "/.config/probation/client-key.pem") });
const get = () => new Promise((resolve, reject) => {
  const request = https.get(process.argv[2], { agent }, (response) => {
    response.resume();
    response.on("end", () => resolve({ status: response.statusCode, reused: request.reusedSocket }));
  });
  request.on("error", reject);
});
writeFileSync("first.json", JSON.stringify(await get()));
while (!existsSync("next")) await sleep(50);
writeFileSync("second.json", JSON.stringify(await get()));
agent.destroy();
`;

function registry(bundle) {
  const id = bundle.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  if (!id) throw new Error("the bundle did not select the npm registry");
  return id;
}
export const meta = {
  id: "E2E-publishing-certificate-npm",
  title: "member certificate setup and npm install through current group policy",
  suites: ["release"],
};

export default async function certificateNpm(h) {
  const { expect } = h;
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const ssoOn = await admin.portal.submit(`/org/${org}`, `/org/${org}/sso`, {
    enabled: "on", issuer: "https://idp.e2e.test", client_id: h.unique("cert-client"),
    allowed_tenant: "", client_secret: "e2e-secret",
  });
  expect(ssoOn.status === 303, `enable fake SSO: ${ssoOn.status}\n${ssoOn.body}`);
  const person = { sub: h.unique("cert-member"), email: `${h.unique("cert")}@example.com` };
  await h.fakes.oidcNext(person);
  const browser = await (await h.browser()).newPage();
  await browser.goto(`/o/${admin.org}`);
  expect(new URL(browser.url()).pathname === "/account", `fake SSO member sign-in: ${browser.url()}`);
  const member = new h.Portal();
  for (const cookie of await browser.context().cookies()) member.cookies.set(cookie.name, cookie.value);
  const memberNumber = await memberId(admin.portal, org, person.email);
  expect(memberNumber, "the fake SSO member has an organisation membership");

  await act(admin.portal, `/org/${org}`, `/org/${org}/groups`, { name: "Certificate readers" });
  const group = (await admin.portal.get(`/org/${org}`)).body.match(/href="\/policy\/group-(\d+)" aria-label="Policy of the Certificate readers group"/)?.[1];
  expect(group, "the certificate reader group is listed");
  await act(admin.portal, `/org/${org}`, `/org/members/${memberNumber}/group`, { group, role: "member" });

  const page = await member.get("/certificates/setup");
  h.expect(page.status === 200, `signed-in member setup page: ${page.status}`);
  const issue = () => member.post("/certificates/setup", { csrf: hidden(page.body, "csrf") });
  const response = await issue();
  h.expect(response.status === 200, `signed-in member setup bundle: ${response.status}`);
  h.expect(response.headers["cache-control"] === "no-store", "setup bundle must not be cached");
  h.expect(response.body.includes("registry=https://fw1.e2e.test/registry/npm/"),
    "setup bundle selects the distinct npm registry namespace");
  const installed = h.stack.exec("client-npm", ["sh"], { input: response.body });
  h.expect(installed.status === 0, `bundle installs user-local npm settings: ${installed.stderr}`);
  const project = `/work/${h.unique("certificate-project")}`;
  const run = h.client("client-npm", "npm install e2e-left@1.0.0 --no-audit --no-fund && node -p \"require('e2e-left/package.json').version\"", {
    dir: project,
    files: { "package.json": JSON.stringify({ name: "certificate-e2e", version: "1.0.0", private: true }) },
  });
  h.expect(run.status === 0, `certificate npm install: ${run.status}\n${run.stdout}\n${run.stderr}`);
  h.expect(run.stdout.trim().endsWith("1.0.0"), `allowed package bytes installed: ${run.stdout}`);
  const leaked = h.stack.exec("client-npm", ["sh", "-c", `find ${project} -type f \\( -name '*.pem' -o -name '.npmrc' \\) -print; grep -R -l 'BEGIN PRIVATE KEY' ${project} || true`]);
  expect(leaked.status === 0 && leaked.stdout.trim() === "", `no private key in package project: ${leaked.stdout}`);
  const history = h.stack.exec("client-npm", ["sh", "-c",
    "grep -l -E 'PRIVATE KEY|client-key.pem|e2e-owner' /root/.bash_history /root/.ash_history /root/.sh_history 2>/dev/null || true"]);
  expect(history.status === 0 && history.stdout.trim() === "", "npm shell history contains no client key or publisher token");
  const keyMarker = response.body.match(/-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=]{24})/)?.[1];
  expect(keyMarker, "npm setup bundle contains a client key for log leakage check");
  const serviceLogs = ["server", "gateway", "firewall-1", "firewall-2"].map((service) => h.stack.logs(service)).join("\n");
  expect(!serviceLogs.includes(keyMarker) && !serviceLogs.includes("e2e-owner"),
    "npm setup key and publisher token are absent from service logs");

  const registryId = registry(response.body);
  const own = `https://fw1.e2e.test/registry/npm/${registryId}/e2e-left`;
  const probe = (url, home = "/root", method = "GET", forwarded = "") => {
    const result = h.client("client-npm", `CERT_HOME=${home} node probe.mjs '${url}' ${method} '${forwarded}'`, { files: { "probe.mjs": PROBE } });
    expect(result.status === 0, `TLS probe ${url}: ${result.status}\n${result.stderr}`);
    return Number(result.stdout.trim());
  };
  const upstreamCount = async () => (await h.fakes.requests("registry.npmjs.org")).length;
  await h.fakes.publishNpm({ name: "123", version: "1.0.0", ageSeconds: 400 * 86_400 });
  const legacyKey = (await h.createKey(admin.portal)).key;
  const legacy = (path) => h.request(`https://fw1.e2e.test${path}`,
    { headers: { authorization: `Bearer ${legacyKey}` } });
  expect((await legacy("/npm/123/1.0.0")).status === 200,
    "legacy numeric npm package and version remain reachable");
  expect((await legacy("/npm/123/-/123-1.0.0.tgz")).status === 200,
    "legacy numeric npm tarball remains reachable");
  expect(probe(`https://fw1.e2e.test/registry/npm/${registryId}/123`) === 200,
    "selected numeric package is separate from the legacy npm path");
  const scopedVersionUrl = `https://fw1.e2e.test/registry/npm/${registryId}/@e2e%2Fscoped/1.0.0`;
  const scopedVersion = h.client("client-npm", `PROBE_BODY=1 CERT_HOME=/root node probe.mjs '${scopedVersionUrl}'`,
    { files: { "probe.mjs": PROBE } });
  expect(scopedVersion.status === 0, `scoped version probe: ${scopedVersion.stderr}`);
  const scopedAnswer = JSON.parse(scopedVersion.stdout.trim());
  expect(scopedAnswer.status === 200,
    `selected encoded scoped version GET succeeds: ${scopedAnswer.status} ${scopedAnswer.body}`);
  const scopedRecord = JSON.parse(scopedAnswer.body);
  expect(scopedRecord.name === "@e2e/scoped" && scopedRecord.version === "1.0.0",
    "selected scoped version returns the requested record");
  expect(new URL(scopedRecord.dist.tarball).pathname.startsWith(`/registry/npm/${registryId}/artifacts/`),
    "selected scoped version points to its registry artifact route");
  expect(probe(scopedRecord.dist.tarball) === 200, "selected scoped tarball is readable");
  const refuseSelected = async (home, reason) => {
    const before = await upstreamCount();
    for (const [kind, url] of [["package", own], ["encoded version", scopedVersionUrl],
      ["artifact", scopedRecord.dist.tarball]]) {
      expect(probe(url, home) === 401, `${reason} certificate refuses selected ${kind}`);
    }
    expect(await upstreamCount() === before, `${reason} certificate makes zero upstream selected-route requests`);
  };
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: "@e2e/scoped",
    what: "version", version: "1.0.1" }, `/policy/group-${group}`);
  await h.waitFor("blocked selected scoped version", () =>
    probe(`https://fw1.e2e.test/registry/npm/${registryId}/@e2e%2Fscoped/1.0.1`) === 403,
  { timeout: 20_000, every: 250 });
  expect(probe(own) === 200, "the SSO member's certificate admits its registry");
  expect(probe(`https://fw1.e2e.test/registry/npm/${registryId}/e2e-right`) === 200, "group member can read before the policy edit");
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: "e2e-right", what: "package" }, `/policy/group-${group}`);
  expect(probe(`https://fw1.e2e.test/registry/npm/${registryId}/e2e-right`) === 403, "the current group blocks e2e-right");

  const inFlightName = h.unique("inflight-policy");
  const policyMarker = h.unique("policy-marker");
  await h.fakes.publishNpm({ name: inFlightName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: policyMarker, version: "1.0.0", ageSeconds: 400 * 86_400 });
  expect(probe(`https://fw1.e2e.test/registry/npm/${registryId}/${policyMarker}`) === 200, "policy marker is readable before the edit");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${inFlightName}`, method: "GET", mode: "hold", times: 1 }]);
  const inFlight = ops(h).background("client-npm", `PROBE_BODY=1 CERT_HOME=/root node probe.mjs 'https://fw1.e2e.test/registry/npm/${registryId}/${inFlightName}'`, {
    files: { "probe.mjs": PROBE },
  });
  let inFlightAnswer;
  try {
    await h.waitFor("the metadata read to pause upstream", async () =>
      (await h.fakes.requests("registry.npmjs.org")).some((request) => request.path === `/${inFlightName}` && request.fault === "hold" && request.status === 0),
    { timeout: 15_000, every: 100 });
    await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: inFlightName, what: "package" }, `/policy/group-${group}`);
    await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: policyMarker, what: "package" }, `/policy/group-${group}`);
    await h.waitFor("the new group block to reach the firewall", async () =>
      probe(`https://fw1.e2e.test/registry/npm/${registryId}/${policyMarker}`) === 403,
    { timeout: 20_000, every: 250 });
    expect((await h.fakes.requests("registry.npmjs.org")).some((request) =>
      request.path === `/${inFlightName}` && request.fault === "hold" && request.status === 0),
    "metadata is still held after the policy reaches the firewall");
  } finally {
    try {
      const released = await h.request("http://fakes.e2e.test:8080/holds/release", { method: "POST" });
      expect(released.status === 200, `release held metadata: ${released.status}`);
    } finally {
      try {
        await h.fakes.faults([]);
      } finally {
        inFlightAnswer = await inFlight;
      }
    }
  }
  expect(inFlightAnswer.status === 0, `in-flight policy probe: ${inFlightAnswer.status}\n${inFlightAnswer.stderr}`);
  const inFlightResponse = JSON.parse(inFlightAnswer.stdout.trim());
  expect(inFlightResponse.status === 503 && JSON.parse(inFlightResponse.body).error === "POLICY_UNAVAILABLE",
    `held metadata did not fail closed with POLICY_UNAVAILABLE: ${inFlightAnswer.stdout}`);

  let before = await upstreamCount();
  const wrongGet = probe(`https://fw1.e2e.test/registry/npm/${registryId}/-/unknown`);
  expect(wrongGet >= 400 && wrongGet < 500, `unknown npm read route refuses: ${wrongGet}`);
  const wrongPost = probe(own, "/root", "POST");
  expect(wrongPost >= 400 && wrongPost < 500, `npm write route remains closed: ${wrongPost}`);
  expect(await upstreamCount() === before, "unknown and wrong-method npm routes made zero upstream calls");

  await act(admin.portal, `/org/${org}`, `/org/${org}/groups`, { name: "Other certificate readers" });
  const otherGroup = (await admin.portal.get(`/org/${org}`)).body.match(/href="\/policy\/group-(\d+)" aria-label="Policy of the Other certificate readers group"/)?.[1];
  expect(otherGroup, "the other certificate reader group is listed");
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "package" }, `/policy/group-${otherGroup}`);
  const otherPerson = { sub: h.unique("other-member"), email: `${h.unique("other-cert")}@example.com` };
  await h.fakes.oidcNext(otherPerson);
  const otherBrowser = await (await h.browser()).newPage();
  await otherBrowser.goto(`/o/${admin.org}`);
  expect(new URL(otherBrowser.url()).pathname === "/account", `second fake SSO member sign-in: ${otherBrowser.url()}`);
  const otherMember = new h.Portal();
  for (const cookie of await otherBrowser.context().cookies()) otherMember.cookies.set(cookie.name, cookie.value);
  const otherMemberNumber = await memberId(admin.portal, org, otherPerson.email);
  expect(otherMemberNumber, "the second fake SSO member has an organisation membership");
  await act(admin.portal, `/org/${org}`, `/org/members/${otherMemberNumber}/group`, { group: otherGroup, role: "member" });
  const otherSetup = await otherMember.get("/certificates/setup");
  const otherMemberBundle = await otherMember.post("/certificates/setup", { csrf: hidden(otherSetup.body, "csrf") });
  expect(otherMemberBundle.status === 200, `second member's own bundle: ${otherMemberBundle.status}`);
  expect(registry(otherMemberBundle.body) === registryId, "members of one account use the same registry");
  const otherHome = "/work/certificate-other-member";
  const otherInstall = h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${otherHome}; HOME=${otherHome} sh`], { input: otherMemberBundle.body });
  expect(otherInstall.status === 0, `second member certificate setup: ${otherInstall.stderr}`);
  before = await upstreamCount();
  expect(probe(own, otherHome) === 403, "second member's group blocks e2e-left");
  expect(await upstreamCount() === before, "second member's blocked package made zero upstream calls");
  expect(probe(`https://fw1.e2e.test/registry/npm/${registryId}/e2e-right`, otherHome) === 200, "second member's own group allows e2e-right");
  expect(probe(own) === 200, "first member's separate group still allows e2e-left");
  await act(admin.portal, `/org/${org}`, `/org/members/${otherMemberNumber}/remove`);
  before = await upstreamCount();
  expect(probe(`https://fw1.e2e.test/registry/npm/${registryId}/e2e-right`, otherHome) === 401, "removed member's certificate refuses on the next request");
  expect(await upstreamCount() === before, "removed member made zero upstream calls");

  const issuedBefore = Number(h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE membership_id = ${memberNumber}`));
  h.stack.sql(`UPDATE registry_certificate_providers SET self_service = false WHERE org_id = ${org}`);
  expect((await member.get("/certificates/setup")).status === 403, "disabled self-service hides the setup page");
  expect((await issue()).status === 404, "disabled self-service refuses a new bundle");
  expect(Number(h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE membership_id = ${memberNumber}`)) === issuedBefore, "disabled self-service issued no new certificate");
  expect(probe(own) === 200, "existing certificate still works when self-service is disabled");
  h.stack.sql(`UPDATE registry_certificate_providers SET self_service = true WHERE org_id = ${org}`);

  const other = await h.signUp({ kind: "org" });
  const otherPage = await other.portal.get("/certificates/setup");
  const otherBundle = await other.portal.post("/certificates/setup", { csrf: hidden(otherPage.body, "csrf") });
  expect(otherBundle.status === 200, `second account's own bundle: ${otherBundle.status}`);
  const otherRegistry = registry(otherBundle.body);
  expect(otherRegistry !== registryId, "accounts select distinct registry identities");
  const foreignHome = "/work/certificate-foreign-member";
  const foreignInstall = h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${foreignHome}; HOME=${foreignHome} sh`], { input: otherBundle.body });
  expect(foreignInstall.status === 0, `foreign certificate setup: ${foreignInstall.stderr}`);

  const lockedAddress = "203.0.113.55";
  const range = await admin.portal.submit(`/org/${org}`, `/org/${org}/ranges`, { cidr: `${lockedAddress}/32` });
  expect(range.status === 303, `register a protected network: ${range.status}\n${range.body}`);
  const rangesPage = await h.operator.portal.get("/admin");
  const rangeId = rangesPage.body.match(new RegExp(`<code>${lockedAddress.replaceAll(".", "\\.")}/32</code>[\\s\\S]*?action="/admin/ranges/(\\d+)/approve"`))?.[1];
  expect(rangeId, "operator sees the protected network");
  const approved = await h.operator.portal.post(`/admin/ranges/${rangeId}/approve`, { csrf: hidden(rangesPage.body, "csrf") });
  expect(approved.status === 303, `operator approves protected network: ${approved.status}`);
  const direct = `https://firewall-1:8080/registry/npm/${otherRegistry}/e2e-left`;
  const backend = `${h.stack.project}_e2e`;
  const npmContainer = h.stack.container("client-npm");
  ops(h).engine(["network", "connect", backend, npmContainer]);
  try {
    const clientAddress = addressOf(h.stack, "client-npm");
    expect(probe(direct, foreignHome, "GET", lockedAddress) === 200, "an untrusted socket cannot spoof a protected client address");
    editConfig(h.stack, "firewall-1", (config) => config
      .replace(/^trusted_proxies = \[(.*)\]$/m, `trusted_proxies = [$1, "${clientAddress}/32"]`)
      .replace(/^max_active_requests = \d+$/m, "max_active_requests = 1"));
    h.restart("firewall-1");
    await h.firewallReady("fw1");
    await h.waitFor("approved network lock on the firewall", () => probe(direct, foreignHome, "GET", lockedAddress) === 403);
  } finally {
    ops(h).engine(["network", "disconnect", backend, npmContainer]);
  }

  before = await upstreamCount();
  expect(probe(`https://fw1.e2e.test/registry/npm/${otherRegistry}/e2e-left`) === 401,
    "cross-account certificate refuses");
  await refuseSelected(foreignHome, "foreign");
  await refuseSelected("none", "missing");
  const malformed = h.client("client-npm", `CERT_MALFORMED=1 CERT_HOME=/root node probe.mjs '${own}'`, { files: { "probe.mjs": PROBE } });
  expect(malformed.status !== 0, "malformed client certificate refuses before an HTTP response");
  expect(await upstreamCount() === before, "cross-account and missing certificate made zero upstream calls");

  const second = await issue();
  expect(second.status === 200, `second certificate for the member: ${second.status}`);
  const secondHome = "/work/certificate-second";
  const secondInstall = h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${secondHome}; HOME=${secondHome} sh`], { input: second.body });
  expect(secondInstall.status === 0, `second certificate setup: ${secondInstall.stderr}`);
  const ids = h.stack.sql(`SELECT id FROM registry_member_certificates WHERE membership_id = ${memberNumber} ORDER BY id`).split("\n");
  expect(ids.length === 2, `two independent certificate rows: ${ids}`);
  expect(probe(own, secondHome) === 200, "second certificate admits");

  const keepaliveDir = `/work/${h.unique("certificate-keepalive")}`;
  const keepalive = ops(h).background("client-npm", `CERT_HOME=${secondHome} node keepalive.mjs '${own}'`, {
    dir: keepaliveDir, files: { "keepalive.mjs": KEEPALIVE },
  });
  await h.waitFor("first request on a reusable TLS connection", () => {
    const ready = h.stack.exec("client-npm", ["sh", "-c", `test -f ${keepaliveDir}/first.json && cat ${keepaliveDir}/first.json`]);
    return ready.status === 0 && JSON.parse(ready.stdout).status === 200;
  });
  h.stack.sql(`UPDATE registry_certificate_roots SET active = false WHERE org_id = ${org}`);
  before = await upstreamCount();
  h.stack.exec("client-npm", ["touch", `${keepaliveDir}/next`], { check: true });
  const reused = await keepalive;
  expect(reused.status === 0, `keepalive TLS probe: ${reused.status}\n${reused.stderr}`);
  const secondAnswer = JSON.parse(h.stack.exec("client-npm", ["cat", `${keepaliveDir}/second.json`], { check: true }).stdout);
  expect(secondAnswer.status === 401 && secondAnswer.reused, `rotated-out root refuses on the same TLS connection: ${JSON.stringify(secondAnswer)}`);
  expect(probe(own, secondHome) === 401, "rotated-out root refuses a new connection too");
  expect(await upstreamCount() === before, "rotated-out root refused before upstream");
  h.stack.sql(`UPDATE registry_certificate_roots SET active = true WHERE org_id = ${org}`);
  expect(probe(own, secondHome) === 200, "restored root admits on the next request");

  const revoked = await member.post(`/certificates/${ids[0]}/revoke`, { csrf: hidden(page.body, "csrf") });
  expect(revoked.status === 303, `targeted own-certificate revocation: ${revoked.status}`);
  await refuseSelected("/root", "revoked");
  expect(probe(own, secondHome) === 200, "targeted revoke leaves second certificate active");

  h.stack.stop("server");
  try {
    before = await upstreamCount();
    expect(probe(own, secondHome) === 503, "management outage refuses an otherwise valid certificate");
    expect(await upstreamCount() === before, "management outage refused before upstream");
  } finally {
    h.stack.start("server");
  }
  await h.waitFor("valid certificate after management returns", () => probe(own, secondHome) === 200, { timeout: 60_000, every: 1000 });

  const disabled = await admin.portal.submit(`/org/${org}`, `/org/members/${memberNumber}/package-disable`, {});
  expect(disabled.status === 303, `admin disables member package access: ${disabled.status}`);
  before = await upstreamCount();
  expect(probe(own, secondHome) === 401, "disabled member's second certificate refuses");
  expect(await upstreamCount() === before, "disabled member refused before upstream");
  expect((await issue()).status === 404, "disabled member cannot obtain another bundle");

  expect(probe(`https://fw1.e2e.test/registry/npm/${otherRegistry}/e2e-left`, foreignHome) === 200, "one active request permit admits a complete certificate read");
}
