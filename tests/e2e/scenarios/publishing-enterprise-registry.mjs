// Enterprise trust and selected-registry behavior at the portal and firewall seams.
import { spawnSync } from "node:child_process";
import { orgId } from "../harness/people.mjs";
import { Portal, hidden } from "../harness/net.mjs";
import { ops } from "../harness/ops.mjs";
import { changePlatform } from "../harness/portal-steps.mjs";

const PROBE = `
import https from "node:https";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
const home = process.env.HOME;
const request = https.get(process.argv[2], {
  ca: readFileSync("/e2e/ca/ca.pem"),
  cert: readFileSync(home + "/.config/probation/client-cert.pem"),
  key: readFileSync(home + "/.config/probation/client-key.pem"),
}, (response) => {
  const chunks = [];
  response.on("data", (chunk) => chunks.push(chunk));
  response.on("end", () => {
    const body = Buffer.concat(chunks);
    console.log(JSON.stringify({ status: response.statusCode, body: body.toString(),
      sha256: createHash("sha256").update(body).digest("hex") }));
  });
});
request.on("error", (error) => { console.error(error); process.exitCode = 2; });
`;
const KEEPALIVE = `
import https from "node:https";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
const home = process.env.HOME;
const agent = new https.Agent({ keepAlive: true, maxSockets: 1,
  ca: readFileSync("/e2e/ca/ca.pem"),
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
export const meta = {
  id: "E2E-publishing-enterprise-registry",
  title: "enterprise certificate admission and registry isolation",
  suites: ["release"],
};

export default async function enterpriseRegistry(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const settings = await admin.portal.get(`/org/${org}/certificates`);
  h.expect(settings.status === 200, `enterprise trust settings are admin-visible: ${settings.status}`);
  const wrongIdentity = await admin.portal.post(`/org/${org}/certificates`, {
    csrf: hidden(settings.body, "csrf"), identity_field: "subject_cn",
    expected_ocsp_url: "https://ocsp.example.test/", root_pem: "unused",
  });
  h.expect(wrongIdentity.status === 403, `an alternate identity selector is refused: ${wrongIdentity.status}`);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect(catalog.status === 200, `registry catalog is available to an admin: ${catalog.status}`);
  const add = async (name, target, trusted = false) => admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name, ecosystem: "npm", target_url: target,
    ...(trusted ? { trusted: "on" } : {}),
  });
  const first = await add("Enterprise A", "https://registry.npmjs.org/", true);
  h.expect(first.status === 303, `first selected registry can be added: ${first.status}`);
  const second = await add("Enterprise B", "https://registry-b.e2e.test/");
  h.expect(second.status === 303, `second selected registry can be added: ${second.status}`);
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const firstId = listed.body.match(/<li>(\d+) Enterprise A npm/)?.[1];
  const secondId = listed.body.match(/<li>(\d+) Enterprise B npm/)?.[1];
  h.expect(firstId && secondId && firstId !== secondId, "two registries receive distinct IDs");
  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200, `admin member setup bundle: ${bundle.status}`);
  const installed = h.stack.exec("client-npm", ["sh"], { input: bundle.body });
  h.expect(installed.status === 0, `client certificate installed: ${installed.stderr}`);
  const name = h.unique("registry-collision");
  await h.fakes.publishNpm({ name, version: "1.0.0", ageSeconds: 400 * 86_400, files: { "marker.txt": "registry-A" } });
  await h.fakes.publishNpmB({ name, version: "1.0.0", ageSeconds: 400 * 86_400, files: { "marker.txt": "registry-B" } });
  await h.fakes.publishNpm({ name, version: "1.1.0", ageSeconds: 3_600 });
  await h.fakes.publishNpmB({ name, version: "1.1.0", ageSeconds: 3_600 });
  const probe = (registry, suffix = name) => {
    const result = h.client("client-npm", `node probe.mjs 'https://fw1.e2e.test/registry/npm/${registry}/${suffix}'`, {
      files: { "probe.mjs": PROBE },
    });
    h.expect(result.status === 0, `certificate probe: ${result.stderr}`);
    return JSON.parse(result.stdout.trim());
  };
  const restoreFreeze = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  let oldReference;
  let replacementId;
  try {
    const a = probe(firstId);
    const b = probe(secondId);
    h.expect(a.status === 200 && b.status === 200, `selected roots answered: A=${a.status}, B=${b.status}`);
    const aDoc = JSON.parse(a.body);
    const bDoc = JSON.parse(b.body);
    h.expect(aDoc.versions["1.1.0"] && !bDoc.versions["1.1.0"], "trusted A exposes a too-new version while untrusted B holds it");
    const aRef = new URL(aDoc.versions["1.0.0"].dist.tarball);
    const bRef = new URL(bDoc.versions["1.0.0"].dist.tarball);
    h.expect(aRef.pathname.startsWith(`/registry/npm/${firstId}/artifacts/`)
      && bRef.pathname.startsWith(`/registry/npm/${secondId}/artifacts/`),
    "each registry returns an artifact URL in its selected namespace");
    oldReference = aRef.pathname.slice(`/registry/npm/${firstId}/`.length);
    h.expect(aRef.href !== bRef.href, "same-name artifacts carry distinct registry references");
    const aBytes = probe(firstId, oldReference);
    const bBytes = probe(secondId, bRef.pathname.slice(`/registry/npm/${secondId}/`.length));
    h.expect(aBytes.status === 200 && bBytes.status === 200 && aBytes.sha256 !== bBytes.sha256,
      "same-name artifacts return each registry's own bytes");
    h.restart("firewall-1");
    await h.firewallReady("fw1");
    const restartedB = probe(secondId);
    h.expect(restartedB.status === 200 && !JSON.parse(restartedB.body).versions["1.1.0"],
      "untrusted B still holds the too-new version after restart");
    h.expect(probe(firstId, oldReference).sha256 === aBytes.sha256,
      "trusted A's artifact remains isolated after restart");
  const removed = await admin.portal.post(`/org/${org}/registries/${firstId}/remove`, {
    csrf: hidden(listed.body, "csrf"),
  });
  h.expect(removed.status === 303, `registry removal: ${removed.status}`);
  const replacement = await add("Enterprise A replacement", "https://registry.npmjs.org/", true);
  h.expect(replacement.status === 303, `replacement registry can be added: ${replacement.status}`);
  const after = await admin.portal.get(`/org/${org}/registries`);
  replacementId = after.body.match(/<li>(\d+) Enterprise A replacement npm/)?.[1];
  h.expect(replacementId && replacementId !== firstId && !after.body.includes(`<li>${firstId} Enterprise A npm`),
    "remove and re-add never reuses the registry ID");
  h.expect(probe(firstId).status === 401, "removed registry ID refuses a saved certificate");
  h.expect(probe(secondId, oldReference).status === 404, "another registry cannot serve the removed reference");
  h.expect(probe(replacementId).status === 200, "replacement registry selects its own new ID");
  h.expect(!JSON.parse(probe(secondId).body).versions["1.1.0"],
    "untrusted B still holds the too-new version after A is removed and re-added");
  const immutableAttempt = await admin.portal.post(`/org/${org}/registries/${secondId}/trust`, {
    csrf: hidden(after.body, "csrf"), ecosystem: "pypi", target_url: "https://registry.npmjs.org/",
  });
  h.expect(immutableAttempt.status === 303, "registry trust edit accepts only its supported field");
  h.expect(h.stack.sql(`SELECT ecosystem || ' ' || target_url FROM registries WHERE id = ${Number(secondId)}`)
    === "npm https://registry-b.e2e.test/", "registry target and ecosystem cannot change through an edit");
  } finally {
    await restoreFreeze();
  }

  // The issuer must prove a live good→committed-revoked transition for one
  // sample before its provider can activate. A different leaf remains usable.
  const memberUuid = h.stack.sql(`SELECT certificate_uuid::text FROM memberships WHERE org_id = ${Number(org)} LIMIT 1`);
  let sample = await h.fakes.issueEnterprise("a", memberUuid);
  const live = await h.fakes.issueEnterprise("a", memberUuid);
  const trust = async (account, accountOrg, rootPem, ocspUrl) => {
    const page = await account.portal.get(`/org/${accountOrg}/certificates`);
    return account.portal.post(`/org/${accountOrg}/certificates`, {
      csrf: hidden(page.body, "csrf"), identity_field: "uri_san_membership_uuid",
      expected_ocsp_url: ocspUrl, root_pem: rootPem,
    });
  };
  h.expect((await trust(admin, org, sample.rootPem, sample.ocspUrl)).status === 303,
    "enterprise root and AIA expectation saved as an inactive draft");
  let testPage = await admin.portal.get(`/org/${org}/certificates`);
  const testSample = (chainPem, phase) => admin.portal.post(`/org/${org}/certificates/test`, {
    csrf: hidden(testPage.body, "csrf"), chain_pem: chainPem, phase,
  });
  const memberNumber = h.stack.sql(`SELECT id FROM memberships WHERE org_id = ${Number(org)} AND certificate_uuid::text = '${memberUuid}'`);
  const duringStatus = async (phase, change) => {
    const before = (await h.fakes.requests("ocsp-a.e2e.test")).length;
    await h.fakes.faults([{ host: "ocsp-a.e2e.test", path: "/status", method: "POST", mode: "hold", times: 1 }]);
    const pending = testSample(sample.leafPem, phase);
    try {
      await h.waitFor(`held ${phase} sample status`, async () =>
        (await h.fakes.requests("ocsp-a.e2e.test")).slice(before).some((entry) => entry.fault === "hold"));
      h.expect((await change()).status === 303, `change commits while ${phase} status is in flight`);
    } finally {
      await h.request("http://fakes.e2e.test:8080/holds/release", { method: "POST" });
      await h.fakes.faults([]);
    }
    return pending;
  };
  const resaveDuringStatus = (phase) => duringStatus(phase, () => trust(admin, org, sample.rootPem, sample.ocspUrl));
  const disableDuringStatus = (phase) => duringStatus(phase, () =>
    admin.portal.submit(`/org/${org}`, `/org/members/${memberNumber}/package-disable`, {}));
  const restoreMember = () => h.stack.sql(`UPDATE memberships SET package_access_disabled_at = NULL WHERE id = ${Number(memberNumber)}`);
  const wrongMember = await h.fakes.issueEnterprise("a", "123e4567-e89b-12d3-a456-426614174000");
  h.expect((await testSample(wrongMember.leafPem, "good")).status === 403,
    "a leaf naming no active organization member cannot start activation");
  const wrongAia = await h.fakes.issueEnterprise("a", memberUuid, "https://ocsp-b.e2e.test/status");
  h.expect((await testSample(wrongAia.leafPem, "good")).status === 403,
    "sample AIA must equal the saved issuer status URL");
  h.expect((await resaveDuringStatus("good")).status === 403,
    "good status from before a same-value settings save cannot create a sample");
  h.expect(h.stack.sql(`SELECT count(*) FROM registry_enterprise_activation_samples WHERE org_id = ${Number(org)}`) === "0",
    "stale good status leaves no activation sample");
  sample = await h.fakes.issueEnterprise("a", memberUuid);
  h.expect((await disableDuringStatus("good")).status === 403,
    "good status cannot record a sample after its member is disabled");
  h.expect(h.stack.sql(`SELECT count(*) FROM registry_enterprise_activation_samples WHERE org_id = ${Number(org)}`) === "0",
    "disabled member leaves no activation sample");
  restoreMember();
  const adminLogin = h.stack.sql(`SELECT login_id FROM memberships WHERE id = ${Number(memberNumber)}`);
  const demoteDuringStatus = () => duringStatus("good", () => {
    h.stack.sql(`UPDATE memberships SET role = 'member' WHERE id = ${Number(memberNumber)}`);
    return { status: 303 };
  });
  h.expect((await demoteDuringStatus()).status === 403,
    "good status cannot record a sample after its operator loses admin authority");
  h.expect(h.stack.sql(`SELECT count(*) FROM registry_enterprise_activation_samples WHERE org_id = ${Number(org)}`) === "0",
    "demoted operator leaves no activation sample");
  h.stack.sql(`UPDATE memberships SET role = 'org_admin' WHERE id = ${Number(memberNumber)}`);
  h.expect((await duringStatus("good", () => {
    h.stack.sql(`DELETE FROM sessions WHERE login_id = ${Number(adminLogin)}`);
    return { status: 303 };
  })).status === 403, "good status cannot record a sample after its session is revoked");
  h.expect(h.stack.sql(`SELECT count(*) FROM registry_enterprise_activation_samples WHERE org_id = ${Number(org)}`) === "0",
    "revoked session leaves no activation sample");
  admin.portal = new Portal();
  const signIn = await admin.portal.submit("/signin", "/signin", { email: admin.email, password: admin.password });
  h.expect(signIn.location === "/totp", "revoked operator session can start a new sign-in");
  const signedIn = await admin.portal.submit("/totp", "/totp", { code: await admin.auth.code() });
  h.expect(signedIn.status === 303, "operator completes a fresh second-factor sign-in");
  testPage = await admin.portal.get(`/org/${org}/certificates`);
  h.expect((await testSample(sample.leafPem, "good")).status === 200,
    "current issuer-authorized good status records the sample");
  h.expect((await testSample(sample.leafPem, "revoked")).status === 403,
    "good status cannot masquerade as a committed revocation");
  await h.fakes.revokeEnterprise("a", sample.id);
  h.expect((await resaveDuringStatus("revoked")).status === 403,
    "revoked status from before a same-value settings save cannot activate");
  h.expect(h.stack.sql(`SELECT kind FROM registry_certificate_providers WHERE org_id = ${Number(org)}`) === "pending",
    "stale revoked status leaves the provider pending");
  sample = await h.fakes.issueEnterprise("a", memberUuid);
  h.expect((await testSample(sample.leafPem, "good")).status === 200,
    "new settings revision requires a new good sample");
  await h.fakes.revokeEnterprise("a", sample.id);
  h.expect((await disableDuringStatus("revoked")).status === 403,
    "revoked status cannot activate after its member is disabled");
  h.expect(h.stack.sql(`SELECT kind FROM registry_certificate_providers WHERE org_id = ${Number(org)}`) === "pending",
    "disabled member leaves the provider pending");
  restoreMember();
  sample = await h.fakes.issueEnterprise("a", memberUuid);
  h.expect((await testSample(sample.leafPem, "good")).status === 200,
    "restored member requires a fresh good sample");
  await h.fakes.revokeEnterprise("a", sample.id);
  h.expect((await testSample(sample.leafPem, "revoked")).status === 303,
    "a new signed revoked response for the same sample activates the issuer");
  const enterpriseHome = h.stack.exec("client-npm", ["sh", "-c", "printf '%s' \"$HOME\""]);
  h.log(`enterprise client ${h.stack.container("client-npm")} HOME before issuer leaf install: ${JSON.stringify(enterpriseHome.stdout)}`);
  const enterpriseInstall = h.client("client-npm",
    "cp leaf.pem $HOME/.config/probation/client-cert.pem && cp key.pem $HOME/.config/probation/client-key.pem",
    { files: { "leaf.pem": live.leafPem, "key.pem": live.keyPem } });
  h.expect(enterpriseInstall.status === 0, `enterprise client certificate installed: ${enterpriseInstall.stderr}`);
  h.expect(probe(replacementId).status === 200, "the active enterprise leaf gets live good status");
  await h.fakes.issueEnterprise("b", "123e4567-e89b-12d3-a456-426614174000");
  for (const mode of ["replay", "wrong-nonce", "wrong-serial", "wrong-issuer", "bad-signature", "no-nonce"]) {
    await h.fakes.enterpriseStatusMode("a", mode);
    h.expect(probe(replacementId).status === 401, `${mode} status refuses the next request`);
  }
  await h.fakes.enterpriseStatusMode("a", "normal");
  await h.fakes.faults([{ host: "ocsp-a.e2e.test", path: "/status", method: "POST", mode: "status", status: 503 }]);
  h.expect(probe(replacementId).status === 401, "OCSP outage fails closed");
  await h.fakes.faults([]);
  h.expect(probe(replacementId).status === 200, "restored live status admits the leaf");
  await h.fakes.revokeEnterprise("a", live.id);
  h.expect(probe(replacementId).status === 401, "a committed revocation refuses the very next request");

  const otherAdmin = await h.signUp({ kind: "org" });
  await h.enableTotp(otherAdmin);
  const otherOrg = await orgId(otherAdmin.portal);
  const otherUuid = h.stack.sql(`SELECT certificate_uuid::text FROM memberships WHERE org_id = ${Number(otherOrg)} LIMIT 1`);
  const otherSample = await h.fakes.issueEnterprise("b", otherUuid);
  const otherLive = await h.fakes.issueEnterprise("b", otherUuid);
  h.expect((await trust(otherAdmin, otherOrg, otherSample.rootPem, otherSample.ocspUrl)).status === 303,
    "a second organization saves its own independent issuer root");
  const otherPage = await otherAdmin.portal.get(`/org/${otherOrg}/certificates`);
  const otherTest = (chainPem, phase) => otherAdmin.portal.post(`/org/${otherOrg}/certificates/test`, {
    csrf: hidden(otherPage.body, "csrf"), chain_pem: chainPem, phase,
  });
  h.expect((await otherTest(live.leafPem, "good")).status === 403,
    "a foreign organization's root and member cannot activate this provider");
  h.expect((await otherTest(otherSample.leafPem, "good")).status === 200, "second issuer sample good");
  await h.fakes.revokeEnterprise("b", otherSample.id);
  h.expect((await otherTest(otherSample.leafPem, "revoked")).status === 303, "second issuer transition activates");
  const otherCatalog = await otherAdmin.portal.get(`/org/${otherOrg}/registries`);
  const otherRegistry = otherCatalog.body.match(/<li>(\d+) Default npm npm/)?.[1];
  h.expect(otherRegistry, "second organization has a selected npm registry");
  const thirdA = await h.fakes.issueEnterprise("a", memberUuid);
  const installLeaf = (cert) => h.client("client-npm",
    "cp leaf.pem $HOME/.config/probation/client-cert.pem && cp key.pem $HOME/.config/probation/client-key.pem",
    { files: { "leaf.pem": cert.leafPem, "key.pem": cert.keyPem } });
  h.expect(installLeaf(thirdA).status === 0, "an unrevoked first-organization leaf installs");
  h.expect(probe(otherRegistry).status === 401, "first organization's valid leaf cannot select second registry");
  h.expect(installLeaf(otherLive).status === 0, "second-organization leaf installs");
  h.expect(probe(otherRegistry).status === 200, "second root admits its own active member and registry");
  h.expect(probe(replacementId).status === 401, "second root cannot select first organization's registry");
  h.stack.sql(`UPDATE registry_certificate_roots SET active = false WHERE org_id = ${Number(otherOrg)}`);
  h.expect(probe(otherRegistry).status === 401, "removing the current root refuses the next request");
  h.stack.sql(`UPDATE registry_certificate_roots SET active = true WHERE org_id = ${Number(otherOrg)}`);
  h.expect(probe(otherRegistry).status === 200, "restoring organization trust restores only its own leaf");
  const keepaliveDir = `/work/${h.unique("enterprise-keepalive")}`;
  const keepalive = ops(h).background("client-npm",
    `node keepalive.mjs 'https://fw1.e2e.test/registry/npm/${otherRegistry}/${name}'`, {
      dir: keepaliveDir, files: { "keepalive.mjs": KEEPALIVE },
    });
  await h.waitFor("enterprise leaf's first request on a reusable TLS connection", () => {
    const ready = h.stack.exec("client-npm", ["sh", "-c", `test -f ${keepaliveDir}/first.json && cat ${keepaliveDir}/first.json`]);
    return ready.status === 0 && JSON.parse(ready.stdout).status === 200;
  });
  h.stack.sql(`UPDATE registry_certificate_roots SET active = false WHERE org_id = ${Number(otherOrg)}`);
  h.stack.exec("client-npm", ["touch", `${keepaliveDir}/next`], { check: true });
  const keepaliveDone = await keepalive;
  h.expect(keepaliveDone.status === 0, `enterprise keepalive probe: ${keepaliveDone.stderr}`);
  const reused = JSON.parse(h.stack.exec("client-npm", ["cat", `${keepaliveDir}/second.json`], { check: true }).stdout);
  h.expect(reused.status === 401 && reused.reused,
    `rotated-out enterprise root refuses on the same TLS connection: ${JSON.stringify(reused)}`);
  h.stack.sql(`UPDATE registry_certificate_roots SET active = true WHERE org_id = ${Number(otherOrg)}`);
  h.expect(probe(otherRegistry).status === 200, "restored enterprise root admits on the next request");

  const rotatedSample = await h.fakes.issueEnterprise("a", otherUuid);
  const rotatedLive = await h.fakes.issueEnterprise("a", otherUuid);
  h.expect((await trust(otherAdmin, otherOrg, rotatedSample.rootPem, rotatedSample.ocspUrl)).status === 303,
    "replacement enterprise trust is saved as an inactive draft");
  h.expect(probe(otherRegistry).status === 401, "superseded B root refuses its leaf on the next request");
  h.expect(h.stack.sql(`SELECT count(*) FROM registry_certificate_roots WHERE org_id = ${Number(otherOrg)} AND active`) === "1",
    "only the replacement root remains active");
  h.expect(installLeaf(rotatedLive).status === 0, "replacement issuer leaf installs");
  h.expect(probe(otherRegistry).status === 401, "replacement leaf waits for a new issuer activation");
  h.expect((await otherTest(rotatedSample.leafPem, "good")).status === 200,
    "replacement issuer sample reports good");
  await h.fakes.revokeEnterprise("a", rotatedSample.id);
  h.expect((await otherTest(rotatedSample.leafPem, "revoked")).status === 303,
    "replacement issuer commits revocation and activates");
  h.expect(probe(otherRegistry).status === 200, "replacement leaf admits after activation");

  // A private origin is permitted only after an operator approves its exact
  // saved host, port, and connected address. A redirect cannot leave it.
  const privateTarget = "https://private-registry.e2e.test/";
  const privateAdd = await otherAdmin.portal.post(`/org/${otherOrg}/registries`, {
    csrf: hidden(otherCatalog.body, "csrf"), name: "Private npm", ecosystem: "npm", target_url: privateTarget,
  });
  h.expect(privateAdd.status === 303, `private registry saved: ${privateAdd.status}`);
  const privateCatalog = await otherAdmin.portal.get(`/org/${otherOrg}/registries`);
  const privateId = privateCatalog.body.match(/<li>(\d+) Private npm npm/)?.[1];
  h.expect(privateId, "private registry has a selected ID");
  const privateLog = () => h.fakes.requests("private-registry.e2e.test");
  const beforePrivate = (await privateLog()).length;
  h.expect(probe(privateId).status === 502, "unapproved private DNS answer fails closed");
  h.expect((await privateLog()).length === beforePrivate, "unapproved private address receives no request");
  const requestEgress = async (account, accountOrg, page, purpose, target, cidr) => {
    const answer = await account.portal.post(`/org/${accountOrg}/private-egress`, {
      csrf: hidden(page.body, "csrf"), purpose, target_url: target, cidr,
    });
    h.expect(answer.status === 303, `${purpose} egress request accepted: ${answer.status}`);
    const id = h.stack.sql(`SELECT id FROM registry_private_egress WHERE org_id = ${Number(accountOrg)} AND purpose = '${purpose}' AND cidr = '${cidr}'::cidr ORDER BY id DESC LIMIT 1`);
    const queue = await h.operator.portal.get("/admin/private-egress");
    h.expect(queue.status === 200 && id, `operator sees ${purpose} request`);
    const approved = await h.operator.portal.post(`/admin/private-egress/${id}/approve`, {
      csrf: hidden(queue.body, "csrf"),
    });
    h.expect(approved.status === 303, `operator approves ${purpose} destination: ${approved.status}`);
  };
  await requestEgress(otherAdmin, otherOrg, privateCatalog, "registry", privateTarget, "10.77.0.3/32");
  h.expect(probe(privateId).status === 502, "approval for a different address does not allow the DNS answer");
  h.expect((await privateLog()).length === beforePrivate, "wrong CIDR cannot reach the private peer");
  await requestEgress(otherAdmin, otherOrg, privateCatalog, "registry", privateTarget, "10.77.0.2/32");
  h.expect(probe(privateId).status === 200, "exact approved private registry and peer are reachable");
  const privateHits = (await privateLog()).length;
  const redirectName = h.unique("private-redirect");
  await h.fakes.publishNpmB({ name: redirectName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.faults([{ host: "private-registry.e2e.test", path: `/${redirectName}`, method: "GET",
    mode: "redirect", location: `https://registry.npmjs.org/${redirectName}` }]);
  h.expect(probe(privateId, redirectName).status === 502, "a private origin cannot redirect to a different registry");
  h.expect((await privateLog()).length > privateHits, "private origin emitted the redirect response");
  await h.fakes.faults([]);

  const privateOcsp = "https://private-ocsp.e2e.test/status";
  const privateSample = await h.fakes.issueEnterprise("a", memberUuid, privateOcsp);
  const privateLive = await h.fakes.issueEnterprise("a", memberUuid, privateOcsp);
  h.expect((await trust(admin, org, privateSample.rootPem, privateOcsp)).status === 303,
    "private AIA saved before its egress is approved");
  h.expect((await testSample(privateSample.leafPem, "good")).status === 403,
    "unapproved private OCSP DNS answer cannot activate the issuer");
  const privateOcspLog = () => h.fakes.requests("private-ocsp.e2e.test");
  h.expect((await privateOcspLog()).length === 0, "unapproved OCSP address receives no request");
  const currentCatalog = await admin.portal.get(`/org/${org}/registries`);
  await requestEgress(admin, org, currentCatalog, "ocsp", privateOcsp, "10.77.0.2/32");
  h.expect((await testSample(privateSample.leafPem, "good")).status === 200,
    "approved private OCSP status reports a current good sample");
  await h.fakes.revokeEnterprise("a", privateSample.id);
  h.expect((await testSample(privateSample.leafPem, "revoked")).status === 303,
    "private issuer's committed revocation activates it");
  h.expect(installLeaf(privateLive).status === 0, "private-AIA enterprise leaf installs");
  h.expect(probe(replacementId).status === 200, "private OCSP is checked for each package request");
  await h.fakes.faults([{ host: "private-ocsp.e2e.test", path: "/status", method: "POST",
    mode: "redirect", location: "https://ocsp-a.e2e.test/status" }]);
  h.expect(probe(replacementId).status === 401, "private OCSP cannot redirect to a different status origin");
  await h.fakes.faults([]);
  h.expect(probe(replacementId).status === 200, "restored private status admits the leaf");

  // Start a second managed firewall with Slice 1's persisted, unscoped package
  // rows. The upgrade must discard those rows without recreating its database.
  const firewall2 = h.stack.container("firewall-2");
  const inspected = spawnSync(h.stack.engine, ["inspect", firewall2], { encoding: "utf8" });
  h.expect(inspected.status === 0, `inspect firewall-2 volume: ${inspected.stderr}`);
  const volume = JSON.parse(inspected.stdout)[0].Mounts.find((mount) => mount.Destination === "/var/lib/probation")?.Name;
  h.expect(volume, "firewall-2 has a persisted data volume");
  const volumePython = (script) => {
    const result = spawnSync(h.stack.engine, ["run", "--rm", "--user", "0", "-v", `${volume}:/v`,
      "localhost/probation-e2e-client:pip26.2", "python3", "-c", script], { encoding: "utf8" });
    h.expect(result.status === 0, `Slice 1 database fixture: ${result.stderr}`);
    return result.stdout.trim();
  };
  h.stop("firewall-2");
  volumePython(`
import os, sqlite3
state = '/v/state'
os.makedirs(state, exist_ok=True)
for name in os.listdir(state):
    if name.startswith('firewall.db'):
        os.remove(os.path.join(state, name))
path = os.path.join(state, 'firewall.db')
db = sqlite3.connect(path)
db.executescript('''
CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, engine_version TEXT NOT NULL);
CREATE TABLE blocklist (id INTEGER PRIMARY KEY, revision INTEGER NOT NULL, generated_at_micros INTEGER NOT NULL, expires_at_micros INTEGER NOT NULL, snapshot BLOB NOT NULL);
CREATE TABLE projects (ecosystem TEXT NOT NULL, name TEXT NOT NULL, payload BLOB NOT NULL, etag TEXT, last_modified TEXT, validated_at_micros INTEGER NOT NULL, fetched_at_micros INTEGER NOT NULL, generation INTEGER NOT NULL, digest_generation INTEGER NOT NULL, PRIMARY KEY (ecosystem, name));
CREATE TABLE artifact_references (id BLOB PRIMARY KEY, ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, filename TEXT NOT NULL, upstream_url TEXT NOT NULL, expected TEXT NOT NULL, publication_micros INTEGER, first_seen_micros INTEGER, pinned_sha256 BLOB, pinned_sha512 BLOB, pinned_size INTEGER, content_key BLOB);
CREATE INDEX artifact_references_by_project ON artifact_references (ecosystem, name);
CREATE INDEX artifact_references_by_content ON artifact_references (content_key);
CREATE TABLE content (key BLOB PRIMARY KEY, sha512 BLOB NOT NULL, size INTEGER NOT NULL, created_micros INTEGER NOT NULL, accessed_micros INTEGER NOT NULL);
INSERT INTO schema_meta VALUES (1, 5, '0.7.2');
INSERT INTO projects (ecosystem, name, payload, validated_at_micros, fetched_at_micros, generation, digest_generation) VALUES ('npm', 'legacy-unscoped', x'7b7d', 1, 1, 1, 1);
INSERT INTO artifact_references (id, ecosystem, name, version, filename, upstream_url, expected) VALUES (x'01', 'npm', 'legacy-unscoped', '1.0.0', 'legacy.tgz', 'https://registry.npmjs.org/legacy.tgz', '[]');
INSERT INTO content VALUES (x'02', x'03', 1, 1, 1);
''')
db.close()
owner = os.stat(state)
os.chown(path, owner.st_uid, owner.st_gid)
`);
  h.start("firewall-2");
  await h.firewallReady("fw2");
  h.stop("firewall-2");
  const migrated = JSON.parse(volumePython(`
import json, sqlite3
db = sqlite3.connect('/v/state/firewall.db')
print(json.dumps({
 'version': db.execute('SELECT schema_version FROM schema_meta').fetchone()[0],
 'projects': db.execute('SELECT count(*) FROM projects').fetchone()[0],
 'references': db.execute('SELECT count(*) FROM artifact_references').fetchone()[0],
 'content': db.execute('SELECT count(*) FROM content').fetchone()[0],
 'scoped': [r[1] for r in db.execute('PRAGMA table_info(projects)')] .count('registry_id'),
}))
`));
  h.expect(migrated.version === 7 && migrated.projects === 0 && migrated.references === 0 && migrated.content === 1 && migrated.scoped === 1,
    `Slice 1 database upgraded with ambiguous package state invalidated: ${JSON.stringify(migrated)}`);
  h.start("firewall-2");
  await h.firewallReady("fw2");
  h.expect(installLeaf(rotatedLive).status === 0, "active replacement leaf restores after migration");
  const fw2 = h.client("client-npm", `node probe.mjs 'https://fw2.e2e.test/registry/npm/${otherRegistry}/${name}'`, {
    files: { "probe.mjs": PROBE },
  });
  h.expect(fw2.status === 0 && JSON.parse(fw2.stdout.trim()).status === 200,
    `migrated firewall serves freshly scoped package state: ${fw2.stderr} ${fw2.stdout}`);
}
