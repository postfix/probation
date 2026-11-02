// X09: every member is created by a real fake-SSO sign-in and receives a real
// setup response. The issuer then signs one distinct leaf for each member.
import { X509Certificate } from "node:crypto";
import { join } from "node:path";
import { configure, hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export const meta = {
  id: "E2E-publishing-certificate-scale",
  title: "10,000 member self-service and organization issuer enrollment",
  suites: ["release"],
  stack: "own",
};

const PROBE = `
import https from "node:https";
import { readFileSync } from "node:fs";
const base = process.env.HOME + "/.config/probation/";
const req = https.get(process.argv[2], {
  ca: readFileSync("/e2e/ca/ca.pem"),
  cert: readFileSync(base + "client-cert.pem"),
  key: readFileSync(base + "client-key.pem"),
}, (res) => { res.resume(); res.on("end", () => console.log(res.statusCode)); });
req.on("error", (error) => { console.error(error.message); process.exitCode = 2; });
`;

const BATCH_PROBE = `
import { X509Certificate } from "node:crypto";
import https from "node:https";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { createReadStream } from "node:fs";
const ca = readFileSync("/e2e/ca/ca.pem");
const url = process.argv[2];
const file = process.argv[3];
const identities = [];
for await (const line of createInterface({ input: createReadStream(file) })) identities.push(JSON.parse(line));
const fingerprints = identities.map((identity) => new X509Certificate(identity.cert).fingerprint256);
if (new Set(fingerprints).size !== identities.length) throw new Error("duplicate certificate identity in client manifest");
const started = Date.now();
let next = 0;
let passed = 0;
const admittedFingerprints = new Set();
async function worker() {
  while (next < identities.length) {
    const index = next++;
    const identity = identities[index];
    const wait = index * 20 - (Date.now() - started);
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    const status = await new Promise((resolve, reject) => {
      const request = https.get(url, { ca, cert: identity.cert, key: identity.key, agent: false, timeout: 15_000 }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      request.on("timeout", () => request.destroy(new Error("TLS probe timed out")));
      request.on("error", reject);
    });
    if (status !== 200) throw new Error("identity " + index + " was denied: " + status);
    admittedFingerprints.add(fingerprints[index]);
    passed++;
  }
}
await Promise.all(Array.from({ length: 32 }, worker));
console.log(JSON.stringify({ admitted: passed, distinct: admittedFingerprints.size }));
`;

function installManifest(h, name, identities) {
  const path = `/work/${name}.jsonl`;
  h.expect(h.stack.exec("client-npm", ["sh", "-c", `: > ${path}`]).status === 0,
    `${name}: client manifest opened`);
  for (let start = 0; start < identities.length; start += 250) {
    const lines = identities.slice(start, start + 250).map((identity) => JSON.stringify(identity)).join("\n") + "\n";
    const written = h.stack.exec("client-npm", ["sh", "-c", `cat >> ${path}`], { input: lines });
    h.expect(written.status === 0, `${name}: client manifest batch ${start}: ${written.stderr}`);
  }
  return path;
}

function admitAll(h, name, identities, url) {
  const distinctFingerprints = new Set(identities.map((identity) => new X509Certificate(identity.cert).fingerprint256));
  h.expect(distinctFingerprints.size === identities.length,
    `${name}: ${distinctFingerprints.size}/${identities.length} unique certificate fingerprints before client transfer`);
  const path = installManifest(h, name, identities);
  const started = Date.now();
  const result = h.client("client-npm", `node batch-probe.mjs '${url}' '${path}'`, { files: { "batch-probe.mjs": BATCH_PROBE } });
  let summary;
  try { summary = JSON.parse(result.stdout.trim()); } catch { /* Failure below includes the client diagnostic. */ }
  h.expect(result.status === 0 && summary?.admitted === identities.length && summary?.distinct === identities.length,
    `${name}: ${identities.length} distinct TLS identities admitted through package client: ${result.stderr} ${result.stdout}`);
  h.log(`${name}: ${identities.length} distinct TLS admissions in ${((Date.now() - started) / 1000).toFixed(1)}s`);
  h.stack.exec("client-npm", ["rm", "-f", path]);
}

function rejectDuplicateManifest(h, identity, url) {
  const path = "/work/duplicate-identity-control.jsonl";
  const lines = `${JSON.stringify(identity)}\n${JSON.stringify(identity)}\n`;
  const written = h.stack.exec("client-npm", ["sh", "-c", `cat > ${path}`], { input: lines });
  h.expect(written.status === 0, `duplicate identity control manifest written: ${written.stderr}`);
  const result = h.client("client-npm", `node batch-probe.mjs '${url}' '${path}'`, { files: { "batch-probe.mjs": BATCH_PROBE } });
  h.stack.exec("client-npm", ["rm", "-f", path]);
  h.expect(result.status !== 0 && result.stderr.includes("duplicate certificate identity"),
    `duplicate cert/key pair is rejected before admission: status=${result.status} stderr=${result.stderr} stdout=${result.stdout}`);
}

function bundleIdentity(bundle) {
  const cert = bundle.match(/cat >"\$base\/client-cert\.pem" <<'PROBATION_CERT'\n([\s\S]*?)PROBATION_CERT\n/)?.[1];
  const key = bundle.match(/cat >"\$base\/client-key\.pem" <<'PROBATION_KEY'\n([\s\S]*?)PROBATION_KEY\n/)?.[1];
  if (!cert || !key) throw new Error("issued bundle has no client certificate and key");
  return { cert, key };
}

function clientIp(index) {
  return `10.201.${Math.floor(index / 254)}.${index % 254 + 1}`;
}

function probe(h, home, url) {
  const result = h.client("client-npm", `HOME=${home} node probe.mjs '${url}'`, { files: { "probe.mjs": PROBE } });
  h.expect(result.status === 0, `scale certificate probe: ${result.stderr}`);
  return Number(result.stdout.trim());
}

export default async function certificateScale(h) {
  const count = Number(process.env.E2E_SCALE_SMOKE_COUNT ?? 10_000);
  h.expect(Number.isInteger(count) && count > 0 && count <= 10_000, "bounded scale fixture count");
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const sso = await admin.portal.submit(`/org/${org}`, `/org/${org}/sso`, {
    enabled: "on", issuer: "https://idp.e2e.test", client_id: h.unique("scale-client"),
    allowed_tenant: "", client_secret: "e2e-secret",
  });
  h.expect(sso.status === 303, `scale fake SSO enabled: ${sso.status}`);
  h.expect((await admin.portal.get(`/org/${org}`)).body.includes(`action="/org/${org}/certificates/lookup"`),
    "administrator member page links to exact certificate lookup");
  const name = h.unique("scale-selected");
  await h.fakes.publishNpm({ name, version: "1.0.0", ageSeconds: 400 * 86_400 });
  const start = Date.now();
  const deadline = start + 30 * 60_000;
  let selected;
  const selfServiceIdentities = [];
  for (let index = 0; index < count; index++) {
    if (Date.now() > deadline) throw new Error(`scale enrollment exceeded 30 minutes at ${index}/${count}`);
    const email = `scale-${index}@example.e2e.test`;
    await h.fakes.oidcNext({ sub: `scale-member-${index}`, email });
    const member = new h.Portal(undefined, clientIp(index));
    const begun = await member.get(`/sso/${org}/start`);
    h.expect(begun.status === 303, `scale member ${index} SSO start: ${begun.status}`);
    const issuer = await h.request(begun.location);
    h.expect(issuer.status === 302, `scale member ${index} IdP redirect: ${issuer.status}`);
    const callback = new URL(issuer.headers.location);
    const signedIn = await member.get(callback.pathname + callback.search);
    h.expect(signedIn.status === 303 && signedIn.location === "/account",
      `scale member ${index} signed in: ${signedIn.status} ${signedIn.location}`);
    const setup = await member.get("/certificates/setup");
    h.expect(setup.status === 200, `scale member ${index} setup page: ${setup.status}`);
    const bundle = await member.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
    h.expect(bundle.status === 200 && bundle.body.includes("client-key.pem"),
      `scale member ${index} issued own bundle: ${bundle.status}`);
    selfServiceIdentities.push(bundleIdentity(bundle.body));
    if (index === Math.floor(count / 2)) {
      selected = {
        bundle: bundle.body, member, email, csrf: hidden(setup.body, "csrf"),
        certId: h.stack.sql(`SELECT id FROM registry_member_certificates WHERE org_id = ${Number(org)} ORDER BY id DESC LIMIT 1`),
      };
    }
    if ((index + 1) % 250 === 0 || index + 1 === count) {
      h.log(`self-service enrollment ${index + 1}/${count} in ${((Date.now() - start) / 1000).toFixed(1)}s`);
    }
  }
  const enrolled = Number(h.stack.sql(`SELECT count(DISTINCT membership_id) FROM registry_member_certificates WHERE org_id = ${Number(org)}`));
  const fingerprints = Number(h.stack.sql(`SELECT count(DISTINCT leaf_fingerprint) FROM registry_member_certificates WHERE org_id = ${Number(org)}`));
  h.expect(enrolled === count && fingerprints === count,
    `${count} distinct members enrolled by self-service: members=${enrolled}, leaves=${fingerprints}`);
  for (let index = 0; index < 55; index++) {
    const extra = await selected.member.post("/certificates/setup", { csrf: selected.csrf });
    h.expect(extra.status === 200, `older-certificate fixture ${index + 1}/55 issued: ${extra.status}`);
  }
  const lookup = await admin.portal.get(`/org/${org}/certificates/lookup?email=${encodeURIComponent(selected.email)}`);
  const olderLink = lookup.body.match(/href="([^"]+)"[^>]*>Older certificates</)?.[1]
    ?.replaceAll("&#38;", "&").replaceAll("&amp;", "&");
  h.expect(lookup.status === 200 && lookup.body.includes(selected.email)
    && !lookup.body.includes(`action="/certificates/${selected.certId}/revoke"`)
    && (lookup.body.match(/action="\/certificates\/\d+\/revoke"/g) ?? []).length === 50
    && olderLink,
  `administrator sees a bounded first page and an older-certificate link: ${lookup.status}`);
  const older = await admin.portal.get(olderLink);
  const olderCount = (older.body.match(/action="\/certificates\/\d+\/revoke"/g) ?? []).length;
  h.expect(older.status === 200 && older.body.includes(`action="/certificates/${selected.certId}/revoke"`)
    && olderCount === 6,
    `administrator finds the oldest of 56 leaves for exactly one member: status=${older.status}, count=${olderCount}, selected=${selected.certId}, link=${olderLink}`);
  h.expect((await selected.member.get(`/org/${org}/certificates/lookup?email=${encodeURIComponent(selected.email)}`)).status === 403,
    "ordinary member cannot enumerate another member's certificate through lookup");
  const foreign = await h.signUp({ kind: "org" });
  h.expect((await foreign.portal.get(`/org/${org}/certificates/lookup?email=${encodeURIComponent(selected.email)}`)).status === 404,
    "another organization cannot look up this member's certificate");
  h.expect((await foreign.portal.get(olderLink)).status === 404,
    "another organization cannot follow the older-certificate page");
  const absent = await admin.portal.get(`/org/${org}/certificates/lookup?email=absent%40example.e2e.test`);
  h.expect(absent.status === 200 && !absent.body.includes('action="/certificates/'),
    "an exact absent member lookup never lists organization certificates");
  const registryId = selected.bundle.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  h.expect(registryId, "scale bundle selects npm registry ID");
  const url = `https://fw1.e2e.test/registry/npm/${registryId}/${name}`;
  rejectDuplicateManifest(h, selfServiceIdentities[0], url);
  admitAll(h, "self-service-admission", selfServiceIdentities, url);
  // The host issued no HTTP requests during the long client-only batch. Its
  // pooled CONNECT tunnels can be stale even though the client requests passed.
  configure({ bridgePort: h.stack.bridgePort, caFile: join(h.stack.work, "ca", "ca.pem") });
  h.log("self-service admission complete; host tunnel pool refreshed");
  h.expect(count === 10_000, `scale smoke ran ${count}/10,000; no X09 completion claim`);
  const home = "/work/scale-selected-member";
  const installed = h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${home}; HOME=${home} sh`], { input: selected.bundle });
  h.expect(installed.status === 0 && probe(h, home, url) === 200,
    `selected self-service member admitted before revocation: ${installed.stderr}`);
  h.log("selected member admitted; checking disabled issuance");
  const issuedBefore = h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`);
  h.stack.sql(`UPDATE registry_certificate_providers SET self_service = false WHERE org_id = ${Number(org)}`);
  h.expect((await selected.member.get("/certificates/setup")).status === 403,
    "disabled self-service refuses a new setup page at 10,000 members");
  h.expect((await selected.member.post("/certificates/setup", { csrf: selected.csrf })).status === 404
    && h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`) === issuedBefore,
    "disabled self-service creates no new certificate at 10,000 members");
  h.expect(probe(h, home, url) === 200,
    "existing selected certificate reads while self-service is disabled");
  h.log("disabled issuance checked; revoking oldest selected leaf");
  const revoked = await admin.portal.post(`/certificates/${selected.certId}/revoke`, { csrf: hidden(older.body, "csrf") });
  h.expect(revoked.status === 303 && probe(h, home, url) === 401,
    `administrator targeted one certificate without listing all 10,000: ${revoked.status}`);
  h.expect(h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`) === issuedBefore,
    "disabled self-service added no certificate during targeted revocation");
  h.log("targeted oldest-leaf revocation complete; activating issuer");

  // The external issuer enrolls the same 10,000 real SSO members with distinct
  // leaves. The provider activates only after its required live good→revoked sample.
  const uuids = h.stack.sql(`SELECT DISTINCT m.certificate_uuid::text FROM memberships AS m
    JOIN registry_member_certificates AS c ON c.membership_id = m.id WHERE m.org_id = ${Number(org)} ORDER BY 1`).split("\n");
  h.expect(uuids.length === 10_000, `issuer has 10,000 enrolled member UUIDs: ${uuids.length}`);
  const sample = await h.fakes.issueEnterprise("a", uuids[0]);
  const settings = await admin.portal.get(`/org/${org}/certificates`);
  const trust = await admin.portal.post(`/org/${org}/certificates`, {
    csrf: hidden(settings.body, "csrf"), identity_field: "uri_san_membership_uuid",
    expected_ocsp_url: sample.ocspUrl, root_pem: sample.rootPem,
  });
  h.expect(trust.status === 303, `issuer trust saved: ${trust.status}`);
  const testPage = await admin.portal.get(`/org/${org}/certificates`);
  const testSample = (phase) => admin.portal.post(`/org/${org}/certificates/test`, {
    csrf: hidden(testPage.body, "csrf"), chain_pem: sample.leafPem, phase,
  });
  h.expect((await testSample("good")).status === 200, "issuer good sample verified");
  await h.fakes.revokeEnterprise("a", sample.id);
  h.expect((await testSample("revoked")).status === 303, "issuer committed revocation activates provider");
  h.expect((await selected.member.get("/certificates/setup")).status === 403
    && (await selected.member.post("/certificates/setup", { csrf: selected.csrf })).status === 404,
    "organization issuer provider refuses portal bundle issuance");
  const issuerIds = new Set();
  const issuerIdentities = [];
  let selectedLeaf;
  for (let index = 0; index < uuids.length; index++) {
    if (Date.now() > deadline) throw new Error(`issuer enrollment exceeded 30 minutes at ${index}/${uuids.length}`);
    const leaf = await h.fakes.issueEnterprise("a", uuids[index]);
    h.expect(leaf.memberUuid === uuids[index] && !issuerIds.has(leaf.id),
      `issuer leaf ${index} uniquely identifies its real member`);
    issuerIds.add(leaf.id);
    issuerIdentities.push({ cert: leaf.leafPem, key: leaf.keyPem });
    if (index === Math.floor(uuids.length / 2)) selectedLeaf = leaf;
    if ((index + 1) % 250 === 0 || index + 1 === uuids.length) {
      h.log(`organization issuer enrollment ${index + 1}/${uuids.length} in ${((Date.now() - start) / 1000).toFixed(1)}s`);
    }
  }
  h.expect(issuerIds.size === 10_000, "10,000 distinct members receive issuer leaves");
  admitAll(h, "organization-issuer-admission", issuerIdentities, url);
  configure({ bridgePort: h.stack.bridgePort, caFile: join(h.stack.work, "ca", "ca.pem") });
  h.log("issuer admission complete; host tunnel pool refreshed");
  const issuerInstall = h.stack.exec("client-npm", ["sh"], { input: `set -eu\numask 077\nmkdir -p ${home}/.config/probation\ncat >${home}/.config/probation/client-cert.pem <<'LEAF'\n${selectedLeaf.leafPem}LEAF\ncat >${home}/.config/probation/client-key.pem <<'KEY'\n${selectedLeaf.keyPem}KEY\n` });
  h.expect(issuerInstall.status === 0 && probe(h, home, url) === 200,
    `selected issuer leaf admits member: ${issuerInstall.stderr}`);
  await h.fakes.revokeEnterprise("a", selectedLeaf.id);
  h.expect(probe(h, home, url) === 401,
    "issuer revokes one selected leaf and the next package request refuses");
}
