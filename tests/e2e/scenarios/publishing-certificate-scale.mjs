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
// argv[4]: milliseconds between the starts of two identities (default 20); argv[5]: concurrent workers (default 32); argv[6]: how many
// identities to try (default all of the manifest).
const pace = Number(process.argv[4] ?? 20);
const workers = Number(process.argv[5] ?? 32);
const limit = Number(process.argv[6] ?? identities.length);
const ceiling = Math.max(3, Math.ceil(limit / 500));
const started = Date.now();
let next = 0;
let nextSlot = started;
let passed = 0;
let retried = 0;
const admittedFingerprints = new Set();
async function worker() {
  while (next < limit) {
    const index = next++;
    const identity = identities[index];
    // The pace is a floor between two starts: a worker that is behind never bursts to catch up (the 32 workers would
    // then offer the responder every identity at once after any stall of it).
    const slot = Math.max(nextSlot, Date.now());
    nextSlot = slot + pace;
    const wait = slot - Date.now();
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    const attempt = () => new Promise((resolve, reject) => {
      const request = https.get(url, { ca, cert: identity.cert, key: identity.key, agent: false, timeout: 15_000 }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      request.on("timeout", () => request.destroy(new Error("TLS probe timed out")));
      request.on("error", reject);
    });
    let status = await attempt();
    // An organisation-issuer admission asks the issuer's responder live and, by contract (D35), a failed ask is REFUSED with 401: the
    // refusal is the product doing what the contract says, and the second try below is a PROBE TOLERANCE of this scenario, not a product
    // behaviour. A lost DNS answer or SYN toward the responder costs one 5 s connect timeout and so one 401 (measured: about 1 in 1,400
    // on this host, 7 in 10,000). Only a 401 is tried again: any other status (a 5xx, a 429, a 503 LOOKUP_BUSY) is a product failure
    // and fails at once. A deterministic refusal (revoked, wrong leaf, wrong issuer) fails again and fails the probe.
    // The ceiling on first refusals is 0.2 percent (20 of 10,000, never fewer than 3 in a smaller run): about 2.8 times the measured mean
    // of 7, so a Poisson run of 10,000 exceeds it with probability near 1 in 50,000, while a regression to 0.9 percent (90 refused) fails.
    const again = status === 401;
    if (again) { retried++; await new Promise((resolve) => setTimeout(resolve, 250)); status = await attempt(); }
    if (status !== 200) throw new Error("identity " + index + " was denied: " + status + (again ? " (after the 401 retry)" : ""));
    if (retried > ceiling) throw new Error("more than 0.2 percent of the identities were refused at first: " + retried + " of " + (index + 1) + " (ceiling " + ceiling + ")");
    admittedFingerprints.add(fingerprints[index]);
    passed++;
  }
}
await Promise.all(Array.from({ length: workers }, worker));
console.log(JSON.stringify({ admitted: passed, distinct: admittedFingerprints.size, retried, ceiling, ms: Date.now() - started }));
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

/// The pace, in milliseconds between two identities, at which the live OCSP check of the organisation-issuer admissions is sustained here.
/// The product guarantee (D35, enterprise_certificate.rs) is that every admission asks the issuer's OCSP responder live with a fresh nonce
/// and is refused (401) when the signed answer is not there inside 10 s (5 s to connect); nothing is cached and there is no per-account cap.
/// Root cause of the earlier refusals at 20 ms (identity 517, 703, 4768 and 6358 in four runs): the FAKE responder signed each answer
/// with a synchronous `openssl` spawn in the one thread that also serves every other fake (its answers took 305 ms at the median under 32
/// workers, with stalls of 1.5 to 2.9 s), and the probe's schedule (`index * pace`) let 32 workers burst at the responder's full rate after
/// any stall. The fake now signs with at most four asynchronous children, the probe's pace is a floor between two starts, and one
/// refusal in about 1,400 (one 5 s connect timeout toward the responder, measured with the firewall's own timing) is tried once more.
/// Still, the probe measures instead of assuming: 150 identities at each of 20, 40, 80, 160 and 320 ms, the first pace that admits all of
/// them, and the probe runs at 1.5 times that pace.
async function ocspPaceMs(h, identities, url) {
  const sample = identities.slice(0, 150);
  const path = installManifest(h, "pace-calibration", sample);
  let chosen = null;
  for (const pace of [20, 40, 80, 160, 320]) {
    const result = h.client("client-npm", `node batch-probe.mjs '${url}' '${path}' ${pace} 32 ${sample.length}`, { files: { "batch-probe.mjs": BATCH_PROBE } });
    let summary = null;
    try { summary = JSON.parse(result.stdout.trim()); } catch { /* denied: the probe threw */ }
    const ok = result.status === 0 && summary?.admitted === sample.length;
    h.log(`calibration: ${sample.length} organisation-issuer admissions at ${pace} ms per identity: ${ok ? "all admitted" : `refused (${(result.stderr.match(/was denied: \d+/) ?? ["no summary"])[0]})`}`);
    // Let the responder's backlog (10 s timeouts) drain before the next trial.
    await new Promise((resolve) => setTimeout(resolve, 12_000));
    if (ok) { chosen = pace; break; }
  }
  h.stack.exec("client-npm", ["rm", "-f", path]);
  // The floor: X09 states no rate (10,000 distinct admissions inside the scenario's 30-minute enrollment deadline), so this harness states
  // one. The recorded runs sustained 20 to 30 ms per identity; 80 ms (12.5 per second, 4 times slower than measured) is the floor, and a
  // calibrated pace above it FAILS instead of being logged: the probe may run slower only because the host is, never because the product is.
  const FLOOR_MS = 80;
  h.expect(chosen !== null && chosen <= FLOOR_MS, `the organisation-issuer admission path sustains at least 12.5 identities per second (a pace of ${FLOOR_MS} ms or better); calibrated: ${chosen ?? "none of 20, 40, 80, 160, 320 ms"}`);
  const pace = Math.ceil(chosen * 1.5);
  h.log(`certificate-scale pace result: ${JSON.stringify({ calibratedMs: chosen, floorMs: FLOOR_MS, probeMs: pace, sample: sample.length })}`);
  h.log(`organisation-issuer admissions are sustained at ${chosen} ms per identity here; probing 10,000 at ${pace} ms (about ${Math.round(pace * 10)} s)`);
  return pace;
}

function admitAll(h, name, identities, url, paceMs = 20) {
  const distinctFingerprints = new Set(identities.map((identity) => new X509Certificate(identity.cert).fingerprint256));
  h.expect(distinctFingerprints.size === identities.length,
    `${name}: ${distinctFingerprints.size}/${identities.length} unique certificate fingerprints before client transfer`);
  const path = installManifest(h, name, identities);
  const started = Date.now();
  const result = h.client("client-npm", `node batch-probe.mjs '${url}' '${path}' ${paceMs}`, { files: { "batch-probe.mjs": BATCH_PROBE } });
  let summary;
  try { summary = JSON.parse(result.stdout.trim()); } catch { /* Failure below includes the client diagnostic. */ }
  h.expect(result.status === 0 && summary?.admitted === identities.length && summary?.distinct === identities.length,
    `${name}: ${identities.length} distinct TLS identities admitted through package client: ${result.stderr} ${result.stdout}`);
  h.log(`${name}: ${identities.length} distinct TLS admissions in ${((Date.now() - started) / 1000).toFixed(1)}s, ${summary?.retried} refused with 401 once and admitted on the second try (ceiling ${summary?.ceiling})`);
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
    // The portal answers 503 ("unavailable") when the database is slow (a COMMIT over its alert threshold on a loaded
    // disk). The member's sign-in, which creates nothing but the membership, is restarted up to three times; the certificate
    // POST below is never repeated, so no member can hold two leaves.
    let member, setup;
    for (let attempt = 1; ; attempt++) {
      try {
        await h.fakes.oidcNext({ sub: `scale-member-${index}`, email });
        member = new h.Portal(undefined, clientIp(index));
        const begun = await member.get(`/sso/${org}/start`);
        h.expect(begun.status === 303, `scale member ${index} SSO start: ${begun.status}`);
        const issuer = await h.request(begun.location);
        h.expect(issuer.status === 302, `scale member ${index} IdP redirect: ${issuer.status}`);
        const callback = new URL(issuer.headers.location);
        const signedIn = await member.get(callback.pathname + callback.search);
        h.expect(signedIn.status === 303 && signedIn.location === "/account",
          `scale member ${index} signed in: ${signedIn.status} ${signedIn.location}`);
        setup = await member.get("/certificates/setup");
        h.expect(setup.status === 200, `scale member ${index} setup page: ${setup.status}`);
        break;
      } catch (error) {
        if (attempt >= 3 || !/ 503\b/.test(String(error?.message))) throw error;
        h.log(`scale member ${index}: the portal answered 503 (attempt ${attempt}); signing in again`);
      }
    }
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
  admitAll(h, "organization-issuer-admission", issuerIdentities, url, await ocspPaceMs(h, issuerIdentities, url));
  configure({ bridgePort: h.stack.bridgePort, caFile: join(h.stack.work, "ca", "ca.pem") });
  h.log("issuer admission complete; host tunnel pool refreshed");
  const issuerInstall = h.stack.exec("client-npm", ["sh"], { input: `set -eu\numask 077\nmkdir -p ${home}/.config/probation\ncat >${home}/.config/probation/client-cert.pem <<'LEAF'\n${selectedLeaf.leafPem}LEAF\ncat >${home}/.config/probation/client-key.pem <<'KEY'\n${selectedLeaf.keyPem}KEY\n` });
  h.expect(issuerInstall.status === 0 && probe(h, home, url) === 200,
    `selected issuer leaf admits member: ${issuerInstall.stderr}`);
  await h.fakes.revokeEnterprise("a", selectedLeaf.id);
  h.expect(probe(h, home, url) === 401,
    "issuer revokes one selected leaf and the next package request refuses");
}
