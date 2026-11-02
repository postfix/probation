// A real organization-issuer transition for package-client matrix modes.
// SQL only identifies an already enrolled member; the portal activates trust.
import { hidden } from "./net.mjs";

function memberUuid(h, org, memberEmail) {
  const email = memberEmail.replaceAll("'", "''");
  const uuid = h.stack.sql(`SELECT m.certificate_uuid::text FROM memberships AS m
    JOIN sign_in_methods AS s ON s.login_id = m.login_id
    WHERE m.org_id = ${Number(org)} AND lower(s.email) = lower('${email}')
    ORDER BY m.id LIMIT 1`);
  h.expect(/^[0-9a-f-]{36}$/.test(uuid), "issuer selects an already enrolled organization member");
  return uuid;
}

export async function issueIssuerLeafFor(h, org, memberEmail) {
  return h.fakes.issueEnterprise("a", memberUuid(h, org, memberEmail));
}

export async function activateIssuerFor(h, admin, org, memberEmail = admin.email) {
  const uuid = memberUuid(h, org, memberEmail);
  const sample = await h.fakes.issueEnterprise("a", uuid);
  const live = await h.fakes.issueEnterprise("a", uuid);
  const settings = await admin.portal.get(`/org/${org}/certificates`);
  h.expect(settings.status === 200, "issuer administrator opens certificate settings");
  const trust = await admin.portal.post(`/org/${org}/certificates`, {
    csrf: hidden(settings.body, "csrf"), identity_field: "uri_san_membership_uuid",
    expected_ocsp_url: sample.ocspUrl, root_pem: sample.rootPem,
  });
  h.expect(trust.status === 303, `issuer trust saved: ${trust.status}`);
  const testPage = await admin.portal.get(`/org/${org}/certificates`);
  const testSample = (phase) => admin.portal.post(`/org/${org}/certificates/test`, {
    csrf: hidden(testPage.body, "csrf"), chain_pem: sample.leafPem, phase,
  });
  h.expect((await testSample("good")).status === 200, "issuer live good sample verified");
  await h.fakes.revokeEnterprise("a", sample.id);
  h.expect((await testSample("revoked")).status === 303, "issuer signed revocation activates provider");
  h.expect((await admin.portal.get("/certificates/setup")).status === 403,
    "organization-issued provider refuses a portal setup bundle");
  return { live, uuid };
}

export function installIssuerLeaf(h, service, leaf, home = "/root") {
  const combined = service !== "client-npm";
  const destination = `${home}/.config/probation`;
  const script = combined
    ? `set -eu\numask 077\nmkdir -p ${destination}\ncat > ${destination}/client.pem <<'LEAF'\n${leaf.leafPem}LEAF\ncat >> ${destination}/client.pem <<'KEY'\n${leaf.keyPem}KEY\n`
    : `set -eu\numask 077\nmkdir -p ${destination}\ncat > ${destination}/client-cert.pem <<'LEAF'\n${leaf.leafPem}LEAF\ncat > ${destination}/client-key.pem <<'KEY'\n${leaf.keyPem}KEY\n`;
  const installed = h.stack.exec(service, ["sh"], { input: script });
  h.expect(installed.status === 0, `${service} installs issuer leaf in user-local config: ${installed.stderr}`);
}
