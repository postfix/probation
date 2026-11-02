// E2E-004 Offboarding and key revocation (docs/plans/e2e-coverage/00-inventory.md §3).
//
// Three members of an organisation and a build machine's service key install through
// both firewalls, so both have every key cached. Then people leave in every way the
// portal and the operator offer: the org admin removes one member (while that member
// creates a key), approves another's leave request and revokes the service key on
// /keys; the operator runs `admin revoke-key` in the server container, once while the
// server runs and once with it stopped; a personal-only user deletes their login. Every
// one of those keys gets 401 on both firewalls within one sync interval, and the real
// clients fail with it; the keys nobody touched keep working. The deleted login comes
// back with "Restore login" (its key works again) and is then replaced with "Start a
// new login" (its key stays refused). `revoke-key` refuses an id that is not a live user
// or service key: twice the same, unknown, and a firewall token's (F13: the docs said
// "any key"), and the firewall keeps serving.

import { accept, act, freshMailWindow, invite, join, keyAnswers, keyId, keyStatus, memberId, onFirewall, orgId } from "../harness/people.mjs";

export const meta = {
  id: "E2E-004",
  title: "Offboarding and key revocation: removal, leave, /keys, revoke-key, login delete and restore",
  suites: ["pr", "nightly", "release"],
};

const INSTALL = "install e2e-left@1.0.0 --no-audit --no-fund";

export default async function offboarding(h) {
  const { expect } = h;
  freshMailWindow(h);
  const cli = (...args) => h.stack.exec("server", ["probation-server", "admin", ...args]);

  // An organisation with three members, each on their own login, and a personal-only
  // user: a personal account and nothing else. (Sign-ups in parallel: each waits for
  // its mail.)
  const [admin, removed, leaving, staying, solo] = await Promise.all([
    h.signUp({ kind: "org" }),
    ...[1, 2, 3, 4].map(() => h.signUp({ kind: "personal" })),
  ]);
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const adminKey = await h.createKey(admin.portal, "admin-laptop");
  await Promise.all([removed, leaving, staying].map((who) => join(h, admin, org, who)));
  const keys = {
    removed: await h.createKey(removed.portal, "removed-laptop"),
    left: await h.createKey(leaving.portal, "left-laptop"),
    cli: await h.createKey(staying.portal, "cli-revoked"),
    cliOffline: await h.createKey(staying.portal, "cli-revoked-offline"),
    kept: await h.createKey(staying.portal, "kept-laptop"),
  };
  let page = await admin.portal.submit("/keys", "/keys/service", { name: "ci-runner", attach: "org" });
  expect(page.status === 200, `service key: ${page.status}\n${page.body}`);
  keys.service = { key: h.between(page.body, '<code id="new-key">', "</code>") };
  keys.service.npmrc = adminKey.npmrc.replace(adminKey.key, keys.service.key);

  keys.solo = await h.createKey(solo.portal, "solo-laptop");

  // Every key installs on firewall-1 with real npm, and is in firewall-2's cache too.
  for (const [who, key] of Object.entries(keys)) {
    const run = h.npm(INSTALL, { npmrc: key.npmrc });
    expect(run.status === 0, `${who} installs before offboarding: ${run.status}\n${run.stdout}\n${run.stderr}`);
    expect((await keyStatus(h, "fw2", key.key)) === 200, `${who} works on fw2`);
  }
  let run = h.npm(INSTALL, { npmrc: onFirewall(keys.removed.npmrc, "fw2") });
  expect(run.status === 0, `npm on fw2: ${run.status}\n${run.stderr}`);

  // 1. Removal, while the removed member creates one more key.
  const removedId = await memberId(admin.portal, org, removed.email);
  expect(removedId, `${removed.email} is on the members list`);
  const [during] = await Promise.all([
    removed.portal.submit("/keys", "/keys", { name: "during-removal" }),
    act(admin.portal, `/org/${org}`, `/org/members/${removedId}/remove`),
  ]);
  const raced = during.status === 200 ? h.between(during.body, '<code id="new-key">', "</code>") : null;
  h.log(`key created during the removal: ${raced ? "yes, made before the removal" : `no (${during.status})`}`);
  expect((await memberId(admin.portal, org, removed.email)) === null, "the removed member is off the members list");

  // 2. A leave request, approved.
  await act(leaving.portal, `/org/${org}`, `/org/${org}/leave`);
  page = await admin.portal.get(`/org/${org}`);
  const leave = page.body.split("<tr>").filter((row) => row.startsWith(`<td>${leaving.email}</td>`)).map((row) => row.match(/\/org\/leave\/(\d+)\/approve/)?.[1]).find(Boolean);
  expect(leave, `the leave request of ${leaving.email} is listed\n${page.body}`);
  await act(admin.portal, `/org/${org}`, `/org/leave/${leave}/approve`);
  expect((await memberId(admin.portal, org, leaving.email)) === null, "the member who left is off the members list");
  page = await leaving.portal.get("/org");
  expect(page.status === 200 && !page.location, `the leaver's /org has no organisation: ${page.status} ${page.location}`);

  // 3. The org admin revokes the service key on /keys.
  await act(admin.portal, "/keys", `/keys/${await keyId(admin.portal, "ci-runner")}/revoke`);

  // 4. The operator revokes a member's key with the CLI in the server container.
  const cliId = await keyId(staying.portal, "cli-revoked");
  let done = cli("revoke-key", "--key-id", cliId);
  expect(done.status === 0 && done.stdout.includes(`revoked key ${cliId}`), `revoke-key: ${done.status}\n${done.stdout}\n${done.stderr}`);

  // 5. The personal-only user deletes their personal account, and with it the login.
  let answer = await solo.portal.submit("/account", "/account/personal/delete", { confirm: "delete" });
  expect(answer.status === 303 && answer.location === "/signin", `delete: ${answer.status} ${answer.location}`);

  // Every one of those keys is refused on both firewalls within one interval.
  const gone = { removed: keys.removed.key, left: keys.left.key, service: keys.service.key, cli: keys.cli.key, solo: keys.solo.key };
  if (raced) gone.raced = raced;
  await Promise.all(Object.entries(gone).map(([what, key]) => keyAnswers(h, key, 401, { what })));
  for (const [what, key] of [["admin", adminKey.key], ["kept", keys.kept.key], ["cliOffline", keys.cliOffline.key]]) {
    for (const host of ["fw1", "fw2"]) expect((await keyStatus(h, host, key)) === 200, `${what} still works on ${host}`);
  }
  // As the clients show it.
  run = h.npm(INSTALL, { npmrc: keys.removed.npmrc });
  expect(run.status !== 0 && /E401|401/.test(run.stdout + run.stderr), `npm with the removed member's key: ${run.status}\n${run.stdout}\n${run.stderr}`);
  run = h.pip("install --no-cache-dir e2e-left==1.0.0", { pipConf: keys.left.pipConf });
  expect(run.status !== 0 && /401/.test(run.stdout + run.stderr), `pip with the leaver's key: ${run.status}\n${run.stdout}\n${run.stderr}`);
  run = h.npm(INSTALL, { npmrc: keys.kept.npmrc });
  expect(run.status === 0, `npm with the kept key: ${run.status}\n${run.stderr}`);

  // What the org admin sees: the operator's revocation in the audit log, and the
  // refused request with the revoked key in Activity.
  page = await admin.portal.get("/audit");
  expect(
    page.body.split("<tr>").some((row) => row.includes("the operator") && row.includes(`key:${cliId}`)),
    `the audit log has the operator's revocation of key ${cliId}`,
  );
  await h.waitFor("the refused request in Activity", async () =>
    (await h.activity(admin.portal)).some((row) => row.key.startsWith("cli-revoked ") && row.result === "Refused: the key was revoked"),
    { timeout: 3 * h.syncInterval * 1000 });

  // 6. revoke-key refuses what is not a live user or service key.
  done = cli("revoke-key", "--key-id", cliId);
  expect(done.status !== 0 && done.stderr.includes(`no live API key ${cliId}`), `revoke-key twice: ${done.status}\n${done.stdout}\n${done.stderr}`);
  done = cli("revoke-key", "--key-id", "2147483000");
  expect(done.status !== 0 && done.stderr.includes("no live API key 2147483000"), `revoke-key unknown: ${done.status}\n${done.stderr}`);
  // An operator who looks up firewall-2's token and tries to revoke it (F13).
  const tokenId = h.stack.sql("SELECT token_key_id FROM firewalls WHERE name = 'firewall-2'");
  done = cli("revoke-key", "--key-id", tokenId);
  expect(done.status !== 0 && done.stderr.includes(`no live API key ${tokenId}`), `revoke-key on a firewall token: ${done.status}\n${done.stdout}\n${done.stderr}`);

  // 7. The CLI works with the server stopped, as the docs say; the revocation reaches
  // the firewalls once the server is back.
  const offlineId = await keyId(staying.portal, "cli-revoked-offline");
  h.stop("server");
  done = h.stack.compose(["run", "--rm", "-T", "--no-deps", "server", "admin", "revoke-key", "--key-id", offlineId], { check: false });
  h.start("server");
  expect(done.status === 0 && done.stdout.includes(`revoked key ${offlineId}`), `revoke-key with the server stopped: ${done.status}\n${done.stdout}\n${done.stderr}`);
  await h.waitFor("the portal is back", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 120_000 });
  await keyAnswers(h, keys.cliOffline.key, 401, { what: "the key revoked offline", timeout: (2 * h.syncInterval + 5) * 1000 });

  // 8. The deleted login comes back with "Restore login", and its key works again.
  const signIn = async () => {
    const portal = new h.Portal();
    const signed = await portal.submit("/signin", "/signin", { email: solo.email, password: solo.password });
    expect(signed.status === 303 && signed.location === "/deleted", `sign-in to the deleted login: ${signed.status} ${signed.location}`);
    const choice = await portal.get("/deleted");
    expect(choice.body.includes("This login was deleted on"), `the deleted-login page:\n${choice.body}`);
    return portal;
  };
  let portal = await signIn();
  answer = await portal.submit("/deleted", "/deleted/restore", {});
  expect(answer.status === 303 && answer.location === "/account", `restore: ${answer.status} ${answer.location}`);
  expect((await portal.get("/account")).body.includes("You have a personal account."), "the personal account is back");
  await keyAnswers(h, keys.solo.key, 200, { what: "the restored login's key" });
  run = h.npm(INSTALL, { npmrc: keys.solo.npmrc });
  expect(run.status === 0, `npm with the restored key: ${run.status}\n${run.stderr}`);

  // 9. Deleted again, then "Start a new login instead": the old key stays refused.
  answer = await portal.submit("/account", "/account/personal/delete", { confirm: "delete" });
  expect(answer.status === 303 && answer.location === "/signin", `delete again: ${answer.status} ${answer.location}`);
  await keyAnswers(h, keys.solo.key, 401, { what: "the key deleted again" });
  portal = await signIn();
  answer = await portal.submit("/deleted", "/deleted/new", {});
  expect(answer.status === 303 && answer.location === "/account", `start a new login: ${answer.status} ${answer.location}`);
  page = await portal.get("/account");
  expect(page.body.includes("You do not have a personal account."), "the new login starts with no personal account");
  expect((await portal.get("/keys")).body.includes("You have no place yet"), "the new login has no keys and no place");

  // Some sync rounds later: the erased login's key, and every other revoked key, are
  // still refused; the firewall whose token the CLI refused still serves.
  await h.sleep((h.syncInterval + 5) * 1000);
  for (const [what, key] of Object.entries({ ...gone, cliOffline: keys.cliOffline.key })) {
    for (const host of ["fw1", "fw2"]) expect((await keyStatus(h, host, key)) === 401, `${what} stays refused on ${host}`);
  }
  await h.firewallReady("fw2", 5000);
  expect((await keyStatus(h, "fw2", keys.kept.key)) === 200, "firewall-2 still serves after the refused revoke-key on its token");

  // A removed member can come back only by a new invitation; their old key stays dead.
  const link = await invite(h, admin, org, removed.email);
  await accept(removed, link);
  // After the sync round that carries the new membership, not before it.
  await h.sleep((h.syncInterval + 5) * 1000);
  for (const host of ["fw1", "fw2"]) {
    expect((await keyStatus(h, host, keys.removed.key)) === 401, `rejoining does not bring the old key back on ${host}`);
  }
}
