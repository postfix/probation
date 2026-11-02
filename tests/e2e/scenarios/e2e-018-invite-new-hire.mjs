// E2E-018 Invite to install, a new hire (docs/plans/e2e-coverage/00-inventory.md §3).
//
// An org admin invites bob@ into the Backend group, whose policy blocks e2e-left 2.0.0.
// Bob has no login. In Chromium he opens the link from the mail (built from base_url)
// signed out, creates a login from there, confirms it from the mail and signs in; the
// invitation must still be in front of him then, without the mail (F17). He accepts,
// works in the organisation, creates a key, and npm installs through both firewalls
// under the Backend group's policy. The used link is refused to him and to anyone else;
// a cancelled link is refused and makes no member.

import { Needs, act, freshMailWindow, invite, keyStatus, onFirewall, orgId } from "../harness/people.mjs";

export const meta = {
  id: "E2E-018",
  title: "Invite to install: a new hire without a login joins by the mailed link and installs",
  suites: ["nightly", "release"],
};

const EXPIRED = "This invitation link has expired or was already used";

export default async function newHire(h) {
  const { expect } = h;
  const needs = new Needs(h.log);
  freshMailWindow(h);
  const [admin, carol] = await Promise.all([h.signUp({ kind: "org" }), h.signUp({ kind: "personal" })]);
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const orgName = admin.org;

  // The Backend group, whose policy blocks one version.
  await act(admin.portal, `/org/${org}`, `/org/${org}/groups`, { name: "Backend" });
  const group = (await admin.portal.get(`/org/${org}`)).body.match(/href="\/policy\/group-(\d+)" aria-label="Policy of the Backend group"/)?.[1];
  expect(group, "the Backend group is listed");
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "2.0.0" }, `/policy/group-${group}`);

  // The invitation, by mail; the link is built from base_url.
  const bob = { email: `${h.unique("bob")}@example.com`, password: `bob ${h.unique("pw")} staple` };
  const link = await invite(h, admin, org, bob.email, { group });
  expect(link.origin === "https://portal.e2e.test", `the link is built from base_url: ${link}`);

  // Bob, signed out and with no login, opens it in Chromium and is asked to sign in.
  const page = await (await h.browser()).newPage();
  const text = () => page.locator("main").innerText();
  await page.goto(link.toString());
  expect(new URL(page.url()).pathname === "/signin", `signed out, the link asks for a sign-in: ${page.url()}`);
  // He has no login: "Create an account" from there, the mail, "Continue", sign in.
  await page.click("main a[href='/signup']");
  await page.fill("#email", bob.email);
  await page.fill("#password", bob.password);
  await page.check("input[name=kind][value=personal]");
  await page.click("form[action='/signup'] button[type=submit]");
  const confirm = await h.mail.link(bob.email, /^\/verify-email$/, { subject: "Confirm your email" });
  await page.goto(confirm.toString());
  expect((await text()).includes("Choose your password to confirm your email address"), "opening the link asks bob to choose a password");
  bob.password = `confirmed ${h.unique("pw")} staple`;
  await page.fill("#new", bob.password);
  await page.fill("#again", bob.password);
  await page.click("form[action='/verify-email'] button[type=submit]");
  expect((await text()).includes("Your email address is confirmed"), "the address is confirmed");
  await page.click("main a.button");
  if (new URL(page.url()).pathname === "/signin") await h.browserSignIn(page, bob);
  const backAtInvitation = new URL(page.url()).pathname === "/invite" && (await text()).includes(`Join ${orgName}`);
  needs.check("F17", backAtInvitation, `after creating a login from the invitation link and signing in, the invitation is shown again (at ${page.url()})`);
  // Until then, he opens the mail's link once more.
  if (!backAtInvitation) await page.goto(link.toString());
  expect((await text()).includes(`Join ${orgName} as a member in the Backend group.`), `the invitation page:\n${await text()}`);
  await page.click("form[action='/invite'] button[type=submit]");
  expect(new URL(page.url()).pathname === `/org/${org}`, `accepted, on the organisation page: ${page.url()}`);

  // He works in the organisation: a key there, npm through both firewalls.
  await page.selectOption("#place-switcher", `org:${org}`);
  await page.click("form[action='/place'] button[type=submit]");
  const lines = await h.browserCreateKey(page, "bob-laptop");
  expect((await text()).includes(`Your keys in ${orgName}`), "the key is in the organisation");
  for (const host of ["fw1", "fw2"]) {
    const run = h.npm("install e2e-left@1.0.0 --no-audit --no-fund", { npmrc: onFirewall(lines.npmrc, host) });
    expect(run.status === 0, `npm on ${host}: ${run.status}\n${run.stdout}\n${run.stderr}`);
  }
  // Under the Backend group's policy.
  const blocked = h.npm("install e2e-left@2.0.0 --no-audit --no-fund", { npmrc: lines.npmrc });
  // npm sees the blocked version left out of the listing; the version itself is 403.
  expect(blocked.status !== 0 && /ETARGET/.test(blocked.stdout + blocked.stderr), `the group's block applies to bob's key: ${blocked.status}\n${blocked.stderr}`);
  const direct = await h.request(`${h.firewalls.fw2}/npm/e2e-left/2.0.0`, { headers: { authorization: `Bearer ${lines.key}` } });
  expect(direct.status === 403, `e2e-left 2.0.0 with bob's key on fw2: ${direct.status}`);
  expect((await keyStatus(h, "fw2", lines.key)) === 200, "bob's key works on fw2");
  const row = (await admin.portal.get(`/org/${org}`)).body.split("<tr>").find((tr) => tr.startsWith(`<td>${bob.email}`));
  expect(row && /<option value="\d+" selected>Backend<\/option>/.test(row), `bob is listed in the Backend group:\n${row}`);

  // The used link: refused to bob and to any other login.
  await page.goto(link.toString());
  expect((await text()).includes(EXPIRED), `bob opens the used link again:\n${await text()}`);
  const token = link.searchParams.get("token");
  let page2 = await carol.portal.get(link.pathname + link.search);
  expect(page2.body.includes(EXPIRED), "another login sees the used link as expired");
  let answer = await carol.portal.post("/invite", { csrf: h.hidden(page2.body, "csrf"), token });
  expect(answer.status === 410, `accepting a used link: ${answer.status}`);

  // A cancelled link: refused, and nobody joins.
  const dave = `${h.unique("dave")}@example.com`;
  const cancelled = await invite(h, admin, org, dave);
  const waiting = (await admin.portal.get(`/org/${org}`)).body.split("<tr>").find((tr) => tr.startsWith(`<td>${dave}</td>`));
  const invitation = waiting?.match(/\/org\/invitations\/(\d+)\/cancel/)?.[1];
  expect(invitation, `the invitation to ${dave} is waiting`);
  await act(admin.portal, `/org/${org}`, `/org/invitations/${invitation}/cancel`);
  page2 = await carol.portal.get(cancelled.pathname + cancelled.search);
  expect(page2.body.includes(EXPIRED), "a cancelled link shows as expired");
  answer = await carol.portal.post("/invite", { csrf: h.hidden(page2.body, "csrf"), token: cancelled.searchParams.get("token") });
  expect(answer.status === 410, `accepting a cancelled link: ${answer.status}`);
  const members = (await admin.portal.get(`/org/${org}`)).body;
  expect(!members.includes(`<td>${carol.email}`), "carol did not join");
  needs.done();
}
