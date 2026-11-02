// Portal steps several scenarios share: the policy editor's settings form, removing a
// block or exception by its row, organisations, groups and invited members, and a key's
// lines on another firewall. Each takes the scenario's `h` (harness/helpers.mjs) and
// drives the portal's own forms, as a person would.

import { randomBytes } from "node:crypto";
import { expect, hidden, unescape } from "./net.mjs";

/// The policy page's editable state: {path, body, csrf, revision, freeze, unit, osv,
/// allow: {allow_exceptions, allow_osv_off, allow_shorter_freeze}}.
export async function policyState(portal, path) {
  const page = await portal.get(path);
  expect(page.status === 200, `the policy page ${path}: ${page.status}\n${page.body}`);
  const body = page.body;
  const allow = {};
  for (const name of ["allow_exceptions", "allow_osv_off", "allow_shorter_freeze"]) {
    allow[name] = new RegExp(`name="${name}" checked`).test(body);
  }
  return {
    path,
    body,
    csrf: hidden(body, "csrf"),
    revision: hidden(body, "revision"),
    freeze: body.match(/id="freeze" name="freeze"[^>]*value="([^"]*)"/)?.[1] ?? "",
    unit: body.match(/<option value="(hours|days)" selected>/)?.[1] ?? "days",
    osv: body.match(/name="osv" value="([a-z_]+)" checked/)?.[1] ?? "inherit",
    allow,
  };
}

/// "Save changes" in the Freeze and OSV form, keeping every field `changes` leaves out
/// (`freeze`, `unit`, `osv`, `allow: {allow_exceptions: bool, ...}`). Answers the
/// portal's answer ({status, location, body}); 303 is saved, 422 shows the refusal.
export async function savePolicy(portal, path, changes = {}) {
  const now = await policyState(portal, path);
  const allow = { ...now.allow, ...changes.allow };
  const form = {
    csrf: now.csrf,
    revision: changes.revision ?? now.revision,
    action: "save",
    freeze: changes.freeze ?? now.freeze,
    unit: changes.unit ?? now.unit,
    osv: changes.osv ?? now.osv,
  };
  for (const [name, on] of Object.entries(allow)) if (on) form[name] = "on";
  return portal.post(path, form);
}

/// One add_block / add_exception / ... post with the page's own csrf and revision;
/// answers the portal's answer without judging it.
export async function policyPost(portal, path, fields) {
  const now = await policyState(portal, path);
  return portal.post(path, { csrf: now.csrf, revision: now.revision, ...fields });
}

/// Presses "Remove" on this layer's own block (kind "block") or exception (kind
/// "exception") whose button label matches `label` (a RegExp over "the block on
/// <package> <what>" or "the exception on <package>").
export async function removeOwn(portal, path, kind, label) {
  const now = await policyState(portal, path);
  const forms = [...now.body.matchAll(/<form method="post" action="[^"]+">([\s\S]*?)<\/form>/g)].map(([, form]) => form);
  const form = forms.find((f) => f.includes(`value="remove_${kind}"`) && label.test(unescape(f.match(/aria-label="([^"]*)"/)?.[1] ?? "")));
  expect(form, `no Remove for the ${kind} ${label} on ${path}`);
  const index = form.match(/name="index" value="(\d+)"/)[1];
  return portal.post(path, { csrf: now.csrf, revision: now.revision, action: `remove_${kind}`, index });
}

/// The signed-in place's organisation id, from where `/org` sends it.
export async function orgIdOf(portal) {
  const page = await portal.get("/org");
  const id = page.location?.match(/^\/org\/(\d+)$/)?.[1];
  expect(id, `/org sends an org admin to /org/<id>: ${page.status} ${page.location}`);
  return Number(id);
}

/// "Create group" on the organisation page; answers the new group's id.
export async function createGroup(portal, org, name) {
  const answer = await portal.submit(`/org/${org}`, `/org/${org}/groups`, { name });
  expect(answer.status === 303, `create group ${name}: ${answer.status}\n${answer.body}`);
  const page = (await portal.get(`/org/${org}`)).body;
  const id = page.match(new RegExp(`<tr><td>${name}</td>[\\s\\S]*?action="/org/groups/(\\d+)/rename"`))?.[1];
  expect(id, `group ${name} is listed on /org/${org}`);
  return Number(id);
}

/// New people in `admin`'s organisation, as it happens for real: each signs up (a
/// personal account) and confirms the address, the org admin sends each an invitation
/// ({role, group: id or "none"}), each opens the link from the mail, accepts, and
/// chooses the organisation in the switcher. The mail sink is polled, so the people
/// are made side by side. Answers [{email, password, portal}] in the order of `specs`.
export async function invitedMembers(h, admin, org, specs) {
  const people = await Promise.all(
    specs.map(() => h.signUp({ kind: "personal", email: `${h.unique("member")}@example.com`, password: randomBytes(18).toString("base64url") })),
  );
  for (const [n, { role = "member", group = "none" }] of specs.entries()) {
    const sent = await admin.portal.submit(`/org/${org}`, `/org/${org}/invitations`, { email: people[n].email, role, group });
    expect(sent.status === 303, `invite ${people[n].email}: ${sent.status}\n${sent.body}`);
  }
  await Promise.all(
    people.map(async (person) => {
      // The newest mail to the address is the invitation once it has arrived.
      const invite = await h.waitFor(`the invitation to ${person.email}`, () => h.mail.link(person.email, /^\/invite$/, { timeout: 2000 }), { timeout: 90_000 });
      const page = await person.portal.get(invite.pathname + invite.search);
      expect(page.status === 200 && page.body.includes("Accept"), `the invitation page: ${page.status}\n${page.body}`);
      const accepted = await person.portal.post("/invite", { csrf: hidden(page.body, "csrf"), token: invite.searchParams.get("token") });
      expect(accepted.status === 303 && accepted.location === `/org/${org}`, `accept: ${accepted.status} ${accepted.location}\n${accepted.body}`);
      await choosePlace(person.portal, `org:${org}`);
    }),
  );
  return people;
}

/// One invited person (see `invitedMembers`).
export async function invitedMember(h, admin, org, spec = {}) {
  return (await invitedMembers(h, admin, org, [spec]))[0];
}

/// The Place switcher: "personal" or "org:<id>".
export async function choosePlace(portal, to) {
  const answer = await portal.submit("/keys", "/place", { to });
  expect(answer.status === 303, `switch to ${to}: ${answer.status}\n${answer.body}`);
}

/// The keys page's client lines, pointed at another firewall of the fleet.
export function onFirewall(lines, host) {
  return lines.replaceAll("fw1.e2e.test", host);
}

/// `GET path` on a firewall with `key` as the npm client sends it: {status, headers, body, json}.
export function fetchWith(h, firewall, path, key, headers = {}) {
  return h.request(firewall + path, { headers: { authorization: `Bearer ${key}`, ...headers }, timeout: 15_000 });
}

/// Waits until `GET path` with `key` answers `status` on every firewall in `firewalls`
/// (a policy or key change reaching the fleet): at most three sync intervals.
export async function untilStatus(h, firewalls, path, key, status, what = `${path} -> ${status}`) {
  for (const firewall of firewalls) {
    let last;
    await h.waitFor(`${what} on ${firewall}`, async () => {
      last = await fetchWith(h, firewall, path, key);
      if (last.status === status) return true;
      throw new Error(`last answer ${last.status} ${last.body.slice(0, 200)}`);
    }, { timeout: 3 * h.syncInterval * 1000, every: 500 });
  }
}

/// Waits for an /activity row matching `match` ({package, result, layer, rule}; each a
/// string the cell must include, or a RegExp). Rows arrive with each firewall's next
/// sync.
export function activityRow(h, portal, match) {
  const fits = (row) =>
    Object.entries(match).every(([field, want]) => (want instanceof RegExp ? want.test(row[field] ?? "") : (row[field] ?? "").includes(want)));
  return h.waitFor(`an activity row ${JSON.stringify(match, (_, v) => (v instanceof RegExp ? String(v) : v))}`, async () => (await h.activity(portal)).find(fits), {
    timeout: 4 * h.syncInterval * 1000,
    every: 1000,
  });
}

/// Changes the platform layer as the operator's global admin (`savePolicy` fields) and
/// answers a function that puts back its freeze, OSV and switches. Scenarios share one
/// stack, so call it in a `finally`.
export async function changePlatform(h, changes) {
  const path = "/policy/platform-1";
  const before = await policyState(h.operator.portal, path);
  const saved = await savePolicy(h.operator.portal, path, changes);
  expect(saved.status === 303, `platform policy ${JSON.stringify(changes)}: ${saved.status}\n${saved.body}`);
  return async () => {
    const back = await savePolicy(h.operator.portal, path, { freeze: before.freeze, unit: before.unit, osv: before.osv, allow: before.allow });
    expect(back.status === 303, `platform policy restored: ${back.status}\n${back.body}`);
  };
}

/// The id of the key named `name` on /keys, for its Revoke button.
export async function keyId(portal, name) {
  const listed = (await portal.get("/keys")).body;
  const id = listed.match(new RegExp(`<td>${name}</td>[\\s\\S]*?action="/keys/(\\d+)/revoke"`))?.[1];
  expect(id, `key ${name} is listed on /keys`);
  return id;
}

/// "Revoke" on the key named `name`.
export async function revokeKey(portal, name) {
  const answer = await portal.submit("/keys", `/keys/${await keyId(portal, name)}/revoke`, {});
  expect(answer.status === 303, `revoke ${name}: ${answer.status}\n${answer.body}`);
}

/// The Basic credentials pip, uv and Poetry send for the keys page's index URL.
export const basic = (key) => `Basic ${Buffer.from(`key:${key}`).toString("base64")}`;

/// A Chromium page signed in as `who` (its API-step session's cookie, as if the same
/// person opened the portal in a browser), for the steps a person does on the page.
export async function browserAs(h, who) {
  const context = await h.browser();
  await context.addCookies(
    [...who.portal.cookies].map(([name, value]) => ({ name, value, url: h.portalUrl, secure: true, httpOnly: true, sameSite: "Lax" })),
  );
  return context.newPage();
}

/// In a browser page on a policy layer: "Add block" with the form's fields
/// ({ecosystem: "npm" | "pypi", name, what: "package" | "version" | "file", version}).
export async function browserAddBlock(page, { ecosystem, name, what, version = "" }) {
  await page.selectOption("#block-ecosystem", ecosystem);
  await page.fill("#block-name", name);
  await page.selectOption("#block-what", what);
  await page.fill("#block-version", version);
  await Promise.all([page.waitForNavigation(), page.click("form:has(#block-name) button[type=submit]")]);
}

/// In a browser page: the text of each row of the first table under `heading` (an h2's text).
export async function tableRows(page, heading) {
  return page.locator(`section:has(h2:text-is("${heading}")) tbody tr`).allInnerTexts();
}
