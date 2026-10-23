// Steps of the scenarios about people and their keys (E2E-004, E2E-017 to E2E-020):
// joining an organisation by invitation, rows of the organisation page, a key's answer
// on the firewalls, and `Needs` for checks that wait on a known product fix.

import { expect, hidden } from "./net.mjs";

/// `.npmrc` or `pip.conf` lines as the keys page shows them (for fw1), for another
/// firewall of the stack.
export const onFirewall = (lines, host) => lines.replaceAll("fw1.e2e.test", `${host}.e2e.test`);

/// Checks that wait on a product fix not merged yet ("needs F7"): a failed one is
/// logged and the scenario goes on, so every later step still runs; `done()` throws,
/// listing them. A check that passes is logged too, so a fix shows in the log.
export class Needs {
  constructor(log) {
    this.log = log;
    this.failed = [];
  }

  check(tag, condition, message) {
    if (condition) {
      this.log(`${tag}: holds (${message})`);
      return true;
    }
    this.log(`EXPECTED FAILURE, needs ${tag}: ${message}`);
    this.failed.push(`needs ${tag}: ${message}`);
    return false;
  }

  done() {
    expect(this.failed.length === 0, `failed only where a product fix is pending:\n- ${this.failed.join("\n- ")}`);
  }
}

/// The id of the organisation the session's place is (`/org` -> `/org/<id>`).
export async function orgId(portal) {
  const { location } = await portal.get("/org");
  const id = location?.match(/^\/org\/(\d+)$/)?.[1];
  expect(id, `/org leads to ${location}`);
  return id;
}

/// The member id on `/org/<org>` of the member whose email is `email` (or null).
export async function memberId(portal, org, email) {
  const page = (await portal.get(`/org/${org}`)).body;
  const row = page.split("<tr>").find((tr) => tr.startsWith(`<td>${email}`) && tr.includes("/org/members/"));
  return row?.match(/\/org\/members\/(\d+)\/remove/)?.[1] ?? null;
}

/// POSTs a form from the page `page` (its CSRF token) to `path`; expects a redirect.
export async function act(portal, page, path, fields = {}) {
  const answer = await portal.submit(page, path, fields);
  expect(answer.status === 303, `${path}: ${answer.status}\n${answer.body}`);
  return answer;
}

/// Deletes the mail to `email` from the sink, so the next `h.mail.latest(email)` waits
/// for a new one.
export async function forgetMail(h, email) {
  const answer = await h.request(`http://mail.e2e.test:8025/api/v1/search?query=${encodeURIComponent(`to:"${email}"`)}`, { method: "DELETE" });
  expect(answer.status === 200, `mail sink: ${answer.status} ${answer.body}`);
}

/// The org admin `admin` invites `email` (role, group id or "none") to `org`; answers
/// the link from the mail.
export async function invite(h, admin, org, email, { role = "member", group = "none" } = {}) {
  await forgetMail(h, email);
  await act(admin.portal, `/org/${org}`, `/org/${org}/invitations`, { email, role, group });
  return h.mail.link(email, /^\/invite$/, { subject: "invitation" });
}

/// Opens an invitation link signed in as `who` and presses Accept: the org id joined.
export async function accept(who, link) {
  const page = await who.portal.get(link.pathname + link.search);
  expect(page.status === 200 && page.body.includes('action="/invite"'), `invitation page: ${page.status}\n${page.body}`);
  const answer = await who.portal.post("/invite", { csrf: hidden(page.body, "csrf"), token: hidden(page.body, "token") });
  const org = answer.location?.match(/^\/org\/(\d+)$/)?.[1];
  expect(answer.status === 303 && org, `accept: ${answer.status} ${answer.location}\n${answer.body}`);
  return org;
}

/// Chooses the organisation `org` in the place switcher.
export async function choose(portal, org) {
  await act(portal, "/account", "/place", { to: `org:${org}` });
}

/// `who` (signed in, with a confirmed address) joins `org` by an invitation from
/// `admin`, accepts it and chooses `org` as the place to work in.
export async function join(h, admin, org, who, options = {}) {
  await accept(who, await invite(h, admin, org, who.email, options));
  await choose(who.portal, org);
  return who;
}

/// The id of the key named `name` on the session's `/keys` page.
export async function keyId(portal, name) {
  const page = (await portal.get("/keys")).body;
  const id = page.match(new RegExp(`<td>${name}</td>[\\s\\S]*?action="/keys/(\\d+)/revoke"`))?.[1];
  expect(id, `key ${name} is listed on /keys`);
  return id;
}

const FIREWALLS = ["fw1", "fw2"];

/// The status a firewall answers for the e2e-left packument with `key`.
export async function keyStatus(h, host, key) {
  return (await h.request(`https://${host}.e2e.test/npm/e2e-left`, { headers: { authorization: `Bearer ${key}` }, timeout: 15_000 })).status;
}

/// Waits until every firewall answers `status` for `key`: within one sync interval of
/// the change, plus the time one sync round and the check itself take.
export async function keyAnswers(h, key, status, { what = "the key", hosts = FIREWALLS, timeout = (h.syncInterval + 5) * 1000 } = {}) {
  await Promise.all(
    hosts.map((host) => h.waitFor(`${what} answers ${status} on ${host}`, async () => (await keyStatus(h, host, key)) === status, { timeout })),
  );
}

/// Every request of the harness reaches the server from one address (the bridge, behind
/// the gateway), so the whole suite shares one client address's caps: 20 mail-sending
/// requests (sign-up, resend, reset) in 15 minutes. A scenario stands for people on
/// their own networks, so it starts with that window back-dated past its 15 minutes
/// (D10).
export function freshMailWindow(h) {
  h.backdate("sign_in_failures", "at", "15 minutes", "scope = 'ip' AND subject LIKE 'mail %'");
}
