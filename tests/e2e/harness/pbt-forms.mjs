// The input properties of the property-based portal test (tests/e2e/README.md): every
// portal form gets random strings in one field at a time (unicode with confusables,
// zero-width and bidi characters, HTML and script fragments, very long, empty and
// whitespace values, SQL-ish text, malformed emails, CIDR ranges and versions). For each:
//
// - no 5xx, and the security headers (pageProperties, on every answer);
// - the value is refused with a message on the page (role="alert"), or stored and shown
//   escaped: no fragment of HTML the value carries reaches a page raw, and in Chromium
//   no element or script of it exists (CSP: default-src 'self');
// - after a refusal the state is as it was (`fingerprint`);
// - every form needs its CSRF token: without it, or with another session's, the same
//   POST answers 403 and writes nothing.
//
// Organisation names with zero-width, bidi or confusable characters are refused once
// F31 is fixed; until then that check is "needs F31".

import fc from "fast-check";
import { Broken, CheckedPortal, newWorld, settle, signUp, totpOn } from "./pbt.mjs";
import { expect, hidden } from "./net.mjs";

const MARK = "pbt";
/// HTML a value may carry: each names the marker, so the page and the DOM can be
/// searched for it.
const HTML = [
  `<b data-${MARK}="1">x</b>`,
  `"><i data-${MARK}="2">`,
  `<script>window.__${MARK}=1</script>`,
  `<img src=x onerror="window.__${MARK}=1" data-${MARK}="3">`,
  `'><svg data-${MARK}="4" onload="window.__${MARK}=1">`,
  `</textarea><b data-${MARK}="5">`,
];
const INVISIBLE = ["​", "‌", "‍", "⁠", "﻿", "‮", "‭", "⁦", "⁧", "⁩", "؜"];
const CONFUSABLE = ["а", "е", "о", "р", "с", "і", "ο", "Α", "Ａ", "Ω"];
const ODD = [
  "",
  " ",
  "\t",
  "\n",
  " ",
  "　",
  "' OR 1=1 --",
  "'; DROP TABLE orgs; --",
  "\\",
  "%00",
  "\u0000",
  "a@b",
  "@example.com",
  "a@@example.com",
  "a b@example.com",
  "<x>@example.com",
  "x@example..com",
  "10.0.0.0/33",
  "::/129",
  "300.1.1.1/8",
  "1.2.3.4/0",
  "0.0.0.0/0",
  "fe80::1%eth0/64",
  "1..0",
  "v1.0.0",
  " 1.0.0",
  "1.0.0-",
  "~1.0",
  "*",
  "-1",
  "999999999999999999999",
  "1e3",
  "NaN",
  "delete ",
  "Ünïcödé",
  "名前",
  "🙂",
  "é",
];

/// A random field value.
export function valueArbitrary() {
  const piece = fc.oneof(
    { weight: 3, arbitrary: fc.constantFrom(...HTML) },
    { weight: 3, arbitrary: fc.constantFrom(...ODD) },
    { weight: 2, arbitrary: fc.constantFrom(...INVISIBLE, ...CONFUSABLE) },
    { weight: 3, arbitrary: fc.string({ maxLength: 12, unit: "grapheme" }) },
    { weight: 2, arbitrary: fc.string({ maxLength: 12, unit: "binary" }) },
    { weight: 2, arbitrary: fc.stringMatching(/^[a-z][a-z0-9-]{0,10}$/) },
  );
  return fc.oneof(
    { weight: 6, arbitrary: fc.array(piece, { minLength: 1, maxLength: 4 }).map((parts) => parts.join("")) },
    // Very long: past every 100-character limit, and past 254 for an email.
    { weight: 1, arbitrary: fc.tuple(piece, fc.integer({ min: 101, max: 20_000 })).map(([part, length]) => (part || "x").repeat(Math.ceil(length / Math.max(1, (part || "x").length))).slice(0, length)) },
  );
}

/// The model-visible state, as one string: the audit log's last row and the row count
/// (or sum) of every table a form writes. A refusal leaves it as it was.
function fingerprint(world) {
  return world.sql(
    `SELECT concat_ws(' ', (SELECT coalesce(max(id), 0) FROM audit_log), (SELECT count(*) FROM orgs), (SELECT count(*) FROM groups),
       (SELECT string_agg(name, ',' ORDER BY id) FROM groups), (SELECT count(*) FROM keys), (SELECT count(*) FROM invitations),
       (SELECT count(*) FROM org_ip_ranges), (SELECT count(*) || ':' || coalesce(max(refused_reason), '') FROM org_ip_ranges WHERE refused_reason IS NOT NULL),
       (SELECT coalesce(sum(revision), 0) FROM policy_layers), (SELECT count(*) FROM email_outbox), (SELECT count(*) FROM memberships),
       (SELECT string_agg(role || coalesce(group_id::text, '-'), ',' ORDER BY id) FROM memberships), (SELECT count(*) FROM logins),
       (SELECT count(*) FROM sign_in_methods), (SELECT count(*) FROM personal_accounts),
       (SELECT string_agg(id || ':' || (retired_at IS NOT NULL)::text, ',' ORDER BY id) FROM firewalls),
       (SELECT count(*) FROM totp WHERE enabled_at IS NOT NULL))`,
  );
}

/// The people and places the forms are posted as: the operator, an org admin with an
/// authenticator (its organisation, a group, a member, a waiting network-lock range),
/// a personal account, and a visitor who is signed out.
async function fixture(world) {
  const { h } = world;
  world.run = { portals: new Map(), auth: new Map() };
  const operator = new CheckedPortal(world, "operator");
  operator.cookies = h.operator.portal.cookies;
  operator.clientIp = h.operator.portal.clientIp;
  const [admin, member, solo] = await Promise.all([signUp(world, 0, "org"), signUp(world, 1, "personal"), signUp(world, 2, "personal")]);
  for (const signed of [admin, member, solo]) world.run.portals.set(signed.person.slot, signed.portal);
  await totpOn(world, admin.person);
  const org = Number(world.sql(`SELECT id FROM orgs WHERE name = '${admin.org}'`));
  expect((await admin.portal.post(`/org/${org}/groups`, { name: "Frontend" })).status === 303, "the fixture's group");
  const group = Number(world.sql(`SELECT id FROM groups WHERE org_id = ${org}`));
  expect((await admin.portal.post(`/org/${org}/invitations`, { email: member.person.email, role: "member", group: "none" })).status === 303, "the fixture's invitation");
  const token = world.sql(`SELECT substring(payload->>'body' from 'token=([A-Za-z0-9_-]+)') FROM email_outbox WHERE to_address = '${member.person.email}' ORDER BY id DESC LIMIT 1`);
  expect((await member.portal.post("/invite", { token })).status === 303, "the fixture's member joins");
  const mid = Number(world.sql(`SELECT m.id FROM memberships AS m JOIN sign_in_methods AS s ON s.login_id = m.login_id WHERE m.org_id = ${org} AND s.email = '${member.person.email}'`));
  expect((await admin.portal.post(`/org/${org}/ranges`, { cidr: "81.2.69.0/24" })).status === 303, "the fixture's range");
  const range = Number(world.sql(`SELECT id FROM org_ip_ranges WHERE org_id = ${org}`));
  const personal = Number(world.sql(`SELECT p.id FROM personal_accounts AS p JOIN sign_in_methods AS s ON s.login_id = p.login_id WHERE s.email = '${solo.person.email}'`));
  const firewall = Number(world.sql("SELECT id FROM firewalls WHERE name = 'firewall-1'"));
  const visitor = new CheckedPortal(world, "visitor");
  return { operator, admin: admin.portal, adminPerson: admin.person, member: member.portal, solo: solo.portal, soloPerson: solo.person, visitor, org, orgName: admin.org, group, mid, range, personal, firewall };
}

/// Portal forms: who posts them, their other fields and where a stored value appears.
/// The fleet's push and rollout buttons get CSRF checks only: valid posts can restart
/// or stop the stack's firewalls.
function forms(f) {
  const layer = (key) => `/policy/${key}`;
  const policy = (key, action, fields) => ({ actor: key.startsWith("personal") ? f.solo : f.admin, path: layer(key), page: layer(key), fields: { action, ...fields }, revision: true, show: layer(key) });
  return {
    "signup email": { actor: f.visitor, path: "/signup", page: "/signup", fields: { password: "a long enough passphrase 17", kind: "personal", org_name: "" }, field: "email", silent: true },
    "signup password": { actor: f.visitor, path: "/signup", page: "/signup", fields: { email: "pbt-signup@example.com", kind: "personal", org_name: "" }, field: "password", silent: true },
    "signup org name": { actor: f.visitor, path: "/signup", page: "/signup", fields: { email: "pbt-org@example.com", password: "a long enough passphrase 17", kind: "org" }, field: "org_name", silent: true, orgName: true },
    "signin email": { actor: f.visitor, path: "/signin", page: "/signin", fields: { password: "wrong password" }, field: "email" },
    "signin password": { actor: f.visitor, path: "/signin", page: "/signin", fields: { email: f.soloPerson.email }, field: "password" },
    "reset email": { actor: f.visitor, path: "/reset", page: "/reset", fields: {}, field: "email", silent: true },
    "resend email": { actor: f.visitor, path: "/verify-email/resend", page: "/signup", fields: {}, field: "email", silent: true },
    "account password": { actor: f.solo, path: "/account/password", page: "/account", fields: {}, field: "new", also: (v) => ({ current: f.soloPerson.password, again: v }), changes: (v) => (f.soloPerson.password = v) },
    "account password again": { actor: f.solo, path: "/account/password", page: "/account", fields: {}, field: "again", also: () => ({ current: f.soloPerson.password, new: "a fresh passphrase for pbt 31" }), changes: () => (f.soloPerson.password = "a fresh passphrase for pbt 31") },
    "account new org": { actor: f.solo, path: "/account/org", page: "/account", fields: {}, field: "name", show: "/account", orgName: true },
    "account delete personal": { actor: f.solo, path: "/account/personal/delete", page: "/account", fields: {}, field: "confirm", unless: (v) => v.trim() === "delete" },
    "account delete login": { actor: f.admin, path: "/account/delete", page: "/account", fields: {}, field: "confirm", unless: (v) => v.trim() === "delete" },
    "authenticator code": { actor: f.solo, path: "/account/totp/enable", page: "/account", fields: {}, field: "code", before: (p) => p.post("/account/totp/setup", {}) },
    "place": { actor: f.solo, path: "/place", page: "/keys", fields: {}, field: "to", unless: (v) => v === "personal" },
    "key name": { actor: f.solo, path: "/keys", page: "/keys", fields: {}, field: "name", show: "/keys", secret: true },
    "service key name": { actor: f.admin, path: "/keys/service", page: "/keys", fields: { attach: "org" }, field: "name", show: "/keys", secret: true },
    "service key attach": { actor: f.admin, path: "/keys/service", page: "/keys", fields: { name: "pbt-attach" }, field: "attach", secret: true },
    "block package name": policy(`org-${f.org}`, "add_block", { ecosystem: "npm", what: "package", version: "", algorithm: "sha256", digest: "" }),
    "block pypi name": policy(`personal-${f.personal}`, "add_block", { ecosystem: "pypi", what: "package", version: "" }),
    "block version": policy(`org-${f.org}`, "add_block", { ecosystem: "npm", name: "e2e-left", what: "version" }),
    "block digest": policy(`org-${f.org}`, "add_block", { ecosystem: "npm", name: "", what: "file", version: "", algorithm: "sha256" }),
    "block ecosystem": policy(`group-${f.group}`, "add_block", { name: "e2e-left", what: "package", version: "" }),
    "exception name": policy(`personal-${f.personal}`, "add_exception", { ecosystem: "npm", version: "", lifts_block: "on" }),
    "exception version": policy(`org-${f.org}`, "add_exception", { ecosystem: "pypi", name: "e2e-left", lifts_freeze: "on" }),
    "freeze": policy(`org-${f.org}`, "save", { unit: "hours", osv: "inherit" }),
    "freeze unit": policy(`org-${f.org}`, "save", { freeze: "2", osv: "inherit" }),
    "osv": policy(`group-${f.group}`, "save", { freeze: "", unit: "days" }),
    "remove block index": policy(`org-${f.org}`, "remove_block", {}),
    "group name": { actor: f.admin, path: `/org/${f.org}/groups`, page: `/org/${f.org}`, fields: {}, field: "name", show: `/org/${f.org}` },
    "group rename": { actor: f.admin, path: `/org/groups/${f.group}/rename`, page: `/org/${f.org}`, fields: {}, field: "name", show: `/org/${f.org}` },
    "invitation email": { actor: f.admin, path: `/org/${f.org}/invitations`, page: `/org/${f.org}`, fields: { role: "member", group: "none" }, field: "email", show: `/org/${f.org}` },
    "invitation role": { actor: f.admin, path: `/org/${f.org}/invitations`, page: `/org/${f.org}`, fields: { email: "pbt-role@example.com", group: "none" }, field: "role" },
    "invitation group": { actor: f.admin, path: `/org/${f.org}/invitations`, page: `/org/${f.org}`, fields: { email: "pbt-group@example.com", role: "member" }, field: "group" },
    "member role": { actor: f.admin, path: `/org/members/${f.mid}/role`, page: `/org/${f.org}`, fields: {}, field: "role" },
    "member group": { actor: f.admin, path: `/org/members/${f.mid}/group`, page: `/org/${f.org}`, fields: {}, field: "group" },
    "range": { actor: f.admin, path: `/org/${f.org}/ranges`, page: `/org/${f.org}`, fields: {}, field: "cidr", show: `/org/${f.org}` },
    "sso issuer": { actor: f.admin, path: `/org/${f.org}/sso`, page: `/org/${f.org}`, fields: { enabled: "on", client_id: "pbt-client", client_secret: "pbt-secret", allowed_tenant: "" }, field: "issuer", show: `/org/${f.org}` },
    "sso client id": { actor: f.admin, path: `/org/${f.org}/sso`, page: `/org/${f.org}`, fields: { enabled: "on", issuer: "https://idp.e2e.test", client_secret: "pbt-secret", allowed_tenant: "" }, field: "client_id", show: `/org/${f.org}` },
    "sso tenant": { actor: f.admin, path: `/org/${f.org}/sso`, page: `/org/${f.org}`, fields: { enabled: "on", issuer: "https://accounts.google.com", client_id: "pbt-google", client_secret: "pbt-secret" }, field: "allowed_tenant", show: `/org/${f.org}` },
    "automation token name": { actor: f.admin, path: `/org/${f.org}/automation`, page: `/org/${f.org}`, fields: { layer: `org-${f.org}` }, field: "name", show: `/org/${f.org}`, secret: true },
    "automation token layer": { actor: f.admin, path: `/org/${f.org}/automation`, page: `/org/${f.org}`, fields: { name: "pbt-layer" }, field: "layer", secret: true },
    "blocklist import": { actor: f.admin, path: `/org/${f.org}/blocklist`, page: `/org/${f.org}`, fields: {}, field: "file" },
    "org delete confirm": { actor: f.admin, path: `/org/${f.org}/delete`, page: `/org/${f.org}`, fields: {}, field: "confirm", unless: (v) => v.split(/\s+/).filter(Boolean).join(" ").toLowerCase() === f.orgName.toLowerCase() },
    "admin invite email": { actor: f.operator, path: "/admin/admins/invite", page: "/admin", fields: {}, field: "email", show: "/admin" },
    "admin range reason": { actor: f.operator, path: `/admin/ranges/${f.range}/refuse`, page: "/admin", fields: {}, field: "reason", show: `/org/${f.org}`, showAs: f.admin },
    "admin limits rate": { actor: f.operator, path: "/admin/limits", page: "/admin", fields: { kind: "org", org: "", keys: "20", service: "" }, field: "rate" },
    "admin limits keys": { actor: f.operator, path: "/admin/limits", page: "/admin", fields: { kind: "personal", org: "", rate: "1200", service: "" }, field: "keys" },
    "admin retention": { actor: f.operator, path: "/admin/retention", page: "/admin", fields: { audit_days: "365" }, field: "activity_days" },
    "platform token name": { actor: f.operator, path: "/admin/tokens", page: "/admin", fields: {}, field: "name", show: "/admin", secret: true },
    "platform blocklist import": { actor: f.operator, path: "/admin/blocklist", page: "/admin", fields: {}, field: "file" },
    "fleet register name": { actor: f.operator, path: "/fleet/register", page: "/fleet", fields: { sources: "11.225.0.0/24" }, field: "name", show: "/fleet", secret: true },
    "fleet register sources": { actor: f.operator, path: "/fleet/register", page: "/fleet", fields: { name: "pbt-sources" }, field: "sources", secret: true },
    "fleet retire confirmation": { actor: f.operator, path: `/fleet/${f.firewall}/retire`, page: "/fleet", fields: {}, field: "confirm", unless: (v) => v.trim() === "firewall-1" },
    "fleet settings CSRF": { actor: f.operator, path: "/fleet/settings", fields: { firewall: String(f.firewall), toml: "max_active_requests = 64\n" }, csrfOnly: true },
    "fleet skip CSRF": { actor: f.operator, path: "/fleet/rollouts/0/skip", fields: {}, csrfOnly: true },
    "fleet resume CSRF": { actor: f.operator, path: "/fleet/rollouts/0/resume", fields: {}, csrfOnly: true },
  };
}

const alertOf = (body) => body.match(/role="alert">\s*([^<]+)</)?.[1]?.trim() ?? "";
/// What a refusal tells the person: the page's alert, or the text of a plain answer
/// (axum's own refusal of a field it cannot read, such as a hidden index).
const messageOf = (answer) => (/^text\/html/.test(answer.headers["content-type"] ?? "") ? alertOf(answer.body) : answer.body.trim());
const invisible = (v) => [...INVISIBLE, ...CONFUSABLE].some((c) => v.includes(c));

/// One form, one value: the input properties.
async function onePost(world, f, name, form, value) {
  const fields = { ...form.fields, ...form.also?.(value), [form.field]: value };
  if (form.before) await form.before(form.actor);
  if (form.revision) fields.revision = hidden((await form.actor.get(form.page)).body, "revision");
  const before = fingerprint(world);
  const answer = await form.actor.submit(form.page, form.path, fields);
  const what = `${name} = ${JSON.stringify(value.length > 80 ? `${value.slice(0, 80)}…(${value.length})` : value)}`;
  const shown = [answer.body];
  const stored = answer.status === 303 || (form.secret && answer.status === 200 && !alertOf(answer.body));
  const accepted = stored || (form.silent && answer.status === 200 && !alertOf(answer.body));
  if (accepted && form.orgName && invisible(value)) world.needs.check("F31", false, `${what}: an organisation name with an invisible, bidi or confusable character is accepted`);
  if (stored) {
    form.changes?.(value);
    if (form.secret) for (const secret of answer.body.match(/<code id="new-(?:key|token)">([^<]*)<\/code>/g) ?? []) world.secrets.add(secret.replace(/<[^>]+>/g, ""));
    if (form.show) shown.push((await (form.showAs ?? form.actor).get(form.show)).body);
  } else if (!accepted) {
    if (!messageOf(answer) && answer.status !== 404) throw new Broken(`${what}: refused (${answer.status}) with no message on the page`);
    const after = fingerprint(world);
    if (after !== before) throw new Broken(`${what}: refused (${answer.status} ${alertOf(answer.body)}) but the state changed:\n  ${before}\n  ${after}`);
  }
  // Shown escaped: none of the HTML the value carries reaches a page as markup.
  for (const fragment of HTML) {
    if (!value.includes(fragment)) continue;
    for (const body of shown) if (body.includes(fragment)) throw new Broken(`${what}: a page shows ${fragment} unescaped`);
  }
  if (stored && form.show && HTML.some((fragment) => value.includes(fragment))) await domClean(world, form.showAs ?? form.actor, form.show, what);
}

/// In Chromium, as the person who stored the value: no element or script of it exists.
async function domClean(world, portal, path, what) {
  if (world.domChecks >= world.settings.domSample) return;
  world.domChecks += 1;
  const context = await world.h.browser();
  try {
    await context.addCookies([...portal.cookies].map(([name, value]) => ({ name, value, url: world.h.portalUrl, secure: true, httpOnly: true, sameSite: "Lax" })));
    const page = await context.newPage();
    const answer = await page.goto(path);
    const csp = answer.headers()["content-security-policy"] ?? "";
    const found = await page.evaluate((mark) => ({ elements: document.querySelectorAll(`[data-${mark}]`).length, script: window[`__${mark}`] !== undefined }), MARK);
    if (found.elements || found.script || !/default-src 'self'/.test(csp)) throw new Broken(`${what}: on ${path} in Chromium ${found.elements} injected elements, script ran: ${found.script}, CSP ${JSON.stringify(csp)}`);
  } finally {
    await context.close();
  }
}

/// Without its CSRF token, or with another session's, every form answers 403 and
/// writes nothing (C101).
async function csrfRequired(world, f, all) {
  const other = hidden((await f.member.get("/account")).body, "csrf");
  for (const [name, form] of Object.entries(all)) {
    const fields = form.csrfOnly ? form.fields : { ...form.fields, [form.field]: "pbt-csrf@example.com" };
    for (const csrf of [undefined, "", other]) {
      const before = fingerprint(world);
      const answer = await form.actor.fetch(form.path, csrf === undefined ? fields : { ...fields, csrf });
      if (answer.status !== 403) throw new Broken(`${name}: a POST to ${form.path} with ${csrf === undefined ? "no" : csrf ? "another session's" : "an empty"} CSRF token answered ${answer.status}`);
      if (fingerprint(world) !== before) throw new Broken(`${name}: a POST to ${form.path} without its CSRF token wrote something`);
    }
  }
}

/// The input properties: `settings.formRuns` random (form, value) pairs, shrunk on
/// failure, after the CSRF check of every form. Throws with the seed and the case.
export async function formProperties(h, config) {
  const world = newWorld(h, config);
  world.domChecks = 0;
  const f = await fixture(world);
  const all = forms(f);
  await csrfRequired(world, f, all);
  h.log(`pbt forms: CSRF required by all ${Object.keys(all).length} forms`);
  const names = Object.keys(all).filter((name) => !all[name].csrfOnly);
  const started = Date.now();
  const details = await fc.check(
    fc.asyncProperty(fc.constantFrom(...names), valueArbitrary(), async (name, value) => {
      const form = all[name];
      if (form.unless?.(value)) return;
      await onePost(world, f, name, form, value);
    }),
    { numRuns: config.formRuns, seed: config.seed, path: config.path, endOnFailure: config.maxShrinks === 0, plugins: [fc.interruptAfterTimeLimit(config.timeLimit * 1000)] },
  );
  h.log(`pbt forms: ${details.numRuns} values over ${names.length} forms in ${((Date.now() - started) / 1000).toFixed(0)} s, ${world.domChecks} DOM checks${details.interrupted ? ", stopped at the time limit" : ""}`);
  if (details.failed) {
    const [name, value] = details.counterexample;
    const error = details.errorInstance;
    throw new Error(
      `PBT forms failure, seed ${details.seed} path ${details.counterexamplePath} after ${details.numShrinks} shrinks: ${String(error?.message ?? error).split("\n")[0]}\n` +
        `replay: E2E_PBT_SEED=${details.seed} E2E_PBT_PATH=${details.counterexamplePath}\nminimal case: ${name} = ${JSON.stringify(value)}\n${error?.stack ?? ""}`,
    );
  }
  settle(world, details.seed);
}

/// Fixed (form, value) cases, as regression scenarios replay them: `form` null is every
/// form. Every case runs; the failures are listed together.
export async function formCases(h, config, cases) {
  const world = newWorld(h, config);
  world.domChecks = 0;
  const f = await fixture(world);
  const all = forms(f);
  const failures = [];
  for (const [only, value] of cases) {
    for (const name of only ? [only] : Object.keys(all)) {
      if (all[name].csrfOnly) continue;
      if (all[name].unless?.(value)) continue;
      try {
        await onePost(world, f, name, all[name], value);
      } catch (err) {
        if (!(err instanceof Broken)) throw err;
        failures.push(`${name} = ${JSON.stringify(value)}: ${err.message}`);
      }
    }
  }
  expect(failures.length === 0, `${failures.length} cases failed:\n- ${failures.join("\n- ")}`);
  settle(world, config.seed);
}
