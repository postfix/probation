// The property-based portal test (tests/e2e/README.md, "Property-based tests"): a
// model-based run of random command sequences with fast-check (`fc.commands` and
// `fc.asyncModelRun`) against the deployed stack, checking after every command what
// each person's portal shows (isolation, C1), who may do what (C24, C27), the audit rows
// (C25) and, on a sample of keys, what the firewalls answer (C8). Every portal answer the
// run gets passes the page properties: no 5xx, the security headers, no secret shown
// after the answer that created it; axe runs on a sample of the pages reached.
//
// The pure model (roles, visibility, the policy merge) is harness/pbt-model.mjs.

import fc from "fast-check";
import { randomBytes } from "node:crypto";
import { Authenticator, Portal, between, expect, hidden, request, unescape } from "./net.mjs";
import { Needs } from "./people.mjs";
import {
  DAY,
  HOUR,
  checkEdit,
  chainOf,
  cloneLayer,
  currentPlace,
  emptyLayer,
  keyDecision,
  mayEdit,
  membership,
  placeOf,
  places,
  roleFor,
  visible,
  withheld,
} from "./pbt-model.mjs";

// ---- Settings --------------------------------------------------------------------------

/// The bounds of each suite; every one can be overridden from the environment.
const PROFILES = {
  // PR: one short sequence with a fixed seed, about a minute.
  pr: { runs: 1, commands: 8, seed: 20261054, timeLimit: 90, maxShrinks: 0, firewallSample: 1, axeSample: 1, formRuns: 40, domSample: 2 },
  // Nightly: its own shard and stack, about 15 minutes.
  pbt: { runs: 20, commands: 25, timeLimit: 11 * 60, maxShrinks: 40, firewallSample: 3, axeSample: 1, formRuns: 400, domSample: 10 },
  "pbt-weekly": { runs: 100, commands: 40, timeLimit: 100 * 60, maxShrinks: 200, firewallSample: 4, axeSample: 2, formRuns: 4000, domSample: 40 },
};

/// E2E_PBT_RUNS, _COMMANDS, _SEED, _PATH, _REPLAY (the commands' replayPath), _TIME_LIMIT
/// (seconds, generation and shrinking), _MAX_SHRINKS, _FIREWALL_SAMPLE (keys per check),
/// _AXE_SAMPLE (pages per run), _MAIL ("outbox" or "sink", see `mailLink`), _PEOPLE (the
/// most people in a run), _FORM_RUNS (values the input properties try), _DOM_SAMPLE
/// (stored HTML values checked in Chromium), _VERBOSE=1 (every command and its answer).
export function settings(suite) {
  const base = PROFILES[suite] ?? PROFILES.pbt;
  const env = (name, fallback, parse = Number) => (process.env[`E2E_PBT_${name}`] === undefined ? fallback : parse(process.env[`E2E_PBT_${name}`]));
  return {
    runs: env("RUNS", base.runs),
    commands: env("COMMANDS", base.commands),
    seed: env("SEED", base.seed ?? Math.floor(Math.random() * 2 ** 31)),
    path: env("PATH", undefined, String),
    replayPath: env("REPLAY", undefined, String),
    timeLimit: env("TIME_LIMIT", base.timeLimit),
    maxShrinks: env("MAX_SHRINKS", base.maxShrinks),
    firewallSample: env("FIREWALL_SAMPLE", base.firewallSample),
    axeSample: env("AXE_SAMPLE", base.axeSample),
    mail: env("MAIL", "outbox", String),
    people: env("PEOPLE", 8),
    formRuns: env("FORM_RUNS", base.formRuns),
    domSample: env("DOM_SAMPLE", base.domSample),
    verbose: env("VERBOSE", false, (v) => v === "1"),
  };
}

// ---- The real system -------------------------------------------------------------------

/// A property of the system that failed: fails the run (and is shrunk).
export class Broken extends Error {}

const q = (text) => `'${String(text).replaceAll("'", "''")}'`;
const SECURITY_HEADERS = {
  "content-security-policy": (v) => /default-src 'self'/.test(v) && /frame-ancestors 'none'/.test(v),
  "x-content-type-options": (v) => v === "nosniff",
  "referrer-policy": (v) => v === "no-referrer",
  "cache-control": (v) => v === "no-store",
};

/// The page properties on one portal answer: below 500, the security headers, and no
/// secret shown by an earlier answer (a key is shown once, on the answer creating it).
export function pageProperties(world, method, path, answer) {
  if (answer.status >= 500) throw new Broken(`${method} ${path} answered ${answer.status}: ${answer.body.slice(0, 300)}`);
  for (const [name, ok] of Object.entries(SECURITY_HEADERS)) {
    if (!ok(answer.headers[name] ?? "")) throw new Broken(`${method} ${path} (${answer.status}): header ${name} is ${JSON.stringify(answer.headers[name])}`);
  }
  for (const secret of world.secrets) {
    if (answer.body.includes(secret)) throw new Broken(`${method} ${path} shows a secret again (…${secret.slice(-4)})`);
  }
}

/// A Portal whose every answer passes `pageProperties`; GET pages are kept for axe.
export class CheckedPortal extends Portal {
  constructor(world, slot) {
    super();
    this.world = world;
    this.slot = slot;
  }

  async fetch(path, form) {
    const answer = await super.fetch(path, form);
    const method = form ? "POST" : "GET";
    pageProperties(this.world, method, path, answer);
    if (!form && answer.status === 200 && /^text\/html/.test(answer.headers["content-type"] ?? "")) {
      this.world.pages.set(path.replace(/\d+/g, "N").replace(/\?.*/, ""), { path, slot: this.slot });
    }
    return answer;
  }

  /// The session's CSRF token, from any signed-in page (it lasts as long as the session).
  async csrf() {
    this.token ??= hidden((await this.get("/account")).body, "csrf");
    return this.token;
  }

  async post(path, form) {
    if (form && !("csrf" in form)) form = { csrf: await this.csrf(), ...form };
    return super.post(path, form);
  }

  forget() {
    this.token = undefined;
  }
}

/// The newest link to `to` whose path matches `path`. With E2E_PBT_MAIL=outbox (the
/// default) it is read from the server's outbox row as soon as the mail is queued, and
/// its delivery through SMTP to the sink is checked at the end of the scenario
/// (`mailDelivered`): the outbox job sends every 30 s, too slow to wait for in each
/// command. With "sink" every link is waited for in the sink.
async function mailLink(world, to, path) {
  const fromText = (text) => text?.match(/https?:\/\/\S+/g)?.map((u) => new URL(u.replace(/[.,)>]+$/, ""))).find((u) => path.test(u.pathname));
  const url = await world.h.waitFor(`mail to ${to}`, async () => {
    if (world.settings.mail === "outbox") {
      const body = world.sql(`SELECT coalesce(payload->>'body', '') FROM email_outbox WHERE to_address = ${q(to)} ORDER BY id DESC LIMIT 1`);
      if (body) return fromText(body);
    }
    const { messages } = (await request(`${MAIL}/search?query=${encodeURIComponent(`to:"${to}"`)}`)).json();
    if (!messages?.length) return null;
    return fromText((await request(`${MAIL}/message/${messages[0].ID}`)).json().Text);
  }, { timeout: 70_000, every: 300 });
  world.mails.push({ to, url: url.toString() });
  return url;
}

const MAIL = "http://mail.e2e.test:8025/api/v1";

/// Every link the run read from the outbox reached the SMTP sink in a mail to its address.
export async function mailDelivered(world) {
  const waiting = world.mails.splice(0);
  await world.h.waitFor(`${waiting.length} mails in the sink`, async () => {
    for (const mail of [...waiting]) {
      const { messages } = (await request(`${MAIL}/search?query=${encodeURIComponent(`to:"${mail.to}"`)}`)).json();
      for (const message of messages ?? []) {
        if ((await request(`${MAIL}/message/${message.ID}`)).json().Text.includes(mail.url)) {
          waiting.splice(waiting.indexOf(mail), 1);
          break;
        }
      }
    }
    if (waiting.length) throw new Error(`not delivered: ${waiting.map((m) => m.to).join(", ")}`);
    return true;
  }, { timeout: 75_000, every: 2000 });
}

/// What the scenario's runs share: the harness, the operator, the needs list and the
/// pages and mails seen. `world.run` is the current run's real side.
let currentWorld;

export function newWorld(h, config) {
  const world = (currentWorld = {
    h,
    settings: config,
    needs: new Needs(h.log),
    sql: (statement) => h.stack.sql(statement),
    secrets: new Set(),
    pages: new Map(),
    mails: [],
    stats: { runs: 0, commands: 0, refused: 0, firewallChecks: 0, axePages: 0, byCommand: {} },
  });
  world.operator = h.operator;
  world.bootstrapOrg = Number(h.bootstrap.org);
  return world;
}

// ---- Steps shared by the commands ------------------------------------------------------

const OLD = 300 * DAY;
/// Versions the firewall checks ask for: the fakes' seed catalogue, plus `e2e-fresh`
/// 1.0.0 published an hour before the scenario starts (`fresh`: its age grows).
const TARGETS = [
  { ecosystem: "npm", name: "e2e-left", version: "1.0.0" },
  { ecosystem: "npm", name: "e2e-left", version: "1.1.0" },
  { ecosystem: "npm", name: "e2e-left", version: "2.0.0" },
  { ecosystem: "npm", name: "e2e-right", version: "1.0.0" },
  { ecosystem: "npm", name: "e2e-fresh", version: "1.0.0", fresh: true },
  { ecosystem: "pypi", name: "e2e-left", version: "1.0.0" },
  { ecosystem: "pypi", name: "e2e-left", version: "1.1.0" },
];

/// Publishes `e2e-fresh` 1.0.0, an hour old, for the freeze checks.
async function publishFresh(world) {
  await world.h.fakes.publishNpm({ name: "e2e-fresh", version: "1.0.0", ageSeconds: HOUR });
  world.freshAt = Date.now() - HOUR * 1000;
}

/// The `Needs` tag of the known defect: a firewall keeps a cached key's policy for up to
/// 5 minutes after the policy changes.
export const STALE = "stale-key-policy";

const ageOf = (world, target) => (target.fresh ? (Date.now() - world.freshAt) / 1000 : OLD);
const NAMES = { npm: ["e2e-left", "e2e-right", "e2e-fresh"], pypi: ["e2e-left"] };
/// The versions of a package blocks and exceptions name: the ones the checks ask for.
const versionsOf = (ecosystem, name) => TARGETS.filter((t) => t.ecosystem === ecosystem && t.name === name).map((t) => t.version);

const pick = (list, k) => (list.length ? list[k % list.length] : undefined);
const live = (person) => person && person.signedIn && !person.loginDeleted;
const orgPlace = (org) => ({ kind: "org", id: org.id, org: org.id });
const userPlace = (org, member) => ({ kind: "user", id: member.mid, org: org.id, group: member.group, mid: member.mid });
const groupPlace = (org, group) => ({ kind: "group", id: group.id, org: org.id, group: group.id });
const keyOfPlace = (place) => `${place.kind}-${place.id}`;
const portalOf = (world, person) => world.run.portals.get(person.slot);
const label = (m, person) => `P${person.slot}`;
const orgLabel = (m, org) => `O${m.orgs.indexOf(org)}`;

/// The answer one action of a person should get: "ok" (303, or 200 for a page that
/// shows a new secret), "404", "403", "2fa" (303 to set up an authenticator), or a
/// refusal shown on the page (409, 410, 422) with its message.
function expectAnswer(answer, expected, what) {
  const alert = answer.body.match(/role="alert">([^<]*)</)?.[1] ?? answer.body.match(/<h1>([^<]*)</)?.[1] ?? "";
  const got = `${answer.status}${answer.location ? ` -> ${answer.location}` : ""} ${unescape(alert)}`.trim();
  const fits = {
    ok: answer.status === 303 && answer.location !== "/account#totp-heading",
    page: answer.status === 200,
    404: answer.status === 404,
    403: answer.status === 403,
    "2fa": answer.status === 303 && answer.location === "/account#totp-heading",
    409: answer.status === 409 && alert.trim() !== "",
    410: answer.status === 410,
    422: answer.status === 422 && alert.trim() !== "",
  }[expected];
  if (!fits) throw new Broken(`${what}: the model expects ${expected}, the portal answered ${got}`);
  if (currentWorld?.run) currentWorld.run.answer = got;
  return answer;
}

/// `admin_on`: the org admin's check of every organisation action after the id.
function adminOn(m, person, place) {
  if (withheld(m, person, place)) return "2fa";
  return roleFor(m, person, place) === "org_admin" ? null : "403";
}

/// The ids the run learns from the system (never what it checks).
function memberIdOf(world, org, person) {
  return Number(world.sql(`SELECT m.id FROM memberships AS m JOIN sign_in_methods AS s ON s.login_id = m.login_id WHERE m.org_id = ${org.id} AND lower(s.email) = ${q(person.email)} AND s.kind = 'password'`));
}

/// A new person signs up (an organisation of their own or a personal account),
/// confirms the address from the mail and signs in: {person, portal, org}.
export async function signUp(world, slot, kind) {
  const person = {
    slot,
    email: `${world.h.unique(`pbt${slot}`)}@example.com`,
    password: randomBytes(18).toString("base64url"),
    totp: false,
    sessionTotpOk: false,
    signedIn: false,
    loginDeleted: false,
    personal: null,
    chosen: null,
  };
  const portal = new CheckedPortal(world, slot);
  const org = kind === "org" ? world.h.unique("PBT") : "";
  let page = await portal.submit("/signup", "/signup", { email: person.email, password: person.password, kind, org_name: org });
  expect(page.status === 200 && page.body.includes("Check your email"), `sign-up: ${page.status}\n${page.body.slice(0, 500)}`);
  const link = await mailLink(world, person.email, /^\/verify-email$/);
  page = await portal.get(link.pathname + link.search);
  expect(page.body.includes("Your email address is confirmed"), `confirm: ${page.status}\n${page.body.slice(0, 500)}`);
  page = await portal.submit("/signin", "/signin", { email: person.email, password: person.password });
  expect(page.status === 303 && page.location === "/account", `sign-in: ${page.status} ${page.location}`);
  person.signedIn = true;
  return { person, portal, org };
}

/// Adds a signed-up person, and their organisation or personal account, to the model.
function register(world, m, { person, portal, org }) {
  world.run.portals.set(person.slot, portal);
  m.people[person.slot] = person;
  if (org) {
    const id = Number(world.sql(`SELECT id FROM orgs WHERE name = ${q(org)}`));
    const record = { id, name: org, status: "active", groups: [], members: [], invitations: [], leave: new Set(), removed: new Map() };
    m.orgs.push(record);
    const mid = memberIdOf(world, record, person);
    record.members.push({ slot: person.slot, mid, role: "org_admin", group: null });
    m.layers[`org-${id}`] = emptyLayer("org");
    m.layers[`user-${mid}`] = emptyLayer("user");
    return ["org.create"];
  }
  const id = Number(world.sql(`SELECT p.id FROM personal_accounts AS p JOIN sign_in_methods AS s ON s.login_id = p.login_id WHERE lower(s.email) = ${q(person.email)}`));
  person.personal = { id, deleted: false };
  m.layers[`personal-${id}`] = emptyLayer("personal");
  return ["personal.create"];
}

/// Turns the authenticator on for a signed-in person's session (the setup form, then
/// a code); the session stays signed in.
export async function totpOn(world, person) {
  const portal = portalOf(world, person);
  const page = await portal.post("/account/totp/setup", {});
  expect(page.status === 200, `authenticator setup: ${page.status}`);
  const auth = new Authenticator(between(page.body, '<code id="totp-key">', "</code>").replace(/\s/g, ""));
  const on = await portal.post("/account/totp/enable", { code: await auth.code() });
  expect(on.status === 303, `authenticator: ${on.status}\n${on.body.slice(0, 300)}`);
  world.run.auth.set(person.slot, auth);
  person.totp = true;
}

/// Ends the membership in the model as `end_membership` does.
function endMembership(m, org, member, removed) {
  for (const key of m.keys) if (key.place === `user-${member.mid}`) key.revoked = true;
  org.leave.delete(member.slot);
  withdrawInvitations(org, member.slot);
  if (removed) org.removed.set(member.slot, ++m.seq);
  org.members.splice(org.members.indexOf(member), 1);
  delete m.layers[`user-${member.mid}`];
}

const withdrawInvitations = (org, slot) => {
  for (const invitation of org.invitations) if (invitation.sender === slot && !invitation.accepted) invitation.withdrawn = true;
};

/// The last org admin of the organisation: refused (409) when they would stop being one.
const lastAdmin = (org, member) => member.role === "org_admin" && !org.members.some((x) => x !== member && x.role === "org_admin");

// ---- Commands --------------------------------------------------------------------------

/// The base of every command: `who` and the other numbers pick among the model's
/// people, orgs and so on at run time (k modulo the count), so a shrunk sequence stays
/// meaningful. `probe` picks the foreign ids the invariants try.
class Command {
  constructor(args) {
    Object.assign(this, args);
  }

  check() {
    return true;
  }

  toString() {
    return this.label ?? `${this.constructor.name}(${JSON.stringify(this.args ?? {})})`;
  }

  async run(m, world) {
    const actions = (await this.act(m, world)) ?? [];
    world.stats.commands += 1;
    const tally = (world.stats.byCommand[this.constructor.name] ??= { changed: 0, unchanged: 0 });
    tally[actions.length ? "changed" : "unchanged"] += 1;
    if (world.settings.verbose) world.h.log(`  ${this} -> ${world.run.answer ?? ""} [${actions.join(" ")}]`);
    world.run.answer = undefined;
    await invariants(m, world, this, actions);
  }
}

/// A signed-in person acting: the `who`-th of those signed in or, with `as`, of those
/// whose role allows the action (`able`) when there are any. Without `as` the actor is
/// anyone, so most of those actions probe a refusal.
class PersonCommand extends Command {
  able() {
    return true;
  }

  actor(m) {
    const people = m.people.filter(live);
    const able = this.as ? people.filter((person) => this.able(m, person)) : [];
    return pick(able.length ? able : people, this.who);
  }

  check(m) {
    return Boolean(this.actor(m));
  }
}

export class SignUp extends Command {
  check(m) {
    return m.people.length < m.maxPeople;
  }

  async act(m, world) {
    this.label = `SignUp(${this.kind}) as P${m.people.length}`;
    return register(world, m, await signUp(world, m.people.length, this.kind));
  }
}

export class SignOut extends PersonCommand {
  async act(m, world) {
    const person = this.actor(m);
    this.label = `SignOut(${label(m, person)})`;
    const portal = portalOf(world, person);
    const answer = await portal.post("/signout", {});
    expect(answer.status === 303 && answer.location === "/signin", `${this.label}: ${answer.status} ${answer.location}`);
    portal.forget();
    person.signedIn = false;
  }
}

/// The `who`-th of the people signed out (whose login is not deleted) signs in.
export class SignIn extends Command {
  person(m) {
    return pick(m.people.filter((p) => !p.signedIn && !p.loginDeleted), this.who);
  }

  check(m) {
    return Boolean(this.person(m));
  }

  async act(m, world) {
    const person = this.person(m);
    this.label = `SignIn(${label(m, person)})`;
    const portal = portalOf(world, person);
    let page = await portal.submit("/signin", "/signin", { email: person.email, password: person.password });
    if (person.totp) {
      expect(page.status === 303 && page.location === "/totp", `${this.label}: asked for a code: ${page.status} ${page.location}`);
      page = await portal.submit("/totp", "/totp", { code: await world.run.auth.get(person.slot).code() });
    }
    expect(page.status === 303 && page.location === "/account", `${this.label}: ${page.status} ${page.location}`);
    portal.forget();
    Object.assign(person, { signedIn: true, chosen: null, sessionTotpOk: person.totp });
  }
}

export class TotpOn extends PersonCommand {
  async act(m, world) {
    const person = this.actor(m);
    this.label = `TotpOn(${label(m, person)})`;
    if (person.totp) {
      // The setup form of a login that has one already sends it back to the account page.
      expect((await portalOf(world, person).post("/account/totp/setup", {})).location === "/account", `${this.label}: on already`);
      return [];
    }
    await totpOn(world, person);
    return ["totp.enable"];
  }
}

export class TotpOff extends PersonCommand {
  able(m, person) {
    return person.totp && !m.orgs.some((org) => membership(org, person.slot)?.role === "org_admin");
  }

  async act(m, world) {
    const person = this.actor(m);
    this.label = `TotpOff(${label(m, person)})`;
    // C24: an org admin of a live organisation keeps it; so does a login without one.
    const required = m.orgs.some((org) => membership(org, person.slot)?.role === "org_admin");
    const portal = portalOf(world, person);
    const answer = await portal.post("/account/totp/disable", {});
    if (required || !person.totp) {
      expectAnswer(answer, "403", this.label);
      return [];
    }
    expectAnswer(answer, "ok", this.label);
    person.totp = false;
    return ["totp.disable"];
  }
}

export class SwitchPlace extends PersonCommand {
  async act(m, world) {
    const person = this.actor(m);
    const own = places(m, person);
    // One past the person's own places: an organisation they are not in (C1, C29).
    const foreign = m.orgs.find((org) => !membership(org, person.slot));
    const choices = [...own, ...(foreign ? [`org:${foreign.id}`] : [])];
    const to = pick(choices, this.place);
    if (!to) return [];
    this.label = `SwitchPlace(${label(m, person)} to ${to.startsWith("org:") ? orgLabel(m, m.orgs.find((o) => `org:${o.id}` === to)) : to})`;
    const answer = await portalOf(world, person).post("/place", { to });
    expectAnswer(answer, own.includes(to) ? "ok" : "404", this.label);
    if (own.includes(to)) person.chosen = to;
  }
}

/// An organisation action by `who` on the `org`-th organisation.
class OrgCommand extends PersonCommand {
  check(m) {
    return m.orgs.length > 0 && super.check(m);
  }

  able(m, person) {
    return roleFor(m, person, orgPlace(pick(m.orgs, this.org))) === "org_admin";
  }

  setup(m) {
    const person = this.actor(m);
    const org = pick(m.orgs, this.org);
    return { person, org, seen: visible(m, person, orgPlace(org)) };
  }
}

export class CreateGroup extends OrgCommand {
  async act(m, world) {
    const { person, org, seen } = this.setup(m);
    const name = world.h.unique("Group");
    this.label = `CreateGroup(${label(m, person)} in ${orgLabel(m, org)})`;
    const expected = seen ? (adminOn(m, person, orgPlace(org)) ?? "ok") : "404";
    expectAnswer(await portalOf(world, person).post(`/org/${org.id}/groups`, { name }), expected, this.label);
    if (expected !== "ok") return [];
    const id = Number(world.sql(`SELECT id FROM groups WHERE org_id = ${org.id} AND name = ${q(name)}`));
    org.groups.push({ id, name });
    m.layers[`group-${id}`] = emptyLayer("group");
    return ["group.create"];
  }
}

/// "Send invitation"; with `answer: "accept"` the invitee, when signed in, opens the
/// link from the mail and accepts it at once ("ignore" leaves it waiting).
export class Invite extends OrgCommand {
  async act(m, world) {
    const { person, org, seen } = this.setup(m);
    const outside = m.people.filter((p) => !membership(org, p.slot));
    const invitee = pick(this.as && outside.length ? outside : m.people, this.invitee);
    const group = this.group === 0 ? null : pick(org.groups, this.group - 1) ?? null;
    this.label = `Invite(${label(m, person)} invites ${label(m, invitee)} to ${orgLabel(m, org)} as ${this.role}${group ? ` in G${org.groups.indexOf(group)}` : ""}; ${this.answer})`;
    let expected = seen ? (adminOn(m, person, orgPlace(org)) ?? "ok") : "404";
    if (expected === "ok" && this.role === "group_admin" && !group) expected = "409";
    const answer = await portalOf(world, person).post(`/org/${org.id}/invitations`, { email: invitee.email, role: this.role, group: group ? String(group.id) : "none" });
    expectAnswer(answer, expected, this.label);
    if (expected !== "ok") return [];
    const link = await mailLink(world, invitee.email, /^\/invite$/);
    const invitation = { email: invitee.email, role: this.role, group: group?.id ?? null, sender: person.slot, seq: ++m.seq, link: link.pathname + link.search, token: link.searchParams.get("token"), accepted: false, withdrawn: false };
    org.invitations.push(invitation);
    if (this.answer !== "accept" || !live(invitee)) return ["invitation.create"];
    return ["invitation.create", ...(await accept(m, world, invitee, org, invitation, this.label))];
  }
}

/// `who` opens the invitation link and presses Accept: who may (C43, C128, T3).
async function accept(m, world, person, org, invitation, what) {
  const portal = portalOf(world, person);
  const page = await portal.get(invitation.link);
  const open = !invitation.accepted && !invitation.withdrawn;
  expect(page.status === 200 && page.body.includes('action="/invite"') === open, `${what}: the invitation page (${page.status}) ${open ? "offers Accept" : "says it expired"}`);
  let expected = open ? "ok" : "410";
  // A removal is lifted only by an invitation sent after it (C128).
  if (open && (org.removed.get(person.slot) ?? 0) >= invitation.seq) expected = "403";
  if (open && membership(org, person.slot)) expected = "403";
  const answer = await portal.post("/invite", { token: invitation.token });
  expectAnswer(answer, expected, what);
  if (expected !== "ok") return [];
  expect(answer.location === `/org/${org.id}`, `${what}: ${answer.location}`);
  invitation.accepted = true;
  const mid = memberIdOf(world, org, person);
  org.members.push({ slot: person.slot, mid, role: invitation.role, group: invitation.group });
  org.removed.delete(person.slot);
  m.layers[`user-${mid}`] = emptyLayer("user");
  return ["invitation.accept"];
}

export class Accept extends PersonCommand {
  check(m) {
    return m.orgs.some((org) => org.invitations.length) && super.check(m);
  }

  able(m, person) {
    return !membership(this.invitationOf(m).org, person.slot);
  }

  /// With `as`, a waiting one when there is one.
  invitationOf(m) {
    const all = m.orgs.flatMap((org) => org.invitations.map((invitation) => ({ org, invitation })));
    const open = all.filter(({ invitation }) => !invitation.accepted && !invitation.withdrawn);
    return pick(this.as && open.length ? open : all, this.invitation);
  }

  async act(m, world) {
    const person = this.actor(m);
    const all = m.orgs.flatMap((org) => org.invitations.map((invitation) => ({ org, invitation })));
    const { org, invitation } = this.invitationOf(m);
    this.label = `Accept(${label(m, person)} opens invitation ${all.findIndex((x) => x.invitation === invitation)} to ${orgLabel(m, org)})`;
    return accept(m, world, person, org, invitation, this.label);
  }
}

/// An org admin action on the `member`-th member of the `org`-th organisation.
class MemberCommand extends OrgCommand {
  check(m) {
    return m.orgs.length > 0 && pick(m.orgs, this.org).members.length > 0 && super.check(m);
  }

  target(m) {
    const { person, org } = this.setup(m);
    const others = org.members.filter((x) => x.slot !== person.slot);
    const member = pick(this.as && others.length ? others : org.members, this.member);
    const target = m.people[member.slot];
    const place = userPlace(org, member);
    return { person, org, member, target, place, seen: visible(m, person, place) };
  }
}

export class SetRole extends MemberCommand {
  async act(m, world) {
    const { person, org, member, target, place, seen } = this.target(m);
    this.label = `SetRole(${label(m, person)} makes ${label(m, target)} ${this.role} in ${orgLabel(m, org)})`;
    let expected = seen ? (adminOn(m, person, place) ?? "ok") : "404";
    const noop = member.role === this.role;
    if (expected === "ok" && !noop && member.role === "org_admin" && lastAdmin(org, member)) expected = "409";
    else if (expected === "ok" && !noop && this.role === "group_admin" && !member.group) expected = "409";
    expectAnswer(await portalOf(world, person).post(`/org/members/${member.mid}/role`, { role: this.role }), expected, this.label);
    if (expected !== "ok" || noop) return [];
    if (member.role === "org_admin") withdrawInvitations(org, member.slot);
    member.role = this.role;
    return ["member.role"];
  }
}

export class Move extends MemberCommand {
  async act(m, world) {
    const { person, org, member, target, place, seen } = this.target(m);
    // With `as`, somewhere else than where the member is.
    const choices = [null, ...org.groups].filter((g) => !this.as || (g?.id ?? null) !== member.group);
    const group = pick(choices.length ? choices : [null], this.group);
    this.label = `Move(${label(m, person)} moves ${label(m, target)} to ${group ? `G${org.groups.indexOf(group)}` : "no group"} in ${orgLabel(m, org)})`;
    const expected = seen ? (adminOn(m, person, place) ?? "ok") : "404";
    expectAnswer(await portalOf(world, person).post(`/org/members/${member.mid}/group`, { group: group ? String(group.id) : "none" }), expected, this.label);
    if (expected !== "ok" || member.group === (group?.id ?? null)) return [];
    member.group = group?.id ?? null;
    m.changedAt[`user-${member.mid}`] = Date.now();
    if (member.role === "group_admin") member.role = "member";
    return ["member.move"];
  }
}

export class Remove extends MemberCommand {
  async act(m, world) {
    const { person, org, member, target, place, seen } = this.target(m);
    this.label = `Remove(${label(m, person)} removes ${label(m, target)} from ${orgLabel(m, org)})`;
    let expected = seen ? (adminOn(m, person, place) ?? "ok") : "404";
    if (expected === "ok" && lastAdmin(org, member)) expected = "409";
    expectAnswer(await portalOf(world, person).post(`/org/members/${member.mid}/remove`, {}), expected, this.label);
    if (expected !== "ok") return [];
    endMembership(m, org, member, true);
    return ["member.remove"];
  }
}

export class AskLeave extends OrgCommand {
  async act(m, world) {
    const { person, org, seen } = this.setup(m);
    this.label = `AskLeave(${label(m, person)} from ${orgLabel(m, org)})`;
    let expected = seen ? "ok" : "404";
    // A suspended organisation is read-only for its members (C64, C78).
    if (seen && org.status === "suspended") expected = "403";
    expectAnswer(await portalOf(world, person).post(`/org/${org.id}/leave`, {}), expected, this.label);
    if (expected !== "ok" || org.leave.has(person.slot)) return [];
    org.leave.add(person.slot);
    return ["leave.ask"];
  }
}

export class DecideLeave extends OrgCommand {
  check(m) {
    return m.orgs.some((org) => org.leave.size > 0) && super.check(m);
  }

  able(m, person) {
    return roleFor(m, person, orgPlace(pick(m.orgs.filter((o) => o.leave.size), this.org))) === "org_admin";
  }

  async act(m, world) {
    const person = this.actor(m);
    const org = pick(m.orgs.filter((o) => o.leave.size), this.org);
    const slot = pick([...org.leave], this.request);
    const member = membership(org, slot);
    const verb = this.approve ? "approve" : "refuse";
    this.label = `DecideLeave(${label(m, person)} ${verb}s P${slot} leaving ${orgLabel(m, org)})`;
    const id = world.sql(`SELECT r.id FROM leave_requests AS r WHERE r.org_id = ${org.id} AND r.login_id = (SELECT login_id FROM memberships WHERE id = ${member.mid})`);
    let expected = visible(m, person, orgPlace(org)) ? (adminOn(m, person, orgPlace(org)) ?? "ok") : "404";
    if (expected === "ok" && this.approve && lastAdmin(org, member)) expected = "409";
    expectAnswer(await portalOf(world, person).post(`/org/leave/${id}/${verb}`, {}), expected, this.label);
    if (expected !== "ok") return [];
    if (this.approve) endMembership(m, org, member, false);
    else org.leave.delete(slot);
    return [`leave.${verb}`];
  }
}

export class CreateKey extends PersonCommand {
  async act(m, world) {
    const person = this.actor(m);
    const current = currentPlace(m, person);
    const portal = portalOf(world, person);
    const name = world.h.unique("key");
    let place;
    let expected;
    let answer;
    if (!this.service) {
      this.label = `CreateKey(${label(m, person)} in ${current ?? "no place"})`;
      if (!current) expected = "404";
      else {
        const org = current === "personal" ? null : m.orgs.find((o) => `org:${o.id}` === current);
        place = org ? userPlace(org, membership(org, person.slot)) : { kind: "personal", id: person.personal.id };
        const own = m.keys.filter((k) => k.place === keyOfPlace(place) && !k.revoked).length;
        expected = roleFor(m, person, place) ? (own >= (org ? 20 : 5) ? "409" : "page") : "403";
      }
      answer = await portal.post("/keys", { name });
    } else {
      const org = current?.startsWith("org:") ? m.orgs.find((o) => `org:${o.id}` === current) : null;
      const group = org && this.attach > 0 ? pick(org.groups, this.attach - 1) : null;
      this.label = `CreateServiceKey(${label(m, person)} on ${org ? (group ? `G${org.groups.indexOf(group)} of ` : "") + orgLabel(m, org) : "no organisation"})`;
      if (!org) expected = "404";
      else {
        place = group ? groupPlace(org, group) : orgPlace(org);
        const role = roleFor(m, person, place);
        expected = role === "org_admin" || (group && role === "group_admin") ? "page" : withheld(m, person, place) ? "2fa" : "403";
      }
      answer = await portal.post("/keys/service", { name, attach: org && this.attach > 0 && org.groups.length ? String(group.id) : "org" });
    }
    expectAnswer(answer, expected, this.label);
    if (expected !== "page") return [];
    const shown = answer.body.match(/<code id="new-key">([^<]*)<\/code>/)?.[1];
    if (!shown) throw new Broken(`${this.label}: no new key on the page`);
    const secret = unescape(shown);
    world.secrets.add(secret);
    const id = Number(world.sql(`SELECT id FROM keys WHERE name = ${q(name)}`));
    m.keys.push({ id, name, secret, place: keyOfPlace(place), owner: this.service ? null : person.slot, revoked: false });
    return ["key.create"];
  }
}

export class Revoke extends PersonCommand {
  check(m) {
    return m.keys.length > 0 && super.check(m);
  }

  able(m, person) {
    const key = pick(m.keys, this.key);
    const place = m.layers[key.place] && placeOf(m, key.place);
    return place && visible(m, person, place) && ["org_admin", "group_admin", "owner"].includes(roleFor(m, person, place));
  }

  async act(m, world) {
    const person = this.actor(m);
    const key = pick(m.keys, this.key);
    this.label = `Revoke(${label(m, person)} revokes key ${m.keys.indexOf(key)})`;
    const place = m.layers[key.place] ? placeOf(m, key.place) : null;
    let expected = "404";
    if (place && visible(m, person, place) && !key.revoked) {
      const role = roleFor(m, person, place);
      if (["org_admin", "group_admin", "owner"].includes(role)) expected = "ok";
      else if (withheld(m, person, place)) expected = "2fa";
    }
    expectAnswer(await portalOf(world, person).post(`/keys/${key.id}/revoke`, {}), expected, this.label);
    if (expected !== "ok") return [];
    key.revoked = true;
    return ["key.revoke"];
  }
}

/// One edit of the `layer`-th layer of the model (any tenant's: a foreign one is 404).
class PolicyCommand extends PersonCommand {
  able(m, person) {
    const place = placeOf(m, this.layerOf(m));
    return visible(m, person, place) && mayEdit(roleFor(m, person, place), place.kind);
  }

  layerOf(m) {
    const keys = Object.keys(m.layers).filter((k) => k !== "platform-1");
    return pick(keys, this.layer);
  }

  async edit(m, world, person, key, fields, proposed) {
    const place = placeOf(m, key);
    const current = m.layers[key];
    let expected = "404";
    if (visible(m, person, place)) {
      const above = chainOf(m, key).slice(0, -1).map((k) => m.layers[k]);
      if (proposed === "invalid") expected = "422";
      else if (checkEdit(above, current, proposed)) expected = "422";
      else if (mayEdit(roleFor(m, person, place), place.kind)) expected = "ok";
      else expected = withheld(m, person, place) ? "2fa" : "403";
    }
    const portal = portalOf(world, person);
    const page = await portal.get(`/policy/${key}`);
    const revision = page.status === 200 ? hidden(page.body, "revision") : "1";
    expectAnswer(await portal.post(`/policy/${key}`, { revision, ...fields }), expected, this.label);
    if (expected !== "ok") return [];
    m.layers[key] = proposed;
    m.changedAt[key] = Date.now();
    await layerShown(world, portal, key, proposed, this.label);
    return ["layer.edit"];
  }
}

/// The policy page of `key` lists the layer's own blocks and exceptions as the model
/// holds them, and its freeze.
async function layerShown(world, portal, key, layer, what) {
  const page = (await portal.get(`/policy/${key}`)).body;
  const own = (kind) => [...page.matchAll(new RegExp(`value="remove_${kind}"`, "g"))].length;
  expect(own("block") === layer.blocks.length, `${what}: /policy/${key} lists ${own("block")} own blocks, the model ${layer.blocks.length}`);
  expect(own("exception") === layer.exceptions.length, `${what}: /policy/${key} lists ${own("exception")} own exceptions, the model ${layer.exceptions.length}`);
  const freeze = page.match(/id="freeze" name="freeze"[^>]*value="([^"]*)"/)?.[1] ?? "";
  const unit = page.match(/<option value="(hours|days)" selected>/)?.[1];
  const seconds = freeze === "" ? null : Number(freeze) * (unit === "hours" ? HOUR : DAY);
  if (seconds !== layer.freeze) throw new Broken(`${what}: /policy/${key} shows the freeze ${freeze} ${unit}, the model ${layer.freeze} s`);
}

const blockText = (b) => `${b.ecosystem} ${b.what === "file" ? `file ${b.digest.slice(0, 8)}` : `${b.name}${b.what === "version" ? `@${b.version}` : ""}`}`;

export class AddBlock extends PolicyCommand {
  async act(m, world) {
    const person = this.actor(m);
    const key = this.layerOf(m);
    const name = pick(NAMES[this.ecosystem], this.name);
    const block = { ecosystem: this.ecosystem, name, what: this.what, version: this.what === "version" ? pick(versionsOf(this.ecosystem, name), this.version) : "", digest: this.what === "file" ? this.digest : "" };
    this.label = `AddBlock(${label(m, person)} on ${key}: ${blockText(block)})`;
    const proposed = cloneLayer(m.layers[key]);
    proposed.blocks.push(block);
    const fields = { action: "add_block", ecosystem: block.ecosystem, name: block.what === "file" ? "" : block.name, what: block.what, version: block.version, algorithm: "sha256", digest: block.digest };
    return this.edit(m, world, person, key, fields, proposed);
  }
}

export class RemoveBlock extends PolicyCommand {
  check(m) {
    return Object.keys(m.layers).some((k) => k !== "platform-1" && m.layers[k].blocks.length) && super.check(m);
  }

  layerOf(m) {
    return pick(Object.keys(m.layers).filter((k) => k !== "platform-1" && m.layers[k].blocks.length), this.layer);
  }

  async act(m, world) {
    const person = this.actor(m);
    const key = this.layerOf(m);
    const index = this.index % m.layers[key].blocks.length;
    this.label = `RemoveBlock(${label(m, person)} on ${key}: ${blockText(m.layers[key].blocks[index])})`;
    const proposed = cloneLayer(m.layers[key]);
    proposed.blocks.splice(index, 1);
    return this.edit(m, world, person, key, { action: "remove_block", index: String(index) }, proposed);
  }
}

export class AddException extends PolicyCommand {
  /// With `as`, an exception that lifts a block in the layer's chain, on a layer whose
  /// parents allow it, when there is one; else the generated one on the `layer`-th layer.
  choice(m) {
    const keys = Object.keys(m.layers).filter((k) => k !== "platform-1");
    const name = pick(NAMES[this.ecosystem], this.name);
    const generated = { ecosystem: this.ecosystem, name, version: this.version === 0 ? null : pick(versionsOf(this.ecosystem, name), this.version - 1), lifts: this.lifts };
    if (this.as) {
      const lifting = keys.flatMap((key) =>
        chainOf(m, key)
          .flatMap((k) => m.layers[k]?.blocks ?? [])
          .filter((b) => b.what !== "file")
          .map((b) => ({ key, exception: { ecosystem: b.ecosystem, name: b.name, version: b.what === "version" ? b.version : null, lifts: { block: true, freeze: false, osv: false } } }))
          .filter(({ exception }) => {
            const proposed = cloneLayer(m.layers[key]);
            proposed.exceptions.push(exception);
            return !checkEdit(chainOf(m, key).slice(0, -1).map((x) => m.layers[x]), m.layers[key], proposed);
          }),
      );
      if (lifting.length) return pick(lifting, this.layer);
    }
    return { key: pick(keys, this.layer), exception: generated };
  }

  layerOf(m) {
    return this.choice(m).key;
  }

  exception(m) {
    return this.choice(m).exception;
  }

  async act(m, world) {
    const person = this.actor(m);
    const key = this.layerOf(m);
    const exception = this.exception(m);
    const lifts = Object.entries(exception.lifts).filter(([, on]) => on).map(([lift]) => lift);
    this.label = `AddException(${label(m, person)} on ${key}: ${exception.ecosystem} ${exception.name}${exception.version ? `@${exception.version}` : ""} lifts ${lifts.join("+") || "nothing"})`;
    const proposed = cloneLayer(m.layers[key]);
    proposed.exceptions.push(exception);
    const fields = { action: "add_exception", ecosystem: exception.ecosystem, name: exception.name, version: exception.version ?? "" };
    for (const lift of lifts) fields[`lifts_${lift}`] = "on";
    return this.edit(m, world, person, key, fields, lifts.length ? proposed : "invalid");
  }
}

export class RemoveException extends PolicyCommand {
  check(m) {
    return Object.keys(m.layers).some((k) => k !== "platform-1" && m.layers[k].exceptions.length) && super.check(m);
  }

  layerOf(m) {
    return pick(Object.keys(m.layers).filter((k) => k !== "platform-1" && m.layers[k].exceptions.length), this.layer);
  }

  async act(m, world) {
    const person = this.actor(m);
    const key = this.layerOf(m);
    const index = this.index % m.layers[key].exceptions.length;
    const e = m.layers[key].exceptions[index];
    this.label = `RemoveException(${label(m, person)} on ${key}: ${e.ecosystem} ${e.name}${e.version ? `@${e.version}` : ""})`;
    const proposed = cloneLayer(m.layers[key]);
    proposed.exceptions.splice(index, 1);
    return this.edit(m, world, person, key, { action: "remove_exception", index: String(index) }, proposed);
  }
}

/// A freeze from the generated choice: null inherits; [count, unit]. None is near the
/// age of `e2e-fresh` (1 to 3 hours in a run), so a check never lands on the boundary.
const FREEZES = [null, [0, "hours"], [6, "hours"], [48, "hours"], [1, "days"], [7, "days"]];
const freezeSeconds = (f) => (f === null ? null : f[0] * (f[1] === "hours" ? HOUR : DAY));

/// "Save changes" in the Freeze and OSV form: the freeze and the three switches (the
/// switches only on platform, organisation and group layers). OSV stays "inherit".
function saveFields(freeze, allow, kind) {
  const fields = { action: "save", freeze: freeze === null ? "" : String(freeze[0]), unit: freeze?.[1] ?? "days", osv: "inherit" };
  if (["platform", "org", "group"].includes(kind)) for (const [name, on] of Object.entries(allow)) if (on) fields[`allow_${name}`] = "on";
  return fields;
}

export class SaveFreeze extends PolicyCommand {
  async act(m, world) {
    const person = this.actor(m);
    const key = this.layerOf(m);
    const freeze = pick(FREEZES, this.freeze);
    const proposed = cloneLayer(m.layers[key]);
    proposed.freeze = freezeSeconds(freeze);
    // No `allow`: the switches stay as they are.
    if (["org", "group"].includes(proposed.kind) && this.allow) proposed.allow = { ...this.allow };
    this.label = `SaveFreeze(${label(m, person)} on ${key}: ${freeze ? freeze.join(" ") : "inherit"}${["org", "group"].includes(proposed.kind) ? `; allow ${Object.keys(proposed.allow).filter((k) => proposed.allow[k]).join("+") || "nothing"}` : ""})`;
    return this.edit(m, world, person, key, saveFields(freeze, proposed.allow, proposed.kind), proposed);
  }
}

/// The operator's global admin sets the platform layer's freeze and its "Allow a
/// shorter freeze" and "Allow package exceptions" switches.
export class PlatformSettings extends Command {
  async act(m, world) {
    const freeze = pick(FREEZES, this.freeze);
    const allow = { exceptions: this.exceptions, osv_off: false, shorter_freeze: this.shorter };
    this.label = `PlatformSettings(freeze ${freeze ? freeze.join(" ") : "none"}; allow shorter ${this.shorter}; exceptions ${this.exceptions})`;
    const portal = world.operator.portal;
    const page = await portal.get("/policy/platform-1");
    const answer = await portal.post("/policy/platform-1", { csrf: hidden(page.body, "csrf"), revision: hidden(page.body, "revision"), ...saveFields(freeze, allow, "platform") });
    pageProperties(world, "POST", "/policy/platform-1", answer);
    expectAnswer(answer, "ok", this.label);
    Object.assign(m.layers["platform-1"], { freeze: freezeSeconds(freeze), allow });
    m.changedAt["platform-1"] = Date.now();
    return ["layer.edit"];
  }
}

export class SetOrgStatus extends Command {
  check(m) {
    return m.orgs.length > 0;
  }

  async act(m, world) {
    const org = pick(m.orgs, this.org);
    const verb = this.suspend ? "suspend" : "activate";
    this.label = `${this.suspend ? "Suspend" : "Activate"}(${orgLabel(m, org)})`;
    const portal = world.operator.portal;
    const page = await portal.get(this.suspend ? `/admin/orgs/${org.id}/suspend` : "/admin");
    pageProperties(world, "GET", "/admin", page);
    const answer = await portal.post(`/admin/orgs/${org.id}/${verb}`, { csrf: hidden(page.body, "csrf") });
    pageProperties(world, "POST", `/admin/orgs/${org.id}/${verb}`, answer);
    expectAnswer(answer, "ok", this.label);
    const status = this.suspend ? "suspended" : "active";
    if (org.status === status) return [];
    org.status = status;
    return [`org.${verb}`];
  }
}

/// "Delete your personal account" (and with it a login in no organisation), or "Delete
/// your login" (offered only to a login with no personal account and no organisation).
export class DeleteLogin extends PersonCommand {
  async act(m, world) {
    const person = this.actor(m);
    const inOrg = m.orgs.some((org) => membership(org, person.slot));
    const portal = portalOf(world, person);
    if (this.personal) {
      this.label = `DeletePersonal(${label(m, person)})`;
      const has = person.personal && !person.personal.deleted;
      const answer = await portal.post("/account/personal/delete", { confirm: "delete" });
      expectAnswer(answer, has ? "ok" : "404", this.label);
      if (!has) return [];
      person.personal.deleted = true;
      if (inOrg) {
        expect(answer.location === "/account", `${this.label}: ${answer.location}`);
        return ["personal.delete"];
      }
      expect(answer.location === "/signin", `${this.label}: the login goes too: ${answer.location}`);
      Object.assign(person, { loginDeleted: true, signedIn: false, withPersonal: true });
      portal.forget();
      return ["personal.delete", "login.delete"];
    }
    this.label = `DeleteLogin(${label(m, person)})`;
    const offered = !person.personal && !inOrg;
    const answer = await portal.post("/account/delete", { confirm: "delete" });
    expectAnswer(answer, offered ? "ok" : "403", this.label);
    if (!offered) return [];
    Object.assign(person, { loginDeleted: true, signedIn: false, withPersonal: false });
    portal.forget();
    return ["login.delete"];
  }
}

/// A deleted login signs in with its password (and code) and presses "Restore login";
/// a live login with a deleted personal account presses "Restore personal account".
export class RestoreLogin extends Command {
  person(m) {
    return pick(m.people.filter((p) => p.loginDeleted || (live(p) && p.personal?.deleted)), this.who);
  }

  check(m) {
    return Boolean(this.person(m));
  }

  async act(m, world) {
    const person = this.person(m);
    const portal = portalOf(world, person);
    if (!person.loginDeleted) {
      this.label = `RestorePersonal(${label(m, person)})`;
      expectAnswer(await portal.post("/account/personal/restore", {}), "ok", this.label);
      person.personal.deleted = false;
      return ["personal.restore"];
    }
    this.label = `RestoreLogin(${label(m, person)})`;
    let page = await portal.submit("/signin", "/signin", { email: person.email, password: person.password });
    if (person.totp) {
      expect(page.location === "/totp", `${this.label}: asked for a code first: ${page.status} ${page.location}`);
      page = await portal.submit("/totp", "/totp", { code: await world.run.auth.get(person.slot).code() });
    }
    expect(page.status === 303 && page.location === "/deleted", `${this.label}: ${page.status} ${page.location}`);
    page = await portal.submit("/deleted", "/deleted/restore", {});
    expect(page.status === 303, `${this.label}: restore: ${page.status} ${page.location}\n${page.body.slice(0, 300)}`);
    portal.forget();
    Object.assign(person, { loginDeleted: false, signedIn: true, chosen: null, sessionTotpOk: person.totp });
    if (person.withPersonal) person.personal.deleted = false;
    return ["login.restore"];
  }
}

/// Firewall truth on a sample of keys: each answers what the model's effective policy
/// predicts, within one sync interval (plus the check's own time).
export class CheckFirewall extends Command {
  check(m) {
    return m.keys.length > 0;
  }

  async act(m, world) {
    this.label = `CheckFirewall(${this.sample})`;
    await firewallTruth(m, world, this.sample);
  }
}

async function firewallTruth(m, world, sample) {
  const { h } = world;
  // First the keys whose predicted answer changed since a firewall last gave one (the
  // change has to reach the fleet), then those whose chain names the package in a block
  // or an exception or holds it by a freeze, then the others; the `sample`-th of each.
  const pairs = m.keys.flatMap((key) => TARGETS.map((target) => ({ key, target: { ...target, age: ageOf(world, target) } })));
  const seen = (world.run.seen ??= new Map());
  const queried = (world.run.queried ??= new Map());
  const id = ({ key, target }) => `${key.id} ${target.name}@${target.version} ${target.ecosystem}`;
  const changed = pairs.filter((pair) => seen.has(id(pair)) && seen.get(id(pair)) !== keyDecision(m, pair.key, pair.target));
  const relevant = pairs.filter(({ key, target }) =>
    !changed.some((pair) => id(pair) === id({ key, target })) &&
    chainOf(m, key.place).some((k) => {
      const layer = m.layers[k];
      return layer && ([...layer.blocks, ...layer.exceptions].some((x) => x.name === target.name && x.ecosystem === target.ecosystem) || (target.fresh && layer.freeze !== null));
    }),
  );
  const rest = pairs.filter((pair) => !changed.includes(pair) && !relevant.includes(pair));
  const checks = [];
  for (const group of [changed, relevant, rest]) {
    for (let n = 0; n < group.length && checks.length < world.settings.firewallSample; n++) {
      const pair = group[(sample + n * 7) % group.length];
      if (!checks.some((check) => id(check) === id(pair))) checks.push({ ...pair, host: (sample + checks.length) % 2 ? "fw2" : "fw1" });
    }
  }
  world.stats.firewallChecks += checks.length;
  await Promise.all(
    checks.map(async ({ key, target, host }) => {
      const want = keyDecision(m, key, target);
      const path = target.ecosystem === "npm" ? `/npm/${target.name}/${target.version}` : `/pypi/simple/${target.name}/`;
      const what = `key ${m.keys.indexOf(key)} (${key.place}) on ${host}: ${target.ecosystem} ${target.name}@${target.version}`;
      let got;
      const times = queried.get(`${key.id}@${host}`) ?? [];
      queried.set(`${key.id}@${host}`, times);
      const ok = await h
        .waitFor(what, async () => {
          const answer = await request(`https://${host}.e2e.test${path}`, { headers: { authorization: `Bearer ${key.secret}` }, timeout: 15_000 });
          times.push(Date.now());
          got = decisionOf(answer, target);
          return got === want;
        }, { timeout: (h.syncInterval + 5) * 1000, every: 500 })
        .then(() => true, () => false);
      seen.set(id({ key, target }), want);
      if (ok) return;
      const message = `firewall truth: ${what} is ${got}, the model's policy says ${want} (chain ${chainOf(m, key.place).join(" > ")})`;
      // The firewall looked this key up in the 5 minutes before its policy last
      // changed: it serves the policy it cached then, for up to 5 minutes (known, being
      // fixed).
      const decisions = ["blocked", "held", "allowed"];
      const changed = Math.max(0, ...chainOf(m, key.place).map((k) => m.changedAt[k] ?? 0));
      const cachedAt = Math.max(0, ...times.filter((t) => t < changed));
      if (decisions.includes(want) && decisions.includes(got) && cachedAt && Date.now() - cachedAt < 330_000) {
        world.needs.check(STALE, false, `${message}; ${host} used the key ${((changed - cachedAt) / 1000).toFixed(0)} s before the change`);
        return;
      }
      throw new Broken(message);
    }),
  );
}

/// The firewall's answer as a decision: "refused" (401), "blocked", "held", "allowed".
function decisionOf(answer, target) {
  if (answer.status === 401) return "refused";
  if (target.ecosystem === "pypi") {
    if (answer.status === 403) return "blocked";
    if (answer.status !== 200) return `status ${answer.status}`;
    return answer.body.includes(`-${target.version}`) ? "allowed" : "blocked";
  }
  if (answer.status === 200) return "allowed";
  if (answer.status === 403) {
    const error = (() => {
      try {
        return answer.json().error;
      } catch {
        return "";
      }
    })();
    return error === "HELD" ? "held" : "blocked";
  }
  return `status ${answer.status}`;
}

// ---- Invariants ------------------------------------------------------------------------

async function invariants(m, world, command, actions) {
  // Audit: exactly the rows the command's change writes, and none for a refusal (C25).
  const rows = world.sql(`SELECT id || ' ' || action FROM audit_log WHERE id > ${world.run.auditMark} ORDER BY id`).split("\n").filter(Boolean);
  const got = rows.map((row) => row.split(" ")[1]).sort();
  if (JSON.stringify(got) !== JSON.stringify([...actions].sort())) throw new Broken(`${command}: the audit log got [${got.join(", ")}], the model expects [${[...actions].sort().join(", ")}]`);
  if (rows.length) world.run.auditMark = Number(rows.at(-1).split(" ")[0]);
  if (!actions.length) world.stats.refused += 1;
  for (const person of m.people) await personSees(m, world, person, command.probe ?? 0);
}

/// What one person's portal shows matches the model: their places, their keys, each of
/// their organisations' pages and policy (C1, C24, C27), and other tenants' ids are 404.
async function personSees(m, world, person, probe) {
  const portal = portalOf(world, person);
  const who = `P${person.slot}`;
  if (!live(person)) {
    const page = await portal.get("/keys");
    expect(page.status === 303 && page.location === "/signin", `${who} is signed out: /keys answers ${page.status} ${page.location}`);
    return;
  }
  const account = await portal.get("/account");
  expect(account.status === 200, `${who}: /account ${account.status} ${account.location}`);
  const options = [...(account.body.match(/<select id="place-switcher"[^>]*>([\s\S]*?)<\/select>/)?.[1] ?? "").matchAll(/<option value="([^"]*)"( selected)?>/g)];
  const shown = options.map(([, value]) => value);
  const expected = places(m, person);
  if (JSON.stringify(shown) !== JSON.stringify(expected)) throw new Broken(`${who}'s place switcher lists [${shown}], the model [${expected}]`);
  const selected = options.find(([, , on]) => on)?.[1] ?? null;
  if (selected !== currentPlace(m, person)) throw new Broken(`${who}'s switcher selects ${selected}, the model ${currentPlace(m, person)}`);
  const totpShown = account.body.includes('action="/account/totp/setup"') ? false : account.body.includes("Turn off");
  if (totpShown !== person.totp) throw new Broken(`${who}'s account page shows the authenticator ${totpShown ? "on" : "off"}, the model ${person.totp ? "on" : "off"}`);

  // Their own keys in the place they work in, by name.
  const keys = await portal.get("/keys");
  const current = currentPlace(m, person);
  if (current) {
    const org = current === "personal" ? null : m.orgs.find((o) => `org:${o.id}` === current);
    const own = org ? `user-${membership(org, person.slot).mid}` : `personal-${person.personal.id}`;
    const section = keys.body.match(/id="own-heading"[\s\S]*?<\/section>/)?.[0] ?? "";
    const listed = [...section.matchAll(/<tr><td>([^<]*)<\/td><td><code>/g)].map(([, name]) => unescape(name)).sort();
    const modelled = m.keys.filter((k) => k.place === own && !k.revoked).map((k) => k.name).sort();
    if (JSON.stringify(listed) !== JSON.stringify(modelled)) throw new Broken(`${who}'s /keys in ${current} lists [${listed}], the model [${modelled}]`);
  }

  // Each of their organisations: the page their role gets, and the policy editor's state.
  for (const org of m.orgs.filter((o) => membership(o, person.slot))) {
    const place = orgPlace(org);
    const page = await portal.get(`/org/${org.id}`);
    const at = `${who} on /org/${org.id} (${orgLabel(m, org)})`;
    if (withheld(m, person, place)) {
      expect(page.status === 303 && page.location === "/account#totp-heading", `${at}: an org admin without a second factor is sent to set one up (C24): ${page.status} ${page.location}`);
    } else if (roleFor(m, person, place) === "org_admin") {
      expect(page.status === 200 && page.body.includes(`action="/org/${org.id}/invitations"`), `${at}: the org admin page: ${page.status}`);
      orgPageMatches(m, org, page.body, at);
    } else {
      expect(page.status === 200 && page.body.includes(`<h1>Organisation: ${org.name}</h1>`), `${at}: the member page: ${page.status}`);
      expect(!page.body.includes(`action="/org/${org.id}/invitations"`) && !page.body.includes("/org/members/"), `${at}: a member who is no org admin sees no admin forms (C27)`);
      const asked = page.body.includes("You asked to leave");
      if (asked !== org.leave.has(person.slot)) throw new Broken(`${at}: the leave request shows ${asked ? "waiting" : "none"}, the model ${org.leave.has(person.slot) ? "waiting" : "none"}`);
    }
    const policy = await portal.get(`/policy/org-${org.id}`);
    expect(policy.status === 200, `${at}: /policy/org-${org.id} ${policy.status}`);
    const editable = !policy.body.includes("You can see this layer but not change it.");
    if (editable !== mayEdit(roleFor(m, person, place), "org")) throw new Broken(`${at}: the organisation layer is ${editable ? "editable" : "read-only"}, the model says ${editable ? "read-only" : "editable"}`);
  }

  // Another tenant's ids answer as unknown ones do, and leak nothing (C1).
  const foreign = [...m.orgs.filter((o) => !membership(o, person.slot)), { id: world.bootstrapOrg, name: "Operators", groups: [], members: [] }];
  const other = pick(foreign, probe + person.slot);
  for (const path of [`/org/${other.id}`, `/policy/org-${other.id}`, ...other.groups.slice(0, 1).map((g) => `/policy/group-${g.id}`), ...other.members.slice(0, 1).map((x) => `/policy/user-${x.mid}`)]) {
    const page = await portal.get(path);
    if (page.status !== 404 || page.body.includes(other.name)) throw new Broken(`${who} opens another tenant's ${path}: ${page.status}${page.body.includes(other.name) ? `, and the page names ${other.name}` : ""}`);
  }
}

/// The org admin page lists exactly the model's members (email, role, group), groups
/// and waiting invitations.
function orgPageMatches(m, org, body, at) {
  const section = (id) => body.match(new RegExp(`id="${id}"[\\s\\S]*?</section>`))?.[0] ?? "";
  const members = [...section("members-heading").matchAll(/<tr><td>([^<]*?)(?: <span class="mut">[^<]*<\/span>)?<\/td>\s*<td><form method="post" action="\/org\/members\/(\d+)\/role"[\s\S]*?<\/tr>/g)].map(([row, email, mid]) => {
    const role = row.match(/<select id="role-\d+" name="role">[\s\S]*?<option value="([a-z_]+)" selected>/)?.[1];
    const group = row.match(/<select id="group-\d+" name="group">[\s\S]*?<option value="([^"]+)" selected>/)?.[1];
    return `${unescape(email)} ${mid} ${role} ${group}`;
  });
  const modelled = org.members.map((x) => `${m.people[x.slot].email} ${x.mid} ${x.role} ${x.group ?? "none"}`);
  if (JSON.stringify(members.sort()) !== JSON.stringify(modelled.sort())) throw new Broken(`${at}: members [${members}], the model [${modelled}]`);
  const groups = [...section("groups-heading").matchAll(/<tr><td>([^<]*)<\/td><td>\d+<\/td>/g)].map(([, name]) => unescape(name)).sort();
  const groupNames = org.groups.map((g) => g.name).sort();
  if (JSON.stringify(groups) !== JSON.stringify(groupNames)) throw new Broken(`${at}: groups [${groups}], the model [${groupNames}]`);
  const waiting = [...body.matchAll(/<tr><td>([^<]*)<\/td><td>(?:Org admin|Group admin|Member)<\/td>/g)].map(([, email]) => unescape(email)).sort();
  const open = org.invitations.filter((i) => !i.accepted && !i.withdrawn).map((i) => i.email).sort();
  if (JSON.stringify(waiting) !== JSON.stringify(open)) throw new Broken(`${at}: waiting invitations [${waiting}], the model [${open}]`);
  // No other tenant's people: every email on the page is one of this organisation's.
  for (const person of m.people) {
    const listed = members.some((row) => row.startsWith(`${person.email} `)) || waiting.includes(person.email);
    if (!listed && body.includes(person.email)) throw new Broken(`${at}: the page shows ${person.email}, who is not in ${org.name}`);
  }
}

// ---- Runs ------------------------------------------------------------------------------

const nat = (n) => fc.nat({ max: n });
const who = nat(11);

/// The commands, as fast-check arbitraries; some appear twice to be drawn more often.
export function commandArbitraries() {
  const lifts = fc.constantFrom({ block: true, freeze: false }, { block: true, freeze: false }, { block: false, freeze: true }, { block: true, freeze: true }, { block: false, freeze: false }).map((l) => ({ ...l, osv: false }));
  const allow = fc.record({ exceptions: fc.boolean(), osv_off: fc.constant(false), shorter_freeze: fc.boolean() });
  const probe = nat(1000);
  const as = fc.constantFrom(true, true, false);
  const make = (Class, shape) => fc.record({ ...shape, ...("who" in shape ? { as } : {}), probe }).map((args) => new Class({ ...args, args }));
  return [
    make(SignUp, { kind: fc.constantFrom("org", "personal") }),
    make(SignOut, { who }),
    make(SignIn, { who }),
    make(TotpOn, { who }),
    make(TotpOn, { who }),
    make(TotpOff, { who }),
    make(CreateGroup, { who, org: nat(11) }),
    make(CreateGroup, { who, org: nat(11) }),
    make(Invite, { who, org: nat(11), invitee: nat(11), role: fc.constantFrom("member", "member", "group_admin", "org_admin"), group: nat(4), answer: fc.constantFrom("accept", "accept", "ignore") }),
    make(Invite, { who, org: nat(11), invitee: nat(11), role: fc.constantFrom("member", "group_admin"), group: nat(4), answer: fc.constantFrom("accept", "ignore") }),
    make(Invite, { who, org: nat(11), invitee: nat(11), role: fc.constant("member"), group: nat(4), answer: fc.constant("accept") }),
    make(Accept, { who, invitation: nat(11) }),
    make(Accept, { who, invitation: nat(11) }),
    make(Accept, { who, invitation: nat(11) }),
    make(SetRole, { who, org: nat(11), member: nat(11), role: fc.constantFrom("member", "group_admin", "org_admin") }),
    make(Move, { who, org: nat(11), member: nat(11), group: nat(4) }),
    make(Remove, { who, org: nat(11), member: nat(11) }),
    make(AskLeave, { who, org: nat(11) }),
    make(DecideLeave, { who, org: nat(11), request: nat(11), approve: fc.boolean() }),
    make(CreateKey, { who, service: fc.boolean(), attach: nat(4) }),
    make(CreateKey, { who, service: fc.constant(false), attach: fc.constant(0) }),
    make(Revoke, { who, key: nat(30) }),
    make(AddBlock, { who, layer: nat(30), ecosystem: fc.constantFrom("npm", "npm", "pypi"), name: nat(5), what: fc.constantFrom("package", "version", "version", "file"), version: nat(5), digest: fc.stringMatching(/^[0-9a-f]{64}$/) }),
    make(AddBlock, { who, layer: nat(30), ecosystem: fc.constant("npm"), name: nat(5), what: fc.constantFrom("package", "version"), version: nat(5), digest: fc.constant("") }),
    make(RemoveBlock, { who, layer: nat(30), index: nat(10) }),
    make(AddException, { who, layer: nat(30), ecosystem: fc.constantFrom("npm", "pypi"), name: nat(5), version: nat(3), lifts }),
    make(RemoveException, { who, layer: nat(30), index: nat(10) }),
    make(SaveFreeze, { who, layer: nat(30), freeze: nat(FREEZES.length - 1), allow: fc.option(allow, { nil: null }) }),
    make(PlatformSettings, { freeze: nat(FREEZES.length - 1), shorter: fc.boolean(), exceptions: fc.constantFrom(true, true, false) }),
    make(SwitchPlace, { who, place: nat(5) }),
    make(SetOrgStatus, { org: nat(11), suspend: fc.boolean() }),
    make(DeleteLogin, { who, personal: fc.boolean() }),
    make(RestoreLogin, { who }),
    make(CheckFirewall, { sample: nat(1000) }),
  ];
}

/// The start of every run (the cast): O0, whose org admin P0 has an authenticator,
/// with group G0 run by P3 and holding P4, and P5 in no group; O1, another tenant,
/// whose org admin P1 has an authenticator and which P5 is in too; P2 with a personal
/// account, as P3 to P5 have; a key for each person in each of their places but P5's in
/// O1, and a service key on G0; the platform with a 6-hour freeze and its
/// "Allow package exceptions" and "Allow a shorter freeze" on, and O0 passing them down
/// (put back after the run). The random commands start from there.
async function cast(world) {
  world.run = { portals: new Map(), auth: new Map(), auditMark: 0 };
  // changedAt: when each layer (or a member's chain) last changed, for STALE below.
  const m = { people: [], orgs: [], keys: [], layers: {}, changedAt: {}, seq: 0, maxPeople: world.settings.people };
  m.layers["platform-1"] = await platformLayer(world);
  world.run.platform = cloneLayer(m.layers["platform-1"]);
  const kinds = ["org", "org", "personal", "personal", "personal", "personal"];
  for (const signed of await Promise.all(kinds.map((kind, slot) => signUp(world, slot, kind)))) register(world, m, signed);
  const [p0, p1, , p3, p4, p5] = m.people;
  await Promise.all([p0, p1].map((person) => totpOn(world, person)));
  const [o0, o1] = m.orgs;
  const name = world.h.unique("Group");
  expect((await portalOf(world, p0).post(`/org/${o0.id}/groups`, { name })).status === 303, "the cast's group");
  const g0 = { id: Number(world.sql(`SELECT id FROM groups WHERE org_id = ${o0.id} AND name = ${q(name)}`)), name };
  o0.groups.push(g0);
  m.layers[`group-${g0.id}`] = emptyLayer("group");
  for (const [admin, org, person, role, group] of [[p0, o0, p3, "group_admin", g0.id], [p0, o0, p4, "member", g0.id], [p0, o0, p5, "member", null], [p1, o1, p5, "member", null]]) {
    expect((await portalOf(world, admin).post(`/org/${org.id}/invitations`, { email: person.email, role, group: group ? String(group) : "none" })).status === 303, "the cast's invitations");
    const link = await mailLink(world, person.email, /^\/invite$/);
    const invitation = { email: person.email, role, group, sender: admin.slot, seq: ++m.seq, link: link.pathname + link.search, token: link.searchParams.get("token"), accepted: false, withdrawn: false };
    org.invitations.push(invitation);
    await accept(m, world, person, org, invitation, `the cast: P${person.slot} joins`);
  }
  // Keys: P2's personal one, P3 to P5's in O0, and a service key on G0.
  const key = async (person, path, fields, place) => {
    const name = world.h.unique("key");
    const answer = await portalOf(world, person).post(path, { name, ...fields });
    const secret = unescape(answer.body.match(/<code id="new-key">([^<]*)<\/code>/)?.[1] ?? "");
    expect(answer.status === 200 && secret, `the cast's key for P${person.slot}: ${answer.status}`);
    world.secrets.add(secret);
    m.keys.push({ id: Number(world.sql(`SELECT id FROM keys WHERE name = ${q(name)}`)), name, secret, place, owner: path === "/keys" ? person.slot : null, revoked: false });
  };
  await key(p0, "/keys", {}, `user-${membership(o0, p0.slot).mid}`);
  await key(p1, "/keys", {}, `user-${membership(o1, p1.slot).mid}`);
  for (const person of [m.people[2], p3, p4, p5]) await key(person, "/keys", {}, `personal-${person.personal.id}`);
  for (const person of [p3, p4, p5]) {
    expect((await portalOf(world, person).post("/place", { to: `org:${o0.id}` })).status === 303, "the cast's place");
    person.chosen = `org:${o0.id}`;
    await key(person, "/keys", {}, `user-${membership(o0, person.slot).mid}`);
  }
  await key(p0, "/keys/service", { attach: String(g0.id) }, `group-${g0.id}`);
  // A platform with a 6-hour freeze that lets the layers below loosen it and add
  // exceptions, and O0 passing both down (O1 does not).
  const allow = { exceptions: true, osv_off: false, shorter_freeze: true };
  for (const [portal, layer] of [[world.operator.portal, "platform-1"], [portalOf(world, p0), `org-${o0.id}`]]) {
    const page = await portal.get(`/policy/${layer}`);
    const freeze = layer === "platform-1" ? [6, "hours"] : null;
    const saved = await portal.post(`/policy/${layer}`, { csrf: hidden(page.body, "csrf"), revision: hidden(page.body, "revision"), ...saveFields(freeze, allow, layer.split("-")[0]) });
    expect(saved.status === 303, `the cast's ${layer}: ${saved.status}`);
    Object.assign(m.layers[layer], { freeze: freezeSeconds(freeze), allow: { ...allow } });
  }
  world.run.auditMark = Number(world.sql("SELECT coalesce(max(id), 0) FROM audit_log"));
  return m;
}

/// The platform layer's freeze and switches as its page shows them (it has no blocks or
/// exceptions in this stack).
async function platformLayer(world) {
  const page = (await world.operator.portal.get("/policy/platform-1")).body;
  const layer = emptyLayer("platform");
  const freeze = page.match(/id="freeze" name="freeze"[^>]*value="([^"]*)"/)?.[1] ?? "";
  const unit = page.match(/<option value="(hours|days)" selected>/)?.[1];
  layer.freeze = freeze === "" ? null : Number(freeze) * (unit === "hours" ? HOUR : DAY);
  for (const name of ["exceptions", "osv_off", "shorter_freeze"]) layer.allow[name] = new RegExp(`name="allow_${name}" checked`).test(page);
  expect(!page.includes('value="remove_block"') && !page.includes('value="remove_exception"'), "the platform layer has no blocks or exceptions of its own");
  return layer;
}

/// After a run: the platform as it was, so the next run starts the same.
async function restorePlatform(world) {
  if (!world.run?.platform) return;
  const { freeze, allow } = world.run.platform;
  const portal = world.operator.portal;
  const page = await portal.get("/policy/platform-1");
  const choice = freeze === null ? null : freeze % DAY === 0 ? [freeze / DAY, "days"] : [freeze / HOUR, "hours"];
  const answer = await portal.post("/policy/platform-1", { csrf: hidden(page.body, "csrf"), revision: hidden(page.body, "revision"), ...saveFields(choice, allow, "platform") });
  expect(answer.status === 303, `platform restored: ${answer.status}`);
}

/// axe on a sample of the pages this run reached, as their person sees them (C84).
async function axeSample(m, world) {
  if (!world.settings.axeSample) return;
  const { AxeBuilder } = await import("@axe-core/playwright");
  const pages = [...world.pages.values()].filter(({ slot }) => live(m.people[slot]));
  for (let n = 0; n < Math.min(world.settings.axeSample, pages.length); n++) {
    const { path, slot } = pages[(world.stats.runs * 13 + n * 5) % pages.length];
    const context = await world.h.browser();
    try {
      await context.addCookies([...portalOf(world, m.people[slot]).cookies].map(([name, value]) => ({ name, value, url: world.h.portalUrl, secure: true, httpOnly: true, sameSite: "Lax" })));
      const page = await context.newPage();
      await page.goto(path);
      const { violations } = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
      world.stats.axePages += 1;
      if (violations.length) throw new Broken(`axe on ${path} as P${slot}: ${violations.map((v) => `${v.id} (${v.nodes.length})`).join(", ")}`);
    } finally {
      await context.close();
    }
  }
}

/// One run of `commands` from a fresh cast, then the end-of-run checks.
async function oneRun(world, commands) {
  world.pages.clear();
  const m = await cast(world);
  try {
    await fc.asyncModelRun(() => ({ model: m, real: world }), commands);
    if (m.keys.length) await firewallTruth(m, world, world.stats.runs);
    await axeSample(m, world);
  } finally {
    world.stats.runs += 1;
    await restorePlatform(world);
  }
}

/// The model-based property: `settings.runs` sequences, each up to `settings.commands`
/// long, shrunk on failure to a minimal sequence. Throws with the seed, the path and the
/// sequence; replay with E2E_PBT_SEED, E2E_PBT_PATH and E2E_PBT_REPLAY.
export async function modelProperty(h, config) {
  const world = newWorld(h, config);
  await publishFresh(world);
  const arbitrary = fc.commands(commandArbitraries(), { maxCommands: config.commands, size: "max", replayPath: config.replayPath });
  const shrinkable = config.maxShrinks > 0 ? fc.limitShrink(arbitrary, config.maxShrinks) : fc.noShrink(arbitrary);
  const started = Date.now();
  h.log(`pbt: seed ${config.seed}, ${config.runs} runs of up to ${config.commands} commands, ${config.timeLimit} s at most`);
  const details = await fc.check(
    fc.asyncProperty(shrinkable, (commands) => oneRun(world, commands)),
    {
      numRuns: config.runs,
      seed: config.seed,
      path: config.path,
      endOnFailure: config.maxShrinks === 0,
      plugins: [fc.interruptAfterTimeLimit(config.timeLimit * 1000)],
    },
  );
  const seconds = ((Date.now() - started) / 1000).toFixed(0);
  h.log(`pbt: commands (changed the state / did not): ${Object.entries(world.stats.byCommand).map(([name, t]) => `${name} ${t.changed}/${t.unchanged}`).join(", ")}`);
  h.log(`pbt: ${details.numRuns} runs (${world.stats.commands} commands, ${world.stats.refused} refused or no-ops, ${world.stats.firewallChecks} firewall checks, ${world.stats.axePages} axe pages) in ${seconds} s${details.interrupted ? ", stopped at the time limit" : ""}`);
  await mailDelivered(world);
  if (details.failed) {
    const sequence = String(details.counterexample[0]);
    const replay = sequence.match(/replayPath="([^"]*)"/)?.[1];
    const error = details.errorInstance ?? details.error;
    throw new Error(
      `PBT failure, seed ${details.seed} path ${details.counterexamplePath} after ${details.numShrinks} shrinks: ${String(error?.message ?? error).split("\n")[0]}\n` +
        `replay: E2E_PBT_SEED=${details.seed} E2E_PBT_PATH=${details.counterexamplePath}${replay ? ` E2E_PBT_REPLAY='${replay}'` : ""}\n` +
        `minimal sequence (after the cast, harness/pbt.mjs \`cast\`):\n  ${sequence.replace(/ \/\*replayPath=.*$/, "").split(",").join("\n  ")}\n${error?.stack ?? ""}`,
    );
  }
  settle(world, details.seed);
  return { details, stats: world.stats };
}

/// The checks that wait on a product fix ("needs F…"), failed with the seed first, as
/// the JUnit message shows it.
export function settle(world, seed) {
  try {
    world.needs.done();
  } catch (err) {
    throw new Error(`PBT seed ${seed}: ${err.message}`);
  }
}

/// A fixed command sequence (a regression scenario) with the same model and checks.
export async function replay(h, commands, config = settings("pr")) {
  const world = newWorld(h, config);
  await publishFresh(world);
  await oneRun(world, commands);
  await mailDelivered(world);
  settle(world, config.seed);
}
