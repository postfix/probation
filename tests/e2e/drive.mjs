// The browser half of tests/e2e/signup_to_install.sh; run it through that script, which
// starts the stack and sets the environment read below.
//
// 1. E2E-signup-to-install (C32 metric 1): a new organisation signs up on the portal,
//    confirms its email, signs in, creates a key, pastes the .npmrc lines the keys page
//    shows and runs `npm install` through firewall-1. No operator step falls inside the
//    clock. Prints `E2E PASS <seconds>` when that took under 600 s.
// 2. M-propagation (C32 metric 2, as slice 4's tests/propagation.rs measures it): two
//    firewalls at a 10 s interval, 50 policy edits and 50 key revocations made on the
//    portal; the p99 of (last firewall apply - commit) is at most the interval, for
//    edits and revocations each. Prints the two `propagation … p99` lines.
//
// The mail the portal would send is read from its outbox (no SMTP relay is configured),
// and two setup steps the portal has no page for are written with SQL (S8-3).

import { execFileSync, spawnSync } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const env = process.env;
const work = env.E2E_WORK;
const portal = `http://127.0.0.1:${env.E2E_PORTAL_PORT}`;
const firewalls = [env.E2E_FIREWALL_1_PORT, env.E2E_FIREWALL_2_PORT].map(
  (port) => `https://localhost:${port}`,
);
const INTERVAL = 10;
const CHANGES = 50;
const BUDGET_SECONDS = 600;

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

/// One SQL statement as the database owner, through the compose project's Postgres.
function sql(statement) {
  return execFileSync(
    "bash",
    ["-c", '$E2E_COMPOSE exec -T postgres psql -U probation -d probation -tAc "$1"', "_", statement],
    { encoding: "utf8" },
  ).trim();
}

function unescape(html) {
  return html
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&#x27;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

function between(body, start, end) {
  const from = body.indexOf(start);
  expect(from >= 0, `no ${start} in the page:\n${body}`);
  const to = body.indexOf(end, from + start.length);
  return unescape(body.slice(from + start.length, to));
}

function hidden(body, name) {
  const found = body.match(new RegExp(`name="${name}" value="([^"]*)"`));
  expect(found, `no hidden ${name} in the page:\n${body}`);
  return unescape(found[1]);
}

/// The portal through one cookie jar, never following a redirect.
class Browser {
  cookies = new Map();

  async fetch(path, form) {
    const headers = {};
    if (this.cookies.size) {
      headers.cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
    }
    let body;
    if (form) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams(form).toString();
    }
    const answer = await fetch(portal + path, {
      method: form ? "POST" : "GET",
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
    for (const line of answer.headers.getSetCookie()) {
      const pair = line.split(";")[0];
      const at = pair.indexOf("=");
      const name = pair.slice(0, at).trim();
      if (/max-age=0/i.test(line)) this.cookies.delete(name);
      else this.cookies.set(name, pair.slice(at + 1));
    }
    return { status: answer.status, location: answer.headers.get("location"), body: await answer.text() };
  }

  get(path) {
    return this.fetch(path);
  }

  post(path, form) {
    return this.fetch(path, form);
  }

  /// Loads `page`, then POSTs `form` to `path` with that page's CSRF token.
  async submit(page, path, form) {
    const csrf = hidden((await this.get(page)).body, "csrf");
    return this.post(path, { ...form, csrf });
  }
}

function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of text.replace(/[\s=]/g, "").toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let at = 0; at + 8 <= bits.length; at += 8) bytes.push(parseInt(bits.slice(at, at + 8), 2));
  return Buffer.from(bytes);
}

/// RFC 6238 with SHA-1, 6 digits, 30 s steps, as an authenticator app computes it.
function totp(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = mac[19] & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

const step = () => Math.floor(Date.now() / 30_000);

/// `GET path` on firewall `f` with `key` as the npm token; the status.
async function status(f, path, key) {
  const answer = await fetch(firewalls[f] + path, {
    headers: { authorization: `Bearer ${key}` },
    signal: AbortSignal.timeout(15_000),
  });
  await answer.arrayBuffer();
  return answer.status;
}

/// `GET path` until it answers 200, waiting out each 503 (a busy lookup budget).
async function warm(f, path, key) {
  for (let attempt = 0; attempt < 15; attempt++) {
    const answer = await status(f, path, key);
    if (answer === 200) return;
    expect(answer === 503, `firewall-${f + 1} ${path}: ${answer}`);
    await sleep(1000);
  }
  throw new Error(`firewall-${f + 1} ${path} never answered 200`);
}

async function ready(f) {
  const deadline = Date.now() + 6 * INTERVAL * 1000;
  for (;;) {
    try {
      const answer = await fetch(`${firewalls[f]}/health/ready`, { signal: AbortSignal.timeout(5000) });
      if (answer.status === 200) return;
    } catch {
      // Not listening yet.
    }
    expect(Date.now() < deadline, `firewall-${f + 1} never became ready`);
    await sleep(500);
  }
}

async function signUpToInstall() {
  const started = performance.now();
  const stamp = Date.now();
  const user = {
    email: `e2e-${stamp}@example.com`,
    password: randomBytes(18).toString("base64url"),
    org: `E2E ${stamp}`,
    browser: new Browser(),
  };
  const { browser } = user;

  let page = await browser.submit("/signup", "/signup", {
    email: user.email,
    password: user.password,
    kind: "org",
    org_name: user.org,
  });
  expect(page.status === 200, `sign-up: ${page.status}\n${page.body}`);
  const mail = sql(
    `SELECT payload->>'body' FROM email_outbox WHERE to_address = '${user.email}' ORDER BY id DESC LIMIT 1`,
  );
  const link = mail.match(/\/verify-email\?token=\S+/);
  expect(link, `no confirmation link in the mail: ${mail}`);
  page = await browser.get(link[0]);
  expect(page.body.includes("Your email address is confirmed"), `confirm: ${page.status}\n${page.body}`);
  page = await browser.submit("/signin", "/signin", { email: user.email, password: user.password });
  expect(page.status === 303 && page.location === "/account", `sign-in: ${page.status} ${page.location}`);

  page = await browser.submit("/keys", "/keys", { name: "laptop" });
  expect(page.status === 200, `create key: ${page.status}\n${page.body}`);
  const npmrc = between(page.body, "<pre>registry=", "</pre>");
  const project = join(work, "project");
  mkdirSync(project, { recursive: true });
  writeFileSync(join(project, "package.json"), '{"name":"e2e-project","version":"1.0.0","private":true}\n');
  // The two lines as shown, plus the e2e CA the firewall's certificate is signed by.
  writeFileSync(join(project, ".npmrc"), `registry=${npmrc}\ncafile=${join(work, "ca", "ca.pem")}\n`);
  writeFileSync(join(work, "empty-npmrc"), "");
  const install = spawnSync(
    "npm",
    ["install", "is-number@7.0.0", "--no-audit", "--no-fund", "--cache", join(work, "npm-cache"), "--userconfig", join(work, "empty-npmrc")],
    { cwd: project, stdio: "inherit" },
  );
  expect(install.status === 0, `npm install exited ${install.status}`);
  const installed = join(project, "node_modules", "is-number", "package.json");
  expect(existsSync(installed) && JSON.parse(readFileSync(installed, "utf8")).version === "7.0.0", "is-number 7.0.0 is installed");

  const seconds = (performance.now() - started) / 1000;
  console.log(`E2E ${seconds < BUDGET_SECONDS ? "PASS" : "FAIL"} ${seconds.toFixed(1)}`);
  expect(seconds < BUDGET_SECONDS, `sign-up to install took ${seconds} s`);
  return user;
}

/// p99 of (last firewall apply - commit), in seconds.
function p99(committed, applied) {
  const latencies = [...committed].map(([n, at]) => Math.max(...firewalls.map((_, f) => applied.get(`${f}:${n}`) - at)) / 1000);
  latencies.sort((a, b) => a - b);
  return latencies[Math.ceil(latencies.length * 0.99) - 1];
}

async function propagation(user) {
  const { browser } = user;
  // An org admin edits policy only with an authenticator (C24): turn it on, then sign
  // in again with a code.
  let page = await browser.submit("/account", "/account/totp/setup", {});
  const secret = between(page.body, '<code id="totp-key">', "</code>");
  const enabledAt = step();
  page = await browser.post("/account/totp/enable", { code: totp(secret, enabledAt), csrf: hidden(page.body, "csrf") });
  expect(page.status === 303, `authenticator: ${page.status}\n${page.body}`);

  // S8-3, test-only setup the portal has no page for: the bootstrap's global admin
  // cannot sign in, so this login becomes one to register firewall-2; and this
  // organisation's keys get room for 52 keys and the pollers' request rate (C114).
  const login = sql(`SELECT login_id FROM sign_in_methods WHERE kind = 'password' AND email = '${user.email}'`);
  sql(`INSERT INTO memberships (login_id, role) VALUES (${login}, 'global_admin')`);
  const org = sql(`SELECT id FROM orgs WHERE name = '${user.org}'`);
  sql(`INSERT INTO limits (scope_kind, scope_id, rate_per_min, max_keys, max_service_keys) VALUES ('org', ${org}, 10000000, 1000, 1000)`);

  await browser.submit("/account", "/signout", {});
  page = await browser.submit("/signin", "/signin", { email: user.email, password: user.password });
  expect(page.location === "/totp", `sign-in asks for a code: ${page.status} ${page.location}`);
  while (step() === enabledAt) await sleep(1000); // a code is accepted once
  page = await browser.submit("/totp", "/totp", { code: totp(secret, step()) });
  expect(page.status === 303, `code: ${page.status}\n${page.body}`);

  page = await browser.submit("/fleet", "/fleet/register", { name: "firewall-2", sources: "0.0.0.0/0 ::/0" });
  writeFileSync(join(work, "firewall-2.token"), `${between(page.body, '<code id="new-token">', "</code>")}\n`);
  execFileSync("bash", ["-c", "$E2E_COMPOSE up -d --no-deps firewall-2"], { stdio: "inherit" });
  await Promise.all([ready(0), ready(1)]);

  const keys = [];
  for (let n = 0; n <= CHANGES; n++) {
    page = await browser.submit("/keys", "/keys", { name: `p-${n}` });
    keys.push(between(page.body, '<code id="new-key">', "</code>"));
  }
  const probe = keys.pop();
  const listed = (await browser.get("/keys")).body;
  const ids = keys.map((_, n) => {
    const row = listed.match(new RegExp(`<td>p-${n}</td>[\\s\\S]*?action="/keys/(\\d+)/revoke"`));
    expect(row, `key p-${n} is listed`);
    return row[1];
  });

  // 51 versions of a real package that firewall-1 serves today (old enough for the
  // cooldown, no OSV finding): 50 to block one by one, and one every key asks for.
  const document = await fetch(`${firewalls[0]}/npm/commander`, { headers: { authorization: `Bearer ${probe}` } });
  expect(document.status === 200, `commander: ${document.status}`);
  const allowed = [];
  for (const version of Object.keys((await document.json()).versions)) {
    if (allowed.length > CHANGES) break;
    if ((await status(0, `/npm/commander/${version}`, probe)) === 200) allowed.push(version);
  }
  expect(allowed.length > CHANGES, `only ${allowed.length} versions of commander are served`);
  const keep = allowed.pop();
  for (let f = 0; f < firewalls.length; f++) {
    for (const version of [...allowed, keep]) await warm(f, `/npm/commander/${version}`, probe);
    for (const key of keys) await warm(f, `/npm/commander/${keep}`, key);
  }

  const policy = (await browser.get("/policy")).location;
  expect(policy?.startsWith("/policy/org-"), `the organisation's policy page: ${policy}`);
  const edits = new Map();
  const revocations = new Map();
  const editsApplied = new Map();
  const revocationsApplied = new Map();
  const writer = (async () => {
    const csrf = hidden((await browser.get("/keys")).body, "csrf");
    // One change every 100 ms or so, edits and revocations alternating.
    for (let n = 0; n < CHANGES; n++) {
      const form = (await browser.get(policy)).body;
      edits.set(n, performance.now());
      const saved = await browser.post(policy, {
        csrf: hidden(form, "csrf"),
        revision: hidden(form, "revision"),
        action: "add_block",
        ecosystem: "npm",
        name: "commander",
        what: "version",
        version: allowed[n],
      });
      expect(saved.status === 303, `edit ${n}: ${saved.status}\n${saved.body}`);
      await sleep(50);
      revocations.set(n, performance.now());
      const revoked = await browser.post(`/keys/${ids[n]}/revoke`, { csrf });
      expect(revoked.status === 303, `revocation ${n}: ${revoked.status}\n${revoked.body}`);
      await sleep(50);
    }
  })();
  const poller = async (f) => {
    const deadline = performance.now() + (CHANGES * 0.3 + 4 * INTERVAL) * 1000;
    for (;;) {
      const asked = [];
      for (const n of edits.keys()) {
        if (editsApplied.has(`${f}:${n}`)) continue;
        asked.push(status(f, `/npm/commander/${allowed[n]}`, probe).then((answer) => {
          if (answer === 403) editsApplied.set(`${f}:${n}`, performance.now());
        }));
      }
      for (const n of revocations.keys()) {
        if (revocationsApplied.has(`${f}:${n}`)) continue;
        asked.push(status(f, `/npm/commander/${keep}`, keys[n]).then((answer) => {
          if (answer === 401) revocationsApplied.set(`${f}:${n}`, performance.now());
        }));
      }
      await Promise.all(asked);
      const done = (applied) => [...applied.keys()].filter((at) => at.startsWith(`${f}:`)).length === CHANGES;
      if (done(editsApplied) && done(revocationsApplied)) return;
      expect(performance.now() < deadline, `firewall-${f + 1} never applied every change`);
      await sleep(50);
    }
  };
  await Promise.all([writer, ...firewalls.map((_, f) => poller(f))]);

  let passed = true;
  for (const [what, committed, applied] of [
    ["edits", edits, editsApplied],
    ["revocations", revocations, revocationsApplied],
  ]) {
    const seconds = p99(committed, applied);
    const within = seconds <= INTERVAL;
    passed &&= within;
    console.log(`propagation ${what} p99 ${within ? "<=" : ">"} interval (${seconds.toFixed(3)} s, interval ${INTERVAL} s)`);
  }
  expect(passed, "a propagation p99 exceeds the interval");
}

try {
  await propagation(await signUpToInstall());
} catch (err) {
  console.error(`E2E FAIL: ${err.message}`);
  process.exit(1);
}
