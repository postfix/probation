// What a scenario gets as `h` (tests/e2e/README.md lists it). API-only steps use the
// cookie-jar Portal; steps a person does in a browser use h.browser() (Playwright
// Chromium, D3). Both reach the stack through the bridge under the stack's own names.

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { Authenticator, Portal, between, expect, hidden, randomClientIp, request, totp, unescape } from "./net.mjs";
import { OPERATOR_EMAIL, SYNC_INTERVAL, enableTotp, signInWithCode, waitFor } from "./stack.mjs";

const FAKES = "http://fakes.e2e.test:8080";
const MAIL = "http://mail.e2e.test:8025/api/v1";

async function call(method, url, body) {
  const answer = await request(url, { method, body });
  expect(answer.status < 300, `${method} ${url}: ${answer.status} ${answer.body}`);
  return /json/.test(answer.headers["content-type"] ?? "") ? answer.json() : answer.body;
}

export function helpers(stack, { log = console.log } = {}) {
  let browser;
  const h = {
    stack,
    log,
    request,
    Portal,
    Authenticator,
    expect,
    between,
    hidden,
    totp,
    waitFor,
    sleep,
    syncInterval: SYNC_INTERVAL,
    operator: stack.operator,
    bootstrap: stack.bootstrap,
    operatorEmail: OPERATOR_EMAIL,
    firewalls: { fw1: "https://fw1.e2e.test", fw2: "https://fw2.e2e.test", standalone: "https://fw-standalone.e2e.test" },
    portalUrl: "https://portal.e2e.test",

    /// A name no other scenario uses: `prefix-<random>`.
    unique: (prefix = "e2e") => `${prefix}-${randomBytes(4).toString("hex")}`,

    fakes: {
      reset: () => call("POST", `${FAKES}/reset`),
      /// Npm.publish: {name, version, ageSeconds | publishedAt, dependencies, tag}.
      publishNpm: (spec) => call("POST", `${FAKES}/npm/publish`, spec),
      /// Pypi.publish: {name, version, ageSeconds | uploadedAt, kinds, requiresPython}.
      publishPypi: (spec) => call("POST", `${FAKES}/pypi/publish`, spec),
      /// {ecosystem: "npm" | "PyPI", name, version, ids: ["MAL-..."]}; [] clears.
      osvFlag: (spec) => call("POST", `${FAKES}/osv/flag`, spec),
      osvQueries: () => call("GET", `${FAKES}/osv/queries`),
      /// Replaces the fault list; see fixtures/fakes/main.mjs. faults([]) clears.
      faults: (faults) => call("POST", `${FAKES}/faults`, { faults }),
      requests: (host) => call("GET", `${FAKES}/log${host ? `?host=${host}` : ""}`),
      leakPassword: (password) => call("POST", `${FAKES}/hibp/leak`, { password }),
      /// Who signs in at the fake IdP next: {sub, email, hd, tid, mode}.
      oidcNext: (person) => call("POST", `${FAKES}/oidc/next`, person),
      oidcRotate: () => call("POST", `${FAKES}/oidc/rotate`),
    },

    mail: {
      purge: () => call("DELETE", `${MAIL}/messages`),
      /// The newest mail to `to` (waits for it): {subject, text, html}.
      async latest(to, { timeout = 65_000, subject } = {}) {
        const found = await waitFor(`mail to ${to}`, async () => {
          const { messages } = await call("GET", `${MAIL}/search?query=${encodeURIComponent(`to:"${to}"`)}`);
          return messages.find((m) => !subject || m.Subject.includes(subject));
        }, { timeout });
        const message = await call("GET", `${MAIL}/message/${found.ID}`);
        return { subject: message.Subject, text: message.Text, html: message.HTML };
      },
      /// The first URL in the newest mail to `to` whose path matches `path` (a RegExp).
      async link(to, path, options) {
        const { text } = await h.mail.latest(to, options);
        const url = text.match(/https?:\/\/\S+/g)?.map((u) => new URL(u.replace(/[.,)>]+$/, ""))).find((u) => path.test(u.pathname));
        expect(url, `no link matching ${path} in the mail to ${to}:\n${text}`);
        return url;
      },
    },

    /// Signs a new account up through the portal (API steps), confirms its address from
    /// the mail and signs in. kind "org" (with `org`) or "personal". Answers
    /// {email, password, org, portal}.
    async signUp({ kind = "org", email = `${h.unique("user")}@example.com`, password = randomBytes(18).toString("base64url"), org } = {}) {
      const portal = new Portal();
      org ??= kind === "org" ? h.unique("Org") : undefined;
      let page = await portal.submit("/signup", "/signup", { email, password, kind, org_name: org ?? "" });
      expect(page.status === 200, `sign-up: ${page.status}\n${page.body}`);
      const link = await h.mail.link(email, /^\/verify-email$/);
      page = await portal.get(link.pathname + link.search);
      expect(page.body.includes("Your email address is confirmed"), `confirm: ${page.status}\n${page.body}`);
      page = await portal.submit("/signin", "/signin", { email, password });
      expect(page.status === 303 && page.location === "/account", `sign-in: ${page.status} ${page.location}`);
      return { email, password, org, portal };
    },

    /// Turns the authenticator on for `who` and signs in again with a code; sets who.auth.
    async enableTotp(who) {
      who.auth = await enableTotp(who.portal);
      await signInWithCode(who);
      return who.auth;
    },

    /// Creates a key on /keys: {key, npmrc, pipConf} as the page shows them.
    async createKey(portal, name = h.unique("key")) {
      const page = await portal.submit("/keys", "/keys", { name });
      expect(page.status === 200, `create key: ${page.status}\n${page.body}`);
      return {
        key: between(page.body, '<code id="new-key">', "</code>"),
        npmrc: `registry=${between(page.body, "<pre>registry=", "</pre>")}\n`,
        pipConf: `[global]${between(page.body, "<pre>[global]", "</pre>")}\n`,
      };
    },

    /// The signed-in place's policy page path (`/policy/org-N` or similar).
    async policyPath(portal) {
      const path = (await portal.get("/policy")).location;
      expect(path?.startsWith("/policy/"), `the policy page: ${path}`);
      return path;
    },

    /// One policy edit, as the policy page's form posts it (action add_block, ...).
    async editPolicy(portal, fields, path) {
      path ??= await h.policyPath(portal);
      const form = (await portal.get(path)).body;
      const saved = await portal.post(path, { csrf: hidden(form, "csrf"), revision: hidden(form, "revision"), ...fields });
      expect(saved.status === 303, `policy edit ${JSON.stringify(fields)}: ${saved.status}\n${saved.body}`);
    },

    /// The rows of /activity: [{at, key, ecosystem, package, result, rule, layer}].
    async activity(portal) {
      const body = (await portal.get("/activity")).body;
      const tbody = body.match(/<tbody>([\s\S]*?)<\/tbody>/)?.[1] ?? "";
      return [...tbody.matchAll(/<tr>([\s\S]*?)<\/tr>/g)].map(([, row]) => {
        const cells = [...row.matchAll(/<td>([\s\S]*?)<\/td>/g)].map(([, cell]) => unescape(cell.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()));
        const [at, key, ecosystem, pkg, result, rule, layer] = cells;
        return { at, key, ecosystem, package: pkg, result, rule, layer };
      });
    },

    /// Runs `script` (sh) in a client container, in a fresh directory holding `files`
    /// ({relative path: content}): {status, stdout, stderr}. Never throws on exit status.
    client(service, script, { files = {}, dir = `/work/${h.unique("run")}` } = {}) {
      const writes = Object.entries(files).map(
        ([path, content]) => `mkdir -p "$(dirname '${path}')" && echo '${Buffer.from(content).toString("base64")}' | base64 -d > '${path}'`,
      );
      return stack.exec(service, ["sh", "-c", ["set -e", `mkdir -p ${dir}`, `cd ${dir}`, ...writes, "set +e", script].join("\n")]);
    },

    /// `npm <args>` in a project whose .npmrc is `npmrc` (as the keys page shows it).
    npm(args, { npmrc, client = "client-npm", packageJson = { name: "e2e-project", version: "1.0.0", private: true }, files = {} } = {}) {
      return h.client(client, `npm ${args}`, {
        files: { "package.json": JSON.stringify(packageJson), ".npmrc": npmrc, ...files },
      });
    },

    /// `pip <args>` with `pipConf` (as the keys page shows it) as the only config.
    pip(args, { pipConf, client = "client-pip", files = {} } = {}) {
      return h.client(client, `PIP_CONFIG_FILE=$PWD/pip.conf pip ${args}`, { files: { "pip.conf": pipConf, ...files } });
    },

    /// Moves `column` of the rows `where` selects back by `interval` (D10), for example
    /// backdate("orgs", "deleted_at", "31 days", "id = 7"); restart the server after.
    backdate(table, column, interval, where) {
      return stack.sql(`UPDATE ${table} SET ${column} = ${column} - interval '${interval}' WHERE ${where}`);
    },

    /// The firewall's "request decided" log lines since `since` (a Date): their fields
    /// ({method, ecosystem, package, version, status, result, reason, ...}), with the
    /// quotes the log puts around strings removed. For an artifact, `package` is its
    /// reference id and `version` its filename.
    decisions(service, since) {
      const run = spawnSync(stack.engine, ["logs", "--since", since.toISOString(), stack.container(service)], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
      return `${run.stdout}\n${run.stderr}`
        .split("\n")
        .filter((line) => line.includes('"request decided"'))
        .map((line) => {
          try {
            const { fields } = JSON.parse(line);
            return Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, typeof v === "string" ? v.replace(/^"|"$/g, "") : v]));
          } catch {
            return null;
          }
        })
        .filter(Boolean);
    },

    restart: (...services) => stack.restart(...services),
    stop: (...services) => stack.stop(...services),
    start: (...services) => stack.start(...services),
    postgresDown: () => stack.stop("postgres"),
    async postgresUp() {
      stack.start("postgres");
      await waitFor("postgres", () => stack.exec("postgres", ["pg_isready", "-U", "probation"]).status === 0);
    },
    firewallReady: (host) => stack.firewallReady(host),

    /// A Playwright Chromium context that reaches the stack through the bridge. The e2e
    /// CA is not in Chromium's store, so certificate errors are ignored there.
    async browser() {
      if (!browser) {
        const { chromium } = await import("playwright");
        browser = await chromium.launch({ proxy: { server: `http://127.0.0.1:${stack.bridgePort}` } });
      }
      // Like a Portal, each context is a person with an address of their own.
      return browser.newContext({ ignoreHTTPSErrors: true, baseURL: h.portalUrl, extraHTTPHeaders: { "x-forwarded-for": randomClientIp() } });
    },

    /// In a browser page: the sign-up form, the confirmation link from the mail, and
    /// the sign-in form. Answers {email, password, org}.
    async browserSignUp(page, { kind = "org", email = `${h.unique("user")}@example.com`, password = randomBytes(18).toString("base64url"), org } = {}) {
      org ??= kind === "org" ? h.unique("Org") : undefined;
      await page.goto("/signup");
      await page.fill("#email", email);
      await page.fill("#password", password);
      await page.check(`input[name=kind][value=${kind}]`);
      if (org) await page.fill("#org_name", org);
      await page.click("form[action='/signup'] button[type=submit]");
      const link = await h.mail.link(email, /^\/verify-email$/);
      await page.goto(link.toString());
      expect((await page.content()).includes("Your email address is confirmed"), "the confirmation page");
      await h.browserSignIn(page, { email, password });
      return { email, password, org };
    },

    async browserSignIn(page, { email, password }) {
      await page.goto("/signin");
      await page.fill("form[action='/signin'] #email", email);
      await page.fill("form[action='/signin'] #password", password);
      await page.click("form[action='/signin'] button[type=submit]");
    },

    /// In a browser page: creates a key on /keys and reads it and the client lines.
    async browserCreateKey(page, name = h.unique("key")) {
      await page.goto("/keys");
      await page.fill("#key-name", name);
      await page.click("form[action='/keys'] button[type=submit]");
      const pre = await page.locator("pre").allTextContents();
      return {
        key: await page.locator("#new-key").textContent(),
        npmrc: `${pre.find((text) => text.startsWith("registry="))}\n`,
        pipConf: `${pre.find((text) => text.startsWith("[global]"))}\n`,
      };
    },

    async close() {
      await browser?.close();
      browser = undefined;
    },
  };
  return h;
}
