// E2E-005: the operator's first deployment in the documented topology
// (docs/management-server.md §4-§5, operations.md §13).
//
// From an empty database: `migrate` as the owner (twice: the second run changes
// nothing), the app role, `admin bootstrap` with firewall-1's own address as
// --firewall-source (the TLS gateway is in both trusted_proxies, so the server sees the
// firewall, not the proxy). Firewall-1 runs plain HTTP behind the gateway with an https
// public_url. In Chromium the operator opens the printed set-password link, gets no
// admin rights before the authenticator, sets it up, reaches /admin, and registers
// firewall-2 by its own address on /fleet. npm and pip install with the printed
// bootstrap key through both firewalls, and every download link the firewalls hand out
// is on their public https address.
//
// Negative and edge cases: the link works once; a second bootstrap is refused; a
// malformed source range is refused on /fleet; a third firewall started with
// firewall-1's token from an unlisted address is refused (403
// FIREWALL_SOURCE_REFUSED) and never becomes ready, while firewall-1 keeps syncing; the
// session cookie is Secure, HttpOnly and SameSite=Lax on the https portal.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ops } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-005",
  title: "Operator's first deployment in the documented topology",
  suites: ["pr", "nightly", "release"],
  stack: "own",
};

const CONFIG = "/etc/probation-server/config.toml";

export default async function firstDeployment(h) {
  const { expect } = h;
  const o = ops(h);
  const net = h.stack.net;
  const address = { fw1: `${net}.201`, fw2: `${net}.202`, fw3: `${net}.203` };
  const operatorEmail = h.operatorEmail;

  try {
    // 1. An empty database, as on the first day. The stack's own firewalls stop; this
    // deployment runs its own, at fixed addresses, under the names the gateway fronts.
    h.stop("server", "firewall-1", "firewall-2");
    o.freshDatabase();

    // 2. migrate as the owner; a second run is a no-op.
    let run = o.server(["migrate"]);
    expect(run.status === 0, `migrate: ${run.status}\n${run.stdout}\n${run.stderr}`);
    const tables = h.stack.sql("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'");
    run = o.server(["migrate"]);
    expect(run.status === 0, `migrate again: ${run.status}\n${run.stderr}`);
    expect(h.stack.sql("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'") === tables, "a second migrate changes nothing");
    h.stack.sql("CREATE ROLE probation_e2e LOGIN PASSWORD 'probation' IN ROLE probation_app");

    // 3. bootstrap with firewall-1's own address.
    run = o.server(["admin", "bootstrap", "--config", CONFIG, "--email", operatorEmail, "--org", "Operators",
      "--firewall", "firewall-1", "--firewall-source", `${address.fw1}/32`]);
    expect(run.status === 0, `admin bootstrap: ${run.status}\n${run.stdout}\n${run.stderr}`);
    const printed = o.printed(run.stdout);
    for (const field of ["global_admin_login", "org", "key_id", "key", "firewall_id", "firewall_token", "set_password_link"]) {
      expect(printed[field], `bootstrap printed no ${field}:\n${run.stdout}`);
    }
    expect(printed.key.startsWith("prb_") && printed.firewall_token.startsWith("fwt_"), `key and token forms: ${run.stdout}`);
    expect(printed.set_password_link.startsWith("https://portal.e2e.test/"), `the link is built from base_url: ${printed.set_password_link}`);

    // Negative: bootstrap refuses a second run and changes nothing.
    const admins = h.stack.sql("SELECT count(*) FROM firewalls");
    run = o.server(["admin", "bootstrap", "--config", CONFIG, "--email", "second@example.com", "--org", "Second",
      "--firewall", "firewall-x", "--firewall-source", `${address.fw3}/32`]);
    expect(run.status === 1 && /probation-server: /.test(run.stderr), `a second bootstrap is refused: ${run.status}\n${run.stdout}\n${run.stderr}`);
    expect(!/firewall_token=/.test(run.stdout), `a refused bootstrap prints no token: ${run.stdout}`);
    expect(h.stack.sql("SELECT count(*) FROM firewalls") === admins, "a refused bootstrap registers nothing");

    // 4. Serve; firewall-1 starts with the printed token.
    h.start("server");
    await h.waitFor("the portal", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 120_000 });
    const firewall1 = o.firewall({ name: "firewall-1", ip: address.fw1, token: printed.firewall_token,
      config: readFileSync(join(h.stack.work, "firewall-1.toml"), "utf8") });
    await h.firewallReady("fw1");
    h.log(`firewall-1 at ${firewall1.ip()} is ready`);

    // 5. The set-password link in Chromium, then the authenticator, then /admin.
    const context = await h.browser();
    const page = await context.newPage();
    const password = `${h.unique("Pw")}-${h.unique("x")}`;
    await page.goto(printed.set_password_link);
    await page.fill("#new", password);
    await page.fill("#again", password);
    await page.click("form[action='/reset/confirm'] button[type=submit]");
    expect((await page.content()).includes("Your password is changed"), `set password: ${await page.content()}`);

    // Edge: the link works once.
    const again = await context.newPage();
    await again.goto(printed.set_password_link);
    expect((await again.content()).includes("This link has expired or was already used"), "the used link is refused");
    await again.close();

    await h.browserSignIn(page, { email: operatorEmail, password });
    await page.waitForURL(/\/account$/);
    const cookie = (await context.cookies()).find((c) => c.httpOnly);
    expect(cookie?.secure && cookie.sameSite === "Lax", `session cookie on https: ${JSON.stringify(await context.cookies())}`);

    // Negative: no admin rights before the authenticator.
    await page.goto("/admin");
    expect(/\/account#totp-heading$/.test(page.url()), `/admin before the authenticator sends to the authenticator set-up: ${page.url()}`);

    await page.goto("/account");
    await page.click("form[action='/account/totp/setup'] button[type=submit]");
    const auth = new h.Authenticator((await page.locator("#totp-key").textContent()).trim());
    await page.fill("#code", await auth.code());
    await page.click("form[action='/account/totp/enable'] button[type=submit]");
    await page.waitForURL(/\/account$/);
    expect((await page.content()).includes("Authenticator app: on"), "the authenticator is on");
    let admin = await page.goto("/admin");
    if (!/\/admin$/.test(page.url())) {
      // The portal asks for a fresh sign-in with the code.
      await page.goto("/account");
      await page.click("form[action='/signout'] button[type=submit]");
      await h.browserSignIn(page, { email: operatorEmail, password });
      await page.waitForURL(/\/totp$/);
      await page.fill("#code", await auth.code());
      await page.click("form[action='/totp'] button[type=submit]");
      admin = await page.goto("/admin");
    }
    expect(admin.status() === 200 && /\/admin$/.test(page.url()) && (await page.content()).includes("<h1>Global admin</h1>"), `/admin with the authenticator: ${admin.status()} ${page.url()}`);

    // 6. Register firewall-2 on /fleet by its own address; a malformed range is refused.
    await page.goto("/fleet");
    await page.fill("#register-name", "firewall-bad");
    await page.fill("#register-sources", "203.0.113.300/32");
    await page.click("form[action='/fleet/register'] button[type=submit]");
    expect((await page.content()).includes("Write each address range like"), "a malformed range is refused");
    expect(!(await page.content()).includes('id="new-token"'), "no token for a refused registration");
    await page.goto("/fleet");
    await page.fill("#register-name", "firewall-2");
    await page.fill("#register-sources", `${address.fw2}/32`);
    await page.click("form[action='/fleet/register'] button[type=submit]");
    const token2 = (await page.locator("#new-token").textContent()).trim();
    expect(token2.startsWith("fwt_"), `firewall-2's token: ${token2}`);
    o.firewall({ name: "firewall-2", ip: address.fw2, token: token2, config: readFileSync(join(h.stack.work, "firewall-2.toml"), "utf8") });
    await h.firewallReady("fw2");
    await h.waitFor("both firewalls healthy on /fleet", async () => {
      await page.goto("/fleet");
      const rows = await page.locator("tbody tr").allTextContents();
      return ["firewall-1", "firewall-2"].every((name) => rows.some((row) => row.includes(name) && row.includes("Healthy") && !row.includes("not reported yet")));
    }, { timeout: 4 * h.syncInterval * 1000, every: 2000 });

    // 7. npm and pip with the printed key, through both firewalls; links on public_url.
    for (const host of ["fw1.e2e.test", "fw2.e2e.test"]) {
      const npmrc = `registry=https://${host}/npm/\n//${host}/npm/:_authToken=${printed.key}\n`;
      const npm = h.npm("install e2e-right@1.0.0 --no-audit --no-fund && node -p \"require('e2e-left/package.json').version\"", { npmrc });
      expect(npm.status === 0, `npm through ${host}: ${npm.status}\n${npm.stdout}\n${npm.stderr}`);
      expect(npm.stdout.trim().endsWith("1.1.0"), `e2e-right pulls e2e-left 1.1.0 through ${host}: ${npm.stdout}`);
      const pipConf = `[global]\nindex-url = https://key:${printed.key}@${host}/pypi/simple/\n`;
      const pip = h.pip("install --no-cache-dir e2e-left==1.1.0 && python -c 'import e2e_left; print(e2e_left.VERSION)'", { pipConf });
      expect(pip.status === 0 && pip.stdout.trim().endsWith("1.1.0"), `pip through ${host}: ${pip.status}\n${pip.stdout}\n${pip.stderr}`);

      const doc = await h.request(`https://${host}/npm/e2e-left`, { headers: { authorization: `Bearer ${printed.key}` } });
      const tarballs = Object.values(doc.json().versions).map((v) => v.dist.tarball);
      expect(tarballs.length && tarballs.every((t) => t.startsWith(`https://${host}/`)), `npm links on ${host}'s public_url: ${tarballs}`);
      const basic = `Basic ${Buffer.from(`key:${printed.key}`).toString("base64")}`;
      const simple = await h.request(`https://${host}/pypi/simple/e2e-left/`, { headers: { authorization: basic, accept: "text/html" } });
      const hrefs = [...simple.body.matchAll(/href="([^"]+)"/g)].map((m) => new URL(m[1], `https://${host}/pypi/simple/e2e-left/`).href);
      expect(hrefs.length && hrefs.every((href) => href.startsWith(`https://${host}/`)), `PyPI links on ${host}'s public_url: ${hrefs}`);
    }

    // 8. A third firewall with firewall-1's token from an address nobody listed.
    const sync = `https://sync.e2e.test/api/v1/sync/lookup`;
    const probe = h.client("client-npm", `node -e '
fetch(${JSON.stringify(sync)}, {method: "POST", headers: {authorization: "Bearer ${printed.firewall_token}", "content-type": "application/json"}, body: JSON.stringify({key_hash: "0".repeat(64)})})
  .then(r => console.log(r.status, r.headers.get("x-probation-error")))'`);
    expect(probe.stdout.trim() === "403 FIREWALL_SOURCE_REFUSED", `the sync API from an unlisted address: ${probe.stdout}${probe.stderr}`);

    const firewall3 = o.firewall({ name: "firewall-3", ip: address.fw3, token: printed.firewall_token, config: o.managedConfig("fw3.e2e.test") });
    await h.waitFor("firewall-3 reports the server unreachable", () => /the management server could not be reached/.test(firewall3.logs()), { timeout: 4 * h.syncInterval * 1000 });
    const deadline = Date.now() + 2 * h.syncInterval * 1000;
    while (Date.now() < deadline) {
      const ready = await firewall3.ready();
      expect(ready === 503, `firewall-3 never becomes ready with a refused source: /health/ready ${ready}`);
      await h.sleep(2000);
    }
    const refused = await o.inside("http://firewall-3:8080/npm/e2e-left", { headers: { authorization: `Bearer ${printed.key}` } });
    expect(refused === 503, `firewall-3 serves nothing: ${refused}`);

    // firewall-1, sharing the token, keeps syncing: a block reaches it.
    const operator = { portal: new h.Portal() };
    for (const c of await context.cookies()) operator.portal.cookies.set(c.name, c.value);
    await h.editPolicy(operator.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "1.0.0" }, `/policy/org-${printed.org}`);
    await h.waitFor("the block reaches firewall-1", async () => (await h.request(`${h.firewalls.fw1}/npm/e2e-left/1.0.0`, { headers: { authorization: `Bearer ${printed.key}` } })).status === 403,
      { timeout: 3 * h.syncInterval * 1000 });
    expect(await firewall3.ready() === 503, "firewall-3 is still not ready");
  } finally {
    o.removeExtras();
  }
}
