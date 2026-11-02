// E2E-016 Network lock and trusted proxies behind a real load balancer (docs/plans/
// e2e-coverage/00-inventory.md §3; docs/operations.md §13 "trusted_proxies";
// portal-guide §3.10, §4.5).
//
// The office is the client-npm container. Two more nginx load balancers sit in front of
// firewall-1 beside the stack's gateway: lb-trusted (listed in firewall-1's
// [management] trusted_proxies by the operator) and lb-untrusted (not listed). Each
// forwards on three ports: :8080 appends the peer to X-Forwarded-For, :8081 sends
// "peer-ip:peer-port" (as some cloud load balancers do; F1), :8082 passes on the
// X-Forwarded-For an outer hop sent (IPv6, bracketed, `unknown`).
//
// 1. Acme's org admin registers the office range and an IPv6 range; nothing changes
//    while they wait; the operator approves them.
// 2. Through the gateway, a Globex key from the office gets 403 NETWORK_NOT_ALLOWED
//    naming the office address and nothing else (npm fails, Globex's Activity shows
//    the refusal); the Acme key installs; the Globex key installs from elsewhere; a
//    forged X-Forwarded-For from the office does not escape the lock.
// 3. lb-trusted: ip:port and bracketed IPv6 entries are read as addresses (needs F1);
//    `unknown` fails closed and names the proxy.
// 4. lb-untrusted: the firewall sees the proxy as the client (the documented cost of
//    an unlisted proxy), and ignores a forwarded address from it.
// 5. Acme removes the office range: lifted within one sync interval.
// 6. Portal: 100 failed sign-ins from the office lock the office out, not another
//    client behind the same gateway.
//
// Not covered here: a real IPv6 client socket (the e2e network is IPv4 only) and the
// docker bridge gateway as the peer (the internal network routes nothing through it).
//
// Own stack: it edits firewall-1's trusted_proxies and locks client-npm's address.

import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { addressOf, editConfig, errorOf, runOnNetwork } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-016",
  title: "Network lock and trusted proxies behind a real load balancer",
  suites: ["nightly", "release"],
  stack: "own",
};

const V6_RANGE = "2001:db8:77::/48";
const V6_INSIDE = "2001:db8:77::5";
const V6_OUTSIDE = "2001:db8:99::1";

const LB_CONF = `resolver \${NGINX_LOCAL_RESOLVERS} valid=2s ipv6=off;
proxy_http_version 1.1;
proxy_ssl_server_name on;
proxy_ssl_name fw1.e2e.test;
proxy_ssl_trusted_certificate /e2e/ca/ca.pem;
proxy_ssl_verify on;
server {
  listen 8080;
  location / { set $u firewall-1:8080; proxy_pass https://$u; proxy_set_header Host fw1.e2e.test; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; }
}
server {
  listen 8081;
  location / { set $u firewall-1:8080; proxy_pass https://$u; proxy_set_header Host fw1.e2e.test; proxy_set_header X-Forwarded-For "$remote_addr:$remote_port"; }
}
server {
  listen 8082;
  location / { set $u firewall-1:8080; proxy_pass https://$u; proxy_set_header Host fw1.e2e.test; proxy_set_header X-Forwarded-For $http_x_forwarded_for; }
}
`;

// Run in client-npm: one GET, or a sign-in spray, printed as JSON.
const FETCH = `const [url, headers] = JSON.parse(process.argv[2]);
const answer = await fetch(url, { headers });
console.log(JSON.stringify({ status: answer.status, body: await answer.text() }));
`;
const SPRAY = `const base = "https://portal.e2e.test:8444";
async function once(email) {
  const page = await fetch(base + "/signin");
  const cookie = page.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const csrf = (await page.text()).match(/name="csrf" value="([^"]*)"/)[1];
  const answer = await fetch(base + "/signin", {
    method: "POST",
    redirect: "manual",
    headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ csrf, email, password: "not-the-password-" + email }),
  });
  return answer.status;
}
const [count, prefix] = [Number(process.argv[2]), process.argv[3]];
const statuses = [];
for (let n = 0; n < count; n += 10) {
  statuses.push(...(await Promise.all(Array.from({ length: Math.min(10, count - n) }, (_, i) => once(prefix + (n + i) + "@example.com")))));
}
console.log(JSON.stringify(statuses));
`;

export default async function networkLock(h) {
  const { expect } = h;
  const interval = h.syncInterval;
  const net = h.stack.net;
  const lbTrusted = `${net}.250`;
  const lbUntrusted = `${net}.251`;
  const quote = (text) => `'${text.replaceAll("'", "'\\''")}'`;
  const show = (run) => `exit ${run.status}\n${run.stdout}\n${run.stderr}`;
  /// F1 cases are checked at the end, so the rest still runs until F1 is merged.
  const deferred = [];
  const later = (ok, message) => ok || deferred.push(message);

  // The load balancers, and the operator lists lb-trusted for firewall-1.
  const template = join(h.stack.work, "lb.conf.template");
  writeFileSync(template, LB_CONF);
  const removals = [];
  try {
    const connected = spawnSync(h.stack.engine, ["network", "connect", `${h.stack.project}_e2e`, h.stack.container("client-npm")], { encoding: "utf8" });
    expect(connected.status === 0, `connect office client to operations network: ${show(connected)}`);
    removals.push(() => spawnSync(h.stack.engine, ["network", "disconnect", `${h.stack.project}_e2e`, h.stack.container("client-npm")], { encoding: "utf8" }));
    for (const [name, ip] of [["lb-trusted", lbTrusted], ["lb-untrusted", lbUntrusted]]) {
      removals.push(
        runOnNetwork(h.stack, {
          name,
          ip,
          image: "docker.io/library/nginx:1.27-alpine",
          env: { NGINX_ENTRYPOINT_LOCAL_RESOLVERS: "1" },
          volumes: [`${template}:/etc/nginx/templates/default.conf.template:ro`, `${join(h.stack.work, "ca")}:/e2e/ca:ro`],
        }),
      );
    }
    editConfig(h.stack, "firewall-1", (text) =>
      text.replace(/^trusted_proxies = \["([^"]+)"\]$/m, `trusted_proxies = ["$1", "${lbTrusted}/32"]`),
    );
    h.restart("firewall-1");
    await h.firewallReady("fw1");
    for (const lb of [lbTrusted, lbUntrusted]) {
      await h.waitFor(`${lb} forwards`, async () => (await h.request(`http://${lb}:8080/health/live`)).status === 200);
    }
    await scenario();
  } finally {
    for (const remove of removals) remove();
  }

  async function scenario() {
    const office = addressOf(h.stack, "client-npm");
    const acme = await h.signUp({ kind: "org" });
    await h.enableTotp(acme);
    const acmeKey = await h.createKey(acme.portal, "acme-laptop");
    const globex = await h.signUp({ kind: "org" });
    const globexKey = await h.createKey(globex.portal, "globex-laptop");
    const bearer = (keys) => ({ authorization: `Bearer ${keys.key}` });

    /// A GET from the office (client-npm): {status, body, json}.
    const fromOffice = (url, headers) => {
      const run = h.client("client-npm", `node fetch.mjs ${quote(JSON.stringify([url, headers]))}`, { files: { "fetch.mjs": FETCH } });
      expect(run.status === 0, `fetch from the office: ${show(run)}`);
      const answer = JSON.parse(run.stdout.trim().split("\n").pop());
      return { ...answer, json: () => JSON.parse(answer.body) };
    };
    /// A GET from elsewhere (the host, through the bridge).
    const fromElsewhere = async (url, headers) => {
      const answer = await h.request(url, { headers });
      return { status: answer.status, body: answer.body, json: () => answer.json() };
    };
    const refusedFrom = (answer, address) => {
      const body = errorOf(answer);
      return answer.status === 403 && body.error === "NETWORK_NOT_ALLOWED" && body.reason === `this API key may not be used from ${address}`;
    };
    const npm = (keys) => h.npm(`view e2e-left@1.0.0 version --fetch-retries=0 --cache "$PWD/.npm-cache-${h.unique("lock")}"`, {
      npmrc: `registry=http://${lbTrusted}:8080/npm/\n//${lbTrusted}:8080/:_authToken=${keys.key}\n`,
    });
    const pkg = "/npm/e2e-left";
    const gateway = `http://${lbTrusted}:8080`;

    let run = npm(globexKey);
    expect(run.status === 0, `Globex installs from the office before any lock: ${show(run)}`);

    // 1. Ranges: registered, waiting, approved.
    const orgId = (await h.policyPath(acme.portal)).slice("/policy/org-".length);
    for (const cidr of [`${office}/32`, V6_RANGE]) {
      const page = await acme.portal.submit(`/org/${orgId}`, `/org/${orgId}/ranges`, { cidr });
      expect(page.status === 303, `add range ${cidr}: ${page.status}\n${page.body}`);
    }
    let org = (await acme.portal.get(`/org/${orgId}`)).body;
    expect((org.match(/Waiting for operator approval/g) ?? []).length === 2, "both ranges wait for the operator");
    const waitedUntil = Date.now() + 2 * interval * 1000;
    while (Date.now() < waitedUntil) {
      const answer = fromOffice(`${gateway}${pkg}`, bearer(globexKey));
      expect(answer.status === 200, `a waiting range has no effect: ${answer.status} ${answer.body}`);
      await h.sleep(2000);
    }
    const admin = (await h.operator.portal.get("/admin")).body;
    for (const cidr of [`${office}/32`, V6_RANGE]) {
      const id = admin.match(new RegExp(`<code>${cidr.replaceAll(".", "\\.")}</code>[\\s\\S]*?action="/admin/ranges/(\\d+)/approve"`))?.[1];
      expect(id, `the operator sees ${cidr} waiting`);
      const page = await h.operator.portal.post(`/admin/ranges/${id}/approve`, { csrf: h.hidden(admin, "csrf") });
      expect(page.status === 303, `approve ${cidr}: ${page.status}\n${page.body}`);
    }
    org = (await acme.portal.get(`/org/${orgId}`)).body;
    expect((org.match(/class="good">Approved/g) ?? []).length === 2, "Acme sees both ranges approved");

    // 2. Through the gateway.
    await h.waitFor("the lock reaches firewall-1", () => refusedFrom(fromOffice(`${gateway}${pkg}`, bearer(globexKey)), office), {
      timeout: 2 * interval * 1000 + 5000,
      every: 1000,
    });
    const refusal = fromOffice(`${gateway}${pkg}`, bearer(globexKey));
    expect(!refusal.body.includes(acme.org) && !refusal.body.includes("Acme"), `the refusal names the address only: ${refusal.body}`);
    run = npm(globexKey);
    expect(run.status !== 0 && /403/.test(run.stderr), `npm with Globex's key from the office: ${show(run)}`);
    run = npm(acmeKey);
    expect(run.status === 0, `npm with Acme's key from the office: ${show(run)}`);
    expect((await fromElsewhere(`${gateway}${pkg}`, bearer(globexKey))).status === 200, "Globex from elsewhere");
    const forged = fromOffice(`${gateway}${pkg}`, { ...bearer(globexKey), "x-forwarded-for": "203.0.113.50" });
    expect(refusedFrom(forged, office), `a forged X-Forwarded-For from the office: ${forged.status} ${forged.body}`);
    await h.waitFor("Globex's Activity shows the refusal", async () =>
      (await h.activity(globex.portal)).some((r) => r.result === `Refused by a network lock (used from ${office})` && r.layer === "Network lock"),
    { timeout: 3 * interval * 1000, every: 2000 });

    // 3. lb-trusted.
    const viaPort = `http://${lbTrusted}:8081${pkg}`;
    let answer = fromOffice(viaPort, bearer(globexKey));
    // needs F1: "ip:port" is the office's address.
    later(refusedFrom(answer, office), `ip:port, Globex from the office: ${answer.status} ${answer.body}`);
    answer = fromOffice(viaPort, bearer(acmeKey));
    later(answer.status === 200, `ip:port, Acme from the office: ${answer.status} ${answer.body}`);
    answer = await fromElsewhere(viaPort, bearer(globexKey));
    later(answer.status === 200, `ip:port, Globex from elsewhere: ${answer.status} ${answer.body}`);

    const via = `http://${lbTrusted}:8082${pkg}`;
    for (const [entry, needsF1] of [[V6_INSIDE, false], [`[${V6_INSIDE}]:443`, true], [`[${V6_INSIDE}]`, true]]) {
      const check = needsF1 ? later : expect;
      answer = await fromElsewhere(via, { ...bearer(globexKey), "x-forwarded-for": entry });
      check(refusedFrom(answer, V6_INSIDE), `X-Forwarded-For ${entry}, Globex: ${answer.status} ${answer.body}`);
      answer = await fromElsewhere(via, { ...bearer(acmeKey), "x-forwarded-for": entry });
      check(answer.status === 200, `X-Forwarded-For ${entry}, Acme: ${answer.status} ${answer.body}`);
    }
    answer = await fromElsewhere(via, { ...bearer(globexKey), "x-forwarded-for": V6_OUTSIDE });
    expect(answer.status === 200, `X-Forwarded-For ${V6_OUTSIDE}, outside the range: ${answer.status} ${answer.body}`);
    answer = await fromElsewhere(via, { ...bearer(acmeKey), "x-forwarded-for": "unknown" });
    expect(refusedFrom(answer, lbTrusted), `X-Forwarded-For unknown fails closed, naming the proxy: ${answer.status} ${answer.body}`);

    // 4. lb-untrusted: every client is the proxy.
    answer = fromOffice(`http://${lbUntrusted}:8080${pkg}`, bearer(globexKey));
    expect(answer.status === 200, `behind an unlisted proxy the office is not seen: ${answer.status} ${answer.body}`);
    answer = await fromElsewhere(`http://${lbUntrusted}:8082${pkg}`, { ...bearer(globexKey), "x-forwarded-for": office });
    expect(answer.status === 200, `an unlisted proxy's X-Forwarded-For is ignored: ${answer.status} ${answer.body}`);

    // 5. Acme removes the office range.
    org = (await acme.portal.get(`/org/${orgId}`)).body;
    const rangeId = org.match(new RegExp(`<code>${office.replaceAll(".", "\\.")}/32</code>[\\s\\S]*?action="/org/ranges/(\\d+)/delete"`))?.[1];
    expect(rangeId, "the office range has Remove");
    const page = await acme.portal.post(`/org/ranges/${rangeId}/delete`, { csrf: h.hidden(org, "csrf") });
    expect(page.status === 303, `remove the range: ${page.status}\n${page.body}`);
    const removed = performance.now();
    await h.waitFor("the lock is lifted", () => fromOffice(`${gateway}${pkg}`, bearer(globexKey)).status === 200, {
      timeout: 2 * interval * 1000 + 5000,
      every: 500,
    });
    const lifted = (performance.now() - removed) / 1000;
    h.log(`lock lifted ${lifted.toFixed(1)} s after the range was removed (interval ${interval} s)`);
    expect(lifted <= interval + 3, `lifted within one interval: ${lifted.toFixed(1)} s`);

    // 6. Sign-in throttle per client, behind the gateway the server trusts.
    run = h.client("client-npm", `node spray.mjs 105 ${h.unique("spray")}-`, { files: { "spray.mjs": SPRAY } });
    expect(run.status === 0, `the spray: ${show(run)}`);
    const statuses = JSON.parse(run.stdout.trim().split("\n").pop());
    const wrong = statuses.filter((s) => s === 422).length;
    expect(wrong <= 100 && statuses.filter((s) => s === 429).length >= 5, `over 100 failures from one client are throttled: ${JSON.stringify(statuses)}`);
    run = h.client("client-npm", `node spray.mjs 1 ${h.unique("again")}-`, { files: { "spray.mjs": SPRAY } });
    expect(JSON.parse(run.stdout.trim().split("\n").pop())[0] === 429, `the office is throttled: ${show(run)}`);
    const victim = new h.Portal();
    const signedIn = await victim.submit("/signin", "/signin", { email: globex.email, password: globex.password });
    expect(signedIn.status === 303 && signedIn.location === "/account", `another client still signs in: ${signedIn.status} ${signedIn.location}`);

    expect(!deferred.length, deferred.join("\n"));
  }
}
