// E2E-008: management server and Postgres outages during installs (operations.md §13
// "When the server is down", §16; api.md §2 status codes).
//
// A request loop with a known key runs through firewall-1 the whole time; it must never
// see a refusal of that key. In each outage a known key installs (served from the
// cache), a key the firewall never saw gets 401, and the firewalls stay ready:
// - the server stopped (the proxy answers 502);
// - the sync proxy dropping every connection for sync.e2e.test;
// - the server hung (paused: TCP connects, nothing answers); firewall-1 is restarted
//   then and comes back ready from its snapshot.
// With Postgres stopped: the sync API answers 503 within its 1-second timeouts, the
// portal shows its error page, the automation API answers 503 (needs F11), the server's
// /health/ready answers 503 and /health/live 200 and `probation-server health` exits 1
// (needs F9), and a policy edit made then is not half-written. Everything comes back
// without a restart of the server or a firewall: the new key works, the activity queued
// during the outage reaches /activity, the edit is absent. What firewall-1 queued before
// its restart during the outage reaches /activity too (NEW DEFECT ND-3: it is lost).
// `docker stop` of the server exits 0 well inside the grace period (needs F8).
// A key revoked while firewall-1 is stopped stops working there within one sync interval
// of its start (F4: the window is measured and printed).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ops } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-008",
  title: "Management server and Postgres outage during installs",
  suites: ["nightly", "release"],
  stack: "own",
};

export default async function outage(h) {
  const { expect } = h;
  const o = ops(h);
  const interval = h.syncInterval * 1000;
  const fw1 = h.firewalls.fw1;
  const fw2 = h.firewalls.fw2;

  // An organisation with an authenticator (org admin rights), three keys and a block.
  const user = await h.signUp({ kind: "org" });
  await h.enableTotp(user);
  const policy = await h.policyPath(user.portal);
  const orgId = policy.slice("/policy/org-".length);
  const known = await h.createKey(user.portal, "known");
  const fresh = await h.createKey(user.portal, "fresh");
  const doomed = await h.createKey(user.portal, "doomed");
  // Used only for allowed requests before the outage, so its one activity row is the
  // refusal queued during the outage.
  const queued = await h.createKey(user.portal, "queued");
  const restarted = await h.createKey(user.portal, "restarted");
  await h.editPolicy(user.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "2.0.0" });
  let page = await user.portal.submit(`/org/${orgId}`, `/org/${orgId}/automation`, { name: "ci", layer: `org-${orgId}` });
  const automation = page.body.match(/<code id="new-token">([^<]+)<\/code>/)?.[1];
  expect(automation, `automation token: ${page.status}`);

  const npmrc = (base, key) => `registry=${base}/npm/\n${base.replace("https:", "")}/npm/:_authToken=${key}\n`;
  const install = (base, key) => h.npm("install e2e-left@1.0.0 --no-audit --no-fund", { npmrc: npmrc(base, key) });
  const get = (url, key, timeout = 15_000) => h.request(url, { headers: { authorization: `Bearer ${key}` }, timeout });
  for (const base of [fw1, fw2]) {
    for (const key of [known.key, doomed.key, queued.key, restarted.key]) {
      const run = install(base, key);
      expect(run.status === 0, `warm-up install through ${base}: ${run.stderr}`);
    }
    await h.waitFor(`the block reaches ${base}`, async () => (await get(`${base}/npm/e2e-left/2.0.0`, known.key)).status === 403, { timeout: 3 * interval });
  }

  // Both firewalls write their snapshot after each sync the server answers: wait for one
  // after the keys were first used, so a restart during the outage finds them.
  const warmed = Date.now();
  await h.waitFor("both firewalls checked in after the warm-up", async () => {
    const rows = (await o.fleet(h.operator.portal)).firewalls.filter((f) => /^firewall-[12]$/.test(f.name));
    return rows.length === 2 && rows.every((f) => {
      const ago = Number(f.checkIn.match(/^(\d+) seconds ago$/)?.[1] ?? Infinity);
      return Date.now() - ago * 1000 > warmed + 1000;
    });
  }, { timeout: 3 * interval, every: 1000 });

  // The request loop: a known key through firewall-1, every 300 ms, for the whole run.
  const seen = [];
  let looping = true;
  const loop = (async () => {
    while (looping) {
      let status;
      try {
        status = (await get(`${fw1}/npm/e2e-left`, known.key, 10_000)).status;
      } catch {
        status = 0;
      }
      seen.push(status);
      await h.sleep(300);
    }
  })();

  /// What every outage must keep: known key installs, a new key 401, both ready.
  const duringOutage = async (what) => {
    for (const base of [fw1, fw2]) {
      const run = install(base, known.key);
      expect(run.status === 0, `${what}: a known key installs through ${base}: ${run.stderr}`);
      const started = Date.now();
      const refused = await get(`${base}/npm/e2e-left`, fresh.key);
      expect(refused.status === 401 && Date.now() - started < 5000, `${what}: an unseen key gets 401 at once through ${base}: ${refused.status} after ${Date.now() - started} ms`);
      expect((await h.request(`${base}/health/ready`)).status === 200, `${what}: ${base} stays ready`);
    }
    const npm = install(fw1, fresh.key);
    expect(npm.status !== 0 && /E401|401/.test(npm.stderr), `${what}: npm shows the 401: ${npm.stderr}`);
  };
  const loggedAt = (line) => {
    try {
      return Date.parse(JSON.parse(line.slice(line.indexOf("{"))).timestamp);
    } catch {
      return 0;
    }
  };
  const unreachableSince = (container, since) =>
    h.waitFor(`${container} finds the server unreachable`, () => o.logs(o.id(container)).split("\n").some((l) => l.includes("could not be reached") && loggedAt(l) > since),
      { timeout: 3 * interval, every: 1000 });

  try {
    // 1. The server stopped.
    let since = Date.now();
    h.stop("server");
    await unreachableSince("firewall-1", since);
    await duringOutage("server stopped");
    // A refusal while the server is down, queued on firewall-1.
    expect((await get(`${fw2}/npm/e2e-left/2.0.0`, queued.key)).status === 403, "the block holds during the outage");
    h.start("server");
    await h.waitFor("the portal is back", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 60_000 });

    // 2. The sync proxy drops every connection for sync.e2e.test.
    o.syncProxy(false);
    since = Date.now();
    await unreachableSince("firewall-2", since);
    await duringOutage("sync proxy dropping connections");
    o.syncProxy(true);

    // 3. The server hangs; firewall-1 restarts meanwhile and is ready from its snapshot.
    o.engine(["pause", o.id("server")]);
    since = Date.now();
    await unreachableSince("firewall-2", since);
    // A refusal queued on firewall-1 just before it restarts during the outage.
    expect((await get(`${fw1}/npm/e2e-left/2.0.0`, restarted.key)).status === 403, "the block holds while the server hangs");
    h.restart("firewall-1");
    const restartedAt = Date.now();
    await h.firewallReady("fw1", 30_000);
    h.log(`firewall-1 ready ${Date.now() - restartedAt} ms after its restart, with the server hung`);
    await duringOutage("server hung");
    o.engine(["unpause", o.id("server")]);

    // 4. Postgres stopped.
    const policyForm = (await user.portal.get(policy)).body;
    const operatorFleet = await o.fleet(h.operator.portal);
    const before = o.inspect(o.id("server"));
    h.postgresDown();
    const token2 = readFileSync(join(h.stack.work, "firewall-2.token"), "utf8").trim();
    let started = Date.now();
    const lookup = await h.request("https://sync.e2e.test/api/v1/sync/lookup", {
      method: "POST", headers: { authorization: `Bearer ${token2}` }, body: { key_hash: "0".repeat(64) },
    });
    const took = Date.now() - started;
    expect(lookup.status >= 500 && took < 3000, `the sync API answers 5xx within its timeouts: ${lookup.status} after ${took} ms`);
    for (const path of ["/keys", policy]) {
      const answer = await user.portal.get(path);
      expect(answer.status === 503 && answer.body.includes("The portal is unavailable"), `the portal's error page for ${path}: ${answer.status} ${answer.body.slice(0, 200)}`);
    }
    const edit = await user.portal.post(policy, { csrf: h.hidden(policyForm, "csrf"), revision: h.hidden(policyForm, "revision"), action: "add_block", ecosystem: "npm", name: "e2e-right", what: "package" });
    expect(edit.status === 503, `a policy edit during the outage: ${edit.status}`);
    const fleetDown = await h.operator.portal.post("/fleet/register", { csrf: operatorFleet.csrf, name: "during-outage", sources: "203.0.113.9/32" });
    expect(fleetDown.status === 503, `registering a firewall during the outage: ${fleetDown.status}`);
    await duringOutage("Postgres stopped");

    // needs F11: the automation API says 503, not 401, when the database is down.
    const api = await h.request(`https://portal.e2e.test/api/v1/blocklist/org-${orgId}`, { headers: { authorization: `Bearer ${automation}` } });
    const live = await h.request(`${h.portalUrl}/health/live`);
    const ready = await h.request(`${h.portalUrl}/health/ready`);
    const healthCommand = h.stack.exec("server", ["probation-server", "health"]);

    await h.postgresUp();

    // 5. Back without restarts.
    await h.waitFor("the portal reads the database again", async () => (await user.portal.get("/keys")).status === 200, { timeout: 30_000 });
    const after = o.inspect(o.id("server"));
    expect(after.Id === before.Id && after.State.StartedAt === before.State.StartedAt && after.RestartCount === before.RestartCount, "the server recovered without a restart");
    await h.waitFor("the unseen key works again", async () => (await get(`${fw1}/npm/e2e-left`, fresh.key)).status === 200, { timeout: 3 * interval });
    const run = install(fw2, fresh.key);
    expect(run.status === 0, `the new key installs after the outage: ${run.stderr}`);
    await h.waitFor("the refusal queued during the outage is on /activity", async () => (await h.activity(user.portal)).some((r) => r.key.includes("queued") && r.package.includes("e2e-left") && /Blocked/.test(r.result)), { timeout: 3 * interval });
    // NEW DEFECT ND-3: the activity queue lives in memory only, so what firewall-1 queued
    // while the server was unreachable is gone after its restart.
    const kept = await h.waitFor("the refusal queued before firewall-1's restart is on /activity", async () => (await h.activity(user.portal)).some((r) => r.key.includes("restarted") && /Blocked/.test(r.result)), { timeout: 2 * interval }).catch(() => false);
    o.needs("the new defect ND-3 (activity queued during an outage is lost on a firewall restart)", kept, "the refusal firewall-1 queued while the server hung never reached /activity after firewall-1 restarted");
    expect(!(await user.portal.get(policy)).body.includes("e2e-right"), "the edit made during the outage was not written");
    expect(!(await o.fleet(h.operator.portal)).firewalls.some((f) => f.name === "during-outage"), "the registration made during the outage was not written");
    await h.waitFor("both firewalls healthy on /fleet", async () => (await o.fleet(h.operator.portal)).firewalls.filter((f) => /^firewall-[12]$/.test(f.name)).every((f) => f.health === "Healthy"), { timeout: 4 * interval, every: 2000 });

    // The checks that need the server fixes, after recovery so a failure leaves the rest proven.
    o.needs("F11", api.status === 503, `the automation API on a database outage answers ${api.status}, not 503`);
    o.needs("F9", live.status === 200 && ready.status === 503, `with Postgres down: /health/live ${live.status}, /health/ready ${ready.status}`);
    o.needs("F9", healthCommand.status === 1, `probation-server health with Postgres down exits ${healthCommand.status}: ${healthCommand.stderr.trim()}`);
    const readyAgain = await h.request(`${h.portalUrl}/health/ready`);
    o.needs("F9", readyAgain.status === 200, `/health/ready after recovery: ${readyAgain.status}`);
    const healthy = h.stack.exec("server", ["probation-server", "health"]);
    o.needs("F9", healthy.status === 0, `probation-server health after recovery exits ${healthy.status}: ${healthy.stderr.trim()}`);

    // 6. needs F8: the server stops cleanly on SIGTERM, well inside the grace period.
    started = Date.now();
    o.engine(["stop", "-t", "30", o.id("server")]);
    const stopSeconds = (Date.now() - started) / 1000;
    const exit = o.state(o.id("server")).exitCode;
    h.start("server");
    await h.waitFor("the portal is back", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 60_000 });
    o.needs("F8", exit === 0 && stopSeconds < 10, `docker stop of the server took ${stopSeconds} s, exit code ${exit}`);

    // 7. F4: a key revoked while firewall-1 is stopped.
    const ids = (await user.portal.get("/keys")).body.match(/<td>doomed<\/td>[\s\S]*?action="\/keys\/(\d+)\/revoke"/);
    expect(ids, "the doomed key is listed");
    h.stop("firewall-1");
    const revoked = await user.portal.submit("/keys", `/keys/${ids[1]}/revoke`, {});
    expect(revoked.status === 303, `revoke: ${revoked.status}`);
    await h.waitFor("firewall-2 refuses the revoked key", async () => (await get(`${fw2}/npm/e2e-left`, doomed.key)).status === 401, { timeout: 3 * interval });
    h.start("firewall-1");
    await h.firewallReady("fw1", 60_000);
    const readyAt = Date.now();
    let served = 0;
    await h.waitFor("firewall-1 refuses the revoked key", async () => {
      const status = (await get(`${fw1}/npm/e2e-left`, doomed.key)).status;
      if (status === 200) served++;
      return status === 401;
    }, { timeout: 2 * interval, every: 200 });
    h.log(`F4: the key revoked while firewall-1 was stopped was served ${served} times, for ${Date.now() - readyAt} ms after it was ready`);
  } finally {
    looping = false;
    await loop;
    try {
      o.engine(["unpause", o.id("server")], { check: false });
      o.syncProxy(true);
    } catch {}
  }
  const refusals = seen.filter((s) => s === 401 || s === 403);
  h.log(`request loop: ${seen.length} requests, ${seen.filter((s) => s === 200).length} served, others ${JSON.stringify([...new Set(seen.filter((s) => s !== 200))])}`);
  expect(refusals.length === 0, `the known key was refused during the outages: ${JSON.stringify(seen)}`);
  o.settle();
}
