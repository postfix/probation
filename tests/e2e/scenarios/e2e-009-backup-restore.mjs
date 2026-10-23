// E2E-009: the backup and restore drill of operations.md §5 "Backing up and restoring
// the management server", with the real pg_dump and pg_restore of Postgres 16.
//
// A dump of the running database; then, after it: a key revoked, firewall-3 registered
// and started, firewall-2 retired, a block added, settings pushed. The restore follows
// the documented steps: stop the server, restore the database, `admin after-restore`,
// `admin revoke-key` for the revocation the restore lost (no server running), start the
// server. Then:
// - firewall-1 resets its cache once (its cursor jumps to the raised counter) and the
//   revoked key gets 401; a live key never gets 401 while the caches refill (503
//   LOOKUP_BUSY is allowed);
// - firewall-3, registered after the backup, gets 401 at its syncs and serves nothing;
//   registered again with a new token it serves (operations.md step 5, F16);
// - firewall-2, retired after the backup, is live again on /fleet; retired again;
// - the block and the settings push are re-applied on the portal: a new push completes;
// - the app role still cannot UPDATE or DELETE audit_log, prune_audit() works, the
//   sequences go on (new key, new firewall);
// - TOTP sign-in works with the same PROBATION_SERVER_SECRET_KEY; with another one it
//   fails, and the operator can tell why from the server's log (NEW DEFECT: the server
//   logs nothing and the page says the code is wrong).
// A second restore without `after-restore` shows the documented failure: a revocation
// made afterwards is skipped by the firewall that already saw higher revisions, until
// `after-restore` is run.

import { ops } from "../harness/ops.mjs";
import { signInWithCode } from "../harness/stack.mjs";

export const meta = {
  id: "E2E-009",
  title: "Backup and restore drill",
  suites: ["nightly", "release"],
  stack: "own",
};

const DUMP = "/var/lib/postgresql/e2e-009.dump";

export default async function restoreDrill(h) {
  const { expect } = h;
  const o = ops(h);
  const interval = h.syncInterval * 1000;
  const operator = h.operator;
  const fw1 = h.firewalls.fw1;
  const status = async (base, path, key) => (await h.request(base + path, { headers: { authorization: `Bearer ${key}` }, timeout: 15_000 })).status;
  const cursor = () => JSON.parse(h.stack.exec("firewall-1", ["cat", "/var/lib/probation/managed-cache.json"]).stdout).cursor;
  const pg = (...argv) => h.stack.exec("postgres", argv, { check: true });

  // An organisation with three keys, warm on firewall-1.
  const user = await h.signUp({ kind: "org" });
  await h.enableTotp(user);
  const policy = await h.policyPath(user.portal);
  const revoked = await h.createKey(user.portal, "revoked-after-backup");
  const live = await h.createKey(user.portal, "live");
  const later = await h.createKey(user.portal, "later");
  const keyId = async (name) => (await user.portal.get("/keys")).body.match(new RegExp(`<td>${name}</td>[\\s\\S]*?action="/keys/(\\d+)/revoke"`))?.[1];
  const revokedId = await keyId("revoked-after-backup");
  for (const key of [revoked.key, live.key, later.key]) expect((await status(fw1, "/npm/e2e-left", key)) === 200, "warm-up");

  try {
    // 1. The backup.
    pg("pg_dump", "-U", "probation", "-d", "probation", "-Fc", "-f", DUMP);
    const auditRows = h.stack.sql("SELECT count(*) FROM audit_log");

    // 2. Changes after the backup.
    let answer = await user.portal.submit("/keys", `/keys/${revokedId}/revoke`, {});
    expect(answer.status === 303, `revoke: ${answer.status}`);
    await h.waitFor("firewall-1 refuses the revoked key", async () => (await status(fw1, "/npm/e2e-left", revoked.key)) === 401, { timeout: 3 * interval });

    let fleet = await o.fleet(operator.portal);
    answer = await operator.portal.post("/fleet/register", { csrf: fleet.csrf, name: "firewall-3", sources: "0.0.0.0/0" });
    const token3 = answer.body.match(/<code id="new-token">([^<]+)<\/code>/)?.[1];
    expect(token3, `register firewall-3: ${answer.status}`);
    const fw3 = o.firewall({ name: "firewall-3", config: o.managedConfig("fw3.e2e.test"), token: token3 });
    await h.waitFor("firewall-3 is ready", async () => (await fw3.ready()) === 200, { timeout: 4 * interval });

    fleet = await o.fleet(operator.portal);
    const fw2Id = fleet.firewalls.find((f) => f.name === "firewall-2").id;
    answer = await operator.portal.post(`/fleet/${fw2Id}/retire`, { csrf: fleet.csrf, confirm: "firewall-2" });
    expect(answer.status === 303, `retire firewall-2: ${answer.status}`);
    await h.waitFor("firewall-2 stops serving", async () => (await status(h.firewalls.fw2, "/npm/e2e-left", live.key)) === 401, { timeout: 3 * interval });

    await h.editPolicy(user.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "1.0.0" });
    await h.waitFor("the block reaches firewall-1", async () => (await status(fw1, "/npm/e2e-left/1.0.0", live.key)) === 403, { timeout: 3 * interval });

    answer = await o.push(operator.portal, ["firewall-1"], "max_active_requests = 512\n");
    expect(answer.status === 303, `push: ${answer.status}`);
    await h.waitFor("the push is done", async () => (await o.fleet(operator.portal)).rollouts[0]?.state === "Done", { timeout: 6 * interval, every: 1000 });
    await h.firewallReady("fw1");
    const cursorBefore = cursor();

    // 3. The restore, step by step.
    h.stop("server");
    pg("dropdb", "-U", "probation", "probation");
    pg("createdb", "-U", "probation", "-O", "probation", "probation");
    pg("pg_restore", "-U", "probation", "-d", "probation", "--exit-on-error", DUMP);
    expect(h.stack.sql("SELECT count(*) FROM audit_log") === auditRows, "the restored audit log is the backup's");
    let run = o.server(["admin", "after-restore"]);
    expect(run.status === 0 && /^change_counter raised from value \d+ \(pruned_through \d+\) to (\d+); every firewall resets at its next sync$/m.test(run.stdout),
      `admin after-restore: ${run.status}\n${run.stdout}\n${run.stderr}`);
    const raised = Number(run.stdout.match(/ to (\d+);/)[1]);
    run = o.server(["admin", "revoke-key", "--key-id", revokedId]);
    expect(run.status === 0 && run.stdout.trim() === `revoked key ${revokedId}`, `admin revoke-key with the server stopped: ${run.status}\n${run.stdout}\n${run.stderr}`);
    run = o.server(["admin", "revoke-key", "--key-id", revokedId]);
    expect(run.status === 1 && run.stderr.includes(`no live API key ${revokedId}`), `revoking it twice: ${run.status} ${run.stderr}`);

    // A live key during the refill: never 401.
    const seen = [];
    let looping = true;
    const loop = (async () => {
      while (looping) {
        try {
          seen.push(await status(fw1, "/npm/e2e-left", live.key));
        } catch {
          seen.push(0);
        }
        await h.sleep(200);
      }
    })();
    h.start("server");
    await h.waitFor("the portal", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 60_000 });

    // 4. firewall-1 reset once; the revocation the restore lost holds.
    await h.waitFor("firewall-1 resets to the raised counter", () => cursor() >= raised, { timeout: 3 * interval });
    expect(cursorBefore < raised, `the counter was raised past firewall-1's cursor: ${cursorBefore} -> ${raised}`);
    await h.waitFor("the revoked key gets 401", async () => (await status(fw1, "/npm/e2e-left", revoked.key)) === 401, { timeout: 3 * interval });
    const resetCursor = cursor();
    await h.sleep(2 * interval);
    expect(cursor() >= resetCursor, "one reset only: the cursor only moves up");
    looping = false;
    await loop;
    expect(!seen.includes(401) && seen.includes(200), `a live key during the refill: ${JSON.stringify([...new Set(seen)])}`);

    // 5. firewall-3 (registered after the backup) is refused; firewall-2 is live again.
    await h.waitFor("firewall-3 stops serving", async () => (await fw3.ready()) === 503, { timeout: 3 * interval });
    expect((await o.inside("http://firewall-3:8080/npm/e2e-left", { headers: { authorization: `Bearer ${live.key}` } })) === 401, "firewall-3 refuses every key");
    fleet = await o.fleet(operator.portal);
    expect(!fleet.firewalls.some((f) => f.name === "firewall-3"), "firewall-3 is not in the restored fleet");
    const restored2 = fleet.firewalls.find((f) => f.name === "firewall-2");
    expect(restored2 && !restored2.retired, `firewall-2 is live again in the restored database: ${JSON.stringify(restored2)}`);

    // Re-applied as step 5 says: retire firewall-2 again, register firewall-3 again.
    answer = await operator.portal.post(`/fleet/${restored2.id}/retire`, { csrf: fleet.csrf, confirm: "firewall-2" });
    expect(answer.status === 303, `retire firewall-2 again: ${answer.status}`);
    answer = await operator.portal.post("/fleet/register", { csrf: (await o.fleet(operator.portal)).csrf, name: "firewall-3", sources: "0.0.0.0/0" });
    const token3b = answer.body.match(/<code id="new-token">([^<]+)<\/code>/)?.[1];
    expect(token3b, `register firewall-3 again: ${answer.status}`);
    fw3.writeToken(token3b);
    fw3.stop(10);
    fw3.start();
    await h.waitFor("firewall-3 serves with its new token", async () => (await fw3.ready()) === 200, { timeout: 4 * interval });
    expect((await o.inside("http://firewall-3:8080/npm/e2e-left", { headers: { authorization: `Bearer ${live.key}` } })) === 200, "firewall-3 serves a live key");
    const ids = (await o.fleet(operator.portal)).firewalls.map((f) => f.id);
    expect(Math.max(...ids) > fw2Id, `the firewall id sequence goes on: ${ids}`);

    // The block and the push, re-applied.
    expect((await status(fw1, "/npm/e2e-left/1.0.0", live.key)) === 200, "the restored policy has no block");
    await h.editPolicy(user.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "1.0.0" }, policy);
    await h.waitFor("the re-applied block reaches firewall-1", async () => (await status(fw1, "/npm/e2e-left/1.0.0", live.key)) === 403, { timeout: 3 * interval });
    answer = await o.push(operator.portal, ["firewall-1"], "max_active_requests = 512\n");
    expect(answer.status === 303, `push again: ${answer.status}`);
    const rollout = (await o.fleet(operator.portal)).rollouts[0];
    expect(rollout.state !== "Done", `a firewall reporting the lost push does not complete the new one at once: ${rollout.state} ${rollout.steps}`);
    await h.waitFor("the re-applied push is done", async () => (await o.fleet(operator.portal)).rollouts[0]?.state === "Done", { timeout: 6 * interval, every: 1000 });
    await h.firewallReady("fw1");

    // 6. Permissions and sequences after pg_restore.
    for (const statement of ["UPDATE audit_log SET subject = subject", "DELETE FROM audit_log", "TRUNCATE audit_log"]) {
      const denied = o.sqlAs("probation_e2e", statement);
      expect(denied.status !== 0 && /permission denied/.test(denied.stderr), `the app role: ${statement}: ${denied.status} ${denied.stderr}`);
    }
    const pruned = o.sqlAs("probation_e2e", "SELECT prune_audit()");
    expect(pruned.status === 0 && /^\d+$/.test(pruned.stdout.trim()), `prune_audit() as the app role: ${pruned.stderr}`);
    const newKey = await h.createKey(user.portal, "after-restore");
    expect((await status(fw1, "/npm/e2e-left", newKey.key)) === 200, "a key made after the restore works");
    expect(Number(await keyId("after-restore")) > Number(await keyId("later")), "the key id sequence goes on");

    // 7. TOTP with the same SECRET_KEY, then with another one.
    await signInWithCode(operator);
    expect((await operator.portal.get("/admin")).status === 200, "the operator signs in with the authenticator after the restore");
    const secretKey = h.stack.secretKey;
    try {
      h.stack.secretKey = "ab".repeat(32);
      h.stack.compose(["up", "-d", "--no-deps", "--force-recreate", "server"]);
      await h.waitFor("the portal", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 60_000 });
      const wrong = { ...operator, portal: new h.Portal() };
      let page = await wrong.portal.submit("/signin", "/signin", { email: operator.email, password: operator.password });
      expect(page.location === "/totp", `password step with another key: ${page.status} ${page.location}`);
      page = await wrong.portal.submit("/totp", "/totp", { code: await operator.auth.code() });
      expect(page.status !== 303, `with another SECRET_KEY the authenticator cannot be checked: ${page.status}`);
      // The recreated container's log is this start's only.
      const logged = o.logs(o.id("server")).replace(/\x1b\[[0-9;]*m/g, "").split("\n");
      o.needs("the new defect ND-2 (a wrong SECRET_KEY is silent)", logged.some((l) => /secret.?key|SECRET_KEY|cannot be (opened|read|decrypted)|unseal/i.test(l)),
        `with another PROBATION_SERVER_SECRET_KEY the page says only "${page.body.match(/class="err"[^>]*>([^<]+)/)?.[1]}" and the server log does not say why:\n${logged.join("\n").slice(-2000)}`);
    } finally {
      h.stack.secretKey = secretKey;
      h.stack.compose(["up", "-d", "--no-deps", "--force-recreate", "server"]);
      await h.waitFor("the portal", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 60_000 });
    }
  } finally {
    o.removeExtras();
  }

  // 8. The documented failure: a restore without `after-restore`. A second backup, then
  // a few changes firewall-1 applies (its cursor N); its syncs then fail (the sync proxy
  // drops them) while the backup is restored (counter M < N) and the server started
  // without after-restore. A key is revoked first (revision M+1 <= N), then changes until
  // the counter passes N. When its syncs get through again, firewall-1 asks for what came
  // after N, and the revocation is skipped.
  const counter = () => Number(h.stack.sql("SELECT value FROM change_counter WHERE id = 1"));
  await signInWithCode(user);
  await signInWithCode(operator);
  expect((await status(fw1, "/npm/e2e-left", later.key)) === 200, "the key to revoke is in firewall-1's cache");
  pg("pg_dump", "-U", "probation", "-d", "probation", "-Fc", "-f", DUMP);
  // Changes in another organisation's layer, so the revoked key's own policy stays
  // current in firewall-1's cache (an edit of its chain would make it look the key up).
  const elsewhere = `/policy/org-${h.bootstrap.org}`;
  for (const version of ["1.1.0", "1.2.0", "1.3.0"]) {
    await h.editPolicy(operator.portal, { action: "add_block", ecosystem: "npm", name: "e2e-many", what: "version", version }, elsewhere);
  }
  await h.waitFor("firewall-1 applied the changes", async () => (await status(fw1, "/npm/e2e-many/1.3.0", h.bootstrap.key)) === 403, { timeout: 3 * interval });
  await h.waitFor("firewall-1 saved its cursor", () => cursor() === counter(), { timeout: 3 * interval });
  const applied = cursor();
  o.syncProxy(false);
  h.stop("server");
  pg("dropdb", "-U", "probation", "probation");
  pg("createdb", "-U", "probation", "-O", "probation", "probation");
  pg("pg_restore", "-U", "probation", "-d", "probation", "--exit-on-error", DUMP);
  expect(counter() < applied, `the restored counter is behind firewall-1: ${counter()} < ${applied}`);
  h.start("server");
  await h.waitFor("the portal", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 60_000 });
  const laterId = await keyId("later");
  const answer = await user.portal.submit("/keys", `/keys/${laterId}/revoke`, {});
  expect(answer.status === 303, `revoke without after-restore: ${answer.status}`);
  for (let minor = 10; counter() <= applied; minor++) {
    await h.editPolicy(operator.portal, { action: "add_block", ecosystem: "npm", name: "e2e-many", what: "version", version: `1.${minor}.0` }, elsewhere);
  }
  o.syncProxy(true);
  await h.waitFor("firewall-1 synced past the restored counter", () => cursor() > applied, { timeout: 3 * interval });
  const skipped = await status(fw1, "/npm/e2e-left", later.key);
  h.log(`without after-restore, the key revoked on the portal answers ${skipped} on firewall-1 (documented: the revocation is skipped)`);
  expect(skipped === 200, `the documented failure without after-restore: the revocation is skipped (got ${skipped})`);
  h.stop("server");
  const run = o.server(["admin", "after-restore"]);
  expect(run.status === 0, `after-restore: ${run.stderr}`);
  h.start("server");
  await h.waitFor("after-restore brings the revocation to firewall-1", async () => (await status(fw1, "/npm/e2e-left", later.key)) === 401, { timeout: 3 * interval });
  o.settle();
}
