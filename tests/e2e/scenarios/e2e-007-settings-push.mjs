// E2E-007: a settings push with exit 75 and a real supervisor (management-server.md §6,
// portal-guide.md §4.9, operations.md §13 "Settings pushes").
//
// 1. With npm installs running through firewall-1, the operator pushes
//    `max_active_requests = 64` to firewall-1 then firewall-2 on /fleet. firewall-1
//    writes the overlay, exits 75, and the container's restart policy
//    (`restart: unless-stopped`) starts it on the overlay; it reports the revision and
//    only then does firewall-2 get the push and do the same. The installs succeed;
//    activity queued before the restart reaches the portal.
// 2. A push that fails the firewall's checks (`max_active_requests = 0`): the step
//    fails with the firewall's reason on the page, the rollout halts, the firewall keeps
//    serving on its old settings and does not restart (no crash loop). "Resume" is not
//    offered, "Skip" is: skipping passes the push to firewall-2 (which refuses it too),
//    skipping again finishes the rollout. The audit log has the rollout.skip rows.
// 3. A firewall whose step is sent and that never checks in is retired: the rollout
//    goes on to the next firewall.
// 4. Once more under systemd: a host container runs the binary with the shipped
//    deploy/probation.service unchanged (Restart=on-failure, check-config before each
//    start, the sandboxing); the only addition is a drop-in naming the e2e CA. The push
//    makes the service exit 75 and systemd starts it again on the overlay.
//
// 5. A firewall run without a restart policy exits 75 and stays stopped (as documented):
//    its step must not count as applied, so the rollout halts after 3 check-ins and the
//    next firewall does not get the push. NEW DEFECT (found here): the firewall reports
//    the pushed revision in its last call before it exits, so the step shows "Applied"
//    and the next firewall gets the push while this one is down.
//
// Not covered: a push that passes the firewall's checks and still fails at start; no
// pushed value reaches that path (only staged, in tests/managed_sync.rs
// t_settings_rollback).

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { unescape } from "../harness/net.mjs";
import { ROOT } from "../harness/stack.mjs";
import { ops } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-007",
  title: "Settings push with exit 75 and a real supervisor",
  suites: ["nightly", "release"],
  stack: "own",
};

export default async function settingsPush(h) {
  const { expect } = h;
  const o = ops(h);
  const operator = h.operator.portal;
  const fw1 = o.id("firewall-1");
  const fw2 = o.id("firewall-2");
  const timeout = 6 * h.syncInterval * 1000;

  // A member with a key and a block, for installs and an activity row.
  const user = await h.signUp({ kind: "org" });
  const { key, npmrc } = await h.createKey(user.portal);
  // Used for one refused request only, just before the push: its row is that one.
  const queued = await h.createKey(user.portal, "queued");
  await h.editPolicy(user.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "2.0.0" });
  const blockedOn = async (fw) => (await h.request(`${fw}/npm/e2e-left/2.0.0`, { headers: { authorization: `Bearer ${key}` } })).status === 403;
  await h.waitFor("the block reaches firewall-2", () => blockedOn(h.firewalls.fw2), { timeout });

  const rollout = async (match) => (await o.fleet(operator)).rollouts.find((r) => r.settings.includes(match));
  const overlay = (service) => h.stack.exec(service, ["cat", "/var/lib/probation/managed-settings.toml"]).stdout;

  // 1. The push, with installs running through firewall-1.
  const started = new Date(Date.now() - 1000);
  const restarts = { fw1: o.state(fw1).restarts, fw2: o.state(fw2).restarts };
  const stopFile = `/work/${h.unique("stop")}`;
  const loop = o.background("client-npm", `n=0; fails=0
while [ ! -e ${stopFile} ] && [ $n -lt 40 ]; do
  rm -rf node_modules package-lock.json
  if npm install e2e-right@1.0.0 --no-audit --no-fund --prefer-online >out.txt 2>&1; then echo ok; else echo FAIL; cat out.txt; fi
  n=$((n+1))
done`, { files: { "package.json": JSON.stringify({ name: "loop", version: "1.0.0", private: true }), ".npmrc": npmrc } });
  await h.sleep(2000);
  // A refused request queued on firewall-1 just before the push.
  await h.waitFor("the block reaches firewall-1", () => blockedOn(h.firewalls.fw1), { timeout });
  const refused = await h.request(`${h.firewalls.fw1}/npm/e2e-left/2.0.0`, { headers: { authorization: `Bearer ${queued.key}` } });
  expect(refused.status === 403, `the refusal queued before the push: ${refused.status}`);

  let saved = await o.push(operator, ["firewall-1", "firewall-2"], "max_active_requests = 64\n");
  expect(saved.status === 303, `push: ${saved.status}\n${saved.body}`);
  await h.waitFor("firewall-1 applied the push", async () => (await rollout("max_active_requests = 64"))?.steps[0]?.startsWith("Applied by firewall-1"), { timeout, every: 1000 });
  await h.waitFor("the rollout is done", async () => (await rollout("max_active_requests = 64"))?.state === "Done", { timeout, every: 1000 });
  const done = await rollout("max_active_requests = 64");
  expect(done.steps[1].startsWith("Applied by firewall-2"), `firewall-2's step: ${done.steps}`);
  h.stack.exec("client-npm", ["touch", stopFile]);
  const installs = await loop;
  const lines = installs.stdout.split("\n").filter((l) => l === "ok" || l === "FAIL");
  expect(lines.length > 0 && !lines.includes("FAIL"), `installs through firewall-1 during the push: ${lines.length} runs\n${installs.stdout}`);

  // Each firewall exited 75 once and its supervisor started it again, firewall-2 only
  // after firewall-1 had reported the revision.
  const exits1 = o.exits(fw1, started);
  const exits2 = o.exits(fw2, started);
  expect(exits1.length === 1 && exits1[0].code === 75, `firewall-1 exits: ${JSON.stringify(exits1)}`);
  expect(exits2.length === 1 && exits2[0].code === 75, `firewall-2 exits: ${JSON.stringify(exits2)}`);
  expect(o.state(fw1).restarts === restarts.fw1 + 1 && o.state(fw2).restarts === restarts.fw2 + 1, "each was restarted by its supervisor once");
  expect(o.state(fw1).running && o.state(fw2).running, "both run again");
  expect(exits2[0].at > exits1[0].at, "firewall-2 restarted after firewall-1");
  for (const service of ["firewall-1", "firewall-2"]) {
    expect(/max_active_requests = 64/.test(overlay(service)), `${service}'s overlay: ${overlay(service)}`);
    const owner = h.stack.exec(service, ["stat", "-c", "%U", "/var/lib/probation/managed-settings.toml"]).stdout.trim();
    expect(owner === "firewall", `${service}'s overlay belongs to the image's user: ${owner}`);
  }
  expect(/settings pushed; restarting to apply them/.test(o.logs(fw1)), "firewall-1 logged the restart for the push");
  await h.firewallReady("fw1");
  await h.firewallReady("fw2");

  // The refused request queued before the restart reaches the portal.
  await h.waitFor("the blocked install is on /activity", async () => (await h.activity(user.portal)).some((r) => r.key.includes("queued") && r.package.includes("e2e-left") && /Blocked/.test(r.result)), { timeout });

  // 2. A push the firewall refuses: halted, its reason shown, no restart, Skip only.
  const before = { fw1: o.state(fw1).restarts, fw2: o.state(fw2).restarts };
  saved = await o.push(operator, ["firewall-1", "firewall-2"], "max_active_requests = 0\n");
  expect(saved.status === 303, `the bad push is saved (the server cannot check it): ${saved.status}\n${saved.body}`);
  await h.waitFor("the rollout halts on firewall-1", async () => (await rollout("max_active_requests = 0"))?.state === "Halted", { timeout, every: 1000 });
  let bad = await rollout("max_active_requests = 0");
  expect(/firewall-1 could not apply the new settings/.test(bad.steps[0]) && /max_active_requests/.test(bad.steps[0]), `the step shows the reason: ${bad.steps[0]}`);
  expect(/gets them after the one before/.test(bad.steps[1]), `firewall-2 waits: ${bad.steps[1]}`);
  expect(!bad.resume && bad.skip, `only Skip is offered for a refused push: resume ${bad.resume}, skip ${bad.skip}`);
  const row = (await o.fleet(operator)).firewalls.find((f) => f.name === "firewall-1");
  expect(/max_active_requests/.test(row.error ?? ""), `firewall-1's last error on /fleet: ${JSON.stringify(row)}`);
  await h.sleep(3 * h.syncInterval * 1000);
  expect(o.state(fw1).restarts === before.fw1 && o.state(fw1).running, "no restart, no crash loop on a refused push");
  expect(/max_active_requests = 64/.test(overlay("firewall-1")), "firewall-1 keeps its previous settings");
  const install = h.npm("install e2e-left@1.0.0 --no-audit --no-fund", { npmrc });
  expect(install.status === 0, `firewall-1 still serves: ${install.stderr}`);
  expect((await rollout("max_active_requests = 0")).state === "Halted", "the refused push is not retried");

  const badId = bad.id;
  let skipped = await operator.post(`/fleet/rollouts/${badId}/skip`, { csrf: (await o.fleet(operator)).csrf });
  expect(skipped.status === 303, `skip: ${skipped.status}\n${skipped.body}`);
  await h.waitFor("firewall-2 refuses it too", async () => /firewall-2 could not apply/.test((await rollout("max_active_requests = 0"))?.steps[1] ?? ""), { timeout, every: 1000 });
  bad = await rollout("max_active_requests = 0");
  expect(/^Skipped firewall-1/.test(bad.steps[0]) && bad.state === "Halted", `after one skip: ${bad.state} ${bad.steps}`);
  skipped = await operator.post(`/fleet/rollouts/${badId}/skip`, { csrf: (await o.fleet(operator)).csrf });
  expect(skipped.status === 303, `skip again: ${skipped.status}`);
  bad = await rollout("max_active_requests = 0");
  expect(bad.state === "Done" && !bad.skip && !bad.resume, `the rollout ends after both skips: ${bad.state} ${bad.steps}`);
  expect(o.state(fw2).restarts === before.fw2, "firewall-2 did not restart for the refused push either");
  // The audit log shows both skips (operator rows, subject rollout:<id>, the failed step before).
  const audit = (await operator.get("/audit")).body;
  const rows = [...audit.matchAll(/<tr>([\s\S]*?)<\/tr>/g)].map(([, r]) => unescape(r.replace(/<[^>]+>/g, " ").replaceAll("&#34;", '"')));
  const skips = rows.filter((r) => r.includes(`rollout:${badId}`) && r.includes('"step": "failed"'));
  expect(skips.length === 2, `the audit log has both rollout.skip rows:\n${rows.filter((r) => r.includes("rollout:")).join("\n")}`);

  // 3. Retiring a firewall whose step is sent releases the next one.
  const fleetPage = await o.fleet(operator);
  const registered = await operator.post("/fleet/register", { csrf: fleetPage.csrf, name: "firewall-phantom", sources: "203.0.113.77/32" });
  expect(registered.status === 200 && registered.body.includes('id="new-token"'), `register the phantom: ${registered.status}`);
  saved = await o.push(operator, ["firewall-phantom", "firewall-2"], "max_active_requests = 128\n");
  expect(saved.status === 303, `push to the phantom: ${saved.status}\n${saved.body}`);
  let third = await rollout("max_active_requests = 128");
  expect(/Waiting for firewall-phantom/.test(third.steps[0]) && /gets them after/.test(third.steps[1]), `the phantom's step is sent: ${third.steps}`);
  const phantom = (await o.fleet(operator)).firewalls.find((f) => f.name === "firewall-phantom");
  const retired = await operator.post(`/fleet/${phantom.id}/retire`, { csrf: (await o.fleet(operator)).csrf, confirm: "firewall-phantom" });
  expect(retired.status === 303, `retire: ${retired.status}\n${retired.body}`);
  await h.waitFor("firewall-2 gets and applies the push", async () => (await rollout("max_active_requests = 128"))?.state === "Done", { timeout, every: 1000 });
  third = await rollout("max_active_requests = 128");
  expect(third.steps.some((s) => s.startsWith("Applied by firewall-2")), `firewall-2 applied it: ${third.steps}`);
  expect(/max_active_requests = 128/.test(overlay("firewall-2")), "firewall-2's overlay");
  await h.firewallReady("fw2");
  expect((await o.fleet(operator)).firewalls.find((f) => f.name === "firewall-phantom").health === "Retired", "the phantom shows Retired");

  // 4. The same under systemd, with the shipped unit.
  const host = await systemdFirewall(h, o, operator);
  try {
    const restartsBefore = Number(host.exec("systemctl", "show", "-p", "NRestarts", "--value", "probation").stdout.trim());
    saved = await o.push(operator, ["firewall-systemd"], "max_active_requests = 32\n");
    expect(saved.status === 303, `push to the systemd host: ${saved.status}\n${saved.body}`);
    await h.waitFor("the systemd firewall applies the push", async () => (await rollout("max_active_requests = 32"))?.state === "Done", { timeout, every: 1000 });
    const restarts = () => Number(host.exec("systemctl", "show", "-p", "NRestarts", "--value", "probation").stdout.trim());
    await h.waitFor("systemd restarts the service", () => restarts() === restartsBefore + 1 && host.exec("systemctl", "is-active", "probation").stdout.trim() === "active", { timeout: 30_000 });
    const journal = host.exec("journalctl", "-u", "probation", "--no-pager").stdout;
    expect(/status=75/.test(journal) && /Scheduled restart job/.test(journal), `systemd saw exit 75 and restarted it:\n${journal.slice(-3000)}`);
    await h.sleep(3 * h.syncInterval * 1000);
    expect(restarts() === restartsBefore + 1, "one restart only, no loop");
    expect(/max_active_requests = 32/.test(host.exec("cat", "/var/lib/probation/managed-settings.toml").stdout), "the overlay under StateDirectory");
    await h.waitFor("the systemd firewall is ready again", async () => (await o.inside("http://firewall-systemd:8080/health/ready")) === 200, { timeout: 30_000 });
  } finally {
    host.rm();
  }

  // 5. No restart policy: the step must not count as applied while the firewall is down.
  const nr = (await operator.post("/fleet/register", { csrf: (await o.fleet(operator)).csrf, name: "firewall-norestart", sources: "0.0.0.0/0" })).body.match(/<code id="new-token">([^<]+)<\/code>/)?.[1];
  expect(nr, "register firewall-norestart");
  const lone = o.firewall({ name: "firewall-norestart", config: o.managedConfig("fw-norestart.e2e.test"), token: nr, restart: "no" });
  try {
    await h.waitFor("firewall-norestart is ready", async () => (await lone.ready()) === 200, { timeout });
    saved = await o.push(operator, ["firewall-norestart", "firewall-2"], "max_active_requests = 48\n");
    expect(saved.status === 303, `push: ${saved.status}`);
    await h.waitFor("firewall-norestart exits 75 and stays stopped", () => !lone.state().running, { timeout });
    expect(lone.state().exitCode === 75, `exit code ${lone.state().exitCode}`);
    let last;
    await h.waitFor("the rollout halts: no success reported within 3 check-ins", async () => {
      last = await rollout("max_active_requests = 48");
      return last.state === "Halted" || /max_active_requests = 48/.test(overlay("firewall-2"));
    }, { timeout: 6 * h.syncInterval * 1000, every: 2000 });
    const defect = "the new defect ND-1 (a push counts as applied before the restart)";
    o.needs(defect, !last.steps[0].startsWith("Applied"), `a firewall that exited for the push and never came back counts as applied: ${last.state}: ${last.steps.join(" | ")}`);
    o.needs(defect, !/max_active_requests = 48/.test(overlay("firewall-2")), "firewall-2 got the push while the firewall before it was down");
    o.needs(defect, last.state === "Halted" && /did not report success within 3 check-ins/.test(last.steps[0]) && last.resume, `the rollout halts with Resume: ${last.state}: ${last.steps.join(" | ")}`);
  } finally {
    o.removeExtras();
  }
  o.settle();
}

/// Registers firewall-systemd on /fleet and starts a systemd host container running the
/// shipped unit with that token; answers {exec, rm} once the service is ready.
async function systemdFirewall(h, o, operator) {
  const tag = `localhost/probation-e2e-systemd:${h.stack.project}`;
  const built = o.engine(["build", "-q", "-f", join(ROOT, "tests/e2e/compose/systemd/Containerfile"),
    "--build-arg", `FIREWALL_IMAGE=${o.image}`, "-t", tag, ROOT], { check: false });
  h.expect(built.status === 0, `the systemd host image: ${built.stderr}`);
  const registered = await operator.post("/fleet/register", { csrf: (await o.fleet(operator)).csrf, name: "firewall-systemd", sources: "0.0.0.0/0" });
  const token = registered.body.match(/<code id="new-token">([^<]+)<\/code>/)?.[1];
  h.expect(token, `register firewall-systemd: ${registered.status}`);
  const dir = join(h.stack.work, "e2e-007-systemd");
  mkdirSync(join(dir, "etc"), { recursive: true });
  mkdirSync(join(dir, "dropin"), { recursive: true });
  writeFileSync(join(dir, "etc", "config.toml"), o.managedConfig("fw-systemd.e2e.test").replace('token_file = "/e2e/firewall.token"', 'token_file = "/etc/probation/firewall.token"'));
  writeFileSync(join(dir, "etc", "firewall.token"), `${token}\n`, { mode: 0o644 });
  // The operator's own CA for the sync proxy and the registries, as a drop-in.
  writeFileSync(join(dir, "dropin", "e2e-ca.conf"), "[Service]\nEnvironment=SSL_CERT_FILE=/e2e/ca/ca.pem\n");
  const container = `${h.stack.project}-x-firewall-systemd`;
  o.engine(["rm", "-f", container], { check: false });
  // systemd as PID 1: podman sets it up itself; docker needs the cgroup tree.
  const systemd = h.stack.engine === "podman" ? ["--systemd=always"]
    : ["--privileged", "--cgroupns=host", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "--tmpfs", "/run", "--tmpfs", "/run/lock"];
  o.engine(["run", "-d", ...systemd, "--name", container, "--label", `e2e.extra=${h.stack.project}`,
    "--network", o.network, "--network-alias", "firewall-systemd",
    "-v", `${join(h.stack.work, "ca")}:/e2e/ca:ro`, "-v", `${join(dir, "etc")}:/etc/probation:ro`,
    "-v", `${join(dir, "dropin")}:/etc/systemd/system/probation.service.d:ro`, tag]);
  const host = {
    exec: (...argv) => o.engine(["exec", container, ...argv], { check: false }),
    rm: () => o.engine(["rm", "-f", "-t", "5", container], { check: false }),
  };
  await h.waitFor("the systemd firewall is ready", async () => (await o.inside("http://firewall-systemd:8080/health/ready")) === 200, { timeout: 6 * h.syncInterval * 1000 });
  return host;
}
