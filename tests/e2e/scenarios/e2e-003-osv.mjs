// E2E-003 OSV enforcement, log-only and outage (docs/plans/e2e-coverage/00-inventory.md
// §3; docs/operations.md §4 "OSV vulnerability checks"; portal-guide §3.8).
//
// The fake OSV flags an npm and a PyPI version `MAL-*` and another version with a
// GHSA advisory only; it refuses any query whose ecosystem is not spelled `npm` or
// `PyPI`, so a misspelt ecosystem shows as a MAL version that installs.
//
// 1. Enforce: a managed platform left empty means OSV Off (C125), so Acme's org admin
//    turns the check On. npm and pip refuse the MAL versions and install the GHSA one;
//    the version route answers 403 BLOCKED; Activity shows the blocks.
// 2. A version flagged after the listing (a lockfile made before the advisory, replayed
//    by CI after it): `npm ci` and pip's direct-URL install are refused at download.
// 3. Log only, in Chromium as Acme's org admin: a group's Log only is refused until the
//    organisation ticks "Allow turning OSV off", which it may pass down only once the
//    operator ticks it on the platform layer; a service key attached to the group
//    then installs the MAL versions while the admin's own key stays enforced, and
//    Activity shows "Would have blocked (log only)" from the artifact path, for npm and
//    PyPI.
// 4. Outage: OSV slow, then refusing connections. Installs keep working (fail open,
//    even a MAL version firewall-2 never saw), firewall-2 logs the failures, the fleet
//    page shows "cannot reach OSV", and it is Healthy again after OSV recovers.

import { browserAs, errorOf, fleetHealth } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-003",
  title: "OSV enforce, log-only and outage, npm and PyPI",
  suites: ["pr", "nightly", "release"],
};

const OLD = 400 * 86_400;
const VERSIONS = ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"];
const MAL = (n) => [`MAL-2026-${n}`];
const LOG_ONLY = "Would have blocked (log only)";

export default async function osv(h) {
  const { expect } = h;
  const name = h.unique("osv");
  const module = name.replaceAll("-", "_");
  const interval = h.syncInterval;
  for (const version of VERSIONS) {
    await h.fakes.publishNpm({ name, version, ageSeconds: OLD });
    await h.fakes.publishPypi({ name, version, ageSeconds: OLD, kinds: ["wheel"] });
  }
  for (const ecosystem of ["npm", "PyPI"]) {
    await h.fakes.osvFlag({ ecosystem, name, version: "1.0.0", ids: MAL(1) });
    await h.fakes.osvFlag({ ecosystem, name, version: "1.1.0", ids: ["GHSA-e2e0-0000-0001"] });
  }

  // A managed platform layer left empty means OSV Off (C125), so Acme's org admin turns
  // the check on for the organisation: a layer may always be stricter.
  const acme = await h.signUp({ kind: "org" });
  await h.enableTotp(acme);
  const a = await h.createKey(acme.portal, "acme-ci");
  const asKey = (key) => ({ headers: { authorization: `Bearer ${key}` } });
  await h.editPolicy(acme.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
  await h.waitFor("OSV On reaches fw1", async () => (await h.request(`${h.firewalls.fw1}/npm/${name}/1.0.0`, asKey(a.key))).status === 403, {
    timeout: 3 * interval * 1000,
  });
  // `then` runs after the client, in the same project.
  const npm = (args, keys, then) =>
    h.npm(`${args} --no-audit --no-fund --cache "$PWD/.npm-cache"${then ? ` && ${then}` : ""}`, { npmrc: keys.npmrc });
  const pip = (args, keys, then) => h.pip(`install --no-cache-dir --retries 0 ${args}${then ? ` && ${then}` : ""}`, { pipConf: keys.pipConf });
  const show = (run) => `exit ${run.status}\n${run.stdout}\n${run.stderr}`;

  // 1. Enforce.
  let run = npm(`install ${name}@1.0.0`, a);
  expect(run.status !== 0, `npm installed the MAL version: ${show(run)}`);
  expect(/ETARGET|No matching version|E403/.test(run.stderr), `npm says why: ${show(run)}`);
  run = pip(`${name}==1.0.0`, a);
  expect(run.status !== 0, `pip installed the MAL version: ${show(run)}`);
  expect(/No matching distribution/.test(run.stdout + run.stderr), `pip says why: ${show(run)}`);
  run = npm(`install ${name}@1.1.0`, a, `node -p "require('${name}/package.json').version"`);
  expect(run.status === 0 && run.stdout.trim().endsWith("1.1.0"), `npm installs the GHSA-only version: ${show(run)}`);
  run = pip(`${name}==1.1.0`, a, `python -c "import ${module}; print(${module}.VERSION)"`);
  expect(run.status === 0 && run.stdout.trim().endsWith("1.1.0"), `pip installs the GHSA-only version: ${show(run)}`);
  let answer = await h.request(`${h.firewalls.fw1}/npm/${name}/1.0.0`, asKey(a.key));
  expect(answer.status === 403 && errorOf(answer).error === "BLOCKED", `version route: ${answer.status} ${answer.body}`);

  const queries = await h.fakes.osvQueries();
  for (const [ecosystem, queried] of [["npm", name], ["PyPI", name]]) {
    expect(
      queries.some((q) => q.package?.ecosystem === ecosystem && q.package?.name.toLowerCase() === queried && q.version === "1.0.0"),
      `OSV was asked about ${ecosystem} ${queried} 1.0.0 with the ecosystem spelt "${ecosystem}"`,
    );
  }

  // 2. Flagged between listing and download. The lockfile and the PyPI file URL come
  // from listings made while 1.2.0 was clean.
  const project = `/work/${h.unique("lock")}`;
  run = h.client("client-npm", `npm install ${name}@1.2.0 --package-lock-only --no-audit --no-fund --cache "$PWD/.npm-cache"`, {
    dir: project,
    files: { "package.json": JSON.stringify({ name: "e2e-project", version: "1.0.0", private: true }), ".npmrc": a.npmrc },
  });
  expect(run.status === 0, `lockfile: ${show(run)}`);
  answer = await h.request(`${h.firewalls.fw1}/pypi/simple/${name}/`, {
    headers: { authorization: `Bearer ${a.key}`, accept: "application/vnd.pypi.simple.v1+json" },
  });
  expect(answer.status === 200, `simple page: ${answer.status} ${answer.body}`);
  const wheel = answer.json().files.find((f) => f.filename.includes("-1.2.0-"))?.url;
  expect(wheel?.startsWith(h.firewalls.fw1), `the 1.2.0 wheel's URL on fw1: ${answer.body}`);
  for (const ecosystem of ["npm", "PyPI"]) await h.fakes.osvFlag({ ecosystem, name, version: "1.2.0", ids: MAL(2) });
  // A "no match" is cached for 30 s (operations.md §4); the download after that asks again.
  await h.waitFor("the flagged wheel is refused at download", async () => (await h.request(wheel, asKey(a.key))).status === 403, {
    timeout: 60_000,
    every: 2000,
  });
  run = h.client("client-npm", `npm ci --no-audit --no-fund --cache "$PWD/.npm-cache"`, { dir: project });
  expect(run.status !== 0, `npm ci installed the version flagged after its lockfile: ${show(run)}`);
  expect(/403|E403|Forbidden/.test(run.stderr), `npm ci names the refusal: ${show(run)}`);
  run = pip(`"${wheel.replace("https://", `https://key:${a.key}@`)}"`, a);
  expect(run.status !== 0, `pip installed the wheel flagged after the listing: ${show(run)}`);
  expect(/403/.test(run.stdout + run.stderr), `pip names the refusal: ${show(run)}`);

  await h.waitFor("Acme's Activity shows the OSV blocks", async () => {
    const rows = await h.activity(acme.portal);
    const blocked = (ecosystem, version) =>
      rows.some((r) => r.ecosystem === ecosystem && r.package === `${name}@${version}` && r.result === "Blocked");
    return blocked("npm", "1.0.0") && blocked("npm", "1.2.0") && blocked("PyPI", "1.2.0");
  }, { timeout: 3 * interval * 1000, every: 2000 });

  // 3. Log only for one group of Acme, in Chromium as Acme's org admin. The group layer
  // inherits On from the organisation, so Log only needs the organisation's "Allow
  // turning OSV off". A service key attached to the group gets the group's policy.
  const acmePolicy = await h.policyPath(acme.portal);
  const context = await browserAs(h, acme);
  const page = await context.newPage();
  await page.goto("/org");
  await page.fill("#group-name", "Build agents");
  await page.click("form[action$='/groups'] button[type=submit]");
  await page.goto(acmePolicy);
  const groupPolicy = await page.getAttribute("nav[aria-label=Layers] a[href^='/policy/group-']", "href");
  expect(groupPolicy, "the policy page links the new group's layer");
  const save = async (path, change) => {
    await page.goto(path);
    await change();
    await page.click("form:has(input[name=action][value=save]) button[type=submit]");
    await page.waitForLoadState();
  };
  await save(groupPolicy, () => page.check("input[name=osv][value=log_only]"));
  const refusal = (await page.locator(".err").allTextContents()).join(" ");
  expect(/Not saved\..*Allow turning OSV off/.test(refusal), `Log only without the organisation's switch is refused: ${refusal}`);
  // The organisation can pass the switch down only if the platform gives it (the box is
  // greyed out until then): the operator ticks it on the platform layer, and puts it
  // back as it was at the end, since the platform is shared.
  await page.goto(acmePolicy);
  expect(await page.isDisabled("input[name=allow_osv_off]"), "Acme cannot pass down a switch the platform does not give");
  const operator = await (await browserAs(h, h.operator)).newPage();
  await operator.goto("/policy/platform-1");
  const platformAllowed = await operator.isChecked("input[name=allow_osv_off]");
  const setPlatformSwitch = async (on) => {
    await operator.goto("/policy/platform-1");
    await operator.setChecked("input[name=allow_osv_off]", on);
    await operator.click("form:has(input[name=action][value=save]) button[type=submit]");
    await operator.waitForLoadState();
    await operator.goto("/policy/platform-1");
    expect((await operator.isChecked("input[name=allow_osv_off]")) === on, `the platform's "Allow turning OSV off" is ${on}`);
  };
  if (!platformAllowed) await setPlatformSwitch(true);
  try {
    await save(acmePolicy, () => page.check("input[name=allow_osv_off]"));
    await save(groupPolicy, () => page.check("input[name=osv][value=log_only]"));
    await page.goto(groupPolicy);
    expect(await page.isChecked("input[name=osv][value=log_only]"), "the group's layer shows Log only");
    await page.goto("/keys");
    await page.fill("#service-name", "build-agent");
    await page.selectOption("#service-attach", { label: "Build agents group" });
    await page.click("form[action='/keys/service'] button[type=submit]");
    const pre = await page.locator("pre").allTextContents();
    const b = {
      key: await page.locator("#new-key").textContent(),
      npmrc: `${pre.find((text) => text.startsWith("registry="))}\n`,
      pipConf: `${pre.find((text) => text.startsWith("[global]"))}\n`,
    };
    expect(b.key, "the service key is shown once");

    await h.waitFor("Log only reaches fw1", async () => (await h.request(`${h.firewalls.fw1}/npm/${name}/1.0.0`, asKey(b.key))).status === 200, {
      timeout: 3 * interval * 1000,
    });
    run = npm(`install ${name}@1.0.0`, b, `node -p "require('${name}/package.json').version"`);
    expect(run.status === 0 && run.stdout.trim().endsWith("1.0.0"), `log only: npm installs the MAL version: ${show(run)}`);
    run = pip(`${name}==1.0.0`, b, `python -c "import ${module}; print(${module}.VERSION)"`);
    expect(run.status === 0 && run.stdout.trim().endsWith("1.0.0"), `log only: pip installs the MAL version: ${show(run)}`);
    answer = await h.request(`${h.firewalls.fw1}/npm/${name}/1.0.0`, asKey(a.key));
    expect(answer.status === 403, `the org admin's own key is still enforced: ${answer.status}`);

    await h.waitFor("Acme's Activity shows would-have-blocked rows for the service key", async () => {
      const rows = await h.activity(acme.portal);
      const seen = (ecosystem) =>
        rows.some((r) => r.ecosystem === ecosystem && r.package === `${name}@1.0.0` && r.result === LOG_ONLY && r.key.startsWith("build-agent"));
      return seen("npm") && seen("PyPI");
    }, { timeout: 3 * interval * 1000, every: 2000 });
  } finally {
    if (!platformAllowed) await setPlatformSwitch(false);
  }
  await context.close();

  // 4. Outage, on firewall-2, which has never asked OSV about this package.
  for (const ecosystem of ["npm", "PyPI"]) await h.fakes.osvFlag({ ecosystem, name, version: "1.3.0", ids: MAL(3) });
  await h.fakes.faults([{ host: "api.osv.dev", mode: "delay", ms: 5000 }]);
  let started = performance.now();
  answer = await h.request(`${h.firewalls.fw2}/npm/${name}/1.3.0`, asKey(a.key));
  const slow = performance.now() - started;
  expect(answer.status === 200, `OSV slow: the never-checked MAL version is served (fail open): ${answer.status} ${answer.body}`);
  expect(slow < 4000, `OSV slow: the answer did not wait for OSV (${slow.toFixed(0)} ms)`);
  run = npm(`install ${name}@1.3.0`, a);
  expect(run.status === 0, `OSV slow: npm install works: ${show(run)}`);

  await h.fakes.faults([{ host: "api.osv.dev", mode: "reset" }]);
  run = h.pip(`install --no-cache-dir --retries 0 ${name}==1.4.0`, { pipConf: a.pipConf.replaceAll("fw1.e2e.test", "fw2.e2e.test") });
  expect(run.status === 0, `OSV down: pip install through fw2 works: ${show(run)}`);
  // A period with one OSV answer reports it reachable, so new packages keep being asked
  // about (as CI does) until a period of failures alone has been reported.
  await h.waitFor("the fleet page shows firewall-2 cannot reach OSV", async () => {
    const another = h.unique("osv-down");
    await h.fakes.publishNpm({ name: another, version: "1.0.0", ageSeconds: OLD });
    const served = await h.request(`${h.firewalls.fw2}/npm/${another}`, asKey(a.key));
    expect(served.status === 200, `OSV down: a new package is served: ${served.status}`);
    return /cannot reach.*OSV/.test(await fleetHealth(h.operator.portal, "firewall-2"));
  }, {
    timeout: 3 * interval * 1000,
    every: 2000,
  });
  const logs = h.stack.logs("firewall-2");
  expect(/OSV lookup batch timed out/.test(logs), "firewall-2 logs the OSV timeout");
  expect(/OSV lookups could not be sent/.test(logs), "firewall-2 logs the refused OSV connection");

  await h.fakes.faults([]);
  const fresh = h.unique("osv-back");
  await h.fakes.publishNpm({ name: fresh, version: "1.0.0", ageSeconds: OLD });
  answer = await h.request(`${h.firewalls.fw2}/npm/${fresh}`, asKey(a.key));
  expect(answer.status === 200, `after recovery: ${answer.status}`);
  await h.waitFor("firewall-2 is Healthy again", async () => (await fleetHealth(h.operator.portal, "firewall-2")) === "Healthy", {
    timeout: 3 * interval * 1000,
    every: 2000,
  });
}
