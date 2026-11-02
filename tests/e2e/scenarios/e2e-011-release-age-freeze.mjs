// E2E-011 Release-age freeze holds and releases.
//
// The fake registries publish a version one hour old (times are relative to now, so no
// clock control). The operator sets a 7-day platform freeze with "Allow a shorter
// freeze" off. On both firewalls the new version is held: `npm install pkg` and
// `pip install pkg` get the previous version, the exact pins fail, and the lockfile
// paths (`npm ci`, a `--require-hashes` file with the artifact URL) get 403 HELD with
// `eligible_at` (publication + 7 days) and `Retry-After`. Activity shows "Held until".
// The org's attempt to set 0 hours is refused and names the switch and the platform; an
// out-of-range freeze is refused. The operator turns the switch on, the org sets 0 hours,
// and within the sync interval the exact installs work, from the lockfiles too. A
// personal account on the same firewalls stays held under the platform's freeze.

import { activityRow, basic, changePlatform, fetchWith, onFirewall, savePolicy, untilStatus } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-011",
  title: "Release-age freeze holds and releases",
  suites: ["pr", "nightly", "release"],
};

const DAY = 86_400;
const HOUR = 3_600;

export default async function releaseAgeFreeze(h) {
  const { expect } = h;
  const firewalls = [h.firewalls.fw1, h.firewalls.fw2];
  const npmName = h.unique("e2e-fresh");
  const pyName = h.unique("py-fresh");
  await h.fakes.publishNpm({ name: npmName, version: "1.0.0", ageSeconds: 300 * DAY });
  const fresh = await h.fakes.publishNpm({ name: npmName, version: "1.1.0", ageSeconds: HOUR });
  const publishedAt = Date.now() - HOUR * 1000;
  await h.fakes.publishPypi({ name: pyName, version: "1.0.0", ageSeconds: 300 * DAY, kinds: ["wheel"] });
  await h.fakes.publishPypi({ name: pyName, version: "1.1.0", ageSeconds: HOUR, kinds: ["wheel"] });
  expect(fresh.tarball.includes(npmName), "the fake published the new version");

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key, npmrc, pipConf } = await h.createKey(admin.portal, "build");
  const policy = await h.policyPath(admin.portal);
  const solo = await h.signUp({ kind: "personal" });
  const soloKey = (await h.createKey(solo.portal, "solo")).key;

  const ok = (what, run) => expect(run.status === 0, `${what} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  const version = (run) => run.stdout.trim().split("\n").at(-1);
  const npmInstall = (spec, rc = npmrc) => h.npm(`install ${spec} --no-audit && node -p "require('${npmName}/package.json').version"`, { npmrc: rc });

  // Before any freeze the new version is served; a CI lockfile pins it, and a
  // hash-pinned requirements file names the firewall's artifact URL of its wheel.
  await untilStatus(h, firewalls, `/npm/${npmName}/1.1.0`, key, 200, "no freeze yet");
  const locked = h.npm(`install ${npmName}@1.1.0 --package-lock-only --no-audit && cat package-lock.json`, { npmrc });
  ok("lockfile", locked);
  const packageLock = locked.stdout.slice(locked.stdout.indexOf("{"));
  const lockedProject = { name: "e2e-project", version: "1.0.0", private: true, dependencies: { [npmName]: "1.1.0" } };
  const simple = await fetchWith(h, firewalls[0], `/pypi/simple/${pyName}/`, null, { authorization: basic(key) });
  const link = simple.body.match(/href="([^"]+-1\.1\.0-py3-none-any\.whl)#sha256=([0-9a-f]{64})"/);
  expect(link, `the 1.1.0 wheel on the firewall's page:\n${simple.body}`);
  const wheelUrl = new URL(link[1], firewalls[0]);
  const hashes = { "req.txt": `${pyName} @ ${wheelUrl} --hash=sha256:${link[2]}\n` };

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    // 1. Held on both firewalls, as every route shows it.
    await untilStatus(h, firewalls, `/npm/${npmName}/1.1.0`, key, 403, "the platform freeze reaches the fleet");
    for (const firewall of firewalls) {
      const held = await fetchWith(h, firewall, `/npm/${npmName}/1.1.0`, key);
      const body = held.json();
      expect(body.error === "HELD" && body.eligible_at, `${firewall}: 403 HELD with eligible_at: ${held.body}`);
      const eligible = Date.parse(body.eligible_at);
      expect(Math.abs(eligible - (publishedAt + 7 * DAY * 1000)) < 120_000, `eligible_at is publication + 7 days: ${body.eligible_at}`);
      const retryAfter = Number(held.headers["retry-after"]);
      const expected = (eligible - Date.now()) / 1000;
      expect(Number.isInteger(retryAfter) && Math.abs(retryAfter - expected) < 120, `Retry-After ${held.headers["retry-after"]} is the wait until eligible_at (${expected.toFixed(0)} s)`);
    }
    const artifact = await fetchWith(h, firewalls[0], wheelUrl.pathname, null, { authorization: basic(key) });
    expect(artifact.status === 403 && artifact.json().error === "HELD" && artifact.json().eligible_at && artifact.headers["retry-after"], `the PyPI artifact is held: ${artifact.status} ${artifact.body}`);
    expect((await fetchWith(h, firewalls[0], `/npm/${npmName}/1.1.0`, soloKey)).status === 403, "a personal account is held by the platform's freeze too");

    for (const rc of [npmrc, onFirewall(npmrc, "fw2.e2e.test")]) {
      const run = npmInstall(npmName, rc);
      ok("npm install during the freeze", run);
      expect(version(run) === "1.0.0", `npm gets the previous version: ${run.stdout}`);
    }
    let run = npmInstall(`${npmName}@1.1.0`);
    expect(run.status !== 0 && /ETARGET|No matching version/.test(run.stderr), `npm install of the held version fails: ${run.status}\n${run.stderr}`);
    run = h.npm("ci --no-audit", { npmrc, packageJson: lockedProject, files: { "package-lock.json": packageLock } });
    expect(run.status !== 0 && /E403|403 Forbidden/.test(run.stderr) && /HELD/.test(run.stderr), `npm ci of the held pin shows 403 HELD: ${run.status}\n${run.stderr}`);
    run = h.pip(`install --no-cache-dir --target t ${pyName}`, { pipConf });
    ok("pip install during the freeze", run);
    expect(run.stdout.includes(`Successfully installed ${pyName}-1.0.0`), `pip gets the previous version: ${run.stdout}`);
    run = h.pip(`install --no-cache-dir --target t ${pyName}==1.1.0`, { pipConf });
    expect(run.status !== 0 && /No matching distribution/.test(run.stderr), `pip install ==1.1.0 fails: ${run.stderr}`);
    run = h.pip("install --no-cache-dir --target t --require-hashes -r req.txt", { pipConf, files: hashes });
    expect(run.status !== 0 && /403/.test(run.stdout + run.stderr), `pip with the artifact URL gets 403: ${run.stdout}\n${run.stderr}`);
    await activityRow(h, admin.portal, { package: `${npmName}@1.1.0`, result: /^Held until \d\d \w{3} \d{4} \d\d:\d\d UTC$/, rule: "freeze", layer: "Platform" });
    await activityRow(h, admin.portal, { package: `${pyName}@1.1.0`, result: "Held until", ecosystem: "PyPI" });

    // 2. The org may not shorten the freeze while the platform's switch is off.
    const page = (await admin.portal.get(policy)).body;
    expect(page.includes("From the platform: 7 days."), "the policy page shows the platform's freeze");
    let saved = await savePolicy(admin.portal, policy, { freeze: "0", unit: "hours" });
    expect(saved.status === 422 && saved.body.includes("Not saved.") && saved.body.includes("Allow a shorter freeze") && saved.body.includes("the platform"), `the shorter freeze is refused, naming the switch: ${saved.status}\n${saved.body}`);
    saved = await savePolicy(admin.portal, policy, { freeze: "400", unit: "days" });
    expect(saved.status === 422 && saved.body.includes("Choose a freeze from 0 hours to 365 days."), `an out-of-range freeze is refused: ${saved.status}`);
    expect((await fetchWith(h, firewalls[0], `/npm/${npmName}/1.1.0`, key)).status === 403, "still held after the refused saves");

    // 3. The operator allows a shorter freeze; the org sets 0 hours and the version is
    //    released within the interval, from the warm caches.
    const restoreSwitch = await changePlatform(h, { allow: { allow_shorter_freeze: true } });
    try {
      saved = await savePolicy(admin.portal, policy, { freeze: "0", unit: "hours" });
      expect(saved.status === 303, `the org sets 0 hours: ${saved.status}\n${saved.body}`);
      const committed = performance.now();
      await untilStatus(h, firewalls, `/npm/${npmName}/1.1.0`, key, 200, "the release reaches the fleet");
      h.log(`released on both firewalls ${((performance.now() - committed) / 1000).toFixed(1)} s after the save`);
      run = npmInstall(`${npmName}@1.1.0`);
      ok("npm install of the released version", run);
      expect(version(run) === "1.1.0", `npm installs 1.1.0: ${run.stdout}`);
      run = h.npm(`ci --no-audit && node -p "require('${npmName}/package.json').version"`, { npmrc, packageJson: lockedProject, files: { "package-lock.json": packageLock } });
      ok("npm ci of the lockfile", run);
      expect(version(run) === "1.1.0", `npm ci installs 1.1.0: ${run.stdout}`);
      ok("pip install ==1.1.0", h.pip(`install --no-cache-dir --target t ${pyName}==1.1.0`, { pipConf }));
      ok("pip with the artifact URL", h.pip("install --no-cache-dir --target t --require-hashes -r req.txt", { pipConf, files: hashes }));
      // The org's 0 hours is the org's own: a personal account keeps the platform's 7 days.
      expect((await fetchWith(h, firewalls[1], `/npm/${npmName}/1.1.0`, soloKey)).status === 403, "the personal account is still held");
    } finally {
      await restoreSwitch();
    }
  } finally {
    await restorePlatform();
  }
}
