// E2E-002 npm block, refuse and unblock on two firewalls.
//
// An org admin without an authenticator is sent to turn it on before a policy edit is
// taken. With it on, in Chromium, the admin blocks a whole package and the newest
// version of another. Within the sync interval both firewalls refuse them: real npm
// falls back to the older version on firewall-1 and firewall-2, `npm install` of the
// blocked package fails with E403 BLOCKED, and `npm ci` with a lockfile pinning the
// blocked version fails and leaves the lockfile as it was. The Activity page shows the
// refusals with rule and layer and the key's name, never the key. The admin removes
// both blocks on the policy page: from the firewalls' warm caches the same installs
// get the newest version again, and `npm ci` of the old lockfile works.

import { activityRow, browserAddBlock, browserAs, fetchWith, onFirewall, orgIdOf, policyPost, tableRows, untilStatus } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-002",
  title: "npm block, refuse and unblock on two firewalls",
  suites: ["pr", "nightly", "release"],
};

const DAY = 86_400;

export default async function npmBlockUnblock(h) {
  const { expect } = h;
  const firewalls = [h.firewalls.fw1, h.firewalls.fw2];
  const pinned = h.unique("e2e-pinned"); // version block on 2.0.0
  const banned = h.unique("e2e-banned"); // whole-package block
  for (const [version, days] of [["1.0.0", 300], ["1.1.0", 250], ["2.0.0", 200]]) {
    await h.fakes.publishNpm({ name: pinned, version, ageSeconds: days * DAY });
  }
  await h.fakes.publishNpm({ name: banned, version: "1.0.0", ageSeconds: 300 * DAY });

  const admin = await h.signUp({ kind: "org" });
  const policy = `/policy/org-${await orgIdOf(admin.portal)}`;
  // Negative: an org admin who signed in with a password only sees the organisation's
  // layer read-only and is sent to turn the authenticator on; the edit is not taken.
  expect((await admin.portal.get(policy)).body.includes("You can see this layer but not change it"), "read-only without a second factor");
  const early = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "npm", name: banned, what: "package" });
  expect(early.status === 303 && early.location?.startsWith("/account"), `an edit without a second factor: ${early.status} ${early.location}`);
  await h.enableTotp(admin);
  expect((await h.policyPath(admin.portal)) === policy, "with the authenticator on, /policy opens the organisation's layer");
  const keyName = "ci-runner";
  const { key, npmrc } = await h.createKey(admin.portal, keyName);
  const npmrcs = [npmrc, onFirewall(npmrc, "fw2.e2e.test")];
  // Nothing is blocked yet (the early edit was not saved).
  await untilStatus(h, firewalls, `/npm/${banned}`, key, 200, "the package is served before any block");

  const installed = (run, name) => run.stdout.trim().split("\n").at(-1) === name;
  const install = (spec, f, extra = "") =>
    h.npm(`install ${spec} --no-audit ${extra} && node -p "require('${pinned}/package.json').version"`, { npmrc: npmrcs[f] });
  // Warm both firewalls' caches with the newest version, and make the lockfile a CI run
  // would replay: it pins 2.0.0.
  for (const f of [0, 1]) {
    const run = install(pinned, f);
    expect(run.status === 0 && installed(run, "2.0.0"), `firewall-${f + 1} serves ${pinned} 2.0.0 before the block: ${run.status}\n${run.stdout}\n${run.stderr}`);
  }
  const locked = h.npm(`install ${pinned}@2.0.0 --package-lock-only --no-audit && cat package-lock.json`, { npmrc });
  expect(locked.status === 0, `lockfile: ${locked.stdout}\n${locked.stderr}`);
  const packageLock = locked.stdout.slice(locked.stdout.indexOf("{"));
  const lockedProject = { name: "e2e-project", version: "1.0.0", private: true, dependencies: { [pinned]: "2.0.0" } };

  // 1. The admin blocks on the policy page, in Chromium.
  const page = await browserAs(h, admin);
  await page.goto(policy);
  await browserAddBlock(page, { ecosystem: "npm", name: banned, what: "package" });
  await browserAddBlock(page, { ecosystem: "npm", name: pinned, what: "version", version: "2.0.0" });
  const blocks = await tableRows(page, "Blocks");
  expect(blocks.some((row) => row.includes(banned) && row.includes("Whole package") && row.includes("This layer")), `the page lists the package block:\n${blocks.join("\n")}`);
  expect(blocks.some((row) => row.includes(pinned) && row.includes("Version 2.0.0")), `the page lists the version block:\n${blocks.join("\n")}`);
  const committed = performance.now();
  await untilStatus(h, firewalls, `/npm/${pinned}/2.0.0`, key, 403, "the version block reaches the fleet");
  await untilStatus(h, firewalls, `/npm/${banned}`, key, 403, "the package block reaches the fleet");
  h.log(`blocks applied on both firewalls ${((performance.now() - committed) / 1000).toFixed(1)} s after the save`);
  const body = (await fetchWith(h, firewalls[0], `/npm/${banned}`, key)).json();
  expect(body.error === "BLOCKED" && body.reason, `the refusal names its code and reason: ${JSON.stringify(body)}`);

  // 2. What real npm does on both firewalls.
  for (const f of [0, 1]) {
    let run = install(pinned, f);
    expect(run.status === 0 && installed(run, "1.1.0"), `firewall-${f + 1}: npm falls back to 1.1.0: ${run.status}\n${run.stdout}\n${run.stderr}`);
    run = h.npm(`install ${banned} --no-audit`, { npmrc: npmrcs[f] });
    expect(run.status !== 0 && /E403/.test(run.stderr) && /BLOCKED/.test(run.stderr), `firewall-${f + 1}: npm shows E403 BLOCKED: ${run.status}\n${run.stderr}`);
  }
  let ci = h.npm("ci --no-audit; echo \"exit=$?\"; sha256sum package-lock.json; ls node_modules 2>/dev/null", {
    npmrc,
    packageJson: lockedProject,
    files: { "package-lock.json": packageLock },
  });
  expect(/exit=[1-9]/.test(ci.stdout) && /E403|403 Forbidden/.test(ci.stderr), `npm ci of the blocked pin fails with 403:\n${ci.stdout}\n${ci.stderr}`);
  const sha = (text) => text.match(/^([0-9a-f]{64}) {2}package-lock\.json$/m)?.[1];
  const lockSha = h.client("client-npm", "sha256sum package-lock.json", { files: { "package-lock.json": packageLock } }).stdout.split(" ")[0];
  expect(sha(ci.stdout) === lockSha, "npm ci leaves the lockfile unchanged");
  expect(!ci.stdout.includes(pinned), `nothing of ${pinned} is installed: ${ci.stdout}`);

  // 3. The Activity page, as the admin sees it in the browser.
  await activityRow(h, admin.portal, { package: banned, result: "Blocked", layer: "Organisation" });
  await activityRow(h, admin.portal, { package: `${pinned}@2.0.0`, result: "Blocked", layer: "Organisation", key: keyName });
  await page.goto("/activity");
  const activity = await page.locator("main").innerText();
  expect(activity.includes(banned) && activity.includes(keyName), `the activity page lists the refusal and the key's name:\n${activity}`);
  expect(!(await page.content()).includes(key), "the activity page never shows the key itself");

  // 4. Unblock: Remove on both rows, in the browser.
  await page.goto(policy);
  for (const label of [`Remove the block on ${banned} Whole package`, `Remove the block on ${pinned} Version 2.0.0`]) {
    await Promise.all([page.waitForNavigation(), page.click(`button[aria-label="${label}"]`)]);
  }
  const left = await tableRows(page, "Blocks");
  expect(!left.some((row) => row.includes(banned) || row.includes(pinned)), `the blocks are gone from the page:\n${left.join("\n")}`);
  await untilStatus(h, firewalls, `/npm/${pinned}/2.0.0`, key, 200, "the unblock reaches the fleet");
  await untilStatus(h, firewalls, `/npm/${banned}`, key, 200, "the package unblock reaches the fleet");
  for (const f of [0, 1]) {
    let run = install(pinned, f);
    expect(run.status === 0 && installed(run, "2.0.0"), `firewall-${f + 1}: npm gets 2.0.0 again from the warm cache: ${run.status}\n${run.stdout}\n${run.stderr}`);
    run = h.npm(`install ${banned} --no-audit`, { npmrc: npmrcs[f] });
    expect(run.status === 0, `firewall-${f + 1}: ${banned} installs again: ${run.stderr}`);
  }
  ci = h.npm(`ci --no-audit && node -p "require('${pinned}/package.json').version"`, {
    npmrc,
    packageJson: lockedProject,
    files: { "package-lock.json": packageLock },
  });
  expect(ci.status === 0 && installed(ci, "2.0.0"), `npm ci of the old lockfile works again: ${ci.status}\n${ci.stdout}\n${ci.stderr}`);
}
