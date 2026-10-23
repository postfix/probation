// E2E-013 Layered policy with groups, users and exceptions.
//
// The platform blocks a package, a file (by digest) and a PyPI version, and holds new
// versions for 7 days, with "Allow package exceptions" on. Organisation A has the group
// Frontend: Bob is its group admin (password only), Mia a member in it, Max a member in
// no group. Organisation B sets nothing. All four keys use the same firewalls.
//
// - Bob blocks package X on the group layer: Mia's npm gets E403, Max and B install X;
//   Bob cannot touch the organisation's layer; Bob's Activity shows Mia's refusal.
// - A's org admin adds exceptions: the platform's package block lifts for A's people
//   only (B stays refused); X stays refused for Mia (the group's block sits below the
//   organisation); a whole-package exception does not lift the platform's file block,
//   an exact-version one does; a PyPI exception written `1.0` lifts the block written
//   `1.0.0`; a freeze exception is refused while the platform's switch is off.
// - Max blocks a package on his own layer: only Max is refused.
// - The operator turns "Allow package exceptions" off: A's exceptions show "not in
//   effect" and the platform's blocks apply again; on again, they lift again.
// - Two browser tabs on A's layer: the stale one's save is "Not saved".
// - remove_exception restores the refusal.
// - A platform block lands while keys are cached and a new key is used right after it:
//   every key gets it within the interval (fails today: see step 7).

import {
  activityRow,
  basic,
  browserAddBlock,
  browserAs,
  changePlatform,
  createGroup,
  fetchWith,
  invitedMembers,
  orgIdOf,
  policyPost,
  removeOwn,
  tableRows,
  untilStatus,
} from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-013",
  title: "Layered policy with groups, users and exceptions",
  suites: ["nightly", "release"],
};

const DAY = 86_400;
const PLATFORM = "/policy/platform-1";

export default async function layeredPolicy(h) {
  const { expect } = h;
  const firewalls = [h.firewalls.fw1, h.firewalls.fw2];
  const [fw1] = firewalls;
  const name = (what) => h.unique(`e2e-${what}`);
  const P = name("plat"); // platform package block
  const D = name("digest"); // platform file block on 1.0.0
  const X = name("group"); // Bob's group block
  const Y = name("own"); // Max's own block
  const F = name("fresh"); // 1.1.0 is an hour old: held by the platform's freeze
  const Z = name("tab"); // the browser tabs' edits
  const Q = name("late"); // a platform block while keys are cached
  const py = h.unique("py-layer");
  for (const pkg of [P, X, Y, F, Z, Q]) await h.fakes.publishNpm({ name: pkg, version: "1.0.0", ageSeconds: 300 * DAY });
  const dist = await h.fakes.publishNpm({ name: D, version: "1.0.0", ageSeconds: 300 * DAY });
  const digest = Buffer.from(dist.integrity.slice("sha512-".length), "base64").toString("hex");
  await h.fakes.publishNpm({ name: F, version: "1.1.0", ageSeconds: 3_600 });
  await h.fakes.publishPypi({ name: py, version: "1.0.0", ageSeconds: 300 * DAY, kinds: ["wheel"] });
  const dTarball = `/npm/${D}/-/${D}-1.0.0.tgz`;

  // Organisation A: its admin, the Frontend group and three invited people.
  const ada = await h.signUp({ kind: "org" });
  await h.enableTotp(ada);
  const orgA = await orgIdOf(ada.portal);
  const orgLayer = `/policy/org-${orgA}`;
  const frontend = await createGroup(ada.portal, orgA, "Frontend");
  const [bob, mia, max] = await invitedMembers(h, ada, orgA, [{ role: "group_admin", group: frontend }, { role: "member", group: frontend }, { role: "member" }]);
  const miaKey = await h.createKey(mia.portal, "mia-laptop");
  const maxKey = (await h.createKey(max.portal, "max-laptop")).key;
  // Organisation B, on the same firewalls.
  const bea = await h.signUp({ kind: "org" });
  const beaKey = (await h.createKey(bea.portal, "bea-laptop")).key;
  const people = { mia: miaKey.key, max: maxKey, bea: beaKey };

  // The PyPI artifact URL of py 1.0.0 as the firewall names it (before any block).
  const probe = (await h.createKey(ada.portal, "ada-probe")).key;
  const simple = await fetchWith(h, fw1, `/pypi/simple/${py}/`, null, { authorization: basic(probe) });
  const pyArtifact = new URL(simple.body.match(/href="([^"#]+-1\.0\.0-py3-none-any\.whl)/)?.[1] ?? "/missing", fw1).pathname;
  expect(pyArtifact.startsWith("/pypi/artifacts/"), `the wheel link on the firewall's page:\n${simple.body}`);

  /// Waits until each of `who` gets `status` for `path` on both firewalls (or `on`).
  const until = async (path, who, status, what, on = firewalls) => {
    for (const person of who) await untilStatus(h, on, path, people[person], status, `${what}: ${person} gets ${status}`);
  };
  /// Asserts each of `who` gets `status` now (after a change that would have moved it
  /// has been seen to apply).
  const now = async (path, who, status, what, on = firewalls) => {
    for (const person of who) {
      for (const firewall of on) {
        const got = (await fetchWith(h, firewall, path, people[person])).status;
        expect(got === status, `${what}: ${person} gets ${got} on ${firewall}, not ${status}`);
      }
    }
  };
  const posted = async (portal, path, fields, status = 303) => {
    const answer = await policyPost(portal, path, fields);
    expect(answer.status === status, `${path} ${JSON.stringify(fields)}: ${answer.status}, not ${status}\n${answer.body}`);
    return answer;
  };

  const op = h.operator.portal;
  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_exceptions: true, allow_shorter_freeze: false } });
  try {
    await posted(op, PLATFORM, { action: "add_block", ecosystem: "npm", name: P, what: "package" });
    await posted(op, PLATFORM, { action: "add_block", what: "file", algorithm: "sha512", digest });
    await posted(op, PLATFORM, { action: "add_block", ecosystem: "pypi", name: py, what: "version", version: "1.0.0" });
    await until(`/npm/${P}`, ["mia", "max", "bea"], 403, "the platform block");
    // An artifact URL is firewall-1's own: firewall-2 knows it only once it has listed
    // the project.
    await until(pyArtifact, ["mia"], 403, "the platform's PyPI block", [fw1]);
    await now(`/npm/${F}/1.1.0`, ["mia", "max", "bea"], 403, "the platform freeze");
    await now(dTarball, ["mia", "bea"], 403, "the platform's file block");

    // 1. Bob, group admin with a password only, blocks X on the Frontend layer.
    const groupLayer = await h.policyPath(bob.portal);
    expect(groupLayer === `/policy/group-${frontend}`, `/policy opens the group's layer for its group admin: ${groupLayer}`);
    const refused = await policyPost(bob.portal, orgLayer, { action: "add_block", ecosystem: "npm", name: X, what: "package" });
    expect(refused.status === 403 || refused.status === 404, `a group admin cannot change the organisation's layer: ${refused.status}`);
    await posted(bob.portal, groupLayer, { action: "add_block", ecosystem: "npm", name: X, what: "package" });
    await until(`/npm/${X}`, ["mia"], 403, "Bob's group block");
    await now(`/npm/${X}`, ["max", "bea"], 200, "the group block reaches only the group");
    let run = h.npm(`install ${X} --no-audit`, { npmrc: miaKey.npmrc });
    expect(run.status !== 0 && /E403/.test(run.stderr) && /BLOCKED/.test(run.stderr), `Mia's npm is refused: ${run.status}\n${run.stderr}`);
    for (const [who, key] of [["max", maxKey], ["bea", beaKey]]) {
      run = h.npm(`install ${X} --no-audit`, { npmrc: miaKey.npmrc.replaceAll(miaKey.key, key) });
      expect(run.status === 0, `${who} installs ${X}: ${run.status}\n${run.stderr}`);
    }
    await activityRow(h, bob.portal, { package: X, result: "Blocked", layer: "Group", key: "mia-laptop" });

    // 2. A's org admin adds exceptions. The platform's package block lifts for A's
    //    people only; X stays refused for Mia; a whole-package exception leaves the
    //    file block in force.
    await posted(ada.portal, orgLayer, { action: "add_exception", ecosystem: "npm", name: X, lifts_block: "on" });
    await posted(ada.portal, orgLayer, { action: "add_exception", ecosystem: "npm", name: D, lifts_block: "on" });
    await posted(ada.portal, orgLayer, { action: "add_exception", ecosystem: "pypi", name: py.toUpperCase(), version: "1.0", lifts_block: "on" });
    await posted(ada.portal, orgLayer, { action: "add_exception", ecosystem: "npm", name: P, lifts_block: "on" });
    await until(`/npm/${P}`, ["mia", "max"], 200, "A's exception on the platform block");
    await now(`/npm/${P}`, ["bea"], 403, "A's exception does not reach organisation B");
    await now(`/npm/${X}`, ["mia"], 403, "an organisation exception does not lift the group's block");
    await now(dTarball, ["mia", "max"], 403, "a whole-package exception does not lift a file block");
    run = h.npm(`install ${D}@1.0.0 --no-audit`, { npmrc: miaKey.npmrc });
    expect(run.status !== 0, `Mia's npm is still refused ${D}: ${run.stdout}\n${run.stderr}`);
    await now(pyArtifact, ["mia"], 200, "the exception written 1.0 lifts the block written 1.0.0", [fw1]);
    run = h.pip(`install --no-cache-dir --target t ${py}==1.0.0`, { pipConf: miaKey.pipConf });
    expect(run.status === 0, `Mia's pip installs ${py} 1.0.0 under the exception: ${run.stdout}\n${run.stderr}`);
    await posted(ada.portal, orgLayer, { action: "add_exception", ecosystem: "npm", name: D, version: "1.0.0", lifts_block: "on" });
    await until(dTarball, ["mia", "max"], 200, "the exact-version exception lifts the file block");
    run = h.npm(`install ${D}@1.0.0 --no-audit`, { npmrc: miaKey.npmrc });
    expect(run.status === 0, `Mia's npm installs ${D} 1.0.0: ${run.stderr}`);
    await now(dTarball, ["bea"], 403, "organisation B keeps the file block");
    // A freeze exception needs "Allow a shorter freeze", which the platform has off.
    const freeze = await policyPost(ada.portal, orgLayer, { action: "add_exception", ecosystem: "npm", name: F, version: "1.1.0", lifts_freeze: "on" });
    expect(freeze.status === 422 && freeze.body.includes("Allow a shorter freeze"), `a freeze exception is refused, naming the switch: ${freeze.status}\n${freeze.body}`);

    // 3. Max blocks Y on his own layer.
    const own = await h.policyPath(max.portal);
    expect(/^\/policy\/user-\d+$/.test(own), `a member's /policy is their own layer: ${own}`);
    const notMax = await policyPost(max.portal, orgLayer, { action: "add_block", ecosystem: "npm", name: Y, what: "package" });
    expect(notMax.status === 403 || notMax.status === 404, `a member cannot change the organisation's layer: ${notMax.status}`);
    await posted(max.portal, own, { action: "add_block", ecosystem: "npm", name: Y, what: "package" });
    await until(`/npm/${Y}`, ["max"], 403, "Max's own block");
    await now(`/npm/${Y}`, ["mia", "bea"], 200, "Max's block is his alone");

    // 4. The operator turns "Allow package exceptions" off: A's exceptions are kept but
    //    not in effect, and enforced so.
    const restoreSwitch = await changePlatform(h, { allow: { allow_exceptions: false } });
    try {
      await until(`/npm/${P}`, ["mia", "max"], 403, "exceptions not in effect");
      await now(dTarball, ["mia"], 403, "the exact-version exception is not in effect either");
      const exceptions = (await ada.portal.get(orgLayer)).body;
      const marked = exceptions.match(/\(not in effect while a stricter rule above applies\)/g) ?? [];
      expect(marked.length >= 4, `every exception of A's layer shows "not in effect" (${marked.length})`);
    } finally {
      await restoreSwitch();
    }
    await until(`/npm/${P}`, ["mia", "max"], 200, "exceptions in effect again");

    // 5. Two tabs on A's layer: the second save, from the stale tab, is not taken.
    const first = await browserAs(h, ada);
    const second = await first.context().newPage();
    await first.goto(orgLayer);
    await second.goto(orgLayer);
    await browserAddBlock(first, { ecosystem: "npm", name: Z, what: "version", version: "1.0.0" });
    await browserAddBlock(second, { ecosystem: "npm", name: Z, what: "package" });
    const conflict = await second.locator("main").innerText();
    expect(conflict.includes("Not saved. This layer was changed meanwhile by someone else"), `the stale tab's save is refused:\n${conflict}`);
    const rows = await tableRows(second, "Blocks");
    expect(rows.some((row) => row.includes(Z) && row.includes("Version 1.0.0")) && !rows.some((row) => row.includes(Z) && row.includes("Whole package")), `the page shows the layer as it is now:\n${rows.join("\n")}`);

    // 6. remove_exception: the platform's block applies to A's people again.
    const removed = await removeOwn(ada.portal, orgLayer, "exception", new RegExp(`^Remove the exception on ${P}$`));
    expect(removed.status === 303, `remove the exception: ${removed.status}\n${removed.body}`);
    await until(`/npm/${P}`, ["mia", "max"], 403, "the removed exception");
    run = h.npm(`install ${P} --no-audit`, { npmrc: miaKey.npmrc });
    expect(run.status !== 0 && /E403/.test(run.stderr), `Mia's npm is refused ${P} again: ${run.stderr}`);

    // 7. A platform block while keys are cached on the firewalls, and a key used for
    //    the first time right after it: all get the new policy within the interval.
    //    New defect (no F number yet): the first-use lookup fetches the new platform
    //    layer before firewall-1's sync, the sync then sees that layer as current and
    //    never rebuilds the cached keys' policies, so Mia and Max keep the old policy
    //    on firewall-1 for key_cache_ttl_seconds (300 s), not one interval.
    await now(`/npm/${Q}`, ["mia", "max"], 200, "before the late block");
    await posted(op, PLATFORM, { action: "add_block", ecosystem: "npm", name: Q, what: "package" });
    const late = (await h.createKey(bea.portal, "bea-late")).key;
    await untilStatus(h, [fw1], `/npm/${Q}`, late, 403, "a key used for the first time after the block");
    await until(`/npm/${Q}`, ["mia", "max"], 403, "keys cached before the block");
  } finally {
    for (const label of [new RegExp(` ${P} `), new RegExp(digest), new RegExp(` ${py} `), new RegExp(` ${Q} `)]) {
      const answer = await removeOwn(op, PLATFORM, "block", label).catch((err) => ({ status: 0, body: err.message }));
      if (answer.status !== 303) h.log(`platform block ${label} not removed: ${answer.status} ${answer.body.slice(0, 200)}`);
    }
    await restorePlatform();
  }
}
