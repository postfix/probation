// E2E-rubygems RubyGems through a managed firewall (row 17; docs/operations.md "RubyGems clients").
//
// The fake RubyGems (fixtures/fakes/rubygems.mjs) answers as rubygems.org: the compact index,
// the legacy tuple indexes, quick gemspecs, real .gem archives and the paged timeframe_versions
// API. An organisation copies the Gemfile line from the keys page; Bundler 2.5 and `gem` 3.5 in
// the Ruby client container install through firewall-1 (TLS via the gateway, the key as Basic).
//
// 1. Under a 7-day platform freeze Bundler locks the old version of a gem whose newest is an
//    hour old and the exact pin of the new one fails; `gem install` of a gem the firewall has
//    never indexed (no warm-up) gets the old version from the dated legacy index; the young
//    platform build of a gem is not listed while its ruby build is, and the artifact route
//    answers 403 HELD for the young file.
// 2. A gem published as `RedCloth`-style mixed case: its index answers any spelling, its
//    files only the exact one (the firewall keeps the client's spelling and the registry
//    refuses the lowercase file); an organisation block written in lowercase hides it under
//    every spelling.
// 3. OSV on: a version flagged MAL is hidden from the index and from Bundler.
// 4. A `gem push` through the firewall needs the caller's own key (401 without) and reaches the
//    fake registry with that key only.
// Activity shows the refusals; the firewall's decision log names them.

import { activityRow, basic, changePlatform, fetchWith, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-rubygems",
  title: "RubyGems through a managed firewall (Bundler, gem, freeze, OSV, mixed case)",
  suites: ["pr", "nightly", "release"],
};

/// What a managed (non-service) firewall answers a RubyGems write with (no such route).
const PUSH_STATUS = 404;
const DAY = 86_400;
const HOUR = 3_600;

export default async function rubygems(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  const suffix = h.unique("r").slice(2);
  const bundlerGem = `rg-bundler-${suffix}`;
  const legacyGem = `rg-legacy-${suffix}`;
  const platGem = `rg-plat-${suffix}`;
  const malGem = `rg-mal-${suffix}`;
  const mixedGem = `RgCase${suffix}`;
  for (const name of [bundlerGem, legacyGem]) {
    await h.fakes.publishRubygems({ name, version: "1.0.0", ageSeconds: 300 * DAY });
    await h.fakes.publishRubygems({ name, version: "2.0.0", ageSeconds: HOUR });
  }
  await h.fakes.publishRubygems({ name: platGem, version: "1.0.0", ageSeconds: 300 * DAY });
  await h.fakes.publishRubygems({ name: platGem, version: "1.0.0", platform: "java", ageSeconds: HOUR });
  for (const version of ["1.0.0", "1.1.0"]) await h.fakes.publishRubygems({ name: malGem, version, ageSeconds: 300 * DAY });
  await h.fakes.osvFlag({ ecosystem: "RubyGems", name: malGem, version: "1.0.0", ids: ["MAL-2026-9001"] });
  await h.fakes.publishRubygems({ name: mixedGem, version: "1.0.0", ageSeconds: 300 * DAY });
  const young = await h.fakes.publishRubygems({ name: mixedGem, version: "1.1.0", ageSeconds: HOUR });
  expect(young.file === `${mixedGem}-1.1.0.gem`, "the fake published the mixed-case gem");

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const keys = await h.createKey(admin.portal, "ruby-ci");
  const { key } = keys;
  const source = `https://key:${key}@fw1.e2e.test/rubygems/`;
  const get = (path, headers = {}) => fetchWith(h, fw1, path, null, { authorization: basic(key), ...headers });
  const ok = (what, run) => expect(run.status === 0, `${what} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  const bundle = (script, gemfile) =>
    h.client("client-ruby", `export BUNDLE_APP_CONFIG=$PWD/.bundle BUNDLE_USER_HOME=$PWD/.bundle-home GEM_HOME=$PWD/.gems GEM_PATH=$PWD/.gems; ${script}`, { files: { Gemfile: gemfile } });
  const since = new Date();

  // The keys page shows the RubyGems line next to npm and pip.
  const created = await admin.portal.submit("/keys", "/keys", { name: "ruby-page" });
  expect(created.body.includes("fw1.e2e.test/rubygems/") && created.body.includes('source "'), `the keys page shows the Gemfile source: ${created.body.slice(0, 400)}`);

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    await h.editPolicy(admin.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
    // The freeze and OSV reach firewall-1 within a few sync intervals.
    await h.waitFor("the freeze reaches firewall-1", async () => {
      const info = await get(`/rubygems/info/${bundlerGem}`);
      return info.status === 200 && info.body.includes("\n1.0.0 ") && !info.body.includes("\n2.0.0 ");
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });

    // 1a. Bundler (compact index): the old version locks, the exact pin of the young one fails.
    let run = bundle("bundle install && cat Gemfile.lock", `source "${source}"\ngem "${bundlerGem}"\n`);
    ok("bundle install", run);
    expect(run.stdout.includes(`${bundlerGem} (1.0.0)`) && !run.stdout.includes("2.0.0"), `Bundler locks 1.0.0:\n${run.stdout}`);
    run = bundle("bundle install", `source "${source}"\ngem "${bundlerGem}", "2.0.0"\n`);
    expect(run.status !== 0 && /Could not find gem|could not find/i.test(run.stdout + run.stderr), `the exact pin of the young version fails: ${run.status}\n${run.stdout}\n${run.stderr}`);

    // 1b. `gem install` of a gem this firewall has never indexed: no warm-up, the dated legacy
    // index lists only the eligible version.
    run = h.client("client-ruby", `export GEM_HOME=$PWD/.gems GEM_PATH=$PWD/.gems HOME=$PWD; gem install ${legacyGem} --clear-sources --source ${source} --no-document && gem list ${legacyGem}`);
    ok("gem install", run);
    expect(run.stdout.includes(`${legacyGem} (1.0.0)`) && !run.stdout.includes("2.0.0"), `gem installs 1.0.0:\n${run.stdout}`);

    // 1c. Platform builds are judged one by one.
    const plat = await get(`/rubygems/info/${platGem}`);
    expect(plat.body.includes("\n1.0.0 ") && !plat.body.includes("-java"), `the young java build is not listed, the old ruby build is:\n${plat.body}`);
    const javaFile = `${platGem}-1.0.0-java.gem`;
    const held = await get(`/rubygems/gems/${javaFile}`);
    expect(held.status === 403, `the young java file is HELD (403): ${held.status} ${held.body.slice(0, 200)}`);
    const dated = h.decisions("firewall-1", since);
    expect(dated.length > 0, "the firewall logged decisions");

    // 3. OSV: the MAL version is hidden, the other installs through Bundler.
    // OSV On reaches the firewall with the same policy sync as the freeze.
    let mal;
    await h.waitFor("the MAL version leaves the index", async () => {
      mal = await get(`/rubygems/info/${malGem}`);
      return mal.status === 200 && !mal.body.includes("\n1.0.0 ");
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 }).catch(() => {});
    expect(mal.body.includes("\n1.1.0 ") && !mal.body.includes("\n1.0.0 "), `the MAL version is not listed:\n${mal.body}`);
    run = bundle("bundle install && cat Gemfile.lock", `source "${source}"\ngem "${malGem}"\n`);
    ok("bundle install of the OSV gem", run);
    expect(run.stdout.includes(`${malGem} (1.1.0)`), `Bundler locks the unflagged version:\n${run.stdout}`);
    const queried = (await h.fakes.osvQueries()).some((q) => JSON.stringify(q).includes('"RubyGems"') && JSON.stringify(q).includes(malGem));
    expect(queried, "the firewall asked OSV about the gem under the ecosystem name RubyGems");

    // 4. A managed (non-service) firewall does not forward writes: `gem push` and `gem yank` are
    // answered locally, with or without a key, and nothing reaches the registry (the shared
    // service forwards them: E2E-publishing-rubygems-service).
    const writesBefore = (await h.fakes.rubygemsWrites()).length;
    for (const [method, path] of [["POST", "/rubygems/api/v1/gems"], ["DELETE", "/rubygems/api/v1/gems/yank"]]) {
      for (const headers of [{ connection: "close" }, { connection: "close", authorization: basic(key) }]) {
        const answer = await h.request(`${fw1}${path}`, { method, body: "x", headers });
        expect(answer.status === PUSH_STATUS, `${method} ${path} (${headers.authorization ? "with" : "without"} a key) is not a route of a managed firewall: ${answer.status}`);
      }
    }
    expect((await h.fakes.rubygemsWrites()).length === writesBefore, "no write reached the fake registry");

    // 2. Mixed case: the index answers any spelling, files only the exact one.
    const lower = mixedGem.toLowerCase();
    const idx = await get(`/rubygems/info/${lower}`);
    expect(idx.status === 200 && idx.body.includes("\n1.0.0 ") && !idx.body.includes("\n1.1.0 "), `the lowercase index lists the old version only:\n${idx.body}`);
    const exact = await get(`/rubygems/gems/${mixedGem}-1.0.0.gem`);
    expect(exact.status === 200, `the exact-case file is delivered: ${exact.status} ${exact.body.slice(0, 120)}`);
    const wrongCase = await get(`/rubygems/gems/${lower}-1.0.0.gem`);
    expect(wrongCase.status === 502, `the lowercase file is refused (the registry says Forbidden, the firewall answers 502): ${wrongCase.status}`);
    const youngMixed = await get(`/rubygems/gems/${young.file}`);
    expect(youngMixed.status === 403, `the young mixed-case file is HELD (403): ${youngMixed.status} ${youngMixed.body.slice(0, 200)}`);
    const policy = await h.policyPath(admin.portal);
    const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "rubygems", name: lower, what: "package", version: "" });
    expect(saved.status === 303, `the lowercase block is saved: ${saved.status}\n${saved.body}`);
    await h.waitFor("the block hides the gem under every spelling", async () => {
      const [a, b] = [await get(`/rubygems/info/${lower}`), await get(`/rubygems/info/${mixedGem}`)];
      return a.status === 200 && b.status === 200 && a.body === "---\n" && b.body === "---\n";
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });

    // Activity shows the refusals of the freeze and the block.
    await activityRow(h, admin.portal, { package: lower });
  } finally {
    await restorePlatform();
  }
}
