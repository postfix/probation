// E2E-conan: Conan 2 through a managed firewall (row 23; docs/operations.md "Conan clients").
//
// The fake ConanCenter (fixtures/fakes/conan.mjs) answers as center2.conan.io and serves the REAL files of a real Conan 2.21.0
// client (fixtures/conan: the recipe `hello` at 1.0 in a Release and a Debug binary and at 2.0 in one binary) with the revision
// times a scenario chooses. Conan 2.21.0 on Python 3.13.0 in the client container reads through firewall-1 (TLS via the gateway,
// `conan remote login` with the key, which a managed firewall answers with the key itself as the token), one remote and no other.
//
// 1. Under a 7-day platform freeze a version range takes the old version of a recipe whose newest is an hour old; the exact pin of
//    the young one fails and its files are HELD (403) when asked for directly; a NEW BINARY of the old recipe (the Debug package,
//    an hour old) is held by its own age while the old Release binary installs; the revision lists show only what passes.
// 2. A block on a version is refused before the remote is asked anything.
// 3. OSV on: a version flagged MAL under ecosystem `ConanCenter` (key: the package name) leaves the search and is refused.
// 4. A managed firewall refuses every write verb and nothing reaches the remote.
// Activity shows the refusals; the firewall's decision log names them.

import { activityRow, changePlatform, fetchWith, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-conan",
  title: "Conan through a managed firewall (revision lists and search filter, file gate, a new binary of an old recipe, blocks, OSV, writes refused)",
  suites: ["pr", "nightly", "release"],
};

const DAY = 86_400;
const HOUR = 3_600;
/// The revisions and package ids of the real files in fixtures/conan (see its README).
const RREV = "55e2afed4998aadc2c38906c5be3d992";
const RELEASE = "efa83b160a55b033c4ea706ddb980cd708e3ba1b";
const DEBUG = "9e186f6d94c008b544af1569d1a6368d8339efc5";

export default async function conan(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  await h.fakes.publishConan({ name: "hello", version: "1.0", ageSeconds: 300 * DAY, binaries: { [DEBUG]: HOUR } });
  await h.fakes.publishConan({ name: "hello", version: "2.0", ageSeconds: HOUR });

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key } = await h.createKey(admin.portal, "conan-ci");
  const get = (p, headers = {}) => fetchWith(h, fw1, p, key, headers);
  const profile = (type) => `[settings]\nos=Linux\narch=x86_64\nbuild_type=${type}\ncompiler=gcc\ncompiler.version=12\ncompiler.libcxx=libstdc++11\ncompiler.cppstd=17\n`;
  // A fresh client home each run: the remote is the firewall alone, the CA is the E2E one, the login is the key.
  const conanRun = (args) =>
    h.client(
      "client-conan",
      `export CONAN_HOME=$PWD/home/.conan2 HOME=$PWD/home; mkdir -p $HOME $CONAN_HOME; ` +
        `printf 'core.net.http:cacert_path=/e2e/ca/ca.pem\\n' > $CONAN_HOME/global.conf; ` +
        `conan remote remove conancenter >/dev/null; conan remote add probation https://fw1.e2e.test/conan >/dev/null && ` +
        `conan remote login probation key -p ${key} >/dev/null && ${args}`,
      { files: { "profile": profile("Release"), "profile-debug": profile("Debug") } },
    );
  const install = (requires, extra = "") => conanRun(`conan install --requires='${requires}' -r probation -pr:h=profile -pr:b=profile ${extra}`);
  const output = (run) => `${run.stdout}\n${run.stderr}`; // conan writes its progress to stderr and its results to stdout
  const since = new Date();

  const created = await admin.portal.submit("/keys", "/keys", { name: "conan-page" });
  expect(created.body.includes("conan remote add probation") && created.body.includes("fw1.e2e.test/conan"), `the keys page shows the Conan lines: ${created.body.slice(0, 400)}`);

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    await h.editPolicy(admin.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
    await h.waitFor("the freeze reaches firewall-1", async () => {
      const listing = await get("/conan/v2/conans/hello/1.0/_/_/revisions");
      return listing.status === 200 && listing.body.includes(RREV);
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    await h.waitFor("the young recipe is held", async () => (await get("/conan/v2/conans/hello/2.0/_/_/revisions")).status === 403, { timeout: 4 * h.syncInterval * 1000, every: 1000 });

    // Authentication: without a key every Conan read is 401.
    const anonymous = await h.request(`${fw1}/conan/v2/conans/hello/1.0/_/_/revisions`, { headers: { connection: "close" } });
    expect(anonymous.status === 401, `an unauthenticated read is 401: ${anonymous.status}`);

    // 1. A range takes the newest ALLOWED version; the exact pin of the young one fails.
    let run = install("hello/[>=1.0]");
    expect(run.status === 0 && /hello\/1\.0#/.test(output(run)) && !/hello\/2\.0/.test(output(run)), `conan takes only 1.0 of the range: ${run.status}\n${run.stdout.slice(-800)}\n${run.stderr.slice(-300)}`);
    run = install("hello/2.0");
    expect(run.status !== 0 && /403|2\.0|not found|Forbidden|held/i.test(run.stdout + run.stderr), `the exact pin of the young recipe fails: ${run.status}\n${run.stdout.slice(-600)}\n${run.stderr.slice(-400)}`);
    const young = `/conan/v2/conans/hello/2.0/_/_/revisions/${RREV}/files`;
    for (const file of ["conanfile.py", "conanmanifest.txt", "conan_sources.tgz"]) {
      const held = await get(`${young}/${file}`);
      expect(held.status === 403, `the young ${file} is HELD (403): ${held.status} ${held.body.slice(0, 160)}`);
    }
    expect((await get(young)).status === 403, "the young recipe's file list is HELD");
    const lists = await get("/conan/v2/conans/hello/1.0/_/_/revisions");
    expect(lists.status === 200 && JSON.parse(lists.body).revisions.length === 1 && JSON.parse(lists.body).reference === "hello/1.0@_/_", `the revision list names the allowed revision: ${lists.body}`);
    const search = await get("/conan/v2/conans/search?q=hello%2F*");
    expect(search.status === 200 && JSON.stringify(JSON.parse(search.body).results) === JSON.stringify(["hello/1.0@_/_"]), `the search lists only the reference with an allowed revision: ${search.body}`);
    const file = await get(`/conan/v2/conans/hello/1.0/_/_/revisions/${RREV}/files/conanfile.py`);
    expect(file.status === 200 && file.body.includes('name = "hello"'), `the recipe of the allowed version is delivered exactly: ${file.status}`);

    // What `conan search`, `conan list` and `conan graph info` read (the reference search, the revision lists and the binary search, with the
    // members the client prints) works through the filter, and shows nothing that is held.
    run = conanRun("conan search 'hello/*' -r probation");
    expect(run.status === 0 && /hello\/1\.0/.test(output(run)) && !/hello\/2\.0/.test(output(run)), `conan search lists only what passes: ${run.status}\n${output(run).slice(-600)}`);
    run = conanRun(`conan list 'hello/1.0#*:*' -r probation`);
    expect(run.status === 0 && output(run).includes(RELEASE) && !output(run).includes(DEBUG), `conan list shows the old binary and not the held one: ${run.status}\n${output(run).slice(-900)}`);
    run = conanRun("conan graph info --requires=hello/1.0 -r probation -pr:h=profile -pr:b=profile");
    expect(run.status === 0 && /hello\/1\.0/.test(output(run)), `conan graph info resolves through the filter: ${run.status}\n${output(run).slice(-600)}`);

    // A new binary of the old recipe has its own age.
    const binaries = JSON.parse((await get(`/conan/v2/conans/hello/1.0/_/_/revisions/${RREV}/search`)).body);
    expect(Object.keys(binaries).length === 1 && RELEASE in binaries, `the binary search lists only the old binary: ${JSON.stringify(Object.keys(binaries))}`);
    const debugFiles = `/conan/v2/conans/hello/1.0/_/_/revisions/${RREV}/packages/${DEBUG}`;
    const latest = await get(`${debugFiles}/latest`);
    expect(latest.status === 403, `the new Debug binary of the old recipe is HELD: ${latest.status} ${latest.body.slice(0, 120)}`);
    run = conanRun(`conan install --requires=hello/1.0 -r probation -pr:h=profile-debug -pr:b=profile-debug`);
    expect(run.status !== 0, `the Debug binary is not offered, and no other remote is tried: ${run.status}\n${run.stdout.slice(-400)}`);
    run = install("hello/1.0");
    expect(run.status === 0 && /Download \(probation\)/.test(output(run)), `the old Release binary is downloaded: ${run.status}\n${run.stdout.slice(-600)}`);

    // 2. A block on a version is refused before the remote is asked anything (the remote has no hello/3.0: unblocked it would be a 404).
    const policy = await h.policyPath(admin.portal);
    const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "conan", name: "hello", what: "version", version: "3.0" });
    expect(saved.status === 303, `the block is saved: ${saved.status}\n${saved.body}`);
    await h.waitFor("the block refuses the version", async () => (await get("/conan/v2/conans/hello/3.0/_/_/revisions")).status === 403, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    const asked = (await h.fakes.requests("center2.conan.io")).length;
    for (const path of ["/conan/v2/conans/hello/3.0/_/_/revisions", "/conan/v2/conans/hello/3.0/_/_/latest", `/conan/v2/conans/hello/3.0/_/_/revisions/${RREV}/files/conanfile.py`]) {
      expect((await get(path)).status === 403, `${path} is refused by the block`);
    }
    expect((await h.fakes.requests("center2.conan.io")).length === asked, "a blocked version reached no upstream call");

    // 3. OSV on: hello 1.0 flagged MAL under ecosystem `ConanCenter` (key: the package name) leaves the search and its files are refused.
    await h.fakes.osvFlag({ ecosystem: "ConanCenter", name: "hello", version: "1.0", ids: ["MAL-2026-9501"] });
    await h.waitFor("the MAL version leaves the search", async () => {
      const found = await get("/conan/v2/conans/search?q=hello%2F*");
      return found.status === 200 && JSON.stringify(JSON.parse(found.body).results) === "[]";
    }, { timeout: 150_000, every: 2000 }); // (a verdict lives two minutes)
    const queried = (await h.fakes.osvQueries()).some((q) => JSON.stringify(q).includes('"ConanCenter"') && JSON.stringify(q).includes('"hello"'));
    expect(queried, "the firewall asked OSV about the package under the ecosystem name ConanCenter");
    expect((await get(`/conan/v2/conans/hello/1.0/_/_/revisions/${RREV}/files/conanfile.py`)).status === 403, "the flagged version's files are refused");
    expect((await get("/conan/v2/conans/hello/1.0/_/_/revisions")).status === 403, "no revision of the flagged version is listed");

    // 4. The write verbs are no route of a managed firewall, and nothing reaches the remote.
    const before = (await h.fakes.requests("center2.conan.io")).length;
    const target = `/conan/v2/conans/hello/1.0/_/_/revisions/${RREV}/files/conanfile.py`;
    for (const method of ["PUT", "DELETE", "POST"]) {
      for (const headers of [{ connection: "close" }, { connection: "close", authorization: `Bearer ${key}` }]) {
        const answer = await h.request(`${fw1}${target}`, { method, body: "x", headers });
        expect(answer.status === 405, `${method} (${headers.authorization ? "with" : "without"} a key) is no route of a managed firewall: ${answer.status}`);
      }
    }
    expect((await h.fakes.requests("center2.conan.io")).length === before && (await h.fakes.conanWrites()).length === 0, "no write reached the fake remote");

    const dated = h.decisions("firewall-1", since).filter((d) => d.ecosystem === "conan");
    expect(dated.some((d) => d.package === "hello" && String(d.version).startsWith("2.0") && String(d.status) === "403"), `a logged decision names the held hello 2.0: ${JSON.stringify(dated.slice(-6))}`);
    await activityRow(h, admin.portal, { package: "hello" });
  } catch (error) {
    const failed = h.decisions("firewall-1", since).filter((d) => Number(d.status) >= 500);
    error.message += `\nfirewall-1 decisions with status >= 500 since the start (${failed.length}): ${JSON.stringify(failed.slice(-10))}`;
    throw error;
  } finally {
    await restorePlatform();
  }
}
