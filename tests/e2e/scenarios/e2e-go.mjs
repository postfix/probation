// E2E-go Go modules through a managed firewall (row 19; docs/operations.md "Go clients").
//
// The fake proxy (fixtures/fakes/go.mjs) answers as proxy.golang.org (`@v/list`, `@latest`, `.info`,
// `.mod`, real stored `.zip` files, `Time` in every `.info`) and as sum.golang.org. Go 1.26 in the
// client container reads through firewall-1 (TLS via the gateway, the key as the GOPROXY userinfo
// the keys page shows), one protected GOPROXY and no fallback.
//
// 1. Under a 7-day platform freeze `go get ...@latest` takes the old version of a module whose newest
//    is an hour old and builds it; `go list -m -versions` shows only it; the exact pin of the young
//    one fails and its `.info`, `.mod` and `.zip` are all HELD (403) when asked for directly.
// 2. Pseudo-versions are not listed: the old one downloads, the young one is held by its own `.info`.
// 3. OSV on: a version flagged MAL under ecosystem `Go` is hidden from the list.
// 4. A module with capitals in its path and in a version (`!`-escaped on the wire): the list names the
//    real spellings, the zip of the escaped prerelease downloads, another spelling is 404, and a block
//    written with the decoded name hides it (and its zip is refused).
// 5. A version with no `Time` waits on first-seen.
// 6. The checksum database route forwards `supported`, `lookup` and tiles to sum.golang.org only, with no
//    credential; another database name is 404; a managed firewall refuses every write verb.
// Activity shows the refusals; the firewall's decision log names them.

import { activityRow, changePlatform, fetchWith, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-go",
  title: "Go modules through a managed firewall (list/latest filter, mod/info/zip gate, pseudo-versions, OSV, mixed case, sumdb)",
  suites: ["pr", "nightly", "release"],
};

const DAY = 86_400;
const HOUR = 3_600;
const escape = (text) => text.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
const pseudo = (at) => `v0.0.0-${at.toISOString().replace(/[-:T]/g, "").slice(0, 14)}-abcdef123456`;

export default async function go(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  const suffix = h.unique("g").slice(2);
  const fresh = `example.com/e2e/fresh-${suffix}`;
  const pseudoModule = `example.com/e2e/pseudo-${suffix}`;
  const malModule = `example.com/e2e/mal-${suffix}`;
  const mixed = `example.com/E2E/Mixed-${suffix}`;
  const undated = `example.com/e2e/undated-${suffix}`;
  const oldPseudo = "v0.0.0-20240101000000-abcdef123456";
  const youngPseudo = pseudo(new Date(Date.now() - HOUR * 1000));
  await h.fakes.publishGo({ module: fresh, version: "v1.0.0", ageSeconds: 300 * DAY });
  await h.fakes.publishGo({ module: fresh, version: "v1.1.0", ageSeconds: HOUR });
  await h.fakes.publishGo({ module: pseudoModule, version: oldPseudo, ageSeconds: 300 * DAY, revs: ["main", "abcdef123456"] });
  await h.fakes.publishGo({ module: pseudoModule, version: youngPseudo, ageSeconds: HOUR, revs: ["dev"] });
  const backdated = `example.com/e2e/backdated-${suffix}`;
  await h.fakes.publishGo({ module: backdated, version: "v1.0.0", ageSeconds: 300 * DAY });
  for (const version of ["v1.0.0", "v1.1.0"]) await h.fakes.publishGo({ module: malModule, version, ageSeconds: 300 * DAY });
  await h.fakes.osvFlag({ ecosystem: "Go", name: malModule, version: "1.0.0", ids: ["MAL-2026-9201"] });
  await h.fakes.publishGo({ module: mixed, version: "v1.0.0-RC1", ageSeconds: 300 * DAY });
  await h.fakes.publishGo({ module: mixed, version: "v1.0.0", ageSeconds: 300 * DAY });
  await h.fakes.publishGo({ module: mixed, version: "v1.1.0", ageSeconds: HOUR });
  await h.fakes.publishGo({ module: undated, version: "v1.0.0", undated: true });

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key } = await h.createKey(admin.portal, "go-ci");
  const get = (path, headers = {}) => fetchWith(h, fw1, path, key, headers);
  const ok = (what, run) => expect(run.status === 0, `${what} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  const proxy = `https://key:${key}@fw1.e2e.test/go/`;
  const goRun = (script, { files = {}, auth = true } = {}) =>
    h.client(
      "client-go",
      `export HOME=$PWD/.home GOPATH=$PWD/.gopath GOMODCACHE=$PWD/.modcache GOCACHE=$PWD/.gocache GOSUMDB=off GOPROXY=${auth ? proxy : "https://fw1.e2e.test/go/"}; ${script}`,
      { files: { "go.mod": "module consumer.example/app\n\ngo 1.21\n", "main.go": "package main\n\nfunc main() {}\n", ...files } },
    );
  const since = new Date();

  // The keys page shows the Go lines next to npm, pip, RubyGems and Cargo.
  const created = await admin.portal.submit("/keys", "/keys", { name: "go-page" });
  expect(created.body.includes("export GOPROXY=https://key:prb_") && created.body.includes("@fw1.e2e.test/go/"), `the keys page shows the GOPROXY line: ${created.body.slice(0, 400)}`);
  expect(!/GOPROXY=[^\n]*(,direct|\|)/.test(created.body), "the keys page shows one protected proxy with no fallback");

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    await h.editPolicy(admin.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
    await h.waitFor("the freeze reaches firewall-1", async () => {
      const list = await get(`/go/${fresh}/@v/list`);
      return list.status === 200 && list.body === "v1.0.0\n";
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });

    // Authentication: without a key every Go read is 401.
    const anonymous = await h.request(`${fw1}/go/${fresh}/@v/list`, { headers: { connection: "close" } });
    expect(anonymous.status === 401, `an unauthenticated read is 401: ${anonymous.status}`);
    let run = goRun("go get " + `${fresh}@latest`, { auth: false });
    expect(run.status !== 0 && /401|Unauthorized|authentication/i.test(run.stdout + run.stderr), `go without a key is refused: ${run.status}\n${run.stdout}\n${run.stderr}`);

    // 1. go takes the old version, lists only it, builds it; the exact pin of the young one fails.
    run = goRun(
      `go get ${fresh}@latest && go list -m -versions ${fresh} && cat go.mod && printf 'package main\\n\\nimport _ "${fresh}"\\n\\nfunc main() {}\\n' > main.go && go build ./... && echo BUILT`,
    );
    ok("go get and build", run);
    expect(run.stdout.includes(`${fresh} v1.0.0\n`) && run.stdout.includes("BUILT"), `go lists and builds only v1.0.0:\n${run.stdout}`);
    expect(!run.stdout.includes("v1.1.0"), `the young version is not offered:\n${run.stdout}`);
    run = goRun(`go mod download ${fresh}@v1.1.0`);
    expect(run.status !== 0 && /403|Forbidden|held|eligible/i.test(run.stdout + run.stderr), `the exact pin of the young version fails: ${run.status}\n${run.stdout}\n${run.stderr}`);
    for (const ext of ["info", "mod", "zip"]) {
      const held = await get(`/go/${fresh}/@v/v1.1.0.${ext}`);
      expect(held.status === 403, `the young .${ext} is HELD (403): ${held.status} ${held.body.slice(0, 160)}`);
      const eligible = await get(`/go/${fresh}/@v/v1.0.0.${ext}`);
      expect(eligible.status === 200, `the eligible .${ext} is delivered: ${eligible.status}`);
    }
    const info = await get(`/go/${fresh}/@v/v1.0.0.info`);
    expect(info.json().Version === "v1.0.0" && /^\d{4}-\d\d-\d\dT[\d:]+Z$/.test(info.json().Time), `the info is the proxy's own: ${info.body}`);
    const latest = await get(`/go/${fresh}/@latest`);
    expect(latest.status === 200 && latest.json().Version === "v1.0.0", `@latest is the best allowed version: ${latest.status} ${latest.body}`);
    const zip = await get(`/go/${fresh}/@v/v1.0.0.zip`);
    expect(zip.status === 200 && zip.bytes.subarray(0, 4).toString("hex") === "504b0304", "the zip is a real module zip, delivered exactly");

    // 2. Pseudo-versions are not in any list: each is judged by its own .info.
    run = goRun(`go mod download -json ${pseudoModule}@${oldPseudo}`);
    ok("the old pseudo-version", run);
    run = goRun(`go mod download ${pseudoModule}@${youngPseudo}`);
    expect(run.status !== 0, `the young pseudo-version is refused: ${run.status}\n${run.stdout}\n${run.stderr}`);
    expect((await get(`/go/${pseudoModule}/@v/${youngPseudo}.zip`)).status === 403, "the young pseudo-version's zip is HELD");

    // 3. OSV: the MAL version is hidden.
    await h.waitFor("the MAL version leaves the list", async () => {
      const mal = await get(`/go/${malModule}/@v/list`);
      return mal.status === 200 && mal.body === "v1.1.0\n";
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    run = goRun(`go get ${malModule}@latest && cat go.mod`);
    ok("go of the OSV module", run);
    expect(run.stdout.includes(`${malModule} v1.1.0`), `go takes the unflagged version:\n${run.stdout}`);
    const queried = (await h.fakes.osvQueries()).some((q) => JSON.stringify(q).includes('"Go"') && JSON.stringify(q).includes(malModule));
    expect(queried, "the firewall asked OSV about the module under the ecosystem name Go");

    // 4. Mixed case: the wire form is !-escaped, the identity is the decoded path.
    const wire = escape(mixed);
    expect(wire !== mixed && wire.includes("!"), `the wire form is case-encoded: ${wire}`);
    const mixedList = await get(`/go/${wire}/@v/list`);
    expect(mixedList.status === 200 && mixedList.body === "v1.0.0-RC1\nv1.0.0\n", `the list names the real spellings, the young version is withheld:\n${mixedList.body}`);
    run = goRun(`go mod download -json ${mixed}@v1.0.0-RC1 && echo DOWNLOADED`);
    ok("the case-encoded module and prerelease", run);
    expect(run.stdout.includes("DOWNLOADED") && run.stdout.includes(`"Path": "${mixed}"`), `go downloaded the upper-case module and version:\n${run.stdout}`);
    expect((await get(`/go/${wire}/@v/${escape("v1.0.0-RC1")}.zip`)).status === 200, "the escaped prerelease zip is delivered");
    for (const wrong of [`/go/${mixed}/@v/list`, `/go/${wire}/@v/v1.0.0-RC1.zip`, `/go/${mixed.toLowerCase()}/@v/list`]) {
      expect((await get(wrong)).status === 404, `another spelling is no module of this proxy: ${wrong}`);
    }
    const policy = await h.policyPath(admin.portal);
    const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "go", name: mixed, what: "package", version: "" });
    expect(saved.status === 303, `the block is saved: ${saved.status}\n${saved.body}`);
    await h.waitFor("the block refuses the module", async () => (await get(`/go/${wire}/@v/list`)).status === 403, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    expect((await get(`/go/${wire}/@v/${escape("v1.0.0-RC1")}.zip`)).status === 403, "and its zip is refused");

    // 5. A version with no Time waits on first-seen (held for the whole cooldown, never dated by a cache).
    const undatedList = await get(`/go/${undated}/@v/list`);
    expect(undatedList.status === 200 && undatedList.body === "", `an undated version is withheld at first sight: ${undatedList.body}`);
    expect((await get(`/go/${undated}/@v/v1.0.0.zip`)).status === 403, "its zip is HELD");

    // 6. The checksum database route and the write refusals.
    const before = (await h.fakes.goSumdb()).length;
    const supported = await get("/go/sumdb/sum.golang.org/supported");
    expect(supported.status === 200 && supported.body === "", `the firewall forwards sumdb/supported: ${supported.status} ${supported.body}`);
    const lookup = await get(`/go/sumdb/sum.golang.org/lookup/${wire}@v1.0.0`);
    expect(lookup.status === 200 && lookup.body.includes(`${mixed} v1.0.0`), `lookup carries the decoded module: ${lookup.status} ${lookup.body}`);
    expect((await get("/go/sumdb/sum.golang.org/tile/8/0/x001/234.p/17")).status === 200, "a tile is forwarded");
    expect((await get("/go/sumdb/evil.example/latest")).status === 404, "another database name is 404");
    const seen = (await h.fakes.goSumdb()).slice(before);
    expect(seen.length === 3 && seen.every((r) => r.authorization === null), `the checksum database got three requests and no credential: ${JSON.stringify(seen)}`);
    const proxyCalls = (await h.fakes.requests("proxy.golang.org")).length;
    for (const [method, path] of [["PUT", `/go/${fresh}/@v/v1.0.0.zip`], ["POST", `/go/${fresh}/@v/v1.0.0.info`], ["DELETE", `/go/${fresh}/@v/v1.0.0.mod`]]) {
      for (const headers of [{ connection: "close" }, { connection: "close", authorization: `Bearer ${key}` }]) {
        const answer = await h.request(`${fw1}${path}`, { method, body: "x", headers });
        expect(answer.status === 405, `${method} ${path} (${headers.authorization ? "with" : "without"} a key) is no route of a managed firewall: ${answer.status}`);
      }
    }
    expect((await h.fakes.requests("proxy.golang.org")).length === proxyCalls, "no write reached the fake proxy");

    // The decision log names the refusals: the young version of the fresh module (403) and the blocked module.
    const dated = h.decisions("firewall-1", since).filter((d) => d.ecosystem === "go");
    expect(dated.some((d) => d.package === fresh && String(d.version).startsWith("v1.1.0") && String(d.status) === "403"), `a logged decision names the held ${fresh} v1.1.0: ${JSON.stringify(dated.slice(-6))}`);
    expect(dated.some((d) => d.package === wire && String(d.status) === "403"), `a logged decision names the blocked module in its wire spelling ${wire}`);
    await activityRow(h, admin.portal, { package: mixed });
    // 2b. Revision queries: `go get mod@main` and `mod@<commit>` resolve upstream, the RESOLVED pseudo-version is judged.
    run = goRun(`go get ${pseudoModule}@main && cat go.mod`);
    ok("go get @main", run);
    expect(run.stdout.includes(`${pseudoModule} ${oldPseudo}`), `@main resolves to the old pseudo-version:\n${run.stdout}`);
    run = goRun(`go get ${pseudoModule}@abcdef123456 && cat go.mod`);
    ok("go get @commit", run);
    expect(run.stdout.includes(`${pseudoModule} ${oldPseudo}`), `@commit resolves to the old pseudo-version:\n${run.stdout}`);
    run = goRun(`go get ${pseudoModule}@dev`);
    expect(run.status !== 0, `a branch that resolves to a young commit is held: ${run.status}\n${run.stdout}\n${run.stderr}`);
    expect((await get(`/go/${pseudoModule}/@v/dev.info`)).status === 403, "its revision .info is 403");
    expect((await get(`/go/${pseudoModule}/@v/Dev.info`)).status === 404, "an upper-case token is no revision");

    // 2c. A back-dated version appearing after the module's first list is held from its first sight (Time says 300 days).
    const first = await get(`/go/${backdated}/@v/list`);
    expect(first.status === 200 && first.body === "v1.0.0\n", `the first list: ${first.body}`);
    await h.fakes.publishGo({ module: backdated, version: "v1.0.1", ageSeconds: 300 * DAY });
    await new Promise((done) => setTimeout(done, 1500));
    const second = await get(`/go/${backdated}/@v/list`);
    expect(second.status === 200 && second.body === "v1.0.0\n", `the back-dated v1.0.1 is not listed: ${second.body}`);
    expect((await get(`/go/${backdated}/@v/v1.0.1.zip`)).status === 403, "its zip is HELD although its Time is 300 days old");
    expect((await get(`/go/${backdated}/@v/v1.0.0.zip`)).status === 200, "the version of the first list is served");
  } catch (error) {
    // Any failure keeps what decides a 5xx: the firewall's own decision lines (status, reason) of the whole run.
    const failed = h.decisions("firewall-1", since).filter((d) => Number(d.status) >= 500);
    error.message += `\nfirewall-1 decisions with status >= 500 since the start (${failed.length}): ${JSON.stringify(failed.slice(-10))}`;
    throw error;
  } finally {
    await restorePlatform();
  }
}
