// E2E-nuget NuGet through a managed firewall (row 20; docs/operations.md "NuGet clients").
//
// The fake NuGet.org (fixtures/fakes/nuget.mjs) answers as api.nuget.org (service index, flat container,
// gzip registration with linked pages for a large package, vulnerability database, repository signatures),
// azuresearch-usnc.nuget.org (search) and www.nuget.org (publish). The .NET SDK 8.0.416 in the client
// container reads through firewall-1 (TLS via the gateway, the key as the source's password the keys page
// shows), one protected source and no fallback.
//
// 1. Under a 7-day platform freeze a floating restore takes the old version of a package whose newest is an
//    hour old; the exact pin of the young one fails and its four files (`.nupkg`, `.nuspec`, readme, icon)
//    are all HELD (403) when asked for directly; `dotnet list package --outdated` (registration) offers
//    only the allowed version.
// 2. Registration: every page inline, young leaves removed, every URL a route of the firewall, a large
//    package with linked pages complete, a package the registration lags on or has unlisted waits on
//    first-seen.
// 3. OSV on: a version flagged MAL under ecosystem `NuGet` is hidden from the flat container.
// 4. A package published `E2E.Mixed-...`: every URL is lower case, another spelling is 404, and a block
//    written with capitals hides it.
// 5. Search and autocomplete show only allowed versions; the vulnerability database and the repository
//    signature index are served through the firewall (`dotnet list package --vulnerable`).
// 6. A managed firewall refuses every write verb and nothing reaches www.nuget.org.
// Activity shows the refusals; the firewall's decision log names them.

import { activityRow, changePlatform, fetchWith, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-nuget",
  title: "NuGet through a managed firewall (flat container and registration filter, nupkg/nuspec gate, OSV, mixed case, search, vulnerabilities)",
  suites: ["pr", "nightly", "release"],
};

const DAY = 86_400;
const HOUR = 3_600;

export default async function nuget(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  const suffix = h.unique("n").slice(2).replaceAll("_", "-");
  const fresh = `e2e.fresh-${suffix}`;
  const malId = `e2e.mal-${suffix}`;
  const mixed = `E2E.Mixed-${suffix}`;
  const lagging = `e2e.lagging-${suffix}`;
  const unlisted = `e2e.unlisted-${suffix}`;
  const big = `e2e.big-${suffix}`;
  const vulnerable = `e2e.vuln-${suffix}`;
  await h.fakes.publishNuGet({ id: fresh, version: "1.0.0", ageSeconds: 300 * DAY });
  await h.fakes.publishNuGet({ id: fresh, version: "1.1.0", ageSeconds: HOUR });
  for (const version of ["1.0.0", "1.1.0"]) await h.fakes.publishNuGet({ id: malId, version, ageSeconds: 300 * DAY });
  await h.fakes.osvFlag({ ecosystem: "NuGet", name: malId, version: "1.0.0", ids: ["MAL-2026-9301"] });
  await h.fakes.publishNuGet({ id: mixed, version: "1.0.0-Beta.1", ageSeconds: 300 * DAY });
  await h.fakes.publishNuGet({ id: mixed, version: "1.0.0", ageSeconds: 300 * DAY });
  await h.fakes.publishNuGet({ id: mixed, version: "1.1.0.0", ageSeconds: HOUR });
  await h.fakes.publishNuGet({ id: lagging, version: "1.0.0", ageSeconds: 300 * DAY, inRegistration: false });
  await h.fakes.publishNuGet({ id: unlisted, version: "1.0.0", ageSeconds: 300 * DAY, unlisted: true });
  for (let n = 0; n < 130; n += 1) await h.fakes.publishNuGet({ id: big, version: `1.0.${n}`, ageSeconds: 300 * DAY });
  await h.fakes.publishNuGet({ id: vulnerable, version: "1.5.0", ageSeconds: 300 * DAY });
  await h.fakes.nugetVulnerability({ id: vulnerable, range: "[1.0.0, 2.0.0)" });

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key } = await h.createKey(admin.portal, "nuget-ci");
  const get = (path, headers = {}) => fetchWith(h, fw1, path, key, headers);
  const ok = (what, run) => expect(run.status === 0, `${what} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  const config = (auth = true) =>
    `<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /><add key="probation" value="https://fw1.e2e.test/nuget/v3/index.json" protocolVersion="3" /></packageSources>${
      auth ? `<packageSourceCredentials><probation><add key="Username" value="key" /><add key="ClearTextPassword" value="${key}" /></probation></packageSourceCredentials>` : ""
    }</configuration>`;
  const project = (references, audit = false) =>
    `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><NuGetAudit>${audit}</NuGetAudit></PropertyGroup><ItemGroup>${references}</ItemGroup></Project>`;
  const dotnet = (script, { references, auth = true, audit = false } = {}) =>
    h.client(
      "client-nuget",
      `export HOME=$PWD/.home DOTNET_CLI_HOME=$PWD/.home NUGET_PACKAGES=$PWD/.packages NUGET_HTTP_CACHE_PATH=$PWD/.httpcache; ${script}`,
      { files: { "app.csproj": project(references, audit), "nuget.config": config(auth) } },
    );
  const since = new Date();

  // The keys page shows the NuGet lines next to npm, pip, RubyGems, Cargo and Go.
  const created = await admin.portal.submit("/keys", "/keys", { name: "nuget-page" });
  expect(created.body.includes("dotnet nuget add source") && created.body.includes("fw1.e2e.test/nuget/v3/index.json"), `the keys page shows the NuGet lines: ${created.body.slice(0, 400)}`);

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    await h.editPolicy(admin.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
    await h.waitFor("the freeze reaches firewall-1", async () => {
      const list = await get(`/nuget/v3-flatcontainer/${fresh}/index.json`);
      return list.status === 200 && JSON.stringify(list.json().versions) === '["1.0.0"]';
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });

    // Authentication: without a key every NuGet read is 401, and dotnet without one is refused.
    const anonymous = await h.request(`${fw1}/nuget/v3/index.json`, { headers: { connection: "close" } });
    expect(anonymous.status === 401, `an unauthenticated read is 401: ${anonymous.status}`);
    let run = dotnet("dotnet restore", { references: `<PackageReference Include="${fresh}" Version="1.0.0" />`, auth: false });
    expect(run.status !== 0 && /401|Unauthorized|NU1301/i.test(run.stdout + run.stderr), `dotnet without a key is refused: ${run.status}\n${run.stdout}\n${run.stderr}`);

    // 1. A floating restore takes the old version; the exact pin of the young one fails.
    run = dotnet("dotnet restore -v n && cat obj/project.assets.json", { references: `<PackageReference Include="${fresh}" Version="*" />` });
    ok("a floating restore", run);
    expect(run.stdout.includes(`${fresh}/1.0.0`) && !run.stdout.includes(`${fresh}/1.1.0`), `dotnet restores only 1.0.0:\n${run.stdout}`);
    run = dotnet("dotnet restore", { references: `<PackageReference Include="${fresh}" Version="1.1.0" />` });
    expect(run.status !== 0 && /NU1102|NU1101|403|Forbidden|1\.1\.0/.test(run.stdout + run.stderr), `the exact pin of the young version fails: ${run.status}\n${run.stdout}\n${run.stderr}`);
    const flat = `/nuget/v3-flatcontainer/${fresh}`;
    for (const [version, file] of [["1.1.0", `${fresh}.1.1.0.nupkg`], ["1.1.0", `${fresh}.nuspec`], ["1.1.0", "readme"], ["1.1.0", "icon"]]) {
      const held = await get(`${flat}/${version}/${file}`);
      expect(held.status === 403, `the young ${file} is HELD (403): ${held.status} ${held.body.slice(0, 160)}`);
    }
    for (const file of [`${fresh}.1.0.0.nupkg`, `${fresh}.nuspec`, "readme", "icon"]) {
      const eligible = await get(`${flat}/1.0.0/${file}`);
      expect(eligible.status === 200, `the eligible ${file} is delivered: ${eligible.status}`);
    }
    const nupkg = await get(`${flat}/1.0.0/${fresh}.1.0.0.nupkg`);
    expect(nupkg.bytes.subarray(0, 4).toString("hex") === "504b0304", "the nupkg is a real zip, delivered exactly");
    // Outdated (registration): the newest the firewall offers is 1.0.0, never the held 1.1.0.
    run = dotnet("dotnet restore && dotnet list package --outdated", { references: `<PackageReference Include="${fresh}" Version="1.0.0" />` });
    ok("dotnet list package --outdated", run);
    expect(!run.stdout.includes("1.1.0"), `the held version is never offered as an update:\n${run.stdout}`);

    // 2. Registration: young leaves removed, every URL a route of the firewall, linked pages complete.
    const reg = await get(`/nuget/v3/registration/${fresh}/index.json`);
    const leaves = reg.json().items.flatMap((page) => page.items);
    expect(reg.status === 200 && leaves.length === 1 && leaves[0].catalogEntry.version === "1.0.0", `registration lists only 1.0.0: ${reg.status} ${reg.body.slice(0, 300)}`);
    expect(leaves[0].packageContent === `https://fw1.e2e.test/nuget/v3-flatcontainer/${fresh}/1.0.0/${fresh}.1.0.0.nupkg`, `packageContent is a route of the firewall: ${leaves[0].packageContent}`);
    expect(!reg.body.includes("api.nuget.org"), "no URL of the registry survives, catalog identifiers and dependency links included");
    expect((await get(`/nuget/v3/registration/${fresh}/1.1.0.json`)).status === 403 && (await get(`/nuget/v3/registration/${fresh}/1.0.0.json`)).status === 200, "the leaf of the young version is HELD, the old one served");
    // The registry linked its pages; so does the firewall, to a route of its own: no leaf is inline, every page is there.
    const bigReg = await get(`/nuget/v3/registration/${big}/index.json`);
    const bigPages = bigReg.json().items;
    expect(bigReg.status === 200 && bigPages.length > 1 && bigPages.every((page) => page.items === undefined && page["@id"].startsWith(`https://fw1.e2e.test/nuget/v3/registration/${big}/page/`)), `a large package's pages are linked to the firewall: ${bigReg.status} ${bigReg.body.slice(0, 300)}`);
    let bigLeaves = 0;
    for (const page of bigPages) {
      const body = await get(new URL(page["@id"]).pathname);
      expect(body.status === 200 && body.json().items.length === page.count, `a linked page is served whole: ${page["@id"]} ${body.status}`);
      bigLeaves += body.json().items.length;
    }
    expect(bigLeaves === 130, `a large package's linked pages hold all 130 versions: ${bigLeaves}`);
    run = dotnet("dotnet restore && cat obj/project.assets.json", { references: `<PackageReference Include="${big}" Version="*" />` });
    ok("a floating restore of a large package", run);
    expect(run.stdout.includes(`${big}/1.0.129`), `dotnet takes the highest of 130 versions:\n${run.stdout.slice(0, 600)}`);
    for (const [id, what] of [[lagging, "registration does not name"], [unlisted, "registration lists as unlisted"]]) {
      const listed = await get(`/nuget/v3-flatcontainer/${id}/index.json`);
      expect(listed.status === 200 && listed.json().versions.length === 0, `a version ${what} waits on first-seen: ${listed.body}`);
      expect((await get(`/nuget/v3-flatcontainer/${id}/1.0.0/${id}.1.0.0.nupkg`)).status === 403, `its nupkg is HELD (${what})`);
    }

    // 3. OSV: the MAL version is hidden.
    await h.waitFor("the MAL version leaves the list", async () => {
      const mal = await get(`/nuget/v3-flatcontainer/${malId}/index.json`);
      return mal.status === 200 && JSON.stringify(mal.json().versions) === '["1.1.0"]';
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    run = dotnet("dotnet restore && cat obj/project.assets.json", { references: `<PackageReference Include="${malId}" Version="*" />` });
    ok("dotnet of the OSV package", run);
    expect(run.stdout.includes(`${malId}/1.1.0`), `dotnet takes the unflagged version:\n${run.stdout.slice(0, 600)}`);
    const queried = (await h.fakes.osvQueries()).some((q) => JSON.stringify(q).includes('"NuGet"') && JSON.stringify(q).includes(malId));
    expect(queried, "the firewall asked OSV about the package under the ecosystem name NuGet, lower case");

    // 4. Mixed case: every URL is lower case; a block written with capitals hides it.
    const lower = mixed.toLowerCase();
    const mixedList = await get(`/nuget/v3-flatcontainer/${lower}/index.json`);
    expect(mixedList.status === 200 && JSON.stringify(mixedList.json().versions) === '["1.0.0-beta.1","1.0.0"]', `the list names the normalised versions, the young one is withheld: ${mixedList.body}`);
    run = dotnet("dotnet restore && cat obj/project.assets.json", { references: `<PackageReference Include="${mixed}" Version="1.0.0-Beta.1" />` });
    ok("the mixed-case package and prerelease", run);
    for (const wrong of [`/nuget/v3-flatcontainer/${mixed}/index.json`, `/nuget/v3-flatcontainer/${lower}/1.1.0.0/${lower}.1.1.0.0.nupkg`, `/nuget/v3-flatcontainer/${lower}/1.0.0-Beta.1/${lower}.1.0.0-Beta.1.nupkg`]) {
      expect((await get(wrong)).status === 404, `another spelling is no package of this firewall: ${wrong}`);
    }
    const policy = await h.policyPath(admin.portal);
    const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "nuget", name: mixed, what: "package", version: "" });
    expect(saved.status === 303, `the block is saved: ${saved.status}\n${saved.body}`);
    await h.waitFor("the block refuses the package", async () => (await get(`/nuget/v3-flatcontainer/${lower}/index.json`)).status === 403, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    expect((await get(`/nuget/v3-flatcontainer/${lower}/1.0.0/${lower}.1.0.0.nupkg`)).status === 403, "and its nupkg is refused");
    expect((await get(`/nuget/v3/registration/${lower}/index.json`)).status === 403, "and its registration");

    // 5. Search and autocomplete: only allowed versions; the vulnerability database and the signatures.
    const search = await get(`/nuget/v3/query?q=${fresh}&take=10&prerelease=true&semVerLevel=2.0.0`);
    const hit = search.json().data.find((item) => item.id === fresh);
    expect(search.status === 200 && hit && JSON.stringify(hit.versions.map((v) => v.version)) === '["1.0.0"]' && hit.version === "1.0.0", `search shows only the allowed version: ${search.status} ${search.body.slice(0, 400)}`);
    expect(hit.registration === `https://fw1.e2e.test/nuget/v3/registration/${fresh}/index.json`, `a search result points at the firewall: ${hit.registration}`);
    const auto = await get(`/nuget/v3/autocomplete?id=${fresh}&prerelease=true`);
    expect(JSON.stringify(auto.json().data) === '["1.0.0"]', `autocomplete of versions shows only the allowed one: ${auto.body}`);
    expect(!(await get(`/nuget/v3/autocomplete?q=e2e.mixed`)).body.toLowerCase().includes(lower), "autocomplete of ids hides a blocked package");
    run = dotnet("dotnet restore -v n && dotnet list package --vulnerable", { references: `<PackageReference Include="${vulnerable}" Version="1.5.0" />`, audit: true });
    expect(/GHSA-e2e/.test(run.stdout + run.stderr), `NuGetAudit and dotnet list --vulnerable use the firewall's vulnerability database:\n${run.stdout}\n${run.stderr}`);
    const signatures = await get("/nuget/v3/repository-signatures/5.0.0/index.json");
    const cert = signatures.json().signingCertificates[0];
    expect(signatures.status === 200 && cert.contentUrl.startsWith("https://fw1.e2e.test/nuget/v3/repository-signatures/certificates/"), `the signature index points at the firewall: ${signatures.body.slice(0, 300)}`);
    expect((await get(new URL(cert.contentUrl).pathname)).status === 200, "the certificate is served through the firewall");

    // 6. The write verbs are no route of a managed firewall, and nothing reaches the publish host.
    const before = (await h.fakes.requests("www.nuget.org")).length;
    for (const [method, path] of [["PUT", "/nuget/api/v2/package"], ["PUT", "/nuget/api/v2/symbolpackage"], ["DELETE", `/nuget/api/v2/package/${fresh}/1.0.0`], ["POST", `/nuget/api/v2/package/${fresh}/1.0.0`], ["PUT", `${flat}/1.0.0/${fresh}.1.0.0.nupkg`]]) {
      for (const headers of [{ connection: "close" }, { connection: "close", authorization: `Bearer ${key}`, "x-nuget-apikey": "e2e-owner-key" }]) {
        const answer = await h.request(`${fw1}${path}`, { method, body: "x", headers });
        expect(answer.status === 405, `${method} ${path} (${headers.authorization ? "with" : "without"} a key) is no route of a managed firewall: ${answer.status}`);
      }
    }
    expect((await h.fakes.requests("www.nuget.org")).length === before && (await h.fakes.nugetWrites()).length === 0, "no write reached the fake publish host");

    // The decision log names the refusals: the young version of the fresh package (403) and the blocked package.
    const dated = h.decisions("firewall-1", since).filter((d) => d.ecosystem === "nuget");
    expect(dated.some((d) => d.package === fresh && String(d.version).startsWith("1.1.0") && String(d.status) === "403"), `a logged decision names the held ${fresh} 1.1.0: ${JSON.stringify(dated.slice(-6))}`);
    expect(dated.some((d) => d.package === lower && String(d.status) === "403"), `a logged decision names the blocked package ${lower}`);
    await activityRow(h, admin.portal, { package: lower });
  } catch (error) {
    // Any failure keeps what decides a 5xx: the firewall's own decision lines (status, reason) of the whole run.
    const failed = h.decisions("firewall-1", since).filter((d) => Number(d.status) >= 500);
    error.message += `\nfirewall-1 decisions with status >= 500 since the start (${failed.length}): ${JSON.stringify(failed.slice(-10))}`;
    throw error;
  } finally {
    await restorePlatform();
  }
}
