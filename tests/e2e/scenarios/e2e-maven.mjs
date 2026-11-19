// E2E-maven: Maven through a managed firewall (row 21; docs/operations.md "Maven and Gradle clients").
//
// The fake Maven Central (fixtures/fakes/maven.mjs) answers as repo.maven.apache.org (the tree below /maven2/: metadata,
// POM, JAR, sources JAR, checksum sidecars, snapshot builds, plugin metadata and an archetype catalog, every file with the
// Last-Modified that dates its version). Maven 3.9.16 on Java 21 in the client container reads through firewall-1 (TLS via the
// gateway, the key as the Basic password the keys page shows), one mirror of everything and no other repository.
//
// 1. Under a 7-day platform freeze a version range takes the old version of an artifact whose newest is an hour old; the exact
//    pin of the young one fails and its POM, JAR, sources JAR and checksum files are all HELD (403) when asked for directly;
//    the metadata lists only the allowed versions, names the newest allowed as latest and release, and its checksum files
//    are the checksums of what was served.
// 2. Snapshots: the newest build is under the freeze, the pointer of the version-level metadata falls back to the older
//    build and a file of the young build is HELD.
// 3. OSV on: a version flagged MAL under ecosystem `Maven` (key `groupId:artifactId`) is hidden from the metadata.
// 4. Case is identity: a block written `org.e2e:Blocked` refuses that artifact id and not `blocked`.
// 5. A version whose files carry no Last-Modified waits on first-seen; the plugin group's metadata lists no blocked plugin;
//    the archetype catalog lists no blocked archetype.
// 6. A managed firewall refuses every write verb and nothing reaches the repository.
// Activity shows the refusals; the firewall's decision log names them.

import { activityRow, changePlatform, fetchWith, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-maven",
  title: "Maven through a managed firewall (metadata filter and checksums, file gate, snapshots, OSV, case identity, plugins, writes refused)",
  suites: ["pr", "nightly", "release"],
};

const DAY = 86_400;
const HOUR = 3_600;

export default async function maven(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  const suffix = h.unique("m").slice(2).replaceAll("_", "-");
  const group = `org.e2e${suffix.replaceAll("-", "")}`;
  const path = (g, a, ...rest) => `/maven/${g.replaceAll(".", "/")}/${a}${rest.length ? `/${rest.join("/")}` : ""}`;
  const lib = "lib";
  await h.fakes.publishMaven({ group, artifact: lib, version: "1.0", ageSeconds: 300 * DAY });
  await h.fakes.publishMaven({ group, artifact: lib, version: "1.1", ageSeconds: 200 * DAY });
  await h.fakes.publishMaven({ group, artifact: lib, version: "2.0", ageSeconds: HOUR });
  for (const version of ["1.0", "1.1"]) await h.fakes.publishMaven({ group, artifact: "mal", version, ageSeconds: 300 * DAY });
  await h.fakes.osvFlag({ ecosystem: "Maven", name: `${group}:mal`, version: "1.0", ids: ["MAL-2026-9401"] });
  await h.fakes.publishMaven({ group, artifact: "snap", version: "1.0-SNAPSHOT", build: "20250101.120000-1", ageSeconds: 300 * DAY });
  await h.fakes.publishMaven({ group, artifact: "snap", version: "1.0-SNAPSHOT", build: "20260401.120000-2", ageSeconds: HOUR });
  for (const artifact of ["Blocked", "blocked"]) await h.fakes.publishMaven({ group, artifact, version: "1.0", ageSeconds: 300 * DAY });
  await h.fakes.publishMaven({ group, artifact: "nodate", version: "1.0", undated: true });
  await h.fakes.publishMaven({ group: `${group}.plugins`, artifact: "good-maven-plugin", version: "1.0", ageSeconds: 300 * DAY });
  await h.fakes.publishMaven({ group: `${group}.plugins`, artifact: "evil-maven-plugin", version: "1.0", ageSeconds: 300 * DAY });
  await h.fakes.mavenPlugin({ group: `${group}.plugins`, name: "Good", prefix: "good", artifact: "good-maven-plugin" });
  await h.fakes.mavenPlugin({ group: `${group}.plugins`, name: "Evil", prefix: "evil", artifact: "evil-maven-plugin" });

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key } = await h.createKey(admin.portal, "maven-ci");
  const get = (p, headers = {}) => fetchWith(h, fw1, p, key, headers);
  const ok = (what, run) => expect(run.status === 0, `${what} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  const settings = (auth = true) =>
    `<settings><mirrors><mirror><id>probation</id><mirrorOf>*</mirrorOf><url>https://fw1.e2e.test/maven/</url></mirror></mirrors>${
      auth ? `<servers><server><id>probation</id><username>key</username><password>${key}</password></server></servers>` : ""
    }</settings>`;
  const project = (dependencies) =>
    `<project><modelVersion>4.0.0</modelVersion><groupId>e2e</groupId><artifactId>app</artifactId><version>1</version><packaging>pom</packaging><dependencies>${dependencies}</dependencies></project>`;
  const dependency = (artifact, version) => `<dependency><groupId>${group}</groupId><artifactId>${artifact}</artifactId><version>${version}</version></dependency>`;
  // Java reads its own trust store: the E2E CA goes into one, and the plugin repository is the seeded copy of the image.
  const mvn = (script, { dependencies = "", auth = true } = {}) =>
    h.client(
      "client-maven",
      `export HOME=$PWD/.home MAVEN_OPTS="-Djavax.net.ssl.trustStore=$PWD/.trust.jks -Djavax.net.ssl.trustStorePassword=changeit"; rm -rf .m2repo out .trust.jks; ` +
        `keytool -importcert -noprompt -alias e2e -file /e2e/ca/ca.pem -keystore .trust.jks -storepass changeit >/dev/null 2>&1; ` +
        `mkdir -p .m2repo && cp -r /opt/seed-m2/. .m2repo/ && ${script}`,
      { files: { "pom.xml": project(dependencies), "settings.xml": settings(auth) } },
    );
  const copy = "mvn -B -s settings.xml -Dmaven.repo.local=$PWD/.m2repo org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies -DoutputDirectory=out && ls out";
  const since = new Date();

  const created = await admin.portal.submit("/keys", "/keys", { name: "maven-page" });
  expect(created.body.includes("settings.xml") && created.body.includes("fw1.e2e.test/maven/"), `the keys page shows the Maven lines: ${created.body.slice(0, 400)}`);

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    await h.editPolicy(admin.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
    await h.waitFor("the freeze reaches firewall-1", async () => {
      const listing = await get(`${path(group, lib)}/maven-metadata.xml`);
      return listing.status === 200 && listing.body.includes("<version>1.1</version>") && !listing.body.includes("<version>2.0</version>");
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });

    // Authentication: without a key every Maven read is 401, and mvn without one is refused.
    const anonymous = await h.request(`${fw1}${path(group, lib)}/maven-metadata.xml`, { headers: { connection: "close" } });
    expect(anonymous.status === 401, `an unauthenticated read is 401: ${anonymous.status}`);
    let run = mvn(copy, { dependencies: dependency(lib, "1.0"), auth: false });
    expect(run.status !== 0 && /401|Unauthorized|status code: 401/i.test(run.stdout + run.stderr), `mvn without a key is refused: ${run.status}\n${run.stdout.slice(-600)}\n${run.stderr.slice(-300)}`);

    // 1. A range takes the newest ALLOWED version; the exact pin of the young one fails.
    run = mvn(copy, { dependencies: dependency(lib, "[1.0,3.0)") });
    ok("a version range", run);
    expect(run.stdout.includes(`${lib}-1.1.jar`) && !run.stdout.includes(`${lib}-2.0.jar`), `mvn takes only 1.1:\n${run.stdout.slice(-800)}`);
    run = mvn(copy, { dependencies: dependency(lib, "2.0") });
    expect(run.status !== 0 && /403|Forbidden|2\.0/.test(run.stdout + run.stderr), `the exact pin of the young version fails: ${run.status}\n${run.stdout.slice(-600)}`);
    const dir = path(group, lib);
    for (const file of [`${lib}-2.0.pom`, `${lib}-2.0.jar`, `${lib}-2.0-sources.jar`, `${lib}-2.0.jar.sha1`, `${lib}-2.0.pom.md5`]) {
      const held = await get(`${dir}/2.0/${file}`);
      expect(held.status === 403, `the young ${file} is HELD (403): ${held.status} ${held.body.slice(0, 160)}`);
    }
    for (const file of [`${lib}-1.0.pom`, `${lib}-1.0.jar`, `${lib}-1.0-sources.jar`, `${lib}-1.0.jar.sha1`]) {
      const eligible = await get(`${dir}/1.0/${file}`);
      expect(eligible.status === 200, `the eligible ${file} is delivered: ${eligible.status}`);
    }
    const jar = await get(`${dir}/1.0/${lib}-1.0.jar`);
    expect(jar.bytes.subarray(0, 4).toString("hex") === "504b0304", "the jar is a real zip, delivered exactly");
    const listing = await get(`${dir}/maven-metadata.xml`);
    expect(/<latest>1.1<\/latest>/.test(listing.body) && /<release>1.1<\/release>/.test(listing.body), `latest and release name the newest allowed: ${listing.body}`);
    const { createHash } = await import("node:crypto");
    for (const [ext, algorithm] of [["sha1", "sha1"], ["md5", "md5"], ["sha256", "sha256"], ["sha512", "sha512"]]) {
      const sum = await get(`${dir}/maven-metadata.xml.${ext}`);
      expect(sum.status === 200 && sum.body === createHash(algorithm).update(listing.bytes).digest("hex"), `${ext} of the metadata is the checksum of what was served: ${sum.status} ${sum.body.slice(0, 80)}`);
    }
    expect((await get(`${dir}/maven-metadata.xml.asc`)).status === 404, "a signature of the repository's bytes does not sign the filtered document");

    // 2. Snapshots: the young build is held, the pointer falls back to the old one.
    const snapDir = `${path(group, "snap")}/1.0-SNAPSHOT`;
    const snap = await get(`${snapDir}/maven-metadata.xml`);
    expect(snap.status === 200 && snap.body.includes("20250101.120000") && !snap.body.includes("20260401.120000") && /<buildNumber>1<\/buildNumber>/.test(snap.body), `the snapshot pointer falls back to the allowed build: ${snap.body}`);
    expect((await get(`${snapDir}/snap-1.0-20250101.120000-1.jar`)).status === 200, "the old build is delivered");
    expect((await get(`${snapDir}/snap-1.0-20260401.120000-2.jar`)).status === 403, "the young build is HELD");

    // 3. OSV: the MAL version is hidden.
    await h.waitFor("the MAL version leaves the metadata", async () => {
      const mal = await get(`${path(group, "mal")}/maven-metadata.xml`);
      return mal.status === 200 && !mal.body.includes("<version>1.0</version>") && mal.body.includes("<version>1.1</version>");
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    run = mvn(copy, { dependencies: dependency("mal", "[1.0,2.0)") });
    ok("mvn of the OSV artifact", run);
    expect(run.stdout.includes("mal-1.1.jar"), `mvn takes the unflagged version:\n${run.stdout.slice(-600)}`);
    const queried = (await h.fakes.osvQueries()).some((q) => JSON.stringify(q).includes('"Maven"') && JSON.stringify(q).includes(`${group}:mal`));
    expect(queried, "the firewall asked OSV about the coordinate under the ecosystem name Maven");

    // 4. Case is identity.
    const policy = await h.policyPath(admin.portal);
    const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "maven", name: `${group}:Blocked`, what: "package", version: "" });
    expect(saved.status === 303, `the block is saved: ${saved.status}\n${saved.body}`);
    await h.waitFor("the block refuses the artifact", async () => (await get(`${path(group, "Blocked")}/maven-metadata.xml`)).status === 403, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    expect((await get(`${path(group, "Blocked")}/1.0/Blocked-1.0.jar`)).status === 403, "its jar is refused");
    expect((await get(`${path(group, "blocked")}/1.0/blocked-1.0.jar`)).status === 200, "another case is another artifact, served");

    // 5. No Last-Modified: first-seen. Plugin prefixes and the archetype catalog follow the blocks.
    const nodate = await get(`${path(group, "nodate")}/maven-metadata.xml`);
    expect(nodate.status === 200 && !nodate.body.includes("<version>1.0</version>"), `an undated version waits on first-seen: ${nodate.body}`);
    expect((await get(`${path(group, "nodate")}/1.0/nodate-1.0.jar`)).status === 403, "its jar is HELD");
    await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "maven", name: `${group}.plugins:evil-maven-plugin`, what: "package", version: "" });
    await h.waitFor("the plugin block reaches firewall-1", async () => {
      const plugins = await get(`/maven/${`${group}.plugins`.replaceAll(".", "/")}/maven-metadata.xml`);
      return plugins.status === 200 && plugins.body.includes("good-maven-plugin") && !plugins.body.includes("evil-maven-plugin");
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    const catalog = await get("/maven/archetype-catalog.xml");
    expect(catalog.status === 200 && catalog.body.includes("<archetype-catalog>") && !catalog.body.includes(`<artifactId>Blocked</artifactId>`), `the archetype catalog lists no blocked artifact: ${catalog.status}`);

    // 6. The write verbs are no route of a managed firewall, and nothing reaches the repository.
    const before = (await h.fakes.requests("repo.maven.apache.org")).length;
    for (const [method, p] of [["PUT", `${dir}/1.0/${lib}-1.0.jar`], ["DELETE", `${dir}/1.0/${lib}-1.0.jar`], ["POST", `${dir}/maven-metadata.xml`], ["PUT", `${dir}/maven-metadata.xml`]]) {
      for (const headers of [{ connection: "close" }, { connection: "close", authorization: `Bearer ${key}` }]) {
        const answer = await h.request(`${fw1}${p}`, { method, body: "x", headers });
        expect(answer.status === 405, `${method} ${p} (${headers.authorization ? "with" : "without"} a key) is no route of a managed firewall: ${answer.status}`);
      }
    }
    expect((await h.fakes.requests("repo.maven.apache.org")).length === before && (await h.fakes.mavenWrites()).length === 0, "no write reached the fake repository");

    const dated = h.decisions("firewall-1", since).filter((d) => d.ecosystem === "maven");
    expect(dated.some((d) => d.package === `${group}:${lib}` && String(d.version).startsWith("2.0") && String(d.status) === "403"), `a logged decision names the held ${group}:${lib} 2.0: ${JSON.stringify(dated.slice(-6))}`);
    expect(dated.some((d) => d.package === `${group}:Blocked` && String(d.status) === "403"), `a logged decision names the blocked artifact`);
    await activityRow(h, admin.portal, { package: `${group}:Blocked` });
  } catch (error) {
    const failed = h.decisions("firewall-1", since).filter((d) => Number(d.status) >= 500);
    error.message += `\nfirewall-1 decisions with status >= 500 since the start (${failed.length}): ${JSON.stringify(failed.slice(-10))}`;
    throw error;
  } finally {
    await restorePlatform();
  }
}
