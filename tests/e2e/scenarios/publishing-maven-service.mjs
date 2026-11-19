// E2E-publishing-maven-service: `mvn deploy` through the shared service (row 21, class W like `gem push`, `cargo publish`
// and `dotnet nuget push`). The service org owns a Maven registry whose target is the fake Maven Central's tree; the real
// `mvn deploy:deploy-file` (a jar with its POM) sends the caller's own Basic credential, the firewall forwards each PUT (the jar,
// the POM, every checksum, maven-metadata.xml) to the registry's own origin with that credential and nothing of the service
// key, and a write without a credential is answered with the Basic challenge Maven waits for, before any upstream request.
// Reads of the same registry (a dependency resolution) go through the same service.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export const meta = { id: "E2E-publishing-maven-service", title: "mvn deploy and a dependency resolution through the shared service", suites: ["release"], stack: "own" };

export default async function mavenServicePublishing(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service Maven", ecosystem: "maven", target_url: "https://repo.maven.apache.org/maven2/",
  })).status === 303, "service Maven registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Service Maven maven/)?.[1];
  h.expect(id, "the Maven registry has an ID");
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "maven-service", attach: "org" });
  h.expect(issued.status === 200, "service policy key issued");
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${serviceKey}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  const root = `https://fw-standalone.e2e.test/registry/maven/${id}/`;
  await h.waitFor("the Maven registry is loaded", async () => (await h.request(`${root}org/e2e/seed/maven-metadata.xml`)).status === 200, { timeout: 30_000 });

  const writes = async () => await h.fakes.mavenWrites();
  const basic = (user, password) => `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}`;
  const name = `pub${h.unique("mv").replace(/[^A-Za-z0-9]/g, "").toLowerCase()}`;
  const tree = `org/e2e/${name}`;

  // No credential: every write is answered with the challenge Maven waits for, nothing reaches the registry.
  const before = (await writes()).length;
  const requestsBefore = (await h.fakes.requests("repo.maven.apache.org")).length;
  for (const method of ["PUT", "DELETE"]) {
    const answer = await h.request(`${root}${tree}/1.0/${name}-1.0.jar`, { method, body: "x", headers: { "content-type": "application/octet-stream", connection: "close" } });
    h.expect(answer.status === 401 && /^Basic/.test(answer.headers["www-authenticate"] ?? ""), `${method} without a credential is challenged with 401 and Basic, got ${answer.status}`);
  }
  h.expect((await writes()).length === before && (await h.fakes.requests("repo.maven.apache.org")).length === requestsBefore, "a challenged write made no upstream request");

  const trust = `keytool -importcert -noprompt -alias e2e -file /e2e/ca/ca.pem -keystore .trust.jks -storepass changeit >/dev/null 2>&1`;
  const dir = `/work/${h.unique("maven-pub")}`;
  // The mirror carries the id the image's seeded plugins were fetched under (`probation`), so they count as already downloaded.
  const settings = (user, password) => `<settings><mirrors><mirror><id>probation</id><mirrorOf>*,!svc</mirrorOf><url>https://fw-standalone.e2e.test/maven/</url></mirror></mirrors><servers><server><id>svc</id><username>${user}</username><password>${password}</password></server></servers></settings>`;
  const pom = `<project><modelVersion>4.0.0</modelVersion><groupId>org.e2e</groupId><artifactId>${name}</artifactId><version>1.0</version></project>`;
  const deploy = (user, password) => h.client("client-maven", `export HOME=$PWD/.home MAVEN_OPTS="-Djavax.net.ssl.trustStore=$PWD/.trust.jks -Djavax.net.ssl.trustStorePassword=changeit"; rm -rf .m2repo .trust.jks; ${trust}; mkdir -p .m2repo && cp -r /opt/seed-m2/. .m2repo/ && printf 'jar bytes' > lib.jar && mvn -B -s settings.xml -Dmaven.repo.local=$PWD/.m2repo org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy-file -Dfile=lib.jar -DpomFile=pom.xml -Durl=${root} -DrepositoryId=svc`, {
    dir,
    files: { "pom.xml": pom, "settings.xml": settings(user, password) },
  });

  // `mvn deploy:deploy-file` sends the caller's own credential: the challenge first, then every file.
  let run = deploy("e2e-owner", "e2e-pass");
  h.expect(run.status === 0 && /BUILD SUCCESS/.test(run.stdout), `mvn deploy with the owner credential: ${run.status}\n${run.stdout.slice(-800)}${run.stderr.slice(-300)}`);
  const sent = (await writes()).filter((w) => w.authorization === basic("e2e-owner", "e2e-pass"));
  const paths = sent.map((w) => w.path);
  for (const want of [`/maven2/${tree}/1.0/${name}-1.0.jar`, `/maven2/${tree}/1.0/${name}-1.0.jar.sha1`, `/maven2/${tree}/1.0/${name}-1.0.pom`, `/maven2/${tree}/maven-metadata.xml`]) {
    h.expect(paths.includes(want), `the registry received ${want}: ${paths.join(", ")}`);
  }
  const jar = sent.find((w) => w.path === `/maven2/${tree}/1.0/${name}-1.0.jar`);
  h.expect(jar.method === "PUT" && jar.bytes === "jar bytes".length, `the jar arrived whole: ${JSON.stringify(jar)}`);

  // The registry's refusal (403) is the caller's answer.
  run = deploy("e2e-denied", "x");
  h.expect(run.status !== 0 && /403|Forbidden|not authori[sz]ed/i.test(run.stdout + run.stderr), `the upstream 403 is passed on: ${run.status}\n${run.stdout.slice(-400)}`);

  // The service key never reaches the registry; an unknown registry makes no upstream call.
  const all = await writes();
  h.expect(all.every((w) => !String(w.authorization ?? "").includes(serviceKey) && !Buffer.from(String(w.authorization ?? "").replace(/^Basic /, ""), "base64").toString().includes(serviceKey)), "the service key was never forwarded");
  const count = (await h.fakes.requests("repo.maven.apache.org")).length;
  const wrong = await h.request(`https://fw-standalone.e2e.test/registry/maven/999999/${tree}/1.0/${name}-1.0.jar`, { method: "PUT", body: "x", headers: { authorization: basic("e2e-owner", "e2e-pass"), connection: "close" } });
  h.expect(wrong.status === 404 && (await h.fakes.requests("repo.maven.apache.org")).length === count, `an unknown Maven registry answers 404 with no upstream call: ${wrong.status}`);

  // Reads of the same registry go through the same service: a dependency resolution of an old artifact.
  await h.fakes.publishMaven({ group: "org.e2e", artifact: "svc-read", version: "1.0", ageSeconds: 400 * 86_400 });
  const resolve = h.client("client-maven", `export HOME=$PWD/.home MAVEN_OPTS="-Djavax.net.ssl.trustStore=$PWD/.trust.jks -Djavax.net.ssl.trustStorePassword=changeit"; rm -rf .m2repo out .trust.jks; ${trust}; mkdir -p .m2repo && cp -r /opt/seed-m2/. .m2repo/ && mvn -B -s settings.xml -Dmaven.repo.local=$PWD/.m2repo org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies -DoutputDirectory=out && ls out`, {
    dir: `${dir}-read`,
    files: {
      "pom.xml": `<project><modelVersion>4.0.0</modelVersion><groupId>e2e</groupId><artifactId>app</artifactId><version>1</version><packaging>pom</packaging><dependencies><dependency><groupId>org.e2e</groupId><artifactId>svc-read</artifactId><version>1.0</version></dependency></dependencies></project>`,
      "settings.xml": `<settings><mirrors><mirror><id>probation</id><mirrorOf>*</mirrorOf><url>https://fw-standalone.e2e.test/maven/</url></mirror></mirrors></settings>`,
    },
  });
  h.expect(resolve.status === 0 && resolve.stdout.includes("svc-read-1.0.jar"), `a dependency resolution through the shared service: ${resolve.status}\n${resolve.stdout.slice(-600)}\n${resolve.stderr.slice(-300)}`);
}
