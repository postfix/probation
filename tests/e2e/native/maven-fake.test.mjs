// The fake Maven Central (fixtures/fakes/maven.mjs): the layout, dated files, checksum sidecars, snapshot metadata, plugin
// metadata, the archetype catalog and the deploy endpoint.
// node tests/e2e/native/maven-fake.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Maven, order } from "../fixtures/fakes/maven.mjs";

const fake = new Maven();
const get = (path, headers = {}) => fake.handle({ method: "GET", headers }, path, "repo.maven.apache.org", Buffer.alloc(0));
const text = (answer) => Buffer.from(answer.body).toString();

assert.ok(order("1.9", "1.10") < 0 && order("2.0", "1.10") > 0 && order("1.0", "1.0.1") < 0 && order("1.0-SNAPSHOT", "1.0") === 0, "version order");

fake.publish({ group: "org.demo", artifact: "lib", version: "1.0", ageSeconds: 400 * 86_400 });
fake.publish({ group: "org.demo", artifact: "lib", version: "1.1", ageSeconds: 3600 });
fake.publish({ group: "org.demo", artifact: "Cased", version: "1.0", ageSeconds: 400 * 86_400 });
fake.publish({ group: "org.demo", artifact: "nodate", version: "1.0", undated: true });
fake.publish({ group: "org.demo", artifact: "snap", version: "1.0-SNAPSHOT", build: "20260101.120000-1", ageSeconds: 400 * 86_400 });
fake.publish({ group: "org.demo", artifact: "snap", version: "1.0-SNAPSHOT", build: "20260102.120000-2", ageSeconds: 3600 });
fake.plugin({ group: "org.demo.plugins", name: "Demo", prefix: "demo", artifact: "demo-maven-plugin" });

const metadata = text(get("/maven2/org/demo/lib/maven-metadata.xml"));
assert.match(metadata, /<latest>1.1<\/latest>[\s\S]*<release>1.1<\/release>[\s\S]*<version>1.0<\/version>\s*<version>1.1<\/version>/);
const pom = get("/maven2/org/demo/lib/1.0/lib-1.0.pom");
assert.equal(pom.status, 200);
assert.ok(Date.now() - Date.parse(pom.headers["last-modified"]) > 399 * 86_400_000, "a file carries the publication time as Last-Modified");
assert.equal(get("/maven2/org/demo/nodate/1.0/nodate-1.0.pom").headers["last-modified"], undefined, "undated: no header");
const jar = get("/maven2/org/demo/lib/1.0/lib-1.0.jar");
assert.equal(jar.body.subarray(0, 4).toString("hex"), "504b0304", "a real zip");
for (const [algorithm, ext] of [["sha1", "sha1"], ["md5", "md5"], ["sha256", "sha256"], ["sha512", "sha512"]]) {
  assert.equal(text(get(`/maven2/org/demo/lib/1.0/lib-1.0.jar.${ext}`)), createHash(algorithm).update(jar.body).digest("hex"), ext);
}
assert.equal(get("/maven2/org/demo/lib/1.0/lib-1.0-sources.jar").status, 200);
assert.equal(get("/maven2/org/demo/lib/1.0/lib-2.0.jar").status, 404);
assert.equal(get("/maven2/org/demo/cased/1.0/cased-1.0.jar").status, 404, "artifact ids are case-exact");
assert.equal(get("/maven2/org/demo/Cased/1.0/Cased-1.0.jar").status, 200);

const snapshot = text(get("/maven2/org/demo/snap/1.0-SNAPSHOT/maven-metadata.xml"));
assert.match(snapshot, /<timestamp>20260102.120000<\/timestamp>\s*<buildNumber>2<\/buildNumber>/);
assert.equal(get("/maven2/org/demo/snap/1.0-SNAPSHOT/snap-1.0-20260101.120000-1.pom").status, 200);
assert.equal(get("/maven2/org/demo/snap/1.0-SNAPSHOT/snap-1.0-20260103.120000-3.pom").status, 404);
assert.match(text(get("/maven2/org/demo/plugins/maven-metadata.xml")), /<artifactId>demo-maven-plugin<\/artifactId>/);
assert.match(text(get("/maven2/archetype-catalog.xml")), /<archetype-catalog>[\s\S]*<artifactId>lib<\/artifactId>/);

// The deploy endpoint records every call and answers by credential.
const put = (authorization, path = "/maven2/org/demo/lib/2.0/lib-2.0.jar") => fake.handle({ method: "PUT", headers: authorization ? { authorization } : {} }, path, "repo.maven.apache.org", Buffer.from("x"));
assert.equal(put(null).status, 401);
assert.match(put(null).headers["www-authenticate"], /^Basic/);
assert.equal(put(`Basic ${Buffer.from("e2e-denied:x").toString("base64")}`).status, 403);
assert.equal(put(`Basic ${Buffer.from("e2e-owner:e2e-pass").toString("base64")}`).status, 201);
assert.equal(fake.writes.length, 4);
assert.equal(fake.writes[3].bytes, 1);
console.log("maven-fake.test: ok");
