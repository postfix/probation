// The fake ConanCenter (fixtures/fakes/conan.mjs): the capability probe, login, search, revision lists newest first with +0000 times, file
// lists with empty values, the binary search, and the upload endpoint that records every write and answers by token.
// node tests/e2e/native/conan-fake.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Conan } from "../fixtures/fakes/conan.mjs";

const fake = new Conan();
const host = "center2.conan.io";
const call = (method, path, headers = {}, body = Buffer.alloc(0)) => fake.handle({ method, headers }, path, host, body);
const json = (answer) => JSON.parse(Buffer.from(answer.body).toString());

const ping = call("GET", "/v1/ping");
assert.equal(ping.status, 200);
assert.equal(ping.headers["x-conan-server-capabilities"], "revisions");
assert.equal(call("GET", "/v2/ping").status, 200);

// Login: any Basic credential gets a token named for the user; a missing or wrong one does not.
assert.equal(call("GET", "/v2/users/authenticate").status, 401);
assert.equal(Buffer.from(call("GET", "/v2/users/authenticate", { authorization: `Basic ${Buffer.from("e2e-owner:e2e-pass").toString("base64")}` }).body).toString(), "tok-e2e-owner");
assert.equal(call("GET", "/v2/users/authenticate", { authorization: `Basic ${Buffer.from("e2e-wrong:x").toString("base64")}` }).status, 401);
assert.equal(call("GET", "/v2/users/check_credentials", { authorization: "Bearer tok-e2e-owner" }).status, 200);
assert.equal(call("GET", "/v2/users/check_credentials").status, 401);

// Uploads: only the owner's token, every call recorded, a revision dated at upload.
const rrev = "aaaa0000000000000000000000000001";
const put = (authorization, path, body = "x") => call("PUT", path, authorization ? { authorization } : {}, Buffer.from(body));
const file = (name) => `/v2/conans/demo/1.0/_/_/revisions/${rrev}/files/${name}`;
assert.equal(put(null, file("conanfile.py")).status, 401);
assert.match(put(null, file("conanfile.py")).headers["www-authenticate"], /^Bearer/);
assert.equal(put("Bearer tok-e2e-denied", file("conanfile.py")).status, 403);
assert.equal(put("Bearer tok-e2e-owner", file("conanfile.py"), "recipe").status, 201);
assert.equal(put("Bearer tok-e2e-owner", file("conanmanifest.txt"), "manifest").status, 201);
const pkg = "b647c43bfefae3f830561ca202b6cfd935b56205";
const prev = "fee20b6da94c4580b0c84ca5ce203fdc";
assert.equal(put("Bearer tok-e2e-owner", `/v2/conans/demo/1.0/_/_/revisions/${rrev}/packages/${pkg}/revisions/${prev}/files/conan_package.tgz`, "binary").status, 201);
assert.equal(fake.writes.length, 6);
assert.equal(fake.writes[5].bytes, 6);
assert.equal(fake.writes[5].sha256, createHash("sha256").update("binary").digest("hex"));

// Reads of what was uploaded.
const revisions = json(call("GET", "/v2/conans/demo/1.0/_/_/revisions"));
assert.equal(revisions.reference, "demo/1.0@_/_");
assert.equal(revisions.revisions[0].revision, rrev);
assert.match(revisions.revisions[0].time, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+0000$/);
assert.equal(json(call("GET", "/v2/conans/demo/1.0/_/_/latest")).revision, rrev);
assert.deepEqual(json(call("GET", `/v2/conans/demo/1.0/_/_/revisions/${rrev}/files`)), { files: { "conanfile.py": {}, "conanmanifest.txt": {} } });
assert.equal(Buffer.from(call("GET", file("conanfile.py")).body).toString(), "recipe");
assert.equal(call("GET", file("missing.txt")).status, 404);
assert.deepEqual(Object.keys(json(call("GET", `/v2/conans/demo/1.0/_/_/revisions/${rrev}/search`))), [pkg]);
assert.equal(json(call("GET", `/v2/conans/demo/1.0/_/_/revisions/${rrev}/packages/${pkg}/latest`)).revision, prev);
assert.equal(json(call("GET", `/v2/conans/demo/1.0/_/_/revisions/${rrev}/packages/${pkg}/revisions`)).packageReference, `demo/1.0@_/_#${rrev}:${pkg}`);
assert.deepEqual(json(call("GET", `/v2/conans/demo/1.0/_/_/revisions/${rrev}/packages/${pkg}/revisions/${prev}/files`)), { files: { "conan_package.tgz": {} } });
assert.deepEqual(json(call("GET", "/v2/conans/search?q=demo/*")).results, ["demo/1.0@_/_"]);
assert.ok(json(call("GET", "/v2/conans/search?q=*")).results.includes("seed/1.0@_/_"), "the seed recipe is there");
assert.equal(call("GET", "/v2/conans/nothing/1.0/_/_/revisions").status, 404);

// Ageing dates every revision, recipe and package alike.
assert.deepEqual(fake.age({ name: "demo", version: "1.0", ageSeconds: 400 * 86_400 }), { aged: 1 });
assert.ok(Date.now() - Date.parse(json(call("GET", "/v2/conans/demo/1.0/_/_/latest")).time.replace("+0000", "Z")) > 399 * 86_400_000);
assert.ok(Date.now() - Date.parse(json(call("GET", `/v2/conans/demo/1.0/_/_/revisions/${rrev}/packages/${pkg}/latest`)).time.replace("+0000", "Z")) > 399 * 86_400_000);
fake.reset();
assert.equal(fake.writes.length, 0);
assert.equal(call("GET", "/v2/conans/demo/1.0/_/_/revisions").status, 404, "reset clears what was uploaded");
console.log("conan-fake.test: ok");
