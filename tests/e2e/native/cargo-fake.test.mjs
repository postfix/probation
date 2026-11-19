// The fake crates.io (fixtures/fakes/cargo.mjs): archives, the sparse index and config.json.
// node tests/e2e/native/cargo-fake.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { Cargo, indexPath } from "../fixtures/fakes/cargo.mjs";

const fake = new Cargo();
const get = (host, path) => fake.handle({ method: "GET", headers: {} }, path, host);
const made = fake.publish({ name: "demo-crate", version: "1.0.0", ageSeconds: 400 * 86_400 });
fake.publish({ name: "demo-crate", version: "2.0.0", ageSeconds: 3600 });
fake.publish({ name: "demo-crate", version: "1.5.0", ageSeconds: 3600, yanked: true });

// The sparse layout: 1/a, 2/ab, 3/a/abc, ab/cd/abcd, always of the lower-cased name.
assert.deepEqual(["a", "ab", "abc", "abcd", "Serde_Json"].map(indexPath), ["1/a", "2/ab", "3/a/abc", "ab/cd/abcd", "se/rd/serde_json"]);

// config.json names the archive host `dl` and an api.
const config = JSON.parse(get("index.crates.io", "/config.json").body);
assert.deepEqual(config, { dl: "https://static.crates.io/crates", api: "https://crates.io" });

// The index: one JSON line per version, pubtime and the checksum of the archive the fake serves.
const lines = get("index.crates.io", `/${indexPath("demo-crate")}`).body.trim().split("\n").map((l) => JSON.parse(l));
assert.equal(lines.length, 3);
assert.deepEqual(lines.map((l) => [l.vers, l.yanked]), [["1.0.0", false], ["2.0.0", false], ["1.5.0", true]]);
assert.match(lines[0].pubtime, /^\d{4}-\d\d-\d\dT[\d:]+Z$/);
assert.equal(lines[0].cksum, made.cksum);
assert.equal(get("index.crates.io", "/de/mo/demo-crate-x").status, 404);
assert.equal(get("index.crates.io", "/zz/zz/demo-crate").status, 404, "a prefix that does not belong to the name is no file");

// An archive is a gzip tar with `<name>-<version>/Cargo.toml` and `src/lib.rs`; its sha256 is the cksum.
const archive = get("static.crates.io", "/crates/demo-crate/1.0.0/download");
assert.equal(archive.status, 200);
assert.equal(createHash("sha256").update(archive.body).digest("hex"), made.cksum);
const tar = gunzipSync(archive.body);
const names = [];
for (let at = 0; at + 512 <= tar.length && tar[at] !== 0; ) {
  names.push(tar.subarray(at, at + 100).toString().replace(/\0.*$/, ""));
  at += 512 + Math.ceil(parseInt(tar.subarray(at + 124, at + 135).toString(), 8) / 512) * 512;
}
assert.deepEqual(names, ["demo-crate-1.0.0/Cargo.toml", "demo-crate-1.0.0/src/lib.rs"]);

// Mixed case: the index file is at the lower-case path with the exact name in its lines; archives are exact.
fake.publish({ name: "Cg_Mixed-x", version: "1.0.0", ageSeconds: 60 });
assert.match(get("index.crates.io", "/cg/_m/cg_mixed-x").body, /^\{"name":"Cg_Mixed-x","vers":"1\.0\.0"/);
assert.equal(get("index.crates.io", "/cg/_M/Cg_Mixed-x").status, 404, "an upper-case path is not the index file");
assert.equal(get("static.crates.io", "/crates/Cg_Mixed-x/1.0.0/download").status, 200);
assert.equal(get("static.crates.io", "/crates/cg_mixed-x/1.0.0/download").status, 403, "the object key is exact");
assert.equal(get("static.crates.io", "/crates/absent/1.0.0/download").status, 404);
assert.equal(get("static.crates.io", "/crates/demo-crate/9.9.9/download").status, 404);
assert.equal(fake.index("absent"), null);
// The registry API (host crates.io): the token is bare in Authorization, every call is recorded.
const api = (method, path, headers = {}, body = "x") => fake.handle({ method, headers }, path, "crates.io", Buffer.from(body));
assert.equal(api("PUT", "/api/v1/crates/new").status, 401, "no token");
assert.equal(api("PUT", "/api/v1/crates/new", { authorization: "e2e-denied" }).status, 403);
assert.equal(api("PUT", "/api/v1/crates/new", { authorization: "e2e-owner", "content-type": "application/octet-stream" }, "crate").status, 200);
assert.equal(api("DELETE", "/api/v1/crates/demo-crate/1.0.0/yank", { authorization: "e2e-owner" }).status, 200);
assert.equal(api("PUT", "/api/v1/crates/demo-crate/owners", { authorization: "e2e-owner" }, '{"users":["u"]}').status, 200);
assert.equal(api("GET", "/api/v1/crates/demo-crate/owners").status, 200, "the owner list needs no token");
assert.equal(api("GET", "/api/v1/crates?q=e2e").status, 200);
const redirect = api("DELETE", "/api/v1/crates/redirect-away-x/1.0.0/yank", { authorization: "e2e-owner" });
assert.deepEqual([redirect.status, redirect.headers.location], [307, "https://static.crates.io/leak"]);
assert.equal(api("DELETE", "/api/v1/crates/redirect-same-x/1.0.0/yank", { authorization: "e2e-owner" }).headers.location, "https://crates.io/api/v1/elsewhere");
fake.handle({ method: "GET", headers: { authorization: "stolen" } }, "/crates/x/1.0.0/download", "static.crates.io");
assert.equal(fake.writes.at(-1).host, "static.crates.io", "a credential at the archive host is recorded");
fake.writes.length = 7;
assert.equal(fake.writes.length, 7);
assert.deepEqual([fake.writes[2].method, fake.writes[2].path, fake.writes[2].authorization, fake.writes[2].contentType, fake.writes[2].bytes], ["PUT", "/api/v1/crates/new", "e2e-owner", "application/octet-stream", 5]);
assert.equal(fake.writes[6].query, "?q=e2e");
fake.reset();
assert.deepEqual(fake.writes, []);
assert.equal(get("index.crates.io", `/${indexPath("demo-crate")}`).status, 404, "reset forgets scenario crates and keeps the seed");
assert.equal(get("index.crates.io", `/${indexPath("e2e-seed")}`).status, 200);
console.log("cargo-fake.test: ok");
