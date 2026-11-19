// The fake RubyGems (fixtures/fakes/rubygems.mjs): archives, indexes and the dated API.
// node tests/e2e/native/rubygems-fake.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gunzipSync, inflateSync } from "node:zlib";
import { PAGE, RubyGems } from "../fixtures/fakes/rubygems.mjs";

const get = (fake, path) => fake.handle({ method: "GET", headers: {} }, path, "rubygems.org", Buffer.alloc(0));
const fake = new RubyGems();
const made = fake.publish({ name: "demo-gem", version: "1.0.0", ageSeconds: 400 * 86_400 });
fake.publish({ name: "demo-gem", version: "2.0.0", ageSeconds: 3600 });
fake.publish({ name: "demo-gem", version: "1.5.0", platform: "java", ageSeconds: 3600 });

// A .gem is a tar of exactly metadata.gz, data.tar.gz and checksums.yaml.gz, and the checksums match.
const gem = get(fake, `/gems/${made.file}`).body;
const names = [];
for (let at = 0; at + 512 <= gem.length && gem[at] !== 0; ) {
  const name = gem.subarray(at, at + 100).toString().replace(/\0.*$/, "");
  const size = parseInt(gem.subarray(at + 124, at + 135).toString(), 8);
  names.push(name);
  at += 512 + Math.ceil(size / 512) * 512;
}
assert.deepEqual(names, ["metadata.gz", "data.tar.gz", "checksums.yaml.gz"]);
assert.equal(createHash("sha256").update(gem).digest("hex"), made.sha256);

// The compact index lists every version and platform with its checksum and registry date.
const info = get(fake, "/info/demo-gem").body.split("\n");
assert.equal(info[0], "---");
assert.match(info[1], /^1\.0\.0 \|checksum:[0-9a-f]{64},created_at:\d{4}-\d\d-\d\dT[\d:]+Z,ruby:>= 0$/);
assert.match(info[3], /^1\.5\.0-java \|checksum:/);
assert.equal(get(fake, "/info/Demo-Gem").status, 200, "the index is case-insensitive like rubygems.org's");
assert.equal(get(fake, "/info/absent").status, 404);

// Tuple indexes are gzip Marshal 4.8 arrays; latest keeps the newest per platform.
for (const [path, tuples] of [["/specs.4.8.gz", 4], ["/latest_specs.4.8.gz", 3], ["/prerelease_specs.4.8.gz", 0]]) {
  const raw = gunzipSync(get(fake, path).body);
  assert.deepEqual([...raw.subarray(0, 3)], [4, 8, 0x5b], path);
  assert.equal(raw[3], tuples === 0 ? 0 : tuples + 5, `${path} holds ${tuples} tuples`);
}
assert.deepEqual([...inflateSync(get(fake, `/quick/Marshal.4.8/${made.file.replace(/\.gem$/, "")}.gemspec.rz`).body).subarray(0, 2)], [4, 8]);

// The dated API: only versions created inside the window, and never a window over seven days.
const iso = (ms) => new Date(ms).toISOString();
const window = `from=${iso(Date.now() - 86_400_000)}&to=${iso(Date.now() + 1000)}`;
const page = (n) => JSON.parse(get(fake, `/api/v1/timeframe_versions.json?${window}&page=${n}`).body);
fake.publish({ name: "RedCloth", version: "4.3.2", ageSeconds: 60 });
assert.equal(page(1).length, PAGE, "a short page");
const all = [...page(1), ...page(2)];
assert.deepEqual(all.map((v) => `${v.name} ${v.number} ${v.platform}`).sort(), ["RedCloth 4.3.2 ruby", "demo-gem 1.5.0 java", "demo-gem 2.0.0 ruby"]);
assert.deepEqual(page(3), [], "a page past the end is empty");
assert.equal(get(fake, `/api/v1/timeframe_versions.json?${window}&page=0`).status, 400);
// A mixed-case gem: its index answers any spelling, its files only the exact one.
assert.match(get(fake, "/info/redcloth").body, /^---\n4\.3\.2 \|checksum:/);
assert.equal(get(fake, "/gems/RedCloth-4.3.2.gem").status, 200);
assert.equal(get(fake, "/gems/redcloth-4.3.2.gem").status, 403);
assert.equal(get(fake, "/quick/Marshal.4.8/redcloth-4.3.2.gemspec.rz").status, 403);
assert.equal(get(fake, `/api/v1/timeframe_versions.json?from=${iso(Date.now() - 8 * 86_400_000)}&to=${iso(Date.now())}`).status, 400);

// versions: a header, then one line per gem with its info checksum.
assert.match(get(fake, "/versions").body, /^created_at: .+\n---\ne2e-seed 1\.0\.0 [0-9a-f]{32}\ndemo-gem /);
// Writes: the key arrives bare in Authorization, with the OTP and the content type, and is recorded.
const write = (method, path, headers, body = "x") => fake.handle({ method, headers }, path, "rubygems.org", Buffer.from(body));
assert.equal(write("POST", "/api/v1/gems", {}).status, 401);
assert.equal(write("POST", "/api/v1/gems", { authorization: "e2e-denied" }).status, 403);
assert.equal(write("POST", "/api/v1/gems", { authorization: "e2e-owner", otp: "123456", "content-type": "application/octet-stream" }, "gem bytes").status, 200);
assert.equal(write("DELETE", "/api/v1/gems/yank", { authorization: "e2e-owner", otp: "654321" }, "gem_name=x&version=1.0.0").status, 200);
assert.deepEqual(fake.writes.at(-2), { method: "POST", path: "/api/v1/gems", authorization: "e2e-owner", otp: "123456", contentType: "application/octet-stream", bytes: 9, body: undefined });
assert.equal(fake.writes.at(-1).body, "gem_name=x&version=1.0.0");
assert.equal(fake.writes.length, 4);
fake.reset();
assert.equal(get(fake, "/info/demo-gem").status, 404, "reset forgets scenario gems and keeps the seed");
console.log("rubygems-fake.test: ok");
