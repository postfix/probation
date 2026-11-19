// The fake Go proxy and checksum database (fixtures/fakes/go.mjs): the GOPROXY protocol with case-encoded paths.
// node tests/e2e/native/go-fake.test.mjs
import assert from "node:assert/strict";
import { Go, escape, unescape } from "../fixtures/fakes/go.mjs";

const fake = new Go();
const proxy = (path) => fake.handle({ method: "GET", headers: {} }, path, "proxy.golang.org");
const sum = (path, headers = {}) => fake.handle({ method: "GET", headers }, path, "sum.golang.org");

// The case encoding round-trips exactly: `A` is `!a`, a path with no capital is unchanged.
assert.equal(escape("github.com/Azure/azure-sdk-for-go"), "github.com/!azure/azure-sdk-for-go");
assert.equal(unescape("github.com/!burnt!sushi/toml"), "github.com/BurntSushi/toml");
assert.equal(escape("v1.0.0-RC1"), "v1.0.0-!r!c1");
assert.equal(unescape(escape("example.com/A/B-c_D")), "example.com/A/B-c_D");

const made = fake.publish({ module: "example.com/Demo/Lib", version: "v1.0.0", ageSeconds: 400 * 86_400 });
fake.publish({ module: "example.com/Demo/Lib", version: "v1.1.0", ageSeconds: 3600 });
fake.publish({ module: "example.com/Demo/Lib", version: "v2.0.0-RC1", ageSeconds: 3600 });
fake.publish({ module: "example.com/Demo/Lib", version: "v0.0.0-20240101000000-abcdef123456", ageSeconds: 3600 });
assert.equal(made.file, "v1.0.0.zip");

// list: tagged versions in insertion order, never a pseudo-version; the lookup is by decoded identity.
assert.equal(proxy("/example.com/!demo/!lib/@v/list").body, "v1.0.0\nv1.1.0\nv2.0.0-RC1\n");
assert.equal(proxy("/example.com/demo/lib/@v/list").status, 404, "an unescaped spelling is another module");
assert.equal(proxy("/example.com/Demo/Lib/@v/list").status, 404, "a capital on the wire is no valid path");

// info: Version and the real publication Time; a version without Time has none.
const info = JSON.parse(proxy("/example.com/!demo/!lib/@v/v1.0.0.info").body);
assert.equal(info.Version, "v1.0.0");
assert.match(info.Time, /^\d{4}-\d\d-\d\dT[\d:]+Z$/);
assert.equal(proxy("/example.com/!demo/!lib/@v/v2.0.0-!r!c1.info").status, 200, "versions are case-encoded too");
assert.equal(proxy("/example.com/!demo/!lib/@v/v2.0.0-RC1.info").status, 404);
assert.equal(proxy("/example.com/!demo/!lib/@v/v9.9.9.info").status, 404);
fake.publish({ module: "example.com/e2e/undated", version: "v1.0.0", undated: true });
assert.deepEqual(JSON.parse(proxy("/example.com/e2e/undated/@v/v1.0.0.info").body), { Version: "v1.0.0" });

// @latest: the highest release; pseudo-versions are reachable by name only.
assert.equal(JSON.parse(proxy("/example.com/!demo/!lib/@latest").body).Version, "v1.1.0");
fake.publish({ module: "example.com/e2e/pre", version: "v1.0.0-rc.1", ageSeconds: 60 });
assert.equal(JSON.parse(proxy("/example.com/e2e/pre/@latest").body).Version, "v1.0.0-rc.1", "no release: the highest prerelease");
fake.publish({ module: "example.com/e2e/ps", version: "v0.0.0-20240101000000-abcdef123456", ageSeconds: 60 });
assert.equal(JSON.parse(proxy("/example.com/e2e/ps/@latest").body).Version, "v0.0.0-20240101000000-abcdef123456", "only a pseudo-version: it is the latest");
assert.equal(proxy("/example.com/e2e/ps/@v/v0.0.0-20240101000000-abcdef123456.zip").status, 200);
assert.equal(proxy("/example.com/e2e/ps/@v/list").body, "", "never listed");

// A revision query: the branch or commit name answers with the version it resolves to.
fake.publish({ module: "example.com/e2e/rev", version: "v0.0.0-20240101000000-abcdef123456", ageSeconds: 400 * 86_400, revs: ["main", "abcdef123456"] });
const resolved = JSON.parse(proxy("/example.com/e2e/rev/@v/main.info").body);
assert.equal(resolved.Version, "v0.0.0-20240101000000-abcdef123456");
assert.equal(JSON.parse(proxy("/example.com/e2e/rev/@v/abcdef123456.info").body).Version, resolved.Version);
assert.equal(proxy("/example.com/e2e/rev/@v/nosuch.info").status, 404);

// mod and zip: the zip is a real stored module zip with go.mod and one source file under module@version/.
assert.equal(proxy("/example.com/!demo/!lib/@v/v1.0.0.mod").body, "module example.com/Demo/Lib\n\ngo 1.21\n");
const archive = proxy("/example.com/!demo/!lib/@v/v1.0.0.zip");
assert.equal(archive.status, 200);
assert.equal(archive.body.subarray(0, 4).toString("hex"), "504b0304");
const text = archive.body.toString("latin1");
assert.ok(text.includes("example.com/Demo/Lib@v1.0.0/go.mod") && text.includes("example.com/Demo/Lib@v1.0.0/lib.go"));

// The checksum database: every read recorded with its Authorization header.
assert.equal(sum("/supported").status, 200);
assert.equal(sum("/latest", { authorization: "Bearer stolen" }).status, 200);
assert.match(sum("/lookup/example.com/!demo/!lib@v1.0.0").body, /^1\nexample\.com\/Demo\/Lib v1\.0\.0 h1:/);
assert.equal(sum("/tile/8/0/x001/234.p/17").body.length, 3);
assert.equal(sum("/other").status, 404);
assert.deepEqual(fake.sumdb.map((r) => r.authorization), [null, "Bearer stolen", null, null, null]);
fake.reset();
assert.deepEqual(fake.sumdb, []);
assert.equal(proxy("/example.com/!demo/!lib/@v/list").status, 404, "reset forgets scenario modules and keeps the seed");
assert.equal(proxy("/example.com/e2e/seed/@v/list").body, "v1.0.0\n");
console.log("go-fake.test: ok");
