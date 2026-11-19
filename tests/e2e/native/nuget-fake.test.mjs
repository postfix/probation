// The fake NuGet.org (fixtures/fakes/nuget.mjs): the v3 documents, lower-case ids and normalised versions in every
// URL, registration as published (gzip, linked pages for a large package, the unlisted sentinel), search and
// autocomplete, the vulnerability and signature documents, and the publish endpoints.
// node tests/e2e/native/nuget-fake.test.mjs
import assert from "node:assert/strict";
import { gunzipSync } from "node:zlib";
import { NuGet, SENTINEL, normalize } from "../fixtures/fakes/nuget.mjs";

const fake = new NuGet();
const get = (path, host = "api.nuget.org", headers = {}) => fake.handle({ method: "GET", headers }, path, host, Buffer.alloc(0));
const body = (answer) => (answer.headers?.["content-encoding"] === "gzip" ? gunzipSync(answer.body) : Buffer.from(answer.body)).toString();
const json = (answer) => JSON.parse(body(answer));

// Normalisation: NuGetVersion.ToNormalizedString lower-cased, without metadata.
for (const [from, to] of [["1.0", "1.0.0"], ["1.0.0.0", "1.0.0"], ["01.2.3.4", "1.2.3.4"], ["1.0.0-Beta+meta", "1.0.0-beta"], ["13.0.3", "13.0.3"]]) {
  assert.equal(normalize(from), to, from);
}

const made = fake.publish({ id: "Demo.Pkg", version: "1.0.0", ageSeconds: 400 * 86_400 });
fake.publish({ id: "Demo.Pkg", version: "1.1.0.0", ageSeconds: 3600 });
fake.publish({ id: "Demo.Pkg", version: "2.0.0-RC.1", ageSeconds: 3600 });
fake.publish({ id: "Demo.Pkg", version: "0.9.0", unlisted: true, ageSeconds: 500 * 86_400 });
fake.publish({ id: "Lagging.Pkg", version: "1.0.0", ageSeconds: 3600, inRegistration: false });
assert.equal(made.file, "demo.pkg.1.0.0.nupkg");

// The service index names this fake's own hosts, the legacy resources the firewall does not serve, and the readme template.
const types = json(get("/v3/index.json")).resources.map((r) => r["@type"]);
for (const type of ["PackageBaseAddress/3.0.0", "RegistrationsBaseUrl/Versioned", "SearchQueryService", "PackagePublish/2.0.0", "RepositorySignatures/5.0.0", "VulnerabilityInfo/6.7.0", "LegacyGallery", "Catalog/3.0.0"]) assert.ok(types.includes(type), type);

// The flat container: lower-case id, normalised sorted versions; a capital in the URL is no package.
assert.deepEqual(json(get("/v3-flatcontainer/demo.pkg/index.json")).versions, ["0.9.0", "1.0.0", "1.1.0", "2.0.0-rc.1"]);
assert.equal(get("/v3-flatcontainer/Demo.Pkg/index.json").status, 404);
assert.equal(get("/v3-flatcontainer/demo.pkg/1.1.0/demo.pkg.1.1.0.nupkg").status, 200);
assert.equal(get("/v3-flatcontainer/demo.pkg/1.1.0.0/demo.pkg.1.1.0.0.nupkg").status, 404, "the version is the normalised spelling");
assert.match(body(get("/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.nuspec")), /<id>Demo.Pkg<\/id>/, "the nuspec carries the id as published");
assert.equal(get("/v3-flatcontainer/demo.pkg/1.0.0/readme").status, 200);
assert.equal(get("/v3-flatcontainer/demo.pkg/1.0.0/icon").status, 200);
const nupkg = get("/v3-flatcontainer/demo.pkg/1.0.0/demo.pkg.1.0.0.nupkg").body;
assert.equal(nupkg.subarray(0, 4).toString("hex"), "504b0304", "a real zip");

// Registration: gzip, the version as published, the unlisted sentinel, a version registration lags on is absent.
const registration = get("/v3/registration5-gz-semver2/demo.pkg/index.json");
assert.equal(registration.headers["content-encoding"], "gzip");
const leaves = json(registration).items.flatMap((page) => page.items);
assert.deepEqual(leaves.map((l) => l.catalogEntry.version), ["0.9.0", "1.0.0", "1.1.0.0", "2.0.0-RC.1"]);
assert.equal(leaves.find((l) => l.catalogEntry.version === "0.9.0").catalogEntry.published, SENTINEL);
assert.equal(leaves.find((l) => l.catalogEntry.version === "0.9.0").catalogEntry.listed, false);
assert.match(leaves.find((l) => l.catalogEntry.version === "1.0.0").catalogEntry.published, /^\d{4}-\d\d-\d\dT[\d:.]+\+00:00$/);
assert.deepEqual(json(get("/v3/registration5-gz-semver2/lagging.pkg/index.json")).items, []);
assert.deepEqual(json(get("/v3-flatcontainer/lagging.pkg/index.json")).versions, ["1.0.0"]);
// A leaf document: the catalog entry is a URL there.
const single = json(get("/v3/registration5-gz-semver2/demo.pkg/1.1.0.json"));
assert.equal(typeof single.catalogEntry, "string");

// A large package has linked pages of 64 versions.
for (let n = 0; n < 150; n += 1) fake.publish({ id: "Big.Pkg", version: `1.0.${n}`, ageSeconds: 400 * 86_400 });
const big = json(get("/v3/registration5-gz-semver2/big.pkg/index.json"));
assert.equal(big.count, 3);
assert.ok(big.items.every((page) => page.items === undefined && page.lower && page.upper), "linked pages carry no items");
const page = json(get(new URL(big.items[1]["@id"]).pathname));
assert.equal(page.items.length, 64);
assert.equal(page.items[0].catalogEntry.version, big.items[1].lower);

// Search and autocomplete.
const search = json(get("/query?q=demo&take=5", "azuresearch-usnc.nuget.org"));
assert.equal(search.totalHits, 1);
assert.equal(search.data[0].id, "Demo.Pkg");
assert.deepEqual(search.data[0].versions.map((v) => v.version), ["1.0.0", "1.1.0", "2.0.0-rc.1"], "an unlisted version is not offered");
assert.deepEqual(json(get("/autocomplete?q=demo", "azuresearch-usnc.nuget.org")).data, ["Demo.Pkg"]);
assert.deepEqual(json(get("/autocomplete?id=demo.pkg", "azuresearch-usnc.nuget.org")).data, ["0.9.0", "1.0.0", "1.1.0", "2.0.0-rc.1"]);

// Vulnerabilities and repository signatures.
fake.vulnerability({ id: "Demo.Pkg", range: "[1.0.0, 2.0.0)" });
const files = json(get("/v3/vulnerabilities/index.json"));
assert.deepEqual(files.map((f) => f["@name"]), ["base", "update"]);
assert.equal(json(get(new URL(files[0]["@id"]).pathname))["demo.pkg"][0].versions, "[1.0.0, 2.0.0)");
const signatures = json(get("/v3-index/repository-signatures/5.0.0/index.json"));
assert.equal(get(new URL(signatures.signingCertificates[0].contentUrl).pathname).status, 200);

// The publish endpoints record every call with its credentials and answer by API key.
const put = (path, key, extra = {}) => fake.handle({ method: "PUT", headers: { "x-nuget-apikey": key, "content-type": "multipart/form-data; boundary=b", ...extra } }, path, "www.nuget.org", Buffer.from("package"));
assert.equal(put("/api/v2/package", "e2e-owner-key").status, 201);
assert.equal(put("/api/v2/package", "e2e-denied").status, 403);
assert.equal(put("/api/v2/package", "wrong").status, 401);
assert.equal(fake.handle({ method: "PUT", headers: {} }, "/api/v2/package", "www.nuget.org", Buffer.from("x")).status, 401);
assert.equal(put("/api/v2/symbolpackage", "e2e-owner-key").status, 201);
assert.equal(fake.handle({ method: "DELETE", headers: { "x-nuget-apikey": "e2e-owner-key" } }, "/api/v2/package/demo.pkg/1.0.0", "www.nuget.org", Buffer.alloc(0)).status, 204);
assert.equal(fake.handle({ method: "POST", headers: { "x-nuget-apikey": "e2e-owner-key" } }, "/api/v2/package/demo.pkg/1.0.0", "www.nuget.org", Buffer.alloc(0)).status, 200);
assert.equal(fake.writes.length, 7);
assert.deepEqual(fake.writes[0], { method: "PUT", path: "/api/v2/package", apiKey: "e2e-owner-key", authorization: null, contentType: "multipart/form-data; boundary=b", bytes: 7, sha256: fake.writes[0].sha256 });
console.log("nuget-fake.test: ok");
