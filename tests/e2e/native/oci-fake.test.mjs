// The fake Docker Hub (fixtures/fakes/oci.mjs): the token challenge, the anonymous and the logged-in token, the manifest and its
// digest, the blob redirect to the storage host, the paged tag list, private repositories, and the push endpoints that record every write.
// node tests/e2e/native/oci-fake.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Oci } from "../fixtures/fakes/oci.mjs";

const fake = new Oci();
const call = (host, method, path, headers = {}, body = Buffer.alloc(0)) => fake.handle({ method, headers }, path, host, body);
const hub = (method, path, token, body) => call("registry-1.docker.io", method, path, token ? { authorization: `Bearer ${token}` } : {}, body);
const sha = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

// No token: the challenge names the realm on the auth host and the service.
const challenge = hub("GET", "/v2/");
assert.equal(challenge.status, 401);
assert.match(challenge.headers["www-authenticate"], /^Bearer realm="https:\/\/auth\.docker\.io\/token",service="registry\.docker\.io"/);
assert.equal(hub("GET", "/v2/", "tok-anon").status, 200);

// Tokens: anonymous, a login, a wrong login.
const token = (headers) => JSON.parse(Buffer.from(call("auth.docker.io", "GET", "/token?service=registry.docker.io&scope=repository:library/alpine:pull", headers).body).toString());
assert.equal(token({}).token, "tok-anon");
assert.equal(token({ authorization: `Basic ${Buffer.from("ana:pw").toString("base64")}` }).token, "tok-ana");
assert.equal(call("auth.docker.io", "GET", "/token", { authorization: `Basic ${Buffer.from("wrong:pw").toString("base64")}` }).status, 401);
assert.equal(fake.tokens.length, 3);
assert.deepEqual(fake.tokens.map((t) => t.basic), [false, true, true]);

// The second registry (ghcr.io) has repositories of its own, its own token endpoint on its own host, and shares nothing with the Hub.
const second = fake.publish({ repo: "team/app", tag: "v1", image: "hello-2", host: "ghcr.io" });
assert.notEqual(second.digest, published0().digest, "the same repository name holds another image on the second registry");
function published0() { return fake.publish({ repo: "team/app", tag: "v1", image: "hello-1" }); }
const ghcr = (method, path, headers = {}) => call("ghcr.io", method, path, headers);
assert.match(ghcr("GET", "/v2/").headers["www-authenticate"], /^Bearer realm="https:\/\/ghcr\.io\/token"/, "its realm is its own host");
assert.equal(JSON.parse(Buffer.from(ghcr("GET", "/token?scope=repository:team/app:pull").body).toString()).token, "tok-anon");
assert.equal(ghcr("GET", "/v2/team/app/manifests/v1", { authorization: "Bearer tok-anon" }).headers["docker-content-digest"], second.digest);
assert.equal(ghcr("GET", "/v2/library/alpine/manifests/latest", { authorization: "Bearer tok-anon" }).status, 404, "the Hub's seeded image is not on the second registry");

// The seeded public image: tag and digest answer the same bytes and name their digest.
const published = fake.publish({ repo: "team/app", tag: "v1", image: "hello-1" });
const byTag = hub("GET", "/v2/team/app/manifests/v1", "tok-anon");
assert.equal(byTag.status, 200);
assert.equal(byTag.headers["docker-content-digest"], published.digest);
assert.equal(sha(byTag.body), published.digest);
assert.equal(hub("GET", `/v2/team/app/manifests/${published.digest}`, "tok-anon").body.toString(), byTag.body.toString());
assert.equal(hub("HEAD", "/v2/team/app/manifests/v1", "tok-anon").body.length, 0);
assert.equal(hub("GET", "/v2/team/app/manifests/nope", "tok-anon").status, 404);

// A blob is a 307 to a signed URL on the storage host, which serves the bytes and sees no credential.
const redirect = hub("GET", `/v2/team/app/blobs/${published.layer}`, "tok-anon");
assert.equal(redirect.status, 307);
const location = new URL(redirect.headers.location);
assert.equal(location.hostname, "production.cloudfront.docker.com");
const stored = call(location.hostname, "GET", location.pathname + location.search);
assert.equal(stored.status, 200);
assert.equal(sha(stored.body), published.layer);
assert.equal(fake.seen.at(-1).authorization, null);

// Tags page by `n` and `last` with a `Link` the registry writes in its own absolute form.
for (const tag of ["a", "b", "c"]) fake.publish({ repo: "team/many", tag, image: "hello-2" });
const page = hub("GET", "/v2/team/many/tags/list?n=2", "tok-anon");
assert.deepEqual(JSON.parse(page.body).tags, ["a", "b"]);
assert.match(page.headers.link, /^<https:\/\/registry-1\.docker\.io\/v2\/team\/many\/tags\/list\?last=b&n=2>; rel="next"$/);
assert.equal(hub("GET", "/v2/team/many/tags/list?n=2&last=b", "tok-anon").headers.link, undefined);

// A private repository refuses the anonymous token and answers a challenge that names its scope.
fake.publish({ repo: "private/app", tag: "v1", image: "hello-1" });
const refused = hub("GET", "/v2/private/app/manifests/v1", "tok-anon");
assert.equal(refused.status, 401);
assert.match(refused.headers["www-authenticate"], /scope="repository:private\/app:pull"/);
assert.equal(hub("GET", "/v2/private/app/manifests/v1", "tok-ana").status, 200);

// A push is recorded with the credential it carried; the anonymous token cannot push.
const layer = Buffer.from("a pushed layer");
assert.equal(hub("POST", "/v2/team/pushed/blobs/uploads/", "tok-anon").status, 401);
const start = hub("POST", "/v2/team/pushed/blobs/uploads/", "tok-ana");
assert.equal(start.status, 202);
assert.match(start.headers.location, /^https:\/\/registry-1\.docker\.io\/v2\/team\/pushed\/blobs\/uploads\/up-\d+\?_state=/);
const session = new URL(start.headers.location);
assert.equal(hub("PATCH", session.pathname + session.search, "tok-ana", layer).status, 202);
assert.equal(hub("PUT", `${session.pathname}?digest=${sha(layer)}`, "tok-ana").status, 201);
assert.equal(hub("PUT", `${session.pathname}?digest=sha256:${"0".repeat(64)}`, "tok-ana").status, 400);
const manifest = Buffer.from('{"schemaVersion":2}');
assert.equal(hub("PUT", "/v2/team/pushed/manifests/v9", "tok-ana", manifest).status, 201);
assert.equal(hub("GET", "/v2/team/pushed/manifests/v9", "tok-anon").body.toString(), manifest.toString());
assert.equal(fake.writes.length, 5);
assert.ok(fake.writes.every((w) => w.authorization === "Bearer tok-ana"));
assert.deepEqual(fake.writes.map((w) => w.method), ["POST", "PATCH", "PUT", "PUT", "PUT"]);

// A foreign layer: the manifest names its URL on the listed host, the registry holds no blob for it, and that host serves it.
const foreignImage = fake.publishForeign({ repo: "win/base", tag: "ltsc", image: "hello-1" });
const foreignManifest = JSON.parse(hub("GET", "/v2/win/base/manifests/ltsc", "tok-anon").body.toString());
assert.equal(foreignManifest.layers[0].urls[0], `https://mcr.microsoft.com/foreign/${foreignImage.layer.replace("sha256:", "")}`);
assert.equal(hub("GET", `/v2/win/base/blobs/${foreignImage.layer}`, "tok-anon").status, 404);
const foreignHost = call("mcr.microsoft.com", "GET", foreignManifest.layers[0].urls[0].replace("https://mcr.microsoft.com", ""), {});
assert.equal(foreignHost.status, 200);
assert.equal(sha(foreignHost.body), foreignImage.layer);

// reset() restores the seed.
fake.reset();
assert.equal(hub("GET", "/v2/library/alpine/manifests/latest", "tok-anon").status, 200);
assert.equal(fake.writes.length, 0);
console.log("oci-fake.test: ok");
