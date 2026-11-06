// The only thing the tunnel exposes: GET of the policy snapshot with the run's throwaway key.
// node tests/e2e/native/snapshot-proxy.test.mjs
import assert from "node:assert/strict";
import http from "node:http";
import { startSnapshotProxy } from "./snapshot-proxy.mjs";

const key = "prb_" + "c".repeat(32);
const forwarded = [];
const proxy = await startSnapshotProxy({
  key,
  forward: async (authorization) => { forwarded.push(authorization); return { status: 200, contentType: "application/json", body: Buffer.from('{"version":1}') }; },
});
const call = (path, { method = "GET", headers = {} } = {}) => new Promise((resolve, reject) => {
  const req = http.request({ host: "127.0.0.1", port: proxy.port, path, method, headers }, (res) => {
    const chunks = []; res.on("data", (c) => chunks.push(c)).on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
  });
  req.on("error", reject); req.end(method === "POST" ? "x" : undefined);
});
const snapshot = "/api/v1/policy/snapshot";
const auth = { authorization: `Bearer ${key}` };

let r = await call(snapshot, { headers: { ...auth, "x-native-job": "darwin-arm64", "cf-connecting-ip": "203.0.113.7" } });
assert.equal(r.status, 200);
assert.equal(r.body, '{"version":1}');
assert.deepEqual(forwarded, [`Bearer ${key}`], "the key is forwarded to the real server");
r = await call(snapshot, { headers: auth });
assert.equal(r.status, 200);
// Everything else is refused here and never reaches the real server.
const before = forwarded.length;
for (const [path, options, status] of [
  [snapshot, { headers: { authorization: "Bearer prb_" + "d".repeat(32) } }, 401], [snapshot, {}, 401], [snapshot, { headers: { authorization: `bearer ${key}` } }, 401],
  [snapshot, { method: "POST", headers: auth }, 404], [`${snapshot}?x=1`, { headers: auth }, 404], ["/api/v1/sync/lookup", { headers: auth }, 404], ["/api/v1/policy/snapshot/", { headers: auth }, 404],
  ["/", {}, 404], ["/signin", {}, 404], ["/api/v1/sync/changes", { method: "POST", headers: auth }, 404],
]) {
  r = await call(path, options);
  assert.equal(r.status, status, `${options.method ?? "GET"} ${path} -> ${r.status}`);
}
assert.equal(forwarded.length, before, "refused requests never reach the real server");
// The log keeps who asked: label, tunnel client address, whether the key was right, the answer.
const [first, second, ...rest] = proxy.log;
assert.deepEqual({ label: first.label, cfIp: first.cfIp, keyOk: first.keyOk, status: first.status, path: first.path }, { label: "darwin-arm64", cfIp: "203.0.113.7", keyOk: true, status: 200, path: snapshot });
assert.equal(second.label, null);
assert.equal(rest.filter((e) => e.status === 200).length, 0, "nothing else is ever answered 200");
assert.ok(rest.every((e) => e.status === 401 || e.status === 404), "every other request is refused");
// An upstream failure is passed on as 502 and logged.
const failing = await startSnapshotProxy({ key, forward: async () => { throw new Error("down"); } });
const down = await new Promise((resolve) => http.get({ host: "127.0.0.1", port: failing.port, path: snapshot, headers: auth }, (res) => { res.resume(); resolve(res.statusCode); }));
assert.equal(down, 502);
await proxy.close(); await failing.close();
console.log("snapshot-proxy.test: ok");
