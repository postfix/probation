// The only thing the tunnel exposes: GET of the policy snapshot with the run's throwaway key.
// node tests/e2e/native/snapshot-proxy.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
// A flood of unauthenticated requests cannot grow the log without bound; requests with the right key are always kept.
const capped = await startSnapshotProxy({ key, forward: async () => ({ status: 200, body: Buffer.from("{}") }), maxLog: 5 });
const hit = (headers) => new Promise((resolve) => http.get({ host: "127.0.0.1", port: capped.port, path: snapshot, headers }, (res) => { res.resume(); resolve(res.statusCode); }));
for (let i = 0; i < 20; i++) assert.equal(await hit({}), 401);
assert.equal(capped.log.length, 5, "unauthenticated entries stop at the cap");
assert.equal(capped.dropped(), 15, "the rest are counted");
assert.equal(await hit(auth), 200);
assert.equal(capped.log.at(-1).keyOk, true, "a request with the key is logged past the cap");
await capped.close();
// Binds loopback by default; an upstream status is passed through; the key is compared in constant time (same length only).
assert.equal(proxy.address, "127.0.0.1", "the default bind is loopback");
const unavailable = await startSnapshotProxy({ key, forward: async () => ({ status: 503, body: Buffer.from("later") }) });
const got503 = await new Promise((resolve) => http.get({ host: "127.0.0.1", port: unavailable.port, path: snapshot, headers: auth }, (res) => { res.resume(); resolve(res.statusCode); }));
assert.equal(got503, 503, "an upstream 503 is not turned into 200");
assert.equal(unavailable.log[0].status, 503);
await unavailable.close();
for (const wrong of [`Bearer ${key}x`, `Bearer ${key.slice(0, -1)}`, `Bearer ${key.slice(0, -1)}d`, key, ""]) {
  const status = await new Promise((resolve) => http.get({ host: "127.0.0.1", port: proxy.port, path: snapshot, headers: { authorization: wrong } }, (res) => { res.resume(); resolve(res.statusCode); }));
  assert.equal(status, 401, JSON.stringify(wrong));
}
assert.match(await readFile(new URL("./snapshot-proxy.mjs", import.meta.url), "utf8"), /timingSafeEqual/, "no plain === on the key");
// A forward answer without a content type is served as application/json.
const bare = await startSnapshotProxy({ key, forward: async () => ({ status: 200, body: Buffer.from("{}") }) });
const bareType = await new Promise((resolve) => http.get({ host: "127.0.0.1", port: bare.port, path: snapshot, headers: auth }, (res) => { res.resume(); resolve(res.headers["content-type"]); }));
assert.equal(bareType, "application/json", "the default content type");
// close() must not wait for an idle keep-alive connection (closeAllConnections), and that connection ends.
const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
await new Promise((resolve) => http.get({ host: "127.0.0.1", port: bare.port, path: snapshot, headers: auth, agent }, (res) => { res.resume(); res.on("end", resolve); }));
const socketClosed = new Promise((resolve) => { const [socket] = Object.values(agent.freeSockets).flat(); assert.ok(socket, "the connection is kept alive"); socket.once("close", () => resolve(true)); });
const closed = await Promise.race([bare.close().then(() => "closed"), new Promise((resolve) => setTimeout(() => resolve("hung"), 4000))]);
assert.equal(closed, "closed", "close() returns while a keep-alive connection is idle");
assert.equal(await socketClosed, true, "and the keep-alive connection is ended");
agent.destroy();
// ... nor for a request still in flight (closeAllConnections; a plain close() waits for it).
const stuck = await startSnapshotProxy({ key, forward: () => new Promise(() => {}) });
const stuckReq = http.get({ host: "127.0.0.1", port: stuck.port, path: snapshot, headers: auth }, () => {});
stuckReq.on("error", () => {});
await new Promise((resolve) => setTimeout(resolve, 300));
assert.equal(await Promise.race([stuck.close().then(() => "closed"), new Promise((resolve) => setTimeout(() => resolve("hung"), 4000))]), "closed", "close() ends a request in flight");
await proxy.close(); await failing.close();
console.log("snapshot-proxy.test: ok");
