// Every fake upstream in one stdlib-only Node process: npm, PyPI, OSV, the leaked-
// password range API and the OIDC IdP, on https :443 under their real names (compose
// gives this container those names as network aliases on the public-range e2e network).
// Plain http :8080 is the control API the harness sets their state through:
//
//   POST /reset                       seed state back, faults and logs cleared
//   GET  /log?host=                   every request served: {at, host, method, path, status, fault}
//   POST /faults {faults: [...]}      replace the fault list ([] clears); see `fault` below
//   POST /npm/publish {...}           Npm.publish; answers the version's dist
//   POST /pypi/publish {...}          Pypi.publish; answers the files made
//   POST /osv/flag {...}              Osv.flag
//   GET  /osv/queries                 every querybatch query received
//   POST /hibp/leak {password}        add a leaked password
//   POST /oidc/next {...}             Oidc.next
//   POST /oidc/rotate                 new IdP signing key
//
// A fault is {host?, path? (prefix), method?, mode, times?, ...}; the first that
// matches a request applies, `times` (default unlimited) counts down. Modes:
//   status   answer `status` (with `retryAfter` as Retry-After) and a short body
//   delay    answer normally after `ms`
//   hang     never answer; the connection stays open until the client gives up
//   reset    close the connection without answering
//   slow     answer normally, `bytesPerSecond` at a time
//   stall    send the headers and the first `afterBytes` of the body, then hang
//   corrupt  answer with one byte of the body flipped
//   novalidators  answer without ETag and never 304

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { setTimeout as sleep } from "node:timers/promises";
import { Hibp } from "./hibp.mjs";
import { Npm } from "./npm.mjs";
import { Oidc } from "./oidc.mjs";
import { Osv } from "./osv.mjs";
import { Pypi } from "./pypi.mjs";

const TLS_DIR = process.env.E2E_TLS_DIR ?? "/e2e/tls";
const fakes = { npm: new Npm(), pypi: new Pypi(), osv: new Osv(), hibp: new Hibp(), oidc: new Oidc() };
const hosts = {
  "registry.npmjs.org": fakes.npm,
  "pypi.org": fakes.pypi,
  "files.pythonhosted.org": fakes.pypi,
  "api.osv.dev": fakes.osv,
  "api.pwnedpasswords.com": fakes.hibp,
  "idp.e2e.test": fakes.oidc,
  "accounts.google.com": fakes.oidc,
};
let faults = [];
let log = [];
const hanging = new Set();

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function fault(host, req) {
  const found = faults.find(
    (f) => (!f.host || f.host === host) && (!f.path || req.url.startsWith(f.path)) && (!f.method || f.method === req.method),
  );
  if (found && found.times !== undefined && --found.times <= 0) faults = faults.filter((f) => f !== found);
  return found;
}

function hang(req) {
  hanging.add(req.socket);
  req.socket.on("close", () => hanging.delete(req.socket));
}

async function serve(req, res) {
  const host = (req.headers.host ?? "").replace(/:\d+$/, "");
  const entry = { at: new Date().toISOString(), host, method: req.method, path: req.url, status: 0 };
  log.push(entry);
  if (log.length > 20_000) log = log.slice(-10_000);
  const body = await readBody(req);
  const f = fault(host, req);
  entry.fault = f?.mode;
  if (f?.mode === "hang") return hang(req);
  if (f?.mode === "reset") return req.socket.destroy();
  if (f?.mode === "delay") await sleep(f.ms ?? 1000);
  let answer;
  if (f?.mode === "status") {
    answer = { status: f.status ?? 503, headers: f.retryAfter ? { "retry-after": String(f.retryAfter) } : {}, body: `fault ${f.status ?? 503}\n` };
  } else {
    const fake = hosts[host];
    answer = fake ? fake.handle(req, req.url, host, body) : { status: 404, body: `no fake for ${host}\n` };
  }
  let bytes = Buffer.from(answer.body ?? "");
  const headers = { ...answer.headers };
  if (answer.status === 200 && req.method === "GET" && f?.mode !== "novalidators") {
    headers.etag = `"${createHash("sha1").update(bytes).digest("hex")}"`;
    if (req.headers["if-none-match"] === headers.etag) {
      answer = { status: 304 };
      bytes = Buffer.alloc(0);
    }
  }
  if (f?.mode === "corrupt" && bytes.length) bytes[bytes.length - 1] ^= 1;
  entry.status = answer.status;
  headers["content-length"] = bytes.length;
  res.writeHead(answer.status, headers);
  if (f?.mode === "stall") {
    res.write(bytes.subarray(0, f.afterBytes ?? 0));
    return hang(req);
  }
  if (f?.mode === "slow") {
    const step = Math.max(1, Math.floor((f.bytesPerSecond ?? 1024) / 10));
    for (let at = 0; at < bytes.length && !res.destroyed; at += step) {
      res.write(bytes.subarray(at, at + step));
      await sleep(100);
    }
    return res.end();
  }
  res.end(bytes);
}

const control = {
  "POST /reset": () => {
    for (const fake of Object.values(fakes)) fake.reset();
    faults = [];
    log = [];
    for (const socket of hanging) socket.destroy();
    return { ok: true };
  },
  "GET /log": (_, url) => log.filter((e) => !url.searchParams.get("host") || e.host === url.searchParams.get("host")),
  "POST /faults": (body) => {
    faults = body.faults ?? [];
    for (const socket of hanging) socket.destroy();
    return { ok: true };
  },
  "POST /npm/publish": (body) => fakes.npm.publish(body),
  "POST /pypi/publish": (body) => fakes.pypi.publish(body),
  "POST /osv/flag": (body) => (fakes.osv.flag(body), { ok: true }),
  "GET /osv/queries": () => fakes.osv.queries,
  "POST /hibp/leak": (body) => (fakes.hibp.leak(body.password), { ok: true }),
  "POST /oidc/next": (body) => (fakes.oidc.next(body), { ok: true }),
  "POST /oidc/rotate": () => (fakes.oidc.rotate(), { ok: true }),
  "GET /health": () => ({ ok: true }),
};

async function controlServe(req, res) {
  const url = new URL(req.url, "http://fakes");
  const route = control[`${req.method} ${url.pathname}`];
  try {
    if (!route) throw Object.assign(new Error(`no route ${req.method} ${url.pathname}`), { status: 404 });
    const raw = (await readBody(req)).toString();
    const answer = await route(raw ? JSON.parse(raw) : {}, url);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(answer));
  } catch (err) {
    res.writeHead(err.status ?? 400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: err.message }));
  }
}

const tls = { cert: readFileSync(`${TLS_DIR}/cert.pem`), key: readFileSync(`${TLS_DIR}/key.pem`) };
const report = (err, res) => {
  console.error(err);
  if (!res.headersSent) res.writeHead(500).end();
};
https.createServer(tls, (req, res) => serve(req, res).catch((err) => report(err, res))).listen(Number(process.env.E2E_HTTPS_PORT ?? 443));
http.createServer((req, res) => controlServe(req, res).catch((err) => report(err, res))).listen(Number(process.env.E2E_CONTROL_PORT ?? 8080));
console.log("fakes listening");
