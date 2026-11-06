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
//   GET  /siem/batches                every batch the log collector (fakes.e2e.test/siem) got
//
// A fault is {host?, path? (prefix), method?, conditional?, mode, times?, ...}; the
// first that matches a request applies, `times` (default unlimited) counts down.
// `conditional: false` matches only requests without If-None-Match (an origin that is
// down behind a CDN still answering revalidations with 304), `true` only those with it.
// Modes:
//   status   answer `status` (with `retryAfter` as Retry-After) and a short body
//   delay    answer normally after `ms`
//   hold     wait for POST /holds/release (at most 60 seconds), then answer normally
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
import { Issuer } from "./issuer.mjs";
import { Npm } from "./npm.mjs";
import { Oidc } from "./oidc.mjs";
import { Osv } from "./osv.mjs";
import { Pypi } from "./pypi.mjs";
import { Siem } from "./siem.mjs";

const TLS_DIR = process.env.E2E_TLS_DIR ?? "/e2e/tls";
const fakes = { npm: new Npm(), npmB: new Npm("https://registry-b.e2e.test"), pypi: new Pypi(), osv: new Osv(), hibp: new Hibp(), oidc: new Oidc(), siem: new Siem() };
const issuers = { a: new Issuer("a"), b: new Issuer("b") };
const hosts = {
  "registry.npmjs.org": fakes.npm,
  "registry-b.e2e.test": fakes.npmB,
  "private-registry.e2e.test": fakes.npmB,
  "pypi.org": fakes.pypi,
  "files.pythonhosted.org": fakes.pypi,
  "api.osv.dev": fakes.osv,
  "api.pwnedpasswords.com": fakes.hibp,
  "idp.e2e.test": fakes.oidc,
  "accounts.google.com": fakes.oidc,
  "fakes.e2e.test": fakes.siem,
};
let faults = [];
let log = [];
const hanging = new Set();
const held = new Set();

function releaseHeld() {
  for (const release of held) release();
}

function hold() {
  return new Promise((resolve) => {
    const release = () => {
      clearTimeout(timer);
      held.delete(release);
      resolve();
    };
    const timer = setTimeout(release, 60_000);
    held.add(release);
  });
}

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
    (f) =>
      (!f.host || f.host === host) &&
      (!f.path || req.url.startsWith(f.path)) &&
      (!f.method || f.method === req.method) &&
      (f.conditional === undefined || f.conditional === Boolean(req.headers["if-none-match"])),
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
  // Only the two signed-delete destinations the scenarios approve are redacted (host and path
  // prefix each; the second only when it really carries the signed query), so the redaction cannot hide an unrelated request in the egress inventory.
  const signedDelete = (host === "registry-b.e2e.test" && req.url.startsWith("/extra/case/"))
    || (host === "registry.npmjs.org" && req.url.startsWith("/custom/case/") && req.url.includes("?sig="));
  const entry = { at: new Date().toISOString(), host, method: req.method,
    peer: req.socket.remoteAddress,
    path: signedDelete ? `${req.url.split("?")[0]}?<redacted>` : req.url,
    signedQueryValid: signedDelete && new URL(req.url, `https://${host}`).searchParams.get("sig") === "d41-signed-secret",
    status: 0,
    contentEncoding: req.headers["content-encoding"] ?? "none",
    credential: req.headers.authorization === "Bearer e2e-owner" ? "developer-owner"
      : req.headers.authorization === "Bearer e2e-denied" ? "developer-denied"
      : req.headers.authorization === "Basic ZTJlLW93bmVyOmUyZS1wYXNzd29yZA==" ? "developer-basic"
      : req.headers.authorization?.startsWith("Bearer prb_") ? "policy-key"
      : req.headers.authorization ? "other" : "none" };
  log.push(entry);
  const body = await readBody(req);
  entry.bodyBytes = body.length;
  const f = fault(host, req);
  entry.fault = f?.mode;
  if (f?.mode === "hang") return hang(req);
  if (f?.mode === "reset") return req.socket.destroy();
  if (f?.mode === "delay") await sleep(f.ms ?? 1000);
  if (f?.mode === "hold") await hold();
  let answer;
  if (f?.mode === "status") {
    answer = { status: f.status ?? 503, headers: f.retryAfter ? { "retry-after": String(f.retryAfter) } : {}, body: `fault ${f.status ?? 503}\n` };
  } else if (f?.mode === "json") {
    answer = { status: f.status ?? 200, headers: { "content-type": "application/json" }, body: JSON.stringify(f.body ?? {}) };
  } else if (f?.mode === "redirect") {
    answer = { status: 302, headers: { location: f.location }, body: "redirect\n" };
  } else if (f?.mode === "oversize") {
    answer = { status: 200, headers: { "content-type": "application/octet-stream" }, body: Buffer.alloc(f.bytes, 120) };
  } else if (host in { "ocsp-a.e2e.test": 1, "ocsp-b.e2e.test": 1, "private-ocsp.e2e.test": 1 } && req.method === "POST" && req.url === "/status") {
    const issuer = issuers[host === "ocsp-b.e2e.test" ? "b" : "a"];
    const signer = issuer.statusMode === "wrong-issuer" ? issuers[issuer.name === "a" ? "b" : "a"] : issuer;
    answer = { status: 200, headers: { "content-type": "application/ocsp-response" }, body: signer.respond(body) };
  } else if (host === "private-registry.e2e.test" && req.method === "POST" && req.url === "/") {
    answer = fakes.pypi.handle(req, req.url, host, body);
  } else {
    const fake = hosts[host];
    answer = fake ? fake.handle(req, req.url, host, body) : { status: 404, body: `no fake for ${host}\n` };
  }
  if (f?.mode === "omit-revision" && answer.status >= 200 && answer.status < 300) {
    const value = JSON.parse(answer.body);
    delete value.rev;
    answer.body = JSON.stringify(value);
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
    for (const issuer of Object.values(issuers)) issuer.reset();
    faults = [];
    log = [];
    releaseHeld();
    for (const socket of hanging) socket.destroy();
    return { ok: true };
  },
  "GET /log": (_, url) => log.filter((e) => !url.searchParams.get("host") || e.host === url.searchParams.get("host")),
  "POST /faults": (body) => {
    faults = body.faults ?? [];
    releaseHeld();
    for (const socket of hanging) socket.destroy();
    return { ok: true };
  },
  "POST /holds/release": () => (releaseHeld(), { ok: true }),
  "POST /npm/publish": (body) => fakes.npm.publish(body),
  "POST /npm-b/publish": (body) => fakes.npmB.publish(body),
  "POST /issuer/issue": (body) => issuers[body.issuer]?.issue(body.memberUuid, body.aiaUrl) ?? (() => { throw new Error("unknown issuer"); })(),
  "POST /issuer/revoke": (body) => issuers[body.issuer]?.revoke(body.id) ?? (() => { throw new Error("unknown issuer"); })(),
  "POST /issuer/mode": (body) => issuers[body.issuer]?.mode(body.mode) ?? (() => { throw new Error("unknown issuer"); })(),
  "POST /pypi/publish": (body) => fakes.pypi.publish(body),
  "POST /osv/flag": (body) => (fakes.osv.flag(body), { ok: true }),
  "GET /osv/queries": () => fakes.osv.queries,
  "POST /hibp/leak": (body) => (fakes.hibp.leak(body.password), { ok: true }),
  "POST /oidc/next": (body) => (fakes.oidc.next(body), { ok: true }),
  "POST /oidc/rotate": () => (fakes.oidc.rotate(), { ok: true }),
  "GET /siem/batches": () => fakes.siem.batches,
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
