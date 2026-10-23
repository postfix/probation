// The host's HTTP client into the stack, and the portal driver for API-only steps.
//
// Every request tunnels through the bridge's CONNECT proxy, so a URL names a service
// exactly as the stack does (`https://fw1.e2e.test/...`) and its certificate is checked
// against the e2e CA. Connections are pooled per host.

import { createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";

let bridge;
let ca;
const agents = new Map();

/// Points the client at the bridge (`127.0.0.1:<port>`) and the e2e CA.
export function configure({ bridgePort, caFile }) {
  bridge = { host: "127.0.0.1", port: bridgePort };
  ca = readFileSync(caFile);
  agents.clear();
}

function tunnel(host, port, callback) {
  const connect = http.request({ ...bridge, method: "CONNECT", path: `${host}:${port}`, agent: false });
  connect.on("connect", (answer, socket) => {
    if (answer.statusCode !== 200) {
      socket.destroy();
      callback(new Error(`bridge refused ${host}:${port}: ${answer.statusCode}`));
    } else callback(null, socket);
  });
  connect.on("error", callback);
  connect.end();
}

/// A keep-alive agent whose connections are tunnels through the bridge.
function tunnelAgent(secure) {
  const Base = secure ? https.Agent : http.Agent;
  const agent = new Base({ keepAlive: true, maxSockets: 64 });
  agent.createConnection = (options, callback) => {
    tunnel(options.host, options.port, (err, socket) => {
      if (err) return callback(err);
      if (!secure) return callback(null, socket);
      const secured = tls.connect({ socket, servername: options.servername ?? options.host, ca });
      secured.once("secureConnect", () => callback(null, secured));
      secured.once("error", callback);
    });
  };
  return agent;
}

function agentFor(url) {
  if (!agents.has(url.protocol)) agents.set(url.protocol, tunnelAgent(url.protocol === "https:"));
  return agents.get(url.protocol);
}

/// One request: {method, headers, body (string | Buffer | object as JSON), timeout ms}.
/// Answers {status, headers, body (string), bytes (Buffer), json()}; never follows a
/// redirect.
export function request(target, { method = "GET", headers = {}, body, timeout = 30_000 } = {}) {
  const url = new URL(target);
  let payload = body;
  const sent = { ...headers };
  if (payload !== undefined && typeof payload === "object" && !Buffer.isBuffer(payload)) {
    payload = JSON.stringify(payload);
    sent["content-type"] ??= "application/json";
  }
  return new Promise((resolve, reject) => {
    const lib = url.protocol === "https:" ? https : http;
    const req = lib.request(url, { method, headers: sent, agent: agentFor(url), timeout }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const bytes = Buffer.concat(chunks);
        const text = bytes.toString();
        resolve({ status: res.statusCode, headers: res.headers, bytes, body: text, json: () => JSON.parse(text) });
      });
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error(`${method} ${target}: no answer in ${timeout} ms`)));
    req.on("error", reject);
    req.end(payload);
  });
}

export function expect(condition, message) {
  if (!condition) throw new Error(message);
}

export function unescape(html) {
  return html
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&#x27;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

/// The text between `start` and `end` in a page, unescaped.
export function between(body, start, end) {
  const from = body.indexOf(start);
  expect(from >= 0, `no ${start} in the page:\n${body}`);
  const to = body.indexOf(end, from + start.length);
  return unescape(body.slice(from + start.length, to));
}

export function hidden(body, name) {
  const found = body.match(new RegExp(`name="${name}" value="([^"]*)"`));
  expect(found, `no hidden ${name} in the page:\n${body}`);
  return unescape(found[1]);
}

/// The portal through one cookie jar, never following a redirect (API-only steps;
/// use the Playwright browser for anything a person does in a browser).
export class Portal {
  cookies = new Map();

  /// `clientIp`: the address this person browses from, sent in X-Forwarded-For (the
  /// server trusts the bridge and the gateway in front of it). A new one for each
  /// Portal, so the server's per-address limits see separate people, not one host.
  constructor(base = "https://portal.e2e.test", clientIp = randomClientIp()) {
    this.base = base;
    this.clientIp = clientIp;
  }

  async fetch(path, form) {
    const headers = { "x-forwarded-for": this.clientIp };
    if (this.cookies.size) headers.cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
    let body;
    if (form) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams(form).toString();
    }
    const answer = await request(this.base + path, { method: form ? "POST" : "GET", headers, body });
    for (const line of [answer.headers["set-cookie"] ?? []].flat()) {
      const pair = line.split(";")[0];
      const at = pair.indexOf("=");
      const name = pair.slice(0, at).trim();
      if (/max-age=0/i.test(line)) this.cookies.delete(name);
      else this.cookies.set(name, pair.slice(at + 1));
    }
    return { status: answer.status, location: answer.headers.location ?? null, body: answer.body };
  }

  get(path) {
    return this.fetch(path);
  }

  post(path, form) {
    return this.fetch(path, form);
  }

  /// Loads `page`, then POSTs `form` to `path` with that page's CSRF token.
  async submit(page, path, form) {
    const csrf = hidden((await this.get(page)).body, "csrf");
    return this.post(path, { ...form, csrf });
  }
}

/// A client address in 10.200.0.0/16, the range the harness's simulated people use.
export function randomClientIp() {
  const [a, b] = randomBytes(2);
  return `10.200.${a}.${b === 0 ? 1 : b}`;
}

function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of text.replace(/[\s=]/g, "").toUpperCase()) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const bytes = [];
  for (let at = 0; at + 8 <= bits.length; at += 8) bytes.push(parseInt(bits.slice(at, at + 8), 2));
  return Buffer.from(bytes);
}

/// RFC 6238 with SHA-1, 6 digits, 30 s steps, as an authenticator app computes it.
export function totp(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = mac[19] & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

export const step = () => Math.floor(Date.now() / 30_000);

/// An authenticator that never repeats a step: the server accepts one step either side
/// of now and each step once (T15), so a code for the next step is used before waiting.
export class Authenticator {
  constructor(secret, lastStep = 0) {
    this.secret = secret;
    this.lastStep = lastStep;
  }

  async code() {
    let next = Math.max(step(), this.lastStep + 1);
    while (next > step() + 1) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      next = Math.max(step(), this.lastStep + 1);
    }
    this.lastStep = next;
    return totp(this.secret, next);
  }
}
