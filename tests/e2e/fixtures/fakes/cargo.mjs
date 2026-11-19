// The fake crates.io, answering as https://index.crates.io (config.json and the sparse index) and
// https://static.crates.io (the crate files `dl` names). Archives are real `.crate` files (a
// gzip tar with `<name>-<version>/Cargo.toml` and `src/lib.rs`) built in memory, so Cargo in the
// stack verifies, unpacks and compiles them. The index lines are shaped as crates.io writes them,
// `pubtime` included. Nothing here shells out.

import { createHash } from "node:crypto";
import { tgz } from "./archive.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/// The path of a crate's index file: `1/a`, `2/ab`, `3/a/abc`, `ab/cd/abcd` of the LOWER-CASED name.
export function indexPath(name) {
  const l = name.toLowerCase();
  if (l.length === 1) return `1/${l}`;
  if (l.length === 2) return `2/${l}`;
  if (l.length === 3) return `3/${l[0]}/${l}`;
  return `${l.slice(0, 2)}/${l.slice(2, 4)}/${l}`;
}

const crateFile = (name, ver) => `${name}-${ver}.crate`;

function buildCrate(name, ver) {
  const root = `${name}-${ver}`;
  return tgz({
    [`${root}/Cargo.toml`]: `[package]\nname = "${name}"\nversion = "${ver}"\nedition = "2021"\ndescription = "e2e crate"\nlicense = "MIT"\n`,
    [`${root}/src/lib.rs`]: `pub fn version() -> &'static str { ${JSON.stringify(ver)} }\n`,
  });
}

export class Cargo {
  constructor() {
    this.reset();
  }

  reset() {
    this.crates = new Map(); // lower-cased name -> {name, versions: [{vers, created (ms), yanked, bytes, cksum}]}
    this.dl = "https://static.crates.io/crates";
    this.writes = [];
    // Seeded so a stack with no scenario still answers like a registry.
    this.publish({ name: "e2e-seed", version: "1.0.0", ageSeconds: 400 * 86_400 });
  }

  /// Adds a release. `ageSeconds` (or `publishedAt`, ISO) is its registry publication time (`pubtime`).
  publish({ name, version: vers, ageSeconds = 0, publishedAt, yanked = false }) {
    const bytes = buildCrate(name, vers);
    const created = publishedAt ? Date.parse(publishedAt) : Date.now() - ageSeconds * 1000;
    const key = name.toLowerCase();
    const entry = this.crates.get(key) ?? { name, versions: [] };
    entry.versions = entry.versions.filter((v) => v.vers !== vers);
    entry.versions.push({ vers, created, yanked, bytes, cksum: sha256(bytes) });
    this.crates.set(key, entry);
    return { name, version: vers, file: crateFile(name, vers), cksum: sha256(bytes), publishedAt: new Date(created).toISOString() };
  }

  line(entry, v) {
    return JSON.stringify({
      name: entry.name,
      vers: v.vers,
      deps: [],
      cksum: v.cksum,
      features: {},
      yanked: v.yanked,
      v: 2,
      pubtime: new Date(v.created).toISOString().replace(/\.\d+Z$/, "Z"),
    });
  }

  /// The index file the fake serves for `name` (lower-case path form), or null.
  index(name) {
    const entry = this.crates.get(name.toLowerCase());
    if (!entry) return null;
    return `${entry.versions.map((v) => this.line(entry, v)).join("\n")}\n`;
  }

  /// The registry API (host crates.io): `cargo publish`, `yank`, `unyank`, `owner` and search. The token
  /// arrives bare in `Authorization`; every call is recorded, the owner's token succeeds and a denied
  /// one gets the registry's 403.
  api(req, url, body) {
    const p = url.pathname;
    const authorization = req.headers.authorization ?? null;
    this.writes.push({
      method: req.method, path: p, query: url.search || null, authorization, contentType: req.headers["content-type"] ?? null,
      bytes: body.length, body: body.length < 4096 ? body.toString("latin1") : undefined,
    });
    const json = (status, value) => ({ status, headers: { "content-type": "application/json" }, body: JSON.stringify(value) });
    const read = req.method === "GET";
    if (!read) {
      if (!authorization) return json(401, { errors: [{ detail: "must be logged in to perform that action" }] });
      if (authorization === "e2e-denied") return json(403, { errors: [{ detail: "this token is not allowed to do that" }] });
      if (authorization !== "e2e-owner") return json(401, { errors: [{ detail: "invalid token" }] });
    }
    if (req.method === "PUT" && p === "/api/v1/crates/new") return json(200, { warnings: { invalid_categories: [], invalid_badges: [], other: [] } });
    if (/^\/api\/v1\/crates\/[^/]+\/owners$/.test(p)) {
      if (read) return json(200, { users: [{ id: 1, login: "e2e-owner", name: null }] });
      return json(200, { ok: true, msg: "owners changed" });
    }
    // A registry that answers a write with a redirect (a crate named `redirect-same-...` to another path of
    // its own host, `redirect-away-...` to the archive host): the firewall must not follow it, so neither
    // target is ever asked and the token never goes there.
    const redirected = p.match(/^\/api\/v1\/crates\/(redirect-(same|away)-[^/]+)\/[^/]+\/yank$/);
    if (redirected) return { status: 307, headers: { location: redirected[2] === "same" ? "https://crates.io/api/v1/elsewhere" : "https://static.crates.io/leak" }, body: "" };
    if (/^\/api\/v1\/crates\/[^/]+\/[^/]+\/(yank|unyank)$/.test(p)) return json(200, { ok: true });
    if (read && p === "/api/v1/crates") return json(200, { crates: [{ name: "e2e-seed", max_version: "1.0.0", description: "seed" }], meta: { total: 1 } });
    return json(404, { errors: [{ detail: "Not Found" }] });
  }

  handle(req, path, host, payload = Buffer.alloc(0)) {
    if (host === "crates.io") return this.api(req, new URL(path, "https://crates.io"), payload);
    const p = new URL(path, `https://${host}`).pathname;
    if (host === "static.crates.io") {
      // Anything that arrives with a credential is recorded: the archive host must never see a token.
      if (req.headers.authorization) this.writes.push({ method: req.method, path: new URL(path, "https://static.crates.io").pathname, host, authorization: req.headers.authorization });
      // `dl` has no markers, so cargo asks `/crates/<name>/<version>/download`; names are exact, as
      // object keys are.
      const m = p.match(/^\/crates\/([^/]+)\/([^/]+)\/download$/);
      const found = m && this.crates.get(m[1].toLowerCase());
      const exact = found?.name === m?.[1];
      const v = exact ? found.versions.find((x) => x.vers === m[2]) : undefined;
      if (v) return { status: 200, headers: { "content-type": "application/gzip" }, body: v.bytes };
      return found && !exact ? { status: 403, body: "Forbidden" } : { status: 404, body: "Not Found" };
    }
    if (p === "/config.json") return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ dl: this.dl, api: "https://crates.io" }) };
    const name = p.split("/").pop();
    if (p.slice(1) !== indexPath(name) || name !== name.toLowerCase()) return { status: 404, body: "Not Found" };
    const body = this.index(name);
    return body === null ? { status: 404, body: "Not Found" } : { status: 200, headers: { "content-type": "text/plain" }, body };
  }
}

export { buildCrate };
