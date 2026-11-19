// The fake RubyGems, answering as https://rubygems.org: the compact index (versions, names,
// info/<gem>), the legacy tuple indexes (specs, latest_specs and prerelease_specs, gzip
// Marshal), quick gemspecs (zlib Marshal), the gems themselves (real .gem archives built in
// memory) and rubygems.org's timeframe_versions API. Nothing here shells out: the Marshal and
// the archives are written by hand, and the Ruby client in the stack reads them.

import { createHash } from "node:crypto";
import { deflateSync, gunzipSync, gzipSync } from "node:zlib";
import { tgz } from "./archive.mjs";

/// Entries per `timeframe_versions` page: short on purpose.
export const PAGE = 2;

const sha = (algo, bytes) => createHash(algo).update(bytes).digest("hex");

// ---- Ruby Marshal 4.8, just the values a gemspec and a tuple index hold ----

function long(n) {
  if (n === 0) return [0];
  if (n > 0 && n < 123) return [n + 5];
  if (n < 0 && n > -124) return [(n - 5) & 0xff];
  const bytes = [];
  let x = n;
  for (let i = 0; i < 4; i++) {
    bytes.push(x & 0xff);
    x >>= 8;
    if (x === 0 || x === -1) break;
  }
  return [n < 0 ? 256 - bytes.length : bytes.length, ...bytes];
}
const sym = (name) => [0x3a, ...long(name.length), ...Buffer.from(name)];
const nil = () => [0x30];
const str = (text) => {
  const bytes = Buffer.from(text);
  return [0x49, 0x22, ...long(bytes.length), ...bytes, ...long(1), ...sym("E"), 0x54];
};
const array = (items) => [0x5b, ...long(items.length), ...items.flat()];
const version = (text) => [0x55, ...sym("Gem::Version"), ...array([str(text)])];
// Requirement#marshal_dump is `[@requirements]`.
const requirement = (op, v) => [0x55, ...sym("Gem::Requirement"), ...array([array([array([str(op), version(v)])])])];
const dump = (body) => Buffer.from([4, 8, ...body.flat()]);

/// What `Gem::Specification#_dump` holds (no dependencies, no date).
function specPayload({ name, ver, platform, summary }) {
  return dump([
    array([
      str("3.6.7"), [0x69, ...long(4)], str(name), version(ver), nil(), str(summary),
      requirement(">=", "0"), requirement(">=", "0"), str(platform), array([]), nil(), nil(),
      array([str("probation-e2e")]), str(summary), nil(), [0x54], str(platform), array([]), [0x7b, ...long(0)],
    ]),
  ]);
}

/// A quick gemspec: `Marshal.dump(spec)` deflated, as `/quick/Marshal.4.8/<file>.gemspec.rz`.
function quickGemspec(spec) {
  const payload = specPayload(spec);
  // Real quick gemspecs are a plain `u:` (no `I` wrapper: RubyGems' safe loader refuses an ivar on it).
  const outer = dump([[0x75, ...sym("Gem::Specification"), ...long(payload.length), ...payload]]);
  return deflateSync(outer);
}

/// A tuple index (`specs.4.8.gz` and its two siblings): `[[name, Gem::Version, platform], ...]`.
function tupleIndex(tuples) {
  return gzipSync(dump([array(tuples.map(([n, v, p]) => array([str(n), version(v), str(p)])))]));
}

// ---- the .gem archive: tar { metadata.gz, data.tar.gz, checksums.yaml.gz } ----

function metadataYaml({ name, ver, platform, summary }) {
  return `--- !ruby/object:Gem::Specification
name: ${name}
version: !ruby/object:Gem::Version
  version: ${ver}
platform: ${platform}
authors:
- probation-e2e
autorequire:
bindir: bin
cert_chain: []
date: 2024-01-01 00:00:00.000000000 Z
dependencies: []
description: ${summary}
email:
executables: []
extensions: []
extra_rdoc_files: []
files:
- lib/${name.replaceAll("-", "_")}.rb
homepage:
licenses: []
metadata: {}
post_install_message:
rdoc_options: []
require_paths:
- lib
required_ruby_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
required_rubygems_version: !ruby/object:Gem::Requirement
  requirements:
  - - ">="
    - !ruby/object:Gem::Version
      version: '0'
requirements: []
rubygems_version: 3.6.7
signing_key:
specification_version: 4
summary: ${summary}
test_files: []
`;
}

function gem(spec) {
  const module = spec.name.replaceAll("-", "_");
  const metadata = gzipSync(Buffer.from(metadataYaml(spec)));
  const data = tgz({ [`lib/${module}.rb`]: `module E2E; VERSION_OF_${module.toUpperCase().replaceAll(/[^A-Z0-9]/g, "_")} = ${JSON.stringify(spec.ver)}; end\n` });
  const checksums = gzipSync(Buffer.from(
    `---\nSHA256:\n  metadata.gz: ${sha("sha256", metadata)}\n  data.tar.gz: ${sha("sha256", data)}\nSHA512:\n  metadata.gz: ${sha("sha512", metadata)}\n  data.tar.gz: ${sha("sha512", data)}\n`,
  ));
  // tgz() gzips a tar of its entries; a .gem is that tar uncompressed.
  return gunzipSync(tgz({ "metadata.gz": metadata, "data.tar.gz": data, "checksums.yaml.gz": checksums }));
}

const fileOf = (name, ver, platform) => `${name}-${ver}${platform === "ruby" ? "" : `-${platform}`}`;

export class RubyGems {
  constructor() {
    this.reset();
  }

  reset() {
    this.gems = new Map(); // name -> [{ver, platform, created (ms), bytes, sha256}]
    this.writes = [];
    // Seeded so a stack with no scenario still answers like a registry.
    this.publish({ name: "e2e-seed", version: "1.0.0", ageSeconds: 400 * 86_400 });
  }

  /// Adds a release. `ageSeconds` (or `createdAt`, ISO) is its registry publication time.
  publish({ name, version: ver, platform = "ruby", ageSeconds = 0, createdAt, summary = "e2e gem" }) {
    const spec = { name, ver, platform, summary };
    const bytes = gem(spec);
    const created = createdAt ? Date.parse(createdAt) : Date.now() - ageSeconds * 1000;
    const list = this.gems.get(name) ?? [];
    const kept = list.filter((g) => !(g.ver === ver && g.platform === platform));
    kept.push({ ver, platform, created, bytes, sha256: sha("sha256", bytes), quick: quickGemspec(spec) });
    this.gems.set(name, kept);
    return { name, version: ver, platform, file: `${fileOf(name, ver, platform)}.gem`, sha256: sha("sha256", bytes), createdAt: new Date(created).toISOString() };
  }

  info(name) {
    const list = this.gems.get(name);
    if (!list) return { status: 404, body: "This gem could not be found" };
    const lines = list.map((g) => `${g.ver}${g.platform === "ruby" ? "" : `-${g.platform}`} |checksum:${g.sha256},created_at:${new Date(g.created).toISOString().replace(/\.\d+Z$/, "Z")},ruby:>= 0`);
    return { status: 200, headers: { "content-type": "text/plain; charset=utf-8" }, body: `---\n${lines.join("\n")}\n` };
  }

  versions() {
    const lines = [...this.gems].map(([n, l]) => `${n} ${l.map((g) => `${g.ver}${g.platform === "ruby" ? "" : `-${g.platform}`}`).join(",")} ${sha("md5", this.info(n).body)}`);
    return { status: 200, headers: { "content-type": "text/plain; charset=utf-8" }, body: `created_at: ${new Date().toISOString()}\n---\n${lines.join("\n")}\n` };
  }

  tuples(which) {
    const all = [...this.gems].flatMap(([n, l]) => l.map((g) => [n, g.ver, g.platform, g]));
    const pre = (v) => /[a-zA-Z]/.test(v);
    let chosen = all.filter(([, v]) => !pre(v));
    if (which === "prerelease") chosen = all.filter(([, v]) => pre(v));
    if (which === "latest") {
      const best = new Map();
      for (const t of chosen) {
        const key = `${t[0]}\0${t[2]}`;
        const cur = best.get(key);
        if (!cur || compare(t[1], cur[1]) > 0) best.set(key, t);
      }
      chosen = [...best.values()];
    }
    return tupleIndex(chosen.map(([n, v, p]) => [n, v, p]));
  }

  /// One page of versions created in [from, to], oldest first. Real rubygems.org pages this API
  /// (`page=`, thousands of versions a week); the fake pages short (PAGE entries) so a client has
  /// to follow it, and a page past the end is `[]`.
  timeframe(from, to, page = 1) {
    const out = [];
    for (const [name, list] of this.gems) {
      for (const g of list) {
        if (g.created >= from && g.created <= to) {
          out.push({ name, number: g.ver, version: g.ver, platform: g.platform, version_created_at: new Date(g.created).toISOString(), sha: g.sha256 });
        }
      }
    }
    out.sort((a, b) => a.version_created_at.localeCompare(b.version_created_at) || a.name.localeCompare(b.name) || a.number.localeCompare(b.number));
    return out.slice((page - 1) * PAGE, page * PAGE);
  }

  handle(req, path, host, body) {
    const url = new URL(path, "https://rubygems.org");
    const p = url.pathname;
    if ((req.method === "POST" && p === "/api/v1/gems") || (req.method === "DELETE" && p === "/api/v1/gems/yank")) {
      // RubyGems takes the API key bare in `Authorization` and a one-time code in `OTP`.
      const authorization = req.headers.authorization;
      const write = {
        method: req.method, path: p, authorization: authorization ?? null, otp: req.headers.otp ?? null,
        contentType: req.headers["content-type"] ?? null, bytes: body.length, body: req.method === "DELETE" ? body.toString() : undefined,
      };
      this.writes.push(write);
      if (!authorization) return { status: 401, body: "Access Denied. Please sign up for an account at https://rubygems.org" };
      if (authorization === "e2e-denied") return { status: 403, body: "The gem owner does not allow this" };
      if (authorization !== "e2e-owner") return { status: 401, body: "Access Denied" };
      return { status: 200, body: req.method === "POST" ? "Successfully registered gem" : "Successfully yanked gem" };
    }
    if (p === "/versions") return this.versions();
    if (p === "/names") return { status: 200, headers: { "content-type": "text/plain" }, body: `---\n${[...this.gems.keys()].join("\n")}\n` };
    let m;
    if ((m = p.match(/^\/info\/([^/]+)$/))) return this.info(this.canonical(decodeURIComponent(m[1])));
    if (p === "/specs.4.8.gz") return { status: 200, headers: { "content-type": "application/octet-stream" }, body: this.tuples("all") };
    if (p === "/latest_specs.4.8.gz") return { status: 200, headers: { "content-type": "application/octet-stream" }, body: this.tuples("latest") };
    if (p === "/prerelease_specs.4.8.gz") return { status: 200, headers: { "content-type": "application/octet-stream" }, body: this.tuples("prerelease") };
    if (p === "/api/v1/timeframe_versions.json") {
      const from = Date.parse(url.searchParams.get("from") ?? "");
      const to = Date.parse(url.searchParams.get("to") ?? "");
      if (Number.isNaN(from) || Number.isNaN(to)) return { status: 400, body: '{"error":"bad time range"}' };
      if (to - from > 7 * 86_400_000) return { status: 400, body: '{"error":"the supplied query time range cannot exceed 7 days"}' };
      const page = Number(url.searchParams.get("page") ?? "1");
      if (!Number.isInteger(page) || page < 1) return { status: 400, body: '{"error":"bad page"}' };
      return { status: 200, headers: { "content-type": "application/json; charset=utf-8" }, body: JSON.stringify(this.timeframe(from, to, page)) };
    }
    if ((m = p.match(/^\/quick\/Marshal\.4\.8\/(.+)\.gemspec\.rz$/))) {
      return this.file(m[1], "quick");
    }
    if ((m = p.match(/^\/gems\/(.+)\.gem$/))) {
      return this.file(m[1], "bytes");
    }
    return { status: 404, body: "Not Found" };
  }

  /// rubygems.org answers the index of `rack` for `Rack` (checked against the real thing).
  canonical(name) {
    return [...this.gems.keys()].find((n) => n.toLowerCase() === name.toLowerCase()) ?? name;
  }

  /// Files are case-exact: `redcloth-4.3.2.gem` of `RedCloth` is Forbidden, as on the real CDN.
  file(file, field) {
    const found = this.byFile(file);
    if (found) return { status: 200, headers: { "content-type": "application/octet-stream" }, body: found[field] };
    const folded = [...this.gems].some(([n, l]) => l.some((g) => fileOf(n, g.ver, g.platform).toLowerCase() === file.toLowerCase()));
    return folded ? { status: 403, body: "Forbidden" } : { status: 404, body: "Not Found" };
  }

  byFile(file) {
    for (const [name, list] of this.gems) {
      for (const g of list) if (fileOf(name, g.ver, g.platform) === file) return g;
    }
    return null;
  }
}

/// Orders versions the way the "latest" index needs: numeric segments numerically.
function compare(a, b) {
  const x = a.split("."), y = b.split(".");
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (Number(x[i] ?? 0) || 0) - (Number(y[i] ?? 0) || 0);
    if (d) return d;
  }
  return 0;
}

export { gem as buildGem, quickGemspec, tupleIndex };
