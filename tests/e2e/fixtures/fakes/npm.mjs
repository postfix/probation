// The fake npm registry, answering as https://registry.npmjs.org: full and abbreviated
// package documents (scoped names too), and tarballs with real sha512 integrity and
// sha1 shasum. Publish times are set per version, so freezes need no clock control.

import { createHash } from "node:crypto";
import { tgz } from "./archive.mjs";

const ORIGIN = "https://registry.npmjs.org";
const DAY = 86_400_000;

export class Npm {
  constructor() {
    this.reset();
  }

  /// The seed catalogue every scenario starts from; all of it older than any freeze.
  reset() {
    this.packages = new Map();
    const ago = (days) => new Date(Date.now() - days * DAY).toISOString();
    for (const [version, days] of [["1.0.0", 400], ["1.1.0", 300], ["2.0.0", 200]]) {
      this.publish({ name: "e2e-left", version, publishedAt: ago(days) });
    }
    this.publish({ name: "e2e-right", version: "1.0.0", publishedAt: ago(400), dependencies: { "e2e-left": "^1.0.0" } });
    this.publish({ name: "@e2e/scoped", version: "1.0.0", publishedAt: ago(400) });
    this.publish({ name: "@e2e/scoped", version: "1.0.1", publishedAt: ago(390) });
    // Many versions of one package, for scenarios that block versions one by one.
    for (let minor = 0; minor < 60; minor++) {
      this.publish({ name: "e2e-many", version: `1.${minor}.0`, publishedAt: ago(400 - minor) });
    }
  }

  /// Adds a version. `ageSeconds` (relative to now) or `publishedAt` (ISO) sets its
  /// publish time; `tag` (default `latest`, null for none) points a dist-tag at it.
  publish({ name, version, publishedAt, ageSeconds, dependencies = {}, tag = "latest", files = {} }) {
    const at = publishedAt ?? new Date(Date.now() - (ageSeconds ?? 0) * 1000).toISOString();
    const base = name.split("/").pop();
    const tarball = tgz({
      "package/package.json": JSON.stringify({ name, version, main: "index.js", dependencies }, null, 2),
      "package/index.js": `module.exports = ${JSON.stringify(`${name}@${version}`)};\n`,
      ...Object.fromEntries(Object.entries(files).map(([path, content]) => [`package/${path}`, content])),
    });
    const record = {
      name,
      version,
      dependencies,
      published: at,
      bytes: tarball,
      dist: {
        tarball: `${ORIGIN}/${name}/-/${base}-${version}.tgz`,
        shasum: createHash("sha1").update(tarball).digest("hex"),
        integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
      },
    };
    let entry = this.packages.get(name);
    if (!entry) this.packages.set(name, (entry = { versions: new Map(), tags: {} }));
    entry.versions.set(version, record);
    if (tag) entry.tags[tag] = version;
    return record.dist;
  }

  document(name, abbreviated) {
    const entry = this.packages.get(name);
    if (!entry) return null;
    const records = [...entry.versions.values()];
    const modified = records.map((r) => r.published).sort().at(-1);
    const versions = {};
    for (const r of records) {
      versions[r.version] = abbreviated
        ? { name, version: r.version, dependencies: r.dependencies, dist: r.dist }
        : { name, version: r.version, dependencies: r.dependencies, main: "index.js", _id: `${name}@${r.version}`, dist: r.dist };
    }
    if (abbreviated) return { name, modified, "dist-tags": entry.tags, versions };
    const time = { created: records.map((r) => r.published).sort()[0], modified };
    for (const r of records) time[r.version] = r.published;
    return { _id: name, name, "dist-tags": entry.tags, versions, time };
  }

  handle(req, path) {
    const decoded = decodeURIComponent(path).slice(1);
    const at = decoded.indexOf("/-/");
    if (at >= 0) {
      const name = decoded.slice(0, at);
      const file = decoded.slice(at + 3);
      const entry = this.packages.get(name);
      const record = entry && [...entry.versions.values()].find((r) => r.dist.tarball.endsWith(`/-/${file}`));
      if (!record) return { status: 404, body: '{"error":"Not found"}' };
      return { status: 200, headers: { "content-type": "application/octet-stream" }, body: record.bytes };
    }
    const abbreviated = (req.headers.accept ?? "").includes("application/vnd.npm.install-v1+json");
    const document = this.document(decoded, abbreviated);
    if (!document) return { status: 404, body: '{"error":"Not found"}' };
    const contentType = abbreviated ? "application/vnd.npm.install-v1+json" : "application/json";
    return { status: 200, headers: { "content-type": contentType }, body: JSON.stringify(document) };
  }
}
