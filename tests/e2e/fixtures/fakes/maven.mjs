// The fake Maven Central, answering as https://repo.maven.apache.org (the tree below `/maven2/`): `maven-metadata.xml` of
// an artifact (artifact level and a snapshot version's), the POM, JAR and sources JAR of every version with the
// repository's `Last-Modified` (the publication time of the file, which is what dates a version), the checksum sidecars
// (`.sha1`, `.md5`, `.sha256`, `.sha512`), a plugin group's metadata, an archetype catalog, and a deploy endpoint that records
// every write and answers by credential. Group ids are directories, artifact ids and versions are case-exact. Jars are real
// stored zips, so `mvn` verifies and uses them. Nothing shells out.

import { createHash } from "node:crypto";
import { zip } from "./archive.mjs";

const DIGESTS = { sha1: "sha1", md5: "md5", sha256: "sha256", sha512: "sha512" };
const hex = (algorithm, bytes) => createHash(algorithm).update(bytes).digest("hex");

/// The HTTP-date of an epoch time in milliseconds.
export const httpDate = (ms) => new Date(ms).toUTCString();

const pom = (group, artifact, version, dependencies = []) =>
  `<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>${group}</groupId>\n  <artifactId>${artifact}</artifactId>\n  <version>${version}</version>\n${dependencies.length ? `  <dependencies>\n${dependencies.map(([g, a, v]) => `    <dependency><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></dependency>\n`).join("")}  </dependencies>\n` : ""}</project>\n`;

const jar = (artifact, version) => zip({ "META-INF/MANIFEST.MF": `Manifest-Version: 1.0\r\nImplementation-Title: ${artifact}\r\nImplementation-Version: ${version}\r\n\r\n`, [`${artifact}.txt`]: `${artifact} ${version}` });

/// Maven version order, close enough for the fake: numeric parts, then qualifiers.
export function order(a, b) {
  const split = (v) => v.replace(/-SNAPSHOT$/, "").split(/[.-]/).map((p) => (/^\d+$/.test(p) ? Number(p) : p));
  const [x, y] = [split(a), split(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const [p, q] = [x[i] ?? 0, y[i] ?? 0];
    if (p === q) continue;
    if (typeof p === "number" && typeof q === "number") return p - q;
    return String(p) < String(q) ? -1 : 1;
  }
  return 0;
}

export class Maven {
  constructor() {
    this.reset();
  }

  reset() {
    this.artifacts = new Map(); // "group:artifact" -> {group, artifact, versions: Map(version -> {created, dated, builds: [...]})}
    this.plugins = new Map(); // group -> [{name, prefix, artifact}]
    this.writes = []; // every deploy-endpoint call: {method, path, authorization, contentType, bytes, sha256}
    this.requests = [];
    this.publish({ group: "org.e2e", artifact: "seed", version: "1.0", ageSeconds: 400 * 86_400 });
  }

  /// Adds a release (or, with `build`, one timestamped build of a `-SNAPSHOT` version). `ageSeconds` (or `publishedAt`, ISO) is the
  /// publication time every file of it carries as `Last-Modified`; `undated` leaves the header out.
  publish({ group, artifact, version, ageSeconds = 0, publishedAt, undated = false, build = null, dependencies = [] }) {
    const key = `${group}:${artifact}`;
    const entry = this.artifacts.get(key) ?? { group, artifact, versions: new Map() };
    const created = publishedAt ? Date.parse(publishedAt) : Date.now() - ageSeconds * 1000;
    const unit = entry.versions.get(version) ?? { builds: new Map(), created, dated: !undated, dependencies };
    if (build) unit.builds.set(build, { created, dated: !undated });
    else Object.assign(unit, { created, dated: !undated, dependencies });
    entry.versions.set(version, unit);
    this.artifacts.set(key, entry);
    return { group, artifact, version, build, publishedAt: new Date(created).toISOString() };
  }

  plugin({ group, name, prefix, artifact }) {
    const list = this.plugins.get(group) ?? [];
    list.push({ name, prefix, artifact });
    this.plugins.set(group, list);
    return { ok: true };
  }

  sorted(entry) {
    return [...entry.versions.keys()].sort(order);
  }

  file(bytes, created, dated, type = "application/octet-stream") {
    const headers = { "content-type": type };
    if (dated) headers["last-modified"] = httpDate(created);
    return { status: 200, headers, body: bytes };
  }

  /// The checksum sidecar of `bytes`, if `algorithm` is a digest.
  sidecar(algorithm, bytes, created, dated) {
    return this.file(Buffer.from(hex(DIGESTS[algorithm], bytes)), created, dated, "text/plain");
  }

  metadata(entry) {
    const names = this.sorted(entry);
    const releases = names.filter((v) => !v.endsWith("-SNAPSHOT"));
    const list = names.map((v) => `      <version>${v}</version>\n`).join("");
    return `<?xml version="1.0" encoding="UTF-8"?>\n<metadata>\n  <groupId>${entry.group}</groupId>\n  <artifactId>${entry.artifact}</artifactId>\n  <versioning>\n    <latest>${names.at(-1)}</latest>\n${releases.length ? `    <release>${releases.at(-1)}</release>\n` : ""}    <versions>\n${list}    </versions>\n    <lastUpdated>20260101000000</lastUpdated>\n  </versioning>\n</metadata>\n`;
  }

  snapshotMetadata(entry, version) {
    const unit = entry.versions.get(version);
    const base = version.replace(/-SNAPSHOT$/, "");
    const builds = [...unit.builds.keys()].sort();
    const [stamp, number] = builds.at(-1).split("-");
    const items = builds.map((b) => `      <snapshotVersion>\n        <extension>jar</extension>\n        <value>${base}-${b}</value>\n        <updated>20260101000000</updated>\n      </snapshotVersion>\n`).join("");
    return `<?xml version="1.0" encoding="UTF-8"?>\n<metadata modelVersion="1.1.0">\n  <groupId>${entry.group}</groupId>\n  <artifactId>${entry.artifact}</artifactId>\n  <version>${version}</version>\n  <versioning>\n    <snapshot>\n      <timestamp>${stamp}</timestamp>\n      <buildNumber>${number}</buildNumber>\n    </snapshot>\n    <lastUpdated>20260101000000</lastUpdated>\n    <snapshotVersions>\n${items}    </snapshotVersions>\n  </versioning>\n</metadata>\n`;
  }

  pluginMetadata(group) {
    const items = this.plugins.get(group).map((p) => `  <plugin>\n    <name>${p.name}</name>\n    <prefix>${p.prefix}</prefix>\n    <artifactId>${p.artifact}</artifactId>\n  </plugin>\n`).join("");
    return `<?xml version="1.0" encoding="UTF-8"?>\n<metadata>\n<plugins>\n${items}</plugins>\n</metadata>\n`;
  }

  catalog() {
    const items = [...this.artifacts.values()].flatMap((e) => [...e.versions.keys()].map((v) => `    <archetype>\n      <groupId>${e.group}</groupId>\n      <artifactId>${e.artifact}</artifactId>\n      <version>${v}</version>\n      <description>e2e</description>\n    </archetype>\n`)).join("");
    return `<?xml version="1.0" encoding="UTF-8"?>\n<archetype-catalog>\n  <archetypes>\n${items}  </archetypes>\n</archetype-catalog>\n`;
  }

  /// A file of the tree below `/maven2/`.
  tree(rest) {
    const text = (status, bodyText) => ({ status, headers: { "content-type": "text/plain" }, body: bodyText });
    const split = (path) => {
      const m = path.match(/^(.*?)(?:\.(sha1|md5|sha256|sha512))?$/);
      return [m[1], m[2] ?? null];
    };
    const [base, sum] = split(rest);
    const answer = (bytes, created, dated, type) => (sum ? this.sidecar(sum, bytes, created, dated) : this.file(bytes, created, dated, type));
    if (base === "archetype-catalog.xml") return answer(Buffer.from(this.catalog()), Date.now(), true, "text/xml");
    const parts = base.split("/");
    const last = parts.at(-1);
    if (last === "maven-metadata.xml") {
      const dirs = parts.slice(0, -1);
      if (dirs.length > 2 && dirs.at(-1).endsWith("-SNAPSHOT")) {
        const entry = this.artifacts.get(`${dirs.slice(0, -2).join(".")}:${dirs.at(-2)}`);
        if (entry?.versions.get(dirs.at(-1))?.builds.size) return answer(Buffer.from(this.snapshotMetadata(entry, dirs.at(-1))), Date.now(), true, "text/xml");
        return text(404, "not found");
      }
      if (this.plugins.has(dirs.join("."))) return answer(Buffer.from(this.pluginMetadata(dirs.join("."))), Date.now(), true, "text/xml");
      const entry = this.artifacts.get(`${dirs.slice(0, -1).join(".")}:${dirs.at(-1)}`);
      return entry ? answer(Buffer.from(this.metadata(entry)), Date.now(), true, "text/xml") : text(404, "not found");
    }
    const [version, artifact] = [parts.at(-2), parts.at(-3)];
    const entry = this.artifacts.get(`${parts.slice(0, -3).join(".")}:${artifact}`);
    const unit = entry?.versions.get(version);
    if (!unit) return text(404, "not found");
    const base2 = version.replace(/-SNAPSHOT$/, "");
    let created = unit.created;
    let dated = unit.dated;
    let fileVersion = version;
    const stamped = last.match(new RegExp(`^${artifact.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-${base2.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-(\\d{8}\\.\\d{6}-\\d+)`));
    if (version.endsWith("-SNAPSHOT") && stamped) {
      const buildUnit = unit.builds.get(stamped[1]);
      if (!buildUnit) return text(404, "not found");
      ({ created, dated } = buildUnit);
      fileVersion = `${base2}-${stamped[1]}`;
    }
    const name = last.replace(/\.(sha1|md5|sha256|sha512)$/, "");
    if (name === `${artifact}-${fileVersion}.pom`) return answer(Buffer.from(pom(entry.group, artifact, fileVersion, unit.dependencies)), created, dated, "text/xml");
    if (name === `${artifact}-${fileVersion}.jar`) return answer(jar(artifact, fileVersion), created, dated, "application/java-archive");
    if (name === `${artifact}-${fileVersion}-sources.jar`) return answer(jar(`${artifact}-sources`, fileVersion), created, dated, "application/java-archive");
    return text(404, "not found");
  }

  /// The deploy endpoint: `PUT` and `DELETE` of any path of the tree. Every call is recorded with its credential; only the
  /// owner (`e2e-owner:e2e-pass`) is accepted, `e2e-denied` is refused with 403, and nothing at all is a 401 challenge.
  deploy(req, url, body) {
    const authorization = req.headers.authorization ?? null;
    this.writes.push({ method: req.method, path: url.pathname, authorization, contentType: req.headers["content-type"] ?? null, bytes: body.length, sha256: body.length ? hex("sha256", body) : null });
    const text = (status, bodyText, headers = {}) => ({ status, headers: { "content-type": "text/plain", ...headers }, body: bodyText });
    if (!authorization) return text(401, "Unauthorized", { "www-authenticate": 'Basic realm="e2e"' });
    const user = Buffer.from(authorization.replace(/^Basic /, ""), "base64").toString();
    if (user.startsWith("e2e-denied:")) return text(403, "Forbidden");
    if (user !== "e2e-owner:e2e-pass") return text(401, "Unauthorized", { "www-authenticate": 'Basic realm="e2e"' });
    return text(req.method === "PUT" ? 201 : 204, req.method === "PUT" ? "Created" : "");
  }

  handle(req, path, host, body) {
    const url = new URL(path, `https://${host}`);
    this.requests.push({ host, method: req.method, path: url.pathname, authorization: req.headers.authorization ?? null });
    if (req.method === "PUT" || req.method === "DELETE") return this.deploy(req, url, body);
    if (req.method !== "GET" && req.method !== "HEAD") return { status: 405, body: "method not allowed" };
    if (!url.pathname.startsWith("/maven2/")) return { status: 404, body: "not found" };
    return this.tree(decodeURIComponent(url.pathname.slice("/maven2/".length)));
  }
}

export { pom, jar };
