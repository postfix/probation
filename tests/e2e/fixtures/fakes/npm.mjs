// The fake npm registry, answering as https://registry.npmjs.org: full and abbreviated
// package documents (scoped names too), and tarballs with real sha512 integrity and
// sha1 shasum. Publish times are set per version, so freezes need no clock control.

import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { tgz } from "./archive.mjs";

const ORIGIN = "https://registry.npmjs.org";
const DAY = 86_400_000;

export class Npm {
  constructor(origin = ORIGIN) {
    this.origin = origin;
    this.reset();
  }

  /// The seed catalogue every scenario starts from; all of it older than any freeze.
  reset() {
    this.packages = new Map();
    this.teams = new Map([["e2e:ops", { "e2e-owner": "developer" }]]);
    this.orgs = new Map([["e2e", { "e2e-owner": "owner" }]]);
    this.profile = { name: "e2e-owner", email: "owner@example.test" };
    this.tokens = new Map();
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
  publish({ name, version, publishedAt, ageSeconds, dependencies = {}, tag = "latest", files = {}, tarballUrl }) {
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
        tarball: tarballUrl ?? `${this.origin}/${name}/-/${base}-${version}.tgz`,
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
      if (name.startsWith("search-bounded-")) versions[r.version].description = "d".repeat(700);
    }
    if (abbreviated) return { name, modified, "dist-tags": entry.tags, versions };
    const time = { created: records.map((r) => r.published).sort()[0], modified };
    for (const r of records) time[r.version] = r.published;
    return { _id: name, _rev: entry.rev ?? "1", name, "dist-tags": entry.tags, versions, time,
      users: entry.users ?? {},
      maintainers: entry.maintainers ?? [{ name: "e2e-owner", email: "owner@example.test" }] };
  }

  handle(req, path, _host, body = Buffer.alloc(0)) {
    const url = new URL(path, this.origin);
    const pathname = url.pathname;
    const json = (value, status = 200) => ({ status, headers: { "content-type": "application/json" }, body: JSON.stringify(value) });
    const accountPath = pathname.startsWith("/-/package/") && /\/(visibility|access|collaborators|trust)(?:\/|$)/.test(pathname)
      || pathname.startsWith("/-/team/") || pathname.startsWith("/-/org/")
      || pathname.startsWith("/-/npm/v1/user") || pathname.startsWith("/-/npm/v1/tokens")
      || pathname === "/-/_view/starredByUser" || pathname.startsWith("/-/stage")
      || pathname.startsWith("/-/user/token/");
    if (accountPath && req.headers.authorization !== "Bearer e2e-owner")
      return json({ error: "denied" }, 403);
    const packageAction = pathname.match(/^\/-\/package\/(.+)\/(visibility|access|collaborators|trust)$/);
    if (packageAction) {
      const name = decodeURIComponent(packageAction[1]);
      const entry = this.packages.get(name);
      if (!entry) return json({ error: "Not found" }, 404);
      if (packageAction[2] === "trust") return json({ error: "trusted publishing unsupported" }, 404);
      if (packageAction[2] === "visibility" && req.method === "GET") return json({ public: entry.access !== "restricted" });
      if (packageAction[2] === "collaborators" && req.method === "GET") return json({ "e2e-owner": "write" });
      if (packageAction[2] === "access" && req.method === "POST") {
        try { entry.access = JSON.parse(body.toString()).access ?? entry.access; }
        catch { return json({ error: "invalid access body" }, 400); }
        return json({ ok: true });
      }
    }
    const packagePermissions = pathname.match(/^\/-\/(team\/[^/]+\/[^/]+|org\/[^/]+)\/package$/);
    if (packagePermissions) {
      if (req.method === "GET") return json({ "@e2e/scoped": "write" });
      if (req.method === "PUT" || req.method === "DELETE") return json({ ok: true });
    }
    if (pathname === "/-/org/e2e/team" && req.method === "GET")
      return json({ ops: { name: "ops" } });
    const teamUser = pathname.match(/^\/-\/team\/([^/]+)\/([^/]+)\/user$/);
    if (teamUser) {
      const key = `${decodeURIComponent(teamUser[1])}:${decodeURIComponent(teamUser[2])}`;
      const members = this.teams.get(key) ?? {};
      if (req.method === "GET") return json(url.searchParams.get("format") === "cli" ? Object.keys(members) : members);
      try {
        const { user } = JSON.parse(body.toString());
        if (!user) return json({ error: "missing user" }, 400);
        if (req.method === "PUT") members[user] = "developer";
        else if (req.method === "DELETE") delete members[user];
        else return json({ error: "unsupported method" }, 405);
      } catch { return json({ error: "invalid team body" }, 400); }
      this.teams.set(key, members);
      return json(members);
    }
    const orgUser = pathname.match(/^\/-\/org\/([^/]+)\/user$/);
    if (orgUser) {
      const key = decodeURIComponent(orgUser[1]);
      const members = this.orgs.get(key) ?? {};
      if (req.method === "GET") return json(members);
      let user;
      let role;
      try {
        ({ user, role } = JSON.parse(body.toString()));
        if (!user) return json({ error: "missing user" }, 400);
        if (req.method === "PUT") members[user] = role ?? "developer";
        else if (req.method === "DELETE") delete members[user];
        else return json({ error: "unsupported method" }, 405);
      } catch { return json({ error: "invalid org body" }, 400); }
      this.orgs.set(key, members);
      return req.method === "PUT"
        ? json({ user, role: members[user], org: { name: key, size: Object.keys(members).length } })
        : json({ ok: true });
    }
    if (pathname === "/-/npm/v1/user") {
      if (req.method === "GET") return json(this.profile);
      if (req.method === "POST") {
        try { Object.assign(this.profile, JSON.parse(body.toString())); }
        catch { return json({ error: "invalid profile body" }, 400); }
        return json(this.profile);
      }
    }
    if (pathname === "/-/npm/v1/tokens") {
      if (req.method === "GET") return json({ objects: [...this.tokens.values()], urls: {} });
      if (req.method === "POST") {
        const key = `fake-token-key-${this.tokens.size + 1}`;
        const record = { key, created: new Date().toISOString(), readonly: false };
        this.tokens.set(key, record);
        return json({ ...record, token: `fake-token-secret-${this.tokens.size}` }, 201);
      }
    }
    if (pathname.startsWith("/-/npm/v1/tokens/token/") && req.method === "DELETE") {
      const key = decodeURIComponent(pathname.slice("/-/npm/v1/tokens/token/".length));
      return this.tokens.delete(key) ? json({ ok: true }) : json({ error: "Not found" }, 404);
    }
    if (pathname.startsWith("/-/user/token/") && req.method === "DELETE") return json({ ok: true });
    if (pathname === "/-/_view/starredByUser" && req.method === "GET") {
      const user = JSON.parse(url.searchParams.get("key") ?? '""');
      return json({ rows: [...this.packages].filter(([, entry]) => entry.users?.[user])
        .map(([name]) => ({ value: name })) });
    }
    if (pathname.startsWith("/-/stage")) return json({ error: "staging unsupported" }, 404);
    if (req.method === "POST" && path === "/-/v1/login") return { status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ loginUrl: "https://browser.example/login", doneUrl: `${this.origin}/-/v1/login/done` }) };
    if (req.method === "GET" && path === "/-/v1/login/done") return { status: 200,
      headers: { "content-type": "application/json" }, body: '{"token":"e2e-owner"}' };
    if (req.method === "GET" && decodeURIComponent(path).startsWith("/-/user/org.couchdb.user:")) {
      const name = decodeURIComponent(path).split(":").at(-1);
      return { status: 200, headers: { "content-type": "application/json" },
        body: JSON.stringify({ _id: `org.couchdb.user:${name}`, name, email: `${name}@example.test`, _rev: "1" }) };
    }
    if (req.method === "PUT" && decodeURIComponent(path).startsWith("/-/user/org.couchdb.user:")) {
      try {
        const user = JSON.parse(body.toString());
        if (user.name !== "e2e-owner" || user.password !== "e2e-password")
          return json({ error: "denied" }, 403);
        return json({ ok: true, id: user._id, rev: "1", token: "e2e-owner" }, 201);
      } catch { return json({ error: "invalid legacy login body" }, 400); }
    }
    if (req.method === "GET" && path.startsWith("/-/package/") && path.endsWith("/dist-tags")) {
      const name = decodeURIComponent(path.slice("/-/package/".length, -"/dist-tags".length));
      const entry = this.packages.get(name);
      return entry ? { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(entry.tags) }
        : { status: 404, body: '{"error":"Not found"}' };
    }
    if (req.method === "PUT" && path.startsWith("/-/package/") && path.includes("/dist-tags/")) {
      if (req.headers.authorization !== "Bearer e2e-owner") return { status: 403, body: '{"error":"denied"}' };
      const rest = path.slice("/-/package/".length);
      const [encodedName, tag] = rest.split("/dist-tags/");
      const entry = this.packages.get(decodeURIComponent(encodedName));
      if (!entry || !tag) return { status: 404, body: '{"error":"Not found"}' };
      entry.tags[decodeURIComponent(tag)] = JSON.parse(body.toString());
      return { status: 201, headers: { "content-type": "application/json" }, body: '{}' };
    }
    if (req.method === "DELETE" && path.startsWith("/-/package/") && path.includes("/dist-tags/")) {
      if (req.headers.authorization !== "Bearer e2e-owner") return { status: 403, body: '{"error":"denied"}' };
      const [encodedName, tag] = path.slice("/-/package/".length).split("/dist-tags/");
      const entry = this.packages.get(decodeURIComponent(encodedName));
      if (!entry || !Object.hasOwn(entry.tags, decodeURIComponent(tag))) return { status: 404, body: '{"error":"Not found"}' };
      delete entry.tags[decodeURIComponent(tag)];
      return { status: 200, headers: { "content-type": "application/json" }, body: '{}' };
    }
    if (req.method === "DELETE" && path.startsWith("/extra/case/") && path.includes("/-rev/")) {
      if (new URL(path, this.origin).searchParams.get("sig") !== "d41-signed-secret") return { status: 403, body: '{"error":"bad signature"}' };
      return req.headers.authorization === "Bearer e2e-owner"
        ? { status: 200, body: '{"ok":true}' }
        : { status: 403, body: '{"error":"denied"}' };
    }
    if (req.method === "DELETE" && path.includes("/-rev/") && [...this.packages.values()].some((entry) => entry.removedVersions?.has(path.split("/-rev/")[0].split("/").at(-1)))) {
      if (req.headers.authorization !== "Bearer e2e-owner") return { status: 403, body: '{"error":"denied"}' };
      const filename = path.split("/-rev/")[0].split("/").at(-1);
      const entry = [...this.packages.values()].find((candidate) => candidate.removedVersions?.has(filename));
      return entry?.removedVersions?.has(filename)
        ? (entry.removedVersions.delete(filename), { status: 200, body: '{"ok":true}' })
        : { status: 404, body: '{"error":"Not found"}' };
    }
    if (req.method === "DELETE" && path.includes("/-rev/") && !path.startsWith("/-/")) {
      if (req.headers.authorization !== "Bearer e2e-owner") return { status: 403, body: '{"error":"denied"}' };
      const name = decodeURIComponent(path.slice(1).split("/-rev/")[0]);
      return this.packages.delete(name) ? { status: 200, body: '{"ok":true}' }
        : { status: 404, body: '{"error":"Not found"}' };
    }
    if (req.method === "PUT" && !path.startsWith("/-/")) {
      if (req.headers.authorization !== "Bearer e2e-owner") return { status: 403, body: '{"error":"denied"}' };
      try {
        const document = JSON.parse(body.toString());
        const name = decodeURIComponent(path.slice(1).split("/-rev/")[0]);
        if (path.includes("/-rev/")) {
          const entry = this.packages.get(name);
          if (!entry) return { status: 404, body: '{"error":"Not found"}' };
          entry.maintainers = document.maintainers;
          if (document.versions) {
            for (const [version, record] of Object.entries(document.versions)) {
              const listed = entry.versions.get(version);
              if (listed && record?.dist?.tarball !== listed.dist.tarball) {
                return { status: 400, body: '{"error":"revision changed advertised tarball"}' };
              }
            }
            entry.removedVersions ??= new Map();
            for (const [version, record] of entry.versions) {
              if (!Object.hasOwn(document.versions, version)) {
                entry.removedVersions.set(new URL(record.dist.tarball).pathname.split("/").at(-1), record);
                entry.versions.delete(version);
              }
            }
            entry.tags = document["dist-tags"] ?? entry.tags;
          }
          entry.rev = "2";
          return { status: 201, headers: { "content-type": "application/json" }, body: JSON.stringify({ ok: true, id: name, rev: "2" }) };
        }
        const existing = this.packages.get(name);
        if (existing && document.users) {
          existing.users = document.users;
          return json({ ok: true, id: name, rev: "2" }, 201);
        }
        const [version] = Object.keys(document.versions ?? {});
        if (!version) return { status: 400, body: '{"error":"missing version"}' };
        this.publish({ name, version, ageSeconds: 400 * 86_400 });
        return { status: 201, headers: { "content-type": "application/json" }, body: JSON.stringify({ ok: true, id: name, rev: "1" }) };
      } catch { return { status: 400, body: '{"error":"invalid document"}' }; }
    }
    if (path.startsWith("/-/v1/search")) {
      const text = new URL(path, this.origin).searchParams.get("text") ?? "";
      const objects = [...this.packages].filter(([name]) => name.includes(text))
        .map(([name, entry]) => {
          const versions = [...entry.versions.keys()];
          const tainted = name.startsWith("search-hidden-latest-") || name.startsWith("search-tainted-allowed-");
          return { package: { name,
            version: name.startsWith("search-tainted-allowed-") ? versions[0] : versions.at(-1),
            description: tainted ? "private-denied-latest" : "fake package",
            maintainers: tainted ? [{ username: "private-denied-latest" }] : [],
            keywords: tainted ? ["private-denied-latest"] : [] } };
        });
      return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ objects, total: objects.length }) };
    }
    if (path === "/-/ping") return { status: 200, body: "{}" };
    if (path === "/-/whoami") return req.headers.authorization === "Bearer e2e-owner"
      ? { status: 200, body: '{"username":"e2e-owner"}' }
      : { status: 403, body: '{"error":"denied"}' };
    if (req.method === "POST" && (path === "/-/npm/v1/security/advisories/bulk" || path === "/-/npm/v1/security/audits/quick")) {
      try {
        const decoded = req.headers["content-encoding"] === "gzip" ? gunzipSync(body) : body;
        if (decoded.length) JSON.parse(decoded.toString());
      } catch {
        return { status: 400, body: '{"error":"invalid audit body or encoding"}' };
      }
      return path.endsWith("/bulk") ? { status: 200, body: "{}" }
        : { status: 200, body: '{"auditReportVersion":2,"vulnerabilities":{}}' };
    }
    const decoded = decodeURIComponent(path.split("?")[0]).slice(1);
    const at = decoded.indexOf("/-/");
    if (at >= 0) {
      const name = decoded.slice(0, at);
      const file = decoded.slice(at + 3);
      const entry = this.packages.get(name);
      const record = entry && [...entry.versions.values()].find((r) => r.dist.tarball.endsWith(`/-/${file}`));
      if (!record) return { status: 404, body: '{"error":"Not found"}' };
      if (name.startsWith("read-private-") && req.headers.authorization !== "Bearer e2e-read")
        return { status: 403, body: '{"error":"read credential required"}' };
      return { status: 200, headers: { "content-type": "application/octet-stream" }, body: record.bytes };
    }
    const abbreviated = (req.headers.accept ?? "").includes("application/vnd.npm.install-v1+json");
    if (decoded.startsWith("token-private-") && req.headers.authorization === "Bearer e2e-denied")
      return { status: 403, body: '{"error":"denied token"}' };
    if (decoded.startsWith("read-private-")
        && !["Bearer e2e-read", "Bearer e2e-owner"].includes(req.headers.authorization))
      return { status: 403, body: '{"error":"read credential required"}' };
    const document = this.document(decoded, abbreviated);
    if (!document) return { status: 404, body: '{"error":"Not found"}' };
    if (decoded.startsWith("token-private-") && req.headers.authorization === "Bearer e2e-owner")
      document.ownerOnly = "private upstream metadata";
    const contentType = abbreviated ? "application/vnd.npm.install-v1+json" : "application/json";
    return { status: 200, headers: { "content-type": contentType }, body: JSON.stringify(document) };
  }
}
