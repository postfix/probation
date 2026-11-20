// The fake ConanCenter, answering as https://center2.conan.io: a Conan 2 remote over memory. It speaks the REST API the real client
// uses (`v1/ping` for capabilities, login, credential check, search, revision lists, file lists, files, the binary search of a recipe
// revision) with the shapes ConanCenter writes (revision lists newest first, `+0000` times, file lists with empty values), and an
// upload endpoint (`PUT` and `DELETE` below `v2/conans/`) that records every write and answers by the token a login handed out. A REAL
// `conan create` and `conan upload` fill it, so every file in it is what the real client packs; a revision's `time` is when it was
// uploaded unless a scenario ages it (`age`). Nothing shells out.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/// Real files of a real Conan client (fixtures/conan/README.md).
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "conan");
const names = (dir) => { try { return readdirSync(dir).sort(); } catch { return []; } };
const filesIn = (dir) => new Map(names(dir).filter((n) => statSync(join(dir, n)).isFile()).map((n) => [n, readFileSync(join(dir, n))]));

const hex = (algorithm, bytes) => createHash(algorithm).update(bytes).digest("hex");
const stamp = (ms) => new Date(ms).toISOString().replace("Z", "").replace(/\.(\d{3}).*$/, ".$1") + "+0000";
const json = (value, status = 200) => ({ status, headers: { "content-type": "application/json" }, body: JSON.stringify(value, null, 2) });
const text = (status, bodyText, headers = {}) => ({ status, headers: { "content-type": "text/plain", ...headers }, body: bodyText });

export class Conan {
  constructor() {
    this.reset();
  }

  reset() {
    this.refs = new Map(); // "name/version/user/channel" -> Map(rrev -> {time, files: Map, packages: Map(pkgid -> Map(prev -> {time, files: Map}))})
    this.writes = []; // every upload-endpoint call: {method, path, authorization, bytes, sha256}
    this.requests = [];
    this.seed();
  }

  /// A recipe old enough for every scenario to read (the registry-loaded probe of the service scenario asks for it).
  seed() {
    const files = new Map([["conanfile.py", Buffer.from("from conan import ConanFile\n\nclass Seed(ConanFile):\n    name = \"seed\"\n    version = \"1.0\"\n")], ["conanmanifest.txt", Buffer.from("1700000000\nconanfile.py: seed\n")]]);
    this.refs.set("seed/1.0/_/_", new Map([["5eed0000000000000000000000000000", { time: Date.now() - 400 * 86_400_000, files, packages: new Map() }]]));
  }

  /// Serves the real files of `name/version` (fixtures/conan) with the recipe revision published `ageSeconds` ago and each binary
  /// (`binaries`: {pkgid: ageSeconds}, otherwise the recipe's age) as old as told. Answers the package ids it holds.
  publish({ name, version, ageSeconds = 0, binaries = {} }) {
    const base = join(FIXTURES, name, version, "_", "_", "revisions");
    const revisions = this.refs.get(`${name}/${version}/_/_`) ?? new Map();
    for (const rrev of names(base)) {
      const rdir = join(base, rrev);
      const packages = new Map();
      for (const pkgid of names(join(rdir, "packages"))) {
        const revs = new Map();
        for (const prev of names(join(rdir, "packages", pkgid, "revisions"))) {
          revs.set(prev, { time: Date.now() - (binaries[pkgid] ?? ageSeconds) * 1000, files: filesIn(join(rdir, "packages", pkgid, "revisions", prev)) });
        }
        packages.set(pkgid, revs);
      }
      revisions.set(rrev, { time: Date.now() - ageSeconds * 1000, files: filesIn(rdir), packages });
    }
    this.refs.set(`${name}/${version}/_/_`, revisions);
    return { reference: `${name}/${version}@_/_`, revisions: [...revisions.keys()], packages: [...[...revisions.values()].flatMap((r) => [...r.packages.keys()])] };
  }

  /// Ages every revision (recipe and package) of `name/version` so it was published `ageSeconds` ago.
  age({ name, version, ageSeconds }) {
    const at = Date.now() - ageSeconds * 1000;
    let aged = 0;
    for (const [key, revisions] of this.refs) {
      if (!key.startsWith(`${name}/${version}/`)) continue;
      for (const recipe of revisions.values()) {
        recipe.time = at;
        aged += 1;
        for (const revs of recipe.packages.values()) for (const rev of revs.values()) rev.time = at;
      }
    }
    return { aged };
  }

  references() {
    return [...this.refs.keys()].map((key) => { const [name, version, user, channel] = key.split("/"); return `${name}/${version}@${user}/${channel}`; });
  }

  list(revisions, head, name, latest) {
    const sorted = [...revisions].sort((a, b) => b[1].time - a[1].time);
    if (!sorted.length) return text(404, "not found");
    const entries = sorted.map(([revision, unit]) => ({ revision, time: stamp(unit.time) }));
    return json(latest ? entries[0] : { [head]: name, revisions: entries });
  }

  filesOf(unit, file) {
    if (file === undefined) return json({ files: Object.fromEntries([...unit.files.keys()].sort().map((n) => [n, {}])) });
    const bytes = unit.files.get(file);
    return bytes ? { status: 200, headers: { "content-type": "application/octet-stream" }, body: bytes } : text(404, "not found");
  }

  read(url) {
    const path = url.pathname;
    if (path === "/v1/ping" || path === "/v2/ping") return text(200, "", { "x-conan-server-capabilities": "revisions" });
    return null;
  }

  get(req, url) {
    const path = url.pathname;
    const ping = this.read(url);
    if (ping) return ping;
    const authorization = req.headers.authorization ?? "";
    if (path === "/v2/users/authenticate") {
      if (!authorization.startsWith("Basic ")) return text(401, "Unauthorized", { "www-authenticate": 'Basic realm="e2e"' });
      const [user, password] = Buffer.from(authorization.slice(6), "base64").toString().split(":");
      if (password === undefined || user === "e2e-wrong") return text(401, "Wrong user or password");
      return text(200, `tok-${user}`);
    }
    if (path === "/v2/users/check_credentials") return authorization.startsWith("Bearer tok-") ? text(200, "") : text(401, "Unauthorized", { "www-authenticate": 'Bearer realm="e2e"' });
    if (path === "/v2/conans/search") {
      const pattern = url.searchParams.get("q") ?? "*";
      const ignorecase = url.searchParams.get("ignorecase") !== "False";
      const re = new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`, ignorecase ? "i" : "");
      return json({ results: this.references().filter((ref) => re.test(ref) || re.test(ref.replace(/@_\/_$/, ""))) });
    }
    const m = path.match(/^\/v2\/conans\/([^/]+)\/([^/]+)\/([^/]+)\/([^/]+)(\/.*)?$/);
    if (!m) return text(404, "not found");
    const [, name, version, user, channel, rest = ""] = m;
    const revisions = this.refs.get(`${name}/${version}/${user}/${channel}`);
    if (!revisions) return text(404, "not found");
    const reference = `${name}/${version}@${user}/${channel}`;
    if (rest === "/revisions" || rest === "/latest") return this.list(revisions, "reference", reference, rest === "/latest");
    let p = rest.match(/^\/revisions\/([^/]+)\/(files|search)(?:\/(.+))?$/);
    if (p) {
      const recipe = revisions.get(p[1]);
      if (!recipe) return text(404, "not found");
      if (p[2] === "files") return this.filesOf(recipe, p[3]);
      return json(Object.fromEntries([...recipe.packages.keys()].sort().map((id) => [id, { settings: {}, options: {}, requires: [] }])));
    }
    p = rest.match(/^\/revisions\/([^/]+)\/packages\/([^/]+)(\/latest|\/revisions|\/revisions\/([^/]+)\/files(?:\/(.+))?)$/);
    if (p) {
      const packages = revisions.get(p[1])?.packages.get(p[2]);
      if (!packages) return text(404, "not found");
      if (p[3] === "/latest" || p[3] === "/revisions") return this.list(packages, "packageReference", `${reference}#${p[1]}:${p[2]}`, p[3] === "/latest");
      const unit = packages.get(p[4]);
      return unit ? this.filesOf(unit, p[5]) : text(404, "not found");
    }
    return text(404, "not found");
  }

  /// The upload endpoint: `PUT` of a file and `DELETE` of anything below `v2/conans/`. Every call is recorded with its credential; a
  /// token handed out to `e2e-owner` is accepted, one handed out to `e2e-denied` is refused with 403, and nothing at all is a 401
  /// challenge. An accepted `PUT` stores the file (a new revision is dated now).
  write(req, url, body) {
    const authorization = req.headers.authorization ?? null;
    this.writes.push({ method: req.method, path: url.pathname, authorization, bytes: body.length, sha256: body.length ? hex("sha256", body) : null });
    if (!authorization) return text(401, "Unauthorized", { "www-authenticate": 'Bearer realm="e2e"' });
    if (authorization === "Bearer tok-e2e-denied") return text(403, "Forbidden");
    if (authorization !== "Bearer tok-e2e-owner") return text(401, "Unauthorized", { "www-authenticate": 'Bearer realm="e2e"' });
    const m = url.pathname.match(/^\/v2\/conans\/([^/]+)\/([^/]+)\/([^/]+)\/([^/]+)\/revisions\/([^/]+)(?:\/packages\/([^/]+)\/revisions\/([^/]+))?\/files\/(.+)$/);
    if (req.method === "DELETE") return text(204, "");
    if (!m) return text(404, "not found");
    const [, name, version, user, channel, rrev, pkgid, prev, file] = m;
    const key = `${name}/${version}/${user}/${channel}`;
    const revisions = this.refs.get(key) ?? new Map();
    this.refs.set(key, revisions);
    const recipe = revisions.get(rrev) ?? { time: Date.now(), files: new Map(), packages: new Map() };
    revisions.set(rrev, recipe);
    let unit = recipe;
    if (pkgid) {
      const packages = recipe.packages.get(pkgid) ?? new Map();
      recipe.packages.set(pkgid, packages);
      unit = packages.get(prev) ?? { time: Date.now(), files: new Map() };
      packages.set(prev, unit);
    }
    unit.files.set(file, Buffer.from(body));
    return text(201, "");
  }

  handle(req, path, host, body) {
    const url = new URL(path, `https://${host}`);
    this.requests.push({ host, method: req.method, path: url.pathname, authorization: req.headers.authorization ?? null });
    if (req.method === "PUT" || req.method === "DELETE") return this.write(req, url, body);
    if (req.method !== "GET" && req.method !== "HEAD") return { status: 405, body: "method not allowed" };
    return this.get(req, url);
  }
}
