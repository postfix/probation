// The fake Go module proxy and checksum database, answering as https://proxy.golang.org (the GOPROXY
// protocol: `@v/list`, `@latest`, `@v/<version>.info|.mod|.zip`) and https://sum.golang.org (the
// sumdb read shapes). Module paths and versions are case-ENCODED on the wire (`!` before a capital
// letter) and case-SENSITIVE as identities. Zips are real module zips (`<module>@<version>/go.mod`
// and one source file, stored), so `go` in the stack verifies and unpacks them. `Time` in `.info`
// is the real publication time, absent when the module is published `undated`. Nothing here
// shells out.

import { zip } from "./archive.mjs";

/// `A` -> `!a`, the proxy protocol's case encoding (module paths and versions alike).
export const escape = (text) => text.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
export const unescape = (text) => text.replace(/!([a-z])/g, (_, c) => c.toUpperCase());

const PSEUDO = /^v\d+\.\d+\.\d+-(?:[0-9A-Za-z.-]+\.)?\d{14}-[0-9a-f]{12}$/;
const isPseudo = (version) => PSEUDO.test(version);
const parse = (version) => {
  const m = version.match(/^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/);
  return m ? { n: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? "" } : null;
};
const compare = (a, b) => {
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i += 1) if (x.n[i] !== y.n[i]) return x.n[i] - y.n[i];
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
};

const modText = (module) => `module ${module}\n\ngo 1.21\n`;
const infoText = (version, created) => JSON.stringify(created === null ? { Version: version } : { Version: version, Time: new Date(created).toISOString().replace(/\.\d+Z$/, "Z") });

function buildZip(module, version) {
  const root = `${module}@${version}`;
  return zip({
    [`${root}/go.mod`]: modText(module),
    [`${root}/lib.go`]: `package lib\n\nconst Version = ${JSON.stringify(version)}\n`,
  });
}

export class Go {
  constructor() {
    this.reset();
  }

  reset() {
    this.modules = new Map(); // decoded module path -> Map(version -> {created (ms) | null, zip})
    this.revs = new Map(); // `${module}\0${rev}` -> version: what a branch or commit name resolves to
    this.sumdb = []; // every request the fake checksum database got: {path, authorization}
    // Seeded so a stack with no scenario still answers like a proxy.
    this.publish({ module: "example.com/e2e/seed", version: "v1.0.0", ageSeconds: 400 * 86_400 });
  }

  /// Adds a release (and the revision names that resolve to it: `revs`, as `go get mod@main` or `mod@<commit>` ask). `ageSeconds` (or `publishedAt`, ISO) is its publication time (`Time`); `undated`
  /// publishes it with no `Time` in its `.info`.
  publish({ module, version, ageSeconds = 0, publishedAt, undated = false, revs = [] }) {
    const versions = this.modules.get(module) ?? new Map();
    const created = undated ? null : publishedAt ? Date.parse(publishedAt) : Date.now() - ageSeconds * 1000;
    const bytes = buildZip(module, version);
    versions.set(version, { created, bytes });
    this.modules.set(module, versions);
    for (const rev of revs) this.revs.set(`${module}\0${rev}`, version);
    return { module, version, file: `${escape(version)}.zip`, publishedAt: created === null ? null : new Date(created).toISOString() };
  }

  /// The `@v/list` text: tagged versions only (a pseudo-version is never listed).
  list(module) {
    const versions = this.modules.get(module);
    if (!versions) return null;
    return [...versions.keys()].filter((v) => !isPseudo(v)).map((v) => `${v}\n`).join("");
  }

  /// The version `@latest` names: the highest release, else the highest prerelease, else the newest pseudo-version.
  latest(module) {
    const versions = this.modules.get(module);
    if (!versions || versions.size === 0) return null;
    const tagged = [...versions.keys()].filter((v) => !isPseudo(v));
    const releases = tagged.filter((v) => !parse(v).pre);
    const pick = (list) => list.sort(compare).at(-1);
    if (releases.length) return pick(releases);
    if (tagged.length) return pick(tagged);
    return [...versions.keys()].sort().at(-1);
  }

  handle(req, path, host) {
    if (host === "sum.golang.org") return this.checksumDb(req, path);
    const p = new URL(path, "https://proxy.golang.org").pathname.slice(1);
    // A capital letter is never written on the wire (it is `!` and a lower-case letter), as on the real proxy.
    if (/[A-Z]/.test(p)) return { status: 404, body: "not found: invalid escaped path" };
    const latest = p.match(/^(.*)\/@latest$/);
    const file = p.match(/^(.*)\/@v\/(.+)$/);
    const text = (body) => ({ status: 200, headers: { "content-type": "text/plain; charset=utf-8" }, body });
    const found = (escaped) => this.modules.get(unescape(escaped));
    if (latest) {
      const module = unescape(latest[1]);
      const version = this.latest(module);
      if (version === null) return { status: 404, body: "not found" };
      return { status: 200, headers: { "content-type": "application/json" }, body: infoText(version, this.modules.get(module).get(version).created) };
    }
    if (!file) return { status: 404, body: "not found" };
    const [, escaped, name] = file;
    const versions = found(escaped);
    if (!versions) return { status: 404, body: "not found" };
    if (name === "list") return text(this.list(unescape(escaped)));
    const m = name.match(/^(.+)\.(info|mod|zip)$/);
    if (!m) return { status: 404, body: "not found" };
    let version = unescape(m[1]);
    // A revision query (`main`, a commit): the answer names the resolved version.
    if (m[2] === "info" && !versions.has(version) && this.revs.has(`${unescape(escaped)}\0${version}`)) version = this.revs.get(`${unescape(escaped)}\0${version}`);
    const entry = versions.get(version);
    if (!entry) return { status: 404, body: "not found" };
    if (m[2] === "info") return { status: 200, headers: { "content-type": "application/json" }, body: infoText(version, entry.created) };
    if (m[2] === "mod") return text(modText(unescape(escaped)));
    return { status: 200, headers: { "content-type": "application/zip" }, body: entry.bytes };
  }

  /// The checksum database reads (`supported`, `latest`, `lookup/<module>@<version>`, `tile/...`); every
  /// request is recorded with its Authorization header, which must never be there.
  checksumDb(req, path) {
    const p = new URL(path, "https://sum.golang.org").pathname;
    this.sumdb.push({ path: p, authorization: req.headers.authorization ?? null });
    if (p === "/supported") return { status: 200, headers: { "content-type": "text/plain" }, body: "" };
    if (p === "/latest") return { status: 200, headers: { "content-type": "text/plain" }, body: "go.sum database tree\n1\ne2e-tree-hash=\n" };
    if (p.startsWith("/lookup/")) {
      const [module, version] = unescape(p.slice(8)).split("@");
      return { status: 200, headers: { "content-type": "text/plain" }, body: `1\n${module} ${version} h1:e2e=\n` };
    }
    if (p.startsWith("/tile/")) return { status: 200, headers: { "content-type": "application/octet-stream" }, body: Buffer.from([1, 2, 3]) };
    return { status: 404, body: "not found" };
  }
}

export { buildZip };
