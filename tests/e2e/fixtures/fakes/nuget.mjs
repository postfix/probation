// The fake NuGet.org, answering as https://api.nuget.org (the v3 service index, the flat container,
// registration served gzip-encoded like the real one, the vulnerability database and the repository
// signature index), https://azuresearch-usnc.nuget.org (search and autocomplete) and
// https://www.nuget.org (the publish endpoints, which record every write and answer by API key).
// Package ids are case-INSENSITIVE and spelled lower case in every URL; versions are normalised
// (`1.0.0.0` is `1.0.0`, a prerelease label lower case in the flat container) and the registration
// keeps the version as published. `published` is the real publication time, and the unlisted
// sentinel (1900-01-01) when a package is published `unlisted`. Packages are real stored zips
// (`.nupkg` with a nuspec), so `dotnet` in the stack verifies and unpacks them. Nothing shells out.

import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { zip } from "./archive.mjs";

/// NuGetVersion.ToNormalizedString lower-cased, without build metadata: `1.0.0.0-Beta+x` -> `1.0.0-beta`.
export function normalize(version) {
  const [core, release] = version.split("+")[0].split(/-(.*)/s);
  const parts = core.split(".").map((n) => String(Number(n)));
  while (parts.length < 3) parts.push("0");
  if (parts.length === 4 && parts[3] === "0") parts.pop();
  return `${parts.join(".")}${release ? `-${release.toLowerCase()}` : ""}`;
}

const order = (a, b) => {
  const split = (v) => {
    const [core, release] = v.split(/-(.*)/s);
    return { n: core.split(".").map(Number), pre: release ?? "" };
  };
  const [x, y] = [split(a), split(b)];
  for (let i = 0; i < 4; i += 1) if ((x.n[i] ?? 0) !== (y.n[i] ?? 0)) return (x.n[i] ?? 0) - (y.n[i] ?? 0);
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
};

const SENTINEL = "1900-01-01T00:00:00+00:00";
const CERTIFICATE = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]);
// The index names the certificate by the SHA-256 of its bytes, and the firewall checks it.
const SIGNATURE = createHash("sha256").update(CERTIFICATE).digest("hex");
const nuspec = (id, version) => `<?xml version="1.0" encoding="utf-8"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>${id}</id><version>${version}</version><authors>e2e</authors><description>e2e package</description><dependencies><group targetFramework=".NETStandard2.0" /></dependencies></metadata></package>`;

function buildNupkg(id, version) {
  return zip({
    "[Content_Types].xml": `<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" /><Default Extension="nuspec" ContentType="application/octet" /><Default Extension="dll" ContentType="application/octet" /></Types>`,
    "_rels/.rels": `<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/${id}.nuspec" Id="R1" /></Relationships>`,
    [`${id}.nuspec`]: nuspec(id, version),
    [`lib/netstandard2.0/${id}.dll`]: `not a real assembly: ${id} ${version}`,
  });
}

export class NuGet {
  constructor() {
    this.reset();
  }

  reset() {
    this.packages = new Map(); // lower id -> {id, versions: Map(normalised -> {version, created (ms), listed, bytes})}
    this.writes = []; // every publish-endpoint call: {method, path, apiKey, authorization, contentType, bytes}
    this.vulnerable = []; // [{id, range}] served by the vulnerability database
    this.requests = [];
    // Seeded so a stack with no scenario still answers like a registry.
    this.publish({ id: "e2e.seed", version: "1.0.0", ageSeconds: 400 * 86_400 });
  }

  /// Adds a release. `ageSeconds` (or `publishedAt`, ISO) is its publication time; `unlisted` publishes it with the
  /// sentinel date; `inRegistration: false` leaves it out of registration (the flat container lists it).
  publish({ id, version, ageSeconds = 0, publishedAt, unlisted = false, inRegistration = true }) {
    const key = id.toLowerCase();
    const entry = this.packages.get(key) ?? { id, versions: new Map() };
    const created = publishedAt ? Date.parse(publishedAt) : Date.now() - ageSeconds * 1000;
    const normal = normalize(version);
    entry.versions.set(normal, { version, created, listed: !unlisted, inRegistration, bytes: buildNupkg(id, normal) });
    this.packages.set(key, entry);
    return { id, version, normalised: normal, file: `${key}.${normal}.nupkg`, publishedAt: new Date(created).toISOString() };
  }

  /// A vulnerable range the database reports for `id` (`[1.0.0, 2.0.0)`).
  vulnerability({ id, range }) {
    this.vulnerable.push({ id, range });
    return { ok: true };
  }

  sorted(entry) {
    return [...entry.versions.keys()].sort(order);
  }

  json(value, headers = {}) {
    return { status: 200, headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(value) };
  }

  gz(value) {
    return { status: 200, headers: { "content-type": "application/json", "content-encoding": "gzip" }, body: gzipSync(Buffer.from(JSON.stringify(value))) };
  }

  serviceIndex() {
    const r = (id, type) => ({ "@id": id, "@type": type });
    return {
      version: "3.0.0",
      resources: [
        r("https://azuresearch-usnc.nuget.org/query", "SearchQueryService"),
        r("https://azuresearch-usnc.nuget.org/query", "SearchQueryService/3.5.0"),
        r("https://azuresearch-usnc.nuget.org/autocomplete", "SearchAutocompleteService"),
        r("https://api.nuget.org/v3/registration5-semver1/", "RegistrationsBaseUrl"),
        r("https://api.nuget.org/v3/registration5-gz-semver2/", "RegistrationsBaseUrl/3.6.0"),
        r("https://api.nuget.org/v3/registration5-gz-semver2/", "RegistrationsBaseUrl/Versioned"),
        r("https://api.nuget.org/v3-flatcontainer/", "PackageBaseAddress/3.0.0"),
        r("https://www.nuget.org/api/v2", "LegacyGallery"),
        r("https://www.nuget.org/api/v2/package", "PackagePublish/2.0.0"),
        r("https://www.nuget.org/api/v2/symbolpackage", "SymbolPackagePublish/4.9.0"),
        r("https://api.nuget.org/v3-index/repository-signatures/5.0.0/index.json", "RepositorySignatures/5.0.0"),
        r("https://api.nuget.org/v3/vulnerabilities/index.json", "VulnerabilityInfo/6.7.0"),
        r("https://api.nuget.org/v3/catalog0/index.json", "Catalog/3.0.0"),
        r("https://api.nuget.org/v3-flatcontainer/{lower_id}/{lower_version}/readme", "ReadmeUriTemplate/6.13.0"),
      ],
    };
  }

  leaf(entry, normal) {
    const v = entry.versions.get(normal);
    const id = entry.id.toLowerCase();
    return {
      "@id": `https://api.nuget.org/v3/registration5-gz-semver2/${id}/${normal}.json`,
      "@type": "Package",
      commitId: "e2e",
      commitTimeStamp: "2026-01-01T00:00:00+00:00",
      catalogEntry: {
        "@id": `https://api.nuget.org/v3/catalog0/data/2026.01.01.00.00.00/${id}.${normal}.json`,
        "@type": "PackageDetails",
        authors: "e2e",
        id: entry.id,
        version: v.version,
        listed: v.listed,
        published: v.listed ? new Date(v.created).toISOString().replace(/Z$/, "+00:00") : SENTINEL,
        packageContent: `https://api.nuget.org/v3-flatcontainer/${id}/${normal}/${id}.${normal}.nupkg`,
        iconUrl: `https://api.nuget.org/v3-flatcontainer/${id}/${normal}/icon`,
        licenseUrl: "https://licenses.invalid/mit",
        dependencyGroups: [{ "@id": "urn:e2e", "@type": "PackageDependencyGroup", targetFramework: ".NETStandard2.0" }],
      },
      packageContent: `https://api.nuget.org/v3-flatcontainer/${id}/${normal}/${id}.${normal}.nupkg`,
      registration: `https://api.nuget.org/v3/registration5-gz-semver2/${id}/index.json`,
    };
  }

  /// Registration pages of 64 versions; a package of more than 128 versions has linked pages, as the real one.
  registrationIndex(entry) {
    const id = entry.id.toLowerCase();
    const names = this.sorted(entry).filter((n) => entry.versions.get(n).inRegistration);
    const pages = [];
    for (let at = 0; at < names.length; at += 64) pages.push(names.slice(at, at + 64));
    const linked = names.length > 128;
    const base = `https://api.nuget.org/v3/registration5-gz-semver2/${id}`;
    return {
      "@id": `${base}/index.json`,
      "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
      commitId: "e2e",
      commitTimeStamp: "2026-01-01T00:00:00+00:00",
      count: pages.length,
      items: pages.map((page) => {
        const [lower, upper] = [page[0], page.at(-1)];
        const item = { "@id": `${base}/page/${lower}/${upper}.json`, "@type": "catalog:CatalogPage", count: page.length, lower, upper, parent: `${base}/index.json` };
        return linked ? item : { ...item, items: page.map((n) => this.leaf(entry, n)) };
      }),
    };
  }

  handle(req, path, host, body) {
    const url = new URL(path, `https://${host}`);
    this.requests.push({ host, method: req.method, path: url.pathname, authorization: req.headers.authorization ?? null });
    if (host === "www.nuget.org") return this.publishApi(req, url, body);
    if (host === "azuresearch-usnc.nuget.org") return this.search(url);
    const p = url.pathname;
    if (p === "/v3/index.json") return this.json(this.serviceIndex());
    let m;
    if ((m = p.match(/^\/v3-flatcontainer\/([^/]+)\/index\.json$/))) {
      const entry = this.packages.get(m[1]);
      if (!entry || m[1] !== m[1].toLowerCase()) return { status: 404, body: "not found" };
      return this.json({ versions: this.sorted(entry) });
    }
    if ((m = p.match(/^\/v3-flatcontainer\/([^/]+)\/([^/]+)\/(.+)$/))) {
      const entry = this.packages.get(m[1]);
      const v = entry?.versions.get(m[2]);
      if (!v || m[1] !== m[1].toLowerCase()) return { status: 404, body: "not found" };
      if (m[3] === `${m[1]}.${m[2]}.nupkg`) return { status: 200, headers: { "content-type": "application/octet-stream" }, body: v.bytes };
      if (m[3] === `${m[1]}.nuspec`) return { status: 200, headers: { "content-type": "text/xml" }, body: nuspec(entry.id, m[2]) };
      if (m[3] === "readme") return { status: 200, headers: { "content-type": "text/markdown" }, body: `# ${entry.id} ${m[2]}\n` };
      if (m[3] === "icon") return { status: 200, headers: { "content-type": "image/png" }, body: Buffer.from([0x89, 0x50, 0x4e, 0x47]) };
      return { status: 404, body: "not found" };
    }
    if ((m = p.match(/^\/v3\/registration5-gz-semver2\/([^/]+)\/index\.json$/))) {
      const entry = this.packages.get(m[1]);
      if (!entry) return { status: 404, body: "not found" };
      return this.gz(this.registrationIndex(entry));
    }
    if ((m = p.match(/^\/v3\/registration5-gz-semver2\/([^/]+)\/page\/([^/]+)\/([^/]+)\.json$/))) {
      const entry = this.packages.get(m[1]);
      if (!entry) return { status: 404, body: "not found" };
      const page = this.registrationIndex(entry).items.find((item) => item.lower === m[2] && item.upper === m[3]);
      if (!page) return { status: 404, body: "not found" };
      const names = this.sorted(entry).filter((n) => entry.versions.get(n).inRegistration && order(n, m[2]) >= 0 && order(n, m[3]) <= 0);
      return this.gz({ ...page, items: names.map((n) => this.leaf(entry, n)) });
    }
    if ((m = p.match(/^\/v3\/registration5-gz-semver2\/([^/]+)\/(.+)\.json$/))) {
      const entry = this.packages.get(m[1]);
      const v = entry?.versions.get(m[2]);
      if (!v) return { status: 404, body: "not found" };
      const leaf = this.leaf(entry, m[2]);
      return this.gz({ ...leaf, catalogEntry: leaf.catalogEntry["@id"], listed: v.listed, published: leaf.catalogEntry.published });
    }
    if (p === "/v3/vulnerabilities/index.json") {
      return this.json([
        { "@name": "base", "@id": "https://api.nuget.org/v3-vulnerabilities/2026.01.01.00.00.00/vulnerability.base.json", "@updated": "2026-01-01T00:00:00Z", comment: "base" },
        { "@name": "update", "@id": "https://api.nuget.org/v3-vulnerabilities/2026.01.01.00.00.00/2026.01.02.00.00.00/vulnerability.update.json", "@updated": "2026-01-02T00:00:00Z", comment: "update" },
      ]);
    }
    if (p.startsWith("/v3-vulnerabilities/")) {
      if (p.endsWith("vulnerability.update.json")) return this.json({});
      const data = {};
      for (const { id, range } of this.vulnerable) data[id.toLowerCase()] = [{ url: "https://github.com/advisories/GHSA-e2e", severity: 3, versions: range }];
      return this.json(data);
    }
    if (p === "/v3-index/repository-signatures/5.0.0/index.json") {
      return this.json({
        allRepositorySigned: false,
        signingCertificates: [{ fingerprints: { "2.16.840.1.101.3.4.2.1": SIGNATURE }, subject: "CN=e2e", issuer: "CN=e2e", notBefore: "2018-04-10T00:00:00.0000000Z", notAfter: "2099-04-14T12:00:00.0000000Z", contentUrl: `https://api.nuget.org/v3-index/repository-signatures/certificates/${SIGNATURE}.crt` }],
      });
    }
    if (p === `/v3-index/repository-signatures/certificates/${SIGNATURE}.crt`) return { status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: CERTIFICATE };
    return { status: 404, body: "not found" };
  }

  search(url) {
    const p = url.pathname;
    const q = (url.searchParams.get("q") ?? "").toLowerCase();
    const take = Math.min(Number(url.searchParams.get("take") ?? 20), 1000);
    if (p === "/autocomplete") {
      const wanted = url.searchParams.get("id");
      if (wanted) {
        const entry = this.packages.get(wanted.toLowerCase());
        return this.json({ "@context": { "@vocab": "http://schema.nuget.org/schema#" }, totalHits: entry ? entry.versions.size : 0, data: entry ? this.sorted(entry) : [] });
      }
      const ids = [...this.packages.values()].map((e) => e.id).filter((id) => id.toLowerCase().includes(q)).slice(0, take);
      return this.json({ "@context": { "@vocab": "http://schema.nuget.org/schema#" }, totalHits: ids.length, data: ids });
    }
    if (p !== "/query") return { status: 404, body: "not found" };
    const entries = [...this.packages.values()].filter((e) => e.id.toLowerCase().includes(q)).slice(0, take);
    return this.json({
      "@context": { "@vocab": "http://schema.nuget.org/schema#", "@base": "https://api.nuget.org/v3/registration5-gz-semver2/" },
      totalHits: entries.length,
      data: entries.map((entry) => {
        const id = entry.id.toLowerCase();
        const names = this.sorted(entry).filter((n) => entry.versions.get(n).listed);
        const latest = names.at(-1) ?? this.sorted(entry).at(-1);
        return {
          "@id": `https://api.nuget.org/v3/registration5-gz-semver2/${id}/index.json`, "@type": "Package",
          registration: `https://api.nuget.org/v3/registration5-gz-semver2/${id}/index.json`,
          id: entry.id, version: latest, description: "e2e package",
          iconUrl: `https://api.nuget.org/v3-flatcontainer/${id}/${latest}/icon`, projectUrl: "https://project.invalid/",
          totalDownloads: 1, verified: false,
          versions: names.map((version) => ({ version, downloads: 1, "@id": `https://api.nuget.org/v3/registration5-gz-semver2/${id}/${version}.json` })),
        };
      }),
    });
  }

  /// The publish endpoints: `PUT /api/v2/package`, `PUT /api/v2/symbolpackage`, `DELETE|POST /api/v2/package/{id}/{version}`.
  /// Every call is recorded with its credentials; only the owner key is accepted.
  publishApi(req, url, body) {
    const p = url.pathname;
    const apiKey = req.headers["x-nuget-apikey"] ?? null;
    const authorization = req.headers.authorization ?? null;
    this.writes.push({
      method: req.method, path: p, apiKey, authorization, contentType: req.headers["content-type"] ?? null,
      bytes: body.length, sha256: body.length ? createHash("sha256").update(body).digest("hex") : null,
    });
    const text = (status, bodyText) => ({ status, headers: { "content-type": "text/plain" }, body: bodyText });
    if (req.method === "GET") return { status: 404, body: "not found" };
    if (!apiKey && !authorization) return text(401, "The API key is invalid.");
    if (apiKey === "e2e-denied") return text(403, "The API key is not authorised to push this package.");
    if (apiKey !== "e2e-owner-key") return text(401, "The specified API key is invalid.");
    if (req.method === "PUT" && (p === "/api/v2/package" || p === "/api/v2/symbolpackage")) return text(201, "Created");
    if ((req.method === "DELETE" || req.method === "POST") && /^\/api\/v2\/package\/[^/]+\/[^/]+$/.test(p)) return text(req.method === "DELETE" ? 204 : 200, "");
    return text(404, "not found");
  }
}

export { buildNupkg, SENTINEL, SIGNATURE };
