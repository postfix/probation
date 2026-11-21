// The fake Docker Hub, answering as https://registry-1.docker.io (the registry API), https://auth.docker.io (its token service) and
// https://production.cloudfront.docker.com (the storage a blob is redirected to), all from one object over memory. It speaks the
// distribution protocol the way the real hub does: `/v2/` answers a Bearer challenge for the token realm on the auth host, an
// anonymous token (`tok-anon`) opens public repositories and a Basic login (`tok-<user>`) opens `private/...` ones, a blob (GET and
// HEAD) answers a 307 to a signed URL on the storage host, a tag list pages with `Link`, and a push (`POST` / `PATCH` / `PUT`) is
// recorded with the credential it carried. The image bytes are the REAL tiny images of fixtures/oci (a gzip layer whose diff id the
// engine verifies). Nothing shells out.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "oci");
const sha = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const json = (value, status = 200, headers = {}) => ({ status, headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(value) });
const MANIFEST = "application/vnd.oci.image.manifest.v1+json";
const REGISTRY = "registry-1.docker.io";
const AUTH = "auth.docker.io";
const STORAGE = "production.cloudfront.docker.com";
const SECOND = "ghcr.io"; // a second registry with repositories of its own and its own token endpoint (/token on the same host)
const FOREIGN = "mcr.microsoft.com"; // where a foreign layer's own URL points (the firewall's default foreign-layer host list names it)

export class Oci {
  constructor(second = false) {
    this.second = second; // true: this object IS the second registry (host ghcr.io); false: the fake Docker Hub, which owns one
    this.auth = second ? SECOND : AUTH;
    this.regHost = second ? SECOND : REGISTRY;
    this.reset();
  }

  reset() {
    if (!this.second) this.other = new Oci(true);
    else this.other = null;
    this.repos = new Map(); // repo -> {tags: Map(tag -> digest), manifests: Map(digest -> {bytes, media}), blobs: Map(digest -> bytes)}
    this.seen = []; // every request: {host, method, path, authorization}
    this.tokens = []; // every token request: {scope, service, basic}
    this.writes = []; // every write: {method, path, authorization, bytes}
    this.uploads = new Map();
    this.foreignLayers = new Map(); // digest -> bytes served at https://mcr.microsoft.com/foreign/<hex>
    this.seed();
  }

  repo(name) {
    if (!this.repos.has(name)) this.repos.set(name, { tags: new Map(), manifests: new Map(), blobs: new Map() });
    return this.repos.get(name);
  }

  /// A small public image every scenario can read (the registry-loaded probe of the service scenario asks for it).
  seed() {
    if (this.second) return;
    this.publish({ repo: "library/alpine", tag: "latest", image: "hello-1" });
  }

  /// Serves the real files of fixture image `image` (hello-1 or hello-2) as `repo:tag`.
  publish({ repo, tag, image = "hello-1", host }) {
    if (host === SECOND) return this.other.publish({ repo, tag, image });
    const read = (kind) => readFileSync(join(FIXTURES, `${image}-${kind}`));
    const [manifest, config, layer] = [read("manifest"), read("config"), read("layer")];
    const target = this.repo(repo);
    const digest = sha(manifest);
    target.manifests.set(digest, { bytes: manifest, media: MANIFEST });
    target.blobs.set(sha(config), config);
    target.blobs.set(sha(layer), layer);
    if (tag) target.tags.set(tag, digest);
    return { repo, tag, digest, config: sha(config), layer: sha(layer) };
  }

  /// A Windows-style image: the real tiny image `image`, but its layer is a FOREIGN layer, named by a download URL on `mcr.microsoft.com`
  /// (the registry holds no blob for it). The manifest is built here, so its digest is its own.
  publishForeign({ repo, tag, image = "hello-1" }) {
    const read = (kind) => readFileSync(join(FIXTURES, `${image}-${kind}`));
    const [config, layer] = [read("config"), read("layer")];
    const doc = JSON.parse(read("manifest").toString());
    doc.layers = [{ mediaType: "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip", digest: sha(layer), size: layer.length, urls: [`https://${FOREIGN}/foreign/${sha(layer).replace("sha256:", "")}`] }];
    const manifest = Buffer.from(JSON.stringify(doc));
    const target = this.repo(repo);
    const digest = sha(manifest);
    target.manifests.set(digest, { bytes: manifest, media: MANIFEST });
    target.blobs.set(sha(config), config);
    this.foreignLayers.set(sha(layer), layer);
    if (tag) target.tags.set(tag, digest);
    return { repo, tag, digest, config: sha(config), layer: sha(layer) };
  }

  /// A tag that points at another image (a moved tag).
  move({ repo, tag, image, host }) {
    return this.publish({ repo, tag, image, host });
  }

  bearer(req) {
    const header = req.headers.authorization ?? "";
    return header.startsWith("Bearer tok-") ? header.slice(7) : null;
  }

  challenge(host) {
    return { status: 401, headers: { "www-authenticate": `Bearer realm="https://${this.auth}/token",service="registry.docker.io"`, "content-type": "application/json" }, body: JSON.stringify({ errors: [{ code: "UNAUTHORIZED" }] }) };
  }

  token(req, url) {
    const authorization = req.headers.authorization ?? "";
    const scope = url.searchParams.get("scope") ?? "";
    this.tokens.push({ scope, service: url.searchParams.get("service"), basic: authorization.startsWith("Basic ") });
    if (authorization.startsWith("Basic ")) {
      const [user, password] = Buffer.from(authorization.slice(6), "base64").toString().split(":");
      if (password === undefined || user.startsWith("wrong")) return json({ errors: [{ code: "UNAUTHORIZED" }] }, 401);
      return json({ token: `tok-${user}`, expires_in: 300 });
    }
    return json({ token: "tok-anon", expires_in: 300 });
  }

  /// Whether this bearer may read `name`: a private repository needs a logged-in token.
  allowed(name, token) {
    return name.startsWith("private/") ? token !== "tok-anon" : true;
  }

  handle(req, path, host, body) {
    const url = new URL(path, `https://${host}`);
    this.seen.push({ host, method: req.method, path: url.pathname, authorization: req.headers.authorization ?? null });
    if (host === SECOND && !this.second) return this.other.handleSecond(req, url, body, this.seen);
    if (host === AUTH) return url.pathname === "/token" ? this.token(req, url) : json({}, 404);
    if (host === STORAGE) return this.storage(url);
    if (host === FOREIGN) return this.foreign(url);
    return this.registry(req, url, body);
  }

  /// A request for the second registry's host: its own token endpoint and its own repositories (never the Hub's).
  handleSecond(req, url, body, seen) {
    seen.push({ host: SECOND, method: req.method, path: url.pathname, authorization: req.headers.authorization ?? null });
    return url.pathname === "/token" ? this.token(req, url) : this.registry(req, url, body);
  }

  foreign(url) {
    const bytes = this.foreignLayers.get(`sha256:${url.pathname.replace(/^\/foreign\//, "")}`);
    return bytes ? { status: 200, headers: { "content-type": "application/octet-stream" }, body: bytes } : { status: 404, body: "not found" };
  }

  storage(url) {
    const digest = url.pathname.replace(/^\/registry-v2\//, "");
    for (const repo of [...this.repos.values(), ...(this.other ? this.other.repos.values() : [])]) {
      const bytes = repo.blobs.get(digest);
      if (bytes) return { status: 200, headers: { "content-type": "application/octet-stream" }, body: bytes };
    }
    return { status: 404, body: "not found" };
  }

  registry(req, url, body) {
    const path = url.pathname;
    const token = this.bearer(req);
    if (!token) return this.challenge();
    if (path === "/v2/" || path === "/v2") return json({}, 200, { "docker-distribution-api-version": "registry/2.0" });
    const m = /^\/v2\/(.+?)\/(manifests|blobs|tags|referrers)\/(.+)$/.exec(path);
    const uploads = /^\/v2\/(.+?)\/blobs\/uploads\/(.*)$/.exec(path);
    if (uploads) return this.upload(req, url, uploads[1], uploads[2], token, body);
    if (!m) return json({ errors: [{ code: "NAME_UNKNOWN" }] }, 404);
    const [, name, kind, rest] = m;
    if (!this.allowed(name, token)) return { status: 401, headers: { "www-authenticate": `Bearer realm="https://${this.auth}/token",service="registry.docker.io",scope="repository:${name}:pull"`, "content-type": "application/json" }, body: JSON.stringify({ errors: [{ code: "UNAUTHORIZED" }] }) };
    const repo = this.repos.get(name);
    if (req.method === "PUT" || req.method === "DELETE") return this.write(req, url, name, kind, rest, token, body);
    if (!repo) return json({ errors: [{ code: "NAME_UNKNOWN" }] }, 404);
    if (kind === "manifests") {
      const digest = rest.includes(":") ? rest : repo.tags.get(rest);
      const found = digest && repo.manifests.get(digest);
      if (!found) return json({ errors: [{ code: "MANIFEST_UNKNOWN" }] }, 404);
      return { status: 200, headers: { "content-type": found.media, "docker-content-digest": digest, "docker-distribution-api-version": "registry/2.0", ...(req.method === "HEAD" ? { "content-length": found.bytes.length } : {}) }, body: req.method === "HEAD" ? Buffer.alloc(0) : found.bytes };
    }
    if (kind === "blobs") {
      if (!repo.blobs.has(rest)) return json({ errors: [{ code: "BLOB_UNKNOWN" }] }, 404);
      return { status: 307, headers: { location: `https://${STORAGE}/registry-v2/${rest}?sig=abc` }, body: "" };
    }
    if (kind === "tags" && rest === "list") {
      const all = [...repo.tags.keys()].sort();
      const n = Number(url.searchParams.get("n") ?? all.length);
      const last = url.searchParams.get("last");
      const from = last ? all.findIndex((tag) => tag > last) : 0;
      const page = from < 0 ? [] : all.slice(from, from + n);
      const headers = page.length && from + n < all.length ? { link: `<https://${this.regHost}/v2/${name}/tags/list?last=${page.at(-1)}&n=${n}>; rel="next"` } : {};
      return json({ name, tags: page }, 200, headers);
    }
    return json({ errors: [{ code: "UNSUPPORTED" }] }, 404);
  }

  record(req, url, body, token) {
    this.writes.push({ method: req.method, path: url.pathname + url.search, authorization: req.headers.authorization ?? null, bytes: body.length });
  }

  upload(req, url, name, session, token, body) {
    if (token === "tok-anon") return { status: 401, headers: { "www-authenticate": `Bearer realm="https://${this.auth}/token",service="registry.docker.io",scope="repository:${name}:pull,push"` }, body: "{}" };
    this.record(req, url, body, token);
    const repo = this.repo(name);
    const id = session || `up-${this.uploads.size + 1}`;
    const location = `https://${this.regHost}/v2/${name}/blobs/uploads/${id}?_state=s${this.uploads.size}`;
    if (req.method === "POST") {
      this.uploads.set(id, []);
      const mount = url.searchParams.get("mount");
      if (mount && this.repos.get(url.searchParams.get("from"))?.blobs.has(mount)) {
        repo.blobs.set(mount, this.repos.get(url.searchParams.get("from")).blobs.get(mount));
        return { status: 201, headers: { location: `https://${this.regHost}/v2/${name}/blobs/${mount}`, "docker-content-digest": mount }, body: "" };
      }
      return { status: 202, headers: { location, "docker-upload-uuid": id, range: "0-0" }, body: "" };
    }
    if (req.method === "PATCH") {
      this.uploads.get(id)?.push(body);
      return { status: 202, headers: { location, "docker-upload-uuid": id, range: `0-${Math.max(0, body.length - 1)}` }, body: "" };
    }
    if (req.method === "PUT") {
      const bytes = Buffer.concat([...(this.uploads.get(id) ?? []), body]);
      const digest = url.searchParams.get("digest");
      if (digest !== sha(bytes)) return json({ errors: [{ code: "DIGEST_INVALID" }] }, 400);
      repo.blobs.set(digest, bytes);
      return { status: 201, headers: { location: `https://${this.regHost}/v2/${name}/blobs/${digest}`, "docker-content-digest": digest }, body: "" };
    }
    return json({}, 405);
  }

  write(req, url, name, kind, rest, token, body) {
    if (token === "tok-anon") return { status: 401, headers: { "www-authenticate": `Bearer realm="https://${this.auth}/token",service="registry.docker.io",scope="repository:${name}:pull,push"` }, body: "{}" };
    this.record(req, url, body, token);
    const repo = this.repo(name);
    if (kind === "manifests" && req.method === "PUT") {
      const digest = sha(body);
      repo.manifests.set(digest, { bytes: body, media: req.headers["content-type"] ?? MANIFEST });
      if (!rest.includes(":")) repo.tags.set(rest, digest);
      return { status: 201, headers: { location: `https://${this.regHost}/v2/${name}/manifests/${digest}`, "docker-content-digest": digest }, body: "" };
    }
    if (req.method === "DELETE") {
      repo.manifests.delete(rest);
      return { status: 202, headers: {}, body: "" };
    }
    return json({}, 405);
  }
}
