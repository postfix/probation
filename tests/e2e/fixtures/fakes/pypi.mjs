// The fake PyPI, answering as https://pypi.org (the Simple API, PEP 503 HTML and PEP 691
// JSON with PEP 700 upload times) and https://files.pythonhosted.org (the files, with
// their real sha256). Wheels and sdists are built in memory.

import { createHash } from "node:crypto";
import { tgz, zip } from "./archive.mjs";

const FILES = "https://files.pythonhosted.org";
const DAY = 86_400_000;

/// PEP 503.
export const normalize = (name) => name.toLowerCase().replace(/[-_.]+/g, "-");

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const recordHash = (bytes) => `sha256=${createHash("sha256").update(bytes).digest("base64url")}`;

function wheel(name, version) {
  const dist = normalize(name).replaceAll("-", "_");
  const info = `${dist}-${version}.dist-info`;
  const files = {
    [`${dist}/__init__.py`]: `VERSION = ${JSON.stringify(version)}\n`,
    [`${info}/METADATA`]: `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n`,
    [`${info}/WHEEL`]: "Wheel-Version: 1.0\nGenerator: probation-e2e\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
  };
  const record = Object.entries(files).map(([path, content]) => `${path},${recordHash(Buffer.from(content))},${Buffer.byteLength(content)}`);
  files[`${info}/RECORD`] = `${[...record, `${info}/RECORD,,`].join("\n")}\n`;
  return { filename: `${dist}-${version}-py3-none-any.whl`, bytes: zip(files) };
}

/// A PEP 517 backend in the sdist itself, stdlib only, so an sdist with `backend:
/// "intree"` builds offline: no build requirement to fetch, no backend in the image.
const INTREE_BACKEND = `import base64, hashlib, os, re, zipfile
def _meta():
    fields = dict(line.split(": ", 1) for line in open("PKG-INFO").read().splitlines() if ": " in line)
    return fields["Name"], fields["Version"]
def get_requires_for_build_wheel(config_settings=None):
    return []
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name, version = _meta()
    dist = re.sub(r"[-_.]+", "_", name).lower()
    info = dist + "-" + version + ".dist-info"
    files = {}
    for root, _, names in os.walk(dist):
        for n in names:
            path = os.path.join(root, n)
            files[path.replace(os.sep, "/")] = open(path, "rb").read()
    files[info + "/METADATA"] = ("Metadata-Version: 2.1\\nName: " + name + "\\nVersion: " + version + "\\n").encode()
    files[info + "/WHEEL"] = b"Wheel-Version: 1.0\\nGenerator: probation-e2e\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"
    record = [p + ",sha256=" + base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b"=").decode() + "," + str(len(b)) for p, b in files.items()]
    files[info + "/RECORD"] = ("\\n".join(record + [info + "/RECORD,,"]) + "\\n").encode()
    filename = dist + "-" + version + "-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(wheel_directory, filename), "w") as z:
        for p, b in files.items():
            z.writestr(p, b)
    return filename
`;

function sdist(name, version, backend) {
  const dist = normalize(name).replaceAll("-", "_");
  const root = `${dist}-${version}`;
  const system =
    backend === "intree"
      ? `[build-system]\nrequires = []\nbuild-backend = "e2e_backend"\nbackend-path = ["."]\n`
      : `[build-system]\nrequires = ["flit_core>=3.2"]\nbuild-backend = "flit_core.buildapi"\n`;
  return {
    filename: `${root}.tar.gz`,
    bytes: tgz({
      [`${root}/PKG-INFO`]: `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n`,
      [`${root}/pyproject.toml`]: `${system}\n[project]\nname = "${name}"\nversion = "${version}"\ndescription = "e2e"\n`,
      [`${root}/${dist}/__init__.py`]: `VERSION = ${JSON.stringify(version)}\n`,
      ...(backend === "intree" ? { [`${root}/e2e_backend.py`]: INTREE_BACKEND } : {}),
    }),
  };
}

export class Pypi {
  constructor() {
    this.reset();
  }

  reset() {
    this.projects = new Map();
    const ago = (days) => new Date(Date.now() - days * DAY).toISOString();
    this.publish({ name: "e2e-left", version: "1.0.0", uploadedAt: ago(400) });
    this.publish({ name: "e2e-left", version: "1.1.0", uploadedAt: ago(300) });
    this.publish({ name: "Foo_Bar", version: "1.0.0", uploadedAt: ago(400) });
  }

  /// Adds a release's files (`kinds`: "wheel", "sdist"). `ageSeconds` or `uploadedAt`
  /// (ISO) sets each file's PEP 700 upload time. `backend: "intree"` makes an sdist that
  /// builds with no build requirement (default: flit_core, which the fakes do not serve).
  /// `untimed: true` lists no upload time (`upload-time: null`), so a firewall falls
  /// back to when it first saw the file.
  publish({ name, version, uploadedAt, ageSeconds, untimed = false, kinds = ["wheel", "sdist"], requiresPython = null, yanked = false, backend }) {
    const at = untimed ? null : (uploadedAt ?? new Date(Date.now() - (ageSeconds ?? 0) * 1000).toISOString());
    const key = normalize(name);
    let project = this.projects.get(key);
    if (!project) this.projects.set(key, (project = { name, files: [] }));
    const made = [];
    for (const kind of kinds) {
      const { filename, bytes } = kind === "wheel" ? wheel(name, version) : sdist(name, version, backend);
      const hash = sha256(bytes);
      const file = {
        filename,
        version,
        bytes,
        sha256: hash,
        uploaded: at,
        requiresPython,
        yanked,
        url: `${FILES}/packages/${hash.slice(0, 2)}/${hash.slice(2, 4)}/${hash.slice(4)}/${filename}`,
      };
      project.files = project.files.filter((f) => f.filename !== filename);
      project.files.push(file);
      made.push({ filename, url: file.url, sha256: hash });
    }
    return made;
  }

  simple(req, name) {
    const key = normalize(name);
    if (key !== name) return { status: 301, headers: { location: `/simple/${key}/` }, body: "" };
    const project = this.projects.get(key);
    if (!project) return { status: 404, body: "Not Found" };
    const accept = req.headers.accept ?? "";
    if (accept.includes("application/vnd.pypi.simple.v1+json")) {
      const body = {
        meta: { "api-version": "1.1" },
        name: key,
        versions: [...new Set(project.files.map((f) => f.version))],
        files: project.files.map((f) => ({
          filename: f.filename,
          url: f.url,
          hashes: { sha256: f.sha256 },
          "requires-python": f.requiresPython,
          "upload-time": f.uploaded,
          yanked: f.yanked,
          size: f.bytes.length,
        })),
      };
      return { status: 200, headers: { "content-type": "application/vnd.pypi.simple.v1+json" }, body: JSON.stringify(body) };
    }
    const links = project.files.map((f) => {
      const python = f.requiresPython ? ` data-requires-python="${f.requiresPython.replaceAll("<", "&lt;").replaceAll(">", "&gt;")}"` : "";
      const yanked = f.yanked ? ` data-yanked="${f.yanked === true ? "" : f.yanked}"` : "";
      return `<a href="${f.url}#sha256=${f.sha256}"${python}${yanked}>${f.filename}</a><br/>`;
    });
    const html = `<!DOCTYPE html>\n<html><head><meta name="pypi:repository-version" content="1.1"><title>Links for ${key}</title></head><body><h1>Links for ${key}</h1>\n${links.join("\n")}\n</body></html>\n`;
    return { status: 200, headers: { "content-type": "text/html" }, body: html };
  }

  handle(req, path, host) {
    if (host === "files.pythonhosted.org") {
      for (const project of this.projects.values()) {
        const file = project.files.find((f) => new URL(f.url).pathname === path);
        if (file) return { status: 200, headers: { "content-type": "application/octet-stream" }, body: file.bytes };
      }
      return { status: 404, body: "Not Found" };
    }
    const match = path.match(/^\/simple\/([^/]+)\/?$/);
    if (match) return this.simple(req, decodeURIComponent(match[1]));
    const json = path.match(/^\/pypi\/([^/]+)\/(?:([^/]+)\/)?json$/);
    if (json) return this.json(decodeURIComponent(json[1]), json[2] && decodeURIComponent(json[2]));
    return { status: 404, body: "Not Found" };
  }

  /// The JSON API (`/pypi/<name>/json`, `/pypi/<name>/<version>/json`), which Poetry
  /// reads for a project on its default source.
  json(name, version) {
    const project = this.projects.get(normalize(name));
    const versions = [...new Set(project?.files.map((f) => f.version) ?? [])];
    const latest = version ?? versions.at(-1);
    if (!project || !versions.includes(latest)) return { status: 404, body: '{"message": "Not Found"}' };
    const file = (f) => ({
      filename: f.filename,
      url: f.url,
      digests: { sha256: f.sha256 },
      packagetype: f.filename.endsWith(".whl") ? "bdist_wheel" : "sdist",
      requires_python: f.requiresPython,
      size: f.bytes.length,
      upload_time_iso_8601: f.uploaded,
      yanked: Boolean(f.yanked),
    });
    const of = (v) => project.files.filter((f) => f.version === v).map(file);
    const first = project.files.find((f) => f.version === latest);
    const body = {
      info: { name: project.name, version: latest, summary: "e2e", requires_dist: null, requires_python: first.requiresPython, yanked: false },
      urls: of(latest),
      ...(version ? {} : { releases: Object.fromEntries(versions.map((v) => [v, of(v)])) }),
    };
    return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  }
}
