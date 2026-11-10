#!/usr/bin/env node
// Native npm/PyPI publishing acceptance (publishing-proxy Slice 5). Everything runs on
// this machine: the Node fake registries and fake policy endpoint (stack.mjs), the natively
// built `probation` binary in service-policy mode, and the real pinned npm, Twine, pip and
// uv as ordinary processes. Package-manager tokens go to the clients only; no client
// certificate or key is configured and Probation holds no registry credential. The pinned
// clients are re-verified first. Any failure, or zero checks, exits non-zero: nothing is
// skipped.
//
//   NATIVE_PLATFORM          required, e.g. linux-x64 (as clients.mjs)
//   NATIVE_PROBATION_BINARY  built binary (default target/debug/probation[.exe])
//   NATIVE_WORK              scratch directory on disk (default: a fresh directory under the OS temp dir)
//   NATIVE_PYTHON            python executable (default "python")
//   NATIVE_E2E_MAP_HOSTS=1   allow mapping pypi.org to loopback outside CI (see stack.mjs)
//   NATIVE_POLICY_URL, NATIVE_SERVICE_KEY_FILE, NATIVE_POLICY_CA, NATIVE_NPM_REGISTRY_ID,
//   NATIVE_PYPI_REGISTRY_ID, NATIVE_NPM_PORT, NATIVE_HIDDEN_NAME: a real policy server
//   (the Linux Docker run); the service key is read from the file, never from the argv.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import https from "node:https";
import { fileURLToPath } from "node:url";
import { checkCountFindings, servedMatchesFakeFindings, buildClientEnv, deniedStepFindings, envFindings, fileUrlFindings, firewallDeniedFindings, hiddenBytesFindings, keyFindings, lockfileFindings, scanFindings, servedRows, uvLockFindings } from "./assertions.mjs";
import { checkClients, loadPins, which } from "./clients.mjs";
import net from "node:net";
import { DENIED, OWNER, runAsync, startStack } from "./stack.mjs";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const win = process.platform === "win32";
const binary = process.env.NATIVE_PROBATION_BINARY ?? join(root, "target/debug", win ? "probation.exe" : "probation");
const python = process.env.NATIVE_PYTHON ?? "python";
const work = process.env.NATIVE_WORK ?? mkdtempSync(join(tmpdir(), "native-publish-"));
const home = join(work, "home");
mkdirSync(home, { recursive: true });

// CI acceptance runs against the real policy server (the handshake of native-clients.yml sets NATIVE_POLICY_URL); the
// in-process snapshot endpoint stays a local-only fixture.
if (process.env.GITHUB_ACTIONS && !process.env.NATIVE_POLICY_URL) {
  console.error("native publishing in CI must run against the real policy server (NATIVE_POLICY_URL from the handshake); the in-process snapshot is a local-only fixture");
  process.exit(2);
}

let checks = 0;
const failures = [];
const expect = (ok, message) => { checks++; console.log(`${ok ? "ok  " : "FAIL"} ${message}`); if (!ok) failures.push(message); };
const tail = (r) => r.out.slice(-300).replace(/\s+/g, " ");
const suffix = randomBytes(4).toString("hex");
// The status the service answers for a policy-hidden artifact (confirmed against the real service).
const HIDDEN_ARTIFACT_REFUSAL = 403;

let stack;
try {
  const preflight = checkClients({ pins: loadPins(), platformWanted: process.env.NATIVE_PLATFORM });
  expect(preflight.failures.length === 0, `the pinned clients are installed at exactly the pins: ${preflight.failures.join("; ")}`);
  console.log(JSON.stringify(preflight.observed));
  if (preflight.failures.length) throw new Error("pinned clients missing or different; nothing was started");
  // Against a real policy server (the Linux Docker run) the catalog, key and the hidden
  // package's policy block are made through its portal beforehand and passed in.
  const real = process.env.NATIVE_POLICY_URL ? {
    publicTrust: process.env.NATIVE_POLICY_PUBLIC_TRUST === "1", url: process.env.NATIVE_POLICY_URL, key: readFileSync(process.env.NATIVE_SERVICE_KEY_FILE, "utf8").trim(), extraCa: process.env.NATIVE_POLICY_CA,
    npmId: Number(process.env.NATIVE_NPM_REGISTRY_ID), pypiId: Number(process.env.NATIVE_PYPI_REGISTRY_ID),
  } : null;
  stack = await startStack({ binary, work: join(work, "stack"), real, npmPort: process.env.NATIVE_NPM_PORT ? Number(process.env.NATIVE_NPM_PORT) : null });
  const { npmBase, pypiBase, caFile, log } = stack;
  const ca = readFileSync(caFile);
  // D4: the clients get an allow-listed environment, never this process's own (which on a
  // runner may carry proxies, TLS switches or certificates of other jobs).
  const trust = { NODE_EXTRA_CA_CERTS: caFile, SSL_CERT_FILE: caFile, REQUESTS_CA_BUNDLE: caFile, PIP_CERT: caFile, TWINE_CERT: caFile };
  const env = buildClientEnv(process.env, {
    HOME: home, USERPROFILE: home, APPDATA: join(home, "AppData"), XDG_CONFIG_HOME: join(home, ".config"),
    npm_config_userconfig: join(home, ".npmrc"), npm_config_cache: join(home, "npm-cache"), npm_config_update_notifier: "false",
    ...trust, PIP_CONFIG_FILE: join(home, "pip.ini"), PIP_DISABLE_PIP_VERSION_CHECK: "1", UV_CACHE_DIR: join(home, "uv-cache"),
  });
  const envProblems = envFindings(env, trust);
  expect(envProblems.length === 0, `the clients' environment holds no certificate, key, proxy or TLS-verification setting: ${envProblems.join("; ")}`);
  // G9: the tools the clients will run are the ones the preflight recorded.
  const recorded = { node: "node", npm: "npm", python, twine: "twine", uv: "uv" };
  const moved = Object.entries(recorded).filter(([key, tool]) => which(tool, env) !== preflight.observed.paths[key === "python" ? "python" : key]);
  expect(moved.length === 0, `PATH in the clients' environment resolves every tool to the path the preflight recorded: ${moved.map(([k]) => k).join(", ")}`);
  const client = (command, args, cwd) => runAsync(command, args, { cwd, env });
  const upstream = (server) => log.filter((e) => e.server === server);
  // D2: a denied step is refused BY THE UPSTREAM: a new row with the denied credential and 403, and E403 text.
  const denied = async (what, server, method, step) => {
    const since = upstream(server).length;
    const result = await step();
    const problems = deniedStepFindings({ rows: upstream(server), since, method, output: result.out, exit: result.status });
    expect(problems.length === 0, `${what}: ${problems.join("; ")} (${tail(result)})`);
    return result;
  };
  const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
  const url = new URL(npmBase);
  const npmrc = (token) => `registry=${npmBase}\n//${url.host}${url.pathname}:_authToken=${token}\n`;
  const dir = (name) => { const d = join(home, name); mkdirSync(d, { recursive: true }); return d; };
  const get = (target, headers = {}) => new Promise((resolve, reject) => https.get(target, { ca, headers }, (res) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c)).on("end", () => { const bytes = Buffer.concat(chunks); resolve({ status: res.statusCode, bytes, body: bytes.toString("latin1") }); });
  }).on("error", reject));
  const request = (method, target, headers, body) => new Promise((resolve, reject) => {
    const req = https.request(target, { method, ca, headers }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
    req.on("error", reject); req.end(body);
  });
  // A1/A2: no client config file may be missing from the certificate scan, so the clients
  // are given the same ones the scan then reads.
  writeFileSync(join(home, "pip.ini"), `[global]\nindex-url = ${pypiBase}simple/\ndisable-pip-version-check = true\n`);
  writeFileSync(join(home, ".pypirc"), `[distutils]\nindex-servers = native\n\n[native]\nrepository = ${pypiBase}\nusername = __token__\n`);
  mkdirSync(join(home, ".config", "uv"), { recursive: true });
  writeFileSync(join(home, ".config", "uv", "uv.toml"), `index-url = "${pypiBase}simple/"\n`);

  // ---- npm: publish, read back, deprecate, unpublish, audit
  const name = `native-pub-${suffix}`;
  const pkg = dir("npm-pkg");
  const manifest = (version) => writeFileSync(join(pkg, "package.json"), JSON.stringify({ name, version, main: "index.js" }));
  writeFileSync(join(pkg, "index.js"), "module.exports = 1;\n");
  const publish = async (token, version) => { manifest(version); writeFileSync(join(pkg, ".npmrc"), npmrc(token)); return client("npm", ["publish", "--no-audit", "--no-fund"], pkg); };
  let r = await publish(OWNER, "1.0.0");
  expect(r.status === 0, `npm publish with the owner token succeeds: ${tail(r)}`);
  expect(upstream("npm").some((e) => e.method === "PUT" && e.credential === "developer-owner" && e.status === 201),
    "selected npm registry received the owner's own token on the publish PUT");
  r = await denied("npm publish with the denied token is refused by the upstream", "npm", "PUT", () => publish(DENIED, "1.0.1"));
  expect(!stack.npm.packages.get(name).versions.has("1.0.1"), "the denied publish left the upstream without that version");
  // Negative control for the old flake: the same kind of denied step against a closed port has
  // no upstream row, so the check must fail (a bare /403/ used to match the port number).
  const closed = await freePort();
  const sinceClosed = upstream("npm").length;
  manifest("1.0.1");
  writeFileSync(join(pkg, ".npmrc"), npmrc(DENIED));
  const nowhere = await client("npm", ["publish", "--no-audit", "--no-fund", "--fetch-retries=0", `--registry=https://127.0.0.1:${closed}/`], pkg);
  const flake = deniedStepFindings({ rows: upstream("npm"), since: sinceClosed, method: "PUT", output: nowhere.out, exit: nowhere.status });
  expect(flake.length >= 2, `a denied step against a closed port (:${closed}) fails the denied-step check: ${flake.join("; ")}`);
  const consumer = dir("npm-consumer");
  writeFileSync(join(consumer, ".npmrc"), npmrc(OWNER));
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0", private: true }));
  r = await client("npm", ["install", `${name}@1.0.0`, "--no-fund"], consumer);
  expect(r.status === 0, `npm install of the published package through the selected registry: ${tail(r)}`);
  const lockProblems = lockfileFindings(readFileSync(join(consumer, "package-lock.json"), "utf8"), npmBase);
  expect(lockProblems.length === 0, `every lockfile resolved URL lies under the selected registry: ${lockProblems.join("; ")}`);
  r = await client("npm", ["view", name, "version", "--json"], consumer);
  expect(r.status === 0 && r.out.includes("1.0.0"), `npm view reads the published version: ${tail(r)}`);
  r = await client("npm", ["audit"], consumer);
  expect(r.status === 0, `npm audit succeeds with no advisories: ${tail(r)}`);
  expect(upstream("npm").some((e) => e.method === "POST" && /security\/(advisories\/bulk|audits\/quick)/.test(e.path) && e.status === 200),
    "npm audit reached the selected registry's audit endpoint");

  const deprecate = async (token, message) => { writeFileSync(join(pkg, ".npmrc"), npmrc(token)); return await client("npm", ["deprecate", `${name}@1.0.0`, message], pkg); };
  const deprecated = async () => { const v = await client("npm", ["view", `${name}@1.0.0`, "deprecated"], consumer); return v.out.trim(); };
  expect(await deprecated() === "", "the version is not deprecated before the owner deprecates it");
  r = await deprecate(OWNER, "native deprecation");
  expect(r.status === 0, `npm deprecate with the owner token succeeds: ${tail(r)}`);
  const shown = await deprecated();
  expect(shown === "native deprecation", `npm view shows the exact deprecation text the owner set: ${JSON.stringify(shown)} (upstream: ${JSON.stringify(stack.npm.packages.get(name).versions.get("1.0.0").deprecated)}; writes: ${JSON.stringify(upstream("npm").filter((e) => e.method !== "GET").map((e) => [e.method, e.path, e.status, e.bodyPreview]))})`);
  r = await denied("npm deprecate with the denied token is refused by the upstream", "npm", "PUT", () => deprecate(DENIED, "denied deprecation"));
  expect(stack.npm.packages.get(name).versions.get("1.0.0").deprecated === "native deprecation" && await deprecated() === "native deprecation",
    "the denied deprecate left the owner's text in place");

  r = await publish(OWNER, "1.0.2");
  expect(r.status === 0, `a second version publishes: ${tail(r)}`);
  writeFileSync(join(pkg, ".npmrc"), npmrc(DENIED));
  r = await denied("npm version unpublish with the denied token is refused by the upstream", "npm", "PUT", () => client("npm", ["unpublish", `${name}@1.0.2`, "--force"], pkg));
  expect(stack.npm.packages.get(name).versions.has("1.0.2"), "the denied unpublish left version 1.0.2 in place");
  writeFileSync(join(pkg, ".npmrc"), npmrc(OWNER));
  r = await client("npm", ["unpublish", `${name}@1.0.2`, "--force"], pkg);
  expect(r.status === 0, `npm version unpublish with the owner token succeeds: ${tail(r)}`);
  expect(!stack.npm.packages.get(name).versions.has("1.0.2"), "the selected upstream no longer lists the unpublished version");
  r = await client("npm", ["unpublish", name, "--force"], pkg);
  expect(r.status === 0 && !stack.npm.packages.has(name), `npm whole-package unpublish with the owner token succeeds: ${tail(r)}`);

  // ---- token-packument: policy hides the package; an upstream-accepted token reads the canonical packument only
  const hidden = real ? process.env.NATIVE_HIDDEN_NAME : `token-private-${suffix}`;
  stack.npm.publish({ name: hidden, version: "1.0.0", ageSeconds: 400 * 86_400 });
  if (!real) stack.policy.blocks.push({ Package: { ecosystem: "Npm", name: hidden } });
  const probe = (path, token) => get(`${npmBase}${path}`, token ? { authorization: `Bearer ${token}` } : {});
  const until = async (check) => { for (let i = 0; i < 60; i++) { if (await check()) return true; await new Promise((x) => setTimeout(x, 500)); } return false; };
  expect(await until(async () => (await probe(hidden)).status === 403), "tokenless read of a policy-hidden package is refused");
  const seen = await probe(hidden, OWNER);
  expect(seen.status === 200 && seen.body.includes("private upstream metadata"), `owner token reads the canonical packument of a hidden package: ${seen.status}`);
  expect((await probe(hidden, DENIED)).status === 403, "an upstream-denied token stays refused");
  expect((await probe(hidden)).status === 403, "a tokenless read cannot reuse the token's metadata");
  expect((await probe(`${hidden}?view=alternate`, OWNER)).status === 404, "a noncanonical query cannot use the token exception");
  const tarball = JSON.parse(seen.body).versions["1.0.0"].dist.tarball;
  expect(tarball.startsWith(npmBase), "the hidden package's artifact link stays on the selected registry URL");
  const hiddenBytes = stack.npm.packages.get(hidden).versions.get("1.0.0").bytes;
  const fetched = [];
  for (const [who, headers] of [["owner", { authorization: `Bearer ${OWNER}` }], ["denied", { authorization: `Bearer ${DENIED}` }], ["none", {}]]) {
    const row = await get(tarball, headers);
    fetched.push({ who, status: row.status, body: row.bytes });
  }
  const leaks = hiddenBytesFindings({ rows: fetched, markerBytes: hiddenBytes.subarray(10, 74), refusal: HIDDEN_ARTIFACT_REFUSAL });
  expect(leaks.length === 0, `the hidden tarball is refused to the owner, the denied token and no token, with none of its bytes: ${leaks.join("; ")} (${fetched.map((f) => f.status)})`);
  for (const [who, rc] of [["owner", npmrc(OWNER)], ["denied", npmrc(DENIED)], ["none", `registry=${npmBase}\n`]]) {
    const project = dir(`hidden-install-${who}`);
    writeFileSync(join(project, ".npmrc"), rc);
    writeFileSync(join(project, "package.json"), JSON.stringify({ name: `hidden-${who}`, version: "1.0.0", private: true }));
    const logBefore = stack.probationLog();
    r = await client("npm", ["install", `${hidden}@1.0.0`, "--no-audit", "--no-fund"], project);
    const refused = firewallDeniedFindings({ logBefore, logAfter: stack.probationLog(), output: r.out });
    expect(r.status !== 0 && !existsSync(join(project, "node_modules", hidden)) && refused.length === 0,
      `npm install of the hidden package fails with the ${who} credential, the firewall logged a 403 and nothing is installed: ${refused.join("; ")} ${tail(r)}`);
  }
  // Positive control: a package that exists is served under the real registry ID, so the 404 below is about the ID.
  expect((await get(`${npmBase}e2e-left`)).status === 200, "an existing package is served under the selected registry ID");
  const beforeUnknown = log.length;
  expect((await get(`${stack.base}/registry/npm/999999/e2e-left`)).status === 404 && log.length === beforeUnknown, "an unknown registry ID is refused with no upstream call");

  // ---- Python: Twine allow/deny, Bearer, pip, uv, wrong ecosystem
  const pyName = `native_pub_${suffix}`;
  const dist = dir("dist");
  // Each wheel carries a padding member of its own size, so every client's download has a size no
  // other wheel and no index page shares (the firewall's log identifies an artifact row by size).
  writeFileSync(join(home, "build.py"), `import sys, zipfile
name, version, out, pad = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
info = f"{name}-{version}.dist-info"
files = {f"{name}/__init__.py": "VALUE = 1\\n", f"{name}/pad.bin": "p" * pad,
         f"{info}/METADATA": f"Metadata-Version: 2.1\\nName: {name}\\nVersion: {version}\\n",
         f"{info}/WHEEL": "Wheel-Version: 1.0\\nGenerator: native\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"}
files[f"{info}/RECORD"] = "".join(f"{p},,\\n" for p in files) + f"{info}/RECORD,,\\n"
with zipfile.ZipFile(f"{out}/{name}-{version}-py3-none-any.whl", "w") as z:
    for p, c in files.items(): z.writestr(p, c)
`);
  const build = async (version, pad) => {
    const built = await client(python, [join(home, "build.py"), pyName, version, dist, String(pad)], home);
    expect(built.status === 0, `wheel ${version} built natively: ${tail(built)}`);
    return join(dist, `${pyName}-${version}-py3-none-any.whl`);
  };
  const wheel = await build("1.0.0", 0);       // Twine, then pip
  const wheelDenied = await build("1.0.1", 37);  // the Bearer upload that must be refused, then accepted as a control
  const wheelUvPip = await build("1.0.2", 111);  // uv pip install
  const wheelUvSync = await build("1.0.3", 222); // uv lock and uv sync
  const upload = (token) => client("twine", ["upload", "--non-interactive", "--repository-url", pypiBase, "-u", "__token__", "-p", token, wheel], home);
  const stored = () => stack.pypi.projects.get(pyName.toLowerCase().replace(/[-_.]+/g, "-"))?.files ?? [];
  r = await upload(OWNER);
  expect(r.status === 0, `twine upload with the owner token succeeds: ${tail(r)}`);
  expect(stored().length === 1 && stored()[0].filename === wheel.split(/[\\/]/).at(-1) && stored()[0].bytes.equals(readFileSync(wheel)), "the selected PyPI stored exactly the uploaded wheel");
  r = await denied("twine upload with the denied token is refused by the upstream", "pypi", "POST", () => upload(DENIED));
  expect(stored().length === 1, "the denied upload stored no second file");
  const posts = upstream("pypi").filter((e) => e.method === "POST");
  expect(posts.length === 2 && posts.some((e) => e.credential === "developer-basic" && e.status === 200) && posts.some((e) => e.credential === "developer-denied" && e.status === 403),
    `selected PyPI saw exactly the two Twine uploads with the package-manager credential: ${JSON.stringify(posts.map((e) => [e.credential, e.status]))}`);
  // Complete, valid Bearer uploads: if the denied one were accepted, the fake would store it.
  const multipart = (version, file) => Buffer.concat([
    Buffer.from(`--x\r\nContent-Disposition: form-data; name="name"\r\n\r\n${pyName}\r\n--x\r\nContent-Disposition: form-data; name="version"\r\n\r\n${version}\r\n`
      + `--x\r\nContent-Disposition: form-data; name="content"; filename="${file.split(/[\\/]/).at(-1)}"\r\n\r\n`),
    readFileSync(file), Buffer.from("\r\n--x--\r\n")]);
  const form = (token, version, file) => request("POST", pypiBase, { authorization: `Bearer ${token}`, "content-type": "multipart/form-data; boundary=x" }, multipart(version, file));
  const sincePosts = upstream("pypi").length;
  expect(await form(DENIED, "1.0.1", wheelDenied) === 403, "a Bearer upload with the denied token keeps the upstream refusal");
  expect(upstream("pypi").slice(sincePosts).some((e) => e.method === "POST" && e.credential === "developer-denied" && e.status === 403), "and the upstream saw it as a 403 for the denied credential");
  expect(stored().length === 1 && !stored().some((f) => f.version === "1.0.1"), "the denied Bearer upload stored no file");
  expect(await form(OWNER, "1.0.1", wheelDenied) === 200 && stored().length === 2, "positive control: the same Bearer upload with the owner token is stored");
  expect(await form(OWNER, "1.0.2", wheelUvPip) === 200 && await form(OWNER, "1.0.3", wheelUvSync) === 200 && stored().length === 4, "the uv wheels are uploaded with the owner token");
  // C5/D3: every client must have its bytes from the firewall. The Simple response points file URLs at
  // the firewall (not pypi.org), each client installs with the fake's own sha256 required (a different
  // byte would fail the install), and the firewall's log gains exactly one served row of that client's
  // own wheel size each time.
  const simple = (id, project) => get(`${stack.base}/registry/pypi/${id}/simple/${project.replace(/[-_.]+/g, "-")}/`, { accept: "application/vnd.pypi.simple.v1+json" });
  const listing = await simple(stack.pypiId, pyName);
  expect(listing.status === 200, `the Simple response for the uploaded project is 200: ${listing.status}`);
  const direct = fileUrlFindings(listing.body, pypiBase);
  expect(direct.length === 0, `the Simple response sends every client to the firewall for files: ${direct.join("; ")}`);
  const sizes = [wheel, wheelDenied, wheelUvPip, wheelUvSync].map((f) => readFileSync(f).length);
  expect(new Set([...sizes, listing.bytes.length]).size === 5, `every wheel and the index page have different sizes: ${sizes} and ${listing.bytes.length}`);
  const [pipSize, , uvPipSize, uvSyncSize] = sizes;
  const sha = (version) => stored().find((f) => f.version === version).sha256;
  writeFileSync(join(home, "pinned-pip.txt"), `${pyName}==1.0.0 --hash=sha256:${sha("1.0.0")}\n`);
  writeFileSync(join(home, "pinned-uvpip.txt"), `${pyName}==1.0.2 --hash=sha256:${sha("1.0.2")}\n`);
  const served = (size) => servedRows(stack.probationLog(), size);
  const fakeGets = (version) => {
    const file = stored().find((f) => f.version === version);
    const path = new URL(file.url).pathname;
    return upstream("pypi").filter((e) => e.method === "GET" && e.status === 200 && e.path === path).length;
  };
  // One client's download: the firewall's served rows of its wheel and the fake's own GETs of that file URL both grow, by the same amount.
  const downloaded = async (what, size, version, install, mode = {}) => {
    const servedBefore = served(size), fakeBefore = fakeGets(version);
    const result = await install();
    expect(result.status === 0, `${what}: ${tail(result)}`);
    const problems = servedMatchesFakeFindings({ servedBefore, servedAfter: served(size), fakeBefore, fakeAfter: fakeGets(version), ...mode });
    expect(problems.length === 0, `the firewall served ${what}'s wheel from the fake: ${problems.join("; ")}`);
  };
  await downloaded("pip installs the uploaded wheel, verified against the fake's sha256, through the selected registry", pipSize, "1.0.0",
    () => client(python, ["-m", "pip", "install", "--no-cache-dir", "--require-hashes", "--target", dir("pip-target"), "-i", `${pypiBase}simple/`, "-r", join(home, "pinned-pip.txt")], home));
  // Negative control: the same wheel fetched straight from the fake leaves the served count unchanged while the
  // fake's GET count grows, and the check says so.
  const servedAfterPip = served(pipSize), fakeAfterPip = fakeGets("1.0.0");
  await get(stored().find((f) => f.version === "1.0.0").url);
  expect(served(pipSize) === servedAfterPip, "a direct download from the fake leaves the firewall's served-row count unchanged");
  const bypass = servedMatchesFakeFindings({ servedBefore: servedAfterPip, servedAfter: served(pipSize), fakeBefore: fakeAfterPip, fakeAfter: fakeGets("1.0.0") });
  expect(bypass.length >= 1, `negative control: a download that bypasses the firewall fails the served-row check: ${bypass.join("; ")}`);
  await downloaded("uv pip installs its wheel, verified against the fake's sha256, through the selected registry", uvPipSize, "1.0.2",
    () => client("uv", ["pip", "install", "--no-cache", "--require-hashes", "--target", dir("uv-target"), "--index-url", `${pypiBase}simple/`, "-r", join(home, "pinned-uvpip.txt")], home));
  const project = dir("uv-project");
  writeFileSync(join(project, "pyproject.toml"), `[project]\nname = "native-consumer"\nversion = "0.1.0"\nrequires-python = ">=3.9"\ndependencies = ["${pyName}==1.0.3"]\n\n[[tool.uv.index]]\nurl = "${pypiBase}simple/"\ndefault = true\n\n[tool.uv]\npackage = false\n`);
  // uv lock reads the wheel's metadata with a range request: the firewall fetches the wheel from the fake once (it is this wheel's first fetch).
  await downloaded("uv lock resolves through the selected registry", uvSyncSize, "1.0.3", () => client("uv", ["lock", "--no-cache"], project), { metadataOnly: true });
  const uvLock = readFileSync(join(project, "uv.lock"), "utf8");
  const uvProblems = uvLockFindings(uvLock, pypiBase);
  expect(uvProblems.length === 0, `every uv.lock URL lies under the selected registry: ${uvProblems.join("; ")}`);
  expect(uvLock.includes(`sha256:${sha("1.0.3")}`), "uv.lock records the fake's own sha256 for the wheel");
  // The firewall now holds that wheel: uv sync gets it from the firewall's cache (served row, no new fake GET).
  await downloaded("uv sync installs the frozen pin and verifies its hash", uvSyncSize, "1.0.3", () => client("uv", ["sync", "--frozen", "--no-cache"], project), { cached: true });
  // Positive controls first: the right ID serves the project and takes the upload, so the 404s below are about the ID.
  const served200 = await simple(stack.pypiId, pyName);
  expect(served200.status === 200 && served200.body.includes(pyName.replaceAll("_", "-")), `the uploaded project is served under the selected PyPI ID: ${served200.status}`);
  const beforeWrong = log.length;
  expect(await request("POST", `${stack.base}/registry/pypi/${stack.npmId}/`, { authorization: `Bearer ${OWNER}`, "content-type": "multipart/form-data; boundary=x" }, multipart("1.0.9", wheelDenied)) === 404,
    "an npm registry ID under the PyPI upload path is refused");
  expect((await simple(stack.npmId, pyName)).status === 404, "an npm registry ID under the PyPI read path is refused");
  expect((await get(`${stack.base}/registry/npm/${stack.pypiId}/e2e-left`)).status === 404, "a PyPI registry ID under the npm path is refused");
  expect(log.length === beforeWrong, "the wrong-ecosystem requests made no upstream call");
  expect(stored().length === 4, "and stored nothing");

  // ---- boundaries
  const registryRows = log.filter((e) => e.server === "npm" || e.server === "pypi");
  expect(registryRows.length > 0 && !registryRows.some((e) => e.credential === "policy-key"), "the policy service key never reaches a package registry");
  const keyProblems = keyFindings({
    key: stack.serviceKey, policyRows: log.filter((e) => e.server === "policy"), registryRows,
    logs: { "probation.log": stack.probationLog() }, requirePolicyRows: !stack.real,
  });
  expect(keyProblems.length === 0, `the service key reached only the policy snapshot endpoint, literally, and no registry or log: ${keyProblems.join("; ")}`);
  expect(!registryRows.some((e) => e.credential === "other"), "registries see only package-manager credentials or none");
  const walk = (d) => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? (/cache|target$/.test(f) ? [] : walk(p)) : [p]; });
  const found = walk(home).filter((p) => /(^|[\\/])(\.npmrc|pip\.ini|\.pypirc|uv\.toml)$/.test(p)).map((path) => ({ path, text: readFileSync(path, "utf8") }));
  const scan = scanFindings({ found, expected: [".npmrc", "pip.ini", ".pypirc", "uv.toml"] });
  expect(scan.length === 0, `client configuration (${found.length} files: .npmrc, pip.ini, .pypirc, uv.toml all scanned) holds no certificate or key setup: ${scan.join("; ")}`);
} catch (error) {
  expect(false, `scenario aborted: ${error?.stack ?? error}`);
  if (stack) console.error(stack.probationLog().slice(-3000));
} finally {
  await stack?.stop();
  if (!process.env.NATIVE_WORK) rmSync(work, { recursive: true, force: true });
}
const floor = checkCountFindings(checks, loadPins().minChecks);
for (const f of floor) console.error(f);
failures.push(...floor);
if (checks === 0 || failures.length) {
  console.error(`native publishing FAILED: ${failures.length} failed of ${checks}`);
  process.exit(1);
}
console.log(`native publishing passed: ${checks} checks on ${process.platform}-${process.arch}`);
process.exit(0);
