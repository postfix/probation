// A complete Probation stack on this machine, for the native publishing acceptance
// (publishing-proxy Slice 5): the Node fake npm / PyPI registries and a fake policy
// endpoint on loopback https ports, a runner-generated test CA trusted by the clients,
// and the natively built `probation` binary in service-policy mode. The registries are
// private (loopback) destinations, so the policy snapshot carries the operator-approved
// exact origin and CIDR for each; the product's refusal of unapproved origins is untouched.
import { spawn, spawnSync } from "node:child_process";
import { closeSync, copyFileSync, readdirSync, realpathSync, mkdirSync, readFileSync, writeFileSync, openSync, chmodSync, renameSync, statSync, unlinkSync } from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import net from "node:net";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Npm } from "../fixtures/fakes/npm.mjs";
import { Pypi } from "../fixtures/fakes/pypi.mjs";
import { launch, taskkillArgs, winCommandLine } from "./spawn-args.mjs";
import { parsePfToken, pfSteps } from "./pf.mjs";
export { winCommandLine };

// On Windows runners a bare `bash` may be WSL's launcher; Git for Windows' bash carries openssl.
export const BASH = process.platform === "win32" ? join(process.env.ProgramFiles ?? "C:\\Program Files", "Git", "bin", "bash.exe") : "bash";
const root = fileURLToPath(new URL("../../..", import.meta.url));
export const OWNER = "e2e-owner";
export const DENIED = "e2e-denied";
const NPM_ID = 1;
const PYPI_ID = 2;

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
  s.on("error", reject);
});
const readBody = (req) => new Promise((resolve, reject) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c)).on("end", () => resolve(Buffer.concat(chunks))).on("error", reject);
});
const basicPassword = (auth) => Buffer.from(auth.slice(6), "base64").toString("utf8").split(":").slice(1).join(":");
const credential = (auth) => auth === `Bearer ${OWNER}` ? "developer-owner" : auth === `Bearer ${DENIED}` ? "developer-denied"
  : auth?.startsWith("Basic ") ? (basicPassword(auth) === DENIED ? "developer-denied" : "developer-basic") : auth?.startsWith("Bearer prb_") ? "policy-key" : auth ? "other" : "none";

/// Setup commands (bash, openssl, certutil, icacls, sudo, security) are real programs: no
/// cmd.exe in between, so a timeout kills the program itself.
export function run(command, args, options = {}) {
  const [file, argv, opts] = launch(command, args, { encoding: "utf8", timeout: 300_000, ...options }, process.platform, { shim: false });
  const r = spawnSync(file, argv, opts);
  return { status: r.status ?? -1, signal: r.signal ?? null, error: r.error?.code ?? r.error?.message ?? null, out: `${r.stdout ?? ""}${r.stderr ?? ""}`, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/// A failure message that is never empty: which command, the exit status or signal, the spawn error (ENOENT ...), both streams.
export function describeFailure(what, r) {
  const how = [r.signal ? `signal ${r.signal}` : `exit ${r.status}`, r.error].filter(Boolean).join(", ");
  return `${what} failed (${how})\n--- stdout ---\n${(r.stdout ?? "").trim() || "(empty)"}\n--- stderr ---\n${(r.stderr ?? "").trim() || "(empty)"}`;
}

/// The clients must not block this process: the fake registries it hosts have to answer them.
export function runAsync(command, args, options = {}) {
  return new Promise((resolve) => {
    const [file, argv, opts] = launch(command, args, options);
    const child = spawn(file, argv, opts);
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.stderr.on("data", (c) => (out += c));
    const timer = setTimeout(() => {
      const kill = taskkillArgs(child.pid);
      if (kill) spawnSync(kill[0], kill[1]); // cmd.exe is only the shell around the shim
      child.kill();
    }, 300_000);
    child.on("error", (e) => { clearTimeout(timer); resolve({ status: -1, out: `${out}${e.code ?? e}` }); });
    child.on("close", (code) => { clearTimeout(timer); resolve({ status: code ?? -1, out }); });
  });
}

/// Trusts the test CA where the Rust service's platform verifier looks. On Linux the
/// service reads SSL_CERT_FILE; on a CI macOS/Windows runner the CA goes into the
/// machine store (removed by `untrust`). Outside CI nothing system-wide is touched.
function trust(caFile) {
  if (!process.env.GITHUB_ACTIONS) return () => {};
  if (process.platform === "darwin") {
    const r = run("sudo", ["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", caFile]);
    if (r.status !== 0) throw new Error(`cannot trust the test CA: ${r.out}`);
    return () => run("sudo", ["security", "remove-trusted-cert", "-d", caFile]);
  }
  if (process.platform === "win32") {
    const r = run("certutil", ["-addstore", "-f", "Root", caFile]);
    if (r.status !== 0) throw new Error(`cannot trust the test CA: ${r.out}`);
    return () => run("certutil", ["-delstore", "Root", "probation-e2e-ca"]);
  }
  return () => {};
}

const HOSTS = process.platform === "win32" ? "C:\\Windows\\System32\\drivers\\etc\\hosts" : "/etc/hosts";
const MARK = "# probation-native-e2e";

/// Replaces `file` with `text` by writing a sibling and renaming it over, so a reader (or
/// a crash) never sees a half-written hosts file; keeps the mode. A file that cannot be
/// renamed over (a bind-mounted /etc/hosts) is written in place instead; without the
/// right to write the directory on POSIX, `sudo` does the same copy-and-rename.
export function writeHostsAtomically(link, text) {
  const file = realpathSync(link); // /etc/hosts is a symlink on macOS: change what it points at, keep the link
  const temp = `${file}.native-e2e.tmp`;
  try {
    writeFileSync(temp, text);
    chmodSync(temp, statSync(file).mode & 0o777);
    renameSync(temp, file);
  } catch (error) {
    try { unlinkSync(temp); } catch { /* none left */ }
    if (error.code === "EBUSY" || error.code === "EXDEV") return writeFileSync(file, text);
    if ((error.code === "EACCES" || error.code === "EPERM") && process.platform !== "win32") {
      const staged = `${file}.native-e2e.stage`;
      const r = spawnSync("sudo", ["-n", "sh", "-c", 'cat > "$2" && chmod 644 "$2" && mv "$2" "$1"', "sh", file, staged], { input: text, encoding: "utf8" });
      if (r.status === 0) return;
      throw new Error(`cannot replace ${file}: ${r.stderr}`);
    }
    throw error;
  }
}

/// SEC1: what a run killed hard (SIGKILL, a Windows kill) leaves behind: the marked hosts line
/// and a trust entry for the test CA. Both are removed at the start of the next run.
export function removeStaleHostsLines(hostsFile) {
  let text;
  try { text = readFileSync(hostsFile, "utf8"); } catch { return false; }
  if (!text.includes(MARK)) return false;
  writeHostsAtomically(hostsFile, text.split("\n").filter((l) => !l.includes(MARK)).join("\n").replace(/\n*$/, "\n"));
  return true;
}

/// CI only (nothing system-wide is touched elsewhere): the test CA's common name is fixed by make-ca.sh.
function removeStaleTrust() {
  if (!process.env.GITHUB_ACTIONS) return;
  if (process.platform === "darwin") run("sudo", ["security", "delete-certificate", "-c", "probation-e2e-ca", "/Library/Keychains/System.keychain"]);
  else if (process.platform === "win32") run("certutil", ["-delstore", "Root", "probation-e2e-ca"]);
}

/// Best effort, CI only: macOS and Windows cache name lookups, and a hosts-file change should not wait for them.
function flushResolverCache() {
  if (!process.env.GITHUB_ACTIONS) return;
  if (process.platform === "darwin") { run("sudo", ["-n", "dscacheutil", "-flushcache"]); run("sudo", ["-n", "killall", "-HUP", "mDNSResponder"]); }
  else if (process.platform === "win32") run("ipconfig", ["/flushdns"]);
}

/// The address every fake registry of the lane listens on. The service's absolute denylist
/// (LS-F9: 127.0.0.0/8 and others, whatever the registry's own private CIDRs say) refuses a
/// loopback registry, so the lane uses a private address that is assigned to the loopback
/// INTERFACE (nothing leaves the machine) and approved as one exact /32 per registry.
export const laneAddr = () => process.env.NATIVE_LANE_ADDR ?? "10.254.77.1";

/// Makes `laneAddr()` a local address: nothing to do when a socket can already bind it;
/// otherwise `ip addr add` (Linux, root or sudo), `ifconfig lo0 alias` (macOS, sudo) or
/// `netsh` on the loopback pseudo-interface (Windows). Only Linux has run here (macOS and
/// Windows are authored). Returns the undo.
async function ensureLaneAddress() {
  const addr = laneAddr();
  const bindable = () => new Promise((resolve) => { const s = net.createServer(); s.once("error", () => resolve(false)); s.listen(0, addr, () => s.close(() => resolve(true))); });
  if (await bindable()) return () => {};
  const root = process.getuid?.() === 0;
  const sudo = (cmd, args) => (root || process.platform === "win32" ? [cmd, args] : ["sudo", ["-n", cmd, ...args]]);
  const [add, del] = {
    linux: [["ip", ["addr", "add", `${addr}/32`, "dev", "lo"]], ["ip", ["addr", "del", `${addr}/32`, "dev", "lo"]]],
    darwin: [["ifconfig", ["lo0", "alias", `${addr}/32`]], ["ifconfig", ["lo0", "-alias", addr]]],
    win32: [["netsh", ["interface", "ip", "add", "address", "Loopback Pseudo-Interface 1", addr, "255.255.255.255"]], ["netsh", ["interface", "ip", "delete", "address", "Loopback Pseudo-Interface 1", addr]]],
  }[process.platform] ?? [null, null];
  if (!add) throw new Error(`no way to assign ${addr} to the loopback interface on ${process.platform}`);
  const done = run(...sudo(...add));
  if (done.status !== 0 || !(await bindable())) throw new Error(describeFailure(`assigning the lane address ${addr} to the loopback interface (the lane needs CAP_NET_ADMIN or sudo; set NATIVE_LANE_ADDR to an existing local non-loopback address to skip this)`, done));
  return () => { run(...sudo(...del)); };
}

/// A selected PyPI registry fetches its files only from the public PyPI origins (the
/// service admits no other file host), so the fake PyPI answers as https://pypi.org:443
/// on the lane address, with the registry's operator-approved /32 covering it. The
/// system hosts file is only touched in CI (GITHUB_ACTIONS) or with the explicit opt-in
/// NATIVE_E2E_MAP_HOSTS=1, and not at all when the name already resolves to the lane address (a
/// pre-mapped namespace or container). Returns the undo.
async function mapPypiHost({ hostsFile, lookup, allowMap }) {
  let address = null;
  try { address = await lookup(); } catch { /* unresolved here */ }
  const lane = laneAddr();
  if (address === lane) return () => {};
  if (!allowMap) {
    throw new Error(`pypi.org does not resolve to the lane address ${lane} (${address ?? "unresolved"}); this run maps it only in CI (GITHUB_ACTIONS) or with NATIVE_E2E_MAP_HOSTS=1`);
  }
  const strip = (text) => text.split("\n").filter((l) => !l.includes(MARK)).join("\n");
  const original = readFileSync(hostsFile, "utf8");
  writeHostsAtomically(hostsFile, `${strip(original).replace(/\n*$/, "\n")}${lane} pypi.org ${MARK}\n`);
  flushResolverCache();
  const undo = () => { writeHostsAtomically(hostsFile, strip(readFileSync(hostsFile, "utf8")).replace(/\n*$/, "\n")); flushResolverCache(); };
  // C4: the line is only useful if the resolver reads it.
  let now = null;
  try { now = await lookup(); } catch (error) { now = `unresolved (${error.code ?? error})`; }
  if (now !== lane) {
    undo();
    throw new Error(`pypi.org still does not resolve to the lane address ${lane} after the hosts file was written (got ${now}); the system resolver does not read ${hostsFile}`);
  }
  return undo;
}

/// S5: Probation checks the service key file's mode with POSIX permissions only (src/config.rs),
/// so on Windows nothing verifies its ACL. Restrict it to the current user, and say plainly
/// that the result was not verified. Returns the warnings.
export function keyFileWarnings({ platform = process.platform, file, restrict = defaultRestrict, describeAcl = defaultDescribeAcl, logDir = null }) {
  if (platform !== "win32") return [];
  const warnings = [];
  const r = restrict(file);
  if (r.status !== 0) warnings.push(`the ACL of ${file} could not be restricted to the current user: ${r.out}`);
  warnings.push(`the ACL of ${file} is not verified: Probation checks key file permissions with POSIX modes only`);
  // Slice 30: the product now refuses a key file whose DACL it cannot prove private (src/key_acl.rs); when it does, this line names what it saw.
  warnings.push(`the ACL of ${file} as the runner sees it: ${describeAcl(file)}`);
  if (logDir) warnings.push(`the ACL of the delivery log directory ${logDir} is not verified on Windows`);
  return warnings;
}
// Not Get-Acl: its module does not load from the hosted runner's shell (run 45455108402). The .NET call needs no module.
export const aclScript = (file) => `"SDDL=" + (New-Object System.IO.FileInfo '${file}').GetAccessControl().GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All); "USER=" + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value`;
function defaultDescribeAcl(file) {
  const r = run("powershell", ["-NoProfile", "-Command", aclScript(file)]);
  return r.status === 0 ? r.out.trim().replace(/\s+/g, " ") : `(unavailable: ${r.error ?? r.status})`;
}
function defaultRestrict(file) {
  return run("icacls", [file, "/inheritance:r", "/grant:r", `${process.env.USERNAME}:F`]);
}

/// Windows only (hosted): the key-file check accepts the runner's own key, and must still refuse a shared one. BUILTIN\Users (S-1-5-32-545) is
/// granted read, `check-config` must exit non-zero with the product's text, then the grant is removed and the key is accepted again.
export const keyRefusalSteps = ({ binary, configFile, keyFile }) => {
  const check = [binary, "check-config", configFile];
  return [
    { name: "accepts the runner's own key", argv: check },
    { name: "grant Users read", argv: ["icacls", keyFile, "/grant", "*S-1-5-32-545:(R)"] },
    { name: "refuses a Users-readable key", argv: check, refuses: "requires a private regular file" },
    { name: "remove the grant", argv: ["icacls", keyFile, "/remove", "*S-1-5-32-545"] },
    { name: "accepts again", argv: check },
  ];
};
export function proveKeyRefusal(steps, exec = run) {
  let failure = null;
  for (const st of steps) {
    const r = exec(st.argv[0], st.argv.slice(1));
    const ok = st.refuses ? r.status !== 0 && r.out.includes(st.refuses) : r.status === 0;
    console.warn(`key check: ${st.name}: ${ok ? "ok" : "FAILED"} (exit ${r.status})`);
    if (!ok) { failure = new Error(describeFailure(`key check "${st.name}"`, r)); break; }
  }
  // Whatever happened, the shared grant must not outlive the check.
  if (failure) exec("icacls", [steps[1].argv[1], "/remove", "*S-1-5-32-545"]);
  if (failure) throw failure;
}

/// What a timeout waiting for the service says: the answer of GET /health/ready, the first 60 lines of its log (the cause is
/// usually early; the tail is only repeated refusals), the last 15 and the data directory's listing.
export function notReadyReport({ ready, log, listing, timeoutMs }) {
  const lines = log.split("\n");
  const head = lines.slice(0, 60).join("\n");
  const tail = lines.length > 60 ? lines.slice(-15).join("\n") : "";
  return [
    `probation not ready within ${timeoutMs} ms`,
    ready ? `GET /health/ready -> ${ready.status} ${JSON.stringify(ready.body)}` : "GET /health/ready: no answer",
    `data directory: ${listing.length ? listing.map((f) => `${f.name} (${f.size} bytes)`).join(", ") : "(empty)"}`,
    `--- first 60 log lines ---\n${head}\n`,
    ...(tail ? [`--- last 15 log lines ---\n${tail}\n`] : []),
  ].join("\n");
}

/// Git bash reads a backslash as an escape: every path handed to a bash script uses forward slashes.
export const posixPath = (path) => path.replaceAll("\\", "/");

/// What the Rust service trusts: the run's CA, a real server's CA, and, when the policy server is behind a public
/// certificate (the tunnel), the system roots on Linux, where SSL_CERT_FILE replaces them (macOS and Windows verify
/// against the system store, which the run's CA is added to separately).
export function composeTrustBundle({ nativePem, extraPem = null, publicTrust = false, platform = process.platform, read = (path) => { try { return readFileSync(path, "utf8"); } catch { return null; } } }) {
  const parts = [nativePem];
  if (extraPem) parts.push(extraPem);
  if (publicTrust && platform === "linux") {
    const system = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"].map(read).find(Boolean);
    if (!system) throw new Error("no system CA bundle found for a policy server behind a public certificate");
    parts.push(system);
  }
  return parts.join("\n");
}

/// `real` (optional) replaces the in-process policy endpoint with a real policy server:
/// `{ url, key, npmId, pypiId, extraCa }` — its catalog already lists the two registries
/// (npm at https://<lane address>:<npmPort>/, PyPI at https://pypi.org/) with the lane /32
/// approved; `extraCa` is the PEM that makes the server's certificate trusted.
/// Signals that end the run through the same cleanup. (SIGBREAK is Windows' console break;
/// SIGKILL and a hard Windows kill cannot be caught, which is what the stale-entry cleanup at the start is for.)
export const HANDLED_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"];

export async function startStack({ binary, work, real = null, npmPort: fixedNpmPort = null, pypiPort = 443, hooks = {} }) {
  // Undo steps run in reverse on any failure, on SIGINT/SIGTERM, on exit and on stop().
  const undo = [];
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    for (const step of undo.reverse()) { try { step(); } catch (error) { console.error(`cleanup step failed: ${error?.message ?? error}`); } }
  };
  const onSignal = (signal) => () => { cleanup(); process.exit(signal === "SIGINT" || signal === "SIGBREAK" ? 130 : 143); };
  const handlers = HANDLED_SIGNALS.map((signal) => [signal, onSignal(signal)]);
  for (const [signal, handler] of handlers) process.on(signal, handler);
  process.on("exit", cleanup);
  const forget = () => { for (const [signal, handler] of handlers) process.off(signal, handler); process.off("exit", cleanup); };
  try {
    const stack = await bringUp({ binary, work, real, fixedNpmPort, pypiPort, hooks, undo });
    return { ...stack, async stop() { try { cleanup(); } finally { forget(); } } };
  } catch (error) {
    try { cleanup(); } finally { forget(); }
    throw error;
  }
}

/// Loads the pf redirect, probes 127.0.0.1:`from`, and registers its undo; false (with the
/// ruleset restored) when it cannot be set up or does not carry a connection.
async function redirectWithPf(from, to, undo) {
  const steps = pfSteps({ from, to });
  const exec = (step) => run(step.command, step.args, step.input === undefined ? {} : { input: step.input });
  let token = null;
  const restore = () => { exec(steps.restore); if (token) exec(steps.release(token)); };
  if (exec(steps.load).status !== 0) { restore(); return false; }
  const enabled = exec(steps.enable);
  token = parsePfToken(enabled.out);
  const works = await new Promise((resolve) => {
    const socket = net.connect(from, "127.0.0.1");
    socket.setTimeout(3000, () => { socket.destroy(); resolve(false); });
    socket.on("connect", () => { socket.destroy(); resolve(true); });
    socket.on("error", () => resolve(false));
  });
  if (!works) { restore(); return false; }
  undo.push(restore);
  return true;
}

async function bringUp({ binary, work, real, fixedNpmPort, pypiPort, hooks, undo }) {
  mkdirSync(work, { recursive: true });
  removeStaleHostsLines(hooks.hostsFile ?? HOSTS);
  (hooks.staleTrust ?? removeStaleTrust)();
  const ca = run(BASH, [posixPath(join(root, "tests/e2e/fixtures/make-ca.sh")), posixPath(work)]);
  if (ca.status !== 0) throw new Error(describeFailure(`make-ca.sh under ${BASH}`, ca));
  const caFile = join(work, "ca", "ca.pem");
  const tls = { cert: readFileSync(join(work, "tls", "cert.pem")), key: readFileSync(join(work, "tls", "key.pem")) };
  undo.push((hooks.trust ?? trust)(caFile));
  const inCi = Boolean(process.env.GITHUB_ACTIONS);
  undo.push(await ensureLaneAddress());
  const lane = laneAddr();
  undo.push(await mapPypiHost({
    hostsFile: hooks.hostsFile ?? HOSTS,
    lookup: hooks.lookup ?? (async () => (await dns.lookup("pypi.org")).address),
    allowMap: hooks.mapHosts ?? (inCi || process.env.NATIVE_E2E_MAP_HOSTS === "1"),
  }));
  const [freeNpm, policyPort, firewallPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const npmPort = fixedNpmPort ?? freeNpm;
  const log = [];
  const servers = [];
  undo.push(() => { for (const server of servers) { server.close(); server.closeAllConnections?.(); } });
  const npm = new Npm(`https://${lane}:${npmPort}`);
  const pypi = new Pypi("https://pypi.org");

  let serviceKey = null; // set below; rows are classified against it
  const listen = (name, port, handler, host = lane) => new Promise((resolve, reject) => {
    const server = https.createServer(tls, async (req, res) => {
      const body = await readBody(req);
      const entry = { server: name, method: req.method, path: req.url, credential: credential(req.headers.authorization), bodyBytes: body.length, status: 0,
        carriesKey: Boolean(serviceKey) && [req.url, JSON.stringify(req.headers), body.toString("latin1")].some((part) => part.includes(serviceKey)) };
      if (name === "policy") entry.authorization = req.headers.authorization;
      if (req.method === "PUT") entry.bodyPreview = body.toString("latin1").slice(0, 400);
      log.push(entry);
      const answer = handler(req, body);
      const bytes = Buffer.from(answer.body ?? "");
      entry.status = answer.status;
      res.writeHead(answer.status, { ...answer.headers, "content-length": bytes.length });
      res.end(bytes);
    });
    servers.push(server);
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  // S3/SEC4: the fakes listen on the lane address (loopback interface, see laneAddr). On a macOS CI
  // runner an unprivileged process can bind a port below 1024 only on the wildcard address, so the
  // fake PyPI on :443 is served on all interfaces of that ephemeral runner (the lane address is an
  // alias of lo0, so the wildcard covers it). The earlier pf redirect of 127.0.0.1:443 (pf.mjs)
  // cannot serve a lane address and is no longer used here.
  const listenLoopback = (name, port, handler) => {
    const mac = process.platform === "darwin" && process.env.GITHUB_ACTIONS && port === 443 && !hooks.noPf;
    return listen(name, port, handler, mac ? "0.0.0.0" : lane);
  };
  await listen("npm", npmPort, (req, body) => npm.handle(req, req.url, "native", body));
  await listenLoopback("pypi", pypiPort, (req, body) => pypi.handle(req, req.url, "native", body));

  serviceKey = real?.key ?? `prb_${randomBytes(16).toString("hex")}`;
  const npmId = real?.npmId ?? NPM_ID;
  const pypiId = real?.pypiId ?? PYPI_ID;
  const layer = (kind, allow, blocks = []) => ({ kind, freeze_seconds: null, osv: null, blocks, exceptions: [], allow });
  const all = { exceptions: true, osv_off: true, shorter_freeze: true };
  const none = { exceptions: false, osv_off: false, shorter_freeze: false };
  const policy = { blocks: [] };
  const snapshot = () => ({
    version: 1, key_id: 1, org: 1, revision: 1,
    place_chain: [{ place: { kind: "Platform", id: 1 }, layer_revision: 1 }, { place: { kind: "Org", id: 1 }, layer_revision: 1 }],
    layers: [
      { place: { kind: "Platform", id: 1 }, layer: layer("Platform", all), revision: 1 },
      { place: { kind: "Org", id: 1 }, layer: layer("Org", none, policy.blocks), revision: 1 },
    ],
    account: { kind: "Org", id: 1 }, rate_limit: null, rate_limit_source: "default",
    registries: [
      { registry: npmId, ecosystem: "Npm", target_url: `https://${lane}:${npmPort}/`, trusted: false, registry_private_cidrs: [`${lane}/32`], deletion_scopes: [] },
      { registry: pypiId, ecosystem: "PyPi", target_url: "https://pypi.org/", trusted: false, registry_private_cidrs: [`${lane}/32`], deletion_scopes: [] },
    ],
  });
  if (!real) await listen("policy", policyPort, (req) => req.url === "/api/v1/policy/snapshot" && req.headers.authorization === `Bearer ${serviceKey}`
    ? { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(snapshot()) }
    : { status: 401, body: "unauthorized" }, "127.0.0.1");

  const data = join(work, "data");
  mkdirSync(data, { recursive: true });
  copyFileSync(join(root, "blocklist.sample.json"), join(work, "blocklist.json"));
  const keyFile = join(work, "service.key");
  writeFileSync(keyFile, `${serviceKey}\n`, { mode: 0o600 });
  chmodSync(keyFile, 0o600);
  const warnings = keyFileWarnings({ file: keyFile, restrict: hooks.restrict });
  for (const warning of warnings) console.warn(`warning: ${warning}`);
  const q = (path) => JSON.stringify(path.replaceAll("\\", "/"));
  const sample = readFileSync(join(root, "config.sample.toml"), "utf8");
  const set = (text, key, value) => text.replace(new RegExp(`^${key} = .*$`, "m"), `${key} = ${value}`);
  let config = sample;
  config = set(config, "listen", JSON.stringify(`127.0.0.1:${firewallPort}`));
  config = set(config, "public_url", JSON.stringify(`https://127.0.0.1:${firewallPort}`));
  config = set(config, "data_dir", q(data));
  config = set(config, "blocklist_file", q(join(work, "blocklist.json")));
  config = set(config, "osv_mode", '"off"');
  config += `\ntls_cert_path = ${q(join(work, "tls", "cert.pem"))}\ntls_key_path = ${q(join(work, "tls", "key.pem"))}\nsync_interval_seconds = 1\n`;
  config += `\n[service_policy]\nserver_url = ${JSON.stringify(real?.url ?? `https://127.0.0.1:${policyPort}`)}\nservice_key_file = ${q(keyFile)}\nsync_interval_seconds = 1\n`;
  const configFile = join(work, "config.toml");
  writeFileSync(configFile, config);

  // The service trusts the native CA and, against a real server, that server's CA too.
  const bundle = join(work, "trust.pem");
  writeFileSync(bundle, composeTrustBundle({ nativePem: readFileSync(caFile, "utf8"), extraPem: real?.extraCa ? readFileSync(real.extraCa, "utf8") : null, publicTrust: Boolean(real?.publicTrust) }));
  if ((hooks.platform ?? process.platform) === "win32") (hooks.proveKey ?? ((steps) => proveKeyRefusal(steps)))(keyRefusalSteps({ binary, configFile, keyFile }));
  const outLog = join(work, "probation.log");
  const fd = openSync(outLog, "w");
  undo.push(() => closeSync(fd));
  const child = spawn(binary, ["serve", "--config", configFile], {
    stdio: ["ignore", fd, fd], env: { ...process.env, SSL_CERT_FILE: bundle },
  });
  undo.push(() => child.kill());
  let exited = null;
  child.on("exit", (code, signal) => { exited = code ?? signal ?? "signal"; });
  const base = `https://127.0.0.1:${firewallPort}`;
  const ready = () => new Promise((resolve) => {
    https.get(`${base}/health/ready`, { ca: readFileSync(caFile) }, (res) => { res.resume(); resolve(res.statusCode === 200); }).on("error", () => resolve(false));
  });
  const deadline = Date.now() + 60_000;
  while (!(await ready())) {
    if (exited !== null) throw new Error(`probation exited ${exited}: ${readFileSync(outLog, "utf8").slice(-2000)}`);
    if (Date.now() > deadline) {
      const answer = await new Promise((resolve) => https.get(`${base}/health/ready`, { ca: readFileSync(caFile) }, (res) => {
        const chunks = []; res.on("data", (c) => chunks.push(c)).on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString().slice(0, 500) }));
      }).on("error", () => resolve(null)));
      let listing = [];
      try { listing = readdirSync(data).map((name) => ({ name, size: statSync(join(data, name)).size })); } catch { /* none */ }
      throw new Error(notReadyReport({ ready: answer, log: readFileSync(outLog, "utf8"), listing, timeoutMs: 60_000 }));
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return {
    base, npmBase: `${base}/registry/npm/${npmId}/`, pypiBase: `${base}/registry/pypi/${pypiId}/`,
    npmId, pypiId, caFile: bundle, npm, pypi, policy, log, serviceKey, warnings, real: Boolean(real),
    probationLog: () => readFileSync(outLog, "utf8"),
  };
}
