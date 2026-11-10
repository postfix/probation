// Pure checks behind publishing.mjs, each with a mutation control in assertions.test.mjs.
// Every function returns a list of findings; an empty list means the property holds.

/// The run made at least `floor` checks (pins.json `minChecks`, per OS): a scenario that stops early cannot pass on the few it ran.
export function checkCountFindings(checks, floor) {
  if (!Number.isInteger(floor) || floor < 1) return ["pins.json has no minChecks floor"];
  return checks >= floor ? [] : [`only ${checks} checks ran, the pinned floor is ${floor}`];
}

/// A1: the three credential cases (`owner`, `denied`, `none`) of a hidden artifact each got
/// exactly `refusal` and a body without any of the tarball's bytes.
export function hiddenBytesFindings({ rows, markerBytes, refusal }) {
  const findings = [];
  for (const who of ["owner", "denied", "none"]) {
    const row = rows.find((r) => r.who === who);
    if (!row) { findings.push(`no ${who} case was fetched`); continue; }
    if (row.status !== refusal) findings.push(`${who}: status ${row.status}, expected the refusal ${refusal}`);
    if (Buffer.from(row.body).includes(markerBytes)) findings.push(`${who}: the refusal body carries the hidden tarball's bytes`);
  }
  return findings;
}

/// A4: every `resolved` URL of an npm lockfile lies under `base`, and there is at least one.
export function lockfileFindings(lockText, base) {
  const lock = JSON.parse(lockText);
  const urls = [];
  const walk = (node) => {
    if (node && typeof node === "object") {
      if (typeof node.resolved === "string") urls.push(node.resolved);
      for (const value of Object.values(node)) walk(value);
    }
  };
  walk(lock);
  if (urls.length === 0) return ["the lockfile lists no resolved URL"];
  return urls.filter((u) => !u.startsWith(base)).map((u) => `resolved URL outside the selected registry: ${u}`);
}

/// A4: every URL in uv.lock lies under `base`, and there is at least one.
export function uvLockFindings(text, base) {
  const urls = [...text.matchAll(/"(https?:\/\/[^"]+)"/g)].map((m) => m[1]);
  if (urls.length === 0) return ["uv.lock lists no URL"];
  return urls.filter((u) => !u.startsWith(base)).map((u) => `uv.lock URL outside the selected registry: ${u}`);
}

/// A4: the certificate/key scan looked at every expected config file and found no setting.
export function scanFindings({ found, expected, pattern = /client_cert|certfile|keyfile|PRIVATE KEY|\bcert\s*=|(^|[\s_.-])key\s*=|strict-ssl\s*=\s*false|\bca\s*=|cafile\s*=|\bca\[\]\s*=|ssl(cert|key)|tls-verify|verify\s*=\s*false|trusted-host|insecure-host|native-tls|\bproxy\s*=/im }) {
  const findings = [];
  for (const name of expected) {
    if (!found.some((f) => f.path.replaceAll("\\", "/").split("/").at(-1) === name)) findings.push(`${name} was not scanned`);
  }
  for (const f of found) if (pattern.test(f.text)) findings.push(`${f.path} holds a certificate or key setting`);
  return findings;
}

/// A3: the service key reached the policy endpoint (and only there), literally as the stack's key.
export function keyFindings({ key, policyRows, registryRows, logs, requirePolicyRows }) {
  const findings = [];
  if (requirePolicyRows && policyRows.length === 0) findings.push("no policy request row was recorded, so the key check would be vacuous");
  for (const row of policyRows) {
    if (row.authorization !== `Bearer ${key}`) findings.push("a policy request did not carry the stack's key literally");
    if (row.path !== "/api/v1/policy/snapshot") findings.push(`the key went to ${row.path}`);
  }
  const carrying = registryRows.filter((r) => r.carriesKey).length;
  if (carrying) findings.push(`${carrying} registry request(s) carried the service key`);
  for (const [name, text] of Object.entries(logs)) if (text.includes(key)) findings.push(`the service key appears in ${name}`);
  return findings;
}

/// C5: every file URL in a PEP 691 Simple response lies under `base` (the firewall), and
/// there is at least one. A response naming pypi.org or files.pythonhosted.org directly would
/// let a client bypass the firewall for the bytes.
export function fileUrlFindings(simpleText, base) {
  const files = JSON.parse(simpleText).files ?? [];
  if (files.length === 0) return ["the Simple response lists no file"];
  return files.filter((f) => !String(f.url).startsWith(base)).map((f) => `file URL outside the firewall: ${f.url}`);
}

/// C5/D3: the firewall's own log gained exactly one served PyPI file of `size` bytes (status
/// 200, GET) since `before` rows of that size were counted: one client, one download. Give
/// every client its own wheel size, and an index page of the same size would show up as a
/// second row. (An artifact row carries no file name on the selected-registry routes.)
export function artifactRowFindings({ logText, size, before }) {
  const served = servedRows(logText, size);
  return served === before + 1 ? [] : [`the firewall log shows ${served} served PyPI row(s) of ${size} bytes, expected exactly ${before + 1}`];
}

/// C7: one client's download. The firewall's served PyPI rows of that wheel's size grew by `ds`, the fake's
/// own 200 GETs of that file's URL grew by `df`: both must be at least 1 and equal, so the bytes came from
/// the fake through the firewall once, a second route or an equal-size page is a second row, and a direct
/// download from the fake is a fake GET with no served row.
export function servedMatchesFakeFindings({ servedBefore, servedAfter, fakeBefore, fakeAfter, cached = false, metadataOnly = false }) {
  const ds = servedAfter - servedBefore, df = fakeAfter - fakeBefore;
  const findings = [];
  if (metadataOnly) { // the client reads only part of the wheel (a range request): no full served row, but the firewall fetched it from the fake once
    if (df !== 1) findings.push(`the fake saw ${df} GET(s) of the file, expected the firewall's one fetch`);
    return findings;
  }
  if (cached) { // the firewall already holds the file: it serves it without asking the fake again
    if (ds < 1) findings.push("the firewall log gained no served row for the download");
    if (df !== 0) findings.push(`the fake saw ${df} GET(s) although the firewall already held the file`);
    return findings;
  }
  if (ds < 1) findings.push("the firewall log gained no served row for the download");
  if (df < 1) findings.push("the fake saw no GET of the file");
  if (ds >= 1 && df >= 1 && ds !== df) findings.push(`the firewall served ${ds} row(s) but the fake saw ${df} GET(s) of the file`);
  if (ds < 1 && df >= 1) findings.push(`the fake saw ${df} GET(s) the firewall did not serve`);
  return findings;
}

export function servedRows(logText, size) {
  return decidedRows(logText).filter((f) => f.ecosystem === "pypi" && f.method === "GET" && f.status === 200 && f.bytes === size).length;
}

/// The firewall's "request decided" rows, strings unquoted.
export function decidedRows(logText) {
  const unquote = (v) => (typeof v === "string" ? v.replace(/^"|"$/g, "") : v);
  const rows = [];
  for (const line of logText.split("\n")) {
    let fields;
    try { fields = JSON.parse(line).fields; } catch { continue; }
    if (unquote(fields?.message) !== "request decided") continue;
    rows.push({ ...fields, method: unquote(fields.method), ecosystem: unquote(fields.ecosystem) });
  }
  return rows;
}

const CONNECTION_ERROR = /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|ECONNRESET|EHOSTUNREACH/;

/// D2: a denied write was refused BY THE UPSTREAM. After the call (rows from index `since`)
/// the upstream saw `method` with the denied credential and answered 403; the client's exit
/// was non-zero and its output says E403 or "403 Forbidden", not a bare "403" (which also
/// matches a port number) and not a connection error.
export function deniedStepFindings({ rows, since, method, output, exit }) {
  const findings = [];
  if (exit === 0) findings.push("the denied step exited 0");
  if (!rows.slice(since).some((r) => r.method === method && r.credential === "developer-denied" && r.status === 403)) {
    findings.push(`no upstream ${method} row with the denied credential and status 403 appeared after the call`);
  }
  if (!/E403|403 Forbidden/.test(output)) findings.push("the client output names neither E403 nor 403 Forbidden");
  if (CONNECTION_ERROR.test(output)) findings.push("the client output reports a connection error, not a refusal");
  return findings;
}

/// D2: a request the firewall itself refused: its log gained a 403 row since `logBefore`,
/// and the client did not just fail to connect.
export function firewallDeniedFindings({ logBefore, logAfter, output }) {
  const findings = [];
  const count = (text) => decidedRows(text).filter((r) => r.status === 403).length;
  if (count(logAfter) <= count(logBefore)) findings.push("the firewall logged no new 403 row");
  if (CONNECTION_ERROR.test(output)) findings.push("the client output reports a connection error, not a refusal");
  return findings;
}

/// D4: what a client may inherit from this process. Everything else is dropped.
const PASSTHROUGH = ["PATH", "Path", "PATHEXT", "SystemRoot", "SYSTEMROOT", "SystemDrive", "ComSpec", "COMSPEC", "TEMP", "TMP", "TMPDIR",
  "LANG", "LC_ALL", "LC_CTYPE", "TERM", "USER", "USERNAME", "LOGNAME", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ALLUSERSPROFILE", "LOCALAPPDATA"];
export function buildClientEnv(processEnv, extra) {
  const env = {};
  for (const name of PASSTHROUGH) if (processEnv[name] !== undefined) env[name] = processEnv[name];
  return { ...env, ...extra };
}

/// D4: no variable that would give a client a certificate or key, a proxy, or a way around
/// TLS verification. The server-trust variables the run sets itself (`trust`: name -> value) are
/// allowed with exactly that value.
const RISKY_ENV = /(CLIENT_?CERT|CLIENT_?KEY|_CERT$|_KEY(_FILE)?$|^(npm_config_|NPM_CONFIG_)(cert|key|cafile|ca$|strict_ssl|proxy|https_proxy|registry)|TLS_REJECT|PROXY|NODE_OPTIONS|PIP_(CERT|TRUSTED_HOST|INDEX_URL|EXTRA_INDEX_URL)|UV_(NATIVE_TLS|NO_VERIFY_SSL|SYSTEM_CERTS|INSECURE|ALLOW_INSECURE|INDEX|DEFAULT_INDEX)|SSL|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|SSL_CERT_(FILE|DIR)|NODE_EXTRA_CA_CERTS|TWINE_(CERT|REPOSITORY|USERNAME|PASSWORD))/i;
export function envFindings(env, trust = {}) {
  return Object.entries(env)
    .filter(([name]) => RISKY_ENV.test(name))
    .filter(([name, value]) => trust[name] !== value)
    .map(([name]) => `${name} is set in the client environment`);
}

/// Requirement 7: for every native job (`labels`) the real server's snapshot proxy saw, through the tunnel and from an address
/// other than the server job's own (its `serverLabel` probe), a labelled probe with the throwaway key AND the native
/// probation's own snapshot request (no label) from that same tunnel-client address.
/// The label is the client-supplied X-Native-Job header: this check guards honest mistakes (a job that never reached the
/// server, or reached it from the server job's own address), NOT forgery by someone who holds the throwaway key, who can
/// send any label. The key holder is trusted for the length of the run.
export function remoteSnapshotFindings({ entries, labels, serverLabel = "linux-server" }) {
  const findings = [];
  const served = (e) => e.keyOk && e.status === 200 && e.path === "/api/v1/policy/snapshot";
  const own = entries.find((e) => e.label === serverLabel && served(e));
  if (!own) findings.push("the server job's own tunnel probe never succeeded, so there is no address to tell the native jobs apart from");
  for (const label of labels) {
    const probe = entries.find((e) => e.label === label && served(e) && e.cfIp);
    if (!probe) { findings.push(`no labelled snapshot probe from ${label} reached the real server through the tunnel`); continue; }
    if (own?.cfIp && probe.cfIp === own.cfIp) findings.push(`the ${label} probe came from the server job's own address ${own.cfIp}`);
    if (!entries.some((e) => e.label === null && served(e) && e.cfIp === probe.cfIp)) {
      findings.push(`${label}: the native probation never fetched the snapshot (no unlabelled request from ${probe.cfIp})`);
    }
  }
  return findings;
}
