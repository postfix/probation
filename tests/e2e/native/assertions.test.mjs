// Pure checks used by publishing.mjs, with the mutation controls the review asked for.
// node tests/e2e/native/assertions.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkCountFindings, decidedRows, artifactRowFindings, remoteSnapshotFindings, servedMatchesFakeFindings, buildClientEnv, deniedStepFindings, envFindings, fileUrlFindings, firewallDeniedFindings, hiddenBytesFindings, keyFindings, lockfileFindings, scanFindings, uvLockFindings } from "./assertions.mjs";

const marker = Buffer.from("TARBALL-BYTES-MARKER");
const refusal = 403;
const rows = (overrides = {}) => ["owner", "denied", "none"].map((who) => ({ who, status: 403, body: Buffer.from('{"error":"refused"}'), ...overrides[who] }));

// A1: hidden bytes. Green: three refusals without the marker. Red (mutation control): a proxy that serves the tarball.
assert.deepEqual(hiddenBytesFindings({ rows: rows(), markerBytes: marker, refusal }), []);
const serving = rows({ owner: { status: 200, body: Buffer.concat([Buffer.from("x"), marker]) } });
assert.ok(hiddenBytesFindings({ rows: serving, markerBytes: marker, refusal }).length >= 2, "serving the tarball is a status and a bytes finding");
assert.ok(hiddenBytesFindings({ rows: rows({ none: { status: 404 } }), markerBytes: marker, refusal }).length === 1, "a different refusal status is a finding");
assert.ok(hiddenBytesFindings({ rows: rows({ denied: { body: marker } }), markerBytes: marker, refusal }).length === 1, "bytes in a refusal body are a finding");
assert.ok(hiddenBytesFindings({ rows: rows().slice(0, 2), markerBytes: marker, refusal }).length === 1, "a missing credential case is a finding");

// A4: lockfiles.
const base = "https://127.0.0.1:1/registry/npm/1/";
const lock = (...resolved) => JSON.stringify({ packages: { "": {}, ...Object.fromEntries(resolved.map((r, i) => [`node_modules/p${i}`, { resolved: r }])) } });
assert.deepEqual(lockfileFindings(lock(`${base}p/-/p-1.tgz`), base), []);
assert.ok(lockfileFindings(lock(`${base}p/-/p-1.tgz`, "https://registry.npmjs.org/q/-/q-1.tgz"), base).length === 1, "a resolved URL outside the selected registry");
assert.ok(lockfileFindings(lock(), base).length === 1, "a lockfile with no resolved URL proves nothing");
assert.deepEqual(uvLockFindings(`source = { registry = "${base}simple" }\nurl = "${base}x.whl"`, base), []);
assert.ok(uvLockFindings(`url = "https://files.pythonhosted.org/x.whl"`, base).length === 1);
assert.ok(uvLockFindings("version = 1", base).length === 1, "no URL at all proves nothing");

// A4: the certificate scan must have scanned every expected config.
const names = [".npmrc", "pip.ini", ".pypirc", "uv.toml"];
const found = names.map((n) => ({ path: `/h/${n}`, text: "[global]\nindex-url = x\n" }));
assert.deepEqual(scanFindings({ found, expected: names }), []);
assert.ok(scanFindings({ found: found.slice(0, 3), expected: names }).some((f) => f.includes("uv.toml")), "an unscanned config is a finding");
assert.ok(scanFindings({ found: [...found.slice(0, 3), { path: "/h/uv.toml", text: "client_cert = /x" }], expected: names }).length === 1, "a certificate setting is a finding");

// C6: every setting that gives a client a key, a custom trust, a proxy, or a way around verification is flagged, one by one.
for (const [line, what] of [["key=/k.pem", "key="], ["strict-ssl=false", "strict-ssl=false"], ["ca=/x.pem", "ca="], ["trusted-host = pypi.org", "trusted-host"],
  ["allow-insecure-host = [\"x\"]", "allow-insecure-host"], ["native-tls = true", "native-tls"], ["proxy=http://p", "proxy="], ["https-proxy=http://p", "https-proxy="],
  ["client_cert = /c", "client_cert"], ["cert=/c", "cert="], ["certfile=/c", "certfile"], ["keyfile=/k", "keyfile"], ["-----BEGIN PRIVATE KEY-----", "PRIVATE KEY"]]) {
  const flagged = scanFindings({ found: [{ path: "/h/.npmrc", text: `registry=x\n${line}\n` }], expected: [] });
  assert.equal(flagged.length, 1, `${what} is a finding`);
}
assert.deepEqual(scanFindings({ found: [{ path: "/h/.npmrc", text: "registry=https://x/\n//x/:_authToken=t\n[global]\nindex-url = https://x/simple/\nrepository = https://x/\nusername = __token__\ndisable-pip-version-check = true\ncafile-not-set\n" }], expected: [] }), [], "ordinary client settings are not findings");

// A3: the service key.
const key = "prb_" + "a".repeat(32);
assert.deepEqual(keyFindings({ key, policyRows: [{ authorization: `Bearer ${key}`, path: "/api/v1/policy/snapshot" }], registryRows: [{ carriesKey: false }], logs: { probation: "ok" }, requirePolicyRows: true }), []);
assert.ok(keyFindings({ key, policyRows: [], registryRows: [{ carriesKey: false }], logs: {}, requirePolicyRows: true }).length === 1, "no policy request row: vacuous");
assert.ok(keyFindings({ key, policyRows: [{ authorization: "Bearer prb_other", path: "/api/v1/policy/snapshot" }], registryRows: [], logs: {}, requirePolicyRows: true }).length >= 1, "the raw header must equal the stack's key literally");
assert.ok(keyFindings({ key, policyRows: [], registryRows: [{ carriesKey: true }], logs: {}, requirePolicyRows: false }).length === 1, "a registry row carrying the key");
assert.ok(keyFindings({ key, policyRows: [], registryRows: [], logs: { probation: `leak ${key}` }, requirePolicyRows: false }).length === 1, "the key in a log");

// C5: the firewall served the files. The Simple response a client gets must point its file
// URLs at the firewall; the negative control is a service handing out a direct pypi.org URL.
const simple = (...urls) => JSON.stringify({ files: urls.map((url, i) => ({ filename: `f${i}.whl`, url })) });
assert.deepEqual(fileUrlFindings(simple(`${base}artifacts/abc/f0.whl`), base), []);
assert.equal(fileUrlFindings(simple("https://pypi.org/packages/ab/cd/f0.whl"), base).length, 1, "a direct pypi.org file URL is a finding");
assert.equal(fileUrlFindings(simple(`${base}artifacts/abc/f0.whl`, "https://files.pythonhosted.org/packages/x/f1.whl"), base).length, 1, "one direct URL among served ones");
assert.equal(fileUrlFindings(JSON.stringify({ files: [] }), base).length, 1, "no file at all proves nothing");
const row = (method, status, bytes, ecosystem = "pypi") => JSON.stringify({ fields: { message: '"request decided"', method: `"${method}"`, ecosystem: `"${ecosystem}"`, package: '""', version: '""', status, bytes } });
const text = (...rows) => ["noise", ...rows].join("\n");
// D3: exactly one more served row of the client's own wheel size.
assert.deepEqual(artifactRowFindings({ logText: text(row("GET", 200, 990)), size: 990, before: 0 }), []);
assert.equal(artifactRowFindings({ logText: text(row("GET", 200, 990), row("GET", 200, 990)), size: 990, before: 0 }).length, 1, "two rows where one was expected: a second route (or an index page of equal size) matched");
assert.equal(artifactRowFindings({ logText: text(row("GET", 200, 990)), size: 990, before: 1 }).length, 1, "the client downloaded from a different route, so no new row appeared");
assert.equal(artifactRowFindings({ logText: "", size: 990, before: 0 }).length, 1, "no row at all");
assert.deepEqual(artifactRowFindings({ logText: text(row("GET", 200, 990), row("GET", 502, 990), row("HEAD", 200, 990), row("GET", 200, 990, "npm"), row("GET", 200, 5)), size: 990, before: 0 }), [], "failed, HEAD, non-PyPI and other-size rows do not count");

// D2: a denied step must show an upstream 403 for the denied credential after the call, in the output as E403 or 403 Forbidden.
const upstream = (...rows) => rows.map(([method, credential, status]) => ({ method, credential, status }));
assert.deepEqual(deniedStepFindings({ rows: upstream(["GET", "none", 200], ["PUT", "developer-denied", 403]), since: 1, method: "PUT", output: "npm error code E403\nnpm error 403 Forbidden - PUT", exit: 1 }), []);
assert.deepEqual(deniedStepFindings({ rows: upstream(["PUT", "developer-denied", 403]), since: 0, method: "POST", output: "HTTPError: 403 Forbidden from https://x/", exit: 1 }).length, 1, "wrong method");
assert.equal(deniedStepFindings({ rows: upstream(["PUT", "developer-denied", 403]), since: 1, method: "PUT", output: "E403", exit: 1 }).length, 1, "a row from before the call does not count");
assert.equal(deniedStepFindings({ rows: upstream(["PUT", "developer-owner", 403]), since: 0, method: "PUT", output: "E403", exit: 1 }).length, 1, "the credential must be the denied one");
assert.equal(deniedStepFindings({ rows: upstream(["PUT", "developer-denied", 200]), since: 0, method: "PUT", output: "E403", exit: 1 }).length, 1, "the status must be 403");
assert.equal(deniedStepFindings({ rows: upstream(["PUT", "developer-denied", 403]), since: 0, method: "PUT", output: "E403", exit: 0 }).length, 1, "a zero exit is no denial");
// The old flake: a denied step against a closed port. "403" appears in the port, the exit is non-zero, no upstream row exists.
assert.ok(deniedStepFindings({ rows: [], since: 0, method: "PUT", output: "npm error code ECONNREFUSED\nnpm error connect ECONNREFUSED 127.0.0.1:40312 - PUT https://127.0.0.1:40312/registry/npm/1/p", exit: 1 }).length >= 2, "refused connection: no upstream row, no E403, and the connection error is named");
assert.ok(deniedStepFindings({ rows: upstream(["PUT", "developer-denied", 403]), since: 0, method: "PUT", output: "ECONNREFUSED 127.0.0.1:40312 E403", exit: 1 }).length === 1, "a connection error in the output is a finding even with a row");
const fw = (status) => row("GET", status, 0, "npm");
assert.deepEqual(firewallDeniedFindings({ logBefore: text(fw(200)), logAfter: text(fw(200), fw(403)), output: "npm error code E403" }), []);
assert.equal(firewallDeniedFindings({ logBefore: text(fw(403)), logAfter: text(fw(403)), output: "E403" }).length, 1, "no new firewall 403 row");
assert.equal(firewallDeniedFindings({ logBefore: "", logAfter: text(fw(403)), output: "ECONNREFUSED 127.0.0.1:1" }).length >= 1, true);

// D4: the clients get an allow-listed environment, with no client certificate, key, proxy or TLS-verification switch.
const trust = { SSL_CERT_FILE: "/ca.pem", NODE_EXTRA_CA_CERTS: "/ca.pem" };
const env = buildClientEnv({ PATH: "/bin", HOME: "/real", CLIENT_CERT: "/c", HTTPS_PROXY: "http://p", NODE_TLS_REJECT_UNAUTHORIZED: "0", npm_config_cafile: "/x", PIP_CLIENT_CERT: "/y", RANDOM_SECRET: "s" }, { HOME: "/h", ...trust });
assert.deepEqual(Object.keys(env).sort(), ["HOME", "NODE_EXTRA_CA_CERTS", "PATH", "SSL_CERT_FILE"], "only the allow-list and the explicit entries survive");
assert.deepEqual(envFindings(env, trust), []);
for (const bad of [{ CLIENT_CERT: "/c" }, { npm_config_cert: "x" }, { NPM_CONFIG_KEY: "x" }, { PIP_CLIENT_CERT: "x" }, { https_proxy: "http://p" }, { NO_PROXY: "*" }, { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
  { UV_INSECURE_HOST: "x" }, { UV_NATIVE_TLS: "1" }, { REQUESTS_CA_BUNDLE: "/other" }, { SSL_CERT_FILE: "/other.pem" }, { TWINE_CERT: "/o" }, { SOME_PRIVATE_KEY: "x" }]) {
  assert.equal(envFindings({ ...env, ...bad }, trust).length, 1, `${Object.keys(bad)[0]} is a finding`);
}

// C7: the firewall's served-row delta for a client equals the fake's own 200 GET delta for that file's URL, and is at least 1.
assert.deepEqual(servedMatchesFakeFindings({ servedBefore: 3, servedAfter: 4, fakeBefore: 1, fakeAfter: 2 }), []);
assert.equal(servedMatchesFakeFindings({ servedBefore: 3, servedAfter: 3, fakeBefore: 1, fakeAfter: 1 }).length, 2, "no served row and no GET at all");
assert.equal(servedMatchesFakeFindings({ servedBefore: 0, servedAfter: 1, fakeBefore: 0, fakeAfter: 2 }).length, 1, "the fake saw more GETs than the firewall served");
assert.equal(servedMatchesFakeFindings({ servedBefore: 0, servedAfter: 2, fakeBefore: 0, fakeAfter: 1 }).length, 1, "an equal-size index page (or a retry) made a second served row");
assert.deepEqual(servedMatchesFakeFindings({ servedBefore: 4, servedAfter: 5, fakeBefore: 2, fakeAfter: 2, cached: true }), [], "served from the firewall's cache");
assert.equal(servedMatchesFakeFindings({ servedBefore: 4, servedAfter: 5, fakeBefore: 2, fakeAfter: 3, cached: true }).length, 1, "a cached file that went back to the fake");
assert.equal(servedMatchesFakeFindings({ servedBefore: 1, servedAfter: 1, fakeBefore: 0, fakeAfter: 1 }).length, 2, "a direct download from the fake: no served row, and the counts differ");
assert.deepEqual(servedMatchesFakeFindings({ servedBefore: 4, servedAfter: 4, fakeBefore: 2, fakeAfter: 3, metadataOnly: true }), [], "a ranged metadata read: one firewall fetch");
assert.equal(servedMatchesFakeFindings({ servedBefore: 4, servedAfter: 4, fakeBefore: 2, fakeAfter: 2, metadataOnly: true }).length, 1, "the file never reached the fake");
assert.equal(servedMatchesFakeFindings({ servedBefore: 4, servedAfter: 4, fakeBefore: 2, fakeAfter: 4, metadataOnly: true }).length, 1, "fetched twice");

// Requirement 7: the real server saw, from outside its own job, a labelled probe and the native probation's own
// snapshot request (no label, same tunnel client address) with the throwaway key, for every native job.
const SNAP = "/api/v1/policy/snapshot";
const entry = (label, cfIp, extra = {}) => ({ label, cfIp, keyOk: true, status: 200, path: SNAP, ...extra });
const labels = ["linux-x64", "darwin-arm64", "win32-x64"];
const goodEntries = [entry("linux-server", "198.51.100.1"),
  entry("linux-x64", "203.0.113.1"), entry(null, "203.0.113.1"), entry("darwin-arm64", "203.0.113.2"), entry(null, "203.0.113.2"), entry(null, "203.0.113.2"),
  entry("win32-x64", "203.0.113.3"), entry(null, "203.0.113.3")];
assert.deepEqual(remoteSnapshotFindings({ entries: goodEntries, labels }), []);
const without = (predicate) => goodEntries.filter((e) => !predicate(e));
assert.ok(remoteSnapshotFindings({ entries: without((e) => e.label === "darwin-arm64"), labels }).some((f) => f.includes("darwin-arm64")), "a job that never probed");
assert.ok(remoteSnapshotFindings({ entries: without((e) => e.label === null && e.cfIp === "203.0.113.3"), labels }).some((f) => f.includes("win32-x64") && /native probation/.test(f)), "a probe without the probation's own request from that address");
assert.ok(remoteSnapshotFindings({ entries: [...without((e) => e.label === "linux-x64"), entry("linux-x64", "198.51.100.1")], labels }).some((f) => /own address/.test(f)), "a probe that came from the server job itself");
assert.ok(remoteSnapshotFindings({ entries: without((e) => e.label === "linux-server"), labels }).some((f) => /own tunnel probe/.test(f)), "no own probe to compare addresses against");
assert.ok(remoteSnapshotFindings({ entries: goodEntries.map((e) => (e.label === "win32-x64" ? { ...e, keyOk: false } : e)), labels }).some((f) => f.includes("win32-x64")), "a probe with the wrong key does not count");
assert.ok(remoteSnapshotFindings({ entries: goodEntries.map((e) => (e.label === null && e.cfIp === "203.0.113.1" ? { ...e, status: 502 } : e)), labels }).some((f) => f.includes("linux-x64")), "an unanswered probation request does not count");
assert.ok(remoteSnapshotFindings({ entries: goodEntries.map((e) => (e.cfIp === "203.0.113.2" ? { ...e, cfIp: null } : e)), labels }).some((f) => f.includes("darwin-arm64")), "no tunnel client address, no proof of origin");

// Survivor controls (adversarial review F6/F8).
assert.equal(lockfileFindings(lock(`https://evil/?x=${base}p-1.tgz`), base).length, 1, "the base inside a query string is not under the base");
assert.equal(lockfileFindings(lock(`https://evil/${base}`), base).length, 1, "nor is the base later in the URL");
assert.equal(keyFindings({ key, policyRows: [{ authorization: `Bearer ${key}`, path: "/api/v1/other" }], registryRows: [], logs: {}, requirePolicyRows: true }).length, 1, "the key sent to another path");
assert.equal(deniedStepFindings({ rows: upstream(["PUT", "developer-denied", 403]), since: 0, method: "PUT", output: "npm error 403", exit: 1 }).length, 1, "a bare 403 (a port number) is not E403");
assert.equal(deniedStepFindings({ rows: upstream(["PUT", "developer-denied", 403]), since: 0, method: "PUT", output: "forbidden", exit: 1 }).length, 1, "no E403 text");
assert.equal(envFindings({ ...env, NODE_OPTIONS: "--require /x" }, trust).length, 1, "NODE_OPTIONS");
for (const name of ["npm_config_ca", "NPM_CONFIG_CAFILE", "UV_NO_VERIFY_SSL", "UV_SYSTEM_CERTS", "GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO", "SSL_CERT_DIR", "SSLKEYLOGFILE"]) {
  assert.equal(envFindings({ ...env, [name]: "1" }, trust).length, 1, `${name} is a finding`);
}
assert.deepEqual(envFindings({ ...env, npm_config_cache: "/c", npm_config_userconfig: "/u" }, trust), [], "npm cache and userconfig are not TLS settings");
for (const text of ["cafile=/x.pem", "ca[]=-----BEGIN", "sslcert = /x", "tls-verify = false", "verify = false", "insecure-host = x"]) {
  assert.equal(scanFindings({ found: [{ path: "/h/.npmrc", text }], expected: [] }).length, 1, `${text} is a finding`);
}
// F-risky: every RISKY_ENV name on its own is a finding, and a trusted exact value is not.
for (const name of ["NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "PIP_TRUSTED_HOST", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CERT", "TWINE_REPOSITORY", "TWINE_USERNAME", "TWINE_PASSWORD", "TWINE_CERT", "CLIENT_CERT", "CLIENT_KEY", "SSL_CERT_FILE", "SSL_CERT_DIR", "CLIENTCERT", "CLIENTKEY", "MY_CERT", "MY_KEY_FILE", "HTTPS_PROXY", "UV_INDEX", "UV_DEFAULT_INDEX", "UV_INSECURE", "UV_ALLOW_INSECURE", "UV_NATIVE_TLS", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS"]) {
  assert.deepEqual(envFindings({ [name]: "x" }, {}), [`${name} is set in the client environment`], `${name} on its own`);
  assert.deepEqual(envFindings({ [name]: "x" }, { [name]: "x" }), [], `${name} with its trusted value`);
}
// every scanFindings alternative on its own
for (const text of ["client_cert=/c", "certfile=/c", "keyfile=/k", "-----BEGIN PRIVATE KEY-----", "cert = /c", "key = /k", "_key = /k", "strict-ssl = false", "ca = /x", "cafile = /x", "ca[] = /x", "sslcert=/c", "sslkey=/k", "tls-verify=false", "tls-verify = true", "verify = false", "trusted-host = h", "insecure-host = h", "native-tls = true", "proxy = http://p"]) {
  assert.equal(scanFindings({ found: [{ path: "/h/x.conf", text: `a=b\n${text}\n` }], expected: [] }).length, 1, `${text} alone is a finding`);
}
// Only "request decided" rows count.
const other = JSON.stringify({ fields: { message: '"something else"', method: '"GET"', ecosystem: '"pypi"', status: 200, bytes: 990 } });
assert.equal(decidedRows(text(other, row("GET", 200, 990))).length, 1, "a row with another message is ignored");
assert.equal(artifactRowFindings({ logText: text(other, row("GET", 200, 990)), size: 990, before: 0 }).length, 0);
// The entry's path matters to the remote probe.
{
  const e = (label, cfIp, path = "/api/v1/policy/snapshot") => ({ label, cfIp, path, keyOk: true, status: 200 });
  const all = [e("linux-server", "1.1.1.1"), e("x", "2.2.2.2"), e(null, "2.2.2.2")];
  assert.deepEqual(remoteSnapshotFindings({ entries: all, labels: ["x"] }), []);
  assert.ok(remoteSnapshotFindings({ entries: all.map((x) => (x.label === "x" ? { ...x, path: "/other" } : x)), labels: ["x"] }).length >= 1, "a probe of another path does not count");
  assert.ok(remoteSnapshotFindings({ entries: all.map((x) => (x.label === null ? { ...x, path: "/other" } : x)), labels: ["x"] }).length >= 1, "an own request of another path does not count");
}
// F8: the check count has a pinned floor.
assert.deepEqual(checkCountFindings(75, 75), []);
assert.equal(checkCountFindings(74, 75).length, 1, "below the floor");
assert.equal(checkCountFindings(0, 75).length, 1);
assert.equal(checkCountFindings(100, undefined).length, 1, "no floor pinned");
assert.equal(JSON.parse(readFileSync(new URL("./pins.json", import.meta.url), "utf8")).minChecks, 75);
assert.match(readFileSync(new URL("./publishing.mjs", import.meta.url), "utf8"), /checkCountFindings\(checks, loadPins\(\)\.minChecks\)/, "publishing.mjs applies the floor");
console.log("assertions.test: ok");
