// A developer token may reveal only a canonical packument at the selected URL.
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";
import { ops, editConfig } from "../harness/ops.mjs";

const PROBE = `
import https from "node:https";
import { readFileSync } from "node:fs";
const home = process.env.HOME;
const options = { method: process.argv[3] || "GET",
  ca: readFileSync("/e2e/ca/ca.pem"),
  headers: { ...(process.argv[4] === "none" ? {} : { authorization: "Bearer " + process.argv[4] }),
    ...(process.env.HEADER_BYTES ? { "x-oversized": "x".repeat(Number(process.env.HEADER_BYTES)) } : {}) },
};
if (!process.env.NO_CERT) {
  options.cert = readFileSync(home + "/.config/probation/client-cert.pem");
  options.key = readFileSync(home + "/.config/probation/client-key.pem");
}
const req = https.request(process.argv[2], options, (res) => { const chunks = []; res.on("data", x => chunks.push(x));
  res.on("end", () => console.log(JSON.stringify({status: res.statusCode, body: Buffer.concat(chunks).toString()}))); });
req.on("error", e => { console.error(e); process.exitCode = 2; });
req.end(process.env.BODY_BYTES ? Buffer.alloc(Number(process.env.BODY_BYTES), 120) : undefined);
`;

export const meta = { id: "E2E-publishing-npm-read", title: "guarded npm reads and token packument", suites: ["release"] };

export default async function npmRead(h, { selfServiceDisabled = process.env.E2E_NPM_READ_DISABLED === "1" } = {}) {
  const npmVersion = h.stack.exec("client-npm", ["npm", "--version"]);
  h.expect(npmVersion.status === 0 && npmVersion.stdout.trim() === "11.21.1",
    `selected npm client is pinned to 11.21.1: ${npmVersion.stdout} ${npmVersion.stderr}`);
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200, `certificate bundle: ${bundle.status}`);
  const installed = h.stack.exec("client-npm", ["sh"], { input: bundle.body });
  h.expect(installed.status === 0, `client certificate install: ${installed.stderr}`);
  h.log(`npm-read ${selfServiceDisabled ? "disabled" : "enabled"}: setup installed`);
  const id = bundle.body.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  h.expect(id, "bundle selects a registry");
  const name = h.unique("token-private");
  await h.fakes.publishNpm({ name, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name, what: "package" });
  const probe = (path, token = "none", method = "GET") => {
    const result = h.client("client-npm", `node probe.mjs 'https://fw1.e2e.test/registry/npm/${id}/${path}' ${method} ${token}`, { files: { "probe.mjs": PROBE } });
    h.expect(result.status === 0, `probe ${path}: ${result.stderr}`);
    return JSON.parse(result.stdout.trim());
  };
  h.expect(probe(name).status === 403, "tokenless hidden packument is filtered");
  const authorized = probe(name, "e2e-owner");
  h.expect(authorized.status === 200 && JSON.parse(authorized.body).versions["1.0.0"],
    `accepted token sees hidden packument without a write: ${authorized.status} ${authorized.body}`);
  h.expect(probe(name, "e2e-denied").status === 403, "upstream-denied token remains denied");
  h.expect(probe(name).status === 403, "tokenless read cannot reuse token metadata");
  h.expect(authorized.body.includes("private upstream metadata"), "owner-only upstream metadata survives the token read");
  h.expect(probe(`${name}?write=true`, "e2e-owner").status === 200,
    "deprecate preflight uses the canonical token-bearing packument guard");
  const beforeAlternate = (await h.fakes.requests("registry.npmjs.org")).length;
  h.expect(probe(`${name}?view=alternate`, "e2e-owner").status === 404,
    "noncanonical query cannot use the token exception");
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeAlternate,
    "noncanonical token route refuses before upstream");
  const ownerFetch = (await h.fakes.requests("registry.npmjs.org")).filter(r => r.path === `/${name}`);
  h.expect(ownerFetch.some(r => r.credential === "developer-owner") && ownerFetch.some(r => r.credential === "developer-denied")
    && ownerFetch.some(r => r.credential === "none") && !ownerFetch.some(r => r.credential === "other"),
    "only the supplied developer credential is sent on canonical packument reads");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${name}`, method: "GET",
    mode: "redirect", location: `/${name}`, times: 1 }]);
  const beforeTokenRedirect = (await h.fakes.requests("registry.npmjs.org")).length;
  const tokenRedirect = probe(name, "e2e-owner");
  const tokenRedirectRequests = (await h.fakes.requests("registry.npmjs.org")).slice(beforeTokenRedirect);
  h.expect(tokenRedirectRequests.length === 1 && tokenRedirectRequests[0].fault === "redirect"
    && tokenRedirectRequests[0].credential === "developer-owner",
    `credential-bearing packument redirect stops after one upstream request: ${JSON.stringify(tokenRedirectRequests)}`);
  h.expect(tokenRedirect.status === 502, `credential-bearing packument redirect refuses: ${tokenRedirect.status}`);
  const hiddenArtifact = new URL(JSON.parse(authorized.body).versions["1.0.0"].dist.tarball);
  h.expect(hiddenArtifact.host === "fw1.e2e.test" && hiddenArtifact.pathname.startsWith(`/registry/npm/${id}/`),
    "token packument artifact link stays on the selected firewall URL");
  h.expect(probe(hiddenArtifact.pathname.split(`/registry/npm/${id}/`)[1], "e2e-owner").status !== 200,
    "developer token cannot grant hidden artifact bytes");

  const second = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(second.status === 200, "second client gets a separate certificate");
  const secondHome = "/work/npm-read-second";
  const secondInstall = h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${secondHome}; HOME=${secondHome} sh`], { input: second.body });
  h.expect(secondInstall.status === 0, `second client setup: ${secondInstall.stderr}`);
  const probationHome = "/work/npm-read-probation";
  h.expect(h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${probationHome}; HOME=${probationHome} sh`],
    { input: second.body }).status === 0, "second Probation certificate remains available for disable control");
  if (selfServiceDisabled) {
    const issued = h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`);
    h.stack.sql(`UPDATE registry_certificate_providers SET self_service = false WHERE org_id = ${Number(org)}`);
    h.expect((await admin.portal.get("/certificates/setup")).status === 403,
      "disabled npm read self-service hides a new setup bundle");
    h.expect((await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404
      && h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(org)}`) === issued,
      "disabled npm read self-service issues no new certificate");
  }
  const otherProbe = (token) => {
    const run = h.client("client-npm", `HOME=${secondHome} node probe.mjs 'https://fw1.e2e.test/registry/npm/${id}/${name}' GET ${token}`,
      { files: { "probe.mjs": PROBE } });
    h.expect(run.status === 0, `second client probe: ${run.stderr}`);
    return JSON.parse(run.stdout.trim());
  };
  h.expect(otherProbe("none").status === 403 && otherProbe("e2e-denied").status === 403,
    "second certificate cannot reuse the first token's private metadata");
  const concurrent = await Promise.all([
    ops(h).background("client-npm", `node probe.mjs 'https://fw1.e2e.test/registry/npm/${id}/${name}' GET e2e-owner`, { files: { "probe.mjs": PROBE } }),
    ops(h).background("client-npm", `HOME=${secondHome} node probe.mjs 'https://fw1.e2e.test/registry/npm/${id}/${name}' GET none`, { files: { "probe.mjs": PROBE } }),
  ]);
  h.expect(concurrent.every(r => r.status === 0), `concurrent probes complete: ${JSON.stringify(concurrent)}`);
  h.expect(JSON.parse(concurrent[0].stdout.trim()).status === 200 && JSON.parse(concurrent[1].stdout.trim()).status === 403,
    "concurrent clients do not coalesce token-private metadata");
  h.restart("firewall-1");
  await h.firewallReady("fw1");
  h.log("npm-read: first firewall recreation ready");
  h.expect(probe(name, "e2e-owner").status === 200 && otherProbe("none").status === 403,
    "restart does not persist token-private metadata for another client");

  const allowed = h.unique("npm-read-allowed");
  await h.fakes.publishNpm({ name: allowed, version: "1.0.0", ageSeconds: 400 * 86_400 });
  h.expect(probe(allowed).status === 200, "ordinary selected packument remains readable");
  const project = `/work/${h.unique("npm-read-project")}`;
  const install = h.client("client-npm", `npm install ${allowed}@1.0.0 --no-audit --no-fund`, {
    dir: project, files: { "package.json": JSON.stringify({ name: "read-e2e", version: "1.0.0", private: true }) },
  });
  h.expect(install.status === 0, `npm install through selected URL: ${install.stderr}`);
  const lock = h.stack.exec("client-npm", ["cat", `${project}/package-lock.json`]);
  h.expect(lock.status === 0 && lock.stdout.includes(`https://fw1.e2e.test/registry/npm/${id}/`)
    && !lock.stdout.includes("e2e-owner") && !lock.stdout.includes("PRIVATE KEY")
    && !lock.stdout.includes("registry.npmjs.org"), "lockfile contains only selected URL and no secrets");
  const npmToken = h.stack.exec("client-npm", ["sh", "-c", `printf '\n//fw1.e2e.test/registry/npm/${id}/:_authToken=e2e-owner\n' >> /root/.npmrc`]);
  h.expect(npmToken.status === 0, "developer token installed in user-local npm config");
  const view = h.client("client-npm", `npm view ${name} version --json --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(view.status === 0 && view.stdout.includes("1.0.0"), `npm view reads hidden packument without a write: ${view.stderr}`);
  const whoamiCli = h.client("client-npm", `npm whoami --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(whoamiCli.status === 0 && whoamiCli.stdout.includes("e2e-owner"), `npm whoami uses selected URL: ${whoamiCli.stderr}`);
  const pingCli = h.client("client-npm", `npm ping --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(pingCli.status === 0, `npm ping uses selected URL: ${pingCli.stderr}`);
  const search = probe(`-/v1/search?text=${name}`);
  h.expect(search.status === 200 && JSON.parse(search.body).objects.length === 0 && JSON.parse(search.body).total === 0,
    "named search filters group-hidden package even with no token");
  h.expect(JSON.parse(probe(`-/v1/search?text=${name}`, "e2e-owner").body).objects.length === 0,
    "developer token does not widen named search");
  const taintedAllowed = h.unique("search-tainted-allowed");
  await h.fakes.publishNpm({ name: taintedAllowed, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: taintedAllowed, version: "2.0.0", ageSeconds: 400 * 86_400 });
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: taintedAllowed,
    what: "version", version: "2.0.0" });
  const taintedSearch = probe(`-/v1/search?text=${taintedAllowed}`);
  h.expect(taintedSearch.status === 200 && JSON.parse(taintedSearch.body).objects.length === 1
    && JSON.parse(taintedSearch.body).objects[0].package.version === "1.0.0"
    && !taintedSearch.body.includes("private-denied-latest"),
    "search rebuilds an allowed advertised hit without denied-version upstream fields");
  const taintedCli = h.client("client-npm", `npm search ${taintedAllowed} --json --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(taintedCli.status === 0 && taintedCli.stdout.includes(taintedAllowed)
    && !taintedCli.stdout.includes("private-denied-latest"),
    `npm search keeps the permitted hit without private fields: ${taintedCli.stderr}`);
  const deniedLatest = h.unique("search-hidden-latest");
  await h.fakes.publishNpm({ name: deniedLatest, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: deniedLatest, version: "2.0.0", ageSeconds: 400 * 86_400 });
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: deniedLatest,
    what: "version", version: "2.0.0" });
  const deniedSearch = probe(`-/v1/search?text=${deniedLatest}`);
  h.expect(deniedSearch.status === 200 && !deniedSearch.body.includes("private-denied-latest")
    && JSON.parse(deniedSearch.body).objects.length === 0 && JSON.parse(deniedSearch.body).total === 0,
    "search omits upstream fields from a denied advertised latest version");
  const npmSearch = h.client("client-npm", `npm search ${deniedLatest} --json --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(npmSearch.status === 0 && !npmSearch.stdout.includes("private-denied-latest"),
    `npm search remains compatible after denying latest: ${npmSearch.stderr}`);
  h.expect(probe("-/ping").status === 200, "named ping reaches selected registry");
  h.expect(JSON.parse(probe("-/whoami", "e2e-owner").body).username === "e2e-owner",
    "named whoami uses developer identity at selected registry");
  h.expect(probe("-/whoami", "e2e-denied").status === 403,
    "upstream whoami denial remains denial");
  h.expect(probe("-/npm/v1/security/advisories/bulk", "none", "POST").status === 200,
    "named bulk audit POST reaches selected registry");
  h.expect(probe("-/npm/v1/security/audits/quick", "none", "POST").status === 200,
    "named quick audit POST reaches selected registry");
  const auditCli = h.client("client-npm", `npm audit --json --registry=https://fw1.e2e.test/registry/npm/${id}/`, { dir: project });
  h.expect(auditCli.status === 0, `npm audit uses selected URL: ${auditCli.stderr}\n${auditCli.stdout}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(r => r.path === "/-/npm/v1/security/advisories/bulk"
    && r.contentEncoding === "gzip" && r.status === 200),
    "npm audit gzip body reaches selected upstream with its encoding intact");
  const auditSentinel = "private-denied-audit";
  await h.fakes.faults([
    { host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
      mode: "json", times: 1, body: {
        [name]: [{ id: 101, title: auditSentinel, severity: "high", vulnerable_versions: "*" }],
        [allowed]: [{ id: 102, title: auditSentinel, severity: "low", vulnerable_versions: "*",
          url: `https://registry.npmjs.org/${name}` }],
      } },
    { host: "registry.npmjs.org", path: "/-/npm/v1/security/audits/quick", method: "POST",
      mode: "json", times: 1, body: { advisories: {
        101: { id: 101, module_name: name, title: auditSentinel, severity: "high", vulnerable_versions: "*" },
        102: { id: 102, module_name: allowed, title: auditSentinel, severity: "low",
          vulnerable_versions: "*", url: `https://registry.npmjs.org/${name}` },
      }, metadata: { private: auditSentinel } } },
  ]);
  const bulkAudit = probe("-/npm/v1/security/advisories/bulk", "none", "POST");
  const quickAudit = probe("-/npm/v1/security/audits/quick", "none", "POST");
  h.expect(bulkAudit.status === 200 && quickAudit.status === 200,
    `nonempty selected audit responses arrive: ${bulkAudit.status}/${quickAudit.status}`);
  const bulkReport = JSON.parse(bulkAudit.body);
  const quickReport = JSON.parse(quickAudit.body);
  h.expect(!JSON.stringify(bulkReport).includes(name) && !JSON.stringify(quickReport).includes(name)
    && !JSON.stringify(bulkReport).includes(auditSentinel)
    && !JSON.stringify(quickReport).includes(auditSentinel),
  `bulk and quick audit exclude group-hidden metadata: ${JSON.stringify({ bulkReport, quickReport })}`);
  h.expect(Array.isArray(bulkReport[allowed]) && bulkReport[allowed].length > 0
    && Object.values(quickReport.advisories ?? {}).some(advisory => advisory.module_name === allowed),
    "permitted advisory remains visible in both audit response shapes");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/audits/quick", method: "POST",
    mode: "json", times: 1, body: { advisories: {}, vulnerabilities: { [allowed]: { severity: "high" } } } }]);
  h.expect(probe("-/npm/v1/security/audits/quick", "none", "POST").status === 502,
    "mixed quick advisory and nonempty vulnerability reports refuse instead of claiming clean");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/audits/quick", method: "POST",
    mode: "json", times: 1, body: { advisories: {}, vulnerabilities: [] } }]);
  h.expect(probe("-/npm/v1/security/audits/quick", "none", "POST").status === 502,
    "malformed quick vulnerability report refuses even when advisories is present");
  const safeBulk = bulkReport[allowed]?.[0];
  h.expect(Object.keys(bulkReport).length === 1 && bulkReport[allowed]?.length === 1
    && safeBulk.id === 1 && safeBulk.title === "Vulnerability in visible version"
    && safeBulk.severity === "low" && safeBulk.vulnerable_versions === "1.0.0"
    && Object.keys(safeBulk).sort().join() === "id,severity,title,vulnerable_versions"
    && Object.keys(quickReport).join() === "advisories"
    && Object.values(quickReport.advisories).length === 1
    && Object.values(quickReport.advisories)[0].vulnerable_versions === "1.0.0",
    `audit responses contain only canonical visible versions and fixed safe advisory fields: ${bulkAudit.body} ${quickAudit.body}`);
  await h.fakes.publishNpm({ name: allowed, version: "2.0.0", ageSeconds: 400 * 86_400 });
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: allowed,
    what: "version", version: "2.0.0" });
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "json", times: 1, body: { [allowed]: [{ severity: "high", vulnerable_versions: "*",
      title: `private ${name} 2.0.0`, url: `https://registry.npmjs.org/${name}` }] } }]);
  const versionReport = probe("-/npm/v1/security/advisories/bulk", "none", "POST");
  h.expect(versionReport.status === 200 && JSON.parse(versionReport.body)[allowed][0].vulnerable_versions === "1.0.0"
    && !versionReport.body.includes("2.0.0") && !versionReport.body.includes(name),
    "audit excludes blocked versions and arbitrary upstream advisory text");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "json", times: 1, body: { [allowed]: [{ severity: "high", vulnerable_versions: "invalid range !!!" }] } }]);
  h.expect(probe("-/npm/v1/security/advisories/bulk", "none", "POST").status === 502,
    "malformed upstream advisory range refuses instead of claiming a clean audit");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "json", times: 1, body: { "e2e-many": Array.from({ length: 137 }, () =>
      ({ severity: "low", vulnerable_versions: "*" })) } }]);
  h.expect(probe("-/npm/v1/security/advisories/bulk", "none", "POST").status === 502,
    "8,220 advisory-version comparisons refuse within the audit deadline");
  const manyAdvisories = Object.fromEntries(Array.from({ length: 1025 }, (_, n) =>
    [`audit-cap-${n}`, [{ severity: "low", vulnerable_versions: "*" }]]));
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "json", times: 1, body: manyAdvisories }]);
  const beforeCap = (await h.fakes.requests("registry.npmjs.org")).length;
  h.expect(probe("-/npm/v1/security/advisories/bulk", "none", "POST").status === 502,
    "1,025 distinct advisory package lookups refuse");
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeCap + 1,
    "1,025th advisory does not trigger a package lookup");
  h.expect(probe(allowed).status === 200, "audit lookup refusal releases the active request permit");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "json", times: 1, body: { [allowed]: [{ id: 77, title: auditSentinel, severity: "high",
      vulnerable_versions: "1.0.0", url: `https://registry.npmjs.org/${name}` }] } }]);
  const nonemptyCli = h.client("client-npm", `npm audit --json --registry=https://fw1.e2e.test/registry/npm/${id}/`, { dir: project });
  h.expect(nonemptyCli.status !== 0 && nonemptyCli.stdout.includes(allowed)
    && !nonemptyCli.stdout.includes(auditSentinel) && !nonemptyCli.stdout.includes(name),
    `npm 11 detects a visible safe advisory without private text: ${nonemptyCli.stderr} ${nonemptyCli.stdout}`);
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "status", status: 404, times: 1 }]);
  const quickBeforeUnsupported = (await h.fakes.requests("registry.npmjs.org"))
    .filter(r => r.path === "/-/npm/v1/security/audits/quick").length;
  const unsupportedBulk = h.client("client-npm", `npm audit --json --registry=https://fw1.e2e.test/registry/npm/${id}/`, { dir: project });
  h.expect(unsupportedBulk.status !== 0 && unsupportedBulk.stderr.includes("404"),
    `npm reports selected upstream's unsupported bulk endpoint: ${unsupportedBulk.stderr}`);
  h.expect((await h.fakes.requests("registry.npmjs.org"))
    .filter(r => r.path === "/-/npm/v1/security/audits/quick").length === quickBeforeUnsupported,
    "npm 11.21.1 does not automatically call quick after bulk 404");
  h.expect(probe("-/npm/v1/security/audits/quick", "none", "POST").status === 200,
    "quick audit route remains available after unsupported bulk");
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(r => r.path === "/-/npm/v1/security/audits/quick" && r.method === "POST"),
    "quick audit POST reaches the selected upstream");
  const before = (await h.fakes.requests("registry.npmjs.org")).length;
  h.expect(probe("-/unknown").status === 404, "unknown route refuses");
  h.expect(probe("-/unknown", "none", "HEAD").status >= 400,
    "unknown HEAD route refuses");
  h.expect(probe(`${name}/-/private.tgz`).status >= 400,
    "alternate artifact path cannot bypass the reference and group guard");
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === before, "unknown route made no upstream call");
  const networks = Object.keys(ops(h).inspect(ops(h).id("client-npm")).NetworkSettings.Networks);
  h.expect(networks.length === 1 && networks[0] === `${h.stack.project}_clients`,
    `npm client is attached only to the client network: ${networks}`);
  const direct = h.stack.exec("client-npm", ["node", "-e",
    "fetch('https://registry.npmjs.org', {signal: AbortSignal.timeout(3000)}).then(() => process.exit(1), () => process.exit(0))"]);
  h.expect(direct.status === 0, "npm client cannot connect directly to upstream registry");

  const boundedName = h.unique("bounded-artifact");
  await h.fakes.publishNpm({ name: boundedName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  const bounded = probe(boundedName);
  h.expect(bounded.status === 200, "bounded artifact reference is advertised before limits change");
  const boundedPath = new URL(JSON.parse(bounded.body).versions["1.0.0"].dist.tarball)
    .pathname.split(`/registry/npm/${id}/`)[1];
  editConfig(h.stack, "firewall-1", text => text
    .replace(/^max_metadata_bytes = .*$/m, "max_metadata_bytes = 4096")
    .replace(/^max_artifact_bytes = .*$/m, "max_artifact_bytes = 8192")
    .replace(/^max_active_requests = .*$/m, "max_active_requests = 1"));
  h.restart("firewall-1");
  await h.firewallReady("fw1");
  h.log("npm-read: bounded response firewall recreation ready");
  const boundedSearch = h.unique("search-bounded");
  for (let n = 0; n < 8; n++) {
    await h.fakes.publishNpm({ name: `${boundedSearch}-${n}`, version: "1.0.0", ageSeconds: 400 * 86_400 });
  }
  h.expect(probe(`-/v1/search?text=${boundedSearch}`).status === 502,
    "search rebuilt from bounded packuments refuses a response larger than M");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${name}`, method: "GET", mode: "oversize", bytes: 4097, times: 1 }]);
  const tooMuchMetadata = probe(name, "e2e-owner");
  h.expect(tooMuchMetadata.status === 502 && !tooMuchMetadata.body.includes("xxxx"),
    `M+1 metadata is refused before a client body: ${tooMuchMetadata.status}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(r => r.path === `/${name}` && r.fault === "oversize" && r.status === 200),
    "M+1 response came from the upstream oversize fault");
  const beforeLargeAuditRequest = (await h.fakes.requests("registry.npmjs.org")).length;
  const largeAuditRequest = h.client("client-npm", `BODY_BYTES=4097 node probe.mjs 'https://fw1.e2e.test/registry/npm/${id}/-/npm/v1/security/advisories/bulk' POST none`,
    { files: { "probe.mjs": PROBE } });
  h.expect(largeAuditRequest.status === 0 && JSON.parse(largeAuditRequest.stdout.trim()).status === 400,
    "M+1 audit input refuses before upstream");
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeLargeAuditRequest,
    "M+1 audit input causes no upstream request");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "oversize", bytes: 4097, times: 1 }]);
  h.expect(probe("-/npm/v1/security/advisories/bulk", "none", "POST").status === 502,
    "M+1 audit output refuses without returning upstream bytes");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${boundedName}/-/`, method: "GET", mode: "oversize", bytes: 8193, times: 1 }]);
  const tooMuchArtifact = probe(boundedPath);
  h.expect(tooMuchArtifact.status !== 200 && tooMuchArtifact.body.length < 8193,
    `A+1 artifact cannot become a complete file: ${tooMuchArtifact.status}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(r => r.path.startsWith(`/${boundedName}/-/`) && r.fault === "oversize" && r.status === 200),
    "A+1 response came from the upstream oversize fault");
  const tarball = `https://registry.npmjs.org/${boundedName}/-/${boundedName}-1.0.0.tgz`;
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${boundedName}/-/`, method: "GET",
    mode: "redirect", location: tarball, times: 7 }]);
  const redirect = probe(boundedPath);
  h.expect(redirect.status === 502, `sixth artifact redirect hop refuses: ${redirect.status}`);
  const redirected = (await h.fakes.requests("registry.npmjs.org")).filter(r => r.path.startsWith(`/${boundedName}/-/`));
  h.expect(redirected.filter(r => r.fault === "redirect").length === 6,
    `exactly six redirect responses were received before refusal: ${JSON.stringify(redirected)}`);
  h.expect(redirected.every(r => r.credential === "none"), "artifact redirects carry no developer token");
  const beforeLargeHeader = (await h.fakes.requests("registry.npmjs.org")).length;
  const largeHeader = h.client("client-npm", `HEADER_BYTES=65537 node probe.mjs 'https://fw1.e2e.test/registry/npm/${id}/${boundedName}' GET none`,
    { files: { "probe.mjs": PROBE } });
  h.expect(largeHeader.status === 0 && JSON.parse(largeHeader.stdout.trim()).status === 431,
    `64KiB+1 header is refused with 431: ${largeHeader.status} ${largeHeader.stdout} ${largeHeader.stderr}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeLargeHeader,
    "oversized headers refuse before upstream lookup");
  editConfig(h.stack, "firewall-1", text => text.replace(/^max_active_requests = .*$/m, "max_active_requests = 64"));
  h.restart("firewall-1");
  await h.firewallReady("fw1");
  h.log("npm-read: normal request limit firewall recreation ready");

  const registryProbe = (registry, path, token = "none", home = "/root") => {
    const run = h.client("client-npm", `HOME=${home} node probe.mjs 'https://fw1.e2e.test/registry/npm/${registry}/${path}' GET ${token}`,
      { files: { "probe.mjs": PROBE } });
    h.expect(run.status === 0, `selected registry ${registry} probe: ${run.stderr}`);
    return JSON.parse(run.stdout.trim());
  };
  const auditPost = (registry, path, home = "/root", noCert = false) => {
    const run = h.client("client-npm", `${noCert ? "NO_CERT=1 " : ""}HOME=${home} node probe.mjs 'https://fw1.e2e.test/registry/npm/${registry}/${path}' POST none`,
      { files: { "probe.mjs": PROBE } });
    h.expect(run.status === 0, `audit POST ${path}: ${run.stderr}`);
    return JSON.parse(run.stdout.trim());
  };
  const auditPaths = ["-/npm/v1/security/advisories/bulk", "-/npm/v1/security/audits/quick"];
  const noCert = h.client("client-npm", `NO_CERT=1 node probe.mjs 'https://fw1.e2e.test/registry/npm/${id}/${allowed}' GET e2e-owner`,
    { files: { "probe.mjs": PROBE } });
  h.expect(noCert.status === 0 && JSON.parse(noCert.stdout.trim()).status === 401,
    "developer token without a certificate refuses before upstream");
  const foreign = await h.signUp({ kind: "org" });
  const foreignPage = await foreign.portal.get("/certificates/setup");
  const foreignBundle = await foreign.portal.post("/certificates/setup", { csrf: hidden(foreignPage.body, "csrf") });
  h.expect(foreignBundle.status === 200, "foreign organization can issue its own certificate");
  const foreignHome = "/work/npm-read-foreign";
  h.expect(h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${foreignHome}; HOME=${foreignHome} sh`],
    { input: foreignBundle.body }).status === 0, "foreign certificate installs");
  const foreignId = foreignBundle.body.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  h.expect(foreignId, "foreign organization has its own selected registry ID");
  const beforeForeign = (await h.fakes.requests("registry.npmjs.org")).length;
  for (const path of auditPaths) {
    h.expect(auditPost(id, path, "/root", true).status === 401,
      `missing certificate refuses selected ${path} before upstream`);
    h.expect(auditPost(id, path, foreignHome).status === 401,
      `foreign organization certificate refuses selected ${path} before upstream`);
  }
  h.expect(registryProbe(id, allowed, "e2e-owner", foreignHome).status === 401,
    "foreign organization's certificate cannot select this registry even with a token");
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeForeign,
    "foreign certificate made no upstream read");
  const foreignBounded = registryProbe(foreignId, boundedName, "none", foreignHome);
  h.expect(foreignBounded.status === 200, "foreign organization can use its own selected registry");
  const foreignBoundedPath = new URL(JSON.parse(foreignBounded.body).versions["1.0.0"].dist.tarball)
    .pathname.split(`/registry/npm/${foreignId}/`)[1];
  const searchSlow = h.unique("search-slow");
  const searchSlowNames = [`${searchSlow}-a`, `${searchSlow}-b`];
  for (const searchName of searchSlowNames) {
    await h.fakes.publishNpm({ name: searchName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  }

  const catalog = await admin.portal.get(`/org/${org}/registries`);
  const addB = (label) => admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: label, ecosystem: "npm", target_url: "https://registry-b.e2e.test/",
  });
  h.expect((await addB("Read B")).status === 303, "second selected registry is added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const bId = listed.body.match(/<li>(\d+) Read B npm/)?.[1];
  h.expect(bId, "second selected registry has an ID");
  const collision = h.unique("read-collision");
  await h.fakes.publishNpm({ name: collision, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpmB({ name: collision, version: "2.0.0", ageSeconds: 400 * 86_400 });
  h.expect(JSON.parse(registryProbe(id, collision).body).versions["1.0.0"]
    && !JSON.parse(registryProbe(id, collision).body).versions["2.0.0"], "registry A sees only A metadata");
  h.expect(JSON.parse(registryProbe(bId, collision).body).versions["2.0.0"]
    && !JSON.parse(registryProbe(bId, collision).body).versions["1.0.0"], "registry B sees only B metadata");
  const aLink = JSON.parse(registryProbe(id, collision).body).versions["1.0.0"].dist.tarball;
  const bLink = JSON.parse(registryProbe(bId, collision).body).versions["2.0.0"].dist.tarball;
  const artifactProbe = `import https from "node:https";import {createHash} from "node:crypto";import {readFileSync} from "node:fs";
const home=process.env.HOME;const req=https.get(process.argv[2],{ca:readFileSync("/e2e/ca/ca.pem"),
cert:readFileSync(home+"/.config/probation/client-cert.pem"),key:readFileSync(home+"/.config/probation/client-key.pem")},
res=>{let parts=[];res.on("data",part=>parts.push(part));res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,
hash:createHash("sha256").update(Buffer.concat(parts)).digest("hex")})));});
req.on("error",e=>{console.error(e);process.exitCode=2});`;
  const selectedArtifact = (url) => {
    const run = h.client("client-npm", `node read-artifact-probe.mjs '${url}'`,
      { files: { "read-artifact-probe.mjs": artifactProbe } });
    h.expect(run.status === 0, `selected artifact probe completes: ${run.stderr}`);
    return JSON.parse(run.stdout.trim());
  };
  const aBytes = selectedArtifact(aLink);
  const bBytes = selectedArtifact(bLink);
  h.expect(aBytes.status === 200 && bBytes.status === 200 && aBytes.hash !== bBytes.hash
    && aLink.includes(`/registry/npm/${id}/`) && bLink.includes(`/registry/npm/${bId}/`),
    "npm read same-name registries return distinct selected artifact bytes");
  await h.fakes.publishNpmB({ name, version: "1.0.0", ageSeconds: 400 * 86_400 });
  h.expect(registryProbe(bId, name, "e2e-owner").status === 200
    && registryProbe(bId, name).status === 403
    && registryProbe(bId, name, "e2e-denied").status === 403,
    "selected B enforces its own developer-token packument and group policy");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).some(r => r.path === `/${name}` && r.credential === "developer-owner")
    && !(await h.fakes.requests("registry.npmjs.org")).some(r => r.path === `/${name}` && r.credential === "other"),
    "developer credential is sent only to the selected B origin");
  const immutable = await admin.portal.post(`/org/${org}/registries/${bId}/trust`, {
    csrf: hidden(listed.body, "csrf"), ecosystem: "pypi", target_url: "https://registry.npmjs.org/",
  });
  h.expect(immutable.status === 303 && h.stack.sql(`SELECT target_url FROM registries WHERE id = ${Number(bId)}`)
    === "https://registry-b.e2e.test/", "registry target cannot be changed in place");
  const removed = await admin.portal.post(`/org/${org}/registries/${bId}/remove`, { csrf: hidden(listed.body, "csrf") });
  h.expect(removed.status === 303 && registryProbe(bId, collision).status === 401,
    "removed registry ID refuses without falling back to A");
  h.expect((await addB("Read B replacement")).status === 303, "registry B can be re-added with a new ID");
  const after = await admin.portal.get(`/org/${org}/registries`);
  const replacementId = after.body.match(/<li>(\d+) Read B replacement npm/)?.[1];
  h.expect(replacementId && replacementId !== bId && registryProbe(replacementId, collision).status === 200,
    "replacement registry gets a fresh ID and selected bytes");
  const beforeOutage = (await h.fakes.requests("registry-b.e2e.test")).length;
  h.stop("server");
  h.log("npm-read: management server stopped for refusal probe");
  try {
    h.expect(registryProbe(replacementId, collision).status !== 200, "management outage refuses selected read");
    h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeOutage,
      "management outage makes no upstream read");
  } finally {
    h.start("server");
  }
  await h.waitFor("management recovery", () => registryProbe(replacementId, collision).status === 200);
  h.log("npm-read: management server recovered");

  const firstCertificate = h.stack.sql(`SELECT id FROM registry_member_certificates WHERE org_id = ${Number(org)} ORDER BY id LIMIT 1`);
  const revokePage = selfServiceDisabled ? setup : await admin.portal.get("/certificates/setup");
  const revoke = await admin.portal.post(`/certificates/${firstCertificate}/revoke`, { csrf: hidden(revokePage.body, "csrf") });
  h.expect(revoke.status === 303 && registryProbe(replacementId, collision).status === 401,
    "revoking the first Probation certificate refuses the next read");
  h.expect(registryProbe(replacementId, collision, "none", secondHome).status === 200,
    "targeted revocation leaves the second certificate usable");

  const memberUuid = h.stack.sql(`SELECT certificate_uuid::text FROM memberships WHERE org_id = ${Number(org)} LIMIT 1`);
  const sample = await h.fakes.issueEnterprise("a", memberUuid);
  const live = await h.fakes.issueEnterprise("a", memberUuid);
  const otherLive = await h.fakes.issueEnterprise("a", memberUuid);
  const settings = await admin.portal.get(`/org/${org}/certificates`);
  const trust = await admin.portal.post(`/org/${org}/certificates`, {
    csrf: hidden(settings.body, "csrf"), identity_field: "uri_san_membership_uuid",
    expected_ocsp_url: sample.ocspUrl, root_pem: sample.rootPem,
  });
  h.expect(trust.status === 303, "enterprise root and issuer AIA expectation saved");
  const activation = await admin.portal.get(`/org/${org}/certificates`);
  const testSample = (phase) => admin.portal.post(`/org/${org}/certificates/test`, {
    csrf: hidden(activation.body, "csrf"), chain_pem: sample.leafPem, phase,
  });
  h.expect((await testSample("good")).status === 200, "enterprise sample has live good status");
  await h.fakes.revokeEnterprise("a", sample.id);
  h.expect((await testSample("revoked")).status === 303, "committed issuer revocation activates enterprise provider");
  const installLeaf = (leaf, home) => h.client("client-npm",
    `HOME=${home} cp leaf.pem ${home}/.config/probation/client-cert.pem && HOME=${home} cp key.pem ${home}/.config/probation/client-key.pem`,
    { files: { "leaf.pem": leaf.leafPem, "key.pem": leaf.keyPem } });
  h.expect(installLeaf(live, "/root").status === 0 && installLeaf(otherLive, secondHome).status === 0,
    "two enterprise issuer clients install separate leaves");
  h.expect(h.stack.exec("client-npm", ["sh", "-c",
    `printf '\n//fw1.e2e.test/registry/npm/${replacementId}/:certfile=/root/.config/probation/client-cert.pem\n//fw1.e2e.test/registry/npm/${replacementId}/:keyfile=/root/.config/probation/client-key.pem\n' >> /root/.npmrc`]).status === 0,
    "npm binds the enterprise certificate files to the replacement selected URL");
  h.expect(registryProbe(replacementId, name, "e2e-owner").status === 200
    && registryProbe(replacementId, name).status === 403
    && registryProbe(replacementId, name, "e2e-denied").status === 403,
    "enterprise provider enforces the same token exception and group policy");
  const enterpriseProject = `/work/${h.unique("enterprise-read-project")}`;
  const enterpriseInstall = h.client("client-npm", `npm install ${collision}@2.0.0 --registry=https://fw1.e2e.test/registry/npm/${replacementId}/ --no-audit --no-fund`, {
    dir: enterpriseProject, files: { "package.json": JSON.stringify({ name: "enterprise-read", version: "1.0.0", private: true }) },
  });
  h.expect(enterpriseInstall.status === 0, `enterprise npm install selected B: ${enterpriseInstall.stderr}`);
  const enterpriseLock = h.stack.exec("client-npm", ["cat", `${enterpriseProject}/package-lock.json`]);
  h.expect(enterpriseLock.status === 0 && enterpriseLock.stdout.includes(`https://fw1.e2e.test/registry/npm/${replacementId}/`)
    && !enterpriseLock.stdout.includes("registry-b.e2e.test") && !enterpriseLock.stdout.includes("e2e-owner"),
    "enterprise lockfile carries only selected URL and no token");
  h.expect(h.stack.exec("client-npm", ["sh", "-c",
    `printf '\n//fw1.e2e.test/registry/npm/${replacementId}/:_authToken=e2e-owner\n' >> /root/.npmrc`]).status === 0,
    "enterprise client gets user-local developer token");
  const enterpriseView = h.client("client-npm", `npm view ${name} version --json --registry=https://fw1.e2e.test/registry/npm/${replacementId}/`);
  h.expect(enterpriseView.status === 0 && enterpriseView.stdout.includes("1.0.0"),
    `enterprise npm view sees hidden metadata without write: ${enterpriseView.stderr}`);
  const enterpriseSearch = h.client("client-npm", `npm search ${collision} --json --registry=https://fw1.e2e.test/registry/npm/${replacementId}/`);
  h.expect(enterpriseSearch.status === 0 && enterpriseSearch.stdout.includes(collision),
    `enterprise npm search uses selected B: ${enterpriseSearch.stderr}`);
  const enterpriseAudit = h.client("client-npm", `npm audit --json --registry=https://fw1.e2e.test/registry/npm/${replacementId}/`,
    { dir: enterpriseProject });
  h.expect(enterpriseAudit.status === 0, `enterprise npm audit uses selected B: ${enterpriseAudit.stderr}`);
  h.expect(h.client("client-npm", `npm whoami --registry=https://fw1.e2e.test/registry/npm/${replacementId}/`).status === 0
    && h.client("client-npm", `npm ping --registry=https://fw1.e2e.test/registry/npm/${replacementId}/`).status === 0,
    "enterprise npm whoami and ping use selected B");
  h.expect(registryProbe(replacementId, "-/ping").status === 200
    && registryProbe(replacementId, "-/whoami", "e2e-owner").status === 200
    && registryProbe(replacementId, "-/v1/search?text=" + name).status === 200,
    "enterprise provider admits named reads at its selected URL");
  h.expect(registryProbe(replacementId, name, "none", secondHome).status === 403,
    "second enterprise certificate cannot see token-private metadata");
  const enterpriseConcurrent = await Promise.all([
    ops(h).background("client-npm", `node probe.mjs 'https://fw1.e2e.test/registry/npm/${replacementId}/${name}' GET e2e-owner`,
      { files: { "probe.mjs": PROBE } }),
    ops(h).background("client-npm", `HOME=${secondHome} node probe.mjs 'https://fw1.e2e.test/registry/npm/${replacementId}/${name}' GET none`,
      { files: { "probe.mjs": PROBE } }),
  ]);
  h.expect(enterpriseConcurrent.every(r => r.status === 0)
    && JSON.parse(enterpriseConcurrent[0].stdout.trim()).status === 200
    && JSON.parse(enterpriseConcurrent[1].stdout.trim()).status === 403,
    "concurrent enterprise clients never share token-private metadata");
  h.restart("firewall-1");
  await h.firewallReady("fw1");
  h.log("npm-read: enterprise cache firewall recreation ready");
  h.expect(registryProbe(replacementId, name, "e2e-owner").status === 200
    && registryProbe(replacementId, name, "none", secondHome).status === 403,
    "enterprise restart does not persist token-private metadata");
  const enterpriseBeforeUnknown = (await h.fakes.requests("registry-b.e2e.test")).length;
  h.expect(registryProbe(replacementId, "-/unknown").status === 404
    && (await h.fakes.requests("registry-b.e2e.test")).length === enterpriseBeforeUnknown,
    "enterprise unknown route refuses before selected upstream");
  const beforeIssuerRevoke = (await h.fakes.requests("registry-b.e2e.test")).length;
  await h.fakes.revokeEnterprise("a", live.id);
  for (const path of auditPaths) {
    h.expect(auditPost(replacementId, path).status === 401,
      `revoked enterprise certificate refuses selected ${path} before upstream`);
  }
  h.expect(registryProbe(replacementId, collision, "e2e-owner").status === 401,
    "committed enterprise issuer revocation refuses the next read");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeIssuerRevoke,
    "revoked enterprise leaf makes no upstream call");
  h.expect(registryProbe(replacementId, collision, "none", secondHome).status === 200,
    "other enterprise leaf remains usable after targeted revocation");
  const membership = h.stack.sql(`SELECT id FROM memberships WHERE org_id = ${Number(org)} AND certificate_uuid::text = '${memberUuid}'`);
  const disable = await admin.portal.submit(`/org/${org}`, `/org/members/${membership}/package-disable`, {});
  h.expect(disable.status === 303, "administrator disables this member's package access");
  const beforeDisabled = (await h.fakes.requests("registry-b.e2e.test")).length;
  h.expect(registryProbe(replacementId, collision, "none", secondHome).status === 401
    && registryProbe(id, allowed, "none", probationHome).status === 401,
    "disabled member's enterprise and Probation certificates refuse the next read");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeDisabled,
    "disabled member made no selected-B upstream read");
  editConfig(h.stack, "firewall-1", text => text.replace(/^max_active_requests = .*$/m, "max_active_requests = 1"));
  h.restart("firewall-1");
  await h.firewallReady("fw1");
  h.log("npm-read: single-permit firewall recreation ready");
  await h.fakes.faults([
    ...searchSlowNames.map(searchName => ({ host: "registry.npmjs.org", path: `/${searchName}`, method: "GET",
      mode: "delay", ms: 20_000, times: 1 })),
    { host: "registry.npmjs.org", path: `/${boundedName}/-/`, method: "GET",
      mode: "stall", afterBytes: 1, times: 1 },
  ]);
  const searchStarted = Date.now();
  const searching = ops(h).background("client-npm",
    `HOME=${foreignHome} node probe.mjs 'https://fw1.e2e.test/registry/npm/${foreignId}/-/v1/search?text=${searchSlow}' GET none`,
    { files: { "probe.mjs": PROBE } });
  await h.waitFor("both cold search packuments to be fetched", async () => {
    const requests = await h.fakes.requests("registry.npmjs.org");
    return searchSlowNames.every(searchName => requests.some(r => r.path === `/${searchName}` && r.fault === "delay"));
  }, { timeout: 25_000, every: 500 });
  const slowSearch = await searching;
  h.expect(slowSearch.status === 0 && JSON.parse(slowSearch.stdout.trim()).status === 504
    && Date.now() - searchStarted < 38_000, "cold search has one 30-second total deadline");
  h.expect(registryProbe(foreignId, "-/ping", "none", foreignHome).status === 200,
    "search deadline releases the sole active request permit");
  const stalled = registryProbe(foreignId, foreignBoundedPath, "none", foreignHome);
  h.expect(stalled.status !== 200 && registryProbe(foreignId, "-/ping", "none", foreignHome).status === 200,
    "30-second idle upstream response releases the sole active request permit");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
    mode: "delay", ms: 31_000, times: 1 }]);
  const auditStarted = Date.now();
  const timedAudit = h.client("client-npm", `HOME=${foreignHome} node probe.mjs 'https://fw1.e2e.test/registry/npm/${foreignId}/-/npm/v1/security/advisories/bulk' POST none`,
    { files: { "probe.mjs": PROBE } });
  h.expect(timedAudit.status === 0 && JSON.parse(timedAudit.stdout.trim()).status === 504
    && Date.now() - auditStarted < 38_000,
    "audit fetch and filter share one 30-second deadline");
  h.expect(registryProbe(foreignId, "-/ping", "none", foreignHome).status === 200,
    "audit timeout releases the sole active request permit");
}
