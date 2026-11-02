// Organization-issued admission for the approved npm read operations.
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";
import { activateIssuerFor, installIssuerLeaf } from "../harness/issuer-setup.mjs";
import { changePlatform } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-publishing-npm-read-issuer",
  title: "organization-issued npm selected-registry reads",
  suites: ["release"],
};

export default async function npmReadIssuer(h) {
  const version = h.stack.exec("client-npm", ["npm", "--version"]);
  h.expect(version.status === 0 && version.stdout.trim() === "11.21.1",
    `issuer npm client is pinned to 11.21.1: ${version.stdout} ${version.stderr}`);
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200, `issuer npm initial selected bundle: ${bundle.status}`);
  const id = bundle.body.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  h.expect(id, "issuer npm bundle selects an exact registry ID");
  const installed = h.stack.exec("client-npm", ["sh"], { input: bundle.body });
  h.expect(installed.status === 0, `issuer npm initial configuration: ${installed.stderr}`);
  const { live } = await activateIssuerFor(h, admin, org);
  installIssuerLeaf(h, "client-npm", live);
  const registry = `https://fw1.e2e.test/registry/npm/${id}/`;

  const allowed = h.unique("issuer-npm-allowed");
  const denied = h.unique("issuer-npm-denied");
  await h.fakes.publishNpm({ name: allowed, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: denied, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: denied, what: "package" });
  const project = `/work/${h.unique("issuer-npm-read")}`;
  const install = h.client("client-npm", `npm install ${allowed}@1.0.0 --no-audit --no-fund`, {
    dir: project, files: { "package.json": JSON.stringify({ name: "issuer-read-e2e", version: "1.0.0", private: true }) },
  });
  h.expect(install.status === 0, `issuer npm install through selected URL: ${install.stderr}`);
  const lock = h.stack.exec("client-npm", ["cat", `${project}/package-lock.json`]);
  h.expect(lock.status === 0 && lock.stdout.includes(registry)
    && !lock.stdout.includes("registry.npmjs.org") && !lock.stdout.includes("PRIVATE KEY")
    && !lock.stdout.includes("e2e-owner"),
  "issuer npm lockfile contains only selected URL and no secrets");
  const deniedInstall = h.client("client-npm", `npm install ${denied}@1.0.0 --no-audit --no-fund`, { dir: project });
  h.expect(deniedInstall.status !== 0,
    `issuer npm blocked package is refused by policy: ${deniedInstall.stdout} ${deniedInstall.stderr}`);
  const upstream = await h.fakes.requests("registry.npmjs.org");
  h.expect(!upstream.some((request) => request.path === `/${denied}/-/${denied}-1.0.0.tgz`),
    "issuer npm blocked package artifact never reaches upstream");

  const token = h.stack.exec("client-npm", ["sh", "-c",
    `printf '\n//fw1.e2e.test/registry/npm/${id}/:_authToken=e2e-owner\n' >> /root/.npmrc`]);
  h.expect(token.status === 0, `issuer npm developer token stays in user-local config: ${token.stderr}`);
  const privateView = h.client("client-npm", `npm view ${denied} version --json --registry=${registry}`);
  h.expect(privateView.status === 0 && privateView.stdout.includes("1.0.0"),
    `issuer npm accepted token sees canonical group-hidden packument: ${privateView.stderr}`);
  const privateInstall = h.client("client-npm", `npm install ${denied}@1.0.0 --no-audit --no-fund --prefer-online`, { dir: project });
  h.expect(privateInstall.status !== 0,
    `issuer npm accepted token cannot install group-hidden artifact: ${privateInstall.stderr}`);
  const whoami = h.client("client-npm", `npm whoami --registry=${registry}`);
  h.expect(whoami.status === 0 && whoami.stdout.includes("e2e-owner"),
    `issuer npm whoami uses selected URL: ${whoami.stderr}`);
  const ping = h.client("client-npm", `npm ping --registry=${registry}`);
  h.expect(ping.status === 0, `issuer npm ping uses selected URL: ${ping.stderr}`);
  const view = h.client("client-npm", `npm view ${allowed} version --json --registry=${registry}`);
  h.expect(view.status === 0 && view.stdout.includes("1.0.0"),
    `issuer npm view uses selected URL: ${view.stderr}`);
  const search = h.client("client-npm", `npm search ${allowed} --json --registry=${registry}`);
  h.expect(search.status === 0 && search.stdout.includes(allowed) && !search.stdout.includes(denied),
    `issuer npm search keeps permitted hit: ${search.stderr}`);
  const hiddenSearch = h.client("client-npm", `npm search ${denied} --json --registry=${registry}`);
  h.expect(hiddenSearch.status === 0 && !hiddenSearch.stdout.includes(denied),
    `issuer npm search filters blocked package: ${hiddenSearch.stderr}`);
  const audit = h.client("client-npm", `npm audit --json --registry=${registry}`, { dir: project });
  h.expect(audit.status === 0, `issuer npm audit uses selected URL: ${audit.stderr} ${audit.stdout}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).some((request) =>
    request.path === "/-/npm/v1/security/advisories/bulk" && request.status === 200),
  "issuer npm audit reaches selected upstream");
  const sentinel = "private-issuer-advisory";
  await h.fakes.faults([
    { host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", method: "POST",
      mode: "json", times: 1, body: {
        [denied]: [{ id: 101, title: sentinel, severity: "high", vulnerable_versions: "*" }],
        [allowed]: [{ id: 102, title: sentinel, severity: "low", vulnerable_versions: "*" }],
      } },
    { host: "registry.npmjs.org", path: "/-/npm/v1/security/audits/quick", method: "POST",
      mode: "json", times: 1, body: { advisories: {
        101: { id: 101, module_name: denied, title: sentinel, severity: "high", vulnerable_versions: "*" },
        102: { id: 102, module_name: allowed, title: sentinel, severity: "low", vulnerable_versions: "*" },
      }, metadata: { private: sentinel } } },
  ]);
  const auditProbe = `import https from "node:https";import {readFileSync} from "node:fs";
const home=process.env.HOME;const req=https.request(process.argv[2],{method:"POST",ca:readFileSync("/e2e/ca/ca.pem"),
cert:readFileSync(home+"/.config/probation/client-cert.pem"),key:readFileSync(home+"/.config/probation/client-key.pem")},
res=>{let body="";res.on("data",part=>body+=part);res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,body})));});
req.on("error",e=>{console.error(e);process.exitCode=2});req.end();`;
  const auditResponse = (path) => {
    const run = h.client("client-npm", `node issuer-audit-probe.mjs '${registry}${path}'`,
      { files: { "issuer-audit-probe.mjs": auditProbe } });
    h.expect(run.status === 0, `issuer npm direct audit completes: ${run.stderr}`);
    return JSON.parse(run.stdout.trim());
  };
  const bulk = auditResponse("-/npm/v1/security/advisories/bulk");
  const quick = auditResponse("-/npm/v1/security/audits/quick");
  h.expect(bulk.status === 200 && quick.status === 200
    && Array.isArray(JSON.parse(bulk.body)[allowed])
    && Object.values(JSON.parse(quick.body).advisories ?? {}).some((item) => item.module_name === allowed)
    && !bulk.body.includes(denied) && !quick.body.includes(denied)
    && !bulk.body.includes(sentinel) && !quick.body.includes(sentinel),
  "issuer npm bulk and quick audit strip group-hidden metadata and arbitrary advisory text");
  await h.fakes.faults([]);
  const beforeRedirect = (await h.fakes.requests("registry.npmjs.org")).length;
  const beforeStorage = (await h.fakes.requests("registry-b.e2e.test")).length;
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${allowed}`, method: "GET",
    mode: "redirect", location: `/${allowed}`, times: 1 }]);
  const redirectProbe = `import https from "node:https"; import {readFileSync} from "node:fs";
const home=process.env.HOME;const req=https.request(process.argv[2], {ca:readFileSync("/e2e/ca/ca.pem"),
cert:readFileSync(home+"/.config/probation/client-cert.pem"),key:readFileSync(home+"/.config/probation/client-key.pem"),
headers:{authorization:"Bearer e2e-owner"}}, res=>{res.resume();res.on("end",()=>console.log(res.statusCode));});
req.on("error",e=>{console.error(e);process.exitCode=2});req.end();`;
  const redirected = h.client("client-npm", `node redirect-probe.mjs '${registry}${allowed}'`,
    { files: { "redirect-probe.mjs": redirectProbe } });
  const redirectRequests = (await h.fakes.requests("registry.npmjs.org")).slice(beforeRedirect);
  h.expect(redirected.status === 0 && redirected.stdout.trim() === "502"
    && redirectRequests.length === 1 && redirectRequests[0].fault === "redirect"
    && redirectRequests[0].credential === "developer-owner"
    && (await h.fakes.requests("registry-b.e2e.test")).length === beforeStorage,
  "issuer npm credential-bearing packument redirect stops after one request without storage leak");
  await h.fakes.faults([]);
  const routeProbe = `import https from "node:https";import {readFileSync} from "node:fs";
const home=process.env.HOME;const req=https.request(process.argv[2],{method:process.argv[3]||"GET",
ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(home+"/.config/probation/client-cert.pem"),
key:readFileSync(home+"/.config/probation/client-key.pem")},res=>{res.resume();res.on("end",()=>console.log(res.statusCode));});
req.on("error",e=>{console.error(e);process.exitCode=2});req.end();`;
  const unknown = (path, method = "GET") => {
    const run = h.client("client-npm", `node issuer-route-probe.mjs '${registry}${path}' ${method}`,
      { files: { "issuer-route-probe.mjs": routeProbe } });
    h.expect(run.status === 0, `issuer npm unknown route probe completes: ${run.stderr}`);
    return Number(run.stdout.trim());
  };
  const beforeUnknown = (await h.fakes.requests("registry.npmjs.org")).length;
  h.expect(unknown("-/unknown") === 404, "issuer npm unknown GET route refuses");
  h.expect(unknown("-/unknown", "HEAD") >= 400, "issuer npm unknown HEAD route refuses");
  h.expect(unknown(`${denied}/-/private.tgz`) >= 400,
    "issuer npm alternate artifact path cannot bypass group guard");
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeUnknown,
    "issuer npm unknown and alternate artifact routes make zero upstream calls");
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  const trustedAdded = await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Issuer trusted", ecosystem: "npm",
    target_url: "https://registry-b.e2e.test/", trusted: "on",
  });
  h.expect(trustedAdded.status === 303, `issuer trusted registry selected: ${trustedAdded.status}`);
  const trustedId = (await admin.portal.get(`/org/${org}/registries`)).body.match(/<li>(\d+) Issuer trusted npm/)?.[1];
  h.expect(trustedId && trustedId !== id, "issuer trusted registry has another exact ID");
  const freshName = h.unique("issuer-npm-fresh");
  for (const [marker, publish] of [["ordinary", h.fakes.publishNpm], ["trusted", h.fakes.publishNpmB]]) {
    await publish({ name: freshName, version: "1.0.0", ageSeconds: 400 * 86_400,
      files: { "marker.txt": marker } });
    await publish({ name: freshName, version: "1.1.0", ageSeconds: 3_600 });
  }
  const restoreFreeze = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    const ageProbe = `import https from "node:https";import {readFileSync} from "node:fs";
const home=process.env.HOME;const req=https.get(process.argv[2],{ca:readFileSync("/e2e/ca/ca.pem"),
cert:readFileSync(home+"/.config/probation/client-cert.pem"),key:readFileSync(home+"/.config/probation/client-key.pem")},
res=>{let body="";res.on("data",part=>body+=part);res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,body})));});
req.on("error",e=>{console.error(e);process.exitCode=2});`;
    const inspect = (registryId) => {
      const run = h.client("client-npm", `node age-probe.mjs 'https://fw1.e2e.test/registry/npm/${registryId}/${freshName}'`,
        { files: { "age-probe.mjs": ageProbe } });
      h.expect(run.status === 0, `issuer age probe completes: ${run.stderr}`);
      return JSON.parse(run.stdout.trim());
    };
    const ordinary = inspect(id);
    const trusted = inspect(trustedId);
    h.expect(ordinary.status === 200 && trusted.status === 200
      && !JSON.parse(ordinary.body).versions["1.1.0"] && JSON.parse(trusted.body).versions["1.1.0"],
    "issuer npm ordinary registry holds new version while trusted registry skips only age delay");
    const ordinaryLink = JSON.parse(ordinary.body).versions["1.0.0"].dist.tarball;
    const trustedLink = JSON.parse(trusted.body).versions["1.0.0"].dist.tarball;
    const artifactProbe = `import https from "node:https";import {createHash} from "node:crypto";import {readFileSync} from "node:fs";
const home=process.env.HOME;const req=https.get(process.argv[2],{ca:readFileSync("/e2e/ca/ca.pem"),
cert:readFileSync(home+"/.config/probation/client-cert.pem"),key:readFileSync(home+"/.config/probation/client-key.pem")},
res=>{let parts=[];res.on("data",part=>parts.push(part));res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,
hash:createHash("sha256").update(Buffer.concat(parts)).digest("hex")})));});
req.on("error",e=>{console.error(e);process.exitCode=2});`;
    const artifact = (url) => {
      const run = h.client("client-npm", `node issuer-artifact-probe.mjs '${url}'`,
        { files: { "issuer-artifact-probe.mjs": artifactProbe } });
      h.expect(run.status === 0, `issuer selected artifact probe completes: ${run.stderr}`);
      return JSON.parse(run.stdout.trim());
    };
    const aBytes = artifact(ordinaryLink);
    const bBytes = artifact(trustedLink);
    h.expect(aBytes.status === 200 && bBytes.status === 200 && aBytes.hash !== bBytes.hash
      && ordinaryLink.includes(`/registry/npm/${id}/`) && trustedLink.includes(`/registry/npm/${trustedId}/`),
    "issuer npm same-name registries return their own distinct selected artifact bytes");
    const identityPage = await admin.portal.get(`/org/${org}/registries`);
    const attemptedEdit = await admin.portal.post(`/org/${org}/registries/${trustedId}/trust`, {
      csrf: hidden(identityPage.body, "csrf"), ecosystem: "pypi", target_url: "https://pypi.org/",
    });
    h.expect(attemptedEdit.status === 303
      && h.stack.sql(`SELECT ecosystem || ' ' || target_url FROM registries WHERE id = ${Number(trustedId)}`)
        === "npm https://registry-b.e2e.test/",
    "issuer npm target and ecosystem edit cannot change selected registry identity");
    const removed = await admin.portal.post(`/org/${org}/registries/${trustedId}/remove`, {
      csrf: hidden(identityPage.body, "csrf"),
    });
    h.expect(removed.status === 303 && inspect(trustedId).status === 401,
      "issuer npm removed registry ID refuses before fallback to ordinary registry");
    const replacementPage = await admin.portal.get(`/org/${org}/registries`);
    const replacement = await admin.portal.post(`/org/${org}/registries`, {
      csrf: hidden(replacementPage.body, "csrf"), name: "Issuer trusted replacement", ecosystem: "npm",
      target_url: "https://registry-b.e2e.test/", trusted: "on",
    });
    const replacementId = (await admin.portal.get(`/org/${org}/registries`)).body.match(/<li>(\d+) Issuer trusted replacement npm/)?.[1];
    h.expect(replacement.status === 303 && replacementId && replacementId !== trustedId
      && inspect(replacementId).status === 200 && artifact(trustedLink).status !== 200,
    "issuer npm replacement registry gets a new ID without old artifact access");
    const beforeOutage = (await h.fakes.requests("registry-b.e2e.test")).length;
    h.stop("server");
    try {
      h.expect(inspect(replacementId).status !== 200,
        "issuer npm management outage refuses selected read");
      h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeOutage,
        "issuer npm management outage makes no selected upstream request");
    } finally {
      h.start("server");
    }
    await h.waitFor("issuer npm management recovery", () => inspect(replacementId).status === 200);
  } finally {
    await restoreFreeze();
  }
}
