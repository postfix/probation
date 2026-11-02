import { hidden } from "../harness/net.mjs";
import { join as joinOrg, orgId } from "../harness/people.mjs";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { activateIssuerFor, installIssuerLeaf, issueIssuerLeafFor } from "../harness/issuer-setup.mjs";

export const meta = { id: "E2E-publishing-npm-actions", title: "npm selected-registry actions", suites: ["release"] };

export default async function npmActions(h, { selfServiceDisabled = false, organizationIssued = false } = {}) {
  h.expect(!(selfServiceDisabled && organizationIssued), "npm actions matrix uses one certificate mode at a time");
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200, `certificate bundle: ${bundle.status}`);
  h.expect(h.stack.exec("client-npm", ["sh"], { input: bundle.body }).status === 0,
    "client certificate installed");
  let existingOther;
  if (selfServiceDisabled || organizationIssued) {
    const selectedOrg = await orgId(admin.portal);
    const other = await joinOrg(h, admin, selectedOrg, await h.signUp({ kind: "personal" }));
    const otherSetup = await other.portal.get("/certificates/setup");
    const otherBundle = await other.portal.post("/certificates/setup", { csrf: hidden(otherSetup.body, "csrf") });
    h.expect(otherBundle.status === 200, "second member receives a certificate before provider mode changes");
    existingOther = { other, otherBundle };
  }
  if (selfServiceDisabled) {
    const selectedOrg = await orgId(admin.portal);
    const issued = h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(selectedOrg)}`);
    h.stack.sql(`UPDATE registry_certificate_providers SET self_service = false WHERE org_id = ${Number(selectedOrg)}`);
    h.expect((await admin.portal.get("/certificates/setup")).status === 403,
      "disabled npm action self-service hides a new setup bundle");
    h.expect((await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") })).status === 404
      && h.stack.sql(`SELECT count(*) FROM registry_member_certificates WHERE org_id = ${Number(selectedOrg)}`) === issued,
      "disabled npm action self-service issues no new certificate");
  }
  let issuerLeaf;
  if (organizationIssued) {
    const selectedOrg = await orgId(admin.portal);
    ({ live: issuerLeaf } = await activateIssuerFor(h, admin, selectedOrg));
    installIssuerLeaf(h, "client-npm", issuerLeaf);
    existingOther.issuerLeaf = await issueIssuerLeafFor(h, selectedOrg, existingOther.other.email);
  }
  const id = bundle.body.match(/registry=https:\/\/fw1\.e2e\.test\/registry\/npm\/(\d+)\//)?.[1];
  h.expect(id, "bundle selected a registry");
  const result = h.client("client-npm", `node action.mjs 'https://fw1.e2e.test/registry/npm/${id}/-/v1/login'`, {
    files: { "action.mjs": `import https from "node:https"; import {readFileSync} from "node:fs";
const req = https.request(process.argv[2], {method:"POST", ca:readFileSync("/e2e/ca/ca.pem"),
  cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),
  key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem"),
  headers:{"content-type":"application/json", ...(process.argv[3] ? {host:process.argv[3]} : {})}}, res => {let body="";res.on("data",x=>body+=x);res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,body})));});
req.on("error", e=>{console.error(e);process.exitCode=2});req.end("{}");` },
  });
  h.expect(result.status === 0, `login request completes: ${result.stderr}`);
  const answer = JSON.parse(result.stdout.trim());
  h.expect(answer.status === 200, `tokenless web login starts on selected URL: ${answer.status} ${answer.body}`);
  h.expect(JSON.parse(answer.body).doneUrl === `https://fw1.e2e.test/registry/npm/${id}/-/v1/login/done`,
    "web login poll remains on selected URL");
  const forged = h.client("client-npm", `node action.mjs 'https://fw1.e2e.test/registry/npm/${id}/-/v1/login' attacker.example`, {
    files: { "action.mjs": `import https from "node:https"; import {readFileSync} from "node:fs";
const req=https.request(process.argv[2], {method:"POST",servername:"fw1.e2e.test",ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem"),headers:{host:process.argv[3],"content-type":"application/json"}},res=>{let body="";res.on("data",x=>body+=x);res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,body})));}); req.on("error",e=>{console.error(e);process.exitCode=2});req.end("{}");` },
  });
  h.expect(forged.status === 0, `forged host login completes: ${forged.stderr}`);
  h.expect(JSON.parse(JSON.parse(forged.stdout.trim()).body).doneUrl === `https://fw1.e2e.test/registry/npm/${id}/-/v1/login/done`,
    "login poll URL ignores an untrusted Host header");
  const beforeTokenless = (await h.fakes.requests("registry.npmjs.org")).length;
  const tokenlessAction = h.client("client-npm", `node action.mjs 'https://fw1.e2e.test/registry/npm/${id}/-/package/tokenless/access'`,
    { files: { "action.mjs": `import https from "node:https"; import {readFileSync} from "node:fs";
const req=https.request(process.argv[2],{method:"POST",ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem"),headers:{"content-type":"application/json"}},res=>{res.resume();res.on("end",()=>console.log(res.statusCode));});req.on("error",e=>{console.error(e);process.exitCode=2});req.end("{}");` } });
  h.expect(tokenlessAction.status === 0 && Number(tokenlessAction.stdout.trim()) === 401,
    `certificate-only named mutation refuses without bearer: ${tokenlessAction.stdout} ${tokenlessAction.stderr}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeTokenless,
    "certificate-only named mutation makes no selected-upstream request");
  const beforeForeignLogin = (await h.fakes.requests("registry-b.e2e.test")).length;
  await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/v1/login", method: "POST", mode: "json",
    body: { loginUrl: "https://browser.example/login", doneUrl: "https://registry-b.e2e.test/-/v1/login/done" }, times: 1 }]);
  try {
    const foreignDone = h.client("client-npm", `node action.mjs 'https://fw1.e2e.test/registry/npm/${id}/-/v1/login'`,
      { files: { "action.mjs": `import https from "node:https"; import {readFileSync} from "node:fs";
const req=https.request(process.argv[2],{method:"POST",ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem"),headers:{"content-type":"application/json"}},res=>{res.resume();res.on("end",()=>console.log(res.statusCode));});req.on("error",e=>{console.error(e);process.exitCode=2});req.end("{}");` } });
    h.expect(foreignDone.status === 0 && Number(foreignDone.stdout.trim()) === 502,
      `foreign upstream doneUrl refuses locally: ${foreignDone.stdout} ${foreignDone.stderr}`);
    h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeForeignLogin,
      "foreign doneUrl makes no foreign outbound request");
  } finally {
    await h.fakes.faults([]);
  }
  const loginRate = h.client("client-npm", `node login-rate.mjs 'https://fw1.e2e.test/registry/npm/${id}/-/v1/login'`, {
    files: { "login-rate.mjs": `import https from "node:https"; import {readFileSync} from "node:fs";
const agent=new https.Agent({keepAlive:true,ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem")});
const start=()=>new Promise((resolve,reject)=>{const req=https.request(process.argv[2],{agent,method:"POST",headers:{"content-type":"application/json"}},res=>{res.resume();res.on("end",()=>resolve(res.statusCode));});req.on("error",reject);req.end("{}");});
const statuses=[];for(let i=0;i<118;i++){statuses.push(await start());await new Promise(resolve=>setTimeout(resolve,20));}agent.destroy();console.log(JSON.stringify(statuses));` },
  });
  h.expect(loginRate.status === 0, `login rate probe completes: ${loginRate.stderr}`);
  const loginStatuses = JSON.parse(loginRate.stdout.trim());
  h.expect(loginStatuses.slice(0, 117).every(status => status === 200) && loginStatuses[117] === 429,
    `121st web-login start is rate-limited before upstream: ${loginRate.stdout}`);
  const token = h.stack.exec("client-npm", ["sh", "-c", `printf '\n//fw1.e2e.test/registry/npm/${id}/:_authToken=e2e-owner\n' >> /root/.npmrc`]);
  h.expect(token.status === 0, "developer token configured in user-local npm config");
  const name = h.unique("action-publish");
  const project = `/work/${h.unique("action-project")}`;
  const published = h.client("client-npm", `npm publish --ignore-scripts --registry=https://fw1.e2e.test/registry/npm/${id}/`, {
    dir: project, files: { "package.json": JSON.stringify({ name, version: "1.0.0" }), "index.js": "module.exports = 1;\n" },
  });
  h.expect(published.status === 0, `npm publish completes through selected URL: ${published.stderr}`);
  h.log("npm-actions: initial publish passed; seeding hidden package");
  const hiddenName = h.unique("action-hidden");
  await h.fakes.publishNpm({ name: hiddenName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  h.log("npm-actions: hidden package seeded; saving group policy");
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: hiddenName, what: "package" });
  h.log("npm-actions: group policy saved; deprecating hidden package");
  const deprecated = h.client("client-npm", `npm deprecate ${hiddenName}@1.0.0 retired --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(deprecated.status === 0, `owner deprecates group-hidden package through selected URL: ${deprecated.stderr}`);
  const writes = (await h.fakes.requests("registry.npmjs.org")).filter(r => r.path.startsWith(`/${hiddenName}`));
  h.expect(writes.some(r => r.method === "GET" && r.path.endsWith("?write=true") && r.credential === "developer-owner")
    && writes.some(r => r.method === "PUT" && r.credential === "developer-owner"),
    "deprecate uses canonical token preflight and a separately authorized write");
  const tags = h.client("client-npm", `npm dist-tag ls ${name} --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(tags.status === 0 && tags.stdout.includes("latest: 1.0.0"),
    `npm dist-tag reads selected package administration: ${tags.stderr} ${tags.stdout}`);
  const addTag = h.client("client-npm", `npm dist-tag add ${name}@1.0.0 stable --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(addTag.status === 0, `npm dist-tag mutates selected package: ${addTag.stderr}`);
  const tagged = h.client("client-npm", `npm dist-tag ls ${name} --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(tagged.status === 0 && tagged.stdout.includes("stable: 1.0.0"),
    `new tag visible at selected registry: ${tagged.stderr} ${tagged.stdout}`);
  const owners = h.client("client-npm", `npm owner ls ${name} --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(owners.status === 0 && owners.stdout.includes("e2e-owner"),
    `npm owner reads selected package administration: ${owners.stderr} ${owners.stdout}`);
  const addOwner = h.client("client-npm", `npm owner add e2e-teammate ${name} --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(addOwner.status === 0, `npm owner mutates selected package: ${addOwner.stderr} ${addOwner.stdout}`);
  const unpublishWhole = h.unique("action-unpublish-whole");
  await h.fakes.publishNpm({ name: unpublishWhole, version: "1.0.0", ageSeconds: 400 * 86_400 });
  const whole = h.client("client-npm", `npm unpublish ${unpublishWhole} --force --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(whole.status === 0, `npm unpublish whole package completes through selected URL: ${whole.stderr}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(r => r.method === "DELETE" && r.path.startsWith(`/${unpublishWhole}/-rev/`)),
    "whole-package unpublish reaches the selected upstream DELETE");
  const unpublishVersion = h.unique("action-unpublish-version");
  await h.fakes.publishNpm({ name: unpublishVersion, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: unpublishVersion, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const version = h.client("client-npm", `npm unpublish ${unpublishVersion}@1.0.0 --force --loglevel=http --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(version.status === 0, `npm unpublish one version completes through selected URL: ${version.stderr}`);
  const versionWrites = (await h.fakes.requests("registry.npmjs.org")).filter(r => r.path.startsWith(`/${unpublishVersion}`));
  h.expect(versionWrites.some(r => r.method === "PUT" && r.path.includes("/-rev/"))
    && versionWrites.some(r => r.method === "DELETE" && r.path.includes("/-rev/")),
    `version unpublish updates selected metadata and deletes its tarball upstream: ${version.stderr}`);

  const noncanonical = h.unique("action-noncanonical");
  const org = await orgId(admin.portal);
  const scopeCatalog = await admin.portal.get(`/org/${org}/registries`);
  const scopeSaved = await admin.portal.post(`/org/${org}/registries/${id}/delete-scope`, {
    csrf: hidden(scopeCatalog.body, "csrf"), origin: "https://registry.npmjs.org", path_prefix: "/custom/case",
  });
  h.expect(scopeSaved.status === 303, `admin approves exact noncanonical deletion path: ${scopeSaved.status}`);
  const noncanonicalTarball = `https://registry.npmjs.org/custom/case/${noncanonical}-1.0.0.tgz`;
  await h.fakes.publishNpm({ name: noncanonical, version: "1.0.0", ageSeconds: 400 * 86_400, tarballUrl: noncanonicalTarball });
  await h.fakes.publishNpm({ name: noncanonical, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const noncanonicalResult = h.client("client-npm", `npm unpublish ${noncanonical}@1.0.0 --force --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(noncanonicalResult.status === 0, `noncanonical version unpublish exits successfully: ${noncanonicalResult.stderr}`);
  const noncanonicalWrites = await h.fakes.requests("registry.npmjs.org");
  h.expect(noncanonicalWrites.some(r => r.method === "DELETE" && r.path === `/custom/case/${noncanonical}-1.0.0.tgz/-rev/2`),
    "noncanonical listed tarball is deleted at its exact upstream path after revision PUT");

  const external = h.unique("action-extra-origin");
  const externalScope = await admin.portal.post(`/org/${org}/registries/${id}/delete-scope`, {
    csrf: hidden(scopeCatalog.body, "csrf"), origin: "https://registry-b.e2e.test", path_prefix: "/extra/case",
  });
  h.expect(externalScope.status === 303, `admin approves extra deletion origin without bearer: ${externalScope.status}`);
  const signedTarball = `https://registry-b.e2e.test/extra/case/${external}-1.0.0.tgz?sig=d41-signed-secret`;
  await h.fakes.publishNpm({ name: external, version: "1.0.0", ageSeconds: 400 * 86_400, tarballUrl: signedTarball });
  await h.fakes.publishNpm({ name: external, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const externalResult = h.client("client-npm", `npm unpublish ${external}@1.0.0 --force --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(externalResult.status !== 0, "extra-origin upstream can deny a credential-free DELETE");
  const externalWrites = await h.fakes.requests("registry-b.e2e.test");
  h.expect(externalWrites.some(r => r.method === "DELETE" && r.path === `/extra/case/${external}-1.0.0.tgz/-rev/2?<redacted>` && r.signedQueryValid && r.credential === "none" && r.status === 403),
    "extra-origin DELETE preserves the sealed signed query and omits bearer by default");

  const bearerScope = await admin.portal.post(`/org/${org}/registries/${id}/delete-scope`, {
    csrf: hidden(scopeCatalog.body, "csrf"), origin: "https://registry-b.e2e.test", path_prefix: "/extra/case", forward_bearer: "on",
  });
  h.expect(bearerScope.status === 303, "admin enables bearer for that exact deletion scope");
  const externalAllowed = h.unique("action-extra-allowed");
  await h.fakes.publishNpm({ name: externalAllowed, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${externalAllowed}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: externalAllowed, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const allowedResult = h.client("client-npm", `npm unpublish ${externalAllowed}@1.0.0 --force --registry=https://fw1.e2e.test/registry/npm/${id}/`);
  h.expect(allowedResult.status === 0, `approved extra-origin bearer unpublish succeeds: ${allowedResult.stderr}`);
  h.expect((await h.fakes.requests("registry-b.e2e.test")).some(r => r.method === "DELETE"
    && r.path === `/extra/case/${externalAllowed}-1.0.0.tgz/-rev/2?<redacted>` && r.signedQueryValid && r.credential === "developer-owner"),
    "extra-origin DELETE sends token only after the administrator opts in");

  const referenceScript = `import https from "node:https"; import {readFileSync} from "node:fs";
const payload=process.argv[4]?Buffer.from(process.argv[4],"base64"):undefined;
const req=https.request(process.argv[3],{method:process.argv[2],ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem"),headers:{authorization:"Bearer "+(process.argv[5]||"e2e-owner"),...(payload?{"content-type":"application/json"}:{}),...(process.argv[6]?{"content-encoding":process.argv[6]}:{})}},res=>{let body="";res.on("data",part=>body+=part);res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,body})));});req.on("error",e=>{console.error(e);process.exitCode=2});req.end(payload);`;
  const referenceRequest = (method, target, body, { token = "e2e-owner", encoding = "", home = "/root" } = {}) => {
    const encoded = body ? Buffer.from(body).toString("base64") : "";
    const result = h.client("client-npm", `HOME=${home} node d41-reference.mjs ${method} '${target}' '${encoded}' '${token}' '${encoding}'`,
      { files: { "d41-reference.mjs": referenceScript } });
    h.expect(result.status === 0, `direct D41 ${method} completes: ${result.stderr}`);
    return JSON.parse(result.stdout.trim());
  };
  for (const [token, expectedStatus, credential] of [
    ["e2e-owner", 200, "developer-owner"],
    ["e2e-denied", 403, "developer-denied"],
  ]) {
    const packageName = h.unique("action-whole-revision");
    await h.fakes.publishNpm({ name: packageName, version: "1.0.0", ageSeconds: 400 * 86_400 });
    const path = `/${packageName}/-rev/1`;
    const target = `https://fw1.e2e.test/registry/npm/${id}${path}`;
    const response = referenceRequest("DELETE", target, undefined, { token });
    h.expect(response.status === expectedStatus && (expectedStatus === 200
      ? JSON.parse(response.body).ok === true : JSON.parse(response.body).error === "denied"),
      `whole-package revision DELETE reflects selected upstream ${expectedStatus}: ${response.status} ${response.body}`);
    const selected = (await h.fakes.requests("registry.npmjs.org"))
      .filter(r => r.method === "DELETE" && r.path === path);
    const other = (await h.fakes.requests("registry-b.e2e.test"))
      .filter(r => r.method === "DELETE" && r.path === path);
    h.expect(selected.length === 1 && selected[0].credential === credential && selected[0].status === expectedStatus && other.length === 0,
      "whole-package revision DELETE reaches exactly the selected origin with its developer bearer, without a version-removal marker");
  }
  const refusedPath = `/${h.unique("action-unknown")}`;
  const beforeRefused = (await h.fakes.requests("registry.npmjs.org")).length;
  for (const [method, path] of [["POST", refusedPath], ["PATCH", `/${name}`]]) {
    h.expect(referenceRequest(method, `https://fw1.e2e.test/registry/npm/${id}${path}`).status >= 400,
      `${method} selected mutation refuses locally`);
  }
  h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeRefused,
    "unknown and PATCH selected mutations make zero upstream calls");
  const ordinary = h.unique("action-ordinary-revision-link");
  const ordinaryTarball = `https://registry.npmjs.org/${ordinary}/-/${ordinary}-1.0.0.tgz`;
  await h.fakes.publishNpm({ name: ordinary, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: ordinaryTarball });
  await h.fakes.publishNpm({ name: ordinary, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const ordinaryUrl = `https://fw1.e2e.test/registry/npm/${id}/${ordinary}`;
  const ordinaryUpstreamUrl = `https://registry.npmjs.org/${ordinary}`;
  const ordinaryUpstream = (await h.request(`${ordinaryUpstreamUrl}?e2e-fixture=before`)).json();
  const partialListing = structuredClone(ordinaryUpstream);
  delete partialListing.versions["1.0.0"];
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${ordinary}?write=true`, method: "GET",
    mode: "json", body: partialListing, times: 1 }]);
  const ordinaryBody = JSON.parse(referenceRequest("GET", `${ordinaryUrl}?write=true`).body);
  await h.fakes.faults([]);
  h.expect(!ordinaryBody.versions["1.0.0"], "unleased ordinary version was absent from write preflight");
  ordinaryBody.versions["1.0.0"] = ordinaryUpstream.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${ordinaryUrl}/-rev/1`, JSON.stringify(ordinaryBody)).status === 201,
    "revision PUT preserves an ordinary upstream tarball URL while restoring selected local links");
  const acceptedOrdinary = (await h.request(`${ordinaryUpstreamUrl}?e2e-fixture=after`)).json();
  h.expect(acceptedOrdinary.versions["1.0.0"].dist.tarball === ordinaryTarball
    && acceptedOrdinary.versions["2.0.0"].dist.tarball === ordinaryUpstream.versions["2.0.0"].dist.tarball,
    "upstream retains exact unleased ordinary and restored leased tarball URLs");
  const fixtureReads = (await h.fakes.requests("registry.npmjs.org"))
    .filter((request) => request.path.startsWith(`/${ordinary}?e2e-fixture=`));
  h.expect(fixtureReads.length === 2
    && fixtureReads[0].path === `/${ordinary}?e2e-fixture=before`
    && fixtureReads[1].path === `/${ordinary}?e2e-fixture=after`
    && fixtureReads.every((request) => request.method === "GET" && request.credential === "none"),
    "two distinct no-credential host fixture reads bracket the revision PUT");
  const changedRetained = h.unique("action-changed-retained-link");
  await h.fakes.publishNpm({ name: changedRetained, version: "1.0.0", ageSeconds: 400 * 86_400 });
  const changedRetainedUrl = `https://fw1.e2e.test/registry/npm/${id}/${changedRetained}`;
  const retainedBody = JSON.parse(referenceRequest("GET", `${changedRetainedUrl}?write=true`).body);
  const beforeDirectDelete = (await h.fakes.requests("registry.npmjs.org")).filter(r => r.method === "DELETE" && r.path.startsWith(`/${changedRetained}/-/`)).length;
  h.expect(referenceRequest("DELETE", `${changedRetainedUrl}/-/${changedRetained}-1.0.0.tgz/-rev/1`).status === 404,
    "direct canonical tarball DELETE refuses without an accepted removal marker");
  h.expect((await h.fakes.requests("registry.npmjs.org")).filter(r => r.method === "DELETE" && r.path.startsWith(`/${changedRetained}/-/`)).length === beforeDirectDelete,
    "direct canonical tarball DELETE makes zero upstream calls");
  const beforeRetained = (await h.fakes.requests("registry.npmjs.org")).filter(r => r.method === "PUT" && r.path.startsWith(`/${changedRetained}/-rev/`)).length;
  for (const replacement of [
    `https://registry.npmjs.org/${changedRetained}/-/${changedRetained}-1.0.0.tgz?changed=1`,
    `https://registry-b.e2e.test/extra/case/${changedRetained}-1.0.0.tgz`,
  ]) {
    retainedBody.versions["1.0.0"].dist.tarball = replacement;
    h.expect(referenceRequest("PUT", `${changedRetainedUrl}/-rev/1`, JSON.stringify(retainedBody)).status === 400,
      "changed retained leased tarball URL refuses");
  }
  h.expect((await h.fakes.requests("registry.npmjs.org")).filter(r => r.method === "PUT" && r.path.startsWith(`/${changedRetained}/-rev/`)).length === beforeRetained,
    "changed retained leased tarball URLs make zero upstream PUTs");
  const emptied = h.unique("action-empty-relisting");
  await h.fakes.publishNpm({ name: emptied, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${emptied}-1.0.0.tgz?sig=d41-signed-secret` });
  const emptyUrl = `https://fw1.e2e.test/registry/npm/${id}/${emptied}`;
  const initiallyListed = JSON.parse(referenceRequest("GET", `${emptyUrl}?write=true`).body);
  const oldEmptyLink = initiallyListed.versions["1.0.0"].dist.tarball;
  const emptyDocument = { name: emptied, _rev: "1", versions: {}, time: {}, "dist-tags": {} };
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${emptied}?write=true`, method: "GET",
    mode: "json", body: emptyDocument, times: 1 }]);
  const emptyPreflight = referenceRequest("GET", `${emptyUrl}?write=true`);
  await h.fakes.faults([]);
  h.expect(emptyPreflight.status === 200 && Object.keys(JSON.parse(emptyPreflight.body).versions).length === 0,
    "upstream empty listing reaches a write preflight and revokes prior unaccepted links");
  h.expect(referenceRequest("PUT", `${emptyUrl}/-rev/1`, JSON.stringify(emptyDocument)).status === 201,
    "selected upstream accepts an empty revision PUT");
  const beforeEmptyDelete = (await h.fakes.requests("registry-b.e2e.test")).length;
  h.expect(referenceRequest("DELETE", `${oldEmptyLink}/-rev/2`).status === 404,
    "an old reference cannot get a marker from a later accepted empty revision PUT");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeEmptyDelete,
    "old empty-listing reference makes no extra-origin DELETE");

  const stale = h.unique("action-stale-relisting");
  const staleTarball = `https://registry-b.e2e.test/extra/case/${stale}-1.0.0.tgz?sig=d41-signed-secret`;
  const staleSecondTarball = `https://registry.npmjs.org/${stale}/-/${stale}-2.0.0.tgz`;
  await h.fakes.publishNpm({ name: stale, version: "1.0.0", ageSeconds: 400 * 86_400, tarballUrl: staleTarball });
  await h.fakes.publishNpm({ name: stale, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const staleUrl = `https://fw1.e2e.test/registry/npm/${id}/${stale}`;
  const staleBody = JSON.parse(referenceRequest("GET", `${staleUrl}?write=true`).body);
  const oldStaleLink = staleBody.versions["1.0.0"].dist.tarball;
  const staleUpstreamBody = structuredClone(staleBody);
  staleUpstreamBody.versions["1.0.0"].dist.tarball = staleTarball;
  staleUpstreamBody.versions["2.0.0"].dist.tarball = staleSecondTarball;
  delete staleBody.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${staleUrl}/-rev/1`, JSON.stringify(staleBody)).status === 201,
    "selected upstream accepts a removal before a stale listing arrives");
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${stale}?write=true`, method: "GET",
    mode: "json", body: staleUpstreamBody, times: 1 }]);
  const staleRead = referenceRequest("GET", `${staleUrl}?write=true`);
  await h.fakes.faults([]);
  h.expect(staleRead.status === 200, "stale relisting of the removed version reaches the preflight");
  h.expect(referenceRequest("DELETE", `${oldStaleLink}/-rev/2`).status === 200,
    "accepted removal marker survives a later stale preflight until its one DELETE");
  h.expect(referenceRequest("DELETE", `${oldStaleLink}/-rev/2`).status === 404,
    "stale relisting cannot make the accepted DELETE replayable");
  const other = existingOther?.other ?? await joinOrg(h, admin, org, await h.signUp({ kind: "personal" }));
  let otherBundle = existingOther?.otherBundle;
  if (!otherBundle) {
    const otherSetup = await other.portal.get("/certificates/setup");
    otherBundle = await other.portal.post("/certificates/setup", { csrf: hidden(otherSetup.body, "csrf") });
  }
  h.expect(otherBundle.status === 200, "second organization member receives an independent certificate");
  const otherHome = "/work/action-other-member";
  h.expect(h.stack.exec("client-npm", ["sh", "-c", `mkdir -p ${otherHome}; HOME=${otherHome} sh`],
    { input: otherBundle.body }).status === 0, "second member certificate installs in its own home");
  if (organizationIssued) installIssuerLeaf(h, "client-npm", existingOther.issuerLeaf, otherHome);
  const sameRef = h.unique("action-two-member");
  await h.fakes.publishNpm({ name: sameRef, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${sameRef}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: sameRef, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const sameRefUrl = `https://fw1.e2e.test/registry/npm/${id}/${sameRef}`;
  const parallelScript = `import https from "node:https"; import {readFileSync} from "node:fs";
const request=(home)=>new Promise((resolve,reject)=>{const req=https.request(process.argv[2],{method:"GET",ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(home+"/.config/probation/client-cert.pem"),key:readFileSync(home+"/.config/probation/client-key.pem"),headers:{authorization:"Bearer e2e-owner"}},res=>{let body="";res.on("data",part=>body+=part);res.on("end",()=>resolve({status:res.statusCode,body}));});req.on("error",reject);req.end();});
console.log(JSON.stringify(await Promise.all([request("/root"),request("/work/action-other-member")])));`;
  let concurrentReads;
  await h.waitFor("two members can preflight the same advertised version", async () => {
    const run = h.client("client-npm", `node two-member-preflight.mjs '${sameRefUrl}?write=true'`,
      { files: { "two-member-preflight.mjs": parallelScript } });
    if (run.status !== 0) return false;
    concurrentReads = JSON.parse(run.stdout.trim());
    return concurrentReads.every(read => read.status === 200);
  }, { timeout: 30_000 });
  const firstMemberBody = JSON.parse(concurrentReads[0].body);
  const secondMemberBody = JSON.parse(concurrentReads[1].body);
  const sharedLink = firstMemberBody.versions["1.0.0"].dist.tarball;
  h.expect(secondMemberBody.versions["1.0.0"].dist.tarball === sharedLink,
    "concurrent same-URL preflights advertise the same reference ID to independent members");
  delete firstMemberBody.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${sameRefUrl}/-rev/1`, JSON.stringify(firstMemberBody)).status === 201,
    "first member receives an upstream-accepted removal marker");
  const beforeOtherDelete = (await h.fakes.requests("registry-b.e2e.test")).length;
  h.expect(referenceRequest("DELETE", `${sharedLink}/-rev/2`, undefined, { home: otherHome }).status === 404,
    "second member cannot consume first member's removal marker for the same reference ID");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeOtherDelete,
    "second member's independent lease makes no unauthorized DELETE");
  h.expect(referenceRequest("DELETE", `${sharedLink}/-rev/2`).status === 200,
    "first member's accepted marker still authorizes its own DELETE");
  const racing = h.unique("action-delete-race");
  await h.fakes.publishNpm({ name: racing, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${racing}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: racing, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const raceUrl = `https://fw1.e2e.test/registry/npm/${id}/${racing}`;
  const raceBody = JSON.parse(referenceRequest("GET", `${raceUrl}?write=true`).body);
  const raceLink = raceBody.versions["1.0.0"].dist.tarball;
  delete raceBody.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${raceUrl}/-rev/1`, JSON.stringify(raceBody)).status === 201,
    "concurrent DELETE fixture has one accepted removal marker");
  const raceScript = `import https from "node:https"; import {readFileSync} from "node:fs";
const send=()=>new Promise((resolve,reject)=>{const req=https.request(process.argv[2],{method:"DELETE",ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync("/root/.config/probation/client-cert.pem"),key:readFileSync("/root/.config/probation/client-key.pem"),headers:{authorization:"Bearer e2e-owner"}},res=>{res.resume();res.on("end",()=>resolve(res.statusCode));});req.on("error",reject);req.end();});
console.log(JSON.stringify(await Promise.all([send(),send()])));`;
  const raceRun = h.client("client-npm", `node race-delete.mjs '${raceLink}/-rev/2'`,
    { files: { "race-delete.mjs": raceScript } });
  h.expect(raceRun.status === 0, `concurrent same-member DELETEs complete: ${raceRun.stderr}`);
  h.expect(JSON.parse(raceRun.stdout.trim()).sort().join(",") === "200,404",
    `exactly one concurrent DELETE consumes the marker: ${raceRun.stdout}`);
  h.expect((await h.fakes.requests("registry-b.e2e.test")).filter(r => r.method === "DELETE"
    && r.path.startsWith(`/extra/case/${racing}-1.0.0.tgz/`)).length === 1,
    "concurrent duplicate DELETEs make one extra-origin request");
  const unwritable = h.unique("action-unwritable-delete");
  await h.fakes.publishNpm({ name: unwritable, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: unwritable, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const unwritableUrl = `https://fw1.e2e.test/registry/npm/${id}/${unwritable}`;
  const unwritableBody = JSON.parse(referenceRequest("GET", `${unwritableUrl}?write=true`).body);
  const unwritableLink = unwritableBody.versions["1.0.0"].dist.tarball;
  delete unwritableBody.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${unwritableUrl}/-rev/1`, JSON.stringify(unwritableBody)).status === 201,
    "unwritable-directory fixture has an accepted removal marker");
  const beforeUnwritable = (await h.fakes.requests("registry.npmjs.org"))
    .filter(r => r.method === "DELETE" && r.path.startsWith(`/${unwritable}/-/`)).length;
  const unwritableDirectory = h.stack.exec("firewall-1", ["chmod", "0500", "/var/lib/probation"]);
  h.expect(unwritableDirectory.status === 0,
    `firewall data directory made temporarily unwritable: ${unwritableDirectory.stderr.trim()}`);
  try {
    h.expect(referenceRequest("DELETE", `${unwritableLink}/-rev/2`).status >= 400,
      "temporary-file creation failure refuses DELETE");
  } finally {
    h.expect(h.stack.exec("firewall-1", ["chmod", "0700", "/var/lib/probation"]).status === 0,
      "firewall data directory restored after temporary-file failure");
  }
  h.expect((await h.fakes.requests("registry.npmjs.org"))
    .filter(r => r.method === "DELETE" && r.path.startsWith(`/${unwritable}/-/`)).length === beforeUnwritable,
    "temporary-file creation failure makes no upstream DELETE");
  h.expect(referenceRequest("DELETE", `${unwritableLink}/-rev/2`).status === 200,
    "accepted marker remains usable after local temporary-file failure");
  h.expect((await h.fakes.requests("registry.npmjs.org"))
    .filter(r => r.method === "DELETE" && r.path.startsWith(`/${unwritable}/-/`)).length === beforeUnwritable + 1,
    "retry makes exactly one selected-upstream DELETE");
  const invalidDestinations = [
    ["foreign host", (name) => `https://foreign.e2e.test/${name}-1.0.0.tgz`],
    ["userinfo", (name) => `https://user:secret@registry.npmjs.org/custom/case/${name}-1.0.0.tgz`],
    ["encoded dot", (name) => `https://registry.npmjs.org/custom/case/%2e%2e/${name}-1.0.0.tgz`],
    ["encoded slash", (name) => `https://registry.npmjs.org/custom/case/%2f/${name}-1.0.0.tgz`],
    ["backslash", (name) => `https://registry.npmjs.org/custom/case/\\/${name}-1.0.0.tgz`],
    ["empty segment", (name) => `https://registry.npmjs.org/custom/case//${name}-1.0.0.tgz`],
    ["URL length 2049", (name) => `https://registry.npmjs.org/custom/case/${name}-1.0.0.tgz?sig=${"x".repeat(2049)}`],
  ];
  for (const [reason, tarball] of invalidDestinations) {
    const invalidName = h.unique("action-invalid-destination");
    await h.fakes.publishNpm({ name: invalidName, version: "1.0.0", ageSeconds: 400 * 86_400,
      tarballUrl: tarball(invalidName) });
    const invalidRead = referenceRequest("GET", `https://fw1.e2e.test/registry/npm/${id}/${invalidName}?write=true`);
    h.expect(invalidRead.status >= 400, `${reason} is refused before advertising a deletion lease: ${invalidRead.status}`);
  }
  const restarted = h.unique("action-extra-restart");
  await h.fakes.publishNpm({ name: restarted, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${restarted}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: restarted, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const restartUrl = `https://fw1.e2e.test/registry/npm/${id}/${restarted}`;
  const firstPackument = referenceRequest("GET", `${restartUrl}?write=true`);
  h.expect(firstPackument.status === 200, "direct D41 write preflight succeeds");
  const revisionBody = JSON.parse(firstPackument.body);
  const oldLink = revisionBody.versions["1.0.0"].dist.tarball;
  h.expect(!oldLink.includes("d41-signed-secret"), "signed query never appears in client artifact link");
  const beforeRefusals = (await h.fakes.requests("registry-b.e2e.test")).length;
  const badReferenceUrls = [
    `${oldLink.replace(/\/artifacts\/[0-9a-f]{64}\//, `/artifacts/${"0".repeat(64)}/`)}/-rev/2`,
    `${oldLink.replace(`/registry/npm/${id}/`, `/registry/npm/${Number(id) + 100}/`)}/-rev/2`,
    `${oldLink.replace(/\.tgz$/, "-wrong.tgz")}/-rev/2`,
    `${oldLink}/-rev/bad!`,
    `${oldLink}/-rev/2`,
  ];
  for (const target of badReferenceUrls) {
    h.expect(referenceRequest("DELETE", target).status >= 400, `unleased, invalid or unmarked DELETE refuses: ${target}`);
  }
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeRefusals,
    "invalid ID, cross-registry ID, filename, revision and absent marker make no extra-origin call");
  delete revisionBody.versions["1.0.0"];
  delete revisionBody.time["1.0.0"];
  revisionBody["dist-tags"].latest = "2.0.0";
  const accepted = referenceRequest("PUT", `${restartUrl}/-rev/${revisionBody._rev}`, JSON.stringify(revisionBody));
  h.expect(accepted.status === 201 && JSON.parse(accepted.body).rev === "2", "selected upstream accepted exact version removal");
  h.expect(referenceRequest("DELETE", `${oldLink}/-rev/1`).status >= 400,
    "wrong resulting revision cannot consume the accepted removal marker");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeRefusals,
    "wrong revision makes no extra-origin call");
  h.stack.restart("firewall-1");
  await h.stack.firewallReady("fw1");
  const refreshed = referenceRequest("GET", `${restartUrl}?write=true`);
  h.expect(refreshed.status === 200 && JSON.parse(refreshed.body)._rev === "2", "restarted firewall reads resulting revision");
  const restartedDelete = referenceRequest("DELETE", `${oldLink}/-rev/2`);
  h.expect(restartedDelete.status === 200, `sealed extra-origin reference and marker survive restart: ${restartedDelete.status} ${restartedDelete.body}`);
  h.expect((await h.fakes.requests("registry-b.e2e.test")).some(r => r.method === "DELETE"
    && r.path === `/extra/case/${restarted}-1.0.0.tgz/-rev/2?<redacted>` && r.signedQueryValid && r.credential === "developer-owner"),
    "restarted DELETE keeps exact old signed destination and current bearer approval");
  const replay = referenceRequest("DELETE", `${oldLink}/-rev/2`);
  h.expect(replay.status === 404, "consumed removal marker refuses replay after restart");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).filter(r => r.path.startsWith(`/extra/case/${restarted}-1.0.0.tgz/`)).length === 1,
    "wrong revision and replay never duplicate the authorized extra-origin DELETE");

  const noMarker = h.unique("action-no-marker");
  await h.fakes.publishNpm({ name: noMarker, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${noMarker}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: noMarker, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const noMarkerUrl = `https://fw1.e2e.test/registry/npm/${id}/${noMarker}`;
  const noMarkerBody = JSON.parse(referenceRequest("GET", `${noMarkerUrl}?write=true`).body);
  const noMarkerLink = noMarkerBody.versions["1.0.0"].dist.tarball;
  const unchangedPut = referenceRequest("PUT", `${noMarkerUrl}/-rev/1`, JSON.stringify(noMarkerBody));
  h.expect(unchangedPut.status === 201, "upstream accepts unchanged revision PUT");
  const beforeNoMarker = (await h.fakes.requests("registry-b.e2e.test")).length;
  h.expect(referenceRequest("DELETE", `${noMarkerLink}/-rev/2`).status === 404,
    "unchanged-version PUT creates no deletion marker");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeNoMarker,
    "unchanged-version marker refusal makes no extra-origin call");

  const deniedMarker = h.unique("action-denied-marker");
  await h.fakes.publishNpm({ name: deniedMarker, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${deniedMarker}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: deniedMarker, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const deniedMarkerUrl = `https://fw1.e2e.test/registry/npm/${id}/${deniedMarker}`;
  const deniedBody = JSON.parse(referenceRequest("GET", `${deniedMarkerUrl}?write=true`).body);
  const deniedLink = deniedBody.versions["1.0.0"].dist.tarball;
  delete deniedBody.versions["1.0.0"];
  const deniedPut = referenceRequest("PUT", `${deniedMarkerUrl}/-rev/1`, JSON.stringify(deniedBody), { token: "e2e-denied" });
  h.expect(deniedPut.status === 403, "upstream denies version-removal revision PUT");
  h.expect(referenceRequest("DELETE", `${deniedLink}/-rev/2`).status === 404,
    "denied revision PUT creates no deletion marker");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeNoMarker,
    "denied PUT and following DELETE make no extra-origin call");

  const inserted = h.unique("action-inserted-link");
  await h.fakes.publishNpm({ name: inserted, version: "1.0.0", ageSeconds: 400 * 86_400 });
  const insertedUrl = `https://fw1.e2e.test/registry/npm/${id}/${inserted}`;
  const insertedBody = JSON.parse(referenceRequest("GET", `${insertedUrl}?write=true`).body);
  insertedBody.versions["3.0.0"] = structuredClone(insertedBody.versions["1.0.0"]);
  insertedBody.versions["3.0.0"].version = "3.0.0";
  insertedBody.versions["3.0.0"].dist.tarball = insertedBody.versions["1.0.0"].dist.tarball;
  const beforeInserted = (await h.fakes.requests("registry.npmjs.org")).filter(r => r.method === "PUT" && r.path.startsWith(`/${inserted}/-rev/`)).length;
  h.expect(referenceRequest("PUT", `${insertedUrl}/-rev/1`, JSON.stringify(insertedBody)).status === 400,
    "client-inserted version with another version's local link refuses before PUT");
  h.expect(referenceRequest("PUT", `${insertedUrl}/-rev/1`, JSON.stringify(insertedBody), { encoding: "gzip" }).status === 400,
    "nonidentity revision encoding refuses before PUT");
  const tooDeep = JSON.stringify({ ...insertedBody, nested: Array(129).fill(0).reduce((value) => [value], 0) });
  h.expect(referenceRequest("PUT", `${insertedUrl}/-rev/1`, tooDeep).status === 400,
    "129-level revision JSON refuses before PUT");
  h.expect((await h.fakes.requests("registry.npmjs.org")).filter(r => r.method === "PUT" && r.path.startsWith(`/${inserted}/-rev/`)).length === beforeInserted,
    "inserted local link, encoding and depth failures make zero upstream writes");

  const changedScope = h.unique("action-changed-scope");
  await h.fakes.publishNpm({ name: changedScope, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${changedScope}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: changedScope, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const changedUrl = `https://fw1.e2e.test/registry/npm/${id}/${changedScope}`;
  const changedBody = JSON.parse(referenceRequest("GET", `${changedUrl}?write=true`).body);
  const changedLink = changedBody.versions["1.0.0"].dist.tarball;
  delete changedBody.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${changedUrl}/-rev/1`, JSON.stringify(changedBody)).status === 201,
    "selected upstream accepts removal before scope changes");
  const removeScope = await admin.portal.post(`/org/${org}/registries/${id}/delete-scope`, {
    csrf: hidden(scopeCatalog.body, "csrf"), origin: "https://registry-b.e2e.test", path_prefix: "/extra/case", remove: "on",
  });
  h.expect(removeScope.status === 303, "administrator removes the approved extra-origin scope");
  const beforeScope = (await h.fakes.requests("registry-b.e2e.test")).length;
  h.expect(referenceRequest("DELETE", `${changedLink}/-rev/2`).status >= 400,
    "removed extra-origin approval refuses old lease before outbound");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeScope,
    "removed approval makes no extra-origin call");
  const narrowerScope = await admin.portal.post(`/org/${org}/registries/${id}/delete-scope`, {
    csrf: hidden(scopeCatalog.body, "csrf"), origin: "https://registry-b.e2e.test", path_prefix: "/extra/other", forward_bearer: "on",
  });
  h.expect(narrowerScope.status === 303, "administrator saves a different path scope");
  h.expect(referenceRequest("DELETE", `${changedLink}/-rev/2`).status >= 400,
    "changed path scope cannot authorize old lease");
  h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeScope,
    "changed path scope makes no extra-origin call");
  const restoredScope = await admin.portal.post(`/org/${org}/registries/${id}/delete-scope`, {
    csrf: hidden(scopeCatalog.body, "csrf"), origin: "https://registry-b.e2e.test", path_prefix: "/extra/case", forward_bearer: "on",
  });
  h.expect(restoredScope.status === 303, "administrator restores the exact approved deletion scope");
  h.expect(referenceRequest("DELETE", `${changedLink}/-rev/2`).status === 200,
    "still-live accepted marker works only after exact approval returns");

  const keyName = h.unique("action-key-restore");
  await h.fakes.publishNpm({ name: keyName, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${keyName}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: keyName, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const keyUrl = `https://fw1.e2e.test/registry/npm/${id}/${keyName}`;
  const keyBody = JSON.parse(referenceRequest("GET", `${keyUrl}?write=true`).body);
  const keyLink = keyBody.versions["1.0.0"].dist.tarball;
  delete keyBody.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${keyUrl}/-rev/1`, JSON.stringify(keyBody)).status === 201,
    "key-loss fixture has an upstream-accepted removal");
  const keyPath = "/var/lib/probation/npm-unpublish.key";
  const backedUpKey = h.stack.exec("firewall-1", ["mv", keyPath, `${keyPath}.e2e-backup`]);
  if (backedUpKey.status !== 0) {
    const files = h.stack.exec("firewall-1", ["ls", "-la", "/var/lib/probation"]);
    h.log(`data-key backup diagnostic: status=${backedUpKey.status} stderr=${backedUpKey.stderr.trim()} files=${files.stdout.trim()}`);
  }
  h.expect(backedUpKey.status === 0, `restart-stable data key is backed up on disk: ${backedUpKey.stderr.trim()}`);
  try {
    const beforeKey = (await h.fakes.requests("registry-b.e2e.test")).length;
    h.expect(referenceRequest("DELETE", `${keyLink}/-rev/2`).status >= 400,
      "missing data key refuses sealed lease without a plaintext fallback");
    h.expect(referenceRequest("GET", `${keyUrl}?write=true`).status >= 400,
      "missing data key refuses a fresh write-preflight lease");
    h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeKey,
      "missing key makes no extra-origin call");
    h.expect(h.stack.exec("firewall-1", ["sh", "-c", `printf bad > ${keyPath}`]).status === 0,
      "corrupt data key installed for rejection witness");
    h.expect(referenceRequest("DELETE", `${keyLink}/-rev/2`).status >= 400,
      "corrupt data key refuses sealed lease");
    h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeKey,
      "corrupt key makes no extra-origin call");
  } finally {
    h.stack.exec("firewall-1", ["rm", "-f", keyPath]);
    h.expect(h.stack.exec("firewall-1", ["mv", `${keyPath}.e2e-backup`, keyPath]).status === 0,
      "original data key restored from disk backup");
  }
  h.expect(referenceRequest("DELETE", `${keyLink}/-rev/2`).status === 200,
    "restored key opens the original signed destination and accepted marker");

  const redirectedDelete = h.unique("action-delete-redirect");
  await h.fakes.publishNpm({ name: redirectedDelete, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${redirectedDelete}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: redirectedDelete, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const redirectUrl = `https://fw1.e2e.test/registry/npm/${id}/${redirectedDelete}`;
  const redirectBody = JSON.parse(referenceRequest("GET", `${redirectUrl}?write=true`).body);
  const redirectLink = redirectBody.versions["1.0.0"].dist.tarball;
  delete redirectBody.versions["1.0.0"];
  h.expect(referenceRequest("PUT", `${redirectUrl}/-rev/1`, JSON.stringify(redirectBody)).status === 201,
    "redirect fixture has an upstream-accepted removal");
  await h.fakes.faults([{ host: "registry-b.e2e.test", path: `/extra/case/${redirectedDelete}-1.0.0.tgz/-rev/2`,
    method: "DELETE", mode: "redirect", location: "https://foreign.e2e.test/escape", times: 1 }]);
  try {
    h.expect(referenceRequest("DELETE", `${redirectLink}/-rev/2`).status === 502,
      "extra-origin credential-bearing DELETE refuses a redirect");
    const redirects = (await h.fakes.requests("registry-b.e2e.test")).filter(r => r.method === "DELETE"
      && r.path.startsWith(`/extra/case/${redirectedDelete}-1.0.0.tgz/`));
    h.expect(redirects.length === 1 && redirects[0].fault === "redirect" && redirects[0].credential === "developer-owner",
      "DELETE makes exactly one authenticated request to the approved peer");
    h.expect(referenceRequest("DELETE", `${redirectLink}/-rev/2`).status === 404,
      "redirected DELETE consumes its attempt and cannot replay");
  } finally {
    await h.fakes.faults([]);
  }

  const uncertainName = h.unique("action-uncertain-revision");
  await h.fakes.publishNpm({ name: uncertainName, version: "1.0.0", ageSeconds: 400 * 86_400,
    tarballUrl: `https://registry-b.e2e.test/extra/case/${uncertainName}-1.0.0.tgz?sig=d41-signed-secret` });
  await h.fakes.publishNpm({ name: uncertainName, version: "2.0.0", ageSeconds: 400 * 86_400 });
  const uncertainUrl = `https://fw1.e2e.test/registry/npm/${id}/${uncertainName}`;
  const uncertainBody = JSON.parse(referenceRequest("GET", `${uncertainUrl}?write=true`).body);
  const uncertainLink = uncertainBody.versions["1.0.0"].dist.tarball;
  delete uncertainBody.versions["1.0.0"];
  await h.fakes.faults([{ host: "registry.npmjs.org", path: `/${uncertainName}/-rev/1`, method: "PUT",
    mode: "json", status: 201, body: { ok: true }, times: 1 }]);
  try {
    const uncertainPut = referenceRequest("PUT", `${uncertainUrl}/-rev/1`, JSON.stringify(uncertainBody));
    h.expect(uncertainPut.status === 503,
      "accepted revision PUT without verifiable resulting rev reports uncertain partial write");
    const beforeUncertain = (await h.fakes.requests("registry-b.e2e.test")).length;
    h.expect(referenceRequest("DELETE", `${uncertainLink}/-rev/2`).status === 404,
      "unverifiable resulting revision creates no deletion marker");
    h.expect((await h.fakes.requests("registry-b.e2e.test")).length === beforeUncertain,
      "unverifiable revision allows no extra-origin DELETE");
  } finally {
    await h.fakes.faults([]);
  }

  const configPath = join(h.stack.work, "firewall-1.toml");
  const originalConfig = readFileSync(configPath, "utf8");
  try {
    writeFileSync(configPath, originalConfig.replace(/^max_artifact_bytes = .*$/m, "max_artifact_bytes = 1048576"));
    h.stack.restart("firewall-1");
    await h.stack.firewallReady("fw1");
    const oversizedName = h.unique("too-large");
    const oversizedScript = `import https from "node:https"; import {readFileSync} from "node:fs";
const req=https.request(process.argv[2],{method:"PUT",ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem"),headers:{authorization:"Bearer e2e-owner","content-type":"application/json",...(process.argv[3]==="declared"?{"content-length":1048577}:{})}},res=>{res.resume();res.on("end",()=>console.log(res.statusCode));});req.on("error",e=>{console.error(e);process.exitCode=2});req.end(process.argv[3]==="declared"?undefined:Buffer.alloc(1048577,65));`;
    const oversized = h.client("client-npm", `node oversized.mjs 'https://fw1.e2e.test/registry/npm/${id}/${oversizedName}'`, {
      files: { "oversized.mjs": oversizedScript },
    });
    h.expect(oversized.status === 0 && oversized.stdout.trim() === "413",
      `chunked B+1 publish is rejected with 413: ${oversized.stderr} ${oversized.stdout}`);
    h.expect(!(await h.fakes.requests("registry.npmjs.org")).some(r => r.path === `/${oversizedName}`),
      "oversized chunked publish makes no upstream write");
    const declared = h.client("client-npm", `node oversized.mjs 'https://fw1.e2e.test/registry/npm/${id}/${oversizedName}' declared`, {
      files: { "oversized.mjs": oversizedScript },
    });
    h.expect(declared.status === 0 && declared.stdout.trim() === "413",
      `declared B+1 publish is rejected before upload: ${declared.stderr} ${declared.stdout}`);
  } finally {
    writeFileSync(configPath, originalConfig);
    h.stack.restart("firewall-1");
    await h.stack.firewallReady("fw1");
  }

  const registryUrl = `https://fw1.e2e.test/registry/npm/${id}/`;
  const namedProbes = [
    ["N14 access", `npm access get status @e2e/scoped --registry=${registryUrl}`, "/-/package/@e2e%2fscoped/visibility"],
    ["N15 team", `npm team ls @e2e:ops --registry=${registryUrl}`, "/-/team/e2e/ops/user"],
    ["N18 org", `npm org ls @e2e --registry=${registryUrl}`, "/-/org/e2e/user"],
    ["N19 profile", `npm profile get --registry=${registryUrl}`, "/-/npm/v1/user"],
    ["N20 token", `npm token list --registry=${registryUrl}`, "/-/npm/v1/tokens"],
    ["N21 stars", `npm stars e2e-owner --registry=${registryUrl}`, "/-/_view/starredByUser"],
    ["N22 stage", `npm stage list --registry=${registryUrl}`, "/-/stage"],
    ["N23 trust", `npm trust list ${name} --registry=${registryUrl}`, `/-/package/${name}/trust`],
  ];
  const namedOutcomes = [];
  for (const [row, command, path] of namedProbes) {
    const result = h.client("client-npm", command);
    const requests = await h.fakes.requests("registry.npmjs.org");
    namedOutcomes.push({ row, status: result.status, path,
      reached: requests.some(request => decodeURIComponent(request.path).startsWith(decodeURIComponent(path))
        && request.credential === "developer-owner"),
      stderr: result.stderr.slice(-350) });
  }
  h.expect(namedOutcomes.every(result => result.reached),
    `pinned npm account commands reach only their selected upstream: ${JSON.stringify(namedOutcomes)}`);
  const checked = (label, command, expected = 0) => {
    const result = h.client("client-npm", `timeout 25s ${command}`);
    h.expect(result.status === expected, `${label}: exit ${result.status}, ${result.stderr.slice(-400)}`);
    return result;
  };
  checked("access mutation", `npm access set status=private @e2e/scoped --registry=${registryUrl}`);
  h.expect(checked("access read after change", `npm access get status @e2e/scoped --registry=${registryUrl}`).stdout.includes("private"),
    "access status change is visible at selected upstream");
  checked("team add", `npm team add @e2e:ops e2e-teammate --registry=${registryUrl}`);
  h.expect(checked("team read after add", `npm team ls @e2e:ops --registry=${registryUrl}`).stdout.includes("e2e-teammate"),
    "team member change is visible at selected upstream");
  checked("team remove", `npm team rm @e2e:ops e2e-teammate --registry=${registryUrl}`);
  checked("org add", `npm org set @e2e e2e-teammate developer --registry=${registryUrl}`);
  h.expect(checked("org read after add", `npm org ls @e2e --registry=${registryUrl}`).stdout.includes("e2e-teammate"),
    "org member change is visible at selected upstream");
  checked("org remove", `npm org rm @e2e e2e-teammate --registry=${registryUrl}`);
  checked("profile set", `npm profile set email updated@example.test --registry=${registryUrl}`);
  h.expect(checked("profile read after set", `npm profile get email --registry=${registryUrl}`).stdout.includes("updated@example.test"),
    "profile change is visible at selected upstream");
  checked("token create", `npm token create --password=e2e-password --json --registry=${registryUrl}`);
  h.expect(checked("token list after create", `npm token list --json --registry=${registryUrl}`).stdout.includes("fake-token-key-1"),
    "created token appears at selected upstream");
  checked("token revoke", `npm token revoke fake-token-key-1 --registry=${registryUrl}`);
  h.expect(!(await h.fakes.requests("registry.npmjs.org")).some(request => request.path.includes("fake-token-secret-1")),
    "created token secret is absent from upstream request paths and test request log");
  checked("star package", `npm star ${name} --registry=${registryUrl}`);
  h.expect(checked("star list", `npm stars e2e-owner --registry=${registryUrl}`).stdout.includes(name),
    "star mutation appears in selected upstream list");
  checked("dist-tag remove", `npm dist-tag rm ${name} stable --registry=${registryUrl}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(request => request.method === "DELETE"
    && request.path === `/-/package/${name}/dist-tags/stable` && request.credential === "developer-owner"),
    "dist-tag removal reaches selected upstream with developer token");
  checked("owner remove", `npm owner rm e2e-teammate ${name} --registry=${registryUrl}`);
  checked("stage list upstream refusal", `npm stage list --registry=${registryUrl}`, 1);
  checked("trust list upstream refusal", `npm trust list ${name} --registry=${registryUrl}`, 1);
  const stageProject = h.unique("stage-project");
  const stageName = h.unique("stage-package");
  const stagePublish = h.client("client-npm", `timeout 25s npm stage publish --registry=${registryUrl}`, {
    dir: `/work/${stageProject}`, files: { "package.json": JSON.stringify({ name: stageName, version: "1.0.0" }), "index.js": "module.exports = 1;\n" },
  });
  h.expect(stagePublish.status !== 0, "unsupported selected upstream refuses npm stage publish");
  const stageId = "00000000-0000-4000-8000-000000000001";
  checked("stage approve upstream refusal", `npm stage approve ${stageId} --registry=${registryUrl}`, 1);
  checked("stage reject upstream refusal", `npm stage reject ${stageId} --registry=${registryUrl}`, 1);
  checked("trust revoke upstream refusal", `npm trust revoke ${name} --id=missing --registry=${registryUrl}`, 1);
  const unsupported = await h.fakes.requests("registry.npmjs.org");
  for (const [method, path] of [["POST", `/-/stage/package/${stageName}`],
    ["POST", `/-/stage/${stageId}/approve`], ["DELETE", `/-/stage/${stageId}`],
    ["DELETE", `/-/package/${name}/trust/missing`]]) {
    h.expect(unsupported.some(request => request.method === method && request.path === path
      && request.status === 404 && request.credential === "developer-owner"),
    `selected upstream explicitly refuses unsupported ${method} ${path}`);
  }
  const deniedName = h.unique("denied-publish");
  const denied = h.client("client-npm", `timeout 25s npm publish --ignore-scripts --registry=${registryUrl}`, {
    files: { "package.json": JSON.stringify({ name: deniedName, version: "1.0.0" }),
      ".npmrc": `//fw1.e2e.test/registry/npm/${id}/:_authToken=e2e-denied\n` },
  });
  h.expect(denied.status !== 0, "upstream denied publisher cannot publish");
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(request => request.method === "PUT"
    && request.path === `/${deniedName}` && request.status === 403 && request.credential === "developer-denied"),
    "denied publish reaches selected upstream once with denied developer token");
  const restoreClient = () => {
    h.expect(h.stack.exec("client-npm", ["sh"], { input: bundle.body }).status === 0,
      "client selected registry and TLS settings restored after npm logout");
    if (organizationIssued) installIssuerLeaf(h, "client-npm", issuerLeaf);
  };
  checked("logout", `npm logout --registry=${registryUrl}`);
  restoreClient();
  checked("fresh whoami after logout", `npm whoami --registry=${registryUrl}`, 1);
  const webLogin = h.client("client-npm", `timeout 25s npm login --registry=${registryUrl}`);
  const loginTrace = (await h.fakes.requests("registry.npmjs.org"))
    .filter((request) => request.path.includes("/-/v1/login"))
    .map(({ method, status }) => ({ method, status }));
  h.expect(webLogin.status === 0,
    `default web login: exit ${webLogin.status}, stderr=${webLogin.stderr.slice(-400)}, stdout-bytes=${webLogin.stdout.length}, trace=${JSON.stringify(loginTrace)}`);
  checked("whoami after web login", `npm whoami --registry=${registryUrl}`);
  checked("logout after web login", `npm logout --registry=${registryUrl}`);
  restoreClient();
  const legacy = h.client("client-npm", `{ printf 'e2e-owner\\n'; sleep 1; printf 'e2e-password\\n'; } | timeout 25s npm login --auth-type=legacy --registry=${registryUrl}`);
  h.expect(legacy.status === 0, `legacy login completes on selected URL: ${legacy.status} ${legacy.stderr.slice(-350)}`);
  h.expect((await h.fakes.requests("registry.npmjs.org")).some(request => request.method === "PUT"
    && decodeURIComponent(request.path).startsWith("/-/user/org.couchdb.user:e2e-owner")
    && request.status === 201 && ["none", "other"].includes(request.credential)),
    "legacy login PUT reaches only the selected upstream without a developer bearer token");
  checked("whoami after legacy login", `npm whoami --registry=${registryUrl}`);

  const actionHome = h.stack.exec("client-npm", ["sh", "-c", "printf '%s' \"$HOME\""]);
  h.log(`npm-actions client HOME before action probe: ${JSON.stringify(actionHome.stdout)}`);
  const actionProbe = `import https from "node:https"; import {readFileSync} from "node:fs";
const req=https.request(process.argv[2], {method:"GET",ca:readFileSync("/e2e/ca/ca.pem"),cert:readFileSync(process.env.HOME+"/.config/probation/client-cert.pem"),key:readFileSync(process.env.HOME+"/.config/probation/client-key.pem"),headers:{authorization:"Bearer e2e-owner",...(process.env.HEADER_BYTES?{"x-fill":"x".repeat(Number(process.env.HEADER_BYTES))}:{})}},res=>{let bytes=0;res.on("data",part=>bytes+=part.length);res.on("end",()=>console.log(JSON.stringify({status:res.statusCode,bytes})));});req.on("error",e=>{console.error(e);process.exitCode=2});req.end();`;
  const probeAction = (env = "") => {
    const result = h.client("client-npm", `${env} node action-probe.mjs '${registryUrl}-/npm/v1/user'`,
      { files: { "action-probe.mjs": actionProbe } });
    h.expect(result.status === 0, `action probe completes: ${result.stderr}`);
    return JSON.parse(result.stdout.trim());
  };
  const boundsConfig = readFileSync(configPath, "utf8");
  const clearFaults = async () => {
    try {
      await h.fakes.faults([]);
    } catch (error) {
      if (!String(error).includes("socket hang up")) throw error;
      // The harness reuses a bridge tunnel that can have closed during the
      // intentional 30-second stall. A fresh idempotent control call is safe.
      await h.fakes.faults([]);
    }
  };
  try {
    writeFileSync(configPath, boundsConfig.replace(/^max_metadata_bytes = .*$/m, "max_metadata_bytes = 4096")
      .replace(/^max_active_requests = .*$/m, "max_active_requests = 1"));
    h.stack.restart("firewall-1");
    await h.stack.firewallReady("fw1");
    const boundedRevision = h.unique("action-bounded-revision");
    await h.fakes.publishNpm({ name: boundedRevision, version: "1.0.0", ageSeconds: 400 * 86_400,
      tarballUrl: `https://registry-b.e2e.test/extra/case/${boundedRevision}-1.0.0.tgz?sig=d41-signed-secret&pad=${"x".repeat(1000)}` });
    await h.fakes.publishNpm({ name: boundedRevision, version: "2.0.0", ageSeconds: 400 * 86_400 });
    const boundedUrl = `https://fw1.e2e.test/registry/npm/${id}/${boundedRevision}`;
    const boundedRead = referenceRequest("GET", `${boundedUrl}?write=true`);
    h.expect(boundedRead.status === 200, "bounded write preflight succeeds before revision M+1 checks");
    const boundedBody = JSON.parse(boundedRead.body);
    const beforeBounded = (await h.fakes.requests("registry.npmjs.org"))
      .filter(r => r.method === "PUT" && r.path.startsWith(`/${boundedRevision}/-rev/`)).length;
    h.expect(referenceRequest("PUT", `${boundedUrl}/-rev/1`, JSON.stringify({ ...boundedBody, padding: "x".repeat(4097) })).status >= 400,
      "M+1 revision input refuses before upstream PUT");
    const emptyPaddedSize = Buffer.byteLength(JSON.stringify({ ...boundedBody, padding: "" }));
    h.expect(emptyPaddedSize < 4080, "bounded revision fixture leaves room for client padding");
    const nearLimit = JSON.stringify({ ...boundedBody, padding: "x".repeat(4080 - emptyPaddedSize) });
    h.expect(Buffer.byteLength(nearLimit) === 4080, "client revision body is below M");
    h.expect(referenceRequest("PUT", `${boundedUrl}/-rev/1`, nearLimit).status >= 400,
      "restored exact upstream tarball URLs exceeding M refuse before upstream PUT");
    h.expect((await h.fakes.requests("registry.npmjs.org"))
      .filter(r => r.method === "PUT" && r.path.startsWith(`/${boundedRevision}/-rev/`)).length === beforeBounded,
      "M+1 input and rendered output cause zero upstream revision writes");
    await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/user", method: "GET",
      mode: "oversize", bytes: 4097, times: 1 }]);
    const oversizedAction = probeAction();
    h.expect(oversizedAction.status === 502 && oversizedAction.bytes < 4097,
      `M+1 action response refuses before a complete client body: ${JSON.stringify(oversizedAction)}`);
    await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/user", method: "GET",
      mode: "redirect", location: "https://registry.npmjs.org/-/npm/v1/user", times: 1 }]);
    h.expect(probeAction().status === 502,
      "credential-bearing action redirect refuses before following its Location");
    const actionRedirects = (await h.fakes.requests("registry.npmjs.org"))
      .filter(request => request.path === "/-/npm/v1/user" && request.fault === "redirect");
    h.expect(actionRedirects.length === 1 && actionRedirects[0].credential === "developer-owner",
      "action redirect makes exactly one authenticated upstream request");
    await clearFaults();
    const beforeHeader = (await h.fakes.requests("registry.npmjs.org")).length;
    h.expect(probeAction("HEADER_BYTES=65537").status === 431,
      "64 KiB+1 action header is refused with 431");
    h.expect((await h.fakes.requests("registry.npmjs.org")).length === beforeHeader,
      "oversized action header causes no upstream request");
    await h.fakes.faults([{ host: "registry.npmjs.org", path: "/-/npm/v1/user", method: "GET",
      mode: "stall", afterBytes: 1, times: 1 }]);
    const priorTimeouts = (h.stack.logs("firewall-1").match(/UPSTREAM_TIMEOUT/g) ?? []).length;
    const slowStarted = Date.now();
    const slowRun = h.client("client-npm", `node action-probe.mjs '${registryUrl}-/npm/v1/user'`,
      { files: { "action-probe.mjs": actionProbe } });
    const slowStatus = slowRun.status === 0 ? JSON.parse(slowRun.stdout.trim()).status : null;
    h.expect((slowStatus === 504 || (slowStatus === null && slowRun.stderr.includes("socket hang up")))
      && Date.now() - slowStarted < 45_000,
    `stalled action response ends within the deadline: ${slowRun.status} ${slowRun.stderr}`);
    await h.waitFor("firewall action upstream timeout", async () =>
      (h.stack.logs("firewall-1").match(/UPSTREAM_TIMEOUT/g) ?? []).length > priorTimeouts,
    { timeout: 15_000, every: 500 });
    await clearFaults();
    h.expect(probeAction().status === 200, "timed-out action releases its active request permit");
    writeFileSync(configPath, boundsConfig.replace(/^max_references_per_project = .*$/m,
      "max_references_per_project = 2"));
    h.stack.restart("firewall-1");
    await h.stack.firewallReady("fw1");
    const overRefs = h.unique("action-ref-cap");
    for (const version of ["1.0.0", "2.0.0", "3.0.0"]) {
      await h.fakes.publishNpm({ name: overRefs, version, ageSeconds: 400 * 86_400 });
    }
    h.expect(referenceRequest("GET", `https://fw1.e2e.test/registry/npm/${id}/${overRefs}?write=true`).status >= 400,
      "max_references_per_project+1 preflight refuses before advertising any local lease");
  } finally {
    await clearFaults();
    writeFileSync(configPath, boundsConfig);
    h.stack.restart("firewall-1");
    await h.stack.firewallReady("fw1");
  }
}
