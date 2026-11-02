// Release aggregation runs the actual client scenarios and records assertions that
// completed. Every required row must be observed in every certificate mode. Missing
// witnesses fail the scenario; a source file or an attempted command is not a pass.
import certificateNpm from "./publishing-certificate-npm.mjs";
import certificateScale from "./publishing-certificate-scale.mjs";
import enterpriseRegistry from "./publishing-enterprise-registry.mjs";
import npmActions from "./publishing-npm-actions.mjs";
import npmActionsIssuer from "./publishing-npm-actions-issuer.mjs";
import npmRead from "./publishing-npm-read.mjs";
import npmReadIssuer from "./publishing-npm-read-issuer.mjs";
import privateRead from "./publishing-private-read.mjs";
import python from "./publishing-python.mjs";
import pythonIssuer from "./publishing-python-issuer.mjs";
import ssoPython from "./publishing-sso-python.mjs";
import uv from "./publishing-uv.mjs";
import uvIssuer from "./publishing-uv-issuer.mjs";
import { helpers } from "../harness/helpers.mjs";
import { ops } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-publishing-full-matrix",
  title: "complete selected-registry client, certificate, and egress matrix",
  suites: ["release"],
};

export const ROWS = [
  "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N09", "N10", "N11", "N12",
  "N13", "N14", "N15", "N16", "N17", "N18", "N19", "N20", "N21", "N22", "N23",
  "P01", "P02", "P03", "P04", "P05", "U01", "U02",
  "X01", "X02", "X03", "X04", "X05", "X06", "X07", "X08", "X09", "X10", "X11",
];
export const MODES = ["probation-enabled", "probation-disabled", "organization-issued"];

const runners = [
  ["certificate-npm", certificateNpm, "probation-enabled"],
  ["enterprise-registry", enterpriseRegistry, "organization-issued"],
  ["npm-actions", npmActions, "probation-enabled"],
  ["npm-read", npmRead, "probation-enabled"],
  ["npm-actions-disabled", (h) => npmActions(h, { selfServiceDisabled: true }), "probation-disabled"],
  ["npm-read-disabled", (h) => npmRead(h, { selfServiceDisabled: true }), "probation-disabled"],
  ["private-read", privateRead, "probation-enabled"],
  ["python", python, "probation-enabled"],
  ["uv", uv, "probation-enabled"],
  ["python-disabled", (h) => python(h, { selfServiceDisabled: true }), "probation-disabled"],
  ["uv-disabled", (h) => uv(h, { selfServiceDisabled: true }), "probation-disabled"],
  ["python-issuer", pythonIssuer, "organization-issued"],
  ["uv-issuer", uvIssuer, "organization-issued"],
  ["npm-actions-issuer", npmActionsIssuer, "organization-issued"],
  ["npm-read-issuer", npmReadIssuer, "organization-issued"],
  ["sso-python-enabled", (h) => ssoPython(h, { mode: "probation-enabled" }), "probation-enabled"],
  ["sso-python-disabled", (h) => ssoPython(h, { mode: "probation-disabled" }), "probation-disabled"],
  ["sso-python-issuer", (h) => ssoPython(h, { mode: "organization-issued" }), "organization-issued"],
  ["certificate-scale", certificateScale, "organization-issued"],
];

const PACKAGE_HOSTS = new Set(["registry.npmjs.org", "registry-b.e2e.test", "private-registry.e2e.test", "pypi.org", "files.pythonhosted.org"]);
const CONTROL_HOSTS = new Set(["api.osv.dev", "api.pwnedpasswords.com", "idp.e2e.test", "accounts.google.com", "fakes.e2e.test", "ocsp-a.e2e.test", "ocsp-b.e2e.test", "private-ocsp.e2e.test"]);
const CLIENTS = ["client-npm", "client-pip", "client-twine", "client-uv"];

function unknownFixtureHosts(trace) {
  return trace.filter((request) => !PACKAGE_HOSTS.has(request.host) && !CONTROL_HOSTS.has(request.host));
}

function currentFirewallPeers(stack) {
  const peers = new Set();
  const engine = ops({ stack });
  for (const service of ["firewall-1", "firewall-2", "firewall-standalone"]) {
    try {
      const networks = engine.inspect(engine.id(service)).NetworkSettings.Networks;
      for (const [network, attached] of Object.entries(networks)) {
        if ((network === `${stack.project}_e2e` || network === `${stack.project}_private`) && attached.IPAddress) {
          peers.add(attached.IPAddress);
        }
      }
    } catch { /* A stopped firewall has no current address. */ }
  }
  return peers;
}

async function assertEgress(h, peers, scenario) {
  const engine = ops(h);
  for (const service of CLIENTS) {
    const networks = Object.keys(engine.inspect(engine.id(service)).NetworkSettings.Networks);
    h.expect(networks.length === 1 && networks[0] === `${h.stack.project}_clients`,
      `${scenario}: ${service} is attached only to the internal client network`);
  }
  const inventory = await h.fakes.requests();
  const unlisted = unknownFixtureHosts(inventory);
  h.expect(unlisted.length === 0,
    `${scenario}: complete fake request inventory has no unlisted upstream host: ${JSON.stringify(unlisted.map(({ host, method, path, peer }) => ({ host, method, path, peer })))}`);
  const trace = inventory.filter((request) => PACKAGE_HOSTS.has(request.host));
  const bridge = engine.inspect(engine.id("bridge")).NetworkSettings.Networks[`${h.stack.project}_e2e`]?.IPAddress;
  h.expect(bridge, `${scenario}: the host fixture bridge has an inspected e2e address`);
  h.expect(unknownFixtureHosts([
    { host: "unlisted-cdn.e2e.test", method: "GET", path: "/package.tgz", peer: bridge },
    { host: "unlisted-cdn.e2e.test", method: "GET", path: "/package.tgz", peer: "198.51.100.9" },
  ]).length === 2,
  `${scenario}: unknown CDN host negative controls reject both bridge and direct-client peers`);
  const fromBridge = trace.filter((request) => request.peer?.replace(/^::ffff:/, "") === bridge);
  const actionFixtureRead = (request) => request.host === "registry.npmjs.org"
    && request.method === "GET"
    && /^\/action-ordinary-revision-link-[0-9a-f]{8}\?e2e-fixture=(before|after)$/.test(request.path)
    && request.credential === "none";
  const actionMode = ["npm-actions", "npm-actions-disabled", "npm-actions-issuer"].includes(scenario);
  const phases = fromBridge.map((request) => request.path.match(/e2e-fixture=(before|after)$/)?.[1]);
  const fixturePackages = fromBridge.map((request) => request.path.split("?")[0]);
  h.expect(fromBridge.length === (actionMode ? 2 : 0) && fromBridge.every(actionFixtureRead)
    && (!actionMode || (phases.join(",") === "before,after" && fixturePackages[0] === fixturePackages[1])),
    `${scenario}: only the two exact no-credential host fixture packument GETs use inspected bridge ${bridge}: ${JSON.stringify(fromBridge.map(({ host, method, path, credential }) => ({ host, method, path, credential })))}`);
  const throughFirewall = trace.filter((request) => request.peer?.replace(/^::ffff:/, "") !== bridge);
  const unknown = throughFirewall.filter((request) => !peers.has(request.peer?.replace(/^::ffff:/, "")));
  h.expect(throughFirewall.length > 0 && unknown.length === 0,
    `${scenario}: ${throughFirewall.length} package upstream requests have inspected firewall peers; unknown=${JSON.stringify(unknown.map(({ host, method, path, peer }) => ({ host, method, path, peer })))}; firewalls=${[...peers].join(",")}`);
  h.log(`${scenario}: ${throughFirewall.length} package upstream requests from inspected firewalls, ${fromBridge.length} exact host fixture reads`);
}

// A witness needs a passing assertion reached inside a real scenario. Client rows
// also require the named command to have executed there. Separate witnesses are
// needed for each certificate mode; they are never inferred from another mode.
const witnesses = [
  ["N01", "probation-enabled", "npm-read", /npm install through selected URL:/, /\bnpm install\b/],
  ["N02", "probation-enabled", "npm-read", /blocked package|group.hidden|too.new|policy filters/i, /\bnpm install\b/],
  ["N03", "probation-enabled", "npm-read", /npm search keeps the permitted hit/, /\bnpm search\b/],
  ["N04", "probation-enabled", "npm-read", /npm audit uses selected URL:/, /\bnpm audit\b/],
  ["N05", "probation-enabled", "npm-actions", /default web login: exit 0/, /\bnpm login\b/],
  ["N06", "probation-enabled", "npm-actions", /legacy login completes on selected URL:/, /\bnpm login --auth-type=legacy\b/],
  ["N07", "probation-enabled", "npm-read", /npm whoami uses selected URL:/, /\bnpm whoami\b/],
  ["N08", "probation-enabled", "npm-actions", /npm publish completes through selected URL:/, /\bnpm publish\b/],
  ["N09", "probation-enabled", "npm-actions", /denied publish reaches selected upstream once/, /\bnpm publish\b/],
  ["N10", "probation-enabled", "npm-actions", /owner deprecates group-hidden package/, /\bnpm deprecate\b/],
  ["N11", "probation-enabled", "npm-actions", /npm unpublish one version completes/, /\bnpm unpublish\b/],
  ["N12", "probation-enabled", "npm-actions", /dist-tag removal reaches selected upstream/, /\bnpm dist-tag\b/],
  ["N13", "probation-enabled", "npm-actions", /npm owner mutates selected package:/, /\bnpm owner\b/],
  ["N14", "probation-enabled", "npm-actions", /access status change is visible/, /\bnpm access\b/],
  ["N15", "probation-enabled", "npm-actions", /team member change is visible/, /\bnpm team\b/],
  ["N16", "probation-enabled", "npm-read", /lockfile contains only selected URL and no secrets/, /\bnpm install\b/],
  ["N17", "probation-enabled", "npm-actions", /fresh whoami after logout: exit 1/, /\bnpm logout\b/],
  ["N18", "probation-enabled", "npm-actions", /org member change is visible/, /\bnpm org\b/],
  ["N19", "probation-enabled", "npm-actions", /profile change is visible/, /\bnpm profile\b/],
  ["N20", "probation-enabled", "npm-actions", /created token appears at selected upstream/, /\bnpm token\b/],
  ["N21", "probation-enabled", "npm-actions", /star mutation appears in selected upstream list/, /\bnpm star\b/],
  ["N22", "probation-enabled", "npm-actions", /unsupported selected upstream refuses npm stage publish/, /\bnpm stage\b/],
  ["N23", "probation-enabled", "npm-actions", /trust list upstream refusal: exit 1/, /\bnpm trust\b/],
  ["N01", "probation-disabled", "npm-read-disabled", /npm install through selected URL:/, /\bnpm install\b/],
  ["N02", "probation-disabled", "npm-read-disabled", /blocked package|group.hidden|too.new|policy filters/i, /\bnpm install\b/],
  ["N03", "probation-disabled", "npm-read-disabled", /npm search keeps the permitted hit/, /\bnpm search\b/],
  ["N04", "probation-disabled", "npm-read-disabled", /npm audit uses selected URL:/, /\bnpm audit\b/],
  ["N05", "probation-disabled", "npm-actions-disabled", /default web login: exit 0/, /\bnpm login\b/],
  ["N06", "probation-disabled", "npm-actions-disabled", /legacy login completes on selected URL:/, /\bnpm login --auth-type=legacy\b/],
  ["N07", "probation-disabled", "npm-read-disabled", /npm whoami uses selected URL:/, /\bnpm whoami\b/],
  ["N08", "probation-disabled", "npm-actions-disabled", /npm publish completes through selected URL:/, /\bnpm publish\b/],
  ["N09", "probation-disabled", "npm-actions-disabled", /denied publish reaches selected upstream once/, /\bnpm publish\b/],
  ["N10", "probation-disabled", "npm-actions-disabled", /owner deprecates group-hidden package/, /\bnpm deprecate\b/],
  ["N11", "probation-disabled", "npm-actions-disabled", /npm unpublish one version completes/, /\bnpm unpublish\b/],
  ["N12", "probation-disabled", "npm-actions-disabled", /dist-tag removal reaches selected upstream/, /\bnpm dist-tag\b/],
  ["N13", "probation-disabled", "npm-actions-disabled", /npm owner mutates selected package:/, /\bnpm owner\b/],
  ["N14", "probation-disabled", "npm-actions-disabled", /access status change is visible/, /\bnpm access\b/],
  ["N15", "probation-disabled", "npm-actions-disabled", /team member change is visible/, /\bnpm team\b/],
  ["N16", "probation-disabled", "npm-read-disabled", /lockfile contains only selected URL and no secrets/, /\bnpm install\b/],
  ["N17", "probation-disabled", "npm-actions-disabled", /fresh whoami after logout: exit 1/, /\bnpm logout\b/],
  ["N18", "probation-disabled", "npm-actions-disabled", /org member change is visible/, /\bnpm org\b/],
  ["N19", "probation-disabled", "npm-actions-disabled", /profile change is visible/, /\bnpm profile\b/],
  ["N20", "probation-disabled", "npm-actions-disabled", /created token appears at selected upstream/, /\bnpm token\b/],
  ["N21", "probation-disabled", "npm-actions-disabled", /star mutation appears in selected upstream list/, /\bnpm star\b/],
  ["N22", "probation-disabled", "npm-actions-disabled", /unsupported selected upstream refuses npm stage publish/, /\bnpm stage\b/],
  ["N23", "probation-disabled", "npm-actions-disabled", /trust list upstream refusal: exit 1/, /\bnpm trust\b/],
  ["N05", "organization-issued", "npm-actions-issuer", /default web login: exit 0/, /\bnpm login\b/],
  ["N06", "organization-issued", "npm-actions-issuer", /legacy login completes on selected URL:/, /\bnpm login --auth-type=legacy\b/],
  ["N08", "organization-issued", "npm-actions-issuer", /npm publish completes through selected URL:/, /\bnpm publish\b/],
  ["N09", "organization-issued", "npm-actions-issuer", /denied publish reaches selected upstream once/, /\bnpm publish\b/],
  ["N10", "organization-issued", "npm-actions-issuer", /owner deprecates group-hidden package/, /\bnpm deprecate\b/],
  ["N11", "organization-issued", "npm-actions-issuer", /npm unpublish one version completes/, /\bnpm unpublish\b/],
  ["N12", "organization-issued", "npm-actions-issuer", /dist-tag removal reaches selected upstream/, /\bnpm dist-tag\b/],
  ["N13", "organization-issued", "npm-actions-issuer", /npm owner mutates selected package:/, /\bnpm owner\b/],
  ["N14", "organization-issued", "npm-actions-issuer", /access status change is visible/, /\bnpm access\b/],
  ["N15", "organization-issued", "npm-actions-issuer", /team member change is visible/, /\bnpm team\b/],
  ["N17", "organization-issued", "npm-actions-issuer", /fresh whoami after logout: exit 1/, /\bnpm logout\b/],
  ["N18", "organization-issued", "npm-actions-issuer", /org member change is visible/, /\bnpm org\b/],
  ["N19", "organization-issued", "npm-actions-issuer", /profile change is visible/, /\bnpm profile\b/],
  ["N20", "organization-issued", "npm-actions-issuer", /created token appears at selected upstream/, /\bnpm token\b/],
  ["N21", "organization-issued", "npm-actions-issuer", /star mutation appears in selected upstream list/, /\bnpm star\b/],
  ["N22", "organization-issued", "npm-actions-issuer", /unsupported selected upstream refuses npm stage publish/, /\bnpm stage\b/],
  ["N23", "organization-issued", "npm-actions-issuer", /trust list upstream refusal: exit 1/, /\bnpm trust\b/],
  ["N01", "organization-issued", "npm-read-issuer", /issuer npm install through selected URL:/, /\bnpm install\b/],
  ["N02", "organization-issued", "npm-read-issuer", /issuer npm blocked package is refused by policy:/, /\bnpm install\b/],
  ["N02", "organization-issued", "npm-read-issuer", /issuer npm accepted token sees canonical group-hidden packument:/, /\bnpm view\b/],
  ["N02", "organization-issued", "npm-read-issuer", /issuer npm accepted token cannot install group-hidden artifact:/, /\bnpm install\b/],
  ["N02", "organization-issued", "npm-read-issuer", /issuer npm ordinary registry holds new version while trusted registry skips only age delay/],
  ["N03", "organization-issued", "npm-read-issuer", /issuer npm view uses selected URL:/, /\bnpm view\b/],
  ["N03", "organization-issued", "npm-read-issuer", /issuer npm search keeps permitted hit:/, /\bnpm search\b/],
  ["N04", "organization-issued", "npm-read-issuer", /issuer npm audit uses selected URL:/, /\bnpm audit\b/],
  ["N04", "organization-issued", "npm-read-issuer", /issuer npm audit reaches selected upstream/],
  ["N04", "organization-issued", "npm-read-issuer", /issuer npm bulk and quick audit strip group-hidden metadata and arbitrary advisory text/],
  ["N07", "organization-issued", "npm-read-issuer", /issuer npm whoami uses selected URL:/, /\bnpm whoami\b/],
  ["N07", "organization-issued", "npm-read-issuer", /issuer npm ping uses selected URL:/, /\bnpm ping\b/],
  ["N16", "organization-issued", "npm-read-issuer", /issuer npm lockfile contains only selected URL and no secrets/, /\bnpm install\b/],
  ["P01", "probation-enabled", "python", /pip sdist install:/, /\bpip install\b/],
  ["P02", "probation-enabled", "python", /pip index versions:/, /\bpip index versions\b/],
  ["P03", "probation-enabled", "python", /Twine wheel and sdist upload succeeded/, /\btwine upload\b/],
  ["P04", "probation-enabled", "python", /upstream denied Twine upload:/, /\btwine upload\b/],
  ["P05", "probation-enabled", "python", /Python project files do not contain client key paths/, /\bpip install\b/],
  ["P01", "probation-disabled", "python-disabled", /pip sdist install:/, /\bpip install\b/],
  ["P02", "probation-disabled", "python-disabled", /pip index versions:/, /\bpip index versions\b/],
  ["P03", "probation-disabled", "python-disabled", /Twine wheel and sdist upload succeeded/, /\btwine upload\b/],
  ["P04", "probation-disabled", "python-disabled", /upstream denied Twine upload:/, /\btwine upload\b/],
  ["P05", "probation-disabled", "python-disabled", /Python project files do not contain client key paths/, /\bpip install\b/],
  ["P01", "organization-issued", "python-issuer", /pip sdist install:/, /\bpip install\b/],
  ["P02", "organization-issued", "python-issuer", /pip index versions:/, /\bpip index versions\b/],
  ["P03", "organization-issued", "python-issuer", /Twine wheel and sdist upload succeeded/, /\btwine upload\b/],
  ["P04", "organization-issued", "python-issuer", /upstream denied Twine upload:/, /\btwine upload\b/],
  ["P05", "organization-issued", "python-issuer", /Python project files do not contain client key paths/, /\bpip install\b/],
  ["U01", "probation-enabled", "uv", /uv\.lock contains selected nonsecret URL/, /\buv lock\b/],
  ["U02", "probation-enabled", "uv", /uv pip install:/, /\buv pip install\b/],
  ["U01", "probation-disabled", "uv-disabled", /uv\.lock contains selected nonsecret URL/, /\buv lock\b/],
  ["U02", "probation-disabled", "uv-disabled", /uv pip install:/, /\buv pip install\b/],
  ["U01", "organization-issued", "uv-issuer", /uv\.lock contains selected nonsecret URL/, /\buv lock\b/],
  ["U02", "organization-issued", "uv-issuer", /uv pip install:/, /\buv pip install\b/],
  ["X01", "probation-enabled", "enterprise-registry", /same-name artifacts return each registry's own bytes/],
  ["X01", "probation-disabled", "npm-read-disabled", /npm read same-name registries return distinct selected artifact bytes/],
  ["X01", "organization-issued", "npm-read-issuer", /issuer npm same-name registries return their own distinct selected artifact bytes/],
  ["X02", "probation-enabled", "certificate-npm", /removed member made zero upstream calls/],
  ["X02", "probation-enabled", "certificate-npm", /cross-account and missing certificate made zero upstream calls/],
  ["X02", "probation-enabled", "certificate-npm", /management outage refused before upstream/],
  ["X02", "probation-disabled", "sso-python-disabled", /removed SSO member selected npm and pip refusals made zero upstream calls/],
  ["X02", "probation-disabled", "sso-python-disabled", /different account selected npm and pip refusals made zero upstream calls/],
  ["X02", "probation-disabled", "npm-read-disabled", /management outage makes no upstream read/],
  ["X02", "organization-issued", "enterprise-registry", /first organization's valid leaf cannot select second registry/],
  ["X02", "organization-issued", "sso-python-issuer", /removed SSO member selected npm and pip refusals made zero upstream calls/],
  ["X02", "organization-issued", "sso-python-issuer", /different account selected npm and pip refusals made zero upstream calls/],
  ["X02", "organization-issued", "npm-read-issuer", /issuer npm management outage makes no selected upstream request/],
  ["X03", "probation-enabled", "enterprise-registry", /replacement registry selects its own new ID/],
  ["X03", "probation-enabled", "enterprise-registry", /registry target and ecosystem cannot change through an edit/],
  ["X03", "probation-disabled", "npm-read-disabled", /registry target cannot be changed in place/],
  ["X03", "probation-disabled", "npm-read-disabled", /removed registry ID refuses without falling back to A/],
  ["X03", "probation-disabled", "npm-read-disabled", /replacement registry gets a fresh ID and selected bytes/],
  ["X03", "organization-issued", "npm-read-issuer", /issuer npm target and ecosystem edit cannot change selected registry identity/],
  ["X03", "organization-issued", "npm-read-issuer", /issuer npm removed registry ID refuses before fallback to ordinary registry/],
  ["X03", "organization-issued", "npm-read-issuer", /issuer npm replacement registry gets a new ID without old artifact access/],
  ["X04", "probation-enabled", "npm-read", /credential-bearing packument redirect stops after one upstream request/],
  ["X04", "probation-enabled", "npm-actions", /action redirect makes exactly one authenticated upstream request/],
  ["X04", "probation-disabled", "npm-read-disabled", /credential-bearing packument redirect stops after one upstream request/],
  ["X04", "probation-disabled", "npm-actions-disabled", /action redirect makes exactly one authenticated upstream request/],
  ["X04", "organization-issued", "npm-read-issuer", /issuer npm credential-bearing packument redirect stops after one request without storage leak/],
  ["X04", "organization-issued", "npm-actions-issuer", /action redirect makes exactly one authenticated upstream request/],
  ["X05", "probation-enabled", "npm-read", /unknown route made no upstream call/],
  ["X05", "probation-enabled", "npm-read", /unknown HEAD route refuses/],
  ["X05", "probation-enabled", "npm-read", /alternate artifact path cannot bypass the reference and group guard/],
  ["X05", "probation-disabled", "npm-read-disabled", /unknown route made no upstream call/],
  ["X05", "probation-disabled", "npm-read-disabled", /unknown HEAD route refuses/],
  ["X05", "probation-disabled", "npm-read-disabled", /alternate artifact path cannot bypass the reference and group guard/],
  ["X05", "organization-issued", "npm-read", /enterprise unknown route refuses before selected upstream/],
  ["X05", "organization-issued", "npm-read-issuer", /issuer npm unknown GET route refuses/],
  ["X05", "organization-issued", "npm-read-issuer", /issuer npm unknown HEAD route refuses/],
  ["X05", "organization-issued", "npm-read-issuer", /issuer npm alternate artifact path cannot bypass group guard/],
  ["X05", "organization-issued", "npm-read-issuer", /issuer npm unknown and alternate artifact routes make zero upstream calls/],
  ["X07", "probation-enabled", "certificate-npm", /cross-account and missing certificate made zero upstream calls/],
  ["X07", "probation-enabled", "npm-read", /developer token without a certificate refuses before upstream/],
  ["X07", "probation-enabled", "npm-read", /accepted token sees hidden packument without a write/],
  ["X07", "probation-enabled", "certificate-npm", /disabled member's second certificate refuses/],
  ["X07", "probation-disabled", "npm-read-disabled", /developer token without a certificate refuses before upstream/],
  ["X07", "probation-disabled", "npm-read-disabled", /foreign certificate made no upstream read/],
  ["X07", "probation-disabled", "npm-read-disabled", /disabled member's enterprise and Probation certificates refuse the next read/],
  ["X07", "probation-disabled", "npm-read-disabled", /revoked enterprise leaf makes no upstream call/],
  ["X07", "probation-disabled", "npm-read-disabled", /accepted token sees hidden packument without a write/],
  ["X07", "probation-disabled", "sso-python-disabled", /different account selected npm and pip refusals made zero upstream calls/],
  ["X07", "organization-issued", "enterprise-registry", /second root cannot select first organization's registry/],
  ["X07", "organization-issued", "npm-read", /disabled member's enterprise and Probation certificates refuse the next read/],
  ["X07", "organization-issued", "npm-read", /revoked enterprise leaf makes no upstream call/],
  ["X07", "organization-issued", "npm-read-issuer", /issuer npm accepted token sees canonical group-hidden packument/],
  ["X07", "organization-issued", "sso-python-issuer", /different account selected npm and pip refusals made zero upstream calls/],
  ["X08", "probation-enabled", "certificate-npm", /disabled member's second certificate refuses/],
  ["X08", "probation-enabled", "certificate-npm", /targeted own-certificate revocation/],
  ["X08", "probation-disabled", "npm-read-disabled", /committed enterprise issuer revocation refuses the next read/],
  ["X08", "probation-disabled", "npm-read-disabled", /disabled member's enterprise and Probation certificates refuse the next read/],
  ["X08", "probation-disabled", "sso-python-disabled", /removed SSO member cannot use selected npm certificate/],
  ["X08", "organization-issued", "enterprise-registry", /committed revocation refuses the very next request/],
  ["X08", "organization-issued", "npm-read", /disabled member's enterprise and Probation certificates refuse the next read/],
  ["X09", "probation-enabled", "certificate-scale", /10000 distinct members enrolled by self-service:/],
  ["X09", "probation-enabled", "certificate-scale", /self-service-admission: 10000 distinct TLS identities admitted through package client/],
  ["X09", "probation-disabled", "certificate-scale", /disabled self-service creates no new certificate at 10,000 members/],
  ["X09", "organization-issued", "certificate-scale", /10,000 distinct members receive issuer leaves/],
  ["X09", "organization-issued", "certificate-scale", /organization-issuer-admission: 10000 distinct TLS identities admitted through package client/],
  ["X10", "probation-enabled", "certificate-npm", /signed-in member setup bundle:/],
  ["X10", "probation-enabled", "certificate-npm", /bundle installs user-local npm settings/],
  ["X10", "probation-enabled", "certificate-npm", /no private key in package project/],
  ["X10", "probation-enabled", "certificate-npm", /npm shell history contains no client key or publisher token/],
  ["X10", "probation-enabled", "certificate-npm", /npm setup key and publisher token are absent from service logs/],
  ["X10", "probation-enabled", "python", /Python project files do not contain client key paths or publisher token/],
  ["X10", "probation-enabled", "python", /Twine project files do not contain client key paths or publisher token/],
  ["X10", "probation-enabled", "python", /client-pip shell history contains no client key/],
  ["X10", "probation-enabled", "python", /client-twine shell history contains no client key/],
  ["X10", "probation-enabled", "python", /Python setup key and publisher token are absent from service logs/],
  ["X10", "probation-enabled", "uv", /uv\.lock contains selected nonsecret URL and no credential/],
  ["X10", "probation-enabled", "uv", /uv shell history contains no client key or publisher token/],
  ["X10", "probation-enabled", "uv", /uv setup key and publisher token are absent from service logs/],
  ["X10", "probation-disabled", "sso-python-disabled", /SSO Python disabled self-service issues no new bundle/],
  ["X10", "probation-disabled", "sso-python-disabled", /SSO npm project files contain no client key/],
  ["X10", "probation-disabled", "sso-python-disabled", /SSO npm shell history contains no client key/],
  ["X10", "probation-disabled", "sso-python-disabled", /SSO Python project files contain no client key/],
  ["X10", "probation-disabled", "sso-python-disabled", /SSO Python shell history contains no client key/],
  ["X10", "probation-disabled", "sso-python-disabled", /SSO Python service logs contain no client key or publisher token/],
  ["X10", "probation-disabled", "python-disabled", /Twine project files do not contain client key paths or publisher token/],
  ["X10", "probation-disabled", "python-disabled", /client-twine shell history contains no client key/],
  ["X10", "probation-disabled", "python-disabled", /Python setup key and publisher token are absent from service logs/],
  ["X10", "probation-disabled", "uv-disabled", /uv\.lock contains selected nonsecret URL and no credential/],
  ["X10", "probation-disabled", "uv-disabled", /uv shell history contains no client key or publisher token/],
  ["X10", "probation-disabled", "uv-disabled", /uv setup key and publisher token are absent from service logs/],
  ["X10", "organization-issued", "sso-python-issuer", /SSO Python organization issuer refuses a new self-service bundle/],
  ["X10", "organization-issued", "sso-python-issuer", /SSO npm project files contain no client key/],
  ["X10", "organization-issued", "sso-python-issuer", /SSO npm shell history contains no client key/],
  ["X10", "organization-issued", "sso-python-issuer", /SSO Python project files contain no client key/],
  ["X10", "organization-issued", "sso-python-issuer", /SSO Python shell history contains no client key/],
  ["X10", "organization-issued", "sso-python-issuer", /SSO Python service logs contain no client key or publisher token/],
  ["X10", "organization-issued", "python-issuer", /Twine project files do not contain client key paths or publisher token/],
  ["X10", "organization-issued", "python-issuer", /client-twine shell history contains no client key/],
  ["X10", "organization-issued", "python-issuer", /Python setup key and publisher token are absent from service logs/],
  ["X10", "organization-issued", "uv-issuer", /uv\.lock contains selected nonsecret URL and no credential/],
  ["X10", "organization-issued", "uv-issuer", /uv shell history contains no client key or publisher token/],
  ["X10", "organization-issued", "uv-issuer", /uv setup key and publisher token are absent from service logs/],
  ["X11", "probation-enabled", "sso-python-enabled", /SSO Python member signs in:/],
  ["X11", "probation-enabled", "sso-python-enabled", /SSO Python member downloads own noncached selected setup bundle/],
  ["X11", "probation-enabled", "sso-python-enabled", /SSO member npm installs selected allowed bytes/],
  ["X11", "probation-enabled", "sso-python-enabled", /SSO Python member pip installs selected allowed bytes/],
  ["X11", "probation-enabled", "sso-python-enabled", /SSO member's current group blocks npm package/],
  ["X11", "probation-enabled", "sso-python-enabled", /SSO Python member's current group blocks pip package/],
  ["X11", "probation-enabled", "sso-python-enabled", /different account receives its own distinct setup bundle/],
  ["X11", "probation-enabled", "sso-python-enabled", /removed SSO Python member cannot download another setup bundle/],
  ["X11", "probation-enabled", "sso-python-enabled", /removed SSO member selected npm and pip refusals made zero upstream calls/],
  ["X11", "probation-enabled", "certificate-npm", /disabled self-service refuses a new bundle/],
  ["X11", "probation-disabled", "sso-python-disabled", /SSO Python member signs in:/],
  ["X11", "probation-disabled", "sso-python-disabled", /SSO Python member downloads own noncached selected setup bundle/],
  ["X11", "probation-disabled", "sso-python-disabled", /SSO member npm installs selected allowed bytes/],
  ["X11", "probation-disabled", "sso-python-disabled", /SSO Python member pip installs selected allowed bytes/],
  ["X11", "probation-disabled", "sso-python-disabled", /SSO member's current group blocks npm package/],
  ["X11", "probation-disabled", "sso-python-disabled", /SSO Python member's current group blocks pip package/],
  ["X11", "probation-disabled", "sso-python-disabled", /different account receives its own distinct setup bundle/],
  ["X11", "probation-disabled", "sso-python-disabled", /removed SSO Python member cannot download another setup bundle/],
  ["X11", "probation-disabled", "sso-python-disabled", /removed SSO member selected npm and pip refusals made zero upstream calls/],
  ["X11", "probation-disabled", "sso-python-disabled", /SSO Python disabled self-service issues no new bundle/],
  ["X11", "organization-issued", "sso-python-issuer", /SSO Python member signs in:/],
  ["X11", "organization-issued", "sso-python-issuer", /SSO Python member downloads own noncached selected setup bundle/],
  ["X11", "organization-issued", "sso-python-issuer", /SSO member npm installs selected allowed bytes/],
  ["X11", "organization-issued", "sso-python-issuer", /SSO Python member pip installs selected allowed bytes/],
  ["X11", "organization-issued", "sso-python-issuer", /SSO member's current group blocks npm package/],
  ["X11", "organization-issued", "sso-python-issuer", /SSO Python member's current group blocks pip package/],
  ["X11", "organization-issued", "sso-python-issuer", /different account receives its own distinct setup bundle/],
  ["X11", "organization-issued", "sso-python-issuer", /removed SSO Python member cannot download another setup bundle/],
  ["X11", "organization-issued", "sso-python-issuer", /removed SSO member selected npm and pip refusals made zero upstream calls/],
  ["X11", "organization-issued", "sso-python-issuer", /SSO Python organization issuer refuses a new self-service bundle/],
];

function coveredCases(asserted, commanded, observed = new Set()) {
  const covered = new Set(observed);
  const groups = new Map();
  for (const [index, [row, mode, , , command]] of witnesses.entries()) {
    const key = `${row}:${mode}`;
    const group = groups.get(key) ?? [];
    group.push(asserted.has(index) && (!command || commanded.has(index)));
    groups.set(key, group);
  }
  for (const [key, parts] of groups) if (parts.every(Boolean)) covered.add(key);
  return covered;
}

export function missingCases(asserted, commanded, observed = new Set()) {
  const covered = coveredCases(asserted, commanded, observed);
  return MODES.map((mode) => {
    const missing = ROWS.filter((row) => !covered.has(`${row}:${mode}`));
    return missing.length ? `${mode}: ${missing.join(", ")}` : null;
  }).filter(Boolean);
}

export default async function fullMatrix(h) {
  // Exercise the same inventory predicate against a real fake-server request,
  // then clear this deliberate host-side probe before client traffic begins.
  const bridge = ops(h).inspect(ops(h).id("bridge")).NetworkSettings.Networks[`${h.stack.project}_e2e`]?.IPAddress;
  const negative = await h.request("https://registry.npmjs.org/x06-negative-control", {
    headers: { host: "unlisted-cdn.e2e.test" },
  });
  const negativeInventory = await h.fakes.requests();
  h.expect(negative.status === 404 && negativeInventory.some((request) =>
    request.host === "unlisted-cdn.e2e.test" && request.path === "/x06-negative-control"
    && request.peer?.replace(/^::ffff:/, "") === bridge)
    && unknownFixtureHosts(negativeInventory).some((request) => request.path === "/x06-negative-control"),
  "X06 real unknown-CDN bridge request is detected by the complete fake inventory");
  await h.fakes.reset();
  const asserted = new Set();
  const commanded = new Set();
  const observed = new Set();
  const egressPassed = new Set();
  const runnerFailures = [];
  for (const [position, [scenario, run]] of runners.entries()) {
    h.log(`matrix runner ${position + 1}/${runners.length}: ${scenario}`);
    await h.stack.up({ build: false });
    const runH = helpers(h.stack, { log: h.log });
    runH.suite = h.suite;
    const clientHome = runH.stack.exec("client-npm", ["sh", "-c", "printf '%s' \"$HOME\""]);
    h.log(`${scenario}: client-npm HOME=${JSON.stringify(clientHome.stdout)} container=${runH.stack.container("client-npm")}`);
    await runH.fakes.reset();
    await runH.mail.purge();
    const peers = currentFirewallPeers(runH.stack);
    const originalRestart = runH.stack.restart;
    const originalStart = runH.stack.start;
    runH.stack.restart = (...services) => {
      for (const peer of currentFirewallPeers(runH.stack)) peers.add(peer);
      originalRestart.call(runH.stack, ...services);
      for (const peer of currentFirewallPeers(runH.stack)) peers.add(peer);
    };
    runH.stack.start = (...services) => {
      originalStart.call(runH.stack, ...services);
      for (const peer of currentFirewallPeers(runH.stack)) peers.add(peer);
    };
    const originalExpect = runH.expect;
    const originalClient = runH.client;
    const runAsserted = new Set();
    const runCommanded = new Set();
    runH.expect = (condition, message) => {
      originalExpect(condition, message);
      for (const [index, witness] of witnesses.entries()) {
        if (witness[2] === scenario && witness[3].test(String(message))) runAsserted.add(index);
      }
    };
    runH.client = (...args) => {
      const result = originalClient(...args);
      for (const [index, witness] of witnesses.entries()) {
        if (witness[2] === scenario && witness[4]?.test(String(args[1]))) runCommanded.add(index);
      }
      return result;
    };
    try {
      await run(runH);
      for (const peer of currentFirewallPeers(runH.stack)) peers.add(peer);
      await assertEgress(runH, peers, scenario);
      for (const index of runAsserted) asserted.add(index);
      for (const index of runCommanded) commanded.add(index);
      egressPassed.add(scenario);
      h.log(`${scenario}: ${coveredCases(runAsserted, runCommanded).size} observed row/mode witnesses after egress`);
    } catch (error) {
      const failure = `${scenario}: ${error?.stack ?? error}`;
      runnerFailures.push(failure);
      h.log(`matrix runner failed: ${failure}`);
    } finally {
      runH.stack.restart = originalRestart;
      runH.stack.start = originalStart;
      runH.expect = originalExpect;
      runH.client = originalClient;
      if (runH !== h) await runH.close();
    }
  }
  const covered = coveredCases(asserted, commanded);
  for (const mode of MODES) {
    const precedingRows = ROWS.slice(0, ROWS.indexOf("X06"));
    if (runners.filter((runner) => runner[2] === mode).every(([name]) => egressPassed.has(name))
        && precedingRows.every((row) => covered.has(`${row}:${mode}`))) {
      observed.add(`X06:${mode}`);
    }
  }
  const missing = missingCases(asserted, commanded, observed);
  h.expect(runnerFailures.length === 0 && missing.length === 0,
    `full client matrix has ${runnerFailures.length} scenario failures and missing observed cases:\n${runnerFailures.join("\n")}\n${missing.join("\n")}`);
}
