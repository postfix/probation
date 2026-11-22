import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { startCommonService } from "../harness/service-setup.mjs";

// Slice 29 smoke: the pinned package clients run natively on the host (Linux, macOS or Windows runner) and install from
// the delivered npm/PyPI shared service with no Probation login. Only runs with --client-host native; the container
// path is the existing service-policy scenario, and a container run cannot stand in for macOS or Windows.
export const meta = {
  id: "E2E-service-native-smoke",
  title: "native npm and pip install through the shared service without login",
  suites: ["release-native"],
  stack: "own",
  clientHost: "native",
  native: { npm: 2, pip: 2 },
};

export default async function nativeSmoke(h) {
  h.expect(h.clientHost?.kind === "native", "the native client host is active");
  const npmName = h.unique("native-npm");
  const wheelName = h.unique("native-wheel");
  const deniedName = h.unique("native-denied");
  const deniedWheel = h.unique("native-denied-wheel");
  await h.fakes.publishNpm({ name: npmName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: deniedName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  // The service's local blocklist (as service-policy.mjs) denies one package; the restart in startCommonService loads it.
  const blocklistPath = join(h.stack.work, "producer", "blocklist.json");
  const list = JSON.parse(readFileSync(blocklistPath, "utf8"));
  list.revision += 1;
  list.blocked_packages.push({ ecosystem: "npm", name: deniedName, version: null, reason: "native smoke control" });
  list.blocked_packages.push({ ecosystem: "pypi", name: deniedWheel, version: null, reason: "native smoke control" });
  writeFileSync(blocklistPath, JSON.stringify(list));
  await h.fakes.publishPypi({ name: deniedWheel, version: "1.0.0", ageSeconds: 400 * 86_400, kinds: ["wheel"] });
  await h.fakes.publishPypi({ name: wheelName, version: "1.0.0", ageSeconds: 400 * 86_400, kinds: ["wheel"] });
  const root = await startCommonService(h);
  const npmrc = `registry=${root}/npm/\ncafile=${h.caFile}\n`;
  const pipConf = `[global]\nindex-url = ${root}/pypi/simple/\ncert = ${h.caFile}\ndisable-pip-version-check = true\nno-cache-dir = true\n`;

  let r = h.npm(`install ${npmName}@1.0.0 --no-audit --no-fund`, { npmrc });
  h.expect(r.status === 0, `native npm without login: ${r.stderr}`);
  r = h.pip(`install --target t ${wheelName}==1.0.0`, { pipConf });
  h.expect(r.status === 0, `native pip without login: ${r.stderr}`);
  // The refusal side: a blocklisted package is refused natively too, not only allowed ones served.
  r = h.npm(`install ${deniedName}@1.0.0 --no-audit --no-fund`, { npmrc });
  h.expect(r.status !== 0 && /403/.test(r.stderr), `native npm: a blocklisted package is refused by the service (403), not by a broken lane: ${r.stderr.slice(-300)}`);
  r = h.pip(`install --target t2 ${deniedWheel}==1.0.0`, { pipConf });
  h.expect(r.status !== 0 && /from versions: none/.test(r.stderr), `native pip: the service lists no version of a blocklisted package (the lane itself works: the allowed wheel installed above): ${r.stderr.slice(-300)}`);
  for (const [ecosystemHost, name] of [["registry.npmjs.org", deniedName], ["pypi.org", deniedWheel]]) {
    h.expect((await h.fakes.requests(ecosystemHost)).filter((row) => row.path.includes(name) && /\.(tgz|whl)$/.test(row.path)).length === 0, `no artifact of ${name} was fetched from the upstream (metadata may be)`);
  }
  const traces = (await h.fakes.requests("registry.npmjs.org")).filter((row) => row.path.includes(npmName));
  h.expect(traces.length > 0, "the native npm install reached the selected upstream through the service");
}
