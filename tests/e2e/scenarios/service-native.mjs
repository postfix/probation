import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { startCommonService } from "../harness/service-setup.mjs";
import { ROOT } from "../harness/stack.mjs";
import { runLifecycle } from "../native/service-lifecycle.mjs";

// Row 25: machine-wide native lifecycle and native package-tool execution. Part 1 installs the REAL probation binary as a service
// under the host's own service manager (systemd, launchd or the Windows SCM) with scripts/install-service.*, then exercises
// start, stop, restart on the same state, a crash restart, the settings-restart exit (75), the second-owner refusal, permissions,
// an upgrade that keeps config and data, and an uninstall that keeps them (native/service-lifecycle.mjs). Part 2 runs the pinned
// native npm and pip against the shared service, allowed and refused. Only with --client-host native. A scope other than the
// default is chosen with E2E_SERVICE_SCOPE=system|user (CI runners use system; a developer host without root uses user).
export const meta = {
  id: "E2E-service-native",
  title: "native service lifecycle and native package tools on this OS",
  suites: ["release-native"],
  stack: "own",
  clientHost: "native",
  native: { npm: 2, pip: 2 },
};

const isWindows = process.platform === "win32";

export default async function serviceNative(h) {
  h.expect(h.clientHost?.kind === "native", "the native client host is active");
  const platform = process.platform;
  const exe = isWindows ? "probation.exe" : "probation";
  const scope = process.env.E2E_SERVICE_SCOPE ?? (isWindows || process.getuid?.() === 0 ? "system" : "user");
  // A runner VM (E2E_SERVICE_DIRS=system) uses the platform's own locations, exactly what an operator gets; anywhere else the
  // service lives in disposable directories under the work dir, under a unique name, and is removed again.
  const evidence = await runLifecycle({
    root: join(h.stack.work, "service-native"), binary: process.env.PROBATION_BIN ?? join(ROOT, "target/debug", exe), scope,
    name: isWindows ? "Probation" : `probation-e2e-${process.pid}`, port: 18000 + (process.pid % 1000), platform,
    systemLocations: process.env.E2E_SERVICE_DIRS === "system",
    expect: (condition, message) => h.expect(condition, message), log: (line) => h.log(`lifecycle ${line}`),
  });
  h.log(`lifecycle evidence: ${JSON.stringify(evidence)}`);

  // Part 2: the pinned native package tools through the shared service, allowed and refused.
  const npmName = h.unique("svc-npm");
  const wheelName = h.unique("svc-wheel");
  const deniedName = h.unique("svc-denied");
  await h.fakes.publishNpm({ name: npmName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishNpm({ name: deniedName, version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.fakes.publishPypi({ name: wheelName, version: "1.0.0", ageSeconds: 400 * 86_400, kinds: ["wheel"] });
  const blocklistPath = join(h.stack.work, "producer", "blocklist.json");
  const list = JSON.parse(readFileSync(blocklistPath, "utf8"));
  list.revision += 1;
  list.blocked_packages.push({ ecosystem: "npm", name: deniedName, version: null, reason: "native service control" });
  writeFileSync(blocklistPath, JSON.stringify(list));
  const root2 = await startCommonService(h);
  // Credential entries the tool owns sit beside the registry line and must reach the tool unchanged.
  const npmrc = `registry=${root2}/npm/\ncafile=${h.caFile}\n//registry.corp.example/:_authToken=keep-me\n`;
  const pipConf = `[global]\nindex-url = ${root2}/pypi/simple/\ncert = ${h.caFile}\ndisable-pip-version-check = true\nno-cache-dir = true\n`;
  let r = h.npm(`install ${npmName}@1.0.0 --no-audit --no-fund`, { npmrc });
  h.expect(r.status === 0, `native npm through the service: ${r.stderr}`);
  r = h.pip(`install --target t ${wheelName}==1.0.0`, { pipConf });
  h.expect(r.status === 0, `native pip through the service: ${r.stderr}`);
  r = h.npm(`install ${deniedName}@1.0.0 --no-audit --no-fund`, { npmrc });
  h.expect(r.status !== 0 && /403/.test(r.stderr), `native npm: a blocked package is refused by the service (403): ${r.stderr.slice(-300)}`);
  r = h.pip(`install --target t2 ${wheelName}==9.9.9`, { pipConf });
  h.expect(r.status !== 0, "native pip: a version the service does not list is not installed");
  h.expect((await h.fakes.requests("registry.npmjs.org")).filter((row) => row.path.includes(deniedName) && row.path.endsWith(".tgz")).length === 0, "the blocked tarball was never fetched upstream");
}
