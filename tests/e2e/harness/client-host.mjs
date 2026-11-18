// Where the package clients of a scenario run (slice 29). `container` is the existing
// client containers (helpers.mjs); `native` runs the pinned clients on the host itself,
// reaching the stack through the bridge's CONNECT proxy under the stack's own names.
// Native never falls back to containers and never skips: an unprovisioned lane, a missing
// scenario or an unused client is a failure (04-slices.md, rule for --client-host native).
import { mkdirSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { checkClients, loadPins } from "../native/clients.mjs";
import { launch } from "../native/spawn-args.mjs";

export function parseClientHost(value) {
  if (value === undefined || value === "container") return "container";
  if (value === "native") return "native";
  throw new Error(`--client-host must be container or native, got ${JSON.stringify(value)}`);
}

/// Throws unless the host has exactly the pinned clients (native/clients.mjs); returns the lane's description.
export function requireNativeLane({ env = process.env, check } = {}) {
  const probe = check ?? (() => checkClients({ pins: loadPins(), platformWanted: env.NATIVE_PLATFORM, env }));
  const failures = [];
  if (!env.NATIVE_PLATFORM) failures.push("NATIVE_PLATFORM is not set");
  else failures.push(...probe().failures);
  if (failures.length) throw new Error(`native client lane is not provisioned:\n  ${failures.join("\n  ")}`);
  return { kind: "native", platform: env.NATIVE_PLATFORM };
}

/// After a native run: every selected scenario ran, declares its native clients (`meta.native = {npm: n, pip: n}`)
/// and used each at least that often. Returns the problems (empty when the run is complete).
export function checkNativeCounts({ selected, results }) {
  const problems = [];
  if (results.length !== selected.length) problems.push(`${selected.length} scenarios expected, ${results.length} ran`);
  for (const scenario of selected) {
    if (!scenario.native) { problems.push(`${scenario.id}: declares no native clients, so it cannot run with --client-host native`); continue; }
    const row = results.find((r) => r.scenario === scenario);
    if (!row) continue;
    for (const [tool, want] of Object.entries(scenario.native)) {
      const got = row.used?.[tool] ?? 0;
      if (got < want) problems.push(`${scenario.id}: ${tool} used ${got} times, expected at least ${want}`);
    }
  }
  return problems;
}

/// The JUnit <properties> of a testcase: which client host ran it and how often each client was called.
export function junitProperties(kind, used) {
  const rows = [["client-host", kind], ...Object.entries(used ?? {}).map(([tool, n]) => [`${tool}-calls`, n])];
  return `<properties>${rows.map(([name, value]) => `<property name="${name}" value="${value}"/>`).join("")}</properties>`;
}

/// The native helpers a scenario gets as `h.clientHost`: same shape as h.npm/h.pip, run on the host.
export function nativeClients({ work, bridgePort, caFile, env = process.env }) {
  const proxy = `http://${env.E2E_BRIDGE_HOST ?? "127.0.0.1"}:${bridgePort}`;
  const used = { npm: 0, pip: 0 };
  let n = 0;
  const run = (tool, command, args, files, extraEnv) => {
    used[tool]++;
    const dir = join(work, "native-clients", `${process.pid}-${++n}`);
    mkdirSync(dir, { recursive: true });
    for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
    const [file, argv, options] = launch(command, args, {
      cwd: dir, encoding: "utf8", timeout: 300_000,
      env: { ...env, HOME: dir, USERPROFILE: dir, HTTPS_PROXY: proxy, https_proxy: proxy, NO_PROXY: "", no_proxy: "", ...extraEnv(dir) },
    }, process.platform, { shim: tool === "npm" });
    const r = spawnSync(file, argv, options);
    return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: `${r.stderr ?? ""}${r.error ?? ""}` };
  };
  return {
    kind: "native", used, caFile, proxy,
    npm: (args, { npmrc, packageJson = { name: "e2e-project", version: "1.0.0", private: true }, files = {} } = {}) =>
      run("npm", "npm", args.split(/\s+/).filter(Boolean), { "package.json": JSON.stringify(packageJson), ".npmrc": npmrc, ...files }, (dir) => ({ npm_config_userconfig: join(dir, ".npmrc") })),
    pip: (args, { pipConf, files = {} } = {}) =>
      run("pip", env.NATIVE_PYTHON ?? "python", ["-m", "pip", ...args.split(/\s+/).filter(Boolean)], { "pip.conf": pipConf, ...files }, (dir) => ({ PIP_CONFIG_FILE: join(dir, "pip.conf") })),
  };
}
