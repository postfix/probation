import { copyFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { setupRealCatalog } from "../native/portal-setup.mjs";
import { buildNativeRun } from "../native/linux-exec.mjs";

// Linux acceptance for the native-runner stack (tests/e2e/native): the native `probation`
// binary, the Node registry fakes and the pinned Node/npm/Python/pip/Twine/uv clients run
// together in one client container on the protected `clients` network, against the real
// policy server and portal catalog. Registries are loopback destinations made usable by the
// operator-approved exact origin and CIDR, as on a runner.
export const meta = { id: "E2E-publishing-native-linux", title: "native service, fakes and pinned clients against the real policy server", suites: ["release"], stack: "own" };

const NPM_PORT = 43111;

export default async function nativeLinux(h) {
  const { npmId, pypiId, key, hiddenName } = await setupRealCatalog(h, { npmPort: NPM_PORT, keyName: "native-linux-service" });

  // This one image (every pinned client plus the native stack's runtime) is built and started
  // for this scenario only, not in every harness stack.
  h.stack.compose(["build", "client-native"]);
  h.stack.start("client-native");
  // The probation binary of the release image runs in the client container.
  const local = join(h.stack.work, "probation.native");
  for (const argv of [["cp", `${h.stack.container("firewall-standalone")}:/usr/local/bin/probation`, local], ["cp", local, `${h.stack.container("client-native")}:/usr/local/bin/probation`]]) {
    const copied = spawnSync(h.stack.engine, argv, { encoding: "utf8" });
    h.expect(copied.status === 0, `engine ${argv.join(" ")}: ${copied.stderr}`);
  }
  h.stack.exec("client-native", ["chmod", "755", "/usr/local/bin/probation"], { check: true });

  const pins = h.stack.exec("client-native", ["env", "NATIVE_PLATFORM=linux-x64", "node", "/src/tests/e2e/native/clients.mjs"]);
  h.log(pins.stdout);
  h.expect(pins.status === 0, `pinned clients are installed at exactly the pins: ${pins.stdout}${pins.stderr}`);
  const run = buildNativeRun({ key, policyUrl: "https://sync.e2e.test", npmId, pypiId, npmPort: NPM_PORT, hiddenName });
  h.stack.exec("client-native", run.keyWriteArgv, { input: run.keyInput, check: true });
  const ran = h.stack.exec("client-native", run.argv);
  h.log(ran.stdout);
  if (ran.stderr) h.log(ran.stderr.slice(-4000));
  h.expect(ran.status === 0 && /native publishing passed: \d+ checks/.test(ran.stdout), `native publishing against the real policy server: exit ${ran.status}`);
}
