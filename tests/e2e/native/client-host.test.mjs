// The native-driver seam's rules (slice 29). node tests/e2e/native/client-host.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { checkNativeCounts, junitProperties, nativeClients, parseClientHost, requireNativeLane } from "../harness/client-host.mjs";
import { helpers } from "../harness/helpers.mjs";

// The flag: absent means containers, native is explicit, anything else is an error.
assert.equal(parseClientHost(undefined), "container");
assert.equal(parseClientHost("container"), "container");
assert.equal(parseClientHost("native"), "native");
assert.throws(() => parseClientHost("nativ"), /--client-host must be container or native/);

// A native lane that cannot be provisioned fails with every reason; it never returns a driver.
assert.throws(() => requireNativeLane({ env: {}, check: () => ({ failures: [] }) }), /NATIVE_PLATFORM is not set/);
assert.throws(
  () => requireNativeLane({ env: { NATIVE_PLATFORM: "linux-x64" }, check: () => ({ failures: ["npm: want 11.21.1, got missing"] }) }),
  /native client lane is not provisioned[\s\S]*npm: want 11\.21\.1, got missing/,
);
const driver = requireNativeLane({ env: { NATIVE_PLATFORM: "linux-x64" }, check: () => ({ failures: [] }) });
assert.equal(driver.kind, "native");

// Expected counts: a missing scenario, a scenario without the declared client calls and a skipped case all fail.
const meta = { id: "E2E-x", native: { npm: 1, pip: 1 } };
assert.deepEqual(checkNativeCounts({ selected: [meta], results: [{ scenario: meta, used: { npm: 1, pip: 2 } }] }), []);
assert.match(checkNativeCounts({ selected: [meta], results: [] }).join("\n"), /1 scenarios expected, 0 ran/);
assert.match(checkNativeCounts({ selected: [meta], results: [{ scenario: meta, used: { npm: 1, pip: 0 } }] }).join("\n"), /E2E-x: pip used 0 times, expected at least 1/);
const plain = { id: "E2E-y" };
assert.match(checkNativeCounts({ selected: [plain], results: [{ scenario: plain, used: {} }] }).join("\n"), /E2E-y: declares no native clients/);

// The runner itself: --client-host native on an unprovisioned host fails before any stack starts, and a bad value fails.
const run = (...args) => spawnSync(process.execPath, [fileURLToPath(new URL("../harness/run.mjs", import.meta.url)), ...args], { encoding: "utf8", env: { PATH: process.env.PATH } });
let r = run("--only", "E2E-service-native-smoke", "--client-host", "native");
assert.equal(r.status, 1, r.stdout + r.stderr);
assert.match(r.stderr, /native client lane is not provisioned/);
assert.doesNotMatch(r.stdout + r.stderr, /starting the stack/, "fails before any container work");
r = run("--only", "E2E-service-native-smoke");
assert.equal(r.status, 1, "the native smoke without --client-host native fails; it never runs in containers");
assert.match(r.stderr, /requires --client-host native/);
r = run("--only", "E2E-service-native-smoke", "--client-host", "bogus");
assert.equal(r.status, 1);
assert.match(r.stderr, /--client-host must be container or native/);
// F3: under the native host no scenario may reach a client container through h.client, and a scenario that declares no
// native clients is rejected when the run is selected, before the preflight or any stack work.
const h = helpers({}, { log() {} });
h.clientHost = { kind: "native" };
assert.throws(() => h.client("client-npm", "true"), /not available with --client-host native/);
r = run("--only", "E2E-002", "--client-host", "native");
assert.equal(r.status, 1);
assert.match(r.stderr, /E2E-002 declares no native clients/);
assert.doesNotMatch(r.stdout + r.stderr, /starting the stack/);

// F5: the JUnit testcase carries the client host and the client use, so a verifier can check them without the log.
assert.equal(junitProperties("native", { npm: 2, pip: 1 }), '<properties><property name="client-host" value="native"/><property name="npm-calls" value="2"/><property name="pip-calls" value="1"/></properties>');
assert.equal(junitProperties("container", undefined), '<properties><property name="client-host" value="container"/></properties>');

// The bridge's published port binds to loopback unless E2E_BRIDGE_BIND says otherwise (a remote native runner needs it).
const compose = readFileSync(new URL("../compose/compose.yml", import.meta.url), "utf8");
assert.ok(compose.includes('"${E2E_BRIDGE_BIND:-127.0.0.1}:${E2E_BRIDGE_PORT:-18128}:3128"'), "default bind stays 127.0.0.1");
assert.ok(!compose.includes('"0.0.0.0:'), "no unconditional wildcard bind");
assert.equal(nativeClients({ work: "w", bridgePort: 1, caFile: "c", env: { E2E_BRIDGE_HOST: "10.1.2.3" } }).proxy, "http://10.1.2.3:1");
assert.equal(nativeClients({ work: "w", bridgePort: 1, caFile: "c", env: {} }).proxy, "http://127.0.0.1:1");
console.log("client-host.test: ok");
