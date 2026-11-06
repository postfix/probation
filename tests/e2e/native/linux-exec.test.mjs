// S4: the service key is passed to the container on stdin, never in an argv.
import assert from "node:assert/strict";
import { buildNativeRun } from "./linux-exec.mjs";

const key = "prb_" + "b".repeat(32);
const run = buildNativeRun({ key, policyUrl: "https://sync.e2e.test", npmId: "4", pypiId: "5", npmPort: 43111, hiddenName: "token-private-x" });
assert.ok(!JSON.stringify(run.argv).includes(key), "no argv element carries the key");
assert.ok(!JSON.stringify(run.argv).includes("prb_"), "nor any key prefix");
assert.equal(run.keyInput, `${key}\n`);
assert.ok(run.argv.some((a) => a.startsWith("NATIVE_SERVICE_KEY_FILE=")), "a file path is passed instead");
assert.ok(run.keyWriteArgv.join(" ").includes("umask 077"), "the key file is created private");
assert.ok(!JSON.stringify(run.keyWriteArgv).includes(key));
console.log("linux-exec.test: ok");
