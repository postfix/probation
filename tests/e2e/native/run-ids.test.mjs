// C1: the harness fails on an --only ID that matches no scenario, and on an empty selection.
// node tests/e2e/native/run-ids.test.mjs   (needs tests/e2e/node_modules for the scenario imports)
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const run = fileURLToPath(new URL("../harness/run.mjs", import.meta.url));
const harness = (...args) => spawnSync(process.execPath, [run, ...args], { encoding: "utf8", timeout: 60_000 });

let r = harness("--only", "E2E-no-such-scenario", "--list");
assert.equal(r.status, 1, `--list with an unknown ID must fail: ${r.stdout}${r.stderr}`);
assert.match(r.stderr, /E2E-no-such-scenario/, "the message names the ID");
r = harness("--only", "E2E-no-such-scenario");
assert.equal(r.status, 1, "a run with an unknown ID fails before any stack is started");
assert.match(r.stderr, /E2E-no-such-scenario/);
r = harness("--only", "E2E-service-policy", "--only", "E2E-misspelt", "--list");
assert.equal(r.status, 1, "one unknown ID among known ones still fails");
assert.match(r.stderr, /E2E-misspelt/);
assert.ok(!/E2E-service-policy\b.*not/.test(r.stderr), "known IDs are not named as unknown");
r = harness("--only", "E2E-service-policy", "--list");
assert.equal(r.status, 0, `a known ID lists: ${r.stderr}`);
assert.match(r.stdout, /^E2E-service-policy\t/m);
r = harness("--suite", "canary", "--only", "", "--list");
assert.equal(r.status, 1, "an empty ID matches nothing");
console.log("run-ids.test: ok");
