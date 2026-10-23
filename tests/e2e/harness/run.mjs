#!/usr/bin/env node
// The e2e runner (tests/e2e/README.md).
//
//   node tests/e2e/harness/run.mjs --suite pr|nightly|release|canary [--only ID] [--list]
//                                  [--skip-build] [--keep]
//
// Brings the stack up once, runs every scenario of the suite against it (a scenario
// with `meta.stack = "own"` gets a fresh stack of its own), resets the fakes and the
// mail sink between scenarios, writes JUnit XML and, for each failure, every
// container's log into $E2E_OUT (default $E2E_WORK/out). Exits 0 only when all pass.
//
// Environment: E2E_WORK (default <repo>/target/e2e), E2E_OUT, E2E_COMPOSE_CMD
// (default "docker compose"; "podman-compose" works too), E2E_BRIDGE_PORT (18128),
// E2E_NET (the e2e subnet's first three octets, 11.220.0), E2E_PROJECT (probation-e2e).

import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { helpers } from "./helpers.mjs";
import { ROOT, Stack } from "./stack.mjs";

const SUITES = ["pr", "nightly", "release", "canary"];
const { values: args } = parseArgs({
  options: {
    suite: { type: "string", default: "pr" },
    only: { type: "string", multiple: true },
    list: { type: "boolean" },
    "skip-build": { type: "boolean", default: Boolean(process.env.E2E_SKIP_BUILD) },
    keep: { type: "boolean", default: Boolean(process.env.E2E_KEEP) },
  },
});
if (!SUITES.includes(args.suite)) throw new Error(`--suite must be one of ${SUITES.join(", ")}`);

const dir = join(ROOT, "tests/e2e/scenarios");
const scenarios = [];
for (const file of readdirSync(dir).filter((f) => f.endsWith(".mjs")).sort()) {
  const module = await import(join(dir, file));
  scenarios.push({ file, ...module.meta, run: module.default });
}
const selected = scenarios
  .filter((s) => (args.only ? args.only.includes(s.id) : s.suites.includes(args.suite)))
  .sort((a, b) => (a.stack === "own") - (b.stack === "own"));
if (args.list) {
  for (const s of selected) console.log(`${s.id}\t${s.suites.join(",")}\t${s.stack ?? "shared"}\t${s.title}`);
  process.exit(0);
}

const work = process.env.E2E_WORK ?? join(ROOT, "target/e2e");
const out = process.env.E2E_OUT ?? join(work, "out");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
const stack = new Stack({
  work,
  project: process.env.E2E_PROJECT ?? "probation-e2e",
  net: process.env.E2E_NET ?? "11.220.0",
  bridgePort: Number(process.env.E2E_BRIDGE_PORT ?? 18128),
  canary: args.suite === "canary",
  nightly: args.suite === "nightly" || args.suite === "release",
});

const results = [];
let built = args["skip-build"];
async function freshStack() {
  console.log(`e2e: starting the stack (${stack.project}, ${stack.net}.0/24)`);
  const started = performance.now();
  await stack.up({ build: !built });
  built = true;
  console.log(`e2e: stack up in ${((performance.now() - started) / 1000).toFixed(0)} s`);
}

let interrupted = false;
process.on("SIGINT", () => {
  interrupted = true;
  if (!args.keep) stack.down();
  process.exit(130);
});

try {
  try {
    await freshStack();
  } catch (err) {
    await stack.collect(join(out, "logs", "setup"));
    throw err;
  }
  let fresh = true;
  for (const scenario of selected) {
    if (scenario.stack === "own" && !fresh) await freshStack();
    fresh = false;
    const h = helpers(stack, { log: (...line) => console.log(`[${scenario.id}]`, ...line) });
    const started = performance.now();
    let error;
    console.log(`e2e: ${scenario.id} ${scenario.title}`);
    try {
      if (!stack.canary) await h.fakes.reset();
      await h.mail.purge();
      await scenario.run(h);
    } catch (err) {
      error = err;
      console.error(`E2E FAIL ${scenario.id}: ${err.stack ?? err}`);
      await stack.collect(join(out, "logs", scenario.id));
    } finally {
      await h.close();
    }
    const seconds = (performance.now() - started) / 1000;
    results.push({ scenario, seconds, error });
    console.log(`e2e: ${scenario.id} ${error ? "FAILED" : "passed"} in ${seconds.toFixed(1)} s`);
  }
} finally {
  writeJunit();
  if (!args.keep && !interrupted) stack.down();
}

const failed = results.filter((r) => r.error);
console.log(`e2e: ${results.length - failed.length} passed, ${failed.length} failed, ${selected.length - results.length} not run (suite ${args.suite})`);
process.exit(failed.length || results.length < selected.length ? 1 : 0);

function writeJunit() {
  const xml = (text) => String(text).replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" })[c]);
  const cases = selected.map((s) => {
    const r = results.find((x) => x.scenario === s);
    const name = `classname="e2e.${args.suite}" name="${xml(`${s.id} ${s.title}`)}" file="tests/e2e/scenarios/${s.file}"`;
    if (!r) return `  <testcase ${name}><skipped message="not run"/></testcase>`;
    const failure = r.error ? `<failure message="${xml(r.error.message.split("\n")[0])}">${xml(r.error.stack ?? r.error)}</failure>` : "";
    return `  <testcase ${name} time="${r.seconds.toFixed(3)}">${failure}</testcase>`;
  });
  const total = results.reduce((sum, r) => sum + r.seconds, 0);
  writeFileSync(
    join(out, "junit.xml"),
    `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="e2e-${args.suite}" tests="${selected.length}" failures="${results.filter((r) => r.error).length}" skipped="${selected.length - results.length}" time="${total.toFixed(3)}">\n${cases.join("\n")}\n</testsuite>\n`,
  );
}
