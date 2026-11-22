#!/usr/bin/env node
// The e2e runner (tests/e2e/README.md).
//
//   node tests/e2e/harness/run.mjs --suite pr|nightly|release|release-native|release-cluster|canary|pbt|pbt-weekly [--only ID] [--list]
//                                  [--skip-build] [--keep]
//
// Brings the stack up once, runs every scenario of the suite against it (a scenario
// with `meta.stack = "own"` gets a fresh stack of its own), resets the fakes and the
// mail sink between scenarios, writes JUnit XML and, for each failure, every
// container's log into $E2E_OUT (default $E2E_WORK/out). Exits 0 only when all pass.
//
// Environment: E2E_WORK (default <repo>/target/e2e), E2E_OUT, E2E_PREBUILT=1 (the two
// images are built already; build only the clients), E2E_COMPOSE_CMD
// (default "docker compose"; "podman-compose" works too), E2E_BRIDGE_PORT (18128),
// E2E_NET (the e2e subnet's first three octets, 11.220.0), E2E_PROJECT (probation-e2e).

import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { checkNativeCounts, junitProperties, nativeClients, parseClientHost, requireNativeLane } from "./client-host.mjs";
import { helpers } from "./helpers.mjs";
import { netStats } from "./net.mjs";
import { ROOT, Stack } from "./stack.mjs";

// pbt and pbt-weekly: the property-based portal tests (harness/pbt.mjs), a shard of their own.
// release-native and release-cluster are the parts of the release gate a container stack cannot run: the native service lifecycle
// on the host's own service manager (needs --client-host native) and the shared service behind a pinned containerd node. The
// release runbook (docs/operations.md, "Release acceptance") runs all three; tests/cross_plan_acceptance.rs checks that every
// scenario belongs to one of them or is a named exception.
const SUITES = ["pr", "nightly", "release", "release-native", "release-cluster", "canary", "pbt", "pbt-weekly"];
const { values: args } = parseArgs({
  options: {
    suite: { type: "string", default: "pr" },
    only: { type: "string", multiple: true },
    list: { type: "boolean" },
    "skip-build": { type: "boolean", default: Boolean(process.env.E2E_SKIP_BUILD) },
    "client-host": { type: "string" },
    keep: { type: "boolean", default: Boolean(process.env.E2E_KEEP) },
  },
});
if (!SUITES.includes(args.suite)) throw new Error(`--suite must be one of ${SUITES.join(", ")}`);

// --client-host native runs the pinned package clients on the host (client-host.mjs). Any
// problem with it ends the run here, before a container exists: it never skips or uses containers.
let clientHostKind;
try { clientHostKind = parseClientHost(args["client-host"]); } catch (err) { console.error(`e2e: ${err.message}`); process.exit(1); }

const dir = join(ROOT, "tests/e2e/scenarios");
const scenarios = [];
for (const file of readdirSync(dir).filter((f) => f.endsWith(".mjs")).sort()) {
  const module = await import(pathToFileURL(join(dir, file)).href);
  scenarios.push({ file, ...module.meta, run: module.default });
}
// An --only ID that names no scenario (a renamed or misspelt one) must not shrink the run
// to nothing and pass: it fails here, naming the ID, before any stack is started.
const unknown = (args.only ?? []).filter((id) => !scenarios.some((s) => s.id === id));
if (unknown.length) {
  console.error(`e2e: --only names no scenario: ${unknown.map((id) => JSON.stringify(id)).join(", ")}`);
  process.exit(1);
}
const selected = scenarios
  .filter((s) => (args.only ? args.only.includes(s.id) : s.suites.includes(args.suite)))
  .sort((a, b) => (a.stack === "own") - (b.stack === "own"));
if (selected.length === 0) {
  console.error(`e2e: no scenario is selected (suite ${args.suite}${args.only ? `, --only ${args.only.join(", ")}` : ""})`);
  process.exit(1);
}
const needNative = selected.filter((s) => s.clientHost === "native" && clientHostKind !== "native");
if (needNative.length) {
  console.error(`e2e: ${needNative.map((s) => s.id).join(", ")} requires --client-host native (it never runs in containers)`);
  process.exit(1);
}
// Selection time, before the preflight and any stack work: every scenario of a native run must declare native clients.
const notNative = clientHostKind === "native" ? selected.filter((s) => !s.native) : [];
if (notNative.length) {
  console.error(`e2e: ${notNative.map((s) => `${s.id} declares no native clients`).join("; ")}: it cannot run with --client-host native`);
  process.exit(1);
}
if (clientHostKind === "native" && !args.list) {
  try { requireNativeLane(); } catch (err) { console.error(`e2e: ${err.message}`); process.exit(1); }
}
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
  nightly: args.suite === "nightly" || args.suite === "release", // release-native and release-cluster start no nightly client container
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
    h.suite = args.suite;
    h.caFile = "/e2e/ca/ca.pem";
    if (clientHostKind === "native") {
      h.caFile = join(stack.work, "ca", "ca.pem");
      h.clientHost = nativeClients({ work: stack.work, bridgePort: stack.bridgePort, caFile: h.caFile });
    }
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
    results.push({ scenario, seconds, error, used: h.clientHost?.used });
    console.log(`e2e: ${scenario.id} ${error ? "FAILED" : "passed"} in ${seconds.toFixed(1)} s`);
  }
} finally {
  writeHarnessEvents();
  writeJunit();
  if (!args.keep && !interrupted) stack.down();
}

const failed = results.filter((r) => r.error);
// Native runs must be complete: expected scenario and client counts, nothing skipped.
const incomplete = clientHostKind === "native" ? checkNativeCounts({ selected, results }) : [];
for (const problem of incomplete) console.error(`e2e: native run incomplete: ${problem}`);
console.log(`e2e: ${results.length - failed.length} passed, ${failed.length} failed, ${selected.length - results.length} not run (suite ${args.suite})`);
process.exit(failed.length || incomplete.length || results.length < selected.length ? 1 : 0);

/// What the harness did that a green result could hide: stack bring-ups retried on an engine or one-off failure, requests sent a second
/// time on a stale kept-alive connection, stale DNS records removed. Printed and written next to junit.xml.
function writeHarnessEvents() {
  const events = { upRetries: stack.upRetries ?? [], netResends: netStats().resends, purgedDnsRecords: stack.purgedDns ?? [] };
  writeFileSync(join(out, "harness-events.json"), `${JSON.stringify(events, null, 2)}\n`);
  console.log(`e2e: harness events: ${events.upRetries.length} stack-up retries${events.upRetries.map((r) => ` [attempt ${r.attempt}: ${r.error}]`).join("")}, ${events.netResends} idempotent resends, ${events.purgedDnsRecords.length} stale DNS records removed`);
}

function writeJunit() {
  const xml = (text) => String(text).replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" })[c]);
  const cases = selected.map((s) => {
    const r = results.find((x) => x.scenario === s);
    const name = `classname="e2e.${args.suite}" name="${xml(`${s.id} ${s.title}`)}" file="tests/e2e/scenarios/${s.file}"`;
    if (!r) return `  <testcase ${name}>${junitProperties(clientHostKind, undefined)}<skipped message="not run"/></testcase>`;
    const failure = r.error ? `<failure message="${xml(r.error.message.split("\n")[0])}">${xml(r.error.stack ?? r.error)}</failure>` : "";
    return `  <testcase ${name} time="${r.seconds.toFixed(3)}">${junitProperties(clientHostKind, r.used)}${failure}</testcase>`;
  });
  const total = results.reduce((sum, r) => sum + r.seconds, 0);
  writeFileSync(
    join(out, "junit.xml"),
    `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="e2e-${args.suite}" tests="${selected.length}" failures="${results.filter((r) => r.error).length}" skipped="${selected.length - results.length}" time="${total.toFixed(3)}">\n${cases.join("\n")}\n</testsuite>\n`,
  );
}
