#!/usr/bin/env node
// Part 1 of E2E-service-native on its own: the native service lifecycle under this host's service manager, with no container stack.
// The macOS and Windows runner lanes run exactly this (their service manager IS the lane; the Linux stack scenario adds the native
// package tools). Exits 1 on the first violated expectation and prints the evidence record as JSON on success.
//   PROBATION_BIN=<built probation> [E2E_SERVICE_SCOPE=system|user] [E2E_SERVICE_DIRS=system] [E2E_SERVICE_PORT=18080]
//   node tests/e2e/native/service-lifecycle-run.mjs
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { runLifecycle } from "./service-lifecycle.mjs";

const platform = process.platform;
const root = join(fileURLToPath(new URL("../../..", import.meta.url)));
const binary = process.env.PROBATION_BIN ?? join(root, "target", "debug", platform === "win32" ? "probation.exe" : "probation");
const scope = process.env.E2E_SERVICE_SCOPE ?? (platform === "win32" || process.getuid?.() === 0 ? "system" : "user");
const expect = (condition, message) => { if (!condition) throw new Error(message); };
try {
  const evidence = await runLifecycle({
    root: join(process.env.NATIVE_TEST_SCRATCH ?? tmpdir(), `service-lifecycle-${process.pid}`), binary, scope, platform,
    name: platform === "win32" ? "Probation" : `probation-ci-${process.pid}`,
    port: Number(process.env.E2E_SERVICE_PORT ?? 18080),
    systemLocations: process.env.E2E_SERVICE_DIRS === "system", expect, log: (line) => console.log(`lifecycle ${line}`),
  });
  console.log(JSON.stringify(evidence));
} catch (error) {
  console.error(`service-lifecycle-run: ${error.message}`);
  process.exit(1);
}
