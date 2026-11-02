// D11: the A11Y-axe and keyboard walk (C84, slices 5 to 7) on the deployed portal behind
// the TLS gateway. Its own stack, because crates/probation-server/tests/seed.sql adds
// fixed organisations (Acme, Globex, Initech) and logins, and the slice 6 and 7 runs turn
// authenticators on, so each runs once per seeded database, in order.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../harness/stack.mjs";

export const meta = {
  id: "E2E-A11Y-axe",
  title: "Accessibility walk (axe-core and keyboard) on every portal page, slices 5 to 7",
  suites: ["nightly", "release"],
  stack: "own",
};

export default async function a11y(h) {
  h.stack.exec("postgres", ["psql", "-U", "probation", "-d", "probation", "-v", "ON_ERROR_STOP=1", "-q", "-f", "-"], {
    input: readFileSync(join(ROOT, "crates/probation-server/tests/seed.sql"), "utf8"),
    check: true,
  });
  const failed = [];
  for (const slice of ["5", "6", "7"]) {
    const run = spawnSync(process.execPath, [join(ROOT, "tests/e2e/a11y/axe.mjs"), "--slice", slice], {
      env: { ...process.env, PORTAL_URL: h.portalUrl, A11Y_PROXY: `http://127.0.0.1:${h.stack.bridgePort}` },
      stdio: ["ignore", "inherit", "inherit"],
    });
    if (run.status !== 0) failed.push(`slice ${slice} (exit ${run.status})`);
  }
  h.expect(failed.length === 0, `A11Y walk failed: ${failed.join(", ")}`);
}
