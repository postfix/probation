// Operator-side helpers for the outage, automation and network-lock scenarios
// (E2E-003, 014, 015, 016): the fleet page, the firewall's config file, a container's
// address, and extra containers on the e2e network. Scenarios import them directly.

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { unescape } from "./net.mjs";

/// A Playwright context signed in as `who` (its cookie-jar session moved over), so a
/// person's next steps happen in Chromium.
export async function browserAs(h, who) {
  const context = await h.browser();
  await context.addCookies([...who.portal.cookies].map(([name, value]) => ({ name, value, url: h.portalUrl })));
  return context;
}

/// The Health cell of firewall `name` on /fleet, as the operator reads it.
export async function fleetHealth(portal, name) {
  const body = (await portal.get("/fleet")).body;
  const row = body.match(new RegExp(`<td>${name}</td>[\\s\\S]*?</tr>`))?.[0] ?? "";
  return unescape(row.match(/<span class="(?:good|bad)">([^<]*)<\/span>/)?.[1] ?? "");
}

/// Edits `$E2E_WORK/<service>.toml` as an operator edits config.toml: `edit(text)`
/// answers the new text. Restart the service after.
export function editConfig(stack, service, edit) {
  const file = join(stack.work, `${service}.toml`);
  writeFileSync(file, edit(readFileSync(file, "utf8")));
}

/// The address of `service` on the e2e network.
export function addressOf(stack, service) {
  const run = spawnSync(stack.engine, ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", stack.container(service)], {
    encoding: "utf8",
  });
  const address = run.stdout.trim().split(/\s+/).find((a) => a.startsWith(`${stack.net}.`));
  if (!address) throw new Error(`${service} has no address on ${stack.net}.0/24: ${run.stdout} ${run.stderr}`);
  return address;
}

/// When `service`'s container last started (changes on every restart).
export function startedAt(stack, service) {
  return spawnSync(stack.engine, ["inspect", "-f", "{{.State.StartedAt}}", stack.container(service)], { encoding: "utf8" }).stdout.trim();
}

/// Starts a container of `image` on the stack's e2e network at `ip` ({name, image,
/// ip, volumes: ["host:container:ro"], env: {}, args: []}); answers a function that
/// removes it. The name carries the project, so stacks running side by side differ.
export function runOnNetwork(stack, { name, image, ip, volumes = [], env = {}, args = [] }) {
  const full = `${stack.project}-${name}`;
  spawnSync(stack.engine, ["rm", "-f", full], { encoding: "utf8" });
  const network = spawnSync(stack.engine, ["network", "ls", "--format", "{{.Name}}"], { encoding: "utf8" })
    .stdout.split("\n")
    .find((n) => n === `${stack.project}_e2e`);
  if (!network) throw new Error(`no network ${stack.project}_e2e`);
  const run = spawnSync(
    stack.engine,
    [
      "run", "-d", "--name", full, "--network", network, "--ip", ip,
      ...volumes.flatMap((v) => ["-v", v]),
      ...Object.entries(env).flatMap(([k, v]) => ["-e", `${k}=${v}`]),
      image, ...args,
    ],
    { encoding: "utf8" },
  );
  if (run.status !== 0) throw new Error(`${stack.engine} run ${name}: ${run.stderr}`);
  return () => spawnSync(stack.engine, ["rm", "-f", full], { encoding: "utf8" });
}

/// The JSON error body of a firewall refusal ({error, reason, request_id}), or {}.
export function errorOf(answer) {
  try {
    return answer.json();
  } catch {
    return {};
  }
}
