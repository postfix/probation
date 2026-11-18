import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/// The row-28 shared service as the e2e stack has it: the standalone firewall (https://fw-standalone.e2e.test) with its
/// listener admitting the gateway peer, which is how service-policy.mjs configures it. Package reads need no login.
export async function startCommonService(h) {
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  return "https://fw-standalone.e2e.test";
}
