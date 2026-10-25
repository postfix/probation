// PBT-model: the model-based property test of the portal (harness/pbt.mjs). Random
// sequences of what people do in the portal (sign-up, sign-in, authenticator, groups,
// invitations, roles, removal and leaving, keys, blocks, exceptions, freezes, OSV, places,
// suspension, deleting and restoring a login) run against the deployed stack. After
// every command each person's portal must show what the model says and nothing of
// another tenant, refusals must match their role and second factor, and the audit log
// must have exactly the command's rows; a sample of keys must get the model's decision
// from the firewalls. On failure fast-check shrinks the sequence; the message has the
// seed, the path and the minimal sequence (replay: E2E_PBT_SEED, E2E_PBT_PATH,
// E2E_PBT_REPLAY). Bounds: harness/pbt.mjs `settings`.

import { modelProperty, settings } from "../harness/pbt.mjs";

export const meta = {
  id: "PBT-model",
  title: "Portal model: random command sequences against isolation, permissions, audit and firewall truth",
  suites: ["pbt", "pbt-weekly"],
  stack: "own",
};

export default async function (h) {
  await modelProperty(h, settings(h.suite));
}
