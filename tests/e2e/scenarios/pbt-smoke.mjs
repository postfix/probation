// PBT-smoke: the PR suite's short run of the model-based portal test (PBT-model), with a
// fixed seed: one sequence of up to 8 commands on the shared stack, about a minute. It
// puts the platform layer back as it found it. The full runs are the pbt and
// pbt-weekly suites (harness/pbt.mjs `settings`).

import { modelProperty, settings } from "../harness/pbt.mjs";

export const meta = {
  id: "PBT-smoke",
  title: "Portal model, smoke: one fixed-seed command sequence",
  suites: ["pr"],
};

export default async function (h) {
  await modelProperty(h, settings("pr"));
}
