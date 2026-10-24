// PBT-regressions: the cases the property-based tests found, fixed (harness/pbt.mjs,
// harness/pbt-forms.mjs). Each fails until the product is fixed.
//
// 1. PBT-forms, seeds 102 and 103, shrunk to `fleet register name = "\u0000"`: a NUL
//    character in a text field reaches Postgres, which refuses it, and the portal
//    answers 503 "The portal is unavailable" instead of refusing the value with a
//    message. The case runs on every form, to show which ones (12 in October 2026).
// 2. PBT-model, seed 105 path 9:3:4:4:3:6:5:3, shrunk to `CheckFirewall; PlatformSettings
//    (freeze 0 hours); CheckFirewall`: a firewall that looked a key up just before a
//    policy change keeps the old decision for about 5 minutes (held for 287 s and more,
//    while the other firewall allowed it at once). Known and being fixed: "needs
//    stale-key-policy". Replayed as shrunk.

import { formCases } from "../harness/pbt-forms.mjs";
import { CheckFirewall, PlatformSettings, replay, settings } from "../harness/pbt.mjs";

export const meta = {
  id: "PBT-regressions",
  title: "Property-based test findings, as fixed cases",
  suites: ["pbt", "pbt-weekly"],
  stack: "own",
};

export default async function (h) {
  const failures = [];
  const step = (run) => run().catch((err) => failures.push(err.message));
  await step(() => formCases(h, settings(h.suite), [[null, "\u0000"]]));
  // The shrunk sequence, after the cast; firewall checks of 3 keys (the pbt profile).
  await step(() =>
    replay(
      h,
      [
        new CheckFirewall({ sample: 0, probe: 0 }),
        new PlatformSettings({ freeze: 1, shorter: false, exceptions: true, probe: 0 }),
        new CheckFirewall({ sample: 979, probe: 0 }),
      ],
      { ...settings("pbt"), firewallSample: 3 },
    ),
  );
  h.expect(failures.length === 0, failures.join("\n"));
}
