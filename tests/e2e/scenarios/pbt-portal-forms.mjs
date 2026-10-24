// PBT-forms: the input properties of every portal form (harness/pbt-forms.mjs). Random
// strings (unicode with confusables, zero-width and bidi characters, HTML and script
// fragments, very long, empty and whitespace values, SQL-ish text, malformed emails,
// CIDR ranges and versions) go into one field at a time: no 5xx and the security
// headers on every answer; the value is refused with a message and nothing changes, or
// stored and shown escaped (no raw markup in the page, none in Chromium's DOM); and
// without its CSRF token every form answers 403 and writes nothing.

import { formProperties } from "../harness/pbt-forms.mjs";
import { settings } from "../harness/pbt.mjs";

export const meta = {
  id: "PBT-forms",
  title: "Portal forms: random input, escaping, refusals that change nothing, CSRF",
  suites: ["pbt", "pbt-weekly"],
  stack: "own",
};

export default async function (h) {
  await formProperties(h, settings(h.suite));
}
