// Preloaded (node --import) by run_tests.py: counts the calls made to node:assert's checking
// functions, so a test whose assertions were commented out cannot pass by printing its success line.
import assert from "node:assert";
import { writeFileSync } from "node:fs";

let count = 0;
// assert.match / doesNotMatch compare their own identity to the exported function, so wrapping
// them would invert them; they are re-implemented instead.
const own = {
  match(string, regexp, message) { count++; if (typeof string !== "string" || !regexp.test(string)) throw new assert.AssertionError({ message: message ?? `${string} does not match ${regexp}`, actual: string, expected: regexp, operator: "match" }); },
  doesNotMatch(string, regexp, message) { count++; if (typeof string === "string" && regexp.test(string)) throw new assert.AssertionError({ message: message ?? `${string} matches ${regexp}`, actual: string, expected: regexp, operator: "doesNotMatch" }); },
};
const wrap = (target) => {
  Object.assign(target, own);
  for (const key of Object.keys(target)) {
    if (typeof target[key] !== "function" || /^[A-Z]/.test(key) || key === "strict" || key in own) continue;
    const original = target[key];
    target[key] = function counted(...args) { count++; return original.apply(this, args); };
  }
};
wrap(assert);
wrap(assert.strict);
process.on("exit", () => {
  if (process.env.NATIVE_ASSERT_COUNT_FILE) writeFileSync(process.env.NATIVE_ASSERT_COUNT_FILE, String(count));
});
