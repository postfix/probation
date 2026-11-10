// SEC4: the macOS loopback redirect of port 443 (argument construction only; pf itself is only on macOS).
// node tests/e2e/native/pf.test.mjs
import assert from "node:assert/strict";
import { parsePfToken, pfRules, pfSteps } from "./pf.mjs";

assert.equal(pfRules({ from: 443, to: 44300 }),
  "rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 44300\n"
  + "pass out on lo0 route-to (lo0 127.0.0.1) inet proto tcp from any to 127.0.0.1 port 443 keep state\n");
for (const bad of [0, 65536, 44.5, "443 -> 1", "x", -1, undefined]) {
  assert.throws(() => pfRules({ from: 443, to: bad }), /port/, `to=${bad}`);
  assert.throws(() => pfRules({ from: bad, to: 44300 }), /port/, `from=${bad}`);
}
const steps = pfSteps({ from: 443, to: 44300 });
assert.deepEqual(steps.load, { command: "sudo", args: ["-n", "pfctl", "-f", "-"], input: pfRules({ from: 443, to: 44300 }) });
assert.deepEqual(steps.enable, { command: "sudo", args: ["-n", "pfctl", "-E"] });
assert.deepEqual(steps.restore, { command: "sudo", args: ["-n", "pfctl", "-f", "/etc/pf.conf"] });
assert.deepEqual(steps.release("12345"), { command: "sudo", args: ["-n", "pfctl", "-X", "12345"] });
for (const bad of ["12345; reboot", "", "1 2", undefined, "-X"]) assert.throws(() => steps.release(bad), /token/);
assert.equal(parsePfToken("pf enabled\nToken : 18446744073709551615\n"), "18446744073709551615");
assert.equal(parsePfToken("pf already enabled\n"), null);
assert.equal(parsePfToken("pf enabled\nToken : 123\n"), "123", "the token line is not the first line");
assert.equal(parsePfToken("a\nb\nToken:7"), "7");
// release takes only a string of digits; the token line must start the line with "Token" and carry digits.
for (const bad of [12345, null, ["12"], { toString: () => "12" }]) assert.throws(() => steps.release(bad), /token/, `non-string ${typeof bad}`);
assert.equal(parsePfToken("xToken : 1\n"), null, "the Token anchor");
assert.equal(parsePfToken("Token : \n"), null, "digits are required");
assert.equal(parsePfToken("Token : x1\n"), null, "digits directly after the colon");
console.log("pf.test: ok");
