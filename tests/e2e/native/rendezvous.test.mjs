// The handshake between the real-server job and the native jobs, with a fake clock and a fake artifact API.
// node tests/e2e/native/rendezvous.test.mjs
import assert from "node:assert/strict";
import { handshakeArtifact, doneArtifact, envLines, maskLines, parseHandshake, pollUntil, waitForArtifact, waitForAll, failedHandshake, signalablePid } from "./rendezvous.mjs";

const key = "prb_" + "e".repeat(32);
const ready = { status: "ready", url: "https://quiet-river-1234.trycloudflare.com", key, npmId: 4, pypiId: 5, npmPort: 43111, hiddenName: "token-private-ab12cd34" };

// A fake clock: sleeping advances time, so a bounded poll finishes at once.
const clock = () => { let t = 0; return { now: () => t, sleep: async (ms) => { t += ms; } }; };

// pollUntil: returns the first truthy value, calls the check as often as the interval allows, then times out.
{
  const { now, sleep } = clock();
  let calls = 0;
  assert.equal(await pollUntil({ check: async () => (++calls === 4 ? "found" : null), timeoutMs: 60_000, intervalMs: 5_000, now, sleep }), "found");
  assert.equal(calls, 4);
  const c2 = clock();
  let n = 0;
  await assert.rejects(pollUntil({ check: async () => { n++; return null; }, timeoutMs: 20_000, intervalMs: 5_000, now: c2.now, sleep: c2.sleep, what: "the handshake" }), /timed out after 20 s waiting for the handshake/);
  assert.equal(n, 5, "checked at 0, 5, 10, 15 and 20 s, then gave up");
}

// waitForArtifact: lists the run's artifacts until the named one appears.
{
  const { now, sleep } = clock();
  let polls = 0;
  const list = async () => (++polls < 3 ? [{ name: "other" }] : [{ name: "other" }, { name: handshakeArtifact("1") }]);
  assert.equal((await waitForArtifact({ list, name: handshakeArtifact("1"), timeoutMs: 600_000, intervalMs: 10_000, now, sleep })).name, handshakeArtifact("1"));
  assert.equal(polls, 3);
  const c = clock();
  await assert.rejects(waitForArtifact({ list: async () => [], name: handshakeArtifact("1"), timeoutMs: 30_000, intervalMs: 10_000, now: c.now, sleep: c.sleep }), /timed out/);
  // A listing error does not end the wait: the next poll tries again.
  const d = clock();
  let flaky = 0;
  assert.ok(await waitForArtifact({ list: async () => { if (++flaky < 3) throw new Error("502"); return [{ name: "x" }]; }, name: "x", timeoutMs: 600_000, intervalMs: 10_000, now: d.now, sleep: d.sleep }));
}

// waitForAll: the server waits for every expected job's done artifact, or the deadline.
{
  const { now, sleep } = clock();
  const present = new Set();
  let polls = 0;
  const list = async () => { polls++; if (polls === 2) present.add("native-done-linux-x64-1"); if (polls === 3) present.add("native-done-win32-x64-1"); if (polls === 4) present.add("native-done-darwin-arm64-1"); return [...present].map((name) => ({ name })); };
  const done = await waitForAll({ list, names: ["linux-x64", "darwin-arm64", "win32-x64"].map((l) => doneArtifact(l, "1")), timeoutMs: 600_000, intervalMs: 10_000, now, sleep });
  assert.deepEqual(done.missing, []);
  const c = clock();
  const partial = await waitForAll({ list: async () => [{ name: doneArtifact("linux-x64", "1") }], names: ["linux-x64", "darwin-arm64"].map((l) => doneArtifact(l, "1")), timeoutMs: 40_000, intervalMs: 10_000, now: c.now, sleep: c.sleep });
  assert.deepEqual(partial.missing, [doneArtifact("darwin-arm64", "1")], "the deadline returns what is still missing instead of hanging");
  assert.equal(c.now() <= 40_000, true, "and never waits past the deadline");
}

// The handshake: strict, because a job sends its throwaway key to the URL in it.
assert.deepEqual(parseHandshake(JSON.stringify(ready)), ready);
const bad = (patch, why) => assert.throws(() => parseHandshake(JSON.stringify({ ...ready, ...patch })), /handshake/, why);
bad({ url: "https://evil.example/" }, "another host");
bad({ url: "https://quiet-river-1234.trycloudflare.com.evil.example" }, "a suffix trick");
bad({ url: "http://quiet-river-1234.trycloudflare.com" }, "not https");
bad({ url: "https://quiet-river-1234.trycloudflare.com/path" }, "a path");
bad({ url: "https://user@quiet-river-1234.trycloudflare.com" }, "credentials");
bad({ url: "https://quiet-river-1234.trycloudflare.com:8443" }, "a port");
bad({ key: "prb_short" }, "a malformed key");
bad({ npmPort: 80 }, "a port outside the high range");
bad({ npmId: -1 }, "an id");
bad({ hiddenName: "../x" }, "a hidden name");
bad({ status: "ok" }, "an unknown status");
assert.throws(() => parseHandshake("not json"), /handshake/);
assert.throws(() => parseHandshake(JSON.stringify(failedHandshake("tunnel did not come up"))), /server job failed: tunnel did not come up/);

// Masks come first and cover the URL, its host and the key; the env lines carry no key.
const masks = maskLines(ready);
assert.deepEqual(masks, [`::add-mask::${ready.url}`, "::add-mask::quiet-river-1234.trycloudflare.com", `::add-mask::${key}`]);
const env = envLines(ready, "/tmp/hs/service.key");
assert.ok(env.includes("NATIVE_POLICY_URL=https://quiet-river-1234.trycloudflare.com"));
assert.ok(env.includes("NATIVE_SERVICE_KEY_FILE=/tmp/hs/service.key"));
assert.ok(env.includes("NATIVE_NPM_PORT=43111") && env.includes("NATIVE_NPM_REGISTRY_ID=4") && env.includes("NATIVE_PYPI_REGISTRY_ID=5") && env.includes("NATIVE_HIDDEN_NAME=token-private-ab12cd34"));
assert.ok(env.includes("NATIVE_POLICY_PUBLIC_TRUST=1"), "the tunnel's certificate is a public one");
assert.ok(!env.join("\n").includes(key), "the key is in a file, not in the environment");
assert.equal(doneArtifact("win32-x64", "2"), "native-done-win32-x64-2");
assert.equal(handshakeArtifact("3"), "native-handshake-3");
assert.notEqual(doneArtifact("win32-x64", "1"), doneArtifact("win32-x64", "2"), "a re-run attempt has its own artifact names");
for (const label of ["../x", "x\n", "-", "a--b", "-a", "a-", ""]) assert.throws(() => doneArtifact(label, "1"), /label/, JSON.stringify(label));
for (const attempt of [undefined, "", "0", "1x", "x1", "1\n", "-1"]) { assert.throws(() => doneArtifact("linux-x64", attempt), /attempt/); assert.throws(() => handshakeArtifact(attempt), /attempt/); }
// a long failure reason is kept whole; a pypiId that is no registry id is refused
assert.equal(failedHandshake("r".repeat(1000)).reason.length, 1000);
bad({ pypiId: 0 }, "a zero pypi id");
bad({ pypiId: "5" }, "a string pypi id");
bad({ pypiId: 1.5 }, "a fractional pypi id");
bad({ pypiId: 2 ** 40 }, "an absurd pypi id");
bad({ pypiId: undefined }, "a missing pypi id");
// signalablePid: only plain decimal pids above 1 (a trailing newline from `echo $! > file` is fine).
for (const [text, want] of [["12345\n", 12345], ["2", 2], ["12345", 12345], ["12345\r\n", 12345]]) assert.equal(signalablePid(text), want, JSON.stringify(text));
for (const bad of ["1", "1\n", "0", "-3", "-12345", "+12", "1e3", "0x10", "0b11", "0o7", " 12\n", "\n12", "1 2", "12abc", "1.5", "", "abc", "007", "9007199254740993", "99999999999999999999", "Infinity", "NaN", undefined, null]) {
  assert.equal(signalablePid(bad), null, `${JSON.stringify(bad)} is refused`);
}
console.log("rendezvous.test: ok");
