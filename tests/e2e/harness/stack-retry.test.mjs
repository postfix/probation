// Run: node --test tests/e2e/harness/stack-retry.test.mjs
// Slice 27 recheck F7: `up()` retries only engine and one-off-step failures, and records each retry; a product start failure is never retried.
import assert from "node:assert/strict";
import test from "node:test";
import { Stack } from "./stack.mjs";

function stackFailing(messages) {
  const stack = Object.create(Stack.prototype);
  stack.project = "probation-test";
  let attempts = 0;
  stack.bringUp = async () => {
    const message = messages[attempts++];
    if (message === undefined) return "up";
    throw new Error(message);
  };
  stack.down = () => {};
  return { stack, attempts: () => attempts };
}

test("an IPAM failure is retried and recorded", async () => {
  const { stack, attempts } = stackFailing(["Error: IPAM already allocated 11.220.0.5"]);
  assert.equal(await stack.up(), "up");
  assert.equal(attempts(), 2);
  assert.equal(stack.upRetries.length, 1);
  assert.match(stack.upRetries[0].error, /IPAM/);
});

test("a one-off step's pool timeout is retried", async () => {
  const { stack } = stackFailing(["harness one-off step admin bootstrap: pool timed out while waiting for an open connection"]);
  assert.equal(await stack.up(), "up");
  assert.equal(stack.upRetries.length, 1);
});

for (const message of ["ECONNREFUSED 127.0.0.1:443", "socket hang up", "the portal not within 120000 ms (connect) ", "pool timed out while waiting for an open connection"]) {
  test(`a product-side failure is not retried: ${message}`, async () => {
    const { stack, attempts } = stackFailing([message, undefined]);
    await assert.rejects(stack.up(), new RegExp(message.slice(0, 12)));
    assert.equal(attempts(), 1);
    assert.equal((stack.upRetries ?? []).length, 0);
  });
}
