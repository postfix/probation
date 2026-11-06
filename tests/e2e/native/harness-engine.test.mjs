// The gateway's DNS resolver depends on the container engine: Docker's embedded DNS is 127.0.0.11, Podman's (netavark/aardvark)
// answers on the network's gateway address. Hosted runners run Docker Engine; the harness had only the Podman value, so nginx's
// upstream names (firewall-1 ...) never resolved and fw1's TLS handshake timed out (hosted linux-managed run 42214231528).
// node tests/e2e/native/harness-engine.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolverFor } from "../harness/stack.mjs";

assert.equal(resolverFor({ versionText: "podman version 5.4.2", net: "11.220.0" }), "11.220.0.1");
assert.equal(resolverFor({ versionText: "Docker version 28.0.4, build b8034c0", net: "11.220.0" }), "127.0.0.11");
assert.equal(resolverFor({ versionText: "Docker version 29.9.2, build x", net: "11.221.0" }), "127.0.0.11");
assert.equal(resolverFor({ versionText: "", net: "11.220.0" }), "127.0.0.11", "an unknown engine is treated as Docker");
assert.equal(resolverFor({ versionText: "Docker version 28", net: "11.220.0", override: "10.0.0.53" }), "10.0.0.53", "E2E_RESOLVER wins");
// The gateway configuration still takes its resolver from the placeholder the harness fills in.
assert.match(readFileSync(new URL("../compose/gateway-nginx.conf", import.meta.url), "utf8"), /resolver E2E_RESOLVER/);
console.log("harness-engine.test: ok");
