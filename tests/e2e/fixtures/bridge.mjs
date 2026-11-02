// The host's way into the internal e2e network: an HTTP CONNECT proxy on the one
// published port. The harness's HTTP client and Playwright Chromium both tunnel
// through it, so from the host every service is reached by the same name, port and
// certificate as from inside the stack. It only opens tunnels to addresses on the e2e
// network itself, so nothing the host does through it reaches the internet.

import { lookup } from "node:dns/promises";
import http from "node:http";
import net from "node:net";

const prefix = process.env.E2E_SUBNET_PREFIX;
const gatewayHosts = new Set(["portal.e2e.test", "sync.e2e.test", "fw1.e2e.test", "fw2.e2e.test", "fw-standalone.e2e.test"]);

const server = http.createServer((_, res) => res.writeHead(405).end("CONNECT only\n"));
server.on("connect", async (req, client, head) => {
  const at = req.url.lastIndexOf(":");
  const host = req.url.slice(0, at);
  const port = Number(req.url.slice(at + 1));
  try {
    const address = gatewayHosts.has(host) ? `${prefix}10` : (await lookup(host, { family: 4 })).address;
    if (!address.startsWith(prefix)) throw new Error(`${host} is ${address}, outside the e2e network`);
    const upstream = net.connect(port, address, () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on("error", () => client.destroy());
    client.on("error", () => upstream.destroy());
  } catch (err) {
    client.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n${err.message}\n`);
  }
});
server.listen(3128, () => console.log("bridge listening"));
