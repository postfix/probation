// What the cloudflared quick tunnel points at, and the only thing it exposes: `GET /api/v1/policy/snapshot`
// carrying this run's throwaway service key (the one call a native probation makes to the policy server).
// Everything else is refused here and never reaches the real server. `forward(authorization)` asks the real
// server and answers {status, contentType, body}. The log records, for each request, the job label
// (X-Native-Job, set by the jobs' own probe), the tunnel client's address (Cf-Connecting-Ip), whether the key
// was right and what was answered, so the real-server job can prove who talked to it.
import http from "node:http";

export const SNAPSHOT_PATH = "/api/v1/policy/snapshot";

export async function startSnapshotProxy({ key, forward, host = "127.0.0.1", maxLog = 10_000 }) {
  const log = [];
  let dropped = 0; // the tunnel is public: unauthenticated requests are logged only up to maxLog, then counted
  const server = http.createServer(async (req, res) => {
    const entry = {
      at: new Date().toISOString(), method: req.method, path: req.url,
      label: req.headers["x-native-job"] ?? null, cfIp: req.headers["cf-connecting-ip"] ?? null,
      keyOk: req.headers.authorization === `Bearer ${key}`, status: 0,
    };
    if (entry.keyOk || log.length < maxLog) log.push(entry); else dropped++;
    const answer = (status, body = "", type = "text/plain") => { entry.status = status; res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body) }); res.end(body); };
    req.resume();
    if (req.method !== "GET" || req.url !== SNAPSHOT_PATH) return answer(404, "not found\n");
    if (!entry.keyOk) return answer(401, "unauthorized\n");
    try {
      const upstream = await forward(req.headers.authorization);
      entry.status = upstream.status;
      res.writeHead(upstream.status, { "content-type": upstream.contentType ?? "application/json", "content-length": upstream.body.length });
      res.end(upstream.body);
    } catch {
      answer(502, "bad gateway\n");
    }
  });
  await new Promise((resolve) => server.listen(0, host, resolve));
  return {
    port: server.address().port,
    log,
    dropped: () => dropped,
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections?.(); }),
  };
}
