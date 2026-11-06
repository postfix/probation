// Local stand-in for the native jobs when the real-server scenario runs with E2E_TUNNEL=stub (no cloudflared, no
// hosted runners): waits for the handshake file, then does for each label what a native job does through the tunnel
// (a labelled probe, then the probation's own unlabelled snapshot request) with a distinct made-up tunnel-client
// address, and writes `release`. node tests/e2e/native/remote-sim.mjs <dir> [label,label,...] [--skip-label X]
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import { join } from "node:path";

const [dir, labelList = "linux-x64,darwin-arm64,win32-x64"] = process.argv.slice(2);
const skip = process.argv.includes("--skip-label") ? process.argv[process.argv.indexOf("--skip-label") + 1] : null;
const handshake = join(dir, "handshake.json");
const until = Date.now() + 15 * 60_000;
while (!existsSync(handshake) && Date.now() < until) await new Promise((r) => setTimeout(r, 1000));
const { url, key } = JSON.parse(readFileSync(handshake, "utf8"));
const get = (headers) => new Promise((resolve) => http.get(`${url}/api/v1/policy/snapshot`, { headers: { authorization: `Bearer ${key}`, ...headers } }, (res) => { res.resume(); resolve(res.statusCode); }));
const labels = labelList.split(",").filter((l) => l !== skip);
for (const [i, label] of labels.entries()) {
  const ip = `203.0.113.${10 + i}`;
  console.log(`${label}: probe ${await get({ "x-native-job": label, "cf-connecting-ip": ip })}`);
  if (label !== "darwin-arm64" || !process.argv.includes("--no-native-request")) console.log(`${label}: native request ${await get({ "cf-connecting-ip": ip })}`);
}
writeFileSync(join(dir, "release"), "release\n");
