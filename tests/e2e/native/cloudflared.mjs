// The pinned cloudflared binary for the real-server job's quick tunnel. It is downloaded only from the
// official GitHub release URL of the version pinned in tunnel.json, and its SHA-256 is checked against the
// pin before the file gets its name or its executable bit. Nothing else runs it.
//   node tests/e2e/native/cloudflared.mjs fetch <dir>     writes <dir>/cloudflared; sets CLOUDFLARED in $GITHUB_ENV
import { createHash } from "node:crypto";
import { appendFileSync, chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import https from "node:https";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export function loadPin() {
  return JSON.parse(readFileSync(fileURLToPath(new URL("./tunnel.json", import.meta.url)), "utf8")).cloudflared;
}

/// The official release URL of an exact version's Linux x64 binary; nothing else is accepted.
export function downloadUrl({ version, asset }) {
  if (!/^\d{4}\.\d+\.\d+$/.test(version)) throw new Error(`cloudflared version must be an exact release like 2026.10.7, got ${JSON.stringify(version)}`);
  if (asset !== "cloudflared-linux-amd64") throw new Error(`cloudflared asset must be cloudflared-linux-amd64, got ${JSON.stringify(asset)}`);
  return `https://github.com/cloudflare/cloudflared/releases/download/${version}/${asset}`;
}

/// A redirect may only stay on GitHub's own hosts, over https, without credentials.
export function redirectAllowed(target) {
  let url;
  try { url = new URL(target); } catch { return false; }
  if (url.protocol !== "https:" || url.username || url.password) return false;
  return url.hostname === "github.com" || url.hostname.endsWith(".githubusercontent.com");
}

export const sha256Of = (bytes) => createHash("sha256").update(bytes).digest("hex");

/// `timeoutMs` bounds each socket's idleness (connect, headers, every body chunk), so a stalled server cannot hang the job.
/// `get` is the test seam for a plain-http local server.
export function defaultDownload(url, { hops = 0, timeoutMs = 120_000, get = https.get } = {}) {
  return new Promise((resolve, reject) => {
    const req = get(url, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        res.resume();
        if (!res.headers.location) return reject(new Error(`redirect ${res.statusCode} without a Location header`));
        let next;
        try { next = new URL(res.headers.location, url).href; } catch { return reject(new Error(`unparsable redirect ${res.headers.location}`)); }
        if (hops >= 5 || !redirectAllowed(next)) return reject(new Error(`refusing the redirect to ${next}`));
        return resolve(defaultDownload(next, { hops: hops + 1, timeoutMs, get }));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`download answered ${res.statusCode}`)); }
      const chunks = [];
      res.on("data", (c) => chunks.push(c)).on("end", () => resolve(Buffer.concat(chunks))).on("error", reject);
    });
    req.setTimeout(timeoutMs, () => { reject(new Error(`download timed out after ${timeoutMs} ms`)); req.destroy(); });
    req.on("error", reject);
  });
}

export async function installVerified({ url, expected, dest, download = defaultDownload }) {
  if (!/^[0-9a-f]{64}$/.test(expected)) throw new Error("the expected checksum is not a SHA-256 hex digest");
  rmSync(dest, { force: true });
  const bytes = await download(url);
  const actual = sha256Of(bytes);
  if (actual !== expected) throw new Error(`checksum mismatch for ${url}: expected ${expected}, got ${actual}`);
  const partial = `${dest}.part`;
  writeFileSync(partial, bytes);
  chmodSync(partial, 0o755);
  renameSync(partial, dest);
  return actual;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const [command, dir] = process.argv.slice(2);
  if (command !== "fetch" || !dir) { console.error("usage: cloudflared.mjs fetch <dir>"); process.exit(2); }
  const pin = loadPin();
  mkdirSync(dir, { recursive: true });
  const dest = join(dir, "cloudflared");
  try {
    const sha = await installVerified({ url: downloadUrl(pin), expected: pin.sha256, dest });
    console.log(`cloudflared ${pin.version} verified (sha256 ${sha})`);
    if (process.env.GITHUB_ENV) appendFileSync(process.env.GITHUB_ENV, `CLOUDFLARED=${dest}\n`);
  } catch (error) {
    console.error(`cloudflared was not installed: ${error.message}`);
    process.exit(1);
  }
}
