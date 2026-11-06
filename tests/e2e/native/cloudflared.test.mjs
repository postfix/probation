// The pinned cloudflared: official URL for the pinned version only, SHA-256 checked before it can run.
// NATIVE_TEST_SCRATCH=<disk dir> node tests/e2e/native/cloudflared.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { downloadUrl, installVerified, loadPin, redirectAllowed, sha256Of } from "./cloudflared.mjs";

const scratch = process.env.NATIVE_TEST_SCRATCH;
assert(scratch, "set NATIVE_TEST_SCRATCH");
const pin = loadPin();
assert.match(pin.version, /^\d{4}\.\d+\.\d+$/, "an exact release, not latest");
assert.match(pin.sha256, /^[0-9a-f]{64}$/);
assert.equal(pin.asset, "cloudflared-linux-amd64");
assert.equal(downloadUrl(pin), `https://github.com/cloudflare/cloudflared/releases/download/${pin.version}/cloudflared-linux-amd64`, "the official release URL of that version");
for (const bad of [{ version: "latest", asset: pin.asset }, { version: "2026.10", asset: pin.asset }, { version: pin.version, asset: "cloudflared-linux-amd64.deb" },
  { version: pin.version, asset: "../x" }, { version: `${pin.version}/../../evil`, asset: pin.asset }]) {
  assert.throws(() => downloadUrl(bad), /official|version|asset/, JSON.stringify(bad));
}
// Redirects stay on GitHub's own hosts over https.
for (const ok of ["https://github.com/cloudflare/cloudflared/releases/download/x/y", "https://objects.githubusercontent.com/a", "https://release-assets.githubusercontent.com/a"]) assert.ok(redirectAllowed(ok), ok);
for (const bad of ["http://github.com/x", "https://evil.example/x", "https://github.com.evil.example/x", "https://githubusercontent.com.evil.example/x", "https://user@github.com/x", "not a url"]) assert.ok(!redirectAllowed(bad), bad);

const bytes = Buffer.from("pretend cloudflared binary");
assert.equal(sha256Of(bytes), createHash("sha256").update(bytes).digest("hex"));
const dir = mkdtempSync(join(scratch, "cf-"));
// A matching download is installed executable; the checksum is verified before the file gets its name or mode.
const dest = join(dir, "cloudflared");
await installVerified({ url: "https://github.com/x", expected: sha256Of(bytes), dest, download: async () => bytes });
assert.deepEqual(readFileSync(dest), bytes);
if (process.platform !== "win32") assert.ok(statSync(dest).mode & 0o100, "executable after verification");
// A different file is refused, never written under the final name, and any older file there is removed.
const dest2 = join(dir, "other");
writeFileSync(dest2, "stale");
await assert.rejects(installVerified({ url: "https://github.com/x", expected: sha256Of(bytes), dest: dest2, download: async () => Buffer.from("tampered") }), /checksum/);
assert.ok(!existsSync(dest2), "nothing is left under the final name");
assert.ok(!existsSync(`${dest2}.part`), "nor a partial file");
await assert.rejects(installVerified({ url: "https://github.com/x", expected: "0".repeat(63), dest: join(dir, "z"), download: async () => bytes }), /expected/);
rmSync(dir, { recursive: true, force: true });
console.log("cloudflared.test: ok");
