// The harness lockfile installs from the public registry: every `resolved` URL is the canonical registry form of its
// package and version (a lockfile written through a local firewall once pointed at https://localhost:8443/npm/artifacts/...,
// which no runner can reach), and no tracked lockfile or requirements file names a loopback address.
// node tests/e2e/native/lockfile.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const lock = JSON.parse(readFileSync(`${root}/tests/e2e/package-lock.json`, "utf8"));
const canonical = (path, version) => {
  const name = path.replace(/^.*node_modules\//, "");
  return `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${version}.tgz`;
};
let checked = 0;
for (const [path, entry] of Object.entries(lock.packages)) {
  if (!entry.resolved) continue;
  checked++;
  assert.equal(entry.resolved, canonical(path, entry.version), `${path}@${entry.version} must resolve to the public registry`);
  assert.match(entry.integrity ?? "", /^sha512-/, `${path} keeps an integrity hash`);
}
assert.ok(checked >= 6, `the lockfile resolves ${checked} packages`);

const tracked = spawnSync("git", ["ls-files", "--", "*package-lock.json", "*requirements*.txt", "*.lock", "*pnpm-lock.yaml", "*yarn.lock"], { cwd: root, encoding: "utf8" }).stdout.split("\n").filter(Boolean);
assert.ok(tracked.includes("tests/e2e/package-lock.json"), "git ls-files sees the lockfile");
for (const file of tracked.filter((f) => !f.startsWith(".scratch/") && !f.includes("node_modules/"))) {
  const text = readFileSync(`${root}/${file}`, "utf8");
  assert.ok(!/https?:\/\/(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)[:/]/.test(text), `${file} names a loopback address`);
}
console.log("lockfile.test: ok");
