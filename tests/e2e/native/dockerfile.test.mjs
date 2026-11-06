// S6: base images by digest, Python tools by exact version and hash.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
// NATIVE_CLIENTS_DIR lets crlf.test.py point this at CRLF copies.
const dir = process.env.NATIVE_CLIENTS_DIR ? `${process.env.NATIVE_CLIENTS_DIR}/` : new URL("../compose/clients/", import.meta.url).href;
const load = (name) => readFileSync(process.env.NATIVE_CLIENTS_DIR ? `${dir}${name}` : new URL(name, dir), "utf8").replace(/\r\n/g, "\n"); // a Windows checkout may be CRLF
const dockerfile = load("native.Dockerfile");
const defaults = [...dockerfile.matchAll(/^ARG (?:NODE|PYTHON)_IMAGE=(\S+)$/gm)].map((m) => m[1]);
assert.equal(defaults.length, 2);
for (const image of defaults) assert.match(image, /@sha256:[0-9a-f]{64}$/, `${image} is pinned by digest`);
assert.match(dockerfile, /pip install[^\n]*--require-hashes[^\n]*-r /, "tools are installed from a hashed requirements file");
const requirements = load("native-requirements.txt");
const pins = [...requirements.matchAll(/^([A-Za-z0-9_.-]+)==([^\s\\]+)/gm)].map((m) => `${m[1].toLowerCase()}==${m[2]}`);
for (const wanted of ["twine==7.0.0", "uv==0.13.5"]) assert.ok(pins.includes(wanted), `${wanted} is pinned`);
assert.ok(/--hash=sha256:[0-9a-f]{64}/.test(requirements));
const logicalLines = requirements.replace(/\\\n/g, " ").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
const unhashed = logicalLines.filter((l) => !/(\s--hash=sha256:[0-9a-f]{64})+$/.test(l));
assert.equal(unhashed.length, 0, `every requirement carries a hash, unhashed: ${unhashed.slice(0, 3).join(" | ")}`);
assert.ok(logicalLines.length >= 20, "the file lists the tools and their dependencies");
console.log("dockerfile.test: ok");
