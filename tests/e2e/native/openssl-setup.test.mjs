// The service links OpenSSL's libcrypto by name (`#[link(name = "crypto")]` in src/managed/enterprise_certificate.rs, the OCSP
// code), so a runner needs one the linker can find: Linux has the system library, macOS needs Homebrew's openssl@3 on the library
// path, Windows needs an MSVC import library named crypto.lib (OpenSSL ships it as libcrypto.lib) and its DLL on PATH.
// node tests/e2e/native/openssl-setup.test.mjs
import assert from "node:assert/strict";
import { assertSingleLine, buildPlan, findImportLibrary, windowsRoots } from "./openssl-setup.mjs";

// macOS: Homebrew's lib directory is added to the linker's search path.
const US = "\x1f"; // CARGO_ENCODED_RUSTFLAGS separates flags with it, so a path may hold spaces
assert.deepEqual(buildPlan({ platform: "darwin", brewPrefix: "/opt/homebrew/opt/openssl@3" }), { env: { CARGO_ENCODED_RUSTFLAGS: `-L${US}native=/opt/homebrew/opt/openssl@3/lib` }, path: [], shim: null });
assert.throws(() => buildPlan({ platform: "darwin", brewPrefix: "" }), /Homebrew/);
// Linux: the system libcrypto (libssl-dev) is already on the default path.
assert.deepEqual(buildPlan({ platform: "linux" }), { env: {}, path: [], shim: null });
// Windows: the import library is copied under the name rustc asks for, and the DLL directory goes on PATH.
const plan = buildPlan({ platform: "win32", found: { lib: "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libcrypto.lib", bin: "C:\\Program Files\\OpenSSL-Win64\\bin", dll: "C:\\Program Files\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll" }, shimDir: "D:\\a\\_temp\\openssl-shim" });
assert.deepEqual(plan.shim, { from: "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libcrypto.lib", to: "D:\\a\\_temp\\openssl-shim\\crypto.lib" });
assert.deepEqual(plan.env, { CARGO_ENCODED_RUSTFLAGS: `-L${US}native=D:/a/_temp/openssl-shim` }, "forward slashes in the flag");
assert.deepEqual(plan.path, ["D:\\a\\_temp\\openssl-shim"], "only the shim directory goes on PATH, never the whole OpenSSL bin");
assert.deepEqual(plan.dll, { from: "C:\\Program Files\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll", to: "D:\\a\\_temp\\openssl-shim\\libcrypto-3-x64.dll" });
assert.throws(() => buildPlan({ platform: "win32", found: null, shimDir: "x" }), /import library/);

// o12: a plan on Windows never goes ahead with a missing DLL or DLL directory.
assert.throws(() => buildPlan({ platform: "win32", found: { lib: "C:\\x\\libcrypto.lib", bin: null, dll: null }, shimDir: "D:\\s" }), /DLL/);
assert.throws(() => buildPlan({ platform: "win32", found: { lib: "C:\\x\\libcrypto.lib", bin: "C:\\x\\bin", dll: null }, shimDir: "D:\\s" }), /DLL/);
assert.throws(() => buildPlan({ platform: "win32", found: { lib: "C:\\x\\libcrypto.lib", bin: null, dll: "C:\\x\\bin\\libcrypto-3.dll" }, shimDir: "D:\\s" }), /DLL/);

// o2: only libcrypto-<digit>...dll counts as the DLL.
for (const bad of ["libcrypto.dll", "xlibcrypto-3.dll", "libcrypto-x.dll", "libcrypto-3.dll.bak", "libcrypto-3.dllx", "libssl-3-x64.dll"]) {
  const t = { "R": ["bin", "lib"], "R\\bin": [bad], "R\\lib": ["libcrypto.lib"] };
  assert.deepEqual(findImportLibrary(["R"], { list: (d) => t[d] ?? null, join: (...p) => p.join("\\") }), { lib: "R\\lib\\libcrypto.lib", bin: null, dll: null }, bad);
}
for (const good of ["libcrypto-3-x64.dll", "LIBCRYPTO-3.DLL", "libcrypto-1_1-x64.dll"]) {
  const t = { "R": ["bin", "lib"], "R\\bin": [good], "R\\lib": ["libcrypto.lib"] };
  assert.equal(findImportLibrary(["R"], { list: (d) => t[d] ?? null, join: (...p) => p.join("\\") }).dll, `R\\bin\\${good}`, good);
}
// o3: the search goes five directories below a root, no deeper.
const chain = (levels) => {
  const t = {};
  let dir = "R";
  for (let i = 0; i < levels; i++) { const next = `${dir}\\d${i}`; t[dir] = [`d${i}`]; dir = next; }
  t[dir] = ["libcrypto.lib"];
  return { list: (d) => t[d] ?? null, join: (...p) => p.join("\\") };
};
assert.ok(findImportLibrary(["R"], chain(5)), "five levels down is found");
assert.equal(findImportLibrary(["R"], chain(6)), null, "six levels down is not");

// An existing RUSTFLAGS or CARGO_ENCODED_RUSTFLAGS is kept (ours is appended), and a path with spaces stays one argument.
assert.deepEqual(buildPlan({ platform: "darwin", brewPrefix: "/p", rustflags: "-C target-cpu=native  -D warnings" }).env, { CARGO_ENCODED_RUSTFLAGS: `-C${US}target-cpu=native${US}-D${US}warnings${US}-L${US}native=/p/lib` });
assert.deepEqual(buildPlan({ platform: "darwin", brewPrefix: "/p", encoded: `-C${US}link-arg=a b`, rustflags: "ignored" }).env, { CARGO_ENCODED_RUSTFLAGS: `-C${US}link-arg=a b${US}-L${US}native=/p/lib` }, "the encoded variable wins, as in cargo");
assert.deepEqual(buildPlan({ platform: "darwin", brewPrefix: "/Users/a b/openssl" }).env, { CARGO_ENCODED_RUSTFLAGS: `-L${US}native=/Users/a b/openssl/lib` });
assert.deepEqual(buildPlan({ platform: "win32", found: { lib: "C:\\x\\libcrypto.lib", bin: "C:\\x\\bin", dll: "C:\\x\\bin\\libcrypto-3.dll" }, shimDir: "D:\\a b\\shim", rustflags: "-D warnings" }).env, { CARGO_ENCODED_RUSTFLAGS: `-D${US}warnings${US}-L${US}native=D:/a b/shim` });

// Finding it: libcrypto.lib (never the static variant), with the DLL directory beside it.
const tree = {
  "C:\\Program Files\\OpenSSL-Win64": ["bin", "lib"],
  "C:\\Program Files\\OpenSSL-Win64\\bin": ["libcrypto-3-x64.dll", "openssl.exe"],
  "C:\\Program Files\\OpenSSL-Win64\\lib": ["VC", "libcrypto.lib"],
  "C:\\Program Files\\OpenSSL-Win64\\lib\\VC": ["static", "x64"],
  "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\static": ["libcrypto64MT.lib", "libcrypto_static.lib"],
  "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64": ["MD"],
  "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD": ["libcrypto.lib", "libssl.lib"],
};
const fs = { list: (dir) => tree[dir] ?? null, join: (...p) => p.join("\\") };
const found = findImportLibrary(["C:\\nowhere", "C:\\Program Files\\OpenSSL-Win64"], fs);
assert.equal(found.lib, "C:\\Program Files\\OpenSSL-Win64\\lib\\libcrypto.lib", "the first libcrypto.lib found, searching breadth first");
assert.equal(found.bin, "C:\\Program Files\\OpenSSL-Win64\\bin");
assert.equal(found.dll, "C:\\Program Files\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll");
assert.equal(findImportLibrary(["C:\\nowhere"], fs), null);
assert.equal(findImportLibrary(["C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\static"], { ...fs }), null, "a static-only directory is not an import library");
assert.ok(windowsRoots({ VCPKG_INSTALLATION_ROOT: "C:\\vcpkg", OPENSSL_ROOT_DIR: "D:\\ossl" }).includes("C:\\vcpkg\\installed\\x64-windows"));
assert.ok(windowsRoots({}).includes("C:\\Program Files\\OpenSSL-Win64"));
// A value with a line break would add a variable or a PATH entry of its own to $GITHUB_ENV / $GITHUB_PATH.
assertSingleLine({ env: { CARGO_ENCODED_RUSTFLAGS: "-L\x1fnative=/ok" }, path: ["/ok"] });
assert.throws(() => assertSingleLine({ env: { X: "a\nEVIL=1" }, path: [] }), /line break/);
assert.throws(() => assertSingleLine({ env: { X: "a\rb" }, path: [] }), /line break/);
assert.throws(() => assertSingleLine({ env: {}, path: ["C:\\x\nC:\\evil"] }), /line break/);
assert.throws(() => assertSingleLine(buildPlan({ platform: "darwin", brewPrefix: "/p\nX=1" })), /line break/);
console.log("openssl-setup.test: ok");
