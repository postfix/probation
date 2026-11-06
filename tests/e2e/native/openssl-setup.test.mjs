// The service links OpenSSL's libcrypto by name (`#[link(name = "crypto")]` in src/managed/enterprise_certificate.rs, the OCSP
// code), so a runner needs one the linker can find: Linux has the system library, macOS needs Homebrew's openssl@3 on the library
// path, Windows needs an MSVC import library named crypto.lib (OpenSSL ships it as libcrypto.lib) and its DLL on PATH.
// node tests/e2e/native/openssl-setup.test.mjs
import assert from "node:assert/strict";
import { buildPlan, findImportLibrary, windowsRoots } from "./openssl-setup.mjs";

// macOS: Homebrew's lib directory is added to the linker's search path.
assert.deepEqual(buildPlan({ platform: "darwin", brewPrefix: "/opt/homebrew/opt/openssl@3" }), { env: { RUSTFLAGS: "-L native=/opt/homebrew/opt/openssl@3/lib" }, path: [], shim: null });
assert.throws(() => buildPlan({ platform: "darwin", brewPrefix: "" }), /Homebrew/);
// Linux: the system libcrypto (libssl-dev) is already on the default path.
assert.deepEqual(buildPlan({ platform: "linux" }), { env: {}, path: [], shim: null });
// Windows: the import library is copied under the name rustc asks for, and the DLL directory goes on PATH.
const plan = buildPlan({ platform: "win32", found: { lib: "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libcrypto.lib", bin: "C:\\Program Files\\OpenSSL-Win64\\bin" }, shimDir: "D:\\a\\_temp\\openssl-shim" });
assert.deepEqual(plan.shim, { from: "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libcrypto.lib", to: "D:\\a\\_temp\\openssl-shim\\crypto.lib" });
assert.deepEqual(plan.env, { RUSTFLAGS: "-L native=D:/a/_temp/openssl-shim" }, "forward slashes in the flag");
assert.deepEqual(plan.path, ["C:\\Program Files\\OpenSSL-Win64\\bin"]);
assert.throws(() => buildPlan({ platform: "win32", found: null, shimDir: "x" }), /import library/);

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
assert.equal(findImportLibrary(["C:\\nowhere"], fs), null);
assert.equal(findImportLibrary(["C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\static"], { ...fs }), null, "a static-only directory is not an import library");
assert.ok(windowsRoots({ VCPKG_INSTALLATION_ROOT: "C:\\vcpkg", OPENSSL_ROOT_DIR: "D:\\ossl" }).includes("C:\\vcpkg\\installed\\x64-windows"));
assert.ok(windowsRoots({}).includes("C:\\Program Files\\OpenSSL-Win64"));
console.log("openssl-setup.test: ok");
