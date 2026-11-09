// The service links OpenSSL's libcrypto by name (`#[link(name = "crypto")]`, src/managed/enterprise_certificate.rs: the OCSP code), so
// the machine that builds it needs one the linker can find. Linux runners have the system library. macOS: Homebrew's openssl@3 with
// its lib directory on the linker's search path. Windows: an MSVC import library named crypto.lib (OpenSSL ships libcrypto.lib), found
// among the preinstalled OpenSSL locations or built by the image's vcpkg, with its DLL directory on PATH for running the binary.
//   node tests/e2e/native/openssl-setup.mjs apply     appends CARGO_ENCODED_RUSTFLAGS (the existing flags kept) to $GITHUB_ENV and the DLL directory to $GITHUB_PATH
import { spawnSync } from "node:child_process";
import { appendFileSync, copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { join, win32 } from "node:path";
import { pathToFileURL } from "node:url";

export function windowsRoots(env) {
  return [env.OPENSSL_ROOT_DIR, "C:\\Program Files\\OpenSSL-Win64", "C:\\Program Files\\OpenSSL", "C:\\OpenSSL-Win64",
    env.VCPKG_INSTALLATION_ROOT && `${env.VCPKG_INSTALLATION_ROOT}\\installed\\x64-windows`].filter(Boolean);
}

/// The first `libcrypto.lib` (never a static variant) under one of the roots, searched breadth first, with the directory of its
/// DLL (`<root>\bin`). `fs.list(dir)` answers the entries of a directory or null; `fs.join` joins path parts.
export function findImportLibrary(roots, fs) {
  for (const root of roots) {
    const queue = [[root, 0]];
    while (queue.length) {
      const [dir, depth] = queue.shift();
      const entries = fs.list(dir);
      if (!entries) continue;
      if (entries.some((e) => e.toLowerCase() === "libcrypto.lib")) {
        const bin = fs.join(root, "bin");
        const dll = (fs.list(bin) ?? []).find((e) => /^libcrypto-\d.*\.dll$/i.test(e));
        return { lib: fs.join(dir, "libcrypto.lib"), bin: dll ? bin : null, dll: dll ? fs.join(bin, dll) : null };
      }
      if (depth < 5) for (const e of entries) if (!/\.[a-z]+$/i.test(e)) queue.push([fs.join(dir, e), depth + 1]);
    }
  }
  return null;
}

const US = "\x1f";
/// Cargo's CARGO_ENCODED_RUSTFLAGS (flags joined by U+001F, so a path may hold spaces) with `-L native=<dir>` appended to whatever
/// flags the environment already has: that variable if set, else RUSTFLAGS split on whitespace (as cargo reads it).
const withLibraryDir = (dir, { encoded, rustflags }) => {
  const existing = encoded ? encoded.split(US) : (rustflags ?? "").split(/\s+/).filter(Boolean);
  return { CARGO_ENCODED_RUSTFLAGS: [...existing, "-L", `native=${dir}`].join(US) };
};

export function buildPlan({ platform, brewPrefix, found, shimDir, encoded, rustflags }) {
  if (platform === "darwin") {
    if (!brewPrefix) throw new Error("Homebrew's openssl@3 prefix is unknown: is openssl@3 installed?");
    return { env: withLibraryDir(`${brewPrefix}/lib`, { encoded, rustflags }), path: [], shim: null };
  }
  if (platform === "win32") {
    if (!found) throw new Error("no OpenSSL import library (libcrypto.lib) was found or built");
    if (!found.bin || !found.dll) throw new Error(`the OpenSSL DLL (libcrypto-3*.dll) is not beside ${found.lib}`);
    // Only the shim directory goes on PATH, holding the import library and libcrypto-3*.dll (whose own imports are all System32 DLLs):
    // the whole <root>\bin of an OpenSSL or vcpkg tree (other DLLs, openssl.exe) never becomes searchable for every later step.
    const dllName = found.dll.split(/[\\/]/).pop();
    return { env: withLibraryDir(shimDir.replaceAll("\\", "/"), { encoded, rustflags }), path: [shimDir],
      shim: { from: found.lib, to: `${shimDir}\\crypto.lib` }, dll: { from: found.dll, to: `${shimDir}\\${dllName}` } };
  }
  return { env: {}, path: [], shim: null };
}

/// $GITHUB_ENV and $GITHUB_PATH are line files: a value with a line break would add a variable or a PATH entry of its own.
export function assertSingleLine(plan) {
  for (const [what, value] of [...Object.entries(plan.env).map(([k, v]) => [k, v]), ...plan.path.map((p) => ["PATH entry", p])]) {
    if (/[\r\n]/.test(`${what}${value}`)) throw new Error(`refusing to write ${what}: its value holds a line break`);
  }
}

/// Runs a command and answers its trimmed stdout; `show` instead lets a chatty command (vcpkg) write straight to the log.
function run(command, args, { show = false } = {}) {
  const r = spawnSync(command, args, { encoding: "utf8", timeout: 1_800_000, maxBuffer: 64 * 1024 * 1024, stdio: show ? "inherit" : ["ignore", "pipe", "inherit"] });
  if (r.status !== 0) throw new Error(`${command} ${args.join(" ")} exited ${r.status}`);
  return show ? "" : r.stdout.trim();
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  if (process.argv[2] !== "apply") { console.error("usage: openssl-setup.mjs apply"); process.exit(2); }
  const platform = process.platform;
  const inherited = { encoded: process.env.CARGO_ENCODED_RUSTFLAGS, rustflags: process.env.RUSTFLAGS };
  let plan;
  if (platform === "darwin") {
    if (spawnSync("brew", ["list", "openssl@3"], { stdio: "ignore" }).status !== 0) run("brew", ["install", "openssl@3"]);
    plan = buildPlan({ platform, brewPrefix: run("brew", ["--prefix", "openssl@3"]), ...inherited });
  } else if (platform === "win32") {
    const fs = { list: (d) => { try { return readdirSync(d); } catch { return null; } }, join: (...p) => win32.join(...p) };
    let found = findImportLibrary(windowsRoots(process.env), fs);
    if (!found && process.env.VCPKG_INSTALLATION_ROOT) {
      console.log("no preinstalled OpenSSL import library: building openssl:x64-windows with the image's vcpkg");
      run(join(process.env.VCPKG_INSTALLATION_ROOT, "vcpkg.exe"), ["install", "openssl:x64-windows", "--clean-after-build"], { show: true });
      found = findImportLibrary(windowsRoots(process.env), fs);
    }
    const shimDir = join(process.env.RUNNER_TEMP ?? process.env.TEMP, "openssl-shim");
    plan = buildPlan({ platform, found, shimDir, ...inherited });
    mkdirSync(shimDir, { recursive: true });
    assertSingleLine(plan);
    copyFileSync(plan.shim.from, plan.shim.to);
    copyFileSync(plan.dll.from, plan.dll.to);
    console.log(`crypto.lib <- ${plan.shim.from}`);
  } else {
    plan = buildPlan({ platform });
  }
  assertSingleLine(plan);
  if (process.env.GITHUB_ENV) for (const [k, v] of Object.entries(plan.env)) appendFileSync(process.env.GITHUB_ENV, `${k}=${v}\n`);
  if (process.env.GITHUB_PATH) for (const p of plan.path) appendFileSync(process.env.GITHUB_PATH, `${p}\n`);
  console.log(`openssl for the linker: ${JSON.stringify(plan.env)} path +${JSON.stringify(plan.path)}`);
}
