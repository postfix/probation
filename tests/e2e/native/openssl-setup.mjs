// The service links OpenSSL's libcrypto by name (`#[link(name = "crypto")]`, src/managed/enterprise_certificate.rs: the OCSP code), so
// the machine that builds it needs one the linker can find. Linux runners have the system library. macOS: Homebrew's openssl@3 with
// its lib directory on the linker's search path. Windows: an MSVC import library named crypto.lib (OpenSSL ships libcrypto.lib), found
// among the preinstalled OpenSSL locations or built by the image's vcpkg, with its DLL directory on PATH for running the binary.
//   node tests/e2e/native/openssl-setup.mjs apply     appends RUSTFLAGS to $GITHUB_ENV and the DLL directory to $GITHUB_PATH
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
        const dll = (fs.list(bin) ?? []).some((e) => /^libcrypto-\d.*\.dll$/i.test(e));
        return { lib: fs.join(dir, "libcrypto.lib"), bin: dll ? bin : null };
      }
      if (depth < 5) for (const e of entries) if (!/\.[a-z]+$/i.test(e)) queue.push([fs.join(dir, e), depth + 1]);
    }
  }
  return null;
}

export function buildPlan({ platform, brewPrefix, found, shimDir }) {
  if (platform === "darwin") {
    if (!brewPrefix) throw new Error("Homebrew's openssl@3 prefix is unknown: is openssl@3 installed?");
    return { env: { RUSTFLAGS: `-L native=${brewPrefix}/lib` }, path: [], shim: null };
  }
  if (platform === "win32") {
    if (!found) throw new Error("no OpenSSL import library (libcrypto.lib) was found or built");
    if (!found.bin) throw new Error(`the OpenSSL DLL (libcrypto-3*.dll) is not beside ${found.lib}`);
    return { env: { RUSTFLAGS: `-L native=${shimDir.replaceAll("\\", "/")}` }, path: [found.bin], shim: { from: found.lib, to: `${shimDir}\\crypto.lib` } };
  }
  return { env: {}, path: [], shim: null };
}

function run(command, args) {
  const r = spawnSync(command, args, { encoding: "utf8", timeout: 1_800_000, stdio: ["ignore", "pipe", "inherit"] });
  if (r.status !== 0) throw new Error(`${command} ${args.join(" ")} exited ${r.status}`);
  return r.stdout.trim();
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  if (process.argv[2] !== "apply") { console.error("usage: openssl-setup.mjs apply"); process.exit(2); }
  const platform = process.platform;
  let plan;
  if (platform === "darwin") {
    if (spawnSync("brew", ["list", "openssl@3"], { stdio: "ignore" }).status !== 0) run("brew", ["install", "openssl@3"]);
    plan = buildPlan({ platform, brewPrefix: run("brew", ["--prefix", "openssl@3"]) });
  } else if (platform === "win32") {
    const fs = { list: (d) => { try { return readdirSync(d); } catch { return null; } }, join: (...p) => win32.join(...p) };
    let found = findImportLibrary(windowsRoots(process.env), fs);
    if (!found && process.env.VCPKG_INSTALLATION_ROOT) {
      console.log("no preinstalled OpenSSL import library: building openssl:x64-windows with the image's vcpkg");
      run(join(process.env.VCPKG_INSTALLATION_ROOT, "vcpkg.exe"), ["install", "openssl:x64-windows", "--clean-after-build"]);
      found = findImportLibrary(windowsRoots(process.env), fs);
    }
    const shimDir = join(process.env.RUNNER_TEMP ?? process.env.TEMP, "openssl-shim");
    plan = buildPlan({ platform, found, shimDir });
    mkdirSync(shimDir, { recursive: true });
    copyFileSync(plan.shim.from, plan.shim.to);
    console.log(`crypto.lib <- ${plan.shim.from}`);
  } else {
    plan = buildPlan({ platform });
  }
  if (process.env.GITHUB_ENV) for (const [k, v] of Object.entries(plan.env)) appendFileSync(process.env.GITHUB_ENV, `${k}=${v}\n`);
  if (process.env.GITHUB_PATH) for (const p of plan.path) appendFileSync(process.env.GITHUB_PATH, `${p}\n`);
  console.log(`openssl for the linker: ${JSON.stringify(plan.env)} path +${JSON.stringify(plan.path)}`);
}
