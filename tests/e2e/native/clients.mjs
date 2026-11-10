#!/usr/bin/env node
// Native package-client preflight (publishing-proxy Slice 5). Exits 1 unless every pinned
// client is installed at exactly its pinned version on the expected platform: a missing or
// different client is a failure, never a skip. The node on PATH is probed as well as the
// running one, each tool's resolved path is recorded, and so is the interpreter uv would
// use. publishing.mjs repeats the check before it starts. Writes the observations as JSON.
//   NATIVE_PLATFORM (required) e.g. linux-x64 | darwin-arm64 | win32-x64
//   NATIVE_PYTHON   python executable (default "python")
//   NATIVE_PINS_FILE (test seam only; the workflow check forbids it) overrides pins.json
import { accessSync, constants, openSync, readFileSync, readSync, closeSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, delimiter, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { launch } from "./spawn-args.mjs";
import { dirname } from "node:path";

const win = process.platform === "win32";
const same = (a, b) => (win ? a.toLowerCase() === b.toLowerCase() : a === b);

/// The first executable `command` names on `PATH` (PATHEXT on Windows), or null.
export function which(command, env = process.env) {
  const extensions = win ? (env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of (env.PATH ?? env.Path ?? "").split(delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = join(dir, command + extension);
      try { accessSync(candidate, win ? constants.F_OK : constants.X_OK); return candidate; } catch { /* next */ }
    }
  }
  return null;
}


/// `path` with its real location: the longest part of it that exists is resolved (symlinks such as macOS's /var ->
/// /private/var), the rest is appended as spelled. A path that does not exist yet must not escape the comparison.
function realish(path, followFinal = true) {
  if (!followFinal) return join(realish(dirname(resolve(path))), basename(path));
  let rest = "";
  let head = resolve(path);
  for (;;) {
    try { return join(realpathSync(head), rest); } catch { /* not there: try the parent */ }
    const parent = dirname(head);
    if (parent === head) return resolve(path);
    rest = rest ? join(head.slice(parent.length).replace(/^[\\/]+/, ""), rest) : head.slice(parent.length).replace(/^[\\/]+/, "");
    head = parent;
  }
}

/// Is `path` inside `prefix` (after resolving both)? `followFinal: false` keeps the last component as installed: an interpreter
/// is where it was put (a venv's python is a symlink to the base interpreter and still belongs to the venv), unlike a tool.
export function inside(path, prefix, { followFinal = true } = {}) {
  const fold = (p) => (win ? p.toLowerCase() : p);
  const p = fold(realish(path, followFinal)), root = fold(realish(prefix));
  return p === root || p.startsWith(root.endsWith(sep) ? root : root + sep);
}

/// The interpreter a console script names on its first line (POSIX `#!`), or null.
function shebang(file) {
  try {
    const fd = openSync(file, "r");
    const buffer = Buffer.alloc(512);
    const n = readSync(fd, buffer, 0, 512, 0);
    closeSync(fd);
    const line = buffer.subarray(0, n).toString("latin1").split(/\r?\n/)[0];
    return line.startsWith("#!") ? line.slice(2).trim().split(/\s+/)[0] : null;
  } catch { return null; }
}

/// `shim` is for npm only (a .cmd file on Windows, run through cmd.exe); everything else is a real
/// program started directly, so a timeout kills that program and not a shell around it.
function output(command, args, env, { shim = false } = {}) {
  const [file, argv, options] = launch(command, args, { encoding: "utf8", timeout: 60_000, env }, process.platform, { shim });
  const r = spawnSync(file, argv, options);
  return { ok: r.status === 0, text: `${r.stdout ?? ""}${r.stderr ?? ""}`.trim(), error: r.error?.code };
}

export function checkClients({ pins, platformWanted, env = process.env, runningNode = process.versions.node, platform = `${process.platform}-${process.arch}` }) {
  const failures = [];
  const seen = { platform, paths: {} };
  const python = env.NATIVE_PYTHON ?? "python";
  const probe = (name, command, args, pattern, want, label = name, how = {}) => {
    const r = output(command, args, env, how);
    const got = r.ok ? r.text.match(pattern)?.[1] : undefined;
    seen[name] = got ?? null;
    if (want === undefined || got !== want) failures.push(`${label}: want ${want ?? "a pinned version (the pin is missing)"}, got ${got ?? `missing or unparsable (${r.error ?? "no match"}: ${r.text.slice(0, 120)})`}`);
    return r;
  };
  if (!platformWanted) failures.push("NATIVE_PLATFORM is not set");
  else if (platform !== platformWanted) failures.push(`platform: want ${platformWanted}, got ${platform}`);
  for (const name of ["node", "npm", "python", "pip", "twine", "uv"]) if (typeof pins[name] !== "string" || !pins[name]) failures.push(`pins.json has no ${name} pin`);
  seen.node = runningNode;
  if (runningNode !== pins.node) failures.push(`node: want ${pins.node}, the running node is ${runningNode}`);
  for (const tool of ["node", "npm", python, "twine", "uv"]) seen.paths[tool === python ? "python" : tool] = which(tool, env);
  const onPath = output("node", ["--version"], env);
  const pathNode = onPath.ok ? onPath.text.match(/^v(\S+)$/)?.[1] : undefined;
  seen.nodeOnPath = pathNode ?? null;
  if (pathNode !== pins.node) failures.push(`node on PATH: want ${pins.node}, got ${pathNode ?? "missing"}`);
  else if (pathNode !== runningNode) failures.push(`node on PATH (${pathNode}) is not the running node (${runningNode})`);
  probe("npm", "npm", ["--version"], /^(\S+)$/, pins.npm, "npm", { shim: true });
  probe("python", python, ["--version"], /^Python (\S+)$/, pins.python);
  probe("pip", python, ["-m", "pip", "--version"], /^pip (\S+) from /, pins.pip);
  probe("twine", "twine", ["--version"], /^twine version (\S+)/, pins.twine);
  probe("uv", "uv", ["--version"], /^uv (\S+)/, pins.uv);
  // Everything belongs to the pinned python: its prefix holds pip, the twine script (which must
  // also name an interpreter inside it) and the interpreter uv would use.
  const probeLines = output(python, ["-c", "import sys;print(sys.prefix);print(sys.executable)"], env);
  const prefix = probeLines.ok ? probeLines.text.split(/\r?\n/)[0] : null;
  seen.pythonPrefix = prefix;
  if (!prefix) failures.push(`python prefix: could not be read (${probeLines.error ?? probeLines.text.slice(0, 120)})`);
  else {
    const pipFrom = output(python, ["-m", "pip", "--version"], env).text.match(/^pip \S+ from (.+?) \(python (\d+\.\d+)\)/);
    if (pipFrom && !inside(pipFrom[1], prefix)) failures.push(`pip: ${pipFrom[1]} is outside the python prefix ${prefix}`);
    if (pipFrom && pipFrom[2] !== String(pins.python).split(".").slice(0, 2).join(".")) failures.push(`pip: runs python ${pipFrom[2]}, want ${pins.python}`);
    const twinePath = seen.paths.twine;
    if (twinePath && !inside(twinePath, prefix)) failures.push(`twine: ${twinePath} is outside the python prefix ${prefix}`);
    else if (twinePath && !win) {
      const interpreter = shebang(twinePath);
      if (!interpreter || !inside(interpreter, prefix, { followFinal: false })) failures.push(`twine: the script runs under ${interpreter ?? "no named interpreter"}, not the pinned python in ${prefix}`);
    }
  }
  if (seen.paths.npm && seen.paths.node && !same(dirname(seen.paths.npm), dirname(seen.paths.node))) {
    failures.push(`npm: ${seen.paths.npm} is not beside the node on PATH (${seen.paths.node})`);
  }
  if (prefix && seen.paths.uv && !inside(seen.paths.uv, prefix)) failures.push(`uv: ${seen.paths.uv} is outside the python prefix ${prefix}`);
  const found = output("uv", ["python", "find"], env);
  const interpreter = found.ok ? found.text.split(/\r?\n/)[0] : null;
  if (!interpreter) failures.push(`uv's python: uv python find gave no interpreter (${found.error ?? found.text.slice(0, 120)})`);
  else {
    seen.paths.uvPython = interpreter;
    const r = output(interpreter, ["--version"], env);
    seen.uvPython = r.ok ? r.text.match(/^Python (\S+)$/)?.[1] ?? null : null;
    if (seen.uvPython !== pins.python) failures.push(`uv's python: want ${pins.python}, got ${seen.uvPython ?? "unreadable"} (${interpreter})`);
    if (prefix && !inside(interpreter, prefix, { followFinal: false })) failures.push(`uv's python: ${interpreter} is outside the python prefix ${prefix}`);
  }
  return { observed: seen, pinned: pins, failures };
}

export function loadPins() {
  return JSON.parse(readFileSync(process.env.NATIVE_PINS_FILE ?? fileURLToPath(new URL("./pins.json", import.meta.url)), "utf8"));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const report = checkClients({ pins: loadPins(), platformWanted: process.env.NATIVE_PLATFORM });
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.failures.length ? 1 : 0);
}
