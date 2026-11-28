// The native service lifecycle driver (row 25): install, start, stop, restart, crash, settings-restart (exit 75), second owner and
// state preservation for the REAL probation binary under the REAL service manager of the host: systemd (system or --user) on
// Linux, launchd (LaunchDaemon or LaunchAgent) on macOS, the service control manager on Windows. The command builders and parsers
// are pure and tested on every OS (service-lifecycle.test.mjs); `exercise` runs them for real, so a lane only counts when the
// host's own service manager executed it. Used by tests/e2e/scenarios/service-native.mjs.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import net from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/// install-service.ps1 declares `[switch]$NoStart`; the POSIX installer takes `--no-start`.
export const noStartFlag = (platform) => (platform === "win32" ? "-NoStart" : "--no-start");

/// The installer's verification flags the driver passes. The installer always verifies in full (attestation, and SHA256SUMS on Windows):
/// there is no way to switch it off here. A build from the tree (no package) has no SHA256SUMS on Windows, which needs -NoVerify. A package
/// built in CI is not a release (no RELEASE-PACKAGE marker, so --dev-package) and is attested by the workflow that built it, named with
/// --signer-workflow (the installer pins the repository and defaults to release.yml), together with --source-digest, the commit it was built
/// from: the installer refuses another workflow without it, so a missing or malformed digest fails here, before the installer runs.
export const installVerifyFlags = ({ platform, packageDir, release, signerWorkflow, sourceDigest }) => {
  const win = platform === "win32";
  if (!packageDir) return win ? ["-NoVerify"] : [];
  if (signerWorkflow && !/^[0-9a-f]{40}$/.test(sourceDigest ?? "")) throw new Error(`a signer workflow needs its source digest (40 lower-case hex characters, E2E_SERVICE_SOURCE_DIGEST), got ${JSON.stringify(sourceDigest)}`);
  return [
    ...(release ? [] : [win ? "-DevPackage" : "--dev-package"]),
    ...(signerWorkflow ? [win ? "-SignerWorkflow" : "--signer-workflow", signerWorkflow, win ? "-SourceDigest" : "--source-digest", sourceDigest] : []),
  ];
};

export const LABEL_PREFIX = "com.postfix.";

/// The command lines (argv arrays) of one platform's lifecycle for the service `name` in `scope` ("system" | "user").
export function commands({ platform, scope = "system", name = "probation", script, binary, dirs = {}, listen = "127.0.0.1:8080", uid = 0 }) {
  const flags = [
    ...(dirs.config ? ["--config-dir", dirs.config] : []),
    ...(dirs.data ? ["--data-dir", dirs.data] : []),
    ...(dirs.log ? ["--log-dir", dirs.log] : []),
    ...(dirs.bin ? ["--bin-dir", dirs.bin] : []),
  ];
  if (platform === "linux") {
    const sc = scope === "user" ? ["systemctl", "--user"] : ["systemctl"];
    const unit = `${name}.service`;
    const show = (property) => [...sc, "show", "-p", property, "--value", unit];
    return {
      manager: "systemd",
      install: (extra = []) => ["bash", script, "install", "--scope", scope, "--name", name, "--binary", binary, "--listen", listen, ...flags, ...extra],
      upgrade: (extra = []) => ["bash", script, "upgrade", "--scope", scope, "--name", name, "--binary", binary, ...flags, ...extra],
      uninstall: () => ["bash", script, "uninstall", "--scope", scope, "--name", name, ...flags],
      start: [...sc, "start", unit],
      stop: [...sc, "stop", unit],
      restart: [...sc, "restart", unit],
      reload: [...sc, "daemon-reload"],
      isActive: [...sc, "is-active", unit],
      mainPid: show("MainPID"),
      restarts: show("NRestarts"),
      lastStatus: show("ExecMainStatus"),
      kill: (pid) => ["kill", "-KILL", String(pid)],
    };
  }
  if (platform === "darwin") {
    const domain = scope === "user" ? `gui/${uid}` : "system";
    const label = `${LABEL_PREFIX}${name}`;
    return {
      manager: "launchd",
      install: (extra = []) => ["bash", script, "install", "--scope", scope, "--name", name, "--binary", binary, "--listen", listen, ...flags, ...extra],
      upgrade: (extra = []) => ["bash", script, "upgrade", "--scope", scope, "--name", name, "--binary", binary, ...flags, ...extra],
      uninstall: () => ["bash", script, "uninstall", "--scope", scope, "--name", name, ...flags],
      // A deliberate stop unloads the job (research-native-supervision.md): launchd never restarts an unloaded job.
      stop: ["launchctl", "bootout", `${domain}/${label}`],
      start: (plist) => ["launchctl", "bootstrap", domain, plist],
      restart: ["launchctl", "kickstart", "-k", `${domain}/${label}`],
      print: ["launchctl", "print", `${domain}/${label}`],
      kill: (pid) => ["kill", "-KILL", String(pid)],
    };
  }
  if (platform === "win32") {
    const ps = (text) => ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", text];
    const file = (action, extra) => ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, action, "-Name", name, ...(action === "uninstall" ? [] : ["-Binary", binary]), ...(action === "install" ? ["-Listen", listen] : []), ...winFlags(dirs), ...extra];
    return {
      manager: "scm",
      install: (extra = []) => file("install", extra),
      upgrade: (extra = []) => file("upgrade", extra),
      uninstall: () => file("uninstall", []),
      stop: ps(`Stop-Service -Name ${name} -Force; (Get-Service -Name ${name}).WaitForStatus('Stopped','00:01:00')`),
      start: ps(`Start-Service -Name ${name}; (Get-Service -Name ${name}).WaitForStatus('Running','00:00:30')`),
      query: ["sc.exe", "queryex", name],
      failureActions: ["sc.exe", "qfailure", name],
      acl: (path) => ["icacls", path],
      owner: (path) => ps(`(Get-Acl -LiteralPath '${path}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`),
      kill: (pid) => ["taskkill", "/F", "/PID", String(pid)],
    };
  }
  throw new Error(`no service manager for ${platform}`);
}

function winFlags(dirs) {
  return [
    ...(dirs.config ? ["-ConfigDir", dirs.config] : []),
    ...(dirs.data ? ["-DataDir", dirs.data] : []),
    ...(dirs.log ? ["-LogDir", dirs.log] : []),
    ...(dirs.bin ? ["-BinDir", dirs.bin] : []),
  ];
}

export const parseLaunchctl = (text) => ({
  pid: /\bpid = (\d+)/.exec(text)?.[1] ? Number(/\bpid = (\d+)/.exec(text)[1]) : null,
  runs: /\bruns = (\d+)/.exec(text)?.[1] ? Number(/\bruns = (\d+)/.exec(text)[1]) : null,
  lastExit: /\blast exit code = (\d+)/.exec(text)?.[1] ? Number(/\blast exit code = (\d+)/.exec(text)[1]) : null,
});
export const parseScQuery = (text) => ({
  state: /STATE\s*:\s*\d+\s+(\w+)/.exec(text)?.[1] ?? null,
  pid: /PID\s*:\s*(\d+)/.exec(text) ? Number(/PID\s*:\s*(\d+)/.exec(text)[1]) : 0,
});

/// What `sc.exe qfailure` must show for the restart policy the installer configures (5 s, 5 s, 60 s; reset 24 h).
export function failurePolicyProblems(text) {
  const problems = [];
  if (!/RESET_PERIOD[^:]*:\s*86400/.test(text)) problems.push("reset period is not 86400 s");
  const restarts = [...text.matchAll(/RESTART -- Delay = (\d+) milliseconds/g)].map((m) => Number(m[1]));
  if (restarts.join(",") !== "5000,5000,60000") problems.push(`restart delays are [${restarts}], want [5000,5000,60000]`);
  return problems;
}

export const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

/// The SID of NT SERVICE\<name>, as install-service.ps1 Get-ServiceSid computes it: SHA-1 of the upper-cased name in UTF-16LE, five little-endian words under S-1-5-80.
export const serviceSid = (name) => { const h = createHash("sha1").update(Buffer.from(name.toUpperCase(), "utf16le")).digest(); return "S-1-5-80-" + [0, 1, 2, 3, 4].map((i) => h.readUInt32LE(4 * i)).join("-"); };

/// Every regular file under `dir` (relative path -> sha256), except the lock file (rewritten by every run).
export function treeHashes(dir) {
  const rows = {};
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile() && entry.name !== "lock") rows[path.slice(dir.length + 1)] = sha256(path);
    }
  };
  walk(dir);
  return rows;
}

export function sh(argv, { env, input, timeout = 120_000 } = {}) {
  const r = spawnSync(argv[0], argv.slice(1), { encoding: "utf8", env: { ...process.env, ...env }, input, timeout });
  return { status: r.status ?? (r.error ? 127 : 1), stdout: r.stdout ?? "", stderr: `${r.stderr ?? ""}${r.error ?? ""}` };
}

export async function waitFor(what, within, condition, step = 250) {
  const deadline = Date.now() + within;
  for (;;) {
    const value = await condition();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`${what} did not happen within ${within} ms`);
    await new Promise((resolve) => setTimeout(resolve, step));
  }
}

export const listening = (port, host = "127.0.0.1") => new Promise((resolve) => {
  const socket = net.connect({ port, host }, () => { socket.destroy(); resolve(true); });
  socket.on("error", () => resolve(false));
  socket.setTimeout(1000, () => { socket.destroy(); resolve(false); });
});

/// Runs the lifecycle for real. `ctx`: { platform, scope, name, script, binary, dirs, port, expect(cond, message), log }.
/// Returns the evidence record. Throws on the first violated expectation (via ctx.expect).
export async function exercise(ctx) {
  const { platform, scope, name, dirs, port, expect, log = () => {} } = ctx;
  const listen = `127.0.0.1:${port}`;
  const c = commands({ platform, scope, name, script: ctx.script, binary: ctx.binary, dirs, listen, uid: process.getuid?.() ?? 0 });
  const run = (argv, options) => sh(argv, options);
  const must = (argv, what) => { const r = run(argv); expect(r.status === 0, `${what}: ${argv.join(" ")} -> ${r.status}: ${r.stdout}${r.stderr}`); return r; };
  const evidence = { manager: c.manager, platform, scope, steps: [] };
  const note = (step, detail) => { evidence.steps.push({ step, detail }); log(`${step}: ${detail}`); };
  const configFile = join(dirs.config, "config.toml");
  const mainPid = () => {
    if (platform === "linux") return Number(run(c.mainPid).stdout.trim()) || 0;
    if (platform === "darwin") return parseLaunchctl(run(c.print).stdout).pid ?? 0;
    return parseScQuery(run(c.query).stdout).pid;
  };
  const plistFile = () => (scope === "user" ? join(process.env.HOME, "Library/LaunchAgents") : "/Library/LaunchDaemons") + `/${LABEL_PREFIX}${name}.plist`;
  const startAgain = () => must(platform === "darwin" ? c.start(plistFile()) : c.start, "start");
  const serviceUp = async () => (await listening(port)) && mainPid() > 0;
  // An install that must be refused (Windows): non-zero, the installer's text (whitespace-normalized: Windows PowerShell wraps the thrown
  // message at the console width), and no install record left behind.
  const refusedWith = (what, text) => {
    const r = run(c.install([noStartFlag(platform), ...(ctx.installExtra ?? [])]));
    const out = `${r.stdout}${r.stderr}`.replace(/\s+/g, " ");
    expect(r.status !== 0 && out.includes(text), `${what}: want a refusal naming "${text}", got ${r.status}: ${out.slice(-600)}`);
    expect(!existsSync(join(dirs.config, `.service-install-${name}`)), `${what}: the failed install left its install record behind`);
  };

  // 1. Install: files, modes, no start yet needed to judge them.
  const installed = must(c.install([noStartFlag(platform), ...(ctx.installExtra ?? [])]), "install");
  // A lane that names the attesting workflow must have VERIFIED: gh missing from PATH would only be said softly by a CI (dev) package.
  if (ctx.requireAttestation) expect(/Verified the attestation of .* \(workflow \.github\/workflows\/native-service\.yml, source [0-9a-f]{40}\)/.test(`${installed.stdout}${installed.stderr}`), `the installer verified the attestation: ${installed.stdout}${installed.stderr}`);
  expect(existsSync(configFile), "install created config.toml");
  note("install", `config ${configFile}`);

  // 2. Permissions.
  if (platform !== "win32") {
    const mode = (path) => statSync(path).mode & 0o777;
    const expected = scope === "user" ? [0o600, 0o700] : [0o640, 0o750];
    expect(mode(configFile) === expected[0], `config.toml mode ${mode(configFile).toString(8)} want ${expected[0].toString(8)}`);
    expect(mode(dirs.config) === expected[1], `config dir mode ${mode(dirs.config).toString(8)} want ${expected[1].toString(8)}`);
    expect(mode(dirs.data) === 0o700, `data dir mode ${mode(dirs.data).toString(8)} want 700`);
    note("permissions", `config ${mode(configFile).toString(8)}, config dir ${mode(dirs.config).toString(8)}, data ${mode(dirs.data).toString(8)}`);
  } else {
    const acl = run(c.acl(dirs.config)).stdout;
    expect(acl.includes(`NT SERVICE\\${name}:(I)(OI)(CI)(RX)`) || acl.includes(`NT SERVICE\\${name}:(OI)(CI)(RX)`), `the service account can only read the config dir: ${acl}`);
    expect(!/BUILTIN\\Users|Everyone/.test(acl), `no broad group on the config dir: ${acl}`);
    const policy = failurePolicyProblems(run(c.failureActions).stdout);
    expect(policy.length === 0, `failure actions: ${policy.join("; ")}`);
    note("permissions", "config dir ACL: service read-only, no Users/Everyone; failure actions 5 s/5 s/60 s");
  }

  // 3. Start. A listener on the loopback port is the readiness proof.
  if (platform === "linux") must(c.reload, "daemon-reload");
  startAgain();
  await waitFor("the service listening", 30_000, serviceUp);
  const firstPid = mainPid();
  note("start", `listening on ${listen}, pid ${firstPid}`);

  // 4. Second owner: another process on the same data directory is refused at the lock and changes nothing.
  const second = join(dirs.config, "second-owner.toml");
  writeFileSync(second, readFileSync(configFile, "utf8").replace(/^listen = .*$/m, `listen = "127.0.0.1:0"`));
  const before = treeHashes(dirs.data);
  const refused = run([ctx.binary, "serve", "--config", second], { timeout: 60_000 });
  expect(refused.status === 1 && /another instance holds the data-directory lock/.test(refused.stdout + refused.stderr), `second owner refused: ${refused.status} ${refused.stdout.slice(-300)}`);
  expect(JSON.stringify(treeHashes(dirs.data)) === JSON.stringify(before), "the refused second owner changed nothing in the data directory");
  expect(await listening(port), "the first owner keeps serving");
  rmSync(second, { force: true }); // a runner-owned file left in config makes the Windows reinstall refuse (Get-DaclViolation)
  note("second owner", "refused with status 1, data tree unchanged, first owner still listening");

  // 5. Stop: no listener, no restart, state intact. Then start again on the same state.
  writeFileSync(join(dirs.data, "operator-note.txt"), "kept\n");
  const stateBeforeStop = treeHashes(dirs.data);
  must(c.stop, "stop");
  await waitFor("the listener to go", 20_000, async () => !(await listening(port)));
  await new Promise((resolve) => setTimeout(resolve, 8000)); // longer than the 5 s restart delay: a stop must STAY stopped
  expect(!(await listening(port)) && mainPid() === 0, "an operator stop stays stopped past the restart delay");
  if (platform === "linux") expect(run(c.lastStatus).stdout.trim() === "0", `the stop was a clean exit (status ${run(c.lastStatus).stdout.trim()})`);
  note("stop", "listener gone, still stopped after 8 s (longer than the restart delay)");
  startAgain();
  await waitFor("the service listening again", 30_000, serviceUp);
  const stateAfterRestart = treeHashes(dirs.data);
  for (const file of Object.keys(stateBeforeStop)) expect(file in stateAfterRestart, `${file} still exists after stop/start`);
  expect(stateAfterRestart["operator-note.txt"] === stateBeforeStop["operator-note.txt"], "the operator's file is byte-identical");
  note("restart on same state", "operator note and stored files intact");

  // 6. Crash: the supervisor restarts it, within the restart allowance, on the same state.
  const victim = mainPid();
  must(c.kill(victim), "kill");
  await waitFor("the supervisor to restart the service", 40_000, async () => (await serviceUp()) && mainPid() !== victim);
  note("crash", `pid ${victim} killed; restarted as ${mainPid()}`);

  // 7. Settings restart (exit 75): the supervisor's reaction to a failure exit.
  const exit75 = ctx.exit75;
  if (exit75) note("exit75", await exit75({ ...ctx, commands: c, run, must, mainPid, serviceUp, plistFile }));

  // 8. Upgrade with the same binary keeps config, blocklist and data; then uninstall keeps them and removes the definition.
  must(c.stop, "stop before upgrade");
  const configBefore = sha256(configFile);
  must(c.upgrade([noStartFlag(platform), ...(ctx.installExtra ?? [])]), "upgrade");
  expect(sha256(configFile) === configBefore, "upgrade left config.toml untouched");
  note("upgrade", "config.toml unchanged, binary replaced, previous kept");
  must(c.uninstall(), "uninstall");
  expect(existsSync(configFile) && existsSync(join(dirs.data, "operator-note.txt")), "uninstall kept config and data");
  note("uninstall", "definition removed; config and data kept");

  // 9. Reinstall over the kept data and logs, which hold files the service itself created (on Windows owned by its virtual account).
  // credential-reads exists only in shared-service mode (src/lib.rs, service_policy); this lane is standalone, so check what a standalone
  // service always creates under data_dir and keeps through stop and uninstall: the lock file (src/store/lock.rs) and the state directory.
  expect(existsSync(join(dirs.data, "lock")) && existsSync(join(dirs.data, "state")), "the service created its lock file and state directory before the reinstall");
  if (platform === "win32") {
    const sid = serviceSid(name);
    for (const item of ["lock", "state"]) {
      const owner = run(c.owner(join(dirs.data, item))).stdout.trim();
      expect(owner === sid, `${item} is owned by the service account ${sid}, got ${owner}`);
      note("owner", `${item} owner SID ${owner} (NT SERVICE\\${name})`);
    }
    // The documented recovery command removes a planted junction without deleting its target (docs/operations.md, security-5-1).
    const canary = join(dirname(dirs.data), "junction-canary");
    mkdirSync(canary, { recursive: true });
    writeFileSync(join(canary, "keep.txt"), "kept\n");
    const planted = join(dirs.data, "credential-reads");
    must(["cmd", "/c", "mklink", "/J", planted, canary], "plant a credential-reads junction");
    must(["cmd", "/c", "rmdir", "/s", "/q", planted], "the documented recovery command");
    expect(!existsSync(planted) && existsSync(join(canary, "keep.txt")), "rmdir /s /q removed the junction and left its target's contents");
    rmSync(canary, { recursive: true, force: true });
    note("recovery", "the documented rmdir removed a planted credential-reads junction; its target kept its file");
    // A service-owned file where the service can only read (the config dir) is refused: the service-SID owner allowance is data and logs only.
    const serviceOwned = join(dirs.config, "service-owned.txt");
    writeFileSync(serviceOwned, "x\n");
    must(["icacls", serviceOwned, "/setowner", `*${sid}`], "make a config file owned by the service account");
    refusedWith("a service-owned file in the config dir", `service-owned.txt is owned by ${sid}`);
    rmSync(serviceOwned, { force: true });
    note("owner refusal", "a service-owned file in the config dir was refused; the install created nothing");
    // The owner refusal, executed (stack.mjs keyRefusalSteps' shape: refuse with the installer's text, revert, accept): the runner wrote
    // operator-note.txt in step 5, so an install over the kept data dir is refused and creates nothing.
    refusedWith("a runner-owned file in the data dir", "operator-note.txt is owned by S-1-5-21-");
    note("owner refusal", "a runner-owned file in the data dir was refused; the install created nothing");
  }
  // The revert: the operator's (runner-written) note goes, after "uninstall kept config and data" needed it.
  rmSync(join(dirs.data, "operator-note.txt"), { force: true });
  if (platform === "win32") {
    // A failed reinstall leaves nothing that blocks the next one (code-review-5-3): check-config rejects a broken config.toml after the
    // binary and the install record were written; the rollback removes both. Writing into the existing file keeps its owner.
    const goodConfig = readFileSync(configFile);
    writeFileSync(configFile, Buffer.concat([goodConfig, Buffer.from("\nthis line is not TOML\n")]));
    expect(run(c.owner(configFile)).stdout.trim() === "S-1-5-32-544", "config.toml is still owned by the Administrators after the edit");
    refusedWith("a reinstall that fails check-config", "rejects");
    writeFileSync(configFile, goodConfig);
    expect(!existsSync(join(dirs.bin, "probation.exe")), "the failed reinstall removed the binary it installed");
    note("failed reinstall", "check-config failure rolled back the binary and the install record");
  }
  // On darwin the reinstall runs without --no-start: the installer's own service_start (enable, then bootstrap, after the uninstall's
  // `launchctl disable`) is the product path under test, so the harness bootstraps nothing there. Elsewhere --no-start/-NoStart holds it back.
  must(c.install([...(platform === "darwin" ? [] : [noStartFlag(platform)]), ...(ctx.installExtra ?? [])]), "reinstall over kept data");
  if (platform !== "darwin") startAgain();
  await waitFor("the reinstalled service listening", 30_000, serviceUp);
  must(c.stop, "stop after reinstall");
  must(c.uninstall(), "uninstall after reinstall");
  note("reinstall", "install over kept data and logs accepted; the service started over its own lock file and state directory");
  return evidence;
}

export const dirsUnder = (root) => {
  const dirs = { config: join(root, "config"), data: join(root, "data"), log: join(root, "log"), bin: join(root, "bin") };
  // Only the root exists: the installer creates the four directories itself, with their documented modes (one that already exists
  // keeps whatever mode it has, so pre-creating them here would hide the modes the installer sets).
  mkdirSync(root, { recursive: true });
  return dirs;
};

/// The platform's own install locations (scripts/install-service.sh, install-service.ps1 defaults).
export function systemDirs(platform) {
  if (platform === "win32") {
    const base = join(process.env.ProgramData ?? "C:\\ProgramData", "Probation");
    return { config: join(base, "config"), data: join(base, "data"), log: join(base, "log"), bin: join(process.env.ProgramFiles ?? "C:\\Program Files", "Probation") };
  }
  return { config: "/etc/probation", data: "/var/lib/probation", log: "/var/log/probation", bin: "/usr/local/bin" };
}


/// Settings restart as the supervisor sees it: the process ends with 75. The real binary ends with 75 only after a settings push
/// from a policy server (tests/managed_sync.rs, E2E-settings-push); here the supervisor's reaction to exactly that exit status
/// is exercised on the real installed definition with a stand-in that exits 75.
export async function exit75Hook({ platform, scope, name, commands: c, run, must, expect, serviceUp, port, plistFile }) {
  if (platform === "linux") {
    const dropIn = scope === "user" ? join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "systemd/user", `${name}.service.d`) : `/etc/systemd/system/${name}.service.d`;
    mkdirSync(dropIn, { recursive: true });
    const file = join(dropIn, "exit75.conf");
    writeFileSync(file, "[Service]\nExecStartPre=\nExecStart=\nExecStart=/bin/sh -c 'exit 75'\n");
    try {
      const baseline = Number(run(c.restarts).stdout.trim());
      must(c.reload, "daemon-reload");
      must(c.restart, "restart onto the exit-75 stand-in");
      await waitFor("two supervisor restarts after exit 75", 20_000, () => Number(run(c.restarts).stdout.trim()) >= baseline + 2, 250);
      await waitFor("the stand-in's exit status 75", 10_000, () => run(c.lastStatus).stdout.trim() === "75", 100);
      expect(!(await listening(port)), "nothing listens while the stand-in exits");
    } finally {
      rmSync(dropIn, { recursive: true, force: true });
      must(c.reload, "daemon-reload");
      run([...c.stop.slice(0, -2), "reset-failed", c.stop.at(-1)]);
    }
    must(c.restart, "restart onto the real binary");
    await waitFor("the real binary listening again", 30_000, serviceUp);
    return "systemd restarted the unit after status 75 (NRestarts >= 2, Restart=on-failure, RestartSec=2), then the real binary came back on the same state";
  }
  if (platform === "darwin") {
    const plist = plistFile();
    const saved = `${plist}.real`;
    copyFileSync(plist, saved);
    try {
      must(c.stop, "bootout");
      must(["plutil", "-replace", "ProgramArguments", "-json", '["/bin/sh","-c","exit 75"]', plist], "stand-in plist");
      must(c.start(plist), "bootstrap the stand-in");
      await waitFor("two launchd runs after exit 75", 30_000, () => /runs = ([2-9]|\d\d+)/.test(run(c.print).stdout) && /last exit code = 75/.test(run(c.print).stdout), 1000);
    } finally {
      run(c.stop);
      copyFileSync(saved, plist);
      rmSync(saved, { force: true });
    }
    must(c.start(plist), "bootstrap the real definition");
    await waitFor("the real binary listening again", 30_000, serviceUp);
    return "launchd restarted the job after status 75 (runs >= 2, last exit code 75), then the real definition came back";
  }
  // Windows: the SCM answers a process that ends WITHOUT reporting Stopped (what exit 75 and any fatal error do, src/lifecycle.rs)
  // exactly as it answers a killed process; that path is the crash step above, and the operator stop stayed stopped.
  return "same SCM failure path as the crash step (process ends without Stopped -> restart action); the real exit-75 push needs a policy server and is covered by E2E-settings-push";
}


/// The whole of Part 1 for one host: disposable directories (or the platform's own with `systemLocations`), a unique service name,
/// the real lifecycle, and a best-effort removal of exactly this run's service afterwards. Returns the evidence record.
export async function runLifecycle({ root, binary: requestedBinary, scope, name, port, expect, log = () => {}, systemLocations = false, platform = process.platform }) {
  // E2E_SERVICE_PACKAGE: a directory made by scripts/package-release.sh. The installer and the binary then come from THAT layout (the
  // released one: its libraries beside the exe, SHA256SUMS), so what runs is what a user unpacks, not the build tree.
  let binary = requestedBinary;
  const packageDir = process.env.E2E_SERVICE_PACKAGE;
  const installer = platform === "win32" ? "install-service.ps1" : "install-service.sh";
  const script = packageDir ? join(packageDir, installer) : join(dirname(fileURLToPath(import.meta.url)), "../../../scripts", installer);
  if (packageDir) binary = join(packageDir, platform === "win32" ? "probation.exe" : "probation");
  rmSync(root, { recursive: true, force: true });
  const dirs = systemLocations ? systemDirs(platform) : dirsUnder(root);
  expect(existsSync(binary), `the native probation binary exists at ${binary} (cargo build --bin probation, or PROBATION_BIN)`);
  expect(!(await listening(port)), `port ${port} is free`);
  try {
    // Without a package (a build from the tree) there is no SHA256SUMS: the Windows installer must be told so, loudly.
    const release = Boolean(packageDir) && existsSync(join(packageDir, "RELEASE-PACKAGE"));
    const installExtra = installVerifyFlags({ platform, packageDir, release, signerWorkflow: process.env.E2E_SERVICE_SIGNER_WORKFLOW, sourceDigest: process.env.E2E_SERVICE_SOURCE_DIGEST });
    const requireAttestation = Boolean(packageDir && process.env.E2E_SERVICE_SIGNER_WORKFLOW);
    return await exercise({ platform, scope, name, script, binary, dirs, port, expect, log, exit75: exit75Hook, installExtra, requireAttestation });
  } finally {
    const argv = platform === "win32"
      ? ["powershell.exe", "-NoProfile", "-File", script, "uninstall", "-Name", name, "-ConfigDir", dirs.config, "-BinDir", dirs.bin, "-DataDir", dirs.data, "-LogDir", dirs.log]
      : ["bash", script, "uninstall", "--scope", scope, "--name", name, "--config-dir", dirs.config, "--data-dir", dirs.data, "--log-dir", dirs.log, "--bin-dir", dirs.bin];
    sh(argv);
  }
}
