// Row 25: the command lines the native lifecycle driver issues on each OS, the parsers of what the service managers print, and
// the static contract of the Windows installer script (which only a Windows runner can execute). Runs on every host.
// node tests/e2e/native/service-lifecycle.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { commands, failurePolicyProblems, installVerifyFlags, noStartFlag, parseLaunchctl, parseScQuery } from "./service-lifecycle.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const dirs = { config: "/c", data: "/d", log: "/l", bin: "/b" };
const base = { script: "/s/install-service.sh", binary: "/b/probation", dirs, name: "pf" };

// Linux, system scope: systemctl, the script's flags in one place.
const sys = commands({ platform: "linux", scope: "system", ...base });
assert.deepEqual(sys.stop, ["systemctl", "stop", "pf.service"]);
assert.deepEqual(sys.restart, ["systemctl", "restart", "pf.service"]);
assert.deepEqual(sys.mainPid, ["systemctl", "show", "-p", "MainPID", "--value", "pf.service"]);
assert.deepEqual(sys.install(["--no-start"]).slice(0, 5), ["bash", "/s/install-service.sh", "install", "--scope", "system"]);
assert.ok(sys.install().join(" ").includes("--config-dir /c --data-dir /d --log-dir /l --bin-dir /b"));
assert.deepEqual(sys.kill(42), ["kill", "-KILL", "42"]);
// The hosted lanes install a package built (and attested by native-service.yml) in CI, with the installer's FULL verification: no
// --no-verify. A CI package carries no RELEASE-PACKAGE marker (it is not a release), so the installer is told it is a dev package, and
// the signer workflow of its attestation is named. A release package and a build from the tree get no extra flag, except that a build from
// the tree on Windows (no SHA256SUMS) needs -NoVerify.
const SIGNER = ".github/workflows/native-service.yml";
assert.deepEqual(installVerifyFlags({ platform: "linux", packageDir: "/p", release: false, signerWorkflow: SIGNER }), ["--dev-package", "--signer-workflow", SIGNER]);
assert.deepEqual(installVerifyFlags({ platform: "darwin", packageDir: "/p", release: false, signerWorkflow: SIGNER }), ["--dev-package", "--signer-workflow", SIGNER]);
assert.deepEqual(installVerifyFlags({ platform: "win32", packageDir: "/p", release: false, signerWorkflow: SIGNER }), ["-DevPackage", "-SignerWorkflow", SIGNER]);
assert.deepEqual(installVerifyFlags({ platform: "linux", packageDir: "/p", release: true }), []);
assert.deepEqual(installVerifyFlags({ platform: "win32", packageDir: "/p", release: true }), []);
assert.deepEqual(installVerifyFlags({ platform: "win32", packageDir: undefined }), ["-NoVerify"]);
assert.deepEqual(installVerifyFlags({ platform: "linux", packageDir: undefined }), []);
for (const platform of ["linux", "darwin", "win32"]) {
  assert.ok(!installVerifyFlags({ platform, packageDir: "/p", release: false, signerWorkflow: SIGNER }).some((f) => /no-?verify|allow-unverified/i.test(f)), `${platform}: a package keeps the full verification`);
}
// install-service.ps1 declares [switch]$NoStart; a `--no-start` there is a parameter-binding error.
assert.equal(noStartFlag("win32"), "-NoStart");
assert.equal(noStartFlag("linux"), "--no-start");
assert.equal(noStartFlag("darwin"), "--no-start");
// Linux, user scope: the same through the user manager.
const usr = commands({ platform: "linux", scope: "user", ...base });
assert.deepEqual(usr.stop, ["systemctl", "--user", "stop", "pf.service"]);
assert.deepEqual(usr.isActive, ["systemctl", "--user", "is-active", "pf.service"]);
assert.ok(usr.install().includes("user"));

// macOS: a deliberate stop unloads the job; the domain follows the scope.
const mac = commands({ platform: "darwin", scope: "system", ...base });
assert.deepEqual(mac.stop, ["launchctl", "bootout", "system/com.postfix.pf"]);
assert.deepEqual(mac.start("/Library/LaunchDaemons/com.postfix.pf.plist"), ["launchctl", "bootstrap", "system", "/Library/LaunchDaemons/com.postfix.pf.plist"]);
assert.deepEqual(mac.print, ["launchctl", "print", "system/com.postfix.pf"]);
assert.deepEqual(commands({ platform: "darwin", scope: "user", uid: 501, ...base }).stop, ["launchctl", "bootout", "gui/501/com.postfix.pf"]);

// Windows: PowerShell wrappers around the script and the service control manager.
const win = commands({ platform: "win32", scope: "system", ...base, script: "C:\\s\\install-service.ps1" });
assert.equal(win.install()[0], "powershell.exe");
assert.ok(win.install().includes("-File") && win.install().includes("-ConfigDir") && win.install().includes("-Binary"));
assert.ok(!win.uninstall().includes("-Binary"), "an uninstall needs no binary");
assert.match(win.stop.at(-1), /Stop-Service -Name pf -Force/);
assert.deepEqual(win.query, ["sc.exe", "queryex", "pf"]);
assert.deepEqual(win.kill(7), ["taskkill", "/F", "/PID", "7"]);
assert.throws(() => commands({ platform: "plan9", ...base }), /no service manager/);

// What the managers print.
assert.deepEqual(parseLaunchctl("state = running\n\tpid = 812\n\truns = 3\n\tlast exit code = 75\n"), { pid: 812, runs: 3, lastExit: 75 });
assert.deepEqual(parseLaunchctl("state = waiting\n"), { pid: null, runs: null, lastExit: null });
assert.deepEqual(parseScQuery("        STATE              : 4  RUNNING\n        PID                : 4321\n"), { state: "RUNNING", pid: 4321 });
assert.deepEqual(parseScQuery("        STATE              : 1  STOPPED\n        PID                : 0\n"), { state: "STOPPED", pid: 0 });
const qfailure = "[SC] QueryServiceConfig2 SUCCESS\nSERVICE_NAME: Probation\n        RESET_PERIOD (in seconds)    : 86400\n        FAILURE_ACTIONS              : RESTART -- Delay = 5000 milliseconds.\n                                       RESTART -- Delay = 5000 milliseconds.\n                                       RESTART -- Delay = 60000 milliseconds.\n";
assert.deepEqual(failurePolicyProblems(qfailure), []);
assert.equal(failurePolicyProblems(qfailure.replace("5000", "1000")).length, 1, "a wrong delay is reported");
assert.equal(failurePolicyProblems("nothing").length, 2);

// The Windows installer's contract, read from the script (it runs only on a Windows runner).
const ps1 = readFileSync(join(here, "../../../scripts/install-service.ps1"), "utf8");
for (const needle of [
  "NT SERVICE\\$Name",                                  // virtual account, no stored password
  "restart/5000/restart/5000/restart/60000",             // 5 s restart delay
  "'reset=', '86400'",
  "ChangeServiceConfig2W",                               // 45 s allowance by the documented API, not a registry value
  "Set-PreshutdownTimeout 45000",
  "'failureflag', $Name, '0'",                           // only a crash-style end restarts it; a reported stop does not
  "icacls",
  "service --config",                                    // the SCM entry point
]) assert.ok(ps1.includes(needle), `install-service.ps1 has ${needle}`);
const install = ps1.slice(ps1.indexOf("'install' {"), ps1.indexOf("'upgrade' {"));
assert.ok(install.indexOf("Test-Config $BinPath") < install.indexOf("Register-Service"), "the configuration is validated before the service is registered");
assert.ok(install.indexOf("Register-Service") < install.indexOf("Set-ServiceAcls"), "the service account exists before ACLs name it");
assert.ok(install.indexOf("New-ProtectedDirectory $dir") < install.indexOf("New-ConfigIfAbsent"), "the directories are created and protected before any file is written");
assert.ok(install.indexOf("Set-ServiceAcls") < install.indexOf("-StartupType Automatic"), "the service becomes automatic only after its ACLs are in place");
assert.ok(install.includes("Invoke-InstallRollback"), "a failed install removes what it created");
assert.match(ps1, /New-Service[^\n]*-StartupType Disabled/, "registered Disabled, never as an automatic LocalSystem service");
assert.match(ps1, /sc\.exe @\('config', \$Name, 'obj=', \$Account\)/, "the virtual account is set at registration");
assert.ok(ps1.includes("Assert-Trusted $ConfigFile") && ps1.includes("GetOwner([Security.Principal.SecurityIdentifier])") && ps1.includes("S-1-5-32-544") && !/Owner -notmatch/.test(ps1), "an existing config.toml must be owned by SYSTEM or Administrators, compared as SIDs not names");
assert.ok(ps1.includes("Get-DaclViolation") && ps1.includes("An empty directory is ours to take over completely") && ps1.includes("it is not this installer's"), "a pre-existing directory is reset when empty and refused when its ACL is not private");
const verify = ps1.slice(ps1.indexOf("function Assert-PackageHashes"), ps1.indexOf("function Install-BinaryFiles"));
assert.ok(verify.includes("has no SHA256SUMS, so the files cannot be verified") && verify.includes("-NoVerify") && verify.includes("DISABLED"), "no SHA256SUMS refuses unless -NoVerify, which warns");
assert.ok(verify.includes("--signer-workflow") && verify.includes("--repo $repo") && verify.includes("--certificate-oidc-issuer https://token.actions.githubusercontent.com") && verify.includes("--certificate-identity-regexp") && verify.includes("--bundle $bundle"), "gh and cosign are pinned to the repository, the workflow, the issuer and the bundle");
assert.ok(verify.includes("this is a release package and gh is not installed") && verify.includes("this is a release package and cosign is not installed") && verify.includes("its cosign bundle is missing"), "a release package refuses without gh, cosign or a bundle");
assert.ok(upgradeBlock().includes("Assert-PackageHashes"), "an upgrade verifies before touching anything");
assert.ok(install.indexOf("Assert-PackageHashes") < install.indexOf("New-ProtectedDirectory $dir"), "the package is verified before any directory or file is created");
assert.ok(ps1.includes("-DevPackage") && ps1.includes("has no RELEASE-PACKAGE marker, so it is not a release package"), "a package without the release marker needs -DevPackage");
assert.ok(ps1.includes("[IO.Path]::GetFullPath($Binary) -ieq") && ps1.includes("compared canonically"), "the shipped binary is recognized however its path is spelled");
assert.ok(ps1.includes("Get-ChildItem -LiteralPath $Path -Recurse -Force") && ps1.includes("anywhere below is refused outright"), "a pre-existing directory is judged with everything under it");
assert.ok(!ps1.includes("*> $null") && ps1.includes("2>$null | Out-Null"), "no PowerShell 7-only redirection of all streams");
assert.ok(ps1.includes('"^https://github\\.com/"') && ps1.includes("@refs/tags/.+$"), "the cosign identity is anchored and escaped");
assert.ok(ps1.includes("PROBATION_SERVICE_NAME"), "the key-file check is told the service name");
assert.ok(ps1.includes("is, or sits behind, a link"), "package-manager files behind a link are refused");
assert.ok(ps1.includes("ReparsePoint") && ps1.includes("is a junction or other reparse point: refusing"), "reparse points are refused");
assert.ok(ps1.includes("-PublicUrl") && ps1.includes("'https://localhost:'") && ps1.includes("'^https://"), "public_url defaults to https and -PublicUrl must be https");
assert.ok(ps1.includes("-TlsCert") && ps1.includes("tls_cert_path"), "a certificate can be named");
assert.ok(ps1.includes("SHA256SUMS") && ps1.includes("does not match SHA256SUMS") && ps1.includes("the release ships none (OpenSSL is linked in): refusing"), "the exe is hash-verified and a package that carries a library is refused (OpenSSL is linked in statically)");
assert.ok(ps1.includes('$env:PATH = "$env:SystemRoot\\System32;$env:SystemRoot"'), "check-config runs with a clean PATH");
assert.ok(ps1.includes("UTF8Encoding($false)") && !/Set-Content|Get-Content/.test(ps1.replace(/<#[\s\S]*?#>/g, "")), "files are read and written as BOM-less UTF-8 bytes, not through the ANSI cmdlets");
assert.ok(ps1.includes("Get-Command npm"), "a missing npm is a branch, not an exception");
// Uninstall removes only paths it computes itself and that the record names; it never follows a reparse point.
const uninstall = ps1.slice(ps1.indexOf("'uninstall' {"));
assert.ok(uninstall.includes("$ours") && uninstall.includes("which this installer never creates: refusing it") && uninstall.includes("is behind a reparse point: refusing it"));
const removes = [...uninstall.matchAll(/Remove-Item[^\n]*/g)].map((m) => m[0]);
assert.equal(removes.length, 2);
assert.ok(removes.every((line) => !/ConfigDir|DataDir|LogDir/.test(line)), `no Remove-Item in uninstall names a config or data directory: ${removes}`);
function upgradeBlock() { return ps1.slice(ps1.indexOf("'upgrade' {"), ps1.indexOf("'uninstall' {")); }
// An upgrade restores the previous files on any failure after the swap and checks the new service stays up.
const upgrade = ps1.slice(ps1.indexOf("'upgrade' {"), ps1.indexOf("'uninstall' {"));
assert.ok(upgrade.includes("catch") && upgrade.includes(".prev") && upgrade.includes("Wait-Stays-Up") && upgrade.includes("Set-ServiceDefinition"));
// A reinstall over kept data meets files the service created (owned by its virtual account): Get-DaclViolation accepts that owner,
// Assert-Trusted (config, blocklist, key files, directory roots) stays strict.
const daclViolation = ps1.slice(ps1.indexOf("function Get-DaclViolation"), ps1.indexOf("function New-ProtectedDirectory"));
assert.ok(/\$owners = \$TrustedOwnerSids \+ \(Get-ServiceSid \$Name\)/.test(daclViolation) && daclViolation.includes("-notin $owners") && !daclViolation.includes("-notin $TrustedOwnerSids"), "Get-DaclViolation accepts the service SID as an owner");
const assertTrusted = ps1.slice(ps1.indexOf("function Assert-Trusted"), ps1.indexOf("function Get-ServiceSid"));
assert.ok(assertTrusted.includes("$TrustedOwnerSids") && !assertTrusted.includes("Get-ServiceSid"), "Assert-Trusted stays strict: the service never owns the config");
// The lifecycle driver reinstalls over the kept data and starts the service once more, on every OS.
const lifecycle = readFileSync(join(here, "service-lifecycle.mjs"), "utf8");
const reinstall = lifecycle.slice(lifecycle.indexOf("// 9."), lifecycle.indexOf("return evidence;"));
// credential-reads exists only in shared-service mode (src/lib.rs, service_policy); the lifecycle lane is standalone, so step 9 checks what a
// standalone service always creates in the data dir (the lock file and the state directory) and, on Windows, logs their owner SID.
assert.ok(!reinstall.includes('existsSync(join(dirs.data, "credential-reads"))'), "step 9 must not require credential-reads: the standalone service never creates it");
assert.ok(reinstall.includes('join(dirs.data, "lock")') && reinstall.includes('join(dirs.data, "state")'), "step 9 checks the lock file and the state directory the standalone service creates");
assert.ok(reinstall.includes("c.owner(") && reinstall.includes("S-1-5-80"), "step 9 prints the owner SID of the service's files on Windows");
assert.ok(commands({ platform: "win32", ...base }).owner("C:\\d\\lock").join(" ").includes("GetOwner([System.Security.Principal.SecurityIdentifier])"), "the Windows owner command asks for the owner as a SID");
assert.ok(reinstall.includes('"reinstall over kept data"') && reinstall.includes('"reinstall over kept data"') && reinstall.includes("serviceUp") && reinstall.includes('"uninstall after reinstall"'), "the lifecycle reinstalls over the kept data, starts, waits until it listens and uninstalls");
assert.ok(reinstall.indexOf("c.install") < reinstall.indexOf("startAgain()") && reinstall.indexOf("startAgain()") < reinstall.indexOf("c.stop") && reinstall.indexOf("c.stop") < reinstall.indexOf("c.uninstall"), "reinstall, start, stop, uninstall in that order");
// Braces and quotes balance, so a syntax slip is caught on any host.
const code = ps1.replace(/<#[\s\S]*?#>/g, "").replace(/(^|\s)#[^\n]*/g, "$1");
assert.equal((code.match(/\{/g) ?? []).length, (code.match(/\}/g) ?? []).length, "braces balance");
assert.equal((code.match(/\(/g) ?? []).length, (code.match(/\)/g) ?? []).length, "parentheses balance");
console.log("service-lifecycle.test: ok");
