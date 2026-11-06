// Starting programs the same way on every platform without a string that a shell re-parses.
// POSIX: the program and its argument array, untouched. Windows: npm, twine and uv are
// .cmd shims or live under "Program Files", so the command goes through cmd.exe as one
// verbatim command line in which the program and every argument are quoted by the rules
// below (tested with a reference splitter in spawn-args.test.mjs).

/// A cmd.exe command line in which the program and every argument stay one word. `%` would
/// be expanded by cmd even inside quotes, and quotes and line breaks cannot be quoted, so
/// those are refused rather than guessed at.
export function winCommandLine(command, args) {
  const word = (text) => {
    if (/[%\r\n"]/.test(text)) throw new Error(`unsafe argument for a Windows command line: ${JSON.stringify(text)}`);
    if (text !== "" && !/[\s&|<>^()!;,=]/.test(text)) return text;
    // Backslashes just before the closing quote would escape it: double them.
    return `"${text.replace(/\\+$/, (run) => run + run)}"`;
  };
  return [command, ...args].map(word).join(" ");
}

/// [file, argv, options] for child_process.spawn/spawnSync. `shim: false` is for real
/// programs (.exe), which Node starts directly with correct quoting and without a shell
/// process to outlive a timeout; npm, twine and uv are shims and keep the default.
export function launch(command, args, options, platform = process.platform, { shim = true } = {}) {
  if (platform !== "win32" || !shim) return [command, args, options];
  return ["cmd.exe", ["/d", "/v:off", "/s", "/c", `"${winCommandLine(command, args)}"`], { ...options, windowsVerbatimArguments: true }];
}

/// M1: `[program, argv]` that kills a process and its children on Windows (cmd.exe is only
/// the shell around the real program), or null where `child.kill()` is enough. The pid is
/// checked to be a positive integer so nothing else can be smuggled into the command.
export function taskkillArgs(pid, platform = process.platform) {
  if (!Number.isInteger(pid) || pid <= 0) throw new Error(`taskkill needs a positive integer pid, got ${JSON.stringify(pid)}`);
  return platform === "win32" ? ["taskkill", ["/T", "/F", "/PID", String(pid)]] : null;
}
