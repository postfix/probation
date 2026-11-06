// SEC4: on a macOS CI runner an unprivileged process may bind a port below 1024 only on the
// wildcard address, never on 127.0.0.1. To keep the fake PyPI on loopback, it listens on a high
// loopback port and pf redirects 127.0.0.1:443 to it (locally originated connections need the
// route-to rule as well). These are only the argument builders; stack.mjs runs them, probes the
// result and falls back to the wildcard bind if the redirect does not work.

const port = (value, label) => {
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error(`pf ${label} port must be an integer in 1..65535, got ${JSON.stringify(value)}`);
  return value;
};

export function pfRules({ from, to }) {
  const [a, b] = [port(from, "source"), port(to, "target")];
  return `rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port ${a} -> 127.0.0.1 port ${b}\n`
    + `pass out on lo0 route-to (lo0 127.0.0.1) inet proto tcp from any to 127.0.0.1 port ${a} keep state\n`;
}

export function pfSteps({ from, to }) {
  const sudo = (...args) => ({ command: "sudo", args: ["-n", "pfctl", ...args] });
  return {
    load: { ...sudo("-f", "-"), input: pfRules({ from, to }) },
    enable: sudo("-E"),
    restore: sudo("-f", "/etc/pf.conf"),
    release: (token) => {
      if (typeof token !== "string" || !/^\d+$/.test(token)) throw new Error(`pf token must be digits, got ${JSON.stringify(token)}`);
      return sudo("-X", token);
    },
  };
}

/// The enable token `pfctl -E` prints ("Token : 123..."), or null if pf was already enabled.
export function parsePfToken(output) {
  return output.match(/^Token\s*:\s*(\d+)/m)?.[1] ?? null;
}
