// Operator-side helpers.
//
// `ops(h)` is for the deployment and operations scenarios (E2E-005 to E2E-010): the
// container engine itself (inspect, events, pause), one-off server commands, commands
// that run in the background, and firewall containers outside the compose file (a
// third firewall, a previous release's image). Nothing in it changes the shared stack
// unless a scenario asks. A firewall started there carries the label
// `e2e.extra=<project>`; the scenario removes it (`fw.rm()`, or `removeExtras()` in a
// finally), since compose does not know it.
//
// The named exports are for the outage, automation and network-lock scenarios (E2E-003,
// 014, 015, 016): the fleet page, the firewall's config file, a container's address,
// and extra containers on the e2e network.

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, hidden, request, unescape } from "./net.mjs";
import { ROOT, waitFor } from "./stack.mjs";

/// A Playwright context signed in as `who` (its cookie-jar session moved over), so a
/// person's next steps happen in Chromium.
export async function browserAs(h, who) {
  const context = await h.browser();
  await context.addCookies([...who.portal.cookies].map(([name, value]) => ({ name, value, url: h.portalUrl })));
  return context;
}

/// The Health cell of firewall `name` on /fleet, as the operator reads it.
export async function fleetHealth(portal, name) {
  const body = (await portal.get("/fleet")).body;
  const row = body.match(new RegExp(`<td>${name}</td>[\\s\\S]*?</tr>`))?.[0] ?? "";
  return unescape(row.match(/<span class="(?:good|bad)">([^<]*)<\/span>/)?.[1] ?? "");
}

/// Edits `$E2E_WORK/<service>.toml` as an operator edits config.toml: `edit(text)`
/// answers the new text. Restart the service after.
export function editConfig(stack, service, edit) {
  const file = join(stack.work, `${service}.toml`);
  writeFileSync(file, edit(readFileSync(file, "utf8")));
}

/// The address of `service` on the e2e network.
export function addressOf(stack, service) {
  const run = spawnSync(stack.engine, ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", stack.container(service)], {
    encoding: "utf8",
  });
  const address = run.stdout.trim().split(/\s+/).find((a) => a.startsWith(`${stack.net}.`));
  if (!address) throw new Error(`${service} has no address on ${stack.net}.0/24: ${run.stdout} ${run.stderr}`);
  return address;
}

/// When `service`'s container last started (changes on every restart).
export function startedAt(stack, service) {
  return spawnSync(stack.engine, ["inspect", "-f", "{{.State.StartedAt}}", stack.container(service)], { encoding: "utf8" }).stdout.trim();
}

/// Starts a container of `image` on the stack's e2e network at `ip` ({name, image,
/// ip, volumes: ["host:container:ro"], env: {}, args: []}); answers a function that
/// removes it. The name carries the project, so stacks running side by side differ.
export function runOnNetwork(stack, { name, image, ip, volumes = [], env = {}, args = [] }) {
  const full = `${stack.project}-${name}`;
  spawnSync(stack.engine, ["rm", "-f", full], { encoding: "utf8" });
  const network = spawnSync(stack.engine, ["network", "ls", "--format", "{{.Name}}"], { encoding: "utf8" })
    .stdout.split("\n")
    .find((n) => n === `${stack.project}_e2e`);
  if (!network) throw new Error(`no network ${stack.project}_e2e`);
  const run = spawnSync(
    stack.engine,
    [
      "run", "-d", "--name", full, "--network", network, "--ip", ip,
      ...volumes.flatMap((v) => ["-v", v]),
      ...Object.entries(env).flatMap(([k, v]) => ["-e", `${k}=${v}`]),
      image, ...args,
    ],
    { encoding: "utf8" },
  );
  if (run.status !== 0) throw new Error(`${stack.engine} run ${name}: ${run.stderr}`);
  return () => spawnSync(stack.engine, ["rm", "-f", full], { encoding: "utf8" });
}

/// The JSON error body of a firewall refusal ({error, reason, request_id}), or {}.
export function errorOf(answer) {
  try {
    return answer.json();
  } catch {
    return {};
  }
}

export function ops(h) {
  const { stack } = h;
  const network = `${stack.project}_e2e`;
  const image = process.env.E2E_FIREWALL_IMAGE ?? "localhost/probation:e2e";
  const serverImage = process.env.E2E_SERVER_IMAGE ?? "localhost/probation-server:e2e";

  /// One engine command (podman or docker): {status, stdout, stderr}; throws unless 0 with `check`.
  function engine(args, { check = true, input } = {}) {
    const run = spawnSync(stack.engine, args, { encoding: "utf8", input, maxBuffer: 256 * 1024 * 1024 });
    const answer = { status: run.status, stdout: run.stdout ?? "", stderr: run.stderr ?? "" };
    if (check && run.status !== 0) throw new Error(`${stack.engine} ${args.join(" ")} exited ${run.status}\n${answer.stdout}\n${answer.stderr}`);
    return answer;
  }

  /// The container of a compose service, running or not.
  function id(service) {
    const out = engine([
      "ps", "-aq",
      "--filter", `label=com.docker.compose.project=${stack.project}`,
      "--filter", `label=com.docker.compose.service=${service}`,
    ]).stdout.trim().split("\n")[0];
    expect(out, `no container for ${service}`);
    return out;
  }

  const inspect = (container) => JSON.parse(engine(["inspect", container]).stdout)[0];

  const pending = [];
  let gatewayOriginal;
  const o = {
    /// A check that holds only once a known product fix is merged ("needs F<n>"): a
    /// failure is recorded and the scenario goes on, so the rest is still proven;
    /// `settle()` at the end fails the scenario with every one recorded.
    needs(fix, ok, message) {
      if (ok) return true;
      pending.push(`needs ${fix}: ${message}`);
      h.log(`FAILS UNTIL ${fix} IS FIXED: ${message}`);
      return false;
    },
    settle() {
      expect(pending.length === 0, `${pending.length} check(s) wait for product fixes:\n${pending.join("\n")}`);
    },
    engine,
    network,
    image,
    serverImage,
    id,
    inspect,

    /// The address of a container (a compose service name or a container id) on the e2e network.
    ip(container) {
      const info = inspect(/^[0-9a-f]{12,}$/.test(container) ? container : id(container));
      const nets = info.NetworkSettings.Networks;
      return (nets[network] ?? Object.values(nets)[0]).IPAddress;
    },

    /// {status, restarts, exitCode, running}
    state(container) {
      const info = inspect(container);
      return { status: info.State.Status, running: info.State.Running, exitCode: info.State.ExitCode, restarts: info.RestartCount ?? 0 };
    },

    /// The exits of a container since `since` (a Date), from the engine's events:
    /// [{code, at (ms since 1970)}], oldest first.
    exits(container, since) {
      const out = engine(["events", "--since", since.toISOString(), "--until", new Date(Date.now() + 1000).toISOString(),
        "--filter", `container=${container}`, "--filter", "event=die", "--format", "json"], { check: false }).stdout;
      return out.split("\n").filter(Boolean).map((line) => {
        const event = JSON.parse(line);
        const nanos = event.timeNano ?? event.time * 1e9;
        return { code: Number(event.ContainerExitCode ?? event.Actor?.Attributes?.exitCode), at: Number(nanos) / 1e6 };
      });
    },

    /// The whole log of a container (all its runs), stdout and stderr.
    logs(container) {
      const run = engine(["logs", container], { check: false });
      return run.stdout + run.stderr;
    },

    /// `probation-server <args>` as a one-off container of the server service (the
    /// operator's commands). Never throws: {status, stdout, stderr}.
    server(args, { env = {} } = {}) {
      const envs = Object.entries(env).flatMap(([k, v]) => ["-e", `${k}=${v}`]);
      return stack.compose(["run", "--rm", "-T", "--no-deps", ...envs, "server", ...args], { check: false, quiet: true });
    },

    /// An empty `probation` database and no app roles, as on the first day (stop the
    /// server first).
    freshDatabase() {
      for (const statement of [
        "DROP DATABASE IF EXISTS probation WITH (FORCE)",
        "DROP ROLE IF EXISTS probation_e2e",
        "DROP ROLE IF EXISTS probation_app",
        "CREATE DATABASE probation OWNER probation",
      ]) {
        stack.exec("postgres", ["psql", "-U", "probation", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", statement], { check: true });
      }
    },

    /// The `name=value` lines a command printed (admin bootstrap, reset-link).
    printed(stdout) {
      return Object.fromEntries(stdout.split(/\r?\n/).filter((l) => /^[a-z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
    },

    /// SQL as another role (`psql -U <role>`): {status, stdout, stderr}; never throws.
    sqlAs(role, statement, db = "probation") {
      return stack.exec("postgres", ["psql", "-U", role, "-d", db, "-v", "ON_ERROR_STOP=1", "-tAc", statement]);
    },

    /// A shell script in a client container, in the background: a Promise of
    /// {status, stdout, stderr}. Files as in h.client.
    background(service, script, { files = {}, dir = `/work/${h.unique("bg")}` } = {}) {
      const writes = Object.entries(files).map(
        ([path, content]) => `mkdir -p "$(dirname '${path}')" && echo '${Buffer.from(content).toString("base64")}' | base64 -d > '${path}'`,
      );
      const clientHome = service.startsWith("client-") ? ["--env", "HOME=/root"] : [];
      const argv = ["exec", ...clientHome, stack.container(service), "sh", "-c", ["set -e", `mkdir -p ${dir}`, `cd ${dir}`, ...writes, "set +e", script].join("\n")];
      return new Promise((resolve) => {
        const child = spawn(stack.engine, argv);
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d) => (stdout += d));
        child.stderr.on("data", (d) => (stderr += d));
        child.on("close", (status) => resolve({ status, stdout, stderr }));
      });
    },

    /// GET `url` from inside the e2e network (a client container), for services the
    /// gateway does not front: the status code, or 0 when nothing answers.
    async inside(url, { client = "bridge", headers = {} } = {}) {
      const script = `fetch(${JSON.stringify(url)}, {headers: ${JSON.stringify(headers)}, signal: AbortSignal.timeout(5000)}).then(r => console.log(r.status), () => console.log(0))`;
      const run = stack.exec(client, ["node", "-e", script]);
      return Number(run.stdout.trim() || 0);
    },

    /// Starts a firewall container outside compose, as an operator would with
    /// `docker run`: `config` (TOML text) at /etc/probation/config.toml, `token` (or
    /// none) at /e2e/firewall.token, its own named volume on /var/lib/probation, on the
    /// e2e network as `name` (so the gateway reaches it when `name` is firewall-1 or
    /// firewall-2), at `ip` if given. Restart policy unless-stopped, as deploy/ has.
    /// `mounts`: more [hostPath, containerPath] bind mounts, read-only.
    firewall({ name, config, token, ip, image: tag = image, volume = `${stack.project}-${name}-data`, env = {}, mounts = [], restart = "unless-stopped" }) {
      const dir = join(stack.work, "extra", name);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "config.toml"), config);
      writeFileSync(join(dir, "firewall.token"), token ? `${token}\n` : "", { mode: 0o644 });
      const container = `${stack.project}-x-${name}`;
      engine(["rm", "-f", container], { check: false });
      const envs = Object.entries({ SSL_CERT_FILE: "/e2e/ca/ca.pem", ...env }).flatMap(([k, v]) => ["-e", `${k}=${v}`]);
      engine([
        "run", "-d", "--name", container, "--label", `e2e.extra=${stack.project}`,
        "--network", network, "--network-alias", name, ...(ip ? ["--ip", ip] : []),
        "--restart", restart, "--stop-timeout", "45", ...envs,
        "-v", `${join(stack.work, "ca")}:/e2e/ca:ro`,
        "-v", `${join(stack.work, "tls")}:/e2e/tls:ro`,
        "-v", `${join(dir, "config.toml")}:/etc/probation/config.toml:ro`,
        "-v", `${join(dir, "firewall.token")}:/e2e/firewall.token:ro`,
        "-v", `${volume}:/var/lib/probation`,
        ...mounts.flatMap(([from, to]) => ["-v", `${from}:${to}:ro`]),
        tag,
      ]);
      const fw = {
        name,
        container,
        volume,
        dir,
        ip: () => o.ip(engine(["inspect", "--format", "{{.Id}}", container]).stdout.trim()),
        logs: () => o.logs(container),
        state: () => o.state(container),
        stop: (seconds = 45) => engine(["stop", "-t", String(seconds), container], { check: false }),
        start: () => engine(["start", container]),
        rm: () => engine(["rm", "-f", "-t", "5", container], { check: false }),
        writeToken: (value) => writeFileSync(join(dir, "firewall.token"), value ? `${value}\n` : ""),
        writeConfig: (text) => writeFileSync(join(dir, "config.toml"), text),
        /// A command inside it: {status, stdout, stderr}.
        exec: (...argv) => engine(["exec", container, ...argv], { check: false }),
        /// /health/ready from inside the network: 200, 503, or 0 when it does not answer.
        ready: () => o.inside(`http://${name}:8080/health/ready`),
      };
      return fw;
    },

    /// Removes every firewall `firewall()` started for this stack, and their volumes.
    removeExtras() {
      const ids = engine(["ps", "-aq", "--filter", `label=e2e.extra=${stack.project}`], { check: false }).stdout.trim().split("\n").filter(Boolean);
      const volumes = ids.flatMap((c) => {
        try {
          return inspect(c).Mounts.filter((m) => m.Type === "volume").map((m) => m.Name);
        } catch {
          return [];
        }
      });
      if (ids.length) engine(["rm", "-f", "-t", "5", ...ids], { check: false });
      // Also the volumes of firewalls removed earlier (named `<project>-…-data`; compose's
      // are `<project>_…`). Never forced: another stack whose project name starts with
      // this one's (`probation-e2e-pbt`) keeps the volumes its containers use.
      const named = engine(["volume", "ls", "-q"], { check: false }).stdout.split("\n").filter((v) => v.startsWith(`${stack.project}-`) && !v.includes("_"));
      const gone = [...new Set([...volumes, ...named])];
      if (gone.length) engine(["volume", "rm", ...gone], { check: false });
    },

    /// The managed firewall config the stack gives firewall-1 (config.sample.toml as an
    /// operator edits it), for another host name.
    managedConfig(host, extra = "") {
      const gateway = `${stack.net}.10`;
      return `${stackSample()
        .replace(/^listen = .*$/m, 'listen = "0.0.0.0:8080"')
        .replace(/^public_url = .*$/m, `public_url = "https://${host}"`)}
sync_interval_seconds = ${h.syncInterval}
${extra}
[management]
url = "https://sync.e2e.test:8444"
token_file = "/e2e/firewall.token"
lookup_budget_per_second = 200
client_lookup_allowance_per_second = 100
trusted_proxies = ["${gateway}/32"]
`;
    },

    /// The /fleet page as a global admin's portal session reads it: {csrf, firewalls:
    /// [{id, name, version, checkIn, health, error, retired}], rollouts: [{id, state,
    /// settings, steps: [text], resume, skip}], body}. Rollouts newest first.
    async fleet(portal) {
      const page = await portal.get("/fleet");
      expect(page.status === 200, `/fleet: ${page.status}\n${page.body}`);
      const body = page.body;
      const text = (html) => unescape(html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
      const firewalls = [...body.matchAll(/<tr id="firewall-(\d+)">([\s\S]*?)<\/tr>/g)].map(([, fid, row]) => {
        const cells = [...row.matchAll(/<td>([\s\S]*?)<\/td>/g)].map(([, cell]) => cell);
        const health = text(cells[4] ?? "");
        return {
          id: Number(fid),
          name: text(cells[1] ?? ""),
          version: text(cells[2] ?? ""),
          checkIn: text(cells[3] ?? ""),
          health: health.replace(/ Last error: [\s\S]*$/, ""),
          error: health.match(/Last error: ([\s\S]*)$/)?.[1] ?? null,
          retired: !cells[0]?.includes("checkbox"),
        };
      });
      const section = body.slice(body.indexOf('id="rollouts-heading"'));
      const rollouts = section.split("<h3>").slice(1).map((chunk) => {
        const head = text(chunk.slice(0, chunk.indexOf("</h3>")));
        return {
          state: head.replace(/^.*: /, ""),
          settings: unescape(chunk.match(/<pre>([\s\S]*?)<\/pre>/)?.[1] ?? ""),
          steps: [...(chunk.match(/<ul>([\s\S]*?)<\/ul>/)?.[1] ?? "").matchAll(/<li>([\s\S]*?)<\/li>/g)].map(([, li]) => text(li)),
          id: Number(chunk.match(/\/fleet\/rollouts\/(\d+)\//)?.[1] ?? 0) || null,
          resume: /\/resume"/.test(chunk),
          skip: /\/skip"/.test(chunk),
        };
      });
      return { csrf: hidden(body, "csrf"), firewalls, rollouts, body };
    },

    /// "Save and apply" on /fleet: `toml` to the firewalls named (in that order).
    async push(portal, names, toml) {
      const { csrf, firewalls } = await o.fleet(portal);
      const ids = names.map((name) => firewalls.find((f) => f.name === name)?.id);
      expect(ids.every(Boolean), `firewalls ${names} on /fleet: ${JSON.stringify(firewalls)}`);
      return portal.post("/fleet/settings", [["csrf", csrf], ...ids.map((fid) => ["firewall", String(fid)]), ["toml", toml]]);
    },

    /// The gateway drops every connection for sync.e2e.test (the sync proxy failing),
    /// while the portal and the firewalls stay reachable; `syncProxy(true)` restores it.
    syncProxy(up) {
      const conf = join(stack.work, "gateway-nginx.conf");
      if (!up) {
        gatewayOriginal = readFileSync(conf, "utf8");
        writeFileSync(conf, gatewayOriginal
          .replace("server_name portal.e2e.test sync.e2e.test;", "server_name portal.e2e.test;")
          .replace(/\n}\s*$/, "\n    server { listen 8443 ssl; listen 8444 ssl; server_name sync.e2e.test; return 444; }\n}\n"));
      } else {
        writeFileSync(conf, gatewayOriginal);
      }
      return stack.exec("gateway", ["nginx", "-s", "reload"]);
    },

    /// Waits until `url` (through the bridge) answers `status`.
    async waitStatus(url, status, { timeout = 60_000, headers = {} } = {}) {
      return waitFor(`${url} answers ${status}`, async () => (await request(url, { headers, timeout: 5000 })).status === status, { timeout });
    },
  };
  return o;
}

const stackSample = () => readFileSync(join(ROOT, "config.sample.toml"), "utf8");
