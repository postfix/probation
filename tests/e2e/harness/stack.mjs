// The e2e stack's lifecycle: compose with docker or podman, the operator's one-time
// steps (docs/management-server.md), and the controls scenarios use on it.

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import { Authenticator, Portal, between, configure, expect, hidden, request } from "./net.mjs";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const COMPOSE_DIR = join(ROOT, "tests/e2e/compose");
export const OPERATOR_EMAIL = "ops@example.com";
/// The managed firewalls' sync interval: short, so waits for propagation stay short.
export const SYNC_INTERVAL = 10;
const CORE = ["postgres", "gateway", "mail", "bridge"];
const CLIENTS = ["client-npm", "client-pip"];
const NIGHTLY_CLIENTS = [
  "client-npm10",
  "client-npm11",
  "client-js",
  "client-yarn-berry",
  "client-bun",
  "client-pip-previous",
  "client-uv",
  "client-poetry",
];

/// Polls `check` (truthy = done) every `every` ms until `timeout` ms pass.
export async function waitFor(what, check, { timeout = 60_000, every = 500 } = {}) {
  const deadline = Date.now() + timeout;
  let last;
  for (;;) {
    try {
      const done = await check();
      if (done) return done;
    } catch (err) {
      last = err;
    }
    if (Date.now() > deadline) throw new Error(`${what}: not within ${timeout} ms${last ? ` (${last.message})` : ""}`);
    await sleep(every);
  }
}

export class Stack {
  /// {work, project, net ("11.220.0"), bridgePort, canary, nightly}
  constructor(options) {
    Object.assign(this, options);
    this.files = ["-f", join(COMPOSE_DIR, "compose.yml")];
    if (this.canary) this.files.push("-f", join(COMPOSE_DIR, "canary.yml"));
    this.command = (process.env.E2E_COMPOSE_CMD ?? "docker compose").split(" ");
    this.engine = process.env.E2E_ENGINE ?? (this.command[0].startsWith("podman") ? "podman" : "docker");
  }

  get env() {
    return {
      ...process.env,
      E2E_WORK: this.work,
      E2E_SECRET_KEY: this.secretKey ?? "",
      E2E_BRIDGE_PORT: String(this.bridgePort),
      E2E_NET: this.net,
      // podman's `compose` wrapper announces its provider on every call otherwise.
      PODMAN_COMPOSE_WARNING_LOGS: "false",
    };
  }

  /// One compose command; throws unless it exits 0 (`check: false` returns instead).
  compose(args, { input, check = true, quiet = false } = {}) {
    // `down` also removes the nightly clients a previous nightly stack left.
    const profiles = this.nightly || args[0] === "down" ? ["--profile", "nightly"] : [];
    const run = spawnSync(this.command[0], [...this.command.slice(1), "-p", this.project, ...this.files, ...profiles, ...args], {
      env: this.env,
      input,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    if (!quiet && run.stderr && run.status !== 0) process.stderr.write(run.stderr);
    if (check && run.status !== 0) throw new Error(`compose ${args.join(" ")} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
    return { status: run.status, stdout: run.stdout ?? "", stderr: run.stderr ?? "" };
  }

  /// The running container of `service`, by the labels both compose tools set.
  container(service) {
    const run = spawnSync(
      this.engine,
      ["ps", "-q", "--filter", `label=com.docker.compose.project=${this.project}`, "--filter", `label=com.docker.compose.service=${service}`],
      { encoding: "utf8" },
    );
    const id = (run.stdout ?? "").trim().split("\n")[0];
    expect(id, `${service} is not running`);
    return id;
  }

  /// A command in a running service's container: {status, stdout, stderr}. Straight to
  /// the engine (no compose wrapper, no TTY), so the output is only the command's.
  exec(service, argv, { input, check = false } = {}) {
    const run = spawnSync(this.engine, ["exec", ...(input === undefined ? [] : ["-i"]), this.container(service), ...argv], {
      input,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
    });
    const answer = { status: run.status, stdout: run.stdout ?? "", stderr: run.stderr ?? "" };
    if (check && run.status !== 0) throw new Error(`${service}: ${argv.join(" ")} exited ${run.status}\n${answer.stdout}\n${answer.stderr}`);
    return answer;
  }

  /// One SQL statement as the database owner; the rows as `psql -tA` prints them.
  sql(statement) {
    return this.exec("postgres", ["psql", "-U", "probation", "-d", "probation", "-v", "ON_ERROR_STOP=1", "-tAc", statement], {
      check: true,
    }).stdout.trim();
  }

  start(...services) {
    this.compose(["up", "-d", "--no-deps", ...services]);
  }

  stop(...services) {
    this.compose(["stop", ...services]);
  }

  restart(...services) {
    this.compose(["restart", ...services]);
  }

  logs(service) {
    const run = this.compose(["logs", service], { check: false, quiet: true });
    return run.stdout + run.stderr;
  }

  get services() {
    return [
      ...CORE,
      ...(this.canary ? [] : ["fakes"]),
      "server",
      "firewall-1",
      "firewall-2",
      "firewall-standalone",
      ...CLIENTS,
      ...(this.nightly ? NIGHTLY_CLIENTS : []),
    ];
  }

  writeFiles() {
    mkdirSync(join(this.work, "producer"), { recursive: true });
    if (!existsSync(join(this.work, "ca", "ca.pem"))) {
      const made = spawnSync("bash", [join(ROOT, "tests/e2e/fixtures/make-ca.sh"), this.work], { stdio: "inherit" });
      expect(made.status === 0, "make-ca.sh failed");
    }
    const gateway = `${this.net}.10`;
    writeFileSync(
      join(this.work, "server.toml"),
      readFileSync(join(COMPOSE_DIR, "server.toml"), "utf8").replaceAll("11.220.0.10", gateway),
    );
    // The shipped sample, edited as an operator would: plain HTTP behind the gateway.
    const sample = readFileSync(join(ROOT, "config.sample.toml"), "utf8").replace(/^listen = .*$/m, 'listen = "0.0.0.0:8080"');
    for (const [name, host] of [
      ["firewall-1", "fw1"],
      ["firewall-2", "fw2"],
    ]) {
      const config = `${sample.replace(/^public_url = .*$/m, `public_url = "https://${host}.e2e.test"`)}
sync_interval_seconds = ${SYNC_INTERVAL}

[management]
url = "https://sync.e2e.test"
token_file = "/e2e/firewall.token"
lookup_budget_per_second = 200
client_lookup_allowance_per_second = 100
trusted_proxies = ["${gateway}/32"]
`;
      writeFileSync(join(this.work, `${name}.toml`), config);
      if (!existsSync(join(this.work, `${name}.token`))) writeFileSync(join(this.work, `${name}.token`), "", { mode: 0o644 });
    }
    writeFileSync(
      join(this.work, "firewall-standalone.toml"),
      sample
        .replace(/^public_url = .*$/m, 'public_url = "https://fw-standalone.e2e.test"')
        .replace(/^blocklist_file = .*$/m, 'blocklist_file = "/e2e/producer/blocklist.json"'),
    );
    copyFileSync(join(ROOT, "blocklist.sample.json"), join(this.work, "producer", "blocklist.json"));
  }

  build() {
    this.compose(["build", "server", "firewall-1", ...CLIENTS, ...(this.nightly ? NIGHTLY_CLIENTS.filter((c) => c !== "client-bun") : [])]);
  }

  /// Brings the stack up from nothing and does the operator's one-time steps; leaves
  /// `this.operator` (signed in, with an authenticator) and `this.bootstrap`.
  async up({ build = true } = {}) {
    this.secretKey = randomBytes(32).toString("hex");
    mkdirSync(this.work, { recursive: true });
    this.compose(["down", "-v"], { check: false, quiet: true });
    this.writeFiles();
    if (build) this.build();
    configure({ bridgePort: this.bridgePort, caFile: join(this.work, "ca", "ca.pem") });

    this.start(...CORE, ...(this.canary ? [] : ["fakes"]));
    await waitFor("postgres", () => this.exec("postgres", ["pg_isready", "-U", "probation"]).status === 0);
    this.compose(["run", "--rm", "-T", "--no-deps", "server", "migrate"]);
    this.sql("CREATE ROLE probation_e2e LOGIN PASSWORD 'probation' IN ROLE probation_app");
    const bootstrap = this.compose([
      "run", "--rm", "-T", "--no-deps", "server", "admin", "bootstrap",
      "--config", "/etc/probation-server/config.toml",
      "--email", OPERATOR_EMAIL, "--org", "Operators",
      "--firewall", "firewall-1", "--firewall-source", "0.0.0.0/0", "--firewall-source", "::/0",
    ]).stdout;
    writeFileSync(join(this.work, "bootstrap.out"), bootstrap);
    this.bootstrap = Object.fromEntries(
      bootstrap.split(/\r?\n/).filter((line) => /^[a-z_]+=/.test(line)).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
    );
    expect(this.bootstrap.firewall_token, `admin bootstrap printed no firewall_token:\n${bootstrap}`);
    writeFileSync(join(this.work, "firewall-1.token"), `${this.bootstrap.firewall_token}\n`);
    this.start("server", "firewall-1", "firewall-standalone", ...CLIENTS, ...(this.nightly ? NIGHTLY_CLIENTS : []));
    await waitFor("the portal", async () => (await request("https://portal.e2e.test/signin")).status === 200, { timeout: 120_000 });
    await this.firewallReady("fw1");
    await this.firewallReady("fw-standalone");

    // The operator's global admin: the printed link sets its password; a global admin
    // acts only with an authenticator (C24). It registers firewall-2 on the fleet page.
    const operator = { email: OPERATOR_EMAIL, password: randomBytes(18).toString("base64url"), portal: new Portal() };
    const link = new URL(this.bootstrap.set_password_link);
    let page = await operator.portal.get(link.pathname + link.search);
    page = await operator.portal.post("/reset/confirm", {
      csrf: hidden(page.body, "csrf"),
      token: link.searchParams.get("token"),
      new: operator.password,
      again: operator.password,
    });
    expect(page.body.includes("Your password is changed"), `set-password link: ${page.status}\n${page.body}`);
    page = await operator.portal.submit("/signin", "/signin", { email: operator.email, password: operator.password });
    expect(page.status === 303 && page.location === "/account", `operator sign-in: ${page.status} ${page.location}`);
    operator.auth = await enableTotp(operator.portal);
    await signInWithCode(operator);
    this.operator = operator;

    page = await operator.portal.submit("/fleet", "/fleet/register", { name: "firewall-2", sources: "0.0.0.0/0 ::/0" });
    writeFileSync(join(this.work, "firewall-2.token"), `${between(page.body, '<code id="new-token">', "</code>")}\n`);
    this.start("firewall-2");
    await this.firewallReady("fw2");
  }

  async firewallReady(host, timeout = 6 * SYNC_INTERVAL * 1000) {
    await waitFor(`${host} ready`, async () => (await request(`https://${host}.e2e.test/health/ready`, { timeout: 5000 })).status === 200, { timeout });
  }

  down() {
    this.compose(["down", "-v"], { check: false, quiet: true });
  }

  /// Every service's log, the fakes' request log and the mail sink's index, into `dir`.
  async collect(dir) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "ps.txt"), this.compose(["ps", "-a"], { check: false, quiet: true }).stdout);
    for (const service of this.services) writeFileSync(join(dir, `${service}.log`), this.logs(service));
    for (const [name, url] of [
      ["fakes-requests.json", "http://fakes.e2e.test:8080/log"],
      ["mail.json", "http://mail.e2e.test:8025/api/v1/messages?limit=500"],
    ]) {
      try {
        writeFileSync(join(dir, name), (await request(url, { timeout: 5000 })).body);
      } catch (err) {
        writeFileSync(join(dir, name), String(err));
      }
    }
  }
}

/// Turns the authenticator on for a signed-in portal session; its Authenticator.
export async function enableTotp(portal) {
  const page = await portal.submit("/account", "/account/totp/setup", {});
  const auth = new Authenticator(between(page.body, '<code id="totp-key">', "</code>"));
  const on = await portal.post("/account/totp/enable", { code: await auth.code(), csrf: hidden(page.body, "csrf") });
  expect(on.status === 303, `authenticator: ${on.status}\n${on.body}`);
  return auth;
}

/// Signs `who` ({portal, email, password, auth}) out and in again with a code.
export async function signInWithCode(who) {
  await who.portal.submit("/account", "/signout", {});
  let page = await who.portal.submit("/signin", "/signin", { email: who.email, password: who.password });
  expect(page.location === "/totp", `${who.email} is asked for a code: ${page.status} ${page.location}`);
  page = await who.portal.submit("/totp", "/totp", { code: await who.auth.code() });
  expect(page.status === 303, `code for ${who.email}: ${page.status}\n${page.body}`);
}
