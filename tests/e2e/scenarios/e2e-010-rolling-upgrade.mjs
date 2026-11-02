// E2E-010: a rolling upgrade from the previous release's images to the ones under test,
// with mixed versions on the way (operations.md §5 "Upgrading the firewall",
// "Upgrading the management server", "Mixed versions").
//
// The previous release: E2E_PREV_FIREWALL_IMAGE (and E2E_PREV_SERVER_IMAGE) when given
// (for example the ghcr.io images release.yml publishes, D7); otherwise the images are
// built from E2E_PREV_REF, by default the newest release tag before HEAD (needs the
// tags: `git fetch --tags`). E2E_BUILD_CPUSET (for example 0-15) pins that build.
//
// Always, on one firewall volume:
// - the previous image runs standalone with a producer blocklist and is filled: an
//   install (a pinned file), a version held by the release-age freeze, a PyPI file with
//   no upload time (its first-seen time), blocklist revision 300;
// - the new image starts on that volume with revision 299 already in the producer's
//   file: the persisted 300 still rules, the install is served, the hold stays, and
//   the old registry-ambiguous package references are invalidated and rebuilt;
// - the same volume goes managed (registered on /fleet): it serves the operator's key;
// - rolled back to the previous image with the managed config, it refuses cleanly (exit
//   non-zero, says why, no restart loop), and the new image starts again on the volume.
// When the previous release has a management server (the first release after 0.2.2
// has), also: the previous server and firewalls are deployed and filled (orgs, keys,
// layers, activity, a rollout and its overlay, the firewalls' snapshots); the new
// `migrate` runs and the server image is swapped while the old firewalls sync; one
// firewall is upgraded on its volume; sync, reports, activity, pushes and propagation
// work across the versions; with the server stopped the upgraded firewall restarts from
// its snapshot (F6); rolled back to the previous image it either serves correctly or
// refuses cleanly, and its volume still starts the new image.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ops } from "../harness/ops.mjs";
import { ROOT, enableTotp, signInWithCode } from "../harness/stack.mjs";

export const meta = {
  id: "E2E-010",
  title: "Rolling upgrade with mixed versions",
  suites: ["nightly", "release"],
  stack: "own",
};

const CONFIG = "/etc/probation-server/config.toml";

export default async function rollingUpgrade(h) {
  const o = ops(h);
  const prev = previousRelease(h, o);
  h.log(`previous release ${prev.ref}: firewall ${prev.firewall} (${prev.version}), server ${prev.server ?? "none"}; under test ${o.image}, ${o.serverImage}`);
  const serverImage = process.env.E2E_SERVER_IMAGE;
  try {
    await standaloneUpgrade(h, o, prev);
    if (prev.server) await managedUpgrade(h, o, prev);
    else h.log(`${prev.ref} has no management server (managed mode is new after 0.2.2): the mixed managed versions are checked from the first release that has one`);
  } finally {
    if (serverImage === undefined) delete process.env.E2E_SERVER_IMAGE;
    else process.env.E2E_SERVER_IMAGE = serverImage;
    o.removeExtras();
  }
}

/// {ref, firewall, server, version}: the previous release's images, given or built.
function previousRelease(h, o) {
  const version = (image) => o.engine(["run", "--rm", "--entrypoint", "probation", image, "--version"]).stdout.trim();
  if (process.env.E2E_PREV_FIREWALL_IMAGE) {
    const firewall = process.env.E2E_PREV_FIREWALL_IMAGE;
    return { ref: process.env.E2E_PREV_REF ?? firewall, firewall, server: process.env.E2E_PREV_SERVER_IMAGE ?? null, version: version(firewall) };
  }
  const git = (...args) => spawnSync("git", ["-C", ROOT, ...args], { encoding: "utf8" });
  let ref = process.env.E2E_PREV_REF;
  if (!ref) {
    const head = git("rev-parse", "HEAD").stdout.trim();
    ref = git("tag", "--merged", "HEAD", "--sort=-v:refname", "--list", "v*").stdout.split("\n").filter(Boolean)
      .find((tag) => git("rev-parse", `${tag}^{commit}`).stdout.trim() !== head);
  }
  h.expect(ref, "no previous release tag: fetch the tags (git fetch --tags) or set E2E_PREV_REF or E2E_PREV_FIREWALL_IMAGE");
  const dir = join(h.stack.work, "prev", ref.replace(/[^\w.-]/g, "_"));
  const tag = (name) => `localhost/${name}:prev-${ref.replace(/[^\w.-]/g, "_")}`;
  const build = (image, args) => {
    if (o.engine(["image", "exists", image], { check: false }).status === 0 || o.engine(["image", "inspect", image], { check: false }).status === 0) return;
    if (!existsSync(join(dir, "Cargo.toml"))) {
      mkdirSync(dir, { recursive: true });
      const archive = spawnSync("sh", ["-c", `git -C '${ROOT}' archive '${ref}' | tar -x -C '${dir}'`], { encoding: "utf8" });
      h.expect(archive.status === 0, `git archive ${ref}: ${archive.stderr}`);
    }
    const cpus = process.env.E2E_BUILD_CPUSET;
    const argv = [...(cpus ? ["taskset", "-c", cpus] : []), h.stack.engine, "build", "-t", image, ...args, dir];
    h.log(`building ${image} from ${ref}`);
    const built = spawnSync(argv[0], argv.slice(1), { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
    h.expect(built.status === 0, `building ${image}: ${built.stderr.slice(-3000)}`);
  };
  build(tag("probation"), []);
  const hasServer = git("cat-file", "-e", `${ref}:crates/probation-server/Dockerfile`).status === 0;
  if (hasServer) build(tag("probation-server"), ["-f", join(dir, "crates/probation-server/Dockerfile")]);
  return { ref, firewall: tag("probation"), server: hasServer ? tag("probation-server") : null, version: version(tag("probation")) };
}

/// The stopped firewall volume's persisted state: the blocklist revision and the
/// references of `pkg` ({filename, first_seen, pinned}), read with Python's sqlite3 in a
/// throwaway container of the pip client image.
function volumeState(o, volume, pkg) {
  const script = `
import json, sqlite3, sys
db = sqlite3.connect("/v/state/firewall.db")
revision = db.execute("SELECT revision FROM blocklist").fetchone()
rows = db.execute("SELECT filename, first_seen_micros, hex(pinned_sha512) FROM artifact_references WHERE name = ?", (sys.argv[1],)).fetchall()
print(json.dumps({"revision": revision and revision[0], "references": [{"filename": f, "first_seen": s, "pinned": p or None} for f, s, p in rows]}))
`;
  const run = o.engine(["run", "--rm", "-v", `${volume}:/v`, "--user", "0", "localhost/probation-e2e-client:pip26.2", "python3", "-c", script, pkg]);
  return JSON.parse(run.stdout.trim());
}

async function standaloneUpgrade(h, o, prev) {
  const { expect } = h;
  const base = h.firewalls.standalone;
  const volume = `${h.stack.project}-e2e010-standalone`;
  const pkg = h.unique("up");
  const producer = join(h.stack.work, "e2e-010-producer");
  mkdirSync(producer, { recursive: true });
  const publish = (revision, blocked = []) => {
    const text = JSON.stringify({
      schema_version: 1, revision,
      generated_at: new Date(Date.now() - 60_000).toISOString().replace(/\.\d+Z$/, "Z"),
      expires_at: "2099-01-01T00:00:00Z",
      blocked_packages: blocked.map((version) => ({ ecosystem: "npm", name: pkg, version, reason: "e2e-010" })),
      blocked_hashes: [],
    });
    writeFileSync(join(producer, ".tmp"), text, { mode: 0o644 });
    renameSync(join(producer, ".tmp"), join(producer, "blocklist.json"));
  };
  const npmrc = `registry=${base}/npm/\n`;
  const install = () => h.npm(`install ${pkg}@1.0.0 --no-audit --no-fund`, { npmrc });
  const held = async () => h.request(`${base}/npm/${pkg}/1.1.0`);

  await h.fakes.publishNpm({ name: pkg, version: "1.0.0", ageSeconds: 300 * 86_400 });
  await h.fakes.publishNpm({ name: pkg, version: "1.1.0", ageSeconds: 3600, tag: null });
  // A PyPI file with no upload time: the firewall records when it first saw it.
  await h.fakes.publishPypi({ name: pkg, version: "1.0.0", untimed: true, kinds: ["wheel"] });
  publish(300);
  // The previous image's own shipped config, edited for this host.
  const shipped = o.engine(["run", "--rm", "--entrypoint", "cat", prev.firewall, "/etc/probation/config.toml"]).stdout;
  const config = shipped
    .replace(/^listen = .*$/m, 'listen = "0.0.0.0:8080"\ntls_cert_path = "/e2e/tls/cert.pem"\ntls_key_path = "/e2e/tls/key.pem"')
    .replace(/^public_url = .*$/m, 'public_url = "https://fw-standalone.e2e.test"')
    .replace(/^blocklist_file = .*$/m, 'blocklist_file = "/srv/producer/blocklist.json"')
    .replace(/^blocklist_poll_seconds = .*$/m, "blocklist_poll_seconds = 2");
  const mounts = [[producer, "/srv/producer"]];

  h.stop("firewall-standalone");
  try {
    // 1. The previous release, filled.
    h.log("standalone 1: the previous release, filled");
    let fw = o.firewall({ name: "firewall-standalone", image: prev.firewall, config, mounts, volume });
    await h.firewallReady("fw-standalone", 60_000);
    let run = install();
    expect(run.status === 0, `install through ${prev.version}: ${run.stderr}`);
    const listed = await h.request(`${base}/pypi/simple/${pkg}/`);
    expect(listed.status === 200, `the PyPI listing through ${prev.version}: ${listed.status}`);
    let answer = await held();
    const before = Number(answer.headers["retry-after"]);
    expect(answer.status === 403 && before > 0, `1.1.0 is held by the freeze: ${answer.status} ${answer.headers["retry-after"]}`);

    // 2. The new image on the same volume. What the previous release persisted is read
    //    from the stopped volume first: the blocklist revision and old references.
    h.log("standalone 2: the new image on the same volume");
    fw.stop();
    fw.rm();
    const persisted = volumeState(o, volume, pkg);
    expect(persisted.revision === 300, `the previous release persisted revision 300: ${JSON.stringify(persisted)}`);
    expect(persisted.references.some((r) => r.filename === `${pkg}-1.0.0.tgz` && r.pinned), `the previous release persisted the installed file's pin: ${JSON.stringify(persisted)}`);
    expect(persisted.references.some((r) => r.filename.endsWith(".whl") && r.first_seen), `the previous release persisted the untimed wheel's first-seen time: ${JSON.stringify(persisted)}`);
    // A lower revision waits in the producer's file before the new image starts: only
    // the persisted revision 300 keeps it out.
    publish(299, ["1.0.0"]);
    fw = o.firewall({ name: "firewall-standalone", config, mounts, volume });
    await h.firewallReady("fw-standalone", 60_000);
    expect(!/will not open|refused and left untouched/i.test(fw.logs()), `the new release opens the previous database:\n${fw.logs().slice(-2000)}`);
    await h.waitFor("the lower revision is refused", () => /the blocklist candidate was rejected/.test(fw.logs()), { timeout: 10_000 });
    expect((await h.request(`${base}/npm/${pkg}/1.0.0`)).status === 200, "the persisted revision 300 still rules over the file's 299");
    run = install();
    expect(run.status === 0, `the install after the upgrade: ${run.stderr}`);
    answer = await held();
    const after = Number(answer.headers["retry-after"]);
    expect(answer.status === 403 && after <= before, `the published release remains held: Retry-After ${before} before, ${answer.status} ${after} after`);
    // The schema upgrade invalidates references without registry identity.
    fw.stop();
    const kept = volumeState(o, volume, pkg);
    fw.start();
    await h.firewallReady("fw-standalone", 60_000);
    expect(kept.revision === 300, `revision 300 is still the persisted one: ${JSON.stringify(kept)}`);
    expect(!kept.references.some((r) => r.filename.endsWith(".whl")), `the ambiguous PyPI reference was invalidated: ${JSON.stringify(kept.references)}`);
    expect(kept.references.some((r) => r.filename.endsWith(".tgz") && r.pinned), `the npm install repinned its reference: ${JSON.stringify(kept.references)}`);
    answer = await h.request(`${base}/pypi/simple/${pkg}/`);
    expect(answer.status === 200, `the PyPI listing can be rebuilt: ${answer.status}`);

    // 3. The same volume goes managed.
    h.log("standalone 3: the same volume goes managed");
    const fleet = await o.fleet(h.operator.portal);
    answer = await h.operator.portal.post("/fleet/register", { csrf: fleet.csrf, name: "firewall-upgraded", sources: "0.0.0.0/0" });
    const token = answer.body.match(/<code id="new-token">([^<]+)<\/code>/)?.[1];
    expect(token, `register firewall-upgraded: ${answer.status}`);
    const managed = o.managedConfig("fw-standalone.e2e.test")
      .replace(/^listen = .*$/m, 'listen = "0.0.0.0:8080"\ntls_cert_path = "/e2e/tls/cert.pem"\ntls_key_path = "/e2e/tls/key.pem"');
    fw.stop();
    fw.rm();
    fw = o.firewall({ name: "firewall-standalone", config: managed, token, volume });
    await h.firewallReady("fw-standalone", 60_000);
    const keyed = h.npm(`install ${pkg}@1.0.0 --no-audit --no-fund`, { npmrc: `${npmrc}//fw-standalone.e2e.test/npm/:_authToken=${h.bootstrap.key}\n` });
    expect(keyed.status === 0, `the managed firewall serves the operator's key: ${keyed.stderr}`);
    expect((await h.request(`${base}/npm/${pkg}`)).status === 401, "managed: no key, no package");

    // 4. Rolled back to the previous image with the managed config: a clean refusal.
    h.log("standalone 4: rolled back with the managed config");
    fw.stop();
    fw.rm();
    const old = o.firewall({ name: "firewall-standalone", image: prev.firewall, config: managed, token, volume, restart: "no" });
    if (!prev.server) {
      // A release without managed mode refuses a later config key cleanly.
      await h.waitFor("the previous release stops", () => !old.state().running, { timeout: 30_000 });
      const refusal = old.logs();
      expect(old.state().exitCode !== 0 && /invalid configuration.*unknown key/.test(refusal), `the previous release refuses the managed config, saying why: exit ${old.state().exitCode}\n${refusal.slice(-1500)}`);
    } else {
      await rolledBack(h, old, base, h.bootstrap.key, `/npm/${pkg}/1.0.0`);
    }
    old.rm();
    fw = o.firewall({ name: "firewall-standalone", config: managed, token, volume });
    await h.firewallReady("fw-standalone", 60_000);
    expect(h.npm(`install ${pkg}@1.0.0 --no-audit --no-fund`, { npmrc: `${npmrc}//fw-standalone.e2e.test/npm/:_authToken=${h.bootstrap.key}\n` }).status === 0, "the volume still serves under the new release");
    fw.rm();
  } finally {
    h.start("firewall-standalone");
  }
}

async function managedUpgrade(h, o, prev) {
  const { expect } = h;
  const interval = h.syncInterval * 1000;
  const status = async (base, path, key) => (await h.request(base + path, { headers: { authorization: `Bearer ${key}` }, timeout: 15_000 })).status;
  const portalUp = () => h.waitFor("the portal", async () => (await h.request(`${h.portalUrl}/signin`)).status === 200, { timeout: 120_000 });
  const swapServer = (image) => {
    process.env.E2E_SERVER_IMAGE = image;
    h.stack.compose(["up", "-d", "--no-deps", "--force-recreate", "server"]);
  };

  // 1. The previous release deployed on a fresh database, as its operator did.
  h.log("managed 1. The previous release deployed on a fresh database, as its operator did");
  h.stop("server", "firewall-1", "firewall-2");
  o.freshDatabase();
  process.env.E2E_SERVER_IMAGE = prev.server;
  let run = o.server(["migrate"]);
  expect(run.status === 0, `the previous migrate: ${run.stderr}`);
  h.stack.sql("CREATE ROLE probation_e2e LOGIN PASSWORD 'probation' IN ROLE probation_app");
  run = o.server(["admin", "bootstrap", "--config", CONFIG, "--email", h.operatorEmail, "--org", "Operators",
    "--firewall", "firewall-1", "--firewall-source", "0.0.0.0/0"]);
  expect(run.status === 0, `the previous bootstrap: ${run.stderr}`);
  const printed = o.printed(run.stdout);
  swapServer(prev.server);
  await portalUp();
  const operator = { email: h.operatorEmail, password: `${h.unique("Pw")}-${h.unique("x")}`, portal: new h.Portal() };
  const link = new URL(printed.set_password_link);
  let page = await operator.portal.get(link.pathname + link.search);
  page = await operator.portal.post("/reset/confirm", { csrf: h.hidden(page.body, "csrf"), token: link.searchParams.get("token"), new: operator.password, again: operator.password });
  expect(page.body.includes("Your password is changed"), `set password on the previous portal: ${page.status}`);
  await operator.portal.submit("/signin", "/signin", { email: operator.email, password: operator.password });
  operator.auth = await enableTotp(operator.portal);
  await signInWithCode(operator);
  page = await operator.portal.submit("/fleet", "/fleet/register", { name: "firewall-2", sources: "0.0.0.0/0" });
  const token2 = page.body.match(/<code id="new-token">([^<]+)<\/code>/)?.[1];
  expect(token2, `register firewall-2 on the previous portal: ${page.status}`);
  const config = (name) => readFileSync(join(h.stack.work, `${name}.toml`), "utf8");
  const volumes = { "firewall-1": `${h.stack.project}-e2e010-fw1`, "firewall-2": `${h.stack.project}-e2e010-fw2` };
  const tokens = { "firewall-1": printed.firewall_token, "firewall-2": token2 };
  const start = (name, image, extra = {}) => o.firewall({ name, image, config: config(name), token: tokens[name], volume: volumes[name], ...extra });
  let fw1 = start("firewall-1", prev.firewall);
  const fw2 = start("firewall-2", prev.firewall);
  await h.firewallReady("fw1");
  await h.firewallReady("fw2");

  // 2. Filled under the previous release.
  h.log("managed 2. Filled under the previous release");
  const user = await h.signUp({ kind: "org" });
  await h.enableTotp(user);
  const policy = await h.policyPath(user.portal);
  const known = await h.createKey(user.portal, "known");
  const doomed = await h.createKey(user.portal, "doomed");
  for (const base of [h.firewalls.fw1, h.firewalls.fw2]) {
    for (const key of [known.key, doomed.key]) expect((await status(base, "/npm/e2e-left", key)) === 200, `warm-up on ${base}`);
  }
  await h.editPolicy(user.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "2.0.0" }, policy);
  await h.waitFor("the block reaches both", async () => (await status(h.firewalls.fw1, "/npm/e2e-left/2.0.0", known.key)) === 403 && (await status(h.firewalls.fw2, "/npm/e2e-left/2.0.0", known.key)) === 403, { timeout: 3 * interval });
  let answer = await o.push(operator.portal, ["firewall-1"], "max_active_requests = 64\n");
  expect(answer.status === 303, `push on the previous release: ${answer.status}`);
  await h.waitFor("the previous rollout is done", async () => (await o.fleet(operator.portal)).rollouts[0]?.state === "Done", { timeout: 6 * interval, every: 1000 });
  await h.firewallReady("fw1");

  // 3. The new migrate, then the new server, while the old firewalls sync.
  h.log("managed 3. The new migrate, then the new server, while the old firewalls sync");
  h.stop("server");
  process.env.E2E_SERVER_IMAGE = o.serverImage;
  run = o.server(["migrate"]);
  expect(run.status === 0, `the new migrate on the previous database: ${run.status}\n${run.stdout}\n${run.stderr}`);
  swapServer(o.serverImage);
  await portalUp();
  await h.editPolicy(user.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "1.1.0" }, policy);
  const ids = (await user.portal.get("/keys")).body.match(/<td>doomed<\/td>[\s\S]*?action="\/keys\/(\d+)\/revoke"/);
  answer = await user.portal.submit("/keys", `/keys/${ids[1]}/revoke`, {});
  expect(answer.status === 303, `revoke on the new server: ${answer.status}`);
  for (const base of [h.firewalls.fw1, h.firewalls.fw2]) {
    await h.waitFor(`the new server's changes reach the old firewall ${base}`, async () => (await status(base, "/npm/e2e-left/1.1.0", known.key)) === 403 && (await status(base, "/npm/e2e-left", doomed.key)) === 401, { timeout: 3 * interval });
  }
  await h.waitFor("an old firewall's activity reaches the new server", async () => (await h.activity(user.portal)).some((r) => /Blocked/.test(r.result) && r.package.includes("e2e-left")), { timeout: 3 * interval });
  await h.waitFor("both old firewalls report to the new server", async () => (await o.fleet(operator.portal)).firewalls.filter((f) => /^firewall-[12]$/.test(f.name)).every((f) => f.health === "Healthy" && f.version !== "not reported yet"), { timeout: 4 * interval, every: 2000 });

  // 4. firewall-1 upgraded on its volume; mixed versions.
  h.log("managed 4. firewall-1 upgraded on its volume; mixed versions");
  fw1.stop();
  fw1.rm();
  fw1 = start("firewall-1", o.image);
  await h.firewallReady("fw1");
  expect((await status(h.firewalls.fw1, "/npm/e2e-left/1.0.0", known.key)) === 200, "the upgraded firewall serves the known key");
  expect(/max_active_requests = 64/.test(fw1.exec("cat", "/var/lib/probation/managed-settings.toml").stdout), "the upgraded firewall keeps the previous overlay");
  const versions = (await o.fleet(operator.portal)).firewalls.filter((f) => /^firewall-[12]$/.test(f.name)).map((f) => `${f.name} ${f.version}`);
  h.log(`fleet versions: ${versions.join(", ")}`);
  answer = await o.push(operator.portal, ["firewall-1", "firewall-2"], "max_active_requests = 96\n");
  expect(answer.status === 303, `push to mixed versions: ${answer.status}`);
  await h.waitFor("the mixed-version rollout is done", async () => (await o.fleet(operator.portal)).rollouts[0]?.state === "Done", { timeout: 8 * interval, every: 1000 });
  for (const fw of [fw1, fw2]) expect(/max_active_requests = 96/.test(fw.exec("cat", "/var/lib/probation/managed-settings.toml").stdout), `${fw.name}'s overlay`);
  await h.firewallReady("fw1");
  await h.firewallReady("fw2");
  await h.editPolicy(user.portal, { action: "add_block", ecosystem: "npm", name: "e2e-right", what: "package" }, policy);
  await h.waitFor("propagation to both versions", async () => (await status(h.firewalls.fw1, "/npm/e2e-right", known.key)) === 403 && (await status(h.firewalls.fw2, "/npm/e2e-right", known.key)) === 403, { timeout: 3 * interval });

  // 5. Server stopped: the upgraded firewall restarts from its snapshot (F6).
  h.log("managed 5. Server stopped: the upgraded firewall restarts from its snapshot (F6)");
  h.stop("server");
  fw1.stop(45);
  fw1.start();
  await h.firewallReady("fw1", 60_000);
  expect((await status(h.firewalls.fw1, "/npm/e2e-left/1.0.0", known.key)) === 200, "the upgraded firewall serves from its snapshot with the server down");
  h.start("server");
  await portalUp();

  // 6. firewall-1 rolled back to the previous image on the upgraded volume.
  h.log("managed 6. firewall-1 rolled back to the previous image on the upgraded volume");
  fw1.stop();
  fw1.rm();
  const back = start("firewall-1", prev.firewall, { restart: "no" });
  if ((await rolledBack(h, back, h.firewalls.fw1, known.key, "/npm/e2e-left/1.0.0")) === "serves") {
    expect((await status(h.firewalls.fw1, "/npm/e2e-left/1.1.0", known.key)) === 403, "the rolled-back firewall enforces the policy");
  }
  back.rm();
  fw1 = start("firewall-1", o.image);
  await h.firewallReady("fw1");
  expect((await status(h.firewalls.fw1, "/npm/e2e-left/1.0.0", known.key)) === 200, "the volume still serves under the new release");
}

/// A previous release started on an upgraded volume either serves `path` with `key`, or
/// stops with a non-zero exit and a log saying why; never a restart loop or a broken
/// half-start. Answers "serves" or "stopped".
async function rolledBack(h, fw, base, key, path) {
  let outcome;
  await h.waitFor("the previous image either serves or stops", async () => {
    if (!fw.state().running) return (outcome = "stopped");
    const got = await h.request(base + path, { headers: { authorization: `Bearer ${key}` }, timeout: 5000 }).then((r) => r.status, () => 0);
    return got === 200 && (outcome = "serves");
  }, { timeout: 60_000, every: 1000 });
  h.log(`rolled back: the previous image ${outcome}`);
  if (outcome === "stopped") h.expect(fw.state().exitCode !== 0 && fw.logs().trim().length > 0, `a clean refusal says why: ${fw.logs().slice(-1500)}`);
  return outcome;
}
