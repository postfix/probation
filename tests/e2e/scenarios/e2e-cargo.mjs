// E2E-cargo Cargo through a managed firewall (row 18; docs/operations.md "Cargo clients").
//
// The fake crates.io (fixtures/fakes/cargo.mjs) answers as index.crates.io (config.json and the
// sparse index, `pubtime` on every line) and static.crates.io (real `.crate` archives). An
// organisation copies the Cargo lines from the keys page; Cargo 1.96 in the client container
// reads through firewall-1 (TLS via the gateway, the key as the registry token).
//
// 1. Under a 7-day platform freeze Cargo locks the old version of a crate whose newest is an
//    hour old, fetches and builds it; the exact pin of the young one fails; the young archive is
//    HELD (403) when asked for directly; the served index keeps every eligible line byte for byte
//    (a yanked line included).
// 2. The rewritten config.json names the firewall for `dl` and `api`, and a managed firewall
//    asks Cargo for its token: without one the answer is 401 with Cargo's challenge.
// 3. OSV on: a version flagged MAL under ecosystem `crates.io` is hidden from the index and Cargo
//    locks the other.
// 4. A crate published as `Cg_Mixed-...`: the index file lives at the lower-case path, the archive
//    only under the exact spelling; an organisation block written `cg-mixed-...` hides it.
// Activity shows the refusals; the firewall's decision log names them.

import { activityRow, changePlatform, fetchWith, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-cargo",
  title: "Cargo through a managed firewall (sparse index, verified archives, freeze, OSV, mixed case)",
  suites: ["pr", "nightly", "release"],
};

const DAY = 86_400;
const HOUR = 3_600;

/// The index path of a crate name, as the sparse layout builds it.
const indexPath = (name) => {
  const l = name.toLowerCase();
  if (l.length <= 2) return `${l.length}/${l}`;
  if (l.length === 3) return `3/${l[0]}/${l}`;
  return `${l.slice(0, 2)}/${l.slice(2, 4)}/${l}`;
};

export default async function cargo(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  const suffix = h.unique("c").slice(2);
  const fresh = `cg-fresh-${suffix}`;
  const yank = `cg-yank-${suffix}`;
  const malCrate = `cg-mal-${suffix}`;
  const mixed = `Cg_Mixed-${suffix}`;
  await h.fakes.publishCargo({ name: fresh, version: "1.0.0", ageSeconds: 300 * DAY });
  await h.fakes.publishCargo({ name: fresh, version: "2.0.0", ageSeconds: HOUR });
  await h.fakes.publishCargo({ name: yank, version: "1.0.0", ageSeconds: 300 * DAY, yanked: true });
  await h.fakes.publishCargo({ name: yank, version: "1.1.0", ageSeconds: 200 * DAY });
  for (const version of ["1.0.0", "1.1.0"]) await h.fakes.publishCargo({ name: malCrate, version, ageSeconds: 300 * DAY });
  await h.fakes.osvFlag({ ecosystem: "crates.io", name: malCrate, version: "1.0.0", ids: ["MAL-2026-9101"] });
  await h.fakes.publishCargo({ name: mixed, version: "1.0.0", ageSeconds: 300 * DAY });
  await h.fakes.publishCargo({ name: mixed, version: "1.1.0", ageSeconds: HOUR });

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key } = await h.createKey(admin.portal, "cargo-ci");
  const get = (path, headers = {}) => fetchWith(h, fw1, path, key, headers);
  const ok = (what, run) => expect(run.status === 0, `${what} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  const registry = "sparse+https://fw1.e2e.test/cargo/";
  const configToml = `[source.crates-io]\nreplace-with = "probation"\n\n[source.probation]\nregistry = "${registry}"\n\n[registries.probation]\nindex = "${registry}"\ncredential-provider = "cargo:token"\n`;
  const credentials = (token) => `mkdir -p $CARGO_HOME && printf '[registries.probation]\\ntoken = "${token}"\\n' > $CARGO_HOME/credentials.toml`;
  const manifest = (dependency) => `[package]\nname = "consumer"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n${dependency}\n`;
  const cargoRun = (script, dependency, { token = `Bearer ${key}` } = {}) =>
    h.client("client-cargo", `export CARGO_HOME=$PWD/.cargo-home CARGO_TERM_COLOR=never CARGO_NET_RETRY=0; ${token ? credentials(token) : "mkdir -p $CARGO_HOME"}; ${script}`, {
      files: { "Cargo.toml": manifest(dependency), "src/lib.rs": "", ".cargo/config.toml": configToml },
    });
  const since = new Date();

  // The keys page shows the Cargo lines next to npm, pip and RubyGems.
  const created = await admin.portal.submit("/keys", "/keys", { name: "cargo-page" });
  expect(created.body.includes('registry = "sparse+https://fw1.e2e.test/cargo/"') && created.body.includes('token = "Bearer prb_'), `the keys page shows the Cargo source and token: ${created.body.slice(0, 400)}`);

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: false } });
  try {
    await h.editPolicy(admin.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
    await h.waitFor("the freeze reaches firewall-1", async () => {
      const index = await get(`/cargo/${indexPath(fresh)}`);
      return index.status === 200 && index.body.includes('"vers":"1.0.0"') && !index.body.includes('"vers":"2.0.0"');
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });

    // 2. config.json: dl and api name the firewall; without a key the firewall asks Cargo for one.
    const config = await get("/cargo/config.json");
    expect(config.status === 200, `config.json: ${config.status} ${config.body}`);
    const rewritten = config.json();
    expect(rewritten.dl === "https://fw1.e2e.test/cargo/crates" && rewritten.api === "https://fw1.e2e.test/cargo" && rewritten["auth-required"] === true, `the rewritten config: ${config.body}`);
    expect(!config.body.includes("static.crates.io") && !config.body.includes("//crates.io"), "no upstream host in the rewritten config");
    const anonymous = await h.request(`${fw1}/cargo/config.json`, { headers: { connection: "close" } });
    const challenge = [anonymous.headers["www-authenticate"]].flat().join(" | ");
    expect(anonymous.status === 401 && challenge.includes("Cargo login_url="), `an unauthenticated read is 401 with Cargo's challenge: ${anonymous.status} ${challenge}`);
    let run = cargoRun("cargo generate-lockfile", `${fresh} = "*"`, { token: "" });
    expect(run.status !== 0 && /authentication|credential|token|401|login/i.test(run.stdout + run.stderr), `Cargo without a token is refused: ${run.status}\n${run.stdout}\n${run.stderr}`);

    // 1a. Cargo locks the old version, fetches and builds it; the exact pin of the young one fails.
    run = cargoRun("cargo generate-lockfile && cat Cargo.lock && cargo fetch --locked && cargo build --offline", `${fresh} = "*"`);
    ok("cargo build", run);
    expect(run.stdout.includes(`name = "${fresh}"\nversion = "1.0.0"`) && !run.stdout.includes("2.0.0"), `Cargo locks 1.0.0:\n${run.stdout}`);
    expect(run.stdout.includes("checksum = "), `Cargo verified the archive against the index checksum:\n${run.stdout}`);
    run = cargoRun("cargo generate-lockfile", `${fresh} = "=2.0.0"`);
    expect(run.status !== 0 && run.stderr.includes(fresh), `the exact pin of the young version fails: ${run.status}\n${run.stdout}\n${run.stderr}`);
    const held = await get(`/cargo/crates/${fresh}/2.0.0/download`);
    expect(held.status === 403, `the young archive is HELD (403): ${held.status} ${held.body.slice(0, 200)}`);
    const archive = await get(`/cargo/crates/${fresh}/1.0.0/download`);
    expect(archive.status === 200, `the eligible archive is delivered: ${archive.status}`);

    // 1b. Kept lines are upstream's text, byte for byte, a yanked line included.
    const upstream = (await h.fakes.cargoIndex(yank)).index;
    const served = await get(`/cargo/${indexPath(yank)}`);
    expect(served.status === 200 && served.body === upstream && upstream.includes('"yanked":true'), `the served index is upstream's file:\n${served.body}\n--\n${upstream}`);
    expect((await get(`/cargo/${indexPath(yank)}`, { "if-none-match": served.headers.etag })).status === 304, "a matching validator is a 304");

    // 3. OSV: the MAL version is hidden, Cargo locks the other.
    await h.waitFor("the MAL version leaves the index", async () => {
      const mal = await get(`/cargo/${indexPath(malCrate)}`);
      return mal.status === 200 && !mal.body.includes('"vers":"1.0.0"');
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    run = cargoRun("cargo generate-lockfile && cat Cargo.lock", `${malCrate} = "*"`);
    ok("cargo of the OSV crate", run);
    expect(run.stdout.includes(`name = "${malCrate}"\nversion = "1.1.0"`), `Cargo locks the unflagged version:\n${run.stdout}`);
    const queried = (await h.fakes.osvQueries()).some((q) => JSON.stringify(q).includes('"crates.io"') && JSON.stringify(q).includes(malCrate));
    expect(queried, "the firewall asked OSV about the crate under the ecosystem name crates.io");

    // 4. Mixed case: the index file is at the lower-case path, the archive only under the exact name.
    const lowerPath = `/cargo/${indexPath(mixed)}`;
    const idx = await get(lowerPath);
    expect(idx.status === 200 && idx.body.includes(`"name":"${mixed}"`) && idx.body.includes('"vers":"1.0.0"') && !idx.body.includes('"vers":"1.1.0"'), `the index lists the old version under its own spelling:\n${idx.body}`);
    expect((await get(`/cargo/${indexPath(mixed).replace(/[^/]+$/, (n) => n.toUpperCase())}`)).status === 404, "an upper-case index path is no index file");
    const exact = await get(`/cargo/crates/${mixed}/1.0.0/download`);
    expect(exact.status === 200, `the exact-spelling archive is delivered: ${exact.status} ${exact.body.slice(0, 120)}`);
    const wrongCase = await get(`/cargo/crates/${mixed.toLowerCase()}/1.0.0/download`);
    expect(wrongCase.status === 404, `another spelling of the file name is no crate of this index: ${wrongCase.status}`);
    const policy = await h.policyPath(admin.portal);
    const folded = mixed.toLowerCase().replaceAll("_", "-");
    const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "cargo", name: folded, what: "package", version: "" });
    expect(saved.status === 303, `the block is saved: ${saved.status}\n${saved.body}`);
    await h.waitFor("the block hides the crate", async () => {
      const blocked = await get(lowerPath);
      return blocked.status === 200 && blocked.body === "";
    }, { timeout: 4 * h.syncInterval * 1000, every: 1000 });
    expect((await get(`/cargo/crates/${mixed}/1.0.0/download`)).status === 403, "and its archive is refused");

    // The decision log names the refusals: the young archive of the fresh crate (403) and the blocked mixed-case one.
    const dated = h.decisions("firewall-1", since).filter((d) => d.ecosystem === "cargo");
    expect(dated.some((d) => d.package === fresh && d.version === "2.0.0" && String(d.status) === "403"), `a logged decision names the held ${fresh} 2.0.0: ${JSON.stringify(dated.slice(-6))}`);
    expect(dated.some((d) => d.package === mixed && d.version === "1.0.0" && String(d.status) === "403"), `a logged decision names the blocked ${mixed} 1.0.0`);

    // A managed (non-service) firewall has no registry-API routes: publish, yank, owners and search are
    // answered locally with exactly 404, with or without a key, and nothing reaches the registry (the
    // shared service forwards them: E2E-publishing-cargo-service).
    const writesBefore = (await h.fakes.cargoWrites()).length;
    for (const [method, path] of [["PUT", "/cargo/api/v1/crates/new"], ["DELETE", `/cargo/api/v1/crates/${fresh}/1.0.0/yank`], ["PUT", `/cargo/api/v1/crates/${fresh}/owners`], ["GET", "/cargo/api/v1/crates"]]) {
      for (const headers of [{ connection: "close" }, { connection: "close", authorization: `Bearer ${key}` }]) {
        const answer = await h.request(`${fw1}${path}`, { method, body: method === "GET" ? undefined : "x", headers });
        expect(answer.status === 404, `${method} ${path} (${headers.authorization ? "with" : "without"} a key) is not a route of a managed firewall: ${answer.status}`);
      }
    }
    expect((await h.fakes.cargoWrites()).length === writesBefore, "no registry-API call reached the fake registry");
    await activityRow(h, admin.portal, { package: folded });
  } finally {
    await restorePlatform();
  }
}
