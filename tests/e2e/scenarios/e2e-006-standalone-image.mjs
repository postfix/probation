// E2E-006: the standalone firewall image (the MVP mode) with a producer-managed
// blocklist file (operations.md §2 "Firewall with Docker", §4 "Standalone: the
// blocklist file", §8 logs, §16 health).
//
// The image runs without [management], as `docker run` with a restart policy, a named
// data volume, the producer's directory bind-mounted read-only, a decision log file and
// a log collector over TLS whose credential comes from PROBATION_SIEM_AUTH. npm and pip
// install through it. The producer replaces blocklist.json atomically (write, rename):
//
// - a new block: within blocklist_poll_seconds the blocked version is refused and npm
//   and pip fall back to the version before it; the warm listing drops it;
// - a malformed file, and a file with a lower revision: refused, the last good one
//   stays in force, ready stays 200;
// - the block removed: the version is back in the warm listings and installs again;
// - a blocklist that expires while in force: /health/ready 503 and every request 503,
//   warm hits included; /health/live stays 200; a current file brings it back;
// - a restart with a malformed file on disk: the persisted snapshot is back in force.
//
// The decision log file is mode 0600 and rolls over to `.1`; the collector gets ndjson
// batches carrying the credential.

import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ops } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-006",
  title: "Standalone firewall image with a producer blocklist",
  suites: ["pr", "nightly", "release"],
};

const POLL = 2;
const SIEM_AUTH = "Bearer e2e-siem-credential";
const LOG = "/var/lib/probation/decisions.ndjson";

export default async function standalone(h) {
  const { expect } = h;
  const o = ops(h);
  const base = h.firewalls.standalone;
  const producer = join(h.stack.work, "e2e-006-producer");
  mkdirSync(producer, { recursive: true });
  const pkg = h.unique("sa");

  /// The producer's atomic replacement: a whole new file, renamed over the old one.
  const publish = (text) => {
    writeFileSync(join(producer, ".blocklist.json.tmp"), text, { mode: 0o644 });
    renameSync(join(producer, ".blocklist.json.tmp"), join(producer, "blocklist.json"));
    return Date.now();
  };
  const blocklist = (revision, blocked, { expiresIn = 365 * 86_400 } = {}) =>
    JSON.stringify({
      schema_version: 1,
      revision,
      generated_at: new Date(Date.now() - 60_000).toISOString().replace(/\.\d+Z$/, "Z"),
      expires_at: new Date(Date.now() + expiresIn * 1000).toISOString().replace(/\.\d+Z$/, "Z"),
      blocked_packages: blocked.map(([ecosystem, version]) => ({ ecosystem, name: pkg, version, reason: `e2e-006 ${ecosystem} ${version}` })),
      blocked_hashes: [],
    }, null, 2);

  const status = async (path) => (await h.request(base + path)).status;
  const npmrc = `registry=${base}/npm/\n`;
  const pipConf = `[global]\nindex-url = ${base}/pypi/simple/\n`;
  const npmVersion = (spec) => {
    const run = h.npm(`install ${spec} --no-audit --no-fund && node -p "require('${pkg}/package.json').version"`, { npmrc });
    expect(run.status === 0, `npm install ${spec}: ${run.status}\n${run.stdout}\n${run.stderr}`);
    return run.stdout.trim().split("\n").at(-1);
  };
  const pipVersion = (spec) => {
    const module = pkg.replaceAll("-", "_");
    const run = h.pip(`install --no-cache-dir --target ./t '${spec}' && PYTHONPATH=./t python -c 'import ${module}; print(${module}.VERSION)'`, { pipConf });
    expect(run.status === 0, `pip install ${spec}: ${run.status}\n${run.stdout}\n${run.stderr}`);
    return run.stdout.trim().split("\n").at(-1);
  };
  const listing = async () => (await h.request(`${base}/npm/${pkg}`)).json();
  const pypiListing = async () => (await h.request(`${base}/pypi/simple/${pkg}/`, { headers: { accept: "text/html" } })).body;

  try {
    for (const version of ["1.0.0", "1.1.0"]) {
      await h.fakes.publishNpm({ name: pkg, version, ageSeconds: 300 * 86_400 });
      await h.fakes.publishPypi({ name: pkg, version, ageSeconds: 300 * 86_400, kinds: ["wheel"] });
    }
    publish(blocklist(100, []));

    // The shipped sample config, as an operator edits it for this host.
    const sample = o.managedConfig("fw-standalone.e2e.test").split("\n[management]")[0].replace(/^sync_interval_seconds = .*$/m, "");
    const config = `${sample
      .replace(/^blocklist_file = .*$/m, 'blocklist_file = "/srv/producer/blocklist.json"')
      .replace(/^blocklist_poll_seconds = .*$/m, `blocklist_poll_seconds = ${POLL}`)}
log_file_path = "${LOG}"
log_file_max_bytes = 16384
siem_url = "https://fakes.e2e.test/siem"
`;
    h.stop("firewall-standalone");
    const fw = o.firewall({ name: "firewall-standalone", config, env: { PROBATION_SIEM_AUTH: SIEM_AUTH }, mounts: [[producer, "/srv/producer"]] });
    await h.firewallReady("fw-standalone");

    // npm and pip install through it, no key.
    expect(npmVersion(`${pkg}@^1.0.0`) === "1.1.0", "npm installs the newest version");
    expect(pipVersion(pkg) === "1.1.0", "pip installs the newest version");
    expect((await listing())["dist-tags"].latest === "1.1.0", "latest before the block");

    // A new block, by atomic rename: refused within the poll interval; installs fall back.
    const at = publish(blocklist(101, [["npm", "1.1.0"], ["pypi", "1.1.0"]]));
    await h.waitFor("the block is in force", async () => (await status(`/npm/${pkg}/1.1.0`)) === 403, { timeout: 3 * POLL * 1000, every: 200 });
    h.log(`block in force ${Date.now() - at} ms after the rename`);
    const blocked = await listing();
    expect(!blocked.versions["1.1.0"] && blocked["dist-tags"].latest === "1.0.0", `the warm listing drops 1.1.0: ${JSON.stringify(blocked["dist-tags"])} ${Object.keys(blocked.versions)}`);
    expect(!(await pypiListing()).includes("1.1.0"), "the PyPI listing drops 1.1.0");
    expect(npmVersion(`${pkg}@^1.0.0`) === "1.0.0", "npm falls back to 1.0.0");
    expect(pipVersion(pkg) === "1.0.0", "pip falls back to 1.0.0");

    // A malformed file, then a lower revision: refused; the last good one stays.
    const rejections = () => (fw.logs().match(/the blocklist candidate was rejected/g) ?? []).length;
    let before = rejections();
    publish("{ this is not a blocklist");
    await h.waitFor("the malformed file is refused and logged", () => rejections() > before, { timeout: 3 * POLL * 1000 });
    before = rejections();
    publish(blocklist(99, []));
    await h.waitFor("the lower revision is refused and logged", () => rejections() > before, { timeout: 3 * POLL * 1000 });
    expect((await h.request(`${base}/health/ready`)).status === 200, "ready stays 200 after refused files");
    expect((await status(`/npm/${pkg}/1.1.0`)) === 403, "the last good blocklist stays in force");

    // The block removed: the version is back in the warm listings.
    publish(blocklist(102, []));
    await h.waitFor("the unblock is in force", async () => (await status(`/npm/${pkg}/1.1.0`)) === 200, { timeout: 3 * POLL * 1000, every: 200 });
    const unblocked = await listing();
    expect(unblocked.versions["1.1.0"] && unblocked["dist-tags"].latest === "1.1.0", `1.1.0 is back in the warm listing: ${JSON.stringify(unblocked["dist-tags"])}`);
    expect((await pypiListing()).includes("1.1.0"), "1.1.0 is back in the PyPI listing");
    expect(npmVersion(`${pkg}@^1.0.0`) === "1.1.0", "npm installs 1.1.0 again");

    // A blocklist that expires while in force: fail closed, warm hits included.
    const tarball = new URL(unblocked.versions["1.1.0"].dist.tarball).pathname;
    expect((await status(tarball)) === 200, "the tarball is warm");
    publish(blocklist(103, [], { expiresIn: 20 }));
    const accepted = (revision) => fw.logs().split("\n").some((l) => l.includes("blocklist accepted") && l.includes(`"revision":${revision}`));
    await h.waitFor("revision 103 is in force", () => accepted(103), { timeout: 3 * POLL * 1000 });
    await h.waitFor("the blocklist expires: not ready", async () => (await h.request(`${base}/health/ready`)).status === 503, { timeout: 60_000, every: 1000 });
    for (const path of [`/npm/${pkg}`, `/npm/${pkg}/1.0.0`, tarball, `/pypi/simple/${pkg}/`]) {
      expect((await status(path)) === 503, `${path} answers 503 with an expired blocklist`);
    }
    expect((await h.request(`${base}/health/live`)).status === 200, "live stays 200");

    // A current file brings it back; a restart with a malformed file on disk uses the
    // persisted snapshot.
    publish(blocklist(104, [["npm", "1.0.0"]]));
    await h.waitFor("ready again", async () => (await h.request(`${base}/health/ready`)).status === 200, { timeout: 3 * POLL * 1000 + 5000 });
    expect((await status(`/npm/${pkg}/1.0.0`)) === 403, "revision 104 is in force");
    publish("[]");
    fw.stop();
    fw.start();
    await h.firewallReady("fw-standalone", 60_000);
    expect(/the persisted blocklist is still valid and is back in force/.test(fw.logs()), "the restart used the persisted snapshot");
    expect((await status(`/npm/${pkg}/1.0.0`)) === 403 && (await status(`/npm/${pkg}/1.1.0`)) === 200, "the persisted revision 104 is in force after the restart");

    // The decision log file and the collector.
    const stat = fw.exec("sh", "-c", `stat -c '%a %s' ${LOG} && ls ${LOG}.1 && tail -n 1 ${LOG}`);
    expect(stat.status === 0, `the log file and its rollover: ${stat.stdout}${stat.stderr}`);
    expect(stat.stdout.startsWith("600 "), `the log file is mode 0600: ${stat.stdout}`);
    const last = JSON.parse(stat.stdout.trim().split("\n").at(-1));
    expect(last.event === "request_decided" && last.blocklist_revision === 104, `ndjson decision records: ${stat.stdout}`);
    await h.waitFor("the collector got batches", async () => {
      const batches = await (await h.request("http://fakes.e2e.test:8080/siem/batches")).json();
      const records = batches.flatMap((b) => b.records);
      expect(batches.every((b) => b.auth === SIEM_AUTH && b.contentType === "application/x-ndjson"), `every batch carries the credential: ${JSON.stringify(batches.map((b) => [b.auth, b.contentType]))}`);
      return records.some((r) => r.event === "request_decided" && r.package?.includes(pkg) && r.status === 403 && r.result === "BLOCKED");
    }, { timeout: 30_000, every: 1000 });
  } finally {
    o.removeExtras();
    h.start("firewall-standalone");
    await h.firewallReady("fw-standalone");
  }
}
