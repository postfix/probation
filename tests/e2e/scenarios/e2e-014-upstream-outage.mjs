// E2E-014 Upstream registry outage and recovery (docs/plans/e2e-coverage/00-inventory.md
// §3; docs/operations.md §3a, §9, §16; SPEC §10-11: 5 s connect, 30 s metadata, 30 s
// artifact read).
//
// firewall-1 keeps the shipped metadata TTL (300 s). The operator edits firewall-2's
// config.toml to metadata_ttl_seconds = 5 and metadata_max_age_seconds = 60 and
// restarts it.
//
// 1. Warm npm and PyPI on firewall-1, then the registries refuse connections: the warm
//    package still installs (metadata fresh, file cached); a cold one answers 502
//    UPSTREAM_FAILURE at once, npm and pip fail with it; the fleet page shows firewall-1
//    cannot reach npm and PyPI.
// 2. 5xx and 429 from the registry: 502. A registry that never answers: 504
//    UPSTREAM_TIMEOUT at about 30 s, and npm gives up then too (no CI hang). A body that
//    stalls mid-way: 504 for metadata, npm tarballs and PyPI files.
// 3. Recovery without a restart: cold installs work, the fleet page shows Healthy.
// 4. firewall-2: past the 5 s TTL a refused revalidation is a refusal (no stale serving)
//    while firewall-1 still serves. With the origin down but revalidations still
//    answered 304, 20 warm packages keep being served until the 60 s age ceiling, then
//    are refused a few at a time (the ceiling is spread over its last tenth), not all at
//    once; they come back when the origin does.
//
// Own stack: it edits firewall-2's config.

import { editConfig, errorOf, fleetHealth, startedAt } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-014",
  title: "Upstream registry outage and recovery",
  suites: ["nightly", "release"],
  stack: "own",
};

const OLD = 400 * 86_400;
const REGISTRIES = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"];
const MAX_AGE = 60;
const AGED = 20;

export default async function upstreamOutage(h) {
  const { expect } = h;
  const interval = h.syncInterval;
  const show = (run) => `exit ${run.status}\n${run.stdout}\n${run.stderr}`;
  const all = (fault) => REGISTRIES.map((host) => ({ host, ...fault }));

  editConfig(h.stack, "firewall-2", (text) =>
    text
      .replace(/^metadata_ttl_seconds = .*$/m, "metadata_ttl_seconds = 5")
      .replace(/^metadata_max_age_seconds = .*$/m, `metadata_max_age_seconds = ${MAX_AGE}`),
  );
  h.restart("firewall-2");
  await h.firewallReady("fw2");

  const names = {};
  for (const what of ["warm", "reset", "s503", "s429", "hang", "hang-npm", "stall", "art", "ttl"]) {
    names[what] = h.unique(what);
    await h.fakes.publishNpm({ name: names[what], version: "1.0.0", ageSeconds: OLD });
    await h.fakes.publishPypi({ name: names[what], version: "1.0.0", ageSeconds: OLD, kinds: ["wheel"] });
  }
  const aged = [];
  for (let n = 0; n < AGED; n++) {
    aged.push(h.unique(`aged${n}`));
    await h.fakes.publishNpm({ name: aged[n], version: "1.0.0", ageSeconds: OLD });
  }

  const org = await h.signUp({ kind: "org" });
  const keys = await h.createKey(org.portal, "ci");
  const bearer = { headers: { authorization: `Bearer ${keys.key}` }, timeout: 90_000 };
  const npm = (spec, extra = "") => h.npm(`install ${spec} --no-audit --no-fund --fetch-retries=0 --cache "$PWD/.npm-cache" ${extra}`, { npmrc: keys.npmrc });
  const pip = (spec) => h.pip(`install --no-cache-dir --retries 0 ${spec}`, { pipConf: keys.pipConf });
  const get = async (url) => {
    const started = performance.now();
    const answer = await h.request(url, bearer);
    return { status: answer.status, error: errorOf(answer).error, seconds: (performance.now() - started) / 1000, answer };
  };
  const npmDoc = (fw, name) => get(`${h.firewalls[fw]}/npm/${name}`);
  const simple = (fw, name) => get(`${h.firewalls[fw]}/pypi/simple/${name}/`);
  const fw1Started = startedAt(h.stack, "firewall-1");

  // 1. Warm, then the registries refuse connections.
  let run = npm(`${names.warm}@1.0.0`);
  expect(run.status === 0, `warm npm: ${show(run)}`);
  run = pip(`${names.warm}==1.0.0`);
  expect(run.status === 0, `warm pip: ${show(run)}`);
  await h.fakes.faults(all({ mode: "reset" }));
  run = npm(`${names.warm}@1.0.0`);
  expect(run.status === 0, `registries down: the warm package still installs with npm: ${show(run)}`);
  run = pip(`${names.warm}==1.0.0`);
  expect(run.status === 0, `registries down: the warm package still installs with pip: ${show(run)}`);
  for (const probe of [npmDoc("fw1", names.reset), simple("fw1", names.reset)]) {
    const got = await probe;
    expect(got.status === 502 && got.error === "UPSTREAM_FAILURE" && got.seconds < 5, `refused connection: ${got.status} ${got.error} in ${got.seconds.toFixed(1)} s`);
  }
  run = npm(`${names.reset}@1.0.0`);
  expect(run.status !== 0 && /502/.test(run.stderr), `npm shows the 502: ${show(run)}`);
  run = pip(`${names.reset}==1.0.0`);
  expect(run.status !== 0 && /502|No matching distribution/.test(run.stdout + run.stderr), `pip fails: ${show(run)}`);
  // A period with one success reports the registry reachable, and the warm-up shares a
  // period with these failures, so clients keep asking (as CI does) until a period of
  // failures alone has been reported.
  await h.waitFor("the fleet page shows firewall-1 cannot reach npm and PyPI", async () => {
    await Promise.all([npmDoc("fw1", names.reset), simple("fw1", names.reset)]);
    return /cannot reach npm, PyPI/.test(await fleetHealth(h.operator.portal, "firewall-1"));
  }, {
    timeout: 3 * interval * 1000,
    every: 2000,
  });

  // 2. Error answers, silence and stalls.
  for (const [fault, name] of [
    [{ mode: "status", status: 503 }, names.s503],
    [{ mode: "status", status: 429, retryAfter: 30 }, names.s429],
  ]) {
    await h.fakes.faults(all(fault));
    for (const got of [await npmDoc("fw1", name), await simple("fw1", name)]) {
      expect(got.status === 502 && got.error === "UPSTREAM_FAILURE", `registry answers ${fault.status}: ${got.status} ${got.error}`);
    }
  }
  await h.fakes.faults(all({ mode: "hang" }));
  for (const got of await Promise.all([npmDoc("fw1", names.hang), simple("fw1", names.hang)])) {
    expect(got.status === 504 && got.error === "UPSTREAM_TIMEOUT", `registry silent: ${got.status} ${got.error} ${got.answer.body}`);
    expect(got.seconds >= 25 && got.seconds <= 40, `registry silent: answered after ${got.seconds.toFixed(1)} s, the 30 s metadata limit`);
  }
  let started = performance.now();
  run = npm(`${names["hang-npm"]}@1.0.0`);
  const npmSeconds = (performance.now() - started) / 1000;
  expect(run.status !== 0 && /504/.test(run.stderr), `npm shows the 504: ${show(run)}`);
  expect(npmSeconds < 60, `npm gave up after ${npmSeconds.toFixed(1)} s, no CI hang`);

  // Stalls: the metadata of one package, the tarball and the wheel of another.
  await h.fakes.faults([]);
  const doc = await npmDoc("fw1", names.art);
  expect(doc.status === 200, `the packument before the stall: ${doc.status}`);
  const tarball = doc.answer.json().versions["1.0.0"].dist.tarball;
  const listing = await h.request(`${h.firewalls.fw1}/pypi/simple/${names.art}/`, {
    headers: { ...bearer.headers, accept: "application/vnd.pypi.simple.v1+json" },
  });
  const wheel = listing.json().files[0].url;
  await h.fakes.faults([
    { host: "registry.npmjs.org", path: `/${names.art}/-/`, mode: "stall", afterBytes: 20 },
    { host: "files.pythonhosted.org", mode: "stall", afterBytes: 20 },
    { host: "registry.npmjs.org", mode: "stall", afterBytes: 20 },
  ]);
  const stalls = await Promise.all([npmDoc("fw1", names.stall), get(tarball), get(wheel)]);
  for (const [what, got] of [["packument", stalls[0]], ["tarball", stalls[1]], ["wheel", stalls[2]]]) {
    expect(got.status === 504 && got.error === "UPSTREAM_TIMEOUT", `${what} stalls mid-body: ${got.status} ${got.error} ${got.answer.body}`);
    expect(got.seconds >= 25 && got.seconds <= 45, `${what} stalls mid-body: answered after ${got.seconds.toFixed(1)} s`);
  }

  // 3. Recovery, without a restart.
  await h.fakes.faults([]);
  run = npm(`${names.hang}@1.0.0`);
  expect(run.status === 0, `after recovery npm installs a cold package: ${show(run)}`);
  run = pip(`${names.hang}==1.0.0`);
  expect(run.status === 0, `after recovery pip installs a cold package: ${show(run)}`);
  run = npm(`${names.art}@1.0.0`);
  expect(run.status === 0, `after recovery the stalled tarball installs: ${show(run)}`);
  expect(startedAt(h.stack, "firewall-1") === fw1Started, "firewall-1 was not restarted");
  await h.waitFor("firewall-1 is Healthy again", async () => (await fleetHealth(h.operator.portal, "firewall-1")) === "Healthy", {
    timeout: 3 * interval * 1000,
    every: 2000,
  });

  // 4. firewall-2: the TTL, then the age ceiling.
  expect((await npmDoc("fw2", names.ttl)).status === 200, "fw2 warm");
  expect((await npmDoc("fw1", names.ttl)).status === 200, "fw1 warm");
  await h.fakes.faults([{ host: "registry.npmjs.org", mode: "reset" }]);
  await h.waitFor("past its 5 s TTL fw2 refuses rather than serve stale", async () => (await npmDoc("fw2", names.ttl)).status === 502, { timeout: 15_000 });
  expect((await npmDoc("fw1", names.ttl)).status === 200, "fw1, inside its 300 s TTL, still serves it");
  await h.fakes.faults([]);

  const warmed = performance.now();
  for (const name of aged) expect((await npmDoc("fw2", name)).status === 200, `fw2 warms ${name}`);
  // The origin is down; revalidations (If-None-Match) are still answered 304.
  await h.fakes.faults([{ host: "registry.npmjs.org", conditional: false, mode: "status", status: 503 }]);
  let first;
  let partial = 0;
  for (;;) {
    const refused = (await Promise.all(aged.map((name) => npmDoc("fw2", name)))).filter((got) => got.status === 502).length;
    const at = (performance.now() - warmed) / 1000;
    if (refused && first === undefined) first = at;
    if (refused > 0 && refused < AGED) partial++;
    if (refused === AGED) break;
    expect(at < MAX_AGE + 20, `all ${AGED} refused by the ${MAX_AGE} s ceiling: ${refused} at ${at.toFixed(1)} s`);
    await h.sleep(500);
  }
  h.log(`age ceiling: first refusal ${first.toFixed(1)} s after warming, ${partial} polls with some but not all refused`);
  expect(first >= MAX_AGE * 0.9 - 3, `served on 304s until the ceiling's last tenth: first refusal at ${first.toFixed(1)} s`);
  expect(partial >= 2, `refusals grew over time, not all at once (${partial} partial polls)`);
  await h.fakes.faults([]);
  for (const name of aged) expect((await npmDoc("fw2", name)).status === 200, `${name} is served again once the origin is back`);
}
