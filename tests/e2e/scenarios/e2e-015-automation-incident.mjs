// E2E-015 Incident response through the automation API (docs/plans/e2e-coverage/
// 00-inventory.md §3; docs/api.md §1; portal-guide §4.8).
//
// 1. The operator creates a platform automation token on /admin. A CI job POSTs a
//    blocklist file (a package in both ecosystems and an npm tarball's sha512) to
//    /api/v1/blocklist/platform-1 through the TLS proxy.
// 2. Within the sync interval both firewalls refuse it for an organisation's key and a
//    personal account's key; npm and pip fail on it. GET exports it; /audit has the push.
// 3. Refused pushes write nothing: no or a wrong token, another layer, a body over
//    1 MiB (a body of exactly 1 MiB passes the proxy and is read), malformed JSON, a
//    wrong schema_version, a bad digest, an unknown ecosystem, a body not in UTF-8.
// 4. PUT of the earlier export lifts the incident; the installs work again.
// 5. Postgres stops: the API answers 503 (F11), and 200 again once Postgres is back.
// 6. The operator revokes the token: 401.
//
// Own stack: it stops Postgres, and it replaces the platform layer's blocks.

export const meta = {
  id: "E2E-015",
  title: "Incident response through the automation API",
  suites: ["nightly", "release"],
  stack: "own",
};

const OLD = 400 * 86_400;
const MIB = 1024 * 1024;

export default async function incident(h) {
  const { expect } = h;
  const interval = h.syncInterval;
  const api = `${h.portalUrl}/api/v1/blocklist/platform-1`;
  const show = (run) => `exit ${run.status}\n${run.stdout}\n${run.stderr}`;

  const bad = h.unique("incident");
  const tampered = h.unique("tampered");
  await h.fakes.publishNpm({ name: bad, version: "1.0.0", ageSeconds: OLD });
  await h.fakes.publishPypi({ name: bad, version: "1.0.0", ageSeconds: OLD, kinds: ["wheel"] });
  const dist = await h.fakes.publishNpm({ name: tampered, version: "1.0.0", ageSeconds: OLD });
  const sha512 = Buffer.from(dist.integrity.slice("sha512-".length), "base64").toString("hex");

  const org = await h.signUp({ kind: "org" });
  const orgKey = await h.createKey(org.portal, "acme-ci");
  const personal = await h.signUp({ kind: "personal" });
  const personalKey = await h.createKey(personal.portal, "laptop");
  const on = (keys, fw) => ({
    npmrc: keys.npmrc.replaceAll("fw1.e2e.test", `${fw}.e2e.test`),
    pipConf: keys.pipConf.replaceAll("fw1.e2e.test", `${fw}.e2e.test`),
    key: keys.key,
  });
  const npm = (spec, keys) => h.npm(`install ${spec} --no-audit --no-fund --fetch-retries=0 --cache "$PWD/.npm-cache"`, { npmrc: keys.npmrc });
  const pip = (spec, keys) => h.pip(`install --no-cache-dir --retries 0 ${spec}`, { pipConf: keys.pipConf });
  const probes = [];
  for (const keys of [orgKey, personalKey]) {
    for (const fw of ["fw1", "fw2"]) {
      for (const path of [`/npm/${bad}/1.0.0`, `/npm/${tampered}/1.0.0`]) probes.push({ url: `${h.firewalls[fw]}${path}`, key: keys.key });
    }
  }
  const statuses = async () => Promise.all(probes.map(async (p) => (await h.request(p.url, { headers: { authorization: `Bearer ${p.key}` } })).status));
  expect((await statuses()).every((s) => s === 200), "before the incident every probe is served");

  // 1. The operator's platform token.
  const tokenName = h.unique("siem-push");
  let page = await h.operator.portal.submit("/admin", "/admin/tokens", { name: tokenName });
  expect(page.status === 200, `create platform token: ${page.status}\n${page.body}`);
  const token = h.between(page.body, '<code id="new-token">', "</code>");
  expect(/^aut_[A-Za-z0-9]{32}$/.test(token), `an aut_ token: ${token}`);
  const auth = { authorization: `Bearer ${token}` };
  const exported = async () => {
    const answer = await h.request(api, { headers: auth });
    expect(answer.status === 200, `export: ${answer.status} ${answer.body}`);
    return answer.json();
  };
  const baseline = await exported();

  const file = (records) => ({
    schema_version: 1,
    revision: 1,
    generated_at: new Date().toISOString(),
    expires_at: "2099-01-01T00:00:00Z",
    ...records,
  });
  const incidentFile = file({
    blocked_packages: [
      { ecosystem: "npm", name: bad, version: null, reason: "Incident E2E-015: credential stealer" },
      { ecosystem: "pypi", name: bad, version: null, reason: "Incident E2E-015: credential stealer" },
    ],
    blocked_hashes: [{ algorithm: "sha512", digest: sha512, reason: "Incident E2E-015: tampered tarball" }],
  });
  let answer = await h.request(api, { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify(incidentFile) });
  expect(answer.status === 200, `POST the incident: ${answer.status} ${answer.body}`);
  const pushed = performance.now();
  const { revision } = answer.json();
  expect(Number.isInteger(revision) && revision > baseline.revision, `a new revision: ${answer.body} after ${baseline.revision}`);

  // 2. Enforced everywhere within the interval.
  await h.waitFor("every firewall refuses the incident for both keys", async () => (await statuses()).every((s) => s === 403), {
    timeout: 2 * interval * 1000 + 5000,
    every: 250,
  });
  const latency = (performance.now() - pushed) / 1000;
  h.log(`incident enforced on both firewalls ${latency.toFixed(1)} s after the push (interval ${interval} s)`);
  expect(latency <= interval + 2, `enforced within the interval: ${latency.toFixed(1)} s`);

  let run = npm(`${bad}@1.0.0`, orgKey);
  expect(run.status !== 0 && /E403|403/.test(run.stderr), `npm, org key, fw1: ${show(run)}`);
  run = npm(`${bad}@1.0.0`, on(personalKey, "fw2"));
  expect(run.status !== 0 && /E403|403/.test(run.stderr), `npm, personal key, fw2: ${show(run)}`);
  run = npm(`${tampered}@1.0.0`, on(personalKey, "fw1"));
  expect(run.status !== 0 && /E403|403|ETARGET|No matching version/.test(run.stderr), `npm, sha512 block, personal key, fw1: ${show(run)}`);
  run = pip(`${bad}==1.0.0`, on(personalKey, "fw2"));
  expect(run.status !== 0 && /No matching distribution|403/.test(run.stdout + run.stderr), `pip, personal key, fw2: ${show(run)}`);
  run = pip(`${bad}==1.0.0`, orgKey);
  expect(run.status !== 0 && /No matching distribution|403/.test(run.stdout + run.stderr), `pip, org key, fw1: ${show(run)}`);

  let now = await exported();
  expect(now.revision === revision, `export carries revision ${revision}: ${now.revision}`);
  expect(now.blocked_packages.some((b) => b.ecosystem === "npm" && b.name === bad && b.version === null), "export lists the npm package");
  expect(now.blocked_packages.some((b) => b.ecosystem === "pypi" && b.name === bad), "export lists the PyPI package");
  expect(now.blocked_hashes.some((b) => b.algorithm === "sha512" && b.digest === sha512), "export lists the sha512");
  const audit = (await h.operator.portal.get("/audit")).body;
  expect(audit.includes(tokenName) && audit.includes(bad), "the operator's audit log has the push, by the token");

  // 3. Refused pushes write nothing.
  const json = { ...auth, "content-type": "application/json" };
  const refusals = [
    ["no token", {}, JSON.stringify(incidentFile), 401],
    ["not an aut_ token", { authorization: `Bearer ${orgKey.key}` }, JSON.stringify(incidentFile), 401],
    ["an unknown aut_ token", { authorization: `Bearer aut_${"x".repeat(32)}` }, JSON.stringify(incidentFile), 401],
    ["the Basic scheme", { authorization: `Basic ${Buffer.from(`key:${token}`).toString("base64")}` }, JSON.stringify(incidentFile), 401],
    ["a body over 1 MiB", json, JSON.stringify(file({})).padEnd(MIB + 1, " "), 413],
    ["malformed JSON", json, '{"schema_version": 1, "blocked_packages": [', 422, /./],
    ["schema_version 2", json, JSON.stringify({ ...file({}), schema_version: 2 }), 422, /schema_version 2 is not 1/],
    ["a bad digest", json, JSON.stringify(file({ blocked_hashes: [{ algorithm: "sha512", digest: "abc" }] })), 422, /blocked_hashes\[0\]/],
    ["an unknown ecosystem", json, JSON.stringify(file({ blocked_packages: [{ ecosystem: "maven", name: "x" }] })), 422, /blocked_packages\[0\]/],
    ["a body not in UTF-8", json, Buffer.from([0x7b, 0xff, 0xfe, 0x7d]), 422, /UTF-8/],
  ];
  for (const [what, headers, body, status, text] of refusals) {
    for (const method of ["PUT", "POST"]) {
      answer = await h.request(api, { method, headers, body });
      expect(answer.status === status, `${method} with ${what}: ${answer.status} (want ${status}) ${answer.body.slice(0, 300)}`);
      if (status === 401) expect(answer.body === "", `${method} with ${what}: 401 has an empty body: ${answer.body}`);
      if (text) expect(text.test(answer.body) && !answer.body.trim().includes("\n"), `${method} with ${what}: one line naming the problem: ${answer.body}`);
    }
  }
  const orgLayer = (await h.policyPath(org.portal)).slice("/policy/".length);
  answer = await h.request(`${h.portalUrl}/api/v1/blocklist/${orgLayer}`, { method: "PUT", headers: json, body: JSON.stringify(file({})) });
  expect(answer.status === 403 && answer.body === "This token writes one other layer.", `another layer: ${answer.status} ${answer.body}`);
  const blocks = (layer) => JSON.stringify([layer.blocked_packages, layer.blocked_hashes]);
  let after = await exported();
  expect(after.revision === revision && blocks(after) === blocks(now), `the refused pushes wrote nothing: ${JSON.stringify(after)}`);
  // Exactly 1 MiB passes the proxy and is read; adding blocks the layer has adds none.
  answer = await h.request(api, { method: "POST", headers: json, body: JSON.stringify(incidentFile).padEnd(MIB, " ") });
  expect(answer.status === 200, `a body of exactly 1 MiB: ${answer.status} ${answer.body.slice(0, 300)}`);
  after = await exported();
  expect(blocks(after) === blocks(now), `the same blocks again add none: ${JSON.stringify(after)}`);

  // 4. PUT without it lifts it.
  answer = await h.request(api, { method: "PUT", headers: json, body: JSON.stringify(baseline) });
  expect(answer.status === 200, `PUT the earlier export: ${answer.status} ${answer.body}`);
  now = await exported();
  expect(!now.blocked_packages.some((b) => b.name === bad) && !now.blocked_hashes.some((b) => b.digest === sha512), "the export no longer lists the incident");
  await h.waitFor("every firewall serves it again", async () => (await statuses()).every((s) => s === 200), {
    timeout: 2 * interval * 1000 + 5000,
  });
  run = npm(`${bad}@1.0.0`, orgKey);
  expect(run.status === 0, `npm after the lift: ${show(run)}`);
  run = npm(`${tampered}@1.0.0`, on(personalKey, "fw2"));
  expect(run.status === 0, `npm (the sha512) after the lift: ${show(run)}`);
  run = pip(`${bad}==1.0.0`, on(personalKey, "fw2"));
  expect(run.status === 0, `pip after the lift: ${show(run)}`);

  // 5. Database outage: the token cannot be checked, which is not "revoked".
  const deferred = [];
  await h.postgresDown();
  try {
    for (const method of ["GET", "PUT"]) {
      answer = await h.request(api, { method, headers: json, body: method === "GET" ? undefined : JSON.stringify(baseline) });
      // needs F11: 503, not 401, when the database fails during the token check. Checked
      // at the end, so the recovery and revocation steps still run until F11 is merged.
      if (answer.status !== 503) deferred.push(`${method} with Postgres down: ${answer.status} (want 503) ${answer.body}`);
    }
  } finally {
    await h.postgresUp();
  }
  await h.waitFor("the API answers again after Postgres is back", async () => (await h.request(api, { headers: auth })).status === 200, { timeout: 60_000 });

  // 6. Revoked.
  const admin = (await h.operator.portal.get("/admin")).body;
  const id = admin.match(new RegExp(`<td>${tokenName}</td>[\\s\\S]*?action="/admin/tokens/(\\d+)/revoke"`))?.[1];
  expect(id, `the token is listed on /admin`);
  page = await h.operator.portal.post(`/admin/tokens/${id}/revoke`, { csrf: h.hidden(admin, "csrf") });
  expect(page.status === 303, `revoke: ${page.status}\n${page.body}`);
  answer = await h.request(api, { headers: auth });
  expect(answer.status === 401, `a revoked token: ${answer.status}`);
  expect(!deferred.length, deferred.join("\n"));
}
