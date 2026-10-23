// E2E-signup-to-install and M-propagation (C32 metrics 1 and 2, C82); the release
// witness. Prints `E2E PASS <seconds>` and the two `propagation … p99` lines.
//
// 1. In Chromium, a new organisation signs up, confirms its address from the mail in
//    the sink, signs in, creates a key, and npm (in its client container) installs with
//    the .npmrc lines the keys page shows, through firewall-1. No operator step falls
//    inside the clock; PASS when that took under 600 s.
// 2. Two firewalls at a 10 s interval, 50 policy edits and 50 key revocations made on
//    the portal: the p99 of (last firewall apply - commit) is at most the interval, for
//    edits and revocations each. The operator's global admin (from `admin bootstrap`)
//    registered firewall-2 at stack start and sets the organisation's limits here.

export const meta = {
  id: "E2E-signup-to-install",
  title: "Sign-up to npm install, and propagation to two firewalls",
  suites: ["pr", "nightly", "release"],
};

const CHANGES = 50;
const BUDGET_SECONDS = 600;
const PACKAGE = "e2e-many";

export default async function signUpToInstall(h) {
  const { expect, hidden } = h;
  const interval = h.syncInterval;
  const firewalls = [h.firewalls.fw1, h.firewalls.fw2];

  // 1. Sign-up to install.
  const context = await h.browser();
  const page = await context.newPage();
  const started = performance.now();
  const account = await h.browserSignUp(page, { kind: "org" });
  const { npmrc } = await h.browserCreateKey(page, "laptop");
  const install = h.npm("install e2e-left@1.0.0 --no-audit --no-fund && node -p \"require('e2e-left/package.json').version\"", { npmrc });
  expect(install.status === 0, `npm install exited ${install.status}\n${install.stdout}\n${install.stderr}`);
  expect(install.stdout.trim().endsWith("1.0.0"), `e2e-left 1.0.0 is installed: ${install.stdout}`);
  const seconds = (performance.now() - started) / 1000;
  // The clock starts at the sign-up page, after the images are built and the stack is up:
  // it measures what a new organisation waits for, not the operator's deployment.
  console.log(
    `E2E ${seconds < BUDGET_SECONDS ? "PASS" : "FAIL"} ${seconds.toFixed(1)} (seconds from sign-up to npm install done; deployment not timed)`,
  );
  expect(seconds < BUDGET_SECONDS, `sign-up to install took ${seconds} s`);

  // 2. Propagation, driven with API steps from the same session.
  const user = { ...account, portal: new h.Portal() };
  for (const cookie of await context.cookies()) user.portal.cookies.set(cookie.name, cookie.value);
  await h.enableTotp(user);
  const operator = h.operator;
  const policy = await h.policyPath(user.portal);
  // Room for 52 keys and the pollers' request rate (C114), as tests/propagation.rs gives.
  let answer = await operator.portal.submit("/admin", `/admin/limits/orgs/${policy.slice("/policy/org-".length)}`, {
    rate: "10000000",
    keys: "1000",
    service: "1000",
  });
  expect(answer.status === 303, `organisation limits: ${answer.status}\n${answer.body}`);

  const keys = [];
  for (let n = 0; n <= CHANGES; n++) keys.push((await h.createKey(user.portal, `p-${n}`)).key);
  const probe = keys.pop();
  const listed = (await user.portal.get("/keys")).body;
  const ids = keys.map((_, n) => {
    const row = listed.match(new RegExp(`<td>p-${n}</td>[\\s\\S]*?action="/keys/(\\d+)/revoke"`));
    expect(row, `key p-${n} is listed`);
    return row[1];
  });

  const status = async (f, path, key) =>
    (await h.request(firewalls[f] + path, { headers: { authorization: `Bearer ${key}` }, timeout: 15_000 })).status;
  /// `GET path` until it answers 200, waiting out each 503 (a busy lookup budget).
  const warm = (f, path, key) =>
    h.waitFor(`firewall-${f + 1} ${path}`, async () => {
      const got = await status(f, path, key);
      expect(got === 200 || got === 503, `firewall-${f + 1} ${path}: ${got}`);
      return got === 200;
    }, { timeout: 15_000, every: 1000 });

  // 51 versions of a fake package (old enough for the freeze, no OSV finding): 50 to
  // block one by one, and one every key asks for.
  const document = await h.request(`${firewalls[0]}/npm/${PACKAGE}`, { headers: { authorization: `Bearer ${probe}` } });
  expect(document.status === 200, `${PACKAGE}: ${document.status}`);
  const allowed = [];
  for (const version of Object.keys(document.json().versions)) {
    if (allowed.length > CHANGES) break;
    if ((await status(0, `/npm/${PACKAGE}/${version}`, probe)) === 200) allowed.push(version);
  }
  expect(allowed.length > CHANGES, `only ${allowed.length} versions of ${PACKAGE} are served`);
  const keep = allowed.pop();
  for (let f = 0; f < firewalls.length; f++) {
    for (const version of [...allowed, keep]) await warm(f, `/npm/${PACKAGE}/${version}`, probe);
    for (const key of keys) await warm(f, `/npm/${PACKAGE}/${keep}`, key);
  }

  const edits = new Map();
  const revocations = new Map();
  const editsApplied = new Map();
  const revocationsApplied = new Map();
  const writer = (async () => {
    const csrf = hidden((await user.portal.get("/keys")).body, "csrf");
    // One change every 100 ms or so, edits and revocations alternating.
    for (let n = 0; n < CHANGES; n++) {
      const form = (await user.portal.get(policy)).body;
      edits.set(n, performance.now());
      const saved = await user.portal.post(policy, {
        csrf: hidden(form, "csrf"),
        revision: hidden(form, "revision"),
        action: "add_block",
        ecosystem: "npm",
        name: PACKAGE,
        what: "version",
        version: allowed[n],
      });
      expect(saved.status === 303, `edit ${n}: ${saved.status}\n${saved.body}`);
      await h.sleep(50);
      revocations.set(n, performance.now());
      const revoked = await user.portal.post(`/keys/${ids[n]}/revoke`, { csrf });
      expect(revoked.status === 303, `revocation ${n}: ${revoked.status}\n${revoked.body}`);
      await h.sleep(50);
    }
  })();
  const poller = async (f) => {
    const deadline = performance.now() + (CHANGES * 0.3 + 4 * interval) * 1000;
    for (;;) {
      const asked = [];
      for (const n of edits.keys()) {
        if (editsApplied.has(`${f}:${n}`)) continue;
        asked.push(status(f, `/npm/${PACKAGE}/${allowed[n]}`, probe).then((got) => {
          if (got === 403) editsApplied.set(`${f}:${n}`, performance.now());
        }));
      }
      for (const n of revocations.keys()) {
        if (revocationsApplied.has(`${f}:${n}`)) continue;
        asked.push(status(f, `/npm/${PACKAGE}/${keep}`, keys[n]).then((got) => {
          if (got === 401) revocationsApplied.set(`${f}:${n}`, performance.now());
        }));
      }
      await Promise.all(asked);
      const done = (applied) => [...applied.keys()].filter((at) => at.startsWith(`${f}:`)).length === CHANGES;
      if (done(editsApplied) && done(revocationsApplied)) return;
      expect(performance.now() < deadline, `firewall-${f + 1} never applied every change`);
      await h.sleep(50);
    }
  };
  await Promise.all([writer, ...firewalls.map((_, f) => poller(f))]);

  /// p99 of (last firewall apply - commit), in seconds.
  const p99 = (committed, applied) => {
    const latencies = [...committed].map(([n, at]) => Math.max(...firewalls.map((_, f) => applied.get(`${f}:${n}`) - at)) / 1000);
    latencies.sort((a, b) => a - b);
    return latencies[Math.ceil(latencies.length * 0.99) - 1];
  };
  let passed = true;
  for (const [what, committed, applied] of [
    ["edits", edits, editsApplied],
    ["revocations", revocations, revocationsApplied],
  ]) {
    const latency = p99(committed, applied);
    const within = latency <= interval;
    passed &&= within;
    console.log(`propagation ${what} p99 ${within ? "<=" : ">"} interval (${latency.toFixed(3)} s, interval ${interval} s)`);
  }
  expect(passed, "a propagation p99 exceeds the interval");
}
