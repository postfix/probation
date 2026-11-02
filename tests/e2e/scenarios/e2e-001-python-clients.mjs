// E2E-001 Python clients in managed mode (pip, uv, poetry).
//
// A new organisation copies the pip line from the keys page; pip, uv (uv.toml) and
// Poetry (source plus http-basic) install a wheel project and an sdist-only project
// through firewall-1, each with a clean cache. The org admin blocks one version under a
// non-canonical spelling (`Py.Mixed_x==1.0` for `py-mixed-x` 1.0.0): every client falls
// back to 0.9.0, the exact pin fails, a `--require-hashes` file that names the blocked
// file's artifact URL gets 403, and a poetry.lock pinning it fails without being
// rewritten. An exact-version exception under a third spelling (`1.0.0`) lets it through
// again. The key is revoked: each client fails fast in a non-TTY shell (no prompt, no
// hang) and the firewall's 401 names the Basic scheme. /activity shows the refusals.

import { activityRow, basic, changePlatform, fetchWith, policyPost, revokeKey, untilStatus } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-001",
  title: "Python clients in managed mode (pip, uv, poetry)",
  suites: ["nightly", "release"],
};

const DAY = 86_400;
/// "Fails fast": a client with a revoked key gives up within this, no prompt, no retry loop.
const FAST_SECONDS = 5;

export default async function pythonClients(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  const suffix = h.unique("p").slice(2);
  const wheelOnly = `py-wheel-${suffix}`;
  const sdistOnly = `py-sdist-${suffix}`;
  const mixed = `py-mixed-${suffix}`; // canonical (PEP 503) name
  await h.fakes.publishPypi({ name: wheelOnly, version: "2.0.0", ageSeconds: 300 * DAY, kinds: ["wheel"] });
  await h.fakes.publishPypi({ name: sdistOnly, version: "3.0.0", ageSeconds: 300 * DAY, kinds: ["sdist"], backend: "intree" });
  for (const [version, days] of [["0.9.0", 500], ["1.0.0", 400]]) {
    await h.fakes.publishPypi({ name: `Py_Mixed_${suffix}`, version, ageSeconds: days * DAY, kinds: ["wheel", "sdist"], backend: "intree" });
  }

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const keyName = "laptop";
  const { key, pipConf } = await h.createKey(admin.portal, keyName);
  expect(pipConf.includes(`https://key:${key}@fw1.e2e.test/pypi/simple/`), `the keys page's pip line: ${pipConf}`);
  const index = `https://key:${key}@fw1.e2e.test/pypi/simple/`;
  const uvToml = `[[index]]\nurl = "${index}"\ndefault = true\n`;
  const pyproject = `[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.10"\ndependencies = []\n\n[tool.poetry]\npackage-mode = false\n`;

  const ok = (what, run) => expect(run.status === 0, `${what} exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  const fails = (what, run, pattern) => {
    const text = run.stdout + run.stderr;
    expect(run.status !== 0, `${what} should fail but exited 0\n${text}`);
    expect(!pattern || pattern.test(text), `${what}: no ${pattern} in\n${text}`);
  };
  /// firewall-1 answered the blocked 1.0.0 wheel with 403 BLOCKED since `since`.
  const blockedSince = (what, since) => {
    const decided = h.decisions("firewall-1", since).filter((d) => /py_mixed_[0-9a-f]+-1\.0\.0-py3-none-any\.whl/.test(d.version ?? ""));
    expect(decided.some((d) => d.status === 403 && d.result === "BLOCKED"), `${what}: firewall-1 refused the 1.0.0 wheel with 403 BLOCKED: ${JSON.stringify(decided)}`);
  };
  const pip = (args) => h.pip(`install --no-cache-dir --target t ${args}`, { pipConf });
  const uv = (args, files = {}) =>
    h.client("client-uv", `export UV_CACHE_DIR=$PWD/.uv-cache; uv venv -q .venv && uv pip install -p .venv ${args}`, { files: { "uv.toml": uvToml, ...files } });
  const poetryEnv = `export POETRY_CACHE_DIR=$PWD/.poetry-cache POETRY_VIRTUALENVS_IN_PROJECT=true POETRY_HTTP_BASIC_PROBATION_USERNAME=key POETRY_HTTP_BASIC_PROBATION_PASSWORD=${key}`;
  const poetryDir = `/work/${h.unique("poetry")}`;
  const poetry = (script, files, dir = poetryDir) => h.client("client-poetry", `${poetryEnv}\n${script}`, { dir, files });
  const poetrySource = "poetry source add --priority=primary probation https://fw1.e2e.test/pypi/simple/";

  // 1. Wheel and sdist-only projects, clean caches, through firewall-1.
  let run = pip(`${wheelOnly} ${sdistOnly}`);
  ok("pip install (wheel and sdist)", run);
  expect(/Successfully installed .*py-sdist-\S+-3\.0\.0/.test(run.stdout) && run.stdout.includes(`${wheelOnly}-2.0.0`), `pip installed both: ${run.stdout}`);
  run = uv(`${wheelOnly} ${sdistOnly}`);
  ok("uv pip install (wheel and sdist)", run);
  expect(run.stderr.includes(`+ ${wheelOnly}==2.0.0`) && run.stderr.includes(`+ ${sdistOnly}==3.0.0`), `uv installed both: ${run.stderr}`);
  run = poetry(
    `${poetrySource} && poetry add ${wheelOnly} ${sdistOnly} ${mixed}`,
    { "pyproject.toml": pyproject },
  );
  ok("poetry add (wheel, sdist and the mixed project)", run);
  expect(run.stdout.includes(`Installing ${sdistOnly} (3.0.0)`) && run.stdout.includes(`Installing ${mixed} (1.0.0)`), `poetry installed: ${run.stdout}`);
  const poetryLock = h.client("client-poetry", "cat poetry.lock", { dir: poetryDir }).stdout;
  expect(poetryLock.includes(`name = "${mixed}"\nversion = "1.0.0"`), `poetry.lock pins ${mixed} 1.0.0:\n${poetryLock}`);

  // The firewall's own artifact URL of the 1.0.0 wheel, as a lockfile tool records it.
  const page = await fetchWith(h, fw1, `/pypi/simple/${mixed}/`, null, { authorization: basic(key) });
  expect(page.status === 200, `simple page: ${page.status} ${page.body}`);
  const wheelLink = page.body.match(/href="([^"]+\/py_mixed_[0-9a-f]+-1\.0\.0-py3-none-any\.whl)#sha256=([0-9a-f]{64})"/);
  expect(wheelLink, `the 1.0.0 wheel link on the firewall's page:\n${page.body}`);
  const [, wheelUrl, wheelSha] = wheelLink;
  expect(new URL(wheelUrl, fw1).host === "fw1.e2e.test", `the artifact URL stays on the firewall: ${wheelUrl}`);
  const lockedUrl = new URL(wheelUrl, fw1).toString();
  const hashes = {
    "url.txt": `py-mixed-${suffix} @ ${lockedUrl} --hash=sha256:${wheelSha}\n`,
    "pinned.txt": `py-mixed-${suffix}==1.0.0 --hash=sha256:${wheelSha}\n`,
  };
  ok("pip --require-hashes (artifact URL) before the block", h.pip("install --no-cache-dir --target t --require-hashes -r url.txt", { pipConf, files: hashes }));

  // 2. A version block under a non-canonical spelling of name and version.
  const policy = await h.policyPath(admin.portal);
  let saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "pypi", name: `Py.Mixed_${suffix}`, what: "version", version: "1.0" });
  expect(saved.status === 303, `add the block: ${saved.status}\n${saved.body}`);
  const blockedPath = new URL(wheelUrl, fw1).pathname;
  await untilStatus(h, [fw1], blockedPath, key, 403, "the block reaches firewall-1");
  const refusal = await fetchWith(h, fw1, blockedPath, null, { authorization: basic(key) });
  expect(refusal.json().error === "BLOCKED", `the artifact refusal names BLOCKED: ${refusal.body}`);

  run = pip(mixed);
  ok("pip falls back", run);
  expect(run.stdout.includes(`Successfully installed ${mixed}-0.9.0`), `pip falls back to 0.9.0: ${run.stdout}`);
  fails("pip install ==1.0.0", pip(`${mixed}==1.0.0`), /No matching distribution found/);
  let since = new Date(Date.now() - 1000);
  fails("pip --require-hashes (artifact URL)", h.pip("install --no-cache-dir --target t --require-hashes -r url.txt", { pipConf, files: hashes }), /HTTP error 403/);
  blockedSince("pip --require-hashes (artifact URL)", since);
  fails("pip --require-hashes (pinned)", h.pip("install --no-cache-dir --target t --require-hashes -r pinned.txt", { pipConf, files: hashes }), /No matching distribution found/);
  run = uv(mixed);
  ok("uv falls back", run);
  expect(run.stderr.includes(`+ ${mixed}==0.9.0`), `uv falls back to 0.9.0: ${run.stderr}`);
  fails("uv pip install ==1.0.0", uv(`${mixed}==1.0.0`), new RegExp(`no version of ${mixed}==1\\.0\\.0`));
  since = new Date(Date.now() - 1000);
  fails("uv pip install (artifact URL)", uv(`--require-hashes -r url.txt`, hashes), /403 Forbidden/);
  blockedSince("uv pip install (artifact URL)", since);
  // The lock pins the blocked 1.0.0: install fails and the lock is not rewritten.
  run = poetry(`rm -rf .venv && poetry install`);
  // The blocked 1.0.0 is not on the firewall's page, so Poetry finds no file for the pin.
  fails("poetry install from the lock", run, new RegExp(`Unable to find installation candidates for ${mixed} \\(1\\.0\\.0\\)`));
  const after = h.client("client-poetry", "cat poetry.lock", { dir: poetryDir }).stdout;
  expect(after === poetryLock, "poetry.lock is unchanged by the refused install");

  // 3. An exact-version exception (a third spelling) lifts the org's block. Exceptions
  //    need "Allow package exceptions" from the platform.
  const restorePlatform = await changePlatform(h, { allow: { allow_exceptions: true } });
  try {
    saved = await policyPost(admin.portal, policy, { action: "add_exception", ecosystem: "pypi", name: `PY-MIXED-${suffix}`, version: "1.0.0", lifts_block: "on" });
    expect(saved.status === 303, `add the exception: ${saved.status}\n${saved.body}`);
    await untilStatus(h, [fw1], blockedPath, key, 200, "the exception reaches firewall-1");
    run = pip(`${mixed}==1.0.0`);
    ok("pip install ==1.0.0 under the exception", run);
    ok("pip --require-hashes (artifact URL) under the exception", h.pip("install --no-cache-dir --target t --require-hashes -r url.txt", { pipConf, files: hashes }));
    ok("uv pip install ==1.0.0 under the exception", uv(`${mixed}==1.0.0`));
    ok("poetry install from the lock under the exception", poetry("poetry install"));
  } finally {
    await restorePlatform();
  }

  // 4. Revoke the key: every client fails fast with 401, never a prompt or a hang.
  await revokeKey(admin.portal, keyName);
  await untilStatus(h, [fw1], `/pypi/simple/${wheelOnly}/`, key, 401, "the revocation reaches firewall-1");
  const denied = await fetchWith(h, fw1, `/pypi/simple/${wheelOnly}/`, null, { authorization: basic(key) });
  expect(denied.status === 401 && /^Basic /.test(denied.headers["www-authenticate"] ?? ""), `401 names the Basic scheme: ${denied.status} ${JSON.stringify(denied.headers)}`);
  // Only the client's own run is timed: the project set-up (venv, Poetry source) comes first.
  const revokedPoetry = `/work/${h.unique("poetry")}`;
  ok("poetry project set-up", poetry(poetrySource, { "pyproject.toml": pyproject }, revokedPoetry));
  const uvDir = `/work/${h.unique("uv")}`;
  ok("uv venv", h.client("client-uv", "uv venv -q .venv", { dir: uvDir, files: { "uv.toml": uvToml } }));
  for (const [what, command] of [
    ["pip", () => pip(wheelOnly)],
    ["uv", () => h.client("client-uv", `export UV_CACHE_DIR=$PWD/.uv-cache-revoked; uv pip install -p .venv ${wheelOnly}`, { dir: uvDir })],
    ["poetry", () => poetry(`poetry add ${wheelOnly}`, {}, revokedPoetry)],
  ]) {
    const started = performance.now();
    run = command();
    const seconds = (performance.now() - started) / 1000;
    fails(`${what} with the revoked key`, run, /401|[Uu]nauthori[sz]ed|[Aa]uthori[sz]ation error/);
    expect(seconds < FAST_SECONDS, `${what} gave up in ${seconds.toFixed(1)} s, not within ${FAST_SECONDS} s`);
    h.log(`${what} with a revoked key failed in ${seconds.toFixed(1)} s`);
  }

  // 5. The org admin's Activity page shows the refusals, never the key itself.
  await activityRow(h, admin.portal, { package: `${mixed}@1.0.0`, result: "Blocked", layer: "Organisation" });
  await activityRow(h, admin.portal, { result: "Refused: the key was revoked", key: keyName });
  expect(!(await admin.portal.get("/activity")).body.includes(key), "the activity page never shows a key");
}
