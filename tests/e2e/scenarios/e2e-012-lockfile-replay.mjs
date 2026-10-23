// E2E-012 Lockfile replay across every documented client.
//
// A project's lockfiles were made against the public registries (each client run with
// no Probation config, so it talks to registry.npmjs.org and pypi.org: the fakes under
// those names). The team then points its clients at firewall-1 as docs/operations.md
// §7 says and replays them with fresh caches: `npm ci` (npm 12, 11, 10),
// `pnpm install --frozen-lockfile`, yarn berry `--immutable`, `bun install
// --frozen-lockfile`, pip `--require-hashes`, `uv sync` (uv.toml) and `poetry install`
// (source plus http-basic; uv and Poetry lock again once against the new index, as
// they ask to). The org then blocks one pinned version in each ecosystem
// (e2e-left 1.1.0, a transitive npm dependency): every replay fails loudly and leaves
// its lockfile unchanged. yarn 1: its yarn.lock names registry.yarnpkg.com; without the
// documented rewrite the install must not bypass the firewall (the stack, like an
// enforced network, has no route there), with it the block holds and the unblocked
// install works.

import { policyPost, removeOwn, untilStatus } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-012",
  title: "Lockfile replay across every documented client",
  suites: ["nightly", "release"],
};

const PUBLIC_NPMRC = "registry=https://registry.npmjs.org/\n";

export default async function lockfileReplay(h) {
  const { expect } = h;
  const firewalls = [h.firewalls.fw1, h.firewalls.fw2];
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key, npmrc, pipConf } = await h.createKey(admin.portal, "ci");
  const policy = await h.policyPath(admin.portal);

  const packageJson = JSON.stringify({ name: "demo", version: "1.0.0", private: true, dependencies: { "e2e-right": "1.0.0", "@e2e/scoped": "1.0.1" } });
  const pyproject = `[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.10"\ndependencies = ["e2e-left==1.1.0"]\n\n[tool.poetry]\npackage-mode = false\n`;
  const uvToml = `[[index]]\nurl = "https://key:${key}@fw1.e2e.test/pypi/simple/"\ndefault = true\n`;
  const yarnrc = `npmRegistryServer: "https://fw1.e2e.test/npm/"\nnpmAuthToken: "${key}"\nnpmAlwaysAuth: true\nnodeLinker: node-modules\nenableGlobalCache: false\nenableMirror: false\n`;
  const poetryEnv = `export POETRY_CACHE_DIR=$PWD/.poetry-cache POETRY_VIRTUALENVS_IN_PROJECT=true POETRY_HTTP_BASIC_PROBATION_USERNAME=key POETRY_HTTP_BASIC_PROBATION_PASSWORD=${key}`;
  // What each install put in place, read with the runtime of its container.
  const nodeCheck = (runtime) =>
    `${runtime} -e "const r=require.resolve('e2e-right');console.log('installed', require('e2e-right'), require('@e2e/scoped'), require(require.resolve('e2e-left',{paths:[r]})))"`;
  const npmInstalled = "installed e2e-right@1.0.0 @e2e/scoped@1.0.1 e2e-left@1.1.0";
  const pyCheck = (python) => `${python} -c "import e2e_left; print('installed e2e-left', e2e_left.VERSION)"`;
  const pyInstalled = "installed e2e-left 1.1.0";

  // Each client: its container, its lockfile, the run that made the lockfile against
  // the public registry, and the replay through the firewall (a fresh cache each run).
  const clients = [
    ...["client-npm", "client-npm11", "client-npm10"].map((service) => ({
      name: `npm ci (${service})`,
      service,
      lock: "package-lock.json",
      make: { files: { "package.json": packageJson, ".npmrc": PUBLIC_NPMRC }, script: "npm install --package-lock-only --no-audit --cache $PWD/.c0" },
      replay: { files: { ".npmrc": npmrc }, script: `rm -rf node_modules; npm ci --no-audit --cache $PWD/.c@FRESH@ && ${nodeCheck("node")}` },
      installed: npmInstalled,
      refusal: { said: /E403|403 Forbidden/, blocked: true },
    })),
    {
      name: "pnpm install --frozen-lockfile",
      service: "client-js",
      lock: "pnpm-lock.yaml",
      make: { files: { "package.json": packageJson, ".npmrc": PUBLIC_NPMRC }, script: "pnpm install --lockfile-only --store-dir $PWD/.s0" },
      replay: { files: { ".npmrc": npmrc }, script: `rm -rf node_modules; pnpm install --frozen-lockfile --store-dir $PWD/.s@FRESH@ && ${nodeCheck("node")}` },
      installed: npmInstalled,
      refusal: { said: /ERR_PNPM_FETCH_403|returned HTTP 403/, blocked: true },
    },
    {
      name: "yarn berry install --immutable",
      service: "client-yarn-berry",
      lock: "yarn.lock",
      make: {
        files: { "package.json": packageJson, ".yarnrc.yml": 'npmRegistryServer: "https://registry.npmjs.org"\nnodeLinker: node-modules\nenableGlobalCache: false\n' },
        script: "YARN_CACHE_FOLDER=$PWD/.y0 yarn install --mode=update-lockfile",
      },
      replay: { files: { ".yarnrc.yml": yarnrc }, script: `rm -rf node_modules; YARN_CACHE_FOLDER=$PWD/.y@FRESH@ yarn install --immutable && ${nodeCheck("node")}` },
      installed: npmInstalled,
      refusal: { said: /403 \(Forbidden\)|Response Code: 403/, blocked: true },
    },
    {
      name: "bun install --frozen-lockfile",
      service: "client-bun",
      lock: "bun.lock",
      make: { files: { "package.json": packageJson }, script: "BUN_INSTALL_CACHE_DIR=$PWD/.b0 bun install --lockfile-only" },
      replay: { files: { ".npmrc": npmrc }, script: `rm -rf node_modules; BUN_INSTALL_CACHE_DIR=$PWD/.b@FRESH@ bun install --frozen-lockfile && ${nodeCheck("bun")}` },
      installed: npmInstalled,
      refusal: { said: /\b403\b/, blocked: true },
    },
    {
      name: "pip install --require-hashes",
      service: "client-pip",
      lock: "requirements.txt",
      // pip-compile --generate-hashes against pypi.org, by hand: the hashes PyPI lists.
      make: { files: {}, script: "true" },
      replay: { files: { "pip.conf": pipConf }, script: `rm -rf t; PIP_CONFIG_FILE=$PWD/pip.conf pip install --no-cache-dir --target t --require-hashes -r requirements.txt && PYTHONPATH=t ${pyCheck("python")}` },
      installed: pyInstalled,
      refusal: { said: /No matching distribution found for e2e-left==1\.1\.0/, blocked: false },
    },
    {
      name: "uv sync",
      service: "client-uv",
      lock: "uv.lock",
      make: { files: { "pyproject.toml": pyproject }, script: "UV_CACHE_DIR=$PWD/.u0 uv lock" },
      // The lock names pypi.org; with uv.toml uv locks once against the firewall.
      relock: { files: { "uv.toml": uvToml }, script: "UV_CACHE_DIR=$PWD/.u1 uv lock" },
      replay: { files: {}, script: `rm -rf .venv; UV_CACHE_DIR=$PWD/.u@FRESH@ uv sync --locked && ${pyCheck(".venv/bin/python")}` },
      installed: pyInstalled,
      refusal: { said: /403 Forbidden/, blocked: true },
    },
    {
      name: "poetry install",
      service: "client-poetry",
      lock: "poetry.lock",
      make: { files: { "pyproject.toml": pyproject }, script: "POETRY_CACHE_DIR=$PWD/.p0 poetry lock" },
      // The documented per-project source; Poetry asks for `poetry lock` after it.
      relock: { files: {}, script: `${poetryEnv}\npoetry source add --priority=primary probation https://fw1.e2e.test/pypi/simple/ && poetry lock` },
      replay: { files: {}, script: `${poetryEnv}\nexport POETRY_CACHE_DIR=$PWD/.p@FRESH@; rm -rf .venv; poetry install && ${pyCheck(".venv/bin/python")}` },
      installed: pyInstalled,
      refusal: { said: /e2e-left \(1\.1\.0\)/, blocked: false },
    },
  ];

  const pypiPage = await h.request("https://pypi.org/simple/e2e-left/", { headers: { accept: "application/vnd.pypi.simple.v1+json" } });
  const hashes = pypiPage.json().files.filter((f) => f.filename.includes("-1.1.0")).map((f) => `--hash=sha256:${f.hashes.sha256}`);
  expect(hashes.length === 2, `pypi.org lists the wheel and the sdist of e2e-left 1.1.0: ${pypiPage.body}`);

  // `@FRESH@` in a script becomes a new name each run: a fresh client cache.
  const run = (client, step) =>
    h.client(client.service, `${step.script.replaceAll("@FRESH@", h.unique("cache"))}\necho "exit=$?"\necho "lock=$(sha256sum ${client.lock} | cut -c1-64)"`, {
      dir: client.dir,
      files: step.files,
    });
  const exitOf = (answer) => Number(answer.stdout.match(/^exit=(\d+)$/m)?.[1]);
  const lockOf = (answer) => answer.stdout.match(/^lock=([0-9a-f]{64})$/m)?.[1];
  const said = (answer) => `${answer.stdout}\n${answer.stderr}`;

  // 1. The lockfiles, made against the public registries.
  for (const client of clients) {
    client.dir = `/work/${h.unique("lock")}`;
    if (client.lock === "requirements.txt") client.make.files["requirements.txt"] = `e2e-left==1.1.0 ${hashes.join(" ")}\n`;
    const made = run(client, client.make);
    expect(exitOf(made) === 0 && lockOf(made), `${client.name}: the lockfile against the public registry: ${said(made)}`);
    if (client.relock) {
      const relocked = run(client, client.relock);
      expect(exitOf(relocked) === 0, `${client.name}: lock against the firewall: ${said(relocked)}`);
    }
  }

  // 2. Replayed through firewall-1 with fresh caches.
  for (const client of clients) {
    const before = lockOf(run(client, { files: {}, script: "true" }));
    const replayed = run(client, client.replay);
    expect(exitOf(replayed) === 0 && replayed.stdout.includes(client.installed), `${client.name} through the firewall: ${said(replayed)}`);
    expect(lockOf(replayed) === before, `${client.name} leaves ${client.lock} as it was`);
    client.lockHash = before;
    h.log(`${client.name}: replayed`);
  }

  // 3. One pinned version blocked in each ecosystem: every replay fails, loudly, and
  //    leaves its lockfile unchanged.
  for (const ecosystem of ["npm", "pypi"]) {
    const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem, name: "e2e-left", what: "version", version: "1.1.0" });
    expect(saved.status === 303, `block e2e-left 1.1.0 (${ecosystem}): ${saved.status}\n${saved.body}`);
  }
  await untilStatus(h, firewalls, "/npm/e2e-left/1.1.0", key, 403, "the blocks reach the fleet");
  for (const client of clients) {
    const since = new Date(Date.now() - 1000);
    const refused = run(client, client.replay);
    expect(exitOf(refused) !== 0 && !refused.stdout.includes(client.installed), `${client.name} must fail on the blocked pin: ${said(refused)}`);
    // The client's own words for this refusal, not just any error.
    expect(client.refusal.said.test(said(refused)), `${client.name} says ${client.refusal.said}: ${said(refused)}`);
    if (client.refusal.blocked) {
      // A client that fetches the pinned artifact was answered 403 BLOCKED for it.
      const decided = h.decisions("firewall-1", since).filter((d) => /e2e[-_]left-1\.1\.0/.test(d.version ?? ""));
      expect(decided.some((d) => d.status === 403 && d.result === "BLOCKED"), `${client.name}: firewall-1 refused e2e-left 1.1.0 with 403 BLOCKED: ${JSON.stringify(decided)}`);
    }
    expect(lockOf(refused) === client.lockHash, `${client.name} leaves ${client.lock} unchanged after the refusal`);
    h.log(`${client.name}: refused`);
  }

  // 4. yarn 1. Its lockfile from the public registry names registry.yarnpkg.com, yarn's
  //    default (made here through registry.npmjs.org, then given yarn's own host).
  const yarn = { service: "client-js", lock: "yarn.lock", dir: `/work/${h.unique("yarn1")}` };
  const made = run(yarn, {
    files: { "package.json": packageJson },
    script: "yarn install --registry https://registry.npmjs.org/ --cache-folder $PWD/.y0 --non-interactive && rm -rf node_modules && sed -i 's#https://registry.npmjs.org/#https://registry.yarnpkg.com/#g' yarn.lock",
  });
  expect(exitOf(made) === 0, `yarn 1 lockfile: ${said(made)}`);
  const yarnInstall = `rm -rf node_modules; timeout 300 yarn install --frozen-lockfile --non-interactive --cache-folder $PWD/.y@FRESH@ && ${nodeCheck("node")}`;
  // Without the rewrite yarn 1 asks registry.yarnpkg.com itself: it must not install
  // around the firewall. Here, as on an enforced network, that fails loudly.
  let answer = run(yarn, { files: { ".npmrc": npmrc }, script: yarnInstall });
  expect(exitOf(answer) !== 0 && !answer.stdout.includes(npmInstalled) && /registry\.yarnpkg\.com/.test(said(answer)), `yarn 1 without the rewrite must not install around the firewall: ${said(answer)}`);
  // The documented rewrite, while e2e-left 1.1.0 is blocked: refused with 403.
  const rewrite = "sed -i 's#https://registry.yarnpkg.com/#https://fw1.e2e.test/npm/#g' yarn.lock";
  answer = run(yarn, { files: {}, script: rewrite });
  const rewritten = lockOf(answer);
  answer = run(yarn, { files: { ".npmrc": npmrc }, script: yarnInstall });
  // needs the yarn 1 auth fix (keys-page .npmrc): today yarn 1 sends no key, so this is 401, not 403.
  expect(exitOf(answer) !== 0 && /Request failed "403 Forbidden"|\b403\b.*Forbidden/.test(said(answer)) && lockOf(answer) === rewritten, `yarn 1 (rewritten) is refused the blocked pin with 403: ${said(answer)}`);

  // Unblock: the rewritten yarn.lock installs through the firewall.
  // The npm and the PyPI block read the same on their Remove buttons.
  for (const ecosystem of ["npm", "pypi"]) {
    const removed = await removeOwn(admin.portal, policy, "block", /^Remove the block on e2e-left Version 1\.1\.0$/);
    expect(removed.status === 303, `unblock (${ecosystem}): ${removed.status}`);
  }
  await untilStatus(h, firewalls, "/npm/e2e-left/1.1.0", key, 200, "the unblock reaches the fleet");
  answer = run(yarn, { files: { ".npmrc": npmrc }, script: yarnInstall });
  // needs the yarn 1 auth fix (keys-page .npmrc).
  expect(exitOf(answer) === 0 && answer.stdout.includes(npmInstalled) && lockOf(answer) === rewritten, `yarn 1 (rewritten) installs through the firewall: ${said(answer)}`);
}
