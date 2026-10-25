# End-to-end tests

The exact release images (the root `Dockerfile` and `crates/probation-server/Dockerfile`)
run as a deployment would, against local fakes of the public services. The run is
offline and repeatable. The scenario catalogue is `docs/plans/e2e-coverage/00-inventory.md` §3.

## Run it

```sh
npm ci --prefix tests/e2e && npx --prefix tests/e2e playwright install chromium
node tests/e2e/harness/run.mjs --suite pr          # or nightly, release, canary, pbt, pbt-weekly
node tests/e2e/harness/run.mjs --only E2E-signup-to-install --skip-build --keep
node tests/e2e/harness/run.mjs --suite nightly --list
```

You need docker with compose, or podman with podman-compose (`docker compose` is the
default; set `E2E_COMPOSE_CMD=podman-compose` to call it directly), node 20 or later,
and openssl. `tests/e2e/signup_to_install.sh` runs the release witness alone.

| Variable | Default | |
|---|---|---|
| `E2E_WORK` | `target/e2e` | generated CA, configs and tokens. Keep it on disk, not under `/tmp`. |
| `E2E_OUT` | `$E2E_WORK/out` | `junit.xml`, plus `logs/<scenario>/` for each failure: every container's log, the fakes' request log, the mail index |
| `E2E_SKIP_BUILD=1` / `--skip-build` | | use the images already built |
| `E2E_PREBUILT=1` | | the two product images are built already (CI builds them with the Actions cache); build only the clients |
| `E2E_KEEP=1` / `--keep` | | leave the stack running afterwards |
| `E2E_BRIDGE_PORT` | `18128` | the one published port (see below) |
| `E2E_NET`, `E2E_PROJECT` | `11.220.0`, `probation-e2e` | to run two stacks at once |

## The stack

`compose/compose.yml`:

| Service | What it is | Name on the network |
|---|---|---|
| `postgres` | Postgres 16 | `postgres` |
| `server` | management server and portal, plain HTTP | behind the gateway |
| `gateway` | nginx, terminates TLS (the documented topology) | `portal.e2e.test`, `sync.e2e.test`, `fw1.e2e.test`, `fw2.e2e.test`, `fw-standalone.e2e.test` |
| `firewall-1`, `firewall-2` | managed firewalls, sync interval 10 s | via the gateway |
| `firewall-standalone` | no `[management]`; producer file in `$E2E_WORK/producer/blocklist.json` | via the gateway |
| `fakes` | `fixtures/fakes/`: npm, PyPI, OSV, range API, OIDC IdP | `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `api.osv.dev`, `api.pwnedpasswords.com`, `accounts.google.com`, `idp.e2e.test`; control API `http://fakes.e2e.test:8080` |
| `mail` | mailpit, STARTTLS required | `mail.e2e.test` (SMTP 1025, API 8025) |
| `bridge` | `fixtures/bridge.mjs`, the host's CONNECT proxy into the network | `127.0.0.1:$E2E_BRIDGE_PORT` |
| `client-*` | pinned client containers (`sleep infinity`) | |

How the stack stays offline and still tests the shipped binary (D1):

- Everything except the bridge is on `e2e`, an `internal` network, so it has no route out.
  Its subnet `11.220.0.0/24` is ordinary public unicast. The firewall's origin guard
  (`src/upstream/resolver.rs::is_public`) and the server's guard therefore accept it.
  It is not in any range the guard refuses: RFC 1918, 100.64/10, 198.18/15, the
  documentation ranges, 0/8, 240/4 and so on. It shadows nothing the stack needs, and
  nothing a CI host reaches: no service the stack or CI uses lives in 11.220.0.0/24.
- The fakes hold the real hostnames as network aliases. `fixtures/make-ca.sh` makes a CA
  per run and one certificate for every name. Only the test stack trusts the CA:
  `SSL_CERT_FILE=/e2e/ca/ca.pem`. Both binaries verify TLS through rustls-native-certs,
  which honours `SSL_CERT_FILE` and `SSL_CERT_DIR`. So no system root is trusted either,
  and a request that leaked to the real internet would fail.
- The host reaches the stack only through the bridge. The harness's HTTP client and
  Chromium both tunnel through it. Every service then has the same name, port and
  certificate from the host as from inside. The bridge opens tunnels only to addresses
  on `e2e`.

The canary suite adds `compose/canary.yml`. The fakes are not started. The server and
the firewalls also join the `edge` network and trust the system roots.

Clients (D2), in `compose/clients/`:

| Suite | Services |
|---|---|
| PR and up | `client-npm` (npm 12.2.1 on Node 24), `client-pip` (pip 26.2.2 on Python 3.15) |
| nightly, release | `client-npm10` (Node 22), `client-npm11` (Node 24), `client-js` (pnpm 12.15.0, yarn 1.22.22), `client-yarn-berry` (yarn 4.18.1), `client-bun` (bun 1.4.4), `client-pip-previous` (pip 26.1.2), `client-uv` (uv 0.13.5), `client-poetry` (poetry 2.5.1) |

Each client trusts the e2e CA (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `PIP_CERT`,
`REQUESTS_CA_BUNDLE`).

## Stack start

`harness/stack.mjs` does what an operator does once: it migrates, creates the app role,
and runs `admin bootstrap` (firewall-1's token, the Operators org and its key, the
set-password link). The operator's global admin sets its password from that link and
turns on its authenticator. It registers firewall-2 on `/fleet`, and firewall-2 starts
with that token. Scenarios get the signed-in operator as `h.operator` (`portal`,
`email`, `password`, `auth`) and the bootstrap output as `h.bootstrap` (`key`,
`firewall_token`, `org`, ...).

Every `Portal` and every browser context is a separate person with an address of its
own in 10.200.0.0/16. The harness sends that address in `X-Forwarded-For`. The server
trusts the bridge (`.11`) and the gateway (`.10`) as proxies, as a real load balancer in
front of nginx is trusted. So its per-address limits (`MAIL_PER_IP`, the sign-in
throttle) count people, not the one host every harness request comes from. A
scenario that wants one address for several requests passes it:
`new h.Portal(undefined, "10.200.0.7")`.

Between scenarios the fakes go back to their seed state and the mail sink is emptied.
The database is not reset. Each scenario makes its own accounts, orgs, keys and package
names (`h.unique()`), so scenarios share one stack and run in any order. A scenario that
breaks the stack (outages, restore, upgrade, disk full) sets `stack: "own"` and gets a
fresh stack: new database, new bootstrap, new volumes.

## Add a scenario

One file per scenario in `scenarios/`:

```js
export const meta = {
  id: "E2E-002",
  title: "npm block, refuse and unblock on two firewalls",
  suites: ["pr", "nightly", "release"], // any of pr, nightly, release, canary
  // stack: "own",                       // only if it breaks the stack
};

export default async function (h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key, npmrc } = await h.createKey(admin.portal);
  await h.editPolicy(admin.portal, { action: "add_block", ecosystem: "npm", name: "e2e-left", what: "version", version: "2.0.0" });
  await h.waitFor("the block reaches fw1", async () => (await h.request(`${h.firewalls.fw1}/npm/e2e-left/2.0.0`, { headers: { authorization: `Bearer ${key}` } })).status === 403, { timeout: 2 * h.syncInterval * 1000 });
  const run = h.npm("install e2e-left", { npmrc });
  h.expect(run.status === 0, run.stderr);
}
```

In managed mode the bootstrap organisation starts with no
release-age freeze and no OSV check (C125, the user's decision). A version published an
hour ago installs, and so does one OSV flags as `MAL-`. A scenario that needs a freeze or
OSV enforcement sets that policy first: the platform layer as `h.operator`, or the org's
own layer. The standalone firewall has `osv_mode = "enforce"` and the sample's 24-hour
cooldown from its config file.

A thrown error fails the scenario. Wait for a condition with a deadline (`h.waitFor`),
never for a fixed time. There are no automatic retries.

What `h` offers (`harness/helpers.mjs`):

| Helper | |
|---|---|
| `h.signUp({kind, email, password, org})` | sign-up, confirmation from the mail, sign-in, through the portal's forms (API steps). Gives `{email, password, org, portal}` |
| `h.enableTotp(who)` | turns the authenticator on and signs in again with a code; `who.auth.code()` gives fresh codes |
| `h.createKey(portal, name)` | `{key, npmrc, pipConf}` as the keys page shows them |
| `h.policyPath(portal)`, `h.editPolicy(portal, fields)` | the policy page and one form post (`action: add_block`, ...) |
| `h.activity(portal)` | the `/activity` rows |
| `h.browser()` | a Playwright Chromium context (D3), with `browserSignUp`, `browserSignIn`, `browserCreateKey` |
| `h.npm(args, {npmrc, client})`, `h.pip(args, {pipConf, client})`, `h.client(service, script, {files})` | a command in a client container, in a fresh directory; `{status, stdout, stderr}` |
| `h.mail.latest(to)`, `h.mail.link(to, /path/)`, `h.mail.purge()` | mail from the sink |
| `h.fakes.publishNpm`, `publishPypi`, `osvFlag`, `osvQueries`, `faults`, `requests`, `leakPassword`, `oidcNext`, `oidcRotate` | set the fakes' state (`fixtures/fakes/main.mjs` documents the fault modes) |
| `h.request(url, {method, headers, body})` | any HTTP call into the stack, by its own names |
| `h.stack.sql(statement)`, `h.backdate(table, column, interval, where)` | SQL as the owner; back-dating plus `h.restart("server")` drives the 30-day and 15-minute timers (D10) |
| `h.restart`, `h.stop`, `h.start`, `h.postgresDown`, `h.postgresUp`, `h.firewallReady("fw1")` | service control |
| `h.operator`, `h.bootstrap`, `h.firewalls`, `h.syncInterval`, `h.unique()` | |

The deployment and operations scenarios (E2E-005 to E2E-010) also use
`harness/ops.mjs` (`const o = ops(h)`): the engine itself (`o.inspect`, `o.state`,
`o.exits`, `o.logs`), one-off server commands (`o.server(["admin", ...])`), SQL as the
app role (`o.sqlAs`), a fresh database (`o.freshDatabase`), commands in the background
(`o.background`), the fleet page (`o.fleet`, `o.push`), the sync proxy failing
(`o.syncProxy(false)`), and firewall containers outside compose (`o.firewall({name,
config, token, image, volume, ...})`, removed by `o.removeExtras()`).
`o.needs("F8", ok, message)` records a check that waits for a known product fix and lets
the scenario go on; `o.settle()` fails it at the end. The log collector a firewall can
ship to is `https://fakes.e2e.test/siem`; its batches are at
`http://fakes.e2e.test:8080/siem/batches`. E2E-010 takes the previous release from
`E2E_PREV_FIREWALL_IMAGE` and `E2E_PREV_SERVER_IMAGE`, or builds it from `E2E_PREV_REF`
(default: the newest `v*` tag before HEAD, so the checkout needs its tags);
`E2E_BUILD_CPUSET` pins that build to some CPUs.

The fakes' seed catalogue (`fixtures/fakes/npm.mjs`, `pypi.mjs`) is all older than 200
days.

- npm: `e2e-left` 1.0.0, 1.1.0 and 2.0.0; `e2e-right` 1.0.0, which depends on
  `e2e-left ^1.0.0`; `@e2e/scoped` 1.0.0 and 1.0.1; `e2e-many` 1.0.0 to 1.59.0.
- PyPI: `e2e-left` 1.0.0 and 1.1.0, and `Foo_Bar` 1.0.0, each as a wheel and an sdist.
- Publish a version "1 hour old" with
  `h.fakes.publishNpm({name, version, ageSeconds: 3600})`.
- The sdists name `flit_core` as their build backend, and the fakes do not serve it. An
  sdist-only install needs the backend published, or `--no-build-isolation` in an image
  that has it.

## Accessibility walk (D11)

`a11y/axe.mjs` is the A11Y-axe and keyboard walk of slices 5 to 7 (C84). Its nightly scenario
`scenarios/a11y-axe.mjs` runs on a stack of its own: it loads
`crates/probation-server/tests/seed.sql`, then walks each slice in Chromium through the
bridge, against the deployed portal behind the TLS gateway. It still runs by hand against
`cargo run -p probation-server -- serve --config crates/probation-server/tests/portal.toml`
with `PORTAL_URL`.

## Property-based tests

`harness/pbt.mjs` and `harness/pbt-forms.mjs` test the portal with
[fast-check](https://fast-check.dev) against the deployed stack. `harness/pbt-model.mjs`
is the model they check against: roles and visibility as `tenancy.rs` has them, and a
port of `crates/probation-policy`'s merge and edit check
(`node tests/e2e/harness/pbt-model.mjs` runs its self-check).

**PBT-model** (`fc.commands`, `fc.asyncModelRun`). Each run starts from a fixed cast
(`cast` in `pbt.mjs`): two organisations, a group, members, a personal account and their
keys. Then random commands follow: sign-up with the confirmation mail, sign-in and
sign-out, the authenticator on and off, groups, invitations accepted or ignored, roles,
moving and removing members, leave requests approved or refused, keys and service keys
and their revocation, blocks (package, version, file), exceptions, freezes and switches,
the platform's freeze, OSV setting and switches (as the operator), the place
switcher, suspending and re-activating an organisation (as the operator), and deleting
and restoring a login. Each command is tried by a person whose role allows it or, a
third of the time, by anyone, so refusals are tested too. After every command:

- each person's places, keys, organisation pages and policy editor match the model, and
  another tenant's ids answer 404 and name nothing of it (C1);
- a member who is not an org admin gets no admin forms, and an org admin without a
  second factor is sent to set one up or sees the layer read-only (C24, C27);
- the audit log has exactly the command's rows, and a refusal writes none;
- every portal answer is below 500, carries the security headers (CSP with
  `frame-ancestors 'none'`, `nosniff`, `no-referrer`, `no-store`) and shows no key
  after the answer that created it.

`CheckFirewall`, and the end of each run, ask fw1 or fw2 for a sample of keys what the
model's effective policy says: blocked, held, allowed, or 401 for a key that no longer
works, within one sync interval. The sample includes npm and PyPI versions flagged
`MAL-*` by the fake OSV service, under randomly edited On, Log only and Off settings.
axe checks a sample of the pages the run reached.

Mail: a link is opened from the server's sealed outbox row with the stack's generated
secret key as soon as it is queued, and at the
end every one of them must have reached the SMTP sink. The outbox job sends every 30 s,
too slow to wait for in each command. `E2E_PBT_MAIL=sink` waits in the sink instead.

**PBT-forms** puts random strings into one field of one form at a time, including the
fleet's retirement confirmation: unicode with confusables, zero-width
and bidi characters, HTML and script fragments, very long, empty and whitespace values,
SQL-ish text, malformed emails, CIDR ranges and versions. The value is refused with a
message and nothing changes, or it is stored and shown escaped (checked in the page and
in Chromium's DOM). Without its CSRF token, or with another session's, every form
answers 403 and writes nothing. Fleet settings push and rollout controls get the CSRF
check; E2E-007 exercises their valid state transitions.

A failure is shrunk to a minimal case. Its message, also the JUnit failure message,
starts with the seed and the path, and lists the command sequence. Replay it:

```sh
E2E_PBT_SEED=… E2E_PBT_PATH=… E2E_PBT_REPLAY='…' node tests/e2e/harness/run.mjs --only PBT-model --suite pbt
```

| Variable | `pr` (PBT-smoke) | `pbt` | `pbt-weekly` | |
|---|---|---|---|---|
| `E2E_PBT_RUNS` | 1 | 20 | 100 | command sequences |
| `E2E_PBT_COMMANDS` | 8 | 25 | 40 | the longest sequence |
| `E2E_PBT_TIME_LIMIT` | 90 | 660 | 6000 | seconds for runs and shrinking |
| `E2E_PBT_MAX_SHRINKS` | 0 | 40 | 200 | |
| `E2E_PBT_FIREWALL_SAMPLE` | 1 | 3 | 4 | key and version pairs per firewall check |
| `E2E_PBT_AXE_SAMPLE` | 1 | 1 | 2 | pages per run |
| `E2E_PBT_FORM_RUNS` | | 400 | 4000 | values PBT-forms tries |
| `E2E_PBT_DOM_SAMPLE` | | 10 | 40 | stored HTML values checked in Chromium |
| `E2E_PBT_SEED` | 20261054 | random | random | |

Also `E2E_PBT_PATH`, `E2E_PBT_REPLAY`, `E2E_PBT_PEOPLE` (8), `E2E_PBT_MAIL` and
`E2E_PBT_VERBOSE=1` (every command and its answer). A check that waits on a known
product fix is logged as "needs F…" and fails the scenario at its end, as `Needs` does.
A product defect a run finds becomes a fixed sequence in `scenarios/pbt-regressions.mjs`.

## Suites

| Suite | When | Clients | Blocks |
|---|---|---|---|
| `pr` | every pull request (`.github/workflows/e2e.yml`, 20 min) | PR clients | the merge |
| `nightly` | nightly on main (90 min) | all | opens an issue |
| `canary` | nightly, live registries (`canary.yml`) | PR clients | nothing; opens an issue |
| `release` | on a tag (`release.yml`, 2 h), before anything is published | all | the release and the image push (D7) |
| `pbt` | nightly, a job and stacks of its own (30 min) | PR clients | opens an issue |
| `pbt-weekly` | Sundays (150 min) | PR clients | opens an issue |

### Image builds in CI

Both Dockerfiles build in stages through cargo-chef. One layer holds the compiled
dependencies, and only a change to `Cargo.toml` or `Cargo.lock` invalidates it. A second
layer compiles this workspace's own crates. The runtime stage is unchanged. `e2e.yml`
builds both images with buildx and the GitHub Actions cache (`mode=max`, one scope per
image), then runs the harness with `E2E_PREBUILT=1`. The release gate builds without a
cache, so nothing a branch wrote into the cache can reach a published image.

Measured locally with 16 cores (`podman build --no-cache`):

| Image | Cold | Dependencies cached | CPU time, cold |
|---|---|---|---|
| firewall | 2 min 32 s (dependencies 1 min 23 s) | 12 s of compiling | 11 min 54 s user |
| server | 2 min 10 s (dependencies 49 s) | 20 s of compiling | 7 min 3 s user |

Estimate for the PR suite on a hosted 4-vCPU runner:
- setup: 1 to 1.5 min (checkout, `npm ci`, Chromium with its system dependencies);
- images, dependencies cached: 3 to 5 min, mostly restoring the cache;
- images, cold (a lock change, or the first run): 8 to 10 min;
- pulls and client images: about 2 min;
- stack start: under 1 min;
- E2E-signup-to-install: under 1 min.

That leaves 10 to 12 min for the other PR scenarios on a warm cache, and 6 to 8 min on a
cold one.

