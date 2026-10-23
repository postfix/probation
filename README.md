# probation

[![crates.io](https://img.shields.io/crates/v/probation.svg)](https://crates.io/crates/probation)

A firewall for npm and PyPI packages. You run it yourself, in front of your own
`npm` and `pip` clients.

It runs in two ways:

- **Standalone.** One firewall, one config file, one blocklist, the same rules for
  every client. No logins.
- **Managed.** Firewalls get their rules from a management server,
  `probation-server`. Each request carries an API key, and the firewall applies the
  policy of that key. People sign up, create keys and edit policy in a self-service
  web portal.

It is for teams and companies that install packages from npm and PyPI and want a
delay and a block list between the public registries and their machines. Managed
mode is for one operator who serves many organisations, or one company with many
groups, from a shared fleet of firewalls.

## The problem

A package can be hijacked and a bad version published in seconds. Malware
scanners and blocklists take hours or days to catch up. In that gap, anyone who
installs the package gets the bad version.

## What it does

Probation sits between your developers and the real npm and PyPI registries. It
holds back any version published too recently (you choose how long; the sample
config uses a day). If a newer version is held back, `npm` and `pip` fall back to the
newest version that is allowed, as if the newer one did not exist yet. Nobody
changes what they typed.

It also checks every download against a blocklist you supply, by package name,
by version, or by exact file.

On top of your blocklist, it checks every package against [OSV](https://osv.dev),
a free, open database of known vulnerabilities. This is on by default and needs
no setup. If OSV is slow or unreachable, that never blocks a download. The extra
check is skipped for that request. See [`docs/operations.md`](docs/operations.md)
§4 to tune or disable it.

"Allowed through" means it passed these checks. It is not a guarantee that a
package is safe.

## Features

The firewall (`probation`):

- holds back versions younger than `cooldown_seconds` (a day in the sample config)
- blocks by package, version or exact file (sha256), from a blocklist file it
  reloads while running
- checks OSV for known vulnerabilities (`osv_mode`), failing open
- verifies every file it hands back
- terminates TLS itself (`tls_cert_path`, `tls_key_path`)
- writes one decision line per request, optionally to a file and to a SIEM
- health checks (`/health/live`, `/health/ready`), and `GET /health/delivery` to
  alert on lost log records

Managed mode adds (`probation-server` and the portal):

- many organisations on one installation; no organisation can see another
- personal accounts, separate from organisations
- policy in layers: platform, organisation, group, user. A lower layer may always
  be stricter; it may be looser only where every layer above allows it
- personal API keys, and organisation service keys (for example pushed to devices
  by MDM)
- sign-in with email and password, Google, GitHub, Microsoft, or an
  organisation's own OIDC single sign-on; authenticator codes (TOTP), required
  for admins who sign in with a password
- a network lock: an organisation registers its office and VPN address ranges;
  once the global admin approves them, the fleet refuses any key from those
  ranges that does not belong to that organisation
- activity (blocked, held and refused requests) and an audit log of every change
- a fleet page: register, watch and retire firewalls, and push settings to them
- an automation API to export, replace or add to a layer's blocklist
- policy edits and key revocations reach every firewall within the sync interval
  (`sync_interval_seconds`, default 60). If the server is down, firewalls keep
  serving what they have cached

## Quick start: standalone firewall

Install it:

```sh
cargo install probation --locked
```

No Rust toolchain on this machine? Build it in a container and install the
binary on the host. This needs only Docker or Podman:

```sh
scripts/build-install.sh
```

Check a config file is valid:

```sh
probation check-config config.sample.toml
```

Run it:

```sh
probation serve --config /etc/probation/config.toml
```

Or run it in Docker:

```sh
docker build -t probation .
docker run -d -p 127.0.0.1:8080:8080 \
  -v /srv/probation:/var/lib/probation \
  probation serve --config /etc/probation/config.toml
```

Then point your tools at it instead of the public registries:

```ini
# .npmrc
registry=https://packages.example.org/npm/
audit=false
```

```ini
# pip.conf
[global]
index-url = https://packages.example.org/pypi/simple/
```

`config.sample.toml` and `blocklist.sample.json` show the file formats.

It terminates TLS itself: set `tls_cert_path` and `tls_key_path` in the config,
with no reverse proxy needed. `public_url` must always be `https`, even for
local testing. See [`docs/operations.md`](docs/operations.md) §6 for the
quickest way to get a trusted local certificate.

**Before running this for real, read [`docs/operations.md`](docs/operations.md).**
Two things catch people out: `cache_max_bytes` does not limit the size of its
database (section 3), and it does not limit how many requests one client can
send. Put that limit on the reverse proxy in front of it (section 6).

## Quick start: managed deployment

You need Postgres 16, a TLS reverse proxy in front of `probation-server` (it
listens on plain HTTP only), and one or more firewalls. In short:

1. Build the images, from the repository root:

   ```sh
   docker build -f crates/probation-server/Dockerfile -t probation-server .
   docker build -t probation .
   ```

2. Write the server's settings file (`[server]`, and `[portal]` for the portal),
   and set the secrets in the environment (`PROBATION_SERVER_DATABASE_URL`,
   `PROBATION_SERVER_SECRET_KEY`, …).
3. Apply the schema as the owner role
   (`PROBATION_SERVER_MIGRATE_DATABASE_URL=… probation-server migrate`), then
   create the server's login role in the `probation_app` group.
4. Create the first global admin, an organisation, a service key and a firewall
   token: `probation-server admin bootstrap --config … --email … --org …
   --firewall … --firewall-source …`. With `[portal]` set, it prints a one-time
   set-password link.
5. Start the server: `probation-server serve --config …`.
6. In each firewall's `config.toml`, set the `[management]` section (`url`,
   `token_file`) and run it under a supervisor that restarts it.

People then sign up in the portal, create a key, and paste the `.npmrc` and
`pip.conf` lines the keys page shows. A managed firewall refuses a request
with no valid key.

The full steps are in [`docs/management-server.md`](docs/management-server.md).
`deploy/docker-compose.yml` shows the server and a firewall side by side.

## Supported clients

| Tool | How |
| --- | --- |
| npm, npx | `.npmrc` |
| pnpm | `.npmrc` |
| bun | `~/.npmrc` or the project's `.npmrc` |
| yarn 1 | `.npmrc`; existing `yarn.lock` files need one rewrite |
| corepack | `COREPACK_NPM_REGISTRY` |
| pip, pipx | `pip.conf` |
| uv | its own `uv.toml` |
| Poetry | `poetry source add`, once per project |

conda channels are not supported. Exact settings for each tool are in
[`docs/operations.md`](docs/operations.md) §7, "Clients". The real `npm` and
`pip` clients are tested in CI.

## What it won't catch

It only checks packages as they are downloaded. So it cannot help with:

- packages already installed, or already in a client's local cache
- anything fetched from somewhere other than npm or PyPI: other registries, Git
  URLs, direct downloads, local files
- a lockfile that pins a direct URL instead of a package name and version

It cannot publish packages, and does not scan files for malware itself. It
enforces the blocklist and policy you give it and what OSV reports. Something
else has to produce that blocklist.

Full details: `docs/operations.md`, sections 7 and 12.

## Building and testing

```sh
cargo clippy --workspace --all-targets -- -D warnings
docker compose -f docker-compose.test.yml up -d --wait postgres   # for probation-server's tests
cargo test --workspace                      # no network access needed
cargo test --test e2e_npm -- --ignored      # runs the real npm client
cargo test --test e2e_pip -- --ignored      # runs the real pip client
tests/e2e/signup_to_install.sh              # managed mode, sign-up to npm install
node tests/e2e/harness/run.mjs --suite pr   # the e2e suites (tests/e2e/README.md)
cargo bench                                 # performance checks
cargo bench --bench delivery_rated_load     # a slower one, ~10 minutes
```

You need `cmake`, a C compiler, and `perl` (one crypto library builds from C),
plus the Rust version pinned in `rust-toolchain.toml`. The e2e tests also need
`npm` and `python3` with `pip`, `setuptools`, and `build` installed. The
managed-mode end-to-end test needs Docker with compose; see
[`docs/management-server.md`](docs/management-server.md) §9.

The repository is a Cargo workspace: the firewall is the root crate (`src/`),
`crates/probation-server` is the management server and portal, and
`crates/probation-policy` holds the policy rules both share. `probation-server`
is not published to crates.io.

In testing, the decision-log pipeline handled about **59,000 decisions/second**
with no dropped records. That is the logging ceiling, not overall throughput. See [`docs/operations.md`](docs/operations.md) §8 and §10 for
how that was measured and what it means for sizing your own setup.

## Documents

- [`docs/operations.md`](docs/operations.md): how to run the firewall, its
  limits, backup and restore, measured performance, and what managed mode
  changes for the operator (§13).
- [`docs/management-server.md`](docs/management-server.md): how to run
  `probation-server` and connect firewalls to it.
- [`docs/portal-guide.md`](docs/portal-guide.md): a guide to the self-service portal,
  by role.
- [`docs/api.md`](docs/api.md): the automation API, the sync API, and every
  command and flag of `probation` and `probation-server`.
- [`CHANGELOG.md`](CHANGELOG.md): what changed in each release.
- [`docs/backlog.md`](docs/backlog.md): requested work not yet planned.
- [`SPEC.md`](SPEC.md): the specification the firewall was built from.
- [`docs/plans/`](docs/plans/): the design and planning history, one folder per
  feature.
- [`docs/adr/`](docs/adr/): architecture decision records.

## License

Every release after 0.2.2 is licensed under the
[Elastic License 2.0](LICENSE) (SPDX `Elastic-2.0`). This covers the whole
repository: the firewall, the management server and the portal.

You may use, copy, modify and run Probation, also inside your company. You may
not:

- provide it to others as a hosted or managed service that gives them access to
  a substantial part of its features
- move, change or disable the license key functions, if any
- remove or hide the license, copyright or other notices

Releases 0.1.0 to 0.2.2 remain under the Apache License 2.0.
