# Running the management server

How to run `probation-server` and point firewalls at it. In managed mode each firewall
serves every request under the policy of the API key it carries: the server holds the
keys, the organisations and their policy layers, and the self-service portal where
people sign up, create keys and edit policy. Firewalls fetch what they need and cache
it; they never take requests from the server.

Licensed under the Elastic License 2.0 (`Elastic-2.0`), like the rest of the
repository; see [LICENSE](../LICENSE).

Operating the firewall itself (disk, blocklist, logs, TLS) is in
[operations.md](operations.md). For both programs, backups and restores are in its
section 5, TLS and reverse proxies in section 6, and the release recovery in section
20. What the portal offers each role is in [portal-guide.md](portal-guide.md). Every
command, flag and API route is in [api.md](api.md).

---

## 1. What runs where

| Piece | Talks to | Notes |
| --- | --- | --- |
| `probation-server` | Postgres | One process: the sync API for firewalls, the automation API, and the portal when `[portal]` is set. Keeps no state on disk. |
| Postgres 16 | — | Everything the server knows. Back it up (operations.md §5). |
| Your TLS reverse proxy | the server | The server listens on **plain HTTP only**. Firewalls refuse a management URL that is not `https` (loopback included), so a proxy in front is required. |
| Each firewall (`probation`) | the server through the proxy; npm, PyPI, OSV | A `[management]` section in its `config.toml` makes it managed. |

The server answers three groups of routes on one port:

- **Sync API** (`POST /api/v1/sync/lookup`, `/api/v1/sync/layers`,
  `/api/v1/sync/changes`). Only firewalls call it, each with its own `fwt_` token. A
  firewall asks for a key it has not seen (`lookup`), fetches policy layers
  (`layers`), and every `sync_interval_seconds` asks what changed since the last
  revision it applied (`changes`). The `changes` call also carries the firewall's
  health report and brings back pushed settings.
- **Automation API** (`GET`, `PUT`, `POST /api/v1/blocklist/{layer}`). Exports,
  replaces or adds to the blocks of one layer, with an `aut_` token made for that
  layer on the organisation page or on `/admin`.
- **Portal** (only with `[portal]`): sign-up and sign-in, `/account`, `/keys`,
  `/policy`, `/activity`, `/audit`, `/org`, and for global admins `/admin` and
  `/fleet`.

## 2. Images and deploy examples

```sh
docker build -f crates/probation-server/Dockerfile -t probation-server .
docker build -t probation .
```

Both build from the repository root. The server image runs `probation-server serve
--config /etc/probation-server/config.toml` as the non-root user `probation`; mount
your settings file there and pass the secrets (§3) as environment variables. The
firewall image runs as the user `firewall`.

- `deploy/docker-compose.yml` runs the server and one managed firewall side by side.
  Postgres is yours. The server reads its secrets from `server.env` and its settings
  from `./server.toml`; the firewall mounts `./config.toml` and `./firewall.token`.
  Both ports are published on `127.0.0.1` only, for your TLS proxy. Copy it and edit
  it; the tests do not use it.
- `deploy/probation.service` runs a firewall from the binary under systemd.

## 3. The server's settings file

```toml
[server]
listen = "0.0.0.0:8080"
trusted_proxies = ["10.0.0.0/8"]
change_log_retention_days = 7

[portal]
base_url = "https://manage.example.org/"
firewall_url = "https://packages.example.org"

[portal.google]
client_id = "…"
[portal.github]
client_id = "…"
[portal.microsoft]
client_id = "…"

[portal.smtp]
host = "smtp.example.org"
port = 587
username = "probation"
from = "Probation <probation@example.org>"
```

The file is passed with `--config` to `serve`, `admin bootstrap` and `admin reset-link`.
Unknown keys are refused at start, and every change needs a restart. Every setting:

| Setting | Default | What |
| --- | --- | --- |
| `[server] listen` | required | Address and port, plain HTTP. |
| `[server] trusted_proxies` | `[]` | Your reverse proxies and load balancers (address ranges). Only from these peers is `X-Forwarded-For` read: the client is the rightmost entry that is not itself a listed proxy. Used for a firewall token's source check and for sign-in throttling. |
| `[server] change_log_retention_days` | `7` | How long change rows are kept; not zero. A firewall offline for longer resets its cache when it comes back. |
| `[portal]` | absent | Leave the whole section out to serve only the sync and automation APIs. Then nobody can sign in, and `admin bootstrap` prints no sign-in link (§5). |
| `[portal] base_url` | required in `[portal]` | The portal's public address. Every emailed link and every OAuth callback is built from it. |
| `[portal] firewall_url` | unset | The firewalls' public address, as npm and pip reach it. The keys page builds the `.npmrc` and `pip.conf` lines from it; unset, they show a `FIREWALL` placeholder. It needs a host and `https` (`http` only for `localhost` or a loopback address); anything else is refused at start. |
| `[portal] leaked_password_url` | `https://api.pwnedpasswords.com/range/` | The range API that new passwords are checked against. |
| `[portal.google]`, `[portal.github]`, `[portal.microsoft]` | absent | A sign-in provider each. Only `client_id` goes here; the client secret comes from the environment. Register `<base_url>oauth/google/callback` (or `github`, `microsoft`) as the redirect URI at the provider. |
| `[portal.smtp] host` | required in `[portal.smtp]` | The mail relay. STARTTLS only. |
| `[portal.smtp] port` | `587` | |
| `[portal.smtp] username` | unset | Signs in to the relay with `PROBATION_SERVER_SMTP_PASSWORD`. |
| `[portal.smtp] from` | required in `[portal.smtp]` | The sender address. |

Without `[portal.smtp]` mail stays in the `email_outbox` table, and nobody can confirm
an email address.

An organisation's own SSO (OIDC) is set on its organisation page, not in this file.
Its redirect URI is `<base_url>sso/<org id>/callback`; the page shows it.

Two more settings live in the database and are changed on `/admin` by a global admin:
the retention of the activity log (default 90 days) and of the audit log (default 365
days), each at least 7 days.

### Environment variables

Secrets come only from the environment, never from the file:

| Variable | Used by | What |
| --- | --- | --- |
| `PROBATION_SERVER_DATABASE_URL` | `serve`, `admin …` | A login role that is a member of `probation_app` (§4). Owns nothing. |
| `PROBATION_SERVER_MIGRATE_DATABASE_URL` | `migrate` | The schema owner. Needs `CREATEROLE` on the first run. |
| `PROBATION_SERVER_SECRET_KEY` | `serve` with `[portal]` | 64 hex characters (32 bytes), for example from `openssl rand -hex 32`. Seals secrets stored in the database (authenticator keys, SSO client secrets). Losing it loses them; keep it with the database backups, but apart from them. |
| `PROBATION_SERVER_GOOGLE_CLIENT_SECRET`, `PROBATION_SERVER_GITHUB_CLIENT_SECRET`, `PROBATION_SERVER_MICROSOFT_CLIENT_SECRET` | `serve` | Required for each provider section you set. |
| `PROBATION_SERVER_SMTP_PASSWORD` | `serve` | With `[portal.smtp] username`; empty when unset. |
| `RUST_LOG` | all | Log filter; default `info`. Logs go to stderr. |

`serve` stops at start with `… is not set` when a variable it needs is missing.

## 4. Migrations and database roles

The schema is built into the binary; `probation-server migrate` applies whatever is
new. Run it as the schema owner, before the first start and again before starting
each new server version:

```sh
PROBATION_SERVER_MIGRATE_DATABASE_URL=postgres://owner:…@db/probation probation-server migrate
```

The first run creates the `probation_app` group role (so the owner needs
`CREATEROLE` then). The server itself connects as a login in that group, which owns
nothing and cannot change or delete audit log rows. Create it once:

```sql
CREATE ROLE probation_server LOGIN PASSWORD '…' IN ROLE probation_app;
```

The server waits at most 1 second for a free database connection and for each
statement, so a stuck database answers an error before a firewall gives up waiting.

## 5. First run

1. Apply the schema and create the login (§4).

2. Create the first global admin, an organisation, a service key and a firewall token:

   ```sh
   probation-server admin bootstrap --config /etc/probation-server/config.toml \
     --email ops@example.org --org "Example" --firewall fw-1 \
     --firewall-source 203.0.113.10/32
   ```

   It prints `global_admin_login`, `org`, `key_id`, `key`, `firewall_id`,
   `firewall_token` and a `set_password_link` once, on this console only; only hashes
   are stored and no mail is sent. The global admin's sign-in is `--email`, already
   confirmed because you vouch for it. Open the link (it works once, for 60 minutes,
   and is built from `[portal] base_url`) to choose the password, then sign in: the
   portal first asks for an authenticator app, and `/admin` and `/fleet` open once it
   is set up. Bootstrap refuses to run a second time.

   Without a `[portal]` section it still creates everything but prints, instead of a
   link, ``note: no [portal] base_url: no sign-in link; add [portal] and run `admin reset-link` later``.

   `--firewall-source` is required and repeatable: the address ranges the token is
   accepted from. Behind a load balancer, list the balancer in `[server]
   trusted_proxies` and give the firewall's own address here.

   Lost the link, or it expired? `probation-server admin reset-link --config … --email
   ops@example.org` prints a fresh one for that global admin (audited). A new link
   cancels every older one, and setting a password through one cancels the rest. It
   changes only the password: an authenticator already set up is still asked for.
   Anyone who knows the admin's address can also request a self-service password
   reset, which cancels the printed link; if the link stops working, run `admin
   reset-link` again.

3. Start the server (`probation-server serve --config …`), with its port published only
   to your TLS proxy.

4. Configure each firewall: start from `config.sample.toml`, uncomment its
   `[management]` section, set `url` to the server's https address and put the token in
   the file `token_file` names. In the container image, the `config.toml` you mount
   must set `listen = "0.0.0.0:8080"` (the sample's `127.0.0.1` is unreachable from
   outside the container), and the token file must be readable by the image's
   `firewall` user. The top-level `sync_interval_seconds` (default 60) is how long an
   edit or a revocation may take to reach the firewall. Start it with a restart
   policy (§6). More firewalls are registered on `/fleet`, which prints each new
   token once.

People then sign up at `base_url`, confirm their email, create a key and paste the lines
the keys page shows into `.npmrc` or `pip.conf`.

## 6. Settings pushes need a restart policy

A global admin can push firewall settings from `/fleet` to chosen firewalls. The push
is a rollout: the firewalls get it one at a time, in the order chosen, and the next
one gets it only after the one before reports success. A firewall that reports an
error, or does not report success within 3 of its sync intervals, halts the rollout;
the page then offers "Skip" (go on with the next firewall) and, after a timeout,
"Resume" (send it again). A firewall still in an unfinished rollout cannot get a new
one.

Settings that belong to one machine cannot be pushed: `management`, `listen`,
`data_dir`, `tls_cert_path`, `tls_key_path`, `public_url`, `siem_url`,
`siem_auth_header`. `npm_upstream_url`, `pypi_upstream_url` and `pypi_artifacts_url`
must be `https://`. Such a push is refused before it is saved. A pushed path must lie
under the firewall's `data_dir`; the firewall checks that itself.

A firewall has no live reload: it checks the pushed settings, writes them to
`<data_dir>/managed-settings.toml` (never to your `config.toml`), drains, and exits with
code 75 so its supervisor starts it again on the new settings. An overlay that fails
validation at start is swapped back for the previous one and the error is reported on
the fleet page, so a bad push never loops.

So every managed firewall needs a supervisor that restarts it: `restart: unless-stopped`
in compose, `Restart=on-failure` under systemd. Both examples in `deploy/` have it.

## 7. Commands

| Command | What |
| --- | --- |
| `probation-server serve --config FILE` | The server. Every hour it prunes change rows, the activity log and the audit log by their retention. |
| `probation-server migrate` | Applies the schema (owner role, §4). |
| `probation-server admin bootstrap --config FILE --email ADDR --org NAME --firewall NAME --firewall-source CIDR…` | First run only (§5). |
| `probation-server admin reset-link --config FILE --email ADDR` | A fresh set-password link for a global admin (§5). Needs `[portal]` in the file. |
| `probation-server admin revoke-key --key-id N` | Revokes any key; every firewall stops accepting it within one sync interval. Works without a running server. |
| `probation-server admin after-restore` | After restoring the database from a backup, before starting the server (operations.md §5). |

Every flag and what each command prints: [api.md](api.md#3-commands) §3.
`probation-server --help` and `--version` work as usual. The `admin` commands need
`PROBATION_SERVER_DATABASE_URL`, and are recorded in the audit log as the operator.

## 8. Security notes

- **Admins need an authenticator app.** A global admin or an organisation admin who
  signs in with a password gets no admin rights until their login has an
  authenticator (TOTP) set up; the portal sends them to `/account` to set it up.
  A sign-in through Google, GitHub, Microsoft or the organisation's SSO counts as
  checked by that provider. `admin reset-link` sets only the password, never the
  authenticator.
- **Firewall tokens work only from their source ranges.** A `fwt_` token is accepted
  only from the ranges given at registration (`--firewall-source`, or on `/fleet`);
  from anywhere else the sync API answers 403 with `FIREWALL_SOURCE_REFUSED` in its
  `x-probation-error` header. Behind a proxy
  that is not in `[server] trusted_proxies`, every firewall looks like the proxy.
- **Only the host operator runs the `admin` commands.** No API route or portal page
  reaches `bootstrap`, `reset-link`, `revoke-key` or `after-restore`; they need the
  database URL. `after-restore` in particular exists only on the command line.
- **Links printed by `bootstrap` and `reset-link` are passwords.** Whoever opens one
  first sets the password.
- **TLS is the proxy's job.** The server speaks plain HTTP; publish its port only to
  the proxy.
- **The secret key seals stored secrets.** Without `PROBATION_SERVER_SECRET_KEY`, the
  authenticator and SSO secrets in the database cannot be read.

## 9. The end-to-end test

`tests/e2e/signup_to_install.sh` builds both images, starts `docker-compose.e2e.yml`
(Postgres, the server, a TLS proxy and two managed firewalls), signs a new organisation
up, installs a package with npm through a firewall, and measures how fast policy edits
and key revocations reach both firewalls. It needs docker with compose, node 20 or
later, npm, openssl, curl and outbound https to registry.npmjs.org, api.osv.dev and
api.pwnedpasswords.com. The release workflow runs it, and nothing is released unless it
prints `E2E PASS` and both `propagation … p99 <= interval` lines. The seconds on the
`E2E PASS` line run from the sign-up page to `npm install` finishing; building the
images and starting the stack happen before that clock starts. Firewall-2 is
registered by the global admin `admin bootstrap` created, through its set-password
link.
