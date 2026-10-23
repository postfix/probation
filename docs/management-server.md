# Running the management server

How to run `probation-server` and point firewalls at it. In managed mode each firewall
serves every request under the policy of the API key it carries: the server holds the
keys, the organisations and their policy layers, and the self-service portal where
people sign up, create keys and edit policy. Firewalls fetch what they need and cache
it; they never take requests from the server.

Licensed under the Elastic License 2.0 (`Elastic-2.0`), like the rest of the
repository; see [LICENSE](../LICENSE).

Operating the firewall itself (disk, blocklist, logs, TLS) is in
[operations.md](operations.md). Backups, restores, reverse proxies and the release
recovery for both are in its section 13.

---

## 1. What runs where

| Piece | Talks to | Notes |
| --- | --- | --- |
| `probation-server` | Postgres | One process: the sync API for firewalls (`/api/v1/sync/…`), the automation API, and the portal when `[portal]` is set. Keeps no state on disk. |
| Postgres 16 | — | Everything the server knows. Back it up (operations.md §13). |
| Your TLS reverse proxy | the server | The server listens on **plain HTTP only**. Firewalls refuse a management URL that is not `https` (loopback included), so a proxy in front is required. |
| Each firewall (`probation`) | the server through the proxy; npm, PyPI, OSV | A `[management]` section in its `config.toml` makes it managed. |

## 2. Images

```sh
docker build -f crates/probation-server/Dockerfile -t probation-server .
docker build -t probation .
```

Both build from the repository root. The server image runs `probation-server serve
--config /etc/probation-server/config.toml` as a non-root user; mount your settings
file there. `deploy/docker-compose.yml` shows both images side by side, and
`deploy/probation.service` runs a firewall from the binary under systemd.

## 3. The server's settings file

```toml
[server]
listen = "0.0.0.0:8080"
# Your reverse proxies. Only from these peers is X-Forwarded-For read, both for a
# firewall's token source check and for the portal's sign-in throttling.
trusted_proxies = ["10.0.0.0/8"]
# How long change_log rows are kept (default 7). A firewall offline for longer
# resets its cache when it comes back.
change_log_retention_days = 7

# Leave the whole section out to serve only the sync and automation APIs. Then
# `admin bootstrap` prints no sign-in link (§4) and nobody can sign in until you add it.
[portal]
# The portal's public address: every emailed link is built from it.
base_url = "https://manage.example.org/"
# The firewalls' public address, as npm and pip reach it. The keys page builds the
# .npmrc and pip.conf lines from it; unset, they show a FIREWALL placeholder. It needs
# a host and https (http only for a loopback host); anything else is refused at start.
firewall_url = "https://packages.example.org"
# leaked_password_url = "https://api.pwnedpasswords.com/range/"   # the default

# Sign-in providers: each one you list needs its client secret in the environment.
[portal.google]
client_id = "…"
[portal.github]
client_id = "…"
[portal.microsoft]
client_id = "…"

# Without [portal.smtp] mail stays in the email_outbox table and nobody can confirm
# an address. STARTTLS only.
[portal.smtp]
host = "smtp.example.org"
port = 587
username = "probation"
from = "Probation <probation@example.org>"
```

Unknown keys are refused at start.

Secrets come only from the environment, never from the file:

| Variable | Used by | What |
| --- | --- | --- |
| `PROBATION_SERVER_DATABASE_URL` | `serve`, `admin …` | A login role that is a member of `probation_app` (see §4). Owns nothing. |
| `PROBATION_SERVER_MIGRATE_DATABASE_URL` | `migrate` | The schema owner. Needs `CREATEROLE` on the first run. |
| `PROBATION_SERVER_SECRET_KEY` | `serve` with `[portal]` | 64 hex characters (32 bytes). Seals secrets stored in the database (TOTP keys, SSO client secrets). Losing it loses them; keep it with the database backups, apart from them. |
| `PROBATION_SERVER_GOOGLE_CLIENT_SECRET`, `…_GITHUB_…`, `…_MICROSOFT_…` | `serve` | One for each provider section you set. |
| `PROBATION_SERVER_SMTP_PASSWORD` | `serve` | With `[portal.smtp] username`. |

## 4. First run

1. Apply the schema as the owner:

   ```sh
   PROBATION_SERVER_MIGRATE_DATABASE_URL=postgres://owner:…@db/probation probation-server migrate
   ```

   This creates the `probation_app` group role. Create the login the server connects
   as, once:

   ```sql
   CREATE ROLE probation_server LOGIN PASSWORD '…' IN ROLE probation_app;
   ```

   Run `migrate` again before starting each new server version.

2. Create the first global admin, an organisation, a service key and a firewall token:

   ```sh
   probation-server admin bootstrap --config /etc/probation-server/config.toml \
     --email ops@example.org --org "Example" --firewall fw-1 \
     --firewall-source 203.0.113.10/32
   ```

   It prints the key, the firewall token and a `set_password_link` once, on this
   console only; only hashes are stored and no mail is sent. The global admin's sign-in
   is `--email`, already confirmed because you vouch for it. Open the link (it works
   once, for 60 minutes, and is built from `[portal] base_url`) to choose the
   password, then sign in: the portal first asks for an authenticator app, and `/admin`
   and the fleet page open once it is set up (C24). Bootstrap refuses to run a second
   time. Without a `[portal]` section in the settings file it still creates everything
   but prints, instead of a link, `note: no [portal] base_url: no sign-in link; add
   [portal] and run `admin reset-link` later`. `--firewall-source` (repeatable) lists the addresses the token is accepted
   from; behind a load balancer, list the balancer in `[server] trusted_proxies` and
   give the firewall's own address here.

   Lost the link, or it expired? `probation-server admin reset-link --config … --email
   ops@example.org` prints a fresh one for that global admin (audited). A new link
   cancels every older one, and setting a password through one cancels the rest. It
   changes only the password: an authenticator already set up is still asked for.

3. Start the server (`probation-server serve --config …`), with its port published only
   to your TLS proxy.

4. Configure each firewall: start from `config.sample.toml`, uncomment its
   `[management]` section, set `url` to the server's https address and put the token in
   the file `token_file` names. In the container image, the `config.toml` you mount
   must set `listen = "0.0.0.0:8080"` (the sample's `127.0.0.1` is unreachable from
   outside the container), and the token file must be readable by the image's
   `firewall` user. Set `sync_interval_seconds` (default 60): that is how
   long an edit or a revocation may take to reach the firewall. Start it with a restart
   policy (§5).

People then sign up at `base_url`, confirm their email, create a key and paste the lines
the keys page shows into `.npmrc` or `pip.conf`.

## 5. Settings pushes need a restart policy

A global admin can push settings to firewalls from the fleet page, one firewall at a
time. A firewall has no live reload: it checks the pushed settings, writes them to
`<data_dir>/managed-settings.toml` (never to your `config.toml`), drains, and exits with
code 75 so its supervisor starts it again on the new settings. An overlay that fails
validation at start is swapped back for the previous one and the error is reported on
the fleet page, so a bad push never loops.

So every managed firewall needs a supervisor that restarts it: `restart: unless-stopped`
in compose, `Restart=on-failure` under systemd. Both examples in `deploy/` have it.

## 6. Commands

| Command | What |
| --- | --- |
| `probation-server serve --config FILE` | The server. Prunes `change_log`, activity and the audit log by their retention every hour. |
| `probation-server migrate` | Applies the schema (owner role). |
| `probation-server admin bootstrap --config FILE --email ADDR …` | First run only (§4). |
| `probation-server admin reset-link --config FILE --email ADDR` | A fresh set-password link for a global admin (§4). |
| `probation-server admin revoke-key --key-id N` | Revokes any key; every firewall stops accepting it within one sync interval. |
| `probation-server admin after-restore` | After restoring the database from a backup, before starting the server (operations.md §13). |

The `admin` commands are for the server host's operator: they need the database URL,
and no API route reaches them.

## 7. The end-to-end test

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
