# API and command reference

Three references in one file:

1. [The automation API](#1-the-automation-api-blocklists-from-ci): CI jobs and blocklist
   tools push blocks into one policy layer of the management server.
2. [The firewall sync API](#2-the-firewall-sync-api): what a managed firewall asks the
   management server. For people who run or debug firewalls.
3. [Commands](#3-commands): every subcommand and flag of `probation` and
   `probation-server`.

How to run the server is in [management-server.md](management-server.md); how to run a
firewall is in [operations.md](operations.md).

Both APIs are served by `probation-server serve` on `[server] listen`, next to the
portal. `probation-server` speaks plain HTTP: put a TLS proxy in front of it
(operations.md §6). The examples use `https://manage.example.org` for that address.

---

## 1. The automation API: blocklists from CI

| Method and route | What it does |
| --- | --- |
| `GET /api/v1/blocklist/{layer}` | Exports the layer's blocks as a blocklist file. |
| `PUT /api/v1/blocklist/{layer}` | Replaces all of the layer's blocks with the blocks in the file. |
| `POST /api/v1/blocklist/{layer}` | Adds the file's blocks the layer does not have yet. |

### Automation tokens

Every call sends an automation token: `Authorization: Bearer aut_…`. A token is
`aut_` and 32 letters and digits. It is shown once, when it is created; the server
keeps only its SHA-256.

- An org admin (or a global admin) creates one on the **Organisation** page, section
  **Automation tokens**, for the organisation's layer or one of its groups' layers.
- A global admin creates one on the **Global admin** page, section **Platform
  automation tokens and blocklist file**, for the platform layer.
- User and personal-account layers cannot have a token.

A token writes exactly one layer. It stops working (`401`) when:

- someone revokes it on the same page;
- the person who created it is deleted, or no longer holds the role that let them
  create it (org admin of that organisation, or global admin);
- the organisation of its layer is suspended or deleted, or the group of its layer
  is deleted.

### The `{layer}` in the route

The layer is written `<kind>-<id>`: `platform-1`, `org-3`, `group-5`. It is the last
part of the layer's policy page address in the portal (`/policy/org-3`). A route that
names any layer other than the token's own answers `403` with the text
`This token writes one other layer.`

### Blocks only

A token may change the layer's blocks and nothing else. `PUT` and `POST` keep the
layer's freeze, OSV setting, exceptions and switches exactly as they are stored. A
save from a token that would change any of them is refused with `403`.

A push goes through the same checks as an edit in the portal, writes an audit-log
row (`layer.edit`, with the token as the actor), and reaches every firewall at its
next sync (`sync_interval_seconds`, 60 by default).

### Requests and answers

- `GET`: no body. The answer is `200` with the blocklist file (`application/json`).
  In the file, `revision` is the layer's revision, `generated_at` is now and
  `expires_at` is one year from now. A block without a reason is written with the
  reason `Blocked in Probation`.
- `PUT`: the body is a blocklist file. All blocks of the layer are replaced by the
  file's blocks. A file with no records clears the layer's blocks.
- `POST`: the body is a blocklist file. Each block is added unless the layer already
  has a block with the same target (ecosystem, name and version, or algorithm and
  digest), whatever its reason.
- `PUT` and `POST` answer `200` with `{"revision": N}`, the layer's new revision.

The `Content-Type` of the request is not checked; send `application/json`.

### The blocklist file

The same format the firewall reads from `blocklist_file` (SPEC §8,
[blocklist.sample.json](../blocklist.sample.json)):

```json
{
  "schema_version": 1,
  "revision": 42,
  "generated_at": "2026-09-17T12:00:00Z",
  "expires_at": "2099-01-01T00:00:00Z",
  "blocked_packages": [
    { "ecosystem": "npm", "name": "example-malware", "version": "1.2.3", "reason": "Known malicious release" },
    { "ecosystem": "pypi", "name": "example-bad-project", "version": null, "reason": "Block every release" }
  ],
  "blocked_hashes": [
    { "algorithm": "sha256", "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "reason": "Known malicious artifact" }
  ]
}
```

On import (`PUT`, `POST`, and the import forms in the portal):

| Field | Rule |
| --- | --- |
| `schema_version` | Required, must be `1`. |
| `revision`, `generated_at`, `expires_at` | Ignored; the server keeps its own revision. |
| `blocked_packages`, `blocked_hashes` | Optional; a missing list is empty. |
| `ecosystem` | `npm` or `pypi`. |
| `name` | A name the ecosystem could publish. |
| `version` | `null` or left out blocks every release of the package; otherwise one exact version, not empty and without spaces around it. |
| `algorithm` | `sha256` (64 hex characters) or `sha512` (128 hex characters). The digest is stored in lowercase. |
| `reason` | Optional, at most 256 bytes. A blank reason is stored as none. |

### Limits

| Limit | Value | Answer |
| --- | --- | --- |
| Request body | 1 MiB | `413`, before the file is parsed |
| Records in one file (packages and hashes together) | 5,000 | `422` |
| Blocks in one layer | 5,000 (a layer already over it may shrink, never grow) | `422` |
| Reason | 256 bytes | `422` |

### Status codes

| Code | Meaning |
| --- | --- |
| `200` | Done. |
| `401` | No token, not an `aut_` token, unknown, revoked, or no longer valid (see above). Also when the database fails while the token is checked. Empty body. |
| `403` | The route names another layer than the token's, or the token may not save this change. |
| `409` | The layer changed while the push was checked. Body: `The layer changed meanwhile; send the push again.` Send the same request again. |
| `413` | The body is over 1 MiB. |
| `422` | The body is not UTF-8, not a blocklist file, or a block in it is refused. The body is one line of plain text naming the problem, for example `schema_version 2 is not 1` or `blocked_hashes[0]: not a sha256 digest in hex`. |
| `503` | The database failed. Try again later. |

### Examples

```sh
# Replace the blocks of organisation 3's layer with the file's.
curl -sS --fail-with-body -X PUT \
  -H "Authorization: Bearer $PROBATION_AUTOMATION_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @blocklist.json \
  https://manage.example.org/api/v1/blocklist/org-3
# {"revision":12}

# Add blocks, keeping the ones the layer has.
curl -sS --fail-with-body -X POST \
  -H "Authorization: Bearer $PROBATION_AUTOMATION_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @new-blocks.json \
  https://manage.example.org/api/v1/blocklist/org-3

# Export the layer's blocks.
curl -sS --fail-with-body \
  -H "Authorization: Bearer $PROBATION_AUTOMATION_TOKEN" \
  https://manage.example.org/api/v1/blocklist/org-3 > blocklist.json
```

Keep the token in your CI system's secret store, never in the repository.

---

## 2. The firewall sync API

A firewall with a `[management]` section calls three routes under its `url`. A
firewall only asks; the server never calls a firewall.

| Route | When the firewall calls it |
| --- | --- |
| `POST /api/v1/sync/lookup` | A request carries an API key the firewall has no live entry for. |
| `POST /api/v1/sync/layers` | It needs the policy layers of a key's places. |
| `POST /api/v1/sync/changes` | Every `sync_interval_seconds` (60 by default): what changed, with its report and its activity. |

Bodies are JSON in both directions. Every answer is read from one database snapshot.
Its `revision` is the change-log revision of that snapshot: every change a firewall
caches (keys, layers, places, rate limits, network-lock ranges, settings) adds one
row to the change log and moves this number up by one.

### Authentication and checks

Each call is checked in this order:

1. **The token.** `Authorization: Bearer fwt_…`, the firewall token that the fleet
   page or `probation-server admin bootstrap` printed. It must belong to a firewall
   that is not retired. Otherwise: `401`.
2. **The source address.** The caller's address must be inside one of the
   firewall's allowed source ranges (`--firewall-source` at bootstrap, or the ranges
   given when the firewall was registered on the fleet page). Otherwise: `403` with
   the header `x-probation-error: FIREWALL_SOURCE_REFUSED`. The address is the TCP
   peer. When the peer is in `[server] trusted_proxies`, it is the rightmost
   `X-Forwarded-For` entry that is not itself a trusted proxy.
3. **The rate.** At most 200 calls a second per firewall token, counted by each
   server process. Over it: `429`.

A token is not an API key: `lookup` answers `unknown` for a firewall or automation
token.

### Limits

| Limit | Value | Answer |
| --- | --- | --- |
| Request body | 2 MiB | `413` |
| Places in one `layers` call | 1,000 | `413` |
| `activity` entries in one `changes` call | 1,000 | `413` |
| `activity_dropped` entries in one `changes` call | 1,000 | `413` |
| `report.last_apply_error` | 2,048 bytes | `413` |
| Answer size the firewall reads | 8 MiB | the firewall treats a bigger answer as no answer |

### Status codes, and what the firewall does with them

| Code | Meaning | Firewall |
| --- | --- | --- |
| `200` | The answer. | Uses it. |
| `401` | The token is unknown or revoked, or the firewall is retired. Empty body. | On `changes`: stops serving every request. |
| `403` + `x-probation-error: FIREWALL_SOURCE_REFUSED` | The caller's address is not in the firewall's ranges. | Same as an unreachable server. |
| `413` | Over a limit above. | On `changes`: counts the activity batch as dropped. |
| `422` | The body is not valid JSON for the route, `since` is above 2^63−1, or a value the database cannot take (for example an `eligible_at` that is not a time). | On `changes`: counts the activity batch as dropped. |
| `429` | Over 200 calls a second. | Same as an unreachable server; a request waiting on `lookup` gets `503 LOOKUP_BUSY`. |
| `503` | The database failed or timed out (each query has 1 second). | Same as an unreachable server. |

While the server is unreachable a firewall keeps serving what it has cached and puts
the activity batch back in its queue (operations.md §13, "When the server is down").
Each call gives up after `request_timeout_seconds` (2 by default). The firewall does
not follow redirects and ignores `HTTPS_PROXY` and the other proxy variables.

### JSON conventions

- **A place** is `{"kind": "Org", "id": 3}`. `kind` is one of `Platform`, `Org`,
  `Group`, `User`, `Personal` (capitalised, unlike the `org-3` form of the automation
  API). The platform is `{"kind": "Platform", "id": 1}`.
- **A layer**, as `layers` returns it:

  ```json
  {
    "kind": "Org",
    "freeze_seconds": 86400,
    "osv": "On",
    "blocks": [
      { "Package": { "ecosystem": "Npm", "name": "example-malware", "reason": "Known malicious" } },
      { "Version": { "ecosystem": "PyPi", "name": "example-bad-project", "version": "1.0.0" } },
      { "File": { "algorithm": "Sha256", "digest": "aaaa…" } }
    ],
    "exceptions": [
      { "ecosystem": "Npm", "name": "left-pad", "version": null,
        "lifts": { "block": false, "freeze": true, "osv": false } }
    ],
    "allow": { "exceptions": true, "osv_off": false, "shorter_freeze": true }
  }
  ```

  `freeze_seconds` and `osv` are `null` when the layer inherits them. `osv` is `Off`,
  `LogOnly` or `On`. A block's `reason` is left out when it has none. `allow` is what
  the layer directly below may loosen.
- Key ids and organisation ids are plain numbers.

### `POST /api/v1/sync/lookup`

Request: the SHA-256 of the whole API key (`prb_…`), 64 lowercase hex characters.
The key itself never leaves the firewall.

```json
{ "key_hash": "3f2a…64 hex characters…" }
```

Answer: one object with a `status`.

```json
{
  "status": "known",
  "key_id": 7,
  "org": 3,
  "account": { "kind": "Org", "id": 3 },
  "place_chain": [
    { "place": { "kind": "Platform", "id": 1 }, "layer_revision": 4 },
    { "place": { "kind": "Org", "id": 3 }, "layer_revision": 11 },
    { "place": { "kind": "Group", "id": 5 }, "layer_revision": 2 }
  ],
  "rate_limit": 600,
  "rate_limit_source": "default",
  "revision": 1042
}
```

| `status` | When | Other fields |
| --- | --- | --- |
| `known` | A live user or service key. | `key_id`; `org` (`null` for a personal account's key); `account`, the organisation or personal account the rate limit counts against; `place_chain`; `rate_limit`, requests a minute counted on each firewall (`null`: no limit); `rate_limit_source` (`default` or `override`); `revision`. |
| `revoked` | The key is revoked; or its owner, its organisation, personal account or group is deleted; or its owner is no longer that member. | `key_id`, `place`, `place_chain`, `revision`. |
| `suspended` | The organisation or personal account is suspended. | `key_id`, `place`, `place_chain`, `revision`. |
| `unknown` | No user or service key has this hash. | `revision`. |

`place_chain` lists the platform first and the key's own place last. Each entry
carries its layer's revision (`0` when the place has no layer).

### `POST /api/v1/sync/layers`

Request: the places whose own layers the firewall wants, at most 1,000.

```json
{ "places": [ { "kind": "Platform", "id": 1 }, { "kind": "Org", "id": 3 } ] }
```

Answer: each place's layer and that layer's revision, plus the snapshot's revision.
A place that has no layer is left out of `layers`.

```json
{
  "layers": [
    { "place": { "kind": "Platform", "id": 1 }, "layer": { "kind": "Platform", "…": "…" }, "revision": 4 },
    { "place": { "kind": "Org", "id": 3 }, "layer": { "kind": "Org", "…": "…" }, "revision": 11 }
  ],
  "revision": 1042
}
```

### `POST /api/v1/sync/changes`

Request:

```json
{
  "since": 1040,
  "report": {
    "settings_revision": 6,
    "last_apply_error": null,
    "status": { "upstreams": { "npm": "ok", "pypi": "ok", "osv": "unreachable" } },
    "effective_period_seconds": 60,
    "version": "0.2.2"
  },
  "activity": [
    {
      "event_id": "19a11c2f3e0-1",
      "key_id": 7,
      "place": { "kind": "Group", "id": 5 },
      "ecosystem": "Npm",
      "package": "example-malware",
      "version": "1.2.3",
      "result": "blocked",
      "rule": "blocked_version",
      "layer": "org",
      "client_ip": null,
      "eligible_at": null,
      "at": "2026-10-23T12:00:10.000000Z"
    }
  ],
  "activity_dropped": [ { "account": { "kind": "Org", "id": 3 }, "count": 12 } ]
}
```

`since` is the revision of the last answer the firewall applied; `0` on its first
sync.

**`report`**, how the firewall is doing:

| Field | Meaning |
| --- | --- |
| `settings_revision` | The settings push the firewall runs with; `0` before the first. |
| `last_apply_error` | Why the last settings push or the last sync could not be applied, cut to 2 KiB; `null` when none. |
| `status.upstreams` | `ok` or `unreachable` for `npm`, `pypi` and `osv` in the last sync period. |
| `effective_period_seconds` | The sync period the firewall runs at, so the server can tell a late check-in. |
| `version` | The firewall's version. |
| `failed_revision` | The settings push the firewall refused, which `last_apply_error` is about. Left out when there is none, and by older firewalls that do not send it. |

The server stores the report as the firewall's last report and moves its "last seen"
time; the fleet page shows both.

**`activity`**, one entry per blocked, held or would-have-blocked decision, or per
refused known key:

| Field | Meaning |
| --- | --- |
| `event_id` | Unique per firewall. A batch sent twice is stored once. |
| `key_id`, `place` | The key and its place. The server stores the event under the key's own place, whatever place is sent. An event whose `key_id` is not a user or service key is not stored. |
| `ecosystem`, `package`, `version` | `Npm` or `PyPi`, the package, the version; `null` on a refusal made before the package was known, and `version` is `null` for a refused package listing. |
| `result` | `blocked`, `held`, `would_block`, `refused_revoked`, `refused_suspended` or `refused_network`. |
| `rule` | Why: `blocked_package`, `blocked_version`, `blocked_digest`, `osv`, `malformed_timestamp`, `future_timestamp`, `no_timestamp`, `freeze`, `revoked`, `suspended` or `network_lock`. |
| `layer` | The layer behind it: `platform`, `org`, `group`, `user`, `personal`, `network` (the network lock) or `none`. |
| `client_ip` | The client's address; kept only on `refused_network`. |
| `eligible_at` | RFC 3339 time the release becomes eligible; holds only. |
| `at` | RFC 3339 UTC time the firewall saw it. Optional. Kept within the activity retention: a time in the future becomes now, an older one becomes the start of the retention. A missing or unreadable time is taken as now. |

**`activity_dropped`**: per account, how many events the firewall lost to its queue
cap or to a rejected batch. Stored with the report.

The report and the activity are stored in one transaction before the changes are
read. They never move the change-log revision.

Answer:

```json
{
  "revision": 1046,
  "changed_keys": [7],
  "changed_layers": [ { "kind": "Org", "id": 3 } ],
  "changed_places": [],
  "changed_limits": [
    { "scope_kind": "org", "scope_id": 3, "rate_per_min": 1200, "source": "override" }
  ],
  "network_lock": null,
  "settings": null,
  "reset": false,
  "retired": false
}
```

| Field | Meaning |
| --- | --- |
| `revision` | The revision this answer brings the firewall to; its next `since`. |
| `changed_keys` | Key ids whose state changed: the firewall drops them and looks them up again on next use. Each id once. |
| `changed_layers` | Places whose own layer changed: fetched again with `layers`. Each place once. |
| `changed_places` | Organisations and personal accounts that were suspended, activated, deleted or restored: keys under them are looked up again. Each place once. |
| `changed_limits` | Rate-limit rows in change order. `scope_kind` is `org` or `personal`; `scope_id` `null` is the default for that kind, a number is one account's override; `rate_per_min` `null` means no limit. Deleting an override sends that account's row with the default's rate and `source: "default"`. |
| `network_lock` | The whole table of approved network-lock ranges, `[{"cidr": "192.0.2.0/24", "org": 3}]`, sent when a range changed, when `since` is `0`, and on every reset. `null`: keep the table you have. |
| `settings` | `{"revision": 7, "toml": "…"}` when the server holds settings for this firewall whose revision differs from `report.settings_revision`; otherwise `null`. |
| `reset` | `true` when `since` is older than the kept change log (`change_log_retention_days`, 7 by default) or above the server's revision (a restored database). The answer then carries only `revision`, `network_lock` and `settings`; the firewall drops every cached key and layer and starts again from `revision`. |
| `retired` | Always `false` from this server. A retired firewall gets `401` instead. |

#### Settings pushes and `failed_revision`

A global admin pushes settings from the fleet page to a list of firewalls, one at a
time. The settings revision is the rollout's id. The server sends `settings` to the
first firewall; at each `changes` call of the firewall that has the push:

- `report.settings_revision` equals the push's revision: the step is applied, and
  the next firewall gets the settings.
- Otherwise, if the firewall has called since the push was sent, `last_apply_error`
  is set, and `failed_revision` is the push's revision (or left out, from an older
  firewall): the step failed and the rollout halts.
- An error with a `failed_revision` of an older push does not fail the current step.
  So a stale error from an earlier rollout never halts a newer one.
- A step not applied within 3 sync periods of that firewall (from
  `effective_period_seconds`, taken as 1 second to 1 day, 60 seconds if it never
  reported) times out and halts the rollout. This is checked when the fleet page is
  read.

The server refuses to store a push that is not TOML, sets a local-only setting
(`management`, `listen`, `data_dir`, `tls_cert_path`, `tls_key_path`, `public_url`,
`siem_url`, `siem_auth_header`), or sets `npm_upstream_url`, `pypi_upstream_url` or
`pypi_artifacts_url` to anything but an `https://` address. The firewall applies a
push by writing it to `<data_dir>/managed-settings.toml` and exiting with code 75
(management-server.md §6).

### Debugging a firewall's sync

- `401` on every call: the token is wrong, revoked, or the firewall was retired on
  the fleet page. Register the firewall again, put the new token in its
  `token_file` and restart it.
- `403` with `FIREWALL_SOURCE_REFUSED`: the server sees an address outside the
  firewall's ranges. Behind a load balancer, list the balancer in `[server]
  trusted_proxies`, or the server sees the balancer's address.
- To check what the server answers for one key, call `lookup` from the firewall's
  host with its token:

  ```sh
  hash=$(printf %s "$API_KEY" | sha256sum | cut -d' ' -f1)
  curl -sS -X POST \
    -H "Authorization: Bearer $(cat /etc/probation/firewall.token)" \
    -H "Content-Type: application/json" \
    -d "{\"key_hash\":\"$hash\"}" \
    https://manage.example.org/api/v1/sync/lookup
  ```

  `lookup` and `layers` only read. Do not send `changes` by hand: it stores a report
  and activity for that firewall and can settle or fail a settings rollout step.

---

## 3. Commands

### `probation` (the firewall)

```
Usage: probation <COMMAND>

Commands:
  serve            Serve filtered npm and PyPI metadata and verified artifacts
  check-config     Validate a configuration file. Exits non-zero on the first problem, naming it, and changes nothing
  check-blocklist  Validate a blocklist snapshot. Exits non-zero on the first problem, naming it, and changes nothing
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

**`probation serve --config <PATH>`**

| Flag | Meaning |
| --- | --- |
| `--config <PATH>` | Path to the TOML configuration file. Required. |

Exit codes: `0` after a clean stop on `SIGTERM` or `SIGINT`; `75` after a managed
firewall wrote a settings push, so its supervisor starts it again; `1` on a bad
configuration, a failed start or an unclean shutdown.

**`probation check-config [PATH]`** or **`probation check-config --config <PATH>`**

| Argument or flag | Meaning |
| --- | --- |
| `[PATH]` | Path to the TOML configuration file. |
| `--config <PATH>` | The same path in the `--config` form SPEC §4 spells the command with. Use one or the other. |

On success it prints `<PATH>: valid configuration (listen <address>, cooldown <N>s)`
and exits `0`. Otherwise it prints `<PATH>: <problem>` on stderr and exits `1`.

**`probation check-blocklist <PATH>`**

| Argument | Meaning |
| --- | --- |
| `<PATH>` | Path to the JSON blocklist snapshot. |

It checks the file against the default size limit, not a configured
`max_blocklist_bytes`. On success it prints `<PATH>: valid blocklist (revision <N>, <N>
entries, expires <time>)` and exits `0`; otherwise `<PATH>: <problem>` on stderr and
exit `1`.

### `probation-server` (the management server)

```
Usage: probation-server <COMMAND>

Commands:
  serve    Serve the firewall sync API, and the portal when `[portal]` is set
  migrate  Apply the database migrations as the owner role
  admin
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Every command prints its errors as `probation-server: <message>` on stderr and exits
`1`; it exits `0` on success. Log lines go to stderr; `RUST_LOG` sets their level
(`info` by default).

Environment variables:

| Variable | Needed by |
| --- | --- |
| `PROBATION_SERVER_DATABASE_URL` | `serve` and every `admin` command: the app role's connection. |
| `PROBATION_SERVER_MIGRATE_DATABASE_URL` | `migrate` only: the owner role's connection. |
| `PROBATION_SERVER_SECRET_KEY` | `serve` with `[portal]`: 64 hex characters (32 bytes). |
| `PROBATION_SERVER_GOOGLE_CLIENT_SECRET`, `PROBATION_SERVER_GITHUB_CLIENT_SECRET`, `PROBATION_SERVER_MICROSOFT_CLIENT_SECRET` | `serve`, for each sign-in provider listed under `[portal]`. |
| `PROBATION_SERVER_SMTP_PASSWORD` | `serve` with `[portal.smtp]`, when the SMTP server needs a password. |

**`probation-server serve --config <CONFIG>`**

Serves the sync API and the automation API, and the portal when the settings file has
a `[portal]` section. Once an hour it prunes the change log, activity and the audit log
by their retention.

| Flag | Meaning |
| --- | --- |
| `--config <CONFIG>` | The server's settings file (management-server.md §3). Required. |

**`probation-server migrate`**

Applies the database migrations, connected with
`PROBATION_SERVER_MIGRATE_DATABASE_URL`. No flags.

**`probation-server admin <COMMAND>`**

The `admin` commands are for the server host's operator. They connect with
`PROBATION_SERVER_DATABASE_URL`; no API route reaches them.

```
Commands:
  bootstrap      Create the first global admin, an organisation, a key and a firewall token
  reset-link     Print a fresh set-password link for a global admin (a lost first link)
  revoke-key     Revoke an API key by its id
  after-restore  After restoring the database from a backup, before starting the server: every firewall resets its cache at its next sync (docs/operations.md)
  help           Print this message or the help of the given subcommand(s)
```

**`probation-server admin bootstrap`**

```
Usage: probation-server admin bootstrap --config <CONFIG> --email <EMAIL> --org <ORG> --firewall <FIREWALL> --firewall-source <FIREWALL_SOURCES>
```

| Flag | Meaning |
| --- | --- |
| `--config <CONFIG>` | The server's settings file: the set-password link uses its `[portal] base_url`. |
| `--email <EMAIL>` | The first global admin's email address. |
| `--org <ORG>` | The name of the first organisation. |
| `--firewall <FIREWALL>` | The name of the first firewall. |
| `--firewall-source <FIREWALL_SOURCES>` | An address range the firewall's token is accepted from, such as `192.0.2.0/24`. Required; repeat it for more ranges. |

It creates the first global admin, an organisation, a service key on it and a firewall
token, in one transaction, and prints:

```
global_admin_login=<id>
org=<id>
key_id=<id>
key=prb_…
firewall_id=<id>
firewall_token=fwt_…
set_password_link=https://…
```

The key and the token are shown only here. Without `[portal] base_url` the last line is
a note instead of a link; add `[portal]` and run `admin reset-link`. It refuses, and
changes nothing, when a global admin exists already, when `--email` is not an email
address, or when that address already has a sign-in.

**`probation-server admin reset-link --config <CONFIG> --email <EMAIL>`**

| Flag | Meaning |
| --- | --- |
| `--config <CONFIG>` | The server's settings file; it must have `[portal] base_url`. |
| `--email <EMAIL>` | The global admin's sign-in address. |

Prints `set_password_link=<link>`, a new single-use link that cancels the older ones.
Fails with `no live global admin signs in as <EMAIL>` for any other address.

**`probation-server admin revoke-key --key-id <KEY_ID>`**

| Flag | Meaning |
| --- | --- |
| `--key-id <KEY_ID>` | The id of the user or service key to revoke, such as the `key_id` that bootstrap printed. |

Prints `revoked key <KEY_ID>`. Every firewall stops accepting the key at its next
sync. Fails with `no live API key <KEY_ID>` when there is no such live key.

**`probation-server admin after-restore`**

No flags. Run it after restoring the database from a backup and before starting the
server (operations.md §5). It raises the change counter above every revision issued
before the restore, so every firewall resets its cache at its next sync, and moves
the settings rollout ids forward so a new rollout never reuses an old id. It prints:

```
change_counter raised from value <old> (pruned_through <old>) to <new>; every firewall resets at its next sync
```
