# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The next release must have a version above 0.2.2.

### Added

- **Managed mode** for the firewall. With a `[management]` section in
  `config.toml`, a firewall serves each request under the policy of the API key
  it carries, fetched from a management server and cached. It syncs every
  `sync_interval_seconds` (default 60) and ignores its local blocklist, so
  `blocklist_file` and `blocklist_poll_seconds` may be left out. While the server
  is down it keeps serving every key it has cached; the cache is saved in
  `<data_dir>/managed-cache.json`, so a restart during an outage keeps serving
  too. See `config.sample.toml` and `docs/operations.md` §13.
- **Management server**, `probation-server` (crate `crates/probation-server`),
  backed by Postgres 16. Commands: `serve`, `migrate`, `admin bootstrap`,
  `admin reset-link`, `admin revoke-key` and `admin after-restore`. It serves the
  sync API for firewalls (`/api/v1/sync/…`), the automation API, and the portal
  when `[portal]` is set. See `docs/management-server.md`.
- **Self-service portal**: sign up and confirm an email address, create and
  revoke API keys (`/keys`), and edit policy (`/policy`). Policy is layered:
  platform, organisation, group and user, or platform and a personal account.
  Organisations have members, groups, invitations, address ranges (the network
  lock) and single sign-on. Sign-in by password, Google, GitHub or Microsoft,
  with an authenticator app (optional for members). `/activity` lists blocked
  and held downloads and `/audit` the audit log, each scoped to what the role may see.
  Global admins also get `/admin`.
- **Fleet page** (`/fleet`): register a firewall and get its token, see each
  firewall's health, retire one, and push settings. A push is applied one
  firewall at a time; a step that fails or times out halts the rollout. A
  timed-out step can be resumed, and a stopped step can be skipped. A firewall writes a push to
  `<data_dir>/managed-settings.toml` (never to `config.toml`) and exits with code
  75 so its supervisor restarts it; a push that fails at start is rolled back.
- **Automation API**: `GET`, `PUT` and `POST` on `/api/v1/blocklist/{layer}`
  export, replace or add to one layer's blocklist, with an automation token
  created on the organisation page (for the platform layer, on `/admin`).
- **`probation-server admin after-restore`**: run it after restoring the
  database from a backup and before starting the server; every firewall then
  resets its cache at its next sync.
- **Bootstrap sign-in**: `admin bootstrap` prints a single-use
  `set_password_link` (valid for 60 minutes, built from `[portal] base_url`) for
  the first global admin. `admin reset-link` prints a new one. A global admin
  who signs in by password must set up an authenticator app before `/admin` and
  the fleet page open.
- `npm_upstream_url`, `pypi_upstream_url` and `pypi_artifacts_url` replace the
  fixed upstream origins, in any mode. Each must be a public `https` origin.
- The shared crate `probation-policy` (`crates/probation-policy`): the policy
  model used by both the firewall and the server.

### Changed

- **License**: the whole repository is now under the Elastic License 2.0
  (`Elastic-2.0`) for every release after 0.2.2. Releases 0.2.2 and earlier stay
  under Apache-2.0.
- In managed mode the PyPI root index lists no project.

## [0.2.2] - 2026-10-19

Licensed under Apache-2.0.

### Fixed

- npm tarballs are also served at upstream's own path, so existing lockfiles
  work.
- The installer keeps the CA certificate and the global npm and pip settings
  readable by every user.

## [0.2.1] - 2026-10-19

Licensed under Apache-2.0.

### Fixed

- Databases from 0.1.0 are upgraded in place. Upgrading is documented in
  `docs/operations.md`.

## [0.2.0] - 2026-10-19

Licensed under Apache-2.0.

### Changed

- OSV enforcement denies with the shipped configuration, and a project's checks
  are batched and run concurrently.
- The service runs as its own account.
- Decision-log delivery stays bounded and counted, and the blocklist poller
  keeps running after errors.
- Many review fixes in policy, HTTP, configuration, storage, upstream and
  shutdown.

## [0.1.0] - 2026-10-12

Licensed under Apache-2.0.

### Added

- First release: a package-registry firewall for npm and PyPI with a cooldown
  for new releases, a blocklist file, OSV checks, a content cache, built-in TLS,
  and decision-log delivery to a file and to a SIEM.

[Unreleased]: https://github.com/postfix/probation/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/postfix/probation/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/postfix/probation/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/postfix/probation/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/postfix/probation/releases/tag/v0.1.0
