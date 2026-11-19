# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The next release must have a version above 0.2.2.

### Changed

- Upload spool fairness (every publish forwarder: npm, PyPI, RubyGems, Cargo, NuGet, Maven):
  places and bytes are counted per real identity (the account in certificate mode, the
  client address in shared-service mode, plus the presented credential), at most half of
  the places and of the byte budget each; the rate clock starts at the first chunk and a
  burst no longer licenses a trickle. New optional `[service_policy] trusted_proxies`.

### Added

- **RubyGems and Cargo** through the firewall (docs/operations.md "RubyGems clients" and
  "Cargo clients"). `rubygems_upstream_url`, `cargo_upstream_url` and `cargo_artifacts_url`
  name their origins like the npm and PyPI keys. Cargo's sparse index is filtered by age,
  blocklist and OSV (`crates.io`) with every kept line unchanged, its `config.json` is
  rewritten to name the firewall, and a crate is delivered only when its SHA-256 equals
  the index `cksum`. Through the shared service `cargo publish`, `yank`, `unyank` and
  `owner` are forwarded with the caller's own token only; the owner list and search are
  forwarded as reads.
- **Maven** through the firewall (docs/operations.md "Maven and Gradle clients"). `maven_upstream_url` (an origin and the path
  prefix of the repository tree, default Maven Central's `maven2`) and `maven_publish_url` (the deploy URL of the public
  registry through the shared service; none by default). `maven-metadata.xml` at artifact, plugin-group and snapshot-version
  level and `archetype-catalog.xml` are filtered by age, blocklist and OSV (`Maven`, key `groupId:artifactId`, case is
  identity) with `latest`, `release` and the snapshot pointer moved to the newest allowed entry and every checksum file
  (`.md5`, `.sha1`, `.sha256`, `.sha512`) rebuilt for what is served; every file of a version (POM, JAR, classifier files,
  `.module`, signatures and checksum sidecars) is gated by the decision of its version or snapshot build, dated by the
  repository's `Last-Modified` of its POM (otherwise by first-seen), and delivered exactly as the repository sent it. Metadata is
  read by a strict bounded XML scanner (no document type, no entity, bounded depth and size). Through the shared service
  `mvn deploy` (`PUT` of each file, checksum, signature and metadata, and `DELETE`) is forwarded with the caller's own
  `Authorization` to the registry's own origin after the `Basic` challenge Maven waits for. A Maven registry may declare an
  archive origin like a Cargo, Go or NuGet one (migration 0020).
- **NuGet** through the firewall (docs/operations.md "NuGet clients"). `nuget_upstream_url`,
  `nuget_search_url` and `nuget_publish_url` name the index, search and publish hosts of the registry (api.nuget.org,
  azuresearch-usnc.nuget.org and www.nuget.org) like the other origin keys; a resource a service index names on any
  other origin is not used. The service index, the flat container (`index.json`, `.nupkg`, `.nuspec`, readme, icon),
  registration (pages the registry inlined stay inline, linked pages are re-linked to the firewall, young leaves removed; every version of a project is kept, judged and listed, with its reference rows made when a file of it is asked for), search, autocomplete, the vulnerability database and the
  repository signature index are filtered or forwarded by age, blocklist and OSV (`NuGet`); the four files of a version are
  gated together and delivered exactly as the registry sent them, ids are case-insensitive (one lower-case identity)
  and versions are NuGet's own (`1.0` is `1.0.0`). Through the shared service `dotnet nuget push`, its symbol package,
  `dotnet nuget delete` and relist are forwarded with the caller's own key to the publish endpoint the registry's
  service index names. A NuGet registry may declare an archive origin like a Cargo or Go one (migration 0018) and a resource path
  prefix (migration 0019). Every upload forwarder (npm, PyPI, RubyGems, Cargo, NuGet) now spools through one bounded place
  (8 uploads, a byte budget of twice the artifact cap taken as bytes arrive, a 60 s idle limit and a 15-minute body deadline). Registration, search and the vulnerability/signature documents are
  shared for a few seconds, bounded per process and per request.
- **Go modules** through the firewall (docs/operations.md "Go clients"). `go_upstream_url`,
  `go_sumdb_url` and `go_artifacts_url` name the proxy, the checksum database and the origin a zip redirect may land on
  (proxy.golang.org redirects large zips to its signed bucket) like the other origin keys. `@v/list` and
  `@latest` are filtered by age, blocklist and OSV (`Go`), the `.info`, `.mod` and `.zip` of a version are
  gated together and delivered exactly as the proxy sent them, case-encoded module paths and versions keep
  one identity, and the checksum database is forwarded separately (hashes only). Go has no write protocol,
  so nothing is forwarded through the shared service.
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
