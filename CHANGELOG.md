# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The next release must have a version above 0.2.2.

### Changed

- Upload spool fairness (every publish forwarder: npm, PyPI, RubyGems, Cargo, NuGet, Maven, Conan):
  places and bytes are counted per real identity (the account in certificate mode, the
  client address in shared-service mode, plus the presented credential), at most half of
  the places and of the byte budget each; the rate clock starts at the first chunk and a
  burst no longer licenses a trickle. New optional `[service_policy] trusted_proxies`.

### Added

- **Cluster endpoint with approved-node trust and no upstream fallback (slice 26).** `deploy/kubernetes/` (namespace with the restricted Pod Security Standard, a single-replica Recreate Deployment over a `ReadWriteOncePod` claim kept outside the kustomization, a generated hash-suffixed ConfigMap so a changed approved-node list rolls the pod, a NodePort with `externalTrafficPolicy: Local` as the namespace's only Service enforced by a ValidatingAdmissionPolicy, default-deny NetworkPolicies, a PodDisruptionBudget, no secrets) and `deploy/kubernetes/node/` (`install-node.sh`: per-registry routes, the containerd `imports` line, the service CA pinned as containerd's only root, a digest-verified preload of the service's own image, rollback; `verify-node.sh`; `install-firewall.sh` with `egress.nft` and `ingress.nft` and a boot unit). The service selects the OCI registry of a plain `/v2/` request by its `ns` (an `ns` no registry serves is refused, the token realm keeps the `ns`), and refuses to start on a network file system unless `allow_network_data_dir = true`. Operations guide: section 21. `check_kubernetes.py`, `tests/cluster_peer.rs`, `tests/node_scripts.rs`, `E2E-service-cluster` and `.github/workflows/cluster.yml` (its kind and CRI jobs are authored, not run). Nothing was run on a Kubernetes cluster: see the slice-26 evidence. Recheck 2: the node firewall unit is `PartOf`/`ReloadPropagatedFrom` nftables and re-asserts its tables on a restart or reload; `verify-node.sh` reads the effective environment of the running containerd (systemd and `/proc/<pid>/environ`), compares against a baseline made at verify time, checks the owner and mode of the empty roots directory and needs containerd 2.0 or later; OCI `ns` routing refuses two registries on one host (404) instead of taking the first; the network-file-system list gained gfs2, ocfs2, gpfs, beegfs and virtiofs and an unclassifiable mount table fails closed; the operator Role lint covers secrets, configmaps, network policies and services. Recheck 3: `install-firewall.sh` enables and restarts the unit (so `PartOf`/`ReloadPropagatedFrom` reach it) and fails unless both tables are loaded and the unit is active, `verify-node.sh --firewall` also requires `systemctl is-active` and keeps its scratch files in a private temporary directory; `install-node.sh` ignores a commented-out `imports` line; a registry targeting `index.docker.io` or `registry.hub.docker.com` answers to the Docker Hub names; the kind lane's `denied` no longer fails under `pipefail`, its D1 phase A lifts the ingress layer with a temporary allow-all policy that an EXIT trap restores, and the Calico pool uses the pod subnet.
- **Native service lifecycle on Linux, macOS and Windows (slice 25).** `scripts/install-service.sh` (systemd, launchd; system or `--scope user`) and `scripts/install-service.ps1` (Windows service `NT SERVICE\Probation`) install, upgrade and uninstall the service: first install creates only what is absent, an upgrade changes the binary and the definition only (the new binary must accept the existing config first, the old one is kept as `probation.prev`), uninstall removes only what install recorded and keeps config and data. The Windows service host (`probation service --config PATH`, Windows builds only, `windows-service` 0.8.1) takes Stop, Pre-shutdown and Shutdown through the graceful path and ends a settings restart (exit 75) or a failure without reporting `Stopped`, so the service control manager restarts it. `deploy/probation.service` gains `UMask=0077`, `StateDirectoryMode=0700`, `LogsDirectoryMode=0750`. `scripts/install-local.sh` no longer replaces an existing `config.toml`, blocklist, certificate or key, edits only the `registry`/`audit`/`index-url` lines it owns (credential entries, comments and other settings stay byte for byte) and takes `--no-service`. Release packages carry the installer, `deploy/` and the samples, and Windows gets a zip. `tests/oci_native.rs` runs against a real Docker Engine 29.9.2 daemon with `PROBATION_OCI_ENGINE=docker`. Fixes the crate not compiling on Windows (`osv::matches::write_atomic`).
- **OCI, recheck-2 round (slice 24).** The certificate-managed pull token is checked for its shape only (a token of another instance or an earlier process is accepted: balancers and restarts); a streaming upload lane is never evicted from the owner table; a manifest naming a layer by sha512 is checked against the blocks by the stored sha256 once the layer's bytes were hashed; a client that leaves a first pull cancels the transfer nobody else waits for.
- **OCI, recheck round (slice 24).** A layer upload takes a place of the owner's upload lane only when its body can be big (a `PATCH`, or a `PUT`/`POST` over 1 MiB or with no declared length): the upload start, the finishing `PUT` and a manifest `PUT` never wait behind a layer, a request that waits holds no active-request place, at most six of an owner wait and the rest are a 503 at once. The registry's token origin works in every mode: a certificate admission carries `token_origin` (additive field), and a standalone, key-managed or certificate firewall without a descriptor names the default registry's with the new `oci_token_url` key. A manifest whose layers name download `urls` (Windows foreign layers) is no longer refused: every URL must be https, on the default port, without a user name and on the new `oci_foreign_layer_hosts` list (default `mcr.microsoft.com`, `*.data.mcr.microsoft.com`, `go.microsoft.com`, `download.microsoft.com`), every digest the manifest names (foreign layers included) is checked against the blocks and pinned under the manifest's cooldown, and the firewall serves the foreign layer at the registry blob route after fetching the listed URL with no credential and verifying its digest; docs/operations.md says what stays outside (a client that fetches `urls` itself). Blobs are served by sha512 as well as sha256 (verified in the algorithm asked, judged by the sha256 computed in the same pass). The first pull of a sha256 layer sends its response headers at once and the body after verification (an aborted connection on a digest mismatch), one pass over the bytes (sha256 and sha512 only for an image). The certificate-managed token is an HMAC-keyed token bound to the holder's place, the registry and five minutes, checked when presented. The repository-count bound is held atomically.
- **OCI, review fixes (slice 24).** The certificate-managed token endpoint answers the firewall's own pull-only token (an HMAC token since the recheck round) and never a registry token or a stored credential; fetch places are shared per owner (client address /64, account) with a second per-credential count, and the token table drops its oldest entries only; a layer pushed with no declared length may take up to two hours at the rate floor and layers beyond an owner's share queue instead of failing mid-stream; a manifest that has its row is read and never rewritten; a registry's HEAD answers a client's HEAD; a per-registry `token_origin` (migration 0023, portal field) names a token service on another host; `OCI-Subject` is relayed and a paged referrers list is followed whole; the referrers fallback index is not cooled down; a digest blocked under any repository is blocked in every one (mounts and sha512 spellings included); a manifest naming foreign-layer URLs is judged (accepted since the recheck round, see above); manifests are served under a manifest media type with `nosniff`; a registry holds a bounded number of repositories.
- **OCI registries** (Docker Hub, GHCR, Quay, ECR, Harbor, Artifactory, any OCI distribution registry) through the firewall (docs/operations.md
  "OCI clients"). `oci_upstream_url` (the default registry, Docker Hub) and `oci_artifacts_url` (the storage host its blob redirects land on). Manifests,
  indexes and blobs are judged by the digest of their exact bytes (a tag is a name asked fresh every time; the age of a digest is when the firewall first saw
  it, never a depositor's `created`), the children of an allowed manifest take its date, a layer is verified in full before the first byte is delivered
  (Range and HEAD work), a blob's redirect is followed to the storage origin only with the credential dropped, and a tag list, the catalog and a referrers
  index are rebuilt with every `Link` rewritten into the firewall's namespace. The registry's own token flow is the login (`/v2/token`; a certificate-managed
  firewall answers it with the API key as the token, a shared service asks the registry's allowed realm with the caller's Basic credential and the firewall takes
  its own anonymous token for public images); through the shared service a push (blob uploads, manifest `PUT`, `DELETE`) is forwarded with the caller's own
  credential and every `Location` is rewritten or refused. Migration 0022 widens who may hold an archive origin to OCI registries. Real clients: podman (native
  lane) and skopeo (E2E), containerd (the cluster probe, whose row-28-only expectations are flipped).
- **Conan 2** through the firewall (docs/operations.md "Conan clients"). `conan_upstream_url` (an origin and the optional path prefix of the
  remote's `v2` tree, default ConanCenter's `https://center2.conan.io`) and `conan_publish_url` (the upload URL of the public registry through
  the shared service; none by default). Recipe and package revision lists (`revisions`, `latest`), the reference search and the binary search
  are filtered by age, blocklist and OSV (`ConanCenter`, key the package name, case is identity); a revision is dated by the `time` of the
  remote's own revision list (a new binary of an old recipe has its own age, no recipe date ever ages a binary); every file of a revision is
  gated by the decision of its revision and delivered exactly; file lists name files only, so no location of the remote reaches a client; the
  Conan 1 routes (`download_urls`, `upload_urls`) are not routed. A certificate-managed firewall answers `conan remote login` with the key as the
  token; through the shared service the login and every later read and upload use the client's own token, and `conan upload` (a `PUT` of each file,
  and a `DELETE`) is forwarded to the registry's own origin. A Conan search judges every result in batches of 5,000 without writing rows, in judging lanes of its own (half of `max_upstream_requests`), with verdicts renewed when read (at most 10 minutes), so a ConanCenter-size search converges at 200 ms of network (measured: 9,000 references in 66 s at 100 ms; two attempts at 200 ms); per-owner shares of the search slots. A Conan registry may declare an archive origin (migration 0021).
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
