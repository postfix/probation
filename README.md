# probation

[![crates.io](https://img.shields.io/crates/v/probation.svg)](https://crates.io/crates/probation)

A firewall for npm and PyPI packages. You run it yourself, in front of your own
`npm` and `pip` clients.

## The problem

A package can be hijacked and a bad version published in seconds. Malware
scanners and blocklists take hours or days to catch up. In that gap, anyone who
installs the package gets the bad version.

## What it does

Probation sits between your developers and the real npm and PyPI registries. It
holds back any version published too recently (you choose how long, a day by
default). If a newer version is held back, `npm` and `pip` fall back to the
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

## Quick start

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
docker build -t probation:mvp .
docker run -d -p 127.0.0.1:8080:8080 \
  -v /srv/probation:/var/lib/probation \
  probation:mvp serve --config /etc/probation/config.toml
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

## What it won't catch

It only checks packages as they are downloaded. So it cannot help with:

- packages already installed, or already in a client's local cache
- anything fetched from somewhere other than npm or PyPI: other registries, Git
  URLs, direct downloads, local files
- a lockfile that pins a direct URL instead of a package name and version

It has no web UI, cannot publish packages, and does not scan files for malware
itself. It enforces the blocklist you give it and what OSV reports. Something
else has to produce that blocklist.

Full details: `docs/operations.md`, sections 7 and 12.

## Building and testing

```sh
cargo clippy --all-targets -- -D warnings
cargo test                                  # no network access needed
cargo test --test e2e_npm -- --ignored      # runs the real npm client
cargo test --test e2e_pip -- --ignored      # runs the real pip client
cargo bench                                 # performance checks
cargo bench --bench delivery_rated_load     # a slower one, ~10 minutes
```

You need `cmake`, a C compiler, and `perl` (one crypto library builds from C),
plus the Rust version pinned in `rust-toolchain.toml`. The e2e tests also need
`npm` and `python3` with `pip`, `setuptools`, and `build` installed.

In testing, it handled about **59,000 requests/second** with no dropped
records. See [`docs/operations.md`](docs/operations.md) §8 and §10 for how that
was measured and what it means for sizing your own setup.

## Documents

- [`SPEC.md`](SPEC.md): the specification this was built from.
- [`docs/operations.md`](docs/operations.md): how to run it, its limits, backup
  and restore, and measured performance.
- [`docs/plans/`](docs/plans/): the design and planning history, one folder per
  feature.

Licensed under Apache-2.0; see [`LICENSE`](LICENSE).
