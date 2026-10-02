# probation

[![crates.io](https://img.shields.io/crates/v/probation.svg)](https://crates.io/crates/probation)

Open-source package firewall for npm and PyPI.

A self-hosted registry proxy that hides releases younger than a configured delay and
hides known-malicious packages and artifacts. `npm` and `pip` keep doing the
dependency resolution; this decides what there is to resolve against, and verifies
every artifact before delivering it.

The problem it addresses: a compromised package can be installed the moment it is
published, before any malware feed has seen it. Blocking only known-bad releases
leaves that window open, and simply refusing a new download breaks installs that an
older compatible release would have satisfied. So the firewall withholds the young
release and lets the client resolve to an older eligible one — without anyone editing
a requirement.

Eligible means "passed the configured checks". It is not a claim that a package is
harmless.

## Quick start

From [crates.io](https://crates.io/crates/probation) (needs the build tools listed
under [Building and testing](#building-and-testing)):

```sh
cargo install probation --locked
probation check-config config.sample.toml
```

or from a checkout:

```sh
cargo build --release --locked
./target/release/probation check-config config.sample.toml
./target/release/probation serve --config /etc/probation/config.toml
```

or from the container image:

```sh
docker build -t probation:mvp .
docker run -d -p 127.0.0.1:8080:8080 \
  -v /srv/probation:/var/lib/probation \
  probation:mvp serve --config /etc/probation/config.toml
```

Point clients at it:

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

`config.sample.toml` and `blocklist.sample.json` in this repository are the shapes
those two files take. **Read [`docs/operations.md`](docs/operations.md) before running
this for real** — in particular section 3, because `cache_max_bytes` does not bound
the state database, and section 6, because per-client rate limiting is the reverse
proxy's job and not this service's.

## What it does not do

It enforces on delivery, so packages already installed or already in a client's own
cache are outside its reach, as are alternate indexes, Git and URL dependencies, local
wheels, and lockfiles pinning upstream URLs directly. It has no UI, no publishing, no
private-registry federation, no vendor feed adapters, no archive scanning and no
administrative API. The blocklist is produced by something else; this consumes one
local JSON file.

`docs/operations.md` §7 and §12 are the complete lists.

## Building and testing

```sh
cargo clippy --all-targets -- -D warnings
cargo test                                  # offline; no test reaches a public network
cargo test --test e2e_npm -- --ignored      # drives the real npm client
cargo test --test e2e_pip -- --ignored      # drives the real pip client
cargo bench                                 # the SPEC §12 measurements
cargo bench --bench delivery_rated_load     # ten minutes; the rated-load figure below
```

Building needs `cmake`, a C compiler and `perl` in addition to the Rust toolchain
pinned by `rust-toolchain.toml`: reqwest's default rustls crypto provider is
`aws-lc-rs`, which builds from C. The e2e tests additionally need `npm`, and `python3`
with `pip`, `setuptools` and `build`.

Benchmark results against the specification's acceptance targets — every one of them
met, with the pre-change baseline kept alongside — are in
[`docs/operations.md`](docs/operations.md) §10.

**Rated load:** the delivery pipeline sustains **59,288 decided requests/second** with
zero records lost, measured on the reference hardware named in
[`docs/operations.md`](docs/operations.md) §8. The default queue budget is sized from a
stated 200 requests/second reference load, not from that ceiling — §8 explains why and
states what a default deployment's budget survives and how to compute your own
tolerance.

## Documents

- [`SPEC.md`](SPEC.md) — the specification this implements.
- [`docs/operations.md`](docs/operations.md) — running it, capacity, backup, restore,
  limits and measured numbers.
- [`docs/plans/package-firewall-mvp/`](docs/plans/package-firewall-mvp/) — the product,
  architecture, design and slice plan this was built from.

`docs/codebase-overview.md` is the pre-implementation onboarding briefing and is
stale: it was written before any source existed and still says so. It is not linked
above for that reason.

Licensed under Apache-2.0; see [`LICENSE`](LICENSE).
