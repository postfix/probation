# Probation — container image (SPEC §3: "Ship one Rust binary and a container
# image built from it").
#
# Plain Dockerfile syntax throughout: no BuildKit-only features, no cache mounts and
# no heredocs, because `docker` in this project's environment is an alias for podman
# and the image has to build under both.
#
# Build stages and a runtime stage, and each side carries a dependency the other does not:
#
#   * The **build** stages need `cmake`, a C compiler and `perl`. reqwest 0.13's
#     default rustls crypto provider is `aws-lc-rs`, which builds `aws-lc-sys` from C
#     (Gate 3 dependency note 3). The C compiler comes with the `rust` image; cmake
#     and perl do not.
#   * The **runtime** stage needs `ca-certificates`. The rustls roots features were
#     removed in reqwest 0.13, so certificate roots come from
#     `rustls-platform-verifier`, which on Linux reads the system trust store. An
#     empty trust store is a total upstream outage, not a degraded mode — every
#     metadata fetch and every artifact download fails — so this package is
#     load-bearing rather than cosmetic.

FROM docker.io/library/rust:1.96.0-bookworm AS chef

RUN apt-get update \
 && apt-get install --yes --no-install-recommends cmake perl \
 && rm -rf /var/lib/apt/lists/*
# cargo-chef splits the build in two: the dependencies, cached as one layer that only
# a Cargo.toml or Cargo.lock change invalidates, then this workspace's own crates. It
# changes how the binary is built, not what is in it.
RUN cargo install cargo-chef --locked --version 0.1.78

WORKDIR /src

FROM chef AS planner

# The manifest names the bench targets, so their sources have to be present for the
# manifest to describe a buildable package. Tests are discovered rather than declared
# and are deliberately left out of the image build.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY benches ./benches
# The workspace members: `probation-policy`, which the firewall depends on.
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build

COPY rust-toolchain.toml ./
COPY --from=planner /src/recipe.json recipe.json
# `--locked` is the point of shipping Cargo.lock: the image is built from the exact
# dependency graph the tests ran against, and a lockfile that no longer matches the
# manifest fails the build instead of silently resolving something else.
RUN cargo chef cook --release --locked --bin probation --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY crates ./crates
RUN cargo build --release --locked --bin probation

FROM docker.io/library/debian:bookworm-slim

LABEL org.opencontainers.image.title="probation" \
      org.opencontainers.image.licenses="Elastic-2.0"

RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/probation /usr/local/bin/probation

# The shipped samples, at the paths SPEC §4's command lines name.
COPY config.sample.toml /etc/probation/config.toml
COPY blocklist.sample.json /etc/probation/blocklist.json

# Two edits to the sample, both forced by the container rather than by taste:
#
#   * `listen` becomes `0.0.0.0:8080`. SPEC §3's loopback default is a host default;
#     inside a container it would make the published port unreachable, and the
#     container's own network namespace is what the loopback default was protecting.
#     Keep the instance behind the reverse proxy SPEC §3 assumes, and publish the port
#     only to that proxy.
#   * `blocklist_file` already points at `/etc/probation/blocklist.json`, which
#     is where the sample lands, so it is left alone. The shipped sample carries a
#     distant `expires_at` so the image starts ready; a deployment mounts its
#     producer's real snapshot over this path.
RUN sed --in-place 's|^listen = .*|listen = "0.0.0.0:8080"|' /etc/probation/config.toml \
 && probation check-config /etc/probation/config.toml \
 && probation check-blocklist /etc/probation/blocklist.json

# SPEC §10: the service holds an exclusive lock on its data directory and owns
# everything in it. It runs as a normal user, so nothing in the image needs root.
RUN useradd --system --create-home --home-dir /var/lib/probation firewall \
 && chown firewall:firewall /var/lib/probation
USER firewall

# Artifact bytes and the state database live here. SPEC §10 and `docs/operations.md`:
# the state database and its write-ahead log are NOT inside `cache_max_bytes`, so this
# volume needs headroom beyond that budget.
VOLUME ["/var/lib/probation"]

EXPOSE 8080

# `serve` shuts down cleanly on SIGINT and SIGTERM alike, so `docker stop` works
# either way; SIGINT is named here only to match the Ctrl-C path exactly.
STOPSIGNAL SIGINT

ENTRYPOINT ["probation"]
CMD ["serve", "--config", "/etc/probation/config.toml"]
