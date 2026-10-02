# Probation — container image (SPEC §3: "Ship one Rust binary and a container
# image built from it").
#
# Plain Dockerfile syntax throughout: no BuildKit-only features, no cache mounts and
# no heredocs, because `docker` in this project's environment is an alias for podman
# and the image has to build under both.
#
# Two stages, and each one carries a dependency the other does not:
#
#   * The **build** stage needs `cmake`, a C compiler and `perl`. reqwest 0.13's
#     default rustls crypto provider is `aws-lc-rs`, which builds `aws-lc-sys` from C
#     (Gate 3 dependency note 3). The C compiler comes with the `rust` image; cmake
#     and perl do not.
#   * The **runtime** stage needs `ca-certificates`. The rustls roots features were
#     removed in reqwest 0.13, so certificate roots come from
#     `rustls-platform-verifier`, which on Linux reads the system trust store. An
#     empty trust store is a total upstream outage, not a degraded mode — every
#     metadata fetch and every artifact download fails — so this package is
#     load-bearing rather than cosmetic.

FROM docker.io/library/rust:1.96.0-bookworm AS build

RUN apt-get update \
 && apt-get install --yes --no-install-recommends cmake perl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# The manifest names the bench targets, so their sources have to be present for the
# manifest to describe a buildable package. Tests are discovered rather than declared
# and are deliberately left out of the image build.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY benches ./benches

# `--locked` is the point of shipping Cargo.lock: the image is built from the exact
# dependency graph the tests ran against, and a lockfile that no longer matches the
# manifest fails the build instead of silently resolving something else.
RUN cargo build --release --locked --bin probation

FROM docker.io/library/debian:bookworm-slim

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

# `serve` waits on SIGINT and installs no SIGTERM handler, and as PID 1 it gets no
# default disposition for a signal it has not handled — so a plain `docker stop` would
# wait out its whole timeout and then SIGKILL the process. Naming the signal the
# process actually listens for makes `docker stop` a graceful shutdown instead. The
# underlying gap (no SIGTERM handler in the binary) is recorded in
# `docs/operations.md`; this line stops it biting anyone using the image.
STOPSIGNAL SIGINT

ENTRYPOINT ["probation"]
CMD ["serve", "--config", "/etc/probation/config.toml"]
