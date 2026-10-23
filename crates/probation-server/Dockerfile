# probation-server — the management server's own container image (C102). Build it from
# the repository root, which is the workspace root:
#
#   docker build -f crates/probation-server/Dockerfile .
#
# The same rules as the firewall's root `Dockerfile`: plain Dockerfile syntax (podman
# stands in for docker), the build stage brings cmake and perl for `aws-lc-sys`, and
# the runtime stage brings `ca-certificates`, because the outbound calls (OAuth and
# OIDC providers, the leaked-password range API) verify against the system trust store.

FROM docker.io/library/rust:1.96.0-bookworm AS build

RUN apt-get update \
 && apt-get install --yes --no-install-recommends cmake perl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Every workspace member's manifest has to be present for `--locked` to resolve, so the
# whole workspace goes in, as in the root `Dockerfile`.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY benches ./benches
COPY crates ./crates

RUN cargo build --release --locked -p probation-server --bin probation-server

FROM docker.io/library/debian:bookworm-slim

RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/probation-server /usr/local/bin/probation-server
RUN probation-server --version

# The server keeps no state on disk: Postgres holds everything. It runs as a normal
# user. Its settings file is mounted at the path below (docs/management-server.md);
# secrets come from the environment, never from that file.
RUN useradd --system --no-create-home probation
USER probation

EXPOSE 8080

ENTRYPOINT ["probation-server"]
CMD ["serve", "--config", "/etc/probation-server/config.toml"]
