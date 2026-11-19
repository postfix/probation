# A Cargo client container: the pinned Rust image (Cargo 1.96.0). The stack itself is offline, so
# nothing is installed at run time; the sparse registry is the firewall, reached over TLS.
ARG RUST_IMAGE=docker.io/library/rust:1.96.0-slim-bookworm
FROM ${RUST_IMAGE}
WORKDIR /work
