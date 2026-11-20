# An OCI registry client container: skopeo (containers/image, the registry client podman, buildah and CRI-O share) installed at image build
# time (the stack itself is offline). The registry is the firewall, reached over TLS (the CA is SSL_CERT_FILE).
ARG BASE_IMAGE=docker.io/library/debian:12-slim
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends skopeo ca-certificates jq && rm -rf /var/lib/apt/lists/*
WORKDIR /work
