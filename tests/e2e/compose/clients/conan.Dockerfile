# A Conan 2 client container: the Python image (3.13.0) pinned by digest with Conan 2.21.0 installed at image build time (the stack itself is
# offline). The remote is the firewall, reached over TLS (the CA is REQUESTS_CA_BUNDLE).
ARG PYTHON_IMAGE=docker.io/library/python:3.13.0-slim@sha256:0de818129b26ed8f46fd772f540c80e277b67a28229531a1ba0fdacfaed19bcb
FROM ${PYTHON_IMAGE}
RUN pip install --no-cache-dir conan==2.21.0
WORKDIR /work
