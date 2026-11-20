# A Conan 2 client container: the pinned Python image (3.13.0) with Conan 2.21.0 installed at image build time (the stack itself is
# offline). The remote is the firewall, reached over TLS (the CA is REQUESTS_CA_BUNDLE).
ARG PYTHON_IMAGE=docker.io/library/python:3.13.0-slim
FROM ${PYTHON_IMAGE}
RUN pip install --no-cache-dir conan==2.21.0
WORKDIR /work
