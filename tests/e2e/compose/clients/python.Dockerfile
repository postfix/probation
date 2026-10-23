# A Python client container: a pinned Python image, optionally with another pip and
# tools installed at build time (the stack itself is offline).
ARG PYTHON_IMAGE=docker.io/library/python:3.15.1-slim-bookworm
FROM ${PYTHON_IMAGE}
ARG PIP_VERSION=
ARG TOOLS=
RUN if [ -n "$PIP_VERSION" ]; then pip install --no-cache-dir "pip==$PIP_VERSION"; fi \
 && if [ -n "$TOOLS" ]; then pip install --no-cache-dir $TOOLS; fi
WORKDIR /work
