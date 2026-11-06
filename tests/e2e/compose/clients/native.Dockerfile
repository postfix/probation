# One container with every pinned client and the native stack's runtime (tests/e2e/native):
# Node and npm from the pinned Node image, Python/pip/Twine/uv from the pinned Python image,
# bash and openssl for the test CA script. Base images are pinned by digest and the Python
# tools by exact version and hash (native-requirements.txt). npm is installed by exact
# version from the npm registry, whose own integrity checks apply. The stack itself is offline.
ARG NODE_IMAGE=docker.io/library/node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
ARG PYTHON_IMAGE=docker.io/library/python:3.15.1-slim-bookworm@sha256:575f8bc12ec26542e0678bc6b60e385218248019d433157ec327264a78c3a853
FROM ${NODE_IMAGE} AS node
FROM ${PYTHON_IMAGE}
ARG NPM_VERSION=11.21.1
RUN apt-get update \
 && apt-get install --yes --no-install-recommends bash openssl ca-certificates libssl3 libstdc++6 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY native-requirements.txt /tmp/native-requirements.txt
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && npm install --global "npm@$NPM_VERSION" && npm cache clean --force \
 && pip install --no-cache-dir --require-hashes -r /tmp/native-requirements.txt \
 && rm /tmp/native-requirements.txt
WORKDIR /work
