# A JavaScript client container: a pinned Node image, optionally with another npm and
# global tools installed at build time (the stack itself is offline). The Node images
# ship yarn 1.22.22; --force lets a global yarn 4 replace it.
ARG NODE_IMAGE=docker.io/library/node:24.22.1-bookworm-slim
FROM ${NODE_IMAGE}
ARG NPM_VERSION=
ARG GLOBALS=
RUN if [ -n "$NPM_VERSION" ]; then npm install --global "npm@$NPM_VERSION"; fi \
 && if [ -n "$GLOBALS" ]; then npm install --global --force $GLOBALS; fi \
 && npm cache clean --force
WORKDIR /work
