#!/usr/bin/env bash
# E2E-signup-to-install and M-propagation (C32 metrics 1 and 2, C82), the release
# witness: runs that one scenario (tests/e2e/scenarios/signup-to-install.mjs) on the
# e2e stack, offline against the fakes. It prints `E2E PASS <seconds>` and
# `propagation edits p99 <= interval` and `propagation revocations p99 <= interval`,
# and exits 0 only when all three pass.
#
# Needs docker with compose (podman with podman-compose works too), node 20 or later,
# npm and openssl. Environment as tests/e2e/harness/run.mjs reads it (E2E_WORK,
# E2E_SKIP_BUILD=1, E2E_KEEP=1, E2E_COMPOSE_CMD, ...).
set -euo pipefail

e2e=$(cd "$(dirname "$0")" && pwd)
if [ ! -d "$e2e/node_modules/playwright" ]; then
  npm ci --prefix "$e2e" --no-audit --no-fund >&2
  npx --prefix "$e2e" playwright install chromium >&2
fi
exec node "$e2e/harness/run.mjs" --only E2E-signup-to-install "$@"
