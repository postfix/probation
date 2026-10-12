#!/usr/bin/env bash
# Build the probation binary in a container (Docker or Podman) and install it on
# the host. For building on a machine with no Rust toolchain: this still needs a
# container engine, but nothing else.
set -euo pipefail

PREFIX="/usr/local/bin"
ENGINE=""
IMAGE_TAG="probation:build-install"

usage() {
  echo "Usage: $0 [--engine docker|podman] [--prefix DIR]"
  echo
  echo "  --engine   container engine to use (default: auto-detect, preferring docker)"
  echo "  --prefix   directory to install the 'probation' binary into (default: /usr/local/bin)"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --engine) ENGINE="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

if [ -z "$ENGINE" ]; then
  if command -v docker >/dev/null 2>&1; then
    ENGINE="docker"
  elif command -v podman >/dev/null 2>&1; then
    ENGINE="podman"
  else
    echo "Need 'docker' or 'podman' installed." >&2
    exit 1
  fi
fi
echo "==> Using container engine: $ENGINE"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building the image (this compiles probation inside the container)"
"$ENGINE" build -t "$IMAGE_TAG" .

CONTAINER_ID="$("$ENGINE" create "$IMAGE_TAG")"
trap '"$ENGINE" rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true' EXIT

TMP_BIN="$(mktemp)"
echo "==> Extracting the binary"
"$ENGINE" cp "$CONTAINER_ID:/usr/local/bin/probation" "$TMP_BIN"
chmod +x "$TMP_BIN"

echo "==> Installing to $PREFIX/probation"
if [ -w "$PREFIX" ] || [ -w "$PREFIX/probation" ] 2>/dev/null; then
  install -m 0755 "$TMP_BIN" "$PREFIX/probation"
else
  echo "    ($PREFIX is not writable; using sudo)"
  sudo install -m 0755 "$TMP_BIN" "$PREFIX/probation"
fi
rm -f "$TMP_BIN"

echo "==> Done: $("$PREFIX/probation" --version 2>/dev/null || echo "$PREFIX/probation")"
