#!/usr/bin/env bash
# Installs and starts the PINNED Docker Engine (29.9.2, official static build, linux x86_64) as the machine's daemon for the native
# OCI lane (tests/oci_native.rs with PROBATION_OCI_ENGINE=docker). Run on a disposable Linux runner (the GitHub-hosted ubuntu-24.04
# image), as a user with sudo. The archive is verified against the digest recorded here before anything is unpacked; a different
# digest, a missing daemon or a daemon that reports another version fails the script. The runner image's own Docker (another
# version) is stopped first so exactly one daemon owns /var/run/docker.sock.
#   tests/e2e/native/docker-engine.sh install
set -euo pipefail

VERSION=29.9.2
URL="https://download.docker.com/linux/static/stable/x86_64/docker-${VERSION}.tgz"
# sha256 of that archive, recorded 2026-11-20 from the download above (the vendor publishes no checksum file for static builds).
SHA256=9ac225999fd5e863f7694c728ef23d480616b1e5639328fa309befd4243d69eb
PREFIX="/opt/docker-${VERSION}"

[ "${1:-}" = install ] || { echo "usage: $0 install" >&2; exit 2; }
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "the pinned engine archive is for linux x86_64; this is $(uname -s)-$(uname -m)" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --silent --show-error --location --output "$work/docker.tgz" "$URL"
echo "${SHA256}  $work/docker.tgz" | sha256sum --check --strict -

sudo mkdir -p "$PREFIX"
sudo tar --extract --gzip --file "$work/docker.tgz" --directory "$PREFIX" --strip-components=1
sudo systemctl stop docker.service docker.socket containerd.service 2>/dev/null || true

# The socket belongs to the runner's own group, mode 0660 (never 666: anyone who can reach a root daemon's socket is root).
# The classic image store is selected explicitly: Docker 29 defaults a fresh install to the containerd image store, and the executed
# witness of this lane (tests/oci_native.rs) ran, and its "the storage host saw no credential" assertion is calibrated, on the
# classic store. A run on the containerd store is a different configuration and is not claimed by this lane.
GROUP="$(id -gn)"

# A transient unit keeps the daemon running after this step and gives it a name the job can inspect and stop.
sudo systemd-run --unit="dockerd-${VERSION}" --description="Docker Engine ${VERSION} (pinned)" \
  --setenv="PATH=${PREFIX}:/usr/sbin:/usr/bin:/sbin:/bin" "${PREFIX}/dockerd" --host=unix:///var/run/docker.sock \
  --group="${GROUP}" --feature containerd-snapshotter=false

for _ in $(seq 1 60); do
  if sudo "${PREFIX}/docker" version >/dev/null 2>&1 && [ -S /var/run/docker.sock ]; then break; fi
  sleep 1
done
got="$("${PREFIX}/docker" version --format '{{.Server.Version}}')"
[ "$got" = "$VERSION" ] || { echo "the daemon reports $got, not $VERSION" >&2; exit 1; }
"${PREFIX}/docker" version --format 'Docker Engine {{.Server.Version}} (api {{.Server.APIVersion}}, {{.Server.Platform.Name}}, {{.Server.Os}}/{{.Server.Arch}}); client {{.Client.Version}}'
echo "${PREFIX}" >> "${GITHUB_PATH:-/dev/null}"
