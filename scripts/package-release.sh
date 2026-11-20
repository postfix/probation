#!/usr/bin/env bash
# Assembles the directory a release archive is made from: the binary, the installer for its OS, deploy/, the samples, and (Windows) the
# libraries the binary loads, with SHA256SUMS over everything executable so the installer verifies what it installs. The release workflow
# and the native-service smoke jobs both call this, so the layout that is released is the layout that is tested.
#   scripts/package-release.sh TARGET BINARY OUTDIR [DLLDIR]      (VERSION=vX.Y.Z names the directory; default "dev")
set -euo pipefail
[ $# -ge 3 ] || { echo "usage: $0 TARGET BINARY OUTDIR [DLLDIR]" >&2; exit 2; }
TARGET="$1"; BINARY="$2"; OUT="$3"; DLLDIR="${4:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$OUT/probation-${VERSION:-dev}-$TARGET"
case "$TARGET" in *windows*) EXE=probation.exe; INSTALLER=install-service.ps1 ;; *) EXE=probation; INSTALLER=install-service.sh ;; esac
[ -f "$BINARY" ] || { echo "no binary at $BINARY" >&2; exit 1; }
mkdir -p "$PKG"
cp "$BINARY" "$PKG/$EXE"
cp "$ROOT/README.md" "$ROOT/LICENSE" "$ROOT/config.sample.toml" "$ROOT/blocklist.sample.json" "$ROOT/scripts/$INSTALLER" "$PKG/"
cp -R "$ROOT/deploy" "$PKG/deploy"
chmod 755 "$PKG/$EXE"
# The marker that tells the installers this directory is a release package, whose provenance they must verify (a missing gh, cosign or bundle
# refuses unless --allow-unverified).
printf 'probation release package\n' > "$PKG/RELEASE-PACKAGE"
if [ -n "$DLLDIR" ]; then
  shopt -s nullglob
  dlls=("$DLLDIR"/libcrypto-3*.dll)
  [ ${#dlls[@]} -gt 0 ] || { echo "no libcrypto-3*.dll in $DLLDIR" >&2; exit 1; }
  cp "${dlls[@]}" "$PKG/"
fi
cd "$PKG"
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
$SUM "$EXE" "$INSTALLER" RELEASE-PACKAGE *.dll > SHA256SUMS 2>/dev/null || $SUM "$EXE" "$INSTALLER" RELEASE-PACKAGE > SHA256SUMS
echo "$PKG"
