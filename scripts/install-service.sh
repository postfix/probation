#!/usr/bin/env bash
# Install, upgrade or remove Probation as an operating-system service on Linux (systemd) and macOS (launchd).
# Windows has scripts/install-service.ps1. docs/operations.md section "Native service".
#
#   install-service.sh install   [options]   first install: creates only what is absent
#   install-service.sh upgrade   [options]   stop, keep the old binary, install the new one, validate, restart
#   install-service.sh uninstall [options]   stop, disable, remove only what install recorded
#
# Never replaces an existing config.toml, blocklist, TLS file, key or data: a sample is copied only where nothing exists,
# an upgrade changes the binary and the service definition and nothing else, and uninstall leaves config and data in place.
# Package-manager configuration (npm, pip: registry URLs and credential entries) is not touched here; scripts/install-local.sh
# edits it and preserves every entry it does not own.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-service.sh {install|upgrade|uninstall} [options]
  --scope system|user   system: a machine service run by a dedicated account (needs root). user: this login's own
                        service (systemd --user, LaunchAgent), for a developer machine. Default: system
  --binary PATH         the probation binary to install (install, upgrade). Default: ./probation beside this script's
                        package, else `probation` on PATH
  --config-dir DIR      default: /etc/probation (system), ~/.config/probation (user)
  --data-dir DIR        default: /var/lib/probation (system), ~/.local/share/probation (user)
  --log-dir DIR         default: /var/log/probation (system), <data-dir>/log (user)
  --bin-dir DIR         where the binary is installed. Default: /usr/local/bin (system), ~/.local/bin (user)
  --listen ADDR         listener for a new config.toml. Default: 127.0.0.1:8080 (loopback; never widened here)
  --public-url URL      public_url for a new config.toml (https required). Default: https://localhost:<listen port>
  --tls-cert FILE --tls-key FILE
                        existing certificate and key to name in a new config.toml (never generated or copied here;
                        scripts/install-local.sh makes a certificate). Without them the listener is plain HTTP, for a
                        TLS-terminating proxy in front.
  --name NAME           unit/label stem. Default: probation (launchd label com.postfix.<name>)
  --service-user NAME   system scope account. Default: probation (Linux), _probation (macOS); created when absent
  --log-namespace NS    Linux system scope: give the unit its own journald namespace, capped at 200 MiB; falls back to the
                        shared journal where the host cannot do it
  --platform linux|macos  default: this host
  --no-verify           (also --allow-unverified) do not verify the release attestation of the binary (done when `gh` is installed and the binary is the
                        one shipped beside this script; a failed verification refuses the install)
  --signer-workflow PATH  the workflow file whose attestation `gh attestation verify` accepts, inside this repository's .github/workflows
                        (default .github/workflows/release.yml). Anything else (another path, `..`, a URL, another repository) is refused.
                        For CI-built packages that a workflow other than the release attests.
  --cosign-bundle FILE  the Sigstore bundle of the binary (default: probation.sigstore.json beside it); verified with `cosign` when
                        cosign is installed, keyless, against this project's release workflow identity
  --dev-package         install the binary shipped beside this script although the directory carries no RELEASE-PACKAGE marker
                        (a build you made yourself); said loudly, and its provenance is checked only if the tools are there
  --no-staging          with `--root /`: really install into the running system (a root of / is otherwise refused)
  --no-start            install the definition, do not start it
  --root DIR            staging root: every path is placed under DIR and NO service manager, account or ownership
                        command runs. For building a package or testing the files an install writes.
EOF
  exit 1
}

ACTION="${1:-}"
[ -n "$ACTION" ] && shift || usage
case "$ACTION" in install|upgrade|uninstall) ;; *) usage ;; esac

SCOPE=system BINARY="" CONFIG_DIR="" DATA_DIR="" LOG_DIR="" BIN_DIR="" LISTEN="127.0.0.1:8080" NAME=probation
COSIGN_BUNDLE="" SERVICE_USER="" LOG_NS="" PLATFORM="" START=1 ROOT="" ROOT_GIVEN=0 NO_STAGING=0 VERIFY=1 DEV_PACKAGE=0 SIGNER_WORKFLOW=".github/workflows/release.yml" PUBLIC_URL="" TLS_CERT="" TLS_KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --scope) SCOPE="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --log-dir) LOG_DIR="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --tls-cert) TLS_CERT="$2"; shift 2 ;;
    --tls-key) TLS_KEY="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --service-user) SERVICE_USER="$2"; shift 2 ;;
    --log-namespace) LOG_NS="$2"; shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    --no-start) START=0; shift ;;
    --root) ROOT="${2%/}"; ROOT_GIVEN=1; shift 2 ;;
    --no-staging) NO_STAGING=1; shift ;;
    --dev-package) DEV_PACKAGE=1; shift ;;
    --no-verify|--allow-unverified) VERIFY=0; shift ;;
    --signer-workflow)
      # One workflow FILE of the pinned repository: no other directory, no `..`, no URL or repository prefix, no leading dot in the name.
      [[ "${2-}" =~ ^\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9._-]*\.ya?ml$ ]] || { echo "--signer-workflow must be a workflow file under .github/workflows of this repository (e.g. .github/workflows/release.yml), got '${2-}'" >&2; exit 1; }
      SIGNER_WORKFLOW="$2"; shift 2 ;;
    --cosign-bundle) COSIGN_BUNDLE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done
case "$SCOPE" in system|user) ;; *) echo "--scope must be system or user" >&2; exit 1 ;; esac
case "$NAME" in *[!a-zA-Z0-9._-]*|"") echo "--name: letters, digits, . _ - only" >&2; exit 1 ;; esac
if [ -z "$PLATFORM" ]; then
  case "$(uname -s)" in Darwin) PLATFORM=macos ;; *) PLATFORM=linux ;; esac
fi
case "$PLATFORM" in linux|macos) ;; *) echo "--platform must be linux or macos" >&2; exit 1 ;; esac


# ---------------------------------------------------------------- argument validation: refusing is the escaping
# Paths and names end up in a unit, a plist, a TOML file and awk programs. Anything outside this alphabet (spaces, quotes, `&`, `\`,
# `<`, `$`, backticks...) is refused rather than escaped three different ways.
bad() { echo "install-service: $1" >&2; exit 1; }
safe_path() { # safe_path LABEL VALUE [absolute]
  [ -z "$2" ] && return 0
  [[ "$2" =~ ^[A-Za-z0-9._/@:+=,-]+$ ]] || bad "$1: '$2' has a character outside A-Z a-z 0-9 . _ / @ : + = , -"
  case "/$2/" in */../*) bad "$1: '$2' has a '..' component" ;; esac
  if [ "${3:-}" = absolute ]; then case "$2" in /*) ;; *) bad "$1: '$2' must be an absolute path" ;; esac; fi
}
safe_text() { [ -z "$2" ] || [[ "$2" =~ ^[][A-Za-z0-9._:/@%+=,-]+$ ]] || bad "$1: '$2' has a character outside the URL alphabet"; }
if [ "$ROOT_GIVEN" -eq 1 ]; then
  if [ -z "$ROOT" ]; then
    [ "$NO_STAGING" -eq 1 ] || bad "--root / would install into the running system: leave --root out, or pass --no-staging to mean it"
  else
    safe_path --root "$ROOT" absolute
  fi
fi
[ -z "$SERVICE_USER" ] || [[ "$SERVICE_USER" =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,31}$ ]] || bad "--service-user: '$SERVICE_USER' is not a plain account name"
safe_path --config-dir "$CONFIG_DIR" absolute; safe_path --data-dir "$DATA_DIR" absolute; safe_path --log-dir "$LOG_DIR" absolute
safe_path --bin-dir "$BIN_DIR" absolute; safe_path --binary "$BINARY"; safe_path --cosign-bundle "$COSIGN_BUNDLE"; safe_path --tls-cert "$TLS_CERT" absolute; safe_path --tls-key "$TLS_KEY" absolute
safe_text --listen "$LISTEN"; safe_text --public-url "$PUBLIC_URL"; safe_text --log-namespace "$LOG_NS"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A release package keeps deploy/ and the samples beside this script; a checkout keeps them one level up.
if [ -d "$HERE/deploy" ]; then RES="$HERE"; else RES="$(cd "$HERE/.." && pwd)"; fi

STAGING=0
[ -n "$ROOT" ] && STAGING=1
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
if [ "$SCOPE" = system ] && [ "$STAGING" -eq 0 ] && [ "$IS_ROOT" -eq 0 ]; then
  echo "A system service needs root: run this with sudo (or use --scope user)." >&2
  exit 1
fi
if [ "$SCOPE" = user ] && [ "$IS_ROOT" -eq 1 ] && [ "$STAGING" -eq 0 ]; then
  echo "--scope user installs for the login that runs this; root is not a login (use --scope system)." >&2
  exit 1
fi

if [ "$SCOPE" = system ]; then
  : "${CONFIG_DIR:=/etc/$NAME}" "${DATA_DIR:=/var/lib/$NAME}" "${LOG_DIR:=/var/log/$NAME}" "${BIN_DIR:=/usr/local/bin}"
  if [ -z "$SERVICE_USER" ]; then
    if [ "$PLATFORM" = macos ]; then SERVICE_USER="_$NAME"; else SERVICE_USER="$NAME"; fi
  fi
else
  : "${CONFIG_DIR:=$HOME/.config/$NAME}" "${DATA_DIR:=$HOME/.local/share/$NAME}" "${BIN_DIR:=$HOME/.local/bin}"
  : "${LOG_DIR:=$DATA_DIR/log}"
  SERVICE_USER="$(id -un)"
fi
safe_path "the default config dir" "$CONFIG_DIR" absolute; safe_path "the default data dir" "$DATA_DIR" absolute
safe_path "the default log dir" "$LOG_DIR" absolute; safe_path "the default bin dir" "$BIN_DIR" absolute
BIN_PATH="$BIN_DIR/probation"
CONFIG_FILE="$CONFIG_DIR/config.toml"
BLOCKLIST="$CONFIG_DIR/blocklist.json"
MANIFEST="$CONFIG_DIR/.service-install-$NAME"
LABEL="com.postfix.$NAME"
UID_NOW="$(id -u)"
# macOS: launchd opens the stdout/stderr files as root, so they live in a ROOT-owned directory (the service owns only its own
# files, never the directory that holds them, and cannot swap one for a symlink); the service-owned log directory keeps the
# decision log the service writes itself. A LaunchAgent is the login's own, so one directory serves.
if [ "$PLATFORM" = macos ] && [ "$SCOPE" = system ]; then LAUNCHD_LOG_DIR="${LOG_DIR}-launchd"; else LAUNCHD_LOG_DIR="$LOG_DIR"; fi

if [ "$PLATFORM" = linux ]; then
  if [ "$SCOPE" = system ]; then DEF_DIR="/etc/systemd/system"; else DEF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"; fi
  DEF_FILE="$DEF_DIR/$NAME.service"
else
  if [ "$SCOPE" = system ]; then DEF_DIR="/Library/LaunchDaemons"; else DEF_DIR="$HOME/Library/LaunchAgents"; fi
  DEF_FILE="$DEF_DIR/$LABEL.plist"
fi
# Where a file is actually written (a staging root moves everything); the paths INSIDE a definition stay the real ones.
at() { printf '%s%s' "$ROOT" "$1"; }

say() { echo "==> $*"; }
die() { echo "install-service: $*" >&2; exit 1; }

# ---------------------------------------------------------------- manifest: only what is recorded is ever removed
record() { printf '%s\n' "$1" >> "$(at "$MANIFEST")"; }
recorded() { [ -f "$(at "$MANIFEST")" ] && grep -qxF "$1" "$(at "$MANIFEST")"; }

# ---------------------------------------------------------------- service definitions
unit_text() {
  # deploy/probation.service is the one definition; install replaces only its example paths and account.
  local unit="$RES/deploy/probation.service"
  [ -f "$unit" ] || die "missing $unit"
  awk -v bin="$BIN_PATH" -v cfg="$CONFIG_FILE" -v user="$SERVICE_USER" -v scope="$SCOPE" -v data="$DATA_DIR" \
      -v logdir="$LOG_DIR" -v ns="$LOG_NS" '
    # A user manager has no privilege to build mount namespaces: only the directives that need none stay (seccomp, address families,
    # personality, W^X; an empty capability set needs CAP_SETPCAP, which a user manager lacks: status 218/CAPABILITIES).
    scope == "user" && /^(User|Group|ProtectSystem|ProtectHome|PrivateTmp|PrivateDevices|ProtectKernelTunables|ProtectKernelModules|ProtectKernelLogs|ProtectControlGroups|ProtectClock|ProtectHostname|ProtectProc|ProcSubset|RemoveIPC|CapabilityBoundingSet|AmbientCapabilities|StateDirectory|StateDirectoryMode|LogsDirectory|LogsDirectoryMode)=/ { next }
    scope == "user" && /^WantedBy=/ { print "WantedBy=default.target"; next }
    scope == "system" && /^User=/ { print "User=" user; next }
    scope == "system" && /^Group=/ { print "Group=" user; next }
    scope == "system" && /^StateDirectory=/ && data != "/var/lib/probation" { print "ReadWritePaths=" data; next }
    scope == "system" && /^StateDirectoryMode=/ && data != "/var/lib/probation" { next }
    scope == "system" && /^LogsDirectory=/ && logdir != "/var/log/probation" { print "ReadWritePaths=" logdir; next }
    scope == "system" && /^LogsDirectoryMode=/ && logdir != "/var/log/probation" { next }
    { gsub("/usr/local/bin/probation", bin); gsub("/etc/probation/config.toml", cfg); print }
    /^\[Service\]/ && ns != "" { print "LogNamespace=" ns }
  ' "$unit"
}

plist_text() {
  local user_keys=""
  if [ "$SCOPE" = system ]; then
    user_keys="  <key>UserName</key><string>$SERVICE_USER</string>
  <key>GroupName</key><string>$SERVICE_USER</string>"
  fi
  # KeepAlive/SuccessfulExit=false restarts a failure and a settings restart (exit 75) but leaves an operator's stop
  # (SIGTERM, exit 0) stopped; ThrottleInterval 5 is the restart delay; ExitTimeOut 45 outlasts the 30 s request drain;
  # Umask 63 is 0077.
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_PATH</string>
    <string>serve</string>
    <string>--config</string>
    <string>$CONFIG_FILE</string>
  </array>
$user_keys
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>ExitTimeOut</key><integer>45</integer>
  <key>Umask</key><integer>63</integer>
  <key>WorkingDirectory</key><string>$DATA_DIR</string>
  <key>StandardOutPath</key><string>$LAUNCHD_LOG_DIR/$NAME.stdout.log</string>
  <key>StandardErrorPath</key><string>$LAUNCHD_LOG_DIR/$NAME.stderr.log</string>
</dict>
</plist>
EOF
}

# ---------------------------------------------------------------- privileged helpers (all no-ops when staging)
own() { # own OWNER:GROUP MODE PATH...  (mode always; ownership only for a real system install running as root)
  local who="$1" mode="$2"; shift 2
  chmod "$mode" "$@"
  if [ "$STAGING" -eq 0 ] && [ "$IS_ROOT" -eq 1 ] && [ "$SCOPE" = system ]; then chown "$who" "$@"; fi
}

ensure_account() {
  [ "$SCOPE" = system ] && [ "$STAGING" -eq 0 ] || return 0
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then return 0; fi
  say "Creating the '$SERVICE_USER' service account"
  if [ "$PLATFORM" = macos ]; then
    local id=299 # the 200-400 range is for daemon accounts; take the first free one
    while dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$id" || dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$id"; do id=$((id - 1)); done
    dscl . -create "/Groups/$SERVICE_USER"
    dscl . -create "/Groups/$SERVICE_USER" PrimaryGroupID "$id"
    dscl . -create "/Users/$SERVICE_USER"
    dscl . -create "/Users/$SERVICE_USER" UniqueID "$id"
    dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$id"
    dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$SERVICE_USER" RealName "Probation package firewall"
    dscl . -create "/Users/$SERVICE_USER" IsHidden 1
  else
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  record "account:$SERVICE_USER"
}

# A sample is copied only where nothing exists. Returns 0 when it created the file.
create_if_absent() { # create_if_absent SRC DEST MODE
  local dest; dest="$(at "$2")"
  if [ -e "$dest" ]; then say "Keeping the existing $2"; return 1; fi
  cp "$1" "$dest"
  chmod "$3" "$dest"
  record "file:$2"
  say "Created $2 from the sample"
}

CONFIG_CREATED=0
write_config() {
  local sample="$RES/config.sample.toml"
  [ -f "$sample" ] || sample="$RES/../config.sample.toml"
  [ -f "$sample" ] || die "missing config.sample.toml"
  local dest; dest="$(at "$CONFIG_FILE")"
  if [ -e "$dest" ]; then say "Keeping the existing $CONFIG_FILE"; return 0; fi
  [ "${LISTEN##*:}" != "$LISTEN" ] || die "--listen needs host:port"
  [ -n "$PUBLIC_URL" ] || PUBLIC_URL="https://localhost:${LISTEN##*:}"
  awk -v listen="$LISTEN" -v url="$PUBLIC_URL" -v data="$DATA_DIR" -v bl="$BLOCKLIST" '
    /^listen = /        { print "listen = \"" listen "\""; next }
    /^public_url = /    { print "public_url = \"" url "\""; next }
    /^data_dir = /      { print "data_dir = \"" data "\""; next }
    /^blocklist_file = /{ print "blocklist_file = \"" bl "\""; next }
    { print }' "$sample" > "$dest"
  # The decision log file rolls itself over (docs/operations.md section 8): bounded at 200 MiB, never logrotate.
  printf '\nlog_file_path = "%s/decisions.ndjson"\nlog_file_max_bytes = 104857600\n' "$LOG_DIR" >> "$dest"
  if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
    printf 'tls_cert_path = "%s"\ntls_key_path = "%s"\n' "$TLS_CERT" "$TLS_KEY" >> "$dest"
  elif [ -n "$TLS_CERT$TLS_KEY" ]; then
    die "--tls-cert and --tls-key go together"
  fi
  chmod 640 "$dest"
  CONFIG_CREATED=1
  record "file:$CONFIG_FILE"
  say "Created $CONFIG_FILE (listen $LISTEN)"
}

install_binary() {
  [ -x "$BINARY" ] || die "no executable probation binary at '$BINARY' (--binary)"
  mkdir -p "$(at "$BIN_DIR")"
  local dest existed=0; dest="$(at "$BIN_PATH")"
  [ -e "$dest" ] && existed=1
  if [ "$existed" -eq 1 ] && [ "$ACTION" = install ] && ! recorded "file:$BIN_PATH" && ! cmp -s "$BINARY" "$dest"; then
    die "$BIN_PATH exists and was not installed by this script; use 'upgrade', or --bin-dir/--name for a second install"
  fi
  # Written beside the target and renamed over it: a running old binary keeps its inode, a crash leaves one whole file.
  install -m 755 "$BINARY" "$dest.new"
  mv -f "$dest.new" "$dest"
  # Only a file this run created is ours to remove later: an identical program that was already there stays the operator's.
  if [ "$existed" -eq 0 ]; then recorded "file:$BIN_PATH" || record "file:$BIN_PATH"; fi
}

# A file that must not exist yet is created with noclobber; one that exists is kept and never recorded as ours.
create_new() { # create_new DEST CONTENT
  local dest; dest="$(at "$1")"
  if [ -e "$dest" ] || [ -L "$dest" ]; then say "Keeping the existing $1 (not ours)"; return 1; fi
  ( set -o noclobber; printf '%s' "$2" > "$dest" ) || die "cannot create $1"
  record "file:$1"
}

# Refuses a symlink; creates the file empty, owned by the service and 0600, inside a directory the service does not own.
precreate_log() {
  local f; f="$(at "$1")"
  [ ! -L "$f" ] || die "$1 is a symbolic link: refusing to write a log through it"
  if [ ! -e "$f" ]; then ( set -o noclobber; : > "$f" ) || die "cannot create $1"; record "file:$1"; fi
  own "$SERVICE_USER:$SERVICE_USER" 600 "$f"
}

# ProtectHome=yes hides /home, /root and /run/user from a system service: a path there is unusable, so say so at install.
check_home_paths() {
  [ "$SCOPE" = system ] && [ "$PLATFORM" = linux ] || return 0
  local label path
  for label in --tls-cert --tls-key --data-dir --log-dir --config-dir --bin-dir; do
    case "$label" in --bin-dir) path="$BIN_DIR" ;; --tls-cert) path="$TLS_CERT" ;; --tls-key) path="$TLS_KEY" ;; --data-dir) path="$DATA_DIR" ;; --log-dir) path="$LOG_DIR" ;; *) path="$CONFIG_DIR" ;; esac
    case "$path" in /home/*|/root/*|/run/user/*) die "$label $path is under a directory the system unit hides (ProtectHome=yes): move it (for example under /etc/$NAME or /var/lib/$NAME), or install with --scope user" ;; esac
  done
}

# A RELEASE package (it carries the RELEASE-PACKAGE marker and the binary beside this script is the one installed) must verify: `gh
# attestation verify` pinned to this repository and its release workflow, then the keyless cosign bundle. A missing gh, cosign or bundle
# REFUSES, unless --no-verify / --allow-unverified is passed, which is said loudly. A binary named with --binary, or a package without
# the marker (a checkout), is not a release artifact: it is checked softly when the tools happen to be there.
# The directory of a file, canonical, joined to its name: `./probation`, `../pkg/probation` and a symlink to it are all the same file.
canon_file() {
  local f="$1" t n=0
  while [ -L "$f" ] && [ "$n" -lt 20 ]; do
    t="$(readlink "$f")"; case "$t" in /*) f="$t" ;; *) f="$(dirname "$f")/$t" ;; esac; n=$((n + 1))
  done
  printf '%s/%s' "$(cd "$(dirname "$f")" 2>/dev/null && pwd -P)" "$(basename "$f")"
}

verify_binary() {
  local repo="${PROBATION_RELEASE_REPO:-postfix/probation}" release=0 shipped=0
  if [ -e "$HERE/probation" ] && [ -e "$BINARY" ] && [ "$(canon_file "$BINARY")" = "$(canon_file "$HERE/probation")" ]; then shipped=1; fi
  [ -f "$HERE/RELEASE-PACKAGE" ] && release=1
  if [ "$VERIFY" -eq 0 ]; then
    [ "$shipped" -eq 0 ] || echo "install-service: WARNING: verification of $BINARY is DISABLED (--no-verify): its provenance is not checked" >&2
    return 0
  fi
  [ "$shipped" -eq 1 ] || return 0
  if [ "$release" -eq 0 ]; then
    [ "$DEV_PACKAGE" -eq 1 ] || die "$HERE has no RELEASE-PACKAGE marker, so it is not a release package and its provenance cannot be verified: pass --dev-package to install a build you made yourself anyway (or --binary for an arbitrary binary)"
    echo "install-service: WARNING: $BINARY comes from a package that is not marked as a release (--dev-package): it is installed without a provenance guarantee" >&2
  fi
  if ! command -v gh >/dev/null 2>&1; then
    [ "$release" -eq 0 ] || die "this is a release package and gh is not installed, so its attestation cannot be verified: install gh, or pass --allow-unverified to accept it unchecked"
    say "gh is not installed: the release attestation of $BINARY was NOT verified"
  else
    gh attestation verify "$BINARY" --repo "$repo" --signer-workflow "$repo/$SIGNER_WORKFLOW" >/dev/null 2>&1 \
      || die "the release attestation of $BINARY does not verify (gh attestation verify, pinned to $repo and its release workflow); refusing. Use --no-verify only for a build you made yourself"
    say "Verified the release attestation of $BINARY"
  fi
  RELEASE_PACKAGE="$release" verify_cosign
}

# The keyless cosign signature, when cosign is installed and a bundle is beside the binary (or named): a bundle that does not verify
# refuses the install. No cosign, or no bundle, is said out loud and is not a failure (gh attestation above is the default check).
verify_cosign() {
  local bundle="${COSIGN_BUNDLE:-$BINARY.sigstore.json}"
  [ -z "$COSIGN_BUNDLE" ] && [ ! -f "$bundle" ] && bundle="$HERE/probation.sigstore.json"
  if ! command -v cosign >/dev/null 2>&1; then
    [ "${RELEASE_PACKAGE:-0}" -eq 0 ] || die "this is a release package and cosign is not installed: install cosign, or pass --allow-unverified"
    say "cosign is not installed: the cosign signature of $BINARY was NOT verified"; return 0
  fi
  if [ ! -f "$bundle" ]; then
    [ "${RELEASE_PACKAGE:-0}" -eq 0 ] || die "this is a release package and its cosign bundle is missing ($bundle): download probation-<version>-<target>.sigstore.json, or pass --allow-unverified"
    say "no cosign bundle ($bundle): the cosign signature of $BINARY was NOT verified"; return 0
  fi
  local repo_re; repo_re="$(printf '%s' "${PROBATION_RELEASE_REPO:-postfix/probation}" | sed -e 's/[.[\*^$()+?{|]/\\&/g')"
  cosign verify-blob --bundle "$bundle" \
    --certificate-identity-regexp "^https://github\.com/${repo_re}/\.github/workflows/release\.yml@refs/tags/.+\$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$BINARY" >/dev/null 2>&1 \
    || die "the cosign signature of $BINARY does not verify; refusing. Use --no-verify only for a build you made yourself"
  say "Verified the cosign signature of $BINARY"
}

# ---------------------------------------------------------------- the service manager
sm_linux() { if [ "$SCOPE" = user ]; then systemctl --user "$@"; else systemctl "$@"; fi; }

service_stop() {
  [ "$STAGING" -eq 0 ] || return 0
  if [ "$PLATFORM" = linux ]; then
    sm_linux stop "$NAME.service" 2>/dev/null || true
  elif [ "$SCOPE" = system ]; then
    launchctl bootout "system/$LABEL" 2>/dev/null || true
  else
    launchctl bootout "gui/$UID_NOW/$LABEL" 2>/dev/null || true
  fi
}

service_start() {
  [ "$STAGING" -eq 0 ] || return 0
  if [ "$PLATFORM" = linux ]; then
    sm_linux daemon-reload
    sm_linux enable "$NAME.service" >/dev/null 2>&1
    sm_linux restart "$NAME.service"
    sleep 1
    if ! sm_linux is-active --quiet "$NAME.service" && [ -n "$LOG_NS" ]; then
      # A host that cannot give the unit its own journal namespace (some containers) must not crash-loop over a log nicety.
      say "LogNamespace is not supported here; using the shared journal"
      awk '!/^LogNamespace=/' "$DEF_FILE" > "$DEF_FILE.tmp" && mv -f "$DEF_FILE.tmp" "$DEF_FILE"
      sm_linux daemon-reload
      sm_linux restart "$NAME.service"
      sleep 1
    fi
    sm_linux is-active --quiet "$NAME.service" || { sm_linux --no-pager status "$NAME.service" || true; die "the service did not start"; }
  elif [ "$SCOPE" = system ]; then
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    launchctl bootstrap system "$DEF_FILE"
    launchctl enable "system/$LABEL"
    launchctl kickstart -k "system/$LABEL"
  else
    launchctl bootout "gui/$UID_NOW/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$UID_NOW" "$DEF_FILE"
    launchctl enable "gui/$UID_NOW/$LABEL"
    launchctl kickstart -k "gui/$UID_NOW/$LABEL"
  fi
}

service_disable() {
  [ "$STAGING" -eq 0 ] || return 0
  if [ "$PLATFORM" = linux ]; then
    sm_linux disable "$NAME.service" >/dev/null 2>&1 || true
  elif [ "$SCOPE" = system ]; then
    launchctl disable "system/$LABEL" 2>/dev/null || true
  else
    launchctl disable "gui/$UID_NOW/$LABEL" 2>/dev/null || true
  fi
}

write_definition() {
  mkdir -p "$(at "$DEF_DIR")"
  local dest tmp; dest="$(at "$DEF_FILE")"; tmp="$dest.new"
  if [ "$PLATFORM" = linux ]; then unit_text > "$tmp"; else plist_text > "$tmp"; fi
  chmod 644 "$tmp"
  if [ "$ACTION" = upgrade ] && [ -f "$dest" ] && ! cmp -s "$tmp" "$dest"; then cp -p "$dest" "$dest.prev"; fi
  mv -f "$tmp" "$dest"
  recorded "file:$DEF_FILE" || record "file:$DEF_FILE"
}

# ---------------------------------------------------------------- actions
validate_as_service() { # validate_as_service BINARY : the configuration, as the service account would read it
  local bin="$1"
  [ "$STAGING" -eq 0 ] || return 0
  if [ "$SCOPE" = system ] && [ "$IS_ROOT" -eq 1 ]; then
    if command -v runuser >/dev/null 2>&1; then runuser -u "$SERVICE_USER" -- "$bin" check-config "$CONFIG_FILE"
    else sudo -u "$SERVICE_USER" "$bin" check-config "$CONFIG_FILE"; fi
  else
    "$bin" check-config "$CONFIG_FILE"
  fi
}

# A release package carries the binary beside this script; otherwise whatever `probation` the PATH names.
default_binary() {
  [ -n "$BINARY" ] && return 0
  if [ -x "$HERE/probation" ]; then BINARY="$HERE/probation"; else BINARY="$(command -v probation || true)"; fi
}

do_install() {
  default_binary
  verify_binary
  check_home_paths
  if [ -f "$(at "$DEF_FILE")" ]; then
    if recorded "file:$DEF_FILE"; then die "$NAME is already installed here; use 'upgrade' to replace the binary"; fi
    die "$DEF_FILE exists and was not installed by this script; use another --name"
  fi
  # Directories that already exist are the operator's: their owner and mode are not touched. New ones get the documented modes.
  # System: the config belongs to root and is only READABLE by the service (the service cannot change its own policy);
  # the data belongs to the service alone. User scope: everything is the login's own.
  new_dir "$CONFIG_DIR" "$([ "$SCOPE" = system ] && echo "root:$SERVICE_USER" || echo "")" "$([ "$SCOPE" = system ] && echo 750 || echo 700)"
  ensure_account
  new_dir "$DATA_DIR" "$SERVICE_USER:$SERVICE_USER" 700
  new_dir "$LOG_DIR" "$SERVICE_USER:$SERVICE_USER" 750
  write_config
  create_if_absent "$RES/blocklist.sample.json" "$BLOCKLIST" 640 || true
  if [ "$CONFIG_CREATED" -eq 1 ]; then
    if [ "$SCOPE" = user ]; then chmod 600 "$(at "$CONFIG_FILE")" "$(at "$BLOCKLIST")" 2>/dev/null || true; else own "root:$SERVICE_USER" 640 "$(at "$CONFIG_FILE")" 2>/dev/null || true; fi
  fi
  install_binary
  validate_as_service "$BIN_PATH"
  write_definition
  if [ -n "$LOG_NS" ] && [ "$PLATFORM" = linux ] && [ "$SCOPE" = system ]; then
    mkdir -p "$(at /etc/systemd)"
    create_new "/etc/systemd/journald@$LOG_NS.conf" $'[Journal]\nStorage=persistent\nSystemMaxUse=200M\n' || true
  fi
  if [ "$PLATFORM" = macos ] && [ "$SCOPE" = system ]; then
    new_dir "$LAUNCHD_LOG_DIR" "root:wheel" 755
    precreate_log "$LAUNCHD_LOG_DIR/$NAME.stdout.log"
    precreate_log "$LAUNCHD_LOG_DIR/$NAME.stderr.log"
    # launchd does not rotate stdout: newsyslog (root) rotates the two files, two generations of 50 MB, in the root-owned directory.
    mkdir -p "$(at /etc/newsyslog.d)"
    create_new "/etc/newsyslog.d/$NAME.conf" "$(printf '%s/%s.stdout.log %s:%s 600 2 51200 * J\n%s/%s.stderr.log %s:%s 600 2 51200 * J\n' \
      "$LAUNCHD_LOG_DIR" "$NAME" "$SERVICE_USER" "$SERVICE_USER" "$LAUNCHD_LOG_DIR" "$NAME" "$SERVICE_USER" "$SERVICE_USER")"$'\n' || true
  fi
  low_port_dropin
  say "Installed $DEF_FILE"
  if [ "$START" -eq 1 ]; then service_start; [ "$STAGING" -eq 1 ] || say "Started $NAME"; fi
}

# The unit keeps no capability, so a port below 1024 cannot be bound. The port is the one the service will actually listen on: the
# configuration's `listen` (an existing config on an upgrade or a kept one on an install), else --listen. For a low one, and only
# then, a drop-in gives the service exactly CAP_NET_BIND_SERVICE (Linux system scope; a user manager cannot grant it and macOS has no
# equivalent for a non-root daemon); when the port no longer is a low one the drop-in the installer made is removed again.
effective_port() {
  local listen=""
  [ -f "$(at "$CONFIG_FILE")" ] && listen="$(awk -F'"' '/^listen = /{print $2; exit}' "$(at "$CONFIG_FILE")")"
  [ -n "$listen" ] || listen="$LISTEN"
  printf '%s' "${listen##*:}"
}

low_port_dropin() {
  local port dropin="$DEF_FILE.d/10-low-port.conf"; port="$(effective_port)"
  if [ "$port" -lt 1024 ] 2>/dev/null; then
    [ "$PLATFORM" = linux ] && [ "$SCOPE" = system ] || die "the listen port $port is below 1024: only a Linux system service can be given the right to bind it (a user service and a macOS daemon cannot): use a port of 1024 or more behind a TLS proxy"
    mkdir -p "$(at "$DEF_FILE.d")"
    create_new "$dropin" $'[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n' || true
  elif recorded "file:$dropin"; then
    rm -f "$(at "$dropin")"; rmdir "$(at "$DEF_FILE.d")" 2>/dev/null || true
    say "Removed $dropin: the listen port $port is not below 1024"
  fi
}

new_dir() { # new_dir DIR OWNER MODE : create it only when absent
  local d; d="$(at "$1")"
  if [ -d "$d" ]; then return 0; fi
  [ ! -L "$d" ] || die "$1 is a symbolic link"
  mkdir -p "$d"
  own "${2:-}" "$3" "$d"
}

# Everything after the old service is stopped is undone on ANY failure: the previous binary and definition come back and the
# previous service is started again.
rollback_upgrade() {
  say "Rolling back to the previous binary and definition"
  if [ -f "$(at "$BIN_PATH").prev" ]; then cp -p "$(at "$BIN_PATH").prev" "$(at "$BIN_PATH").restore" && mv -f "$(at "$BIN_PATH").restore" "$(at "$BIN_PATH")"; fi
  if [ -f "$(at "$DEF_FILE").prev" ]; then cp -p "$(at "$DEF_FILE").prev" "$(at "$DEF_FILE").restore" && mv -f "$(at "$DEF_FILE").restore" "$(at "$DEF_FILE")"; fi
  if [ "$START" -eq 1 ]; then service_start || echo "install-service: the previous service did not start either" >&2; fi
}

do_upgrade() {
  default_binary
  verify_binary
  check_home_paths
  [ -f "$(at "$DEF_FILE")" ] || die "nothing to upgrade: $DEF_FILE does not exist (run 'install')"
  recorded "file:$DEF_FILE" || die "$DEF_FILE was not installed by this script"
  [ -f "$(at "$CONFIG_FILE")" ] || die "$CONFIG_FILE is missing; an upgrade never creates one"
  [ -x "$BINARY" ] || die "no executable probation binary at '$BINARY' (--binary)"
  # The new binary must accept the existing configuration BEFORE anything is replaced. It is checked from a copy in the bin
  # directory (readable by the service account), not from the package directory, which may be in somebody's private home.
  mkdir -p "$(at "$BIN_DIR")"
  local probe; probe="$(at "$BIN_DIR")/.probation-check.$$"
  install -m 755 "$BINARY" "$probe"
  if ! validate_as_service "${probe#"$ROOT"}"; then rm -f "$probe"; die "the new binary rejects $CONFIG_FILE; nothing was changed"; fi
  rm -f "$probe"
  service_stop
  [ -f "$(at "$BIN_PATH")" ] && cp -p "$(at "$BIN_PATH")" "$(at "$BIN_PATH").prev"
  cp -p "$(at "$DEF_FILE")" "$(at "$DEF_FILE").prev"
  if ! ( install_binary && validate_as_service "$BIN_PATH" && write_definition && low_port_dropin ); then rollback_upgrade; die "the upgrade failed; the previous binary and definition are back"; fi
  if [ "$START" -eq 1 ]; then
    if ! ( service_start && healthy ); then rollback_upgrade; die "the new binary did not stay up; the previous binary and definition are back and running"; fi
    [ "$STAGING" -eq 1 ] || say "Started $NAME"
  fi
  say "Upgraded $BIN_PATH (previous kept as $BIN_PATH.prev); config, blocklist and data untouched"
}

# Up and still up after a few seconds: a binary that validates its config and then dies at bind is a failed upgrade.
healthy() {
  [ "$STAGING" -eq 0 ] || return 0
  local n
  if [ "$PLATFORM" = linux ]; then
    for n in 1 2 3 4 5; do sm_linux is-active --quiet "$NAME.service" || return 1; sleep 1; done
  else
    # launchd: `launchctl print` reports state = running while the job is up; a job that dies and waits out the throttle is "not running".
    local target; if [ "$SCOPE" = system ]; then target="system/$LABEL"; else target="gui/$UID_NOW/$LABEL"; fi
    # Output is captured first (under pipefail `grep -q` closing the pipe would fail the pipeline), and a short settle time follows the
    # kickstart: right after it the job is still "spawn scheduled", not yet running.
    local out
    sleep "${HEALTH_SETTLE:-2}"
    for n in 1 2 3 4 5; do
      out="$(launchctl print "$target" 2>/dev/null || true)"
      case "$out" in *"state = running"*) ;; *) return 1 ;; esac
      sleep "${HEALTH_SLEEP:-1}"
    done
  fi
}

# Only the paths this script itself computes are ever removed, and only when the manifest names them AND this install created
# them. A manifest edited by someone else cannot point the removal anywhere else.
do_uninstall() {
  [ -f "$(at "$MANIFEST")" ] || die "no install record at $MANIFEST: nothing this script installed under that name"
  service_stop
  service_disable
  local ours=" $BIN_PATH $DEF_FILE $DEF_FILE.d/10-low-port.conf /etc/systemd/journald@$LOG_NS.conf /etc/newsyslog.d/$NAME.conf $LAUNCHD_LOG_DIR/$NAME.stdout.log $LAUNCHD_LOG_DIR/$NAME.stderr.log "
  local path refused=0 line
  while IFS= read -r line; do
    case "$line" in
      file:*)
        path="${line#file:}"
        case "$path" in
          /*) ;;
          *) echo "install-service: the install record names '$path', which is not absolute: refusing it" >&2; refused=1; continue ;;
        esac
        case "/$path/" in */../*|*/./*) echo "install-service: the install record names '$path' with a dot component: refusing it" >&2; refused=1; continue ;; esac
        if [ "$path" = "$CONFIG_FILE" ] || [ "$path" = "$BLOCKLIST" ]; then say "Keeping $path"; continue; fi
        case "$path" in
          /etc/systemd/journald@*.conf) rm -f "$(at "$path")" && say "Removed $path"; continue ;;
        esac
        case "$ours" in
          *" $path "*) rm -f "$(at "$path")" "$(at "$path").prev" && say "Removed $path" ;;
          *) echo "install-service: the install record names '$path', which this installer never creates: refusing it" >&2; refused=1 ;;
        esac ;;
    esac
  done < "$(at "$MANIFEST")"
  if [ "$STAGING" -eq 0 ] && [ "$PLATFORM" = linux ]; then sm_linux daemon-reload; fi
  rmdir "$(at "$DEF_FILE.d")" 2>/dev/null || true
  rm -f "$(at "$MANIFEST")"
  say "Left in place: $CONFIG_DIR and $DATA_DIR (and the service account). Delete them yourself if you mean to."
  [ "$refused" -eq 0 ] || exit 1
}

[ "${INSTALL_SERVICE_SOURCE_ONLY:-0}" -eq 1 ] && return 0 2>/dev/null
case "$ACTION" in
  install) do_install ;;
  upgrade) do_upgrade ;;
  uninstall) do_uninstall ;;
esac
