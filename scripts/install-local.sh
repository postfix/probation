#!/usr/bin/env bash
# Full local install: generates a TLS cert, writes a real /etc/probation config
# and blocklist, prepares the data directory, validates everything, and points
# the machine's GLOBAL npm/pip config at the running instance (every user on
# this host, not just whoever ran this script) -- npm's own globalconfig path
# and pip's documented /etc/pip.conf, not either tool's per-user config. Uses
# sudo for anything under /etc or /var/lib. See docs/operations.md §6.
set -euo pipefail

HOST="localhost"
LISTEN_PORT="8443"
ETC_DIR="/etc/probation"
DATA_DIR="/var/lib/probation"
NPMRC=""
PIP_CONF=""
FORCE_SELF_SIGNED=0
START=0

usage() {
  echo "Usage: $0 [--host HOST] [--listen-port PORT] [--self-signed] [--start]"
  echo "          [--etc-dir DIR] [--data-dir DIR] [--npmrc FILE] [--pip-conf FILE]"
  echo
  echo "  --host         hostname the cert covers and clients use (default: localhost)"
  echo "  --listen-port  port probation listens on (default: 8443; needs root for <1024)"
  echo "  --self-signed  skip mkcert even if installed; use an untrusted openssl cert"
  echo "  --start        also start 'probation serve' in the background after install"
  echo "  --etc-dir      where config/blocklist/cert go (default: /etc/probation)"
  echo "  --data-dir     probation's data directory (default: /var/lib/probation)"
  echo "  --npmrc        npm config file to update (default: npm's own global config path,"
  echo "                 e.g. /usr/etc/npmrc -- NOT ~/.npmrc; pass ~/.npmrc explicitly"
  echo "                 for a per-user install instead of a machine-wide one)"
  echo "  --pip-conf     pip config file to update (default: /etc/pip.conf, pip's"
  echo "                 documented global location -- NOT ~/.config/pip/pip.conf)"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --self-signed) FORCE_SELF_SIGNED=1; shift ;;
    --start) START=1; shift ;;
    --etc-dir) ETC_DIR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --npmrc) NPMRC="$2"; shift 2 ;;
    --pip-conf) PIP_CONF="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A sudo wrapper that skips sudo entirely when already root, so this works
# whether install-local.sh itself was invoked with or without a leading sudo.
run_priv() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

# Whoever should actually own and run this, even when this whole script was
# invoked as `sudo ./install-local.sh`: $HOME and `id -un` are both root's at
# that point, which would otherwise point npmrc/pip.conf at root's files and
# hand file ownership to root instead of the person who ran this.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  REAL_USER="$SUDO_USER"
  REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
  REAL_USER="$(id -un)"
  REAL_HOME="$HOME"
fi
REAL_GROUP="$(id -gn "$REAL_USER")"

# npm's "global" config is a different, machine-wide file from the per-user
# ~/.npmrc -- its path is compiled into that npm install (commonly
# /usr/etc/npmrc on Debian/Ubuntu, but genuinely varies), so it is asked for
# rather than guessed. Run as the real user: root's own `npm`, if it resolves
# to one at all, is not necessarily the same install everyone else's npm is.
HAVE_NPM=0
if [ -z "$NPMRC" ]; then
  if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
    NPMRC="$(sudo -u "$REAL_USER" npm config get globalconfig 2>/dev/null || true)"
  else
    NPMRC="$(npm config get globalconfig 2>/dev/null || true)"
  fi
fi
[ -n "$NPMRC" ] && [ "$NPMRC" != "undefined" ] && HAVE_NPM=1

# pip's documented global location (Unix). Unlike npm's, this one is fixed by
# pip itself, not computed from an install prefix.
HAVE_PIP=0
[ -z "$PIP_CONF" ] && PIP_CONF="/etc/pip.conf"
if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
  sudo -u "$REAL_USER" bash -c 'command -v pip >/dev/null 2>&1 || python3 -m pip --version >/dev/null 2>&1' && HAVE_PIP=1
else
  { command -v pip >/dev/null 2>&1 || python3 -m pip --version >/dev/null 2>&1; } && HAVE_PIP=1
fi

# `command -v` alone misses an installed binary when this is run under
# top-level sudo: root's PATH (sudoers' `secure_path`, typically) usually
# excludes the real user's `~/.cargo/bin`.
PROBATION_BIN="$(command -v probation || true)"
if [ -z "$PROBATION_BIN" ]; then
  for candidate in "$REAL_HOME/.cargo/bin/probation" /usr/local/bin/probation /usr/bin/probation; do
    if [ -x "$candidate" ]; then
      PROBATION_BIN="$candidate"
      break
    fi
  done
fi
if [ -z "$PROBATION_BIN" ]; then
  echo "==> 'probation' not found; building and installing it (needs Docker or Podman)"
  # Runs as the real user, not as root: a container engine set up for a normal
  # user (rootless Podman, most commonly) generally is not reachable from root
  # at all, so building as root here would fail for a different reason than
  # the one this is working around.
  if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
    sudo -u "$REAL_USER" "$REPO_ROOT/scripts/build-install.sh"
  else
    "$REPO_ROOT/scripts/build-install.sh"
  fi
  PROBATION_BIN="$(command -v probation || true)"
  [ -z "$PROBATION_BIN" ] && [ -x /usr/local/bin/probation ] && PROBATION_BIN=/usr/local/bin/probation
  if [ -z "$PROBATION_BIN" ]; then
    echo "==> Still can't find 'probation' after building it. Something went wrong" >&2
    echo "    in scripts/build-install.sh above; see its output." >&2
    exit 1
  fi
fi

# Who runs the service. A personal install (directories this user can create
# without privilege) runs as that user. A system install runs as a dedicated
# `probation` account that can read its policy but not change it: otherwise any
# code running as the login user -- a package's postinstall script, say -- could
# rewrite the blocklist and config, or replace a verified tarball in the cache,
# for every user this host's npm/pip config points here.
SYSTEM_INSTALL=0
SERVICE_USER="$REAL_USER"
if [ "$(id -u)" -ne 0 ] && mkdir -p "$ETC_DIR/tls" "$DATA_DIR" 2>/dev/null; then
  echo "==> Created $ETC_DIR and $DATA_DIR"
else
  SYSTEM_INSTALL=1
  SERVICE_USER="probation"
  echo "==> Creating $ETC_DIR and $DATA_DIR (sudo)"
  run_priv mkdir -p "$ETC_DIR/tls" "$DATA_DIR"
  # Writable by the installing user only while this script fills them in; the
  # final ownership is set once, at the end.
  run_priv chown -R "$REAL_USER:$REAL_GROUP" "$ETC_DIR" "$DATA_DIR"
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    echo "==> Creating the '$SERVICE_USER' system account"
    run_priv useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
fi

# The service account cannot run a binary from a home directory (0700 on many
# distributions), so a system install runs a root-owned copy instead.
if [ "$SYSTEM_INSTALL" -eq 1 ] && [ "${PROBATION_BIN#"$REAL_HOME"/}" != "$PROBATION_BIN" ]; then
  echo "==> Installing $PROBATION_BIN to /usr/local/bin/probation for the service account"
  run_priv install -m 755 "$PROBATION_BIN" /usr/local/bin/probation
  PROBATION_BIN=/usr/local/bin/probation
fi

CERT="$ETC_DIR/tls/$HOST.pem"
KEY="$ETC_DIR/tls/$HOST-key.pem"
TRUSTED=0

if [ "$FORCE_SELF_SIGNED" -eq 0 ] && command -v mkcert >/dev/null 2>&1; then
  echo "==> Generating a locally-trusted cert with mkcert"
  mkcert -install
  mkcert -cert-file "$CERT" -key-file "$KEY" "$HOST" 127.0.0.1 ::1
  TRUSTED=1
else
  if [ "$FORCE_SELF_SIGNED" -eq 0 ]; then
    echo "==> mkcert not found; falling back to an untrusted self-signed cert"
    echo "    (install mkcert for a cert your tools trust automatically: https://github.com/FiloSottile/mkcert)"
  else
    echo "==> Generating an untrusted self-signed cert with openssl"
  fi
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CERT" -days 365 \
    -subj "/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST,IP:127.0.0.1" >/dev/null 2>&1
fi
chmod 600 "$KEY"

# What Node-based clients (npm, bun, corepack) must trust to reach this instance:
# mkcert's root, or the self-signed cert itself. Copied here because mkcert's root
# lives in the installing user's home, which other users may not be able to read.
CA_FILE="$ETC_DIR/tls/ca.pem"
if [ "$TRUSTED" -eq 1 ]; then
  cp "$(mkcert -CAROOT)/rootCA.pem" "$CA_FILE"
else
  cp "$CERT" "$CA_FILE"
fi

echo "==> Writing $ETC_DIR/config.toml"
cp "$REPO_ROOT/config.sample.toml" "$ETC_DIR/config.toml"
sed --in-place \
  -e "s|^listen = .*|listen = \"127.0.0.1:$LISTEN_PORT\"|" \
  -e "s|^public_url = .*|public_url = \"https://$HOST:$LISTEN_PORT\"|" \
  -e "s|^data_dir = .*|data_dir = \"$DATA_DIR\"|" \
  -e "s|^blocklist_file = .*|blocklist_file = \"$ETC_DIR/blocklist.json\"|" \
  "$ETC_DIR/config.toml"
{
  echo ""
  echo "tls_cert_path = \"$CERT\""
  echo "tls_key_path = \"$KEY\""
  echo ""
  # Without this, probation's one-line-per-request decision log (pinned at
  # INFO, cannot be turned down) only reaches stdout -> the systemd journal,
  # with no bound of its own. This turns on probation's own self-rotating
  # file sink instead: rolls over at 100 MiB, keeps one backup generation, so
  # at most 200 MiB total -- never hand this file to logrotate, it rotates
  # itself (docs/operations.md §8).
  echo "log_file_path = \"$DATA_DIR/decisions.ndjson\""
  echo "log_file_max_bytes = 104857600"
} >> "$ETC_DIR/config.toml"

echo "==> Writing $ETC_DIR/blocklist.json (sample — replace with your producer's real snapshot)"
cp "$REPO_ROOT/blocklist.sample.json" "$ETC_DIR/blocklist.json"

echo "==> Validating"
"$PROBATION_BIN" check-config "$ETC_DIR/config.toml"
"$PROBATION_BIN" check-blocklist "$ETC_DIR/blocklist.json"

if [ "$HAVE_NPM" -eq 1 ]; then
  echo "==> Updating $NPMRC (npm's machine-wide config — every user on this host)"
  TMP_NPMRC="$(mktemp)"
  run_priv test -f "$NPMRC" && run_priv cat "$NPMRC" | grep -v '^registry=\|^audit=\|^cafile=' > "$TMP_NPMRC" || true
  {
    cat "$TMP_NPMRC"
    echo "registry=https://$HOST:$LISTEN_PORT/npm/"
    echo "audit=false"
  } > "$TMP_NPMRC.new"
  run_priv mkdir -p "$(dirname "$NPMRC")"
  run_priv install -m 644 "$TMP_NPMRC.new" "$NPMRC"
  rm -f "$TMP_NPMRC" "$TMP_NPMRC.new"
else
  echo "==> Skipping npm config: no npm found for $REAL_USER"
fi

if [ "$HAVE_PIP" -eq 1 ]; then
  echo "==> Updating $PIP_CONF (pip's machine-wide config — every user on this host)"
  TMP_PIP="$(mktemp)"
  run_priv test -f "$PIP_CONF" && run_priv cat "$PIP_CONF" > "$TMP_PIP" || true
  python3 - "$TMP_PIP" "$HOST" "$LISTEN_PORT" "$TRUSTED" "$CERT" <<'EOF'
import configparser, sys
path, host, port, trusted, cert = sys.argv[1:6]
config = configparser.ConfigParser()
config.read(path)
if "global" not in config:
    config["global"] = {}
config["global"]["index-url"] = f"https://{host}:{port}/pypi/simple/"
if trusted == "0":
    config["global"]["cert"] = cert
elif "cert" in config["global"]:
    del config["global"]["cert"]
with open(path, "w") as f:
    config.write(f)
EOF
  run_priv mkdir -p "$(dirname "$PIP_CONF")"
  run_priv install -m 644 "$TMP_PIP" "$PIP_CONF"
  rm -f "$TMP_PIP"
else
  echo "==> Skipping pip config: no pip found for $REAL_USER"
fi

# Node does not read the machine's trust store, so npm, bun and corepack are given
# this instance's authority with NODE_EXTRA_CA_CERTS, which adds to Node's list. Not
# npm's `cafile`: that replaces the list, and npm could then reach nothing else over
# TLS. /etc/environment is machine-wide, so only a system install writes it, and
# Node takes only one such file, so one this machine already names is left alone.
ENV_LINE="NODE_EXTRA_CA_CERTS=$CA_FILE"
if [ "$SYSTEM_INSTALL" -eq 1 ]; then
  CURRENT_ENV="$(mktemp)"
  if [ -e /etc/environment ] && ! cat /etc/environment > "$CURRENT_ENV"; then
    echo "==> Cannot read /etc/environment; leaving it unchanged." >&2
    exit 1
  fi
  PREVIOUS="$(sed -n 's/^NODE_EXTRA_CA_CERTS=//p' "$CURRENT_ENV" | tail -n 1 | tr -d '"')"
  if [ -n "$PREVIOUS" ] && [ "$PREVIOUS" != "$CA_FILE" ]; then
    echo "==> /etc/environment already sets NODE_EXTRA_CA_CERTS=$PREVIOUS; leaving it."
    echo "    Node trusts only one extra file. To keep both, combine them and point it there:"
    echo "      cat $PREVIOUS $CA_FILE > /usr/local/share/node-extra-ca.pem"
  else
    echo "==> Setting $ENV_LINE in /etc/environment (from your next login)"
    { grep -v '^NODE_EXTRA_CA_CERTS=' "$CURRENT_ENV" || true; } > "$CURRENT_ENV.new"
    echo "$ENV_LINE" >> "$CURRENT_ENV.new"
    run_priv install -m 644 "$CURRENT_ENV.new" /etc/environment
  fi
  rm -f "$CURRENT_ENV" "$CURRENT_ENV.new"
else
  echo "==> Add this to your shell profile so npm, bun and corepack trust $CA_FILE:"
  echo "      export $ENV_LINE"
fi

# Final ownership, set once here rather than at every write site above.
#
# System install: $ETC_DIR (config, blocklist, TLS key) is root-owned and only
# group-readable by the service account, so neither the service nor the login
# user can change policy; $DATA_DIR belongs to the service account alone. The
# blocklist producer must therefore write $ETC_DIR/blocklist.json as root.
#
# Personal install: everything belongs to the user who ran this, which is also
# who runs the service.
#
# npmrc/pip.conf are NOT included here: they are the machine's global config,
# so staying root-owned (their normal state on any system) is correct. They and
# the unit files are written with `install -m 644`, not `cp` of a `mktemp` file:
# that would leave them 0600, and pip silently ignores a config it cannot read.
if [ "$SYSTEM_INSTALL" -eq 1 ]; then
  run_priv chown -R "root:$SERVICE_USER" "$ETC_DIR"
  run_priv chmod -R u=rwX,g=rX,o= "$ETC_DIR"
  # The certificate is public, and every user's npm and pip read it as their CA.
  run_priv chmod o+x "$ETC_DIR" "$ETC_DIR/tls"
  run_priv chmod o+r "$CERT" "$CA_FILE"
  run_priv chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
  run_priv chmod 700 "$DATA_DIR"
elif [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
  chown -R "$REAL_USER:$REAL_GROUP" "$ETC_DIR" "$DATA_DIR"
fi

echo
echo "==> Install complete."
echo "    Config:     $ETC_DIR/config.toml"
echo "    Blocklist:  $ETC_DIR/blocklist.json (sample — point your producer at this path)"
if [ "$SYSTEM_INSTALL" -eq 1 ]; then
  echo "    Runs as:    $SERVICE_USER (reads $ETC_DIR, cannot change it; the producer writes as root)"
fi
echo "    Cert:       $CERT"
echo "    Decision log: $DATA_DIR/decisions.ndjson (self-rotating, capped at 200 MiB total;"
echo "                  stdout/journald still gets the same lines too, uncapped by this script)"
if [ "$TRUSTED" -eq 0 ] && [ "$HAVE_PIP" -eq 1 ]; then
  echo "    This cert is untrusted; pip was configured with an explicit cert."
fi
if [ "$HAVE_NPM" -eq 1 ]; then
  echo "    npm (every user, machine-wide): $NPMRC -> https://$HOST:$LISTEN_PORT/npm/"
fi
echo "    Shells already open: export $ENV_LINE"
if [ "$HAVE_PIP" -eq 1 ]; then
  echo "    pip (every user, machine-wide): $PIP_CONF -> https://$HOST:$LISTEN_PORT/pypi/simple/"
fi

# systemctl can be present without systemd actually being the running init
# (some containers, WSL1) — /run/systemd/system only exists when it is.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  echo "==> Installing the systemd service"

  # probation's per-request decision log (pinned at INFO, high volume) hits
  # stdout -> journald same as everything else, which would otherwise mean
  # either bloating the MAIN system journal (shared by every other service
  # on this host) or leaving it uncapped. LogNamespace= gives this one unit
  # its own separate journald instance, capped independently here, so no
  # other service's logging or retention is touched by this install.
  JOURNALD_NS_CONF="/etc/systemd/journald@probation.conf"
  TMP_JOURNALD_NS="$(mktemp)"
  cat > "$TMP_JOURNALD_NS" <<EOF
[Journal]
Storage=persistent
SystemMaxUse=200M
EOF
  run_priv install -m 644 "$TMP_JOURNALD_NS" "$JOURNALD_NS_CONF"
  rm -f "$TMP_JOURNALD_NS"

  UNIT_FILE="/etc/systemd/system/probation.service"
  TMP_UNIT="$(mktemp)"
  cat > "$TMP_UNIT" <<EOF
[Unit]
Description=Probation package firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
LogNamespace=probation
ExecStart=$PROBATION_BIN serve --config $ETC_DIR/config.toml
Restart=on-failure
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  run_priv install -m 644 "$TMP_UNIT" "$UNIT_FILE"
  rm -f "$TMP_UNIT"
  run_priv systemctl daemon-reload
  run_priv systemctl enable probation.service >/dev/null
  echo "    Installed: $UNIT_FILE (enabled — starts on boot)"
  echo "    Journal:   capped at 200 MiB, in its own namespace, isolated from"
  echo "               every other service's logs ($JOURNALD_NS_CONF)"

  if [ "$START" -eq 1 ]; then
    echo "==> Starting the service"
    run_priv systemctl restart probation.service
    sleep 1
    # LogNamespace= needs mount-namespace capability, which some containers
    # and restricted kernels refuse ("Operation not supported", exit
    # 226/NAMESPACE) -- confirmed by testing this exact unit, not a guess.
    # Falling back to the plain system journal is strictly better than
    # leaving the service crash-looping over a log-isolation nicety.
    if ! run_priv systemctl is-active --quiet probation.service; then
      echo "    LogNamespace isolation isn't supported on this host (mount"
      echo "    namespacing unavailable — common in some containers); falling"
      echo "    back to the plain system journal for this service's logs."
      run_priv sed --in-place '/^LogNamespace=/d' "$UNIT_FILE"
      run_priv rm -f "$JOURNALD_NS_CONF"
      run_priv systemctl daemon-reload
      run_priv systemctl restart probation.service
      sleep 1
    fi
    run_priv systemctl --no-pager --lines=5 status probation.service || true
    echo "    Manage it with: systemctl {status,stop,restart} probation"
    if grep -q '^LogNamespace=' "$UNIT_FILE" 2>/dev/null; then
      echo "    Logs: journalctl --namespace=probation -u probation -f"
    else
      echo "    Logs: journalctl -u probation -f (shared with other services'"
      echo "          retention — see the decision log file instead for a"
      echo "          bounded, probation-only copy)"
    fi
  else
    echo "    Start it with: sudo systemctl start probation"
    echo "    (if LogNamespace isn't supported on this host, that start will"
    echo "     crash-loop; re-run this script with --start to detect and"
    echo "     automatically fall back)"
  fi
else
  echo "==> No running systemd found; falling back to a plain background process"
  echo "    (no restart-on-crash, nothing survives a reboot — install systemd"
  echo "     support in your init system for that)"
  if [ "$START" -eq 1 ]; then
    echo "==> Starting 'probation serve' in the background"
    if [ "$SYSTEM_INSTALL" -eq 1 ]; then
      # The redirect runs as the service account: $DATA_DIR is not writable by
      # whoever ran this script.
      run_priv sudo -u "$SERVICE_USER" sh -c 'exec nohup "$0" serve --config "$1" > "$2/probation.log" 2>&1' \
        "$PROBATION_BIN" "$ETC_DIR/config.toml" "$DATA_DIR" &
    elif [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != "root" ]; then
      sudo -u "$REAL_USER" nohup "$PROBATION_BIN" serve --config "$ETC_DIR/config.toml" \
        > "$DATA_DIR/probation.log" 2>&1 &
    else
      nohup "$PROBATION_BIN" serve --config "$ETC_DIR/config.toml" \
        > "$DATA_DIR/probation.log" 2>&1 &
    fi
    disown
    echo "    Started (check 'pgrep -u $SERVICE_USER -f probation.serve' for the PID),"
    echo "    logs at $DATA_DIR/probation.log"
  else
    echo "    Start it with: $PROBATION_BIN serve --config $ETC_DIR/config.toml"
  fi
fi
