#!/bin/sh
# Checks that a node's containerd can reach ONE registry endpoint and no other: the Probation service. Exit 0 only when every check
# holds; each failure prints one FAIL line. Offline checks read files and the effective containerd configuration; --online also asks
# the endpoint and, with --check-egress, proves the node cannot reach a registry origin directly; --service-pool also checks that the
# service's own image is already in the node's content store (the service cannot be pulled through itself).
#
#   verify-node.sh --endpoint URL [--certs-dir DIR] [--containerd-config FILE] [--systemd-dir DIR] [--allow-origin HOST]...
#       [--service-pool --image-ref REPO@sha256:DIGEST [--containerd-address SOCKET] [--containerd-namespace k8s.io]]
#       [--containerd-unit NAME] [--proc-dir DIR]   the systemd unit that runs containerd (default containerd) and where /proc is
#       [--firewall]   both nft tables are loaded (a flush of the rule set, e.g. a restart of nftables.service, would have removed them)
#       [--prove-pin]  a negative test with ctr: a certificate of another CA, trusted by a populated system-style certificate directory, is
#                      accepted when the pin is off (the control) and REJECTED with the environment containerd really runs with (the
#                      running daemon's /proc/<pid>/environ, else systemd's effective Environment, else the installed drop-in)
#
# Needs containerd 2.0 or later (the drop-in, the config schema and the CRI image service this installs for are 2.x). On a systemd host the
# EFFECTIVE environment of containerd is checked, not only the drop-in file: run it after `systemctl daemon-reload` and a restart of containerd.
#       [--online --ca FILE [--check-egress]]
set -u

certs_dir=/etc/containerd/certs.d
cfg=/etc/containerd/config.toml
systemd_dir=/etc/systemd/system
endpoint=
ca=
online=0
egress=0
pool=0
firewall=0
prove=0
image_ref=
address=/run/containerd/containerd.sock
namespace=k8s.io
unit_name=containerd
proc_dir=/proc
allow_origins=
marker='# managed by probation install-node.sh'
nl='
'
fail=0
bad() { echo "FAIL: $*"; fail=1; }
die() { echo "verify-node: $*" >&2; exit 2; }

# Every scratch file (the baseline copy of the main config, the comparison files, the pin probe) lives in ONE private directory that goes with
# the script, also when it is interrupted; nothing is written next to the containerd configuration.
tmpd=$(mktemp -d) || die "cannot create a temporary directory"
trap 'rm -rf "$tmpd"; [ -z "${server:-}" ] || kill "$server" 2>/dev/null' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

while [ $# -gt 0 ]; do
  case "$1" in
    --online) online=1; shift; continue ;;
    --check-egress) egress=1; shift; continue ;;
    --service-pool) pool=1; shift; continue ;;
    --firewall) firewall=1; shift; continue ;;
    --prove-pin) prove=1; shift; continue ;;
  esac
  [ $# -ge 2 ] || die "$1 needs a value"
  case $2 in *"$nl"*) die "$1 contains a control character or a newline" ;; esac
  [ -z "$(printf '%s' "$2" | LC_ALL=C tr -d '[:print:]')" ] || die "$1 contains a control character or a newline"
  case "$1" in
    --endpoint) endpoint=$2 ;;
    --certs-dir) certs_dir=$2 ;;
    --containerd-config) cfg=$2 ;;
    --systemd-dir) systemd_dir=$2 ;;
    --ca) ca=$2 ;;
    --image-ref) image_ref=$2 ;;
    --containerd-address) address=$2 ;;
    --containerd-namespace) namespace=$2 ;;
    --containerd-unit) unit_name=$2 ;;
    --proc-dir) proc_dir=$2 ;;
    --allow-origin) allow_origins="$allow_origins $2" ;;
    *) die "unknown argument $1" ;;
  esac
  shift 2
done
[ -n "$endpoint" ] || die "--endpoint is required"
printf '%s\n' "$endpoint" | grep -Eq '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$' || die "the endpoint must be an https origin: $endpoint"
# The host part: a bracketed IPv6 literal keeps its brackets out of getent and curl --resolve, a name or IPv4 loses its port.
rest=${endpoint#https://}
case "$rest" in
  \[*) host=${rest%%]*}; host=${host#\[} ;;
  *) host=${rest%%:*} ;;
esac

# 1. The default hosts file names the endpoint as the server, for pull and resolve, with the service CA, and nothing else.
hosts="$certs_dir/_default/hosts.toml"
if [ ! -r "$hosts" ]; then
  bad "$hosts is missing: containerd would use each registry's own address"
else
  grep -qxF "server = \"$endpoint\"" "$hosts" || bad "$hosts does not name the server $endpoint"
  grep -Eq '^capabilities = \["pull", "resolve"\]$' "$hosts" || bad "$hosts must grant exactly pull and resolve"
  grep -Eq '^ca = "/.*"$' "$hosts" || bad "$hosts names no CA file"
  ! grep -Eq '^[[:space:]]*\[' "$hosts" || bad "$hosts has a table: a [host.\"...\"] entry is another place to pull from"
  ! grep -Eq 'skip_verify|override_path|http://' "$hosts" || bad "$hosts weakens TLS or rewrites paths"
  caf=$(sed -n 's/^ca = "\(.*\)"$/\1/p' "$hosts")
  [ -z "$caf" ] || [ -r "$caf" ] || bad "the CA file $caf of $hosts cannot be read"
fi

# 2. Per-registry directories win over _default for their registry: each must be endpoint-only (the endpoint, or its
# /registry/oci/<id> route), hold no legacy certificate file, and have a hosts.toml at all. --allow-origin HOST names the one
# registry a service-pool node may go to directly (a dedicated registry that holds only the service's image).
if [ -d "$certs_dir" ]; then
  for dir in "$certs_dir"/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    [ "$name" = _default ] && continue
    for legacy in "$dir"*.crt "$dir"*.cert "$dir"*.key; do
      [ -e "$legacy" ] && bad "$legacy is a legacy certificate file: containerd goes to the registry's own address for $name"
    done
    file="${dir}hosts.toml"
    if [ ! -e "$file" ]; then
      bad "$dir has no hosts.toml: containerd uses $name's own address"
      continue
    fi
    server=$(sed -n 's/^server = "\(.*\)"$/\1/p' "$file")
    case " $allow_origins " in *" $name "*) [ "$server" = "https://$name" ] || bad "$file: the allowed origin $name must name server https://$name"; continue ;; esac
    case "$server" in
      "$endpoint") ;;
      "$endpoint"/registry/oci/*) printf '%s\n' "${server#"$endpoint"/registry/oci/}" | grep -Eq '^[0-9]{1,9}$' || bad "$file: the route $server is not /registry/oci/<id>" ;;
      *) bad "$file overrides the endpoint for $name (server is '$server')" ;;
    esac
    grep -Eq '^capabilities = \["pull", "resolve"\]$' "$file" || bad "$file must grant exactly pull and resolve"
    ! grep -Eq '^[[:space:]]*\[' "$file" || bad "$file overrides the endpoint for $name with a table (another place to pull from)"
    ! grep -Eq 'skip_verify|override_path|http://' "$file" || bad "$file weakens TLS or rewrites paths for $name"
  done
fi

# 3. The effective containerd configuration reads exactly this directory (so the drop-in IS imported) and has no legacy mirrors.
if ! command -v containerd >/dev/null 2>&1; then
  bad "containerd is not installed, so its effective configuration cannot be read"
elif ! cver=$(containerd --version 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^v?[0-9]+\.[0-9]+/) { v = $i; sub(/^v/, "", v); sub(/\..*/, "", v); print v; exit } }') || [ -z "$cver" ]; then
  bad "cannot read the version of containerd (containerd --version): this installer supports containerd 2.0 or later only"
elif [ "$cver" -lt 2 ]; then
  bad "unsupported: containerd $cver.x. The node scripts need containerd 2.0 or later (its config schema, hosts directory and CRI image service); this node's runtime is older"
elif [ ! -r "$cfg" ]; then
  bad "$cfg cannot be read"
else
  dump=$(containerd --config "$cfg" config dump 2>&1) || bad "containerd cannot load $cfg: $(printf '%s' "$dump" | tail -n 1)"
  path=$(printf '%s\n' "$dump" | sed -n "/'io.containerd.cri.v1.images'.registry\]/,/^\$/s/^ *config_path = '\(.*\)'\$/\1/p")
  if [ "$path" != "$certs_dir" ]; then
    bad "containerd's registry config_path is '${path:-unset}', not '$certs_dir': the drop-in conf.d/probation.toml is probably not imported (run install-node.sh, which adds the imports line to $cfg)"
  fi
  # Only the registry config_path and the import may differ from the main file WITHOUT the installer's import line: a drop-in whose schema
  # does not match the main file silently changes the CRI settings (SystemdCgroup, the sandbox image). The baseline is made now from the
  # current file, so a later legitimate edit of the main file (a runtime option, a kubeadm rewrite) is in both sides and never fails here.
  if grep -qF "$marker" "$cfg"; then
    basefile="$tmpd/config.probation-verify.toml"
    if ! grep -vF "$marker" "$cfg" > "$basefile"; then
      bad "cannot make a copy of $cfg to compare the configuration without the installer's import"
    else
      base=$(containerd --config "$basefile" config dump 2>&1) || bad "containerd cannot load $cfg without the installer's import line"
      cmp1="$tmpd/cmp1"; cmp2="$tmpd/cmp2"
      # containerd's own log lines (`time="..." level=warning ... t="10.9µs"`, e.g. "Configuration migrated from version 2") share the dump's stderr and
      # differ on every call: they are not configuration.
      printf '%s\n' "$base" | grep -vE "config_path|^imports|^ *imports|^time=\"" > "$cmp1"
      printf '%s\n' "$dump" | grep -vE "config_path|^imports|^ *imports|^time=\"" > "$cmp2"
      changed=$(diff "$cmp1" "$cmp2" | grep -E '^[<>]' | head -n 5)
      [ -z "$changed" ] || bad "the drop-in changes more than the registry config_path of $cfg (first differences: $(printf '%s' "$changed" | tr '\n' ' ')): its schema does not match the main file"
    fi
  fi
  printf '%s\n' "$dump" | grep -Eq "registry\.(mirrors|configs)|\.mirrors\.|\.configs\." && bad "containerd's own configuration carries registry mirrors or configs, which bypass the hosts directory"
fi

# 4. Trust only the service CA: the hosts.toml `ca` adds to the system roots, so the systemd drop-in must replace them. Go replaces its FILE list
# with SSL_CERT_FILE but still reads the default certificate DIRECTORIES unless SSL_CERT_DIR is set too, to a directory that stays empty.
unit="$systemd_dir/containerd.service.d/probation-ca.conf"
empty_roots="$certs_dir/_default/roots-empty"
if [ ! -r "$unit" ] || ! grep -qxF "Environment=\"SSL_CERT_FILE=$certs_dir/_default/probation-ca.pem\"" "$unit"; then
  bad "$unit does not set SSL_CERT_FILE to the service CA: containerd would also trust every CA of the system roots for the endpoint's name"
elif ! grep -qxF "Environment=\"SSL_CERT_DIR=$empty_roots\"" "$unit"; then
  bad "$unit does not set SSL_CERT_DIR to the empty directory $empty_roots: Go still reads /etc/ssl/certs and /etc/pki/tls/certs, so every system CA is still trusted"
elif [ ! -d "$empty_roots" ] || [ -n "$(ls -A "$empty_roots" 2>/dev/null)" ]; then
  bad "$empty_roots must be an existing EMPTY directory (anything in it is a trusted root)"
else
  # Who can write into it can add a trusted root: owned by root (by the verifying user when that is not root), no group or world write.
  want_owner=$(id -u); owner=$(stat -c %u "$empty_roots" 2>/dev/null); perms=$(stat -c %a "$empty_roots" 2>/dev/null)
  tail2=${perms#"${perms%??}"}
  case "$owner:$perms" in :*|*:) bad "cannot read the owner and mode of $empty_roots" ;; esac
  [ "$owner" = "$want_owner" ] || bad "$empty_roots is owned by uid $owner, not $want_owner: its owner can add a trusted root"
  case $tail2 in *[2367]*) bad "$empty_roots has mode $perms: a group or world writable directory lets anyone add a trusted root" ;; esac
fi

# 4a. The EFFECTIVE environment of the containerd that runs: the last assignment of a variable wins across drop-ins (a later zz-corp.conf with
# SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt undoes the pin), and a daemon that was not restarted since the install still has the old one.
want_file="$certs_dir/_default/probation-ca.pem"
eff() { printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s/^\"\{0,1\}$1=//p" | tail -n 1 | sed 's/"$//'; }
pin_file=$want_file; pin_dir=$empty_roots
if command -v systemctl >/dev/null 2>&1; then
  load=$(systemctl show "$unit_name" -p LoadState --value 2>/dev/null)
  if [ "$load" != loaded ]; then
    bad "systemd has no loaded unit '$unit_name' (LoadState=${load:-unknown}): pass --containerd-unit NAME when another unit runs containerd (k3s, RKE2, a custom unit)"
  else
    senv=$(systemctl show "$unit_name" -p Environment --value 2>/dev/null)
    drops=$(systemctl show "$unit_name" -p DropInPaths --value 2>/dev/null)
    sfile=$(eff SSL_CERT_FILE "$senv"); sdir=$(eff SSL_CERT_DIR "$senv")
    if [ "$sfile" != "$want_file" ] || [ "$sdir" != "$empty_roots" ]; then
      bad "systemd's effective environment of $unit_name is SSL_CERT_FILE='${sfile:-unset}' SSL_CERT_DIR='${sdir:-unset}', not the pin ($want_file, $empty_roots); a later drop-in overrides it (drop-ins in order: ${drops:-none})"
    fi
    [ -z "$sfile" ] || pin_file=$sfile
    [ -z "$sdir" ] || pin_dir=$sdir
    pid=$(systemctl show "$unit_name" -p MainPID --value 2>/dev/null)
    case $pid in ''|*[!0-9]*|0) bad "$unit_name is not running, so the environment of the daemon cannot be checked" ;; *)
      if [ ! -r "$proc_dir/$pid/environ" ]; then
        bad "cannot read $proc_dir/$pid/environ (run this as root): the environment of the running containerd is unchecked"
      else
        penv=$(tr '\0' '\n' < "$proc_dir/$pid/environ")
        dfile=$(printf '%s\n' "$penv" | sed -n 's/^SSL_CERT_FILE=//p' | tail -n 1); ddir=$(printf '%s\n' "$penv" | sed -n 's/^SSL_CERT_DIR=//p' | tail -n 1)
        if [ "$dfile" != "$want_file" ] || [ "$ddir" != "$empty_roots" ]; then
          bad "the running containerd (pid $pid) has SSL_CERT_FILE='${dfile:-unset}' SSL_CERT_DIR='${ddir:-unset}': it was not restarted since the install, or something overrides the pin"
        fi
        pin_file=${dfile:-$pin_file}; pin_dir=${ddir:-$pin_dir}
      fi ;;
    esac
  fi
else
  echo "NOTE: systemctl is not available: the environment of the running containerd was not checked"
fi

# 4b. A negative test of the pin itself, with the runtime's own TLS code (ctr is Go like containerd): the endpoint name is served by a local
# TLS server whose certificate was signed by a throwaway CA that sits in a POPULATED system-style certificate directory.
if [ "$prove" = 1 ]; then
  if ! command -v ctr >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    bad "--prove-pin needs ctr and openssl"
  else
    pd="$tmpd/prove"; mkdir "$pd"; port=$(( 20000 + $$ % 20000 ))
    ( cd "$pd" && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca2.key -out ca2.pem -subj /CN=probation-pin-probe-ca -days 1 >/dev/null 2>&1 \
      && openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout srv.key -out srv.csr -subj /CN=localhost >/dev/null 2>&1 \
      && printf 'subjectAltName=DNS:localhost\n' > san.cnf \
      && openssl x509 -req -in srv.csr -CA ca2.pem -CAkey ca2.key -CAcreateserial -out srv.pem -days 1 -extfile san.cnf >/dev/null 2>&1 ) || bad "--prove-pin could not make the throwaway certificates"
    mkdir -p "$pd/system-certs" "$pd/hosts/_default"
    cp "$pd/ca2.pem" "$pd/system-certs/second-ca.pem"
    printf 'server = "https://localhost:%s"\ncapabilities = ["pull", "resolve"]\nca = "%s/_default/probation-ca.pem"\n' "$port" "$certs_dir" > "$pd/hosts/_default/hosts.toml"
    # The port is taken from a pid-based start and moved on when the listener cannot bind (another process holds it).
    attempt=0
    while :; do
      printf 'server = "https://localhost:%s"\ncapabilities = ["pull", "resolve"]\nca = "%s/_default/probation-ca.pem"\n' "$port" "$certs_dir" > "$pd/hosts/_default/hosts.toml"
      openssl s_server -accept "$port" -cert "$pd/srv.pem" -key "$pd/srv.key" -www >"$pd/server.log" 2>&1 &
      server=$!
      sleep 1
      kill -0 "$server" 2>/dev/null && break
      attempt=$((attempt + 1)); port=$((port + 1))
      [ "$attempt" -lt 5 ] || { bad "--prove-pin: no local port for the probe server"; break; }
    done
    probe() { env "$@" HTTPS_PROXY= https_proxy= NO_PROXY=localhost no_proxy=localhost timeout 15 ctr --address "$address" content fetch --hosts-dir "$pd/hosts" localhost:"$port"/pin/probe:1 2>&1; }
    control=$(probe SSL_CERT_FILE="$certs_dir/_default/probation-ca.pem" SSL_CERT_DIR="$pd/system-certs")
    pinned=$(probe SSL_CERT_FILE="$pin_file" SSL_CERT_DIR="$pin_dir")
    kill "$server" 2>/dev/null; wait "$server" 2>/dev/null
    if printf '%s' "$control" | grep -Eq 'x509|connection refused|no such host|i/o timeout|deadline exceeded|timed out' || [ -z "$control" ]; then
      bad "--prove-pin: the control (a populated certificate directory that trusts the second CA) was rejected or never reached the probe server, so the probe proves nothing: $(printf '%s' "$control" | tail -n 1)"
    elif ! printf '%s' "$pinned" | grep -q 'x509: certificate signed by unknown authority'; then
      bad "the pin does not hold: with the installed environment a certificate of another CA was not rejected: $(printf '%s' "$pinned" | tail -n 1)"
    fi
      fi
fi

# 4c. The boot unit has not been undone by a `flush ruleset`: both tables are loaded.
if [ "$firewall" = 1 ]; then
  for table in probation_node_egress probation_node_ingress; do
    nft list table inet "$table" >/dev/null 2>&1 || bad "the nft table inet $table is not loaded (a boot-time flush of the rule set, or the unit never ran)"
  done
  # An inactive unit does not follow a later restart or reload of nftables.service (PartOf=, ReloadPropagatedFrom=), so the tables would stay gone.
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet probation-node-firewall.service || bad "probation-node-firewall.service is not active: a restart of nftables.service would remove the tables and nothing would restore them (install-firewall.sh starts it)"
  fi
fi

# 5. Service-pool node: the service's own image must already be on the node (it cannot be pulled through the service it starts).
if [ "$pool" = 1 ]; then
  printf '%s\n' "$image_ref" | grep -Eq '^[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}$' || die "--service-pool needs --image-ref REPO@sha256:<digest>"
  if ! command -v ctr >/dev/null 2>&1; then
    bad "ctr is not installed, so the preloaded service image cannot be checked"
  else
    have=$(ctr --address "$address" -n "$namespace" images ls "name==$image_ref" 2>/dev/null | awk 'NR > 1 { print $3 }')
    [ "$have" = "${image_ref#*@}" ] || bad "the service image $image_ref is not in the $namespace content store of this node (${have:-absent}): preload it with install-node.sh --preload-image"
  fi
fi

if [ "$online" = 1 ]; then
  [ -n "$ca" ] || die "--online needs --ca"
  getent hosts "$host" >/dev/null 2>&1 || bad "the name $host does not resolve on this node"
  code=$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$ca" "$endpoint/v2/" 2>/dev/null)
  case "$code" in 200|401) ;; *) bad "$endpoint/v2/ answered '${code:-nothing}' with the service CA (200 or 401 expected)" ;; esac
  if [ "$egress" = 1 ]; then
    # Blocked is a refusal or a reset of a connection to an address that resolved; no DNS, no route and a timeout say nothing.
    for origin in registry-1.docker.io ghcr.io quay.io; do
      if ! getent hosts "$origin" >/dev/null 2>&1; then
        bad "$origin does not resolve on this node: 'blocked' cannot be told from 'no network'"
        continue
      fi
      curl --noproxy '*' -sS -o /dev/null --max-time 8 "https://$origin/v2/" >/dev/null 2>&1
      rc=$?
      case $rc in
        0|22) bad "this node reaches https://$origin/v2/ directly: the egress rules are not in force" ;;
        7|35|56) ;;
        *) bad "the direct connection to $origin ended inconclusively (curl exit $rc): not proof of a closed egress" ;;
      esac
    done
  fi
fi

[ "$fail" = 0 ] && echo "verify-node: ok"
exit "$fail"
