#!/bin/sh
# Points a node's containerd at the one Probation endpoint (C1023: the service is the `server`, the original registry kept as ?ns=)
# and gives it the service CA. Writes only these files, each carrying the marker line, and restarts nothing:
#   <certs-dir>/_default/hosts.toml       every registry without a file of its own goes to the endpoint (it selects the registry by ?ns=)
#   <certs-dir>/<registry>/hosts.toml     one per --registry host=id: that registry goes to <endpoint>/registry/oci/<id>
#   <certs-dir>/_default/probation-ca.pem the service CA
#   <config-dir>/conf.d/probation.toml    containerd drop-in: ONE config_path
#   <config-file>                         an `imports` line for the drop-in (refused, before anything is written, when it has another imports line)
#   <systemd-dir>/containerd.service.d/probation-ca.conf   SSL_CERT_FILE=<the CA> and SSL_CERT_DIR=<an empty directory>: containerd then trusts ONLY the service CA
# Needs containerd 2.0 or later (refused otherwise). A missing main config file is created in the schema of the installed containerd (2.x: version 3).
# Restart containerd after it (systemctl daemon-reload first), THEN run verify-node.sh: it checks the environment the running daemon has.
# Optional: --preload-image imports the service's own image (an OCI archive) into the k8s.io content store, verified by digest.
# --rollback removes what this script wrote (marker-checked) and restores the config file.
#
#   install-node.sh --endpoint https://probation.cluster.example:30443 --ca ca.pem [--registry ghcr.io=2]... [--certs-dir DIR]
#       [--config-dir DIR] [--config-file FILE] [--systemd-dir DIR | --no-systemd] [--preload-image ARCHIVE --image-ref REPO@sha256:DIGEST
#       [--containerd-address SOCKET] [--containerd-namespace k8s.io]] [--rollback]
set -eu

certs_dir=/etc/containerd/certs.d
config_dir=/etc/containerd
config_file=
systemd_dir=/etc/systemd/system
no_systemd=0
rollback=0
endpoint=
ca=
preload=
image_ref=
address=/run/containerd/containerd.sock
namespace=k8s.io
registries=
marker='# managed by probation install-node.sh'
nl='
'

die() { echo "install-node: $*" >&2; exit 2; }
# No control character (a newline included) in any value that reaches a file or a command line.
clean() {
  case $2 in *"$nl"*) die "$1 contains a control character or a newline" ;; esac
  [ -z "$(printf '%s' "$2" | LC_ALL=C tr -d '[:print:]')" ] || die "$1 contains a control character or a newline"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) rollback=1; shift; continue ;;
    --no-systemd) no_systemd=1; shift; continue ;;
  esac
  [ $# -ge 2 ] || die "$1 needs a value"
  clean "$1" "$2"
  case "$1" in
    --endpoint) endpoint=$2 ;;
    --ca) ca=$2 ;;
    --certs-dir) certs_dir=$2 ;;
    --config-dir) config_dir=$2 ;;
    --config-file) config_file=$2 ;;
    --systemd-dir) systemd_dir=$2 ;;
    --registry) registries="$registries$2$nl" ;;
    --preload-image) preload=$2 ;;
    --image-ref) image_ref=$2 ;;
    --containerd-address) address=$2 ;;
    --containerd-namespace) namespace=$2 ;;
    *) die "unknown argument $1" ;;
  esac
  shift 2
done
[ -n "$config_file" ] || config_file="$config_dir/config.toml"
case "$certs_dir:$config_dir:$config_file:$systemd_dir" in /*:/*:/*:/*) ;; *) die "--certs-dir, --config-dir, --config-file and --systemd-dir must be absolute paths" ;; esac
case "$certs_dir$config_dir$config_file$systemd_dir$endpoint" in *'"'*|*"'"*|*'\'*|*' '*) die "quotes, backslashes and spaces are not accepted" ;; esac
dropin="$config_dir/conf.d/probation.toml"
want_line="imports = [\"$config_dir/conf.d/*.toml\"] $marker"
empty_roots="$certs_dir/_default/roots-empty"
unit_dropin="$systemd_dir/containerd.service.d/probation-ca.conf"
hosts="$certs_dir/_default/hosts.toml"
created_marker="$certs_dir/_default/.probation-created"

owned() { [ -f "$1" ] && grep -qxF "$marker" "$1"; }

if [ "$rollback" = 1 ]; then
  for f in "$hosts" "$certs_dir/_default/probation-ca.pem" "$dropin" "$unit_dropin"; do
    if [ -e "$f" ]; then
      case "$f" in *.pem) rm -f "$f" ;; *) if owned "$f"; then rm -f "$f"; else echo "install-node: $f is not ours, left in place" >&2; fi ;; esac
    fi
  done
  rmdir "$empty_roots" 2>/dev/null || true
  for d in "$certs_dir"/*/; do
    [ -d "$d" ] || continue
    [ "$(basename "$d")" != _default ] || continue
    if owned "${d}hosts.toml"; then rm -f "${d}hosts.toml"; fi
    rmdir "$d" 2>/dev/null || true
  done
  # `_default` goes too when this script created it and nothing else is in it now.
  if [ -f "$created_marker" ] && [ "$(ls -A "$certs_dir/_default")" = ".probation-created" ]; then rm -f "$created_marker"; rmdir "$certs_dir/_default" 2>/dev/null || true; fi
  # Only the line this script inserted goes: edits made to the file since (a new runtime option, another import) stay. A main file this
  # script created holds nothing else and goes with it; the backup of the original is deleted, never copied back over later edits.
  if [ -e "$config_file" ] && grep -qxF "$want_line" "$config_file"; then
    tmp="$config_file.tmp.$$"
    grep -vxF "$want_line" "$config_file" > "$tmp" || true
    if [ "$(grep -vxF -e "$marker" -e 'version = 3' "$tmp" | grep -c .)" = 0 ] && grep -qxF "$marker" "$tmp"; then rm -f "$tmp" "$config_file"; else cat "$tmp" > "$config_file" && rm -f "$tmp"; fi
  fi
  rm -f "$config_file.probation-backup"
  echo "install-node: rolled back; restart containerd (and run systemctl daemon-reload) to make it take effect. A preloaded image is not removed."
  exit 0
fi

[ -n "$endpoint" ] && [ -n "$ca" ] || die "--endpoint and --ca are required"
clean --ca "$ca"
[ -r "$ca" ] || die "cannot read the CA file $ca"
grep -q 'BEGIN CERTIFICATE' "$ca" || die "$ca holds no PEM certificate"
# An https origin only: a host name, an IPv4 address or a bracketed IPv6 address, an optional port, no path, user name or query.
printf '%s\n' "$endpoint" | grep -Eq '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$' \
  || die "the endpoint must be an https origin (https://host[:port], no path or credentials): $endpoint"

# Registries: host=id pairs, each host once.
printf '%s' "$registries" | while IFS= read -r pair; do
  [ -n "$pair" ] || continue
  printf '%s\n' "$pair" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?=[0-9]{1,9}$' || { echo "install-node: --registry wants host=id (a registry host and the firewall's OCI registry id), got: $pair" >&2; exit 2; }
done || exit 2
hosts_mapped=$(printf '%s' "$registries" | sed 's/=.*//' | sort)
[ -z "$(printf '%s\n' "$hosts_mapped" | sort | uniq -d)" ] || die "a registry is mapped twice"

# Directories that already exist next to _default decide for their registry (they win over _default): every one must be mapped, hold
# no legacy certificate files (a legacy layout sends containerd to the registry's own address) and no hosts file that is not ours.
if [ -d "$certs_dir" ]; then
  for d in "$certs_dir"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    [ "$name" = _default ] && continue
    printf '%s\n' "$hosts_mapped" | grep -qxF "$name" || die "$d exists and is not mapped: it would send $name to its own origin; map it with --registry $name=<id> or remove it"
    for f in "$d"*.crt "$d"*.cert "$d"*.key; do [ -e "$f" ] && die "$f is a legacy certificate file: containerd would go to $name's own address; move it away"; done
    [ ! -e "${d}hosts.toml" ] || owned "${d}hosts.toml" || die "${d}hosts.toml exists and was not written by this script"
  done
fi
if [ -e "$hosts" ] && ! owned "$hosts"; then
  die "$hosts exists and was not written by this script; move it away or merge by hand (a per-registry override is a way around the endpoint)"
fi
if [ -e "$dropin" ] && ! owned "$dropin"; then die "$dropin exists and was not written by this script"; fi
if [ -e "$unit_dropin" ] && ! owned "$unit_dropin"; then die "$unit_dropin exists and was not written by this script"; fi

if [ -n "$preload" ]; then
  [ -r "$preload" ] || die "cannot read the image archive $preload"
  printf '%s\n' "$image_ref" | grep -Eq '^[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}$' || die "--image-ref must be a digest-pinned reference (repository@sha256:<64 hex>)"
  command -v ctr >/dev/null 2>&1 || die "ctr is not installed (needed to import the image)"
fi

# The drop-in must speak the schema of the MAIN file: containerd lets an imported `version` win over the main file's, and a version-2 main
# file's CRI sections (SystemdCgroup, the sandbox image, the runtimes) are then ignored, silently switching the runtime's settings. So the
# drop-in carries NO version line and the registry section of the main file's own schema; an unknown version is refused.
# containerd 2.0 or later only: an older runtime reads another schema and another hosts-directory default.
if command -v containerd >/dev/null 2>&1; then
  cver=$(containerd --version 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^v?[0-9]+\.[0-9]+/) { v = $i; sub(/^v/, "", v); sub(/\..*/, "", v); print v; exit } }')
  [ -n "$cver" ] || die "cannot read the version of containerd (containerd --version): these scripts support containerd 2.0 or later only"
  [ "$cver" -ge 2 ] || die "containerd $cver.x is not supported: these scripts need containerd 2.0 or later"
else
  echo "install-node: containerd is not on this PATH: its version is not checked (2.0 or later is required); a new main file is written as version 3" >&2
fi
cfg_version=3
if [ -e "$config_file" ]; then
  cfg_version=$(awk '/^[[:space:]]*\[/ { exit } /^[[:space:]]*version[[:space:]]*=/ { v = $0; gsub(/[^0-9]/, "", v); print v; exit }' "$config_file")
  case $cfg_version in
    2|3) ;;
    *) die "cannot determine the schema version of $config_file (found '${cfg_version:-no top-level version line}'): refusing to write a drop-in whose schema might not match; add 'version = 2' or 'version = 3' to it" ;;
  esac
fi
if [ "$cfg_version" = 2 ]; then
  registry_section="[plugins.\"io.containerd.grpc.v1.cri\".registry]"
else
  registry_section="[plugins.'io.containerd.cri.v1.images'.registry]"
fi

# What the main file needs, decided before anything is written (a refusal leaves no half install).
import_action=insert
if [ ! -e "$config_file" ]; then
  import_action=create
elif grep -E '^[[:space:]]*imports[[:space:]]*=' "$config_file" | grep -qF "$config_dir/conf.d/*.toml"; then
  # (only an UNCOMMENTED `imports` key counts: a `# imports = [...]` comment is not an import)
  import_action=have
elif grep -Eq '^[[:space:]]*imports[[:space:]]*=' "$config_file"; then
  die "$config_file has an imports line that does not name $config_dir/conf.d/*.toml: add that pattern to it by hand, then run this again"
fi
[ ! -d "$empty_roots" ] || [ -z "$(ls -A "$empty_roots")" ] || die "$empty_roots is not empty: anything in it is a trusted root; empty it or move it away"

umask 022
[ -d "$certs_dir/_default" ] || created_default=1
mkdir -p "$certs_dir/_default" "$config_dir/conf.d" "$empty_roots"
[ "${created_default:-0}" = 0 ] || : > "$created_marker"
# The empty directory decides which roots are trusted: root-owned, nobody else may write in it.
chmod 0755 "$empty_roots"
[ "$(id -u)" != 0 ] || chown root:root "$empty_roots"
write() { # write DEST CONTENT: replace atomically
  tmp="$1.tmp.$$"
  printf '%s\n' "$2" > "$tmp"
  mv -f "$tmp" "$1"
}
cp "$ca" "$certs_dir/_default/probation-ca.pem.tmp.$$"
mv -f "$certs_dir/_default/probation-ca.pem.tmp.$$" "$certs_dir/_default/probation-ca.pem"
write "$hosts" "$marker
server = \"$endpoint\"
capabilities = [\"pull\", \"resolve\"]
ca = \"$certs_dir/_default/probation-ca.pem\""
printf '%s' "$registries" | while IFS= read -r pair; do
  [ -n "$pair" ] || continue
  host=${pair%%=*}; id=${pair#*=}
  mkdir -p "$certs_dir/$host"
  write "$certs_dir/$host/hosts.toml" "$marker
server = \"$endpoint/registry/oci/$id\"
capabilities = [\"pull\", \"resolve\"]
ca = \"$certs_dir/_default/probation-ca.pem\""
done
# One directory only: containerd 2.x defaults to '/etc/containerd/certs.d:/etc/docker/certs.d', and a per-registry file in the second one
# would be a route around the endpoint.
write "$dropin" "$marker
$registry_section
  config_path = '$certs_dir'"

# The drop-in is read only when the main file imports it.
case $import_action in
  create)
    mkdir -p "$(dirname "$config_file")"
    write "$config_file" "$marker
version = 3
$want_line" ;;
  insert)
    tmp="$config_file.tmp.$$"
    awk -v want="$want_line" '{ print } /^[[:space:]]*version[[:space:]]*=/ && !done { print want; done = 1 }' "$config_file" > "$tmp"
    cat "$tmp" > "$config_file" && rm -f "$tmp" ;;
esac

# Trust only the service CA. The `ca` of hosts.toml only ADDS to the system roots. Go replaces its FILE list with SSL_CERT_FILE but still
# reads the default certificate DIRECTORIES (/etc/ssl/certs, /etc/pki/tls/certs) unless SSL_CERT_DIR is also set: the drop-in sets both,
# the directory being an EMPTY one this script created (not a path somebody else could create and fill).
if [ "$no_systemd" = 0 ]; then
  mkdir -p "$systemd_dir/containerd.service.d"
  write "$unit_dropin" "$marker
[Service]
Environment=\"SSL_CERT_FILE=$certs_dir/_default/probation-ca.pem\"
Environment=\"SSL_CERT_DIR=$empty_roots\""
fi

if [ -n "$preload" ]; then
  want_digest=${image_ref#*@}
  # --digests --base-name creates repository@<manifest digest> (the image's own digest); --index-name would wrap it in an index of
  # another digest. --no-unpack leaves unpacking to the CRI plugin at the first container start.
  ctr --address "$address" -n "$namespace" images import --local --no-unpack --digests --base-name "${image_ref%@*}" "$preload" >/dev/null || die "ctr could not import $preload"
  have=$(ctr --address "$address" -n "$namespace" images ls "name==$image_ref" | awk 'NR > 1 { print $3 }')
  if [ "$have" != "$want_digest" ]; then
    ctr --address "$address" -n "$namespace" images rm "$image_ref" >/dev/null 2>&1 || true
    die "the imported image is ${have:-absent}, not $want_digest: removed"
  fi
  echo "install-node: preloaded $image_ref ($want_digest) into the $namespace content store"
fi

echo "install-node: wrote $hosts, $certs_dir/_default/probation-ca.pem, $dropin and the import of it in $config_file"
[ "$no_systemd" = 1 ] || echo "install-node: wrote $unit_dropin (run systemctl daemon-reload)"
echo "install-node: next: systemctl daemon-reload; systemctl restart containerd; then verify-node.sh --endpoint $endpoint --certs-dir $certs_dir --containerd-config $config_file --systemd-dir $systemd_dir (it checks the environment of the running daemon)"
