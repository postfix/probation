#!/bin/sh
# Renders egress.nft and ingress.nft for this cluster from arguments, checks them with `nft -c`, installs them with the boot unit
# probation-node-firewall.service, ENABLES AND STARTS the unit (the unit loads both files) and checks that it is active and both tables are loaded.
# An INACTIVE unit would not follow a later `systemctl restart nftables` (PartOf= and ReloadPropagatedFrom= only reach a unit that is active), so
# the rules would stay gone until the next boot. --rollback removes the tables, the unit and the files.
#
#   install-firewall.sh --service4 192.0.2.20 --service-port 30443 --cluster4 10.0.0.0/8,172.16.0.0/12 --dns4 10.96.0.10,192.0.2.53
#       --approved4 192.0.2.11,192.0.2.12 [--service6 .. --cluster6 .. --dns6 .. --approved6 .. --extra4 .. --extra6 ..] [--root DIR] [--load] [--no-load]
# --root DIR stages the files under DIR and touches neither systemd nor the rule set, unless --load asks for the start and the checks anyway
# (tests with stub tools; a staged root on a host that really runs them).
# --dns4/--dns6 list EVERY resolver the node uses: the cluster's DNS service AND the host's own upstream resolver (systemd-resolved's
# forwarders, the DHCP or VPC resolver); a resolver that is not listed gets nothing on port 53, the node then cannot resolve the endpoint.
# Lists are comma-separated addresses or CIDRs. An IPv6 list left out becomes `::1` (matches nothing a node would connect to).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=
noload=0
load=0
rollback=0
service4= service6=::1 port=30443 cluster4= cluster6=::1 dns4= dns6=::1 extra4=127.0.0.1 extra6=::1 approved4= approved6=::1

die() { echo "install-firewall: $*" >&2; exit 2; }
list() { # list NAME VALUE: a non-empty comma-separated list of addresses or CIDRs and nothing else
  [ -n "$2" ] || die "--$1 is required"
  printf '%s\n' "$2" | grep -Eq '^[0-9a-fA-F:.]+(/[0-9]{1,3})?(,[0-9a-fA-F:.]+(/[0-9]{1,3})?)*$' || die "--$1 must be a comma-separated list of addresses or CIDRs: $2"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) rollback=1; shift; continue ;;
    --no-load) noload=1; shift; continue ;;
    --load) load=1; shift; continue ;;
  esac
  [ $# -ge 2 ] || die "$1 needs a value"
  case "$1" in
    --root) root=$2 ;;
    --service4) service4=$2 ;; --service6) service6=$2 ;;
    --service-port) port=$2 ;;
    --cluster4) cluster4=$2 ;; --cluster6) cluster6=$2 ;;
    --dns4) dns4=$2 ;; --dns6) dns6=$2 ;;
    --extra4) extra4=$2 ;; --extra6) extra6=$2 ;;
    --approved4) approved4=$2 ;; --approved6) approved6=$2 ;;
    *) die "unknown argument $1" ;;
  esac
  shift 2
done

etc="$root/etc/probation"
unit="$root/etc/systemd/system/probation-node-firewall.service"
if [ "$rollback" = 1 ]; then
  if [ -z "$root" ]; then
    nft delete table inet probation_node_egress 2>/dev/null || true
    nft delete table inet probation_node_ingress 2>/dev/null || true
    systemctl disable --now probation-node-firewall.service 2>/dev/null || true
  fi
  rm -f "$etc/node-egress.nft" "$etc/node-ingress.nft" "$unit"
  [ -n "$root" ] || systemctl daemon-reload 2>/dev/null || true
  echo "install-firewall: rolled back"
  exit 0
fi

for pair in service4:"$service4" service6:"$service6" cluster4:"$cluster4" cluster6:"$cluster6" dns4:"$dns4" dns6:"$dns6" extra4:"$extra4" extra6:"$extra6" approved4:"$approved4" approved6:"$approved6"; do
  list "${pair%%:*}" "${pair#*:}"
done
printf '%s\n' "$port" | grep -Eq '^[0-9]{1,5}$' || die "--service-port must be a port number"

render() { # render SRC DEST NAME=VALUE...
  src=$1; dest=$2; shift 2
  tmp="$dest.tmp.$$"
  cp "$here/$src" "$tmp"
  for kv in "$@"; do
    name=${kv%%=*}; value=$(printf '%s' "${kv#*=}" | sed 's/,/, /g')
    # a number is not a set
    case "$name" in service_port|nodeport) new="define $name = $value" ;; *) new="define $name = { $value }" ;; esac
    grep -q "^define $name = " "$tmp" || { rm -f "$tmp"; die "$src has no define $name"; }
    sed "s|^define $name = .*|$new|" "$tmp" > "$tmp.2" && mv "$tmp.2" "$tmp"
  done
  mv "$tmp" "$dest"
}

mkdir -p "$etc" "$(dirname "$unit")"
render egress.nft "$etc/node-egress.nft" "service4=$service4" "service6=$service6" "service_port=$port" "cluster4=$cluster4" "cluster6=$cluster6" "dns4=$dns4" "dns6=$dns6" "extra4=$extra4" "extra6=$extra6"
render ingress.nft "$etc/node-ingress.nft" "nodeport=$port" "approved4=$approved4" "approved6=$approved6"
cp "$here/probation-node-firewall.service" "$unit"

do_load=0
{ [ -z "$root" ] || [ "$load" = 1 ]; } && [ "$noload" = 0 ] && do_load=1
if command -v nft >/dev/null 2>&1; then
  nft -c -f "$etc/node-egress.nft" || die "the rendered egress rules do not pass nft -c"
  nft -c -f "$etc/node-ingress.nft" || die "the rendered ingress rules do not pass nft -c"
elif [ "$do_load" = 1 ]; then
  die "nft is not installed"
fi
if [ "$do_load" = 1 ]; then
  # The unit loads both files (each starts with `delete table`, so a second start replaces the tables). `restart`, not `start`: an unchanged
  # active oneshot unit would ignore a start and keep the OLD tables after a re-render.
  systemctl daemon-reload
  systemctl enable probation-node-firewall.service
  systemctl restart probation-node-firewall.service || die "probation-node-firewall.service did not start: journalctl -u probation-node-firewall"
  for table in probation_node_egress probation_node_ingress; do
    nft list table inet "$table" >/dev/null 2>&1 || die "the nft table inet $table is not loaded after the start of probation-node-firewall.service"
  done
  systemctl is-active --quiet probation-node-firewall.service || die "probation-node-firewall.service is not active: a restart of nftables.service would not bring the tables back"
fi
echo "install-firewall: wrote $etc/node-egress.nft, $etc/node-ingress.nft and $unit"
