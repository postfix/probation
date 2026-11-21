#!/bin/sh
# Runs inside the container of the Dockerfile next to it, with /node (deploy/kubernetes/node) mounted read-only. The SHIPPED renderer
# (install-firewall.sh, staged with --root) turns the cluster's addresses into the rule files, `nft -c` checks them, they are loaded,
# and real connections show what they do. Addresses on a dummy interface stand for: the Probation endpoint (10.77.0.20, port 30443),
# a registry origin (10.77.0.30), a cluster address (10.77.0.40), an extra allowed address (10.77.0.50), the cluster resolver
# (10.77.0.53) and another resolver (10.77.0.54); 10.77.0.2 is an approved node and 10.77.0.3 an unapproved host.
# Prints `before|after OPEN|CLOSED <addr>:<port>` (egress), `ingress OPEN|CLOSED <source> <addr>:<port>` and the syntax/reload results.
set -eu
ip link add d0 type dummy
ip link set d0 up
for a in 10.77.0.20 10.77.0.30 10.77.0.40 10.77.0.50 10.77.0.53 10.77.0.54 10.77.0.2 10.77.0.3; do ip addr add "$a/32" dev d0; done
sh /node/install-firewall.sh --root /stage --service4 10.77.0.20 --service-port 30443 --cluster4 10.77.0.40/32 --dns4 10.77.0.53 \
  --extra4 10.77.0.50 --approved4 10.77.0.2 >/dev/null
for spec in 10.77.0.20:30443 10.77.0.20:443 10.77.0.30:443 10.77.0.30:30443 10.77.0.40:6443 10.77.0.50:8080 10.77.0.53:53 10.77.0.54:53; do
  busybox nc -ll -p "${spec#*:}" -s "${spec%:*}" -e /bin/true >/dev/null 2>&1 &
done
# UDP DNS: a datagram to each resolver; it arrived when its listener wrote it down.
for ip in 10.77.0.53 10.77.0.54; do socat -u "UDP-RECV:53,bind=$ip" "OPEN:/tmp/udp-$ip,creat,append" 2>/dev/null & done
sleep 1
udp() { : > "/tmp/udp-$1"; echo "q-$2" | socat -u - "UDP-SENDTO:$1:53" 2>/dev/null || true; sleep 1; if [ -s "/tmp/udp-$1" ]; then echo "udp-$2 OPEN $1:53"; else echo "udp-$2 CLOSED $1:53"; fi; }
probe() { if busybox nc -w 2 -z "${1%:*}" "${1#*:}" 2>/dev/null; then echo "$2 OPEN $1"; else echo "$2 CLOSED $1"; fi; }
from() { if busybox nc -w 2 -s "$1" -z "${2%:*}" "${2#*:}" 2>/dev/null; then echo "ingress OPEN $1 $2"; else echo "ingress CLOSED $1 $2"; fi; }
targets="10.77.0.20:30443 10.77.0.20:443 10.77.0.30:443 10.77.0.30:30443 10.77.0.40:6443 10.77.0.50:8080 10.77.0.53:53 10.77.0.54:53"
for spec in $targets; do probe "$spec" before; done
udp 10.77.0.53 before; udp 10.77.0.54 before
nft -c -f /stage/etc/probation/node-egress.nft && nft -c -f /stage/etc/probation/node-ingress.nft && echo "SYNTAX ok"
nft -f /stage/etc/probation/node-egress.nft
for spec in $targets; do probe "$spec" after; done
udp 10.77.0.53 after; udp 10.77.0.54 after
# The NodePort's ingress rule: an approved node reaches it, another host does not (checked with the egress table removed, so only
# this table decides; the connection's source address is chosen with -s).
nft delete table inet probation_node_egress
before_in=$(from 10.77.0.3 10.77.0.20:30443)
nft -f /stage/etc/probation/node-ingress.nft
echo "$before_in" | sed 's/^ingress/ingress-before/'
from 10.77.0.2 10.77.0.20:30443
from 10.77.0.3 10.77.0.20:30443
nft -f /stage/etc/probation/node-ingress.nft && nft -f /stage/etc/probation/node-egress.nft && echo "RELOAD ok"
# M1: what `systemctl restart|reload nftables` does is `flush ruleset`: both tables are gone and the node is open again, until the unit's
# own reload path (its ExecReload lines, taken from the staged unit file and run here) puts them back.
nft flush ruleset
probe 10.77.0.30:443 flushed
from 10.77.0.3 10.77.0.20:30443 | sed 's/^ingress/flushed-ingress/'
unit=/stage/etc/systemd/system/probation-node-firewall.service
sed -n 's/^ExecReload=-\{0,1\}//p' "$unit" | sed 's#/usr/sbin/nft#nft#; s#/etc/probation#/stage/etc/probation#' | while read -r line; do sh -c "$line"; done
probe 10.77.0.30:443 reasserted
from 10.77.0.3 10.77.0.20:30443 | sed 's/^ingress/reasserted-ingress/'
from 10.77.0.2 10.77.0.20:30443 | sed 's/^ingress/reasserted-ingress/'
grep -q '^PartOf=nftables.service' "$unit" && grep -q '^ExecStop=-' "$unit" && echo "UNIT partof ok"
sh /node/install-firewall.sh --root /stage --rollback && [ ! -e /stage/etc/probation/node-egress.nft ] && echo "ROLLBACK ok"
