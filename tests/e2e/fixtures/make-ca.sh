#!/usr/bin/env bash
# The e2e test CA and the one certificate every TLS endpoint of the stack serves: the
# fakes under their real public names, the mail sink, and the gateway in front of the
# portal, the sync API and the firewalls. Only the test stack trusts the CA
# (SSL_CERT_FILE in compose.yml); nothing on the host does.
#
#   make-ca.sh <dir>   writes <dir>/ca/ca.pem, <dir>/ca.key, <dir>/tls/{cert,key}.pem
set -euo pipefail

dir=$1
# OPENSSL names the program explicitly (tests use a fake); by default whatever `openssl` is on PATH.
openssl=${OPENSSL:-openssl}
# Git for Windows rewrites an argument that starts with `/` (-subj /CN=...) into a Windows path before a native openssl sees it.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
names=(
  registry.npmjs.org registry-b.e2e.test private-registry.e2e.test ocsp-a.e2e.test ocsp-b.e2e.test private-ocsp.e2e.test pypi.org files.pythonhosted.org api.osv.dev api.pwnedpasswords.com
  accounts.google.com idp.e2e.test fakes.e2e.test mail.e2e.test unlisted-cdn.e2e.test
  portal.e2e.test sync.e2e.test fw1.e2e.test fw2.e2e.test fw-standalone.e2e.test
  localhost
)
mkdir -p "$dir/ca" "$dir/tls"
# openssl's own messages are kept for a failure instead of being thrown away.
log="$dir/openssl.log"
: > "$log"
trap 'status=$?; echo "make-ca.sh: a command failed (exit $status); openssl said:" >&2; cat "$log" >&2; exit $status' ERR
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
  -subj /CN=probation-e2e-ca -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign -keyout "$dir/ca.key" -out "$dir/ca/ca.pem" 2>>"$log"
"$openssl" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=probation-e2e \
  -keyout "$dir/tls/key.pem" -out "$dir/tls.csr" 2>>"$log"
{
  printf 'subjectAltName=IP:127.0.0.1'
  printf ',DNS:%s' "${names[@]}"
  printf '\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n'
} >"$dir/tls.ext"
"$openssl" x509 -req -in "$dir/tls.csr" -CA "$dir/ca/ca.pem" -CAkey "$dir/ca.key" -set_serial "0x$("$openssl" rand -hex 8)" \
  -days 7 -extfile "$dir/tls.ext" -out "$dir/tls/cert.pem" 2>>"$log"
# The services run as their own users.
chmod 0644 "$dir/tls/key.pem"
rm -f "$dir/tls.csr" "$dir/tls.ext" "$log"
