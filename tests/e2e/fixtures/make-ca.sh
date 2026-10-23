#!/usr/bin/env bash
# The e2e test CA and the one certificate every TLS endpoint of the stack serves: the
# fakes under their real public names, the mail sink, and the gateway in front of the
# portal, the sync API and the firewalls. Only the test stack trusts the CA
# (SSL_CERT_FILE in compose.yml); nothing on the host does.
#
#   make-ca.sh <dir>   writes <dir>/ca/ca.pem, <dir>/ca.key, <dir>/tls/{cert,key}.pem
set -euo pipefail

dir=$1
names=(
  registry.npmjs.org pypi.org files.pythonhosted.org api.osv.dev api.pwnedpasswords.com
  accounts.google.com idp.e2e.test fakes.e2e.test mail.e2e.test
  portal.e2e.test sync.e2e.test fw1.e2e.test fw2.e2e.test fw-standalone.e2e.test
  localhost
)
mkdir -p "$dir/ca" "$dir/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
  -subj /CN=probation-e2e-ca -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign -keyout "$dir/ca.key" -out "$dir/ca/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=probation-e2e \
  -keyout "$dir/tls/key.pem" -out "$dir/tls.csr" 2>/dev/null
{
  printf 'subjectAltName=IP:127.0.0.1'
  printf ',DNS:%s' "${names[@]}"
  printf '\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n'
} >"$dir/tls.ext"
openssl x509 -req -in "$dir/tls.csr" -CA "$dir/ca/ca.pem" -CAkey "$dir/ca.key" -set_serial "0x$(openssl rand -hex 8)" \
  -days 7 -extfile "$dir/tls.ext" -out "$dir/tls/cert.pem" 2>/dev/null
# The services run as their own users.
chmod 0644 "$dir/tls/key.pem"
rm -f "$dir/tls.csr" "$dir/tls.ext"
