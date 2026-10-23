#!/usr/bin/env bash
# E2E-signup-to-install and M-propagation (C32 metrics 1 and 2, C82), run before every
# release by .github/workflows/release.yml.
#
# Builds both images, starts docker-compose.e2e.yml, does what an operator does once
# (migrate, the app's database role, `admin bootstrap`, firewall-1's token), then hands
# over to drive.mjs, which signs a new organisation up and installs with npm through
# firewall-1 (prints `E2E PASS <seconds>`), and measures propagation to two firewalls
# (prints `propagation edits p99 <= interval` and `propagation revocations p99 <=
# interval`). Exits 0 only when all three pass.
#
# Needs docker with compose (podman and podman-compose do), node 20 or later, npm,
# openssl and curl, and outbound https to registry.npmjs.org, api.osv.dev and
# api.pwnedpasswords.com. Environment:
#   E2E_WORK          the directory for generated files (default: a new mktemp -d)
#   E2E_SKIP_BUILD=1  use the images already built
#   E2E_KEEP=1        leave the stack running afterwards
#   E2E_PORTAL_PORT, E2E_FIREWALL_1_PORT, E2E_FIREWALL_2_PORT  (18088, 18443, 18444)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
E2E_WORK=${E2E_WORK:-$(mktemp -d)}
mkdir -p "$E2E_WORK"
E2E_WORK=$(cd "$E2E_WORK" && pwd)
export E2E_WORK
export E2E_PORTAL_PORT=${E2E_PORTAL_PORT:-18088}
export E2E_FIREWALL_1_PORT=${E2E_FIREWALL_1_PORT:-18443}
export E2E_FIREWALL_2_PORT=${E2E_FIREWALL_2_PORT:-18444}
E2E_SECRET_KEY=$(openssl rand -hex 32)
export E2E_SECRET_KEY
export E2E_COMPOSE="docker compose -p probation-e2e -f $root/docker-compose.e2e.yml"

stop() {
  if [ -z "${E2E_KEEP:-}" ]; then
    $E2E_COMPOSE down -v >/dev/null 2>&1 || true
  fi
}
trap stop EXIT

# One CA, and one certificate for the sync proxy (`sync`) and the firewalls
# (`localhost`, as the host reaches their published ports).
mkdir -p "$E2E_WORK/ca" "$E2E_WORK/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=probation-e2e-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
  -keyout "$E2E_WORK/ca.key" -out "$E2E_WORK/ca/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$E2E_WORK/tls/key.pem" -out "$E2E_WORK/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,DNS:sync,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >"$E2E_WORK/tls.ext"
openssl x509 -req -in "$E2E_WORK/tls.csr" -CA "$E2E_WORK/ca/ca.pem" -CAkey "$E2E_WORK/ca.key" \
  -set_serial 1 -days 2 -extfile "$E2E_WORK/tls.ext" -out "$E2E_WORK/tls/cert.pem" 2>/dev/null
# The services run as their own users.
chmod 0644 "$E2E_WORK/tls/key.pem"

cat >"$E2E_WORK/server.toml" <<EOF
[server]
listen = "0.0.0.0:8080"

[portal]
base_url = "http://127.0.0.1:$E2E_PORTAL_PORT/"
firewall_url = "https://localhost:$E2E_FIREWALL_1_PORT"
EOF

cat >"$E2E_WORK/nginx.conf" <<'EOF'
events {}
http {
  server {
    listen 8443 ssl;
    ssl_certificate /e2e/tls/cert.pem;
    ssl_certificate_key /e2e/tls/key.pem;
    location / {
      proxy_pass http://server:8080;
    }
  }
}
EOF

# The shipped sample, made managed: TLS on the published port, a 10 s sync interval
# (M-propagation), and a per-client lookup allowance above what the pollers' 50 keys
# from one host address need, so the measurement is of propagation, not of C120.
for n in 1 2; do
  port_var=E2E_FIREWALL_${n}_PORT
  sed -e 's|^listen = .*|listen = "0.0.0.0:8443"|' \
    -e "s|^public_url = .*|public_url = \"https://localhost:${!port_var}\"|" \
    "$root/config.sample.toml" >"$E2E_WORK/firewall-$n.toml"
  cat >>"$E2E_WORK/firewall-$n.toml" <<'EOF'

sync_interval_seconds = 10
tls_cert_path = "/e2e/tls/cert.pem"
tls_key_path = "/e2e/tls/key.pem"

[management]
url = "https://sync:8443"
token_file = "/e2e/firewall.token"
lookup_budget_per_second = 200
client_lookup_allowance_per_second = 100
EOF
  : >"$E2E_WORK/firewall-$n.token"
done

if [ -z "${E2E_SKIP_BUILD:-}" ]; then
  $E2E_COMPOSE build server firewall-1
fi

# What the operator does once (docs/management-server.md).
$E2E_COMPOSE up -d postgres
for _ in $(seq 60); do
  $E2E_COMPOSE exec -T postgres pg_isready -U probation >/dev/null 2>&1 && break
  sleep 1
done
$E2E_COMPOSE run --rm --no-deps server migrate
$E2E_COMPOSE exec -T postgres psql -U probation -d probation -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE probation_e2e LOGIN PASSWORD 'probation' IN ROLE probation_app"
$E2E_COMPOSE run --rm --no-deps server admin bootstrap --org Operators \
  --firewall firewall-1 --firewall-source 0.0.0.0/0 --firewall-source ::/0 >"$E2E_WORK/bootstrap.out"
sed -n 's/^firewall_token=//p' "$E2E_WORK/bootstrap.out" >"$E2E_WORK/firewall-1.token"
test -s "$E2E_WORK/firewall-1.token"
$E2E_COMPOSE up -d --no-deps server sync firewall-1

for _ in $(seq 120); do
  curl -sf --cacert "$E2E_WORK/ca/ca.pem" "https://localhost:$E2E_FIREWALL_1_PORT/health/ready" >/dev/null &&
    curl -sf "http://127.0.0.1:$E2E_PORTAL_PORT/signin" >/dev/null && break
  sleep 1
done

NODE_EXTRA_CA_CERTS="$E2E_WORK/ca/ca.pem" node "$root/tests/e2e/drive.mjs"
