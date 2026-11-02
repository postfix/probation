# Install

Choose [standalone](#standalone-firewall) for one firewall with local rules, or [managed](#managed-deployment) for accounts, a web portal, and selected registries. Both need a trusted HTTPS address for package clients. [Configuration](configuration.md) explains where each setting lives.

## Standalone firewall

1. Install the published firewall:

   ```sh
   cargo install probation --locked
   ```

   To use features in this checkout, build from source instead:

   ```sh
   cargo build --release --locked -p probation
   sudo install -m 0755 target/release/probation /usr/local/bin/probation
   ```

   `cargo install` installs the version published on crates.io. A source build needs the Rust version in `rust-toolchain.toml`, `cmake`, a C compiler, and `perl`. With Docker or Podman and no Rust toolchain on the host, run `scripts/build-install.sh`.

2. Copy `config.sample.toml` to `/etc/probation/config.toml` and `blocklist.sample.json` to `/etc/probation/blocklist.json`. Set `data_dir`, `blocklist_file`, `public_url`, `listen`, `tls_cert_path`, and `tls_key_path` for your host. Use a real blocklist before relying on its rules. Make the data folder writable by the firewall user.

3. Check both files, then start:

   ```sh
   probation check-config /etc/probation/config.toml
   probation check-blocklist /etc/probation/blocklist.json
   probation serve --config /etc/probation/config.toml
   ```

4. Point npm or pip at the firewall as shown in [Usage](usage.md#connect-a-package-client). Check `https://YOUR-FIREWALL/health/ready`; a ready firewall answers `200`.

The sample config holds new versions for 24 hours and enables OSV checks. Change `cooldown_seconds` and `osv_mode` to match your policy. The firewall needs system CA certificates to reach HTTPS registries. Put a reverse proxy in front of it for per-client rate limits; see the [operations reference](operations.md#6-tls-reverse-proxies-and-outbound-traffic).

For container or systemd setup, use the commands and permissions in the [operations reference](operations.md#2-installing-and-running). `scripts/install-local.sh` sets up a local firewall and client configuration on one machine.

## Managed deployment

You need PostgreSQL 16, a TLS reverse proxy for the management server, and at least one firewall. The server listens on plain HTTP; clients and firewalls reach it through the HTTPS proxy.

1. Build both images from the repository root:

   ```sh
   docker build -f crates/probation-server/Dockerfile -t probation-server .
   docker build -t probation .
   ```

   Or build and install the server binary on the host for the commands below:

   ```sh
   cargo build --release --locked -p probation-server
   sudo install -m 0755 target/release/probation-server /usr/local/bin/probation-server
   ```

2. Create the server settings file. Set `[server] listen`; add `[portal] base_url` for the web portal. Supply `PROBATION_SERVER_DATABASE_URL`, `PROBATION_SERVER_MIGRATE_DATABASE_URL`, and, with the portal, `PROBATION_SERVER_SECRET_KEY`. Add SMTP settings so users can confirm email. Back up the secret key alongside each database backup, but store it separately. Use the [server settings reference](management-server.md#3-the-servers-settings-file).

3. Apply the schema as its owner. The commands below use the host binary; with the image, run them inside the server container:

   ```sh
   probation-server migrate
   ```

   Run this with `PROBATION_SERVER_MIGRATE_DATABASE_URL` set. Create a PostgreSQL login in the `probation_app` group as shown in the [database role instructions](management-server.md#4-migrations-and-database-roles). Set `PROBATION_SERVER_DATABASE_URL` to that login for the next commands.

4. Create the first administrator and firewall token. Use the server config path and the real address range from which the firewall connects:

   ```sh
   probation-server admin bootstrap --config /etc/probation-server/config.toml \
     --email ops@example.org --org "Example" --firewall fw-1 \
     --firewall-source 203.0.113.10/32
   ```

   Save the printed key and firewall token immediately. The password link is shown once.

5. Start `probation-server serve --config /etc/probation-server/config.toml` behind the TLS proxy. In each firewall config, set `[management] url` to the server's HTTPS address and `token_file` to a file containing its firewall token. Run the firewall under a restart policy: a settings push makes it exit so the supervisor can start it with the new settings.

6. Open the portal, set the administrator password, and set up an authenticator app. Use [Usage](usage.md) to create keys, rules, and registries. Check readiness as described in [Troubleshooting](troubleshooting.md#service-is-not-ready).

`deploy/docker-compose.yml` shows the server and one managed firewall. The [management server reference](management-server.md#5-first-run) has the complete first-run sequence.
