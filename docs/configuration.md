# Configuration

Use the right place for each change:

| What you are changing | Where it lives | How it takes effect |
| --- | --- | --- |
| Firewall address, storage, TLS, cache limits, release delay, or OSV mode | `config.toml`; start from [`config.sample.toml`](../config.sample.toml) | Check the file, then restart the firewall. |
| Standalone package and file blocks | The JSON file named by `blocklist_file` | Check the new file, then replace the live file; the firewall reloads it. |
| Managed accounts, policy, registries, certificates, and fleet settings | Web interface | Policy and key changes reach firewalls at their next sync. A fleet settings push restarts each firewall. |
| Management server address, portal, mail, and sign-in providers | Server TOML file and environment variables | Restart `probation-server`. |

## Firewall file

At minimum, set `listen`, `public_url`, `data_dir`, and the cache limits shown in the sample. For standalone mode, also set `blocklist_file`, `cooldown_seconds`, and `blocklist_poll_seconds`. Set both `tls_cert_path` and `tls_key_path` to serve HTTPS directly. Give clients the HTTPS `public_url`.

Check the firewall file before restarting. In standalone mode, check the blocklist too:

```sh
probation check-config /etc/probation/config.toml
probation check-blocklist /etc/probation/blocklist.json
```

In managed mode, add `[management]` with the server's HTTPS `url` and a `token_file` containing the firewall token. The local blocklist is ignored; policy comes from the server. Keep the token out of `config.toml`. The full [firewall settings reference](operations.md#14-firewall-configuration-reference) lists defaults and limits.

## Server file and secrets

Set `[server] listen` in the server TOML file. Add `[portal] base_url` to enable the web interface and `[portal.smtp]` to send confirmation mail. Set `[portal] firewall_url` so the API keys page can show usable npm and pip settings. The server listens on plain HTTP; put a TLS proxy in front of it.

Set database URLs and the 64-character `PROBATION_SERVER_SECRET_KEY` in the environment. Keep the secret key with each database backup, stored separately from the backup itself. Provider client secrets and the mail password also use environment variables. See the [server settings reference](management-server.md#3-the-servers-settings-file) for exact names and the [database steps](management-server.md#4-migrations-and-database-roles).

## Portal settings

Open **Policy** to change managed package rules. Open **Organisation → Package registries** to add an npm or PyPI target, a read credential, or an approved deletion destination. Open **Fleet** as a global admin to send shared firewall settings. Address, storage, TLS, and management connection settings stay in each firewall's own `config.toml`; they cannot be pushed. Give every managed firewall a restart policy so a settings push can take effect.

See [Web interface](web-interface.md) for the pages and [Troubleshooting](troubleshooting.md) when a check or restart fails.
