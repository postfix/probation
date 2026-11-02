# Troubleshooting

Start with the error shown by your client or the portal. Check the firewall's log and `https://YOUR-FIREWALL/health/ready`. The [operations reference](operations.md#19-troubleshooting) has the full error list.

## Service is not ready

| What you see | Check | Do this |
| --- | --- | --- |
| Standalone readiness is `503` | Blocklist, storage, and disk space | Run `probation check-blocklist /etc/probation/blocklist.json`; read the firewall log. |
| Managed readiness is `503` after first start | Server URL, TLS, token file, first sync | Check `[management] url`, token file permissions, and the server log. |
| Firewall stopped after a settings push | Service restart policy | Add a restart policy, then start the firewall. |
| Server will not start after a restore | Database migration or secret key | Run the migration for this version and restore the `PROBATION_SERVER_SECRET_KEY` backed up with that database. |

Run `probation check-config /etc/probation/config.toml` to find a missing or unknown firewall setting. Run it as the same user and with the same environment as the service.

## Client gets an error

| What you see | Likely cause | Do this |
| --- | --- | --- |
| `401` on every managed request | Missing or revoked API key | Recopy client settings from **API keys**. If only one firewall fails, check its `token_file` and **Fleet** status. |
| Selected registry request is refused | Certificate, membership, registry, or group no longer allowed | Check **Package client setup**, **Organisation → Package registries**, and the member's current group. Get a fresh certificate if needed. |
| `403` for one version | A block, age delay, or OSV finding | Check **Activity** and the effective **Policy**. |
| npm audit returns an upstream error | The selected npm registry does not serve the audit endpoint npm called | Check the upstream registry's audit support. Package installs can still work. |
| `502 INTEGRITY_MISMATCH` | File bytes changed after Probation first saw them | Treat the package and registry as a security incident; inspect the upstream artifact before retrying. |
| No packages resolve | Client URL, TLS trust, or upstream connectivity | Check the exact URL in the client's config, the certificate chain, and the firewall log. |

## Portal sign-in or email fails

- **No confirmation mail:** Check `[portal.smtp]` and the server log. Without SMTP settings, mail waits in the server database and cannot reach users.
- **Administrator page asks for an authenticator:** Open **Account settings → Authenticator app** and finish setup.
- **First administrator link expired:** Run `probation-server admin reset-link --config /etc/probation-server/config.toml --email ops@example.org` with the real administrator email and server database environment set.
- **Server says its secret key does not match:** Restore the secret key saved with that database. A new key cannot open existing authenticator and sign-in provider secrets.

For backups, restores, logs, network limits, and exact error codes, use the [operations reference](operations.md). For server settings and first-run recovery, use the [management server reference](management-server.md).
