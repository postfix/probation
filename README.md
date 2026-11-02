# Probation: overview

Probation checks npm and PyPI packages before your tools download them. It sits between package clients and a registry. It can delay new releases, block packages or exact files, check known vulnerabilities through [OSV](https://osv.dev), and verify downloaded files.

| Part | Use it for |
| --- | --- |
| `probation` | The package firewall. It serves npm and PyPI requests. |
| `probation-server` | Optional management server and web portal for accounts, rules, registries, and firewall settings. It needs PostgreSQL. |

## Choose a setup

- **Standalone:** One firewall uses a local blocklist and the same rules for every client. Start with [Install](docs/install.md#standalone-firewall).
- **Managed:** People sign in, select an account or organisation, and use its rules. Administrators can add npm and PyPI registries. Start with [Install](docs/install.md#managed-deployment).

The firewall can serve an older allowed version when a newer one is held back. In managed mode, an administrator can select an upstream registry for package reads and supported publishing actions. Selected npm and PyPI URLs have separate paths under `/registry/`. Package clients use a certificate for these paths; the portal offers a setup bundle when self-service certificates are enabled. The upstream registry still decides whether a user may publish or remove a package.

“Allowed” means the request passed the configured checks. It does not promise that the package is safe. Checks apply to requests that reach Probation; they cannot inspect packages already installed, files in a client cache, or downloads from other sources.

## Guides

1. [Install](docs/install.md): build, configure, and start either setup.
2. [Usage](docs/usage.md): connect clients, manage rules, registries, and accounts.
3. [Troubleshooting](docs/troubleshooting.md): diagnose common failures.
4. [Web interface](docs/web-interface.md): find each portal control and learn who can use it.
5. [Policy](docs/policy.md): set release delays, vulnerability checks, blocks, and exceptions.
6. [Configuration](docs/configuration.md): find each settings file and know when to restart.

For exact settings and limits, use the [operations reference](docs/operations.md). The [management server reference](docs/management-server.md), [portal guide](docs/portal-guide.md), and [API and command reference](docs/api.md) give full details. [End-to-end tests](tests/e2e/README.md) explain the release test setup.

## Build and test from source

Use the Rust version in `rust-toolchain.toml`. The build also needs `cmake`, a C compiler, and `perl`.

```sh
cargo build --workspace --locked
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The managed tests need PostgreSQL. The browser and package-client tests also need a container engine and Node; see [end-to-end tests](tests/e2e/README.md) for setup.

## License

Releases after 0.2.2 use the [Elastic License 2.0](LICENSE). Releases 0.1.0 through 0.2.2 remain under Apache 2.0.
