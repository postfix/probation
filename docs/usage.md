# Usage

## Connect a package client

For a standalone firewall, replace `packages.example.org` with your firewall's HTTPS host:

```ini
# .npmrc
registry=https://packages.example.org/npm/
```

```ini
# pip.conf
[global]
index-url = https://packages.example.org/pypi/simple/
```

In managed mode, sign in, choose your personal account or organisation, and open **API keys**. Create a key and copy the npm or pip settings shown there. The key is displayed once. A managed firewall refuses requests without a valid key. Revoking a key stops it after the next firewall sync, normally within a minute.

For pnpm, Yarn, Bun, pipx, uv, and Poetry, use the settings in the [client reference](operations.md#clients). A client may reuse packages already in its own cache without contacting Probation.

## Set rules

See [Policy](policy.md) for the rules, who can change them, and how to check the result.

- **Standalone:** Edit the file named by `blocklist_file`. The firewall reloads it. Run `probation check-blocklist /etc/probation/blocklist.json` before replacing a live file.
- **Managed:** Open **Policy** for the selected account, organisation, or group. Set the release-age delay, OSV check, blocks, and exceptions. Higher-level rules can restrict lower levels. Open **Activity** to see held, blocked, and refused requests.

An administrator can update a layer's blocks from automation. Create a token in the portal and use the [automation API](api.md#1-the-automation-api-blocklists-from-ci).

## Use a selected npm or PyPI registry

An organisation administrator opens **Organisation → Package registries** and adds an npm or PyPI HTTPS target. The page also controls its read credential, whether to skip the age delay, approved npm deletion destinations, and requests to allow private destinations. The registry's own permissions still govern writes.

For an organisation using Probation-issued client certificates, members open **Package client setup** and download their personal setup bundle. Run its script on the intended machine to write user-local certificate and client settings for the selected registry. Keep its private key and any publishing token private. When the organisation uses its own certificate issuer, follow its administrator's certificate setup instead.

Selected clients use `/registry/npm/<id>/` or `/registry/pypi/<id>/simple/`, with the ID and host supplied by the setup. Legacy `/npm/` and `/pypi/simple/` paths continue to serve ordinary downloads. For publishing, use the selected URL and credentials authorized by the upstream registry. A denied upstream write stays denied. An npm registry without a bulk audit endpoint returns that upstream error to npm; Probation cannot make the registry support it.

## Manage people and firewalls

Use [Web interface](web-interface.md) to find each portal page and [Configuration](configuration.md) to see which settings live in files or the portal.

**Account settings** handles sign-in methods, passwords, and the authenticator app. **Organisation** handles members, invitations, groups, and service keys. **Global admin** handles platform rules and approvals. **Fleet** registers firewalls, shows status, and sends settings. The [portal guide](portal-guide.md) gives each role's full controls.

Policy edits and key revocations reach managed firewalls at their next sync. A firewall can keep serving cached rules during a short server outage; see the [operations reference](operations.md#13-managed-mode) for the limits.
