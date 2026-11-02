# Web interface

The web interface is available in a managed deployment when the server settings include `[portal]`. Open the address set by `[portal] base_url`. [Install](install.md#managed-deployment) explains how the operator starts it.

## First visit

1. Choose **Create an account**, or use a sign-in method your operator enabled.
2. Confirm your email if you signed up with a password.
3. Choose a personal account or organisation in the **Place** menu. The pages below act on that choice.
4. If you are an administrator signing in with a password, open **Account → Authenticator app** and finish setup before using admin pages.

## Find a control

| Page | What you can do |
| --- | --- |
| **API keys** | Create and revoke keys for ordinary npm and pip downloads. Copy a new key when shown; it appears only once. Org admins can also create service keys. |
| **Policy** | View the rules that apply to the selected place. Change the release delay, OSV check, blocks, and exceptions if your role permits it. |
| **Activity** | See held, blocked, and refused package requests. |
| **Organisation** | Manage members, invitations, groups, sign-in, service keys, network ranges, and the organisation's audit log. Org admins can open **Package registries** and **Enterprise certificates** here. |
| **Audit log** | See changes made in the selected place. |
| **Account** | Change your password, sign-in methods, authenticator, and personal account. |
| **Global admin** | Manage platform rules, organisations, approvals, limits, and retention. Visible only to service operators. |
| **Fleet** | Register firewalls, check their status, and send settings to them. Visible only to global admins. |

Members of an organisation that uses Probation-issued certificates can open **Package client setup** and download their personal setup bundle. Its script contains a private key. Run it only on the intended machine and keep it private. An organisation using its own certificate issuer follows its administrator's setup.

Open [Policy](policy.md) for the rule model and worked actions. Open [Configuration](configuration.md) for the files and server settings behind these pages. The [full portal reference](portal-guide.md) covers every role and control.
