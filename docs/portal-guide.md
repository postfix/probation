# Portal guide

The portal is the web site of the Probation management server. People use it to sign
up, create API keys for npm and pip, set policy, and run their organisation. The
service operator uses it to run the platform and the firewalls.

The portal lives at the address in `[portal] base_url` of the server's settings file.
Installing and starting the server is in [management-server.md](management-server.md).

This guide is ordered by role:

1. [Every user](#1-every-user): sign-up, sign-in, authenticator, password, sign-in
   methods, places, deleting and restoring.
2. [Members](#2-members): API keys, your own policy, activity.
3. [Org admins and group admins](#3-org-admins-and-group-admins).
4. [Global admins](#4-global-admins) (the service operator).

## Words used here

| Word | Meaning |
| --- | --- |
| Login | One person's identity in the portal. It has one or more sign-in methods. |
| Sign-in method | Email and password, Google, GitHub, Microsoft, or one organisation's company SSO. |
| Place | Where you work: your personal account or one of your organisations. The **Place** switcher at the top of every page chooses it. |
| Layer | One level of policy: Platform, organisation, group, and a user's own layer (or a personal account). Each layer inherits everything above it. |
| Key | An API key. npm or pip sends it to a firewall. Every download made with it gets the policy of the place it belongs to. |

| Role | What it can do |
| --- | --- |
| Member | Own keys, own policy layer, own activity. |
| Group admin | Also: the group's policy, the group's service keys, the group's activity and audit log. |
| Org admin | Everything in the organisation: members, groups, invitations, policy, SSO, network lock, automation tokens, audit log, deletion. |
| Global admin | The service operator: every organisation, personal accounts, platform policy, limits, retention, fleet. |

Org admins and global admins need a second factor. A session opened with Google,
GitHub, Microsoft or company SSO has one. A session opened with email and password has
one only when the login has an authenticator app. Without it the admin role is held
back, and admin pages send you to **Account settings** to turn the authenticator on.

The navigation bar shows **API keys** (`/keys`), **Policy** (`/policy`), **Activity**
(`/activity`), **Organisation** (`/org`), **Audit log** (`/audit`) and **Account**
(`/account`). A global admin also sees **Global admin** (`/admin`) and **Fleet**
(`/fleet`).

Changes to keys and policy reach every firewall within about 1 minute (one
`sync_interval_seconds`, 60 by default).

---

## 1. Every user

### 1.1 Create an account

Open `/signup` (**Create an account** on the sign-in page). There are two ways:

- **Sign up with Google**, **GitHub** or **Microsoft**. Only the providers the operator
  configured are shown. This creates a login with no place. Then go to **Account
  settings** and add a personal account or create an organisation (§1.7).
- **Email and password.** Enter your email and a password of at least 12 characters.
  Passwords known from data leaks are refused. Then choose **What do you want to set
  up?**:
  - **A free personal account**: just for you, with your own rules on top of the
    platform rules.
  - **A new organisation**: for a company or team. Enter the **Organisation name** (at
    most 100 characters; names are unique, ignoring case and extra spaces). You become its
    org admin.

  Press **Create account**. The page says **Check your email**.

Do not sign up a second time to add another way of signing in: that makes a separate
login. Sign in and link the new method instead (§1.6).

To join an organisation that already exists, ask one of its org admins for an
invitation (§1.8), or use company SSO if the organisation has connected it.

### 1.2 Confirm your email

The email has a link to `/verify-email`. It works once and expires in 24 hours. Opening
it confirms the address; then press **Continue**.

Until the address is confirmed, a signed-in login reaches only the **Confirm your
email** page; nothing else works. On that page, **Send the link again** sends a new
link.

The page always looks the same, so it does not tell anyone whether an address has a
login. If the address already has an email-and-password login, you get an email that
says so, and no new login is made. At most 5 emails go to one address in 15 minutes, and
one client address may make at most 20 email-sending requests in 15 minutes; over that,
nothing is sent.

Google, GitHub, Microsoft and company SSO sign-ins need no confirmation.

### 1.3 Sign in

Open `/signin`. You can:

- **Continue with Google**, **Continue with GitHub** or **Continue with Microsoft**.
- **Sign in with company SSO**: type the **Organisation name** and press **Continue**.
  Your organisation can also give you its own link: `/o/<organisation name>`. An
  unknown name, or an organisation without SSO, shows the normal sign-in page. The
  first time you sign in this way you join the organisation as a member with no group
  (unless an org admin removed you, see §3.4).
- **Email and password**, then **Sign in**.

Each sign-in method you have not linked starts a **separate login**, even when its
email matches a login you already have. Logins are never merged by email.

A session opened through company SSO works only inside that organisation. The
switcher shows only that organisation, and you cannot change your login's settings
(sign-in methods, password, authenticator, personal account, new organisations). Sign
in another way to do that.

After 10 failed attempts for one email, or 100 from one client address, in 15 minutes,
the page says **Too many attempts. Wait 15 minutes and try again.**

A signed-in session lasts 12 hours. **Sign out** is at the top right.

### 1.4 Authenticator app and backup codes

The authenticator app adds a 6-digit code to email-and-password sign-ins. It is not
asked for Google, GitHub, Microsoft or SSO sign-ins.

To turn it on: **Account settings** → **Authenticator app** → **Turn on**.

1. Scan the QR code with an authenticator app, or type the key shown under it.
2. Save the **10 backup codes**. Each one works once. They are not shown again.
3. Enter the current code and press **Turn on**.

If the code is wrong, the page shows a new key and new backup codes; scan again. Turning
it on signs out your other sessions.

At sign-in you then get the **Authenticator code** page. Enter the code from the app, or
one of your backup codes. Each code works once. After 5 wrong codes in 15 minutes, wait
15 minutes.

**Turn off** is in the same section. Org admins and global admins cannot turn it off.

Lost the app and all backup codes? If your login belongs to one organisation only (no
personal account, no other organisation) and you are not its org admin, an org admin of
that organisation can reset it (§3.2). Everyone else asks the service operator (§4.1,
§4.3).
A reset removes the authenticator and its backup codes and signs the login out
everywhere.

### 1.5 Password

**Forgot your password?** on the sign-in page opens `/reset`. Enter your email and press
**Send reset link**. The answer is the same for any address. The link works once and
expires in 60 minutes; a newer link cancels older ones. Choose the new password (at
least 12 characters, not known from data leaks) and sign in. A reset signs the login
out everywhere. It does not remove the authenticator: you still enter its code.

To change a password you know: **Account settings** → **Password**. Enter the current
password and the new one twice, then **Change password**. Your other sessions end.

### 1.6 Sign-in methods

**Account settings** → **Sign-in methods** lists the methods of your login: the method,
the email it uses and when it was linked.

To add one, you must be signed in:

- **Link Google**, **Link GitHub** or **Link Microsoft**.
- **Link company SSO**: type the organisation name and press the button. Linking an
  organisation's SSO also makes you a member of it (unless an org admin removed you).

A method that already belongs to another login cannot be linked. Sign in with it and
remove it there first.

**Remove** takes a method off. You can remove a method only while another one stays.
Removing one signs out your other sessions. To remove the last one, delete the login
(§1.10).

### 1.7 Places

The **Place** switcher at the top lists your personal account and your organisations.
Choose one and press **Switch**. API keys, Policy, Activity, Organisation and Audit log
all work on the chosen place.

In **Account settings** → **Your places**:

- **Create an organisation**: enter a name and press **Create organisation**. You become
  its org admin.
- **Add a personal account**: if you do not have one. A login has at most one personal
  account.

### 1.8 Join an organisation with an invitation

An org admin sends you an email with a link to `/invite`. Sign in (or create a login)
first, then open the link. The page says what it grants, for example "Join Acme as a
member in the &lt;group&gt; group". Press **Accept**.

- The link works once, for 7 days, for whichever login accepts it. Make sure you are
  signed in with the right login.
- Your email must be confirmed first.
- The link stops working if the org admin who sent it is no longer an org admin there.
- If an org admin removed you, only an invitation sent **after** the removal lets you
  back in.

### 1.9 Leave an organisation

Members cannot leave on their own. On the **Organisation** page, press **Ask to leave
&lt;organisation&gt;**. You stay a member until an org admin approves. While it waits you
can press **Cancel my request**. When it is approved, your keys in that organisation
stop working within about 1 minute.

### 1.10 Delete and restore

**Delete your personal account** (in **Account settings**, type `delete` to confirm):

- Its keys stop working within about 1 minute.
- Everything else is erased after 30 days. Until then, **Restore personal account** in
  **Account settings** brings it back, and its keys work again within about 1 minute.
- If your login belongs to no organisation, the login is deleted with it. You are
  signed out. The last global admin cannot do this.

**Delete your login** is offered only when the login has no personal account and
belongs to no organisation. Type `delete` to confirm. All its sign-in methods stop
opening it. The last global admin cannot delete their login.

**Restore a deleted login.** Within 30 days, sign in with any of its old methods. If the
login has an authenticator and you use the password, you enter the code first. The page
**This login was deleted on …** offers:

- **Restore login**: brings back the login and any personal account deleted with it.
- **Start a new login instead**: erases the old login, and any personal account deleted
  with it, for good, now. You continue with a new login that has only the method you
  just used.

Until the old login is restored or erased, its email address cannot be used for a new
email-and-password sign-up. After 30 days it is erased and the address is free.

The audit log keeps its entries for their normal retention in all these cases.

---

## 2. Members

### 2.1 API keys

Open **API keys** (`/keys`). Every key belongs to the place chosen at the top, and that
decides the rules for every download made with it. In an organisation, your key gets
your group's policy (or the organisation's, with no group) and your own layer.

1. Enter a **New key name** (at most 100 characters) and press **Create key**.
2. Copy the key now. It is not shown again.
3. Copy the setup lines the page shows.

For npm, add to `.npmrc`:

```ini
registry=https://<firewall>/npm/
//<firewall>/npm/:_authToken=<key>
```

For pip, add to `pip.conf`:

```ini
[global]
index-url = https://key:<key>@<firewall>/pypi/simple/
```

uv and Poetry use the same index URL. The page fills in the firewall address from
`[portal] firewall_url`. When the operator has not set it, the lines show `FIREWALL`;
replace it with your firewall's address.

The list **Your keys in &lt;place&gt;** shows each key's name, its last four characters
and when it was created. **Revoke** stops a key within about 1 minute and cannot be
undone. Keys do not expire. A key also stops when its owner leaves or is removed from
the organisation, or when the place is deleted. While the place is suspended, its keys
are refused.

There is a limit on keys per person (§4.6). Over it, the page says how many you have
and asks you to revoke one or to ask the service operator to raise the limit.

### 2.2 Your own policy

**Policy** (`/policy`) opens your own layer: **Your own policy in &lt;organisation&gt;**,
or **Your personal account**. You can make your own rules stricter than the ones above.
The editor is described in §3.8.

### 2.3 Activity

**Activity** (`/activity`) lists downloads that Probation stopped, newest first, times
in UTC, at most 500 rows:

| Result | Meaning |
| --- | --- |
| Blocked | A rule refused it. |
| Held until … | The version is too new and waits out the freeze. |
| Would have blocked (log only) | OSV reports it as malicious, but the OSV check is set to Log only, so it was let through. |
| Refused: the key was revoked | |
| Refused: the account is suspended | |
| Refused by a network lock (used from …) | Another organisation's network lock refused the key from that address (§3.10). |

Each row names the key, the package and version, the rule and the layer that set it.
Allowed downloads are not listed. Requests made without a key are not shown.

What you see depends on your role: a member sees their own keys, a group admin sees the
group's members and service keys, an org admin sees the whole organisation. Rows are
kept for the number of days the operator sets (90 by default).

---

## 3. Org admins and group admins

Everything in this part needs the org admin role, unless it says group admin. Org
admins need a second factor (see "Words used here").

An organisation can have several org admins and always keeps at least one. The portal
refuses to remove or demote the last one.

If the service operator suspends the organisation, a banner says so. Everyone can still
sign in and look, but nothing can be changed, and its keys are refused until it is
re-activated.

### 3.1 The Organisation page

**Organisation** (`/org`) opens `/org/<id>` for the organisation chosen at the top. Org
admins get the full page. Other members see only the leave request section (§1.9).

### 3.2 Members

The **Members** table lists each member's email, role and group. "joined through
company SSO" marks people who came in through SSO.

- **Change role**: Org admin, Group admin or Member. A group admin runs the group they
  are in, so put the person in a group first. Stopping someone being an org admin also
  withdraws the invitations they sent and revokes their automation tokens.
- **Move**: choose a group or **No group**. A person is in at most one group. "No group"
  means they get the organisation policy directly. Moving a group admin to another
  group, or to **No group**, makes them a member.
- **Remove**: ends the membership. Their keys in the organisation stop within about
  1 minute, their own layer is deleted, and their automation tokens are revoked. See
  §3.4 for coming back.
- **Reset authenticator**: only for a member whose login belongs to this organisation
  alone (no personal account, no other organisation) and who is not an org admin (and
  was not one here in the last 30 days). For everyone else the row says
  "Authenticator: ask the service operator".

### 3.3 Invitations

Under **Invite someone**, enter the **Email address**, the **Role** and the **Group**,
then press **Send invitation**. A new group admin needs a group.

The email address is only where the link goes: whoever signs in and opens the link
accepts it. The link works once, for 7 days. **Invitations waiting to be accepted**
lists open links with **Cancel invitation**.

### 3.4 Removal and SSO

When you **Remove** a member, the organisation's company SSO does not add them back,
neither the same login nor a new login with the same SSO identity. Only an invitation
sent after the removal lets them in again; accepting it lifts the removal. An approved
leave request (§3.6) does not block SSO.

When you turn SSO off, people who joined through it stay members. They can sign in by
setting a password from a reset email (§1.5). If their address already has a password
on another login, invite that other login instead.

### 3.5 Groups

- **Create group**: enter a name (at most 100 characters).
- **Rename**: enter the new name in the group's row.
- **Policy**: opens the group's layer in the policy editor.
- **Delete**: a confirmation page lists what happens. The group's policy is deleted,
  its members go to **No group** and get the organisation policy, and its service keys
  are revoked (anything using them stops within about 1 minute). Press **Delete
  group**.

Only org admins move people between groups.

### 3.6 Leave requests

**Leave requests** lists members who asked to leave. **Approve** ends the membership,
and their keys in the organisation stop within about 1 minute. **Refuse** keeps them as
members.

### 3.7 Company SSO (OIDC)

Connect Microsoft Entra ID, Google Workspace, Okta or another OIDC provider. Anyone who
signs in through it joins the organisation as a member with no group.

1. In your provider, register an app with the redirect address the page shows (it ends
   in `/sso/<id>/callback`).
2. Tick **Company SSO is on**.
3. Fill in **Issuer URL** (https), **Client ID** and **Client secret**.
4. For a shared issuer (`https://accounts.google.com` or
   `https://login.microsoftonline.com/common…`), fill in **Required tenant**: the
   Google Workspace domain or the Microsoft tenant id.
5. Press **Save**.

The client secret is stored encrypted and never shown again. Leave it empty to keep it,
as long as the issuer and client ID stay the same. Two organisations cannot use the same
issuer and client ID.

Tell your people to sign in at `/o/<organisation name>`, or with **Sign in with company
SSO** on the sign-in page.

### 3.8 Policy

**Policy** (`/policy`) opens the organisation layer for an org admin and the group
layer for a group admin. The **Layers** line links the layers you may open: the
organisation, its groups (all of them for an org admin) and your own layer. **Chain**
shows the layers from the platform down to this one.

Each layer inherits everything above it. You can always make things stricter. You can
make them looser only where the layer above allows it. Who may change which layer:

| Layer | Who changes it |
| --- | --- |
| Platform | Global admins |
| Organisation | Org admins |
| Group | Org admins, and the group's group admins |
| A member's own layer | That member, and org admins |
| Personal account | Its owner |

Everyone else sees the layer read-only.

**Freeze.** **Hold new versions for** a number of **hours** or **days**, from 0 hours
to 365 days. It holds versions newer than that for npm and PyPI. Empty inherits the
layer above. A shorter freeze than the one above needs **Allow a shorter freeze** from
the layer above.

**OSV malicious-package check.** **Inherit from the layer above**, **On: block them**,
**Log only** (let them through and record them in Activity as "would have blocked"), or
**Off: do not check**. Log only and Off need **Allow turning OSV off** from the layer
above.

**What the layer below may loosen** (platform, organisation and group layers only):
**Allow package exceptions**, **Allow turning OSV off**, **Allow a shorter freeze**. You
can pass down only a switch the layer above gives you; otherwise it is greyed out.

Press **Save changes**.

**Blocks.** The table shows the blocks of this layer and the layers above (**Set by**).
Only this layer's blocks have **Remove**. To add one, choose the **Ecosystem** (npm or
PyPI), enter the **Package name**, and choose **What**:

- **Whole package**;
- **One version**: also fill in **Version**;
- **One exact file**: choose sha256 or sha512 and enter the **Digest (hex)**. A file is
  named by its digest alone.

Press **Add block**.

**Exceptions.** An exception lets one package, or one exact version, through checks
that would stop it. Leave **Exact version** empty for the whole package, future
versions included. Tick what it lets through: **Blocklist**, **Freeze**, **OSV**. An
exception to a rule set higher up needs every layer between the rule's owner and this
one to allow it: **Allow package exceptions** for the blocklist, **Allow a shorter
freeze** for the freeze, **Allow turning OSV off** for OSV.

**"Not in effect".** When a layer above turns a switch off after you saved a looser
value, your value stays stored but the page marks it "not in effect while a stricter
rule above applies". It applies again when the switch goes back on. It also applies for
a package where an exception lifts the stricter rule above.

If someone else saved the layer while you were editing, the page says **Not saved** and
shows the layer as it is now. Make your change again.

### 3.9 Service keys

The **API keys** page has a **Service keys** section for org admins and group admins. A
service key belongs to the organisation, not to a person, so it keeps working when
people leave. Use it on company devices (push it with your device management tool).

Enter a **Name**, choose **Attach to** (the organisation itself or a group) and press
**Create service key**. Downloads made with it get the policy of what it is attached to.
Org admins can attach to any group; group admins only to their own group, and they can
revoke any service key attached to it.

### 3.10 Network lock (IP ranges)

From the addresses in the network lock, Probation refuses every key that does not
belong to your organisation, for example a personal account key or another
organisation's key.

Enter an **IP range** such as `192.0.2.0/24` and press **Add range**. A range does
nothing until the service operator approves it. Its status is **Waiting for operator
approval**, **Approved**, or **Refused by operator: &lt;reason&gt;**. A refused range has
**Resubmit**. **Remove** deletes a range.

The network lock is a second line of defence. Phone networks and some whole countries
put many unrelated people behind one address, so an address cannot identify your
company on its own.

### 3.11 Automation tokens and the blocklist file

An automation token lets an existing blocklist tool change the blocks of one layer, and
nothing else. Enter a **Token name**, choose the **Layer** (the organisation or one
group) and press **Create token**. Copy the token now; it is not shown again. **Revoke**
ends it. A token also stops when the org admin who created it leaves or stops being an
org admin.

The tool sends `Authorization: Bearer <token>` to `/api/v1/blocklist/<layer>`, where
`<layer>` is `org-<id>` or `group-<id>`, at the server's address:

| Method | Does |
| --- | --- |
| `GET` | Exports the layer's blocks. |
| `PUT` | Replaces the layer's blocks. |
| `POST` | Adds blocks. |

The body is a blocklist file in the firewall's format, at most 1 MiB; a larger body
gets `413`. Every push is in the audit log. Status codes, limits and examples are in
[api.md](api.md#1-the-automation-api-blocklists-from-ci) §1.

Under **Blocklist file**, **Export &lt;organisation&gt;'s blocks** downloads the
organisation layer's blocks. To import, paste a file into **Blocklist file to import**
and press **Import**: its blocks are added to the organisation layer, with the same
checks as any edit.

### 3.12 Audit log

**Audit log** (`/audit`) lists every change an admin can make: policies, keys,
membership, roles, company SSO, network lock, deletion and restore, firewall settings,
and every operator action. Each row has when, who, the kind, what changed, and the value before and after.
"(operator)" marks a change a global admin made. Key secrets never appear, only key
names. At most 500 rows, newest first, times in UTC.

An org admin sees the whole organisation; a group admin sees their group; a personal
account owner sees their personal account. Entries are kept for the number of days the
operator sets (365 by default).

### 3.13 Limits

The operator sets, per organisation, the most requests per minute, keys per member and
service keys (§4.6). Requests over the rate are refused with a "too many requests"
error. When a key limit is reached, new keys are refused; existing keys keep working.

### 3.14 Delete and restore the organisation

At the bottom of the page, **Delete &lt;organisation&gt;**: type the organisation's
name and press **Delete organisation**.

- All its keys, service keys included, stop within about 1 minute.
- Everything else is erased after 30 days.
- Until then any of its org admins can restore it: open **Organisation**; the page
  lists the deleted organisation with **Restore &lt;organisation&gt;**. Its keys work
  again within about 1 minute.

The audit log is kept for its normal retention.

---

## 4. Global admins

Global admins are the service operators. The first one is created with
`probation-server admin bootstrap` ([management-server.md](management-server.md#5-first-run) §5).
More are added by invitation (§4.4).

A global admin needs a second factor. With email and password, set up the
authenticator first; until then `/admin` and `/fleet` send you to **Account settings**.

Every change a global admin makes is in the audit log, marked "(operator)" in the
organisation's own log. A global admin's **Audit log** shows every organisation, every
personal account and the platform, with a **Where** column.

### 4.1 Organisations

**Global admin** (`/admin`) → **Organisations** lists every organisation with its
status (**Active**, **Suspended**, or **Deleted, erased on …**), members and keys.

- **Open as org admin** opens `/org/<id>` with everything an org admin can do there.
  Note: on that page the **Reset authenticator** button shows only for members whose
  login belongs to that organisation alone and who are not org admins, as for an org
  admin. For an org admin, or a login in several places, there is no button yet; the
  server accepts the reset from a global admin, but the page does not offer it.
- **Suspend** shows a confirmation page, then refuses all of the organisation's keys
  within about 1 minute. Members can still sign in, read-only, with a banner.
- **Re-activate** ends the suspension.

An organisation is active as soon as it signs up.

### 4.2 Platform policy

The platform layer is inherited by every organisation and personal account. Edit it in
the policy editor at `/policy/platform-1` (linked from the top of `/admin`). The editor
works as in §3.8. Another organisation's layer is at `/policy/org-<id>`.

### 4.3 Personal accounts

**Personal accounts** lists each one with its email, status, keys and creation date.

- **Suspend** / **Make active**.
- **Revoke keys**: a confirmation page, then all its keys stop within about 1 minute.
  This cannot be undone.
- **Reset authenticator**: resets the authenticator of the account's login.
- **Delete**: a confirmation page. Its keys stop within about 1 minute; the rest is
  erased after 30 days.
- **Restore**: for a deleted account, within its 30 days.

### 4.4 Global admins

**Global admins** lists them with **Remove**. To add one, enter the **Email address**
and press **Invite global admin**. The link works once, for 7 days, for whoever signs in
and opens it. The new global admin sets up an authenticator before using admin
features. The last global admin cannot be removed.

### 4.5 Network lock ranges

**Network lock ranges** lists ranges waiting for approval, then approved ones.

- **Approve**: the range starts working. You cannot approve a range that overlaps an
  approved range.
- **Refuse**: enter the **Reason** the org admins will see.
- **Remove** (approved ranges): firewalls drop it within about 1 minute.

Before approving, check that the range really is that organisation's office or VPN.
From an approved range, every key that is not the organisation's own is refused.

### 4.6 Limits

**Limits per kind of account** has the defaults:

| Kind | Fields | Default |
| --- | --- | --- |
| Personal accounts | Most requests per minute, per account; most keys | 1200; 5 |
| Organisations | Most requests per minute, per organisation; most keys, per member; most service keys (blank = no limit) | 6000; 20; 50 |

**Set an organisation's own limits** gives one organisation its own values. **Back to
default for &lt;organisation&gt;** removes them.

Each firewall counts requests on its own. Lowering a key limit stops no existing key;
the account just cannot create new ones until it is under the limit.

### 4.7 Retention

**How long history is kept**: **Blocked and held downloads (Activity), in days**
(default 90) and **Audit log, in days** (default 365). Each from 7 to 36500 days. Older
history is deleted once an hour.

### 4.8 Platform automation tokens and blocklist file

Works like §3.11, for the platform layer (`/api/v1/blocklist/platform-1`): **Create
platform token**, **Revoke**, **Export the platform's blocks**, and **Import** (adds the
file's blocks to the platform policy).

### 4.9 Fleet

**Fleet** (`/fleet`) lists the firewalls every organisation and personal account
downloads through.

**Register a firewall.** Enter a **Name** and the **Address ranges its token is
accepted from** (for example `203.0.113.10/32`; separate several with spaces). Press
**Register firewall** and copy the token now; it is not shown again. Write it to the
file named by `token_file` in the `[management]` section of that firewall's
`config.toml`. Its last check-in reads "never" until it starts with the token.

**Health.** The table shows each firewall's version, last check-in and health:

| Health | Meaning |
| --- | --- |
| Healthy | |
| Waiting for its first check-in | |
| Unhealthy: missed 3 check-ins | No check-in for 3 sync periods. |
| Unhealthy: cannot reach … | It reports it cannot reach npm, PyPI or OSV. |
| Retired | |

"Last error" shows the last error a firewall reported, for example settings it could
not apply.

**Push settings (staggered rollout).** Tick the firewalls, write settings as lines of
the firewall's `config.toml` (for example `sync_interval_seconds = 60`) and press
**Save and apply**. These stay on each firewall and cannot be pushed: `listen`,
`data_dir`, `[management]`, `tls_cert_path`, `tls_key_path`, `public_url`, `siem_url`,
`siem_auth_header`. The upstream URLs (`npm_upstream_url`, `pypi_upstream_url`,
`pypi_artifacts_url`) must be `https://`.

The firewalls get the settings one at a time: the next one gets them after the one
before reports success. Each firewall restarts to apply them, so it needs a restart
policy ([management-server.md](management-server.md#6-settings-pushes-need-a-restart-policy)
§6). A firewall still in a rollout cannot get a new one until that rollout is finished,
skipped or resumed.

**Settings changes** shows the latest rollouts: **Applying**, **Done** or **Halted**,
with each firewall's step:

- **Applied by …**, **Waiting for … to pick them up**, or "gets them after the one
  before reports success".
- **… could not apply the new settings**: it keeps running on its old settings and
  shows what it reported. The rollout halts. The firewall will not try these settings
  again, so press **Skip it and go on**, then push corrected settings to it.
- **… did not report success within 3 check-ins**: the rollout halts. Press **Resume:
  send them to it again**, or **Skip it and go on**.

**Retire.** Type the firewall's name and press **Retire &lt;name&gt;**. Its token stops
working: at its next check-in it stops serving every request. This cannot be undone; to
bring it back, register it again.
