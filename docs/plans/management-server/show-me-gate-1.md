## What problem do we have?
Probation today is a firewall you run yourself, set by one config file and one blocklist. Everyone behind a firewall gets the same policy, nobody signs in, and every change means editing files on each server. This breaks when many companies or teams need different rules, when a developer needs an exception today, when an operator must keep several firewalls in step by hand, and when a person wants protection without running a server.

## How will we solve it?
A central management server and self-service portal. People sign in, get an API key, and manage their own policy inside the limits set above them. One shared firewall fleet serves everyone.

**Who is who**
- **Global admin** (the service operator; several allowed, at least one, C90): manages every organisation, personal account, the platform policy and the fleet (C4). Inside an organisation can do everything an org admin can, and every such change shows in that organisation's audit log (C79).
- **Organisation**: sealed; no organisation can see that another exists (C1). It has several org admins, group admins and members.
- **Personal account**: one person, no organisation, free, only its owner's own policy (C6).
- **Login**: one person's set of linked sign-in methods. A method joins a login only when linked while signed in; matching emails never merge logins (C75). One login can have a personal account and belong to several organisations (C29).
- **Keys**: user keys (several, named, revocable, owner's policy) and **service keys**, owned by the organisation and attached to a group or the organisation, which survive staff changes and can be pushed by MDM such as Intune (C14, C15). Each key belongs to exactly one place, and that fixes its policy (C29).

**Policy layers**
```
platform -> organisation -> group -> user
platform -> personal account
```
- Stricter is always allowed: more blocks, longer freeze, OSV on. Looser applies only where the layer above allows it; otherwise it is refused (C8, C9).
- Each layer has three switches for the layer directly below: allow package exceptions, allow OSV off, allow a shorter freeze (C11).
- An exception lifts a block, a freeze hold or an OSV flag for one package; each lift needs its matching switch (C16). Blocks name a whole package, one version or one exact file; exceptions name one exact version or a whole package, including future versions (C17). A whole-package exception may also lift OSV when OSV off is allowed (C18).
- OSV has three values: on (block), log only (allow and record as "would have blocked"), off. Log only and off both count as loosening (C81).

**Firewalls**
- One shared fleet serves every organisation; the key matches each request to its user and organisation (C3).
- Managed mode is opt-in. A firewall with no management server works exactly as today (C12).
- A managed firewall refuses a request with no valid key with an authentication error (C13).
- If the management server is down, firewalls keep serving from cache; new keys and policy changes wait (C19).
- A policy change or key revocation reaches every firewall within 1 minute by default, configurable (C20).
- The global admin registers, monitors and retires firewalls and edits their settings from the portal (C22).
- With key and policy cached, a request takes at most 1 ms longer than standalone, and throughput stays at least 90% of standalone, measured with the existing benchmarks (C83).

**Main journey**
- Sign up -> confirm email -> a new organisation with you as org admin (C5, C41)
- Create a key -> paste it into `.npmrc` or `pip.conf` -> `npm install` goes through the fleet under your policy
- Admin adds a block -> every firewall applies it within the sync interval

**Screens (9 mockups):** [sign-in](mockups/sign-in.html), [account](mockups/account.html), [policy](mockups/policy.html), [api-keys](mockups/api-keys.html), [activity](mockups/activity.html), [organisation](mockups/organisation.html), [audit-log](mockups/audit-log.html), [global-admin](mockups/global-admin.html), [fleet](mockups/fleet.html).

> **The screens changed after you approved them (C74).** Their wording was edited to show C75-C94 and to fix review findings F1-F5: role wording, the note when SSO is turned off and the address already has a password, an example IP address, and the restore wording on the delete dialogs (account.html, sign-in.html). Please look at them again.

**Not in this release:** billing (orgs are active at once, suspended by hand, C7, C78); SAML (OIDC only, C21); a user in more than one group (C10); separate freeze or OSV for npm and PyPI (C31); stopping off-network bypass without an MDM-locked config (C30); showing allowed requests (C23); any change to standalone firewalls (C12); stopping a hijacked release under a whole-package OSV exception (C18); leaving an organisation without org admin approval (C85); timing real customers (C82); the local blocklist file in managed mode (C80); the network lock identifying a company on its own (C77).

## How will we confirm it is solved?
| Scenario | Expected result | Check |
|---|---|---|
| 1. Script signs up a new organisation, creates a key, runs `npm install` through the fleet | Whole run under 10 minutes, no operator help | Automated end-to-end test before every release (C32, C82). Planned |
| 2. A block or key revocation is saved | Every managed firewall applies it within the sync interval (default 1 minute) in 99% of cases | Time from save to the last firewall applying it, per change (C32, C20). Planned |

Both checks are planned; nothing has run yet. Speed limits (C83) and WCAG 2.2 AA (C84) are also measurable targets.

Recommendation: Approve. QA is READY: 94 decisions, no open questions for you, success is measurable, and only four technical items move to Gate 2.
Limits: Accepted risks: a whole-package exception lifting OSV does not stop a hijacked release (C18); a key revoked while the management server is down works until it returns (C19); off-network use without an MDM lock is not prevented, and the network lock is secondary and needs global admin approval per IP range (C30, C77). Deferred to Gate 2: how a firewall identifies the user and gets the policy (C2), the firewall connection settings and exact `.npmrc` / `pip.conf` lines (C34), the full list of firewall settings and TLS handling (C35), the blocklist import/export format and push interface (C86). Optional wording note N1 in global-admin.html is not applied; applying it needs a new review. The mockups were read as text, not rendered.
Gate 1 in progress; QA READY verified with `router gate-qa verify --plan-root docs/plans/management-server --gate 1`.
Sources: [01-product.md](01-product.md) (C1-C94), [gate-1-qa.md](gate-1-qa.md), [mockups/](mockups/)
Approve Gate 1, or what should change?
