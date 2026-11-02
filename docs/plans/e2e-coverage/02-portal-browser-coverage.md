# Portal browser coverage (2026-10-30)

The older `00-inventory.md` counts cases from 2026-10-23, before the current browser scenarios. Its percentages are not a current measure of portal coverage. The checks below use Chromium against the deployed local Podman stack. The accessibility walk also runs axe and keyboard checks on 66 rendered states.

| Portal area | Browser behavior checked | Scenario |
| --- | --- | --- |
| Sign-up, email verification, sign-in, authenticator | Organisation and personal sign-up, mail link, TOTP and backup-code sign-in | E2E-017 |
| Invitations and place switching | New hire joins from a mailed invite, switches place, creates a key | E2E-018 |
| Password reset | Reset and account-takeover refusal flows | E2E-019 |
| OAuth and company SSO | Provider sign-in, linked identity, org membership | E2E-020 |
| Account | Settings opens; authenticator and password flows above; personal account add/delete/restore; personal-only login deletion and restoration | E2E-portal-areas-browser, E2E-portal-login-deletion-browser, E2E-017, E2E-019 |
| API keys | Create, show once, revoke | E2E-portal-areas-browser, E2E-017 |
| Policy | Save freeze value and unit, OSV block mode and a platform permission switch; add/remove a package block and exception | E2E-portal-areas-browser |
| Organisation and Users | Create, rename and delete a group; invite and cancel an invitation; change role and group, reset an org-only member's authenticator, disable package access and remove a member; select a member's certificates; request/cancel leaving; add, approve, refuse, resubmit and remove a network range | E2E-portal-areas-browser, E2E-portal-members-browser, E2E-018, E2E-020 |
| Activity and audit | Both signed-in views open; these pages have no filter controls | E2E-portal-areas-browser |
| Package registries | Navigate, add and remove a registry, save trust and read credential, approve and remove a deletion destination | E2E-publishing-portal-ui |
| Package client setup | Navigate and download the member setup bundle | E2E-publishing-portal-ui |
| Enterprise certificates | Save issuer trust, check a good sample, verify its committed revocation and activate | E2E-publishing-portal-ui |
| Private egress and global admin | Request and approve a private destination; approve/refuse a network range; save account limits and retention; suspend/reactivate an organisation | E2E-publishing-portal-ui, E2E-portal-members-browser, E2E-portal-areas-browser |
| Fleet | Register a firewall, show its token once, push settings, see rollout, skip a refused step, resume a timed-out step, retire it | E2E-portal-areas-browser, E2E-007 |
| Member certificates | Find an issued certificate and revoke it | E2E-publishing-portal-ui |

`E2E-A11Y-axe` covers sign-in and account states, keys, policy, activity, organisation, Users and groups, audit, global admin, fleet, registry, certificate, and setup pages. It checks accessibility and keyboard behavior, not every business result. Server-side portal and end-to-end API tests cover further form outcomes.

Verification on the final local deployed stack: the complete release suite passed 41 scenarios with 0 failures, including the 19-part selected-registry client matrix, two independent 10,000-member certificate scale runs, and the expanded portal browser controls. The accessibility walk passed 22 + 28 + 16 = 66 rendered states with no reported problems. The Rust workspace suite passed 762 tests (21 ignored), strict workspace Clippy passed, cargo packaging passed, and `git diff --check` passed. The release CI timeout is 180 minutes because the local scenarios alone took 114 minutes, before stack startup and CI setup.

Release preparation still needs a new version and tag: both Cargo packages remain at 0.2.2, which already has a `v0.2.2` tag, and the current feature changes are uncommitted. The restore drill also proves the documented operational requirement to run `after-restore`: omitting it can leave a revoked key usable on a firewall.

This is broad browser coverage, **not exhaustive per-control browser coverage**. The selected-registry client and certificate release matrix exercises deeper service behavior through HTTP and real package clients; it does not substitute for every possible combination of UI controls.
