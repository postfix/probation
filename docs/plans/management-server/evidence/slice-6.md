# Slice 6 evidence — org admins, group admins and users manage members, groups, invitations, keys, policy, activity, audit, ranges and org deletion in the portal

Started 2026-10-22 at the user's request, in worktree ../probation-slice6 (branch `management-server-slice6`), from `management-server-slice5` at c5714ff: slice 5 complete but pre-review. Slices 3–5 review fixes and C126 are merged in later.

## Decisions and deviations
| ID | Status | Item | Decision |
|---|---|---|---|
| S6-1 | closed | `Actor` is a public enum with public fields; `Tenancy::actor` sets `global_admin` ignoring the SSO `scope_org_id`; `CheckedEdit`'s place is not bound to an `Authorized<Place>`. | A login's and a token's roles are in private structs only tenancy builds (`Actor::Operator` stays public for the CLI); an SSO session's memberships are limited to its organisation; an actor holds a role only on the place it was loaded for, so `authorize` refuses a `CheckedEdit` for another place. T-sso-session-scope, T-cross-tenant-routes-places. |
| S6-2 | decided | Purging logins hits foreign keys. | invitations.created_by/accepted_by: ON DELETE CASCADE; leave_requests.approved_by: SET NULL; org_ip_ranges.approved_by: FK dropped and kept as a historical login id. SET NULL there would un-approve ranges, because "approved" means approved_by IS NOT NULL in sync.rs network_lock and in the exclusion constraint, so it would fail open. Test: purging the approver keeps the range approved and locked. |
| S6-3 | decided | The place switcher posted labels: inner whitespace collapses in the browser, so an organisation could be unreachable or the wrong one of the user's own organisations selected. | Options carry `value="personal"`/`"org:<id>"`, resolved among the session's own places and through authorized_place; organisation names have inner whitespace collapsed at creation and in the uniqueness check. |
| S6-4 | decision | C39 loophole: an org admin demotes another admin, resets their TOTP, then promotes them back. | An org admin may not reset the authenticator of a login that held org_admin in that org within the last 30 days (a global admin still may): `former_org_admins`, written on demotion, removal and leave. Reset and role changes lock the org row. T-portal-totp-reset-scope (demote; remove and re-invite). |
| S6-6 | accepted | templates/base.html (outside the file list) gets the navigation links and the place switcher. | Accepted by the lead; tests/accounts.rs `switcher()` reads the option labels. |
| S6-7 | accepted | The portal test harness lives in tests/accounts.rs. | Copied into tests/portal_places.rs (backlog S1). |
| S6-8 | decided (C128, C130, AC3) | Who SSO adds back after a removal. | Only an org admin's removal blocks: `org_removals` (org, login) and `org_sso_removals` (org, issuer, subject, login), each with `removed_at`, erased with the removed login (purge, C93, C94); an approved leave writes none; every SSO sign-in of a live login joins unless blocked. Only an invitation created after the removal re-admits and clears them; an older one is refused for that login (S6-SEC-4 fixed). T-portal-sso-removed-not-rejoined. |
| S6-9 | accepted (C24) | The second factor for admin roles. | Global and org admin roles need it (an OAuth or SSO sign-in, or the login's authenticator); without it `Tenancy::actor` holds the role back and the portal sends the session to set-up, while activity and audit show a member's view. Group admins need none. Turning the authenticator on ends the login's other sessions. |
| S6-10 | open, slice 8 | The .npmrc and pip.conf lines need the firewall's public address; the portal has no setting for it. | A `FIREWALL` placeholder; slice 8's end-to-end test needs a real address. |
| S6-11 | accepted | Mockup states not built. | Activity and audit filters (both list the newest 500 rows), a separate confirmation before revoking a key; blocklist import and export are slice 7's. No organisation rename exists, so org-name normalisation applies at sign-up and "Create organisation". |

## Review (2026-10-22)
Confirmed and sent to slice 6: the admin TOTP gate for every admin action (F1/S6-SEC-1/ADV-3); the C128 removal recorded by SSO identity (ADV-1); deterministic race tests for last-admin and invitation accept (F2/F3); the SSO secret on issuer change (SEC-2); purge vs restore (ADV-2); the C39 demote/reset loophole (SEC-3, see S6-4); switcher tests posting real values (ADV-4).

### Backlog (minor or refuted)
| Finding | Where | Title |
|---|---|---|
| code-review F4 | crates/probation-server/migrations/0004_removals_and_erasure.sql:6 | C128 removal is forgotten when the purge erases a removed member's login, so SSO adds the person back — intended under C130 |
| code-review F5 | crates/probation-server/tests/portal_places.rs:3621 | T-cross-tenant-routes-places switcher probes post labels, which no longer match any switcher value — fixed (M5) |
| code-review S1 | crates/probation-server/tests/portal_places.rs:150 | Simplification (reuse): ~400 lines of test harness copied from tests/accounts.rs |
| code-review S2 | crates/probation-server/src/tenancy.rs:714 | Simplification (reuse): the 'runs the organisation' role check is repeated 8 times |
| code-review S3 | crates/probation-server/src/accounts.rs:716 | Simplification (shrink): `unconfirmed` repeats `unconfirmed_email`'s query |
| security S6-SEC-4 | crates/probation-server/src/tenancy.rs:898 | A removed or demoted org admin's pending invitations still grant their role, and accepting one clears the removal — fixed: an invitation stands only while its sender is a live org admin of the organisation (or a global admin), checked on accept under the organisation's lock; a demotion or removal withdraws the sender's open invitations; AC3 refuses links older than a removal (S6-8) |
| adversarial S6-ADV-5 | crates/probation-server/src/portal/policy.rs:244 | An exception that still partly applies is labelled entirely 'not in effect' |
| adversarial S6-ADV-6 | crates/probation-server/src/portal/activity.rs:121 | A group admin's activity view follows current group membership, so a member's history moves with them between groups |
| S6-5 | backlog | tests/content_store.rs `an_open_during_eviction_is_refused_and_a_second_eviction_stands_aside` failed once in a loaded full run, then passed alone and in the full rerun. Firewall test, not slice 6. | Backlog: find the race by reading the code; no load loops. |
