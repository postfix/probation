# Slice 6 evidence — org admins, group admins and users manage members, groups, invitations, keys, policy, activity, audit, ranges and org deletion in the portal

Started 2026-10-22 at the user's request, in worktree ../probation-slice6 (branch `management-server-slice6`), from `management-server-slice5` at c5714ff: slice 5 complete but pre-review. Slices 3–5 review fixes and C126 are merged in later.

## Decisions and deviations
| ID | Status | Item | Decision |
|---|---|---|---|
| S6-1 | carried from slice 4 verification | `Actor` is a public enum with public fields; `Tenancy::actor` sets `global_admin` ignoring the SSO `scope_org_id`; `CheckedEdit`'s place is not bound to an `Authorized<Place>`. Close these with the portal routes (T-sso-session-scope, T-cross-tenant-routes-places). | Assigned to slice 6. |
| S6-2 | decided | Purging logins hits foreign keys. | invitations.created_by/accepted_by: ON DELETE CASCADE; leave_requests.approved_by: SET NULL; org_ip_ranges.approved_by: FK dropped and kept as a historical login id. SET NULL there would un-approve ranges, because "approved" means approved_by IS NOT NULL in sync.rs network_lock and in the exclusion constraint, so it would fail open. Test: purging the approver keeps the range approved and locked. |
| S6-3 | decided | The place switcher posted labels: inner whitespace collapses in the browser, so an organisation could be unreachable or the wrong one of the user's own organisations selected. | Options carry `value="personal"`/`"org:<id>"`, resolved through authorized_place; organisation names have inner whitespace collapsed at creation and in the uniqueness check. |

| S6-4 | decision | C39 loophole: an org admin demotes another admin, resets their TOTP, then promotes them back. | An org admin may not reset the authenticator of a login that held org_admin in that org within the last 30 days (a global admin still may). Reset and role changes lock the org row. |

## Review (2026-10-22)
Confirmed and sent to slice 6: the admin TOTP gate for every admin action (F1/S6-SEC-1/ADV-3); the C128 removal recorded by SSO identity (ADV-1); deterministic race tests for last-admin and invitation accept (F2/F3); the SSO secret on issuer change (SEC-2); purge vs restore (ADV-2); the C39 demote/reset loophole (SEC-3, see S6-4); switcher tests posting real values (ADV-4).

### Backlog (minor or refuted)
| Finding | Where | Title |
|---|---|---|
| code-review F4 | crates/probation-server/migrations/0004_removals_and_erasure.sql:6 | C128 removal is forgotten when the purge erases a removed member's login, so SSO adds the person back |
| code-review F5 | crates/probation-server/tests/portal_places.rs:3621 | T-cross-tenant-routes-places switcher probes post labels, which no longer match any switcher value |
| code-review S1 | crates/probation-server/tests/portal_places.rs:150 | Simplification (reuse): ~400 lines of test harness copied from tests/accounts.rs |
| code-review S2 | crates/probation-server/src/tenancy.rs:714 | Simplification (reuse): the 'runs the organisation' role check is repeated 8 times |
| code-review S3 | crates/probation-server/src/accounts.rs:716 | Simplification (shrink): `unconfirmed` repeats `unconfirmed_email`'s query |
| security S6-SEC-4 | crates/probation-server/src/tenancy.rs:898 | A removed or demoted org admin's pending invitations still grant their role, and accepting one clears the removal |
| adversarial S6-ADV-5 | crates/probation-server/src/portal/policy.rs:244 | An exception that still partly applies is labelled entirely 'not in effect' |
| adversarial S6-ADV-6 | crates/probation-server/src/portal/activity.rs:121 | A group admin's activity view follows current group membership, so a member's history moves with them between groups |
| S6-5 | backlog | tests/content_store.rs `an_open_during_eviction_is_refused_and_a_second_eviction_stands_aside` failed once in a loaded full run, then passed alone and in the full rerun. Firewall test, not slice 6. | Backlog: find the race by reading the code; no load loops. |
