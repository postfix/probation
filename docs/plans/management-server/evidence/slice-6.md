# Slice 6 evidence — org admins, group admins and users manage members, groups, invitations, keys, policy, activity, audit, ranges and org deletion in the portal

Started 2026-10-22 at the user's request, in worktree ../probation-slice6 (branch `management-server-slice6`), from `management-server-slice5` at c5714ff: slice 5 complete but pre-review. Slices 3–5 review fixes and C126 are merged in later.

## Decisions and deviations
| ID | Status | Item | Decision |
|---|---|---|---|
| S6-1 | carried from slice 4 verification | `Actor` is a public enum with public fields; `Tenancy::actor` sets `global_admin` ignoring the SSO `scope_org_id`; `CheckedEdit`'s place is not bound to an `Authorized<Place>`. Close these with the portal routes (T-sso-session-scope, T-cross-tenant-routes-places). | Assigned to slice 6. |
