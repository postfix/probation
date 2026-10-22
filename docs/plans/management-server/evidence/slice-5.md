# Slice 5 evidence — sign-up, verification, sign-in (password, OAuth, SSO), linking, TOTP, delete/restore in the portal

Started 2026-10-22 at the user's request ("start slice 5 in parallel too"), in worktree ../probation-slice5 (branch `management-server-slice5`), from `management-server-slice4` at d148f8a (slices 1–4, with the slice-4 review fixes; slice 3's review fixes are still pending). It is built in parallel with the slice 3/4 review fixes and merged after them.

## Decisions and deviations
| ID | Status | Item | Decision |
|---|---|---|---|
| S5-1 | process | The user asked to start slice 6 in parallel. Slice 6 edits slice 5's new files (accounts.rs, portal/mod.rs, axe.mjs, seed.sql) and signs in through slice 5's portal. | Slice 5 lands its portal foundation first (router, sessions, CSRF, base template, password sign-in, tests) and reports a CHECKPOINT. I commit it, and slice 6 branches from that commit. After that the foundation's API stays stable. |
