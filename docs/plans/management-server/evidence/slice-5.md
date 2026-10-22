# Slice 5 evidence — sign-up, verification, sign-in (password, OAuth, SSO), linking, TOTP, delete/restore in the portal

Started 2026-10-22 at the user's request ("start slice 5 in parallel too"), in worktree ../probation-slice5 (branch `management-server-slice5`), from `management-server-slice4` at d148f8a (slices 1–4, with the slice-4 review fixes; slice 3's review fixes are still pending). It is built in parallel with the slice 3/4 review fixes and merged after them.

## Decisions and deviations
| ID | Status | Item | Decision |
|---|---|---|---|
| S5-1 | process | The user asked to start slice 6 in parallel. Slice 6 edits slice 5's new files (accounts.rs, portal/mod.rs, axe.mjs, seed.sql) and signs in through slice 5's portal. | Slice 5 lands its portal foundation first (router, sessions, CSRF, base template, password sign-in, tests) and reports a CHECKPOINT. I commit it, and slice 6 branches from that commit. After that the foundation's API stays stable. |
| S5-2 | decision C127 | A taken organisation name is refused at sign-up, which reveals that the organisation exists. | User: accept, like A3. |
| S5-3 | decision C128 | SSO join timing. | User: an SSO user joins at sign-in; a removed member is not re-added by SSO (current behaviour). |
| S5-4 | to slice 6 | T-portal-unverified-blocked holds only structurally: an unconfirmed login has no place. If slice 6 lets an unconfirmed login gain a place (for example by invitation), add a verification check in tenancy.rs. | Sent to slice 6. |
| S5-5 | for review | Deviations: OIDC through `jsonwebtoken` with hand-written discovery, PKCE, state, nonce and issuer checks, and GitHub OAuth by hand (not `openidconnect`); the portal's client-IP code copies `sync::source_address` (merge after slices land); PROBATION_SERVER_SESSION_KEY unused (sessions are random ids stored hashed); backup codes are HMAC-SHA256 under a key derived from SECRET_KEY, not Argon2; a sent mail's body is wiped; TOTP throttle is 5 failures per 15 min, and a throttled sign-in answers 429 identically for known and unknown emails; `GuardedClient::allowing_loopback_for_tests()` is hidden-public; axum `form`/`query` features added; purge runs one transaction per login, and erasing a global admin who owns slice 6/7 rows will fail (slices 6/7 decide); the place switcher does nothing until slice 6; the A11Y-keyboard checklist is in tdd-slice-5.md; tests/a11y/node_modules must not be committed (needs a .gitignore entry). | Reviewers judge. |

## Review (2026-10-22)
Confirmed and sent to slice 5: TOTP before the deleted-login choice (D1/F1/ADV-3); throttle races (D3/ADV-4); OIDC nonce/state/tid tests (D4); mail and sign-up rate limits (D5); SSO-scoped /account escape (F2); pending sessions surviving password changes (ADV-2). Already fixed on slice 6's branch: C128 rejoin (D2/ADV-1) and the purge foreign keys (ADV-5; check the fifth key at the merge).

### Backlog (minor or refuted)
| Finding | Where | Title |
|---|---|---|
| security F3 | crates/probation-server/src/portal/signin.rs:600 | Sign-in and TOTP throttles check then record in separate statements, so concurrent attempts get past the 10/100/5 limits |
| security F4 | crates/probation-server/src/portal/signin.rs:871 | OAuth callback does not bind the flow's organisation to the callback's IdP, and SSO/OAuth start is an unauthenticated GET (login CSRF via an attacker-controlled org IdP) |
| security F5 | crates/probation-server/src/accounts.rs:1799 | C128 (removed members not re-added by SSO) has no hook: every new-method path joins the org unconditionally; org-admin TOTP reset (C76/C39) promised for slice 5 is absent |
| adversarial S5-ADV-6 | crates/probation-server/src/accounts.rs:1587 | SSO callback does not check the flow's organisation, so an IdP mix-up is possible |
| S5-6 | re-check → rework | R1–R6 resolved. New: (N1) the Argon2id permit is released on cancellation while the hash keeps running; (N2) mail-cap keys collide with sign-in-failure rows (`mail:<email>` is a valid email), a silent mail lockout; (N3) the mail cap takes a second pool connection inside an open transaction; (N4) R5's pending-deleted clause is untested; (N5) the sign-up IP cap is counted before password validation. | Fix all five. N5 decision: the IP cap counts only requests that would send mail (after validation); password errors show normally. |
