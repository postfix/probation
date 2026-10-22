# Gate 1 QA
## Verdict
READY

## Overall assessment
F5 is resolved and no blocking finding or user question remains. The account.html "delete your login" dialog now says deleting stops the sign-in methods from opening the login and that restore is by signing in again with any of them and choosing "Restore login" (C94). The delete-personal-account dialog says a personal account alone is restored in Account settings, and a login deleted with it is restored by signing in again (C85, C94). The sign-in.html deleted-login state says "Restore login" also brings back a personal account deleted with it, and "Start a new login instead" erases both. The 94 rows, the sections and the nine mockups agree. Success is measurable. C2, C34, C35 and C86 stay deferred to Gate 2 under their original IDs. One non-blocking wording note (N1) is recorded below for the author.

## Questions and findings
**F5 (from the previous review): resolved.** See the overall assessment. The wording follows C85, C93 and C94 and adds no new decision. It changes approved mockup wording, so mention it to the user when presenting, as with F3.

**N1 (non-blocking, clarity). The operator's delete-personal-account dialog does not say who restores the account.** Location: mockups/global-admin.html, state "destructive confirm, act on a personal account" ("Everything else is erased after 30 days and can be restored until then."). Problem: the sentence is passive, and the screen has no restore action and no "deleted" filter for personal accounts. The existing rows already answer it: C33 and C73 make the owner restore (in Account settings), and C85 deletes a login with no organisation together with its personal account, restored through C94. Consequence: small. A reader might expect the operator to restore it, but the rows settle the behaviour and Gate 2 can follow them. Recommendation (optional): change the sentence to "Everything else is erased after 30 days. Until then its owner can restore it from Account settings, or by signing in again and choosing Restore login if the login is deleted with it." No user decision is needed.

No questions for the user.

## What was checked
- **Previous finding:** F5 is resolved in account.html (both delete dialogs) and sign-in.html (deleted-login state), as described above. The wording matches C33 (keys stop within the sync interval, 30-day grace, audit-log retention), C85, C93 and C94 (restore by signing in with any old method; reserved email-and-password address until restore or erase).
- **Completeness:** Passes. The users (operators/global admins, org admins, group admins, members, personal-account owners), the problem, the promised outcome, the scope and twelve non-goals are clear. Every requested capability appears in rows and mockups: Google, GitHub and Microsoft sign-in, company OIDC SSO (C21), and email sign-in; user and service API keys; layered policy with blocks, exceptions, three-value OSV and freeze (C8 to C18, C31, C44 to C47, C81); global admin; fleet (C22, C69 to C72). The login lifecycle is closed: linking (C75, C89), leaving (C85, C88), deletion (C33, C85, C93) and restore (C63, C73, C94).
- **User experience:** Passes. The nine mockups cover the primary, empty, error and destructive states for each screen. The main journey can be followed from sign-in.html and api-keys.html: sign up, confirm email, create a key, paste the `.npmrc` or `pip.conf` lines (exact lines deferred as C34), install. The deletion and restore journeys can now be followed from account.html, organisation.html and sign-in.html.
- **Acceptance:** Passes. Metric 1 is a pass/fail automated end-to-end test with a 10-minute limit, run before every release (C82). Metric 2 is the per-change time from save to the last firewall applying it, judged at the 99th percentile against the sync interval (C20, C32). C83 gives numeric performance limits measured with the existing benchmarks. C84 names WCAG 2.2 AA.
- **Constraints and risks:** Passes. Tenant sealing (C1) holds in Activity (C92) and the network lock (C77, C87). Email-and-password addresses stay unique without revealing which are registered (C91, C94). Admin authenticators are required (C24, C60, C90). Accepted risks (C18, C19, C30, C77) and limits (C26, C28, C66 to C68) are recorded as product expectations. Managed mode is opt-in and leaves standalone behaviour unchanged (C12). This matches README.md and config.sample.toml (no client authentication; `osv_mode` enforce or diagnostic corresponds to C81's on or log only).
- **Clarity:** Passes, with the optional N1. Terms (login, personal account, service key) are defined with words to avoid. The announcement agrees with the scope and non-goals.
- **Clarification inventory:** 94 rows, each with ID, class, status, owning and target Gate, selected value and decision source. C2, C34, C35 and C86 are technical choices correctly deferred to Gate 2 with their IDs. The last workflow-history entry is hand → qa (retry), and `router gate-qa prepare` returned PREPARED.

## Limitations
- 00-status.md and the previous gate-1-qa.md are machine state or a generated report and are not review sources. The status was checked through `router check`; the previous report was used only to list the earlier finding.
- The mockups were read as text with tags removed and were not rendered, which fits C74's content-only approval.
- The grilling transcript is not available, so the rows are taken as the record of the user's answers.

## Next steps
Present Gate 1 for the user's approval. When presenting, mention that the approved mockup wording changed for F3 and F5 (C74 approved the earlier content). The author may apply N1 first; doing so changes a reviewed file and needs a fresh review before presentation.
