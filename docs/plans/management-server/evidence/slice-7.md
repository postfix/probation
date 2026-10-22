# Slice 7 evidence — global admins, fleet, blocklist import/export, automation, retention

Started 2026-10-22 at the user's request, in worktree ../probation-slice7 (branch `management-server-slice7`), from `management-server-slice6` at 96b428b: slices 1–6, with slice 3/4 fixes and C126 merged in; slices 5–6 are pre-review.

## Decisions and deviations
| ID | Status | Item | Decision |
|---|---|---|---|
| S7-1 | carried | `settings_rollouts.created_by` has no ON DELETE, so purging the creator's login fails (found by slice 6). | Slice 7 decides; prefer SET NULL. |
| S7-2 | carried | The .npmrc and pip.conf snippets use a `FIREWALL` placeholder; there is no portal setting for the firewall's address (slice 6 deviation 3). | Slice 7 adds it with the fleet pages, or slice 8 handles it. Report. |
| S7-3 | deviation (scope) | `Block.reason: Option<String>` (serde default + skip) added to every Block variant, with mechanical `..`/`reason: None` edits in src/policy/{blocklist,effective}.rs, probation-policy edit.rs, portal/policy.rs and the test files of slices 2–6. | Approved. A pinned pre-change fingerprint proves reason-less policies are unchanged. |
| S7-4 | deviation (scope) | crates/probation-server/src/sync.rs: `record_report` calls `fleet::settle` (staggered rollout release, 02 § Data), and SyncState gains `pub(crate) fn pool()`. | Approved. |
| S7-5 | deviation (scope) | src/config.rs `LOCAL_ONLY_KEYS` now uses `probation_policy::LOCAL_ONLY_SETTINGS`, so the firewall and server share one allow-list (C35/C118). | Approved, with a test. |
