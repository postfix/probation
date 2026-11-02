# Red team report (design, round 1)

Source: sf-red-team, independent review of the combined design, 2026-10-21. Verbatim report below; dispositions are in 03-program-design.md § Review dispositions.

```text
Review kind: red-team
Verdict: NEEDS REVISION
Review: independent
Subject: design (combined) docs/plans/management-server/02-architecture.md=d852a418fd180b553ff55e126d5ba34df3dc85268190babb78c9f0d73fd920fa; 03-program-design.md=f4bf05c63975a0f0fda98a59c6c76cf223eb36284e2f4fdb4f65a71e78c066d5; 04-slices.md=0db305d3db1d3dacecc3388514d1027ded608f87349c5722a9921c807e7119e0; upstream 01-product.md=1ece2bbc7a9739d8e25454601af17680103b4ca8f9304ac3c4da0c33b28aa396; molecule-flow.json=016fcbd3f0341a08fb97f34ea51eb8c23137944731dfc838eae6a62a4f95713d; molecule-contracts.json=1206878bbf3489e890c7e931c45b8ba7a89eb2c67b75cc7f5099a94f55179085; evidence/repository-structure.md=098220e808ecc0a991a9e36e7b4e20951288c46912a87edf6bdfe17a0628e424
Bottom line: The structure holds up: shared rules crate, lookup-and-cache, change_log cursor and the slice order are sound. The plan still has two blockers. Approved activity requirements (C23, C55, C56, C92) and limits/retention (C26, C28, C66, C67) have nowhere to live, and a managed firewall would still be gated by the local blocklist that C80 says it ignores. Separately, C105 restart-on-push, the C83 and C32 hard bars, and two slice witnesses each have a gap that will fail in practice.
BLOCKERS:
F1 BLOCKER · coverage · activity and limits have no design home. 03:149-154 Principal has no key id, but 03:175 says events carry one. 03:195 lookup turns a revoked key into `Unknown`, so the key's owner is lost. record_activity is fed only from `decide` (03:61), and 02:84 `result` is only blocked|held|would_block. So C55 refusals (revoked key, network lock), the C23 "key" column, C92 Layer "none" and the C56 eligible time cannot be produced. The 02:73-84 Data section has no storage for C28/C51/C66/C67 limits, C26/C68 retention or C87 refusal reason. KeyLookup carries no limit, yet slice 3 (04:11) promises T-rate-limits.
F2 BLOCKER · foundations · a managed firewall still depends on the local blocklist. In src/config.rs (REQUIRED_KEYS) `blocklist_file` is required. In src/http/health.rs `ready` is "a valid blocklist in force". npm, pypi and artifacts answer 503 POLICY_UNAVAILABLE on a missing or expired snapshot (evidence §3). No slice touches health.rs or the key list (04:10). A managed firewall (C80: ignores its blocklist file) is either never ready, or 503s everything when a dummy file expires.
MAJOR: F3 settings-push restart (C105) and memory-only state; F4 C12, C83 and C32 hard bars not credible as planned; F5 witnesses that pass before any code exists; F6 security fixes incomplete. Details below.

Findings:
1. BLOCKER · Coverage · 02:84, 03:61, 03:149-154, 03:175, 03:195, 02:73-84, 04:11 · Evidence: the lines above against 01:27 (C23), :59 (C55), :60 (C56), :96 (C92), :30 (C26), :32 (C28), :70-71 (C66/C67), :91 (C87). C96 "a key not used for one TTL is dropped" (02:10) also has no mechanism in KeyCache (03:145, 03:170). · Consequence: slice 6's activity page cannot show the key, revoked-key or network-lock rows, or the leave-freeze time. Slice 3's rate limit has no input, and slices 4 and 7 have no tables for limits, retention or refusal reason. Each of these means rework later. · Smallest fix:
   - Add `key_id` to the KeyLookup result and to Principal.
   - Server-side lookup returns `Revoked{key_id, place}` and `Suspended{...}`; both are still 401 on the wire.
   - authenticate's 401 and 403 refusals call record_activity.
   - Extend `activity.result` with `refused_revoked|refused_network` and add `eligible_at` and `layer`.
   - Add a `limits(scope_kind, scope_id null, rate_per_min, max_keys, max_service_keys)` table and a `platform_settings(retention_activity, retention_audit)` row.
   - Add `org_ip_ranges.refused_reason`, and carry the place's rate limit in KeyLookup.
   - State that the rate limit is counted per firewall (C66 then holds per firewall, up to N× fleet-wide), or ask the user.
2. BLOCKER · Foundations · 04:10 (slice 2 files), 03:72, 03:137 · Evidence: src/config.rs REQUIRED_KEYS contains "blocklist_file". src/http/health.rs `ready` returns 503 unless `app.blocklist()` is valid. The serve paths 503 on an absent or expired snapshot (evidence §3, src/npm/mod.rs:62-65). The Dockerfile ships a sample blocklist with a "distant expires_at so the image starts ready". · Consequence: C80 is contradicted. The local file still decides readiness and availability, and when that file expires every managed request goes down. · Smallest fix, in slice 2:
   - When `[management]` is set, `blocklist_file` and `blocklist_poll_seconds` become optional and the blocklist poller is not spawned.
   - `ready` means "first sync done, not retired, store healthy".
   - The per-route snapshot gates are skipped.
   - Add T-managed-ignores-blocklist (no file, file expired: still 200).
3. MAJOR · Dependencies · 03:7 (C105), 02:86, 02:103, 02:33, 03:71, 03:195 · C105 restart against C71, C22, C19 and C70. Evidence:
   - The sync cursor, key cache and network-lock table are memory-only (02:86).
   - After the exit-75 restart the firewall sends `since=0`, and nothing says the server withholds `settings` already applied. 03:195 has no applied-revision field in the report, so the firewall can restart in a loop.
   - The image copies config to /etc/probation/config.toml as root and runs as `USER firewall` (Dockerfile). An atomic write into /etc/probation fails.
   - 02:103 says "the docker image already uses" a restart policy. Restart policy is a run-time setting, not an image one, and the repository has no compose or unit file (grep for restart/unless-stopped: 0 hits).
   - C71 needs the start failure reported after rollback, which needs persisted state, but 02:86 says nothing is persisted.
   - C70 pushes restart every selected firewall at once.
   - Every lookup returns a full merged EffectivePolicy per key (02:61, 03:195) and each cache entry holds its own Arc (03:145). Firewall memory then grows as keys × union-blocklist. A platform edit expires every entry (03:91), so each firewall re-fetches the whole platform blocklist once per active key.

   Consequence: restart loops, fleet-wide drains, and a push that fails with EACCES in the shipped image. Any restart during an outage 401s every key (the C19 promise breaks). There is also a lookup storm on every platform block (C80 says blocks are added one at a time). · Smallest fix, keeping C105:
   - FirewallReport carries `settings_revision`, kept in a sidecar file under `data_dir`. The server sends `settings` only when it differs.
   - Write the config under `data_dir` (or a documented writable path), and keep `config.prev` plus a `last_apply_error` file there for C71 reporting.
   - Stagger C70 pushes, one firewall at a time, each after its report.
   - Slice 8 ships compose/systemd with `restart: unless-stopped` and fixes the 02:103 text.
   - Intern EffectivePolicy by fingerprint on the firewall. Better: lookup returns chain plus layer revisions, the firewall caches layers per place and runs the shared `resolve` itself.
   - Decide explicitly whether the key cache persists across restarts (C19), or record the gap as a new acceptance for the user.
4. MAJOR · Hard bar + risk order · 03:134, 03:9 (C107), 03:249, 04:16, 02:46, 03:235 · Evidence:
   - (a) C12/C83, OSV order: today `osv::evaluate` (src/osv/mod.rs) asks OSV only when the OSV-blind decision is Allow and the mode is not Off. This is pinned by the test `evaluate_skips_osv_when_producer_already_denies`. `decide(policy, candidate, now, osv_matched: bool)` needs the OSV fact up front, so either every candidate pays an OSV round trip (C83) or the standalone OSV traffic and diagnostics change (C12).
   - (b) C12, log format: `delivery::Decision` is `Serialize` with the fixed SPEC §11 fields. C107's `place: u32` adds a field to every standalone NDJSON and SIEM line.
   - (c) C83 measurement: C83 says "at most 1 ms … measured with the existing benchmarks". The plan writes a new `benches/managed.rs` and checks p50 (03:249). The existing `warm_metadata` and `artifact_throughput` benches report p95 and a throughput ratio (Cargo.toml comment). The check also runs only in slice 8, after slices 1-3 have rebuilt the hot path.
   - (d) C32 metric 2 (p99 ≤ interval, measured at the last firewall): policy_sync copies `blocklist_poller` (sleep, then pass), so the real period is interval + pass + RTT. With N firewalls, roughly N×(pass time)/interval of changes miss the bound. T-auth-revoked-401-after-sync accepts "interval + lookup time" (03:235). M-propagation runs once, in slice 8, and the plan names no firewall count.

   Consequence: C12 and C83 can both be broken before anyone measures, and the C32 metric 2 hard bar fails structurally. · Smallest fix:
   - Keep the two-step call: `decide(p,c,now,false)`, then only on Allow with `p.osv != Off` query OSV and call decide again. Add a per-policy-mode wrapper and keep the existing test.
   - Make `place: Option<u32>` with `skip_serializing_if` (8 B; 248 ≤ 256).
   - Run the managed variant of the existing two benches at their p95, as an assertion, in slice 2, and a standalone non-regression run in slice 1.
   - Use a fixed-rate `tokio::time::interval`, and poll at least 2 × RTT before the interval ends.
   - Test revocation at ≤ interval, and run M-propagation with ≥ 2 firewalls in slice 4.
5. MAJOR · Verifiability · 04:9, 04:11, 04:16, 04:12 · Evidence and fixes:
   - The slice 1 witness `cargo test --workspace` exits 0 today, because a single package is an implicit workspace. Slice 3's `cargo test --test managed_mode` exits 0 once slice 2 lands. Neither fails before implementation. Fix: `cargo test -p probation-policy` plus `cargo test --test managed_mode -- --exact <names>` with a required "N passed" count.
   - The `cargo bench` and axe witnesses only "report", nothing asserts. Fix: have the bench assert its threshold.
   - axe "0 violations" does not establish WCAG 2.2 AA (C84), and it arrives only in slice 8 while the pages are built in slices 5-7. Fix: run `npx @axe-core/cli` from slice 5 on (it needs no tooling), plus a keyboard/focus checklist.
   - T-secrets-at-rest in slice 4 covers TOTP and SSO secrets that only exist in slices 5-6. Fix: move it to slice 5.
6. MAJOR · Security (applies the supplied model) · 02:62 vs 03:195, 02:106, 02:75 vs 03:305, 03:342, 04:14 · Evidence:
   - B1 data path is inconsistent. 02:62 delivers `network_lock` in `changes`. 03:195 puts it in `KeyLookup::Known`, and `ChangesResponse` lacks both `network_lock` and `retired`. Nothing says a `reset` or first sync carries the full table, so after a restart or reset the lock can be empty (fail-open).
   - T23 contradicts the shipped deployment. The Dockerfile says "Keep the instance behind the reverse proxy SPEC §3 assumes", so C30/C77 sees only the proxy IP and is inert by default.
   - B2 is half-applied. 02:75 looks up by (kind, issuer, subject) only, while T2 says org SSO methods are "scoped to org_id". With a shared issuer (Google Workspace) one sub cannot be an SSO member of two orgs.
   - 03:342 widens the user's C19 acceptance to "attacker-induced outage" without asking.
   - B3: T-grant-by-invitation runs only in slice 6. The global-admin grant (slice 7) and the slice 4 bootstrap CLI are untested.

   Fixes:
   - One `ChangesResponse` type with `network_lock` and `retired`. Every `reset` and the first sync carry the full table, and that first sync completes before the listener binds.
   - Either support PROXY protocol or trusted-proxy X-Forwarded-For, or state in 02 that the network lock requires direct TLS termination and change the Dockerfile comment.
   - Include `org_id` in the SSO-callback lookup and in its unique key.
   - List the broadened C19 acceptance as A7 for Q56.
   - Add global-admin and bootstrap cases to T-grant-by-invitation in slice 7.

Checked clean: Sizing — slices are coherent. Slice 4 is the largest but is one deployable server increment, and no ceremony-only fragments. Over-build notes, not blocking:
- C35 (a user decision) makes `cooldown_seconds`, `osv_mode` and `blocklist_*` portal-editable even though managed mode ignores them. Cheapest fix within C35: grey them out as "not used in managed mode".
- "ArcSwap per entry" can reuse the existing `ShardedCache` (src/store/cache.rs).

Asked questions:
- C105 against C71/C22: consistent in intent, but broken in mechanism (F3).
- C83 and C12: not credible as planned (F4).
- Dependency order of slices 2→3→4 is otherwise correct: the fake server supplies lookup in slice 2.

Threat model: MODELED (supplied) — B1 consistent in 02:32/03:58/03:304 but delivery and reset are incomplete; B2 holds for distinct issuers, with the org_id scoping inconsistent; B3 holds in design but the global-admin and bootstrap paths are untested (F6). A1–A6 treated as proposed. No finding depends on approving them; the broadened C19 should be added as A7.
Limitations:
- Code claims are Manual tier: SMTC file read and grep only, every result `dirty_build: true`.
- The npm/pypi 503 gates are taken from evidence/repository-structure.md (Structural, sf-repo-view), not re-read.
- The "no restart policy anywhere" claim is a negative grep: README, Dockerfile and docs/*.md returned 0 hits. A broader docs grep returned a ref of ~7.4k tokens, which I did not open (over the 4,096 limit).
- The propagation miss rate is an analytic estimate, not a measurement.
- Molecule files: I only checked that molecule-flow.json does not model `settings` at all.

SMTC receipt (session sf-red-team-2026-10-21, root /home/john/go/src/github.com/postfix/probation):
1. search symbol `evaluate` — run; ok; Structural; truncated (6/12) — located osv::evaluate at src/osv/mod.rs:256-289.
2. file read src/osv/mod.rs 250-295 — run; ok; Manual — OSV is queried only after a blind Allow and not when Off.
3. file read src/http/mod.rs 98-115 — run; ok — `admit` reads blocklist validity.
4. file read src/config.rs 176-214 — run; ok — `blocklist_file` is in REQUIRED_KEYS.
5. file read src/http/health.rs — run; ok — readiness = valid blocklist.
6. file grep restart|[[bench]] in Cargo.toml/Dockerfile/yml — run; ok — benches are warm_metadata, artifact_throughput, blocklist_swap, delivery_rated_load; no restart policy.
7. file find Dockerfile/yml/service — run; ok — only Dockerfile and CI workflows; no compose file.
8. file grep restart in docs/** — run; ok; truncated ref-0 (7372 tokens), not opened.
9. file grep unless-stopped|--restart|restart: in README.md, Dockerfile, docs/*.md — run; ok; 0 matches.
10. file grep settings|network_lock|cursor in molecule-flow.json — run; ok — settings and network_lock are not modeled.
11. file read Cargo.toml 26-110 — run; ok; clamped — existing benches measure p95 and a throughput ratio.
12. file read Dockerfile — run; ok — config at /etc/probation copied as root, USER firewall, "behind the reverse proxy SPEC §3 assumes".
13. file read src/delivery/mod.rs 155-182 — run; ok — `Decision` is Serialize with fixed SPEC §11 fields.
```

## C123 re-review (2026-10-22)

Scope: the T19 control change (C123). Verdict: NEEDS REVISION, with 0 blocking, 3 MAJOR and 3 MINOR findings. All six were fixed in 03 and 04 before Design QA.

1. MAJOR. `Config.siem_auth_header` defaults to `header::AUTHORIZATION`, so a handler can read the key through `headers.get(&config.siem_auth_header)` without matching any token. Fix: `siem_auth_header` is now a scanned token with pinned uses, plus a mutant case.
2. MAJOR. The exact-text `--callsites-matching AUTHORIZATION` misses `header::AUTHORIZATION`, `&AUTHORIZATION` and UFCS, and its output has no enclosing fn. Fix: the glob `'*AUTHORIZATION'`, argument index 0 and 1, `get` and `get_all`, absolute roots for both trees, and a pass condition on path plus expression.
3. MAJOR. T-key-canary sat in slice 2, but the 403, per-account 429, activity and report paths come in slice 3. Fix: slice 2 covers the sync server's 429 served as 503; slice 3 Acceptance extends the canary.
4. MINOR. The canary needs harness work: trace capture, lookup-body recording, a shared SIEM collector, and the production transport. Fix: named in 04 § Slice 2 interfaces; the canary runs in its own test binary (`tests/key_canary.rs`).
5. MINOR. Whole-line pinning breaks on a rename or a rustfmt rewrap, and trailing and block comments counted. Fix: hits are keyed by (file, nearest preceding `fn`, matched token or call text); comments are stripped first.
6. MINOR. Stale text at 03:507, 03 § Files and the 04 fail-today wording. Fix: updated. show-me-design.md is replaced by the new design presentation.
