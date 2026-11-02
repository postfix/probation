## What problem do we have?
You approved the design on 2026-10-21. Since then, one approved check turned out to be impossible to build.

The design said an SMTC analyzer would prove one promise (T19): "only `Managed::authenticate` reads the API key header, and only the key's hash leaves it." This SMTC build ignores argument matching in specs. So the analyzer cannot tell `get(AUTHORIZATION)` apart from any other `get` call (evidence/smtc-argument-matching.md). Slice 2 is paused until you approve a replacement.

Slice 1 also left two questions for you (C124, C125) and two follow-ups (S1-1, S1-6).

Everything else in the design is unchanged and stays approved.

## How will we solve it?
There are five changes. Each one starts with what changes for you.

### 1. The key-header check (C123)
**What changes for you:** the promise stays the same. Three checks replace the analyzer.

| Check | What it does | When it runs |
|---|---|---|
| T-authorization-read-once (`tests/authorization_read_once.rs`) | A CI test. It scans `src` and `crates/probation-policy/src`, with comments removed. It counts every use of `AUTHORIZATION`, `siem_auth_header`, the text `authorization` (any case) and `Authorization`. The counts must equal a pinned list: the import and `get(AUTHORIZATION)` in `authenticate`; the `siem_auth_header` field, parsing and default in src/config.rs; its uses in src/delivery/mod.rs. Any other use fails and names its file and line. | written in slice 2; rerun in slices 2–8 |
| C123 SMTC query | `smtc callers --callsites-matching '*AUTHORIZATION'` for `get` and `get_all`, argument 0 and 1, over `src` and `crates/probation-policy/src`. It passes only when there is exactly one site: `headers.get(AUTHORIZATION)` in src/managed/mod.rs. | every Recheck, slices 2–8 |
| T-key-canary (`tests/key_canary.rs`) | A leak test. It sends a fake key `prb_CANARY…` as Bearer, as Basic, too long and malformed. The key, its Basic form and its SHA-256 hash must not appear in any log, record, SIEM body, response, or upstream request. The hash goes only into the `sync/lookup` call. | slice 2: the 401, 503 and server-429 paths. Slice 3 adds T-key-canary-sync: the 403 network lock, the account 429, stale answers, and the activity and `FirewallReport` bodies |

The test must fail on each of these changed copies: a second `headers.get(AUTHORIZATION)` in a handler; an `AUTHORIZATION as A` import; `get("authorization")`; `HeaderMap::get(&h, AUTHORIZATION)`; `remove(AUTHORIZATION)`; `headers.get(&config.siem_auth_header)` in a handler; the read moved into `admit`. A copy that only adds a comment must pass.

No analyzer spec is written. It is planned again once SMTC enforces argument matching in specs.

### 2. A "not in effect" value under an exception (C124, you chose 24 h)
**What changes for you:** a group's saved "not in effect" value applies again to a package when an exception removes the stricter rule above it.

Example from C124. The platform freeze is 48 h. The organisation lets its groups shorten the freeze, and a group sets 24 h. Then the organisation turns that permission off. The 24 h is kept and shown as "not in effect" (C47). Then the organisation adds an exception that removes the freeze for one package. A user in that group now waits 24 h for that package.

The portal label becomes "not in effect while a stricter rule above applies". Check: T-portal-not-in-effect (slice 6). Slice 1 already merges this way (slice-1 deviation 2).

### 3. Empty platform values (C125, you chose "keep as is")
**What changes for you:** nothing is forced. If the platform policy leaves OSV and freeze empty, they mean OSV off and freeze 0.

This applies to every layer below that sets nothing. The server and the firewall force no value, and nothing fills in platform values. It fails open, by your choice. Check: T-resolve-empty-platform (slice 2) expects freeze 0, OSV Off and no source layer.

### 4. Two follow-ups now planned
**What changes for you:** two gaps found in slice 1 now have an owner and a test.

- **Each edit is checked against its own layer chain** (S1-1). A new function, `PolicyStore::parent_policy`, picks the chain. T-edit-parent-chain (slice 4) checks three places: a personal account gets [platform]; a user with no group gets [platform, organisation]; a user in a group gets [platform, organisation, their own group], never a sibling group. It also checks that a re-save of an unchanged kept value is accepted (C47).
- **The blocklist `reason` survives import and export** (S1-6, slice 7). Blocks without a reason keep the same fingerprint.

```rust
// crates/probation-server/src/policy.rs — NEW (slice 4)
impl PolicyStore {
    /// Gives an edit the parent policy and the stored layer it is checked against.
    /// Loads the place's own ancestor chain (C9, C10): platform -> organisation -> group -> user,
    /// or platform -> personal account. The portal, the automation push and the bootstrap CLI
    /// all take both values from here, so the chain is chosen in one place.
    /// Ok.0: `resolve` of the layers above the place (`EffectivePolicy::root()` for the platform layer).
    /// Ok.1: the place's current stored layer.
    pub async fn parent_policy(&self, place: &Authorized<Place>) -> Result<(EffectivePolicy, Layer), StoreError>;
}

// crates/probation-policy — CHANGED meaning (C124, C125); signatures unchanged
pub struct EffectivePolicy {
    pub chain: Vec<LayerSettings>, // keeps C47 "not in effect" values; the rules_for merge drops them
                                   // while an unlifted value above applies (C124); the fingerprint includes them
    /* blocks, exceptions, allow, fingerprint: unchanged */
}
pub struct CandidateRules {
    pub freeze_seconds: u64, // 0 when every freeze is lifted or none is set (C125)
    pub osv: OsvSetting,     // Off when no unlifted layer sets it (C125)
    /* freeze_from, osv_from, lifted_blocks: unchanged */
}

// shared Block — CHANGED in slice 7
pub reason: Option<String>, // serialized with skip_serializing_if = "Option::is_none":
                            // a policy without reasons keeps its fingerprint
```

### 5. Slice changes
**What changes for you:** four slices get more tests. The slice order is the same.

| Slice | Change | Witness |
|---|---|---|
| Slice 2 | adds `tests/authorization_read_once.rs`, `tests/key_canary.rs` and T-resolve-empty-platform | read-once test passes and its changed copies fail; `cargo test --test key_canary` prints `1 passed`; `cargo test -p probation-policy --lib tests::t_resolve_empty_platform` prints `1 passed` |
| Slice 3 | adds T-key-canary-sync | `cargo test --test key_canary` prints `2 passed` |
| Slice 4 | adds T-edit-parent-chain | `policy_edit` rises from 7 to `8 passed` |
| Slice 7 | T-blocklist-roundtrip also covers `reason` | `admin_fleet` stays `29 passed` |
| Slices 2–8 | Recheck runs the read-once test, the canary and the C123 query instead of the analyzer | as above |

## How will we confirm it is solved?
The behavior flow is unchanged: `managed-request`, `policy-edit` and `sync-changes`, molecule-check PASS. No obligation was deleted or weakened (gate-4-qa.md).

| Property | Evidence/status | Assumptions/limits |
|---|---|---|
| Key header read in one place (T19) | C123 query on today's tree: exactly one site, `headers.get(AUTHORIZATION)` in src/managed/mod.rs; a grep agrees with the pinned list (QA round 4). Read-once test: planned, slice 2 | the test file is not written yet |
| Only the hash leaves (T19) | T-key-canary (slice 2), T-key-canary-sync (slice 3): planned | the canary checks the paths each slice has |
| C124 kept value applies under an exception | T-portal-not-in-effect (slice 6): planned; slice 1 merge already does this (deviation 2) | label checked in slice 6 |
| C125 empty means off and 0 | T-resolve-empty-platform (slice 2): planned; slice-1 merge default (deviation 3) | fails open by your choice |
| Edit checked against its own chain | T-edit-parent-chain (slice 4): planned | Postgres integration test |
| `reason` round-trips | T-blocklist-roundtrip (slice 7): planned | — |
| Source obligations | 3 PASS on current source; 9 PENDING until slices 3–4 | call order only |

**Security coverage, changed rows only.** All other rows are unchanged.

| Threat / guarantee | Spec or obligation | Evidence / gap |
|---|---|---|
| Key read once, never recorded (T19) | CHANGED: was `managed-authorization-read-once.yaml`; now T-authorization-read-once, the C123 SMTC query and T-key-canary | threat re-model MODELED: bypasses T19a–h are covered; no new risk acceptance |
| Empty platform values fail open (C125) | NEW row: none, an accepted user decision | pinned by T-resolve-empty-platform (slice 2) |

**Reviews.** Threat model: MODELED (T19a–h). Red team: NEEDS REVISION, 6 findings (3 major, 3 minor), all fixed (evidence/red-team.md § "C123 re-review"). Design QA: round 1 QUESTIONS (answered as C124), round 2 REVISE, round 3 REVISE, round 4 READY. You approved round 4.

Recommendation: Approve. The promise is the same as before; only the way it is checked changes, and it now has three checks instead of one. C124 and C125 record your answers, and both follow-ups have a test in a named slice.
Limits: `tests/authorization_read_once.rs` and `tests/key_canary.rs` do not exist yet, so QA did not assess them. The SMTC query runs on a dirty SMTC build and must be rerun in every Recheck. Slice 2 code is written but not committed or reviewed. 9 obligations stay PENDING until slices 3–4. 48 h is the platform freeze in the C124 example; the documents name no default freeze, and an empty platform freeze means 0 (C125).
Status: Gate 3 in progress and Gate 4 pending (reopened). Slice 1 is done. Slice 2 is implemented and paused until this approval. Design QA round 4 READY; gate-qa verify READY. This approval covers 02, 03 and 04 together.
Sources: 01-product.md; 02-architecture.md; 03-program-design.md (C123–C125, § Test plan, § Threat model, § Security coverage); 04-slices.md; gate-4-qa.md; evidence/smtc-argument-matching.md; evidence/red-team.md § "C123 re-review"; evidence/slice-1.md (S1-1, S1-5, S1-6, S1-7); evidence/slice-2.md (S2-1); 00-status.md.
Approve the design, or what should change?
