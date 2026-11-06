# Service-policy API seam — 2026-11-02

sf-repo-view `shared_policy_api_seam`: PARTIAL. Subject `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`; SMTC generation 55, dirty_build true. Structural orientation plus selected text, not a clean-commit/runtime certificate. No edits, builds or tests by the reviewer.

## Existing facts

- `crates/probation-policy/src/api.rs:142–208` supplies ChainLink(place, layer_revision), PlaceLayer(place, layer, revision), LayersResponse(layers, revision), and KeyLookup::Known(key_id, org, account, place_chain, rate_limit, rate_limit_source, revision). Chain order is platform first, own place last. Layer and the shared resolver preserve ancestor exception/loosening rules. Ecosystem still has only Npm/PyPi.
- `crates/probation-server/src/sync.rs:611` uses REPEATABLE READ READ ONLY and reads change_counter first. `look_up` at line 937 reuses standing/links but accepts user and service keys; Known omits kind. A new organisation-service-key endpoint must explicitly require database kind=service. Prefix or Known alone is insufficient.
- Existing POST /api/v1/sync/{certificate,lookup,layers,changes} uses fleet fwt authentication, firewall identity/source CIDRs and fleet limits. Layers permits arbitrary requested places under fleet authority. These routes are not a scoped service-key API. The org registries portal is signed-in admin HTML.
- RegistryId and selected-registry descriptors exist. CertificateAdmission::Granted additionally includes read_authorization and certificate/member fields. Reusing it wholesale would violate new credential custody. Registry queries must retain live organisation ownership and removed_at checks. Exact-file text search found no record_change/ChangeKind in portal/registries.rs; current global revision is not evidence of registry-edit freshness.
- `src/managed/cache.rs:916` Snapshot(version,cursor,keys,layers,network_lock) and SavedKey/SavedLayer support atomic save and previous-file recovery. This format is not bound to the proposed service identity/registry descriptor contract. Existing ordinary HTTP managed requests authenticate headers/peer, conflicting with C1021. New requests need the service's policy, without requiring a downstream Probation credential. Service key attribution is not individual caller identity.

## Proposed seam, not existing implementation

GET /api/v1/policy/snapshot with Authorization Bearer organisation-service-key. No caller-supplied organisation or arbitrary place list. Return one coherent key/organisation/place-chain/layers/rate-limit snapshot and permitted registry descriptors. Use existing shared types/resolver where applicable. Verify selected RegistryId belongs to the key's live organisation. Exclude registry read_authorization, encrypted credentials, policy/fleet key material, member certificates and sessions.

Read standing, key kind, chain, layers and registry ownership in one read-only snapshot transaction. Initially poll the full snapshot; a revision-only conditional response would miss registry edits unless their revision participation is added and tested. One fetch in flight; validate complete chain and revisions before atomically activating the response.

Suggested errors: 401 missing/malformed/unknown/wrong-kind/revoked key; 403 suspended authority; 404 selected registry absent from that organisation; 429 fetch budget; 503 unavailable storage. Explicit authority refusal stops admission and durably invalidates remembered authority; transient transport/5xx retains previously validated matching policy under management C19/C20.

Persist a new envelope bound to server identity, configured key hash, managed mode and selected registry set. A durable invalidated-authority state must prevent previous-file recovery from resurrecting a revoked/suspended grant. No matching valid cache means no managed admission. Standalone remains a distinct explicit authority.

## SMTC receipt and limits

Root /home/john/go/src/github.com/postfix/probation; session sf-shared-policy-api-seam-2026-11-02. Run map (1024 tokens), inspect, architecture/cycles, find/read/grep and bounded ref operations (2048 tokens otherwise). Outer/inner OK except an invalid nonexistent sync/mod.rs path, corrected to discovered sync.rs; no native fallback. File/text evidence functions analyzed n/a. Broad map/import/search output was truncated; decisive claims use narrowed complete reads. References over 4096 tokens were not opened. The mixed production/test cycle is not a runtime defect. Zero text matches are not caller/reachability proofs. Omitted deciding findings: zero.

Deciding complete reads: api.rs:1–210/210–360; policy lib.rs:1–220; sync.rs:1–160/192–245/360–400/480–665/937–1080; keys.rs:1–180/390–580; managed/cache.rs:1–200/910–1100; managed/mod.rs:45–90; managed/sync.rs:100–225; portal/registries.rs:24–60/106–149. No exhaustive caller trace or external protocol research.

Risk: treating old fleet authentication, certificate admission or restart cache as the delivered scoped service-policy contract. New source and executable conformance checks are required.
