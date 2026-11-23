# Deployment contract grounding — 2026-11-02

sf-repo-view deployment_contract_review: PARTIAL. Subject `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`, SMTC generation55/dirty_build true. Selected source and structural orientation only; no build/runtime result.

## Deciding existing facts

- Foreground `serve --config` and validation commands exist. `src/main.rs` handles Unix SIGINT/SIGTERM; pushed settings gracefully stop and exit75. `src/lib.rs:632,653–709` drains requests for30seconds before background/log/storage shutdown and lock release. The file sink has a separate5second drain. Total process shutdown is not proved bounded by30seconds.
- Config has one listener, HTTPS public_url without path/query/fragment/userinfo and absolute data_dir. `src/lib.rs:365–447` can terminate TLS directly. Default is loopback; parser accepts non-loopback, so parser success does not prove admission.
- fs4 lock immediately rejects a second data-directory owner. Startup requires WAL/FULL and retains unusable database bytes while blocking readiness/delivery. Decision file has one writer. No distributed locking or network-filesystem guarantee was established.
- `deploy/probation.service` already supplies dedicated account, preflight, Restart=on-failure,45second stop allowance and protected paths. Compose persists data/restarts. Dockerfile uses non-root firewall account. `scripts/install-local.sh` makes a second weaker unit, falls back to unsupervised nohup, overwrites samples and regenerates certificates: it is not a safe upgrade path. build-install extracts a Linux binary, not native macOS/Windows setup.
- CI tests Ubuntu; release packages Linux/macOS x86_64/ARM64, no Windows/service payload. Unix imports remain in main.rs, http/unpublish_reference.rs, delivery/mod.rs and delivery/file.rs; blocklist watcher has a weaker non-Unix branch.
- Root SCHEMA_VERSION is7, Turso0.7.2. Existing4/5 migration drops projects/artifact_references,6 updates metadata to7, others refuse. This historical behavior is not permission for a new destructive migration. Ecosystem::from_tag decodes TEXT; explicit npm/pypi tags and serde variants must remain stable.
- Existing prefixes: /registry/npm/{registry}/..., /registry/pypi/{registry}/simple/..., their ecosystem-rooted artifact routes, legacy /npm and /pypi and selected publishing/action routes. Preserve reference IDs and prefixes.

## Smallest proposed deployment

Reuse Linux service template and foreground application; consolidate generated units. Add macOS system LaunchDaemon and a Windows service-stop adapter with dedicated identity/ACLs, preserving shared graceful shutdown. Verify native template APIs before treating them as executable. Cluster: one active process, own PVC, stable TLS endpoint, replacement ordering without overlapping store owners. A one-replica deployment remains subject to storage fencing on node failure; never share embedded store between replicas. A deployment update/node loss can interrupt service.

Keep machine listeners local. VM-hosted Docker may need a separately protected reachable host endpoint; do not assume loopback reaches it or silently expose wildcard ingress. Every approved cluster node needs endpoint DNS/route/CA and runtime/host egress controls. Pod NetworkPolicy alone does not prove host-runtime control. Use the researched explicit-server pull/resolve candidate with no origin fallback and reconcile per-registry overrides. Native cached images may avoid a pull; no execution revocation is promised.

Credentials stay configured in package managers/runtimes. Preserve existing publishing forwarding; add no firewall registry-credential setting or public/private mode.

## Preservation and acceptance

First install creates defaults only if absent. Upgrade stops/backups/installs/validates under service identity/restarts with same state; never replace config/certificates/keys with samples. Repeated tool setup preserves credential entries and unrelated settings. Removal stops/disables and reverses only recorded setup changes; data remains by default.

Native Linux/macOS/Windows lanes must execute service setup/start/stop/restart, exit75 restart, second-owner refusal, state preservation, package-tool allow/deny and outside-host rejection. Retain existing publishing tests. Linux policy-server integration is separate; another Actions job is not macOS/Windows localhost. Use an explicitly reachable Linux endpoint on a protected runner network for integration.

Actual local-daemon Docker lanes record host/daemon location/mode and versions and run genuine allowed/denied pulls. Ubuntu VM has documented daemon capacity; non-Linux requires verified native runners with local Docker/VM. Remote Linux daemon is narrower evidence. Cluster checks include fresh tag/digest allow/deny, denied and service-down zero-origin-fallback, approved/unapproved nodes, cache behavior, restart and store-owner transitions. Exact Windows dependencies/ACL/directory durability, service templates, native pins, runner connectivity and pinned runtime/storage behavior remain unverified.

## SMTC receipt

Root /home/john/go/src/github.com/postfix/probation; session sf-deployment-contract-review-2026-11-02. Run map1024, inspect/architecture/cycles/find/read/grep2048; outer/innerOK, no operation refusal. Complete deciding ranges cover source/deploy/scripts/workflows/sample/schema/rows/router; capped locators and broad maps were narrowed. Imports ref-209 estimated41120 tokens was unopened. Entry analysis returned5/11 with2192 unresolved dispatches/analyzed_clean false, so no complete-flow claim. No native fallback. Files changed by reviewer: none. Omitted deciding evidence: zero.
