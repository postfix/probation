# Slice 5 molecule-verify: verdict PASS (2026-11-10)

## Command

```text
SF_RUST_RECEIVER_SCOPES_FILE=docs/plans/publishing-proxy/evidence/slice-5-rust-receiver-scopes.json \
systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900 \
  $HOME/.claude/skills/sf-start/scripts/router molecule-verify --plan-root docs/plans/publishing-proxy --slice 5
```

Installed SMTC: `smtc 0.1.0`, commit `9f8652644680`, rebuilt 2026-11-10 16:49 (after the SMTC fix below).
Result: PASS, no findings. All nine checks PASS: classify-selected-registry, upstream-publisher-auth-before-send,
canonical-token-packument, audit-filter-before-render, current-policy-before-service-response,
service-reference-before-delete, service-marker-before-delete, classify-npm-delete-routes,
service-removal-marker-after-put.

## History

Earlier the same command returned UNKNOWN for five checks (`SOURCE_SUBJECT_VACUOUS`) on the 2026-11-10 02:59 build.
Cause: SMTC `call_sites` returned 0 findings for `.rs` files outside the crate `mod` tree, and the Factory capture held
`src/http/service_registry.rs` and `src/http/service_unpublish.rs` without `src/http/mod.rs`. The source was not
changed: `respond` and `consume_service_marker_then_send` still hold the guard and operation calls. The SMTC team
fixed the indexing; this run is the re-check. Receipt `slice-5-rust-receiver-scopes.json` is unchanged.
