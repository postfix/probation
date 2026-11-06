# Slice 3 installed SMTC bounded verdicts

Verdict: **PASS** for all four current-source ordered properties; each current unsafe control returns **FAIL** at its intended operation. Evidence tier: **Structural**. This is an independently reproduced spec-run report, not an exported formal certificate.

Run date: 2026-11-03T19:24:05.039709+00:00. Repository root: `/home/john/go/src/github.com/postfix/probation`. Session: `sf-slice3-installed-cert`.

## Deciding evidence

| Property | Current source | Unsafe control | Intended control witness |
|---|---|---|---|
| `npm-delete-routes-classify-before-dispatch` | PASS: 1 operations / 1 guard / 0 scoped findings | FAIL: 1 operation / 0 guards / 1 finding | `respond` → `dispatch_npm_delete_route`, line 49 |
| `service-removal-marker-after-put` | PASS: 1 operations / 1 guard / 0 scoped findings | FAIL: 1 operation / 0 guards / 1 finding | `record_successful_service_removal` → `commit_service_removal_marker`, line 25 |
| `service-unpublish-reference-before-send` | PASS: 10 operations / 1 guard / 0 scoped findings | FAIL: 1 operation / 0 guards / 1 finding | `consume_service_marker_then_send` → `app.transport.send_action`, line 103 |
| `service-unpublish-marker-before-delete` | PASS: 10 operations / 1 guard / 0 scoped findings | FAIL: 1 operation / 0 guards / 1 finding | `consume_service_marker_then_send` → `app.transport.send_action`, line 103 |

The fifth deciding item is immutable subject/tool binding: all 15 manifest-listed files match their recorded hashes; all four exact YAML specs and four unsafe Rust control files have unchanged before/after SHA-256 values. All 42 captured paths, including existing control caches, the manifest, and both installed binaries, remained unchanged. Omitted deciding items: 0.

The two `send_action` properties each encounter 10 operation sites, one guard, and nine unguarded operations before the caller filter; their explicit `consume_service_marker_then_send` scope removes those nine unrelated findings. This is a scoped ordering result, not a clean result for every `send_action` in the repository. Both unsafe findings retain the exact summary `Operation 'send_action' lacks required guard (callee: app.transport.send_action)` and the full `callee_qualified_name` of `app.transport.send_action`.

All eight spec runs report outer `ok: true`, a real `Protocol` trace using `find_call_sites_bulk`, `cfg_dominance`, and `expr_eval`, no inner error, no `VacuousObligation`, empty diagnostics and refs, and no reported truncation or incompleteness. The operation does not expose an explicit overall fidelity or functions-analyzed field; unsafe finding confidence is exactly `structural`. No stronger fidelity or whole-program completeness is inferred.

## Subject and installed daemon binding

- Subject manifest: `.scratch/slice3/current-subject.json`; SHA-256 `a85bfdde9de40508ce3c512087d59461037b0710b125f2382359832d66e201b9`; base recorded in that manifest: `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`.
- Installed CLI `/home/john/.local/bin/smtc`: SHA-256 `fbde1a91373107ccee46a79201a1f084b40ddf7f5763007aff9d458687512bc4`.
- Installed daemon `/home/john/.local/bin/smtc-daemon`: SHA-256 `2d149b7d5cced35398796ec48e9a8b99a44a5a6dc7ea8433a24879d8716344f5`.
- A direct `SO_PEERCRED` observation of `/home/john/.cache/smtc/daemon/daemon.sock` identified PID 2020323, UID/GID 1000. `/proc/2020323/exe` resolves to the installed daemon and has the expected SHA-256. The same process/hash was observed before the runs. Other candidate daemons were present; this receipt binds the actual default socket peer, not merely a process name.
- Full values are retained in `.scratch/slice3-installed-cert/before-hashes.json`, `daemon-before.json`, and `after-hashes.json`.

## SMTC receipt

The exact argv, request IDs, raw hashes, outer/inner status, observed fidelity, operation/guard counts, truncation/refs, and interpretation for each of the eight deciding `run` legs are in `.scratch/slice3-installed-cert/command-receipts.json`. No argv secrets required redaction. Every run used the absolute installed CLI and explicitly cleared `SMTC_RUNTIME_DIR` and `SMTC_DAEMON_BIN`:

```text
env -u SMTC_RUNTIME_DIR -u SMTC_DAEMON_BIN /home/john/.local/bin/smtc spec run --root <exact-root> --spec-file <absolute-spec-path> --format json --max-tokens 2048 --session-id sf-slice3-installed-cert
```

For each table row, the exact spec path is `/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/<property>.yaml`. The safe root is `/home/john/go/src/github.com/postfix/probation`; its separate unsafe control root is `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/<property>/unsafe`. Raw complete command envelopes are retained under `.scratch/slice3-installed-cert/`:

| Raw envelope | SHA-256 |
|---|---|
| `npm-delete-routes-classify-before-dispatch-safe.json` | `cd6bfac4e6fc37a14f75f59ef6438a521a6085922ef6ab5d38d3584fb694587c` |
| `npm-delete-routes-classify-before-dispatch-unsafe.json` | `cd74fc6f45d3ed6dc7c929066f7c5ece2152c44f3827e0566925d168ef5bc330` |
| `service-removal-marker-after-put-safe.json` | `6f9f1a229ecc0cd65f7ae9ed1e230c3a6aaf323d06ee0b2c6158fcd4d7dc60ca` |
| `service-removal-marker-after-put-unsafe.json` | `1e28a0388d3b3222aa89325f09bfa0058d45a0d6a0ba6b1968b6027bbcd1fd1c` |
| `service-unpublish-reference-before-send-safe.json` | `f69053ab046e84120bfe17b30a23563a3dd9ac09987292c640f0b3d02c53204b` |
| `service-unpublish-reference-before-send-unsafe.json` | `f363a67f23f324e2026068d2aaaab197f2f28481f2a087b9fb2a7ba1fe98dfef` |
| `service-unpublish-marker-before-delete-safe.json` | `fa4db3f650726cecd6f61bbc6502ad40d70bc0490dd834b3bf770f69bd604092` |
| `service-unpublish-marker-before-delete-unsafe.json` | `ace8e2b15beedd18ed323b43d3edc8856200964933e28e1463818f17ccde5ba5` |

Supporting legs: installed `spec list --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-installed-cert` initially returned `daemon_unavailable` because sandbox IPC was refused. The identical read-only operation succeeded with approved local IPC escalation (`ok: true`, 28 catalog specs, no refs/truncation); this was an IPC permission issue, not a spec-run result. The registered `.smtc/analyzers` catalog does not enumerate these four explicitly supplied YAML targets. SMTC `file read` resolved each exact supplied YAML path with no ambiguity; direct successful `--spec-file` runs establish the installed interface behavior without relying on catalog membership.

Supporting `file read` legs used the same installed CLI/env/session/format/bound: the subject manifest and all four specs (complete), then `--root <unsafe-root> --path src/http/service_unpublish.rs` for the three service controls (complete). The classifier whole-file read was summarized to `ref-1` (2,648 estimated tokens); it was narrowed to `--root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/npm-delete-routes-classify-before-dispatch/unsafe --path src/http/service_registry.rs --start-line 35 --end-line 55`, which completed inline and confirmed the unchecked classifier call immediately before dispatch. That summarized supporting read is not used as a clean negative. A supporting `file find` for `.scratch/slice3-specs/**/unsafe/**` returned zero because it respects gitignore; it is irrelevant to control existence, which the exact-root reads and runs establish. Supporting reads expose text evidence only; they do not raise the Structural tier.

## Limits

These four specs establish only the named call-order/dominance properties in their configured caller scopes, with each current positive control firing at the expected site. They do not prove exact value binding, route semantics, durable marker correctness, runtime behavior, or whole-program safety. Unsafe controls intentionally rename guard calls and were analyzed structurally; this report makes no claim that they compile. No compile check, full build, runtime test, exported certificate, or global graph/daemon-health verdict was performed. Existing source, tests, specs, controls, and Factory completion state were not edited.
