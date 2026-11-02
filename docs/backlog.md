# Backlog

Open work that no plan covers yet: requested features, known limits, flaky tests and small
review findings. An entry here is a candidate, not a commitment. Each line says what it is, why
it matters, and where it is recorded. `evidence/` means `docs/plans/management-server/evidence/`.

## Shipped (removed from this list)

- **B1, block on OSV findings:** shipped in f5ec49a through `docs/plans/osv-intel/`.
- **B4, a password per user on inbound requests:** shipped as managed mode through
  `docs/plans/management-server/`: each person or service has named, revocable API keys, and a
  managed firewall answers 401 to a missing or unknown key. A standalone firewall stays open to
  anonymous clients by decision (C12).

## Before the next release

- **Version above 0.2.2.** `probation` 0.2.2 is on crates.io, and the published crates `probation`
  and `probation-policy` still say 0.2.2, so the next publish fails until the version is raised; it
  is also the first Elastic-2.0 release.
  `evidence/slice-8.md` S8-15.
- **Re-run the managed benchmark on a quiet host.** Run `cargo bench --bench warm_metadata --bench
  artifact_throughput -- --managed` at load average below 2. On a busy host warm_metadata
  throughput was 82.6–101.4 % against the 90 % target (C83); the user accepted it only until
  this recheck. `evidence/slice-8.md` S8-18, `evidence/slice-2.md` S2-4.
- **Manual accessibility checks.** Run the "A11Y-keyboard, still manual" items, for example:
  reflow at 320 px and 200% zoom, screen-reader reading of errors and of a token shown once,
  keyboard copy of that token, the confirmation pages, and keyboard use of the Google, GitHub,
  Microsoft and company SSO sign-in round trips. axe and the automated keyboard walk do not judge
  these. `evidence/tdd-slice-5.md`, `tdd-slice-6.md`, `tdd-slice-7.md` §
  A11Y-axe and A11Y-keyboard.

## Flaky tests

Fix these by reading the code and making the test deterministic, not by running it under load.

- **B5, `tests/decision_log_delivery.rs::tp16_unopenable_log_path_fails_startup`.** It frees a
  port and later checks that nothing answers on it; a parallel test can take that port in
  between. Hold the listener, or check the refused start in another way. `evidence/slice-2.md`
  S2-8.
- **`tests/blocklist_reload.rs` timing tests.** They wait a fixed 2.5 s (`TWO_INTERVALS`) and
  failed twice in full parallel workspace runs; each passes alone. Use an injected clock or an
  event to wait on. `evidence/slice-6.md` S6-12.
- **`tests/content_store.rs::an_open_during_eviction_is_refused_and_a_second_eviction_stands_aside`.**
  Failed once in a loaded full run, passed alone and on rerun; there is a race to find.
  `evidence/slice-6.md` S6-5.
- **Pooled wiremock servers.** `tests/common/mod.rs`, `artifacts_concurrency.rs`,
  `origin_guard.rs`, `managed_sync.rs`, `osv_enforcement.rs` and `decision_log_delivery.rs` still
  use `MockServer::start()`. A pooled server can receive a request another test left half-sent,
  which caused an OSV test flake; `MockServer::builder().start()` fixed it there.
  `evidence/tdd-slice-3.md` (Rework 3), `evidence/slice-4.md` re-verification.

## Known limits (accepted for now)

- **Self-service reset cancels the operator's printed link.** Anyone who knows a global admin's
  address can request a reset, which marks the bootstrap or `admin reset-link` link used. The
  fix today is to run `admin reset-link` again (`docs/management-server.md` §5). `evidence/slice-8.md`
  final verification, S8-17 (1).
- **A firewall that never refused a push.** `fleet::settle` fails a rollout step by
  `FirewallReport.failed_revision` only when the report has it. A current firewall with no
  refused push sends none, so a rejected-batch error in its `last_apply_error` can still fail a
  step under the old rule. `evidence/slice-7.md` S7-14.
- **One sync answer can pass the firewall's 8 MiB cap.** A layer may hold 5000 blocks (about
  2.9 MB), so a delta that changes three or more full layers in one call can be refused by the
  firewall. `evidence/slice-7.md` S7-12.
- **`admin after-restore` can run about 2,000 times.** Each run moves `settings_rollouts_id_seq`
  forward by 1 000 000, and the sequence is `integer`. `evidence/slice-8.md` S8-17 (8).

## Small findings from reviews (not fixed)

- **Sync body read before the token check.** The sync handlers read a body of up to 2 MiB before
  the firewall token is looked up and rate-limited, so a caller with a made-up `fwt_` token costs
  the server that read and a Postgres query. `evidence/slice-4.md` code-review F5, security F4.
- **Last sync before a settings restart is not saved.** The final sync before a restart applies
  key revocations but does not save the snapshot, so after the restart the firewall starts from
  the older snapshot until its next sync. `evidence/slice-3.md` security S3-SEC-5.
- **Bootstrap audit row sits in the new organisation's log.** `admin bootstrap` writes
  `admin.bootstrap` with the new organisation as its `org_id`, so that organisation's admins see
  an operator action in their audit log. `evidence/slice-4.md` re-verification (F7).
- **Group activity follows current membership.** A group admin's activity view selects members
  by their group today, so a member's past rows move with them to a new group.
  `evidence/slice-6.md` S6-ADV-6.
- **Partial exception shown as "not in effect".** An exception that still applies in part is
  labelled entirely "not in effect while a stricter rule above applies". `evidence/slice-6.md`
  S6-ADV-5.
- **PyPI activity cases without tests.** A held-only PyPI listing, and a listing that serves some
  files, have no activity test. `evidence/slice-3.md` final verification.
- **Simplifications.** `crates/probation-server/tests/portal_places.rs` copies about 400 lines of
  the test harness from `tests/accounts.rs` beside it; the org-admin-or-global-admin check
  (`runs_org` in `crates/probation-server/src/tenancy.rs`) is written again in other modules;
  `accounts::unconfirmed` repeats `unconfirmed_email`'s query. `evidence/slice-6.md` S1, S2, S3.
