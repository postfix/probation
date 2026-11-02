# Missing end-to-end scenarios

After the 20 P0 scenarios (E2E-001 to E2E-020) were written, a review looked at the product through several lenses (security, operations, clients, tenancy, load) and listed scenarios that are still missing. A skeptic then checked each finding against the code, the written scenarios and the integration tests. This file keeps only what survived that check, in the reduced form the skeptic proposed.

- 52 findings were kept. Near-duplicates were merged, which leaves **46 scenarios, E2E-040 to E2E-085**.
- Most of them are **extra steps in a scenario that already exists**, not new files. Each entry says where to write it.
- File names are in the `probation-e2e` repo, under `tests/e2e/scenarios/`. Fixture codes are the ones in `00-inventory.md` §3.
- Many entries expose a product defect. Following D9, write the test to the **correct** behaviour and let it fail until the product is fixed. Entries marked **Decision first** need a ruling before the test can say what is correct.

Kind:

- **New scenario**: the review found a journey that nothing covers.
- **Weakness in an existing P0**: a written scenario claims to cover something but does not.

---

## 1. Summary

### 1.1 Counts by priority and area

| Area | P0 | P1 | P2 | Total |
|---|---|---|---|---|
| Clients and lockfiles | 1 | 4 | 5 | 10 |
| Upstreams, integrity and TLS | 0 | 2 | 2 | 4 |
| Policy and tenancy | 0 | 1 | 5 | 6 |
| Managed sync and fleet | 0 | 4 | 4 | 8 |
| Server, database and load | 0 | 2 | 1 | 3 |
| Accounts, sign-in and portal | 0 | 4 | 7 | 11 |
| Deployment and operations | 0 | 3 | 1 | 4 |
| **Total** | **1** | **20** | **25** | **46** |

By kind: 33 new scenarios, 13 weaknesses in existing scenarios.

By where to write them: 8 new files, 1 harness change for every scenario, 33 as extra steps in written scenarios, 4 as extra steps in catalogue scenarios that are not written yet (E2E-023, 025, 037, 038).

### 1.2 Index

| # | Title | Pri | Area | Write it in |
|---|---|---|---|---|
| 040 | Lockfiles made through one firewall fail on another firewall | P0 | Clients | new file |
| 041 | yarn 1 sends no key with the keys-page `.npmrc` | P1 | Clients | E2E-012 |
| 042 | Python build requirements go through the firewall | P1 | Clients | new file |
| 043 | uv `exclude-newer` fails: PyPI JSON drops `upload-time` | P1 | Clients | E2E-001 |
| 044 | Lockfiles from the previous image after an upgrade | P1 | Clients | E2E-010 |
| 045 | Upstream serves tampered artifact bytes | P1 | Upstreams | E2E-014 |
| 046 | Bad certificates on outbound channels (MITM) | P1 | Upstreams | new file |
| 047 | Group lifecycle: move a member, delete a group | P1 | Policy | new file |
| 048 | A proxy or WAF answers 4xx on the sync API | P1 | Sync | E2E-008 |
| 049 | Large layers push the layers refetch past 8 MiB | P1 | Sync | new file |
| 050 | E2E-007 never reaches "pushed settings fail at start" | P1 | Sync | E2E-007 |
| 051 | E2E-007 never presses Resume | P1 | Sync | E2E-007 |
| 052 | A read-only or full Postgres stops revocations | P1 | Server | E2E-008 |
| 053 | Unauthenticated floods starve the sync API | P1 | Server | E2E-037 |
| 054 | Pre-account takeover: the attacker keeps a confirmed login | P1 | Accounts | E2E-019 |
| 055 | A stolen session becomes a permanent takeover | P1 | Accounts | E2E-019/020 |
| 056 | Invitation mail as a spam and phishing relay | P1 | Accounts | E2E-018 |
| 057 | A removed member's Activity disappears | P1 | Accounts | E2E-004 |
| 058 | Restore into a new Postgres cluster; settings revert | P1 | Ops | E2E-009 |
| 059 | Stock proxy settings in front of firewall and server | P1 | Ops | gateway variant |
| 060 | File-descriptor limit under the shipped unit | P1 | Ops | E2E-023 |
| 061 | Everyday npm with the keys-page `.npmrc` | P2 | Clients | E2E-002 |
| 062 | Re-lock while a block is active | P2 | Clients | E2E-012 |
| 063 | Outage with default client retries | P2 | Clients | E2E-014 |
| 064 | A blocked optional dependency is skipped silently | P2 | Clients | E2E-012 |
| 065 | Older clients common in CI images | P2 | Clients | new file |
| 066 | A resolver that never answers | P2 | Upstreams | E2E-014 |
| 067 | Outage longer than the metadata TTL | P2 | Upstreams | E2E-014 |
| 068 | Taking back loosening; allowed freeze and OSV exceptions | P2 | Policy | E2E-011, 003, 013 |
| 069 | The freeze runs out by itself | P2 | Policy | E2E-011 |
| 070 | PyPI sha256 file block from the portal | P2 | Policy | E2E-013 |
| 071 | A PyPI artifact URL learned from another tenant | P2 | Policy | E2E-013 |
| 072 | Network lock with a personal-account key | P2 | Policy | E2E-016 |
| 073 | No client credential leaves the firewall | P2 | Sync | harness |
| 074 | Two firewall replicas sharing one token | P2 | Sync | E2E-007 |
| 075 | A re-registered firewall keeps old settings unseen | P2 | Sync | E2E-025 |
| 076 | A firewall far from the server (slow link) | P2 | Sync | E2E-008 |
| 077 | A frozen Postgres (paused or cut off) | P2 | Server | E2E-008 |
| 078 | GitHub and Microsoft sign-in in the deployed config | P2 | Accounts | E2E-020 |
| 079 | Company IdP migration (issuer change) | P2 | Accounts | new file |
| 080 | Sign-in throttle with forged `X-Forwarded-For` | P2 | Accounts | E2E-016 |
| 081 | SMTP relay faults and STARTTLS downgrade | P2 | Accounts | new file |
| 082 | Back after sign-out shows a one-time secret | P2 | Accounts | E2E-017 |
| 083 | Lookalike organisation names | P2 | Accounts | E2E-038 |
| 084 | Accessibility of error pages, reflow, keyboard tasks | P2 | Accounts | a11y-axe |
| 085 | Standalone firewall with its own TLS | P2 | Ops | E2E-006 |

### 1.3 New suspect defects

These came out of the review. They are proposals: add them to `00-inventory.md` §1.3 and rule on them in D9.

| Proposed # | Defect | Scenario |
|---|---|---|
| F18 | The keys-page `.npmrc` has no `always-auth=true`, so yarn 1 sends no key | 041 |
| F19 | `GET /verify-email` consumes the token, confirms the squatter's password and builds the squatter's sign-up payload | 054 |
| F20 | Linking a sign-in method or turning TOTP off needs no fresh proof and sends no mail; a newly linked method counts as a second factor | 055 |
| F21 | Invitations skip the mail caps; the org name goes into the mail as is | 056 |
| F22 | After a member leaves or is removed, their Activity rows are hidden from every view | 057 |
| F23 | The sync `changes` call writes the report first, so a write failure stops the delta (revocations) | 052 |
| F24 | Any 401 from the server URL means "retired"; other 4xx make the firewall not ready | 048 |
| F25 | All stale layers are fetched in one call, which can pass the 8 MiB answer cap forever | 049 |
| F26 | The PyPI JSON page drops `upload-time` | 043 |
| F27 | Artifact references are local to one firewall, so lockfiles fail on any other firewall | 040 |
| F28 | Restore into a new cluster is not documented; `settings_revision` is not monotonic | 058 |
| F29 | Nothing raises `RLIMIT_NOFILE`; running out shows up as STORAGE_UNUSABLE | 060 |
| F30 | The mail outbox gives up after 10 tries with no final log line | 081 |
| F31 | Org names accept confusable, zero-width and bidi characters | 083 |
| F32 | An unknown `fwt_` token costs a 2 MiB body read and a DB lookup before any limit | 053 |
| F33 | `operations.md` §3a promises outage survival up to the max age; cached files stop at the TTL | 067 |
| F34 | One-time secrets are shown straight from the POST, with no post-redirect-get | 082 |

---

## 2. P0

### Clients and lockfiles

#### E2E-040 Lockfiles made through one firewall fail on another firewall

- **Priority:** P0. **Kind:** new scenario (3 findings merged). **Write it in:** a new file.
- **Fixture:** TLS (gateway with one round-robin name for fw1 and fw2), NPM, PYPI, one new firewall on an empty volume (`o.firewall()`); clients npm, bun, uv, pip.
- **Steps:**
  1. Through fw1 only, with clean caches, make lockfiles that record the firewall's own artifact URLs: `npm install --package-lock-only` (`resolved` is `/npm/artifacts/<ref>/...`), `bun install --lockfile-only`, `uv lock`, and a pip `--require-hashes` file with firewall URLs (the E2E-001 shape).
  2. Replay them with `npm ci`, `bun install --frozen-lockfile`, `uv sync --locked` and `pip install --require-hashes`: (a) through fw2, which has never listed these projects; (b) through the new firewall on an empty volume.
  3. Put fw1 and fw2 behind one name. Run 10 cold `pip install` and `uv sync` runs through it.
  4. Block one locked version. Repeat (a) and (b).
- **Expected:** Each replay installs, or gets a policy refusal, the same way on every firewall. Never a bare 404. The blocked version gets 403 BLOCKED everywhere. Behind one name, installs never fail at random.
- **Why:** `load_reference` (`src/artifacts/mod.rs:289`) answers 404 for any reference the firewall never stored, on purpose (SPEC §9). After rollout, teams re-lock through the firewall, so every committed lockfile names firewall-local URLs. A second firewall, a replacement or a lost volume then breaks every CI run. E2E-002, E2E-011 and E2E-012 replay only on the same warm firewall.
- **Decision first:** either a firewall resolves an unknown reference under policy (put the name in the URL, or refresh the project from the file name), or the docs say firewalls are not interchangeable, require sticky routing, and the client gets a clear "re-lock" error. Proposed F27.
- **Left out:** pnpm (its lockfile uses name and version, which works today); `poetry.lock` and pip-compile (they store hashes and list the index again); a changed `public_url` (a docs note about npm's `replace-registry-host`).

---

## 3. P1

### Clients and lockfiles

#### E2E-041 yarn 1 sends no key with the keys-page `.npmrc`

- **Priority:** P1. **Kind:** weakness in existing P0. **Write it in:** `e2e-012-lockfile-replay.mjs`, step 4.
- **Fixture:** NPM, client-js (yarn 1.22.22).
- **Steps:** Add a fresh `yarn add e2e-left` (no lockfile) on fw1 with the keys-page `.npmrc` copied exactly. Assert that it installs and that the firewall log names the key's account.
- **Expected:** yarn 1 works with the keys-page snippet. Either the snippet gets `always-auth=true`, or the page shows a yarn 1 line and `operations.md` §7 says so.
- **Why:** The keys page (`templates/keys.html:16-17`) prints only `registry=` and `_authToken`. yarn 1 sends the token for unscoped packages only with `always-auth`, so every yarn 1 install gets 401 in managed mode. §7 lists yarn 1 as supported. The defect is only written down in a test comment today.
- **Decision first:** number it (proposed F18) and rule on it in D9. The existing step 4 already asserts the correct behaviour and fails today.

#### E2E-042 Python build requirements go through the firewall

- **Priority:** P1. **Kind:** new scenario. **Write it in:** a new file (short).
- **Fixture:** PYPI with a vendored `flit_core` wheel; client-pip, client-uv, client-poetry.
- **Steps:**
  1. Serve a real `flit_core` wheel. Publish sdists with `requires = ["flit_core>=3.2"]`.
  2. With clean caches, pip, uv and poetry each install one of these sdists through fw1.
  3. Read the fakes request log.
  4. Put the newest `flit_core` under the freeze. Install again.
  5. Block every `flit_core` version. Install again.
- **Expected:** `flit_core` is fetched only through fw1, never directly from pypi.org, for all three clients. Step 4 builds with the older `flit_core`. Step 5 fails with the firewall's refusal.
- **Why:** Build backends are a known supply-chain path. Every E2E-001 sdist uses an in-tree backend with `requires = []`, so build isolation never fetches anything. If Poetry's isolated build ignores the configured source, it silently goes around the firewall.
- **Left out:** transitive dependencies, extras, markers, `requires-python`, yanked files. The firewall judges each request on its own; the rest is client behaviour or integration tests.

#### E2E-043 uv `exclude-newer` fails: PyPI JSON drops `upload-time`

- **Priority:** P1. **Kind:** new scenario. **Write it in:** `e2e-001-python-clients.mjs`, plus a unit test in `src/pypi/render.rs`.
- **Fixture:** PYPI with releases aged 1, 5 and 30 days; client-uv.
- **Steps:** Org freeze 3 days. Through fw1 with clean caches: `uv pip install --exclude-newer <10 days ago> pkg`; `uv lock` with `exclude-newer` in `pyproject.toml`; `uv sync --locked`.
- **Expected:** uv resolves the 30-day version. `uv.lock` keeps `upload-time`. Never "no versions found".
- **Why:** `json_file` in `src/pypi/render.rs` emits no PEP 700 `upload-time`, although the firewall reads it from upstream for its own policy (`src/pypi/mod.rs:890`). uv treats a file without an upload time as excluded, so every uv resolve with `exclude-newer` fails through the firewall. `exclude-newer` is common CI practice. Proposed F26.
- **Left out:** Renovate, pnpm and yarn age gates, `npm --before`.

#### E2E-044 Lockfiles from the previous image after an upgrade

- **Priority:** P1. **Kind:** weakness in existing P0. **Write it in:** `e2e-010-rolling-upgrade.mjs`, plus a golden-value unit test for `ReferenceId::compute` (`src/artifacts/reference.rs`).
- **Fixture:** PREV images, NPM, PYPI.
- **Steps:**
  1. Standalone, previous image: make a `package-lock.json` through the firewall and a pip `--require-hashes` file with artifact URLs.
  2. Upgrade on the same volume, as E2E-010 does.
  3. Run `npm ci` and `pip install --require-hashes` from those files.
  4. Block the locked version. Replay again.
- **Expected:** Step 3 installs with no change. Step 4 gives 403 BLOCKED, never 404. If the URL encoding changes, the release gate fails and the release notes name the break.
- **Why:** `reference_id` is a SHA-256 of an encoding (SPEC.md:252). Any change to that encoding, the artifact path or the reference rows changes every URL in customers' committed lockfiles, so all their CI breaks at upgrade. E2E-010 only reinstalls with fresh metadata. `operations.md` already records one such break.
- **Note:** a replay on a new image with an empty `data_dir` is the E2E-040 case.

### Upstreams, integrity and TLS

#### E2E-045 Upstream serves tampered artifact bytes

- **Priority:** P1. **Kind:** new scenario (2 findings merged). **Write it in:** `e2e-014-upstream-outage.mjs`.
- **Fixture:** NPM, PYPI, with the fakes' existing `corrupt` fault.
- **Steps:**
  1. Publish npm `T` 1.0.0 and a PyPI wheel `T` 1.0.0.
  2. Turn on `corrupt` for `registry.npmjs.org` `/T/-/` and for `files.pythonhosted.org`.
  3. Cold, on fw1 and fw2: `npm install T@1.0.0` and `pip install T==1.0.0`.
  4. Clear the fault. Repeat.
  5. With the file now cached, turn `corrupt` on again. Repeat.
  6. Read the firewall log, the decision log and the SIEM batches.
- **Expected:** Step 3: both clients fail with 502 INTEGRITY_MISMATCH and receive no bytes. Step 4: 200, and the bytes match the advertised digest. Step 5: 200 from the cache, with no upstream artifact request. The logs name INTEGRITY_MISMATCH.
- **Why:** Serving verified artifacts is the core promise. `operations.md` §9 calls a mismatch a security incident. The `corrupt` mode exists in `fixtures/fakes/main.mjs`, but no scenario uses it. The logic is integration-tested; this proves the shipped image with real clients.
- **Also:** add the PyPI sha256-mismatch case as an integration test in `tests/artifacts_verification.rs`. Coalescing, HEAD, Range and pins stay in integration tests.

#### E2E-046 Bad certificates on outbound channels (MITM)

- **Priority:** P1, nightly only. **Kind:** new scenario (2 findings merged). **Write it in:** a new file.
- **Fixture:** TLS: a second, untrusted CA and per-host certificate switching in `fixtures/fakes/main.mjs`; a gateway variant for sync; mailpit with an untrusted certificate.
- **Steps:** One channel at a time, the fake presents a certificate from the untrusted CA: `registry.npmjs.org`, `files.pythonhosted.org`, `api.osv.dev`, `sync.e2e.test`, `mail.e2e.test` (STARTTLS), `idp.e2e.test`, `api.pwnedpasswords.com`, the SIEM collector. For the registry and sync only, also an expired certificate and one with the wrong host name. Each time run a cold and a warm install, a sign-up, an SSO sign-in and a fresh firewall's first start.
- **Expected:**
  - Registry and files host: cold requests get 502 and nothing is cached. Warm requests behave as for an unreachable upstream.
  - OSV: fails open as documented, with a log line and "cannot reach OSV" on the fleet page.
  - Sync: treated as unreachable. A warm firewall serves stale; a fresh firewall stays 503 NOT_READY.
  - SMTP: no mail is sent and the row stays queued.
  - IdP: sign-in refused, no session. HIBP: "try again". SIEM: delivery fails and is counted.
  - No channel falls back to plain or unverified TLS.
- **Why:** Every scenario trusts the one e2e CA, so a regression to "accept any certificate", or to the wrong trust store in the image, passes every test. The inventory lists "TLS cert mismatch", "sync proxy certificate not trusted" and "TLS failure at first sync" with no scenario.
- **Check first:** lettre is built with `webpki-roots` only, so SMTP may not trust the e2e CA at all. That would also affect E2E-017's real-mail path.

### Policy and tenancy

#### E2E-047 Group lifecycle: move a member, delete a group

- **Priority:** P1. **Kind:** new scenario. **Write it in:** a new file (or extra steps in E2E-013).
- **Fixture:** NPM, SMTP.
- **Steps:**
  1. Groups Strict (blocks `X`) and Loose. Mia is in Loose; her key is warm on fw1 and fw2. Strict has a service key and an automation token.
  2. The org admin moves Mia to Strict.
  3. Moves her to No group.
  4. Deletes Strict.
- **Expected:** Step 2: Mia's cached key gets 403 for `X` within one interval on both firewalls. Step 3: her key follows the org policy. Step 4: Strict's service key and token get 401 within about a minute, and its members go to No group with the org policy. Every change is in `/audit`.
- **Why:** Moving people between groups is the everyday way policy gets stricter. Inventory A6 marks "Move member" and group delete as NONE. If cached keys keep the old group's policy, a stricter group silently does nothing. E2E-013 step 7 already found one stale-policy defect of this kind.
- **Open:** what happens to a pending invitation into a deleted group. Leave it out until decided.
- **Left out:** a group admin losing pages after a move (portal only, integration test).

### Managed sync and fleet

#### E2E-048 A proxy or WAF answers 4xx on the sync API

- **Priority:** P1. **Kind:** new scenario. **Write it in:** `e2e-008-server-outage.mjs`, as variants; plus an integration test of `request_changes` with a stub server.
- **Fixture:** TLS gateway with switchable sync variants (401 basic-auth, 403 WAF page, 404, 400); NPM.
- **Steps:** Warm stack, both firewalls serve known keys, install loops run. Make the sync gateway answer 401 itself (no server headers) for 2 intervals, then restore it. Repeat with 403, 404 and 400. Each time check `/health/ready`, known keys, the log, and recovery without a restart.
- **Expected:** Only an answer the server itself produced means "retired" or "refused". A proxy's own 4xx is treated as unreachable: serve from the cache, stay ready, log a warning, recover alone.
- **Why:** Today any 401 from the server URL marks the firewall retired, clears its key cache and refuses every key until restart (`src/managed/sync.rs:136`, `src/managed/mod.rs:632`). Two other 4xx in a row turn `/health/ready` to 503 (`src/tasks/policy_sync.rs:79`). One proxy mistake takes the whole fleet out of rotation, against the promise that a firewall whose server is only unreachable stays ready. Fixing F5 (persist "retired") would make this permanent.
- **Decision first:** how the firewall tells a server answer from a proxy answer (new D item, tied to F5). Proposed F24.

#### E2E-049 Large layers push the layers refetch past 8 MiB

- **Priority:** P1. **Kind:** new scenario. **Write it in:** a new file; plus an integration test in `src/managed` with a fake server that answers more than 8 MiB.
- **Fixture:** NPM; automation API through the TLS proxy; the E2E-039 generator for 5000-record blocklists with maximum-length names and reasons; a path-scoped fault on the sync proxy.
- **Steps:**
  1. Org Mallory (self sign-up) fills its org layer and 3 group layers with 5000 blocks each, maximum-length names and reasons (about 2.6 MB per layer).
  2. Install once with a key from each group through fw1, so fw1 holds all four layers.
  3. Acme and Globex have cached keys on fw1.
  4. In one interval: Mallory adds one block to each layer, Acme blocks `X`, the operator suspends Globex.
  5. Watch fw1 for 3 intervals.
  6. Variant: `/sync/layers` answers 5xx while `/sync/changes` works.
- **Expected:** Within 1 to 2 intervals Acme's key gets 403 for `X` and Globex's key gets 401 on fw1, the same as on a firewall without Mallory's layers. fw1 does not mark the server down. The fleet page does not flap.
- **Why:** `after_answer` fetches every stale layer in one `/sync/layers` call (`src/managed/mod.rs`). An answer over `MAX_ANSWER_BYTES` (8 MiB, `src/managed/client.rs`) becomes "unreachable", the server is marked down, cached policies are not rebuilt, and this repeats forever. Any free sign-up can stop other tenants' blocks and the operator's suspensions on a shared firewall, using only documented limits. Proposed F25.

#### E2E-050 E2E-007 never reaches "pushed settings fail at start"

- **Priority:** P1. **Kind:** weakness in existing P0. **Write it in:** `e2e-007-settings-push.mjs` (lines 28-30 say it is not covered).
- **Fixture:** SUP, NPM.
- **Steps:**
  1. Push `log_file_path = "<data_dir>/logs/d.ndjson"`. It applies (exit 75, restart).
  2. `docker stop` the firewall. Make `<data_dir>/logs` unwritable as root. `docker start` it.
  3. Do the same under systemd.
- **Expected:** `managed-settings.prev.toml` is restored. The log says "the pushed settings fail at start; restoring the previous ones". `/fleet` shows `failed_revision`. The rollout halts. The same revision is never applied again. The restart count stays at one (no crash loop).
- **Why:** This branch stops a bad fleet-wide push from crash-looping every firewall. Only an in-process test covers it (`tests/managed_sync.rs` `t_settings_rollback`). The catalogue entry promises it; the written scenario drops it.
- **Note:** stop and start is deterministic. Do not try to win a race against the exit-75 restart.

#### E2E-051 E2E-007 never presses Resume

- **Priority:** P1. **Kind:** weakness in existing P0. **Write it in:** `e2e-007-settings-push.mjs`, step 5 (lines 185-205).
- **Fixture:** SUP (a container with `restart: no`), NPM, two managed firewalls.
- **Steps:** In step 5 (firewall-norestart halted, Resume offered): start the stopped firewall by hand. Note whether the step settles by itself. Press "Resume: send them to it again".
- **Expected:** The firewall gets the settings, applies them and reports the revision. Then firewall-2 gets them and the rollout reaches Done. The audit log has a `rollout.resume` row.
- **Why:** Resume is the operator's only way out of the most common halt (a firewall that was down during its step). No scenario calls `/fleet/rollouts/{id}/resume`, and the audit row is never checked. Only a real firewall shows what happens when Resume re-sends a push it already wrote before exit 75.
- **Left out:** the refusals (Resume on a Done or failed rollout) go to `crates/probation-server/tests/admin_fleet.rs`.

### Server, database and load

#### E2E-052 A read-only or full Postgres stops revocations

- **Priority:** P1. **Kind:** new scenario. **Write it in:** `e2e-008-server-outage.mjs`; plus a server integration test (read-only test DB, call `/changes`, expect the delta with the revoked key).
- **Fixture:** NPM; Postgres control (`ALTER SYSTEM`); a small Postgres data volume on disk (never under `/tmp`).
- **Steps:**
  1. Keys K1 and K2 are cached on fw1 and fw2.
  2. Revoke K1. Within a second, make Postgres read-only: `ALTER SYSTEM SET default_transaction_read_only=on; SELECT pg_reload_conf()`.
  3. Watch for 3 intervals.
  4. Repeat with the Postgres volume full.
  5. Restore. Check that queued activity arrives.
- **Expected:** K1 is refused on fw1 and fw2 within one interval while Postgres can still be read. Activity arrives after recovery.
- **Why:** `changes` writes the report and activity before it computes the delta (`crates/probation-server/src/sync.rs:449-451`). Any write failure fails the whole call, so revocations stop while reads still work. A full disk is a normal incident. E2E-008 only stops Postgres completely. Proposed F23.
- **Left out:** readiness staying 200 is documented (`api.md:563`). A lock on `activity` needs a manual operator action.

#### E2E-053 Unauthenticated floods starve the sync API

- **Priority:** P1. **Kind:** new scenario (2 findings merged). **Write it in:** E2E-037 (not written yet; promote it to P1 and add these checks); plus a server integration test with a small pool.
- **Fixture:** TLS proxy with XFF as in the deploy example; NPM; a request-burst client at a modest rate (no CPU burners); a docker CPU limit on the server; a small pool size so the result is deterministic.
- **Steps:**
  1. Through the public gateway, send concurrent sign-in, sign-up and reset POSTs from many source addresses, and POSTs to `/api/v1/sync/changes` and `/lookup` with random `fwt_` tokens and 2 MiB bodies.
  2. During the flood: a never-seen Acme key installs through fw1 and fw2; Acme revokes key K.
  3. Record sync latency and the firewall logs.
  4. Repeat with the server limited to 1 to 2 CPUs.
- **Expected:** Sync stays under the firewall's request timeout (2 s). The new key gets 200, not 401 or LOOKUP_BUSY. K is refused within one interval. No firewall marks the server down. The portal may slow down or throttle. Unknown tokens are refused cheaply or limited per source address; or the docs say to restrict `/api/v1/sync` at the proxy and this scenario proves that it works.
- **Why:** One sqlx pool (10 connections, 1 s acquire timeout) and one runtime serve the portal, sync and automation. For any `fwt_` token, the server reads the body and runs a DB lookup before the source check and the rate limit (`sync.rs:204-233`), and the rate limit is per firewall. Argon2 permits can take every CPU. Anyone on the internet can stop new CI keys for all tenants and delay revocations. Proposed F32.

### Accounts, sign-in and portal

#### E2E-054 Pre-account takeover: the attacker keeps a confirmed login

- **Priority:** P1. **Kind:** weakness in existing P0 (2 findings merged). **Write it in:** `e2e-019-password-reset.mjs`, squat block.
- **Fixture:** SMTP (mail catcher with a link-prefetch mode), HIBP.
- **Steps:**
  1. The attacker signs up `victim@` with their own password, kind org, org name "VictimCorp".
  2. (a) The victim clicks the confirm link, as today. (b) Variant: a "scanner" opens every link in the mail once, with no cookies, before the human does (as Safe Links and Proofpoint do).
  3. In a fresh session, the attacker signs in with `victim@` and their password. Check `/account`, the place switcher and `/keys`.
  4. The real user clicks after the scanner.
  5. One-line checks: invitation and reset links still work after the scanner.
- **Expected:** The squatter's password never becomes the confirmed password of the victim's address. The victim's click does not create the attacker's org. A cookie-less GET confirms nothing (the page confirms with a POST). The real user's click works.
- **Why:** `verify_email` (`accounts.rs:544`) uses up the token on a GET, marks the attacker's password as verified and builds the attacker's sign-up payload. After any click, or a mail scanner's prefetch, the attacker signs in fresh with a confirmed `victim@` login and owns "VictimCorp". F7 only ends the old session.
- **Decision first:** proposed F19 and a D9 ruling (confirming needs setting a password, or confirming drops the sign-up password and payload).

#### E2E-055 A stolen session becomes a permanent takeover

- **Priority:** P1. **Kind:** new scenario. **Write it in:** `e2e-019-password-reset.mjs` or `e2e-020-oauth-sso.mjs`.
- **Fixture:** fake OIDC as Google and GitHub with a victim and an attacker identity; SMTP; two browser contexts.
- **Steps:**
  1. Org admin Alice has a password and TOTP. The attacker has a copy of one of her live sessions.
  2. From that session, link the attacker's Google identity (`POST /account/link/google` and the fake IdP round trip).
  3. Alice changes her password, and a global admin resets her authenticator. Both end all sessions.
  4. The attacker signs in with "Continue with Google".
  5. Check `/org`, `/policy`, the automation pages, the audit log and the mail outbox.
- **Expected:** Linking needs a fresh proof (password and TOTP, or a fresh sign-in with an already linked method) and sends a notice mail. A password change, reset or TOTP reset removes or flags methods linked since then. A newly linked method does not count as a second factor until proven. In step 4 the attacker gets no admin access.
- **Why:** `/account/link` and `/account/totp/disable` need only a CSRF token and a session (`portal/account.rs:101`, `:369`). `link_method` (`accounts.rs:2487`) ends no sessions and sends no mail. An OAuth sign-in skips TOTP by design. One stolen session survives every documented recovery step and gets around the C24 admin hold-back.
- **Decision first:** proposed F20 and a D9 ruling. The step-up checks themselves belong in integration tests; e2e shows the backdoor survives recovery.

#### E2E-056 Invitation mail as a spam and phishing relay

- **Priority:** P1. **Kind:** new scenario. **Write it in:** `e2e-018-invite-new-hire.mjs`.
- **Fixture:** SMTP.
- **Steps:**
  1. A free sign-up creates an org named `Acme IT: your account is locked, verify at https://evil.example` and turns on TOTP.
  2. It sends more than 5 invitations to one address, and more than 20 to different addresses, within 15 minutes.
  3. Read the mail catcher.
- **Expected:** Invitations count against the mail caps (5 per address and 20 per client per 15 minutes) or a cap of their own. The org name in the mail is quoted, so it cannot look like the operator's instructions or a link.
- **Why:** `tenancy::invite` queues every invitation with no cap check (`tenancy.rs:1453-1510`); the caps apply only to sign-up, resend and reset. Anyone can send mail from the operator's signed domain with their own text. That ruins the domain's mail reputation (confirm and reset mail goes to spam for every customer) and allows phishing under the operator's name. Proposed F21.

#### E2E-057 A removed member's Activity disappears

- **Priority:** P1. **Kind:** new scenario. **Write it in:** `e2e-004-offboarding.mjs`; plus a Postgres integration test for the Activity query.
- **Fixture:** NPM, PYPI.
- **Steps:**
  1. Before offboarding, record a Blocked row for the member who will be removed and one for the member who will leave.
  2. Remove one; approve the other's leave (as E2E-004 does).
  3. Use their revoked keys on fw1 and fw2 (401).
  4. The org admin opens `/activity`.
- **Expected:** The org admin still sees the old Blocked rows and the new "Refused: the key was revoked" rows for the full retention (90 days by default), with the person's email or key name.
- **Why:** `end_membership` deletes the membership row. After that `place_org('user', id)` returns NULL (`0001_init.sql:319`), and the Activity query filters on it (`portal/activity.rs:118-127`). All history and all later refusals vanish from every view. After offboarding, "is an ex-employee's key still in use?" is the main question an admin asks Activity. Proposed F22.

### Deployment and operations

#### E2E-058 Restore into a new Postgres cluster; settings revert

- **Priority:** P1. **Kind:** new scenario. **Write it in:** `e2e-009-backup-restore.mjs`, as a variant.
- **Fixture:** DBR; a second Postgres container whose schema owner is not a superuser; SUP; NPM.
- **Steps:**
  1. `pg_dump -Fc` from cluster A.
  2. Restore into an empty cluster B as the schema owner, following `operations.md` §5 word for word.
  3. Run `after-restore`, start the server, check the app role's grants and that `audit_log` is still append-only.
  4. Variant on the same cluster: push settings S1 before the backup and S2 after it. Restore. Watch the next sync.
- **Expected:** The docs give the exact steps for a new cluster (roles, `--no-owner` or `--role`, grants), and the drill passes with them. In the variant, the move back to S1 follows rollout order or is documented, and `/fleet` shows it. A firewall never silently keeps S2 while the server says something else.
- **Why:** A disaster restore rarely lands in the same cluster. `probation_app` is created only by the first migrate (`0001_init.sql:6-13`) and the dump holds no roles, so the restore fails on a new cluster, and §5 says only "Restore the database". `settings_revision` is not monotonic: the server sends any revision that differs, so every firewall gets S1 and exits 75 at the same time, outside rollout gating. E2E-009 restores into the same cluster with no push before the backup. Proposed F28.

#### E2E-059 Stock proxy settings in front of firewall and server

- **Priority:** P1. **Kind:** weakness in existing P0. **Write it in:** a stock variant of `tests/e2e/compose/gateway.conf.template` (used by E2E-005 and E2E-014, and by E2E-027 once written).
- **Fixture:** TLS gateway with stock nginx defaults (60 s read timeout, buffering on, 1m body); one load-balancer profile with a 60 s idle timeout; NPM, PYPI, NET.
- **Steps:**
  1. Add the stock gateway variant.
  2. Run the E2E-027 cold large artifact through it (the firewall verifies before it sends the first byte).
  3. Run a slow upstream.
  4. Run the tuned template with exactly the settings `operations.md` lists.
- **Expected:** Installs work behind stock settings, or `operations.md` §6 lists the proxy settings needed (timeouts, body size, buffering) and step 4 proves them.
- **Why:** The e2e gateway sets `proxy_read_timeout 1200s` and turns buffering off, which hides failures. Behind a stock 60 s timeout a cold multi-GB wheel gets 504, because the client gets no byte until verification ends. §6 requires a proxy but gives no settings, and §18 allows a 2 MiB sync body, more than nginx's 1m default.
- **Left out:** HAProxy; the sync body over 1 MiB (integration test with a fake 413, after checking the real size); `%2F` decoding.

#### E2E-060 File-descriptor limit under the shipped unit

- **Priority:** P1. **Kind:** new scenario. **Write it in:** E2E-023 (not written yet), as a variant; plus an integration test run under `prlimit`.
- **Fixture:** SUP (the systemd container from E2E-007, `deploy/probation.service` unchanged); a container with soft `nofile` 1024; NET (slow clients); NPM.
- **Steps:** Open about 1000 slow client connections plus cold downloads with `max_upstream_requests = 32`, with the log file and SIEM on. Run under the unchanged systemd unit, then under the container runtime default.
- **Expected:** Extra clients get a clean 503 busy. Never STORAGE_UNUSABLE, failed artifact writes or failed SQLite opens. Readiness recovers alone. The firewall raises its soft limit at start, or the unit sets `LimitNOFILE`, or `check-config` warns.
- **Why:** Rust does not raise `RLIMIT_NOFILE`, and nothing in `src/` or `deploy/` does. The default `max_active_requests` (1024) equals the usual soft limit. A failed content write marks the store unhealthy (`src/store/mod.rs:566`), and then every request, cached ones too, gets STORAGE_UNUSABLE (`src/http/mod.rs:117`). The outage looks like a disk fault and sends operators the wrong way. Proposed F29.

---

## 4. P2

### Clients and lockfiles

#### E2E-061 Everyday npm with the keys-page `.npmrc`

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-002-npm-block-unblock.mjs` (or E2E-033 when written); plus a contract test that the rendered `.npmrc` has `audit=false`.
- **Fixture:** NPM; npm 10, 11, 12, pnpm, bun.
- **Steps:** With the keys-page `.npmrc` copied exactly (audit left on), run `npm install` on npm 10, 11, 12, pnpm and bun. Then run `npm publish` and `npm login` against the firewall and read the fakes log.
- **Expected:** Each install exits 0 without a long wait, with nothing spurious in the decision log or Activity. publish and login are refused with a clear status, and nothing reaches upstream.
- **Why:** Every written npm step passes `--no-audit`, but the keys page lacks the `audit=false` that `operations.md` §7 shows. The firewall routes only GET under `/npm/-/`, so the default audit POST has never been tried.
- **Left out:** proxying the advisories and keys endpoints, and `npm audit signatures`, are product decisions, not tests.

#### E2E-062 Re-lock while a block is active

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-012-lockfile-replay.mjs`, as step 3b.
- **Fixture:** NPM, PYPI; the client containers E2E-012 already uses.
- **Steps:** With `e2e-left` 1.1.0 still blocked, run one documented update command per client (`npm update`, `pnpm update`, `yarn up`, `bun update`, `uv lock --upgrade-package`, `poetry update`). Replay each new lock with fresh caches on fw1 and fw2.
- **Expected:** Each lock names 1.0.0. The replays pass on both firewalls. Activity shows only the earlier refusal. If a tool's plain update fails, §7 gives the command that works.
- **Why:** This is what every team does after a block. E2E-012 stops at "the replays fail".

#### E2E-063 Outage with default client retries

- **Priority:** P2. **Kind:** weakness in existing P0. **Write it in:** `e2e-014-upstream-outage.mjs` (E2E-003, 015 and 016 also turn retries off).
- **Fixture:** NPM, PYPI, NET.
- **Steps:** One `npm install` and one `pip install` with default retry settings, under an upstream hang and under 5xx. Record the wall time.
- **Expected:** Each fails or recovers within a bound that the ops docs state.
- **Why:** All outage runs use `--fetch-retries=0` or `--retries 0`, unlike real CI. pip retries 502 to 504 five times, so a 30 s metadata deadline times the retries can stall CI for minutes.

#### E2E-064 A blocked optional dependency is skipped silently

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-012-lockfile-replay.mjs`, as a variant; plus a unit check that `os` and `cpu` survive in `src/npm/render.rs`.
- **Fixture:** NPM with one optional platform package (`os`, `cpu` fields).
- **Steps:** `e2e-app` has an optional dependency on a linux-x64 package. Block that package. Run `npm ci` and `bun install`.
- **Expected:** The client exits 0 (its own behaviour), Activity records the refusal, and the docs warn that a blocked optional dependency is skipped without an error.
- **Why:** E2E-012 claims every replay "fails loudly", but for optional dependencies npm exits 0. The docs do not mention it.

#### E2E-065 Older clients common in CI images

- **Priority:** P2, nightly. **Kind:** new scenario. **Write it in:** a new file: a version matrix that runs the core of E2E-001, 002 and 012.
- **Fixture:** NPM, PYPI, new client containers (the Dockerfiles already take `NODE_IMAGE` and `PIP_VERSION` build args): pip 22.0.2 (Ubuntu 22.04), pip 23.0.1 (Debian 12), npm 8 or 9. Poetry 1.8, yarn 3 and pnpm 8 are optional.
- **Steps:** In each container: keys-page config, install, fallback after a version block, frozen-lockfile replay of a blocked pin, 401 after the key is revoked.
- **Expected:** Each passes, or the docs give a minimum version per client and the failure is clean (no bypass to the public registry, no hang, no prompt).
- **Why:** Distro pip and old Node images are common in CI. Only npm 10 to 12 and pip 25 to 26 are tested.

### Upstreams, integrity and TLS

#### E2E-066 A resolver that never answers

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-014-upstream-outage.mjs`, as a DNS variant.
- **Fixture:** NET plus a dnsmasq container used as the firewall's resolver; NPM, PYPI.
- **Steps:** Make the resolver drop queries for `registry.npmjs.org`. Run cold installs, warm installs and health probes. Then one split-horizon answer (one public and one RFC 1918 address).
- **Expected:** Cold requests fail within about 5 s. Warm installs, snapshot writes and `/health` stay fine. Recovery needs no restart. The split-horizon answer is refused with a log line that names the address.
- **Why:** `lookup_host` runs `getaddrinfo` on tokio's blocking pool. The connect timeout drops the future, not the thread, so threads may pile up under a cold CI fan-out. Corporate split DNS is the realistic way the origin guard causes an outage.
- **Left out:** SERVFAIL, NXDOMAIN and private answers are already covered.

#### E2E-067 Outage longer than the metadata TTL

- **Priority:** P2. **Kind:** weakness in existing P0. **Write it in:** `e2e-014-upstream-outage.mjs`, step 4 (firewall-2 already runs with a 5 s TTL); plus a docs fix to `operations.md` §3a.
- **Fixture:** NPM, PYPI with reset faults.
- **Steps:** On firewall-2, warm a lockfile project and a `--require-hashes` project. Refuse all registry connections. After the TTL, run `npm ci` and `pip install`.
- **Expected:** The test asserts the real behaviour (cached artifacts get 502 after the TTL), and §3a is corrected to match.
- **Why:** Every artifact request needs a fresh project snapshot (`src/artifacts/mod.rs:181`); after the TTL a failed revalidation is a refusal. §3a says downloaded files are never affected and that a longer max age gives longer survival. Operators size their outage tolerance from it. Proposed F33.

### Policy and tenancy

#### E2E-068 Taking back loosening; allowed freeze and OSV exceptions

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-011-release-age-freeze.mjs`, `e2e-003-osv.mjs`, `e2e-013-layered-policy.mjs`.
- **Fixture:** NPM, PYPI, OSV.
- **Steps:**
  - E2E-011: after `restoreSwitch`, both firewalls hold 1.1.0 again (403 HELD) and Activity shows Held.
  - E2E-003: after `setPlatformSwitch(false)`, the build-agent key is refused the MAL version again, and Activity shows Blocked, not `would_block`.
  - E2E-013: with the switches on, add an allowed exact-version freeze exception and a whole-package OSV exception. A newly flagged MAL version passes under the OSV exception. Turn the switches off: both exceptions stop.
- **Expected:** As above, within one interval, on both firewalls, from warm caches.
- **Why:** Taking back delegated loosening is the platform's emergency control. Today the switches are reset only in `finally` blocks and never checked. Freeze and OSV exceptions are tested only for refusal.

#### E2E-069 The freeze runs out by itself

- **Priority:** P2. **Kind:** weakness in existing P0. **Write it in:** `e2e-011-release-age-freeze.mjs`.
- **Fixture:** NPM, PYPI with relative publish times.
- **Steps:** Publish a version that reaches the freeze about 60 s after start. Warm both firewalls and make a lockfile pinning it (403 HELD). Change no policy. Poll past `eligible_at`, then run `npm install`, `npm ci` of the lockfile and `pip install ==new`.
- **Expected:** Released within seconds of `eligible_at` on both firewalls, from warm caches, and `latest` moves.
- **Why:** Waiting out the freeze is the normal CI path after HELD, but E2E-011 releases only by setting the freeze to 0. The logic is tested on a fake clock; this proves the real clock wiring in the image.

#### E2E-070 PyPI sha256 file block from the portal

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-013-layered-policy.mjs` (or E2E-001), one step.
- **Fixture:** PYPI.
- **Steps:** Add an org-layer sha256 block on the wheel of a release that has a wheel and an sdist. Check the HTML and JSON listings, the artifact URL, a `--require-hashes` replay, pip by default, and pip `--only-binary :all:`.
- **Expected:** The wheel is gone from both listings. Its URL and the replay give 403 BLOCKED. pip falls back to the sdist. `--only-binary` fails.
- **Why:** Inventory A2 lists the direct URL of a digest-blocked file and the sha256 block as gaps. No P0 uses a PyPI sha256 block.
- **Left out:** a new wheel added to an old release (`tests/pypi_metadata.rs:502` covers it).

#### E2E-071 A PyPI artifact URL learned from another tenant

- **Priority:** P2. **Kind:** weakness in existing P0. **Write it in:** `e2e-013-layered-policy.mjs`.
- **Fixture:** NPM, PYPI.
- **Steps:** Add: Bea gets 403 on `pyArtifact` after org A's 1.0 exception. Bea's simple page for `py` has no 1.0.0 link. Bea's abbreviated packument for P is still 403. `/pypi/simple/` is empty for both keys.
- **Expected:** As listed.
- **Why:** `pyArtifact` came from org A's listing and is only checked for Mia. That is exactly how a cross-tenant leak through shared caches would show (threat T8).
- **Left out:** single flight, ETag and each document form (covered in `tests/managed_mode.rs`).

#### E2E-072 Network lock with a personal-account key

- **Priority:** P2. **Kind:** weakness in existing P0. **Write it in:** `e2e-016-network-lock-proxies.mjs`.
- **Fixture:** TLS, NPM.
- **Steps:** With Acme's office range approved, a personal-only login's key installs from inside the range and from outside.
- **Expected:** Inside: 403 naming the office address. Outside: 200. The personal account's Activity shows "Refused by a network lock (used from <office>)".
- **Why:** `portal-guide` §3.10 names this as the main use of the lock. The firewall side is tested; the real server answering "no org" for a personal key, and the Activity row, are not.

### Managed sync and fleet

#### E2E-073 No client credential leaves the firewall

- **Priority:** P2. **Kind:** new scenario. **Write it in:** the harness (`fixtures/fakes/main.mjs` and global teardown), so it runs in every scenario.
- **Fixture:** NPM, PYPI, OSV.
- **Steps:**
  1. The fakes' `/log` records whether `authorization`, `proxy-authorization` or `cookie` arrived (not the values).
  2. At teardown, assert that no NPM, PyPI or OSV request had any of them.
  3. Search the firewall container stdout and the decision NDJSON for every `prb_` key the run created, and for its base64 Basic form.
- **Expected:** Nothing found.
- **Why:** SPEC §7 forbids sending client credentials upstream. `tests/key_canary.rs` proves it in-process, but a regression only in the image (release log level, proxy environment) passes every e2e test. Closes inventory A3 "Key canary: shipped image's stdout".

#### E2E-074 Two firewall replicas sharing one token

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-007-settings-push.mjs`, as a variant, after the decision.
- **Fixture:** NPM, PYPI, a load balancer with two upstreams, SUP.
- **Steps:** Two containers with one config and one token file behind one host name. Install. Push settings to "that" firewall. Watch `/fleet` and the restarts.
- **Expected:** The server notices one token used by two instances and flags it, or the docs forbid it and say "one registration per replica". A push never restarts both replicas at once.
- **Why:** Sharing a secret across an autoscaling group is the default way people build HA. Nothing tells the replicas apart (no instance id), so a push restarts them all together.
- **Decision first:** a docs rule, or server-side detection (then an integration test).

#### E2E-075 A re-registered firewall keeps old settings unseen

- **Priority:** P2. **Kind:** new scenario. **Write it in:** E2E-025 (not written yet).
- **Fixture:** NPM, SUP.
- **Steps:** Push `max_active_requests` to firewall-1. Do the documented re-register and token swap (needed after a re-IP or NAT change). Read the overlay file, the value in effect and what `/fleet` shows for the new entry. Push to the new entry.
- **Expected:** The server and the firewall agree on which settings are in effect, and `/fleet` shows it.
- **Why:** The overlay stays in `data_dir`. A new fleet entry has `settings_revision` 0, and the server sends no push in that case (`sync.rs:596`). So the old settings stay in force, and the fleet page records nothing.
- **Left out:** "stale but ready" on a source refusal is by design (`api.md:216`); see F3.

#### E2E-076 A firewall far from the server (slow link)

- **Priority:** P2, nightly. **Kind:** new scenario. **Write it in:** `e2e-008-server-outage.mjs`, as a link-profile variant; plus an integration test with a throttling proxy and a sizing rule in `operations.md`.
- **Fixture:** NET (netem or a throttling proxy on the firewall-2 sync path); E2E-039 large-layer data.
- **Steps:** Set 150 ms round trip, 2 Mbit/s up, 1% loss. Build an activity backlog during a 5-minute server stop, then restore the link. Revoke a key.
- **Expected:** The backlog drains and the revocation arrives, or `/fleet` and a log line show that syncs keep failing, and the docs give a sizing rule.
- **Why:** One deadline (`request_timeout_seconds`, default 2) covers TLS, a 2 MiB upload and an 8 MiB answer (`src/managed/sync.rs:123-135`). Branch offices and other regions are normal.

### Server, database and load

#### E2E-077 A frozen Postgres (paused or cut off)

- **Priority:** P2. **Kind:** weakness in existing P0. **Write it in:** `e2e-008-server-outage.mjs` (step 4 only stops Postgres).
- **Fixture:** NET (`docker pause`, `docker network disconnect`).
- **Steps:** With installs and portal traffic running: `docker pause postgres`; separately, disconnect it from the network. Send portal, automation and sync calls and `/health/ready`. Send SIGTERM to the server during the freeze. Unpause.
- **Expected:** New requests get 5xx in about 1 s. `/health/ready` answers 503 within 2 s. Firewalls serve stale. SIGTERM exits within 20 s. Recovery needs no restart, and the pool is not stuck.
- **Why:** A managed-database failover looks like this. New requests are bounded, but a query already running when the freeze starts has no bound in the client.

### Accounts, sign-in and portal

#### E2E-078 GitHub and Microsoft sign-in in the deployed config

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-020-oauth-sso.mjs`.
- **Fixture:** OIDC fake extended with GitHub OAuth, `api.github.com/user` and Microsoft `common` discovery; `[portal.github]` and `[portal.microsoft]` in `tests/e2e/compose/server.toml`.
- **Steps:** One GitHub sign-up and one Microsoft `common` sign-up in Chromium.
- **Expected:** Logins are created as `portal-guide` §1.6 says.
- **Why:** The compose file configures only Google. The real call to `api.github.com` (the only non-OIDC path) has never run; integration tests replace it with a fake.
- **Left out:** the Microsoft issuer check, link and unlink, CSRF (covered in `accounts.rs` tests); the second-factor rule (integration test).

#### E2E-079 Company IdP migration (issuer change)

- **Priority:** P2. **Kind:** new scenario. **Write it in:** a new file, after the decision; the core check as an integration test next to `T-portal-sso-removed-not-rejoined`.
- **Fixture:** OIDC with two issuers, SMTP, NPM.
- **Steps:** Acme uses issuer A. Ann (group Backend) and Ben joined through it; Carl was removed. Switch Acme to issuer B, which has the same people. All three sign in at `/o/acme`. Check members, groups, keys and the audit log.
- **Expected:** Either identities carry over, or the admin sees both entries for the same person and a clear way to clean up. Carl cannot rejoin through B without a new invitation (or the docs say removals are tied to the issuer). Old logins' keys stop or are listed for revocation.
- **Why:** Logins are matched only by issuer and subject, and removals are recorded against the old login and old subject. After the change, removed people rejoin, and old keys stay live with no IdP control. Moving from Okta to Entra is a routine company event.

#### E2E-080 Sign-in throttle with forged `X-Forwarded-For`

- **Priority:** P2. **Kind:** weakness in existing P0. **Write it in:** `e2e-016-network-lock-proxies.mjs`, step 6.
- **Fixture:** TLS, SMTP.
- **Steps:** Add a changing `X-Forwarded-For` header to the step 6 spray. Then send 100 failures with `X-Forwarded-For` set to the victim's address. The victim signs in.
- **Expected:** Still 429 after the limit. The victim is not locked out.
- **Why:** Nobody has tested whether the real portal gateway appends to or passes on a header the client sent. Changing XFF and spoofing the victim are the first things an attacker tries.

#### E2E-081 SMTP relay faults and STARTTLS downgrade

- **Priority:** P2. **Kind:** new scenario. **Write it in:** a new file; plus a unit test and docs fix for the outbox limit.
- **Fixture:** SMTP: mailpit variants (stopped, no STARTTLS, untrusted certificate) and a small scriptable SMTP fake for a hang and 4xx/5xx answers.
- **Steps:** For each fault: sign up, request a reset, send an invitation. Restore mail. Restart the server while the outbox is sending.
- **Expected:** Pages answer fast. No mail goes out without TLS. Rows retry and arrive after recovery. A restart in the middle of sending loses nothing (at most a duplicate with the same link). The mail timeout holds against a hanging relay.
- **Why:** Confirm, reset and invitation links are credentials, and only the happy path of real SMTP is tested. The outbox also drops a row after 10 tries (about 4 hours) with no final log line, though `operations.md` says mail "waits in the email_outbox table". Proposed F30.

#### E2E-082 Back after sign-out shows a one-time secret

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-017-browser-signup.mjs`; plus an integration test for a repeated POST.
- **Fixture:** NPM.
- **Steps:** In Chromium: create a key, sign out, press Back. Do the same on the backup-codes page.
- **Expected:** After sign-out, Back never shows the secret or the backup codes.
- **Why:** Keys, firewall tokens and TOTP set-up show the secret straight from the POST, with no post-redirect-get. Only a real browser shows what its page cache does with no-store pages. The integration test covers the rest: a Reload repeats the POST and creates a second live key or firewall token, and TOTP set-up replaces the backup codes each time. Proposed F34.

#### E2E-083 Lookalike organisation names

- **Priority:** P2. **Kind:** new scenario. **Write it in:** E2E-038 (not written yet), one step; the main check as a unit test of `org_name` and `org_name_problem`.
- **Fixture:** SMTP.
- **Steps:** Next to an existing "Acme Corp", create orgs named "Acme Cоrp" (Cyrillic о), "Acme​Corp" (zero-width space) and one with U+202E. Invite the victim. Look at `/invite` and the place switcher.
- **Expected:** These names are refused or normalised (NFKC, a confusable check, no invisible or direction characters), or the UI tells them apart.
- **Why:** `org_name` only collapses white space (`accounts.rs:245`), so U+200B passes. A victim who picks the lookalike creates keys under the attacker's policy, and the attacker sees the victim's blocked package names. The C37 claim that two places never read alike is false. Proposed F31.
- **Left out:** a C-locale Postgres; labels of same-email logins in admin lists.

#### E2E-084 Accessibility of error pages, reflow, keyboard tasks

- **Priority:** P2. **Kind:** weakness in existing scenario. **Write it in:** `a11y-axe.mjs` (`tests/e2e/a11y/axe.mjs`).
- **Fixture:** none beyond the a11y stack.
- **Steps:**
  1. Run axe on the 403 refusal, "form has expired", 404, the 503 "portal unavailable", the 409 policy conflict, `/invite` accept, `/reset/confirm` with an error, the Confirmed page and the revoke-keys confirmation.
  2. Check reflow at 320 CSS px and 200% zoom on `/org`, `/admin`, `/fleet` and `/policy`.
  3. Keyboard only: invite, change role, move to a group, delete a group, revoke a key, retire a firewall. After a server error, focus or a live region reaches the alert.
- **Expected:** No axe violations. No horizontal page scroll. Every task can be finished by keyboard, and errors are announced.
- **Why:** The walk covers only seeded happy pages. The 503 answer is plain text with no `lang` or title; the 404 and 403 pages have no stylesheet or skip link (`portal/mod.rs`). Reflow is part of the WCAG 2.2 AA claim (C84).
- **Left out:** confirmations on one-click destructive buttons (product decision); the 503 content type (unit test).

### Deployment and operations

#### E2E-085 Standalone firewall with its own TLS

- **Priority:** P2. **Kind:** new scenario. **Write it in:** `e2e-006-standalone-image.mjs`, as a variant.
- **Fixture:** NPM, PYPI; a certificate from the e2e CA; no gateway.
- **Steps:** Run the standalone image with `tls_cert_path`, `tls_key_path` and `public_url` on its https name. npm, pip, uv and poetry install, trusting the e2e CA. Swap the certificate files: the old one is served until a restart, the new one after it.
- **Expected:** Installs work over the firewall's own TLS, download links use `public_url`, and a renewed certificate takes effect only after a restart, as documented.
- **Why:** `operations.md` §6 documents this path for standalone use, but every e2e firewall sits behind the gateway, and the in-process test accepts any certificate.
- **Left out:** cooldown, OSV and hash blocks (same engine as managed mode); key without certificate and CLI exit codes (integration tests).

---

## 5. Combined plan

### 5.1 What to write next

Write next: all P0 and P1 work that is still unwritten.

- From the catalogue: E2E-021 to E2E-030, and E2E-037 promoted to P1 (it carries E2E-053).
- Not in a writer package: E2E-031 already exists as `canary-live.mjs`, and E2E-032 is release-workflow work.
- From this file: E2E-040 to E2E-060.

Later, in the weekly run: catalogue E2E-033 to 036, 038 and 039, plus E2E-061 to E2E-085. Most of those are a few extra steps each, about 60 minutes of scenario time in total.

Before writing, get the D9 rulings this plan depends on: F18 to F25 and F27 to F29. A test is written to the correct behaviour and may fail until the product is fixed. Scratch copies, build output and data volumes go on disk next to the project, never under `/tmp`.

### 5.2 Work packages

Five packages. Each one fits one writer, and similar fixtures are kept together. The time is the added nightly scenario time, in minutes.

| Package | Scenarios | Fixtures | Decisions it waits on | Added time |
|---|---|---|---|---|
| **WP1 Clients and lockfiles** | E2E-040, 041, 042, 043, 023, 026, 060 | shared stack, NPM, PYPI, all client containers, a fresh firewall, round-robin gateway, systemd container (060) | F27 (040), F18 (041) | about 25 |
| **WP2 Upstreams, proxies and TLS** | E2E-045, 046, 059, 027, 028 | own stack, fake faults (`corrupt`, throttle), second CA with per-host certificates, stock gateway variant, mirror host | none | about 26 |
| **WP3 Sync and fleet faults** | E2E-048, 049, 050, 051, 052, 024, 025 | own stacks, SUP, sync-proxy variants, Postgres control, small on-disk volumes, the E2E-039 blocklist generator | F24 (048), F5 (025) | about 31 |
| **WP4 Restore, upgrade, purge and load** | E2E-058, 044, 022, 037 with 053 | DBR, second Postgres cluster, PREV images, SQL back-dating, request-burst client, CPU limits | F28 (058) | about 23 |
| **WP5 Tenancy, accounts and portal** | E2E-047, 054, 055, 056, 057, 021, 029, 030 | shared stack, SMTP, OIDC, Chromium | F19, F20, F21, F22 | about 24 |

Total: 32 scenarios (21 from this file, 11 from the catalogue), about 130 minutes of scenario time.

Effect on the nightly run:

- If each package gets its own stack and they run in parallel, the nightly wall time grows by about **35 minutes** (the longest package, WP3, plus stack start).
- On today's 3-stack layout it grows by about 45 minutes. That goes past the D4 budget of 90 minutes, so either run 5 stacks or move E2E-046 and E2E-060 to the weekly run.
