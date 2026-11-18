# Security review (re-check r2)
Verdict: FIX FIRST
Subject and scope: slice 30 as committed at b02e088 (HEAD 2115a17 adds docs only; working tree clean apart from an untracked code-review-r2.md). Bounded recheck of the claims behind SEC-1..SEC-9 and the new surface (the `osv` object in FirewallReport, the leader writing into the shared cache past a request's deadline). Static read only; no command run. Files read: crates/probation-server/src/osv.rs, crates/probation-policy/src/osv_key.rs, crates/probation-server/src/sync.rs (`osv_caller`, `firewall_identity`, `source_of`, `source_address`, `record_report`), src/osv/mod.rs (`spawn_central`, `central_http_client`, `central_base`), src/osv/batcher.rs (`send_central`), src/lib.rs:330-375, src/main.rs, crates/probation-policy/src/api.rs (`OsvReport`).
Fingerprints (sha256 prefix): osv.rs b9779313, osv_key.rs 45c0dc5f, sync.rs 9e56e7e5, osv/mod.rs 98df10dc, batcher.rs b30fc65d. Unchanged during review: yes (recorded once, at the start).
Summary: open: SEC-2 (partly fixed; the retry cannot help a slow leader), NEW-1 (the auth gate is a pre-auth DoS lever), NEW-2 (a slow body holds a parse permit with no timeout). Hardening/residual: SEC-5, SEC-1 (PyPI only). Closed: SEC-3, SEC-4 (except NEW-2), SEC-8, SEC-9, and the new surface.

## Status per prior finding
| ID | Status | One line |
|---|---|---|
| SEC-1 | closed for npm; residual unknown for PyPI (Low) | limits 1024/1024 |
| SEC-2 | open (Medium, plausible), partly fixed | chunking and retry exist, but do not cover a slow leader |
| SEC-3 | closed as written; its replacement risk is NEW-1 | throttle is now cosmetic |
| SEC-4 | closed, with NEW-2 | buckets are right; the parse permit has a hole |
| SEC-5 | open as hardening (Low/Medium) | the global budget is itself a lever |
| SEC-6, SEC-7 | unchanged, user decisions | not re-reviewed |
| SEC-8 | closed (Info residual) | own client; seam not feature-gated |
| SEC-9 | closed | pages followed to 10 |

## Findings

### SEC-1 closed for npm, residual PyPI (Low, unknown)
osv_key.rs:11-13 sets MAX_NAME = MAX_VERSION = 1024; osv_key.rs:35 accepts the legacy npm `!'()*`. npm's real maxima are name 214 (names.rs:10 agrees) and version 256 (node-semver MAX_LENGTH, which npm publish enforces; this is from memory, not re-checked online), so a publisher can no longer choose an npm name or version the function refuses. The "allowed but counted in `osv_keys_refused`" outcome matches the spec's fail-open rule for degraded results (C3/C14), and it is visible in the report (`keys_refused`) but it never blocks. It is only a bypass where the registry accepts a key longer than 1024 bytes. PyPI has no documented length cap on project name or version that I could confirm. So PyPI names or versions over 1024 bytes remain an attacker-selected skip of OSV: unknown, Low, because the request URL and metadata limits probably stop such a value before it reaches the key function. Smallest correction: either confirm the PyPI maxima, or make "refused for length only" hold for the new-install decision rather than allow. Stale comment: osv_key.rs:41 still says "1 to 128 bytes".

### SEC-2 open, Medium, plausible: a slow leader still degrades a follower; the retry is ineffective for exactly that case
Location: crates/probation-server/src/osv.rs:515-523 (retry), 480-486 (`register` checks `inflight` first), 589-601 (`settle`), 623-638 (`fetch`), 650-660 and 706-716 (`post_batch` and `answer_for` are sequential).
Mechanism:
1. The retry fires only when `now < deadline_at`. A follower of a slow leader leaves `settle` precisely when `deadline_at` passes, so the retry never runs for it.
2. Even if it ran, `register` finds the key still in `inflight` (the leader lives up to `upstream_timeout` of 10 s) and joins it again. The retry therefore only helps when the leader failed fast and has already left the table.
3. A leader chunk is slow without any help from a slow upstream. `post_batch` handles the chunk's keys one after another, and `answer_for` follows up to 10 pages per key one after another, all while the single upstream permit is held. Any credential holder can put the keys a victim will ask about into a 256-key chunk of multi-page packages. The chunk runs past 1.5 s, and a timed-out chunk (10 s) is Failed for every key and caches nothing, so the attacker can repeat it. The victim's follower waits 1.5 s and is degraded (fail-open). Cost to the attacker is at most 256 keys per chunk against a 10 keys/s credential budget with burst 1000, so about 3 credentials sustain it.
4. After a successful slow leader, the cache is filled and a later retry converges. The window is still up to 10 s per attacker repetition.
The 1500 ms leader-versus-follower question you asked: the leader's 10 s timeout is independent of the 1500 ms deadline (osv.rs:625), so a leader never fails a follower early, but a follower always gives up at 1500 ms. The result is degraded, not blocked.
Smallest correction: a follower that has waited about half its deadline on a foreign leader fires its own single-key call, bypassing `inflight`, with a short per-call timeout charged to the follower. Alternatively, run the keys and pages of a chunk concurrently (bounded) so a chunk is not slower than its slowest key.
Closure checks: (a) a 256-key chunk with a deliberately slow tail does not degrade a concurrent single-key request from another credential; (b) a healthy leader still gives one upstream call for N followers.

### NEW-1 open, Low/Medium, confirmed in source: pre-auth flood can exhaust the auth gate
Location: osv.rs:430-436 (gate of `auth_concurrency` = 4, 1 s wait, then 429), 437-446.
The pre-auth throttle (SEC-3 fix) now runs only after the credential lookup has failed, and its only effect is the status code (429 instead of 401). A blocked source still does the database lookup. An unauthenticated attacker sending bad bearer tokens needs only enough request rate to keep 4 permits busy for 1 s. Every valid caller then gets 429 and its keys are degraded, which is fail-open for the whole fleet while the flood lasts. It does not touch `/sync`'s pool (that was the point of the gate), so it is limited to OSV protection.
Smallest correction: reject a request cheaply before the gate when the source is already blocked and the bearer is not a known-good cached hash, or cache recently seen good credential hashes so valid callers skip the gate. Closure check: with 1000 bad-token requests per second from one source, a valid request still gets 200.

### NEW-2 open, Low/Medium, confirmed in source: slow body holds a parse permit with no timeout
Location: osv.rs:451-456 (`parse_permit` taken with `try_acquire`, then `to_bytes(...).await` while holding it); no timeout layer in crates/probation-server/src/lib.rs or main.rs (grep for timeout found only the pool acquire timeout and a 2 s select at lib.rs:257).
One credential holder opens 64 connections and drips body bytes. All 64 parse permits are held and every other credential gets 429 until the connections drop. Cost to the attacker is one credential and 64 sockets. A reverse proxy with a body timeout would mitigate it, but that is not in the repo.
Smallest correction: read the body before taking the permit with a total timeout (for example 2 s), or wrap the `to_bytes` call in `tokio::time::timeout`. Closure check: 64 dripping connections do not stop a normal request from another credential.

### SEC-3 closed (the mechanism as written)
`source` is `state.sync.source_of(peer, &headers)` (osv.rs:426-428), the same derivation as `/sync`. If the peer is not in `[server] trusted_proxies`, X-Forwarded-For is ignored entirely. If it is trusted, `source_address` scans entries from the right and takes the first one not in the trusted range (sync.rs:315-324), so a spoofed left-hand entry is never reached and an attacker cannot frame another client. The throttle is reached only on `Unauthenticated` or `SourceRefused` (osv.rs:437-441), so a valid credential is never throttled (exemption confirmed). The table is an LRU of 10,000 (osv.rs:373-380), so it cannot grow without bound. Remaining notes: a malformed or non-UTF-8 X-Forwarded-For line makes `source_address` return None, and `source_of` falls back to the peer (the proxy's address); this lets an attacker attribute its failures to the proxy address, which now only changes 401 versus 429 for failing requests. An attacker with many source addresses (an IPv6 /64) evades the per-source count; since the count only changes a status code, this no longer matters. The trusted-proxy configuration must stay accurate: if `trusted_proxies` contains a range the attacker can send from, or a proxy that does not overwrite the right-hand entry, source spoofing returns (for `/sync`'s `allowed_source_cidrs` too, which is pre-existing).

### SEC-4 closed, with NEW-2
Per-credential request bucket 100/s burst 500 charged before parse (osv.rs:447; `admit_request`, cost 1). Key bucket 600/min burst 1000. Parse concurrency 64 by `try_acquire` (429 beyond). The buckets are keyed by authenticated callers, so their tables are bounded by the number of credentials (`retain` above 10,000). Hole: NEW-2.

### SEC-5 open, Low/Medium (hardening): the global 12,000/min, burst 3,000 budget is a cross-tenant lever
Location: osv.rs:330-345 (`charge`).
It stops the upstream-429 breaker problem (a breaker opening for 60 s degrades every tenant), but it is first come, first served. An attacker needs about 20 credentials at the full 600/min each (or 3 credentials draining the 3,000 burst, refilling at 200/s) to leave other tenants on `Pending::Budget`, which is degraded (fail-open). A tenant that can create many service keys or firewall tokens has the credentials it needs. The per-credential limit is a limit per key, not per organisation. Correction: give each organisation a share (cap per org, plus a small reserved slice for every credential) and alert on the global bucket reaching 0. Also note the refund at osv.rs:344 can push a credential's tokens above its burst until the next take (cosmetic).

### SEC-8 closed (Info residual)
`spawn_central` builds its own client with `central_http_client(options.allow_http)`: redirects off, `https_only` unless `allow_http` (src/osv/mod.rs:413-420, 481-498). The caller passes no client. The `Authorization` header is `set_sensitive`. The `send_central` origin comparison is still always true (it compares the URL with the origin it was built from), so it is a no-op, not a defense; the redirect-less client is the defense. The seam: `CentralOptions::allow_http` and `AppDeps::osv_server_origin_override` are public and not feature-gated; production sets the override to None (src/main.rs) and derives `allow_http` from it (src/lib.rs:343-349), and no config key or environment variable reaches it. Suggestion: put both behind `cfg(any(test, feature = "test-support"))`.

### SEC-9 closed
`answer_for` follows `next_page_token` for a key, up to `max_pages` = 10 (osv.rs:700-716); beyond that the key is `Answer::Failed` (degraded, not cached, other keys unaffected). Page tokens go back to the fixed upstream only. The MAL filter applies to every page. Residual: pages are sequential and add to the chunk time (SEC-2).

### New surface: `osv` in FirewallReport — closed
`OsvReport` is a `Copy` struct of one bool and eight `u64` counters (api.rs:322-336), parsed with serde and stored through `record_report` as the re-serialized typed value (sync.rs:733-746), so no string from the firewall reaches the stored row, and a 100-byte bound on size follows from the type. Unknown fields are dropped on re-serialization. Nothing else on the server reads `report.osv`. The firewall's own counters are aggregate counts only. The sender is already authenticated as that firewall (same as every other report field), so it can lie about its own health but only to its own tenant's view.

### New surface: leader writing into the shared cache past a deadline — closed (amplification bounded)
Poisoning: `fetch` stores only `Matched` (answers whose ids start with `MAL-`, osv.rs:733) or `NoMatch` from an upstream answer whose result count equals the key count (osv.rs:690-693), under the exact validated key; `Failed` is never stored. A slow leader therefore writes the same data a fast one would. Amplification: a leader is charged to its credential and to the global budget when it is created (osv.rs:482-487), and the upstream call has a 10 s cap and 8 concurrent permits, so abandoned leaders cost the attacker budget. Residual: if a `fetch` task panics before publishing, its keys stay in `inflight` for the life of the process and every later request for that key is a follower of a dead sender (Failed). I found no panic path other than poisoned mutexes (`expect`), so this is a hardening note: remove the keys with a drop guard.

## Security properties
| Property | Boundary/owning code | Status | Evidence | Limits or finding |
|---|---|---|---|---|
| Authentication on the route | sync.rs `osv_caller`; osv.rs:430-446 | closed | live `fwt_` token with source CIDR check, or live service key; nothing else | NEW-1 for availability |
| Pre-auth abuse limit | osv.rs:437-441, 373-380 | closed as a status code only | cosmetic: lookups still run | NEW-1 |
| Per-credential rate and parse bound | osv.rs:447-456 | open | buckets fine | NEW-2 |
| Cross-tenant fairness on the shared egress | osv.rs `charge`, `fetch`, `post_batch` | open | global budget first come first served; slow chunk | SEC-2, SEC-5 |
| Key function not attacker-selectable | osv_key.rs | closed (npm), unknown (PyPI >1024) | SEC-1 | |
| Credential only to the configured origin | osv/mod.rs:413-420, 481-498 | closed | own client, no redirects, https | SEC-8 residual (seam not gated) |
| Cache and relay integrity | osv.rs `fetch`, `mal_refs`, `Cache::put` | closed | exact key, MAL only, never Failed | dead-leader hardening note |
| Pagination | osv.rs `answer_for` | closed | max 10 pages then degraded | |
| Report field injection and size | api.rs `OsvReport`, sync.rs `record_report` | closed | typed numbers and one bool | |

## Verification and limits
No command run; no live calls. Subject fingerprints above. The supplied evidence (evidence/slice-30.md) was read and taken as supplied; its tests were not re-run; tdd-slice-30.md was not found at the named path in the plan directory (the file does not exist there), so no mutation-probe evidence was reviewed. Not examined: `trusted_proxies` deployment documentation, the real api.osv.dev paging and rate behavior, PyPI's actual name and version length limits, npm's 256-byte version limit (stated from memory), the portal `set_osv_scope` handler, dependency advisories. The 1500 ms versus 2000 ms deadline numbers are the user's decision and were not assessed.

## Next steps
1. Fix SEC-2 (follower fires its own call; or concurrent keys in a chunk), NEW-1 (gate exhaustion), NEW-2 (body-read timeout). Each is a small change in osv.rs.
2. SEC-5: per-organisation share of the global budget; optional: gate the test seam behind `cfg`.
3. Confirm the PyPI maxima for SEC-1; fix the stale "128 bytes" comment.
4. Re-check those three paths with the closure checks above.
