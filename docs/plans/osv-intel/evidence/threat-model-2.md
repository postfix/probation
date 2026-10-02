# Threat model — OSV batch-query design (Gate 2, re-steer)

`sf-threat-model`, 2026-09-27. Scope: the revised design (C6b) — internet-fetched, TLS-only OSV
responses feeding a production block decision via `osv::OsvClient::check` -> cache (C13) ->
`osv::batcher` mpsc/oneshot (C12) -> `POST api.osv.dev/v1/querybatch` -> `policy::evaluate`'s
`osv_matched` tier -> decision log (`DenyReason::BlockedByOsv`, C8). Supersedes
`evidence/threat-model-1.md`, which modeled the bulk-zip design (C6, now superseded).

First verdict: UNKNOWN — three gaps in the architecture text (not in written code — none exists yet,
expected at Gate 2):

- **G1 (batcher self-timeout)**: the outbound `POST /v1/querybatch` call, if awaited unbounded inside
  the batcher's `select!` loop (as `delivery/siem.rs`'s best-effort delivery is), would let one hung
  OSV connection stall the whole task, backing up every subsequently-enqueued key behind it — directly
  at odds with the `rated-load-guard` latency goal the Constraints section already names.
- **G2 (channel capacity unspecified)**: no stated bound on the `mpsc` channel or behavior when full —
  either unbounded growth (memory) or an indefinite blocking `send` on the request path.
- **G3 (positional-matching mechanism unstated)**: a `results[i]`/`queries[i]` length mismatch
  (research-2.md's named risk) was not given an explicit guard. An unchecked index panics (full
  process crash); a naive `zip()` silently truncates, which is worse than a crash — a truncated key
  would be treated as "no match" and cached under C13's *normal* TTL rather than C14's short
  negative TTL, letting a real malicious-package match go uncaught for a full cache window.

## Resolution

C12a (bounded channel + enqueue-timeout fail-open) closes G2. C12b (length-equality check before any
positional pairing; a mismatch takes the whole-batch fail-open path) closes G3. C12c
(`tokio::time::timeout`-wrapped outbound call, batcher always returns to draining `rx`) closes G1. All
three are additive mechanism statements inside `osv::batcher`, not architectural reversals — C6b, C1,
C3, C5 all still hold.

## Confirmed non-gaps

- **T1 (a wholesale-erroneous OSV match)**: accepted by design — C4 (Gate 1) already commits to
  trusting any `MAL-*` match unconditionally; TLS authenticates the connection is genuinely to
  `api.osv.dev`; C13's short TTL bounds how long a bad entry persists. Not a Gate 2 gap — a Gate 1
  policy already on record.
- **T5 (oversized response body)**: bounded by OSV's own documented 32 MiB HTTP/1.1 cap
  (research-1.md); exceeding it requires OSV itself or a TLS-boundary compromise, the same accepted
  trust boundary as T1. Optional defense-in-depth (explicit client-side size limit) noted, not
  blocking.
- **Blast radius vs. the superseded bulk-zip design**: materially smaller — no single poisoned
  response can taint a whole ecosystem at once; a bad answer now affects one
  (ecosystem, name, version) key for one cache-TTL window. Confirms C6b's stated rationale.
- **OR-only merge (C1) and C15's OSV-blind-first evaluation order**: correctly prevent OSV
  failure/absence from ever producing `Decision::Unavailable` or un-blocking a producer-blocked
  package. Verified against the Constraints section, no gap.

Re-review against the revised text (`sf-threat-model`, 2026-09-27, C12a/b/c in place): **MODELED**.
G1 confirmed closed by C12c (`tokio::time::timeout`-wrapped outbound call; the task's control flow
returns to `rx.recv()` within a bounded interval regardless of OSV connection state). G2 confirmed
closed by C12a (bounded channel capacity; enqueue-onto-full-channel is itself timeout-bounded and
fails open, never an indefinite blocking send on the request path). G3 confirmed closed by C12b
(`results.len() == queries.len()` checked before any positional pairing; a mismatch takes the
whole-batch fail-open path, never a partial/truncated pairing or an unchecked index). Non-gap and
constraint re-check passed: T1/T5 unaffected, C1 (OR-only merge), C3 (never fail-closed), C5 (no
provider abstraction), and C15 (OSV-blind-first ordering) all still hold — C12a/b/c are mechanism-only
additions inside `osv::batcher`, no architectural reversal. Exact numeric values (channel capacity,
enqueue-timeout, outbound-call timeout) remain a Gate 3 config deferral, not a mechanism gap: the
design commits to "bounded," "short," and "no looser than C14's bound" as binding properties any
Gate 3 config must satisfy.
