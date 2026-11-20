# Code review: slice 24 (OCI registry), uncommitted on slice5-native-ci at aa774dc

Procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md (read-only; no source edited).
Verdict: FIX FIRST
Scope: src/oci/{coords,serve}.rs, src/http/oci_routes.rs, the shared-service classifier (src/http/service_registry.rs), transport `fetch_oci`, artifacts/origins/store/config diffs, migration 0022, tests/authorization_read_once.rs repair, tests/oci_native.rs, the cluster-probe and publishing-oci scenarios, evidence/slice-24.md and tdd-slice-24.md (incl. "Spec changes needed"). Compared with slices 17-23 patterns (Conan owner shares, Maven row writes, spool contract). Docs prose, portal templates, E2E fakes were read only for claims, not line by line.
Fingerprints (sha256) at review: src/oci/serve.rs 4200e7d2...adb8d8 (as in tdd file), src/http/oci_routes.rs d9a7b50e...5bff (as in tdd file), tests/oci_native.rs b49ff658...55c5. Tree unchanged during review: yes (scratch target deleted).

## Findings

### F1 - high - correctness - a legitimate multi-GiB layer push is cut after 5 minutes (docker/skopeo/containerd push chunked, no Content-Length)
Location: src/http/oci_routes.rs:419 (spool call with `declared` = Content-Length header only); src/http/spool.rs:25 and :93 (`UNDECLARED_DEADLINE` 5 min).
Requirement: "no 400/withhold of valid inputs", evidence slice-24.md "a multi-GiB layer streams to disk and is forwarded"; question "can a legitimate 5 GiB layer push succeed?".
Failure: docker, containers/image (skopeo, podman) and containerd send a layer as one streamed PATCH with `Transfer-Encoding: chunked` (no `Content-Length`). `body_deadline(None)` is 5 minutes for the whole body (+60 s first chunk), so a 5 GiB layer needs about 15 MB/s (120 Mbit/s) sustained, a 2 GiB layer about 6 MB/s. Anything slower gets `InvalidInput("the upload took too long")` mid-stream and the push fails; retry fails the same way. The only test of the path (`a_chunked_blob_upload_is_spooled_and_forwarded_with_its_real_length`) is small and never approaches the deadline.
Evidence: constants read; no OCI-specific deadline in forward_write. Not run (needs a slow multi-GiB body); the arithmetic follows from the constants.
Correction: for OCI uploads pass a deadline derived from the cap (for example `BODY_DEADLINE`, or cap/MIN_RATE bounded) when `declared` is None, via `spool_with`/`spool_paced`, and add a test with a fake clock/slow chunked body longer than 5 minutes. Cost: a slot is held longer by a slow legitimate client (still bounded by seats, budget share, MIN_RATE floor).
Blocking: yes (valid push refused; full parity is binding).

### F2 - medium - capacity - three concurrent large layers of one client fail mid-stream (docker pushes 5 layers in parallel)
Location: src/http/limits.rs:202-206 (budget = 4 x max_artifact_bytes = 20 GiB, owner half = 10 GiB, 4 seats), used from oci_routes.rs:419.
Failure: with the default 5 GiB cap one owner (client /64 in service mode) can hold 10 GiB of spool. One 5 GiB layer succeeds, two simultaneous 5 GiB layers just fit (undeclared length means the `spool_turn` serialisation never applies, since it is keyed on a declared length), a third 4-5 GiB layer waits `SPOOL_BUDGET_WAIT` (30 s) per chunk and then answers 503 in the middle of the stream. A docker push of an ML-style image (layers 4-5 GiB, `max-concurrent-uploads` 5) fails and retries into the same wall. The evidence states the single-layer bound (10 GiB) but not this parallel limit.
Correction: document the limit honestly in operations.md and the evidence (honest red line), or let an undeclared body of an OCI layer take the turn queue so parallel layers serialise instead of failing. Cost: slower pushes.
Blocking: no (documented-bound class; but the evidence must state it).

### F3 - medium - fairness - registry fetch places have no per-owner share; rotating `Authorization` values defeats the per-credential cap
Location: src/oci/serve.rs:200-225 (`places`: credential key = hash of the header text only), constants :52-53.
Requirement: checklist "per-owner shares for every shared slot/lane" (slice 23: Conan has `owner_searches`, `owner_total`, `owner_judging` keyed by `spool::owner_of`; src/conan/serve.rs:60-66, :203-206).
Failure: in shared-service mode the firewall cannot tell a valid credential from junk. One client address sending 8 requests with 8 different junk `Authorization: Bearer x{n}` headers (or none at all: anonymous callers have no per-credential limit) holds all 8 places of the registry and, with the global lane (half of `max_upstream_requests`, at most 32), starves every other client for `PLACE_WAIT` 30 s then 504. The implementer's own test states it: "16 callers with different tokens peak at 8".
Evidence: `one_credential_cannot_hold_all_of_a_registrys_fetch_places` (tests/oci_service.rs:393-416) asserts peak 8 for different tokens.
Correction: add an owner dimension (the `spool::owner_of` key: address /64 in service mode, account in certificate mode) with at most half of the registry's and the global places, as Conan does. Cost: one more table, bounded like the others.
Blocking: yes (the slice-23 lesson was an explicit review checklist item; the same hole is re-introduced).

### F4 - medium - efficiency/latency - every manifest request takes the repository row gate and commits a DB row even when nothing changes
Location: src/oci/serve.rs:792-805 (`judge`: `row_gate` then `commit_rows` unconditionally); compare src/maven/serve.rs:548-562 (returns early when the stored row already holds the date, no write, no gate).
Failure: each GET and HEAD of a manifest (a pull makes at least three: tag, index, child) does a Postgres/SQLite transaction while holding the per-repository mutex. For a hot repository (`library/alpine` pulled by a node fleet) all manifest requests of the repository are serialised behind one write each, and every read is a write. First-seen/date are already stored, so the write changes nothing (the store keeps the earlier first-seen and the larger date).
Correction: when `existing` is Some, skip the gate and the commit (use the stored first-seen); gate and write only for a new row. Closure: a test counting store commits for 100 repeated reads (expect 1). Cost: none.
Blocking: no for correctness; yes for the "measured bounds for latency" checklist if the project holds that bar (the evidence has no latency measurement for the gate).

### F5 - medium - parity - no way to name a token realm that is on another host (GitLab registry, self-hosted registries with a separate auth host)
Location: src/oci/serve.rs:70 (hard-coded `REALM_TABLE`) and :286-297 (`realm_allowed`).
Failure: a registry whose challenge points at another host than the registry (GitLab Container Registry: `registry.gitlab.example.com` challenges with `https://gitlab.example.com/jwt/auth`; some Harbor/Keycloak set-ups) is a valid registry, yet every read and every login is a 502 (`UpstreamFailure`): the realm is neither the registry origin nor in the table, and an operator has no field or config key to declare it (archive_origin exists for storage, nothing for the token host). The evidence lists the table under "stubs" but not this consequence.
Correction: a per-registry declared token origin (descriptor field, same pattern and migration shape as `archive_origin`, fail closed in an enforcer that does not know it), or at minimum record it in "Not done" for the user as a parity loss. Cost: one descriptor field and a portal input.
Blocking: no for this review's confirmed set only if the user accepts it; under the binding parity ruling it needs an explicit decision, so treat as open.

### F6 - medium - spec correctness - `OCI-Subject` is captured by the transport but never relayed on a manifest PUT
Location: src/upstream/reqwest_transport.rs:290 (captured); src/http/oci_routes.rs:455-471 (relay list has Location, Range, Docker-Upload-UUID, Docker-Content-Digest only).
Failure: OCI Distribution 1.1 requires a registry that supports the referrers API to answer a manifest PUT with a `subject` with `OCI-Subject: <digest>`. oras, cosign and containers/image read it to decide whether to use the referrers API; when it is missing they assume no support and write the `sha256-<digest>` fallback tag index, which then also goes through this firewall and (F8) is held by the cooldown. No test covers it (`grep oci-subject tests/oci_service.rs` finds nothing).
Correction: relay `oci-subject` (digest-shaped value only) and test it with a subject manifest. Cost: three lines.
Blocking: no.

### F7 - low/medium - parity - referrers pagination `Link` is dropped, so a long referrers list is silently truncated
Location: src/oci/serve.rs:1073 (`link: None`); `rewrite_link` already supports the filter key.
Failure: a registry that paginates `GET /v2/{name}/referrers/{digest}` (spec: `Link: rel="next"`) answers a first page only; the client never sees the rest (for example further signatures or SBOMs, so a verification can miss one). Evidence "Lists" says links are rewritten for referrers; the code drops it.
Correction: rewrite the link with keys `["artifactType"]` plus the registry's paging keys. Blocking: no.

### F8 - low - tag-schema referrers fallback is cooled down like an image
Location: src/oci/serve.rs:792 (`judge` for every manifest digest, including the `sha256-<hex>` fallback index tag).
Failure: for a registry without the referrers API, a client reads the fallback tag (an index of descriptors that changes with each new signature). Each new version is a new digest with its own cooldown, so the client gets 403 instead of the empty/404 answer it expects, and tools such as cosign verify fail for a week after a new signature. This follows from the first-seen rule and is the safe direction, but it is not mentioned in the evidence or docs.
Correction: record it as a known limit (or serve an index of descriptors-only without the cooldown, since it delivers no content; needs a decision). Blocking: no.

### F9 - low - dead/false claim - GET of an upload session is documented as class W and is a 405
Location: src/http/oci_routes.rs:322 (`write` is false for GET, so the request goes to `read`/`run`, which answers `MethodNotAllowed` at the `Parsed::Upload` arm), :371 (the GET arm of `write_segments` is unreachable); evidence slice-24.md "Writes" lists GET.
Failure: upload status (`GET .../blobs/uploads/{uuid}`, used to resume a chunked upload) is refused with 405, a valid OCI request withheld.
Correction: treat GET of an upload session as a write-class forward (credential required, no body), or remove the claim. Blocking: no.

### F10 - low - comment contradicts code - manifest PUT of a blocked tag or digest is not refused
Location: src/http/oci_routes.rs:405-411 (comment "A tag or digest a policy blocks is not pushed over either", code checks the repository only and then `let _ = reference;`).
Failure: a block naming `team/app:v1` does not stop `PUT .../manifests/v1`; reads of it are still refused, so the effect is limited. Either enforce (`locally_blocked(name, Some(&reference.text()))`) or fix the comment. Blocking: no.

### F11 - low - the row bound double-counts existing rows
Location: src/oci/serve.rs:843 (`within_row_bound(.., upserts.len())` counts all children, including ones already stored).
Failure: near the cap (default 5 x 20,000 rows per repository, rows never pruned) the hourly re-registration of an allowed manifest returns 503 although it adds no row. Only reachable in a very large repository. Correction: count only children without a row. Blocking: no.

### F12 - low - shared token table is cleared whole when full
Location: src/oci/serve.rs:423-425 (`tokens.clear()` at 256 entries; same pattern for realms, manifest memo, exists, registered).
Failure: a client requesting 256+ distinct (made-up) repository names drops every other client's anonymous token each time, so each legitimate request repeats a token round trip to the registry's realm (Docker Hub rate-limits the token endpoint per address). Bounded, not unbounded growth. Correction: evict the oldest entries instead of clearing. Blocking: no.

### F13 - low - Docker Hub rate-limit amplification and storage-host assumptions (operational)
Location: src/oci/serve.rs:739-760 (`serve_manifest` fetches by GET for HEAD too); src/upstream/origins.rs `hub_storage` (two hosts).
Failure: Docker Hub counts manifest GETs, not HEADs, as pulls; the firewall turns the client's free HEAD into a GET against its one anonymous address (documented limit). Hub has also redirected blobs to other storage hosts (Cloudflare R2) than the two admitted; a blob redirect to any other host is a 502 until an operator sets `oci_artifacts_url`. Measured once (2026-11-20, CloudFront). Correction: record it; optionally serve HEAD from the registry's `Docker-Content-Digest` of a HEAD (the digest is verified when the client then asks by digest). Blocking: no.

## Requirement coverage

| Requirement and source | Implementation / connection | Check and limits | Status |
|---|---|---|---|
| `/v2/` ping, Distribution-API-Version header, token flow with Bearer realm/service/scope, realm confinement (row 24, LS-F4) | serve.rs `parse_challenge`, `realm_allowed`, `fetch_token`, `ping`; oci_routes `challenge_header` | read in full; unit tests and tests/oci_service.rs pass; real podman pass (3 tests, ran, not skipped). Confinement is strict (origin or fixed table) which causes F5 | MET with F5 open |
| Manifests by tag/digest, HEAD, Accept, index/list, children, artifactType/subject | `fetch_manifest`, `read_children`, `register_children`; Accept passes through; subject/artifactType not interpreted (fine) | digest and Docker-Content-Digest verified; `OCI-Subject` not relayed (F6) | MET except F6 |
| Referrers API and tag fallback | `serve_referrers`; fallback tag is an ordinary tag | link dropped (F7), fallback held by cooldown (F8) | partly MET |
| Blobs HEAD/GET/Range, 307 handling, verified in full before delivery | `reference_for_blob`, shared artifact pipeline, redirect only to the storage origin with the credential dropped | transport tests on real sockets pass; multi-GiB latency/disk cost is the shared pipeline's (whole layer is fetched and hashed before the first byte, up to 5 GiB; same as Maven/Conan bigger files, not measured for OCI sizes); anonymous blob HEAD runs the cold download (documented) | MET with limits |
| tags/list and _catalog paging, Link rewriting | `rewrite_link`, typed decode, rebuilt lists | test `a_tag_list_is_rebuilt...` passes; ordering by `Link` preserved | MET |
| Uploads: monolithic, chunked, mount, DELETE via the shared spool | `forward_write` | credential and Location handling sound; F1, F2, F9 | NOT MET (F1) |
| Dating by first-seen, children take manifest date, config `created` never releases | `judge`, `register_children`, store max rule | traced: a child's date is the allowed manifest's first-seen (already past the cooldown when registered), a shared layer can only move later; a tag is judged by the digest it names now. Sound | MET |
| FIX-16-A mid-request block, no double rate charge | `read` fingerprint recheck; legacy `managed.reauthenticate`; `recheck_for` uses `admit_certificate(.., false)`, `an_oci_read_costs_one_rate_token` passes | read; tests pass | MET |
| Read-only judging vs anchor rows / first-seen safety | rows are written only on first sight and after an allowed manifest; reads create rows only for digests the registry really has; row bound per repository | F4, F11 | MET with F4 |
| C1028 | `cache_token` gates the manifest and exists memos; `FamilyReadRules::OCI` | tests/credential_bearing_reads.rs 26 pass | MET |
| Per-owner shares for shared slots | spool uses `owner_of` (good); fetch places do not | F3 | NOT MET |
| Test seams only under test-support | `with_oci` is `pub fn` on `OriginSet` documented "Tests only", same as `with_go_archives`; not feature-gated | follows the existing pattern; origin_guard binary passes per the implementer | MET (pattern parity) |
| Migration 0022, config keys, ALL=9, tag `oci` | constraint found by what it constrains; keys in OPTIONAL_KEYS and sample; additive `Upstreams.oci` | SQL read (matches 0017-0021 style); server tests not re-run (need Postgres) | MET (migration not executed by me) |
| Baseline repair of tests/authorization_read_once.rs | allowlist now names `authenticate_charging`; the two anchors carry `charge_rate: bool` so they are unique | diff read; the scan still demands exactly one `get(AUTHORIZATION)` site there, so a second site would fail; binary passes (4). The two new allowlist entries are the OCI sites in oci_routes.rs `credential` and transport `fetch_oci`, both inspected. Neutral: yes | MET |
| ROW24-FLIP in the cluster probe | both tagged expectations flipped; probe sets service cooldown 0 | scenario read; E2E not re-run. The probe now proves routing, and a 0-day cooldown means it no longer shows a held pull through containerd | MET (E2E unverified by me) |
| Final-rerun gap (oci_native.rs, cluster-probe, publishing scenarios edited after the last full run) | | oci_native read in full, then run: 3 passed with podman actually running; oci_registry 15, oci_service 18, oci_transport 4, listener_admission 16, authorization_read_once 4, maven_service_write 16, credential_bearing_reads 26 all pass on a fresh scratch build. The two scenarios were read, not run (they need the built images and stack); no defect found by reading | no regression found |
| Test-first evidence | tdd-slice-24.md has `tdd:` lines, 17 with a real red, the rest honestly `red not observed`, mutation probes P1-P19 with P18 surviving | line count and honesty fine; F1 shows the test gap | MET (history unverified for the "not observed" rows) |

## Conventions and simplifications
- `let _ = Reference::Tag(String::new());` (oci_routes.rs, end of `forward_write`) and `let _ = doc.name;` (serve.rs, `serve_tags`) are leftovers that exist only to silence unused warnings; delete the imports/fields.
- `origins_of` and `origins_for` build the same `Origins` twice; `ambient_authorization` repeats `authorization()`'s Basic exchange. Cosmetic.
- `is_manifest` cap 8 MiB for a push while the spec only promises 4 MiB: fine.

## Uncertainties
- U1 (plausible): pull latency for a first-time multi-GiB layer: the client receives no byte until the layer is downloaded and hashed (up to 5 GiB). Whether docker/containerd/skopeo time out depends on their header timeouts (not measured; the other families' bigger files use the same pipeline). Check: pull a 2-3 GiB fake layer at 50 MB/s through podman and containerd. Owner: implementer.
- U2 (plausible): foreign layers with `urls` in a descriptor are fetched by the client from those URLs directly, bypassing the firewall; the digest is verified by the client and the manifest is judged, so it is not a content bypass, but the "everything goes through the firewall" claim does not hold for such layers. Needs a statement in the evidence.
- U3: only sha256/sha512 digests are verified; other algorithms are a 404/502 (documented). Under the parity ruling the user should say this loss is acceptable.

## Verification and limits
Commands run (all inside `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`, target under /home/john/go/src/github.com/postfix/.probation-scratch/oci-review, deleted afterwards): `cargo test -j 8 --test oci_native --test oci_registry --test oci_service --test oci_transport --test listener_admission --test authorization_read_once --test maven_service_write --test credential_bearing_reads` exit 0 (3, 15, 18, 4, 16, 4, 16, 26 tests passed); `cargo test --test oci_native -- --nocapture` confirmed podman ran (no SKIPPED line).
Not run: server crate tests (Postgres), full workspace, clippy, E2E stack and the three scenarios, mutation probes. Supplied evidence reused: tdd-slice-24.md results for those.
Lenses with no finding: security of realm confinement and credential routing (sound apart from F5), Location/Link rewriting, digest verification of manifests, redirect handling, migration SQL.

## Next steps
Fix F1 and F3 (blocking), decide F5 with the user (parity loss or a descriptor field), then F4, F6, F7, F9, F10 (small); record F2, F8, F11, F13 and U1-U3 in the evidence "Not done" list. A re-review should rerun oci_service and a new slow chunked upload test (F1) and an owner-share test (F3).
