# Probation — Rust MVP Specification

Status: reviewed implementation specification; runtime validation pending  
Date: 2026-09-19  
Revision: 3 — bounded maximum age for cached project metadata  
Principles: KISS, YAGNI, fast warm requests, bounded resource use

## 1. Problem and solution

Developers and CI systems can install a compromised package immediately after publication, before a malware feed identifies it. Blocking only known malicious releases leaves this detection window open. Simply refusing a new download also breaks installations that could have used an older compatible release.

Probation is an open-source, self-hosted registry proxy for public npm and PyPI packages, implemented in Rust. It hides releases younger than a configured delay and hides known malicious packages and artifacts. Existing package managers resolve dependencies against the remaining candidates. Every artifact download through the firewall is checked before delivery.

The default delay is 24 hours, configurable in seconds. An eligible package has passed the configured checks; eligibility is not proof that the package is harmless.

The firewall owns availability policy. npm and pip own dependency resolution, compatibility checks, and lockfiles.

## 2. Product contract

| Input or condition | Required behavior |
| --- | --- |
| Latest release is too young | Offer an older eligible release using the ecosystem rules below. |
| Dependency specifies a range | Expose eligible candidates; the client selects within its original constraints. |
| Exact version is too young or blocked | Refuse it. Never substitute different package bytes or a different version. |
| Frozen lockfile references a blocked artifact | Refuse the download. Updating the lockfile is a separate client operation. |
| All compatible candidates are excluded | Resolution fails. Never weaken dependency requirements. |
| Release completes its delay | Make it eligible automatically on the next applicable request. |
| A cached artifact becomes blocked | Refuse subsequent downloads, including requests using previously issued URLs. |
| An artifact is already installed or in a client cache | Outside the proxy's enforcement boundary. |

Example: `2.4.2` is two hours old, `2.4.1` is blocked, and `2.4.0` is ten days old. A compatible range can resolve to `2.4.0`. An exact request for `2.4.2` fails.

Automatic fallback occurs during metadata-based resolution. A client that has already selected an artifact may stop after its download is denied; the firewall cannot require that client to retry another version.

## 3. Small deployment and implementation

Ship one Rust binary and a container image built from it. Run one process against one local data directory. Use an existing reverse proxy for TLS and deployment access control. The default listener is loopback. All consumers of an instance share one policy.

The binary performs four jobs:

1. Serve npm metadata and the PyPI Simple API.
2. Apply cooldown and blocklist rules.
3. Fetch, verify, cache, and deliver artifacts.
4. Reload a normalized local blocklist in the background.

Use ordinary Rust modules in one Cargo package:

| Module | Responsibility |
| --- | --- |
| `config` | Parse and validate TOML at startup. |
| `policy` | Pure eligibility decisions and immutable blocklist snapshots. |
| `npm` | npm names, metadata, versions, tags, and tarball references. |
| `pypi` | Python project names and Simple API HTML/JSON rendering. |
| `upstream` | Pooled HTTPS clients, timeouts, size bounds, origin validation. |
| `artifacts` | Download coalescing, verification, disk files, response streaming. |
| `store` | Embedded Turso records and bounded memory caches. |
| `http` | Routing, error responses, health, structured logs. |

Use Tokio, Axum, Reqwest with rustls, Serde, TOML, the `turso` crate, SHA-2 hashing, and tracing. Use maintained parsing libraries for URLs, timestamps, npm version ordering, Python distribution filenames and PEP 440 versions, and SRI integrity fields. Add legacy SHA-1 verification only for npm artifacts whose upstream metadata supplies no stronger integrity digest. Do not implement a dependency solver or generic plugin framework.

Use the embedded **Turso Database engine written in Rust**, through its local async API. It is MIT-licensed. No hosted service, account, network database, subscription, or cloud synchronization is required. The older libSQL engine and the remote Turso clients are not this dependency. [Engine and license](https://github.com/tursodatabase/turso/blob/main/LICENSE.md), [Rust API](https://docs.turso.tech/sdk/rust/reference).

One async storage task owns one local connection and serializes database operations through a bounded queue. Warm requests use memory and artifact files directly. Batch the records for one project refresh in one transaction and batch approximate access-time updates; do not write a transaction for each cache hit. Policy snapshots, first-seen times, and verified-artifact mappings require acknowledged commits before dependent responses are published. Use the operating system's file cache for artifact bytes.

Open `data_dir/state/firewall.db` using `turso::Builder::new_local(...).build().await` and `db.connect()`. Use ordinary WAL transactions with `PRAGMA synchronous=FULL`; verify the effective setting at startup. Keep transaction ownership inside the storage task so cancellation of a caller cannot leave a transaction open. Use parameterized SQL and basic tables, indexes, and explicit transactions. Extra database features are unnecessary.

Pin a published Turso crate release and Cargo.lock before implementation validation. Test that exact version's SQL, transaction, checkpoint, and recovery behavior. The upstream project reports production users but remains pre-1.0 and documents compatibility differences; this specification does not treat SQLite compatibility as a guarantee that every SQLite setting or operation works. [Project status](https://github.com/tursodatabase/turso#faq), [Compatibility](https://github.com/tursodatabase/turso/blob/main/COMPAT.md).

The MVP does not include a UI, package publishing, private registry federation, vendor feed adapters, archive-content scanning, LLM analysis, distributed storage, or an administrative REST API. These are scope boundaries, not an implementation backlog.

## 4. Configuration and commands

```toml
listen = "127.0.0.1:8080"
public_url = "https://packages.example.org"
data_dir = "/var/lib/probation"
blocklist_file = "/etc/probation/blocklist.json"

cooldown_seconds = 86400
metadata_ttl_seconds = 300
metadata_max_age_seconds = 86400      # 24 h ceiling on a cached copy; 0 disables
blocklist_poll_seconds = 5

cache_max_bytes = 107374182400        # 100 GiB, including temporary downloads
memory_cache_max_bytes = 268435456    # 256 MiB cache budget, not total process RSS
max_artifact_bytes = 5368709120       # 5 GiB
max_metadata_bytes = 67108864        # 64 MiB after decompression
max_blocklist_bytes = 134217728       # 128 MiB
max_upstream_requests = 32
max_artifact_downloads = 8
max_active_requests = 1024
```

Public upstreams are fixed in this release: `https://registry.npmjs.org` and `https://pypi.org`. PyPI artifact downloads use `https://files.pythonhosted.org`. The public URL has no query, fragment, or path prefix. Configuration changes require a restart; blocklist changes do not.

Reject invalid configuration, including an artifact limit larger than the total cache budget. Durations are nonnegative integers; zero cooldown explicitly disables only the age rule. Zero polling intervals and zero capacity limits are invalid. A nonzero `metadata_max_age_seconds` below `metadata_ttl_seconds` is invalid, because a ceiling beneath the revalidation interval would expire every copy before it could be revalidated; zero explicitly disables the ceiling and restores unbounded revalidation.

```text
probation serve --config /etc/probation/config.toml
probation check-config --config /etc/probation/config.toml
probation check-blocklist /etc/probation/blocklist.json
```

Validation commands exit nonzero on failure and do not modify state. No remote control endpoint is required.

## 5. Eligibility rules

Evaluate using one UTC `now` value per decision and a consistent blocklist snapshot:

```text
if blocklist is missing or expired: UNAVAILABLE
if package or package/version is blocked: DENY
if any known artifact digest is blocked: DENY
if publication time is malformed or in the future: DENY
if now < effective_publication_time + cooldown: HOLD(until)
otherwise: ALLOW
```

For npm, age is based on the version's upstream publication timestamp. For PyPI, age is based on each file's upstream upload timestamp: a new wheel cannot inherit the age of an older source distribution.

When a timestamp is absent, use a persisted first-seen timestamp for that exact artifact reference. Persist it before using it to make an artifact eligible. Restarting the service must not reset it. If a valid upstream timestamp later appears, use it. Changed URLs or expected digests constitute a new reference; never silently replace the bytes behind an existing reference.

An exact artifact reference includes ecosystem, normalized package name, upstream version, filename, upstream URL, and expected integrity digests. Treat contradictory metadata for the same published filename/version as an upstream integrity error until fresh consistent metadata is available.

The host must maintain an accurate clock. Cached projection expiry uses monotonic time as well as the UTC eligibility deadline. Recompute projections after a detected backward wall-clock jump; do not reuse an earlier age decision until its timestamp is eligible again.

The metadata maximum-age ceiling is deliberately a wall-clock comparison rather than a monotonic one, because the time it measures from is persisted and must survive a restart, which no monotonic reading does. A wall-clock jump therefore shifts when the ceiling trips rather than defeating it: a forward jump makes snapshots look over-age early, which costs an extra full fetch and fails safe; a backward jump delays the trip by at most the size of the jump, after which wall time advances again and the ceiling applies as before.

Known malware always overrides age. There are no implicit exemptions for top-level dependencies, locked dependencies, or popular packages.

## 6. npm behavior

Use the full upstream package document as the authoritative source because it contains publication times. Cache it; do not fetch it separately for every client request. Filter the full response and derive the abbreviated install response from that same snapshot using the documented npm field set. Preserve dependency, optional dependency, peer dependency, platform, and engine information. Never edit dependency constraints.

For each response:

1. Remove versions denied or held by policy.
2. Rewrite each remaining `dist.tarball` to a firewall artifact URL.
3. Preserve integrity values and relevant per-version metadata.
4. Remove excluded version entries from the publication-time map.
5. Apply the tag rules below.

Tags:

- Preserve a tag unchanged if its target is eligible.
- If `latest` targets an excluded version, select the highest eligible stable version whose npm version precedence is no greater than that target. This is an explicit firewall fallback policy; it does not claim to reconstruct historic publisher tags.
- If no such version exists, omit `latest`.
- If another tag, such as `beta` or `next`, targets an excluded version, omit it. Do not guess another channel member.
- If upstream `latest` is absent or invalid, do not invent it.

An upstream tag deliberately pointing at an eligible prerelease remains unchanged. Direct range requests can still select any eligible version permitted by the client's normal rules.

Support unscoped and scoped package names, including npm's percent-encoded scoped form. Validate and normalize route components before lookup. Support package metadata, exact-version/tag metadata, and `/-/ping`. Exact-version metadata passes the same checks as package metadata.

If some candidates remain, return the filtered document. If the project exists but none remain, return a policy denial. A real upstream absence is `404`.

Unsupported API routes receive an explicit error and are never blindly forwarded. The supported product operation is installation; publishing, login, search, and vulnerability audit endpoints are outside this MVP.

## 7. PyPI behavior

Fetch the upstream Simple API JSON project document. Normalize project names by lowercasing and replacing each run of `-`, `_`, or `.` with `-`. Obtain each file's version with a maintained distribution-filename parser and match version blocks using parsed PEP 440 equality, including equivalent version spellings. Preserve the original filename and version spelling in client-facing metadata. Exclude files whose project/version identity cannot be established; log the unsupported filename rather than guessing.

Filter files individually by age and hash. A package/version block removes all its files. Keep files' compatibility and yanked metadata intact; the Python client decides whether they are acceptable. Recompute any advertised version list from remaining files.

Serve both Simple API HTML and JSON with correct content negotiation. Rewrite artifact URLs through the firewall and preserve file hash information. HTML must escape filenames and attribute values correctly. Return the required canonical trailing-slash redirects locally.

For simplicity, omit optional separate core-metadata advertisements and provenance links in this release. Clients obtain dependency metadata from the verified distribution itself. Do not leave upstream auxiliary download links in the response. This deliberately trades some cold-resolution speed for a smaller implementation.

Serve `/pypi/simple/` as a valid index of projects already known to this instance, not a mirror of all PyPI projects. Installation of a project not listed there still works through its project endpoint. For an existing project with no eligible files, return an empty valid project listing; pip reports no matching distribution. Log why the files were excluded.

The cooldown applies to wheels, source distributions, and build dependencies fetched through the configured index. It does not inspect code executed by package installers.

## 8. Blocklist interface

The service consumes one local JSON snapshot. An external producer merges threat intelligence and atomically replaces the file. Vendor integration and feed deduplication belong to that producer, outside this binary.

```json
{
  "schema_version": 1,
  "revision": 42,
  "generated_at": "2026-09-17T12:00:00Z",
  "expires_at": "2026-09-18T12:00:00Z",
  "blocked_packages": [
    {
      "ecosystem": "npm",
      "name": "example-malware",
      "version": "1.2.3",
      "reason": "Known malicious release"
    },
    {
      "ecosystem": "pypi",
      "name": "example-bad-project",
      "version": null,
      "reason": "Block every release"
    }
  ],
  "blocked_hashes": [
    {
      "algorithm": "sha256",
      "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "reason": "Known malicious artifact"
    }
  ]
}
```

Hashes identify the exact downloaded archive bytes, not a manifest, extracted file, or decompressed tar stream. Accept SHA-256 and SHA-512 with exact-length hexadecimal digests; normalize their case. Reject unsupported algorithms and malformed records. npm SRI base64 is decoded to the same digest bytes before comparison.

Reload procedure:

1. Every polling interval, check whether the file changed.
2. Read within the size limit and validate the entire candidate snapshot off the request path.
3. Require a strictly increasing revision for changed contents; identical revision/content is a no-op. Reject rollback and changed contents with an unchanged revision.
4. Require `generated_at <= now < expires_at` and `generated_at < expires_at`.
5. Persist the accepted snapshot and revision transactionally, then atomically publish immutable in-memory hash sets.

Persist the last accepted snapshot so restart can use it while still valid. A malformed replacement retains the valid last snapshot and logs an error. At expiry, both new resolutions and artifact downloads fail with `503`, including cache hits. Liveness remains healthy; readiness becomes unhealthy. Never silently substitute an empty blocklist. An intentionally empty, valid snapshot is allowed and means only cooldown protection is active.

A newer full snapshot replaces the previous one, including removals. The producer therefore owns block withdrawal and must retain still-active detections. Files are writable only by trusted operators or the producer. No user-supplied URL is fetched as a feed.

The lookup path uses hash sets for package, package/version, and algorithm/digest keys. No remote intelligence request is made during an installation.

## 9. Artifact download and verification

Artifact URLs have one of these two forms, one per ecosystem:

```text
/npm/artifacts/{reference_id}/{filename}
/pypi/artifacts/{reference_id}/{filename}
```

Artifacts are served under the same path prefix as the ecosystem's metadata because npm 12 defaults `allow-remote` to `none` and exempts a registry's own tarballs only when the tarball URL shares both the origin and the path prefix of the configured registry. A tarball served outside that prefix is classed as a remote dependency and refused. PyPI uses the same shape for symmetry.

`reference_id` is a SHA-256 digest of an unambiguous, length-prefixed encoding of the exact artifact reference. It is a lookup key, not a content hash or authorization token. Persist its record before advertising the URL. The filename preserves the original extension and wheel name. The server looks up the record; it never constructs an upstream URL from an arbitrary client URL parameter.

The ecosystem in the URL is part of what the client is asserting, and it is checked the same way: the server compares it with the stored record's own ecosystem and answers `404` on a mismatch, on every method and for a byte range as well as a whole body. Because the reference id is derived from public metadata and is not an authorization token, an unchecked ecosystem segment would let a valid reference be served, and logged, under an ecosystem that did not decide it.

Every artifact request must confirm that the reference is still advertised by a sufficiently fresh upstream project snapshot, pass the current blocklist/age checks, and then use the flow below. A removed reference is unavailable even if its bytes remain cached. Perform locally conclusive denials first: a known malware block or expired blocklist must not wait for upstream metadata. Local absence of a denial does not authorize delivery.

```text
serve(reference):
    reject expired policy or a locally known package/digest block
    ensure current project metadata, refreshing if its TTL expired
    require reference still belongs to that project snapshot
    evaluate current policy using advertised and previously computed digests

    if verified content is cached:
        open and pin the immutable file
    else:
        join or start the bounded shared download for this reference
        stream upstream bytes to a temporary file
        compute SHA-256 and SHA-512 in the same pass
        verify upstream integrity and expected size when available
        require digests equal previously pinned digests for this reference, if any
        persist computed digests, even when policy now blocks them
        reevaluate the latest policy
        atomically publish allowed bytes in the content cache

    revalidate project membership if metadata expired while downloading
    perform the final policy check immediately before response creation
    stream the already verified local file to the client
```

If a computed digest reveals a block not visible in upstream metadata, invalidate that project's filtered metadata. The next resolution hides the affected artifact. The first install may fail instead of falling back; do not pretend that every client retries resolution after a download error.

Compute the archive SHA-256 even when npm supplies only SHA-512 or legacy SHA-1. Enforce SRI verification semantics through a library and reject malformed/conflicting expected integrity data. Preserve upstream integrity fields in client metadata; never generate a replacement digest to conceal an integrity mismatch.

The first complete, upstream-integrity-verified download pins the reference's computed SHA-256 and SHA-512 permanently, including when those bytes are subsequently denied by policy. Cache eviction removes bytes and their content mapping, not these pins. Every later download of that reference must match them. A mismatch is `502 INTEGRITY_MISMATCH`; discard the new bytes and retain the original pins. An incomplete or upstream-integrity-failing download never establishes a pin.

Do not forward any body bytes before full verification. Do not redirect artifact downloads to upstream. Disable HTTP content decoding for artifact transfers so hashes and cached bytes refer to the distribution itself.

Concurrent requests for one reference share one fetch and verification result. Each waiter rechecks policy before its own response starts. Bound active downloads globally. A download failure removes its temporary file and is returned consistently to waiters. A subsequent request may retry; no detached infinite retry loop.

A disconnected waiter releases its request resources without canceling other waiters. If the last waiter leaves before artifact publication, cancel the fetch and remove its temporary file and reservation. Once the durable publication transaction starts, finish that bounded operation and leave a valid cache entry. Apply a 30-second downstream write-idle timeout and a 15-minute response-body lifetime; timeout or disconnect releases file pins and permits. These are initial implementation defaults, to be included in slow-client tests.

Verified cache hits are not rehashed on every request. The data directory is trusted, owned by the service, and inaccessible for untrusted writes. Detect missing files and size mismatches and discard their cache mappings.

Support `GET`, `HEAD`, and a single byte range on a fully verified artifact. `HEAD` has the same policy checks and may require verification on a cold reference. Ignore unsupported multiple ranges and return the complete verified body. Preserve ordinary `206`/`416` semantics for supported ranges.

A request is authorized by its final successful policy check immediately before response creation. Loading the immutable policy snapshot for that check is the ordering point: a request loading it after publication of an update must see the update. A blocklist update does not recall bytes already sent or abort an already authorized response. This is the explicit revocation boundary; it avoids a global lock around network writes.

## 10. State, caching, and bounded work

Persist only:

| Record | Required fields |
| --- | --- |
| Schema | Schema version and the Turso engine/crate version used by this build. |
| Project snapshot | Ecosystem, normalized name, upstream payload, validators, last successful validation time, last full fetch time, generation. |
| Artifact reference | Reference ID, project, version, filename, URL, expected digests, publication/first-seen time, computed digests, optional content key. |
| Content | SHA-256 key, SHA-512, size, creation/access timestamps. |
| Blocklist | Last accepted revision, timestamps, complete validated snapshot. |

Keep relationships sufficient to invalidate a project's rendered responses when its artifact digest knowledge changes. Store timestamps as UTC microseconds since the Unix epoch; use checked arithmetic for deadlines. Logs remain structured stdout; they are not another database table.

Commit a project snapshot, its reference upserts, and new first-seen values together before publishing the new in-memory generation. Reuse existing reference pins. Persist a new blocklist before publishing its memory snapshot. A database error prevents the dependent state change; do not publish a successful response backed only by uncommitted records. Give pending blocklist commits priority over ordinary queued cache maintenance, without interrupting an active transaction.

Cache verified files under a path derived from their content SHA-256. Flush and synchronize the completed temporary file, atomically rename within the same filesystem, synchronize the destination directory, and only then commit its database mapping. Where another reference already published that content key, reuse the verified file without replacing an open file. On startup, let Turso recover its database, remove incomplete artifact temporary files, clear mappings to missing files, and reclaim unreferenced content. Never delete Turso's WAL as temporary artifact cleanup. A crash must never make a temporary file downloadable. Hold an exclusive data-directory process lock.

If database recovery fails, keep readiness false and stop package delivery; never silently recreate the database and lose first-seen times, digest pins, or the blocklist revision. Keep independent backups of configuration, the producer's current blocklist, and the stopped service's complete `state/` directory. Artifact bytes are replaceable; policy and identity records are not. Restore while stopped, reload a current blocklist before readiness, and treat uncertain metadata freshness as expired. No SQLite-to-Turso migration is needed because this task changes a specification, not a deployed database.

Memory caches are bounded and hold parsed project metadata, hot reference records, and serialized filtered responses. On a fully warm request, policy and response lookup require no database query, upstream call, or repeated JSON parsing. Immutable policy snapshots can use `ArcSwap`; ordinary bounded cache synchronization is sufficient elsewhere.

A rendered metadata cache entry is reusable only while all of these match:

- Project snapshot generation.
- Blocklist revision.
- That project's computed-digest generation.
- Requested representation.
- Its expiration deadline.

The deadline is the earliest of upstream metadata TTL, blocklist expiry, and the next held artifact's eligibility time. A released artifact therefore appears without waiting for a background scheduler. Request-time checks still reject expired blocklists and invalid clock-dependent eligibility.

After metadata TTL, revalidate upstream before responding. An upstream `304` renews upstream freshness, but the firewall still rebuilds its policy-dependent representation when required. Coalesce concurrent metadata refreshes for the same project. Do not serve expired metadata during an upstream outage in the MVP.

A cached project snapshot has a maximum age independent of revalidation. Track the last full fetch time separately from the last successful validation time: a `304` renews validation time only, never full fetch time. Once a snapshot's age since its last full fetch reaches `metadata_max_age_seconds`, it is over-age; the next request must fetch it in full, sending no validators, so upstream cannot answer `304`. An over-age snapshot is never served: if the full fetch fails or upstream is unreachable, refuse the request under the existing rule against serving expired metadata, rather than serving the over-age copy. This bounds how long an unchanging or dishonest upstream can hold this firewall's view of a project fixed. It is a freshness bound only; it neither weakens nor substitutes for blocklist enforcement, which invalidates rendered responses on its own revision and does not depend on upstream contact.

Spread the ceiling so that projects fetched together do not all expire together. Each project's effective ceiling is its configured ceiling reduced by a deterministic per-project offset of up to one tenth of that ceiling, derived from the project's own identity so it is stable across restarts and across instances. The offset only ever shortens, so the configured value is never exceeded by the spread itself. Without this, a bulk seed or a restore leaves every snapshot sharing one expiry instant, and an upstream outage that crosses it turns a gradual lapse into a simultaneous fleet-wide refusal.

The precise staleness bound, stated exactly rather than as an absolute, because coalescing makes an absolute unachievable without breaking it: a snapshot is never served beyond `metadata_max_age_seconds` plus at most the duration of one in-flight upstream refresh, itself bounded by the upstream request timeout. The overshoot is reachable only for a request that joins a refresh already in flight, and only when that refresh outlasts the joined project's spread offset — so it requires an offset near zero, which occurs for roughly one project in `metadata_max_age_seconds / 10`, and for every project when the ceiling is configured below ten times the upstream timeout. Requests that do not coalesce onto an in-flight refresh are never served beyond the configured maximum. The overshoot does not compound: the stored full fetch time is never advanced by it, no rendered representation is cached past the ceiling, and the next request that does not coalesce re-evaluates against its own clock and refuses. Closing the gap entirely would require each waiter to re-evaluate freshness after the refresh it joined completes, which contradicts the coalescing requirement above and would convert one refresh into one unconditional full fetch per waiter.

The ceiling applies to project metadata only. It does not apply to verified artifact bytes, which are content-addressed and cannot become stale; their only removal reason remains capacity eviction. It does not apply to cached absent-name marks either: those already expire at `metadata_ttl_seconds` on the monotonic clock and are always rechecked unconditionally, so a ceiling that cannot be shorter than that TTL could never bind on them.

Send `Cache-Control: no-store` on downstream metadata, artifacts, and errors. Do not forward upstream validators or return downstream `304` responses in this release. This avoids intermediaries retaining previously allowed responses. Package managers may still use their own local caches; HTTP headers do not eliminate that boundary.

Disk eviction uses approximate least-recently-used order, with access updates batched off the request path. Never evict open files. Reserve capacity for temporary downloads; count unknown-length downloads against `max_artifact_bytes` until their final size is known. If capacity cannot be reserved or reclaimed, refuse the cold request without deleting in-use files. Reject an artifact exceeding its size cap even when `Content-Length` is missing.

The memory-cache budget excludes the required blocklist and bounded in-flight buffers. Document actual total RSS. Use semaphores and bounded queues; reject overload instead of allowing unbounded waiters or tasks.

The artifact cache limit does not cap the persistent state database or WAL. Monitor their size and filesystem free space separately; preserve sufficient operational headroom for a blocklist commit and checkpoint. Checkpoint with the pinned engine's supported API outside HTTP handling, and verify WAL growth under sustained updates. Do not assume deleting rows shrinks the database file or require experimental in-place vacuum. Storage write failures make readiness false and deny package responses with `503` until storage is usable again; never relax policy to free space.

## 11. HTTP interface, failure behavior, and deployment

| Endpoint | Behavior |
| --- | --- |
| `GET /npm/{package}` | Filtered full or abbreviated npm metadata. |
| `GET /npm/{package}/{version-or-tag}` | Policy-checked individual version metadata. |
| `GET /npm/-/ping` | npm connectivity response. |
| `GET /pypi/simple/` | Known-project index. |
| `GET /pypi/simple/{project}/` | Filtered HTML or JSON file listing. |
| `GET, HEAD /npm/artifacts/{reference_id}/{filename}` | Verified artifact delivery for an npm reference. |
| `GET, HEAD /pypi/artifacts/{reference_id}/{filename}` | Verified artifact delivery for a PyPI reference. |
| `GET /health/live` | Process liveness. |
| `GET /health/ready` | Valid policy, usable storage, service ready; no live upstream probe. |

`{package}` denotes npm's validated logical package name, including scoped names; implement explicit routes rather than a catch-all proxy. Reject request methods outside the supported set.

| Failure | HTTP response |
| --- | --- |
| Exact artifact/version held or blocked | `403`, machine-readable reason. |
| Unknown package/reference or upstream removal | `404`. |
| Invalid input | `400`. |
| Unsupported route/method/representation | `404`, `405`, or `406` as applicable. |
| Missing/expired blocklist, local capacity exhausted, overloaded | `503`. |
| Upstream failure, invalid upstream metadata, integrity failure | `502`; timeout is `504`. |

Policy errors include `error`, `reason`, `request_id`, and, for cooldown, `eligible_at`. Include a numeric `Retry-After` on cooldown responses. Do not require clients to recognize custom error fields for correctness. Log exclusions that cannot be represented in an ecosystem listing.

Use a pooled upstream HTTP client. Set connect timeout to 5 seconds, metadata total timeout to 30 seconds, artifact idle timeout to 30 seconds, and artifact total timeout to 15 minutes. Do not add automatic application-level retries in the MVP; clients can retry failed requests.

Allow only the fixed upstream HTTPS origins. Reject cross-origin redirects, URL credentials, unexpected ports, and addresses resolving to loopback/private/link-local networks. Never forward a client's authorization, cookies, or proxy credentials upstream. Treat package names, filenames, upstream JSON, and HTML attributes as untrusted data.

Example client configuration:

```ini
# .npmrc
registry=https://packages.example.org/npm/
audit=false
```

```ini
# pip.conf
[global]
index-url = https://packages.example.org/pypi/simple/
```

These configure cooperative clients. Enforced use requires network policy that prevents direct public-registry downloads and a controlled cache policy. Alternate indexes, Git/URL dependencies, local wheels, preexisting caches, and installer-initiated network downloads are outside registry-proxy coverage. Existing lockfiles containing direct upstream URLs must be assessed during deployment; never claim that changing one registry setting rewrites every lockfile URL.

Log request ID, ecosystem, package/version when known, policy result, reason, blocklist revision, cache status, duration, and bytes served. Never log credentials. Emit counts and timing summaries periodically to stdout; no separate metrics service is required for the MVP.

## 12. Performance requirements

Fast means the normal request uses a current in-memory decision and existing local data. It does not mean skipping verification. The first artifact download necessarily waits for the complete upstream transfer and hashing; document that cost clearly.

Initial acceptance targets, to be measured rather than advertised as achieved:

| Scenario | Target |
| --- | --- |
| Warm metadata, representative 100-version project | At least 1,000 responses/second with p95 server latency at most 5 ms. |
| Warm policy denial | p95 server latency at most 2 ms. |
| Verified warm artifact | p95 additional time-to-first-byte at most 5 ms versus the same unfiltered local-file server. |
| Verified artifact throughput | At least 85% of that local-file baseline under identical conditions. |
| Concurrent cold requests for one reference | Exactly one successful upstream transfer and verification. |
| Valid blocklist replacement | Active within two configured polling intervals for a 100,000-entry fixture under the benchmark load. |

Reference environment: release build, Linux, four dedicated modern CPU cores, 8 GiB RAM, local NVMe, direct HTTP without TLS, a separate load-generator process, and no upstream internet latency in warm tests. Record CPU model, concurrency, payload sizes, blocklist size, cache state, RSS, and client/server timings. Repeat a separate end-to-end run through the production TLS proxy.

Test both the representative fixture and large real-shaped metadata. Size limits are operational limits and can reject unusually large projects; do not hide that tradeoff. Optimize only measured bottlenecks. Do not add sharding, Redis, background registry mirroring, or speculative prefetching to meet assumed future scale.

## 13. Verification and completion criteria

Use a local deterministic fake registry with harmless package fixtures. Control the clock; do not rely on publishing real packages or downloading malware. The test harness injects its transport and origins into the application constructor; the release binary exposes no origin override or private-address bypass. Test the pure policy first, then protocol behavior, then real package-manager installations.

Required behavior tests:

1. Cooldown before, exactly at, and after the threshold; absent timestamps persist across restart; malformed and future times remain excluded.
2. npm `latest` fallback, preserved eligible tags, blocked custom tags, scoped names, prereleases, exact pins, and transitive/peer constraints.
3. PyPI HTML/JSON equivalence, normalized names, Python compatibility, yanked files, wheel filenames, and a new wheel added to an old release.
4. Package-wide, version-specific, SHA-256, and SHA-512 blocks; newly computed SHA-256 detecting a block absent from npm's advertised SHA-512.
5. Known blocked digests disappear from subsequent metadata; the first download failure is reported without an invented fallback guarantee.
6. Zero artifact body bytes reach a client before cold verification completes; truncated downloads, integrity failures, and blocked bytes never become cache hits.
7. Blocklist replacement invalidates metadata and cached downloads; stale URLs and HEAD/range requests obey the same policy.
8. Snapshot expiry, malformed replacements, rollback rejection, valid empty snapshots, and restart with the last accepted snapshot.
9. Coalesced concurrent downloads, update during a download, bounded overload, disk eviction, and crash recovery around file rename/database commit.
10. Upstream removal, metadata revalidation, cooldown-driven projection expiry, and wall-clock rollback handling.
11. Eviction and refetch preserve pinned digests, including a fixture without a strong advertised digest; changed bytes for the same reference are refused.
12. Cancellation of one/all download waiters, slow downstream consumers, timeout cleanup, and permit/file-pin release.
13. Atomic project/reference publication, file synchronization order, Turso WAL recovery, rollback, disk-full errors, failed recovery, and restoration with a current blocklist.
14. Real-client tests can use test-only local origins while the release configuration continues to reject them.

Run end-to-end installations using pinned, recorded versions of current stable npm and pip at implementation time, plus the previous supported npm major and pip minor. Use `npm install --audit=false` and `npm ci --audit=false`; verify an allowed lockfile succeeds and a blocked pinned dependency fails without rewriting it. Use fresh client caches for proxy enforcement tests and one deliberate cache-reuse test documenting the boundary. Test pip installation and resolution from both wheels and source distributions.

The MVP is complete when these tests pass, benchmark results meet or explicitly revise the agreed targets, startup/operation instructions work from a clean container, and every decision is explainable from the policy and logs. Deliver source, Cargo.lock, container build, sample configuration, sample normalized blocklist, tests, benchmark harness/results, and an operations README. Select an explicit open-source license before public release.

Implement in this order: pure policy and fake-registry fixtures; local Turso persistence/recovery tests; npm and PyPI metadata; artifact verification and cache; client integration; mixed cold/warm load and restart tests. Do not infer persistence speed from Rust alone. Benchmark cold reference reads, batched project writes, blocklist commits under download load, restart recovery, and total process memory for the pinned Turso version. These are production release gates, not reasons to add another database backend.

## 14. Protocol and library references

These references define upstream interfaces; the firewall's policy choices above are product decisions.

- [npm package metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md): full and abbreviated documents, version records, timestamps, and distribution fields.
- [Python Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/): HTML/JSON representations, file hashes, upload timestamps, compatibility, and optional metadata.
- [npm ci](https://docs.npmjs.com/cli/v11/commands/npm-ci/): frozen installation behavior.
- [pip caching](https://pip.pypa.io/en/stable/topics/caching/): client-side caches that can avoid network requests.
- [Axum](https://docs.rs/axum/latest/axum/) and [Reqwest](https://docs.rs/reqwest/latest/reqwest/): HTTP implementation.
- [Turso Rust API](https://docs.turso.tech/sdk/rust/reference), [Turso MIT license](https://github.com/tursodatabase/turso/blob/main/LICENSE.md), and [compatibility reference](https://github.com/tursodatabase/turso/blob/main/COMPAT.md): local persistence.
- [ArcSwap](https://docs.rs/arc-swap/latest/arc_swap/): atomic snapshot publication.

## 15. Review record for revision 2

Review mode: standard specification review with targeted corrections. Target: an implementable single-process MVP; implementation and production readiness are not established by this document review. Reviewed baseline SHA-256: `46eaec2752c5deebc748c256a717af772bd65a223a1ec84351fa16313e1ce18d`.

### Findings and corrections

| ID | Severity | Evidence and failure scenario in revision 1 | Correction and verification |
| --- | --- | --- | --- |
| STATE-01 | High, conditional on absent/weak upstream integrity | Sections 5 and 9 promise immutable references, but refetch verification checks only current upstream integrity. After eviction, a reference without a strong upstream digest could acquire different bytes despite a stored computed digest. | Permanently pin computed digests, retain them on eviction, and compare every refetch. The opposite interpretation was considered: upstream SHA-256/SHA-512 already protects most references, but the baseline explicitly permits weaker/missing integrity, so the invariant still needs this rule. Test 11 closes that path. |
| REL-01 | Medium | Section 10 says rename then database commit, without file/directory synchronization or the joint project/reference transaction boundary. A storage crash can leave committed identity records pointing to nondurable bytes; partial metadata publication can advertise missing references. | Define file sync ordering, atomic project/reference commits, WAL recovery, and failure behavior. Missing bytes are redownloaded against retained pins. Verify with fault injection in test 13. |
| FLOW-01 | Medium | Section 9 coalesces downloads and forbids evicting open files but gives no downstream timeout or last-waiter cancellation behavior. Abandoned work or slow readers can retain download slots, disk reservations, and file pins. | Add waiter ownership, cleanup, and bounded response defaults. Verify both one-waiter and all-waiter cancellation and timeout release in test 12. |
| PERF-01 | Medium | Artifact pseudocode refreshes upstream metadata before checking a locally known malware block. Expired metadata makes a conclusive denial wait on the network, conflicting with the fast-denial intent. | Reject locally conclusive blocks first; authorization still requires fresh metadata. Benchmark this case with an unavailable upstream. |
| TEST-01 | Medium | Section 13 requires a local fake registry, while sections 4 and 11 fix public origins and reject private addresses. No test integration seam is defined. | Add a test-only injected transport/origin set, with no release bypass switch. Test 14 verifies both configurations. |
| OPS-01 | Medium | Section 10 budgets artifact files but does not identify state/WAL capacity, recovery failure, or retained security records. An operator could misread the artifact quota as a complete storage bound or delete state to recover. | Explicitly separate state capacity, preserve the WAL, define storage-failure readiness, stopped backups, and restore rules. State growth remains an operational capacity limit, not an automatic-pruning guarantee. |

These are specification findings and corrections, not reproduced defects in an existing implementation. No confirmed Critical finding remains. STATE-01 is logically validated against the permitted no-strong-digest case; other findings concern missing sequencing or operational behavior.

### Decision and change ledger

| Change | Authority | Source and intent impact |
| --- | --- | --- |
| Select embedded Turso, replacing the earlier SQLite choice and intermediate DuckDB request | Explicit user decision | Native Rust engine and MIT license; package policy is unchanged. |
| Preserve immutable identity, define publication order, and retain recovery-critical records | Clarified/derived from existing invariants | STATE-01, REL-01, OPS-01; makes existing promises enforceable. |
| Define cancellation ownership and initial response timeouts | Clarification plus explicit implementation defaults | FLOW-01 and the bounded-resource requirement; slow clients may need to retry. Thresholds are engineering defaults, not previously established business policy. |
| Move conclusive denials before network work and add test injection | Clarified implementation | PERF-01, TEST-01; preserves policy and enables stated tests. |
| Use one async storage owner and validate pinned Turso semantics | Implementation choice under KISS and the user-selected engine | Avoids transaction interleaving and unnecessary database concurrency. |

License clarification: SQLite itself is public domain and does not require a commercial license; its optional paid Warranty of Title is a separate offering. Turso is chosen for the requested native Rust implementation and conventional MIT terms, not to escape an obligatory SQLite license fee. [SQLite's statement](https://www.sqlite.org/copyright.html).

Post-rewrite verification covered resolution, cooldown, hash enforcement, cache reuse, blocklist replacement, concurrency, recovery, deployment boundaries, and performance/test contracts. JSON and TOML examples were parsed. Protocol compatibility, Turso persistence behavior, and performance have not been executed here. The design can proceed to implementation with the pinned-engine tests above as release gates; production readiness remains unassessed. Client-cache control and external intelligence quality retain their stated MVP boundaries.

## 16. Review record for revision 3

Revision 3 adds one control: a configurable maximum age for a cached project snapshot, so that
repeated upstream `304` answers cannot hold this firewall's view of a project fixed indefinitely.
It adds `metadata_max_age_seconds` to §4, "last full fetch time" to the §10 persistence table, a
ceiling paragraph and a spreading rule to §10, and a clock-dependence paragraph to §5.

The revision was reviewed adversarially before any code was written, and three findings changed
it. The first was a blocker: the draft applied the ceiling to cached absent-name marks as well as
to project snapshots, which cannot work. §4 requires the ceiling to be at least
`metadata_ttl_seconds`, absent marks already expire at exactly that TTL on the monotonic clock and
are rechecked unconditionally, and the mark carries no wall-clock field for a ceiling to read — so
the ceiling could never bind on them, and a test named for it could only have passed by
coincidence with behaviour that already existed. The claim and its test were removed rather than
given a mechanism, because the property they described was already true.

The second finding was that fail-closed expiry needed a spreading rule. Snapshots fetched together
share an expiry instant, so a bulk seed or a restore would make an upstream outage that crosses
the ceiling produce one simultaneous fleet-wide refusal instead of a gradual lapse. The same
property gives an actor who can disrupt only the network path to upstream a new lever: sustaining
that disruption past the ceiling once now takes warm projects offline that previously survived an
outage indefinitely. The deterministic per-project offset in §10 answers the first and bounds the
second; the residual risk is accepted, owned by operations, and documented there rather than left
implicit. The offset only ever shortens a ceiling, so the spread itself never exceeds the
configured value.

The third finding was that the ceiling's clock dependence was stated nowhere, which §5 now covers.

**Amended 2026-09-20, after implementation.** Revision 3 originally stated in §10 that "no snapshot
is served beyond `metadata_max_age_seconds`, and the configured value remains a true maximum."
Implementation and three independent reviews established that this absolute is not achievable
alongside the coalescing requirement in the same section. A request that joins a refresh already in
flight inherits the classification the leader made when it started, so a copy that crosses the
ceiling mid-flight can be served to that joiner — bounded by one upstream request timeout, and
reachable only when the refresh outlasts the joined project's spread offset. §10 now states the
precise bound instead of the absolute. The alternative was rejected on the evidence: re-evaluating
freshness per waiter after the joined refresh completes would convert one refresh into one
unconditional full fetch per waiter, since over-age requests send no validators, which is the
duplicated-upstream-traffic failure the coalescing requirement exists to prevent. The guarantee the
control was asked for — that an unchanging or dishonest upstream cannot hold this firewall's view
of a project fixed — is unaffected, because the overshoot is bounded by a single request timeout,
never advances the stored full fetch time, and cannot compound across requests.

Retained limitation: the review was a self-review rather than an independent pass, because no
isolated reviewer was available in the session that produced it. That is the same constraint
recorded for the two previous adversarial passes on this specification.
