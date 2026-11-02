# Slice 2 evidence — managed firewall serves each request under its own key's policy (fake server), 401 for missing or unknown keys

## Clarifications
| ID | Class | Status | Question | Decision | Source |
|---|---|---|---|---|---|
| S2-1 | user clarification | resolved | (S1-2) A global admin saves the platform policy with OSV and freeze left empty. What happens? | Keep as is: an empty platform field means OSV Off and freeze 0 for everything below (slice-1 merge default, deviation 3). The firewall does not fail closed and the server does not force values. ADR candidate. | user answer, 2026-10-22 |
| S2-2 | deferred | The per-client lookup allowance (C120) is keyed by the full peer `IpAddr`. A client that rotates addresses inside one IPv6 /64, or uses about 8 IPv4 addresses, can use up the unreserved budget. Found by security review (MINOR) and adversarial testing (design gap). | Deferred to slice 3, where the C113 client-address derivation lands. Key IPv6 by /64 and IPv4-mapped addresses as IPv4. Managed mode is unreleased before slice 8. | security and adversarial review, 2026-10-22 |
| S2-3 | deviation | The C123 scan keys a hit by its "nearest preceding `fn`". That credits `RawConfig.siem_auth_header` to `Cidr::parse`, so harmless edits fail the test, including slice 3's `Cidr::contains`. | Refined to "the nearest preceding item header (`fn`, `struct`, `enum`, `impl`, `mod`)". The guarantee is unchanged, with exact multiset counts. | adversarial review, 2026-10-22 |
| S2-4 | accepted | The `--managed` bench throughput ratio is noisy: 74.6% FAIL once at load average 17, then 107.5, 91.6 and 100.0% when run alone. | The witness is taken from runs on a quiet machine with the load average recorded. A gate in CI would need more rounds and the median of per-round ratios. | code review, 2026-10-22 |
| S2-5 | rejected | Code review suggested replacing the hand-written base64 decoder with the `base64` crate. | Rejected: 03 § Files keeps the bounded standard-alphabet decoder and adds no crate in slices 2–3. Its unit test gets a named-mutant red line instead. | implementer conflict report, 2026-10-22 |
| S2-6 | note, slice 8 docs | The sync client ignores environment proxies (`.no_proxy()`, security fix R1). A site that can only reach the management server through an egress proxy cannot reach it at all. | Document this in docs/operations.md (slice 8). If the need comes up, a proxy setting would be a new design decision. | security re-review, 2026-10-22 |
| S2-7 | accepted | Remaining limits of the C123 token scan, from the round-3 adversarial re-check: (G1) a read moved into another fn that contains a nested `fn authenticate() {}` stays keyed to `authenticate`, because keys use the nearest preceding header; (G2) a `$v fn` from a macro or a `safe fn` is not a header, which only matters together with G1; (G3) `#[instrument(fields(path = …))]` and (G4) `-> impl … + use<T>` fail loudly. | Accepted. G1 and G2 need deliberate obfuscation, which is T19h and is held by T-key-canary and code review; G3 and G4 are loud false failures, never false passes. Exact multiset counts still catch any second read. | adversarial re-check round 3, 2026-10-22 |
| S2-8 | carried forward | Notes from verification for later slices: slice 3 uses `NOT_READY` for a missing peer, a managed `blocklist_revision` once C109 removes the local gate, and a per-place single-flight and budget for layer fetches. Slice 8 adds `config.sample.toml` `[management]` and updates `t_config_management_required` with it, amends C123's key-rule wording for S2-3, and gates B-auth-overhead on the median of per-round ratios. The pre-existing flake `tests/decision_log_delivery.rs::tp16_unopenable_log_path_fails_startup` (a port reused by a parallel test) goes to the backlog. | carried forward | sf-verification, 2026-10-22 |

## Direct witness (main-agent rerun on the final tree, 2026-10-22)
| Command | Observed |
|---|---|
| `cargo test --test managed_mode` | `test result: ok. 10 passed` |
| `cargo test -p probation-policy --lib tests::t_resolve_empty_platform` | `test result: ok. 1 passed` |
| `cargo test --test authorization_read_once` | `test result: ok. 4 passed` (the tree; must-fail mutated copies; must-pass harmless edits) |
| `cargo test --test key_canary` | `test result: ok. 1 passed` |
| `cargo test --workspace` | 36 `test result: ok`, 0 FAILED |
| `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check` | clean |
| `cargo llvm-cov --locked --summary-only --fail-under-lines 98` | 98.46 % lines |
| `docker build .` | exit 0 |
| `router molecule-check` | PASS |
| `router molecule-verify --slice 2` | `authenticate-checks-retired-first` PASS, both controls detected; the 9 later-slice obligations SOURCE_PENDING |
| C123 SMTC query (`smtc callers --callsites-matching '*AUTHORIZATION'`, 2 roots × `get`/`get_all` × argument index 0/1) | exactly 1 site, `headers.get(AUTHORIZATION)` in src/managed/mod.rs |
| `cargo bench --bench warm_metadata --bench artifact_throughput -- --managed` | overhead p95 ≤ 0.022 ms PASS. Metadata throughput 89.4 % FAIL once at load average 18.45; reruns at load 15–18 gave 110.7, 109.6 and 99.1 % PASS; median across about 20 runs about 97 % (S2-4) |
| `cargo bench … -- --assert` | 9/9 `SPEC §12 … PASS`; warm denial p95 1.469–1.751 ms |

## Security coverage
- The SMTC analyzers (sf-verify-cert) pass 9 of 9: managed-auth-retired-checked-first at src/managed, the 4 baselines at their documented roots, and the 4 baselines at src/managed. Every control fires.
- C123 (T19) is held by T-authorization-read-once, T-key-canary and the SMTC query.
- Security review: FIX FIRST, then CLEAR. The fixes were: the sync client uses `.no_proxy()`; a layer revision can never go backwards; durations are bounded; the token must be visible ASCII; and `http://` is refused under C34.
- Deferred: the IPv6 /64 allowance (S2-2).

## Reviews
| Review | Rounds | Final |
|---|---|---|
| code-review | FIX FIRST (eviction test could not fail; stale listing; proxy; layer revision) → SHIP (3 minor) → SHIP (4 minor, fixed) | SHIP |
| security | FIX FIRST (proxy MAJOR; IPv6 allowance; layer revision) → CLEAR | CLEAR |
| adversarial | FIX (listing invalidation; layer revision; token; TTL panic; http loopback; scan gaps) → FIX (refresh pins race; scan key rule) → FIX (cfg_attr path; impl arguments) → FIX (macro-forwarded path, fixed; remaining limits accepted as S2-7) | fixed |
| qa (sf-verification) | FAILED (SPEC.md:10 drift only; everything else VERIFIED) → VERIFIED (SPEC.md:10 fixed; 92 of 95 paths byte-identical, only SPEC.md and plan docs changed; molecule-verify slice-2 obligation PASS) | VERIFIED |

## Changed files
Slice-2 scope: `crates/probation-policy/src/{api.rs,lib.rs}`, `src/managed/{mod.rs,client.rs,cache.rs}`, `src/lib.rs`, `src/config.rs`, `src/http/{mod.rs,error.rs,logging.rs,health.rs,npm_routes.rs,pypi_routes.rs,artifact_routes.rs}`, `src/npm/mod.rs`, `src/pypi/mod.rs`, `src/artifacts/{mod.rs,download.rs}`, `src/store/cache.rs`, `src/delivery/{mod.rs,file.rs}`, `benches/{warm_metadata.rs,artifact_throughput.rs}`, `tests/{managed_mode.rs,authorization_read_once.rs,key_canary.rs,common/mod.rs,npm_metadata.rs,pypi_metadata.rs}`, `SPEC.md`, `docs/adr/0001-consumer-identity-analyzer-allows-exactly-one-read.md`. `src/tasks/mod.rs` was not changed. No `.smtc/analyzers/managed-authorization-read-once.yaml` exists (C123).

Slice 2 presented 2026-10-22 (show-me-slice-2.html). The user chose to continue to slice 3.
