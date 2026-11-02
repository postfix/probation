# Rust same-value checking capability

Verdict: UNAVAILABLE in the installed SMTC backend for the required source property that the validated host/registry context is the exact value used for outbound selection. `sf-spec-authoring` probed a schema-valid `ordered_obligation` with `same_argument` on existing Rust source. SMTC returned `analysis_failed`: `same_argument currently supports TypeScript and JavaScript only`. `sf-smtc-doctor capability` repeated the probe and confirmed the daemon is healthy but no Rust SMTC substitute establishes this value identity.

Source analysis can still check narrower Rust ordering or flow properties, but those do not prove this guarantee. A typed immutable request context, source review and a focused regression test with a wrong-registry substitution are feasible implementation checks. The formal source obligation remains UNKNOWN; no approval should claim SMTC proved it.

The exact probe was `smtc spec run` on `src/upstream/reqwest_transport.rs`, scoped to `ReqwestTransport.fetch_metadata`, with `same_argument` matching guard argument 0 to operation argument 0. No project code or test was changed.
