# 0001 — The consumer-identity analyzer allows exactly one read, not zero

Date: 2026-09-23. Status: accepted. Source: decision-log-delivery Gate 3 C29, raised by the
slice 3 security review (F3).

## Context

`src/http/logging.rs` deliberately reads one inbound-request accessor,
`request.extensions()`, to obtain the peer address for opt-in consumer identification. The
retained analyzer spec that guards "nothing a client sends reaches a record" matches receiver
idioms by call name, and its call-name list cannot see `extensions`. Its pass condition was
zero findings across the product root, and its own prose claimed it fails the moment any
inbound-request accessor call site exists — which was no longer true.

## Decision

A second retained spec, `.smtc/analyzers/consumer-identity-extension-read.yaml`, covers
`extensions` with the same `request|req|parts` receiver idiom. Its pass condition is **exactly
one finding, at `src/http/logging.rs`**, not zero. `extensions` was deliberately not added to
the existing spec.

## Why

Adding `extensions` to the existing spec would fire on the one approved read and destroy that
spec's zero-findings pass condition, leaving no guard at all. Putting the exception in the pass
condition keeps it in the spec rather than in an engine suppression feature this SMTC build is
not confirmed to have. A count moving off 1 is as loud a signal as a zero becoming 1.

## Addendum (2026-10-22, management-server slice 2)

The one approved `extensions` read now also runs when the firewall is managed (`[management]`
set), and the server is then always built with connect-info. `decide` stores the peer address
in the request context; `admit` reads it from there for the per-client lookup allowance (C120),
and from slice 3 the network lock uses the same address (C113). `Decision.consumer` stays
gated on `log_consumer_identification`, so managed mode alone records no address. The pass
condition is unchanged: exactly one finding, in `src/http/logging.rs`.

Managed mode also reads the `Authorization` header, from the handler's `HeaderMap` rather than
from the request, in exactly one function, `Managed::authenticate`. Neither spec here matches
that read, and no analyzer spec can: this SMTC build ignores argument matching in specs
(C123). The same "exactly one" pass condition is held instead by three checks
(docs/plans/management-server/03-program-design.md, C123): `tests/authorization_read_once.rs`
(a token allowlist over `src` and `crates/probation-policy/src`), the SMTC `callers` query on
`get` and `get_all` with `--callsites-matching '*AUTHORIZATION'` (exactly one site), and
`tests/key_canary.rs` (only the key's hash leaves the firewall).
