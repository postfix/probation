# SMTC argument matching in specs (premise of C123)

Date: 2026-10-22. SMTC `smtc 0.1.0`, commit e2ded45de151 (dirty build), daemon healthy, `src` root fresh.

- sf-spec-authoring: UNKNOWN for `.smtc/analyzers/managed-authorization-read-once.yaml`.
  - `call_sites.calls` accepts only `name`, `receiver_type` and `package`; `args` is refused as an unknown field.
  - `value_constraints.constant_args` parses but has no effect. With pattern `nomatch_qqq` the probe still returns 7 `headers.get` sites, and no constraint step appears in the trace.
  - `where` filters only on `file`, `line` and `summary`.
- sf-smtc-doctor: UNSUPPORTED.
  - `constant_args` is ignored even for string literals: `dist.get("integrity")` with `constant_args` `integrity` returns all 3 `dist.get` sites, where 1 was expected.
  - `ordered_obligation` refuses `value_constraints`.
  - The compiled schema has no argument-text field.
  - The CLI query `smtc callers --name get --callsites-matching AUTHORIZATION --argument-index 0` does match argument text and returns exactly one site, in src/managed/mod.rs.
  - No newer SMTC build is on disk.
- sf-red-team (C123 re-review): `--callsites-matching` compares the whole argument text exactly. The glob `'*AUTHORIZATION'` also matches `header::AUTHORIZATION` and `&AUTHORIZATION`. `--argument-index 1` catches UFCS calls.
- Re-dispatch sf-spec-authoring for a T19 spec once SMTC enforces argument matching in specs.
