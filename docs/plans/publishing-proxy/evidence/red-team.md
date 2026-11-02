# Publishing proxy combined design red-team — C36–C38 recheck

Review kind: red-team  
Verdict: SOUND  
Review: independent  
Subject: slices `04-slices.md`=`0acab5fed921ce98c29528224e2503c6e8e7b32815d93c429e540c0a0ce03e18`; upstream design `03-program-design.md`=`02f6de417b9c0f29a6043ea435402ea15c3047c46fc07957a6b6420c68b3ed31`; architecture `02-architecture.md`=`65dcde19be5e4af8c594dfc722906b9e6223b1cd56d6f2fe5b31c45c1648f00c`; approved product `01-product.md`=`31b1037c3697b949ddb223fff9432eb7eeb875ea4043d787b8d0291257d76658`.  
Bottom line: The thirteen-flow model and thirteen selected source obligations now include audit, with a planned Slice 3 guard-order check and separate byte-level proof. The slices cover the approved URL and audit decisions without an unresolved plan blocker.  
Findings: none; omitted findings: 0.

## Deciding evidence

1. **Audit work is bounded and false-clean refusal is explicit.** `03-program-design.md:97,123` caps audit input/output at M, permits at most 1,024 distinct advisory-package visibility lookups total and 16 concurrent lookups, and shares one 30-second upstream/filter/render deadline. `04-slices.md:43` requires the 1,025th lookup to return an error with no extra upstream call; `03-program-design.md:123` also checks permit release. Malformed or incomplete data errors rather than returning an empty clean report. The updated supplied threat model TM-08 repeats the mitigation and its cap+1 witness.
2. **All certificate modes have explicit X09–X11 results.** `03-program-design.md:127–133` names success/refusal for Probation self-service enabled, Probation self-service disabled and organization-issued modes. Disabled mode denies new bundle issuance while an existing certificate still works; organization-issued mode denies the portal bundle and admits an issuer-provided certificate. `04-slices.md:51` requires all these mode outcomes in the full matrix without skipping. This resolves the matrix's generic every-row/three-mode instruction without treating a prohibited bundle as success.
3. **Audit now has model and source-contract ownership.** `molecule-flow.json:4149–4326,6113–6377` places `serve_audit_read` after classification and admission, with required visible-safe, invalid/incomplete refusal, over-limit refusal and unsupported-bulk outcomes. `molecule-contracts.json:317–341` binds its `audit-policy-safe` flow to planned Slice 3 `src/http/audit_filter.rs::filter_audit_response`; `specs/audit-filter-before-render.yaml` demands `visible_advisories` dominate rendering and its unsafe control replaces that guard with `unchecked_advisories`. The exact `router molecule-check --plan-root docs/plans/publishing-proxy` returned PASS. `03-program-design.md:160` and `04-slices.md:43` explicitly limit the planned source check to call order and assign filtered-value use, response bytes, error semantics, cap+1/no-extra-call/no-permit-leak, real npm 11 detection and independent Slice 3 security source review as delivery proofs.
4. **C36–C38 still have delivery witnesses.** `03-program-design.md:121–124` and `04-slices.md:27,41–43` require legacy `/npm/123/1.0.0` and tarball behavior alongside selected `/registry/npm/<id>/123`, nonempty bulk/quick output without hidden names/versions or upstream text, real npm 11 detection of a visible advisory, and selected-upstream bulk 404 without fabricated quick fallback. The intentionally red audit E2E remains a pre-implementation control, not proof of delivered behavior.
5. **The security and integration interfaces remain ordered.** The selected registry principal, immutable registry ID and scoped state precede audit and actions; real issuer status, token-private packument cache separation, selected-origin transport and group-filtered artifact reads retain named source-review and runtime witnesses (`02-architecture.md:43–71`; `03-program-design.md:119–125`; `04-slices.md:25–29`).

Checked clean: **coverage** — approved C36–C38 and the release matrix have named outcomes; **dependencies** — admission, registry isolation, npm reads/audit, actions and Python follow their interfaces; **risk order** — pinned client probes and issuer/collision checks precede protocol breadth; **foundations** — immutable IDs, current principal, error refusal and bounded audit work precede consumers; **verifiability** — each slice has a client-visible success and refusal check, including cap+1 and all X09–X11 modes; **sizing** — five coherent increments; **hard bar** — age isolation, 10,000 clients, secret/egress checks and nonempty visible audit detection have direct witnesses; **security** — the supplied TM-01–TM-08 boundaries have mitigation and verification properties.  
Threat model: MODELED (supplied `evidence/threat-model.md`=`62c8527c24984c469234e48e15ec5b0251ee192491d201aa5fbadc999aa5c553`).  
Evidence tier: Structural for the finite-model consistency PASS; Manual for plan/contract coverage and the reported synthetic SMTC safe/unsafe result. No source contract, client or E2E check was completed by this review.  
Limitations: `router molecule-verify --plan-root docs/plans/publishing-proxy --slice 2` returned UNKNOWN/EROFS before checks because this host cannot create `/home/john/.local/state/software-factory/contract-evidence/run-XXXXXX`; the reported 10 PASS / 3 future PENDING count was not independently reverified here. The Slice 3 audit source is absent by plan. Exact runtime route separation, safe audit bytes, npm client compatibility, SQL value binding, issuer freshness, cache isolation and egress remain delivery proofs. The design requires a real organization issuer read-after-write status witness before activating that provider.

## Additional evidence hashes

- `evidence/client-operation-matrix.md`=`abd351ca829e6033ff375247617be712c8d64f0db65ac062e46a0aee76071cbc`
- `evidence/research-5.md`=`1f0a5727e3a26c39793ecaf6f05e0352c67976958dd13c48a71f547ed94f6810`
- `evidence/slice-3.md`=`007f70c10d0c7247ff26baafa55a166c82e8d204efe300a34431fa01a2388f07`
- `molecule-flow.json`=`f6525c9c417da58ccab440ba187ae2e5bbfcee77ea46649ecca5ac127d913a18`
- `molecule-contracts.json`=`6b960bb9081c40422d37def153b81f13252e42ee6d19db5369bc40e84e1df823`
- `specs/audit-filter-before-render.yaml`=`0f711f3c225e269ffa23574186ceca127a84a48358524ba788e733394d6285b9`

## SMTC receipt

Root `/home/john/go/src/github.com/postfix/probation`; session `sf-red-team-2026-10-27`. Question-specific SMTC recipes: `irrelevant`; no existing-code behavior decided this plan recheck. Outer/inner status, fidelity/functions analyzed, truncation/ref: not applicable. No SMTC-backed code verdict is claimed. The separate `router molecule-check --plan-root docs/plans/publishing-proxy` exited 0/PASS with no findings, for finite declared model consistency only. `router molecule-verify --plan-root docs/plans/publishing-proxy --slice 2` exited 1/UNKNOWN with EROFS before executing checks; its expected structural obligations were not rerun here.

## D40/D41 reopened design re-review, 2026-10-28

**Verdict: SOUND (cumulative).** The first pass found missing Slice 4 ownership, an early pinned npm shape probe and a quota fixture. The second pass found an unbound DELETE revision. The revised architecture, program design, slices and fifteen-flow model address those findings. The reviewer rechecked the revision binding after the final edit and reported no remaining blocking design gap.

- An administrator approves one selected registry's exact HTTPS origin and segment-boundary path prefix, with explicit extra-origin bearer mode. Parsed outbound paths with ambiguous encoded traversal refuse. Current approval, TLS name, DNS and connected peer are checked at DELETE; redirects refuse.
- `?write=true` preflight may atomically persist a bounded, encrypted member-bound URL lease. Signed query text does not enter links or logs. The revision PUT restores every retained tarball URL before upstream write.
- An accepted PUT removing the exact leased version obtains the resulting revision from its response or an immediate authenticated selected-upstream refetch. A durable marker binds registry, member, reference and revision before PUT success. Denied/unchanged PUTs create no marker; inability to verify or commit after acceptance reports uncertain partial write. DELETE checks the exact revision and consumes the marker atomically once before outbound I/O.
- The pinned npm 11.21.1 probe, wrong-revision, concurrent/replay, sealed-query, changed-approval and quota witnesses remain Slice 4 delivery work. The finite model PASS proves declared routes only; implementation and client behavior are not claimed complete by this review.

**Omitted findings: 0.** Source checks for the absent Slice 4 reference module remain explicitly PENDING by design.
