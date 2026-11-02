# Slice 4 direct DELETE and leased URL threat review

Verdict: **MODELED**, 2026-10-28. The amended Gate 3/4 design covers both findings from fresh implementation review. This is design evidence; the revised runtime and source checks remain due.

| Threat | Required boundary | Slice 4 proof |
|---|---|---|
| Direct canonical tarball DELETE bypasses the accepted-removal marker through generic forwarding | Classify the public route as refused, even with a developer bearer | Exact direct-route request returns local refusal with zero upstream calls; fresh security source review checks every DELETE route |
| Revision PUT changes a leased retained version's tarball URL to another HTTPS or same-origin URL | Require the submitted value to equal the exact local link or original leased URL; restore the original before upstream PUT. Versions without a lease may carry ordinary upstream URLs. | Changed leased URL refuses before outbound PUT; unleased ordinary URL passes; outgoing retained link equals the original |
| Cross-member reference, stale or replayed marker | Bind registry/member/package/version/reference and consume the accepted resulting-revision marker once | Two-member, concurrent/replay, expiry and stale-relisting checks |
| Extra-origin SSRF or bearer leak | Recheck current exact origin/path, connected peer and bearer mode; refuse redirects | Signed-query, scope-change, private-peer, redirect and bearer-mode checks |
| Sealed URL leak or dead link | Seal URL with restart-stable key; commit bounded leases before advertising | Key-loss/restore, query-redaction, quota and atomic-failure checks |

No blocking design gap or risk acceptance was found. Existing structural checks cover the reference path and link-restore ordering only; they cannot prove the direct route's zero outbound calls or exact URL equality. Those remain explicit runtime and independent source-review requirements.

## DQA-42 model correction

Fresh threat review returned **MODELED** after the finite model added `changed_leased_tarball_url` and the required `revision-put-changed-leased-url` refusal flow. The model now makes `restored` and `invalid` unavailable for a changed leased URL. This is a declared premise; the Slice 4 runtime witness still must prove exact bytes and zero upstream PUT. Direct canonical DELETE remains a separate public entry point with a zero outbound refusal witness. No risk acceptance or new threat gap was found.
