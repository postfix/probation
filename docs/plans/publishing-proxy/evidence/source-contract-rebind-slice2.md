# Slice 2 source-control rebind

`policy-before-package-send` still requires package resolution to precede npm metadata rendering in `serve_with_url`. Slice 2 adds the selected registry ID, origin and private CIDRs to the existing `resolve` call. The approved unsafe control matched the old six-argument call literally, so it could no longer apply its mutation; the verifier reported `CONTROL_MUTATION` rather than a policy-order failure.

`molecule-contracts.json` now matches the current call exactly and changes only `resolve` to `unchecked_resolve`, retaining every argument. The obligation, analyzer spec, model flow and expected finding are unchanged. The control must produce `Operation 'render' lacks required guard`; production must report no finding. Exact policy decisions, selected registry values, artifacts and age behavior remain assigned to source review and the Slice 2 runtime witness.

Before this rebind, `molecule-check` passed, `current-certificate-before-grant` and both due Slice 2 controls passed, and the expanded enterprise E2E selected one scenario and passed it. The final source and control results are recorded below after rerun.

## Rerun

`router molecule-check` returned `PASS`. `router molecule-verify --slice 2` reported all nine source obligations due through Slice 2 as `PASS`, including `policy-before-package-send` with one detected unsafe control. Its overall verdict was `PENDING` only for three absent sources assigned to Slices 3–4 (`canonical-token-packument`, `origin-before-action-send`, `publisher-auth-before-send`). Evidence: `/home/john/.local/state/software-factory/contract-evidence/run-kVnH9o`.
