# npm audit protocol compatibility

Question: Can Probation convert an npm 11 Bulk Advisory request into an accurate Quick Audit request for a quick-only company registry?

Answer: No general transparent conversion is possible. The pinned npm 11.21.1 client sends package names and installed version arrays to Bulk and has no Quick fallback ([source](https://github.com/npm/cli/blob/v11.21.1/workspaces/arborist/lib/audit-report.js#L317-L384); [11.0.0 fallback removal](https://github.com/npm/cli/blob/v11.21.1/CHANGELOG.md)). The [npm 10.9.4 Quick request](https://github.com/npm/cli/blob/v10.9.4/workspaces/arborist/lib/audit-report.js#L1678-L1726) includes a full dependency tree and runtime metadata absent from Bulk. Its [response conversion](https://github.com/npm/cli/blob/v10.9.4/workspaces/arborist/lib/audit-report.js#L275-L301) can map a valid Quick response into Bulk-style advisories, but cannot recover the missing request data. The [npm 11 audit documentation](https://docs.npmjs.com/cli/v11/commands/npm-audit/) still describes fallback, conflicting with the pinned code and the selected E2E trace.

A shim for one known registry would require that registry to guarantee identical complete advisory sets for valid Quick trees with the same name/version map but different edges and runtime metadata. No such company-registry contract or witness is supplied here. The user clarified that Probation remains a proxy: it forwards and filters the selected registry's audit result, and reports an unsupported upstream operation.

See [the decision and observed trace](npm-audit-fallback.md).
