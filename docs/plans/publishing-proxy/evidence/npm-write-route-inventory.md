# Selected npm mutation route inventory

Source review: `src/http/mod.rs` route table, `src/http/registry_routes.rs` handlers, and `src/http/registry_action.rs` named-action classifier, inspected on 2026-10-28. This inventory sets the Slice 4 source-review denominator together with [N05–N23](client-operation-matrix.md). It is structural evidence, not an executed authorization test.

| Public selected route | Method | Action boundary |
|---|---|---|
| `/registry/npm/<id>/<package>` | PUT | Named package publish forwards to selected upstream after developer authorization. |
| `/registry/npm/<id>/<package>/-rev/<revision>` | PUT | Revision body passes lease-link restoration and accepted-removal marker rules before selected-upstream send. |
| `/registry/npm/<id>/<package>/-rev/<revision>` | DELETE | Whole-package removal forwards to selected upstream under developer authorization; no version-tarball marker. |
| `/registry/npm/<id>/<package>/-/<filename>/-rev/<revision>` | DELETE | Direct canonical tarball deletion refuses locally. |
| `/registry/npm/<id>/artifacts/<reference-id>/<filename>/-rev/<revision>` | DELETE | Member-bound lease and one-use accepted-removal marker precede the vetted destination send. |
| `/registry/npm/<id>/-/<named action>` | PUT/POST/DELETE | Classifier admits only named login, package settings, dist-tag, access, owner, organization/team, profile, token, star, stage and trust operations; selected upstream decides authorization. Web-login start/poll may be tokenless; legacy login sends Basic username/password to the selected registry; later actions require a developer token. |
| Other selected mutations, including PATCH | any | Refuse locally before outbound action. |

N05–N23 also include adjacent read operations (whoami, ping, list, profile get, token list, stars and stage/trust list). Each must be checked against its named route and read/admission rule. A complete route review checks each matrix row's classifier, selected destination, credential mode, upstream allow/deny result and local refusal where applicable. The prior security review's SMTC entry inventory was incomplete, so dynamic dispatch completeness remains a source-review and pinned-client obligation. The finite model and structural source checks do not prove exact route or credential values.
