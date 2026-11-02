# Slice 4 direct DELETE and leased URL Red Team

Verdict: **SOUND**, 2026-10-28, after the [fresh MODELED threat review](threat-model-direct-delete.md).

The revised design refuses direct canonical tarball DELETE before outbound I/O, including a bearer-bearing request. Every version-unpublish DELETE uses the member-bound reference route with an accepted-removal marker. A revision PUT checks each leased version's submitted URL against its exact local link or exact original upstream URL; changed same-origin and other HTTPS values refuse before PUT, while valid unleased ordinary URLs pass. The Slice 4 witness names exact direct-route zero-outbound and changed-URL controls. Existing structural specs establish only order on the reference path; runtime bytes and route coverage remain due.

No blocking design finding. This is a manual review of the design, not implementation verification.

## DQA-42 recheck

Fresh independent Red Team returned **SOUND** after the finite model added a required refusal route for `changed_leased_tarball_url`. The exact leased URL rule, positive ordinary unleased URL case, direct canonical DELETE refusal, and their Slice 4 witnesses are coherent. Model PASS remains consistency under declared premises; implementation and runtime checks remain due.
