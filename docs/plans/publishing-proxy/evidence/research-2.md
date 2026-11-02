# Python client identity and publisher credentials

Verdict: ANSWERED for client behavior. The selected design uses revocable user/group virtual-host capabilities (Gate 2 C10–C11).

Current pip documentation supports `--index-url` for the selected Simple API. Twine supports an explicit `--repository-url` and publisher HTTP credentials; its source sends Basic credentials on upload. The chosen design uses the user/group host for Probation context and leaves upstream HTTP credentials available to the selected registry.

pip's `--extra-index-url` does not give priority to the primary index: pip considers all configured locations. The approved explicit registry selection therefore needs one selected Probation index, rather than depending on index ordering.

Primary sources: [pip install](https://pip.pypa.io/en/stable/cli/pip_install/), [Twine CLI](https://twine.readthedocs.io/en/stable/), [Twine repository source](https://twine.readthedocs.io/en/stable/_modules/twine/repository.html).

Evidence: current client documentation and Twine 7.0.0 source. No live Probation/client probe was run. Host-capability lookup, revocation and file URL containment still need design and integration checks.
