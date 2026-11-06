# Local-client platform baseline

Date: 2026-11-02. sf-repo-view `local_auth`; verdict PARTIAL, structural/text evidence. This inventory describes configured builds and documented installation, not successfully shipped or tested desktop clients.

## Findings

- The complete binary matrix in [.github/workflows/release.yml](../../../../.github/workflows/release.yml) contains `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin` and `x86_64-apple-darwin`. It packages probation, README and LICENSE as tarballs with SHA256 files. No Windows binary target is configured.
- [.github/workflows/rust.yml](../../../../.github/workflows/rust.yml) configures formatting, clippy, workspace tests, coverage and pinned npm/pip checks on Ubuntu. Release E2E uses Ubuntu/backend images. The inspected macOS/ARM release entries build binaries; they do not establish native installation, background-service or package-client setup coverage.
- [docs/install.md](../../../install.md) documents cargo installation, source builds, `scripts/build-install.sh`, `scripts/install-local.sh` and links to container/systemd operation. Installer internals and referenced service definitions were outside this bounded pass.
- The existing CLI runs `probation serve --config PATH`, with configuration/blocklist validation commands. Managed settings application relies on an operator-configured supervisor restart. This does not establish a packaged desktop-service lifecycle.
- Previously inspected certificate setup emits a Unix shell script configuring npm, pip, uv and Twine plus certificate files. It does not install a local enforcement process or establish Windows setup.

## Decision needed

Q7 / C1016 selects whether this first installed-client release retains Linux/macOS targets or adds Windows. The selected platforms need explicit native setup, process-lifecycle and package-client acceptance checks during design/delivery. Container availability and portable Rust are not substitutes for those checks.

## Evidence and limits

Repository root: `/home/john/go/src/github.com/postfix/probation`. SMTC session: `sf-local-client-platforms-2026-11-02`. Eight deciding legs succeeded without inner refusal: workflow discovery, Dockerfile discovery, README locator search, Cargo manifest read, complete release matrix read, complete Rust workflow read, README read and installation-document read. Functions analyzed: not applicable; source text/structural orientation only. The capped README search only located subsequent reads. Prior `repository-ecosystem-auth.md` supplies the setup-bundle source evidence.

No builds, downloads, release-run verification, installer/service inspection or native-client tests ran. Configured target coverage is not verified shipped support. No product source changed.
