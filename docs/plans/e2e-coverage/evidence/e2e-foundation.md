# E2E foundation: evidence

## Product change: lettre trusts the system certificate store

| | |
|---|---|
| Change | `crates/probation-server/Cargo.toml`: lettre gains the `rustls-native-certs` feature; `Cargo.lock` gains lettre's edge to `rustls-native-certs` 0.8.4 (already in the lock through `rustls-platform-verifier`). |
| Why | `SmtpMailer` (STARTTLS required) was built with lettre's `webpki-roots` only, so it trusted the compiled-in Mozilla roots and nothing else: it ignored the image's `ca-certificates`, `SSL_CERT_FILE` and `SSL_CERT_DIR`. The e2e stack's mail sink presents a test-CA certificate, and delivery failed with `invalid peer certificate: UnknownIssuer`. With both features, lettre loads the native roots in place of the webpki ones. |
| Operator effect | The server now verifies its SMTP relay as it verifies every other outbound call (IdPs, the range API): against the system store, honouring `SSL_CERT_FILE` and `SSL_CERT_DIR`. An internal mail relay signed by a private CA now works once that CA is in the store; before, it could not be used at all. A relay with a public certificate is unaffected (the image's `ca-certificates` holds the same roots). |
| Docs | `docs/management-server.md`, `[portal.smtp] host`. |
| Check | `cargo tree -p probation-server -i rustls-native-certs -e normal` lists `lettre v0.11.23` as a dependent. |
| End to end | `tests/e2e/signup_to_install.sh` (server image rebuilt): the confirmation mail is read from the mailpit sink (STARTTLS required, test-CA certificate); exit 0, `E2E PASS 27.6`, `propagation edits p99 <= interval (4.952 s, interval 10 s)`, `propagation revocations p99 <= interval (5.022 s, interval 10 s)`. No mail is read through SQL. |
