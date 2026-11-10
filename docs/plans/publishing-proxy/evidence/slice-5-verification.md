# Slice 5 verification: VERIFIED (2026-11-10)

Subject: HEAD 89604a6 (matches hosted runs 42656332388 "Native package clients" and 42656332482 "Native call probe", all jobs green).

- Native publishing: 75 client-facing checks pass on linux-x64, darwin-arm64 and win32-x64; zero skipped clients (only two harness unit-test files skip on win32, POSIX-shell fakes).
- Linux policy-server integration: real-server job, 3 native jobs reached the real server, 39 snapshot requests, 0 refused; linux-managed Docker harness green.
- No certificate setup, no firewall-held registry credentials (no repository secrets; per-run throwaway snapshot key; run-time CA is server trust only and removed again).
- molecule-verify: PASS, 9/9 (slice-5-molecule-verify.md).
- Accepted scope and six residuals as recorded in slice-5-engineering.md (user, 2026-11-09).
- Limitations: runtime evidence is hosted-CI logs; independent verifier did not rebuild Rust; local run_tests.py under Node 20 gives 24 findings because the Node 24.22.1 pin guard refuses it (hosted runs on Node 24 pass).
- At merge: remove the temporary push triggers (native-clients.yml, native-call-probe.yml).
