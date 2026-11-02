# npm 11 authorization at one registry URL

Verdict: ANSWERED. Decision supported: Gate 2 C10, separating policy identity from upstream publisher authorization while retaining one registry URL.

The saved npm 11 probe sent a GET and PUT to `/npm/<package>` and selected the Probation project key for both when it and a publisher token were configured for the same registry URL. Current npm 11 source explains that result: registry credentials are selected by the longest matching host/path, and each request gets one HTTP `Authorization` value; a bearer token takes precedence over Basic. `npm login` stores credentials for its selected registry and `npm publish` uses that registry. A second token for the same URL cannot independently identify the Probation project.

The npm client supports a registry-scoped TLS client certificate and key alongside HTTP token or Basic authorization. This was a research observation, not a design selection: the user explicitly rejected client certificates and selected unguessable, revocable user/group hosts as bearer capabilities in C10–C11. The `npm-scope` header is only routing context.

Primary sources: [npm 11.21.1 lockfile](https://github.com/npm/cli/blob/v11.21.1/package-lock.json), [npm login](https://docs.npmjs.com/cli/v11/commands/npm-login/), [npm publish](https://docs.npmjs.com/cli/v11/commands/npm-publish/), [npm-registry-fetch 19.1.1 auth lookup](https://github.com/npm/npm-registry-fetch/blob/v19.1.1/lib/auth.js), [request header and TLS transport](https://github.com/npm/npm-registry-fetch/blob/v19.1.1/lib/index.js), [.npmrc configuration](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/).

Evidence: npm documentation and inspected pinned-version source. This does not establish Probation's TLS topology, certificate lifecycle or behavior of Python clients; those require separate checks. The earlier live npm probe did not test client certificates.
