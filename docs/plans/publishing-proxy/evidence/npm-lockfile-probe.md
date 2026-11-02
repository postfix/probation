# npm lockfile omission probe

On 2026-10-25, local npm 11.16.0 installed a disposable package from a loopback fake registry. The project-local configuration set `omit-lockfile-registry-resolved=true`. The install exited 0 and produced lockfile v3; a scan found **no fake registry hostname or port** in `package-lock.json`. The lock entry retained name and version without a `resolved` URL. The fake served a package document with an absolute tarball URL, so the absence was attributable to the npm setting. Temporary files and the local server were removed.

This is a small live probe of the leak control, not a release pass: it used npm 11.16.0, plain loopback HTTP, no virtual host, no redirects, and no `npm ci` replay. The required E2E witness N16 uses pinned npm 11.21.1, HTTPS capability host, selected registry and committed-file scan. [npm configuration](https://docs.npmjs.com/cli/v11/using-npm/config/) documents `omit-lockfile-registry-resolved`.
