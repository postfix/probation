# npm two-route credential probe

On 2026-10-25, installed npm 11.16.0 used a disposable loopback registry with separate `/install/` and `/publish/` paths. User-local `.npmrc` set the install path as the default registry, a different bearer token for each path, and project `package.json` set `publishConfig.registry` to the publish path. `npm install probe-dep@1.0.0` and `npm publish --ignore-scripts --access=public` both exited 0.

Captured requests, with values redacted:

| Client operation | Request | Authorization |
|---|---|---|
| install | GET `/install/probe-dep` | shared install token |
| install | GET `/install/probe-dep/-/probe-dep-1.0.0.tgz` | shared install token |
| publish | two GET `/publish/probe-publisher` preflights | publisher token |
| publish | PUT `/publish/probe-publisher` | publisher token |

The local server and projects were removed after the run. This proves npm's path-specific credential selection and `publishConfig.registry` behavior for the installed client only. It does not prove login, deprecate/unpublish, HTTPS, alternate artifact paths, or pinned npm 11.21.1. Release witnesses must cover those and must refuse package-file GET on the publish route. [npm package configuration](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/) documents `publishConfig`.
