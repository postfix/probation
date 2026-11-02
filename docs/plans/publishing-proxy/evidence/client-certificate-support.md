# Client certificate feasibility for scope reapproval

The pinned client matrix now requires one registry URL and a TLS client certificate for reads and writes. Primary client documentation provides a configuration path for each baseline client:

| Client | Documented client-certificate setting | Source |
|---|---|---|
| npm 11 | Registry-scoped `certfile` and `keyfile` paths; unscoped `cert` and `key` are deprecated for most registry operations | [npm CLI 11 configuration](https://docs.npmjs.com/cli/v11/using-npm/config/) |
| pip | `--client-cert` / `PIP_CLIENT_CERT`, with certificate and private key in one PEM file | [pip CLI options](https://pip.pypa.io/en/stable/cli/pip/) |
| Twine 7 | `--client-cert` path, with certificate and private key in one PEM file | [Twine 7 command reference](https://twine.readthedocs.io/en/stable/index.html#twine-upload) |
| uv | `SSL_CLIENT_CERT` path, with certificate followed by private key in one PEM file | [uv TLS certificate guide](https://docs.astral.sh/uv/concepts/authentication/certificates/) |

This confirms configuration surfaces, not end-to-end behavior with the pinned versions, SNI, artifact redirects, or web login. The release matrix must exercise each client with a real certificate and verify the certificate/key remain outside committed project files. The server currently has no client-certificate verifier or verified ingress identity in its request path; see [repository structure](repository-structure.md#tls-and-proxy-identity-addendum).
