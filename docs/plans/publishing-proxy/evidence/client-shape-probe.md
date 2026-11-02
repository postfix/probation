# Pre-Slice-1 pinned-client request-shape probe

Date: 2026-10-26. **Verdict: client assumptions witnessed; no approved one-URL, certificate, or credential guarantee was contradicted.** These are disposable client-to-fake-registry probes, not the later Probation integration or full release matrix.

## Setup and controls

The fake selected registry was https://registry.test:8443/, served by a local Node TLS server on a Podman internal network (network inspection reported Internal=true). Each client container joined only that network. The server required a client certificate and validated a disposable CA. Its request log recorded method, path/query, credential **category** (not value), TLS authorization, peer CN, Host, and Accept. All 34 recorded HTTP requests had TLS authorization=true, peer CN=probe-client, and Host=registry.test:8443. A request with no client certificate failed TLS with TLSV13_ALERT_CERTIFICATE_REQUIRED before HTTP logging. The browser login URL was displayed but not opened. No real registry was a behavior-probe target; no real registry was mutated or given a probe credential.

The host's docker wrapper is Podman. Inside the normal sandbox it failed at read-only /run/user/1000/libpod; outside the sandbox the daemon and disposable containers worked. Cached images supplied pip 26.2.2 and uv 0.13.5. Exact npm 11.21.1 and Twine 7.0.0 were installed into disposable images using public registry **read-only tool downloads** before the isolated behavior probes. Version commands in those images returned 11.21.1 and twine version 7.0.0. The Python images reported pip 26.2.2 and uv 0.13.5.

The fake registry accepted an owner developer Bearer token for a group-hidden packument and write; it accepted a denied developer token for that packument but refused the write; it refused a separate shared-read token on deprecate preflight. It refused the hidden package artifact even with the owner token. Fake tokens, CA, member key, packages, client configs, and output files lived only in disk-backed .scratch/client-shape-probe/ and were removed after scans. The test server stored only credential categories.

## Exact observed requests

All paths below use registry.test:8443. Empty query means no query string. The TLS and peer result above applies to each recorded HTTP request.

| Pinned client and command | Ordered method and path/query | Credential and outcome |
|---|---|---|
| npm install probe-pkg@1.0.0 | GET /probe-pkg; GET /probe-pkg/-/probe-pkg-1.0.0.tgz | No HTTP Authorization; succeeded with registry-scoped certfile/keyfile and cafile in user config. |
| npm view hidden-pkg version --json | GET /hidden-pkg | Owner Bearer token; returned 1.0.0 with **no later write**. This is the canonical packument path. |
| npm publish, new probe-publisher@1.0.0 | GET /probe-publisher twice; PUT /probe-publisher | Owner Bearer token on all three; succeeded. Both preflight GETs had no query. |
| npm publish, existing hidden-pkg@2.0.0 | GET /hidden-pkg; PUT /hidden-pkg | Owner token: accepted metadata and write. Denied token: metadata accepted, write 403. Shared-read token: metadata 403, then npm **still attempted** PUT, which was separately 403. Preflight denial alone does not stop npm publish. |
| npm deprecate hidden-pkg@1.0.0 retired | GET /hidden-pkg?write=true; PUT /hidden-pkg | Owner token: hidden packument accepted and deprecate succeeded. Denied token: GET accepted, PUT 403. Shared-read token: GET 403 and no PUT. The write=true query is specific to deprecate; publish used a queryless canonical GET. |
| npm web login | POST /-/v1/login; GET /-/v1/login/done | No Authorization at start/poll; fake response displayed browser URL https://browser.example/login; CLI polled the same registry authority and saved the returned fake token in user config. The browser URL was not fetched. |
| npm legacy login --auth-type=legacy | PUT /-/user/org.couchdb.user:probe-user | No Authorization; interactive username/password were in the request body, fake token returned and saved in user config. |
| pip install probe-pkg==1.0.0 | GET /simple/probe-pkg/; GET /files/probe_pkg-1.0.0-py3-none-any.whl | No Authorization; --index-url, --cert CA path and --client-cert combined PEM. Succeeded. |
| uv pip install and project uv sync | Each run: GET /simple/probe-pkg/; HEAD /files/probe_pkg-1.0.0-py3-none-any.whl; GET /files/probe_pkg-1.0.0-py3-none-any.whl twice | No Authorization; SSL_CERT_FILE CA path and SSL_CLIENT_CERT combined PEM. Both succeeded. The extra GET is an observed client behavior, not a distinct origin. |
| Twine upload of the wheel | POST /legacy/ | Basic Authorization from disposable TWINE_USERNAME/TWINE_PASSWORD; --cert CA path and --client-cert combined PEM. Succeeded. |
| Direct hidden-artifact control | GET /hidden-pkg/-/hidden-pkg-1.0.0.tgz | Owner Bearer token, valid client cert; fake registry returned 403. This control used an HTTP client, not npm's install flow. |

For pip the index Accept included application/vnd.pypi.simple.v1+json and HTML; uv sent the same types with slightly different quality values. npm publish preflight preferred application/vnd.npm.install-v1+json then JSON; npm view requested JSON. The fake returned JSON/HTML as appropriate. These headers did not require a second URL.

## Generated files, secrets and egress

npm install wrote package.json, package-lock.json, node_modules/, and its nested lockfile in the disposable project. The lockfile contained the fake registry tarball URL. npm web and legacy login saved fake tokens in their **user-config** .npmrc files; those files also held certificate/key **paths**, not key contents. The npm publish/deprecate project files were just disposable package manifests and code. pip installed the wheel under its disposable target. uv project sync wrote .venv/ and uv.lock; the lockfile contained the fake index and wheel URLs. Twine produced no project file in this run. The combined PEM and private key were mounted only from scratch, outside all package project directories.

A scan of the npm install/publish/hidden project trees and uv project for fake token values and private-key markers found no matches. The user-config files intentionally contained login tokens and were disposed of with scratch. The client network was Internal=true; the sole attached service was the fake registry, and the browser URL was never fetched. This topology plus the server's 34-request log establishes zero direct client connections to an upstream registry or CDN **within this probe**. It is not a packet-level witness for future Probation deployment.

The first Twine attempt failed before HTTP because the disposable CA lacked a keyUsage extension required by its TLS stack. Regenerating the fake CA with keyCertSign/cRLSign resolved it; the final Twine upload succeeded with mTLS. This was a test-fixture correction, not an approved-design contradiction.

## Scope of this result

The one URL and client certificate settings worked for these pinned clients and fake responses. npm publish requires an independent write refusal even when a shared-read preflight receives 403. The later slices still need full Probation admission, live status, group/cache isolation, redirects, issuer integration, scale, and egress witnesses from the approved matrix. No product source or approved design document was changed by this probe.

## D40/D41 version-unpublish shape probe (2026-10-28)

Before D40 source edits, the cached `localhost/probation-e2e-client:npm11.21.1` image reported npm **11.21.1**. A disposable Node HTTPS registry listened only on the local test ports 18443 and 18444, required a client certificate, and served two versions of each probe package. The client received an owner bearer token scoped to the selected registry at 18443. The local self-signed test certificate was trusted only by this disposable client. No real registry was contacted or mutated. `node tests/e2e/harness/run.mjs --list --only E2E-publishing-npm-actions` selected exactly one ID.

Each `npm unpublish <name>@1.0.0 --force --registry=https://localhost:18443/` succeeded and sent this order: two `GET /<name>?write=true`, `PUT /<name>/-rev/1`, another `GET /<name>?write=true`, then a tarball `DELETE` with `/-rev/2`. All recorded HTTP requests had authorized client TLS with peer CN `localhost`. All went to the selected authority at port 18443 with a bearer credential; port 18444 received none. The PUT body retained version `2.0.0` with its exact upstream tarball URL and omitted removed version `1.0.0`.

| Advertised removed-version tarball | Final npm DELETE on selected authority |
|---|---|
| `https://localhost:18443/shape-canonical/-/shape-canonical-1.0.0.tgz` | `/shape-canonical/-/shape-canonical-1.0.0.tgz/-rev/2` |
| `https://localhost:18443/custom/case/shape-same-1.0.0.tgz?sig=same-secret` | `/custom/case/shape-same-1.0.0.tgz/-rev/2` |
| `https://localhost:18444/extra/case/shape-extra-1.0.0.tgz?sig=extra-secret` | `/extra/case/shape-extra-1.0.0.tgz/-rev/2` |

npm drops the advertised query and retargets the extra-origin URL to the selected registry authority for its final DELETE. Thus the proxy must map an opaque local reference to the sealed exact old destination and restore its query itself; it cannot rely on npm to preserve either. This observed client behavior is compatible with the approved D40/D41 lease design, but the direct probe alone does not prove the proxy mapping or extra-origin transport. The disposable probe script and category-only request trace are in `.scratch/d41-shape-probe/`; they are not product source.
