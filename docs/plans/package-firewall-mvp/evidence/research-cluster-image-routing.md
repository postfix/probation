# Cluster image-pull routing — 2026-11-02

Researcher: sf-research, cluster_pull_routing. Verdict: UNKNOWN for the complete private-registry contract; documented routing candidate found. No runtime probe, deployment change or selected runtime version.

## User clarification — 2026-11-02

Final C1024 clarification: handle requested registries the same way as public registries using the existing forwarding/protection behavior. Keep existing publishing credentials and upstream authorization. The assistant's public-only/authentication-exclusion interpretation was withdrawn; do not use it to remove existing behavior, create a public/private mode or redesign credentials. The research below is historical evidence, not a new product requirement. Cluster routing/no-fallback and cache checks remain relevant. C1022 selects approved-node trust.

## Question and decision

How can Kubernetes/containerd image pulls use a shared enforcing service while retaining the original registry identity and preventing upstream fallback after denial? This supports C1019–C1021, not a claim of delivered compatibility.

## Deciding evidence

1. Containerd CRI config_path and `_default/hosts.toml` can select an explicit service as `server`, with capabilities `pull` and `resolve`. Registry-specific configuration overrides the default and must also enforce this route. A host-only mirror permits upstream fallback. Requests to a different host preserve the original registry in the `ns` query parameter and repository/reference in the path. [Official hosts documentation](https://github.com/containerd/containerd/blob/main/docs/hosts.md#setup-default-mirror-for-all-registries), current main fetched 2026-11-02. Documented, not runtime-tested.
2. Resolve authority covers tag-to-digest resolution; pull authority covers content retrieval. Keep TLS verification enabled and configure trusted CA material. Pull-only routing is insufficient for the selected whole-image path. [Capabilities](https://github.com/containerd/containerd/blob/main/docs/hosts.md#capabilities-field). Documentation at the same snapshot.
3. CRI accepts kubelet authentication parameters, with documented precedence over node-configured credentials. This does not prove correct credential/challenge/token behavior through a differently named service endpoint. Basic/Bearer private-registry forwarding and concurrent credential isolation remain UNKNOWN until the pinned runtime check. Never use the organisation policy key as a registry credential. [CRI registry authentication](https://github.com/containerd/containerd/blob/main/docs/cri/registry.md#configure-registry-credentials).
4. Kubelet asks the node runtime to pull. Every pulling node therefore needs tested endpoint DNS/routing/CA trust, independently of Pod DNS. Endpoint type alone proves no connectivity. [Nodes](https://kubernetes.io/docs/concepts/architecture/nodes/), [images](https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy), [DNS](https://kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/#introduction), [Services](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types). Deployment consequences are inference from official documentation fetched 2026-11-02.
5. Pod NetworkPolicy alone does not establish host-runtime egress control or workload identity at the listener. IfNotPresent/Never may use local cached images. This is pull enforcement, not execution-time revocation or per-workload identity. [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/), [image pull policy](https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy). Documentation plus stated inference.

Documentation conflict: the local-mirror example describes omission of server differently from the detailed server definition. Use the explicit service-as-server candidate and require runtime evidence; do not infer no-fallback from omission.

## Candidate configuration, not an accepted deployment

```toml
server = "https://oci.probation.internal"
capabilities = ["pull", "resolve"]
ca = "/etc/containerd/probation-ca.pem"
```

The cluster administrator must manage every pulling node's runtime configuration and host egress and supply one HTTPS endpoint resolvable/reachable by those nodes. Whether admission trusts approved nodes or requires workload-specific restrictions remains a user-owned choice. The service remains one common policy under C1020.

## Historical broader settling check

These cases record the original research question, not a selected authentication redesign. Preserve existing publishing/authentication regressions and use relevant public/anonymous fixtures for protection checks, including any required OCI challenge. Do not turn C1024 into an instruction to remove credential handling or exclude existing authentication acceptance. Retain tag/digest allow/deny, no-fallback, approved-node reachability and cache checks.

On a disposable node with explicitly pinned containerd/Kubernetes versions and controlled upstream registries:

- Route every participating node through the explicit server; replace conflicting registry-specific configuration.
- Launch four Pods pinned to the test node using original upstream names, imagePullPolicy Always and upstream imagePullSecrets: allowed tag, allowed digest, denied tag, denied digest. Require allow success and deny failure, correlating service, upstream, runtime and network records.
- Repeat Basic and Bearer authentication, invalid credentials and concurrent callers with distinct credentials. Assert original namespace/reference, correct upstream principal, credential isolation and no policy-key disclosure.
- Keep the upstream healthy and reachable; make the service deny and then become unavailable. Use fresh uncached references. Assert zero direct runtime-to-upstream requests, then demonstrate the intended host egress control. Pod failure alone does not establish absent fallback.
- Warm image caches, change policy to deny and repeat tag/digest launches, recording whether the service is consulted. Cached launches limit the guarantee to requests that actually reach the enforcer; they are not execution revocation evidence.

Render this template per case, then run `kubectl apply -f CASE_NAME.yaml`, `kubectl get pod CASE_NAME -o yaml` and `kubectl describe pod CASE_NAME`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: CASE_NAME
spec:
  nodeName: TEST_NODE
  restartPolicy: Never
  imagePullSecrets:
    - name: upstream-fixture
  containers:
    - name: fixture
      image: ORIGINAL_UPSTREAM_REFERENCE
      imagePullPolicy: Always
```

Fixtures need a known long-running default command. No command above has run. Omitted decision-bearing findings: zero. Private authentication, endpoint reachability, no-fallback behavior and cache behavior remain unproven.
