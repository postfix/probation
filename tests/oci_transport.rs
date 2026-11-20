//! Row 24: the OCI transport against real sockets. A registry answers a blob with a redirect to a signed storage URL; the caller's
//! credential goes to the registry only and is dropped at the first hop, and the redirect is followed only to the one storage origin
//! that is allowed (the public registry's, or the registry descriptor's own archive origin). The registry exchange never follows a
//! redirect and hands back only the headers an OCI client reads.

mod common;

use futures_util::StreamExt;
use probation::upstream::{ArtifactRequest, OciRequest, OriginSet, ReqwestTransport, Transport, UpstreamError};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn origins(registry: &MockServer, storage: &MockServer) -> OriginSet {
    OriginSet::for_tests(Url::parse("https://npm.invalid").unwrap(), Url::parse("https://pypi.invalid").unwrap(), Url::parse("https://files.invalid").unwrap())
        .with_oci(Url::parse(&registry.uri()).unwrap(), Url::parse(&storage.uri()).unwrap())
}

fn blob(registry: &MockServer, authorization: Option<&str>, archive: Option<&MockServer>, redirect: bool) -> ArtifactRequest {
    ArtifactRequest {
        url: Url::parse(&format!("{}/v2/app/blobs/{DIGEST}", registry.uri())).unwrap(),
        origin: None,
        private_cidrs: Vec::new(),
        read_authorization: authorization.map(str::to_owned),
        max_bytes: 1 << 20,
        archive_origin: archive.map(|server| Url::parse(&server.uri()).unwrap()),
        allow_archive_redirect: redirect,
    }
}

async fn bytes_of(transport: &ReqwestTransport, request: ArtifactRequest) -> Result<Vec<u8>, UpstreamError> {
    let mut body = transport.open_artifact(request).await?;
    let mut out = Vec::new();
    while let Some(chunk) = body.stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

async fn mounted(registry: &MockServer, location: &str) {
    Mock::given(method("GET")).and(path(format!("/v2/app/blobs/{DIGEST}"))).respond_with(ResponseTemplate::new(307).insert_header("location", location)).mount(registry).await;
}

fn authorizations(requests: Option<Vec<wiremock::Request>>) -> Vec<Option<String>> {
    requests.unwrap().iter().map(|r| r.headers.get("authorization").map(|v| v.to_str().unwrap().to_owned())).collect()
}

#[tokio::test]
async fn a_blobs_redirect_reaches_the_storage_origin_without_the_callers_credential() {
    let (registry, storage) = (MockServer::start().await, MockServer::start().await);
    mounted(&registry, &format!("{}/signed/xyz?X-Sig=1", storage.uri())).await;
    Mock::given(method("GET")).and(path("/signed/xyz")).respond_with(ResponseTemplate::new(200).set_body_bytes(b"layer".to_vec())).mount(&storage).await;
    let transport = ReqwestTransport::for_origins(origins(&registry, &storage));
    assert_eq!(bytes_of(&transport, blob(&registry, Some("Bearer callers-token"), None, true)).await.unwrap(), b"layer");
    assert_eq!(authorizations(registry.received_requests().await), [Some("Bearer callers-token".to_owned())]);
    assert_eq!(authorizations(storage.received_requests().await), [None], "the storage host never saw the credential");
}

#[tokio::test]
async fn a_redirect_to_any_other_origin_or_without_permission_is_refused_and_nothing_is_asked() {
    let (registry, storage, other) = (MockServer::start().await, MockServer::start().await, MockServer::start().await);
    let transport = ReqwestTransport::for_origins(origins(&registry, &storage));
    // Another host (a hostile registry's choice).
    mounted(&registry, &format!("{}/steal", other.uri())).await;
    let refused = bytes_of(&transport, blob(&registry, Some("Bearer callers-token"), None, true)).await;
    assert!(matches!(refused, Err(UpstreamError::RejectedRedirect { .. })), "{refused:?}");
    assert!(other.received_requests().await.unwrap().is_empty(), "the other host was never contacted");
    // The storage origin, but the transfer is not one that may follow a redirect.
    registry.reset().await;
    mounted(&registry, &format!("{}/signed/xyz", storage.uri())).await;
    let refused = bytes_of(&transport, blob(&registry, None, None, false)).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(storage.received_requests().await.unwrap().is_empty());
}

/// A selected registry (a descriptor with a target) follows a blob's redirect to the archive origin its descriptor declared and to no
/// other: admission is the origin set's, so it is witnessed there (the sockets above cover the transfer itself).
#[test]
fn a_selected_registry_follows_only_to_its_declared_archive_origin() {
    use probation::upstream::OriginKind;
    let url = |text: &str| Url::parse(text).unwrap();
    let selected = OriginSet::selected_npm_with_private(url("https://reg.example.org/artifactory/api/docker/images/"), Vec::new()).unwrap();
    let signed = url("https://blobs.example.org/store/xyz?sig=1");
    assert!(!selected.admits_archive_redirect(OriginKind::NpmMetadata, &signed), "no declared archive origin: no redirect");
    let declared = selected.with_selected_archive(url("https://blobs.example.org/store"));
    assert!(declared.admits_archive_redirect(OriginKind::NpmMetadata, &signed));
    for refused in ["https://evil.example/store/xyz", "https://blobs.example.org.evil.example/store/xyz", "http://blobs.example.org/store/xyz", "https://blobs.example.org/other/xyz", "https://blobs.example.org:8443/store/xyz", "https://user:pw@blobs.example.org/store/xyz"] {
        assert!(!declared.admits_archive_redirect(OriginKind::NpmMetadata, &url(refused)), "{refused}");
    }
}

#[tokio::test]
async fn the_registry_exchange_never_follows_a_redirect_and_returns_only_what_a_client_reads() {
    let (registry, storage) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET")).and(path("/v2/app/manifests/v1")).respond_with(
        ResponseTemplate::new(307).insert_header("location", format!("{}/elsewhere", storage.uri()).as_str()).insert_header("set-cookie", "a=b").insert_header("docker-content-digest", DIGEST).insert_header("www-authenticate", "Bearer realm=\"x\"").insert_header("link", "<x>; rel=\"next\"").insert_header("x-secret", "s"),
    ).mount(&registry).await;
    let transport = ReqwestTransport::for_origins(origins(&registry, &storage));
    let request = |url: String, max: u64| OciRequest { url: Url::parse(&url).unwrap(), origin: None, private_cidrs: Vec::new(), method: axum::http::Method::GET, authorization: Some("Bearer t".into()), accept: None, content_type: None, content_range: None, body: None, max_bytes: max };
    let response = transport.fetch_oci(request(format!("{}/v2/app/manifests/v1", registry.uri()), 1 << 20)).await.unwrap();
    assert_eq!(response.status, 307, "a redirect is the answer it is");
    let names: Vec<&str> = response.headers.iter().map(|(name, _)| *name).collect();
    assert!(names.contains(&"location") && names.contains(&"docker-content-digest") && names.contains(&"www-authenticate") && names.contains(&"link"), "{names:?}");
    assert!(!names.iter().any(|name| name.contains("cookie") || name.contains("secret")), "{names:?}");
    assert!(storage.received_requests().await.unwrap().is_empty(), "the redirect was not followed");
    // A body over its cap is refused, and a URL of another origin is never asked.
    Mock::given(method("GET")).and(path("/big")).respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 5000])).mount(&registry).await;
    let big = transport.fetch_oci(request(format!("{}/big", registry.uri()), 100)).await;
    assert!(matches!(big, Err(UpstreamError::TooLarge { .. })), "{:?}", big.err());
    let foreign = transport.fetch_oci(request(format!("{}/v2/x", storage.uri()), 100)).await;
    assert!(matches!(foreign, Err(UpstreamError::RejectedUrl(_))), "{:?}", foreign.err());
}

/// R3: a foreign layer's own URL is fetched only when it is on the operator's list AND the request carries no credential, and it is decided before
/// a socket is opened (these URLs would otherwise reach the real network, so only the refusals are witnessed here; the list itself is in
/// tests/origin_guard.rs and the whole path in tests/oci_service.rs).
#[tokio::test]
async fn a_foreign_layer_url_is_never_fetched_off_the_list_or_with_a_credential() {
    let (registry, storage) = (MockServer::start().await, MockServer::start().await);
    let transport = ReqwestTransport::for_origins(origins(&registry, &storage));
    let ask = |url: &str, authorization: Option<&str>| ArtifactRequest { url: Url::parse(url).unwrap(), origin: None, private_cidrs: Vec::new(), read_authorization: authorization.map(str::to_owned), max_bytes: 1 << 20, archive_origin: None, allow_archive_redirect: true };
    let off_list = transport.open_artifact(ask("https://elsewhere.example/layer", None)).await;
    assert!(matches!(off_list, Err(UpstreamError::RejectedUrl(_))), "{:?}", off_list.err());
    let credentialed = transport.open_artifact(ask("https://mcr.microsoft.com/layer", Some("Bearer callers-token"))).await;
    assert!(matches!(credentialed, Err(UpstreamError::RejectedUrl(_))), "a listed host with a credential is refused: {:?}", credentialed.err());
    let unlisted_scheme = transport.open_artifact(ask("http://mcr.microsoft.com/layer", None)).await;
    assert!(unlisted_scheme.is_err());
}
