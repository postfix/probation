//! Row 24 fixtures shared by tests/oci_*.rs: an in-process OCI registry (`FakeOci`, a `Transport`) with the real protocol's shapes
//! (a token realm and its `WWW-Authenticate` challenge, manifests that carry their own `Docker-Content-Digest`, blobs that answer a
//! HEAD, tag lists with a `Link`, upload sessions with a `Location`), and builders for images whose digests are real.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use probation::oci::coords::{Algorithm, Digest};
use probation::upstream::{ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, OciRequest, OciResponse, Transport, UpstreamError};

pub const REGISTRY: &str = "https://oci.invalid";
pub const CDN: &str = "https://cdn.invalid";

pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

pub fn sha256(bytes: &[u8]) -> String {
    Digest::of(Algorithm::Sha256, bytes).to_string()
}

pub struct Image {
    pub manifest: Vec<u8>,
    pub digest: String,
    pub config: Vec<u8>,
    pub config_digest: String,
    pub layers: Vec<Vec<u8>>,
    pub layer_digests: Vec<String>,
}

/// An image of `layers` (bytes) with a config naming a build time that is NOT its publication time.
pub fn image(seed: &str, layers: &[&[u8]]) -> Image {
    let config = format!(r#"{{"architecture":"amd64","os":"linux","created":"2001-01-01T00:00:00Z","config":{{"Labels":{{"seed":"{seed}"}}}}}}"#).into_bytes();
    let config_digest = sha256(&config);
    let layer_digests: Vec<String> = layers.iter().map(|layer| sha256(layer)).collect();
    let descriptors: Vec<serde_json::Value> = layers.iter().zip(&layer_digests).map(|(layer, digest)| serde_json::json!({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest, "size": layer.len()})).collect();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config.len()},
        "layers": descriptors,
    })).unwrap();
    Image { digest: sha256(&manifest), manifest, config, config_digest, layers: layers.iter().map(|layer| layer.to_vec()).collect(), layer_digests }
}

pub fn index_of(images: &[&Image]) -> (Vec<u8>, String) {
    let manifests: Vec<serde_json::Value> = images.iter().map(|image| serde_json::json!({"mediaType": OCI_MANIFEST, "digest": image.digest, "size": image.manifest.len(), "platform": {"architecture": "amd64", "os": "linux"}})).collect();
    let body = serde_json::to_vec(&serde_json::json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests})).unwrap();
    let digest = sha256(&body);
    (body, digest)
}

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub authorization: Option<String>,
}

#[derive(Default)]
struct State {
    manifests: HashMap<(String, String), (Vec<u8>, String)>,
    blobs: HashMap<(String, String), Vec<u8>>,
    tags: HashMap<String, (Vec<String>, Option<String>)>,
    referrers: HashMap<(String, String), String>,
    referrer_pages: HashMap<(String, String, String), (String, Option<String>)>,
    catalog: Option<(String, Option<String>)>,
    seen: Vec<Seen>,
    artifacts: Vec<(String, Option<String>, Option<url::Url>, bool)>,
    writes: Vec<(String, String, u64)>,
    require_token: bool,
    basic_only: bool,
    foreign_realm: Option<String>,
    location: Option<String>,
    claimed_digest: Option<String>,
    offline: bool,
    deny_anonymous: bool,
    prefix: String,
    delay_ms: u64,
    in_flight: usize,
    peak: usize,
    big_tags: usize,
    subject_answers: bool,
    foreign: HashMap<String, Vec<u8>>,
    artifact_delay_ms: u64,
}

#[derive(Default)]
pub struct FakeOci {
    state: Mutex<State>,
}

impl FakeOci {
    pub fn new() -> Arc<FakeOci> {
        Arc::new(FakeOci::default())
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    /// Registers an image under a tag and its digest, with its blobs.
    pub fn put_image(&self, repo: &str, tag: Option<&str>, image: &Image) {
        self.with(|s| {
            if let Some(tag) = tag {
                s.manifests.insert((repo.to_owned(), tag.to_owned()), (image.manifest.clone(), OCI_MANIFEST.to_owned()));
            }
            s.manifests.insert((repo.to_owned(), image.digest.clone()), (image.manifest.clone(), OCI_MANIFEST.to_owned()));
            s.blobs.insert((repo.to_owned(), image.config_digest.clone()), image.config.clone());
            for (digest, bytes) in image.layer_digests.iter().zip(&image.layers) {
                s.blobs.insert((repo.to_owned(), digest.clone()), bytes.clone());
            }
        });
    }

    pub fn put_manifest(&self, repo: &str, reference: &str, body: &[u8], media: &str) {
        self.with(|s| {
            s.manifests.insert((repo.to_owned(), reference.to_owned()), (body.to_vec(), media.to_owned()));
        });
    }

    pub fn put_blob(&self, repo: &str, digest: &str, bytes: &[u8]) {
        self.with(|s| {
            s.blobs.insert((repo.to_owned(), digest.to_owned()), bytes.to_vec());
        });
    }

    pub fn put_tags(&self, repo: &str, tags: &[&str], link: Option<&str>) {
        self.with(|s| {
            s.tags.insert(repo.to_owned(), (tags.iter().map(|t| (*t).to_owned()).collect(), link.map(str::to_owned)));
        });
    }

    pub fn put_referrers(&self, repo: &str, digest: &str, body: &str) {
        self.with(|s| {
            s.referrers.insert((repo.to_owned(), digest.to_owned()), body.to_owned());
        });
    }

    /// A paged referrers list: the page that follows `last` (the first page is `""`), and the `Link` it carries.
    pub fn put_referrer_page(&self, repo: &str, digest: &str, last: &str, body: &str, link: Option<&str>) {
        self.with(|s| {
            s.referrer_pages.insert((repo.to_owned(), digest.to_owned(), last.to_owned()), (body.to_owned(), link.map(str::to_owned)));
        });
    }

    pub fn put_catalog(&self, body: &str, link: Option<&str>) {
        self.with(|s| s.catalog = Some((body.to_owned(), link.map(str::to_owned))));
    }

    /// Every read needs `Authorization: Bearer tok-...`; `/token` hands one out (`tok-anon`, or `tok-user` for a Basic credential).
    pub fn require_token(&self) {
        self.with(|s| s.require_token = true);
    }

    pub fn basic_only(&self) {
        self.with(|s| {
            s.require_token = true;
            s.basic_only = true;
        });
    }

    /// The challenge names a realm on another host.
    pub fn foreign_realm(&self, realm: &str) {
        self.with(|s| s.foreign_realm = Some(realm.to_owned()));
    }

    /// What an upload answers in `Location` (default: a relative path).
    pub fn upload_location(&self, location: &str) {
        self.with(|s| s.location = Some(location.to_owned()));
    }

    /// The `Docker-Content-Digest` every manifest answer claims (a lying registry).
    pub fn claim_digest(&self, digest: &str) {
        self.with(|s| s.claimed_digest = Some(digest.to_owned()));
    }

    /// `/token` refuses a caller with no Basic credential (a private registry).
    pub fn deny_anonymous(&self) {
        self.with(|s| s.deny_anonymous = true);
    }

    /// The registry lives under a path prefix (an Artifactory repository does).
    pub fn set_prefix(&self, prefix: &str) {
        self.with(|s| s.prefix = prefix.to_owned());
    }

    /// Every manifest answer waits this long (a registry a network away).
    pub fn set_delay_ms(&self, ms: u64) {
        self.with(|s| s.delay_ms = ms);
    }

    /// The most manifest requests the registry had in flight at once.
    pub fn peak_in_flight(&self) -> usize {
        self.with(|s| s.peak)
    }

    /// The tag list of every repository is this many tags long (about 17 bytes each).
    pub fn big_tag_list(&self, count: usize) {
        self.with(|s| s.big_tags = count);
    }

    /// A manifest PUT is answered with `OCI-Subject` (a registry with the referrers API).
    pub fn answer_oci_subject(&self) {
        self.with(|s| s.subject_answers = true);
    }

    /// A blob download (the registry's, or a foreign layer's) waits this long before it answers (a layer a network away).
    pub fn set_artifact_delay_ms(&self, ms: u64) {
        self.with(|s| s.artifact_delay_ms = ms);
    }

    /// A layer served from a URL of its own (a foreign layer); the fake answers it for any credential-free request.
    pub fn put_foreign(&self, url: &str, bytes: &[u8]) {
        self.with(|s| {
            s.foreign.insert(url.to_owned(), bytes.to_vec());
        });
    }

    pub fn go_offline(&self) {
        self.with(|s| s.offline = true);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.with(|s| s.seen.clone())
    }

    pub fn seen_matching(&self, needle: &str) -> Vec<Seen> {
        self.seen().into_iter().filter(|call| call.path.contains(needle)).collect()
    }

    pub fn count(&self, needle: &str) -> usize {
        self.seen_matching(needle).len()
    }

    pub fn artifact_requests(&self) -> Vec<(String, Option<String>, Option<url::Url>, bool)> {
        self.with(|s| s.artifacts.clone())
    }

    pub fn writes(&self) -> Vec<(String, String, u64)> {
        self.with(|s| s.writes.clone())
    }
}

fn answer(status: u16, headers: &[(&'static str, String)], body: impl Into<Bytes>) -> Result<OciResponse, UpstreamError> {
    Ok(OciResponse { status, headers: headers.to_vec(), body: body.into() })
}

struct InFlight<'a>(&'a FakeOci);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().in_flight -= 1;
    }
}

#[async_trait]
impl Transport for FakeOci {
    async fn fetch_metadata(&self, _req: MetadataRequest) -> Result<MetadataResponse, UpstreamError> {
        Ok(MetadataResponse::Missing)
    }

    async fn fetch_oci(&self, mut req: OciRequest) -> Result<OciResponse, UpstreamError> {
        let (delay, counted) = {
            let mut state = self.state.lock().unwrap();
            let counted = req.url.path().contains("/manifests/");
            if counted {
                state.in_flight += 1;
                state.peak = state.peak.max(state.in_flight);
            }
            (state.delay_ms, counted)
        };
        if delay > 0 && counted {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        let _guard = counted.then(|| InFlight(self));
        let full_path = req.url.path().to_owned();
        let prefix = self.state.lock().unwrap().prefix.clone();
        let path = full_path.strip_prefix(&prefix).unwrap_or(&full_path).to_owned();
        let body_len = match req.body.as_mut() {
            Some((file, length)) => {
                use tokio::io::AsyncReadExt;
                let mut sink = Vec::new();
                file.read_to_end(&mut sink).await.unwrap();
                assert_eq!(sink.len() as u64, *length);
                *length
            }
            None => 0,
        };
        let mut state = self.state.lock().unwrap();
        state.seen.push(Seen { method: req.method.to_string(), path: full_path.clone(), query: req.url.query().map(str::to_owned), authorization: req.authorization.clone() });
        if state.offline {
            return Err(UpstreamError::Transport("offline".into()));
        }
        let origin = format!("{}://{}", req.url.scheme(), req.url.host_str().unwrap());
        if path == "/token" || path == "/jwt/auth" {
            if state.deny_anonymous && !req.authorization.as_deref().is_some_and(|a| a.starts_with("Basic ")) {
                return answer(401, &[], "{}");
            }
            let token = if req.authorization.as_deref().is_some_and(|a| a.starts_with("Basic ")) { "tok-user" } else { "tok-anon" };
            return answer(200, &[("content-type", "application/json".into())], format!(r#"{{"token":"{token}","expires_in":300}}"#));
        }
        let tokened = req.authorization.as_deref().is_some_and(|a| a.starts_with("Bearer tok-"));
        let basic_ok = state.basic_only && req.authorization.as_deref().is_some_and(|a| a.starts_with("Basic "));
        if state.require_token && !tokened && !basic_ok {
            let challenge = if state.basic_only { "Basic realm=\"fake\"".to_owned() } else { format!("Bearer realm=\"{}\",service=\"fake\"", state.foreign_realm.clone().unwrap_or(format!("{origin}{}/token", state.prefix))) };
            return answer(401, &[("www-authenticate", challenge)], "{}");
        }
        let Some(rest) = path.strip_prefix("/v2/").or(if path == "/v2" { Some("") } else { None }) else { return answer(404, &[], "") };
        use probation::oci::coords::{Parsed, parse};
        let Some(parsed) = parse(rest) else { return answer(404, &[], "") };
        let write = !matches!(req.method.as_str(), "GET" | "HEAD") || matches!(parsed, Parsed::Upload { .. });
        if write {
            let name = match &parsed {
                Parsed::UploadStart { name } | Parsed::Upload { name, .. } | Parsed::Manifest { name, .. } | Parsed::Blob { name, .. } => name.clone(),
                _ => return answer(404, &[], ""),
            };
            state.writes.push((req.method.to_string(), format!("{}{}", full_path, req.url.query().map(|q| format!("?{q}")).unwrap_or_default()), body_len));
            let location = state.location.clone().unwrap_or_else(|| format!("{}/v2/{name}/blobs/uploads/uuid-1?_state=opaque", state.prefix));
            return match (req.method.as_str(), &parsed) {
                ("POST", Parsed::UploadStart { .. }) => answer(202, &[("location", location), ("docker-upload-uuid", "uuid-1".into()), ("range", "0-0".into())], ""),
                ("PATCH", _) => answer(202, &[("location", location), ("docker-upload-uuid", "uuid-1".into()), ("range", format!("0-{}", body_len.saturating_sub(1)))], ""),
                ("PUT", Parsed::Upload { .. }) => answer(201, &[("location", format!("{}/v2/{name}/blobs/sha256:{}", state.prefix, "0".repeat(64))), ("docker-content-digest", format!("sha256:{}", "0".repeat(64)))], ""),
                ("PUT", Parsed::Manifest { .. }) => {
                    // A registry with the referrers API says so when a manifest names a subject.
                    let mut headers = vec![("location", format!("{}/v2/{name}/manifests/x", state.prefix))];
                    if state.subject_answers {
                        headers.push(("oci-subject", format!("sha256:{}", "5".repeat(64))));
                    }
                    answer(201, &headers, "")
                }
                ("DELETE", _) => answer(202, &[], ""),
                ("GET", Parsed::Upload { .. }) => answer(204, &[("location", location), ("docker-upload-uuid", "uuid-1".into()), ("range", "0-99".into())], ""),
                _ => answer(405, &[], ""),
            };
        }
        match parsed {
            Parsed::Ping => answer(200, &[], "{}"),
            Parsed::Manifest { name, reference } => {
                let key = (name, reference.text());
                match state.manifests.get(&key).cloned() {
                    Some((body, media)) => {
                        let digest = state.claimed_digest.clone().unwrap_or_else(|| sha256(&body));
                        let mut headers = vec![("content-type", media), ("docker-content-digest", digest)];
                        headers.push(("content-length", body.len().to_string()));
                        answer(200, &headers, if req.method.as_str() == "HEAD" { Vec::new() } else { body })
                    }
                    None => answer(404, &[], r#"{"errors":[{"code":"MANIFEST_UNKNOWN"}]}"#),
                }
            }
            Parsed::Blob { name, digest } => match state.blobs.get(&(name, digest.to_string())) {
                Some(bytes) => answer(200, &[("content-length", bytes.len().to_string())], Vec::new()),
                None => answer(404, &[], ""),
            },
            Parsed::Tags { name } if state.big_tags > 0 => {
                let tags: Vec<String> = (0..state.big_tags).map(|n| format!("tag-{n:012}")).collect();
                answer(200, &[("content-type", "application/json".to_owned())], serde_json::json!({"name": name, "tags": tags}).to_string())
            }
            Parsed::Tags { name } => match state.tags.get(&name).cloned() {
                Some((tags, link)) => {
                    let mut headers = vec![("content-type", "application/json".to_owned())];
                    if let Some(link) = link {
                        headers.push(("link", link));
                    }
                    answer(200, &headers, serde_json::json!({"name": name, "tags": tags}).to_string())
                }
                None => answer(404, &[], ""),
            },
            Parsed::Referrers { name, digest } if !state.referrer_pages.is_empty() => {
                let last = req.url.query_pairs().find(|(k, _)| k == "last").map(|(_, v)| v.into_owned()).unwrap_or_default();
                match state.referrer_pages.get(&(name, digest.to_string(), last)).cloned() {
                    Some((body, link)) => {
                        let mut headers = vec![("content-type", OCI_INDEX.to_owned())];
                        if let Some(link) = link {
                            headers.push(("link", link));
                        }
                        answer(200, &headers, body)
                    }
                    None => answer(404, &[], ""),
                }
            }
            Parsed::Referrers { name, digest } => match state.referrers.get(&(name, digest.to_string())).cloned() {
                Some(body) => answer(200, &[("content-type", OCI_INDEX.into())], body),
                None => answer(404, &[], ""),
            },
            Parsed::Catalog => match state.catalog.clone() {
                Some((body, link)) => answer(200, &link.map(|l| vec![("link", l)]).unwrap_or_default(), body),
                None => answer(404, &[], ""),
            },
            _ => answer(404, &[], ""),
        }
    }

    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        let delay = self.state.lock().unwrap().artifact_delay_ms;
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        let mut state = self.state.lock().unwrap();
        state.artifacts.push((req.url.path().to_owned(), req.read_authorization.clone(), req.archive_origin.clone(), req.allow_archive_redirect));
        state.seen.push(Seen { method: "GET".into(), path: req.url.path().to_owned(), query: None, authorization: req.read_authorization.clone() });
        if state.offline {
            return Err(UpstreamError::Transport("offline".into()));
        }
        if let Some(bytes) = state.foreign.get(req.url.as_str()).cloned() {
            let declared = bytes.len() as u64;
            return Ok(ArtifactBody { declared_length: Some(declared), stream: probation::upstream::capped(Box::pin(futures_util::stream::once(async move { Ok(Bytes::from(bytes)) })), req.max_bytes) });
        }
        if state.require_token && !req.read_authorization.as_deref().is_some_and(|a| a.starts_with("Bearer tok-") || (state.basic_only && a.starts_with("Basic "))) {
            return Err(UpstreamError::Status(401));
        }
        use probation::oci::coords::{Parsed, parse};
        let stripped = req.url.path().strip_prefix(state.prefix.as_str()).unwrap_or(req.url.path()).to_owned();
        let Some(Parsed::Blob { name, digest }) = stripped.strip_prefix("/v2/").and_then(parse) else { return Err(UpstreamError::Status(404)) };
        let Some(bytes) = state.blobs.get(&(name, digest.to_string())).cloned() else { return Err(UpstreamError::Status(404)) };
        let declared = bytes.len() as u64;
        Ok(ArtifactBody { declared_length: Some(declared), stream: probation::upstream::capped(Box::pin(futures_util::stream::once(async move { Ok(Bytes::from(bytes)) })), req.max_bytes) })
    }
}
