//! The outbound boundary: the one seam through which this process reaches a
//! registry, and the one place a byte count is kept while it does.
//!
//! `Transport` is injected (SPEC §13, finding TEST-01), so tests never reach the
//! network and the production implementation is named only in `main.rs`. The two
//! gates that keep a request on a configured origin live beside it: [`origins`],
//! which admits a URL before the request and again on every redirect hop, and
//! [`resolver`], which refuses a loopback, private or link-local answer before a
//! connection is made.

pub mod origins;
pub mod reqwest_transport;
pub mod resolver;

use std::fmt;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use axum::http::Method;
use futures_util::{Stream, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

pub use origins::{OriginKind, OriginSet, UrlRejection};
pub use reqwest_transport::ReqwestTransport;

/// Every upstream read in this crate is one of these two calls. Both take
/// `max_bytes` as a required parameter with no default, so "every upstream read is
/// size-capped" is a property of the signature rather than of the caller.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    async fn fetch_metadata(&self, req: MetadataRequest)
    -> Result<MetadataResponse, UpstreamError>;
    async fn fetch_token_packument(&self, _req: MetadataRequest, _authorization: &str)
    -> Result<MetadataResponse, UpstreamError> {
        Err(UpstreamError::Status(501))
    }
    async fn fetch_named_read(&self, _req: NamedReadRequest) -> Result<Bytes, UpstreamError> {
        Err(UpstreamError::Status(501))
    }
    async fn send_action(&self, _req: ActionRequest) -> Result<ActionResponse, UpstreamError> {
        Err(UpstreamError::Status(501))
    }
    /// One exchange with an OCI registry (a read of a manifest, a tag list, a token, or a write with the caller's own
    /// credential): the status, the headers an OCI client reads and a capped body. Redirects are never followed here (a blob's
    /// redirect is the artifact transfer's, with its own origin rules); a 3xx comes back as the answer it is.
    async fn fetch_oci(&self, _req: OciRequest) -> Result<OciResponse, UpstreamError> {
        Err(UpstreamError::Status(501))
    }
    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError>;
    /// Whether the file at `req.url` exists, and the validators it carries, without reading its body (a Maven file's own
    /// `Last-Modified`). `None` is the repository's 404 or 410. The default reads at most one byte through `fetch_metadata`: a
    /// body over it is "exists" with no validators.
    async fn probe_file(&self, mut req: MetadataRequest) -> Result<Option<UpstreamValidators>, UpstreamError> {
        req.max_bytes = 1;
        match self.fetch_metadata(req).await {
            Ok(MetadataResponse::Fresh { validators, .. }) => Ok(Some(validators)),
            Err(UpstreamError::TooLarge { .. }) => Ok(Some(UpstreamValidators::default())),
            Ok(MetadataResponse::Missing) => Ok(None),
            Ok(MetadataResponse::NotModified { .. }) => Err(UpstreamError::Status(304)),
            Err(error) => Err(error),
        }
    }
}

/// `ETag` and `Last-Modified` as upstream spelled them. Kept for the conditional
/// request that revalidates a snapshot; never forwarded downstream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpstreamValidators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl UpstreamValidators {
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

pub struct MetadataRequest {
    pub url: Url,
    /// Live selected catalog origin; None uses the configured standalone origins.
    pub origin: Option<Url>,
    pub private_cidrs: Vec<ipnet::IpNet>,
    /// Configured registry read credential; never used by token packuments.
    pub read_authorization: Option<String>,
    pub accept: &'static str,
    pub validators: Option<UpstreamValidators>,
    pub max_bytes: u64,
}

pub struct NamedReadRequest {
    pub url: Url,
    pub origin: Url,
    pub private_cidrs: Vec<ipnet::IpNet>,
    pub method: Method,
    pub authorization: Option<String>,
    pub content_encoding: Option<&'static str>,
    pub body: Bytes,
    pub max_bytes: u64,
}

pub struct ActionRequest {
    pub url: Url,
    pub origin: Url,
    pub private_cidrs: Vec<ipnet::IpNet>,
    pub method: Method,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    /// RubyGems' MFA one-time password (`OTP` header), forwarded as the caller sent it.
    pub otp: Option<String>,
    /// NuGet's `X-NuGet-ApiKey`, forwarded as the caller sent it.
    pub api_key: Option<String>,
    pub body: tokio::fs::File,
    pub body_len: u64,
    pub max_bytes: u64,
}

pub struct OciRequest {
    pub url: Url,
    /// The registry's own origin (a token realm's origin for a token request); `None` is the default registry.
    pub origin: Option<Url>,
    pub private_cidrs: Vec<ipnet::IpNet>,
    pub method: Method,
    pub authorization: Option<String>,
    pub accept: Option<String>,
    pub content_type: Option<String>,
    pub content_range: Option<String>,
    /// A body spooled to a file, and its length.
    pub body: Option<(tokio::fs::File, u64)>,
    pub max_bytes: u64,
}

/// The headers of an OCI answer a client reads (names lower case); everything else stays behind.
pub struct OciResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

impl OciResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| *key == name).map(|(_, value)| value.as_str())
    }
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers.iter().filter(move |(key, _)| *key == name).map(|(_, value)| value.as_str())
    }
}

pub struct ActionResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Bytes,
}

pub enum MetadataResponse {
    Fresh {
        body: Bytes,
        validators: UpstreamValidators,
    },
    NotModified {
        validators: UpstreamValidators,
    },
    /// Upstream `404` or `410`: the project is not there, which is a different
    /// answer from "we could not ask" (SPEC §11's `404` row, not its `502` row).
    Missing,
}

pub struct ArtifactRequest {
    pub url: Url,
    pub origin: Option<Url>,
    pub private_cidrs: Vec<ipnet::IpNet>,
    pub read_authorization: Option<String>,
    pub max_bytes: u64,
    /// A Go registry's declared archive origin (descriptor `archive_origin`): the one other origin and
    /// path prefix a redirect of its zip may land on. `None` for every other request.
    pub archive_origin: Option<Url>,
    /// A Go `.zip` transfer: the only request whose redirect may land on an archive origin (the proxy's
    /// bucket, or the registry's declared one). Never set for `.info`, `.mod` or any other family.
    pub allow_archive_redirect: bool,
}

/// A stream of body bytes that has already been capped. Errors are ours, not
/// reqwest's, so no caller of `Transport` depends on the HTTP client.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, UpstreamError>> + Send>>;

pub struct ArtifactBody {
    /// `Content-Length` when upstream declared one. Advisory: the cap is enforced
    /// by counting bytes, never by trusting this.
    pub declared_length: Option<u64>,
    pub stream: ByteStream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamError {
    Timeout,
    Transport(String),
    Status(u16),
    TooLarge {
        limit: u64,
    },
    RejectedUrl(UrlRejection),
    RejectedRedirect {
        to: Url,
    },
    /// The chain was still on the admitted origin when it reached the hop limit;
    /// `to` is the hop that was not followed.
    RedirectLimit {
        to: Url,
    },
    RejectedAddress {
        addr: IpAddr,
    },
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Timeout => write!(f, "the upstream request timed out"),
            UpstreamError::Transport(reason) => write!(f, "upstream transport failure: {reason}"),
            UpstreamError::Status(code) => write!(f, "upstream answered {code}"),
            UpstreamError::TooLarge { limit } => {
                write!(f, "the upstream body exceeds the {limit}-byte cap")
            }
            UpstreamError::RejectedUrl(rejection) => {
                write!(f, "the upstream URL was refused: {rejection}")
            }
            UpstreamError::RejectedRedirect { to } => {
                write!(f, "refused to follow a redirect to {to}")
            }
            UpstreamError::RedirectLimit { to } => {
                write!(f, "stopped at the redirect limit before following {to}")
            }
            UpstreamError::RejectedAddress { addr } => {
                write!(f, "refused to connect to {addr}")
            }
        }
    }
}

impl std::error::Error for UpstreamError {}

/// SPEC §4's `max_upstream_requests`: at most this many calls open to upstream at
/// once, across every registry and both kinds of call. A call beyond it waits for a
/// slot rather than being refused — the requests waiting are already bounded by
/// `max_active_requests`, and refusing would turn a burst of cold requests into
/// errors that one more second would have answered.
///
/// An artifact call keeps its slot until its body is dropped, because that is how
/// long it holds a connection to upstream.
pub struct Limited {
    inner: Arc<dyn Transport>,
    slots: Arc<Semaphore>,
}

impl Limited {
    pub fn wrap(inner: Arc<dyn Transport>, max_upstream_requests: usize) -> Arc<dyn Transport> {
        Arc::new(Limited {
            inner,
            slots: Arc::new(Semaphore::new(max_upstream_requests)),
        })
    }

    async fn slot(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("the upstream limiter is never closed")
    }
}

#[async_trait]
impl Transport for Limited {
    async fn send_action(&self, req: ActionRequest) -> Result<ActionResponse, UpstreamError> {
        let _slot = self.slot().await;
        self.inner.send_action(req).await
    }

    async fn fetch_metadata(
        &self,
        req: MetadataRequest,
    ) -> Result<MetadataResponse, UpstreamError> {
        let _slot = self.slot().await;
        self.inner.fetch_metadata(req).await
    }

    async fn fetch_token_packument(&self, req: MetadataRequest, authorization: &str)
    -> Result<MetadataResponse, UpstreamError> {
        let _slot = self.slot().await;
        self.inner.fetch_token_packument(req, authorization).await
    }

    async fn fetch_named_read(&self, req: NamedReadRequest) -> Result<Bytes, UpstreamError> {
        let _slot = self.slot().await;
        self.inner.fetch_named_read(req).await
    }

    async fn probe_file(&self, req: MetadataRequest) -> Result<Option<UpstreamValidators>, UpstreamError> {
        let _slot = self.slot().await;
        self.inner.probe_file(req).await
    }

    async fn fetch_oci(&self, req: OciRequest) -> Result<OciResponse, UpstreamError> {
        let _slot = self.slot().await;
        self.inner.fetch_oci(req).await
    }

    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        let slot = self.slot().await;
        let body = self.inner.open_artifact(req).await?;
        Ok(ArtifactBody {
            declared_length: body.declared_length,
            stream: Box::pin(body.stream.map(move |chunk| {
                let _held = &slot;
                chunk
            })),
        })
    }
}

/// Wraps `stream` so it fails the moment the running total passes `max_bytes`.
///
/// reqwest exposes no response-size cap, and decompression has none either, so this
/// counted loop is the only thing standing between a hostile upstream and memory or
/// disk. It aborts on the chunk that crosses the cap rather than after the body
/// finishes, and it never buffers the whole body to find out.
pub fn capped(stream: ByteStream, max_bytes: u64) -> ByteStream {
    Box::pin(futures_util::stream::unfold(
        (stream, 0u64, false),
        move |(mut stream, total, finished)| async move {
            if finished {
                return None;
            }
            match stream.next().await {
                None => None,
                Some(Err(err)) => Some((Err(err), (stream, total, true))),
                Some(Ok(chunk)) => {
                    let total = total.saturating_add(chunk.len() as u64);
                    if total > max_bytes {
                        let err = UpstreamError::TooLarge { limit: max_bytes };
                        Some((Err(err), (stream, total, true)))
                    } else {
                        Some((Ok(chunk), (stream, total, false)))
                    }
                }
            }
        },
    ))
}

/// The same counted loop, drained into one buffer. This is how a metadata body
/// becomes bytes; `reqwest::Response::bytes()` is never called anywhere in this
/// crate, because it would read the whole body before anyone could object.
pub async fn collect_capped(stream: ByteStream, max_bytes: u64) -> Result<Bytes, UpstreamError> {
    let mut stream = capped(stream, max_bytes);
    let mut buffer = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        buffer.extend_from_slice(&chunk?);
    }
    Ok(buffer.freeze())
}
