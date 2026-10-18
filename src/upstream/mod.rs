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
    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError>;
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
    pub accept: &'static str,
    pub validators: Option<UpstreamValidators>,
    pub max_bytes: u64,
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
    pub max_bytes: u64,
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
    async fn fetch_metadata(
        &self,
        req: MetadataRequest,
    ) -> Result<MetadataResponse, UpstreamError> {
        let _slot = self.slot().await;
        self.inner.fetch_metadata(req).await
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
