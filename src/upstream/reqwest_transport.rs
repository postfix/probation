//! The production [`Transport`]: two clients, a same-origin redirect policy, and
//! size-capped streaming reads.
//!
//! Two clients and not one because SPEC §11 asks for four timeouts that one
//! `ClientBuilder` cannot carry: `timeout` is a total deadline, so the 30-second
//! metadata deadline and the 15-minute artifact deadline cannot share a client. The
//! metadata client decompresses; the artifact client must not, so that the bytes we
//! hash and cache are the distribution itself (SPEC §9). Two clients means two
//! connection pools, which is accepted.
//!
//! No client header ever comes from a downstream request. Requests are built here
//! from a URL, an `Accept` and — for a revalidation — our own stored validators, so
//! a client's `Authorization`, `Cookie` or `Proxy-Authorization` has nothing to
//! travel on. `no_proxy` is set for the same reason from the other direction: with
//! reqwest's default `system-proxy`, `HTTPS_PROXY` in the environment would send
//! every upstream request, and any credentials in it, to a host of the environment's
//! choosing.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use reqwest::header::{self, HeaderValue};
use reqwest::{Client, ClientBuilder, Response, redirect};
use url::Url;

use crate::upstream::origins::{OriginKind, OriginSet};
use crate::upstream::resolver::GuardedResolver;
use crate::upstream::{
    ArtifactBody, ArtifactRequest, ByteStream, MetadataRequest, MetadataResponse, Transport,
    UpstreamError, UpstreamValidators, capped, collect_capped,
};

/// SPEC §11's four numbers.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const METADATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const ARTIFACT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const ARTIFACT_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// reqwest's custom redirect policy does not carry the default loop protection, so
/// the chain length is bounded here.
const MAX_REDIRECT_HOPS: usize = 5;

const USER_AGENT: &str = concat!("probation/", env!("CARGO_PKG_VERSION"));

pub struct ReqwestTransport {
    origins: OriginSet,
    metadata_client: Client,
    artifact_client: Client,
}

impl ReqwestTransport {
    /// The transport `main.rs` builds. Panics only if TLS cannot be initialised,
    /// which is a broken build or a broken host rather than a runtime condition —
    /// the same bargain `reqwest::Client::new` makes.
    pub fn production() -> ReqwestTransport {
        ReqwestTransport::for_origins(OriginSet::production())
    }

    pub fn for_origins(origins: OriginSet) -> ReqwestTransport {
        let metadata_client = base_builder(&origins)
            .timeout(METADATA_TOTAL_TIMEOUT)
            .build()
            .expect("the metadata client builds");

        let artifact_client = base_builder(&origins)
            .read_timeout(ARTIFACT_READ_TIMEOUT)
            .timeout(ARTIFACT_TOTAL_TIMEOUT)
            // SPEC §9: "Disable HTTP content decoding for artifact transfers so
            // hashes and cached bytes refer to the distribution itself." These three
            // are exactly the codecs this crate enables, so each call turns off
            // something that is really on.
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .build()
            .expect("the artifact client builds");

        ReqwestTransport {
            origins,
            metadata_client,
            artifact_client,
        }
    }

    /// Admission before any request: the URL must belong to a configured origin,
    /// and must pass the same check a redirect hop passes.
    fn admitted(&self, url: &Url) -> Result<OriginKind, UpstreamError> {
        self.origins
            .admit_any(url)
            .map_err(UpstreamError::RejectedUrl)
    }
}

fn base_builder(origins: &OriginSet) -> ClientBuilder {
    Client::builder()
        .tls_backend_rustls()
        .user_agent(USER_AGENT)
        // Nothing about a downstream request travels upstream, not even as a hint.
        .referer(false)
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .dns_resolver(GuardedResolver::new(origins.allows_private_addresses()))
        .redirect(same_origin_policy(origins.clone()))
}

/// Every hop is admitted against the origin the previous hop was on, so a chain
/// cannot walk from one of our registries to another, let alone off the map.
fn same_origin_policy(origins: OriginSet) -> redirect::Policy {
    redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > MAX_REDIRECT_HOPS {
            return attempt.stop();
        }
        let Some(previous) = attempt.previous().last() else {
            return attempt.stop();
        };
        let Some(kind) = origins.kind_of(previous) else {
            return attempt.stop();
        };
        match origins.admit(attempt.url(), kind) {
            Ok(()) => attempt.follow(),
            // `stop` rather than `error`, so the refused hop arrives here as a 3xx
            // response and can be reported as the redirect it was, with its target.
            Err(_) => attempt.stop(),
        }
    })
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn fetch_metadata(
        &self,
        req: MetadataRequest,
    ) -> Result<MetadataResponse, UpstreamError> {
        self.admitted(&req.url)?;

        let mut request = self
            .metadata_client
            .get(req.url.clone())
            .header(header::ACCEPT, req.accept);
        if let Some(validators) = &req.validators {
            if let Some(etag) = validator_header(validators.etag.as_deref()) {
                request = request.header(header::IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = validator_header(validators.last_modified.as_deref()) {
                request = request.header(header::IF_MODIFIED_SINCE, last_modified);
            }
        }

        let response = request.send().await.map_err(upstream_error)?;

        // The status match runs first. `StatusCode::is_redirection` spans the whole
        // `300..400` range, 304 included, and reqwest hands a bare 304 back as an
        // ordinary terminal response rather than routing it through the redirect
        // policy — so a refused-redirect check placed ahead of this would turn every
        // successful revalidation into a `502`.
        match response.status().as_u16() {
            200 => {
                let validators = validators_of(&response);
                let body = collect_capped(byte_stream(response), req.max_bytes).await?;
                Ok(MetadataResponse::Fresh { body, validators })
            }
            304 => Ok(MetadataResponse::NotModified {
                validators: validators_of(&response),
            }),
            404 | 410 => Ok(MetadataResponse::Missing),
            code => match refused_redirect(&response) {
                Some(rejected) => Err(rejected),
                None => Err(UpstreamError::Status(code)),
            },
        }
    }

    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        self.admitted(&req.url)?;

        let response = self
            .artifact_client
            .get(req.url.clone())
            .send()
            .await
            .map_err(upstream_error)?;

        let status = response.status().as_u16();
        if status != 200 {
            return match refused_redirect(&response) {
                Some(rejected) => Err(rejected),
                None => Err(UpstreamError::Status(status)),
            };
        }

        // Advisory only: a declared length lets a caller reserve space, and the cap
        // below is what actually stops an oversized body.
        let declared_length = response.content_length();
        Ok(ArtifactBody {
            declared_length,
            stream: capped(byte_stream(response), req.max_bytes),
        })
    }
}

/// A redirect that reached us is one the policy refused to follow: reqwest returns
/// the redirect response itself rather than the body behind it.
///
/// Exactly the five statuses reqwest routes through a `redirect::Policy`, so a `304`
/// — or a `300`/`305`, which reqwest also treats as terminal — is never mistaken for
/// a refused hop. A redirect status carrying no usable `Location` is not a refused
/// hop either; it is a malformed response, and saying `Status(301)` is truer than
/// inventing a target for it.
fn refused_redirect(response: &Response) -> Option<UpstreamError> {
    if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = response.headers().get(header::LOCATION)?.to_str().ok()?;

    // Resolved against the request URL the way any client resolves a `Location`,
    // because a bare `Url::parse` fails on `/elsewhere` and on `//evil.example/x` —
    // and protocol-relative is the shape an exfiltration attempt is likeliest to
    // use, so reporting the URL we were already at would blind the audit record
    // exactly where it matters. This `join` builds a string for an error, never a
    // request: the hop is already stopped and nothing fetches this URL. Upstream
    // request URLs are still built only by `OriginSet::url_for`.
    let to = response.url().join(location).ok()?;
    Some(UpstreamError::RejectedRedirect { to })
}

fn validators_of(response: &Response) -> UpstreamValidators {
    UpstreamValidators {
        etag: header_string(response, header::ETAG),
        last_modified: header_string(response, header::LAST_MODIFIED),
    }
}

fn header_string(response: &Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// A stored validator is upstream's own bytes, so it is re-validated before it goes
/// back out: a value carrying a newline would otherwise be a request-splitting tool.
fn validator_header(value: Option<&str>) -> Option<HeaderValue> {
    value.and_then(|value| HeaderValue::from_str(value).ok())
}

fn byte_stream(response: Response) -> ByteStream {
    Box::pin(response.bytes_stream().map_err(upstream_error))
}

fn upstream_error(err: reqwest::Error) -> UpstreamError {
    if err.is_timeout() {
        return UpstreamError::Timeout;
    }
    // The resolver's refusal is boxed by hyper and again by reqwest; recovering it
    // keeps a blocked address reported as itself rather than as a connect failure.
    if let Some(found) = refusal_in(&err) {
        return found;
    }
    UpstreamError::Transport(err.to_string())
}

/// The first [`UpstreamError`] in an error's source chain, if one is there.
pub fn refusal_in(err: &(dyn std::error::Error + 'static)) -> Option<UpstreamError> {
    let mut current = Some(err);
    while let Some(err) = current {
        if let Some(upstream) = err.downcast_ref::<UpstreamError>() {
            return Some(upstream.clone());
        }
        current = err.source();
    }
    None
}
