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
use bytes::Bytes;
use futures_util::TryStreamExt;
use reqwest::header::{self, HeaderName, HeaderValue};
use reqwest::{Client, ClientBuilder, Response, redirect};
use tokio::io::AsyncReadExt;
use url::Url;

use crate::upstream::origins::{OriginKind, OriginSet};
use crate::upstream::resolver::GuardedResolver;
use crate::upstream::{
    ActionRequest, ActionResponse, ArtifactBody, ArtifactRequest, ByteStream, MetadataRequest,
    MetadataResponse, NamedReadRequest, OciRequest, OciResponse, Transport, UpstreamError,
    UpstreamValidators, capped, collect_capped,
};

/// SPEC §11's four numbers.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const METADATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const ARTIFACT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const ARTIFACT_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// An action body above this is an upload: it gets the 15-minute lifetime, not the
/// 30-second metadata deadline. reqwest's `read_timeout` also runs while the request body
/// is still being sent, so it cannot serve as the write-idle limit here.
// ponytail: size threshold and a lifetime only, no write-idle timer (reqwest has none); a
// stalled upstream write holds its permit up to 15 minutes. Add a body-progress watchdog if that matters.
const UPLOAD_BODY_BYTES: u64 = 1 << 20;

/// reqwest's custom redirect policy does not carry the default loop protection, so
/// the chain length is bounded here.
const MAX_REDIRECT_HOPS: usize = 5;

const USER_AGENT: &str = concat!("probation/", env!("CARGO_PKG_VERSION"));

pub struct ReqwestTransport {
    origins: OriginSet,
    metadata_client: Client,
    artifact_client: Client,
    /// The artifact client without the archive redirect (a Go `.info` or `.mod`, and every other family).
    plain_artifact_client: Client,
    /// LS-F9: applied to every selected (snapshot-sourced) registry.
    service_deny: Option<std::sync::Arc<crate::http::service_connector::Denylist>>,
}

impl ReqwestTransport {
    /// The transport `main.rs` builds. Panics only if TLS cannot be initialised,
    /// which is a broken build or a broken host rather than a runtime condition —
    /// the same bargain `reqwest::Client::new` makes.
    pub fn production() -> ReqwestTransport {
        ReqwestTransport::for_origins(OriginSet::production())
    }

    pub fn for_origins(origins: OriginSet) -> ReqwestTransport {
        let metadata_client = base_builder(&origins, false)
            .timeout(METADATA_TOTAL_TIMEOUT)
            .build()
            .expect("the metadata client builds");

        let plain_artifact_client = base_builder(&origins, false)
            .read_timeout(ARTIFACT_READ_TIMEOUT)
            .timeout(ARTIFACT_TOTAL_TIMEOUT)
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .build()
            .expect("the plain artifact client builds");

        let artifact_client = base_builder(&origins, true)
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
            plain_artifact_client,
            service_deny: None,
        }
    }

    /// Snapshot-sourced registries (every selected origin) are dialled under this denylist
    /// (LS-F9). Standalone and legacy targets keep their own gate.
    pub fn with_denylist(
        mut self,
        deny: std::sync::Arc<crate::http::service_connector::Denylist>,
    ) -> ReqwestTransport {
        self.service_deny = Some(deny);
        self
    }

    /// Admission before any request: the URL must belong to a configured origin,
    /// and must pass the same check a redirect hop passes.
    fn admitted(origins: &OriginSet, url: &Url) -> Result<OriginKind, UpstreamError> {
        origins.admit_any(url).map_err(UpstreamError::RejectedUrl)
    }

    fn selected(
        &self,
        origin: Option<&Url>,
        private_cidrs: &[ipnet::IpNet],
        artifact: bool,
        follow_redirects: bool,
    ) -> Result<(OriginSet, Client), UpstreamError> {
        self.selected_within(
            origin,
            private_cidrs,
            artifact,
            follow_redirects,
            METADATA_TOTAL_TIMEOUT,
            None,
            false,
        )
    }

    /// `archive`: a Go registry's declared archive origin, the one other origin a redirect of its zip may land on.
    #[allow(clippy::too_many_arguments)]
    fn selected_within(
        &self,
        origin: Option<&Url>,
        private_cidrs: &[ipnet::IpNet],
        artifact: bool,
        follow_redirects: bool,
        metadata_total: Duration,
        archive: Option<&Url>,
        archives: bool,
    ) -> Result<(OriginSet, Client), UpstreamError> {
        let origins = match origin {
            Some(origin) => {
                let selected =
                    OriginSet::selected_npm_with_private(origin.clone(), private_cidrs.to_vec())
                        .map_err(UpstreamError::RejectedUrl)?;
                let selected = match archive {
                    Some(archive) => selected.with_selected_archive(archive.clone()),
                    None => selected,
                }
                .with_foreign_of(&self.origins);
                match &self.service_deny {
                    Some(deny) => selected.with_denylist(std::sync::Arc::clone(deny)),
                    None => selected,
                }
            }
            None if follow_redirects => {
                return Ok((
                    self.origins.clone(),
                    match (artifact, archives) {
                        (true, true) => self.artifact_client.clone(),
                        (true, false) => self.plain_artifact_client.clone(),
                        (false, _) => self.metadata_client.clone(),
                    },
                ));
            }
            None => self.origins.clone(),
        };
        let mut builder = base_builder(&origins, artifact && archives);
        if !follow_redirects {
            // A developer credential may only reach the canonical packument URL.
            builder = builder.redirect(redirect::Policy::none());
        }
        if artifact {
            builder = builder
                .read_timeout(ARTIFACT_READ_TIMEOUT)
                .timeout(ARTIFACT_TOTAL_TIMEOUT)
                .no_gzip()
                .no_brotli()
                .no_zstd();
        } else {
            builder = builder.timeout(metadata_total);
        }
        let client = builder
            .build()
            .map_err(|err| UpstreamError::Transport(err.to_string()))?;
        Ok((origins, client))
    }
}

/// `archives`: the client of an artifact transfer, whose redirects may also land on a Go proxy's archive origin.
fn base_builder(origins: &OriginSet, archives: bool) -> ClientBuilder {
    Client::builder()
        .tls_backend_rustls()
        .user_agent(USER_AGENT)
        // Nothing about a downstream request travels upstream, not even as a hint.
        .referer(false)
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .dns_resolver(GuardedResolver::with_denylist(
            origins.allows_private_addresses(),
            origins.private_cidrs().to_vec(),
            origins.denylist(),
            origins
                .origin(OriginKind::NpmMetadata)
                .port_or_known_default(),
        ))
        .redirect(same_origin_policy(origins.clone(), archives))
}

/// Every hop is admitted against the origin the previous hop was on, so a chain
/// cannot walk from one of our registries to another, let alone off the map.
fn same_origin_policy(origins: OriginSet, archives: bool) -> redirect::Policy {
    redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > MAX_REDIRECT_HOPS {
            // An error rather than `stop`, so it reaches the caller as itself: a
            // `stop` here would look exactly like a refused cross-origin hop.
            let limit = UpstreamError::RedirectLimit {
                to: attempt.url().clone(),
            };
            return attempt.error(limit);
        }
        let Some(previous) = attempt.previous().last() else {
            return attempt.stop();
        };
        let Some(kind) = origins.kind_of(previous) else {
            // A foreign layer's URL redirects only within the foreign list (credentials were never sent to it).
            return if archives
                && origins.admits_foreign(previous)
                && origins.admits_foreign(attempt.url())
            {
                attempt.follow()
            } else {
                attempt.stop()
            };
        };
        match origins.admit(attempt.url(), kind) {
            Ok(()) => attempt.follow(),
            Err(_) if archives && origins.admits_archive_redirect(kind, attempt.url()) => {
                attempt.follow()
            }
            // `stop` rather than `error`, so the refused hop arrives here as a 3xx
            // response and can be reported as the redirect it was, with its target.
            Err(_) => attempt.stop(),
        }
    })
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn send_action(&self, req: ActionRequest) -> Result<ActionResponse, UpstreamError> {
        let total = if req.body_len > UPLOAD_BODY_BYTES {
            ARTIFACT_TOTAL_TIMEOUT
        } else {
            METADATA_TOTAL_TIMEOUT
        };
        let (origins, client) = self.selected_within(
            Some(&req.origin),
            &req.private_cidrs,
            false,
            false,
            total,
            None,
            false,
        )?;
        Self::admitted(&origins, &req.url)?;
        let mut request = client
            .request(req.method, req.url)
            .header(header::ACCEPT, "application/json");
        if let Some(authorization) = req.authorization {
            request = request.header(
                header::AUTHORIZATION,
                HeaderValue::from_str(&authorization).map_err(|_| UpstreamError::Status(400))?,
            );
        }
        if let Some(content_type) = req.content_type {
            request = request.header(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type).map_err(|_| UpstreamError::Status(400))?,
            );
        }
        if let Some(otp) = req.otp {
            request = request.header(
                "OTP",
                HeaderValue::from_str(&otp).map_err(|_| UpstreamError::Status(400))?,
            );
        }
        if let Some(api_key) = req.api_key {
            let mut value =
                HeaderValue::from_str(&api_key).map_err(|_| UpstreamError::Status(400))?;
            value.set_sensitive(true);
            request = request.header("X-NuGet-ApiKey", value);
        }
        let body = futures_util::stream::try_unfold(req.body, |mut file| async move {
            let mut chunk = [0u8; 64 * 1024];
            let count = file.read(&mut chunk).await?;
            Ok::<_, std::io::Error>(
                (count != 0).then(|| (Bytes::copy_from_slice(&chunk[..count]), file)),
            )
        });
        let response = request
            .header(header::CONTENT_LENGTH, req.body_len.to_string())
            .body(reqwest::Body::wrap_stream(body))
            .send()
            .await
            .map_err(upstream_error)?;
        check_connected_peer(&response, &origins)?;
        if let Some(rejected) = refused_redirect(&response) {
            return Err(rejected);
        }
        let status = response.status().as_u16();
        let content_type = header_string(&response, header::CONTENT_TYPE);
        let body = collect_capped(byte_stream(response), req.max_bytes).await?;
        Ok(ActionResponse {
            status,
            content_type,
            body,
        })
    }

    async fn fetch_oci(&self, req: OciRequest) -> Result<OciResponse, UpstreamError> {
        let long = req
            .body
            .as_ref()
            .is_some_and(|(_, length)| *length > UPLOAD_BODY_BYTES);
        let (origins, client) = self.selected_within(
            req.origin.as_ref(),
            &req.private_cidrs,
            false,
            false,
            if long {
                ARTIFACT_TOTAL_TIMEOUT
            } else {
                METADATA_TOTAL_TIMEOUT
            },
            None,
            false,
        )?;
        // Only the registry itself (or the realm origin a caller named): the storage origin of a blob redirect is not a registry.
        if !matches!(
            Self::admitted(&origins, &req.url)?,
            OriginKind::OciRegistry | OriginKind::NpmMetadata
        ) {
            return Err(UpstreamError::RejectedUrl(
                crate::upstream::UrlRejection::ForeignOrigin,
            ));
        }
        let bad = |_| UpstreamError::Status(400);
        let mut request = client.request(req.method, req.url);
        request = request.header(
            header::ACCEPT,
            HeaderValue::from_str(req.accept.as_deref().unwrap_or("*/*")).map_err(bad)?,
        );
        if let Some(authorization) = req.authorization {
            let mut value = HeaderValue::from_str(&authorization).map_err(bad)?;
            value.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, value);
        }
        if let Some(content_type) = req.content_type {
            request = request.header(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type).map_err(bad)?,
            );
        }
        if let Some(range) = req.content_range {
            request = request.header(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&range).map_err(bad)?,
            );
        }
        if let Some((file, length)) = req.body {
            let body = futures_util::stream::try_unfold(file, |mut file| async move {
                let mut chunk = [0u8; 64 * 1024];
                let count = file.read(&mut chunk).await?;
                Ok::<_, std::io::Error>(
                    (count != 0).then(|| (Bytes::copy_from_slice(&chunk[..count]), file)),
                )
            });
            request = request
                .header(header::CONTENT_LENGTH, length.to_string())
                .body(reqwest::Body::wrap_stream(body));
        }
        let response = request.send().await.map_err(upstream_error)?;
        check_connected_peer(&response, &origins)?;
        let status = response.status().as_u16();
        let mut headers = Vec::new();
        for (name, key) in [
            ("content-type", header::CONTENT_TYPE),
            ("content-length", header::CONTENT_LENGTH),
            ("www-authenticate", header::WWW_AUTHENTICATE),
            ("link", header::LINK),
            ("location", header::LOCATION),
            ("range", header::RANGE),
            (
                "docker-content-digest",
                HeaderName::from_static("docker-content-digest"),
            ),
            (
                "docker-upload-uuid",
                HeaderName::from_static("docker-upload-uuid"),
            ),
            ("oci-subject", HeaderName::from_static("oci-subject")),
            (
                "oci-filters-applied",
                HeaderName::from_static("oci-filters-applied"),
            ),
        ] {
            for value in response.headers().get_all(&key).iter().take(8) {
                if let Some(text) = value.to_str().ok().filter(|text| text.len() <= 8192) {
                    headers.push((name, text.to_owned()));
                }
            }
        }
        let body = collect_capped(byte_stream(response), req.max_bytes).await?;
        Ok(OciResponse {
            status,
            headers,
            body,
        })
    }

    async fn fetch_named_read(&self, req: NamedReadRequest) -> Result<bytes::Bytes, UpstreamError> {
        let (origins, client) =
            self.selected(Some(&req.origin), &req.private_cidrs, false, true)?;
        Self::admitted(&origins, &req.url)?;
        let mut request = client
            .request(req.method, req.url)
            .header(header::ACCEPT, "application/json");
        if let Some(authorization) = req.authorization {
            let value =
                HeaderValue::from_str(&authorization).map_err(|_| UpstreamError::Status(400))?;
            request = request.header(header::AUTHORIZATION, value);
        }
        if let Some(content_encoding) = req.content_encoding {
            request = request.header(header::CONTENT_ENCODING, content_encoding);
        }
        if !req.body.is_empty() {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(req.body);
        }
        let response = request.send().await.map_err(upstream_error)?;
        check_connected_peer(&response, &origins)?;
        if response.status().as_u16() != 200 {
            return match refused_redirect(&response) {
                Some(rejected) => Err(rejected),
                None => Err(UpstreamError::Status(response.status().as_u16())),
            };
        }
        collect_capped(byte_stream(response), req.max_bytes).await
    }

    async fn fetch_token_packument(
        &self,
        req: MetadataRequest,
        authorization: &str,
    ) -> Result<MetadataResponse, UpstreamError> {
        let (origins, client) =
            self.selected(req.origin.as_ref(), &req.private_cidrs, false, false)?;
        Self::admitted(&origins, &req.url)?;
        let authorization =
            HeaderValue::from_str(authorization).map_err(|_| UpstreamError::Status(400))?;
        let response = client
            .get(req.url)
            .header(header::ACCEPT, req.accept)
            .header(header::AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(upstream_error)?;
        check_connected_peer(&response, &origins)?;
        match response.status().as_u16() {
            200 => Ok(MetadataResponse::Fresh {
                validators: UpstreamValidators::default(),
                body: collect_capped(byte_stream(response), req.max_bytes).await?,
            }),
            404 | 410 => Ok(MetadataResponse::Missing),
            code => match refused_redirect(&response) {
                Some(rejected) => Err(rejected),
                None => Err(UpstreamError::Status(code)),
            },
        }
    }

    async fn fetch_metadata(
        &self,
        req: MetadataRequest,
    ) -> Result<MetadataResponse, UpstreamError> {
        let (origins, client) =
            self.selected(req.origin.as_ref(), &req.private_cidrs, false, true)?;
        Self::admitted(&origins, &req.url)?;

        let mut request = client
            .get(req.url.clone())
            .header(header::ACCEPT, req.accept);
        if let Some(authorization) = req.read_authorization {
            request = request.header(
                header::AUTHORIZATION,
                HeaderValue::from_str(&authorization).map_err(|_| UpstreamError::Status(400))?,
            );
        }
        if let Some(validators) = &req.validators {
            if let Some(etag) = validator_header(validators.etag.as_deref()) {
                request = request.header(header::IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = validator_header(validators.last_modified.as_deref()) {
                request = request.header(header::IF_MODIFIED_SINCE, last_modified);
            }
        }

        let response = request.send().await.map_err(upstream_error)?;
        check_connected_peer(&response, &origins)?;

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

    async fn probe_file(
        &self,
        req: MetadataRequest,
    ) -> Result<Option<UpstreamValidators>, UpstreamError> {
        let (origins, client) =
            self.selected(req.origin.as_ref(), &req.private_cidrs, false, true)?;
        Self::admitted(&origins, &req.url)?;
        let mut request = client
            .get(req.url.clone())
            .header(header::ACCEPT, req.accept);
        if let Some(authorization) = req.read_authorization {
            request = request.header(
                header::AUTHORIZATION,
                HeaderValue::from_str(&authorization).map_err(|_| UpstreamError::Status(400))?,
            );
        }
        // Only the headers are read: the response (and its body) is dropped, closing the transfer.
        let response = request.send().await.map_err(upstream_error)?;
        check_connected_peer(&response, &origins)?;
        match response.status().as_u16() {
            200 => Ok(Some(validators_of(&response))),
            404 | 410 => Ok(None),
            code => match refused_redirect(&response) {
                Some(rejected) => Err(rejected),
                None => Err(UpstreamError::Status(code)),
            },
        }
    }

    async fn open_artifact(&self, req: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        let credentialed = req.read_authorization.is_some();
        let (origins, client) = self.selected_within(
            req.origin.as_ref(),
            &req.private_cidrs,
            true,
            !credentialed,
            METADATA_TOTAL_TIMEOUT,
            req.archive_origin
                .as_ref()
                .filter(|_| req.allow_archive_redirect),
            req.allow_archive_redirect,
        )?;
        // A foreign layer's own URL (an OCI layer descriptor's `urls`, https on the operator's list) is an artifact like any other, fetched with no credential.
        if !(req.allow_archive_redirect
            && req.read_authorization.is_none()
            && origins.admits_foreign(&req.url))
        {
            Self::admitted(&origins, &req.url)?;
        }
        let mut url = req.url;
        let mut authorization = req.read_authorization;
        let mut redirects = 0;
        let response = loop {
            let mut request = client.get(url.clone());
            if let Some(value) = authorization.take() {
                request = request.header(
                    header::AUTHORIZATION,
                    HeaderValue::from_str(&value).map_err(|_| UpstreamError::Status(400))?,
                );
            }
            let response = request.send().await.map_err(upstream_error)?;
            check_connected_peer(&response, &origins)?;
            if credentialed && matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(UpstreamError::Status(response.status().as_u16()))?;
                let next = url
                    .join(location)
                    .map_err(|_| UpstreamError::Status(response.status().as_u16()))?;
                if redirects >= MAX_REDIRECT_HOPS {
                    return Err(UpstreamError::RedirectLimit { to: next });
                }
                // The credential travels on the first request only. A later hop must stay on the origin the
                // previous hop was on, or be a Go zip's redirect to its archive origin: never another origin of the
                // set (the public proxy, the checksum database, another family's host).
                let from = origins.kind_of(&url).unwrap_or(OriginKind::NpmMetadata);
                if origins.admit(&next, from).is_err()
                    && !(req.allow_archive_redirect
                        && (origins.admits_archive_redirect(from, &next)
                            || (origins.admits_foreign(&url) && origins.admits_foreign(&next))))
                {
                    return Err(UpstreamError::RejectedRedirect { to: next });
                }
                url = next;
                redirects += 1;
                continue;
            }
            break response;
        };

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

/// DNS vetting precedes connect; this also checks the peer reqwest actually used.
/// A missing peer address is not evidence of a permitted connection.
fn check_connected_peer(response: &Response, origins: &OriginSet) -> Result<(), UpstreamError> {
    let peer = response.remote_addr().ok_or_else(|| {
        UpstreamError::Transport("upstream connected peer unavailable".to_owned())
    })?;
    if !origins.allows_endpoint(peer) {
        return Err(UpstreamError::RejectedAddress { addr: peer.ip() });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod connected_peer_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn actual_private_peer_must_be_in_the_approved_cidr() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let response = Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        server.await.unwrap();
        let origins = OriginSet::selected_npm_with_private(
            Url::parse("https://private-registry.e2e.test/").unwrap(),
            vec!["10.77.0.2/32".parse().unwrap()],
        )
        .unwrap();
        assert!(matches!(check_connected_peer(&response, &origins),
            Err(UpstreamError::RejectedAddress { addr }) if addr.is_loopback()));
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
