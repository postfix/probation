//! The management server's `sync lookup` and `sync layers` calls (02-architecture.md
//! § Endpoints). Bodies are encoded with `serde_json`: this crate's reqwest has no
//! `json` feature.

use std::time::Duration;

use probation_policy::PlaceRef;
use probation_policy::api::{
    CertificateAdmission, CertificateAdmissionRequest, KeyHash, KeyLookup, KeyLookupRequest,
    LayersRequest, LayersResponse,
};
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::config::{FirewallToken, ManagementConfig};

/// Why a call has no answer to use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallError {
    /// Connect error, timeout, 5xx, an unexpected status, or a body cut short or too
    /// big.
    Unreachable,
    /// A `200` whose body does not decode (F3): most likely a server newer than this
    /// firewall.
    Unreadable,
    /// The server answered `429`.
    Busy,
    /// The server refused this firewall's token (`401`).
    TokenRefused,
}

/// The biggest answer read: a layer with many blocks, well under the server's own caps.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;

pub struct SyncClient {
    http: reqwest::Client,
    base: Url,
    token: FirewallToken,
    timeout: Duration,
}

impl SyncClient {
    pub fn new(config: &ManagementConfig) -> SyncClient {
        SyncClient {
            // No redirects and no proxy from the environment: the token and the key
            // hashes are for this URL only.
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("an HTTP client with the default TLS backend"),
            base: base_of(&config.url),
            token: config.token.clone(),
            timeout: Duration::from_secs(config.request_timeout_seconds.get()),
        }
    }

    pub async fn lookup(&self, key_hash: KeyHash) -> Result<KeyLookup, CallError> {
        self.call("api/v1/sync/lookup", &KeyLookupRequest { key_hash })
            .await
    }

    pub async fn layers(&self, places: Vec<PlaceRef>) -> Result<LayersResponse, CallError> {
        self.call("api/v1/sync/layers", &LayersRequest { places })
            .await
    }

    pub async fn certificate(
        &self,
        asked: CertificateAdmissionRequest,
    ) -> Result<CertificateAdmission, CallError> {
        self.call("api/v1/sync/certificate", &asked).await
    }

    /// One `POST`, sent and read within `request_timeout_seconds`.
    async fn call<B: Serialize, A: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<A, CallError> {
        let url = self.base.join(path).map_err(|_| CallError::Unreachable)?;
        let body = serde_json::to_vec(body).map_err(|_| CallError::Unreachable)?;
        // One deadline for the whole exchange: the send below, then the body.
        let deadline = tokio::time::Instant::now() + self.timeout;
        let sent = self
            .http
            .post(url)
            .bearer_auth(self.token.expose())
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send();
        let response = tokio::time::timeout(self.timeout, sent)
            .await
            .map_err(|_| CallError::Unreachable)?
            .map_err(|_| CallError::Unreachable)?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => return Err(CallError::Busy),
            StatusCode::UNAUTHORIZED => return Err(CallError::TokenRefused),
            _ => return Err(CallError::Unreachable),
        }
        let answer = tokio::time::timeout_at(deadline, read_bounded(response))
            .await
            .map_err(|_| CallError::Unreachable)??;
        serde_json::from_slice(&answer).map_err(|_| CallError::Unreadable)
    }
}

/// The body, refused past `MAX_ANSWER_BYTES` however it is framed.
async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, CallError> {
    let mut answer = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| CallError::Unreachable)? {
        if answer.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(CallError::Unreachable);
        }
        answer.extend_from_slice(&chunk);
    }
    Ok(answer)
}

/// `url` as a base `join` keeps the whole path of: a `/prefix` without its trailing
/// slash would otherwise lose `prefix`.
fn base_of(url: &Url) -> Url {
    let mut base = url.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base
}
