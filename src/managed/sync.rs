//! Policy sync: ask the management server what changed and act on its answer (C20,
//! C72, C96). Only an answer may shrink the key cache.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use probation_policy::api::{ChangesRequest, ChangesResponse, SettingsPush};
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use url::Url;

use self::SyncFailure::{Unreachable, Unreadable};
use super::cache::{KeyCache, Policies};
use super::lock::NetworkLock;
use crate::config::{FirewallToken, ManagementConfig};

/// The biggest `changes` answer read: a full network-lock table and a long delta, well
/// under any server cap.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;

pub struct KeySync {
    publication_gate: Arc<super::service_policy::PolicyPublicationGate>,
    http: reqwest::Client,
    changes_url: Url,
    token: FirewallToken,
    timeout: Duration,
    cache: Arc<KeyCache>,
    layers: Arc<Policies>,
    network_lock: Arc<NetworkLock>,
    retired: Arc<AtomicBool>,
    cursor: AtomicU64,
    /// The settings push of the last answer, for the sync task to apply (C105).
    pushed: Mutex<Option<SettingsPush>>,
}

/// What one round of `changes(since)` came back with.
enum Answer {
    Changes(ChangesResponse),
    /// The cursor is older than the retained change log: the whole answer, with the
    /// full network-lock table.
    Reset(ChangesResponse),
    Retired,
    /// A 4xx other than 401, 429 and 403 `FIREWALL_SOURCE_REFUSED`: the server refused
    /// this request (for example an oversized batch).
    Rejected,
}

/// What the caller does with the activity batch it sent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Synced {
    /// The answer was applied; the batch was delivered.
    Applied,
    /// The server refused the batch; count it as dropped, do not re-queue it.
    BatchRejected,
}

/// No answer this firewall can apply; the caller re-queues the batch.
#[derive(Debug)]
pub enum SyncFailure {
    /// Connect error, timeout, 5xx, 429, or 403 `FIREWALL_SOURCE_REFUSED`.
    Unreachable,
    /// A 2xx whose body does not decode (F3): most likely a server newer than this
    /// firewall, which no number of retries fixes.
    Unreadable,
}

impl KeySync {
    pub(super) fn new(
        config: &ManagementConfig,
        cache: Arc<KeyCache>,
        layers: Arc<Policies>,
        network_lock: Arc<NetworkLock>,
        retired: Arc<AtomicBool>,
        cursor: u64,
        publication_gate: Arc<super::service_policy::PolicyPublicationGate>,
    ) -> KeySync {
        let mut base = config.url.clone();
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        KeySync {
            publication_gate,
            // No redirects and no proxy from the environment: the token and the activity
            // rows are for this URL only.
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("an HTTP client with the default TLS backend"),
            changes_url: base
                .join("api/v1/sync/changes")
                .expect("a path joins any base URL"),
            token: config.token.clone(),
            timeout: Duration::from_secs(config.request_timeout_seconds.get()),
            cache,
            layers,
            network_lock,
            retired,
            cursor: AtomicU64::new(cursor),
            pushed: Mutex::new(None),
        }
    }

    /// One sync round. Only a server answer may shrink the key cache.
    pub async fn fetch_changes(&self, request: &ChangesRequest) -> Result<Synced, SyncFailure> {
        // The `Err(_)` arm keeps the text the source obligations' controls mutate
        // (molecule-contracts.json).
        let answer = match self.request_changes(request).await {
            Ok(answer) => answer,
            Err(Unreadable) => return Err(Unreadable),
            Err(_) => return Err(Unreachable),
        };
        self.mark_reachable();
        if matches!(answer, Answer::Rejected) { return Ok(Synced::BatchRejected); }
        let changed = match &answer {
            Answer::Changes(delta) => delta.revision != self.cursor()
                || delta.network_lock.is_some() || !delta.changed_layers.is_empty()
                || !delta.changed_limits.is_empty() || !delta.changed_keys.is_empty()
                || !delta.changed_places.is_empty(),
            Answer::Reset(_) | Answer::Retired => true,
            Answer::Rejected => false,
        };
        let apply = || match answer {
            Answer::Changes(delta) => self.apply_changes(&delta),
            Answer::Reset(full) => {
                self.reset_cursor(full.revision);
                self.cache.reset_invalidations(full.revision);
                self.drop_cache();
                self.network_lock.adopt(full.network_lock.as_deref());
                self.offer(full.settings);
            }
            Answer::Retired => self.stop_serving(),
            Answer::Rejected => {},
        };
        if changed {
            self.publication_gate.publish(apply).map_err(|_| Unreadable)?
        } else {
            apply()
        };
        Ok(Synced::Applied)
    }

    async fn request_changes(&self, request: &ChangesRequest) -> Result<Answer, SyncFailure> {
        let body = serde_json::to_vec(request).map_err(|_| Unreachable)?;
        // One deadline for the whole exchange: the send below, then the body.
        let deadline = tokio::time::Instant::now() + self.timeout;
        let sending = self
            .http
            .post(self.changes_url.clone())
            .bearer_auth(self.token.expose())
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send();
        let response = tokio::time::timeout(self.timeout, sending)
            .await
            .map_err(|_| Unreachable)?
            .map_err(|_| Unreachable)?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Ok(Answer::Retired);
        }
        if status == StatusCode::TOO_MANY_REQUESTS || source_refused(&response) {
            return Err(Unreachable);
        }
        if status.is_client_error() {
            return Ok(Answer::Rejected);
        }
        if !status.is_success() {
            return Err(Unreachable);
        }
        let bytes = tokio::time::timeout_at(deadline, read_bounded(response))
            .await
            .map_err(|_| Unreachable)??;
        let changes: ChangesResponse = serde_json::from_slice(&bytes).map_err(|_| Unreadable)?;
        if changes.retired {
            return Ok(Answer::Retired);
        }
        if changes.reset {
            return Ok(Answer::Reset(changes));
        }
        Ok(Answer::Changes(changes))
    }

    fn mark_reachable(&self) {
        self.cache.note_server_seen();
    }

    fn reset_cursor(&self, revision: u64) {
        self.cursor.store(revision, Ordering::Release);
    }

    /// Adopt a sent network-lock table, mark changed layers stale, update changed rate
    /// limits in place, remove changed keys, expire changed places, then move the cursor
    /// past the delta. Each invalidation records `delta.revision`, so a late answer read
    /// before it is dropped.
    // One statement a line, as the source obligations on this order read them
    // (molecule-contracts.json).
    #[rustfmt::skip]
    fn apply_changes(&self, delta: &ChangesResponse) {
        self.network_lock.adopt(delta.network_lock.as_deref());
        self.layers.mark_stale(&delta.changed_layers, delta.revision);
        self.cache.update_limits(&delta.changed_limits, delta.revision);
        self.cache.remove_keys(&delta.changed_keys, delta.revision);
        self.cache.expire_places(&delta.changed_places, delta.revision);
        self.advance_cursor(delta.revision);
        self.offer(delta.settings.clone());
    }

    fn advance_cursor(&self, revision: u64) {
        self.cursor.store(revision, Ordering::Release);
    }

    /// Everything the firewall learned from the change log: keys, layers and compiled
    /// policies.
    fn drop_cache(&self) {
        self.cache.clear();
        self.layers.clear();
    }

    /// The server retired this firewall or rejected its token: serve nothing more.
    fn stop_serving(&self) {
        self.retired.store(true, Ordering::Release);
        self.cache.clear();
    }

    fn offer(&self, settings: Option<SettingsPush>) {
        if settings.is_some() {
            *self.pushed.lock().unwrap_or_else(PoisonError::into_inner) = settings;
        }
    }

    /// The settings push the last answer carried, once.
    pub fn take_settings(&self) -> Option<SettingsPush> {
        self.pushed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// The change-log revision this firewall has applied.
    pub fn cursor(&self) -> u64 {
        self.cursor.load(Ordering::Acquire)
    }
}

/// 403 with the `FIREWALL_SOURCE_REFUSED` code: the server refused this firewall's
/// source address. Handled like an unreachable server; any other 403 is a rejected
/// request.
fn source_refused(response: &reqwest::Response) -> bool {
    response.status() == StatusCode::FORBIDDEN
        && response
            .headers()
            .get("x-probation-error")
            .is_some_and(|code| code == "FIREWALL_SOURCE_REFUSED")
}

/// The body, refused past `MAX_ANSWER_BYTES` however it is framed.
async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, SyncFailure> {
    let mut answer = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Unreachable)? {
        if answer.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(Unreachable);
        }
        answer.extend_from_slice(&chunk);
    }
    Ok(answer)
}
