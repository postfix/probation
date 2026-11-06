//! The shared service's remembered policy and durable authority refusal.

use crate::config::ServicePolicyConfig;
use probation_policy::{
    Ecosystem, LayerKind, PlaceRef,
    api::{KeyHash, RegistryId, ServicePolicySnapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const SNAPSHOT: &str = "service-policy.json";
const PREVIOUS: &str = "service-policy.prev.json";
const REFUSED: &str = "service-policy.refused";
const CHECKING: &str = "service-policy.checking";

/// Shared ordering point for local policy publication and response handoff.
#[derive(Default)]
pub struct PolicyPublicationGate {
    gate: RwLock<()>,
    generation: AtomicU64,
}

impl PolicyPublicationGate {
    pub(crate) fn read<T>(&self, inspect: impl FnOnce(u64) -> T) -> Result<T, ServicePolicyError> {
        let _guard = self.gate.read().map_err(|_| ServicePolicyError)?;
        Ok(inspect(self.generation()))
    }
    pub fn publish<T>(&self, update: impl FnOnce() -> T) -> Result<T, ServicePolicyError> {
        let _guard = self.gate.write().map_err(|_| ServicePolicyError)?;
        let result = update();
        self.generation.fetch_add(1, Ordering::Release);
        Ok(result)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn authorize_current_policy<'a>(
        &'a self,
        prepared: &'a PreparedResponse,
    ) -> Result<AuthorizedResponse<'a>, ServicePolicyError> {
        let guard = self.gate.read().map_err(|_| ServicePolicyError)?;
        if !std::ptr::eq(self, Arc::as_ptr(&prepared.gate))
            || self.generation() != prepared.generation
        {
            return Err(ServicePolicyError);
        }
        Ok(AuthorizedResponse {
            _guard: guard,
            prepared,
        })
    }
}

/// Owns the exact prepared response; authorization borrows it, so it cannot be replaced.
pub struct PreparedResponse {
    gate: Arc<PolicyPublicationGate>,
    generation: u64,
    response: Mutex<Option<PreparedBody>>,
}

enum PreparedBody {
    Http(axum::response::Response),
    Artifact(crate::artifacts::stream::ArtifactResponse),
}

#[derive(Clone)]
pub(crate) struct AuthorityReceipt {
    pub gate: Arc<PolicyPublicationGate>,
    pub generation: u64,
}

impl PreparedResponse {
    pub(crate) fn new(
        gate: Arc<PolicyPublicationGate>,
        generation: u64,
        response: axum::response::Response,
    ) -> Self {
        Self {
            gate,
            generation,
            response: Mutex::new(Some(PreparedBody::Http(response))),
        }
    }

    pub(crate) fn artifact(
        authority: AuthorityReceipt,
        response: crate::artifacts::stream::ArtifactResponse,
    ) -> Self {
        Self {
            gate: authority.gate,
            generation: authority.generation,
            response: Mutex::new(Some(PreparedBody::Artifact(response))),
        }
    }
}

pub struct AuthorizedResponse<'a> {
    _guard: std::sync::RwLockReadGuard<'a, ()>,
    prepared: &'a PreparedResponse,
}

pub fn release_verified_response(
    authorization: AuthorizedResponse<'_>,
) -> Result<axum::response::Response, ServicePolicyError> {
    use axum::response::IntoResponse;
    match authorization
        .prepared
        .response
        .lock()
        .map_err(|_| ServicePolicyError)?
        .take()
        .ok_or(ServicePolicyError)?
    {
        PreparedBody::Http(response) => Ok(response),
        PreparedBody::Artifact(response) => Ok(response.into_response()),
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Binding {
    server: String,
    key: KeyHash,
    mode: String,
}

#[derive(Serialize, Deserialize)]
struct SavedPolicy {
    binding: Binding,
    selection: Vec<RegistryId>,
    reply: ServicePolicySnapshot,
}

pub struct ServicePolicy {
    config: ServicePolicyConfig,
    binding: Binding,
    data_dir: PathBuf,
    http: reqwest::Client,
    poll: tokio::sync::Mutex<()>,
    current: Mutex<Option<Arc<ServicePolicySnapshot>>>,
    rates: super::RateLimits,
    pub publication_gate: Arc<PolicyPublicationGate>,
}

#[derive(Debug)]
pub struct ServicePolicyError;

impl ServicePolicy {
    pub fn load(config: &ServicePolicyConfig, data_dir: &Path) -> Self {
        Self::load_with_clock(config, data_dir, Arc::new(crate::clock::SystemClock))
    }

    pub(crate) fn load_with_clock(
        config: &ServicePolicyConfig,
        data_dir: &Path,
        clock: Arc<dyn crate::clock::Clock>,
    ) -> Self {
        let binding = Binding {
            server: config.server_url.to_string(),
            key: KeyHash::of(config.service_key.expose()),
            mode: "service_policy".into(),
        };
        let read = |name| {
            let path = data_dir.join(name);
            if std::fs::metadata(&path).ok()?.len() > MAX_SNAPSHOT_BYTES as u64 {
                return None;
            }
            let saved: SavedPolicy = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
            if saved.binding != binding
                || saved.selection
                    != saved
                        .reply
                        .registries
                        .iter()
                        .map(|r| r.registry)
                        .collect::<Vec<_>>()
            {
                return None;
            }
            validate(&saved.reply).ok()?;
            Some(Arc::new(saved.reply))
        };
        let current = if [REFUSED, CHECKING]
            .iter()
            .any(|name| data_dir.join(name).try_exists().unwrap_or(true))
        {
            None
        } else {
            read(SNAPSHOT).or_else(|| read(PREVIOUS))
        };
        Self {
            config: config.clone(),
            binding,
            data_dir: data_dir.into(),
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .expect("service policy HTTP client"),
            poll: tokio::sync::Mutex::new(()),
            current: Mutex::new(current),
            rates: super::RateLimits::new(clock),
            publication_gate: Arc::new(PolicyPublicationGate::default()),
        }
    }

    pub async fn sync_once(&self) -> Result<(), ServicePolicyError> {
        let _poll = self.poll.lock().await;
        // Record uncertainty before contacting authority: a refusal may arrive
        // after storage stops accepting writes. A surviving intent closes restart.
        let uncertain = self
            .data_dir
            .join(CHECKING)
            .try_exists()
            .map_err(|_| ServicePolicyError)?;
        crate::config::write_atomically(&self.data_dir.join(CHECKING), b"checking\n", None)
            .map_err(|_| ServicePolicyError)?;
        let mut refused = false;
        let fetched = async {
            let mut base = self.config.server_url.clone();
            if !base.path().ends_with('/') {
                base.set_path(&format!("{}/", base.path()));
            }
            let mut response = self
                .http
                .get(
                    base.join("api/v1/policy/snapshot")
                        .map_err(|_| ServicePolicyError)?,
                )
                .bearer_auth(self.config.service_key.expose())
                .send()
                .await
                .map_err(|_| ServicePolicyError)?;
            if matches!(response.status().as_u16(), 401 | 403 | 404) {
                refused = true;
                self.refuse()?;
                return Err(ServicePolicyError);
            }
            if !response.status().is_success() {
                return Err(ServicePolicyError);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| ServicePolicyError)? {
                if bytes.len().saturating_add(chunk.len()) > MAX_SNAPSHOT_BYTES {
                    return Err(ServicePolicyError);
                }
                bytes.extend_from_slice(&chunk);
            }
            let reply = serde_json::from_slice(&bytes).map_err(|_| ServicePolicyError)?;
            validate_policy_snapshot(&reply, &self.binding).await?;
            Ok(reply)
        }
        .await;
        match fetched {
            Ok(reply) => self.activate(reply).await,
            Err(error) => {
                // Only this completed transient/invalid check may be forgotten.
                // Never clear uncertainty inherited from a prior crash/refusal.
                if !refused && !uncertain {
                    self.clear_marker(CHECKING)?;
                }
                Err(error)
            }
        }
    }

    async fn activate(&self, reply: ServicePolicySnapshot) -> Result<(), ServicePolicyError> {
        let binding = self.binding.clone();
        validate_policy_snapshot(&reply, &binding).await?;
        self.persist_policy_snapshot(&reply, binding)?;
        self.publish_policy_snapshot(reply)
    }

    /// Complete durable cache/refusal recovery before making a grant live.
    fn persist_policy_snapshot(
        &self,
        reply: &ServicePolicySnapshot,
        binding: Binding,
    ) -> Result<(), ServicePolicyError> {
        let saved = SavedPolicy {
            binding,
            selection: reply.registries.iter().map(|r| r.registry).collect(),
            reply: reply.clone(),
        };
        let bytes = serde_json::to_vec(&saved).map_err(|_| ServicePolicyError)?;
        crate::config::write_atomically(
            &self.data_dir.join(SNAPSHOT),
            &bytes,
            Some(&self.data_dir.join(PREVIOUS)),
        )
        .map_err(|_| ServicePolicyError)?;
        // Rotation must not clear a refusal while leaving the refused binding in
        // the fallback file. Delete it durably before removing the tombstone.
        let previous = self.data_dir.join(PREVIOUS);
        if previous.try_exists().map_err(|_| ServicePolicyError)? {
            let matching = std::fs::metadata(&previous)
                .is_ok_and(|metadata| metadata.len() <= MAX_SNAPSHOT_BYTES as u64)
                && std::fs::read(&previous)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<SavedPolicy>(&bytes).ok())
                    .is_some_and(|previous| {
                        previous.binding == self.binding && previous.selection == saved.selection
                    });
            if !matching {
                std::fs::remove_file(&previous).map_err(|_| ServicePolicyError)?;
                crate::config::sync_directory(&self.data_dir).map_err(|_| ServicePolicyError)?;
            }
        }
        self.clear_marker(REFUSED)?;
        self.clear_marker(CHECKING)?;
        Ok(())
    }

    fn clear_marker(&self, name: &str) -> Result<(), ServicePolicyError> {
        if self
            .data_dir
            .join(name)
            .try_exists()
            .map_err(|_| ServicePolicyError)?
        {
            std::fs::remove_file(self.data_dir.join(name)).map_err(|_| ServicePolicyError)?;
            crate::config::sync_directory(&self.data_dir).map_err(|_| ServicePolicyError)?;
        }
        Ok(())
    }

    fn publish_policy_snapshot(
        &self,
        reply: ServicePolicySnapshot,
    ) -> Result<(), ServicePolicyError> {
        // Polling is serialized. Only an exactly equal complete grant is a no-op;
        // a refused state is None and must pass through publication on recovery.
        if self.snapshot().as_deref() == Some(&reply) {
            return Ok(());
        }
        self.publication_gate.publish(|| {
            *self.current.lock().map_err(|_| ServicePolicyError)? = Some(Arc::new(reply));
            Ok(())
        })?
    }

    pub fn snapshot(&self) -> Option<Arc<ServicePolicySnapshot>> {
        self.current.lock().ok()?.clone()
    }

    pub(crate) fn admit_request(&self, snapshot: &ServicePolicySnapshot) -> bool {
        self.rates.prune();
        self.rates.admit(snapshot.account, snapshot.rate_limit)
    }

    pub fn principal(
        &self,
        registry: RegistryId,
        ecosystem: Ecosystem,
    ) -> Option<super::Principal> {
        self.publication_gate
            .read(|generation| self.principal_at(registry, ecosystem, generation))
            .ok()?
    }

    fn principal_at(
        &self,
        registry: RegistryId,
        ecosystem: Ecosystem,
        generation: u64,
    ) -> Option<super::Principal> {
        let snapshot = self.snapshot()?;
        let descriptor = snapshot
            .registries
            .iter()
            .find(|item| item.registry == registry && item.ecosystem == ecosystem)?;
        let policy = probation_policy::resolve(
            &snapshot
                .layers
                .iter()
                .map(|item| item.layer.clone())
                .collect::<Vec<_>>(),
        );
        let policy = if descriptor.trusted {
            crate::policy::CompiledPolicy::managed_trusted(policy)
        } else {
            crate::policy::CompiledPolicy::managed(policy)
        };
        Some(super::Principal {
            place: snapshot.place_chain.last()?.place,
            key_id: snapshot.key_id,
            policy: Arc::new(policy),
            account: snapshot.account,
            rate_limit: snapshot.rate_limit,
            rate_limit_source: snapshot.rate_limit_source,
            org: Some(snapshot.org),
            chain: snapshot.place_chain.iter().map(|link| link.place).collect(),
            registry_origin: descriptor
                .target_url
                .as_ref()
                .map(|url| url.parse())
                .transpose()
                .ok()?,
            registry_read_authorization: None,
            registry_trusted: descriptor.trusted,
            registry_private_cidrs: descriptor
                .registry_private_cidrs
                .iter()
                .map(|text| text.parse())
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
            deletion_scopes: descriptor.deletion_scopes.clone(),
            authority: Some(AuthorityReceipt {
                gate: Arc::clone(&self.publication_gate),
                generation,
            }),
        })
    }

    pub async fn run(&self, shutdown: tokio_util::sync::CancellationToken) {
        let mut ticks =
            tokio::time::interval(Duration::from_secs(self.config.sync_interval_seconds.get()));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticks.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticks.tick() => { let _ = self.sync_once().await; }
            }
        }
    }

    fn refuse(&self) -> Result<(), ServicePolicyError> {
        self.publication_gate.publish(|| {
            *self.current.lock().map_err(|_| ServicePolicyError)? = None;
            Ok(())
        })??;
        // A separate durable tombstone prevents previous-file recovery resurrecting a grant.
        crate::config::write_atomically(&self.data_dir.join(REFUSED), b"refused\n", None)
            .map_err(|_| ServicePolicyError)
    }
}

async fn validate_policy_snapshot(
    reply: &ServicePolicySnapshot,
    binding: &Binding,
) -> Result<(), ServicePolicyError> {
    if binding.mode != "service_policy" {
        return Err(ServicePolicyError);
    }
    validate(reply)
}

fn validate(reply: &ServicePolicySnapshot) -> Result<(), ServicePolicyError> {
    let org = PlaceRef {
        kind: LayerKind::Org,
        id: reply.org.0,
    };
    if reply.version != 1
        || reply.key_id.0 == 0
        || reply.key_id.0 > i64::MAX as u64
        || reply.org.0 == 0
        || reply.account != org
        || !(2..=3).contains(&reply.layers.len())
        || reply.layers.len() != reply.place_chain.len()
        || reply.layers[0].place
            != (PlaceRef {
                kind: LayerKind::Platform,
                id: 1,
            })
        || reply.layers[1].place != org
        || (reply.layers.len() == 3 && reply.layers[2].place.kind != LayerKind::Group)
        || !probation_policy::is_chain(
            &reply
                .layers
                .iter()
                .map(|layer| layer.layer.kind)
                .collect::<Vec<_>>(),
        )
        || reply
            .layers
            .iter()
            .zip(&reply.place_chain)
            .any(|(layer, link)| {
                layer.place != link.place
                    || layer.place.kind != layer.layer.kind
                    || layer.place.id == 0
                    || layer.revision != link.layer_revision
            })
        || reply.registries.len() > 1000
    {
        return Err(ServicePolicyError);
    }
    let mut ids = HashSet::new();
    for registry in &reply.registries {
        if registry.registry.0 == 0
            || registry.registry.0 > i64::MAX as u64
            || !ids.insert(registry.registry)
            || registry.registry_private_cidrs.len() > 1000
            || registry.deletion_scopes.len() > 1000
        {
            return Err(ServicePolicyError);
        }
        let cidrs = registry
            .registry_private_cidrs
            .iter()
            .map(|text| text.parse::<ipnet::IpNet>().map_err(|_| ServicePolicyError))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(target) = &registry.target_url {
            if target.len() > 2048 {
                return Err(ServicePolicyError);
            }
            crate::upstream::OriginSet::selected_npm_with_private(
                target.parse().map_err(|_| ServicePolicyError)?,
                cidrs,
            )
            .map_err(|_| ServicePolicyError)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use axum::{body::Body, response::Response};

    #[tokio::test]
    async fn handoff_binds_gate_generation_and_exact_owned_response() {
        let gate = Arc::new(PolicyPublicationGate::default());
        let other = PolicyPublicationGate::default();
        let prepared = PreparedResponse::new(
            Arc::clone(&gate),
            0,
            Response::new(Body::from("exact verified response")),
        );
        assert!(other.authorize_current_policy(&prepared).is_err());
        let authorization = gate.authorize_current_policy(&prepared).unwrap();
        let (started, receiver) = std::sync::mpsc::channel();
        let writer_gate = Arc::clone(&gate);
        let writer = std::thread::spawn(move || {
            started.send(()).unwrap();
            writer_gate.publish(|| ()).unwrap();
        });
        receiver.recv().unwrap();
        assert_eq!(
            gate.generation(),
            0,
            "publication cannot pass a held final authorization"
        );
        let response = release_verified_response(authorization).unwrap();
        writer.join().unwrap();
        assert_eq!(gate.generation(), 1);
        assert!(
            gate.authorize_current_policy(&prepared).is_err(),
            "old generation cannot authorize another handoff"
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 100)
                .await
                .unwrap()
                .as_ref(),
            b"exact verified response"
        );
    }

    #[test]
    fn poisoned_publication_gate_refuses_final_authorization() {
        let gate = Arc::new(PolicyPublicationGate::default());
        let prepared = PreparedResponse::new(Arc::clone(&gate), 0, Response::new(Body::empty()));
        let writer = Arc::clone(&gate);
        assert!(
            std::thread::spawn(move || {
                let _ = writer.publish(|| panic!("publication failed"));
            })
            .join()
            .is_err()
        );
        assert!(gate.authorize_current_policy(&prepared).is_err());
    }
}
