//! The shared service's remembered policy and durable authority refusal.

use crate::config::ServicePolicyConfig;
use crate::http::service_connector::{Denylist, check_target};
use probation_policy::{
    Ecosystem, LayerKind, PlaceRef,
    api::{KeyHash, RegistryId, ServicePolicySnapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
    },
    time::Duration,
};

const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const SNAPSHOT: &str = "service-policy.json";
const PREVIOUS: &str = "service-policy.prev.json";
const REFUSED: &str = "service-policy.refused";
const CHECKING: &str = "service-policy.checking";

pub use super::publication_gate::{AuthorizedResponse, PolicyPublicationGate, PreparedResponse, release_verified_response};
pub(crate) use super::publication_gate::AuthorityReceipt;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Binding {
    server: String,
    key: KeyHash,
    mode: String,
}

/// The best identity available to a local command: the invoking user (`SUDO_USER` when run
/// through sudo, else `USER`/`LOGNAME`/`USERNAME`) and, on Unix, the numeric uid of this
/// process. Both come from the environment and the OS of the host; this is an audit hint
/// for an operator-only command, not an authentication.
fn operator_identity() -> String {
    let name = ["SUDO_USER", "USER", "LOGNAME", "USERNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata("/proc/self") {
            return format!("{name} (uid {})", meta.uid());
        }
    }
    name
}

/// LS-F8: the persisted revision floor (additive optional envelope field).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ActiveRevision {
    revision: u64,
    digest: [u8; 32],
}

impl ActiveRevision {
    pub(super) fn of(reply: &ServicePolicySnapshot) -> Self {
        Self { revision: reply.revision, digest: reply.policy_digest() }
    }

    /// Activated only when strictly newer, or equal with an identical digest.
    pub(super) fn admits(&self, reply: &ServicePolicySnapshot) -> bool {
        reply.revision > self.revision
            || (reply.revision == self.revision && reply.policy_digest() == self.digest)
    }
}

#[derive(Serialize, Deserialize)]
struct SavedPolicy {
    binding: Binding,
    selection: Vec<RegistryId>,
    reply: ServicePolicySnapshot,
    #[serde(default)]
    floor: Option<ActiveRevision>,
    /// R28-7: registries and rule count the snapshot named with an unknown ecosystem tag
    /// (already removed from `reply`), kept so readiness survives a restart.
    #[serde(default)]
    unavailable: Vec<RegistryId>,
    #[serde(default)]
    skipped: u64,
}

/// Marker the reset command leaves for a running enforcer (LS-F8).
const FLOOR_RESET: &str = "revision-floor-reset";

/// The unknown-ecosystem state of the saved envelope bound to `binding` (R28-7).
fn saved_degraded(data_dir: &Path, binding: &Binding) -> (Vec<RegistryId>, u64) {
    [SNAPSHOT, PREVIOUS]
        .iter()
        .find_map(|name| {
            let path = data_dir.join(name);
            if std::fs::metadata(&path).ok()?.len() > MAX_SNAPSHOT_BYTES as u64 {
                return None;
            }
            let saved: SavedPolicy = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
            (saved.binding == *binding).then_some((saved.unavailable, saved.skipped))
        })
        .unwrap_or_default()
}

/// The floor of the saved envelope bound to `binding`, whether or not a refusal is
/// recorded: a refusal never clears the floor.
fn saved_floor(data_dir: &Path, binding: &Binding) -> Option<ActiveRevision> {
    [SNAPSHOT, PREVIOUS].iter().find_map(|name| {
        let path = data_dir.join(name);
        if std::fs::metadata(&path).ok()?.len() > MAX_SNAPSHOT_BYTES as u64 {
            return None;
        }
        let saved: SavedPolicy = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        (saved.binding == *binding).then_some(saved.floor).flatten()
    })
}

pub struct ServicePolicy {
    config: ServicePolicyConfig,
    binding: Binding,
    data_dir: PathBuf,
    http: reqwest::Client,
    poll: tokio::sync::Mutex<()>,
    current: Mutex<Option<Arc<ServicePolicySnapshot>>>,
    floor: Mutex<Option<ActiveRevision>>,
    deny: Arc<Denylist>,
    health: Mutex<Option<Arc<super::report::UpstreamHealth>>>,
    unavailable: Mutex<Vec<RegistryId>>,
    skipped: std::sync::atomic::AtomicU64,
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
            validate(&saved.reply, &Denylist::default()).ok()?;
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
        let floor = saved_floor(data_dir, &binding);
        let (unavailable, skipped) = if current.is_some() { saved_degraded(data_dir, &binding) } else { (Vec::new(), 0) };
        Self {
            config: config.clone(),
            floor: Mutex::new(floor),
            deny: Arc::new(Denylist::default()),
            health: Mutex::new(None),
            unavailable: Mutex::new(unavailable),
            skipped: std::sync::atomic::AtomicU64::new(skipped),
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

    /// Operator command `reset-revision-floor` (LS-F8). Clears only the persisted floor of
    /// the envelope bound to this configuration, never a refusal, and leaves a marker a
    /// running enforcer consumes at the start of its next poll. Works when the enforcer is
    /// not running; there is no network trigger.
    pub fn reset_revision_floor(config: &ServicePolicyConfig, data_dir: &Path) -> Result<(), ServicePolicyError> {
        let binding = Binding {
            server: config.server_url.to_string(),
            key: KeyHash::of(config.service_key.expose()),
            mode: "service_policy".into(),
        };
        let previous = saved_floor(data_dir, &binding);
        for name in [SNAPSHOT, PREVIOUS] {
            let path = data_dir.join(name);
            let Ok(bytes) = std::fs::read(&path) else { continue };
            let Ok(mut saved) = serde_json::from_slice::<SavedPolicy>(&bytes) else { continue };
            if saved.binding != binding {
                continue;
            }
            saved.floor = None;
            let bytes = serde_json::to_vec(&saved).map_err(|_| ServicePolicyError)?;
            crate::config::write_atomically(&path, &bytes, None).map_err(|_| ServicePolicyError)?;
        }
        // Always written: it tells a running enforcer to drop its in-memory floor at its next
        // poll. Harmless when no enforcer runs (the first poll consumes it, clearing a floor
        // that is already clear) and when the floor was already absent.
        crate::config::write_atomically(&data_dir.join(FLOOR_RESET), b"reset\n", None).map_err(|_| ServicePolicyError)?;
        tracing::warn!(
            previous_floor = previous.map(|floor| floor.revision),
            account = operator_identity(),
            "revision floor reset by the operator command"
        );
        Ok(())
    }

    /// LS-F3: registries the last activated snapshot named with an ecosystem tag this
    /// enforcer cannot serve. Requests to them refuse; readiness lists them degraded.
    pub fn unavailable_registries(&self) -> Vec<RegistryId> {
        self.unavailable.lock().map(|ids| ids.clone()).unwrap_or_default()
    }

    /// LS-F3: layer rules of the last activated snapshot skipped for an unknown ecosystem
    /// tag (the counter `policy_rules_skipped_unknown_ecosystem`).
    pub fn rules_skipped_unknown_ecosystem(&self) -> u64 {
        self.skipped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Names this enforcer's own listener so a descriptor cannot point back at it (LS-F9).
    pub fn with_listener(mut self, listen: std::net::SocketAddr) -> Self {
        self.deny = Arc::new(Denylist::new(Some(listen), self.deny.control_plane_cidrs.clone()));
        self
    }

    /// Mirrors the skipped-rule counter into the upstream health report (LS-F3).
    pub fn with_health(self, health: Arc<super::report::UpstreamHealth>) -> Self {
        if let Ok(mut slot) = self.health.lock() {
            *slot = Some(health);
        }
        self
    }

    /// Cluster control-plane ranges no descriptor may name (LS-F9).
    pub fn with_control_plane(mut self, cidrs: Vec<ipnet::IpNet>) -> Self {
        self.deny = Arc::new(Denylist::new(self.deny.listener, cidrs));
        self
    }

    pub async fn sync_once(&self) -> Result<(), ServicePolicyError> {
        let _poll = self.poll.lock().await;
        if self.data_dir.join(FLOOR_RESET).try_exists().unwrap_or(false) {
            *self.floor.lock().map_err(|_| ServicePolicyError)? = None;
            self.clear_marker(FLOOR_RESET)?;
        }
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
            if matches!(response.status().as_u16(), 401 | 403) {
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
            let (reply, unavailable, skipped) = classify_snapshot(&bytes)?;
            // Structural rejection (LS-F8): last good retained, no refusal change.
            if self.binding.mode != "service_policy" {
                return Err(ServicePolicyError);
            }
            let floor = self.floor.lock().map_err(|_| ServicePolicyError)?.clone();
            super::order_guards::activation_order(&reply, &self.deny, floor.as_ref())?;
            check_hostnames(&reply, &self.deny).await?;
            Ok((reply, unavailable, skipped))
        }
        .await;
        match fetched {
            Ok((reply, unavailable, skipped)) => {
                self.activate(reply, &unavailable, skipped).await?;
                if skipped > 0 || !unavailable.is_empty() {
                    tracing::warn!(skipped, unavailable = unavailable.len(), "snapshot names an ecosystem this enforcer cannot serve");
                }
                *self.unavailable.lock().map_err(|_| ServicePolicyError)? = unavailable;
                self.skipped.store(skipped, std::sync::atomic::Ordering::Relaxed);
                if let Ok(slot) = self.health.lock()
                    && let Some(health) = slot.as_ref()
                {
                    health.set_policy_rules_skipped_unknown_ecosystem(skipped);
                }
                Ok(())
            }
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

    async fn activate(&self, reply: ServicePolicySnapshot, unavailable: &[RegistryId], skipped: u64) -> Result<(), ServicePolicyError> {
        let binding = self.binding.clone();
        validate_policy_snapshot(&reply, &binding, &self.deny).await?;
        self.persist_policy_snapshot(&reply, binding, unavailable, skipped)?;
        self.publish_policy_snapshot(reply)
    }

    /// Complete durable cache/refusal recovery before making a grant live.
    fn persist_policy_snapshot(
        &self,
        reply: &ServicePolicySnapshot,
        binding: Binding,
        unavailable: &[RegistryId],
        skipped: u64,
    ) -> Result<(), ServicePolicyError> {
        let saved = SavedPolicy {
            binding,
            selection: reply.registries.iter().map(|r| r.registry).collect(),
            reply: reply.clone(),
            floor: Some(ActiveRevision::of(reply)),
            unavailable: unavailable.to_vec(),
            skipped,
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
        *self.floor.lock().map_err(|_| ServicePolicyError)? = saved.floor;
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
            registry_archive_origin: descriptor
                .archive_origin
                .as_ref()
                .map(|url| url.parse())
                .transpose()
                .ok()?,
            registry_resource_prefix: descriptor.resource_path_prefix.clone(),
            registry_read_authorization: None,
            registry_trusted: descriptor.trusted,
            registry_private_cidrs: descriptor
                .registry_private_cidrs
                .iter()
                .map(|text| text.parse())
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
            deletion_scopes: descriptor.deletion_scopes.clone(),
            authority: Some(AuthorityReceipt::new(Arc::clone(&self.publication_gate), generation)),
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

/// LS-F3: parse a snapshot body. A registry descriptor with an unknown `ecosystem` tag is
/// removed and reported unavailable; a layer rule (block or exception) with an unknown tag
/// is skipped and counted. Everything else, including malformed JSON, stays structural.
fn classify_snapshot(bytes: &[u8]) -> Result<(ServicePolicySnapshot, Vec<RegistryId>, u64), ServicePolicyError> {
    use serde_json::Value;
    let known = |tag: Option<&Value>| tag.is_some_and(|tag| serde_json::from_value::<Ecosystem>(tag.clone()).is_ok());
    let mut raw: Value = serde_json::from_slice(bytes).map_err(|_| ServicePolicyError)?;
    let (mut unavailable, mut skipped) = (Vec::new(), 0u64);
    if let Some(registries) = raw.get_mut("registries").and_then(Value::as_array_mut) {
        registries.retain(|item| {
            let keep = known(item.get("ecosystem"));
            if !keep && let Some(id) = item.get("registry").and_then(Value::as_u64) {
                unavailable.push(RegistryId(id));
            }
            keep
        });
    }
    for layer in raw.get_mut("layers").and_then(Value::as_array_mut).into_iter().flatten() {
        for field in ["blocks", "exceptions"] {
            let Some(rules) = layer.get_mut("layer").and_then(|l| l.get_mut(field)).and_then(Value::as_array_mut) else { continue };
            rules.retain(|rule| {
                // A block is `{"Package": {"ecosystem": ..}}`; an exception is flat.
                let tag = rule.get("ecosystem").or_else(|| rule.as_object().and_then(|o| o.values().next()).and_then(|v| v.get("ecosystem")));
                let keep = tag.is_none() || known(tag);
                skipped += u64::from(!keep);
                keep
            });
        }
    }
    let reply = serde_json::from_value(raw).map_err(|_| ServicePolicyError)?;
    Ok((reply, unavailable, skipped))
}

/// LS-F9 / D5: a descriptor hostname is resolved at activation and every answer checked with
/// the target port (loopback, link-local, metadata, own listener). The connect-time resolver
/// repeats the check, so a DNS answer that changes later is still refused. A name that does
/// not resolve now is not an activation failure: it fails at connect.
async fn check_hostnames(reply: &ServicePolicySnapshot, deny: &Denylist) -> Result<(), ServicePolicyError> {
    for registry in &reply.registries {
        for text in [registry.target_url.as_deref(), registry.archive_origin.as_deref()] {
            let Some(url) = text.and_then(|text| url::Url::parse(text).ok()) else { continue };
            let (Some(url::Host::Domain(host)), Some(port)) = (url.host(), url.port_or_known_default()) else { continue };
            // Bounded: an unreachable resolver must not stall activation (connect time still checks).
            let Ok(Ok(answers)) = tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host((host, port))).await else { continue };
            if answers.into_iter().any(|addr| deny.denies_endpoint(addr.ip(), port)) {
                return Err(ServicePolicyError);
            }
        }
    }
    Ok(())
}

async fn validate_policy_snapshot(
    reply: &ServicePolicySnapshot,
    binding: &Binding,
    deny: &Denylist,
) -> Result<(), ServicePolicyError> {
    if binding.mode != "service_policy" {
        return Err(ServicePolicyError);
    }
    validate(reply, deny)
}

/// LS-F7: JSON nesting at most 16 and every string at most 2048 bytes.
fn within_wire_bounds(value: &serde_json::Value, depth: usize) -> bool {
    use serde_json::Value;
    match value {
        Value::String(text) => text.len() <= 2048,
        Value::Array(items) => depth < 16 && items.iter().all(|item| within_wire_bounds(item, depth + 1)),
        Value::Object(map) => depth < 16 && map.iter().all(|(key, item)| key.len() <= 2048 && within_wire_bounds(item, depth + 1)),
        _ => true,
    }
}

pub(super) fn validate(reply: &ServicePolicySnapshot, deny: &Denylist) -> Result<(), ServicePolicyError> {
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
        || reply.registries.len() > 256
        || reply.place_chain.len() > 16
        || reply.layers.iter().any(|layer| layer.layer.blocks.len() + layer.layer.exceptions.len() > 10_000)
        || reply.layers.iter().map(|layer| layer.layer.blocks.len() + layer.layer.exceptions.len()).sum::<usize>() > 100_000
        || !within_wire_bounds(&serde_json::to_value(reply).map_err(|_| ServicePolicyError)?, 1)
    {
        return Err(ServicePolicyError);
    }
    let mut ids = HashSet::new();
    for registry in &reply.registries {
        if registry.registry.0 == 0
            || registry.registry.0 > i64::MAX as u64
            || !ids.insert(registry.registry)
            || registry.registry_private_cidrs.len() > 64
            || registry.deletion_scopes.len() > 1000
        {
            return Err(ServicePolicyError);
        }
        let cidrs = registry
            .registry_private_cidrs
            .iter()
            .map(|text| text.parse::<ipnet::IpNet>().map_err(|_| ServicePolicyError))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(archive) = &registry.archive_origin {
            // Only a Cargo registry (archives apart from its index) or a Go registry (zip redirects to its
            // storage) has an archive origin, and one needs a target of its own.
            if archive.len() > 2048 || !matches!(registry.ecosystem, probation_policy::Ecosystem::Cargo | probation_policy::Ecosystem::Go | probation_policy::Ecosystem::NuGet | probation_policy::Ecosystem::Maven) || registry.target_url.is_none() {
                return Err(ServicePolicyError);
            }
            let url: url::Url = archive.parse().map_err(|_| ServicePolicyError)?;
            // The same absolute denylist as the target (LS-F9 / D5), and the same shape rules: https, no
            // userinfo, query or fragment.
            check_target(&url, deny).map_err(|_| ServicePolicyError)?;
            crate::upstream::OriginSet::selected_npm_with_private(url, cidrs.clone()).map_err(|_| ServicePolicyError)?;
        }
        if let Some(prefix) = &registry.resource_path_prefix {
            // Only a NuGet registry with a target has one, and it is whole path segments.
            if registry.ecosystem != probation_policy::Ecosystem::NuGet || registry.target_url.is_none() || !valid_resource_prefix(prefix) {
                return Err(ServicePolicyError);
            }
        }
        if let Some(target) = &registry.target_url {
            if target.len() > 2048 {
                return Err(ServicePolicyError);
            }
            let url: url::Url = target.parse().map_err(|_| ServicePolicyError)?;
            // LS-F9 / D5: an absolute denylist the registry's own private CIDRs cannot unlock.
            check_target(&url, deny).map_err(|_| ServicePolicyError)?;
            crate::upstream::OriginSet::selected_npm_with_private(
                url,
                cidrs,
            )
            .map_err(|_| ServicePolicyError)?;
        }
    }
    Ok(())
}

/// A NuGet registry's resource path prefix: `/` then whole segments of `[A-Za-z0-9._~-]`, no dot-only segment, no
/// trailing slash, at most 512 bytes (the portal and the activation use this one rule).
pub fn valid_resource_prefix(prefix: &str) -> bool {
    prefix.len() <= 512
        && prefix.starts_with('/')
        && prefix.len() > 1
        && !prefix.ends_with('/')
        && prefix[1..].split('/').all(|segment| !segment.is_empty() && segment != "." && segment != ".." && segment.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')))
}
