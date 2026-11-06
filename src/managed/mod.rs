//! Managed mode: turn a request's API key into its compiled policy, keep that fresh
//! from the management server, and ship activity (C2, C19, C20, C96).
//!
//! The `Authorization` header is read here and nowhere else (T19). Only its SHA-256
//! leaves this module; neither the key nor its hash reaches a record, an activity row,
//! a report or a log line.

pub mod activity;
pub mod service_policy;
mod cache;
pub mod certificates;
pub mod enterprise_certificate;
pub mod client;
mod lock;
pub mod report;
pub mod sync;

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue};
use probation_policy::PlaceRef;
use probation_policy::api::{
    ActivityEvent, ActivityLayer, ActivityResult, CertificateAdmission,
    CertificateAdmissionRequest, ChainLink, FirewallReport, KeyHash, KeyId, KeyLookup,
    LayersResponse, LimitSource, OrgId, RegistryId, ReportStatus, Upstreams,
};
use tokio_util::sync::CancellationToken;
use url::Url;

use self::activity::ActivityQueue;
use self::cache::{
    Budget, Insert, KeyCache, KnownRefusal, Policies, Snapshot, Standing, UNKNOWN_FOR, Unresolved,
};
use self::client::{CallError, SyncClient};
use self::lock::{NetworkLock, TrustedProxies};
use self::sync::KeySync;
use crate::clock::Clock;
use crate::concurrency::{Resolution, SingleFlight};
use crate::config::{ManagementConfig, SettingsState};
use crate::managed::certificates::VerifiedPeer;
use crate::policy::{Candidate, CompiledPolicy, Decision, DenyReason, Ecosystem, PolicyVerdict};

/// Who a request runs as. Never holds the key or its hash.
#[derive(Clone)]
pub struct Principal {
    pub(crate) authority: Option<service_policy::AuthorityReceipt>,
    /// The key's own place, the last of `chain`.
    pub place: PlaceRef,
    /// The server's id, for activity rows.
    pub key_id: KeyId,
    /// Interned by fingerprint, so every key with the same effective policy shares it.
    pub policy: Arc<CompiledPolicy>,
    /// The organisation or personal account the rate limit counts against (C28).
    pub account: PlaceRef,
    /// The account's requests per minute on this firewall (C66, C114).
    pub rate_limit: Option<NonZeroU32>,
    pub rate_limit_source: LimitSource,
    /// `None` for a personal account.
    pub org: Option<OrgId>,
    /// Platform -> … -> place.
    pub chain: Arc<[PlaceRef]>,
    /// Immutable origin selected by the live registry join. Key principals have none.
    pub registry_origin: Option<Url>,
    /// Request-scoped shared credential, for ordinary selected-registry reads only.
    pub registry_read_authorization: Option<String>,
    pub registry_trusted: bool,
    pub registry_private_cidrs: Vec<ipnet::IpNet>,
    pub deletion_scopes: Vec<probation_policy::api::RegistryDeletionScope>,
}

/// Why `authenticate` refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Missing, malformed, unknown, revoked or suspended, no answer from the server for
    /// a key with no entry, or a retired firewall: `401` with one fixed message (C13).
    Unauthenticated,
    /// `403 NETWORK_NOT_ALLOWED`: another organisation's network lock covers this client
    /// address (C30, C92). Carries the address the answer shows.
    Network(IpAddr),
    /// `429 TOO_MANY_REQUESTS`: the key's account is over its rate on this firewall
    /// (C66, C114).
    RateLimited,
    /// `503 LOOKUP_BUSY`: the lookup budget is spent or the server answered `429`, so a
    /// valid key is told to retry rather than that it is wrong.
    Busy,
}

/// Why a call to the server gave no principal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Failed {
    /// The answer itself refuses the key.
    Refused(Refusal),
    /// The budget is spent, or the server cannot answer yet.
    Busy,
    /// The server could not be reached.
    Unreachable,
}

/// The managed half of `App`, present only when `[management]` is set.
pub struct Managed {
    #[cfg(test)]
    admission_checkpoint: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    publication_gate: Arc<service_policy::PolicyPublicationGate>,
    cache: Arc<KeyCache>,
    budget: Budget,
    policies: Arc<Policies>,
    network_lock: Arc<NetworkLock>,
    proxies: TrustedProxies,
    rates: RateLimits,
    activity: ActivityQueue,
    lookups: SingleFlight<KeyHash, Result<Principal, Failed>>,
    /// One `layers` call per place in flight, however many requests need it.
    layer_fetches: SingleFlight<PlaceRef, Result<(), Failed>>,
    client: SyncClient,
    sync: KeySync,
    /// Set once this firewall is retired (C72); checked before anything else.
    retired: Arc<AtomicBool>,
    /// A cache snapshot was loaded or a sync applied: until then no request is served,
    /// so the network lock never runs on an empty table (T1).
    ready: AtomicBool,
    /// Why the last sync could not be delivered, when the server refused even an empty
    /// one; shown on `/health/ready` and in the next report.
    sync_error: Mutex<Option<String>>,
    /// Why the last answer could not be read (F3): reported, never a readiness failure.
    /// Cleared by the next readable `changes` answer, and set again by an unreadable
    /// call after it.
    version_skew: Mutex<Option<String>>,
    settings: Mutex<SettingsState>,
    /// The push this process runs with: the one in force when it started. Reported
    /// instead of a push written since, which is only run after the restart (ND-1).
    running_revision: u64,
    /// Cancelled once a settings push is written: the process drains and exits 75.
    restart: CancellationToken,
    data_dir: PathBuf,
    period: Duration,
    clock: Arc<dyn Clock>,
}

/// The longest `Authorization` value decoded. A key is 36 characters; anything this
/// long is refused before a byte of it is decoded (T19).
const MAX_CREDENTIALS_BYTES: usize = 1024;

/// The most calls one ask makes: two lookups, and two rounds of two `layers` calls.
const ASK_CALLS: u32 = 6;

/// The longest `last_apply_error` a report carries, below the server's cap.
const MAX_APPLY_ERROR_BYTES: usize = 2048;

impl Managed {
    /// Certificate admission never consults the key cache: every request gets one
    /// current management answer and its policy layers from the same snapshot.
    ///
    /// A policy publication (every sync apply is one) that lands mid-admission voids
    /// the answer, so it is asked again against the new generation, at most three
    /// times, rather than reported as busy. The check and the rate charge happen under
    /// one read of the publication gate, so a voided answer spends no token and no
    /// publication can slip between them. A failed management call is not retried.
    pub async fn admit_certificate(
        &self,
        peer: &VerifiedPeer,
        registry: RegistryId,
        ecosystem: Ecosystem,
        socket: IpAddr,
        headers: &HeaderMap,
        charge_rate: bool,
    ) -> Result<Principal, Refusal> {
        for _ in 0..3 {
            let (principal, generation, client) = self
                .admit_certificate_at(peer, registry, ecosystem, socket, headers)
                .await?;
            let admitted = self
                .publication_gate
                .read(|now| {
                    if now != generation {
                        return None;
                    }
                    Some(if charge_rate {
                        self.admit(&principal, client)
                    } else {
                        self.admit_network(&principal, client)
                    })
                })
                .map_err(|_| Refusal::Busy)?;
            match admitted {
                Some(admission) => return admission.map(|()| principal),
                None => continue,
            }
        }
        Err(Refusal::Busy)
    }

    /// One management answer, built into a principal stamped with the generation read
    /// before the call. Not yet charged to the account's rate or checked against the
    /// network lock.
    async fn admit_certificate_at(
        &self,
        peer: &VerifiedPeer,
        registry: RegistryId,
        ecosystem: Ecosystem,
        socket: IpAddr,
        headers: &HeaderMap,
    ) -> Result<(Principal, u64, IpAddr), Refusal> {
        let generation = self.publication_gate.generation();
        let client = self
            .proxies
            .client(socket, headers)
            .ok_or(Refusal::Network(socket.to_canonical()))?;
        let answer = self
            .client
            .certificate(CertificateAdmissionRequest {
                registry,
                ecosystem,
                chain: peer.chain.iter().cloned().collect(),
            })
            .await
            .map_err(|error| {
                // The kind only: never the chain or any key material.
                tracing::warn!(?error, "the certificate admission call failed; answering busy");
                Refusal::Busy
            })?;
        let CertificateAdmission::Granted {
            registry: granted_registry,
            target_url,
            read_authorization,
            trusted,
            registry_private_cidrs,
            deletion_scopes,
            enterprise_status,
            org,
            member: _,
            place,
            layers,
            rate_limit,
            rate_limit_source,
        } = answer
        else {
            return Err(Refusal::Unauthenticated);
        };
        if let Some(status) = enterprise_status.as_ref() {
            enterprise_certificate::resolve_enterprise_certificate(
                &enterprise_certificate::EnterprisePeer { chain: peer, status },
            ).await.map_err(|_| Refusal::Unauthenticated)?;
        }
        let registry_private_cidrs = registry_private_cidrs.iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>().map_err(|_| Refusal::Unauthenticated))
            .collect::<Result<Vec<_>, _>>()?;
        let registry_origin = target_url
            .as_deref()
            .map(|target| {
                let url = Url::parse(target).map_err(|_| Refusal::Unauthenticated)?;
                crate::upstream::OriginSet::selected_npm_with_private(url.clone(), registry_private_cidrs.clone())
                    .map_err(|_| Refusal::Unauthenticated)?;
                Ok(url)
            })
            .transpose()?;
        if granted_registry != registry
            || layers
                .first()
                .is_none_or(|layer| layer.place.kind != probation_policy::LayerKind::Platform)
            || layers.last().is_none_or(|layer| layer.place != place)
            || !layers.iter().any(|layer| {
                layer.place
                    == PlaceRef {
                        kind: probation_policy::LayerKind::Org,
                        id: org.0,
                    }
            })
        {
            return Err(Refusal::Unauthenticated);
        }
        let chain: Arc<[PlaceRef]> = layers
            .iter()
            .map(|layer| layer.place)
            .collect::<Vec<_>>()
            .into();
        let layer_values = layers
            .into_iter()
            .map(|layer| layer.layer)
            .collect::<Vec<_>>();
        let account = PlaceRef {
            kind: probation_policy::LayerKind::Org,
            id: org.0,
        };
        let policy = probation_policy::resolve(&layer_values);
        let policy = if trusted {
            CompiledPolicy::managed_trusted(policy)
        } else {
            CompiledPolicy::managed(policy)
        };
        // shortcut: certificate activity has no key row; add a separate certificate
        // activity identity when the activity schema supports it.
        let principal = Principal {
            authority: Some(service_policy::AuthorityReceipt { gate: Arc::clone(&self.publication_gate), generation }),
            place,
            key_id: KeyId(0),
            policy: Arc::new(policy),
            account,
            rate_limit,
            rate_limit_source,
            org: Some(org),
            chain,
            registry_origin,
            registry_read_authorization: read_authorization,
            registry_trusted: trusted,
            registry_private_cidrs,
            deletion_scopes,
        };
        Ok((principal, generation, client))
    }
    /// Loads `<data_dir>/managed-cache.json` when there is one, so a restart while the
    /// server is down keeps serving (C19, C115).
    pub fn new(
        config: &ManagementConfig,
        sync_interval: Duration,
        clock: Arc<dyn Clock>,
        data_dir: &Path,
    ) -> Managed {
        let ttl = Duration::from_secs(config.key_cache_ttl_seconds.get());
        let request_timeout = Duration::from_secs(config.request_timeout_seconds.get());
        // An ask is at most two lookups and two rounds of two `layers` calls, each
        // within the request timeout; an invalidation outlives any answer read before it.
        let cache = Arc::new(
            KeyCache::new(config.key_cache_max_entries.get(), ttl, Arc::clone(&clock))
                .keeping_records_for(request_timeout * ASK_CALLS),
        );
        let policies = Arc::new(Policies::default());
        let publication_gate = Arc::new(service_policy::PolicyPublicationGate::default());
        let network_lock = Arc::new(NetworkLock::default());
        let retired = Arc::new(AtomicBool::new(false));
        let snapshot = cache::read_snapshot(data_dir);
        let ready = snapshot.is_some();
        let mut cursor = 0;
        if let Some(snapshot) = snapshot {
            cursor = snapshot.cursor;
            policies.restore(snapshot.layers);
            network_lock.adopt(Some(&snapshot.network_lock));
            for key in snapshot.keys {
                let Some(policy) = policies.compile_places(&key.chain) else {
                    continue;
                };
                cache.restore(
                    key.hash,
                    Principal {
                        authority: None,
                        place: key.place,
                        key_id: key.key_id,
                        policy,
                        account: key.account,
                        rate_limit: key.rate_limit,
                        rate_limit_source: key.rate_limit_source,
                        org: key.org,
                        chain: key.chain.into(),
                        registry_origin: None,
                        registry_read_authorization: None,
                        registry_trusted: false,
                        registry_private_cidrs: Vec::new(),
                        deletion_scopes: Vec::new(),
                    },
                );
            }
        }
        let margin = Duration::from_secs(config.sync_margin_seconds.get());
        let settings = SettingsState::load(data_dir);
        let activity = ActivityQueue::new(clock.now_utc_micros());
        activity.restore(data_dir);
        Managed {
            #[cfg(test)]
            admission_checkpoint: Mutex::new(None),
            budget: Budget::new(
                config.lookup_budget_per_second.get(),
                config.client_lookup_allowance_per_second.get(),
                Arc::clone(&clock),
            ),
            proxies: TrustedProxies::new(config.trusted_proxies.clone()),
            rates: RateLimits::new(Arc::clone(&clock)),
            activity,
            lookups: SingleFlight::new(),
            layer_fetches: SingleFlight::new(),
            client: SyncClient::new(config),
            sync: KeySync::new(
                config,
                Arc::clone(&cache),
                Arc::clone(&policies),
                Arc::clone(&network_lock),
                Arc::clone(&retired),
                cursor,
                Arc::clone(&publication_gate),
            ),
            publication_gate,
            cache,
            policies,
            network_lock,
            retired,
            ready: AtomicBool::new(ready),
            sync_error: Mutex::new(None),
            version_skew: Mutex::new(None),
            running_revision: settings.settings_revision,
            settings: Mutex::new(settings),
            restart: CancellationToken::new(),
            data_dir: data_dir.to_path_buf(),
            period: sync_interval
                .saturating_sub(margin)
                .max(Duration::from_secs(1)),
            clock,
        }
    }

    /// How many requests share the lookup in flight for `hash`; zero when none is.
    /// **Compiled only under `test-support`**, so a test can wait for a burst to join
    /// rather than sleep.
    #[cfg(feature = "test-support")]
    pub fn waiting_on(&self, hash: &KeyHash) -> usize {
        self.lookups.waiting_on(hash)
    }

    /// How many requests share the `layers` call in flight for `place`. **Compiled only
    /// under `test-support`.**
    #[cfg(feature = "test-support")]
    pub fn waiting_on_layer(&self, place: PlaceRef) -> usize {
        self.layer_fetches.waiting_on(&place)
    }

    /// Whether requests may be authenticated: a cache snapshot was loaded or a sync
    /// applied (C109). A retired firewall is ready, and refuses every key itself.
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// `/health/ready`: [`Managed::ready`] and not retired, unless the server keeps
    /// refusing even an empty sync.
    pub fn healthy(&self) -> bool {
        self.ready() && !self.retired.load(Ordering::Acquire) && lock(&self.sync_error).is_none()
    }

    /// The fixed rate the sync loop runs at: `sync_interval − sync_margin` (C112).
    pub fn sync_period(&self) -> Duration {
        self.period
    }

    pub fn sync(&self) -> &KeySync {
        &self.sync
    }

    pub fn activity(&self) -> &ActivityQueue {
        &self.activity
    }

    /// Resolves once a settings push was written and the process should drain and exit
    /// with code 75 (C105).
    pub async fn restart_requested(&self) {
        self.restart.cancelled().await;
    }

    pub fn restart_pending(&self) -> bool {
        self.restart.is_cancelled()
    }

    /// The only reader of the `Authorization` header. Only the key's SHA-256 leaves.
    /// `peer` is the connection's address; behind a listed proxy the client address is
    /// taken from `X-Forwarded-For` (C113), and it is what the network lock and the
    /// per-client lookup allowance use (C120).
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        peer: IpAddr,
    ) -> Result<Principal, Refusal> {
        if self.retired.load(Ordering::Acquire) {
            return Err(Refusal::Unauthenticated);
        }
        let presented = headers.get(AUTHORIZATION).ok_or(Refusal::Unauthenticated)?;
        let hash = key_hash(presented)?;
        let client = self
            .proxies
            .client(peer, headers)
            .ok_or(Refusal::Network(peer.to_canonical()))?;
        // Freshness and its authority generation are one protected observation.
        let (observed_generation, fresh) = self.publication_gate.read(|generation| {
            (generation, self.cache.fresh(&hash))
        }).map_err(|_| Refusal::Busy)?;
        #[cfg(test)]
        if let Some(checkpoint) = lock(&self.admission_checkpoint).take() { checkpoint(); }
        let (generation, mut principal) = if let Some(principal) = fresh {
            (observed_generation, principal)
        } else {
            self.look_up(&hash, client).await?;
            self.publication_gate.read(|generation| {
            if self.retired.load(Ordering::Acquire) { return Err(Refusal::Unauthenticated); }
            // C19: an unreadable/unreachable layer refresh keeps its last known
            // policy, but a publication during lookup must not bless an old entry.
            let current = self.cache.fresh(&hash).or_else(|| {
                (generation == observed_generation).then(|| self.cache.stale(&hash)).flatten()
            }).ok_or(Refusal::Busy)?;
            Ok((generation, current))
            }).map_err(|_| Refusal::Busy)??
        };
        principal.authority = Some(service_policy::AuthorityReceipt { gate: Arc::clone(&self.publication_gate), generation });
        self.admit(&principal, client)?;
        Ok(principal)
    }

    /// The network lock, then the account's rate (C30, C66).
    fn admit(&self, principal: &Principal, client: IpAddr) -> Result<(), Refusal> {
        self.admit_network(principal, client)?;
        if !self.rates.admit(principal.account, principal.rate_limit) {
            return Err(Refusal::RateLimited);
        }
        Ok(())
    }

    fn admit_network(&self, principal: &Principal, client: IpAddr) -> Result<(), Refusal> {
        if self.network_lock.refuses(client, principal.org) {
            if principal.key_id.0 != 0 {
                self.record(
                    principal.account,
                    ActivityEvent {
                        client_ip: Some(client),
                        ..row(
                            principal.key_id,
                            principal.place,
                            ActivityResult::RefusedNetwork,
                            "network_lock",
                            ActivityLayer::Network,
                        )
                    },
                );
            }
            return Err(Refusal::Network(client));
        }
        Ok(())
    }

    /// Single-flighted per hash: a burst of requests with one new key makes one lookup,
    /// and only the request that makes it is charged to the budget. While the server is
    /// marked down an expired entry is served as it is, with no wait (C96).
    async fn look_up(&self, hash: &KeyHash, client: IpAddr) -> Result<Principal, Refusal> {
        if self.cache.server_down()
            && let Some(stale) = self.cache.stale(hash)
        {
            return Ok(stale);
        }
        let (slot, leader, _waiter) = self.lookups.join(*hash);
        let answer = if leader {
            let mut resolution = Resolution::new(
                self.lookups.clone(),
                *hash,
                Arc::clone(&slot),
                Err(Failed::Busy),
                // Never the hash: it does not go in a log line.
                "a key lookup".to_owned(),
            );
            let answer = self.ask(hash, client).await;
            resolution.answer(answer.clone());
            answer
        } else {
            slot.wait().await.unwrap_or(Err(Failed::Busy))
        };
        answer.map_err(|failed| match failed {
            Failed::Refused(refusal) => refusal,
            Failed::Busy => Refusal::Busy,
            Failed::Unreachable => Refusal::Unauthenticated,
        })
    }

    /// The server's answer for `hash`, or the expired entry it replaces when the server
    /// cannot give one: always while it is unreachable, and while it is busy unless a
    /// `place` row expired the entry (C19, C96).
    async fn ask(&self, hash: &KeyHash, client: IpAddr) -> Result<Principal, Failed> {
        let invalidated = match self.cache.standing(hash) {
            Standing::Refused(known) => {
                if let Some(known) = known {
                    self.record_refusal(&known);
                }
                return Err(Failed::Refused(Refusal::Unauthenticated));
            }
            Standing::Expired { invalidated } => Some(invalidated),
            Standing::Missing => None,
        };
        let answer = self.ask_server(hash, client, invalidated.is_some()).await;
        match (answer, invalidated) {
            (Err(Failed::Unreachable), Some(_)) => self.cache.stale(hash).ok_or(Failed::Busy),
            // Read again: a `place` row may have expired the entry while it was asked
            // about, and a place-expired entry is never served for a busy server.
            (Err(Failed::Busy), Some(false))
                if matches!(
                    self.cache.standing(hash),
                    Standing::Expired { invalidated: false }
                ) =>
            {
                self.cache.stale(hash).ok_or(Failed::Busy)
            }
            (answer, _) => answer,
        }
    }

    async fn ask_server(
        &self,
        hash: &KeyHash,
        client: IpAddr,
        has_entry: bool,
    ) -> Result<Principal, Failed> {
        if !self.budget.take(client, has_entry) {
            return Err(Failed::Busy);
        }
        // The reset epoch each call starts in: an answer from before a reset is never
        // kept (C126).
        let mut epoch = self.cache.epoch();
        let mut answer = self
            .client
            .lookup(*hash)
            .await
            .map_err(|e| self.failed(e))?;
        if !self.cache.is_current(&answer) || self.cache.epoch() != epoch {
            // Read before an invalidation this firewall has already applied: dropped,
            // and asked once more (H6).
            epoch = self.cache.epoch();
            answer = self
                .client
                .lookup(*hash)
                .await
                .map_err(|e| self.failed(e))?;
            if !self.cache.is_current(&answer) {
                return Err(Failed::Busy);
            }
        }
        let suspended = matches!(answer, KeyLookup::Suspended { .. });
        // Checked again where it is cached: an invalidation can land while the layers
        // are fetched.
        let read = answer.clone();
        let (key_id, org, account, chain, rate_limit, rate_limit_source) = match answer {
            KeyLookup::Known {
                key_id,
                org,
                account,
                place_chain,
                rate_limit,
                rate_limit_source,
                ..
            } => (
                key_id,
                org,
                account,
                place_chain,
                rate_limit,
                rate_limit_source,
            ),
            KeyLookup::Unknown { .. } => {
                let _ = self.publication_gate.publish(|| self.cache
                    .refuse_current(*hash, Some(UNKNOWN_FOR), None, &read, epoch));
                return Err(Failed::Refused(Refusal::Unauthenticated));
            }
            KeyLookup::Revoked {
                key_id,
                place,
                place_chain,
                ..
            }
            | KeyLookup::Suspended {
                key_id,
                place,
                place_chain,
                ..
            } => {
                let chain: Arc<[PlaceRef]> = place_chain.iter().map(|link| link.place).collect();
                let known = KnownRefusal {
                    key_id,
                    place,
                    // The organisation or personal account: second in every chain.
                    account: chain.get(1).copied().unwrap_or(place),
                    chain,
                    suspended,
                };
                if !self.publication_gate.publish(|| self.cache
                    .refuse_current(*hash, None, Some(known.clone()), &read, epoch)).unwrap_or(false)
                {
                    // A `key` or `place` row since may have restored it: asked again.
                    return Err(Failed::Busy);
                }
                self.record_refusal(&known);
                return Err(Failed::Refused(Refusal::Unauthenticated));
            }
        };
        let policy = self.policy_of(&chain, client).await?;
        let found = Principal {
            authority: None,
            place: chain
                .last()
                .map(|link| link.place)
                .ok_or(Failed::Refused(Refusal::Unauthenticated))?,
            key_id,
            policy,
            account,
            rate_limit,
            rate_limit_source,
            org,
            chain: chain.iter().map(|link| link.place).collect(),
            registry_origin: None,
            registry_read_authorization: None,
            registry_trusted: false,
            registry_private_cidrs: Vec::new(),
            deletion_scopes: Vec::new(),
        };
        match self.publication_gate.publish(|| self.cache
            .insert_current(*hash, found.clone(), &read, epoch)).map_err(|_| Failed::Busy)?
        {
            Insert::Done => {}
            // Invalidated while its layers were fetched (H6), or the cache is full while
            // the server is down, when nothing is evicted.
            Insert::Late | Insert::Full => return Err(Failed::Busy),
        }
        // Retired, or a `layer` row for its chain, since the policy was built: its own
        // invalidation already ran, so the entry it would have cleared goes now.
        let retired = self.retired.load(Ordering::Acquire);
        if retired || self.policies.any_stale(&found.chain) {
            self.cache.remove_live(hash, key_id);
            return Err(if retired {
                Failed::Refused(Refusal::Unauthenticated)
            } else {
                Failed::Busy
            });
        }
        Ok(found)
    }

    /// The compiled policy of a key's chain, fetching the layers this firewall does not
    /// hold at the revisions the chain names, or holds stale.
    async fn policy_of(
        &self,
        chain: &[ChainLink],
        client: IpAddr,
    ) -> Result<Arc<CompiledPolicy>, Failed> {
        let mut compiled = Err(Unresolved::Behind);
        // Twice at most: a reset can drop layers this chain needs while they are fetched.
        for _ in 0..2 {
            let missing = self.policies.missing(chain);
            if !missing.is_empty() {
                self.fetch_layers(missing, Some(client)).await?;
            }
            compiled = self.policies.compile(chain);
            if !matches!(compiled, Err(Unresolved::Behind)) {
                break;
            }
        }
        compiled.map_err(|unresolved| match unresolved {
            // A valid key that cannot be checked yet is told to retry, never refused.
            Unresolved::Behind => {
                tracing::warn!(
                    "the management server's layers answer holds a layer older than its \
                         chain names, or none; answering busy"
                );
                Failed::Busy
            }
            Unresolved::Inconsistent => {
                tracing::error!(
                    "the management server answered a lookup with a chain whose layers \
                     this firewall cannot resolve; refusing the request"
                );
                Failed::Refused(Refusal::Unauthenticated)
            }
        })
    }

    /// One `layers` call for the places this caller is first to need; the others are
    /// waited for. A request's fetch is charged to the lookup budget; the sync task's
    /// (`client` `None`) is not.
    async fn fetch_layers(
        &self,
        places: Vec<PlaceRef>,
        client: Option<IpAddr>,
    ) -> Result<(), Failed> {
        let mut leading = Vec::new();
        let mut joined = Vec::new();
        for place in places {
            let (slot, leader, waiter) = self.layer_fetches.join(place);
            if leader {
                let resolution = Resolution::new(
                    self.layer_fetches.clone(),
                    place,
                    slot,
                    Err(Failed::Busy),
                    "a layer fetch".to_owned(),
                );
                leading.push((place, resolution, waiter));
            } else {
                joined.push((slot, waiter));
            }
        }
        let mut outcome = Ok(());
        if !leading.is_empty() {
            let places = leading.iter().map(|(place, ..)| *place).collect();
            outcome = self.ask_layers(places, client).await;
            for (_, resolution, _) in &mut leading {
                resolution.answer(outcome);
            }
        }
        for (slot, _waiter) in joined {
            outcome = outcome.and(slot.wait().await.unwrap_or(Err(Failed::Busy)));
        }
        outcome
    }

    async fn ask_layers(
        &self,
        places: Vec<PlaceRef>,
        client: Option<IpAddr>,
    ) -> Result<(), Failed> {
        if let Some(client) = client
            && !self.budget.take(client, true)
        {
            return Err(Failed::Busy);
        }
        let epoch = self.cache.epoch();
        let answer = self
            .client
            .layers(places.clone())
            .await
            .map_err(|e| self.failed(e))?;
        if self.store_layers(answer, epoch) {
            return Ok(());
        }
        // Read before a `layer` row or a reset this firewall has applied: asked once
        // more (H6).
        let epoch = self.cache.epoch();
        let answer = self
            .client
            .layers(places)
            .await
            .map_err(|e| self.failed(e))?;
        if self.store_layers(answer, epoch) {
            Ok(())
        } else {
            Err(Failed::Busy)
        }
    }

    /// Keeps a `layers` answer unless a reset happened since its call started (C126) or
    /// it was read before an invalidation (H6).
    ///
    /// A layer newer than the one cached keys were built on rebuilds them at once, so a
    /// shared layer's edit that arrives with another key's lookup reaches every key now,
    /// not at its cache TTL; the next sync's `layer` row finds it current (E2E-013).
    fn store_layers(&self, answer: LayersResponse, epoch: u64) -> bool {
        self.publication_gate.publish(|| {
        let floor = self.cache.floor();
        let mut replaced = Vec::new();
        let current = self.cache.in_epoch(epoch, || {
            let (current, newer) = self.policies.store(answer, floor);
            replaced = newer;
            current
        });
        if !replaced.is_empty() {
            let policies = &self.policies;
            self.cache
                .rebuild(&replaced, |chain| policies.compile_places(chain));
        }
        current
        }).unwrap_or(false)
    }

    /// What a failed call to the server means for this firewall.
    fn failed(&self, error: CallError) -> Failed {
        match error {
            CallError::Busy => Failed::Busy,
            CallError::Unreadable => {
                self.note_unreadable();
                self.cache.note_server_down();
                Failed::Unreachable
            }
            CallError::Unreachable => {
                tracing::warn!("the management server could not be asked about a key");
                self.cache.note_server_down();
                Failed::Unreachable
            }
            CallError::TokenRefused => {
                // As a retired answer to a sync does: every later request is refused,
                // and this answer is never cached as a key's (C72).
                tracing::error!("the management server refused this firewall's token");
                let _ = self.publication_gate.publish(|| {
                    self.retired.store(true, Ordering::Release);
                    self.cache.clear();
                });
                Failed::Refused(Refusal::Unauthenticated)
            }
        }
    }

    fn record_refusal(&self, known: &KnownRefusal) {
        let (result, rule) = if known.suspended {
            (ActivityResult::RefusedSuspended, "suspended")
        } else {
            (ActivityResult::RefusedRevoked, "revoked")
        };
        self.record(
            known.account,
            row(known.key_id, known.place, result, rule, ActivityLayer::None),
        );
    }

    /// Queues `event`, stamped with when it happened (M3): a batch re-sent after an
    /// outage keeps its time.
    fn record(&self, account: PlaceRef, mut event: ActivityEvent) {
        event.at = Some(crate::delivery::rfc3339(self.clock.now_utc_micros()));
        self.activity.record_activity(account, event);
    }

    /// A blocked, held or would-have-blocked decision, recorded for the key's owner with
    /// the rule and layer behind it (C23, C56, C81, C92).
    /// `version` is `None` for a refused listing, whose row carries the package alone
    /// (S3-8).
    pub fn record_decision(
        &self,
        principal: &Principal,
        ecosystem: Ecosystem,
        package: &str,
        version: Option<&str>,
        verdict: &PolicyVerdict,
    ) {
        if principal.key_id.0 == 0 {
            return;
        }
        let (result, rule, eligible_at) = match verdict.decision {
            Decision::Allow if verdict.would_block => (ActivityResult::WouldBlock, "osv", None),
            Decision::Allow | Decision::Unavailable => return,
            Decision::Hold { eligible_at_micros } => (
                ActivityResult::Held,
                "freeze",
                // As the 403 body spells it (SPEC §11).
                jiff::Timestamp::from_microsecond(eligible_at_micros)
                    .ok()
                    .map(|at| at.to_string()),
            ),
            Decision::Deny(reason) => (ActivityResult::Blocked, deny_rule(reason), None),
        };
        let layer = verdict
            .layer
            .map_or(ActivityLayer::None, ActivityLayer::Layer);
        self.record(
            principal.account,
            ActivityEvent {
                ecosystem: Some(ecosystem),
                package: Some(package.to_owned()),
                version: version.map(str::to_owned),
                eligible_at,
                ..row(principal.key_id, principal.place, result, rule, layer)
            },
        );
    }

    /// The row for a request `decision` refused, naming `candidate`'s version when
    /// `names_version`.
    pub fn record_refused(
        &self,
        principal: &Principal,
        policy: &CompiledPolicy,
        now: i64,
        candidate: &Candidate<'_>,
        decision: Decision,
        names_version: bool,
    ) {
        let verdict = refused_verdict(policy, now, candidate, decision);
        let version = names_version.then_some(candidate.version);
        self.record_decision(
            principal,
            candidate.ecosystem,
            candidate.name,
            version,
            &verdict,
        );
    }

    /// After a sync the server answered: refetch the stale layers in one call and
    /// rebuild the policies that hold them, then prune what no key used for a TTL
    /// (C96, C111). Never after an outage, which must not shrink the cache (W3).
    pub async fn after_answer(&self) {
        self.ready.store(true, Ordering::Release);
        *lock(&self.sync_error) = None;
        // Before the layers call below, which sets it again if its answer is unreadable.
        *lock(&self.version_skew) = None;
        let stale = self.policies.stale();
        if !stale.is_empty() && self.fetch_layers(stale.clone(), None).await.is_ok() {
            let _ = self.publication_gate.publish(|| {
                let policies = &self.policies;
                self.cache
                    .rebuild(&stale, |chain| policies.compile_places(chain));
            });
        }
        let used = self.cache.prune_idle();
        self.policies.retain(&used, self.cache.records_for());
        self.rates.prune();
    }

    /// The server could not be reached, or refused even an empty sync: until it next
    /// answers, expired entries are served stale with no lookup.
    pub fn note_unreachable(&self, error: Option<String>) {
        self.cache.note_server_down();
        if error.is_some() {
            *lock(&self.sync_error) = error;
        }
    }

    /// A `2xx` answer that does not decode (F3): logged at error level and reported on
    /// the fleet page, while the firewall stays ready and serves its cache as for an
    /// unreachable server (decision 2026-10-23).
    pub fn note_unreadable(&self) {
        let error = format!(
            "the management server's answer could not be read; this firewall (v{}) may be older than the server",
            env!("CARGO_PKG_VERSION")
        );
        tracing::error!("{error}; serving from the cache");
        *lock(&self.version_skew) = Some(error);
    }

    /// Writes what is still queued to `<data_dir>/managed-activity.json` for the next
    /// start to send (ND-3). Called once, as the process stops.
    pub fn save_activity(&self) {
        if let Err(err) = self.activity.save(&self.data_dir) {
            tracing::error!(error = %err, "the undelivered activity could not be saved; it is lost");
        }
    }

    /// Writes `<data_dir>/managed-cache.json` off the async runtime (C115).
    pub async fn save_snapshot(&self) {
        let snapshot = Snapshot {
            version: cache::SNAPSHOT_VERSION,
            cursor: self.sync.cursor(),
            keys: self.cache.saved(),
            layers: self.policies.saved(),
            network_lock: self.network_lock.ranges(),
        };
        let data_dir = self.data_dir.clone();
        let written =
            tokio::task::spawn_blocking(move || cache::write_snapshot(&data_dir, &snapshot)).await;
        if !matches!(written, Ok(Ok(()))) {
            tracing::error!("the managed cache snapshot could not be written");
        }
    }

    /// The report sent with the next `changes` call.
    pub fn report(&self, upstreams: Upstreams) -> FirewallReport {
        let settings = lock(&self.settings);
        let (error, failed_revision) = match lock(&self.sync_error)
            .clone()
            .or_else(|| settings.last_apply_error.clone())
        {
            Some(error) => (Some(error), settings.failed_revision),
            // Not an apply failure: revision 0, which no settings rollout has, so the
            // server never fails a rollout step on it (S7-14).
            None => match lock(&self.version_skew).clone() {
                Some(skew) => (Some(skew), Some(0)),
                None => (None, settings.failed_revision),
            },
        };
        let error = error.map(|mut error| {
            let mut end = error.len().min(MAX_APPLY_ERROR_BYTES);
            while !error.is_char_boundary(end) {
                end -= 1;
            }
            error.truncate(end);
            error
        });
        FirewallReport {
            settings_revision: self.running_revision,
            last_apply_error: error,
            status: ReportStatus { upstreams },
            effective_period_seconds: self.period.as_secs(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            failed_revision,
        }
    }

    /// The settings state, to decide on a push.
    pub fn settings(&self) -> SettingsState {
        lock(&self.settings).clone()
    }

    /// Records the outcome of a push. A written one asks the process to restart (C105).
    pub fn settle_settings(&self, state: SettingsState, restart: bool) {
        if let Err(err) = state.save(&self.data_dir) {
            tracing::error!(error = %err, "the settings state could not be written");
        }
        *lock(&self.settings) = state;
        if restart {
            self.restart.cancel();
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

/// An activity row with no coordinates, filled in by the caller.
fn row(
    key_id: KeyId,
    place: PlaceRef,
    result: ActivityResult,
    rule: &str,
    layer: ActivityLayer,
) -> ActivityEvent {
    ActivityEvent {
        event_id: String::new(),
        key_id,
        place,
        ecosystem: None,
        package: None,
        version: None,
        result,
        rule: rule.to_owned(),
        layer,
        client_ip: None,
        eligible_at: None,
        at: None,
    }
}

/// The verdict behind a refusal `decision`. `osv::evaluate` hands back only the
/// decision, so the layer is the one `decide` names for the same inputs: an OSV denial
/// is the one decided with a match.
pub fn refused_verdict(
    policy: &CompiledPolicy,
    now: i64,
    candidate: &Candidate<'_>,
    decision: Decision,
) -> PolicyVerdict {
    let osv_matched = decision == Decision::Deny(DenyReason::BlockedByOsv);
    crate::policy::decide(policy, candidate, now, osv_matched)
}

const fn deny_rule(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::BlockedPackage => "blocked_package",
        DenyReason::BlockedVersion => "blocked_version",
        DenyReason::BlockedDigest => "blocked_digest",
        DenyReason::BlockedByOsv => "osv",
        DenyReason::MalformedTimestamp => "malformed_timestamp",
        DenyReason::FutureTimestamp => "future_timestamp",
        DenyReason::NoTimestamp => "no_timestamp",
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Each account's requests a minute on this firewall (C28, C66, C114): a token bucket
/// of capacity `limit`, refilled at `limit / 60` a second on the injected clock.
struct RateLimits {
    clock: Arc<dyn Clock>,
    buckets: Mutex<HashMap<PlaceRef, Bucket>>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl RateLimits {
    fn new(clock: Arc<dyn Clock>) -> RateLimits {
        RateLimits {
            clock,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn admit(&self, account: PlaceRef, limit: Option<NonZeroU32>) -> bool {
        let Some(limit) = limit else {
            return true;
        };
        let limit = f64::from(limit.get());
        let now = self.clock.now_monotonic();
        let mut buckets = lock(&self.buckets);
        let bucket = buckets.entry(account).or_insert(Bucket {
            tokens: limit,
            at: now,
        });
        let refill = now.saturating_duration_since(bucket.at).as_secs_f64() * limit / 60.0;
        bucket.tokens = (bucket.tokens + refill).min(limit);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Forgets the buckets a minute has refilled: they are full again either way.
    fn prune(&self) {
        let now = self.clock.now_monotonic();
        lock(&self.buckets)
            .retain(|_, bucket| now.saturating_duration_since(bucket.at) < Duration::from_secs(60));
    }
}

fn key_hash(presented: &HeaderValue) -> Result<KeyHash, Refusal> {
    let key = bearer_or_basic_password(presented).ok_or(Refusal::Unauthenticated)?;
    Ok(KeyHash::of(&key))
}

/// The key from `Bearer <key>` (npm) or the password of `Basic <user:key>` (pip, uv,
/// Poetry; any username), if it has a key's shape. Format is checked before hashing.
fn bearer_or_basic_password(value: &HeaderValue) -> Option<String> {
    if value.len() > MAX_CREDENTIALS_BYTES {
        return None;
    }
    let (scheme, credentials) = value.to_str().ok()?.split_once(' ')?;
    let credentials = credentials.trim();
    let key = if scheme.eq_ignore_ascii_case("bearer") {
        credentials.to_owned()
    } else if scheme.eq_ignore_ascii_case("basic") {
        let decoded = String::from_utf8(base64_decode(credentials)?).ok()?;
        decoded.split_once(':')?.1.to_owned()
    } else {
        return None;
    };
    let shaped = key
        .strip_prefix("prb_")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_graphic()));
    shaped.then_some(key)
}

/// Standard-alphabet base64 with padding, the form RFC 7617 puts in a Basic header.
/// The caller has already bounded `text`.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let chunks = text.len() / 4;
    let mut out = Vec::with_capacity(chunks * 3);
    for (index, chunk) in text.as_bytes().chunks(4).enumerate() {
        let mut bits = 0u32;
        let mut padding = 0;
        for (position, &c) in chunk.iter().enumerate() {
            let value = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if position >= 2 && index == chunks - 1 => {
                    padding += 1;
                    0
                }
                _ => return None,
            };
            if padding > 0 && c != b'=' {
                return None;
            }
            bits = bits << 6 | u32::from(value);
        }
        out.extend_from_slice(&bits.to_be_bytes()[1..4 - padding]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn place_invalidation_cannot_stamp_an_old_admission_with_new_authority() {
        use probation_policy::{Layer, LayerKind};
        let dir = tempfile::tempdir().unwrap();
        let config = ManagementConfig {
            url: "http://127.0.0.1:1".parse().unwrap(),
            token: crate::config::FirewallToken::new("test".into()),
            token_file: "/test/token".into(),
            key_cache_ttl_seconds: 300.try_into().unwrap(),
            key_cache_max_entries: 64.try_into().unwrap(),
            lookup_budget_per_second: 100.try_into().unwrap(),
            client_lookup_allowance_per_second: 100.try_into().unwrap(),
            request_timeout_seconds: 1.try_into().unwrap(),
            sync_margin_seconds: 1.try_into().unwrap(),
            trusted_proxies: vec![],
        };
        let managed = Arc::new(Managed::new(&config, Duration::from_secs(60), Arc::new(crate::clock::SystemClock), dir.path()));
        let platform = PlaceRef { kind: LayerKind::Platform, id: 1 };
        let place = PlaceRef { kind: LayerKind::Org, id: 10 };
        let principal = Principal {
            authority: None, place, key_id: KeyId(1),
            policy: Arc::new(CompiledPolicy::managed(probation_policy::resolve(&[Layer::empty(LayerKind::Platform), Layer::empty(LayerKind::Org)]))),
            account: place, rate_limit: None, rate_limit_source: LimitSource::Default,
            org: Some(OrgId(10)), chain: Arc::from([platform, place]), registry_origin: None,
            registry_read_authorization: None, registry_trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![],
        };
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer prb_01234567890123456789012345678901"));
        let hash = key_hash(headers.get(AUTHORIZATION).unwrap()).unwrap();
        assert!(managed.cache.insert(hash, principal));
        let (reached, wait) = tokio::sync::oneshot::channel();
        let (resume, paused) = std::sync::mpsc::channel();
        *lock(&managed.admission_checkpoint) = Some(Box::new(move || {
            reached.send(()).unwrap();
            paused.recv().unwrap();
        }));
        let request_managed = Arc::clone(&managed);
        let request = tokio::spawn(async move { request_managed.authenticate(&headers, "127.0.0.1".parse().unwrap()).await });
        wait.await.unwrap();
        managed.publication_gate.publish(|| managed.cache.expire_places(&[place], 2)).unwrap();
        resume.send(()).unwrap();
        if let Ok(principal) = request.await.unwrap() {
            assert_ne!(principal.authority.unwrap().generation, managed.publication_gate.generation(),
                "a place-invalidated old principal must not acquire the new publication generation");
        }
    }

    /// A fake management server for certificate admission: `publish_on` lists the
    /// 1-based hits that publish a policy generation before answering, `grant`
    /// chooses a Granted answer over `429`.
    async fn certificate_fixture(
        publish_on: &'static [usize],
        grant: bool,
        rate_limit: Option<u32>,
    ) -> (Arc<Managed>, Arc<std::sync::atomic::AtomicUsize>, wiremock::MockServer, tempfile::TempDir) {
        use probation_policy::api::{MemberCertificateId, PlaceLayer};
        use probation_policy::{Layer, LayerKind};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let config = ManagementConfig {
            url: server.uri().parse().unwrap(),
            token: crate::config::FirewallToken::new("test".into()),
            token_file: "/test/token".into(),
            key_cache_ttl_seconds: 300.try_into().unwrap(),
            key_cache_max_entries: 64.try_into().unwrap(),
            lookup_budget_per_second: 100.try_into().unwrap(),
            client_lookup_allowance_per_second: 100.try_into().unwrap(),
            request_timeout_seconds: 5.try_into().unwrap(),
            sync_margin_seconds: 1.try_into().unwrap(),
            trusted_proxies: vec![],
        };
        let managed = Arc::new(Managed::new(&config, Duration::from_secs(60), Arc::new(crate::clock::SystemClock), dir.path()));
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let platform = PlaceRef { kind: LayerKind::Platform, id: 1 };
        let place = PlaceRef { kind: LayerKind::Org, id: 10 };
        let granted = serde_json::to_value(CertificateAdmission::Granted {
            registry: RegistryId(4),
            target_url: None,
            read_authorization: None,
            trusted: false,
            registry_private_cidrs: vec![],
            deletion_scopes: vec![],
            enterprise_status: None,
            org: OrgId(10),
            member: MemberCertificateId("member".into()),
            place,
            layers: vec![
                PlaceLayer { place: platform, layer: Layer::empty(LayerKind::Platform), revision: 1 },
                PlaceLayer { place, layer: Layer::empty(LayerKind::Org), revision: 1 },
            ],
            rate_limit: rate_limit.map(|limit| limit.try_into().unwrap()),
            rate_limit_source: LimitSource::Default,
        })
        .unwrap();
        let gate = Arc::clone(&managed.publication_gate);
        let seen = Arc::clone(&hits);
        Mock::given(method("POST"))
            .and(path("/api/v1/sync/certificate"))
            .respond_with(move |_: &wiremock::Request| {
                let hit = seen.fetch_add(1, Ordering::SeqCst) + 1;
                if publish_on.contains(&hit) {
                    gate.publish(|| ()).unwrap();
                }
                if grant {
                    ResponseTemplate::new(200).set_body_json(granted.clone())
                } else {
                    ResponseTemplate::new(429)
                }
            })
            .mount(&server)
            .await;
        (managed, hits, server, dir)
    }

    async fn admit_one(managed: &Managed) -> Result<Principal, Refusal> {
        let peer = VerifiedPeer { chain: Arc::from(vec![vec![1u8]]) };
        managed
            .admit_certificate(&peer, RegistryId(4), Ecosystem::Npm, "127.0.0.1".parse().unwrap(), &HeaderMap::new(), true)
            .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_publication_during_admission_is_asked_again_and_charged_once() {
        let (managed, hits, _server, _dir) = certificate_fixture(&[1], true, Some(1)).await;
        let principal = admit_one(&managed).await.expect("the second answer is current");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "one voided answer, one current answer");
        assert_eq!(
            principal.authority.unwrap().generation,
            managed.publication_gate.generation(),
            "the admitted principal carries the generation it was checked against"
        );
        // One request consumed the account's single token exactly once.
        assert!(matches!(admit_one(&managed).await, Err(Refusal::RateLimited)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_busy_management_server_is_not_asked_again_without_a_publication() {
        let (managed, hits, _server, _dir) = certificate_fixture(&[], false, None).await;
        assert!(matches!(admit_one(&managed).await, Err(Refusal::Busy)));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_busy_management_server_is_not_asked_again_even_when_a_publication_lands() {
        let (managed, hits, _server, _dir) = certificate_fixture(&[1, 2, 3, 4], false, None).await;
        assert!(matches!(admit_one(&managed).await, Err(Refusal::Busy)));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a failed call is not a superseded answer");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_publications_stop_the_retry_at_three_asks() {
        let (managed, hits, _server, _dir) = certificate_fixture(&[1, 2, 3, 4], true, None).await;
        assert!(matches!(admit_one(&managed).await, Err(Refusal::Busy)));
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_third_ask_may_succeed() {
        let (managed, hits, _server, _dir) = certificate_fixture(&[1, 2], true, None).await;
        assert!(admit_one(&managed).await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn base64_decodes_what_rfc_4648_encodes() {
        assert_eq!(base64_decode("Zm9vYmFy").as_deref(), Some(&b"foobar"[..]));
        assert_eq!(base64_decode("Zm9vYg==").as_deref(), Some(&b"foob"[..]));
        assert_eq!(base64_decode("Zm9vYmE=").as_deref(), Some(&b"fooba"[..]));
        for bad in ["", "Zm9", "Zm=v", "Zg==Zm9v", "Zm9v!A==", "Z==="] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn only_a_key_shaped_credential_is_hashed() {
        let header = |text: &str| HeaderValue::from_str(text).unwrap();
        assert_eq!(
            bearer_or_basic_password(&header("bearer prb_abc")).as_deref(),
            Some("prb_abc")
        );
        for refused in [
            "Bearer prb_",
            "Bearer prb_a b",
            "Bearer abc",
            "Digest prb_abc",
        ] {
            assert_eq!(
                bearer_or_basic_password(&header(refused)),
                None,
                "{refused}"
            );
        }
        // "user" with no colon.
        assert_eq!(bearer_or_basic_password(&header("Basic dXNlcg==")), None);
    }
}
