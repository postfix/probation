//! What a managed firewall remembers between requests: the key cache, the lookup
//! budget, and the layers and compiled policies the keys share (C111), with the
//! revisions that invalidated them, so an answer read before an invalidation is never
//! cached (H6), and the snapshot that carries them across a restart (C115).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use probation_policy::api::{
    AccountKind, ChainLink, KeyHash, KeyId, KeyLookup, LayersResponse, LimitChange, LimitSource,
    LockRange, OrgId,
};
use probation_policy::{Layer, LayerKind, PlaceRef, PolicyFingerprint, is_chain, resolve};
use serde::{Deserialize, Serialize};

use super::Principal;
use crate::clock::Clock;
use crate::policy::CompiledPolicy;

const SHARDS: usize = 16;

/// How long an `Unknown` answer is believed (T10).
pub(super) const UNKNOWN_FOR: Duration = Duration::from_secs(30);

enum Entry {
    Live {
        principal: Principal,
        expires_at: Instant,
        last_used: Instant,
        /// Expired by a `place` row rather than by its TTL: re-looked-up on next use,
        /// and served stale only while the server cannot be reached.
        invalidated: bool,
    },
    /// Unknown, revoked or suspended: refused without asking until `expires_at`.
    Refused {
        expires_at: Instant,
        known: Option<KnownRefusal>,
    },
}

/// A revoked or suspended key's answer: who to record each refusal for, and the chain
/// a `place` row clears it by.
#[derive(Clone, Debug)]
pub(super) struct KnownRefusal {
    pub key_id: KeyId,
    pub place: PlaceRef,
    pub account: PlaceRef,
    pub chain: Arc<[PlaceRef]>,
    pub suspended: bool,
}

/// What the cache holds for a hash that has no fresh entry.
#[derive(Clone, Debug)]
pub(super) enum Standing {
    /// A refusal that has not expired; `Some` for a revoked or suspended key.
    Refused(Option<KnownRefusal>),
    /// A key whose entry outlived its TTL, or that a `place` row expired; it is looked
    /// up again.
    Expired {
        invalidated: bool,
    },
    Missing,
}

/// The revision each key, place and `limits` scope was last invalidated at, and the
/// reset floor. A lookup answer read before any of them is dropped (H6).
#[derive(Default)]
struct Invalidations {
    floor: u64,
    keys: HashMap<KeyId, Seen>,
    places: HashMap<PlaceRef, Seen>,
    limits: HashMap<(AccountKind, Option<u32>), Seen>,
}

#[derive(Clone, Copy)]
struct Seen {
    revision: u64,
    at: Instant,
}

fn note<K: std::hash::Hash + Eq>(records: &mut HashMap<K, Seen>, key: K, revision: u64) {
    let seen = records.entry(key).or_insert(Seen {
        revision,
        at: Instant::now(),
    });
    seen.revision = seen.revision.max(revision);
    seen.at = Instant::now();
}

fn after<K: std::hash::Hash + Eq>(records: &HashMap<K, Seen>, key: &K, revision: u64) -> bool {
    records
        .get(key)
        .is_some_and(|seen| seen.revision > revision)
}

/// The `limits` scope an account's rate comes from: its own override, or its kind's
/// default.
fn account_kind(account: PlaceRef) -> Option<AccountKind> {
    match account.kind {
        LayerKind::Org => Some(AccountKind::Org),
        LayerKind::Personal => Some(AccountKind::Personal),
        _ => None,
    }
}

/// Key hash -> entry, in 16 shards each holding at most its share of
/// `key_cache_max_entries`. A full shard evicts its least recently used entry, except
/// while the server is marked down: then nothing is evicted (C96).
pub(super) struct KeyCache {
    shards: Vec<Mutex<HashMap<KeyHash, Entry>>>,
    shard_capacity: usize,
    ttl: Duration,
    clock: Arc<dyn Clock>,
    invalidations: Mutex<Invalidations>,
    /// Set by a failed call to the server, cleared by the next answered sync.
    down: AtomicBool,
}

impl KeyCache {
    pub(super) fn new(max_entries: usize, ttl: Duration, clock: Arc<dyn Clock>) -> KeyCache {
        KeyCache {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            shard_capacity: max_entries.div_ceil(SHARDS),
            ttl,
            clock,
            invalidations: Mutex::new(Invalidations::default()),
            down: AtomicBool::new(false),
        }
    }

    fn shard(&self, hash: &KeyHash) -> MutexGuard<'_, HashMap<KeyHash, Entry>> {
        // The hash is SHA-256 output, so its first byte is already uniform.
        lock(&self.shards[usize::from(hash.0[0]) % SHARDS])
    }

    fn invalidations(&self) -> MutexGuard<'_, Invalidations> {
        lock(&self.invalidations)
    }

    /// The server answered a sync: expired entries are looked up again.
    pub(super) fn note_server_seen(&self) {
        self.down.store(false, Ordering::Release);
    }

    /// A call to the server failed: until the next answered sync, expired entries are
    /// served stale without asking (C96).
    pub(super) fn note_server_down(&self) {
        self.down.store(true, Ordering::Release);
    }

    pub(super) fn server_down(&self) -> bool {
        self.down.load(Ordering::Acquire)
    }

    /// The principal of a live, unexpired entry, marked as used now.
    pub(super) fn fresh(&self, hash: &KeyHash) -> Option<Principal> {
        let now = self.clock.now_monotonic();
        match self.shard(hash).get_mut(hash) {
            Some(Entry::Live {
                principal,
                expires_at,
                last_used,
                ..
            }) if now < *expires_at => {
                *last_used = now;
                Some(principal.clone())
            }
            _ => None,
        }
    }

    /// The principal of an expired entry, served while it cannot be looked up again.
    pub(super) fn stale(&self, hash: &KeyHash) -> Option<Principal> {
        let now = self.clock.now_monotonic();
        match self.shard(hash).get_mut(hash) {
            Some(Entry::Live {
                principal,
                last_used,
                ..
            }) => {
                *last_used = now;
                Some(principal.clone())
            }
            _ => None,
        }
    }

    pub(super) fn standing(&self, hash: &KeyHash) -> Standing {
        let now = self.clock.now_monotonic();
        match self.shard(hash).get(hash) {
            Some(Entry::Refused { expires_at, known }) if now < *expires_at => {
                Standing::Refused(known.clone())
            }
            Some(Entry::Live { invalidated, .. }) => Standing::Expired {
                invalidated: *invalidated,
            },
            _ => Standing::Missing,
        }
    }

    /// Caches `principal`. False when the shard is full while the server is marked
    /// down: nothing is evicted then, so the key is told to retry.
    pub(super) fn insert(&self, hash: KeyHash, principal: Principal) -> bool {
        let now = self.clock.now_monotonic();
        self.put(
            hash,
            Entry::Live {
                principal,
                expires_at: now + self.ttl,
                last_used: now,
                invalidated: false,
            },
        )
    }

    /// Refuses `hash` without asking for `unknown_for`, or for one TTL when `None`
    /// (revoked and suspended keys).
    pub(super) fn refuse(
        &self,
        hash: KeyHash,
        unknown_for: Option<Duration>,
        known: Option<KnownRefusal>,
    ) {
        let expires_at = self.clock.now_monotonic() + unknown_for.unwrap_or(self.ttl);
        self.put(hash, Entry::Refused { expires_at, known });
    }

    fn put(&self, hash: KeyHash, entry: Entry) -> bool {
        let mut shard = self.shard(&hash);
        if shard.len() >= self.shard_capacity && !shard.contains_key(&hash) {
            if self.server_down() {
                return false;
            }
            // ponytail: a scan of one full shard per insert; keep an LRU order per shard
            // if a cache this full shows up in profiles.
            let victim = shard
                .iter()
                .min_by_key(|(_, entry)| match entry {
                    // Refusals go first: they cost a client nothing to lose.
                    Entry::Refused { .. } => None,
                    Entry::Live { last_used, .. } => Some(*last_used),
                })
                .map(|(victim, _)| *victim);
            if let Some(victim) = victim {
                shard.remove(&victim);
            }
        }
        shard.insert(hash, entry);
        true
    }

    fn each(&self, mut visit: impl FnMut(&mut HashMap<KeyHash, Entry>)) {
        for shard in &self.shards {
            visit(&mut lock(shard));
        }
    }

    /// Every entry gone: a reset, or a retired firewall.
    pub(super) fn clear(&self) {
        self.each(HashMap::clear);
    }

    /// A reset: every lookup answer read below `revision` is dropped.
    pub(super) fn raise_invalidation_floor(&self, revision: u64) {
        let mut invalidations = self.invalidations();
        invalidations.floor = invalidations.floor.max(revision);
    }

    pub(super) fn floor(&self) -> u64 {
        self.invalidations().floor
    }

    /// `key` rows: exactly these keys' entries go, so a revoked key is never served
    /// stale once this firewall has heard of it.
    pub(super) fn remove_keys(&self, keys: &[KeyId], revision: u64) {
        if keys.is_empty() {
            return;
        }
        // Held until the entries are gone, so an insert checked against these records
        // either sees them or lands before them (H6).
        let mut invalidations = self.invalidations();
        for key in keys {
            note(&mut invalidations.keys, *key, revision);
        }
        self.each(|shard| {
            shard.retain(|_, entry| {
                let id = match entry {
                    Entry::Live { principal, .. } => Some(principal.key_id),
                    Entry::Refused { known, .. } => known.as_ref().map(|known| known.key_id),
                };
                !id.is_some_and(|id| keys.contains(&id))
            });
        });
    }

    /// `place` rows: every entry whose chain holds one of these places is looked up on
    /// next use; a refusal naming one is forgotten, so a restored organisation's keys
    /// are asked about again.
    pub(super) fn expire_places(&self, places: &[PlaceRef], revision: u64) {
        if places.is_empty() {
            return;
        }
        let mut invalidations = self.invalidations();
        for place in places {
            note(&mut invalidations.places, *place, revision);
        }
        let now = self.clock.now_monotonic();
        let named = |chain: &[PlaceRef]| chain.iter().any(|place| places.contains(place));
        self.each(|shard| {
            shard.retain(|_, entry| match entry {
                Entry::Live {
                    principal,
                    expires_at,
                    invalidated,
                    ..
                } => {
                    if named(&principal.chain) {
                        *expires_at = now;
                        *invalidated = true;
                    }
                    true
                }
                Entry::Refused { known, .. } => {
                    !known.as_ref().is_some_and(|known| named(&known.chain))
                }
            });
        });
    }

    /// `limits` rows, applied in place with no lookup: a default touches only entries
    /// whose rate came from their kind's default; an override touches its account and
    /// sets where the rate came from.
    pub(super) fn update_limits(&self, changes: &[LimitChange], revision: u64) {
        if changes.is_empty() {
            return;
        }
        let mut invalidations = self.invalidations();
        for change in changes {
            note(
                &mut invalidations.limits,
                (change.scope_kind, change.scope_id),
                revision,
            );
        }
        self.each(|shard| {
            for entry in shard.values_mut() {
                let Entry::Live { principal, .. } = entry else {
                    continue;
                };
                for change in changes {
                    if account_kind(principal.account) != Some(change.scope_kind) {
                        continue;
                    }
                    match change.scope_id {
                        None if principal.rate_limit_source == LimitSource::Default => {
                            principal.rate_limit = change.rate_per_min;
                        }
                        Some(id) if id == principal.account.id => {
                            principal.rate_limit = change.rate_per_min;
                            principal.rate_limit_source = change.source;
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    /// Whether a lookup answer was read after every invalidation that touches it.
    pub(super) fn is_current(&self, answer: &KeyLookup) -> bool {
        current(&self.invalidations(), answer)
    }

    /// Caches `principal`, unless `answer`, the lookup it came from, is no longer
    /// current: checked and inserted under the invalidations lock, so an invalidation
    /// applied while its layers were fetched is never undone (H6).
    pub(super) fn insert_current(
        &self,
        hash: KeyHash,
        principal: Principal,
        answer: &KeyLookup,
    ) -> Insert {
        let invalidations = self.invalidations();
        if !current(&invalidations, answer) {
            return Insert::Late;
        }
        if self.insert(hash, principal) {
            Insert::Done
        } else {
            Insert::Full
        }
    }

    /// [`KeyCache::refuse`], under the same rule as [`KeyCache::insert_current`].
    pub(super) fn refuse_current(
        &self,
        hash: KeyHash,
        unknown_for: Option<Duration>,
        known: Option<KnownRefusal>,
        answer: &KeyLookup,
    ) -> bool {
        let invalidations = self.invalidations();
        if !current(&invalidations, answer) {
            return false;
        }
        self.refuse(hash, unknown_for, known);
        true
    }

    /// Drops `hash`'s entry if it is still `key`'s live one.
    pub(super) fn remove_live(&self, hash: &KeyHash, key: KeyId) {
        let mut shard = self.shard(hash);
        if matches!(shard.get(hash), Some(Entry::Live { principal, .. }) if principal.key_id == key)
        {
            shard.remove(hash);
        }
    }

    /// After an answered sync only: entries unused for one TTL and refusals past their
    /// time go, so an outage never shrinks the cache (C96, W3). Returns every place a
    /// remaining entry's chain names.
    pub(super) fn prune_idle(&self) -> HashSet<PlaceRef> {
        let now = self.clock.now_monotonic();
        let mut used = HashSet::new();
        self.each(|shard| {
            shard.retain(|_, entry| match entry {
                Entry::Live {
                    principal,
                    last_used,
                    ..
                } => {
                    let keep = now < *last_used + self.ttl;
                    if keep {
                        used.extend(principal.chain.iter().copied());
                    }
                    keep
                }
                Entry::Refused { expires_at, .. } => now < *expires_at,
            });
        });
        // An answer can only be late by the length of one call; a record older than a
        // TTL guards nothing.
        let mut invalidations = self.invalidations();
        let ttl = self.ttl;
        let young = |seen: &mut Seen| seen.at.elapsed() < ttl;
        invalidations.keys.retain(|_, seen| young(seen));
        invalidations.places.retain(|_, seen| young(seen));
        invalidations.limits.retain(|_, seen| young(seen));
        used
    }

    /// Recompiles the policy of every entry whose chain holds one of `places`, after
    /// their layers were refetched.
    pub(super) fn rebuild(
        &self,
        places: &[PlaceRef],
        compile: impl Fn(&[PlaceRef]) -> Option<Arc<CompiledPolicy>>,
    ) {
        self.each(|shard| {
            for entry in shard.values_mut() {
                if let Entry::Live { principal, .. } = entry
                    && principal.chain.iter().any(|place| places.contains(place))
                    && let Some(policy) = compile(&principal.chain)
                {
                    principal.policy = policy;
                }
            }
        });
    }

    /// The live entries, for the snapshot.
    pub(super) fn saved(&self) -> Vec<SavedKey> {
        let mut saved = Vec::new();
        self.each(|shard| {
            for (hash, entry) in shard.iter() {
                if let Entry::Live { principal, .. } = entry {
                    saved.push(SavedKey {
                        hash: *hash,
                        place: principal.place,
                        key_id: principal.key_id,
                        account: principal.account,
                        rate_limit: principal.rate_limit,
                        rate_limit_source: principal.rate_limit_source,
                        org: principal.org,
                        chain: principal.chain.to_vec(),
                    });
                }
            }
        });
        saved
    }

    /// Puts a snapshot's entry back, already expired: it is looked up on first use,
    /// and served stale while the server cannot be reached (C19).
    pub(super) fn restore(&self, hash: KeyHash, principal: Principal) {
        let now = self.clock.now_monotonic();
        self.put(
            hash,
            Entry::Live {
                principal,
                expires_at: now,
                last_used: now,
                invalidated: false,
            },
        );
    }
}

/// Whether `answer` was read after every invalidation in `invalidations` that touches
/// it: its key, a place of its chain, its account's limits, and the reset floor.
fn current(invalidations: &Invalidations, answer: &KeyLookup) -> bool {
    let (revision, key, chain, account) = match answer {
        KeyLookup::Known {
            key_id,
            place_chain,
            account,
            revision,
            ..
        } => (*revision, Some(*key_id), &place_chain[..], Some(*account)),
        KeyLookup::Revoked {
            key_id,
            place_chain,
            revision,
            ..
        }
        | KeyLookup::Suspended {
            key_id,
            place_chain,
            revision,
            ..
        } => (*revision, Some(*key_id), &place_chain[..], None),
        KeyLookup::Unknown { revision } => (*revision, None, &[][..], None),
    };
    if revision < invalidations.floor {
        return false;
    }
    let key_late = key.is_some_and(|key| after(&invalidations.keys, &key, revision));
    let place_late = chain
        .iter()
        .any(|link| after(&invalidations.places, &link.place, revision));
    let limit_late = account.is_some_and(|account| {
        account_kind(account).is_some_and(|kind| {
            after(&invalidations.limits, &(kind, None), revision)
                || after(&invalidations.limits, &(kind, Some(account.id)), revision)
        })
    });
    !(key_late || place_late || limit_late)
}

/// What [`KeyCache::insert_current`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Insert {
    Done,
    /// The answer was read before an invalidation applied since.
    Late,
    /// The cache is full while the server is down.
    Full,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Nothing panics while one of these is held, so a poisoned lock holds no torn state.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The lookups this firewall may send each second (T10, C120). Fixed one-second
/// windows on the injected clock: the firewall-wide budget, a fifth of it (at least one
/// once the budget is two) kept for keys that already have an entry so a flood of unknown keys cannot starve re-lookups, and
/// each client's allowance for keys with no entry. A client is its address, with an
/// IPv6 address counted by its /64, so one host cannot rotate around its allowance.
///
/// ponytail: fixed windows let a burst straddling a boundary reach twice the rate for
/// an instant; a sliding window if the server ever notices.
pub(super) struct Budget {
    per_second: u32,
    per_client: u32,
    clock: Arc<dyn Clock>,
    origin: Instant,
    window: Mutex<Window>,
}

#[derive(Default)]
struct Window {
    second: u64,
    used: u32,
    clients: HashMap<IpAddr, u32>,
}

/// The address a client's allowance is counted under: IPv4 (an IPv4-mapped address
/// folded to it), or the /64 an IPv6 address belongs to.
pub(super) fn allowance_key(client: IpAddr) -> IpAddr {
    match client.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        v4 => v4,
    }
}

impl Budget {
    pub(super) fn new(per_second: u32, per_client: u32, clock: Arc<dyn Clock>) -> Budget {
        Budget {
            per_second,
            per_client,
            origin: clock.now_monotonic(),
            clock,
            window: Mutex::new(Window::default()),
        }
    }

    /// Takes one lookup from this second's budget, if there is one left for this client.
    pub(super) fn take(&self, client: IpAddr, has_entry: bool) -> bool {
        let client = allowance_key(client);
        let second = self
            .clock
            .now_monotonic()
            .saturating_duration_since(self.origin)
            .as_secs();
        let mut window = lock(&self.window);
        if window.second != second {
            *window = Window {
                second,
                ..Window::default()
            };
        }
        let allowed = if has_entry {
            window.used < self.per_second
        } else {
            // A fifth of the budget, and at least one lookup once there are two.
            let reserved = (self.per_second / 5).max(u32::from(self.per_second >= 2));
            let unreserved = self.per_second - reserved;
            window.used < unreserved
                && window.clients.get(&client).copied().unwrap_or(0) < self.per_client
        };
        if allowed {
            window.used += 1;
            if !has_entry {
                *window.clients.entry(client).or_insert(0) += 1;
            }
        }
        allowed
    }
}

/// Why a chain's policy cannot be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Unresolved {
    /// A layer is missing, or older than the revision the chain names: the server's
    /// answers have not caught up with each other yet.
    Behind,
    /// A layer is not the kind of its place, or the chain is not one `resolve`
    /// accepts: an answer this firewall cannot trust.
    Inconsistent,
}

/// One place's layer and the change-log revision of the answer it came in.
struct HeldLayer {
    revision: u64,
    read_at: u64,
    layer: Layer,
}

#[derive(Default)]
struct LayerTable {
    held: HashMap<PlaceRef, HeldLayer>,
    /// The revision of each place's last `layer` row, held or not, so a `layers`
    /// answer read before it is dropped (H6). A held layer read before its row is stale:
    /// still used, and refetched.
    invalidated: HashMap<PlaceRef, Seen>,
}

impl LayerTable {
    fn is_stale(&self, place: &PlaceRef) -> bool {
        self.held
            .get(place)
            .is_some_and(|held| after(&self.invalidated, place, held.read_at))
    }
}

/// Each place's layer, held once however many keys share it, and the compiled
/// policies built from them, interned by fingerprint (C111). A policy no key holds any
/// more is dropped with its last principal.
#[derive(Default)]
pub(super) struct Policies {
    layers: Mutex<LayerTable>,
    interned: Mutex<HashMap<PolicyFingerprint, Weak<CompiledPolicy>>>,
}

impl Policies {
    /// The places of `chain` whose layer is not held at the revision it names, or is
    /// stale.
    pub(super) fn missing(&self, chain: &[ChainLink]) -> Vec<PlaceRef> {
        let layers = lock(&self.layers);
        chain
            .iter()
            .filter(|link| {
                layers.is_stale(&link.place)
                    || layers
                        .held
                        .get(&link.place)
                        .is_none_or(|held| held.revision < link.layer_revision)
            })
            .map(|link| link.place)
            .collect()
    }

    /// Keeps each place's newest layer. A whole answer read below `floor`, and a layer
    /// read before its place's last `layer` row, is dropped; returns false when one was.
    pub(super) fn store(&self, answer: LayersResponse, floor: u64) -> bool {
        if answer.revision < floor {
            return false;
        }
        let mut layers = lock(&self.layers);
        let mut current = true;
        for place in answer.layers {
            if after(&layers.invalidated, &place.place, answer.revision) {
                current = false;
                continue;
            }
            match layers.held.get_mut(&place.place) {
                Some(held) if held.revision >= place.revision => {
                    held.read_at = held.read_at.max(answer.revision);
                }
                _ => {
                    layers.held.insert(
                        place.place,
                        HeldLayer {
                            revision: place.revision,
                            read_at: answer.revision,
                            layer: place.layer,
                        },
                    );
                }
            }
        }
        current
    }

    /// `layer` rows: these layers are stale from `revision` on. Each stays in use as the
    /// last known layer until it is refetched (C19).
    pub(super) fn mark_stale(&self, places: &[PlaceRef], revision: u64) {
        let mut layers = lock(&self.layers);
        for place in places {
            note(&mut layers.invalidated, *place, revision);
        }
    }

    /// Whether a layer of `chain` is held stale: a `layer` row arrived after it was read.
    pub(super) fn any_stale(&self, chain: &[PlaceRef]) -> bool {
        let layers = lock(&self.layers);
        chain.iter().any(|place| layers.is_stale(place))
    }

    /// The held layers a `layer` row made stale.
    pub(super) fn stale(&self) -> Vec<PlaceRef> {
        let layers = lock(&self.layers);
        layers
            .held
            .keys()
            .filter(|place| layers.is_stale(place))
            .copied()
            .collect()
    }

    /// Every layer and compiled policy gone: a reset.
    pub(super) fn clear(&self) {
        let mut layers = lock(&self.layers);
        layers.held.clear();
        layers.invalidated.clear();
        lock(&self.interned).clear();
    }

    /// Drops the layers no remaining key uses, and the `layer` records older than
    /// `ttl` that no held layer is still stale by.
    pub(super) fn retain(&self, used: &HashSet<PlaceRef>, ttl: Duration) {
        let mut layers = lock(&self.layers);
        layers.held.retain(|place, _| used.contains(place));
        let LayerTable { held, invalidated } = &mut *layers;
        invalidated.retain(|place, seen| {
            seen.at.elapsed() < ttl
                || held
                    .get(place)
                    .is_some_and(|layer| seen.revision > layer.read_at)
        });
    }

    /// The policy of `chain`, interned, or why it cannot be built from what is held.
    pub(super) fn compile(&self, chain: &[ChainLink]) -> Result<Arc<CompiledPolicy>, Unresolved> {
        let layers = {
            let layers = lock(&self.layers);
            chain
                .iter()
                .map(|link| match layers.held.get(&link.place) {
                    Some(held) if held.revision < link.layer_revision => Err(Unresolved::Behind),
                    Some(held) if held.layer.kind == link.place.kind => Ok(held.layer.clone()),
                    Some(_) => Err(Unresolved::Inconsistent),
                    None => Err(Unresolved::Behind),
                })
                .collect::<Result<Vec<Layer>, Unresolved>>()?
        };
        let kinds: Vec<_> = layers.iter().map(|layer| layer.kind).collect();
        if kinds.is_empty() || !is_chain(&kinds) {
            return Err(Unresolved::Inconsistent);
        }
        let policy = resolve(&layers);

        let mut interned = lock(&self.interned);
        if let Some(compiled) = interned.get(&policy.fingerprint).and_then(Weak::upgrade) {
            return Ok(compiled);
        }
        interned.retain(|_, compiled| compiled.strong_count() > 0);
        let fingerprint = policy.fingerprint;
        let compiled = Arc::new(CompiledPolicy::managed(policy));
        interned.insert(fingerprint, Arc::downgrade(&compiled));
        Ok(compiled)
    }

    /// The policy of a cached entry's chain, from whatever layers are held.
    pub(super) fn compile_places(&self, chain: &[PlaceRef]) -> Option<Arc<CompiledPolicy>> {
        let links: Vec<ChainLink> = chain
            .iter()
            .map(|place| ChainLink {
                place: *place,
                layer_revision: 0,
            })
            .collect();
        self.compile(&links).ok()
    }

    /// The held layers, for the snapshot.
    pub(super) fn saved(&self) -> Vec<SavedLayer> {
        let layers = lock(&self.layers);
        layers
            .held
            .iter()
            .map(|(place, held)| SavedLayer {
                place: *place,
                revision: held.revision,
                read_at: held.read_at,
                stale: layers.is_stale(place),
                layer: held.layer.clone(),
            })
            .collect()
    }

    pub(super) fn restore(&self, saved: Vec<SavedLayer>) {
        let mut layers = lock(&self.layers);
        for layer in saved {
            if layer.stale {
                note(&mut layers.invalidated, layer.place, layer.read_at + 1);
            }
            layers.held.insert(
                layer.place,
                HeldLayer {
                    revision: layer.revision,
                    read_at: layer.read_at,
                    layer: layer.layer,
                },
            );
        }
    }
}

/// `<data_dir>/managed-cache.json`: what a restart while the server is down serves
/// from (C19, C115). Key hashes only, never a key.
#[derive(Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub cursor: u64,
    pub keys: Vec<SavedKey>,
    pub layers: Vec<SavedLayer>,
    pub network_lock: Vec<LockRange>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SavedKey {
    pub hash: KeyHash,
    pub place: PlaceRef,
    pub key_id: KeyId,
    pub account: PlaceRef,
    pub rate_limit: Option<NonZeroU32>,
    pub rate_limit_source: LimitSource,
    pub org: Option<OrgId>,
    pub chain: Vec<PlaceRef>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SavedLayer {
    pub place: PlaceRef,
    pub revision: u64,
    pub read_at: u64,
    pub stale: bool,
    pub layer: Layer,
}

const SNAPSHOT: &str = "managed-cache.json";
const PREVIOUS_SNAPSHOT: &str = "managed-cache.prev.json";

/// Writes the snapshot atomically, keeping the one it replaces as the previous.
pub(super) fn write_snapshot(data_dir: &Path, snapshot: &Snapshot) -> io::Result<()> {
    let bytes = serde_json::to_vec(snapshot).map_err(io::Error::other)?;
    crate::config::write_atomically(
        &data_dir.join(SNAPSHOT),
        &bytes,
        Some(&data_dir.join(PREVIOUS_SNAPSHOT)),
    )
}

/// The last snapshot, or the one before it when the last cannot be read.
pub(super) fn read_snapshot(data_dir: &Path) -> Option<Snapshot> {
    let read = |path: PathBuf| -> Option<Snapshot> {
        let bytes = std::fs::read(&path).ok()?;
        match serde_json::from_slice(&bytes) {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "the cache snapshot cannot be read");
                None
            }
        }
    };
    read(data_dir.join(SNAPSHOT)).or_else(|| read(data_dir.join(PREVIOUS_SNAPSHOT)))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use probation_policy::Switches;
    use probation_policy::api::PlaceLayer;

    use super::*;

    struct ManualClock {
        base: Instant,
        micros: AtomicU64,
    }

    impl Clock for ManualClock {
        fn now_utc_micros(&self) -> i64 {
            0
        }
        fn now_monotonic(&self) -> Instant {
            self.base + Duration::from_micros(self.micros.load(Ordering::SeqCst))
        }
    }

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock {
            base: Instant::now(),
            micros: AtomicU64::new(0),
        })
    }

    const PLATFORM: PlaceRef = PlaceRef {
        kind: LayerKind::Platform,
        id: 1,
    };

    fn answer(layers: Vec<PlaceLayer>) -> LayersResponse {
        LayersResponse {
            layers,
            revision: 1,
        }
    }

    fn link(place: PlaceRef) -> ChainLink {
        ChainLink {
            place,
            layer_revision: 1,
        }
    }

    fn principal(policies: &Policies) -> Principal {
        policies.store(
            answer(vec![PlaceLayer {
                place: PLATFORM,
                layer: Layer::empty(LayerKind::Platform),
                revision: 1,
            }]),
            0,
        );
        Principal {
            place: PLATFORM,
            key_id: KeyId(1),
            policy: policies.compile(&[link(PLATFORM)]).expect("a policy"),
            account: PLATFORM,
            rate_limit: None,
            rate_limit_source: LimitSource::Default,
            org: None,
            chain: Arc::from([PLATFORM]),
        }
    }

    /// Four hashes that land in one shard.
    fn same_shard() -> Vec<KeyHash> {
        (0u8..4).map(|n| KeyHash([n * 16; 32])).collect()
    }

    /// A full shard makes room by dropping its least recently used entry: here the one
    /// inserted second, because the first was used since.
    #[test]
    fn a_full_shard_evicts_the_least_recently_used_entry() {
        let clock = clock();
        // Two entries a shard.
        let cache = KeyCache::new(2 * SHARDS, Duration::from_secs(300), clock.clone());
        let policies = Policies::default();
        let hashes = same_shard();
        cache.insert(hashes[0], principal(&policies));
        clock.micros.store(1, Ordering::SeqCst);
        cache.insert(hashes[1], principal(&policies));
        clock.micros.store(2, Ordering::SeqCst);
        assert!(cache.fresh(&hashes[0]).is_some(), "the first is used again");
        clock.micros.store(3, Ordering::SeqCst);
        cache.insert(hashes[2], principal(&policies));
        assert!(
            matches!(cache.standing(&hashes[1]), Standing::Missing),
            "the LRU entry"
        );
        assert!(cache.fresh(&hashes[0]).is_some());
        assert!(cache.fresh(&hashes[2]).is_some());
    }

    /// A refusal is evicted before any live entry, however recently it was made.
    #[test]
    fn a_full_shard_evicts_refusals_first() {
        let clock = clock();
        let cache = KeyCache::new(2 * SHARDS, Duration::from_secs(300), clock.clone());
        let policies = Policies::default();
        let hashes = same_shard();
        cache.insert(hashes[0], principal(&policies));
        clock.micros.store(1, Ordering::SeqCst);
        cache.refuse(hashes[1], Some(UNKNOWN_FOR), None);
        clock.micros.store(2, Ordering::SeqCst);
        cache.insert(hashes[2], principal(&policies));
        assert!(
            matches!(cache.standing(&hashes[1]), Standing::Missing),
            "the refusal"
        );
        assert!(
            cache.fresh(&hashes[0]).is_some(),
            "the older live entry stays"
        );
        assert!(cache.fresh(&hashes[2]).is_some());
    }

    /// A layer answer older than the one held never replaces it, and a chain naming a
    /// newer revision than the one held does not compile from the older one.
    #[test]
    fn an_older_layer_never_replaces_a_newer_one() {
        let policies = Policies::default();
        let at = |revision, freeze| PlaceLayer {
            place: PLATFORM,
            layer: Layer {
                freeze_seconds: Some(freeze),
                ..Layer::empty(LayerKind::Platform)
            },
            revision,
        };
        let names = |layer_revision| ChainLink {
            place: PLATFORM,
            layer_revision,
        };
        policies.store(answer(vec![at(1, 60)]), 0);
        assert_eq!(
            policies.compile(&[names(2)]).err(),
            Some(Unresolved::Behind),
            "rev 1 is not rev 2"
        );
        assert_eq!(policies.missing(&[names(2)]), vec![PLATFORM]);
        policies.store(answer(vec![at(2, 3_600)]), 0);
        policies.store(answer(vec![at(1, 60)]), 0);
        let compiled = policies.compile(&[names(2)]).expect("rev 2 is held");
        assert_eq!(compiled.policy.chain[0].freeze_seconds, Some(3_600));
        assert!(policies.missing(&[names(2)]).is_empty());
    }

    /// The reserve kept for keys with an entry is a fifth of the budget, and at least
    /// one lookup once the budget is two or more.
    #[test]
    fn the_budget_keeps_a_reserve_for_known_keys() {
        let client: IpAddr = [127, 0, 0, 1].into();
        for (budget, unknown) in [(1, 1), (2, 1), (4, 3), (50, 40)] {
            let take = Budget::new(budget, u32::MAX, clock());
            let taken = (0..budget).filter(|_| take.take(client, false)).count();
            assert_eq!(
                taken, unknown as usize,
                "unknown keys under a budget of {budget}"
            );
            let reserved = (0..budget).filter(|_| take.take(client, true)).count();
            assert_eq!(reserved as u32, budget - unknown, "the reserve of {budget}");
        }
    }

    /// An entry past its TTL is not served, and is looked up as one that has an entry.
    #[test]
    fn an_expired_entry_is_not_fresh() {
        let clock = clock();
        let cache = KeyCache::new(100, Duration::from_secs(300), clock.clone());
        let hash = KeyHash([7; 32]);
        cache.insert(hash, principal(&Policies::default()));
        clock.micros.store(300_000_000, Ordering::SeqCst);
        assert!(cache.fresh(&hash).is_none());
        assert!(matches!(
            cache.standing(&hash),
            Standing::Expired { invalidated: false }
        ));
    }

    /// A chain whose layers disagree with its places, or that is not a C9 chain, is not
    /// compiled; one compiled twice is the same policy.
    #[test]
    fn only_a_consistent_chain_compiles() {
        let policies = Policies::default();
        let org = PlaceRef {
            kind: LayerKind::Org,
            id: 2,
        };
        policies.store(
            answer(vec![
                PlaceLayer {
                    place: PLATFORM,
                    layer: Layer {
                        allow: Switches::ALL,
                        ..Layer::empty(LayerKind::Platform)
                    },
                    revision: 1,
                },
                PlaceLayer {
                    place: org,
                    layer: Layer::empty(LayerKind::Group),
                    revision: 1,
                },
            ]),
            0,
        );
        let inconsistent = Some(Unresolved::Inconsistent);
        assert_eq!(
            policies.compile(&[link(PLATFORM), link(org)]).err(),
            inconsistent
        );
        assert_eq!(policies.compile(&[link(org)]).err(), inconsistent);
        assert_eq!(policies.compile(&[]).err(), inconsistent);
        let first = policies.compile(&[link(PLATFORM)]).expect("a policy");
        let second = policies.compile(&[link(PLATFORM)]).expect("a policy");
        assert!(Arc::ptr_eq(&first, &second), "interned by fingerprint");
        assert_eq!(policies.missing(&[link(PLATFORM), link(org)]), Vec::new());
        let newer = ChainLink {
            place: org,
            layer_revision: 2,
        };
        assert_eq!(policies.missing(&[newer]), vec![org]);
    }

    fn known(key: u64, account: PlaceRef, revision: u64) -> KeyLookup {
        KeyLookup::Known {
            key_id: KeyId(key),
            org: None,
            account,
            place_chain: vec![link(PLATFORM), link(account)],
            rate_limit: None,
            rate_limit_source: LimitSource::Default,
            revision,
        }
    }

    /// H6: an answer read before an invalidation of its key, a chain place, its
    /// account's limits, or below the reset floor is not current; one read after is.
    #[test]
    fn a_late_lookup_answer_is_not_current() {
        let cache = KeyCache::new(100, Duration::from_secs(300), clock());
        let acme = PlaceRef {
            kind: LayerKind::Org,
            id: 10,
        };
        assert!(cache.is_current(&known(1, acme, 1)));
        cache.remove_keys(&[KeyId(1)], 5);
        assert!(!cache.is_current(&known(1, acme, 4)), "the key");
        assert!(cache.is_current(&known(1, acme, 5)));
        cache.expire_places(&[acme], 7);
        assert!(!cache.is_current(&known(2, acme, 6)), "a chain place");
        let change = |scope_id| LimitChange {
            scope_kind: AccountKind::Org,
            scope_id,
            rate_per_min: None,
            source: LimitSource::Default,
        };
        cache.update_limits(&[change(None)], 9);
        assert!(!cache.is_current(&known(3, acme, 8)), "the default limit");
        cache.update_limits(&[change(Some(10))], 11);
        assert!(!cache.is_current(&known(3, acme, 10)), "its own limit");
        assert!(cache.is_current(&known(3, acme, 11)));
        cache.raise_invalidation_floor(20);
        assert!(
            !cache.is_current(&KeyLookup::Unknown { revision: 19 }),
            "the floor"
        );
        assert!(cache.is_current(&KeyLookup::Unknown { revision: 20 }));
    }

    /// A layer read before its place's `layer` row is dropped, held or not, and a held
    /// one is stale until refetched; an answer below the floor is dropped whole.
    #[test]
    fn a_late_layer_answer_is_dropped() {
        let policies = Policies::default();
        let platform = |revision, freeze| PlaceLayer {
            place: PLATFORM,
            layer: Layer {
                freeze_seconds: Some(freeze),
                ..Layer::empty(LayerKind::Platform)
            },
            revision,
        };
        let at = |layers, revision| LayersResponse { layers, revision };
        assert!(policies.store(at(vec![platform(1, 60)], 1), 0));
        policies.mark_stale(&[PLATFORM], 3);
        assert_eq!(policies.stale(), vec![PLATFORM]);
        assert_eq!(policies.missing(&[link(PLATFORM)]), vec![PLATFORM]);
        assert!(
            !policies.store(at(vec![platform(2, 120)], 2), 0),
            "read before the row"
        );
        assert_eq!(policies.stale(), vec![PLATFORM], "still stale");
        assert!(
            !policies.store(at(vec![platform(3, 180)], 5), 6),
            "below the floor"
        );
        assert!(policies.store(at(vec![platform(3, 180)], 3), 0));
        assert!(policies.stale().is_empty());
        let compiled = policies.compile_places(&[PLATFORM]).expect("a policy");
        assert_eq!(compiled.policy.chain[0].freeze_seconds, Some(180));
    }

    /// A `limits` default spares overrides; an override row sets its source; a `place`
    /// row expires a live entry as invalidated and forgets a refusal naming it; idle
    /// entries are pruned and the places still used are reported.
    #[test]
    fn invalidations_touch_exactly_their_entries() {
        let clock = clock();
        let cache = KeyCache::new(100, Duration::from_secs(10), clock.clone());
        let policies = Policies::default();
        let org = PlaceRef {
            kind: LayerKind::Org,
            id: 10,
        };
        let mut overridden = principal(&policies);
        overridden.account = org;
        overridden.key_id = KeyId(2);
        overridden.rate_limit_source = LimitSource::Override;
        overridden.chain = Arc::from([PLATFORM, org]);
        let mut defaulted = overridden.clone();
        defaulted.key_id = KeyId(3);
        defaulted.rate_limit_source = LimitSource::Default;
        let [a, b, c, d] = [
            KeyHash([1; 32]),
            KeyHash([2; 32]),
            KeyHash([3; 32]),
            KeyHash([4; 32]),
        ];
        cache.insert(a, overridden);
        cache.insert(b, defaulted);
        cache.refuse(
            c,
            None,
            Some(KnownRefusal {
                key_id: KeyId(4),
                place: org,
                account: org,
                chain: Arc::from([PLATFORM, org]),
                suspended: true,
            }),
        );
        cache.update_limits(
            &[LimitChange {
                scope_kind: AccountKind::Org,
                scope_id: None,
                rate_per_min: NonZeroU32::new(7),
                source: LimitSource::Default,
            }],
            1,
        );
        assert_eq!(
            cache.fresh(&a).unwrap().rate_limit,
            None,
            "the override is spared"
        );
        assert_eq!(cache.fresh(&b).unwrap().rate_limit, NonZeroU32::new(7));
        cache.update_limits(
            &[LimitChange {
                scope_kind: AccountKind::Org,
                scope_id: Some(10),
                rate_per_min: NonZeroU32::new(9),
                source: LimitSource::Default,
            }],
            2,
        );
        let a_now = cache.fresh(&a).unwrap();
        assert_eq!(
            (a_now.rate_limit, a_now.rate_limit_source),
            (NonZeroU32::new(9), LimitSource::Default)
        );
        cache.expire_places(&[org], 3);
        assert!(cache.fresh(&a).is_none());
        assert!(matches!(
            cache.standing(&a),
            Standing::Expired { invalidated: true }
        ));
        assert!(cache.stale(&a).is_some(), "still there to serve stale");
        assert!(
            matches!(cache.standing(&c), Standing::Missing),
            "the refusal forgotten"
        );
        cache.refuse(d, Some(UNKNOWN_FOR), None);
        cache.remove_keys(&[KeyId(3)], 4);
        assert!(matches!(cache.standing(&b), Standing::Missing));
        clock.micros.store(11_000_000, Ordering::SeqCst);
        assert!(cache.stale(&a).is_some());
        let used = cache.prune_idle();
        assert!(used.contains(&org), "a was used just now");
        clock.micros.store(40_000_000, Ordering::SeqCst);
        assert!(
            cache.prune_idle().is_empty(),
            "idle for a TTL, and the refusal is over"
        );
        assert!(matches!(cache.standing(&d), Standing::Missing));
    }

    /// A full cache evicts nothing while the server is down: the new key is told to
    /// retry instead.
    #[test]
    fn nothing_is_evicted_while_the_server_is_down() {
        let cache = KeyCache::new(SHARDS, Duration::from_secs(300), clock());
        let policies = Policies::default();
        let hashes = same_shard();
        assert!(cache.insert(hashes[0], principal(&policies)));
        cache.note_server_down();
        assert!(cache.server_down());
        assert!(!cache.insert(hashes[1], principal(&policies)));
        assert!(cache.fresh(&hashes[0]).is_some());
        cache.note_server_seen();
        assert!(cache.insert(hashes[1], principal(&policies)));
    }

    /// One IPv6 /64 is one client, and a mapped IPv4 address is its IPv4 address (S2-2).
    #[test]
    fn the_allowance_is_counted_per_host_prefix() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(
            allowance_key(ip("2001:db8::1")),
            allowance_key(ip("2001:db8::ffff:1"))
        );
        assert_ne!(
            allowance_key(ip("2001:db8::1")),
            allowance_key(ip("2001:db8:0:1::1"))
        );
        assert_eq!(allowance_key(ip("::ffff:192.0.2.9")), ip("192.0.2.9"));
        let budget = Budget::new(50, 2, clock());
        assert!(budget.take(ip("2001:db8::1"), false));
        assert!(budget.take(ip("2001:db8::2"), false));
        assert!(!budget.take(ip("2001:db8::3"), false), "the same /64");
        assert!(budget.take(ip("2001:db8:0:1::1"), false));
    }

    /// The snapshot round-trips keys, layers with their stale marker, and the files are
    /// written with the previous kept.
    #[test]
    fn a_snapshot_survives_a_truncated_current_file() {
        let dir = tempfile::tempdir().unwrap();
        let policies = Policies::default();
        let cache = KeyCache::new(100, Duration::from_secs(300), clock());
        cache.insert(KeyHash([9; 32]), principal(&policies));
        policies.mark_stale(&[PLATFORM], 7);
        let snapshot = |cursor| Snapshot {
            cursor,
            keys: cache.saved(),
            layers: policies.saved(),
            network_lock: Vec::new(),
        };
        write_snapshot(dir.path(), &snapshot(1)).unwrap();
        write_snapshot(dir.path(), &snapshot(2)).unwrap();
        assert_eq!(read_snapshot(dir.path()).unwrap().cursor, 2);
        std::fs::write(dir.path().join(SNAPSHOT), b"{\"cursor\":").unwrap();
        let restored = read_snapshot(dir.path()).expect("the previous one");
        assert_eq!(restored.cursor, 1);
        assert_eq!(restored.keys.len(), 1);
        let again = Policies::default();
        again.restore(restored.layers);
        assert_eq!(again.stale(), vec![PLATFORM], "the stale marker survives");
        std::fs::remove_file(dir.path().join(PREVIOUS_SNAPSHOT)).unwrap();
        assert!(read_snapshot(dir.path()).is_none());
    }
}
