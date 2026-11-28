//! Conan 2 remote delivery on the shared firewall machinery. The remote's revision lists (`revisions`, `latest`), its search
//! documents and its file lists are filtered by policy; each file of a recipe or package revision is gated by the decision of
//! its revision before a byte is delivered.
//!
//! Identity. Policy sees the package name and the recipe version (`zlib`, `1.3.1`); the thing that has a publication time is a
//! revision (a recipe revision `rrev`, or a package revision `prev` of one package id of one recipe revision). A new binary of an old
//! recipe is a new package revision with its own time: no recipe date ever ages a binary, and no binary date a recipe.
//!
//! Dates. The remote's own `revisions` document names each revision's `time`; it is read (never invented), kept per unit in a
//! bounded in-memory table and committed on the revision's anchor row (its `conanmanifest.txt`), only ever later. A revision with no
//! usable time waits on the committed first-seen time. Dating costs no call beyond the list itself.
//!
//! URLs. Every upstream URL is rebuilt from the parsed identity, and every document the firewall serves is rebuilt from what it
//! understood (a file list carries names only), so no URL of the remote reaches a client through this family (the Conan 2 REST
//! API has no `download_urls` indirection; the v1 routes of it are not routed at all).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use url::Url;

use crate::App;
use crate::artifacts::ArtifactReference;
use crate::conan::coords::{self, Package, PackageRev, Parsed, Recipe, Rref};
use crate::http::error::{ApiError, storage_error};
use crate::managed::Principal;
use crate::managed::report::Call;
use crate::policy::{Candidate, Decision, DenyReason, Ecosystem, PublicationTime};
use crate::store::cache::Advertised;
use crate::store::rows::{ProjectRefresh, ReferenceId, ReferenceUpsert};
use crate::upstream::{
    MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError, UpstreamValidators,
};

pub struct Rendered {
    pub body: bytes::Bytes,
    pub content_type: &'static str,
    /// Entries a search left out because their lists were unreadable (reported in `x-probation-withheld`).
    pub withheld: usize,
}

const JSON: &str = "application/json";
const TEXT: &str = "text/plain; charset=utf-8";

/// LS-F7: no valid revision list, file list or search document is refused before this cap. The largest real documents measured
/// (evidence/slice-23.md) are 222 KB (`search?q=*` on ConanCenter) and 32 KB (the binaries of boost); 16 MiB is 70 times the first.
pub const DOC_FLOOR_CAP: u64 = 16 << 20;
/// A login token or a credential check answer.
const AUTH_CAP: u64 = 64 << 10;
/// Entries per document (revisions, files, search results, package ids).
const MAX_ENTRIES: usize = 500_000;
/// Revision lists one registry has being judged for searches at once (fetched, then decided: a store read and an OSV answer). Judging has
/// lanes of its own, apart from the four fetch places of a registry that installs and document reads use, and the process's judging lanes are
/// HALF of `max_upstream_requests` (16 at the default of 32), so a search never takes a fetch place or an upstream slot an install needs. A list
/// is a round trip to the remote: 16 lanes at 100 ms are 160 lists a second, at 200 ms 80, and a ConanCenter search of 9,000 references needs
/// 75 a second to finish inside one verdict life (longer needs a retry or two: verdicts are renewed when read). One owner holds at most half.
const JUDGE_PLACES: usize = 16;
/// References of one search judged at once by that search.
const JUDGE_AHEAD: usize = 16;
/// Lanes one owner holds at most, across all the registries it reads (12 of the process's 16): one honest caller judges with 12 lanes, and
/// one owner (two registries of its own) can never take every lane.
const OWNER_LANES: usize = 12;
/// Searches judging at once, per registry and in the process (more is a 503 with `Retry-After`).
const SEARCHES_PER_REGISTRY: usize = 4;
const SEARCHES_TOTAL: usize = 16;
/// One owner (see `spool::owner_of`: the account, or the client address and credential) holds at most half of them.
const OWNER_SEARCHES_PER_REGISTRY: usize = 2;
const OWNER_SEARCHES_TOTAL: usize = 8;
/// References of one search made, judged and dropped at a time (the memory of a search is its result strings and one batch).
const SEARCH_BATCH: usize = 5_000;
/// A document over this is decoded under the process-wide `BIG_DECODES` permits (its tree is several times its size).
const BIG_BODY: usize = 256 << 10;
const BIG_DECODES: usize = 4;
/// Revisions one credential may have remembered as its own uploads.
const OWN_PER_CREDENTIAL: usize = 4_096;
/// Units remembered per package in memory, parent lists per package, and packages per process.
const MAX_UNITS: usize = 16_384;
const MAX_CELLS: usize = 128;
/// How long a shared-service read trusts that a unit still exists (membership stays current).
const SERVICE_EXISTS_TTL: Duration = Duration::from_secs(5);
/// Document fetches at once, process-wide, and per registry (id 0 is the public one), and how long one waits.
const REFRESHES: usize = 16;
const REFRESHES_PER_REGISTRY: usize = 4;
const REFRESH_WAIT: Duration = Duration::from_secs(30);
/// A document request's whole deadline (every route but a file transfer).
pub const DOCUMENT_DEADLINE: Duration = Duration::from_secs(120);
const MAX_GATES: usize = 256;
/// Revision lists a credential-free read just fetched are kept for a moment, bounded by entries and size.
const RAW_TTL: Duration = Duration::from_secs(5);
const MAX_RAW: usize = 1_024;
const MAX_RAW_BYTES: usize = 4 << 20;
const MAX_RAW_TOTAL: usize = 48 << 20;
/// Verdicts of judged references and package ids live two minutes from when they were made. While a registry's last search ended unfinished (a
/// 504, for two minutes after it), a search that reads a verdict renews it, but never beyond `VERDICT_LIFE` from when it was made: a retry
/// after a 504 finds what the attempts before it made, so a search too large for one attempt converges over a few retries at any latency, and
/// an OSV change or a hold that ends shows within two minutes of a search that finished (a finished search renews nothing), within
/// `VERDICT_LIFE` while searches keep failing (a policy change shows at once: the policy is part of the key). A full document of
/// `MAX_ENTRIES` fits, and one verdict is 16 bytes of key and two instants.
const VERDICT_TTL: Duration = Duration::from_secs(120);
const VERDICT_LIFE: Duration = Duration::from_secs(600);
const MAX_VERDICTS: usize = 600_000;
/// Revisions handled per database round trip while one list is judged (memory and transaction size stay bounded).
const BATCH: usize = 1_000;
/// Revisions a credential uploaded through this firewall, remembered so that its own existence checks keep working.
const OWN_TTL: Duration = Duration::from_secs(7 * 86_400);
const MAX_OWN: usize = 65_536;
/// Fetch places one credential may hold of a registry's four (a junk `Authorization` cannot starve the others).
const PER_CREDENTIAL_PLACES: usize = 2;
/// Rows a project may have beyond which one more revision is refused (a multiple of the bound).
const ROWS_FACTOR: u64 = 5;

/// What a unit is known by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dated {
    /// The remote's own revision time, microseconds since the epoch.
    Upstream(i64),
    /// No usable time: only the committed first-seen time can date it.
    Undated,
}

#[derive(Clone, Copy, Debug)]
struct Known {
    time: Dated,
    first_seen: Option<i64>,
    /// Judged for a search without a row: a list or file request still writes the anchor row.
    rowless: bool,
    /// When this process last confirmed the unit exists upstream.
    checked: Instant,
}

impl Known {
    fn publication(&self) -> PublicationTime {
        match self.time {
            Dated::Upstream(micros) => PublicationTime::Upstream(micros),
            Dated::Undated => self
                .first_seen
                .map_or(PublicationTime::Unknown, PublicationTime::FirstSeen),
        }
    }
}

#[derive(Default)]
struct Cell {
    units: std::sync::Mutex<HashMap<String, Known>>,
}

/// (registry, selected origin, package name).
type CellKey = (u64, Option<String>, String);
/// (registry, package name).
type GateKey = (u64, String);
/// (registry, a digest of the credential).
type CredentialKey = (u64, [u8; 8]);
/// Remembered uploads, kept in insertion order so that every eviction takes the oldest in O(log n): `by_key` (key -> when, credential tag,
/// sequence number), `order` (sequence number -> key, oldest first, so the table's oldest and its expired ones are its first entries) and
/// `per_credential` (credential tag -> its sequence numbers, so one credential's oldest is its first). The three change together.
#[derive(Default)]
struct OwnTable {
    by_key: HashMap<[u8; 16], (Instant, [u8; 8], u64)>,
    order: std::collections::BTreeMap<u64, [u8; 16]>,
    per_credential: HashMap<[u8; 8], std::collections::BTreeSet<u64>>,
    next: u64,
}

impl OwnTable {
    fn forget(&mut self, key: &[u8; 16]) {
        if let Some((_, tag, seq)) = self.by_key.remove(key) {
            self.order.remove(&seq);
            if let Some(held) = self.per_credential.get_mut(&tag) {
                held.remove(&seq);
                if held.is_empty() {
                    self.per_credential.remove(&tag);
                }
            }
        }
    }

    fn oldest(&self) -> Option<[u8; 16]> {
        self.order.first_key_value().map(|(_, key)| *key)
    }
}
/// (registry, selected origin, the list's URL).
type RawKey = (u64, Option<String>, String);

/// The process-owned memory: unit tables, refresh places and row gates. Credential-free reads only share (C1028): a read that
/// carries the caller's own credential reads and fills none of it.
pub struct Shared {
    cells: std::sync::Mutex<HashMap<CellKey, Arc<Cell>>>,
    refresh: Arc<tokio::sync::Semaphore>,
    per_registry: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    /// One writer per project at a time between the row-bound check and the commit of a new row.
    row_gates: std::sync::Mutex<HashMap<GateKey, Arc<tokio::sync::Mutex<()>>>>,
    /// Revision lists fetched by credential-free reads, for `RAW_TTL`.
    raw: std::sync::Mutex<HashMap<RawKey, (Instant, bytes::Bytes)>>,
    /// Verdicts of judged references and package ids (credential-free reads only).
    verdicts: std::sync::Mutex<HashMap<[u8; 16], (Instant, Instant, Verdict)>>,
    /// Judging jobs in flight, shared by every request that needs them (they outlive a request's deadline).
    flights: std::sync::Mutex<HashMap<[u8; 16], tokio::sync::watch::Receiver<Option<Verdict>>>>,
    /// Per registry: lists being judged for searches, and searches judging.
    judging: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    judging_total: Arc<tokio::sync::Semaphore>,
    /// Registries whose last search ended unfinished (a 504), until when: while it is open, a search that reads a verdict renews it.
    unfinished: std::sync::Mutex<HashMap<u64, Instant>>,
    searches: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    searches_total: Arc<tokio::sync::Semaphore>,
    /// Searches each owner holds: per (registry, owner) and in all; and the lists of a registry one owner judges at once.
    owner_searches: std::sync::Mutex<HashMap<(u64, u64), usize>>,
    owner_total: std::sync::Mutex<HashMap<u64, usize>>,
    owner_judging: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    big_decodes: Arc<tokio::sync::Semaphore>,
    /// Places held per (registry, credential) of the registry's four.
    per_credential: std::sync::Mutex<HashMap<CredentialKey, Arc<tokio::sync::Semaphore>>>,
    /// Revisions uploaded through this firewall by a credential: (credential, registry, unit) -> when.
    own: std::sync::Mutex<OwnTable>,
}

impl Default for Shared {
    fn default() -> Shared {
        Shared::new(32)
    }
}

impl Shared {
    /// `max_upstream_requests` is the process's cap on calls open to remotes; judging takes at most half of it.
    pub fn new(max_upstream_requests: usize) -> Shared {
        Shared {
            cells: Default::default(),
            refresh: Arc::new(tokio::sync::Semaphore::new(REFRESHES)),
            per_registry: Default::default(),
            row_gates: Default::default(),
            raw: Default::default(),
            verdicts: Default::default(),
            flights: Default::default(),
            judging: Default::default(),
            unfinished: Default::default(),
            judging_total: Arc::new(tokio::sync::Semaphore::new(
                (max_upstream_requests / 2).max(1),
            )),
            searches: Default::default(),
            searches_total: Arc::new(tokio::sync::Semaphore::new(SEARCHES_TOTAL)),
            owner_searches: Default::default(),
            owner_total: Default::default(),
            owner_judging: Default::default(),
            big_decodes: Arc::new(tokio::sync::Semaphore::new(BIG_DECODES)),
            per_credential: Default::default(),
            own: Default::default(),
        }
    }
}

/// The sizes of the process-owned tables (cells, refresh-place tables, row gates, shared lists), so a test can assert each stays bounded.
pub fn table_sizes(app: &App) -> [usize; 4] {
    [
        lock(&app.conan.cells).len(),
        lock(&app.conan.per_registry).len(),
        lock(&app.conan.row_gates).len(),
        lock(&app.conan.raw).len(),
    ]
}

/// How many verdicts the process holds (a test measures the judging rate by it).
#[cfg(feature = "test-support")]
pub fn verdict_count(app: &App) -> usize {
    lock(&app.conan.verdicts).len()
}

/// (Remembered uploads, the sum of the per-credential counts, the length of the order index): the three are always equal.
#[cfg(feature = "test-support")]
pub fn own_sizes(app: &App) -> (usize, usize, usize) {
    let own = lock(&app.conan.own);
    (
        own.by_key.len(),
        own.per_credential
            .values()
            .map(std::collections::BTreeSet::len)
            .sum(),
        own.order.len(),
    )
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn origin_key(principal: Option<&Principal>) -> Option<String> {
    principal
        .and_then(|p| p.registry_origin.as_ref())
        .map(Url::to_string)
}

fn cell_for(app: &App, registry_id: u64, principal: Option<&Principal>, name: &str) -> Arc<Cell> {
    if crate::http::credential_read::cache_token(app).is_none() {
        return Arc::new(Cell::default());
    }
    let key = (registry_id, origin_key(principal), name.to_owned());
    let mut cells = lock(&app.conan.cells);
    if cells.len() >= MAX_CELLS && !cells.contains_key(&key) {
        cells.retain(|_, cell| Arc::strong_count(cell) > 1);
    }
    Arc::clone(cells.entry(key).or_default())
}

fn exists_ttl(app: &App) -> Duration {
    if app.service_policy().is_some() {
        SERVICE_EXISTS_TTL
    } else {
        Duration::from_secs(app.config.metadata_ttl_seconds)
    }
}

/// A short digest of a credential (or of nothing): who a place or an upload belongs to.
fn credential_digest(principal: Option<&Principal>) -> Option<[u8; 16]> {
    principal
        .and_then(|p| p.registry_read_authorization.as_deref())
        .map(digest_of_text)
}

fn digest_of_text(text: &str) -> [u8; 16] {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(text.as_bytes());
    hash[..16].try_into().expect("16 bytes")
}

fn digest_of(parts: &[&[u8]]) -> [u8; 16] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize()[..16].try_into().expect("16 bytes")
}

/// The places one fetch holds: its credential's share (a caller with a credential holds at most `PER_CREDENTIAL_PLACES` of the registry's
/// four, so a junk `Authorization` cannot starve the others), the registry's, and a process-wide one.
struct Places {
    _credential: Option<tokio::sync::OwnedSemaphorePermit>,
    _registry: tokio::sync::OwnedSemaphorePermit,
    _global: tokio::sync::OwnedSemaphorePermit,
}

async fn refresh_places(
    app: &App,
    registry_id: u64,
    principal: Option<&Principal>,
) -> Result<Places, ApiError> {
    let credential = credential_digest(principal);
    tokio::time::timeout(REFRESH_WAIT, async {
        let share =
            credential.map(|digest| {
                let mut map = lock(&app.conan.per_credential);
                let key = (registry_id, digest[..8].try_into().expect("8 bytes"));
                if map.len() >= 1_024 && !map.contains_key(&key) {
                    map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
                }
                Arc::clone(map.entry(key).or_insert_with(|| {
                    Arc::new(tokio::sync::Semaphore::new(PER_CREDENTIAL_PLACES))
                }))
            });
        let credential = match share {
            Some(semaphore) => Some(
                semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| ApiError::InternalFailure)?,
            ),
            None => None,
        };
        let own =
            {
                let mut map = lock(&app.conan.per_registry);
                if map.len() >= MAX_GATES && !map.contains_key(&registry_id) {
                    map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
                }
                Arc::clone(map.entry(registry_id).or_insert_with(|| {
                    Arc::new(tokio::sync::Semaphore::new(REFRESHES_PER_REGISTRY))
                }))
            };
        let registry = own
            .acquire_owned()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        let global = Arc::clone(&app.conan.refresh)
            .acquire_owned()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        Ok::<_, ApiError>(Places {
            _credential: credential,
            _registry: registry,
            _global: global,
        })
    })
    .await
    .map_err(|_| ApiError::UpstreamTimeout)?
}

/// What a policy sees as the package's name: lower case, so a remote that folds case (Artifactory repositories may) cannot be asked
/// for `Zlib` to get round a block on `zlib`. URLs and rows keep the remote's own spelling.
fn pname(rref: &Rref) -> String {
    rref.name.to_ascii_lowercase()
}

fn own_key(credential: [u8; 16], registry_id: u64, unit_key: &str) -> [u8; 16] {
    digest_of(&[&credential, &registry_id.to_le_bytes(), unit_key.as_bytes()])
}

/// Records that the credential `authorization` uploaded this unit through the firewall (a 2xx answer of the registry). In memory and per
/// process only: a restart forgets it and a second instance behind a balancer does not see it (so uploads and their existence checks need
/// sticky routing, or the cooldown applies to the check). Bounded per credential (the oldest goes first) and in all (the oldest tenth goes).
pub fn note_upload(app: &App, authorization: &str, registry_id: u64, unit: &UnitRef) {
    let credential = digest_of_text(authorization);
    let tag: [u8; 8] = credential[..8].try_into().expect("8 bytes");
    let key = own_key(credential, registry_id, &unit.key());
    let now = app.clock.now_monotonic();
    let mut own = lock(&app.conan.own);
    own.forget(&key);
    if own.by_key.len() >= MAX_OWN {
        // Expired entries are the oldest ones; then the oldest tenth.
        while let Some(old) = own.oldest() {
            if own
                .by_key
                .get(&old)
                .is_some_and(|(at, _, _)| now.saturating_duration_since(*at) >= OWN_TTL)
            {
                own.forget(&old);
            } else {
                break;
            }
        }
        for _ in 0..if own.by_key.len() >= MAX_OWN {
            MAX_OWN / 10
        } else {
            0
        } {
            let Some(old) = own.oldest() else { break };
            own.forget(&old);
        }
    }
    let seq = own.next;
    own.next += 1;
    own.by_key.insert(key, (now, tag, seq));
    own.order.insert(seq, key);
    let held = own.per_credential.entry(tag).or_default();
    held.insert(seq);
    let oldest = if held.len() > OWN_PER_CREDENTIAL {
        held.first().copied()
    } else {
        None
    };
    if let Some(old) = oldest.and_then(|first| own.order.get(&first).copied()) {
        own.forget(&old);
    }
}

/// A decision the cooldown alone made: the one thing an uploader's own revisions are exempt from (a block, an OSV verdict or a digest
/// block is never exempt).
fn cooldown_only(decision: &Decision) -> bool {
    matches!(decision, Decision::Hold { .. })
}

/// Whether the caller's own credential uploaded this unit (its upload existence checks, and its reads of the lists naming it, must work
/// while the unit is in its cooldown; any other credential sees the cooldown).
fn uploaded_by_caller(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    unit_key: &str,
) -> bool {
    let Some(credential) = credential_digest(principal) else {
        return false;
    };
    let now = app.clock.now_monotonic();
    lock(&app.conan.own)
        .by_key
        .get(&own_key(credential, registry_id, unit_key))
        .is_some_and(|(at, _, _)| now.saturating_duration_since(*at) < OWN_TTL)
}

// ------------------------------------------------------------------ origins and upstream

struct Origins {
    set: OriginSet,
    kind: OriginKind,
}

fn origins_for(app: &App, principal: Option<&Principal>) -> Result<Origins, ApiError> {
    match principal.and_then(|p| p.registry_origin.as_ref()) {
        // A selected registry's origin (its remote root, path included) travels in the slot `selected_npm_with_private` fills.
        Some(origin) => Ok(Origins {
            set: OriginSet::selected_npm_with_private(
                origin.clone(),
                principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            )
            .map_err(|_| ApiError::NotFound)?,
            kind: OriginKind::NpmMetadata,
        }),
        None => Ok(Origins {
            set: app.origins.clone(),
            kind: OriginKind::ConanRemote,
        }),
    }
}

fn url_of(origins: &Origins, segments: &[String]) -> Result<Url, ApiError> {
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    origins
        .set
        .url_for(origins.kind, &parts)
        .map_err(|_| ApiError::NotFound)
}

fn status_error(app: &App, error: UpstreamError) -> ApiError {
    match error {
        UpstreamError::Status(401) if app.service_policy().is_some() => {
            ApiError::UpstreamUnauthenticated
        }
        UpstreamError::Status(403) if app.service_policy().is_some() => ApiError::UpstreamDenied,
        UpstreamError::Timeout => ApiError::UpstreamTimeout,
        other => {
            tracing::warn!(error = %other, "the Conan remote fetch failed");
            ApiError::UpstreamFailure
        }
    }
}

async fn fetch(
    app: &App,
    principal: Option<&Principal>,
    url: Url,
    accept: &'static str,
    max_bytes: u64,
) -> Result<Option<bytes::Bytes>, ApiError> {
    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            origin: principal.and_then(|p| p.registry_origin.clone()),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept,
            validators: None,
            max_bytes,
        })
        .await;
    app.upstreams.record_upstream(Call::Conan, &fetched);
    match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => Ok(Some(body)),
        Ok(MetadataResponse::Missing) => Ok(None),
        Ok(MetadataResponse::NotModified { .. }) => Err(ApiError::UpstreamInvalid),
        Err(error) => Err(status_error(app, error)),
    }
}

/// Whether a file exists upstream and its own `Last-Modified`, asked without reading its body (inside the registry's fetch places).
async fn probe(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    url: Url,
) -> Result<Option<Dated>, ApiError> {
    let _places = refresh_places(app, registry_id, principal).await?;
    let fetched = app
        .transport
        .probe_file(MetadataRequest {
            url,
            origin: principal.and_then(|p| p.registry_origin.clone()),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept: "*/*",
            validators: None,
            max_bytes: 1,
        })
        .await;
    app.upstreams.record_upstream(Call::Conan, &fetched);
    match fetched {
        Ok(Some(validators)) => Ok(Some(
            match validators
                .last_modified
                .as_deref()
                .map(|text| jiff::fmt::rfc2822::DateTimeParser::new().parse_timestamp(text.trim()))
            {
                Some(Ok(at)) if at.as_second() >= EARLIEST => Dated::Upstream(at.as_microsecond()),
                _ => Dated::Undated,
            },
        )),
        Ok(None) => Ok(None),
        Err(error) => Err(status_error(app, error)),
    }
}

/// No Conan revision is older than 2000: an earlier time (the epoch a remote writes for "unknown") is no date, and the revision waits on
/// first-seen instead of looking a quarter-century old.
const EARLIEST: i64 = 946_684_800;

fn invalid(what: &'static str) -> ApiError {
    tracing::warn!(what, "the remote's document is unusable");
    ApiError::UpstreamInvalid
}

/// A revision's `time` as a publication time: absent or unparseable is no date (the unit then waits on first-seen, which is never
/// earlier than the truth). Conan servers write `2024-12-11T16:57:24.862+0000`.
pub fn dated_of(text: Option<&str>) -> Dated {
    let Some(text) = text
        .map(str::trim)
        .filter(|text| !text.is_empty() && text.len() <= 64)
    else {
        return Dated::Undated;
    };
    // `jiff` reads the offset as `+0000`, `+00:00` and `Z` alike; one with no offset at all is UTC.
    let parsed = text
        .parse::<jiff::Timestamp>()
        .ok()
        .or_else(|| format!("{text}Z").parse::<jiff::Timestamp>().ok());
    match parsed {
        Some(at) if at.as_second() >= EARLIEST => Dated::Upstream(at.as_microsecond()),
        _ => Dated::Undated,
    }
}

// ------------------------------------------------------------------ units

/// A recipe revision or a package revision: the thing that has a publication time.
#[derive(Clone, Debug)]
pub enum UnitRef {
    Recipe(Recipe),
    Package(PackageRev),
}

impl UnitRef {
    fn rref(&self) -> &Rref {
        match self {
            UnitRef::Recipe(recipe) => &recipe.rref,
            UnitRef::Package(package) => &package.package.recipe.rref,
        }
    }

    fn below(&self) -> Vec<String> {
        match self {
            UnitRef::Recipe(recipe) => coords::recipe_segments(recipe),
            UnitRef::Package(package) => coords::package_rev_segments(package),
        }
    }

    fn key(&self) -> String {
        match self {
            UnitRef::Recipe(recipe) => unit_key(&recipe.rref, &recipe.rrev, None),
            UnitRef::Package(package) => unit_key(
                &package.package.recipe.rref,
                &package.package.recipe.rrev,
                Some((&package.package.pkgid, &package.prev)),
            ),
        }
    }

    /// The list that names this unit's time.
    fn parent(&self) -> Parent {
        match self {
            UnitRef::Recipe(recipe) => Parent::Recipe(recipe.rref.clone()),
            UnitRef::Package(package) => Parent::Package(package.package.clone()),
        }
    }

    fn revision(&self) -> &str {
        match self {
            UnitRef::Recipe(recipe) => &recipe.rrev,
            UnitRef::Package(package) => &package.prev,
        }
    }
}

fn unit_key(rref: &Rref, rrev: &str, package: Option<(&str, &str)>) -> String {
    match package {
        None => format!("r:{}/{}@{}#{rrev}", rref.user, rref.channel, rref.version),
        Some((pkgid, prev)) => format!(
            "p:{}/{}@{}#{rrev}:{pkgid}#{prev}",
            rref.user, rref.channel, rref.version
        ),
    }
}

/// What a revision list belongs to.
#[derive(Clone, Debug)]
pub enum Parent {
    Recipe(Rref),
    Package(Package),
}

impl Parent {
    fn rref(&self) -> &Rref {
        match self {
            Parent::Recipe(rref) => rref,
            Parent::Package(package) => &package.recipe.rref,
        }
    }

    fn list_segments(&self) -> Vec<String> {
        let below = match self {
            Parent::Recipe(rref) => {
                let mut segments = rref.segments();
                segments.push("revisions".to_owned());
                segments
            }
            Parent::Package(package) => {
                let mut segments = coords::recipe_segments(&package.recipe);
                segments.extend([
                    "packages".to_owned(),
                    package.pkgid.clone(),
                    "revisions".to_owned(),
                ]);
                segments
            }
        };
        coords::upstream_segments(&below)
    }

    fn key(&self) -> String {
        match self {
            Parent::Recipe(rref) => format!(
                "R:{}/{}/{}@{}",
                rref.name, rref.version, rref.user, rref.channel
            ),
            Parent::Package(package) => format!(
                "P:{}/{}/{}@{}#{}:{}",
                package.recipe.rref.name,
                package.recipe.rref.version,
                package.recipe.rref.user,
                package.recipe.rref.channel,
                package.recipe.rrev,
                package.pkgid
            ),
        }
    }

    fn unit(&self, revision: &str) -> UnitRef {
        match self {
            Parent::Recipe(rref) => UnitRef::Recipe(Recipe {
                rref: rref.clone(),
                rrev: revision.to_owned(),
            }),
            Parent::Package(package) => UnitRef::Package(PackageRev {
                package: package.clone(),
                prev: revision.to_owned(),
            }),
        }
    }
}

/// The reference of one file of a unit.
fn reference_of(
    origins: &Origins,
    unit: &UnitRef,
    file: &str,
    registry_id: u64,
) -> Option<(ReferenceId, ArtifactReference)> {
    let below = unit.below();
    let mut under = below.clone();
    under.push("files".to_owned());
    under.extend(file.split('/').map(str::to_owned));
    let url = url_of(origins, &coords::upstream_segments(&under)).ok()?;
    let rref = unit.rref();
    let reference = ArtifactReference {
        ecosystem: Ecosystem::Conan,
        name: pname(rref),
        version: rref.version.clone(),
        filename: coords::row_file_name(rref, &below, file),
        upstream_url: url,
        // The remote's `conanmanifest.txt` is the client's check (it fetches it through this firewall); the first verified download pins
        // the digests (SPEC §9, STATE-01).
        expected: Vec::new(),
    };
    Some((
        ReferenceId::compute_in_registry(registry_id, &reference),
        reference,
    ))
}

// ------------------------------------------------------------------ policy

fn check_policy(
    app: &App,
    principal: Option<&Principal>,
) -> Result<(Arc<crate::policy::CompiledPolicy>, i64), ApiError> {
    let now = app.clock.now_utc_micros();
    let policy = app
        .policy_for(principal)
        .ok_or(ApiError::PolicyUnavailable)?;
    if !policy
        .snapshot
        .as_deref()
        .is_some_and(|snapshot| snapshot.is_valid_at(now))
    {
        return Err(ApiError::PolicyUnavailable);
    }
    Ok((policy, now))
}

fn blocked_outright(
    policy: &crate::policy::CompiledPolicy,
    now: i64,
    name: &str,
    version: Option<&str>,
) -> Option<Decision> {
    let candidate = Candidate {
        ecosystem: Ecosystem::Conan,
        name,
        version: version.unwrap_or(""),
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    match crate::policy::decide(policy, &candidate, now, false).decision {
        decision @ Decision::Deny(DenyReason::BlockedPackage | DenyReason::BlockedVersion) => {
            Some(decision)
        }
        _ => None,
    }
}

/// A name or version a policy blocks outright is refused without asking upstream anything (PERF-01).
fn locally_blocked(
    app: &App,
    principal: Option<&Principal>,
    name: &str,
    version: Option<&str>,
) -> Result<(), ApiError> {
    let (policy, now) = check_policy(app, principal)?;
    if let Some(decision) = blocked_outright(&policy, now, name, version) {
        if let (Some(principal), Some(managed)) = (principal, app.managed()) {
            let candidate = Candidate {
                ecosystem: Ecosystem::Conan,
                name,
                version: version.unwrap_or(""),
                publication: PublicationTime::Unknown,
                advertised_digests: &[],
                pinned_digests: &[],
            };
            managed.record_refused(
                principal,
                &policy,
                now,
                &candidate,
                decision,
                version.is_some(),
            );
        }
        return Err(crate::artifacts::decision_error(decision, now));
    }
    Ok(())
}

fn candidate<'a>(
    name: &'a str,
    version: &'a str,
    known: &Known,
    pinned: &'a [crate::policy::Digest],
) -> Candidate<'a> {
    Candidate {
        ecosystem: Ecosystem::Conan,
        name,
        version,
        publication: known.publication(),
        advertised_digests: &[],
        pinned_digests: pinned,
    }
}

/// The decision of one unit as the artifact pipeline will take it; anything but Allow is answered (and logged for a managed key) now.
/// `exempt`: a document (a list, a file list) the caller's own credential uploaded the unit for is not held by its cooldown (a block still is).
async fn refuse_unless_allowed(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    unit: &UnitRef,
    known: &Known,
    exempt: bool,
) -> Result<(), ApiError> {
    let rref = unit.rref();
    let name = pname(rref);
    let (policy, now) = check_policy(app, principal)?;
    let decision = crate::osv::evaluate_scoped(
        &app.osv,
        &policy,
        now,
        &candidate(&name, &rref.version, known, &[]),
        app.osv_scope(registry_id),
    )
    .await;
    if matches!(decision, Decision::Allow)
        || (exempt
            && cooldown_only(&decision)
            && uploaded_by_caller(app, principal, registry_id, &unit.key()))
    {
        return Ok(());
    }
    if let (Some(principal), Some(managed)) = (principal, app.managed()) {
        managed.record_refused(
            principal,
            &policy,
            now,
            &candidate(&name, &rref.version, known, &[]),
            decision,
            true,
        );
    }
    Err(crate::artifacts::decision_error(decision, now))
}

// ------------------------------------------------------------------ rows

/// The project's row gate: held from the bound check to the commit of the rows it admits, so simultaneous first requests cannot
/// each see room for the same last row. (Per process: one firewall owns its store.)
async fn row_gate(app: &App, registry_id: u64, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
    let gate = {
        let mut gates = lock(&app.conan.row_gates);
        let key = (registry_id, name.to_owned());
        if gates.len() >= 1024 && !gates.contains_key(&key) {
            gates.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        Arc::clone(gates.entry(key).or_default())
    };
    gate.lock_owned().await
}

fn row_limit(app: &App) -> u64 {
    ROWS_FACTOR * u64::from(app.config.max_references_per_project.get())
}

/// A project may hold at most `ROWS_FACTOR` times `max_references_per_project` reference rows: past it a new row is a 503.
async fn within_row_bound(app: &App, registry_id: u64, name: &str) -> Result<(), ApiError> {
    let rows = app
        .store()
        .count_project_references_in(registry_id, Ecosystem::Conan, name)
        .await
        .map_err(storage_error)?;
    if rows >= row_limit(app) {
        tracing::warn!(package = %name, rows, "a project is at its reference row bound: one more revision or file is refused");
        return Err(ApiError::Overloaded);
    }
    Ok(())
}

/// Commits the anchors of every `(unit key, anchor id, anchor reference, dated)` once and returns what was learned (in the order of
/// `items`). A date can only get later (the later of what this process saw, what the row already holds (`stored`, read once for the
/// project) and what the remote says now: a throwaway table of a credential-bearing read, an evicted table or a restart cannot make a unit
/// look older). The unit table takes at most `MAX_UNITS` entries and is never cleared to make room.
async fn record(
    app: &App,
    registry_id: u64,
    name: &str,
    cell: &Cell,
    stored: &HashMap<ReferenceId, i64>,
    items: &[(String, ReferenceId, ArtifactReference, Dated)],
) -> Result<Vec<Known>, ApiError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let now = app.clock.now_utc_micros();
    let mono = app.clock.now_monotonic();
    let merged: Vec<Dated> = {
        let units = lock(&cell.units);
        items
            .iter()
            .map(|(key, id, _, dated)| {
                let remembered = match units.get(key).map(|known| known.time) {
                    Some(Dated::Upstream(micros)) => Some(micros),
                    _ => None,
                };
                let upstream = match dated {
                    Dated::Upstream(micros) => Some(*micros),
                    Dated::Undated => None,
                };
                match [remembered, stored.get(id).copied(), upstream]
                    .into_iter()
                    .flatten()
                    .max()
                {
                    Some(micros) => Dated::Upstream(micros),
                    None => Dated::Undated,
                }
            })
            .collect()
    };
    let references = items
        .iter()
        .zip(&merged)
        .map(|((_, id, reference, _), dated)| ReferenceUpsert {
            id: *id,
            reference: reference.clone(),
            publication_micros: match dated {
                Dated::Upstream(micros) => Some(*micros),
                Dated::Undated => None,
            },
            first_seen_micros: Some(now),
        })
        .collect();
    // Reference identity, first-seen times and pins only: no response body is retained (C1028); the unit table is the only memory.
    let committed = app
        .store()
        .commit_request_references_in(
            registry_id,
            ProjectRefresh {
                ecosystem: Ecosystem::Conan,
                name: name.to_owned(),
                payload: Arc::from(&[][..]),
                validators: UpstreamValidators::default(),
                validated_at_micros: now,
                fetched_at_micros: now,
                references,
            },
        )
        .await
        .map_err(storage_error)?;
    let mut units = lock(&cell.units);
    let mut learned = Vec::with_capacity(items.len());
    for ((key, id, ..), dated) in items.iter().zip(merged) {
        let known = Known {
            time: dated,
            first_seen: committed.first_seen.get(id).copied(),
            rowless: false,
            checked: mono,
        };
        if units.len() < MAX_UNITS || units.contains_key(key) {
            units.insert(key.clone(), known);
        }
        learned.push(known);
    }
    Ok(learned)
}

// ------------------------------------------------------------------ revision lists

struct Rev {
    revision: String,
    time: Option<String>,
    dated: Dated,
}

struct RevDoc {
    /// The string members of the document other than `revisions` (`reference`, `packageReference`), served back as they were.
    head: Vec<(String, String)>,
    entries: Vec<Rev>,
}

/// A revision list, read strictly: one object, `revisions` an array of objects each with a valid `revision` (once) and a string `time`
/// when it has one; anything else is the remote's fault (502).
fn read_revisions(body: &[u8], max: usize) -> Result<RevDoc, ()> {
    // Typed: the entries are never a `Value` tree (a 16 MiB list would be several times that). A `revisions` that is not an array, a
    // repeated `revisions`, an entry that is not an object with a string `revision` and a string or null `time` are all errors.
    #[derive(serde::Deserialize)]
    struct RawRev {
        revision: String,
        #[serde(default)]
        time: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct RawList {
        revisions: Vec<RawRev>,
        #[serde(flatten)]
        rest: HashMap<String, serde_json::Value>,
    }
    let raw: RawList = serde_json::from_slice(body).map_err(|_| ())?;
    if raw.revisions.len() > max {
        return Err(());
    }
    let mut seen = HashSet::with_capacity(raw.revisions.len());
    let mut entries = Vec::with_capacity(raw.revisions.len());
    for item in raw.revisions {
        if !coords::id_ok(&item.revision)
            || !seen.insert(item.revision.clone())
            || item.time.as_ref().is_some_and(|time| time.len() > 64)
        {
            return Err(());
        }
        entries.push(Rev {
            dated: dated_of(item.time.as_deref()),
            revision: item.revision,
            time: item.time,
        });
    }
    let mut head: Vec<(String, String)> = raw
        .rest
        .into_iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::String(text)
                if matches!(key.as_str(), "reference" | "packageReference")
                    && text.len() <= 1024
                    && text.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || matches!(b, b'_' | b'+' | b'.' | b'-' | b'@' | b'/' | b'#' | b':')
                    }) =>
            {
                Some((key, text))
            }
            _ => None,
        })
        .collect();
    head.sort();
    Ok(RevDoc { head, entries })
}

fn revision_json(entry: &Rev) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert("revision".to_owned(), entry.revision.clone().into());
    if let Some(time) = &entry.time {
        object.insert("time".to_owned(), time.clone().into());
    }
    serde_json::Value::Object(object)
}

/// A revision list with the decided entries of it.
struct Listing {
    doc: RevDoc,
    decisions: Vec<Decision>,
    /// What is known of each unit (`None`: not recorded, withheld).
    known: Vec<Option<Known>>,
    now: i64,
}

/// The revision list of `parent` as the remote wrote it, read strictly (a credential-free read shares it for `RAW_TTL`).
async fn fetch_list(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    parent: &Parent,
    judge: bool,
) -> Result<RevDoc, ApiError> {
    let url = url_of(origins, &parent.list_segments())?;
    let cap = app.config.max_metadata_bytes.get().max(DOC_FLOOR_CAP);
    let raw_key: RawKey = (registry_id, origin_key(principal), url.to_string());
    let body = match shared_raw(app, &raw_key) {
        Some(body) => Some(body),
        None => {
            // A judging fetch is already inside one of the registry's judging lanes (`compute_verdict`) and takes none of the fetch places.
            let fetched = {
                let _places = if judge {
                    None
                } else {
                    Some(refresh_places(app, registry_id, principal).await?)
                };
                fetch(app, principal, url, JSON, cap).await?
            };
            if let Some(body) = &fetched {
                remember_raw(app, raw_key, body);
            }
            fetched
        }
    };
    let Some(body) = body else {
        return Err(ApiError::NotFound);
    };
    // A big list is DECODED under one of a few process-wide permits (the parse is several times its size); the permit is dropped as soon as
    // the typed list exists, before any row, decision or wait.
    let _decode = if body.len() > BIG_BODY {
        Some(big_permit(app).await?)
    } else {
        None
    };
    read_revisions(&body, MAX_ENTRIES).map_err(|()| invalid("a revision list"))
}

/// High-water mark of big decodes at once, for the test that the bound holds.
#[cfg(feature = "test-support")]
pub fn peak_big() -> usize {
    PEAK_BIG.load(std::sync::atomic::Ordering::SeqCst)
}

static PEAK_BIG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

async fn big_permit(app: &App) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    let permit = tokio::time::timeout(
        REFRESH_WAIT,
        Arc::clone(&app.conan.big_decodes).acquire_owned(),
    )
    .await
    .map_err(|_| ApiError::UpstreamTimeout)?
    .map_err(|_| ApiError::InternalFailure)?;
    PEAK_BIG.fetch_max(
        BIG_DECODES - app.conan.big_decodes.available_permits(),
        std::sync::atomic::Ordering::SeqCst,
    );
    Ok(permit)
}

/// Fetches and judges one revision list: every revision is a unit whose anchor row carries its date (bounded by the project's row
/// room; one past it is withheld, fail closed), and each unit's decision is the one the artifact pipeline will take. The work is done in
/// batches of `BATCH` units (one stored-date read per list, one commit per batch, decisions in groups), so the memory of a list is its
/// entries and one small record per unit, whatever its size; nothing clears the unit table to make room.
async fn list_units(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    cell: &Cell,
    parent: &Parent,
    judge_only: bool,
) -> Result<Listing, ApiError> {
    let doc = fetch_list(app, principal, registry_id, origins, parent, judge_only).await?;
    let n = doc.entries.len();
    let rref = parent.rref();
    let name = pname(rref);
    let (policy, now) = check_policy(app, principal)?;
    let blocked = blocked_outright(&policy, now, &name, Some(&rref.version)).is_some();
    // After a restart or an eviction the table is empty but the store still holds every date it recorded: one read for the project.
    let stored = app
        .store()
        .list_project_publications_in(registry_id, Ecosystem::Conan, &name)
        .await
        .map_err(storage_error)?;
    let mono = app.clock.now_monotonic();
    // A search judges a revision the remote does not date by the first-seen of its row, when it has one (a list or file request wrote it).
    let firsts = if judge_only
        && doc
            .entries
            .iter()
            .any(|entry| matches!(entry.dated, Dated::Undated))
    {
        app.store()
            .list_project_first_seen_in(registry_id, Ecosystem::Conan, &name)
            .await
            .map_err(storage_error)?
    } else {
        HashMap::new()
    };
    let mut known: Vec<Option<Known>> = vec![None; n];
    let mut wanted: Vec<usize> = Vec::new();
    {
        let mut table = lock(&cell.units);
        for (i, entry) in doc.entries.iter().enumerate() {
            let unit = parent.unit(&entry.revision);
            let key = unit.key();
            // A unit seen again is confirmed to exist now (so one expiry does not make every file request re-judge the list).
            if let Some(mut held) = table
                .get(&key)
                .copied()
                .filter(|held| !stale(held, entry.dated) && (judge_only || !held.rowless))
            {
                held.checked = mono;
                table.insert(key, held);
                known[i] = Some(held);
                continue;
            }
            let stored_at = reference_of(origins, &unit, coords::ANCHOR, registry_id)
                .and_then(|(id, _)| stored.get(&id).copied());
            match stored_at {
                Some(micros) if !matches!(entry.dated, Dated::Upstream(says) if says > micros) => {
                    let held = Known {
                        time: Dated::Upstream(micros),
                        first_seen: None,
                        rowless: false,
                        checked: mono,
                    };
                    if table.len() < MAX_UNITS {
                        table.insert(key, held);
                    }
                    known[i] = Some(held);
                }
                // A search only asks WHETHER a revision passes: one the remote dates needs no row and no write (the stored date, if later, was read
                // above; rows are made when a file or a list of the revision is asked for), so judging costs one read of the project.
                // One the remote does not date is judged as a row made now would be (its first-seen is now), also without a write; it is not
                // remembered, and neither kind is taken for a recorded unit by a list or file request, which writes the anchor row.
                _ if judge_only => {
                    let upstream = matches!(entry.dated, Dated::Upstream(_));
                    let row = reference_of(origins, &unit, coords::ANCHOR, registry_id)
                        .and_then(|(id, _)| firsts.get(&id).copied());
                    let held = Known {
                        time: entry.dated,
                        first_seen: if upstream {
                            None
                        } else {
                            Some(row.unwrap_or_else(|| app.clock.now_utc_micros()))
                        },
                        rowless: row.is_none(),
                        checked: mono,
                    };
                    if upstream && table.len() < MAX_UNITS {
                        table.insert(key, held);
                    }
                    known[i] = Some(held);
                }
                _ => wanted.push(i),
            }
        }
    }
    // (A name or version a policy blocks outright gets no row: nothing is judged for it that the block does not already say.)
    if !blocked {
        for chunk in wanted.chunks(BATCH) {
            let _gate = row_gate(app, registry_id, &name).await;
            let rows = app
                .store()
                .count_project_references_in(registry_id, Ecosystem::Conan, &name)
                .await
                .map_err(storage_error)?;
            let mut room = row_limit(app).saturating_sub(rows) as usize;
            let (mut items, mut slots) = (Vec::new(), Vec::new());
            for &i in chunk {
                let unit = parent.unit(&doc.entries[i].revision);
                let Some((id, reference)) =
                    reference_of(origins, &unit, coords::ANCHOR, registry_id)
                else {
                    continue;
                };
                // A unit that already has its row needs no room; a new one is taken only while the project has some.
                if !stored.contains_key(&id) {
                    if room == 0 {
                        continue;
                    }
                    room -= 1;
                }
                items.push((unit.key(), id, reference, doc.entries[i].dated));
                slots.push(i);
            }
            for (slot, learned) in slots
                .into_iter()
                .zip(record(app, registry_id, &name, cell, &stored, &items).await?)
            {
                known[slot] = Some(learned);
            }
        }
    }
    // (A digest block is enforced when a file is delivered: a search's verdict is made without the pins.)
    let pins = if judge_only {
        HashMap::new()
    } else {
        app.store()
            .list_project_pins_in(registry_id, Ecosystem::Conan, &name)
            .await
            .map_err(storage_error)?
    };
    let scope = app.osv_scope(registry_id);
    let credentialed = credential_digest(principal).is_some();
    let mut decisions = Vec::with_capacity(n);
    for start in (0..n).step_by(256) {
        let end = (start + 256).min(n);
        let group = futures_util::future::join_all((start..end).map(|i| {
            let (policy, pins, known, doc, name) = (&policy, &pins, &known, &doc, &name);
            async move {
                let Some(known) = known[i] else {
                    // Undated and unrecorded: withheld, for the reason policy gives a version with no date (a blocked name or version says so).
                    let undated = Candidate {
                        ecosystem: Ecosystem::Conan,
                        name,
                        version: &rref.version,
                        publication: PublicationTime::Unknown,
                        advertised_digests: &[],
                        pinned_digests: &[],
                    };
                    return crate::policy::decide(policy, &undated, now, false).decision;
                };
                let unit = parent.unit(&doc.entries[i].revision);
                let pinned: Vec<crate::policy::Digest> =
                    reference_of(origins, &unit, coords::ANCHOR, registry_id)
                        .iter()
                        .flat_map(|(id, _)| pins.get(id).into_iter().flatten().cloned())
                        .collect();
                let decision = crate::osv::evaluate_scoped(
                    &app.osv,
                    policy,
                    now,
                    &candidate(name, &rref.version, &known, &pinned),
                    scope,
                )
                .await;
                // The caller's own upload (same credential) keeps its existence checks working during the cooldown; a block, an OSV
                // verdict or a digest block still wins.
                if credentialed
                    && cooldown_only(&decision)
                    && uploaded_by_caller(app, principal, registry_id, &unit.key())
                {
                    return Decision::Allow;
                }
                decision
            }
        }))
        .await;
        decisions.extend(group);
    }
    Ok(Listing {
        doc,
        decisions,
        known,
        now,
    })
}

fn shared_raw(app: &App, key: &RawKey) -> Option<bytes::Bytes> {
    crate::http::credential_read::cache_token(app)?;
    let now = app.clock.now_monotonic();
    lock(&app.conan.raw)
        .get(key)
        .filter(|(at, _)| now.saturating_duration_since(*at) < RAW_TTL)
        .map(|(_, body)| body.clone())
}

fn remember_raw(app: &App, key: RawKey, body: &bytes::Bytes) {
    if crate::http::credential_read::cache_token(app).is_none() || body.len() > MAX_RAW_BYTES {
        return;
    }
    let now = app.clock.now_monotonic();
    let mut raw = lock(&app.conan.raw);
    let total = |raw: &HashMap<RawKey, (Instant, bytes::Bytes)>| {
        raw.values().map(|(_, body)| body.len()).sum::<usize>()
    };
    if raw.len() >= MAX_RAW || total(&raw) + body.len() > MAX_RAW_TOTAL {
        raw.retain(|_, (at, _)| now.saturating_duration_since(*at) < RAW_TTL);
        if raw.len() >= MAX_RAW || total(&raw) + body.len() > MAX_RAW_TOTAL {
            raw.clear();
        }
    }
    raw.insert(key, (now, body.clone()));
}

/// The remote now states a later time than the one remembered.
fn stale(known: &Known, now_dated: Dated) -> bool {
    match (known.time, now_dated) {
        (Dated::Upstream(have), Dated::Upstream(says)) => says > have,
        (Dated::Undated, Dated::Upstream(_)) => true,
        _ => false,
    }
}

/// The index of the newest allowed entry: the greatest time, the earliest in the list on a tie (a remote lists newest first).
fn newest_allowed(listing: &Listing) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, decision) in listing.decisions.iter().enumerate() {
        if !matches!(decision, Decision::Allow) {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => match (listing.doc.entries[i].dated, listing.doc.entries[b].dated) {
                (Dated::Upstream(a), Dated::Upstream(c)) => a > c,
                (Dated::Upstream(_), Dated::Undated) => true,
                _ => false,
            },
        };
        if better {
            best = Some(i);
        }
    }
    best
}

fn record_refused_listing(
    app: &App,
    principal: Option<&Principal>,
    rref: &Rref,
    decisions: &[Decision],
) {
    let (Some(principal), Some(managed)) = (principal, app.managed()) else {
        return;
    };
    let Some(policy) = app.policy_for(Some(principal)) else {
        return;
    };
    let now = app.clock.now_utc_micros();
    let Some(decision) = decisions.iter().find(|d| {
        matches!(
            d,
            Decision::Deny(
                DenyReason::BlockedPackage
                    | DenyReason::BlockedVersion
                    | DenyReason::BlockedByOsv
                    | DenyReason::BlockedDigest
            )
        )
    }) else {
        return;
    };
    let name = pname(rref);
    let candidate = Candidate {
        ecosystem: Ecosystem::Conan,
        name: &name,
        version: &rref.version,
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    let verdict = crate::managed::refused_verdict(&policy, now, &candidate, *decision);
    managed.record_decision(principal, Ecosystem::Conan, &name, None, &verdict);
}

/// The first unit's decision as the answer when nothing in a list is allowed (so the client is told why: the hold's deadline, the block).
fn nothing_allowed(
    app: &App,
    principal: Option<&Principal>,
    listing: &Listing,
    rref: &Rref,
) -> ApiError {
    record_refused_listing(app, principal, rref, &listing.decisions);
    match listing.decisions.first() {
        Some(decision) => crate::artifacts::decision_error(*decision, listing.now),
        None => ApiError::NotFound,
    }
}

fn render(value: serde_json::Value) -> Result<Rendered, ApiError> {
    render_with(value, 0)
}

fn render_with(value: serde_json::Value, withheld: usize) -> Result<Rendered, ApiError> {
    serde_json::to_vec(&value)
        .map(|body| Rendered {
            body: body.into(),
            content_type: JSON,
            withheld,
        })
        .map_err(|_| ApiError::InternalFailure)
}

fn listing_json(doc: &RevDoc, keep: &[usize]) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for (key, value) in &doc.head {
        object.insert(key.clone(), value.clone().into());
    }
    object.insert(
        "revisions".to_owned(),
        keep.iter()
            .map(|&i| revision_json(&doc.entries[i]))
            .collect::<Vec<_>>()
            .into(),
    );
    serde_json::Value::Object(object)
}

/// A package's own revisions are served only while its recipe revision passes too (a binary of a held recipe is not offered, and neither
/// are its lists): the recipe's own gate, with the recipe's own date.
async fn recipe_gate(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    cell: &Cell,
    parent: &Parent,
    exempt: bool,
) -> Result<(), ApiError> {
    let Parent::Package(package) = parent else {
        return Ok(());
    };
    let unit = UnitRef::Recipe(package.recipe.clone());
    let known = resolve(app, principal, registry_id, &unit, origins, cell).await?;
    refuse_unless_allowed(app, principal, registry_id, &unit, &known, exempt).await
}

/// `revisions` and `latest` of a recipe or of one package id: only the revisions that pass are listed, and `latest` is the newest of
/// them. When none passes the answer is the decision of the newest (403 with the hold's deadline, or the block).
pub async fn serve_revisions(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    parent: &Parent,
    latest: bool,
) -> Result<Rendered, ApiError> {
    let rref = parent.rref();
    locally_blocked(app, principal, &pname(rref), Some(&rref.version))?;
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &pname(rref));
    recipe_gate(app, principal, registry_id, &origins, &cell, parent, true).await?;
    let listing = list_units(app, principal, registry_id, &origins, &cell, parent, false).await?;
    let keep: Vec<usize> = (0..listing.decisions.len())
        .filter(|&i| matches!(listing.decisions[i], Decision::Allow))
        .collect();
    if keep.is_empty() {
        if listing.decisions.is_empty() {
            return Err(ApiError::NotFound);
        }
        return Err(nothing_allowed(app, principal, &listing, rref));
    }
    if latest {
        let at = newest_allowed(&listing).ok_or(ApiError::InternalFailure)?;
        return render(revision_json(&listing.doc.entries[at]));
    }
    render(listing_json(&listing.doc, &keep))
}

// ------------------------------------------------------------------ one unit

/// The unit's table entry, confirmed to exist within the freshness window: from memory, else the list that names it.
async fn resolve(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    unit: &UnitRef,
    origins: &Origins,
    cell: &Cell,
) -> Result<Known, ApiError> {
    let key = unit.key();
    let mono = app.clock.now_monotonic();
    if let Some(known) = lock(&cell.units).get(&key).copied()
        && mono.saturating_duration_since(known.checked) < exists_ttl(app)
    {
        return Ok(known);
    }
    // The row bound is hard: a unit with no anchor row gets none past it.
    let (id, _) =
        reference_of(origins, unit, coords::ANCHOR, registry_id).ok_or(ApiError::NotFound)?;
    if app
        .store()
        .get_reference(id)
        .await
        .map_err(storage_error)?
        .is_none()
    {
        within_row_bound(app, registry_id, &pname(unit.rref())).await?;
    }
    let listing = list_units(
        app,
        principal,
        registry_id,
        origins,
        cell,
        &unit.parent(),
        false,
    )
    .await?;
    let Some(at) = listing
        .doc
        .entries
        .iter()
        .position(|entry| entry.revision == unit.revision())
    else {
        lock(&cell.units).remove(&key);
        return Err(ApiError::NotFound);
    };
    listing.known[at].ok_or(ApiError::Overloaded)
}

/// The reference a `GET .../files/{file}` names: the unit is dated (one list at most) and the file's own row committed before
/// anything else is asked of upstream. A file that does not exist upstream makes no row.
pub async fn reference_for_file(
    app: &App,
    principal: Option<&Principal>,
    unit: &UnitRef,
    file: &str,
    registry_id: u64,
) -> Result<(ReferenceId, String), ApiError> {
    let rref = unit.rref();
    let name = pname(rref);
    locally_blocked(app, principal, &name, Some(&rref.version))?;
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &name);
    let (id, reference) =
        reference_of(&origins, unit, file, registry_id).ok_or(ApiError::NotFound)?;
    // A binary is also gated by its recipe revision (the client reads the recipe first; asked for directly, a held recipe's binary is held).
    recipe_gate(
        app,
        principal,
        registry_id,
        &origins,
        &cell,
        &unit.parent(),
        false,
    )
    .await?;
    let known = resolve(app, principal, registry_id, unit, &origins, &cell).await?;
    let existing = app.store().get_reference(id).await.map_err(storage_error)?;
    let unit_dated = match known.time {
        Dated::Upstream(micros) => Some(micros),
        Dated::Undated => None,
    };
    let mut dated = unit_dated;
    let filename = reference.filename.clone();
    if existing.is_none() {
        // A unit the policy refuses (held, blocked, flagged) is answered with its reason before anything is asked of the remote about
        // one more of its files, and makes no row: the unit's own anchor row already carries the clock.
        refuse_unless_allowed(app, principal, registry_id, unit, &known, false).await?;
        within_row_bound(app, registry_id, &name).await?;
        // A file other than the anchor is confirmed to exist before it gets a row (a made-up file name makes none), and brings its own
        // `Last-Modified`: a file added to an old revision later waits its own cooldown, never the revision's.
        if file != coords::ANCHOR {
            let Some(file_dated) =
                probe(app, principal, registry_id, reference.upstream_url.clone()).await?
            else {
                return Err(ApiError::NotFound);
            };
            if let (Some(revision), Dated::Upstream(own)) = (unit_dated, file_dated)
                && own > revision
            {
                dated = Some(own);
                let later = Known {
                    time: Dated::Upstream(own),
                    ..known
                };
                refuse_unless_allowed(app, principal, registry_id, unit, &later, false).await?;
            }
        }
    } else if dated.is_none_or(|d| {
        existing
            .as_ref()
            .is_none_or(|row| row.publication_micros.is_some_and(|stored| stored >= d))
    }) {
        // The row exists and holds a date at least as late as the unit's: nothing to write (a date only ever gets later).
        return Ok((id, filename));
    }
    let _gate = row_gate(app, registry_id, &name).await;
    if existing.is_none() {
        within_row_bound(app, registry_id, &name).await?;
    }
    let now = app.clock.now_utc_micros();
    let refresh = ProjectRefresh {
        ecosystem: Ecosystem::Conan,
        name: name.clone(),
        payload: Arc::from(&[][..]),
        validators: UpstreamValidators::default(),
        validated_at_micros: now,
        fetched_at_micros: now,
        references: vec![ReferenceUpsert {
            id,
            reference,
            publication_micros: dated,
            first_seen_micros: Some(known.first_seen.unwrap_or(now)),
        }],
    };
    app.store()
        .commit_request_references_in(registry_id, refresh)
        .await
        .map_err(storage_error)?;
    Ok((id, filename))
}

/// SPEC §9 membership: the file the reference names, if its unit still exists.
pub async fn ensure_fresh_project_in(
    app: &App,
    reference: &ArtifactReference,
    registry_id: u64,
    principal: Option<&Principal>,
) -> Result<Arc<Advertised>, ApiError> {
    // (A row's `filename` starts with the remote's own spelling of the name and the version.)
    let path = format!("v2/conans/{}", reference.filename);
    let (unit, file) = match coords::parse(&path, None) {
        Some(Parsed::RecipeFile(recipe, file)) => (UnitRef::Recipe(recipe), file),
        Some(Parsed::PackageFile(package, file)) => (UnitRef::Package(package), file),
        _ => return Err(ApiError::NotFound),
    };
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &reference.name);
    let (id, own) = reference_of(&origins, &unit, &file, registry_id).ok_or(ApiError::NotFound)?;
    resolve(app, principal, registry_id, &unit, &origins, &cell).await?;
    Ok(Arc::new(Advertised::new([(id, own.filename.as_str())])))
}

/// `.../revisions/{rrev}/files` and `.../revisions/{prev}/files`: the names of the files of a unit the policy allows, nothing else of
/// the remote's document (so no location of the remote reaches a client).
pub async fn serve_files(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    unit: &UnitRef,
) -> Result<Rendered, ApiError> {
    let rref = unit.rref();
    locally_blocked(app, principal, &pname(rref), Some(&rref.version))?;
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &pname(rref));
    recipe_gate(
        app,
        principal,
        registry_id,
        &origins,
        &cell,
        &unit.parent(),
        true,
    )
    .await?;
    let known = resolve(app, principal, registry_id, unit, &origins, &cell).await?;
    refuse_unless_allowed(app, principal, registry_id, unit, &known, true).await?;
    let mut below = unit.below();
    below.push("files".to_owned());
    let url = url_of(&origins, &coords::upstream_segments(&below))?;
    let body = {
        let _places = refresh_places(app, registry_id, principal).await?;
        fetch(
            app,
            principal,
            url,
            JSON,
            app.config.max_metadata_bytes.get().max(DOC_FLOOR_CAP),
        )
        .await?
    };
    let Some(body) = body else {
        return Err(ApiError::NotFound);
    };
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| invalid("a file list"))?;
    let serde_json::Value::Object(mut map) = value else {
        return Err(invalid("a file list"));
    };
    let Some(serde_json::Value::Object(files)) = map.remove("files") else {
        return Err(invalid("a file list"));
    };
    if files.len() > MAX_ENTRIES {
        return Err(invalid("a file list"));
    }
    let names: serde_json::Map<String, serde_json::Value> = files
        .into_iter()
        .filter(|(name, _)| coords::file_ok(name))
        .map(|(name, _)| (name, serde_json::Value::Object(serde_json::Map::new())))
        .collect();
    render(serde_json::json!({ "files": names }))
}

// ------------------------------------------------------------------ search

/// `name/version@user/channel` as the remote prints a reference (`_/_` for none), parsed strictly.
fn parse_result(text: &str) -> Option<Rref> {
    let (head, tail) = text.split_once('@').unwrap_or((text, "_/_"));
    let (name, version) = head.split_once('/')?;
    let (user, channel) = tail.split_once('/')?;
    match coords::parse(
        &format!("v2/conans/{name}/{version}/{user}/{channel}/latest"),
        None,
    ) {
        Some(Parsed::Latest(rref)) => Some(rref),
        _ => None,
    }
}

/// How long a search may judge before it answers 504 (a retry finds what was made: a verdict is kept and renewed). A knob so a test can
/// shorten it (its own test binary).
static JUDGE_WAIT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100_000);

#[cfg(feature = "test-support")]
pub fn set_judge_wait_ms(ms: u64) {
    JUDGE_WAIT_MS.store(ms, std::sync::atomic::Ordering::SeqCst);
}

/// What judging a reference or a package id found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// A revision of it passes.
    Allow,
    /// None does.
    Hold,
    /// Its list is gone or not one document: it is withheld and reported (a header and a log line), the others are still served.
    Unreadable,
}

/// A verdict lives `VERDICT_TTL` from the moment it was made or last read, and at most `VERDICT_LIFE` in all. A retry after a 504 finds what the
/// attempts before it made, if it comes within the time.
fn get_verdict(app: &App, registry_id: u64, key: &[u8; 16]) -> Option<Verdict> {
    let now = app.clock.now_monotonic();
    let retrying = lock(&app.conan.unfinished)
        .get(&registry_id)
        .is_some_and(|until| *until > now);
    let mut verdicts = lock(&app.conan.verdicts);
    let (born, until, verdict) = verdicts.get_mut(key).filter(|(_, until, _)| *until > now)?;
    if retrying {
        *until = (now + VERDICT_TTL).min(*born + VERDICT_LIFE).max(*until);
    }
    Some(*verdict)
}

/// A full table loses what has expired, then its oldest tenth: never everything (a finished judging's verdicts are not wiped by another's).
fn put_verdict(app: &App, key: [u8; 16], verdict: Verdict) {
    let now = app.clock.now_monotonic();
    let mut verdicts = lock(&app.conan.verdicts);
    if verdicts.len() >= MAX_VERDICTS && !verdicts.contains_key(&key) {
        verdicts.retain(|_, (_, until, _)| *until > now);
        if verdicts.len() >= MAX_VERDICTS {
            let mut ages: Vec<(Instant, [u8; 16])> = verdicts
                .iter()
                .map(|(key, (born, ..))| (*born, *key))
                .collect();
            ages.sort_unstable();
            for (_, old) in ages.into_iter().take(MAX_VERDICTS / 10) {
                verdicts.remove(&old);
            }
        }
    }
    verdicts.insert(key, (now, now + VERDICT_TTL, verdict));
}

/// Removes a verdict's flight when the work ends, however it ends (done, failed or dropped with its request).
struct Flight<'a> {
    app: &'a App,
    key: [u8; 16],
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        lock(&self.app.conan.flights).remove(&self.key);
    }
}

fn registry_semaphore(
    map: &std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    registry_id: u64,
    permits: usize,
) -> Arc<tokio::sync::Semaphore> {
    let mut map = lock(map);
    if map.len() >= MAX_GATES && !map.contains_key(&registry_id) {
        map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
    }
    Arc::clone(
        map.entry(registry_id)
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(permits))),
    )
}

/// Reads one list and says what it means for the search: at most `JUDGE_PLACES` of a registry's lists are judged at once (installs keep
/// the other fetch places). A list that is gone or not one document is `Unreadable`; any other failure (the remote down, a timeout) fails.
async fn compute_verdict(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    owner: Option<u64>,
    parent: &Parent,
) -> Result<Verdict, ApiError> {
    // One owner holds at most `OWNER_LANES` judging lanes in all, whichever registries it reads: a caller with junk credentials, which cannot share
    // work, or with two registries of its own, still cannot keep every lane busy for everyone else.
    let _share = match owner {
        Some(owner) => {
            let semaphore = {
                let mut map = lock(&app.conan.owner_judging);
                if map.len() >= 1_024 && !map.contains_key(&owner) {
                    map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
                }
                Arc::clone(
                    map.entry(owner)
                        .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(OWNER_LANES))),
                )
            };
            Some(
                tokio::time::timeout(REFRESH_WAIT, semaphore.acquire_owned())
                    .await
                    .map_err(|_| ApiError::UpstreamTimeout)?
                    .map_err(|_| ApiError::InternalFailure)?,
            )
        }
        None => None,
    };
    let _place = tokio::time::timeout(
        REFRESH_WAIT,
        registry_semaphore(&app.conan.judging, registry_id, JUDGE_PLACES).acquire_owned(),
    )
    .await
    .map_err(|_| ApiError::UpstreamTimeout)?
    .map_err(|_| ApiError::InternalFailure)?;
    let _process = tokio::time::timeout(
        REFRESH_WAIT,
        Arc::clone(&app.conan.judging_total).acquire_owned(),
    )
    .await
    .map_err(|_| ApiError::UpstreamTimeout)?
    .map_err(|_| ApiError::InternalFailure)?;
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &pname(parent.rref()));
    match list_units(app, principal, registry_id, &origins, &cell, parent, true).await {
        Ok(listing) => Ok(
            if listing
                .decisions
                .iter()
                .any(|decision| matches!(decision, Decision::Allow))
            {
                Verdict::Allow
            } else {
                Verdict::Hold
            },
        ),
        Err(ApiError::NotFound | ApiError::UpstreamInvalid) => {
            tracing::warn!(reference = %parent.rref().display(), "a listed reference's revision list is unreadable: it is withheld from the search");
            Ok(Verdict::Unreadable)
        }
        Err(error) => Err(error),
    }
}

/// One verdict, shared: a verdict already made is used, one being made by another request is waited for (the work is done once, whoever
/// asked), else this request makes it. A request that is dropped (its deadline, a client that left) drops its flights; a waiter then makes
/// the verdict itself.
async fn judge_one(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    owner: Option<u64>,
    parent: &Parent,
    key: Option<[u8; 16]>,
) -> Result<Verdict, ApiError> {
    let Some(key) = key else {
        return compute_verdict(app, principal, registry_id, owner, parent).await;
    };
    loop {
        if let Some(verdict) = get_verdict(app, registry_id, &key) {
            return Ok(verdict);
        }
        let role = {
            let mut flights = lock(&app.conan.flights);
            match flights.get(&key) {
                Some(running) => Err(running.clone()),
                None => {
                    let (sender, receiver) = tokio::sync::watch::channel(None);
                    flights.insert(key, receiver);
                    Ok(sender)
                }
            }
        };
        match role {
            Err(mut running) => match running.wait_for(|made| made.is_some()).await {
                Ok(made) => return (*made).ok_or(ApiError::InternalFailure),
                Err(_) => continue,
            },
            Ok(sender) => {
                let _flight = Flight { app, key };
                let verdict = compute_verdict(app, principal, registry_id, owner, parent).await?;
                put_verdict(app, key, verdict);
                let _ = sender.send(Some(verdict));
                return Ok(verdict);
            }
        }
    }
}

/// A search attempt that does not reach its end (the client gave up, a deadline, any error) leaves its registry marked unfinished for two
/// minutes, so the retry renews the verdicts it reads; one that finishes clears the mark (a finished search renews nothing).
struct Attempt<'a> {
    app: &'a App,
    registry_id: u64,
    done: bool,
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        let now = self.app.clock.now_monotonic();
        let mut open = lock(&self.app.conan.unfinished);
        if self.done {
            open.remove(&self.registry_id);
        } else {
            if open.len() >= 1_024 {
                open.retain(|_, until| *until > now);
            }
            open.insert(self.registry_id, now + VERDICT_TTL);
        }
    }
}

#[cfg(feature = "test-support")]
pub fn unfinished_marks(app: &App) -> usize {
    lock(&app.conan.unfinished).len()
}

/// The search slots one request holds: one of the process's 16 and one of its registry's 4, and (with an owner) at most half of each for one
/// owner. Released when the request ends.
struct SearchSlots<'a> {
    app: &'a App,
    registry_id: u64,
    owner: Option<u64>,
    _total: tokio::sync::OwnedSemaphorePermit,
    _registry: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for SearchSlots<'_> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner {
            let key = (self.registry_id, owner);
            let mut per = lock(&self.app.conan.owner_searches);
            if let Some(held) = per.get_mut(&key) {
                *held -= 1;
                if *held == 0 {
                    per.remove(&key);
                }
            }
            let mut total = lock(&self.app.conan.owner_total);
            if let Some(held) = total.get_mut(&owner) {
                *held -= 1;
                if *held == 0 {
                    total.remove(&owner);
                }
            }
        }
    }
}

fn search_slots(
    app: &App,
    registry_id: u64,
    owner: Option<u64>,
) -> Result<SearchSlots<'_>, ApiError> {
    if let Some(owner) = owner {
        // Taken first, given back by `Drop` of the slots (or at once when a later step refuses).
        let mut per = lock(&app.conan.owner_searches);
        let mut total = lock(&app.conan.owner_total);
        if per.get(&(registry_id, owner)).copied().unwrap_or(0) >= OWNER_SEARCHES_PER_REGISTRY
            || total.get(&owner).copied().unwrap_or(0) >= OWNER_SEARCHES_TOTAL
        {
            return Err(ApiError::Overloaded);
        }
        *per.entry((registry_id, owner)).or_default() += 1;
        *total.entry(owner).or_default() += 1;
    }
    let undo = |owner: Option<u64>| {
        if let Some(owner) = owner {
            let mut per = lock(&app.conan.owner_searches);
            if let Some(held) = per.get_mut(&(registry_id, owner)) {
                *held -= 1;
                if *held == 0 {
                    per.remove(&(registry_id, owner));
                }
            }
            let mut total = lock(&app.conan.owner_total);
            if let Some(held) = total.get_mut(&owner) {
                *held -= 1;
                if *held == 0 {
                    total.remove(&owner);
                }
            }
        }
    };
    let Ok(total) = Arc::clone(&app.conan.searches_total).try_acquire_owned() else {
        undo(owner);
        return Err(ApiError::Overloaded);
    };
    let Ok(registry) = registry_semaphore(&app.conan.searches, registry_id, SEARCHES_PER_REGISTRY)
        .try_acquire_owned()
    else {
        undo(owner);
        return Err(ApiError::Overloaded);
    };
    Ok(SearchSlots {
        app,
        registry_id,
        owner,
        _total: total,
        _registry: registry,
    })
}

/// Judges the parents of one batch (no cap below the document's own bound), a few at a time. Credential-free reads share verdicts and the
/// work (verdicts kept two minutes from when they were made); a read with the caller's own credential judges alone and keeps nothing (C1028).
/// All of it is the request's own work and ends with its deadline; what it made stays for the retry.
async fn judge_parents(
    app: &Arc<App>,
    principal: Option<&Principal>,
    registry_id: u64,
    owner: Option<u64>,
    parents: &[Parent],
    deadline: tokio::time::Instant,
    _slots: &SearchSlots<'_>,
) -> Result<Vec<Verdict>, ApiError> {
    use futures_util::TryStreamExt as _;
    let shared = crate::http::credential_read::cache_token(app).is_some();
    let prefix = if shared {
        let (policy, _) = check_policy(app, principal)?;
        Some(digest_of(&[
            &registry_id.to_le_bytes(),
            origin_key(principal).unwrap_or_default().as_bytes(),
            format!("{:?}", policy.policy.fingerprint).as_bytes(),
        ]))
    } else {
        None
    };
    let judged = futures_util::stream::iter(0..parents.len())
        .map(|i| {
            let key = prefix.map(|prefix| digest_of(&[&prefix, parents[i].key().as_bytes()]));
            async move {
                judge_one(app, principal, registry_id, owner, &parents[i], key)
                    .await
                    .map(|verdict| (i, verdict))
            }
        })
        .buffer_unordered(JUDGE_AHEAD)
        .try_collect::<Vec<_>>();
    let judged = tokio::time::timeout_at(deadline, judged)
        .await
        .map_err(|_| ApiError::UpstreamTimeout)??;
    let mut out = vec![Verdict::Hold; parents.len()];
    for (i, verdict) in judged {
        out[i] = verdict;
    }
    Ok(out)
}

/// `v2/conans/search?q=`: the references a policy does not block and that have a revision that passes. The result strings are decoded typed
/// (no `Value` tree, under a big-decode permit only while decoding) and judged in batches of `SEARCH_BATCH`, so what one search holds is its
/// result strings and one batch, whatever the document's size.
pub async fn serve_search(
    app: &Arc<App>,
    principal: Option<&Principal>,
    registry_id: u64,
    owner: Option<u64>,
    pattern: &str,
    ignorecase: Option<bool>,
) -> Result<Rendered, ApiError> {
    let slots = search_slots(app, registry_id, owner)?;
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(JUDGE_WAIT_MS.load(std::sync::atomic::Ordering::Relaxed));
    let origins = origins_for(app, principal)?;
    let mut url = url_of(&origins, &coords::upstream_segments(&["search".to_owned()]))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("q", pattern);
        if let Some(ignorecase) = ignorecase {
            query.append_pair("ignorecase", if ignorecase { "True" } else { "False" });
        }
    }
    let body = {
        let _places = refresh_places(app, registry_id, principal).await?;
        fetch(
            app,
            principal,
            url,
            JSON,
            app.config.max_metadata_bytes.get().max(DOC_FLOOR_CAP),
        )
        .await?
    };
    let Some(body) = body else {
        return Err(ApiError::NotFound);
    };
    #[derive(serde::Deserialize)]
    struct RawSearch {
        results: Vec<String>,
    }
    let results = {
        let _decode = if body.len() > BIG_BODY {
            Some(big_permit(app).await?)
        } else {
            None
        };
        serde_json::from_slice::<RawSearch>(&body)
            .map_err(|_| invalid("a search result"))?
            .results
    };
    drop(body);
    if results.len() > MAX_ENTRIES {
        return Err(invalid("a search result"));
    }
    // Judging starts here: only from now on does a search that stops leave the registry marked unfinished.
    let mut attempt = Attempt {
        app,
        registry_id,
        done: false,
    };
    let mut seen: HashSet<u64> = HashSet::new();
    let (mut kept, mut withheld) = (Vec::new(), 0usize);
    for (batch_at, batch) in results.chunks(SEARCH_BATCH).enumerate() {
        let (policy, now) = check_policy(app, principal)?;
        let mut refs: Vec<(usize, Rref)> = Vec::new();
        for (i, text) in batch.iter().enumerate() {
            // A reference the layout cannot carry, one policy blocks outright, and a repeat are not listed.
            if let Some(rref) = parse_result(text)
                && blocked_outright(&policy, now, &pname(&rref), Some(&rref.version)).is_none()
                && seen.insert(u64::from_le_bytes(
                    digest_of_text(&rref.display())[..8]
                        .try_into()
                        .expect("8 bytes"),
                ))
            {
                refs.push((batch_at * SEARCH_BATCH + i, rref));
            }
        }
        let parents: Vec<Parent> = refs
            .iter()
            .map(|(_, rref)| Parent::Recipe(rref.clone()))
            .collect();
        let verdicts = judge_parents(
            app,
            principal,
            registry_id,
            owner,
            &parents,
            deadline,
            &slots,
        )
        .await?;
        for ((at, rref), verdict) in refs.iter().zip(&verdicts) {
            match verdict {
                Verdict::Unreadable => withheld += 1,
                Verdict::Allow
                    if blocked_outright(&policy, now, &pname(rref), Some(&rref.version))
                        .is_none() =>
                {
                    kept.push(*at)
                }
                _ => {}
            }
        }
    }
    attempt.done = true;
    // What a blocklist published while the verdicts were made blocks is dropped now (a standalone firewall's blocklist is read live here). A
    // managed or shared firewall's change of policy is caught by the route, which admits the request again when the policy's fingerprint changed
    // (src/http/conan_routes.rs); a digest block is enforced when a file is delivered.
    let (policy, now) = check_policy(app, principal)?;
    let listed: Vec<&str> = kept
        .iter()
        .map(|&at| results[at].as_str())
        .filter(|text| {
            parse_result(text).is_some_and(|rref| {
                blocked_outright(&policy, now, &pname(&rref), Some(&rref.version)).is_none()
            })
        })
        .collect();
    #[derive(serde::Serialize)]
    struct Listed<'a> {
        results: Vec<&'a str>,
    }
    let body =
        serde_json::to_vec(&Listed { results: listed }).map_err(|_| ApiError::InternalFailure)?;
    Ok(Rendered {
        body: body.into(),
        content_type: JSON,
        withheld,
    })
}

/// One entry of a binary search as the remote wrote it, reduced to the members Conan reads: `settings` and `options` (objects of plain
/// values), `requires`, `build_requires`, `python_requires` and `conf`, `recipe_hash` and `content` (text). Any other member is dropped; a value
/// inside a kept member is data (an option may be a URL: Conan never fetches from it), so it never drops its key.
fn plain_info(value: serde_json::Value) -> serde_json::Value {
    fn plain(value: &serde_json::Value, depth: usize) -> bool {
        match value {
            serde_json::Value::String(text) => text.len() <= 8192,
            serde_json::Value::Number(_) | serde_json::Value::Bool(_) | serde_json::Value::Null => {
                true
            }
            serde_json::Value::Array(items) => {
                depth < 3 && items.len() <= 4096 && items.iter().all(|item| plain(item, depth + 1))
            }
            serde_json::Value::Object(map) => {
                depth < 3
                    && map.len() <= 4096
                    && map
                        .iter()
                        .all(|(key, item)| key.len() <= 256 && plain(item, depth + 1))
            }
        }
    }
    let serde_json::Value::Object(map) = value else {
        return serde_json::json!({});
    };
    serde_json::Value::Object(
        map.into_iter()
            .filter(|(key, item)| {
                matches!(
                    key.as_str(),
                    "settings"
                        | "options"
                        | "requires"
                        | "build_requires"
                        | "python_requires"
                        | "conf"
                        | "recipe_hash"
                        | "content"
                ) && plain(item, 0)
            })
            .collect(),
    )
}

/// `.../revisions/{rrev}/search`: the binary packages of a recipe revision the policy allows, each with a package revision that passes.
pub async fn serve_package_search(
    app: &Arc<App>,
    principal: Option<&Principal>,
    registry_id: u64,
    owner: Option<u64>,
    recipe: &Recipe,
) -> Result<Rendered, ApiError> {
    let slots = search_slots(app, registry_id, owner)?;
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(JUDGE_WAIT_MS.load(std::sync::atomic::Ordering::Relaxed));
    let unit = UnitRef::Recipe(recipe.clone());
    let rref = unit.rref();
    locally_blocked(app, principal, &pname(rref), Some(&rref.version))?;
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &pname(rref));
    let known = resolve(app, principal, registry_id, &unit, &origins, &cell).await?;
    refuse_unless_allowed(app, principal, registry_id, &unit, &known, true).await?;
    let mut below = unit.below();
    below.push("search".to_owned());
    let url = url_of(&origins, &coords::upstream_segments(&below))?;
    let body = {
        let _places = refresh_places(app, registry_id, principal).await?;
        fetch(
            app,
            principal,
            url,
            JSON,
            app.config.max_metadata_bytes.get().max(DOC_FLOOR_CAP),
        )
        .await?
    };
    let Some(body) = body else {
        return Err(ApiError::NotFound);
    };
    // Typed: the ids and each id's info as the text the remote wrote (no tree of the document); the info of a kept id is read and reduced when the
    // answer is written.
    let packages = {
        // (The permit is held for the decode only.)
        let _decode = if body.len() > BIG_BODY {
            Some(big_permit(app).await?)
        } else {
            None
        };
        serde_json::from_slice::<PackageDoc>(&body)
            .map_err(|_| invalid("a package search"))?
            .0
    };
    drop(body);
    let mut attempt = Attempt {
        app,
        registry_id,
        done: false,
    };
    let (mut kept, mut withheld) = (Vec::new(), 0usize);
    for (batch_at, batch) in packages.chunks(SEARCH_BATCH).enumerate() {
        let parents: Vec<Parent> = batch
            .iter()
            .map(|(pkgid, _)| {
                Parent::Package(Package {
                    recipe: recipe.clone(),
                    pkgid: pkgid.clone(),
                })
            })
            .collect();
        let verdicts = judge_parents(
            app,
            principal,
            registry_id,
            owner,
            &parents,
            deadline,
            &slots,
        )
        .await?;
        for (i, verdict) in verdicts.iter().enumerate() {
            match verdict {
                Verdict::Unreadable => withheld += 1,
                Verdict::Allow => kept.push(batch_at * SEARCH_BATCH + i),
                Verdict::Hold => {}
            }
        }
    }
    attempt.done = true;
    // The answer is written entry by entry (a kept id's info is parsed, reduced and written, then dropped).
    let mut body = Vec::with_capacity(2 + kept.len() * 128);
    body.push(b'{');
    for (n, &at) in kept.iter().enumerate() {
        let (id, info) = &packages[at];
        let info: serde_json::Value =
            serde_json::from_str(info.get()).map_err(|_| ApiError::InternalFailure)?;
        if n > 0 {
            body.push(b',');
        }
        serde_json::to_writer(&mut body, id).map_err(|_| ApiError::InternalFailure)?;
        body.push(b':');
        serde_json::to_writer(&mut body, &plain_info(info))
            .map_err(|_| ApiError::InternalFailure)?;
    }
    body.push(b'}');
    Ok(Rendered {
        body: body.into(),
        content_type: JSON,
        withheld,
    })
}

/// A package search document: `{package id: info}`, read as the ids that are ids and each one's info as the text the remote wrote. More than
/// `MAX_ENTRIES` members is refused.
struct PackageDoc(Vec<(String, Box<serde_json::value::RawValue>)>);

impl<'de> serde::Deserialize<'de> for PackageDoc {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PackageDoc;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a package search")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<PackageDoc, A::Error> {
                let (mut out, mut members, mut seen) = (Vec::new(), 0usize, HashSet::new());
                while let Some(id) = map.next_key::<String>()? {
                    let info: Box<serde_json::value::RawValue> = map.next_value()?;
                    members += 1;
                    if members > MAX_ENTRIES {
                        return Err(serde::de::Error::custom("too many package ids"));
                    }
                    if coords::id_ok(&id)
                        && seen.insert(u64::from_le_bytes(
                            digest_of_text(&id)[..8].try_into().expect("8 bytes"),
                        ))
                    {
                        out.push((id, info));
                    }
                }
                Ok(PackageDoc(out))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

// ------------------------------------------------------------------ the client's own credential

/// `v2/users/authenticate` and `v2/users/check_credentials`: asked of the remote with the caller's own credential (the token a login
/// returns is the remote's, relayed as text and never kept).
pub async fn serve_auth(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    authenticate: bool,
) -> Result<Rendered, ApiError> {
    let origins = origins_for(app, principal)?;
    let segments = [
        "v2",
        "users",
        if authenticate {
            "authenticate"
        } else {
            "check_credentials"
        },
    ]
    .map(str::to_owned);
    let url = url_of(&origins, &segments)?;
    let body = {
        let _places = refresh_places(app, registry_id, principal).await?;
        fetch(app, principal, url, "*/*", AUTH_CAP).await?
    };
    match body {
        Some(body) => Ok(Rendered {
            body,
            content_type: TEXT,
            withheld: 0,
        }),
        None => Err(ApiError::NotFound),
    }
}

// ------------------------------------------------------------------ writes

/// Where an upload of `segments` goes: the registry's own origin, or for the public registry the configured publish URL.
pub struct PublishTarget {
    pub url: Url,
    pub origin: Url,
}

pub fn publish_target(
    app: &App,
    principal: &Principal,
    segments: &[String],
) -> Result<PublishTarget, ApiError> {
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    match principal.registry_origin.as_ref() {
        Some(origin) => {
            let set = OriginSet::selected_npm_with_private(
                origin.clone(),
                principal.registry_private_cidrs.clone(),
            )
            .map_err(|_| ApiError::NotFound)?;
            let url = set
                .url_for(OriginKind::NpmMetadata, &parts)
                .map_err(|_| ApiError::NotFound)?;
            Ok(PublishTarget {
                url,
                origin: origin.clone(),
            })
        }
        None => {
            if !app.origins.conan_publish_configured() {
                return Err(ApiError::NotFound);
            }
            let url = app
                .origins
                .url_for(OriginKind::ConanPublish, &parts)
                .map_err(|_| ApiError::NotFound)?;
            Ok(PublishTarget {
                url,
                origin: app.origins.origin(OriginKind::ConanPublish).clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_revision_time_is_the_publication_time_and_nothing_else_is() {
        assert_eq!(
            dated_of(Some("2024-12-11T16:57:24.862+0000")),
            Dated::Upstream(1_733_936_244_862_000)
        );
        assert_eq!(
            dated_of(Some("2024-12-11T16:57:24.862+00:00")),
            Dated::Upstream(1_733_936_244_862_000)
        );
        assert_eq!(
            dated_of(Some("2024-12-11T16:57:24Z")),
            Dated::Upstream(1_733_936_244_000_000)
        );
        assert_eq!(
            dated_of(Some("2024-12-11T18:57:24+0200")),
            Dated::Upstream(1_733_936_244_000_000)
        );
        assert_eq!(
            dated_of(Some("2024-12-11T16:57:24")),
            Dated::Upstream(1_733_936_244_000_000),
            "no offset is UTC"
        );
        for bad in [
            "",
            "not a date",
            "1970-01-01T00:00:00.000+0000",
            "2024-13-45T99:00:00Z",
        ] {
            assert_eq!(dated_of(Some(bad)), Dated::Undated, "{bad}");
        }
        assert_eq!(dated_of(None), Dated::Undated);
    }

    #[test]
    fn a_revision_list_is_read_strictly() {
        let good = br#"{"reference":"zlib/1.3.1@_/_","revisions":[{"revision":"aaa","time":"2024-01-01T00:00:00.000+0000"},{"revision":"bbb"}]}"#;
        let doc = read_revisions(good, 10).unwrap();
        assert_eq!(
            doc.head,
            vec![("reference".to_owned(), "zlib/1.3.1@_/_".to_owned())]
        );
        assert_eq!(doc.entries.len(), 2);
        assert_eq!(doc.entries[1].dated, Dated::Undated);
        for bad in [
            &br#"[]"#[..],
            br#"{"revisions":{}}"#,
            br#"{"reference":"x"}"#,
            br#"{"revisions":[{"revision":"a/b"}]}"#,
            br#"{"revisions":[{"revision":"aaa"},{"revision":"aaa"}]}"#,
            br#"{"revisions":[{"time":"x"}]}"#,
            br#"{"revisions":[{"revision":"aaa","time":5}]}"#,
            br#"not json"#,
        ] {
            assert!(
                read_revisions(bad, 10).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert!(
            read_revisions(br#"{"revisions":[{"revision":"a"},{"revision":"b"}]}"#, 1).is_err(),
            "too many entries"
        );
    }

    /// R1: the uploader's exemption is for the cooldown (a hold) and nothing else.
    #[test]
    fn only_a_hold_is_exempt_for_an_uploader() {
        assert!(cooldown_only(&Decision::Hold {
            eligible_at_micros: 1
        }));
        for decision in [
            Decision::Allow,
            Decision::Unavailable,
            Decision::Deny(DenyReason::BlockedByOsv),
            Decision::Deny(DenyReason::BlockedPackage),
            Decision::Deny(DenyReason::BlockedVersion),
            Decision::Deny(DenyReason::BlockedDigest),
            Decision::Deny(DenyReason::NoTimestamp),
        ] {
            assert!(!cooldown_only(&decision), "{decision:?}");
        }
    }

    #[test]
    fn a_search_result_is_a_reference_or_nothing() {
        let r = parse_result("zlib/1.3.1@_/_").unwrap();
        assert_eq!(
            (
                r.name.as_str(),
                r.version.as_str(),
                r.user.as_str(),
                r.channel.as_str()
            ),
            ("zlib", "1.3.1", "_", "_")
        );
        assert_eq!(parse_result("zlib/1.3.1").unwrap().user, "_");
        assert_eq!(
            parse_result("mylib/2.0@acme/stable").unwrap().channel,
            "stable"
        );
        for bad in [
            "",
            "zlib",
            "zlib/1.3.1@acme",
            "zlib/1.3.1@_/stable",
            "../x/1@_/_",
            "a b/1@_/_",
            "zlib/1.3.1@_/_/x",
        ] {
            assert!(parse_result(bad).is_none(), "{bad}");
        }
    }
}
