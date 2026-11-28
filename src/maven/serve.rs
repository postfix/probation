//! Maven repository delivery on the shared firewall machinery: `maven-metadata.xml` (artifact, plugin-group and
//! snapshot level) and `archetype-catalog.xml` are filtered by policy, their checksum files are the checksums of what is
//! served, and each file of a version (POM, JAR, classifier files, `.module`, `.asc` and every checksum sidecar) is gated
//! by the decision of the version before a byte is delivered.
//!
//! Identity. The policy key, the blocklist and the OSV key are `groupId:artifactId` as the layout spells it (case is
//! identity), the version is the version directory verbatim. A snapshot file belongs to the directory version
//! (`1.0-SNAPSHOT`, which is what a block or an exception names) but it is aged by its own build
//! (`20200101.120000-17`): the thing that has a publication time is a *unit*, a release version or one snapshot build.
//!
//! Dates. A repository has no per-version document with times. The time of a unit is the `Last-Modified` of its POM (a
//! hosted repository sets it when the file is uploaded, Central when it is synced). It is read (never invented),
//! kept per unit in a bounded in-memory table and committed on the unit's reference rows, only ever later. A unit whose
//! POM carries no usable `Last-Modified` waits on the committed first-seen time; a unit with no POM is dated by the first
//! request for it. No directory listing time, cache age or build time is used.
//!
//! Fan-out. Filtering an artifact's metadata needs one POM per listed version of unknown age. That fan-out is decided
//! before the first call: at most `DATE_CAP` calls per request (more than the 1,956 versions of the largest artifact measured on
//! Maven Central), `DATE_PARALLEL` at a time, newest versions first, and a version still undated after that is withheld (fail
//! closed) until a later request has dated it (the dates are committed, so every request settles more). A version that policy already blocks outright is never fetched.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use url::Url;

use crate::App;
use crate::artifacts::ArtifactReference;
use crate::http::error::{ApiError, storage_error};
use crate::http::logging;
use crate::managed::Principal;
use crate::managed::report::Call;
use crate::maven::coords::{self, FileRef, Level, Side, Unit};
use crate::maven::meta::{self, Edit, Entry, Meta};
use crate::maven::xml;
use crate::policy::{Candidate, Decision, DenyReason, Ecosystem, PublicationTime};
use crate::store::cache::Advertised;
use crate::store::rows::{ProjectRefresh, ReferenceId, ReferenceUpsert};
use crate::upstream::{
    MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError, UpstreamValidators,
};

pub struct Rendered {
    pub body: bytes::Bytes,
    pub content_type: &'static str,
}

const XML: &str = "application/xml";
const TEXT: &str = "text/plain; charset=utf-8";

/// LS-F7: no valid `maven-metadata.xml` is refused before this cap. The largest real one measured
/// (evidence/slice-21.md) is 66 KB for 1,956 versions; 16 MiB is 250 times that.
pub const DOC_FLOOR_CAP: u64 = 16 << 20;
/// `archetype-catalog.xml` of Maven Central is 18.6 MB inflated (440 KB on the wire); 128 MiB is 6.9 times that.
pub const CATALOG_CAP: u64 = 128 << 20;
/// A POM read to date its unit.
const POM_CAP: u64 = 16 << 20;
/// A signature or a checksum relayed from the repository.
const SIDE_CAP: u64 = 1 << 20;
/// Entries per document (versions, builds, plugins, archetypes).
const MAX_ENTRIES: usize = 500_000;
/// Upstream POM calls one metadata request may make (measured: the largest artifact of Maven Central has 1,956 versions), and
/// how many run at once.
pub const DATE_CAP: usize = 2048;
const DATE_PARALLEL: usize = 16;
/// Units remembered per artifact in memory, and artifacts per process.
const MAX_UNITS: usize = 16_384;
const MAX_CELLS: usize = 128;
/// How long a shared-service read trusts that a unit still exists (membership stays current).
const SERVICE_EXISTS_TTL: Duration = Duration::from_secs(5);
/// Metadata refreshes at once, process-wide, and per registry (id 0 is the public one), and how long one waits.
const REFRESHES: usize = 16;
const REFRESHES_PER_REGISTRY: usize = 4;
const REFRESH_WAIT: Duration = Duration::from_secs(30);
/// A document request's whole deadline (every route but a file transfer).
pub const DOCUMENT_DEADLINE: Duration = Duration::from_secs(120);
/// Documents a credential-free read just fetched are kept for a moment, bounded by entries and size.
const RAW_TTL: Duration = Duration::from_secs(5);
const MAX_RAW: usize = 8;
const MAX_RAW_BYTES: usize = 16 << 20;
/// The one catalog kept for a moment (Central's is 18.6 MB; a larger one is read each time).
const MAX_CATALOG_CACHE: usize = 64 << 20;
const MAX_GATES: usize = 256;
/// Rows a project may have beyond which a file of a new version or classifier is refused (a multiple of the bound).
const ROWS_FACTOR: u64 = 5;

/// What a unit is known by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dated {
    /// The repository's own `Last-Modified`, microseconds since the epoch.
    Upstream(i64),
    /// No usable time: only the committed first-seen time can date it.
    Undated,
}

#[derive(Clone, Copy, Debug)]
struct Known {
    time: Dated,
    first_seen: Option<i64>,
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

/// (registry, selected origin, `groupId:artifactId`).
type CellKey = (u64, Option<String>, String);
/// (registry, `groupId:artifactId`).
type GateKey = (u64, String);
/// (registry, selected origin, the document's path).
type RawKey = (u64, Option<String>, String);

/// The process-owned memory: unit tables, shared documents, refresh gates and places. Credential-free reads only
/// share (C1028): a read that carries the caller's own credential reads and fills none of it.
pub struct Shared {
    cells: std::sync::Mutex<HashMap<CellKey, Arc<Cell>>>,
    raw: std::sync::Mutex<HashMap<RawKey, (Instant, bytes::Bytes)>>,
    gates: std::sync::Mutex<HashMap<CellKey, Arc<tokio::sync::Mutex<()>>>>,
    refresh: tokio::sync::Semaphore,
    per_registry: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    /// One archetype catalog (tens of MB) at a time for credential-free reads (the public registry's), process-wide.
    catalog: tokio::sync::Semaphore,
    /// A read that carries the caller's credential holds one slot of ITS registry (and one of a small process-wide pool), never
    /// the public one: a slow private registry cannot keep other registries' catalogs waiting.
    catalog_private: tokio::sync::Semaphore,
    catalog_registries: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    /// One writer per project at a time between the row-bound check and the commit of a new row.
    row_gates: std::sync::Mutex<HashMap<GateKey, Arc<tokio::sync::Mutex<()>>>>,
    /// The catalog a credential-free read just fetched, for `RAW_TTL`: one entry, at most `MAX_CATALOG_CACHE` bytes.
    catalog_doc: std::sync::Mutex<Option<(RawKey, Instant, bytes::Bytes)>>,
}

impl Default for Shared {
    fn default() -> Shared {
        Shared {
            cells: Default::default(),
            raw: Default::default(),
            gates: Default::default(),
            refresh: tokio::sync::Semaphore::new(REFRESHES),
            per_registry: Default::default(),
            catalog: tokio::sync::Semaphore::new(1),
            catalog_private: tokio::sync::Semaphore::new(4),
            catalog_registries: Default::default(),
            row_gates: Default::default(),
            catalog_doc: Default::default(),
        }
    }
}

/// The sizes of the process-owned tables (cells, raw documents, gates), so a test can assert each stays bounded.
pub fn table_sizes(app: &App) -> [usize; 3] {
    [
        lock(&app.maven.cells).len(),
        lock(&app.maven.raw).len(),
        lock(&app.maven.gates).len(),
    ]
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
    let mut cells = lock(&app.maven.cells);
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

/// A place to refresh in: this registry's share first (so a registry out of places queues without holding a global one),
/// then a process-wide one.
async fn refresh_places(
    app: &App,
    registry_id: u64,
) -> Result<
    (
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::SemaphorePermit<'_>,
    ),
    ApiError,
> {
    tokio::time::timeout(REFRESH_WAIT, async {
        let own =
            {
                let mut map = lock(&app.maven.per_registry);
                if map.len() >= MAX_GATES && !map.contains_key(&registry_id) {
                    map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
                }
                Arc::clone(map.entry(registry_id).or_insert_with(|| {
                    Arc::new(tokio::sync::Semaphore::new(REFRESHES_PER_REGISTRY))
                }))
            };
        let own = own
            .acquire_owned()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        let place = app
            .maven
            .refresh
            .acquire()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        Ok::<_, ApiError>((own, place))
    })
    .await
    .map_err(|_| ApiError::UpstreamTimeout)?
}

/// One request at a time computes one artifact's listing (credential-free reads): the others wait and then find the dates
/// it committed. A read that carries the caller's credential shares nothing and takes no gate.
async fn single_flight(
    app: &App,
    key: &CellKey,
) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, ApiError> {
    if crate::http::credential_read::cache_token(app).is_none() {
        return Ok(None);
    }
    let gate = {
        let mut gates = lock(&app.maven.gates);
        if gates.len() >= MAX_GATES && !gates.contains_key(key) {
            gates.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        Arc::clone(gates.entry(key.clone()).or_default())
    };
    tokio::time::timeout(REFRESH_WAIT, gate.lock_owned())
        .await
        .map(Some)
        .map_err(|_| ApiError::UpstreamTimeout)
}

// ------------------------------------------------------------------ origins

/// The origin set a request reads through and the kind its URLs are built under.
struct Origins {
    set: OriginSet,
    kind: OriginKind,
}

fn origins_for(app: &App, principal: Option<&Principal>) -> Result<Origins, ApiError> {
    match principal.and_then(|p| p.registry_origin.as_ref()) {
        // A selected registry's origin (its repository root, path included) travels in the slot
        // `selected_npm_with_private` fills.
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
            kind: OriginKind::MavenRepo,
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

// ------------------------------------------------------------------ upstream

fn status_error(app: &App, error: UpstreamError) -> ApiError {
    match error {
        UpstreamError::Status(401) if app.service_policy().is_some() => {
            ApiError::UpstreamUnauthenticated
        }
        UpstreamError::Status(403) if app.service_policy().is_some() => ApiError::UpstreamDenied,
        UpstreamError::Timeout => ApiError::UpstreamTimeout,
        other => {
            tracing::warn!(error = %other, "the Maven repository fetch failed");
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
) -> Result<Option<(bytes::Bytes, UpstreamValidators)>, ApiError> {
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
    app.upstreams.record_upstream(Call::Maven, &fetched);
    match fetched {
        Ok(MetadataResponse::Fresh { body, validators }) => Ok(Some((body, validators))),
        Ok(MetadataResponse::Missing) => Ok(None),
        Ok(MetadataResponse::NotModified { .. }) => Err(ApiError::UpstreamInvalid),
        Err(error) => Err(status_error(app, error)),
    }
}

/// Whether a file exists upstream and its own `Last-Modified`, asked without reading its body.
async fn probe_dated(
    app: &App,
    principal: Option<&Principal>,
    url: Url,
) -> Result<Option<Dated>, ApiError> {
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
    app.upstreams.record_upstream(Call::Maven, &fetched);
    match fetched {
        Ok(Some(validators)) => Ok(Some(dated_of(&validators))),
        Ok(None) => Ok(None),
        Err(error) => Err(status_error(app, error)),
    }
}

/// `Last-Modified` as a publication time: absent or unparseable is no date (the unit then waits on first-seen, which is
/// never earlier than the truth).
pub fn dated_of(validators: &UpstreamValidators) -> Dated {
    let Some(text) = validators.last_modified.as_deref() else {
        return Dated::Undated;
    };
    match jiff::fmt::rfc2822::DateTimeParser::new().parse_timestamp(text.trim()) {
        Ok(at) if at.as_second() > 0 => Dated::Upstream(at.as_microsecond()),
        _ => Dated::Undated,
    }
}

// ------------------------------------------------------------------ references

fn reference_of(
    origins: &Origins,
    group: &str,
    artifact: &str,
    version: &str,
    file: &str,
    registry_id: u64,
) -> Option<(ReferenceId, ArtifactReference)> {
    let mut segments: Vec<String> = group.split('.').map(str::to_owned).collect();
    segments.push(artifact.to_owned());
    segments.push(version.to_owned());
    segments.push(file.to_owned());
    let url = url_of(origins, &segments).ok()?;
    let reference = ArtifactReference {
        ecosystem: Ecosystem::Maven,
        name: format!("{group}:{artifact}"),
        version: version.to_owned(),
        filename: file.to_owned(),
        upstream_url: url,
        // A repository's checksum files are the client's check (it fetches them through this firewall); the first verified
        // download pins the digests (SPEC §9, STATE-01).
        expected: Vec::new(),
    };
    Some((
        ReferenceId::compute_in_registry(registry_id, &reference),
        reference,
    ))
}

/// One unit's anchor (its POM) as a reference.
fn anchor_of(
    origins: &Origins,
    group: &str,
    artifact: &str,
    unit: &Unit,
    registry_id: u64,
) -> Option<(ReferenceId, ArtifactReference)> {
    reference_of(
        origins,
        group,
        artifact,
        &unit.version,
        &unit.anchor(artifact),
        registry_id,
    )
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
        ecosystem: Ecosystem::Maven,
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
                ecosystem: Ecosystem::Maven,
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

// ------------------------------------------------------------------ units

/// Commits the anchors of every `(unit, anchor, dated)` once and remembers what was learned. A date can only get later
/// (the later of what this process saw, what the row already holds and what the repository says now: a throwaway table of
/// a credential-bearing read, an evicted table or a restart cannot make a unit look older).
async fn record(
    app: &App,
    registry_id: u64,
    name: &str,
    cell: &Cell,
    items: &[(String, ReferenceId, ArtifactReference, Dated)],
) -> Result<Vec<Known>, ApiError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let now = app.clock.now_utc_micros();
    let mono = app.clock.now_monotonic();
    let mut stored = Vec::with_capacity(items.len());
    for (_, id, ..) in items {
        let row = app
            .store()
            .get_reference(*id)
            .await
            .map_err(storage_error)?;
        stored.push(row.and_then(|row| row.publication_micros));
    }
    let merged: Vec<Dated> = {
        let units = lock(&cell.units);
        items
            .iter()
            .zip(stored)
            .map(|((key, _, _, dated), stored)| {
                let remembered = match units.get(key).map(|known| known.time) {
                    Some(Dated::Upstream(micros)) => Some(micros),
                    _ => None,
                };
                let upstream = match dated {
                    Dated::Upstream(micros) => Some(*micros),
                    Dated::Undated => None,
                };
                match [remembered, stored, upstream].into_iter().flatten().max() {
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
    // Reference identity, first-seen times and pins only: no response body is retained (C1028); the unit table above is
    // the only metadata memory.
    let committed = app
        .store()
        .commit_request_references_in(
            registry_id,
            ProjectRefresh {
                ecosystem: Ecosystem::Maven,
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
    let mut learned = Vec::with_capacity(items.len());
    let mut units = lock(&cell.units);
    if units.len() + items.len() > MAX_UNITS {
        // ponytail: an artifact with more than 16,384 units in play forgets them all and re-asks the store; a bounded LRU
        // if that ever measures.
        units.clear();
    }
    for ((key, id, ..), dated) in items.iter().zip(merged) {
        let known = Known {
            time: dated,
            first_seen: committed.first_seen.get(id).copied(),
            checked: mono,
        };
        units.insert(key.clone(), known);
        learned.push(known);
    }
    Ok(learned)
}

/// The unit's table entry, confirmed to exist within the freshness window: from memory, else one POM. `probe` is the file a
/// request asked for: a unit with no POM (a bare jar) exists when that file does, and is undated.
async fn resolve(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    fr: &FileRef,
    origins: &Origins,
    cell: &Cell,
    probe: Option<Url>,
) -> Result<Known, ApiError> {
    let unit = fr.unit();
    let key = unit.key();
    let mono = app.clock.now_monotonic();
    if let Some(known) = lock(&cell.units).get(&key).copied()
        && mono.saturating_duration_since(known.checked) < exists_ttl(app)
    {
        return Ok(known);
    }
    let (id, reference) = anchor_of(origins, &fr.group, &fr.artifact, &unit, registry_id)
        .ok_or(ApiError::NotFound)?;
    // The row bound is hard: a unit that has no anchor row yet gets none past it (a POM of a fresh version is a 503 at the bound).
    // Checked before anything is fetched, and again under the project's gate right before the row is committed.
    let has_row = app
        .store()
        .get_reference(id)
        .await
        .map_err(storage_error)?
        .is_some();
    if !has_row {
        within_row_bound(app, registry_id, &fr.name()).await?;
    }
    let dated = match fetch(
        app,
        principal,
        reference.upstream_url.clone(),
        "*/*",
        POM_CAP,
    )
    .await?
    {
        Some((_, validators)) => dated_of(&validators),
        None => {
            let present = match probe {
                Some(url) => probe_dated(app, principal, url).await?.is_some(),
                None => false,
            };
            if !present {
                lock(&cell.units).remove(&key);
                return Err(ApiError::NotFound);
            }
            Dated::Undated
        }
    };
    let _gate = row_gate(app, registry_id, &fr.name()).await;
    if !has_row
        && app
            .store()
            .get_reference(id)
            .await
            .map_err(storage_error)?
            .is_none()
    {
        within_row_bound(app, registry_id, &fr.name()).await?;
    }
    let learned = record(
        app,
        registry_id,
        &fr.name(),
        cell,
        &[(key, id, reference, dated)],
    )
    .await?;
    learned.into_iter().next().ok_or(ApiError::InternalFailure)
}

/// The project's row gate: held from the bound check to the commit of the rows it admits, so simultaneous first requests cannot
/// each see room for the same last row. (Per process: one firewall owns its store.)
async fn row_gate(app: &App, registry_id: u64, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
    let gate = {
        let mut gates = lock(&app.maven.row_gates);
        let key = (registry_id, name.to_owned());
        if gates.len() >= 1024 && !gates.contains_key(&key) {
            gates.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        Arc::clone(gates.entry(key).or_default())
    };
    gate.lock_owned().await
}

/// A project may hold at most `ROWS_FACTOR` times `max_references_per_project` reference rows: past it a new row is a 503.
async fn within_row_bound(app: &App, registry_id: u64, name: &str) -> Result<(), ApiError> {
    let rows = app
        .store()
        .count_project_references_in(registry_id, Ecosystem::Maven, name)
        .await
        .map_err(storage_error)?;
    if rows >= ROWS_FACTOR * u64::from(app.config.max_references_per_project.get()) {
        tracing::warn!(package = %name, rows, "a project is at its reference row bound: a file of one more version or classifier is refused");
        return Err(ApiError::Overloaded);
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
        ecosystem: Ecosystem::Maven,
        name,
        version,
        publication: known.publication(),
        advertised_digests: &[],
        pinned_digests: pinned,
    }
}

// ------------------------------------------------------------------ files

/// The reference a `GET {group}/{artifact}/{version}/{file}` names: the unit is dated (one POM at most) and the file's own
/// row committed before anything else is asked of upstream. A file that does not exist upstream makes no row.
pub async fn reference_for_file(
    app: &App,
    principal: Option<&Principal>,
    fr: &FileRef,
    registry_id: u64,
) -> Result<(ReferenceId, String), ApiError> {
    let name = fr.name();
    locally_blocked(app, principal, &name, Some(&fr.version))?;
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &name);
    let (id, reference) = reference_of(
        &origins,
        &fr.group,
        &fr.artifact,
        &fr.version,
        &fr.file,
        registry_id,
    )
    .ok_or(ApiError::NotFound)?;
    let known = resolve(
        app,
        principal,
        registry_id,
        fr,
        &origins,
        &cell,
        Some(reference.upstream_url.clone()),
    )
    .await?;
    let existing = app.store().get_reference(id).await.map_err(storage_error)?;
    let unit_dated = match known.time {
        Dated::Upstream(micros) => Some(micros),
        Dated::Undated => None,
    };
    let mut dated = unit_dated;
    if existing.is_none() {
        // A unit the policy refuses (held, blocked, flagged) is answered with its reason before anything is asked of the
        // repository about one more of its files, and makes no row: the unit's own anchor row already carries the clock.
        refuse_unless_allowed(app, principal, registry_id, &name, &fr.version, &known).await?;
        within_row_bound(app, registry_id, &name).await?;
        // (Checked again under the project's gate right before the row is committed, below.)
        // The unit's own anchor was just read; any other file is confirmed to exist before it gets a row (a made-up file name
        // makes none) and brings its own `Last-Modified`: a file added to an old version later (a new classifier) waits its own
        // cooldown, never the POM's.
        if fr.file != unit_anchor_name(fr) {
            let Some(file_dated) =
                probe_dated(app, principal, reference.upstream_url.clone()).await?
            else {
                return Err(ApiError::NotFound);
            };
            if let (Some(unit), Dated::Upstream(file)) = (unit_dated, file_dated)
                && file > unit
            {
                dated = Some(file);
                let later = Known {
                    time: Dated::Upstream(file),
                    ..known
                };
                refuse_unless_allowed(app, principal, registry_id, &name, &fr.version, &later)
                    .await?;
            }
        }
        if fr.file.ends_with(".module") {
            module_stays_inside(app, principal, reference.upstream_url.clone()).await?;
        }
    } else if dated.is_none_or(|d| {
        existing
            .as_ref()
            .is_none_or(|row| row.publication_micros.is_some_and(|stored| stored >= d))
    }) {
        // The row exists and holds a date at least as late as the unit's: nothing to write (a date only ever gets later, and a file
        // that is later than its unit keeps its own).
        return Ok((id, fr.file.clone()));
    }
    let _gate = row_gate(app, registry_id, &name).await;
    if existing.is_none() {
        within_row_bound(app, registry_id, &name).await?;
    }
    let now = app.clock.now_utc_micros();
    let refresh = ProjectRefresh {
        ecosystem: Ecosystem::Maven,
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
    Ok((id, fr.file.clone()))
}

/// The decision of one unit as the artifact pipeline will take it; anything but Allow is answered (and logged for a managed key) now.
async fn refuse_unless_allowed(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    name: &str,
    version: &str,
    known: &Known,
) -> Result<(), ApiError> {
    let (policy, now) = check_policy(app, principal)?;
    let decision = crate::osv::evaluate_scoped(
        &app.osv,
        &policy,
        now,
        &candidate(name, version, known, &[]),
        app.osv_scope(registry_id),
    )
    .await;
    if matches!(decision, Decision::Allow) {
        return Ok(());
    }
    if let (Some(principal), Some(managed)) = (principal, app.managed()) {
        managed.record_refused(
            principal,
            &policy,
            now,
            &candidate(name, version, known, &[]),
            decision,
            true,
        );
    }
    Err(crate::artifacts::decision_error(decision, now))
}

/// Gradle Module Metadata may name files by absolute URL (`files[].url`, `available-at.url`): a `.module` that points outside this
/// repository would send the client to a host no decision here covers. One that does is refused; a relative URL (the normal form) is not.
async fn module_stays_inside(
    app: &App,
    principal: Option<&Principal>,
    url: Url,
) -> Result<(), ApiError> {
    let Some((body, _)) = fetch(app, principal, url, "application/json", POM_CAP).await? else {
        return Err(ApiError::NotFound);
    };
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| invalid("a Gradle module file"))?;
    if names_outside(&value) {
        return Err(ApiError::Blocked {
            reason: "the module metadata names a location outside this repository",
        });
    }
    Ok(())
}

fn names_outside(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            (key == "url" && value.as_str().is_some_and(absolute_url)) || names_outside(value)
        }),
        serde_json::Value::Array(items) => items.iter().any(names_outside),
        _ => false,
    }
}

/// A scheme (`https:`, `file:`), a network-path reference (`//host`) or a backslash form: anything but a relative path.
fn absolute_url(text: &str) -> bool {
    text.starts_with("//")
        || text.starts_with('\\')
        || text
            .split('/')
            .next()
            .is_some_and(|first| first.contains(':'))
}

fn unit_anchor_name(fr: &FileRef) -> String {
    fr.unit().anchor(&fr.artifact)
}

/// SPEC §9 membership: the file the reference names, if its unit still exists.
pub async fn ensure_fresh_project_in(
    app: &App,
    reference: &ArtifactReference,
    registry_id: u64,
    principal: Option<&Principal>,
) -> Result<Arc<Advertised>, ApiError> {
    let (group, artifact) = reference.name.split_once(':').ok_or(ApiError::NotFound)?;
    let path = format!(
        "{}/{artifact}/{}/{}",
        group.replace('.', "/"),
        reference.version,
        reference.filename
    );
    let Some(coords::Parsed::File(fr)) = coords::parse(&path) else {
        return Err(ApiError::NotFound);
    };
    let origins = origins_for(app, principal)?;
    let cell = cell_for(app, registry_id, principal, &reference.name);
    let (id, own) = reference_of(
        &origins,
        &fr.group,
        &fr.artifact,
        &fr.version,
        &fr.file,
        registry_id,
    )
    .ok_or(ApiError::NotFound)?;
    resolve(
        app,
        principal,
        registry_id,
        &fr,
        &origins,
        &cell,
        Some(own.upstream_url),
    )
    .await?;
    Ok(Arc::new(Advertised::new([(id, fr.file.as_str())])))
}

// ------------------------------------------------------------------ listings

struct Listed {
    key: String,
    id: ReferenceId,
    reference: ArtifactReference,
    ids: [Option<ReferenceId>; 2],
}

/// The decision of each unit of a listing, dating those of unknown age first (bounded, newest first).
#[allow(clippy::too_many_arguments)]
async fn judge_units(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    group: &str,
    artifact: &str,
    origins: &Origins,
    cell: &Cell,
    units: &[Unit],
) -> Result<Vec<Decision>, ApiError> {
    let (policy, now) = check_policy(app, principal)?;
    let name = format!("{group}:{artifact}");
    let listed: Vec<Option<Listed>> = units
        .iter()
        .map(|unit| {
            let (id, reference) = anchor_of(origins, group, artifact, unit, registry_id)?;
            let jar = reference_of(
                origins,
                group,
                artifact,
                &unit.version,
                &format!("{artifact}-{}.jar", unit.file_version()),
                registry_id,
            )
            .map(|(id, _)| id);
            Some(Listed {
                key: unit.key(),
                id,
                reference,
                ids: [Some(id), jar],
            })
        })
        .collect();
    // After a restart or an eviction the table is empty but the store still holds every date it recorded: seed from it.
    let stored = app
        .store()
        .list_project_publications_in(registry_id, Ecosystem::Maven, &name)
        .await
        .map_err(storage_error)?;
    let mono = app.clock.now_monotonic();
    {
        let mut table = lock(&cell.units);
        for item in listed.iter().flatten() {
            if table.len() >= MAX_UNITS {
                break;
            }
            if let (false, Some(micros)) = (table.contains_key(&item.key), stored.get(&item.id)) {
                table.insert(
                    item.key.clone(),
                    Known {
                        time: Dated::Upstream(*micros),
                        first_seen: None,
                        checked: mono,
                    },
                );
            }
        }
    }
    // Units of unknown age, newest first (a repository lists oldest to newest), bounded before the first call.
    let missing: Vec<usize> = {
        let table = lock(&cell.units);
        (0..units.len())
            .rev()
            .filter(|&i| {
                listed[i]
                    .as_ref()
                    .is_some_and(|item| !table.contains_key(&item.key))
            })
            .collect()
    };
    // The rows one project may hold bound its dating too: an artifact (a hostile registry's) that lists more versions than the project
    // may keep rows for is dated only up to the bound, and the rest wait (fail closed) like any undated version.
    let rows = app
        .store()
        .count_project_references_in(registry_id, Ecosystem::Maven, &name)
        .await
        .map_err(storage_error)?;
    let room = (ROWS_FACTOR * u64::from(app.config.max_references_per_project.get()))
        .saturating_sub(rows) as usize;
    let wanted: Vec<usize> = missing
        .into_iter()
        .filter(|&i| blocked_outright(&policy, now, &name, Some(&units[i].version)).is_none())
        .take(DATE_CAP.min(room))
        .collect();
    let fetched: Vec<(usize, Result<Option<Dated>, ApiError>)> = futures_util::stream::iter(wanted)
        .map(|i| {
            let item = listed[i].as_ref().expect("filtered above");
            let url = item.reference.upstream_url.clone();
            async move {
                (
                    i,
                    fetch(app, principal, url, "*/*", POM_CAP)
                        .await
                        .map(|found| found.map(|(_, validators)| dated_of(&validators))),
                )
            }
        })
        .buffer_unordered(DATE_PARALLEL)
        .collect()
        .await;
    let mut items: Vec<(String, ReferenceId, ArtifactReference, Dated)> = Vec::new();
    for (i, result) in fetched {
        match result {
            Ok(Some(dated)) => {
                let item = listed[i].as_ref().expect("filtered above");
                items.push((item.key.clone(), item.id, item.reference.clone(), dated));
            }
            // A listed version with no POM (a bare jar on a private repository) is not cut for ever: it gets its first-seen row now
            // and ages like any undated unit (its files are confirmed to exist when one is asked for).
            Ok(None) => {
                let item = listed[i].as_ref().expect("filtered above");
                items.push((
                    item.key.clone(),
                    item.id,
                    item.reference.clone(),
                    Dated::Undated,
                ));
            }
            // Withheld, not fatal: one failed call never hides its neighbours.
            Err(error) => tracing::warn!(
                ?error,
                "a unit of the listing could not be dated and is withheld"
            ),
        }
    }
    {
        // Room is counted again under the project's gate, so listings and file requests together never pass the bound.
        let _gate = row_gate(app, registry_id, &name).await;
        let rows = app
            .store()
            .count_project_references_in(registry_id, Ecosystem::Maven, &name)
            .await
            .map_err(storage_error)?;
        let room = (ROWS_FACTOR * u64::from(app.config.max_references_per_project.get()))
            .saturating_sub(rows) as usize;
        items.truncate(room);
        record(app, registry_id, &name, cell, &items).await?;
    }
    let pins = app
        .store()
        .list_project_pins_in(registry_id, Ecosystem::Maven, &name)
        .await
        .map_err(storage_error)?;
    let scope = app.osv_scope(registry_id);
    let known: Vec<Option<Known>> = {
        let table = lock(&cell.units);
        listed
            .iter()
            .map(|item| item.as_ref().and_then(|item| table.get(&item.key).copied()))
            .collect()
    };
    let decisions = futures_util::future::join_all(units.iter().enumerate().map(|(i, unit)| {
        let (policy, pins, known, listed, name) = (&policy, &pins, &known, &listed, &name);
        async move {
            let (Some(known), Some(item)) = (known[i], listed[i].as_ref()) else {
                // Undated: withheld, for the reason policy gives a version with no date (a blocked name or version says so).
                let undated = Candidate {
                    ecosystem: Ecosystem::Maven,
                    name,
                    version: &unit.version,
                    publication: PublicationTime::Unknown,
                    advertised_digests: &[],
                    pinned_digests: &[],
                };
                return crate::policy::decide(policy, &undated, now, false).decision;
            };
            let pinned: Vec<crate::policy::Digest> = item
                .ids
                .iter()
                .flatten()
                .flat_map(|id| pins.get(id).into_iter().flatten().cloned())
                .collect();
            crate::osv::evaluate_scoped(
                &app.osv,
                policy,
                now,
                &candidate(name, &unit.version, &known, &pinned),
                scope,
            )
            .await
        }
    }))
    .await;
    Ok(decisions)
}

fn record_refused_listing(
    app: &App,
    principal: Option<&Principal>,
    name: &str,
    version: &str,
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
    let candidate = Candidate {
        ecosystem: Ecosystem::Maven,
        name,
        version,
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    let verdict = crate::managed::refused_verdict(&policy, now, &candidate, *decision);
    managed.record_decision(principal, Ecosystem::Maven, name, None, &verdict);
}

fn invalid(what: &'static str) -> ApiError {
    tracing::warn!(what, "the repository's document is unusable");
    ApiError::UpstreamInvalid
}

fn is_snapshot(version: &str) -> bool {
    version.ends_with("-SNAPSHOT")
}

/// The document filtered for policy, and whether it differs from the repository's bytes.
struct Filtered {
    body: Vec<u8>,
    changed: bool,
}

/// A document nothing was removed from is served as the repository wrote it (whatever its encoding), so its signature still holds.
fn unchanged_is_original(filtered: Filtered, original: &[u8]) -> Filtered {
    if filtered.changed {
        filtered
    } else {
        Filtered {
            body: original.to_vec(),
            changed: false,
        }
    }
}

fn finish(original: &[u8], edits: Vec<Edit>) -> Filtered {
    if edits.is_empty() {
        return Filtered {
            body: original.to_vec(),
            changed: false,
        };
    }
    let body = meta::apply(original, edits);
    Filtered {
        changed: body != original,
        body,
    }
}

/// `groupId`'s plugin prefixes (`mvn compiler:compile`): a plugin whose package a policy blocks is not listed.
fn filter_plugins(
    app: &App,
    principal: Option<&Principal>,
    group: &str,
    doc: &[u8],
    meta: &Meta,
) -> Result<Filtered, ApiError> {
    let (policy, now) = check_policy(app, principal)?;
    let mut edits = Vec::new();
    for plugin in &meta.plugins {
        let name = format!("{group}:{}", plugin.value);
        if plugin.value.is_empty()
            || !coords::artifact_ok(&plugin.value)
            || blocked_outright(&policy, now, &name, None).is_some()
        {
            edits.push(meta::cut(doc, plugin.span));
        }
    }
    Ok(finish(doc, edits))
}

/// An artifact's `maven-metadata.xml`.
#[allow(clippy::too_many_arguments)]
async fn filter_artifact(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    group: &str,
    artifact: &str,
    origins: &Origins,
    cell: &Cell,
    doc: &[u8],
    meta: &Meta,
) -> Result<Filtered, ApiError> {
    let name = format!("{group}:{artifact}");
    // Versions the layout can carry, once each, in the repository's order; anything else is never delivered.
    let mut seen = HashSet::new();
    let entries: Vec<(&Entry, bool)> = meta
        .versions
        .iter()
        .map(|entry| {
            (
                entry,
                coords::version_ok(&entry.value) && seen.insert(entry.value.as_str()),
            )
        })
        .collect();
    let units: Vec<Unit> = entries
        .iter()
        .filter(|(entry, ok)| *ok && !is_snapshot(&entry.value))
        .map(|(entry, _)| Unit {
            version: entry.value.clone(),
            build: None,
        })
        .collect();
    let (policy, now) = check_policy(app, principal)?;
    let decisions = judge_units(
        app,
        principal,
        registry_id,
        group,
        artifact,
        origins,
        cell,
        &units,
    )
    .await?;
    let by_version: HashMap<&str, Decision> = units
        .iter()
        .zip(&decisions)
        .map(|(unit, decision)| (unit.version.as_str(), *decision))
        .collect();
    // A snapshot directory is a container: its builds are judged one by one (version-level metadata and their files), so it
    // is listed unless a block names it.
    let allowed = |version: &str| -> bool {
        if is_snapshot(version) {
            blocked_outright(&policy, now, &name, Some(version)).is_none()
        } else {
            matches!(by_version.get(version), Some(Decision::Allow))
        }
    };
    let mut edits = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    for (entry, ok) in &entries {
        if *ok && allowed(&entry.value) {
            kept.push(&entry.value);
        } else {
            edits.push(meta::cut(doc, entry.span));
        }
    }
    let newest = |releases_only: bool| {
        kept.iter()
            .rev()
            .find(|version| !releases_only || !is_snapshot(version))
            .copied()
    };
    for (text, releases_only) in [(&meta.latest, false), (&meta.release, true)] {
        let Some(text) = text else { continue };
        if kept.contains(&text.value.as_str()) {
            continue;
        }
        match newest(releases_only) {
            Some(version) => edits.push(meta::replace_text(text, version)),
            None => {
                // No version is left to name: the element goes (its tags are on one line by the format).
                if let Some(edit) = element_around(doc, text.inner) {
                    edits.push(edit);
                }
            }
        }
    }
    if !entries.is_empty() && kept.is_empty() {
        record_refused_listing(
            app,
            principal,
            &name,
            entries[0].0.value.as_str(),
            &decisions,
        );
    }
    Ok(finish(doc, edits))
}

/// The whole element whose text is `inner`: from its `<` to the `>` of its end tag.
fn element_around(doc: &[u8], inner: (usize, usize)) -> Option<Edit> {
    let start = doc[..inner.0].iter().rposition(|b| *b == b'<')?;
    let end = inner.1 + doc[inner.1..].iter().position(|b| *b == b'>')? + 1;
    Some(meta::cut(doc, (start, end)))
}

/// A snapshot version's `maven-metadata.xml`: each build is judged, `snapshotVersions` entries of a withheld build are cut and
/// the `snapshot` pointer names the newest build that remains.
#[allow(clippy::too_many_arguments)]
async fn filter_snapshot(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    group: &str,
    artifact: &str,
    version: &str,
    origins: &Origins,
    cell: &Cell,
    doc: &[u8],
    meta: &Meta,
) -> Result<Filtered, ApiError> {
    let name = format!("{group}:{artifact}");
    let base = version.strip_suffix("-SNAPSHOT").unwrap_or(version);
    let token_of = |value: &str| -> Option<String> {
        let token = value.strip_prefix(base)?.strip_prefix('-')?;
        coords::parse(&format!(
            "g/{artifact}/{version}/{artifact}-{base}-{token}.pom"
        ))
        .and_then(|parsed| match parsed {
            coords::Parsed::File(file) => file.build,
            _ => None,
        })
    };
    let pointer = match (&meta.snapshot_timestamp, &meta.snapshot_build) {
        (Some(ts), Some(n)) => Some(format!("{}-{}", ts.value, n.value)),
        _ => None,
    };
    // Every distinct build the document names, in the order it names them (the pointer last: it is the newest).
    // (Lookups are by hash: a hostile document names up to the entry bound of distinct builds.)
    let mut builds: Vec<String> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for entry in &meta.snapshot_versions {
        if let Some(token) = token_of(&entry.value)
            && !index.contains_key(&token)
        {
            index.insert(token.clone(), builds.len());
            builds.push(token);
        }
    }
    if let Some(token) = &pointer
        && token_of(&format!("{base}-{token}")).is_some()
        && !index.contains_key(token)
    {
        index.insert(token.clone(), builds.len());
        builds.push(token.clone());
    }
    let units: Vec<Unit> = builds
        .iter()
        .map(|build| Unit {
            version: version.to_owned(),
            build: Some(build.clone()),
        })
        .collect();
    let decisions = judge_units(
        app,
        principal,
        registry_id,
        group,
        artifact,
        origins,
        cell,
        &units,
    )
    .await?;
    let decision_of = |token: &str| index.get(token).map(|i| decisions[*i]);
    let allowed = |token: &str| matches!(decision_of(token), Some(Decision::Allow));
    let mut edits = Vec::new();
    for entry in &meta.snapshot_versions {
        // An entry that is the literal `-SNAPSHOT` name or no build at all is not a build: it is kept unless a block names it.
        match token_of(&entry.value) {
            Some(token) if !allowed(&token) => edits.push(meta::cut(doc, entry.span)),
            None if entry.value != version && !entry.value.is_empty() => {
                edits.push(meta::cut(doc, entry.span))
            }
            _ => {}
        }
    }
    if let Some(token) = &pointer
        && !allowed(token)
    {
        // The newest build is withheld: name the newest one that is not (and say so with its reason when there is none).
        let newest = decisions
            .iter()
            .rposition(|decision| matches!(decision, Decision::Allow))
            .map(|i| &builds[i]);
        match (newest, &meta.snapshot_timestamp, &meta.snapshot_build) {
            (Some(build), Some(ts), Some(n)) => {
                let (stamp, number) = build
                    .split_once('-')
                    .ok_or_else(|| invalid("a snapshot build"))?;
                edits.push(meta::replace_text(ts, stamp));
                edits.push(meta::replace_text(n, number));
            }
            _ => {
                let decision =
                    decision_of(token).unwrap_or(Decision::Deny(DenyReason::BlockedVersion));
                let (_, now) = check_policy(app, principal)?;
                record_refused_listing(app, principal, &name, version, &[decision]);
                return Err(crate::artifacts::decision_error(decision, now));
            }
        }
    }
    Ok(finish(doc, edits))
}

/// `maven-metadata.xml` of `dirs` with its sidecars.
pub async fn serve_metadata(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    dirs: &[String],
    level: Level,
    side: Side,
) -> Result<Rendered, ApiError> {
    let group_only =
        dirs.len() == 1 || (level == Level::Artifact && coords::artifact_of(dirs).is_none());
    let artifact_id = coords::artifact_of(dirs).filter(|_| level == Level::Artifact && !group_only);
    let snapshot_id = coords::snapshot_of(dirs).filter(|_| level == Level::Snapshot);
    // The identity pre-check: a blocked package (or version) costs nothing upstream.
    if let Some((group, artifact)) = &artifact_id {
        locally_blocked(app, principal, &format!("{group}:{artifact}"), None)?;
    }
    if let Some((group, artifact, version)) = &snapshot_id {
        locally_blocked(
            app,
            principal,
            &format!("{group}:{artifact}"),
            Some(version),
        )?;
    }
    let origins = origins_for(app, principal)?;
    let path = coords::metadata_segments(dirs, Side::Doc);
    let url = url_of(&origins, &path)?;
    let cap = app.config.max_metadata_bytes.get().max(DOC_FLOOR_CAP);
    let cell_name = match (&artifact_id, &snapshot_id) {
        (Some((group, artifact)), _) | (_, Some((group, artifact, _))) => {
            format!("{group}:{artifact}")
        }
        _ => dirs.join("."),
    };
    let gate_key = (
        registry_id,
        origin_key(principal),
        format!("{cell_name}@{}", path.join("/")),
    );
    let _gate = single_flight(app, &gate_key).await?;
    let _places = refresh_places(app, registry_id).await?;
    let raw_key = (registry_id, origin_key(principal), path.join("/"));
    let body = match shared_raw(app, &raw_key) {
        Some(body) => Some(body),
        None => {
            let fetched = fetch(app, principal, url, "application/xml", cap)
                .await?
                .map(|(body, _)| body);
            if let Some(body) = &fetched {
                remember_raw(app, raw_key, body);
            }
            fetched
        }
    };
    let Some(original) = body else {
        return Err(ApiError::NotFound);
    };
    // A document declared ISO-8859-1 is read as UTF-8 text (and served so only when something was removed from it).
    let work = xml::to_utf8(&original).map_err(|_| invalid("a metadata document's encoding"))?;
    let body: &[u8] = &work;
    let max = MAX_ENTRIES
        .min((ROWS_FACTOR * u64::from(app.config.max_references_per_project.get())) as usize);
    let meta = meta::read(body, max).map_err(|error| {
        tracing::warn!(?error, "the repository's metadata is unusable");
        ApiError::UpstreamInvalid
    })?;
    if meta.root != "metadata" {
        return Err(invalid("a metadata root"));
    }
    let filtered = if let Some((group, artifact, version)) = &snapshot_id {
        if meta.has_versions || meta.has_plugins {
            return Err(invalid("a snapshot-level document"));
        }
        let cell = cell_for(app, registry_id, principal, &cell_name);
        filter_snapshot(
            app,
            principal,
            registry_id,
            group,
            artifact,
            version,
            &origins,
            &cell,
            body,
            &meta,
        )
        .await?
    } else if meta.has_plugins {
        filter_plugins(app, principal, &dirs.join("."), body, &meta)?
    } else if let Some((group, artifact)) = &artifact_id {
        if meta.snapshot_span.is_some() || !meta.snapshot_versions.is_empty() {
            return Err(invalid("an artifact-level document"));
        }
        let cell = cell_for(app, registry_id, principal, &cell_name);
        filter_artifact(
            app,
            principal,
            registry_id,
            group,
            artifact,
            &origins,
            &cell,
            body,
            &meta,
        )
        .await?
    } else {
        // A group-level path whose document names no plugin: nothing in it is a version, so it is passed on.
        if meta.has_versions || !meta.versions.is_empty() {
            return Err(invalid("a group-level document"));
        }
        Filtered {
            body: body.to_vec(),
            changed: false,
        }
    };
    let filtered = unchanged_is_original(filtered, &original);
    logging::record_cache(logging::CacheStatus::Miss);
    match side {
        Side::Doc => Ok(Rendered {
            body: filtered.body.into(),
            content_type: XML,
        }),
        Side::Sum(sum) => Ok(Rendered {
            body: sum.hex(&filtered.body).into_bytes().into(),
            content_type: TEXT,
        }),
        // A signature is of the repository's bytes: it is relayed only when the served document is those bytes.
        Side::Asc | Side::AscSum(_) if !filtered.changed => {
            let url = url_of(&origins, &coords::metadata_segments(dirs, side))?;
            match fetch(app, principal, url, "*/*", SIDE_CAP).await? {
                Some((body, _)) => Ok(Rendered {
                    body,
                    content_type: TEXT,
                }),
                None => Err(ApiError::NotFound),
            }
        }
        Side::Asc | Side::AscSum(_) => Err(ApiError::NotFound),
    }
}

fn shared_raw(app: &App, key: &RawKey) -> Option<bytes::Bytes> {
    crate::http::credential_read::cache_token(app)?;
    let now = app.clock.now_monotonic();
    lock(&app.maven.raw)
        .get(key)
        .filter(|(at, _)| now.saturating_duration_since(*at) < RAW_TTL)
        .map(|(_, body)| body.clone())
}

fn remember_raw(app: &App, key: RawKey, body: &bytes::Bytes) {
    if crate::http::credential_read::cache_token(app).is_none() || body.len() > MAX_RAW_BYTES {
        return;
    }
    let now = app.clock.now_monotonic();
    let mut raw = lock(&app.maven.raw);
    if raw.len() >= MAX_RAW {
        raw.retain(|_, (at, _)| now.saturating_duration_since(*at) < RAW_TTL);
        if raw.len() >= MAX_RAW {
            raw.clear();
        }
    }
    raw.insert(key, (now, body.clone()));
}

/// `archetype-catalog.xml`: an archetype whose package or version a policy blocks is not listed. (An archetype is a
/// template the client asks for by name and version; the files of the version it names are gated like any other.)
pub async fn serve_catalog(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    side: Side,
) -> Result<Rendered, ApiError> {
    let (policy, now) = check_policy(app, principal)?;
    let origins = origins_for(app, principal)?;
    let url = url_of(&origins, &[coords::CATALOG.to_owned()])?;
    // The one catalog slot is taken BEFORE a refresh place: a request that waits for it holds nothing another document needs.
    // A credential-free read (the public registry's) takes the one process-wide slot; one that carries the caller's credential takes
    // its own registry's slot and one of a few process-wide private ones, so a slow private registry never holds the public slot.
    let shared = crate::http::credential_read::cache_token(app).is_some();
    let own = if shared {
        None
    } else {
        let semaphore = {
            let mut map = lock(&app.maven.catalog_registries);
            if map.len() >= MAX_GATES && !map.contains_key(&registry_id) {
                map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
            }
            Arc::clone(
                map.entry(registry_id)
                    .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1))),
            )
        };
        Some(
            tokio::time::timeout(REFRESH_WAIT, semaphore.acquire_owned())
                .await
                .map_err(|_| ApiError::UpstreamTimeout)?
                .map_err(|_| ApiError::InternalFailure)?,
        )
    };
    let slot = if shared {
        &app.maven.catalog
    } else {
        &app.maven.catalog_private
    };
    let _one = tokio::time::timeout(REFRESH_WAIT, slot.acquire())
        .await
        .map_err(|_| ApiError::UpstreamTimeout)?
        .map_err(|_| ApiError::InternalFailure)?;
    let _own = own;
    let key: RawKey = (
        registry_id,
        origin_key(principal),
        coords::CATALOG.to_owned(),
    );
    let cached = crate::http::credential_read::cache_token(app).and_then(|_| {
        let now = app.clock.now_monotonic();
        lock(&app.maven.catalog_doc)
            .as_ref()
            .filter(|(k, at, _)| *k == key && now.saturating_duration_since(*at) < RAW_TTL)
            .map(|(_, _, body)| body.clone())
    });
    let body = match cached {
        Some(body) => body,
        None => {
            let _places = refresh_places(app, registry_id).await?;
            let Some((body, _)) = fetch(
                app,
                principal,
                url,
                "application/xml",
                app.config.max_metadata_bytes.get().max(CATALOG_CAP),
            )
            .await?
            else {
                return Err(ApiError::NotFound);
            };
            if crate::http::credential_read::cache_token(app).is_some()
                && body.len() <= MAX_CATALOG_CACHE
            {
                *lock(&app.maven.catalog_doc) =
                    Some((key, app.clock.now_monotonic(), body.clone()));
            }
            body
        }
    };
    let original = body;
    let work = xml::to_utf8(&original).map_err(|_| invalid("an archetype catalog encoding"))?;
    let body: &[u8] = &work;
    let meta = meta::read(body, MAX_ENTRIES).map_err(|error| {
        tracing::warn!(?error, "the repository's archetype catalog is unusable");
        ApiError::UpstreamInvalid
    })?;
    if meta.root != "archetype-catalog" {
        return Err(invalid("an archetype catalog"));
    }
    let mut edits = Vec::new();
    for archetype in &meta.archetypes {
        let (Some(group), Some(artifact)) =
            (archetype.field("groupId"), archetype.field("artifactId"))
        else {
            edits.push(meta::cut(body, archetype.span));
            continue;
        };
        let name = format!("{group}:{artifact}");
        let version = archetype.field("version");
        if !probation_policy::names::valid_name(Ecosystem::Maven, &name)
            || blocked_outright(&policy, now, &name, version).is_some()
        {
            edits.push(meta::cut(body, archetype.span));
        }
    }
    // An entry's own `<repository>` names another repository's URL: the entry stays, the URL goes (a client resolves the archetype
    // through this firewall's one mirror, never through a repository the catalog names).
    let mut removed: Vec<(usize, usize)> =
        edits.iter().map(|edit| (edit.start, edit.end)).collect();
    removed.sort_unstable();
    for span in &meta.archetype_repositories {
        // Inside a removed entry? The removed ranges are disjoint and sorted: the last one starting at or before the span.
        let at = removed.partition_point(|(start, _)| *start <= span.0);
        if !(at > 0 && span.1 <= removed[at - 1].1) {
            edits.push(meta::cut(body, *span));
        }
    }
    let filtered = unchanged_is_original(finish(body, edits), &original);
    match side {
        Side::Doc => Ok(Rendered {
            body: filtered.body.into(),
            content_type: XML,
        }),
        Side::Sum(sum) => Ok(Rendered {
            body: sum.hex(&filtered.body).into_bytes().into(),
            content_type: TEXT,
        }),
        Side::Asc | Side::AscSum(_) if !filtered.changed => {
            let url = url_of(&origins, &[format!("{}{}", coords::CATALOG, side.suffix())])?;
            match fetch(app, principal, url, "*/*", SIDE_CAP).await? {
                Some((body, _)) => Ok(Rendered {
                    body,
                    content_type: TEXT,
                }),
                None => Err(ApiError::NotFound),
            }
        }
        Side::Asc | Side::AscSum(_) => Err(ApiError::NotFound),
    }
}

// ------------------------------------------------------------------ writes

/// Where a deploy of `path` goes: the registry's own origin, or for the public registry the configured publish URL.
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
            if !app.origins.maven_publish_configured() {
                return Err(ApiError::NotFound);
            }
            let url = app
                .origins
                .url_for(OriginKind::MavenPublish, &parts)
                .map_err(|_| ApiError::NotFound)?;
            Ok(PublishTarget {
                url,
                origin: app.origins.origin(OriginKind::MavenPublish).clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_modified_is_the_publication_time_and_nothing_else_is() {
        let at = |text: &str| {
            dated_of(&UpstreamValidators {
                etag: None,
                last_modified: Some(text.to_owned()),
            })
        };
        assert_eq!(
            at("Sat, 13 Feb 2021 16:31:54 GMT"),
            Dated::Upstream(1_613_233_914_000_000)
        );
        assert_eq!(at("not a date"), Dated::Undated);
        assert_eq!(
            at("Thu, 01 Jan 1970 00:00:00 GMT"),
            Dated::Undated,
            "the epoch is no date"
        );
        assert_eq!(dated_of(&UpstreamValidators::default()), Dated::Undated);
    }
}
