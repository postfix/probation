//! Go module proxy delivery on the shared firewall machinery. One protected GOPROXY: `@v/list`
//! and `@latest` are filtered by policy, and each `.info`, `.mod` and `.zip` is gated by the same
//! decision before a byte is delivered (the zip is never judged on its own).
//!
//! Identities (the defects slices 17 and 18 taught): the policy key, blocklist and OSV key are the
//! decoded module path (case-sensitive) and the version without its `v`; the URL and the file
//! name keep the proxy's `!`-escaped spelling, rebuilt from the decoded identity and compared
//! exactly (src/go_modules/escape.rs), so the two forms round-trip.
//!
//! Dates. The proxy protocol has no per-module document with times: a version's real publication
//! time is the `Time` of its own `.info`. It is read (never invented), kept in a bounded in-memory
//! table per module and committed on the reference rows. A version whose `.info` has no `Time`
//! (or the zero time) waits on the committed first-seen time; an unparseable `Time` refuses the
//! version (502). No cache-age or build-time substitute is used.
//!
//! Fan-out. A list needs one `.info` per version of unknown age. That fan-out is decided before
//! the first call: at most `LIST_INFO_CAP` calls per request, eight at a time, newest versions
//! first, and a version still undated after that is withheld (fail closed) until a later request
//! has dated it. A version that policy already blocks outright is never fetched.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use serde::Deserialize;

use crate::App;
use crate::artifacts::ArtifactReference;
use crate::go_modules::escape::{self, policy_version};
use crate::http::error::{ApiError, storage_error};
use crate::http::logging;
use crate::managed::Principal;
use crate::managed::report::Call;
use crate::policy::{Candidate, Decision, DenyReason, Ecosystem, PublicationTime};
use crate::store::cache::Advertised;
use crate::store::rows::{ProjectRefresh, ReferenceId, ReferenceUpsert};
use crate::upstream::{
    MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError, UpstreamValidators,
};

pub struct Rendered {
    pub body: Arc<[u8]>,
    pub content_type: &'static str,
}

const TEXT: &str = "text/plain; charset=utf-8";

/// LS-F7: no valid list is refused before this cap. A list is one short line per version
/// (largest measured in evidence/slice-19.md); 16 MiB is far above 4x any real list.
pub const LIST_FLOOR_CAP: u64 = 16 << 20;
/// A `.info` is a few hundred bytes (`Version`, `Time`, optional `Origin`).
const INFO_CAP: u64 = 256 << 10;
/// Upstream `.info` calls one list request may make, and how many run at once.
pub const LIST_INFO_CAP: usize = 64;
const LIST_INFO_PARALLEL: usize = 8;
/// Versions remembered per module in memory, and modules remembered per process.
const MAX_DOC_VERSIONS: usize = 8192;
const MAX_DOCS: usize = 128;
/// How long a shared-service read trusts that a version still exists (membership stays current).
const SERVICE_EXISTS_TTL: Duration = Duration::from_secs(5);

/// The three files of one version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Info,
    Mod,
    Zip,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Info, Kind::Mod, Kind::Zip];

    pub fn ext(self) -> &'static str {
        match self {
            Kind::Info => "info",
            Kind::Mod => "mod",
            Kind::Zip => "zip",
        }
    }

    pub fn from_ext(ext: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.ext() == ext)
    }
}

/// What a `.info` says about when a version appeared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dated {
    /// The proxy's own `Time`, microseconds since the epoch.
    Upstream(i64),
    /// No `Time`, or the zero time: only the committed first-seen time can date it.
    Undated,
}

#[derive(Clone, Copy, Debug)]
struct Known {
    time: Dated,
    first_seen: Option<i64>,
    /// When this process last confirmed the version exists upstream.
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
    versions: std::sync::Mutex<HashMap<String, Known>>,
    /// One list fan-out per module at a time, so a burst of lists costs one set of `.info` calls.
    list_gate: tokio::sync::Mutex<()>,
}

/// (registry, selected origin, decoded module path).
type DocKey = (u64, Option<String>, String);

/// The in-memory version tables. Shared by credential-free reads only: a request that carries the
/// caller's own credential reads and fills nothing here (C1028).
#[derive(Default)]
pub struct Shared {
    docs: std::sync::Mutex<HashMap<DocKey, Arc<Cell>>>,
    /// Distinct revision queries (`@v/main.info`, `@v/abc1234.info`) per (registry, module) in the current window.
    revs: std::sync::Mutex<HashMap<RevKey, RevWindow>>,
    /// The same windows per (registry, module) across every principal: the ceiling.
    rev_modules: std::sync::Mutex<HashMap<(u64, String), RevWindow>>,
    /// Per (registry, module, org): one org's keys together stay under a share of the ceiling.
    rev_orgs: std::sync::Mutex<HashMap<RevOrgKey, RevWindow>>,
    /// Per (registry, key): the distinct modules it asked about in the window.
    rev_keys: std::sync::Mutex<HashMap<(u64, Option<u64>), RevWindow>>,
}

/// (registry, module, the key asking: `None` for the standalone firewall, which has one).
type RevOrgKey = (u64, String, Option<u32>);
type RevKey = (u64, String, Option<u64>);

/// When a module's revision window opened and the distinct tokens asked in it.
type RevWindow = (Instant, HashSet<String>);

/// Each revision query asks upstream to resolve a name; bounded per module and window so a client cannot
/// walk upstream's branch space through this firewall.
const MAX_REVS_PER_WINDOW: usize = 32;
const REV_WINDOW: Duration = Duration::from_secs(60);
/// Distinct tokens per module per window across every principal (several times the per-principal bound).
const MAX_REVS_PER_MODULE: usize = 256;
/// One org's share of that ceiling (a quarter: other orgs always keep three quarters), and one key's distinct modules.
const MAX_REVS_PER_ORG: usize = 64;
const MAX_REV_MODULES_PER_KEY: usize = 64;
const MAX_REV_ENTRIES: usize = 1024;

fn cell_for(
    app: &App,
    registry_id: u64,
    principal: Option<&Principal>,
    module: &str,
) -> Result<Arc<Cell>, ApiError> {
    if crate::http::credential_read::cache_token(app).is_none() {
        return Ok(Arc::new(Cell::default()));
    }
    let key = (
        registry_id,
        principal
            .and_then(|p| p.registry_origin.as_ref())
            .map(|origin| origin.to_string()),
        module.to_owned(),
    );
    Ok(table_cell(&app.go, key))
}

/// The shared cell of a module. Poison-tolerant like every other lock here: one panic while the map is held must
/// not turn into a permanent Go outage until restart.
fn table_cell(shared: &Shared, key: DocKey) -> Arc<Cell> {
    let mut docs = lock(&shared.docs);
    if docs.len() >= MAX_DOCS && !docs.contains_key(&key) {
        docs.retain(|_, cell| Arc::strong_count(cell) > 1);
    }
    Arc::clone(docs.entry(key).or_default())
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn exists_ttl(app: &App) -> Duration {
    if app.service_policy().is_some() {
        SERVICE_EXISTS_TTL
    } else {
        Duration::from_secs(app.config.metadata_ttl_seconds)
    }
}

/// The origin set a request reads through and the kind its URLs are built under.
struct Origins {
    set: OriginSet,
    kind: OriginKind,
}

fn origins_for(app: &App, principal: Option<&Principal>) -> Result<Origins, ApiError> {
    match principal.and_then(|p| p.registry_origin.as_ref()) {
        // A selected registry's origin travels in the slot `selected_npm_with_private` fills; its
        // zips are served by the same proxy (Go has no separate archive origin).
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
            kind: OriginKind::GoProxy,
        }),
    }
}

// ------------------------------------------------------------------ parsing

#[derive(Deserialize)]
struct InfoDoc {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Time", default)]
    time: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InfoError {
    NotJson,
    /// The `Version` field is not a Go version, or is not the one asked for.
    Version,
    /// `Time` is present but is not an RFC 3339 timestamp: the version is refused, never dated.
    Time,
}

/// A `.info` or `@latest` body: its version and when the proxy says it appeared. `expected` is the
/// version the URL named (an `@latest` body names its own).
pub fn parse_info(body: &[u8], expected: Option<&str>) -> Result<(String, Dated), InfoError> {
    let doc: InfoDoc = serde_json::from_slice(body).map_err(|_| InfoError::NotJson)?;
    if !escape::valid_version(&doc.version)
        || expected.is_some_and(|expected| expected != doc.version)
    {
        return Err(InfoError::Version);
    }
    let dated = match doc.time.as_deref().map(str::trim) {
        None | Some("") => Dated::Undated,
        Some(text) => match text.parse::<jiff::Timestamp>() {
            // Go writes the zero time for "unknown" (Athens does for a module it never dated).
            Ok(at) if at.as_second() <= -62_135_596_800 => Dated::Undated,
            Ok(at) => Dated::Upstream(at.as_microsecond()),
            Err(_) => return Err(InfoError::Time),
        },
    };
    Ok((doc.version, dated))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListError {
    NotUtf8,
    TooMany,
}

/// The versions of an `@v/list` body in upstream order: one per line, a line that is not a canonical
/// Go version dropped (never delivered), a repeated version kept once.
pub fn parse_list(body: &[u8], max: usize) -> Result<Vec<String>, ListError> {
    let text = std::str::from_utf8(body).map_err(|_| ListError::NotUtf8)?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() || !escape::valid_version(line) || !seen.insert(line) {
            continue;
        }
        if out.len() >= max {
            return Err(ListError::TooMany);
        }
        out.push(line.to_owned());
    }
    Ok(out)
}

// ------------------------------------------------------------------ references

type Refs = [(Kind, ReferenceId, ArtifactReference); 3];

/// The three references of one version, URLs rebuilt from the decoded identity.
fn references(origins: &Origins, module: &str, version: &str, registry_id: u64) -> Option<Refs> {
    let mut segments = escape::module_segments(module)?;
    segments.push("@v".to_owned());
    let escaped = escape::escape(version)?;
    let build = |kind: Kind| {
        let filename = format!("{escaped}.{}", kind.ext());
        let mut parts: Vec<&str> = segments.iter().map(String::as_str).collect();
        parts.push(&filename);
        let url = origins.set.url_for(origins.kind, &parts).ok()?;
        let reference = ArtifactReference {
            ecosystem: Ecosystem::Go,
            name: module.to_owned(),
            version: policy_version(version).to_owned(),
            filename,
            upstream_url: url,
            // The proxy protocol advertises no digest (go.sum and the checksum database are the
            // client's check); the first verified download pins one (SPEC §9, STATE-01).
            expected: Vec::new(),
        };
        Some((
            kind,
            ReferenceId::compute_in_registry(registry_id, &reference),
            reference,
        ))
    };
    Some([build(Kind::Info)?, build(Kind::Mod)?, build(Kind::Zip)?])
}

fn id_of(refs: &Refs, kind: Kind) -> ReferenceId {
    refs.iter()
        .find(|(k, ..)| *k == kind)
        .map(|(_, id, _)| *id)
        .expect("every kind is built")
}

fn module_ok(module: &str) -> Result<&str, ApiError> {
    escape::valid_module_path(module)
        .then_some(module)
        .ok_or(ApiError::NotFound)
}

fn version_ok(version: &str) -> Result<&str, ApiError> {
    escape::valid_version(version)
        .then_some(version)
        .ok_or(ApiError::NotFound)
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
            tracing::warn!(error = %other, "the Go proxy fetch failed");
            ApiError::UpstreamFailure
        }
    }
}

async fn fetch(
    app: &App,
    principal: Option<&Principal>,
    url: url::Url,
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
            validators: None::<UpstreamValidators>,
            max_bytes,
        })
        .await;
    app.upstreams.record_upstream(Call::Go, &fetched);
    match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => Ok(Some(body)),
        Ok(MetadataResponse::Missing) => Ok(None),
        Ok(MetadataResponse::NotModified { .. }) => Err(ApiError::UpstreamInvalid),
        Err(error) => Err(status_error(app, error)),
    }
}

fn info_cap(app: &App) -> u64 {
    INFO_CAP.min(app.config.max_metadata_bytes.get())
}

/// One `.info`: `None` when upstream has no such version (404 or 410).
async fn fetch_info(
    app: &App,
    principal: Option<&Principal>,
    refs: &Refs,
    version: &str,
) -> Result<Option<Dated>, ApiError> {
    let url = refs
        .iter()
        .find(|(k, ..)| *k == Kind::Info)
        .map(|(_, _, r)| r.upstream_url.clone())
        .ok_or(ApiError::InternalFailure)?;
    let Some(body) = fetch(app, principal, url, "application/json", info_cap(app)).await? else {
        return Ok(None);
    };
    match parse_info(&body, Some(version)) {
        Ok((_, dated)) => Ok(Some(dated)),
        Err(error) => {
            tracing::warn!(?error, "the proxy's .info is unusable");
            Err(ApiError::UpstreamInvalid)
        }
    }
}

/// The marker reference of a module: its first-seen time is the moment this firewall first saw the module's list.
/// It is identity only (never served): the version `@list`, the file name `@list`, a constant URL.
fn baseline_id(registry_id: u64, module: &str) -> ReferenceId {
    ReferenceId::compute_in_registry(
        registry_id,
        &ArtifactReference {
            ecosystem: Ecosystem::Go,
            name: module.to_owned(),
            version: "@list".to_owned(),
            filename: "@list".to_owned(),
            upstream_url: BASELINE_URL.parse().expect("a constant URL"),
            expected: Vec::new(),
        },
    )
}

/// A list's versions are witnessed the moment the list is first seen, dated or not: their first-seen time is that
/// moment, so a later fan-out dating them over several requests cannot make the old catalogue look new, and a
/// version that appears in a LATER list has a later first-seen time (the baseline rule in `record`).
async fn witness(
    app: &App,
    registry_id: u64,
    module: &str,
    all_refs: &[Option<Refs>],
) -> Result<(), ApiError> {
    let now = app.clock.now_utc_micros();
    let existing = app
        .store()
        .list_project_first_seen_in(registry_id, Ecosystem::Go, module)
        .await
        .map_err(storage_error)?;
    let marker = baseline_id(registry_id, module);
    let mut references = Vec::new();
    let upsert = |id: ReferenceId, reference: ArtifactReference| ReferenceUpsert {
        id,
        reference,
        publication_micros: None,
        first_seen_micros: Some(now),
    };
    if !existing.contains_key(&marker) {
        let reference = ArtifactReference {
            ecosystem: Ecosystem::Go,
            name: module.to_owned(),
            version: "@list".to_owned(),
            filename: "@list".to_owned(),
            upstream_url: BASELINE_URL.parse().expect("a constant URL"),
            expected: Vec::new(),
        };
        references.push(upsert(marker, reference));
    }
    for refs in all_refs.iter().flatten() {
        let (kind, id, reference) = &refs[0];
        debug_assert_eq!(*kind, Kind::Info);
        if !existing.contains_key(id) {
            references.push(upsert(*id, reference.clone()));
        }
    }
    if references.is_empty() {
        return Ok(());
    }
    app.store()
        .commit_request_references_in(
            registry_id,
            ProjectRefresh {
                ecosystem: Ecosystem::Go,
                name: module.to_owned(),
                payload: Arc::from(&[][..]),
                validators: UpstreamValidators::default(),
                validated_at_micros: now,
                fetched_at_micros: now,
                references,
            },
        )
        .await
        .map_err(storage_error)?;
    Ok(())
}

const BASELINE_URL: &str = "https://baseline.invalid/list";

/// Commits the references of every `(version, refs, dated)` once and remembers what was learned.
/// A date can only get later (a version re-dated earlier keeps the date already seen).
async fn record(
    app: &App,
    registry_id: u64,
    module: &str,
    cell: &Cell,
    items: &[(&str, Refs, Dated)],
) -> Result<Vec<Known>, ApiError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let now = app.clock.now_utc_micros();
    let mono = app.clock.now_monotonic();
    // First-seen times this firewall already holds for the module, and the baseline: the moment it first saw the
    // module's list. A version that appears after that is dated no earlier than its own first sight, whatever
    // `Time` says (a commit time is the publisher's to choose).
    let existing = app
        .store()
        .list_project_first_seen_in(registry_id, Ecosystem::Go, module)
        .await
        .map_err(storage_error)?;
    let baseline = existing.get(&baseline_id(registry_id, module)).copied();
    // The date only gets later: the later of what this process saw, what the reference row already holds
    // (so a throwaway table of a credential-bearing read, an evicted table or a restart cannot be used to
    // make a version look older) and what upstream says now.
    let mut stored = Vec::with_capacity(items.len());
    for (_, refs, _) in items {
        let row = app
            .store()
            .get_reference(id_of(refs, Kind::Info))
            .await
            .map_err(storage_error)?;
        stored.push(row.and_then(|row| row.publication_micros));
    }
    let merged: Vec<Dated> = {
        let versions = lock(&cell.versions);
        items
            .iter()
            .zip(stored)
            .map(|((version, refs, dated), stored)| {
                let remembered = match versions.get(*version).map(|known| known.time) {
                    Some(Dated::Upstream(micros)) => Some(micros),
                    _ => None,
                };
                let latest = [
                    remembered,
                    stored,
                    match dated {
                        Dated::Upstream(micros) => Some(*micros),
                        Dated::Undated => None,
                    },
                ]
                .into_iter()
                .flatten()
                .max();
                let first_seen = existing
                    .get(&id_of(refs, Kind::Info))
                    .copied()
                    .unwrap_or(now);
                let appeared_later = baseline.is_some_and(|baseline| first_seen > baseline);
                match latest {
                    Some(micros) if appeared_later => Dated::Upstream(micros.max(first_seen)),
                    Some(micros) => Dated::Upstream(micros),
                    None => Dated::Undated,
                }
            })
            .collect()
    };
    let mut references = Vec::with_capacity(items.len() * 3);
    for ((_, refs, _), dated) in items.iter().zip(&merged) {
        for (_, id, reference) in refs {
            references.push(ReferenceUpsert {
                id: *id,
                reference: reference.clone(),
                publication_micros: match dated {
                    Dated::Upstream(micros) => Some(*micros),
                    Dated::Undated => None,
                },
                first_seen_micros: Some(now),
            });
        }
    }
    // Reference identity, first-seen times and pins only: no response body is retained (C1028), the
    // version table above is the only metadata memory.
    let committed = app
        .store()
        .commit_request_references_in(
            registry_id,
            ProjectRefresh {
                ecosystem: Ecosystem::Go,
                name: module.to_owned(),
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
    let mut versions = lock(&cell.versions);
    if versions.len() + items.len() > MAX_DOC_VERSIONS {
        // ponytail: a module with more than 8192 versions in play forgets them all and re-asks
        // upstream; a bounded LRU if that ever measures.
        versions.clear();
    }
    for ((version, refs, _), dated) in items.iter().zip(merged) {
        let first_seen = committed.first_seen.get(&id_of(refs, Kind::Info)).copied();
        let known = Known {
            time: dated,
            first_seen,
            checked: mono,
        };
        versions.insert((*version).to_owned(), known);
        learned.push(known);
    }
    Ok(learned)
}

/// The version's table entry, confirmed to exist within the freshness window: from memory, else one `.info`.
async fn resolve(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    module: &str,
    version: &str,
    refs: &Refs,
) -> Result<Known, ApiError> {
    let cell = cell_for(app, registry_id, principal, module)?;
    let mono = app.clock.now_monotonic();
    if let Some(known) = lock(&cell.versions).get(version).copied()
        && mono.saturating_duration_since(known.checked) < exists_ttl(app)
    {
        return Ok(known);
    }
    match fetch_info(app, principal, refs, version).await? {
        None => {
            lock(&cell.versions).remove(version);
            Err(ApiError::NotFound)
        }
        Some(dated) => {
            let learned = record(
                app,
                registry_id,
                module,
                &cell,
                &[(version, refs.clone(), dated)],
            )
            .await?;
            learned.into_iter().next().ok_or(ApiError::InternalFailure)
        }
    }
}

// ------------------------------------------------------------------ policy

fn candidate<'a>(
    module: &'a str,
    version: &'a str,
    known: &Known,
    pinned: &'a [crate::policy::Digest],
) -> Candidate<'a> {
    Candidate {
        ecosystem: Ecosystem::Go,
        name: module,
        version: policy_version(version),
        publication: known.publication(),
        advertised_digests: &[],
        pinned_digests: pinned,
    }
}

fn pins_of(
    pins: &HashMap<ReferenceId, Vec<crate::policy::Digest>>,
    refs: &Refs,
) -> Vec<crate::policy::Digest> {
    refs.iter()
        .flat_map(|(_, id, _)| pins.get(id).into_iter().flatten().cloned())
        .collect()
}

/// A name or version a policy blocks outright is refused without asking upstream anything
/// (PERF-01): the decision with no date is conclusive for these two reasons only.
fn locally_blocked(
    app: &App,
    principal: Option<&Principal>,
    module: &str,
    version: Option<&str>,
) -> Result<(), ApiError> {
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
    let candidate = Candidate {
        ecosystem: Ecosystem::Go,
        name: module,
        version: version.map_or("", policy_version),
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    let verdict = crate::policy::decide(&policy, &candidate, now, false);
    match verdict.decision {
        decision @ Decision::Deny(DenyReason::BlockedPackage | DenyReason::BlockedVersion) => {
            if let (Some(principal), Some(managed)) = (principal, app.managed()) {
                managed.record_refused(
                    principal,
                    &policy,
                    now,
                    &candidate,
                    decision,
                    version.is_some(),
                );
            }
            Err(crate::artifacts::decision_error(decision, now))
        }
        _ => Ok(()),
    }
}

/// The reference a `GET {module}/@v/{version}.{ext}` names: the version is confirmed (one `.info`
/// at most) and its three references committed before anything else is asked of upstream.
pub async fn reference_for_version(
    app: &App,
    principal: Option<&Principal>,
    module: &str,
    version: &str,
    kind: Kind,
    registry_id: u64,
) -> Result<ReferenceId, ApiError> {
    let (module, version) = (module_ok(module)?, version_ok(version)?);
    locally_blocked(app, principal, module, Some(version))?;
    let origins = origins_for(app, principal)?;
    let refs = references(&origins, module, version, registry_id).ok_or(ApiError::NotFound)?;
    resolve(app, principal, registry_id, module, version, &refs).await?;
    Ok(id_of(&refs, kind))
}

/// Counts a revision query, refusing (429) before any upstream call. Four bounds, each over one window:
/// distinct tokens per (registry, module, key) `MAX_REVS_PER_WINDOW`, per (registry, module, org) `MAX_REVS_PER_ORG`
/// (so one org's many keys cannot use up the ceiling), per module across everyone `MAX_REVS_PER_MODULE`, and distinct
/// modules per key `MAX_REV_MODULES_PER_KEY` (so a key cannot flood junk module names to evict and reset its own
/// windows, and cannot spend more than that many modules' worth of upstream calls). The tables are bounded; when full
/// they drop expired windows and then the oldest one.
fn admit_rev(
    app: &App,
    registry_id: u64,
    module: &str,
    principal: Option<&Principal>,
    rev: &str,
) -> Result<(), ApiError> {
    let who = principal.map(|p| p.key_id.0);
    let org = principal.and_then(|p| p.org).map(|org| org.0);
    admit_rev_at(
        &app.go,
        app.clock.now_monotonic(),
        (registry_id, who, org),
        module,
        rev,
    )
}

fn admit_rev_at(
    go: &Shared,
    now: Instant,
    (registry_id, who, org): (u64, Option<u64>, Option<u32>),
    module: &str,
    rev: &str,
) -> Result<(), ApiError> {
    let mut revs = lock(&go.revs);
    let mut orgs = lock(&go.rev_orgs);
    let mut modules = lock(&go.rev_modules);
    let mut keys = lock(&go.rev_keys);
    let fresh = |window: &RevWindow| now.saturating_duration_since(window.0) < REV_WINDOW;
    make_room(&mut revs, now);
    make_room(&mut orgs, now);
    make_room(&mut modules, now);
    make_room(&mut keys, now);
    let key_modules = keys
        .entry((registry_id, who))
        .or_insert_with(|| (now, HashSet::new()));
    if !fresh(key_modules) {
        *key_modules = (now, HashSet::new());
    }
    if !key_modules.1.contains(module) && key_modules.1.len() >= MAX_REV_MODULES_PER_KEY {
        return Err(ApiError::TooManyRequests);
    }
    let entry = revs
        .entry((registry_id, module.to_owned(), who))
        .or_insert_with(|| (now, HashSet::new()));
    if !fresh(entry) {
        *entry = (now, HashSet::new());
    }
    let org_window = orgs
        .entry((registry_id, module.to_owned(), org))
        .or_insert_with(|| (now, HashSet::new()));
    if !fresh(org_window) {
        *org_window = (now, HashSet::new());
    }
    let ceiling = modules
        .entry((registry_id, module.to_owned()))
        .or_insert_with(|| (now, HashSet::new()));
    if !fresh(ceiling) {
        *ceiling = (now, HashSet::new());
    }
    let over =
        |window: &RevWindow, bound: usize| !window.1.contains(rev) && window.1.len() >= bound;
    if over(entry, MAX_REVS_PER_WINDOW)
        || over(org_window, MAX_REVS_PER_ORG)
        || over(ceiling, MAX_REVS_PER_MODULE)
    {
        return Err(ApiError::TooManyRequests);
    }
    key_modules.1.insert(module.to_owned());
    for window in [entry, org_window, ceiling] {
        window.1.insert(rev.to_owned());
    }
    Ok(())
}

/// Keeps a window table under `MAX_REV_ENTRIES`: expired windows go first, then the oldest.
fn make_room<K: Clone + Eq + std::hash::Hash>(table: &mut HashMap<K, RevWindow>, now: Instant) {
    if table.len() < MAX_REV_ENTRIES {
        return;
    }
    table.retain(|_, window| now.saturating_duration_since(window.0) < REV_WINDOW);
    while table.len() >= MAX_REV_ENTRIES {
        let Some(oldest) = table
            .iter()
            .min_by_key(|(_, window)| window.0)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        table.remove(&oldest);
    }
}

/// `GET {module}/@v/{rev}.info` for a branch, a commit or a short tag (`go get mod@main`): upstream resolves the
/// name to a version and its time; the RESOLVED version (a pseudo-version or a tag) goes through the ordinary gate
/// (block, age, OSV) and is answered, as its own `.info`, only when allowed. Its `.mod` and `.zip` then take the
/// ordinary path. The token is validated and counted before upstream is asked anything.
pub async fn rev_reference(
    app: &App,
    principal: Option<&Principal>,
    module: &str,
    rev: &str,
    registry_id: u64,
) -> Result<(String, ReferenceId), ApiError> {
    let module = module_ok(module)?;
    if !escape::valid_rev(rev) {
        return Err(ApiError::NotFound);
    }
    locally_blocked(app, principal, module, None)?;
    admit_rev(app, registry_id, module, principal, rev)?;
    let origins = origins_for(app, principal)?;
    let mut segments = escape::module_segments(module).ok_or(ApiError::NotFound)?;
    segments.push("@v".to_owned());
    segments.push(format!(
        "{}.info",
        escape::escape(rev).ok_or(ApiError::NotFound)?
    ));
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    let url = origins
        .set
        .url_for(origins.kind, &parts)
        .map_err(|_| ApiError::NotFound)?;
    let body = fetch(app, principal, url, "application/json", info_cap(app))
        .await?
        .ok_or(ApiError::NotFound)?;
    let (version, dated) = parse_info(&body, None).map_err(|error| {
        tracing::warn!(?error, "the proxy's answer to a revision query is unusable");
        ApiError::UpstreamInvalid
    })?;
    // The resolved version is the one judged: a name for a blocked version is as blocked as the version.
    locally_blocked(app, principal, module, Some(&version))?;
    let refs =
        references(&origins, module, &version, registry_id).ok_or(ApiError::UpstreamInvalid)?;
    let cell = cell_for(app, registry_id, principal, module)?;
    let known = record(
        app,
        registry_id,
        module,
        &cell,
        &[(&version, refs.clone(), dated)],
    )
    .await?
    .remove(0);
    let now = app.clock.now_utc_micros();
    let policy = app
        .policy_for(principal)
        .ok_or(ApiError::PolicyUnavailable)?;
    let pins = app
        .store()
        .list_project_pins_in(registry_id, Ecosystem::Go, module)
        .await
        .map_err(storage_error)?;
    let pinned = pins_of(&pins, &refs);
    let candidate = candidate(module, &version, &known, &pinned);
    match crate::osv::evaluate_scoped(
        &app.osv,
        &policy,
        now,
        &candidate,
        app.osv_scope(registry_id),
    )
    .await
    {
        Decision::Allow => Ok((version.clone(), id_of(&refs, Kind::Info))),
        decision => {
            if let (Some(principal), Some(managed)) = (principal, app.managed()) {
                managed.record_refused(principal, &policy, now, &candidate, decision, true);
            }
            Err(crate::artifacts::decision_error(decision, now))
        }
    }
}

/// SPEC §9 membership: the three ids of the version the reference names, if it still exists.
pub async fn ensure_fresh_project_in(
    app: &App,
    reference: &ArtifactReference,
    registry_id: u64,
    principal: Option<&Principal>,
) -> Result<Arc<Advertised>, ApiError> {
    let module = module_ok(&reference.name)?;
    let version = format!("v{}", reference.version);
    let version = version_ok(&version)?;
    let origins = origins_for(app, principal)?;
    let refs = references(&origins, module, version, registry_id).ok_or(ApiError::NotFound)?;
    resolve(app, principal, registry_id, module, version, &refs).await?;
    Ok(Arc::new(Advertised::new(refs.iter().map(
        |(_, id, reference)| (*id, reference.filename.as_str()),
    ))))
}

/// One version of a judged list.
struct Judged {
    version: String,
    decision: Decision,
}

async fn judged_list(
    app: &App,
    principal: Option<&Principal>,
    module: &str,
    registry_id: u64,
) -> Result<Vec<Judged>, ApiError> {
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
    let origins = origins_for(app, principal)?;
    let mut segments = escape::module_segments(module).ok_or(ApiError::NotFound)?;
    segments.push("@v".to_owned());
    segments.push("list".to_owned());
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    let url = origins
        .set
        .url_for(origins.kind, &parts)
        .map_err(|_| ApiError::NotFound)?;
    let cap = app.config.max_metadata_bytes.get().max(LIST_FLOOR_CAP);
    let body = fetch(app, principal, url, "text/plain", cap)
        .await?
        .ok_or(ApiError::NotFound)?;
    let max_versions = (app.config.max_references_per_project.get() as usize / 3).max(1);
    let versions = parse_list(&body, max_versions).map_err(|error| {
        tracing::warn!(?error, "the Go proxy's list is unusable");
        ApiError::UpstreamInvalid
    })?;
    let cell = cell_for(app, registry_id, principal, module)?;
    // One fan-out per module at a time; a request that finds it running does not wait (waiting would pin its request
    // permit behind a slow upstream): it serves what is dated already and withholds the rest.
    let shared = crate::http::credential_read::cache_token(app).is_some();
    let gate = if shared {
        cell.list_gate.try_lock().ok()
    } else {
        None
    };
    let fan_out = !shared || gate.is_some();
    let mono = app.clock.now_monotonic();
    let all_refs: Vec<Option<Refs>> = versions
        .iter()
        .map(|version| references(&origins, module, version, registry_id))
        .collect();
    witness(app, registry_id, module, &all_refs).await?;
    // After a restart or an eviction the table is empty but the store still holds every date it ever recorded: seed
    // the table from it, so a long list is not dated again 64 versions per request.
    let stored = app
        .store()
        .list_project_publications_in(registry_id, Ecosystem::Go, module)
        .await
        .map_err(storage_error)?;
    {
        let mut table = lock(&cell.versions);
        for (version, refs) in versions.iter().zip(&all_refs) {
            if table.len() >= MAX_DOC_VERSIONS {
                break;
            }
            if let (false, Some(refs)) = (table.contains_key(version), refs)
                && let Some(micros) = stored.get(&id_of(refs, Kind::Info))
            {
                table.insert(
                    version.clone(),
                    Known {
                        time: Dated::Upstream(*micros),
                        first_seen: None,
                        checked: mono,
                    },
                );
            }
        }
    }
    // The list just confirmed these versions exist.
    {
        let mut table = lock(&cell.versions);
        for version in &versions {
            if let Some(known) = table.get_mut(version) {
                known.checked = mono;
            }
        }
    }
    // Versions of unknown age, newest first, bounded before the first call.
    let mut missing: Vec<usize> = {
        let table = lock(&cell.versions);
        (0..versions.len())
            .filter(|&i| all_refs[i].is_some() && !table.contains_key(&versions[i]))
            .collect()
    };
    missing.sort_by_key(|&i| std::cmp::Reverse(semver::Version::parse(&versions[i][1..]).ok()));
    let blocked_outright = |version: &str| {
        let candidate = Candidate {
            ecosystem: Ecosystem::Go,
            name: module,
            version: policy_version(version),
            publication: PublicationTime::Unknown,
            advertised_digests: &[],
            pinned_digests: &[],
        };
        matches!(
            crate::policy::decide(&policy, &candidate, now, false).decision,
            Decision::Deny(DenyReason::BlockedPackage | DenyReason::BlockedVersion)
        )
    };
    let wanted: Vec<usize> = missing
        .into_iter()
        .filter(|&i| !blocked_outright(&versions[i]))
        .take(if fan_out { LIST_INFO_CAP } else { 0 })
        .collect();
    let fetched: Vec<(usize, Result<Option<Dated>, ApiError>)> =
        futures_util::stream::iter(wanted.iter().copied())
            .map(|i| {
                let refs = all_refs[i].as_ref().expect("filtered above");
                let version = &versions[i];
                async move { (i, fetch_info(app, principal, refs, version).await) }
            })
            .buffer_unordered(LIST_INFO_PARALLEL)
            .collect()
            .await;
    let mut items: Vec<(&str, Refs, Dated)> = Vec::new();
    for (i, result) in fetched {
        match result {
            Ok(Some(dated)) => items.push((
                &versions[i],
                all_refs[i].clone().expect("filtered above"),
                dated,
            )),
            Ok(None) => {}
            // Withheld, not fatal: one unusable `.info` or one failed call never hides its neighbours.
            Err(error) => tracing::warn!(
                ?error,
                "a version of the list could not be dated and is withheld"
            ),
        }
    }
    record(app, registry_id, module, &cell, &items).await?;
    let pins = app
        .store()
        .list_project_pins_in(registry_id, Ecosystem::Go, module)
        .await
        .map_err(storage_error)?;
    let scope = app.osv_scope(registry_id);
    let known: Vec<Option<Known>> = {
        let table = lock(&cell.versions);
        versions
            .iter()
            .map(|version| table.get(version).copied())
            .collect()
    };
    let judged = futures_util::future::join_all(versions.iter().enumerate().map(|(i, version)| {
        let (policy, pins, known, all_refs) = (&policy, &pins, &known, &all_refs);
        async move {
            let (Some(known), Some(refs)) = (known[i], all_refs[i].as_ref()) else {
                // Undated (over the cap, failed, or not buildable): withheld, and for the reason policy
                // gives for a version with no date (a blocked name or version says so).
                let undated = Candidate {
                    ecosystem: Ecosystem::Go,
                    name: module,
                    version: policy_version(version),
                    publication: PublicationTime::Unknown,
                    advertised_digests: &[],
                    pinned_digests: &[],
                };
                return Judged {
                    version: version.clone(),
                    decision: crate::policy::decide(policy, &undated, now, false).decision,
                };
            };
            let pinned = pins_of(pins, refs);
            let candidate = candidate(module, version, &known, &pinned);
            Judged {
                version: version.clone(),
                decision: crate::osv::evaluate_scoped(&app.osv, policy, now, &candidate, scope)
                    .await,
            }
        }
    }))
    .await;
    Ok(judged)
}

fn record_refused_listing(
    app: &App,
    principal: Option<&Principal>,
    module: &str,
    judged: &[Judged],
) {
    let (Some(principal), Some(managed)) = (principal, app.managed()) else {
        return;
    };
    let Some(policy) = app.policy_for(Some(principal)) else {
        return;
    };
    let now = app.clock.now_utc_micros();
    let blocked = judged.iter().find(|j| {
        matches!(
            j.decision,
            Decision::Deny(
                DenyReason::BlockedPackage
                    | DenyReason::BlockedVersion
                    | DenyReason::BlockedByOsv
                    | DenyReason::BlockedDigest
            )
        )
    });
    let Some(j) = blocked else { return };
    let candidate = Candidate {
        ecosystem: Ecosystem::Go,
        name: module,
        version: policy_version(&j.version),
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    let verdict = crate::managed::refused_verdict(&policy, now, &candidate, j.decision);
    managed.record_decision(principal, Ecosystem::Go, module, None, &verdict);
}

/// `GET {module}/@v/list`: the versions policy allows, in upstream order, one per line.
pub async fn serve_list(
    app: &App,
    principal: Option<&Principal>,
    module: &str,
    registry_id: u64,
) -> Result<Rendered, ApiError> {
    let module = module_ok(module)?;
    locally_blocked(app, principal, module, None)?;
    let judged = judged_list(app, principal, module, registry_id).await?;
    logging::record_cache(logging::CacheStatus::Miss);
    if !judged.is_empty() && !judged.iter().any(|j| matches!(j.decision, Decision::Allow)) {
        record_refused_listing(app, principal, module, &judged);
    }
    let mut body = String::new();
    for j in judged
        .iter()
        .filter(|j| matches!(j.decision, Decision::Allow))
    {
        body.push_str(&j.version);
        body.push('\n');
    }
    Ok(Rendered {
        body: Arc::from(body.into_bytes()),
        content_type: TEXT,
    })
}

/// Highest release among `allowed`, else the highest prerelease (the order `go` itself applies to a list).
fn best_of(allowed: &[String]) -> Option<&String> {
    fn parsed(v: &String) -> Option<(semver::Version, &String)> {
        semver::Version::parse(&v[1..])
            .ok()
            .map(|parsed| (parsed, v))
    }
    let mut releases: Vec<_> = allowed
        .iter()
        .filter_map(parsed)
        .filter(|(p, _)| p.pre.is_empty())
        .collect();
    if releases.is_empty() {
        releases = allowed.iter().filter_map(parsed).collect();
    }
    releases
        .into_iter()
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, v)| v)
}

/// `GET {module}/@latest`: the proxy's own answer when policy allows it, else the best version the
/// filtered list still offers. The version returned is then served as its `.info` (the same
/// reference, the same gate).
pub async fn latest_reference(
    app: &App,
    principal: Option<&Principal>,
    module: &str,
    registry_id: u64,
) -> Result<(String, ReferenceId), ApiError> {
    let module = module_ok(module)?;
    locally_blocked(app, principal, module, None)?;
    let origins = origins_for(app, principal)?;
    let mut segments = escape::module_segments(module).ok_or(ApiError::NotFound)?;
    segments.push("@latest".to_owned());
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    let url = origins
        .set
        .url_for(origins.kind, &parts)
        .map_err(|_| ApiError::NotFound)?;
    if let Some(body) = fetch(app, principal, url, "application/json", info_cap(app)).await? {
        let (version, dated) = parse_info(&body, None).map_err(|error| {
            tracing::warn!(?error, "the proxy's @latest is unusable");
            ApiError::UpstreamInvalid
        })?;
        let refs =
            references(&origins, module, &version, registry_id).ok_or(ApiError::UpstreamInvalid)?;
        let cell = cell_for(app, registry_id, principal, module)?;
        let known = record(
            app,
            registry_id,
            module,
            &cell,
            &[(&version, refs.clone(), dated)],
        )
        .await?
        .remove(0);
        let now = app.clock.now_utc_micros();
        let policy = app
            .policy_for(principal)
            .ok_or(ApiError::PolicyUnavailable)?;
        let pins = app
            .store()
            .list_project_pins_in(registry_id, Ecosystem::Go, module)
            .await
            .map_err(storage_error)?;
        let pinned = pins_of(&pins, &refs);
        let decision = crate::osv::evaluate_scoped(
            &app.osv,
            &policy,
            now,
            &candidate(module, &version, &known, &pinned),
            app.osv_scope(registry_id),
        )
        .await;
        if matches!(decision, Decision::Allow) {
            let id = id_of(&refs, Kind::Info);
            return Ok((version, id));
        }
    }
    // The proxy's latest is held or blocked (or it has none): the best allowed version of its list.
    let judged = judged_list(app, principal, module, registry_id).await?;
    let allowed: Vec<String> = judged
        .iter()
        .filter(|j| matches!(j.decision, Decision::Allow))
        .map(|j| j.version.clone())
        .collect();
    let version = best_of(&allowed).ok_or(ApiError::NotFound)?.clone();
    let refs = references(&origins, module, &version, registry_id).ok_or(ApiError::NotFound)?;
    Ok((version, id_of(&refs, Kind::Info)))
}

/// The file name a reference of `version`/`kind` is served under.
pub fn file_name(version: &str, kind: Kind) -> Option<String> {
    Some(format!("{}.{}", escape::escape(version)?, kind.ext()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window tables stay bounded and a flood only evicts old windows: it never refuses.
    #[test]
    fn the_revision_tables_are_bounded_by_dropping_the_oldest_window() {
        let start = Instant::now();
        let mut table: HashMap<u32, RevWindow> = (0..(MAX_REV_ENTRIES as u32 + 50))
            .map(|n| {
                (
                    n,
                    (start + Duration::from_millis(u64::from(n)), HashSet::new()),
                )
            })
            .collect();
        make_room(&mut table, start + Duration::from_millis(1));
        assert!(table.len() < MAX_REV_ENTRIES, "{}", table.len());
        assert!(
            table.contains_key(&(MAX_REV_ENTRIES as u32 + 49)),
            "the newest windows stay"
        );
        assert!(!table.contains_key(&0), "the oldest go first");
    }

    /// A panic while the table of modules is held must leave the next request a working table.
    #[test]
    fn a_poisoned_module_table_is_still_served() {
        let shared = Arc::new(Shared::default());
        let held = Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let _guard = held.docs.lock().unwrap();
            panic!("a panic while the table is held");
        })
        .join();
        assert!(shared.docs.is_poisoned());
        let cell = table_cell(&shared, (7, None, "example.com/m".to_owned()));
        assert!(
            Arc::ptr_eq(
                &cell,
                &table_cell(&shared, (7, None, "example.com/m".to_owned()))
            ),
            "the same module, the same cell"
        );
    }

    /// L2: one org's keys together never use more than their share of a module's ceiling, so another org still resolves.
    #[test]
    fn one_org_cannot_use_up_the_ceiling_of_a_module() {
        let go = Shared::default();
        let now = Instant::now();
        let mut refused = 0;
        for key in 0..8_u64 {
            for n in 0..MAX_REVS_PER_WINDOW {
                if admit_rev_at(
                    &go,
                    now,
                    (1, Some(key), Some(7)),
                    "example.com/m",
                    &format!("r{key}-{n}"),
                )
                .is_err()
                {
                    refused += 1;
                }
            }
        }
        assert_eq!(
            refused,
            8 * MAX_REVS_PER_WINDOW - MAX_REVS_PER_ORG,
            "the org stops at its share"
        );
        assert!(
            admit_rev_at(&go, now, (1, Some(100), Some(8)), "example.com/m", "main").is_ok(),
            "another org still resolves"
        );
        // Without orgs (standalone keys) the module ceiling itself still holds.
        let go = Shared::default();
        let mut admitted = 0;
        for key in 0..20_u64 {
            for n in 0..MAX_REVS_PER_WINDOW {
                if admit_rev_at(
                    &go,
                    now,
                    (1, Some(key), None),
                    "example.com/m",
                    &format!("r{key}-{n}"),
                )
                .is_ok()
                {
                    admitted += 1;
                }
            }
        }
        assert_eq!(
            admitted, MAX_REVS_PER_ORG,
            "keys without an org share one org share"
        );
    }

    /// L3: a key flooding junk module names cannot reset its own window for a module: it stops at its distinct-module
    /// bound, and the tokens it already used stay counted.
    #[test]
    fn a_key_cannot_reset_its_bound_by_flooding_module_names() {
        let go = Shared::default();
        let now = Instant::now();
        for n in 0..MAX_REVS_PER_WINDOW {
            admit_rev_at(
                &go,
                now,
                (1, Some(1), Some(1)),
                "example.com/m",
                &format!("r{n}"),
            )
            .unwrap();
        }
        for n in 0..(MAX_REV_ENTRIES * 2) {
            let _ = admit_rev_at(
                &go,
                now + Duration::from_millis(n as u64),
                (1, Some(1), Some(1)),
                &format!("junk{n}.example/m"),
                "a",
            );
        }
        assert!(
            admit_rev_at(
                &go,
                now + Duration::from_secs(5),
                (1, Some(1), Some(1)),
                "example.com/m",
                "fresh"
            )
            .is_err(),
            "the flood did not reset the window"
        );
        assert!(
            admit_rev_at(
                &go,
                now + Duration::from_secs(5),
                (1, Some(2), Some(2)),
                "example.com/m",
                "fresh"
            )
            .is_ok(),
            "another key is unaffected"
        );
    }
}
