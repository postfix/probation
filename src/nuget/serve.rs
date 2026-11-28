//! NuGet v3 delivery on the shared firewall machinery. Every document a client reads is fetched,
//! decoded strictly, judged version by version and rendered with every URL pointing at this
//! firewall; every file (`.nupkg`, `.nuspec`, readme, icon) is delivered through the shared artifact
//! pipeline, so one version's four files are all allowed or all refused by the same decision.
//!
//! Identity (the defects slices 17 to 19 taught). A NuGet id is case-insensitive and every URL of the
//! protocol spells it lower case, so there is exactly one spelling: the policy key, the blocklist, the OSV
//! key, the project row, the reference rows and the upstream URLs all carry the lower-cased id, and a
//! request that spells it otherwise (or spells a version other than its normalised lower-case form) is a
//! 404 before any upstream call. The version policy and OSV see is NuGet's normalised form without build
//! metadata (`probation_policy::names::nuget_version`).
//!
//! Dates. A version's publication time is the `published` of its registration leaf. The unlisted sentinel
//! (1900-01-01), an absent value and an unparseable one are "no date": the version waits on the committed
//! first-seen time and is never dated by invention, a cache age or a build time.
//!
//! Resources. The service index of a registry names every resource this firewall serves; each is used only
//! when it lies on a configured origin (the registry's own origin for a selected registry), and every URL a
//! client is given is a route here.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use probation_policy::names::{canonical_name, nuget_version, valid_name};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::App;
use crate::http::error::{ApiError, storage_error};
use crate::http::logging;
use crate::managed::Principal;
use crate::managed::report::Call;
use crate::nuget::doc::{self, Links, ResourceKind, Resources};
use crate::policy::{Candidate, Decision, DenyReason, Ecosystem, PublicationTime};
use crate::store::cache::{Advertised, CachedProject, ProjectKey};
use crate::store::rows::{
    ArtifactReference, Generation, ProjectRefresh, ProjectRow, ReferenceId, ReferenceUpsert,
};
use crate::upstream::{MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError};

pub struct Rendered {
    pub body: bytes::Bytes,
    pub content_type: &'static str,
}

const JSON: &str = "application/json";

/// LS-F7: no valid document is refused before this cap (the largest registration measured is in
/// evidence/slice-20.md); the real cap is `max(max_metadata_bytes, FLOOR)`.
pub const DOC_FLOOR_CAP: u64 = 16 << 20;
/// The service index is a few kilobytes (api.nuget.org: 8 KiB); 1 MiB is far above 100x that.
const SERVICE_INDEX_CAP: u64 = 1 << 20;
/// One repository certificate is a few kilobytes.
const CERT_CAP: u64 = 256 << 10;
/// `base` and `update` of the vulnerability database: the full base file is a few megabytes.
const VULNERABILITY_CAP: u64 = 32 << 20;
/// The vulnerability and signature indexes are a few hundred bytes.
const VULNERABILITY_INDEX_CAP: u64 = 1 << 20;
const MAX_RESOURCES: usize = 512;
const SERVICE_INDEX_TTL: Duration = Duration::from_secs(60);
const SERVICE_INDEX_FAILURE_TTL: Duration = Duration::from_secs(15);
/// How long shareable service-mode reads share one fetched project.
const SERVICE_SHARE_TTL: Duration = Duration::from_secs(5);
/// Registration pages of one project (nuget.org writes 64 versions per page: 200,000 versions are 3,125 pages).
const MAX_PAGES: usize = 4096;
const PAGE_PARALLEL: usize = 4;
/// Search results judged for one request (the search API's own ceiling for `take`): each needs a project, so each costs
/// upstream calls, judged `SEARCH_PARALLEL` at a time under the request's deadline.
pub const SEARCH_TAKE_CAP: usize = 1000;
/// Cold projects one search judges at once: half of a registry's refresh places, so a take=1000 search leaves the rest to
/// everyone else's reads (the public registry has one share for all its users).
const SEARCH_PARALLEL: usize = 2;
/// Reference rows one project may hold in all: the newest versions' (`max_references_per_project`) and the rows made
/// when a file of an older version is asked for (four times that); past it such a file is a 503.
const LAZY_ROWS_FACTOR: u64 = 4;
/// Tables bounded: registries' service indexes and shared projects remembered per process.
const MAX_SERVICE_INDEXES: usize = 64;
const MAX_SHARED_PROJECTS: usize = 256;
/// A published version longer than this is not a NuGet version.
pub const MAX_VERSION: usize = 256;
/// Four files per version: the project's reference rows are 4x its versions.
const FILES_PER_VERSION: usize = 4;
/// Versions one project may have (a few bytes each: far above any real project). Every one is kept in the stored project, judged
/// and listed; only the newest `max_references_per_project / 4` have their four reference rows made at refresh, any other
/// version gets its rows when a file of it is first asked for (`reference_for_file`).
const MAX_FLAT_VERSIONS: usize = 200_000;

/// The four files of one version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum File {
    Nupkg,
    Nuspec,
    Readme,
    Icon,
}

impl File {
    pub const ALL: [File; FILES_PER_VERSION] =
        [File::Nupkg, File::Nuspec, File::Readme, File::Icon];

    /// The file name under `{id}/{version}/` (and the reference's file name).
    pub fn name(self, id: &str, version: &str) -> String {
        match self {
            File::Nupkg => format!("{id}.{version}.nupkg"),
            File::Nuspec => format!("{id}.nuspec"),
            File::Readme => "readme".to_owned(),
            File::Icon => "icon".to_owned(),
        }
    }

    pub fn of_name(name: &str, id: &str, version: &str) -> Option<File> {
        File::ALL
            .into_iter()
            .find(|file| file.name(id, version) == name)
    }
}

/// One version of a project as it is stored and judged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(rename = "v")]
    pub version: String,
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    pub published: Option<i64>,
    #[serde(rename = "l", default = "yes")]
    pub listed: bool,
    /// Present in the flat container (so downloadable); a version only registration names is advertised
    /// for membership but never listed by the flat container.
    #[serde(rename = "f", default = "yes")]
    pub in_flat: bool,
    /// When this firewall first saw a version that carries no date: the age such a version has before it has rows (the
    /// committed first-seen time of its rows wins once they exist).
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<i64>,
}

const fn yes() -> bool {
    true
}

/// The stored form of a project: the lower-cased id and its versions, built from the flat container and
/// registration; no upstream document is stored.
#[derive(Serialize, Deserialize)]
struct Payload {
    id: String,
    versions: Vec<Entry>,
}

fn parse_payload(payload: &[u8], max: usize) -> Option<Payload> {
    let parsed: Payload = serde_json::from_slice(payload).ok()?;
    (parsed.versions.len() <= max).then_some(parsed)
}

struct ServiceCell {
    at: Instant,
    result: Result<Arc<Resources>, ServiceFailure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceFailure {
    Unauthenticated,
    Denied,
    Timeout,
    Failed,
    Invalid,
    Missing,
}

impl From<ServiceFailure> for ApiError {
    fn from(failure: ServiceFailure) -> ApiError {
        match failure {
            ServiceFailure::Unauthenticated => ApiError::UpstreamUnauthenticated,
            ServiceFailure::Denied => ApiError::UpstreamDenied,
            ServiceFailure::Timeout => ApiError::UpstreamTimeout,
            ServiceFailure::Failed => ApiError::UpstreamFailure,
            ServiceFailure::Invalid | ServiceFailure::Missing => ApiError::UpstreamInvalid,
        }
    }
}

/// One registry's service index and when it was read.
type ServiceSlot = Arc<tokio::sync::Mutex<Option<ServiceCell>>>;

/// (registry, selected origin, document URL).
type DocKey = (u64, Option<String>, String);

/// (registry, selected origin, exact id).
type ShareKey = (u64, Option<String>, String);

/// Project refreshes (the flat container and registration fetches of one id) running at once, process-wide: a search, a
/// burst of registration reads or credential-bearing reads (which share nothing) cannot make more upstream work than this.
const REFRESHES: usize = 16;
/// Of those, the most one registry (id 0 is the public one) may hold, so one tenant's slow registry cannot take them all.
const REFRESHES_PER_REGISTRY: usize = 4;
/// How long a request waits for one of those places before it is refused (a 504).
const REFRESH_WAIT: Duration = Duration::from_secs(30);
/// A document request's whole deadline (every route but a file transfer).
pub const DOCUMENT_DEADLINE: Duration = Duration::from_secs(60);
/// Registration bytes and aux documents kept for a few seconds for credential-free reads, bounded by entries and size.
const RAW_TTL: Duration = Duration::from_secs(5);
const MAX_RAW: usize = 8;
const MAX_GATES: usize = 256;
const MAX_RAW_BYTES: usize = 16 << 20;
const DOC_TTL: Duration = Duration::from_secs(30);
const MAX_DOCS: usize = 16;
const MAX_DOC_BYTES: usize = 8 << 20;

pub struct Shared {
    /// (registry, selected origin) -> the registry's service index, read by credential-free requests only.
    services: std::sync::Mutex<HashMap<(u64, Option<String>), ServiceSlot>>,
    /// Shared-service mode only: the project a shareable (credential-free) read just fetched.
    shared: std::sync::Mutex<HashMap<ShareKey, (Instant, Arc<CachedProject>)>>,
    /// The registration documents a credential-free read just fetched, per (registry, origin, id).
    raw: std::sync::Mutex<HashMap<ShareKey, (Instant, Arc<RegRaw>)>>,
    /// One refresh of one project at a time, per (registry, origin, id): the gates of the credential-free reads.
    gates: std::sync::Mutex<HashMap<ShareKey, Arc<tokio::sync::Mutex<()>>>>,
    /// Vulnerability and signature documents, per (registry, origin, document URL): credential-free reads only.
    docs: std::sync::Mutex<HashMap<DocKey, (Instant, bytes::Bytes)>>,
    refresh: tokio::sync::Semaphore,
    /// Per registry, the places it holds out of `refresh`.
    per_registry: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
}

impl Default for Shared {
    fn default() -> Shared {
        Shared {
            services: Default::default(),
            shared: Default::default(),
            raw: Default::default(),
            gates: Default::default(),
            docs: Default::default(),
            refresh: tokio::sync::Semaphore::new(REFRESHES),
            per_registry: Default::default(),
        }
    }
}

/// The sizes of the process-owned tables (service indexes, shared projects, registration documents, aux documents,
/// refresh gates), so a test can assert each stays bounded.
pub fn table_sizes(app: &App) -> [usize; 5] {
    [
        lock(&app.nuget.services).len(),
        lock(&app.nuget.shared).len(),
        lock(&app.nuget.raw).len(),
        lock(&app.nuget.docs).len(),
        lock(&app.nuget.gates).len(),
    ]
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ------------------------------------------------------------------ origins

/// The origin set a request reads through and the kinds of the resources.
struct Origins {
    set: OriginSet,
    index: OriginKind,
    search: OriginKind,
    publish: OriginKind,
    /// The selected registry's origin with no path: every resource of the registry lives under it.
    root: Option<Url>,
    /// The registry's service index URL.
    service_index: Url,
    /// The path prefix (whole segments) every resource of a selected registry must lie under, when its descriptor says so.
    prefix: Option<String>,
}

/// A selected registry's origin without the path of its `target_url`: its resources (flat container,
/// registration, search) are named by its service index and live anywhere on its host.
pub fn registry_root(target: &Url) -> Url {
    let mut root = target.clone();
    root.set_path("/");
    root.set_query(None);
    root.set_fragment(None);
    root
}

/// A registry's `target_url` names its service index: the document itself (`.../index.json`) or its directory.
fn service_index_of(target: &Url) -> Url {
    let mut url = target.clone();
    url.set_query(None);
    url.set_fragment(None);
    if !url
        .path()
        .rsplit('/')
        .next()
        .unwrap_or("")
        .ends_with(".json")
    {
        let mut path = url.path().to_owned();
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str("index.json");
        url.set_path(&path);
    }
    url
}

/// The origin a selected registry's resources must lie on, when it is a registry of its own. A registry whose
/// target is the configured public NuGet host (an organisation adds nuget.org by its service index URL) is the
/// public registry: its resources are the three configured public hosts, as for a firewall with no target.
pub fn selected_root(app: &App, target: &Url) -> Option<Url> {
    let root = registry_root(target);
    (root.origin() != app.origins.origin(OriginKind::NugetIndex).origin()).then_some(root)
}

fn origins_for(app: &App, principal: Option<&Principal>) -> Result<Origins, ApiError> {
    let target = principal.and_then(|p| p.registry_origin.as_ref());
    match target.and_then(|target| selected_root(app, target).map(|root| (target, root))) {
        Some((target, root)) => Ok(Origins {
            set: OriginSet::selected_npm_with_private(
                root.clone(),
                principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            )
            .map_err(|_| ApiError::NotFound)?,
            index: OriginKind::NpmMetadata,
            search: OriginKind::NpmMetadata,
            publish: OriginKind::NpmMetadata,
            service_index: service_index_of(target),
            root: Some(root),
            prefix: principal.and_then(|p| p.registry_resource_prefix.clone()),
        }),
        None => Ok(Origins {
            service_index: match target {
                Some(target) => service_index_of(target),
                None => app
                    .origins
                    .url_for(OriginKind::NugetIndex, &["v3", "index.json"])
                    .map_err(|_| ApiError::NotFound)?,
            },
            set: app.origins.clone(),
            index: OriginKind::NugetIndex,
            search: OriginKind::NugetSearch,
            publish: OriginKind::NugetPublish,
            root: None,
            prefix: None,
        }),
    }
}

impl Origins {
    /// Whether `url` lies under the registry's resource path prefix (whole segments), when it declared one.
    fn under_prefix(&self, url: &Url) -> bool {
        self.prefix.as_deref().is_none_or(|prefix| {
            url.path() == prefix || url.path().starts_with(&format!("{prefix}/"))
        })
    }

    fn kind_of(&self, resource: ResourceKind) -> OriginKind {
        match resource {
            ResourceKind::Search | ResourceKind::Autocomplete => self.search,
            ResourceKind::Publish | ResourceKind::SymbolPublish => self.publish,
            _ => self.index,
        }
    }
}

fn index_cap(app: &App) -> u64 {
    app.config.max_metadata_bytes.get().max(DOC_FLOOR_CAP)
}

fn max_versions(app: &App) -> usize {
    (app.config.max_references_per_project.get() as usize / FILES_PER_VERSION).max(1)
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
            tracing::warn!(error = %other, "the NuGet registry fetch failed");
            ApiError::UpstreamFailure
        }
    }
}

/// One metadata document: `None` when the registry has no such document (404 or 410).
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
            origin: principal
                .and_then(|p| p.registry_origin.as_ref())
                .and_then(|target| selected_root(app, target)),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept,
            validators: None,
            max_bytes,
        })
        .await;
    app.upstreams.record_upstream(Call::Nuget, &fetched);
    match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => Ok(Some(body)),
        Ok(MetadataResponse::Missing) => Ok(None),
        Ok(MetadataResponse::NotModified { .. }) => Err(ApiError::UpstreamInvalid),
        Err(error) => Err(status_error(app, error)),
    }
}

fn service_failure(error: ApiError) -> ServiceFailure {
    match error {
        ApiError::UpstreamUnauthenticated => ServiceFailure::Unauthenticated,
        ApiError::UpstreamDenied => ServiceFailure::Denied,
        ApiError::UpstreamTimeout => ServiceFailure::Timeout,
        ApiError::UpstreamInvalid => ServiceFailure::Invalid,
        _ => ServiceFailure::Failed,
    }
}

async fn fetch_resources(
    app: &App,
    principal: Option<&Principal>,
    origins: &Origins,
) -> Result<Arc<Resources>, ServiceFailure> {
    let body = match fetch(
        app,
        principal,
        origins.service_index.clone(),
        JSON,
        SERVICE_INDEX_CAP.min(app.config.max_metadata_bytes.get()),
    )
    .await
    {
        Ok(Some(body)) => body,
        Ok(None) => return Err(ServiceFailure::Missing),
        Err(error) => return Err(service_failure(error)),
    };
    let admit = |kind: ResourceKind, url: &Url| {
        origins.set.admit(url, origins.kind_of(kind)).is_ok() && origins.under_prefix(url)
    };
    doc::parse_service_index(&body, MAX_RESOURCES, &admit)
        .map(Arc::new)
        .map_err(|error| {
            tracing::warn!(?error, "the registry's service index is unusable");
            ServiceFailure::Invalid
        })
}

/// The resources of the registry the request reads through: cached 60 s per (registry, origin) with one fetch
/// at a time, and never read from or written to the cache by a credential-bearing read (C1028).
pub async fn resources(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
) -> Result<Arc<Resources>, ApiError> {
    let origins = origins_for(app, principal)?;
    let cacheable = crate::http::credential_read::cache_token(app).is_some();
    if !cacheable {
        return fetch_resources(app, principal, &origins)
            .await
            .map_err(ApiError::from);
    }
    let key = (
        registry_id,
        principal
            .and_then(|p| p.registry_origin.as_ref())
            .map(|origin| format!("{origin}|{}", origins.prefix.as_deref().unwrap_or(""))),
    );
    let cell = {
        let mut map = lock(&app.nuget.services);
        if map.len() >= MAX_SERVICE_INDEXES && !map.contains_key(&key) {
            map.retain(|_, cell| Arc::strong_count(cell) > 1);
        }
        Arc::clone(map.entry(key).or_default())
    };
    let mut guard = cell.lock().await;
    if let Some(cell) = guard.as_ref() {
        let ttl = if cell.result.is_ok() {
            SERVICE_INDEX_TTL
        } else {
            SERVICE_INDEX_FAILURE_TTL
        };
        if app.clock.now_monotonic().saturating_duration_since(cell.at) < ttl {
            return cell.result.clone().map_err(ApiError::from);
        }
    }
    let result = fetch_resources(app, principal, &origins).await;
    *guard = Some(ServiceCell {
        at: app.clock.now_monotonic(),
        result: result.clone(),
    });
    result.map_err(ApiError::from)
}

fn valid_id(id: &str) -> Result<&str, ApiError> {
    (valid_name(Ecosystem::NuGet, id) && !id.bytes().any(|b| b.is_ascii_uppercase()))
        .then_some(id)
        .ok_or(ApiError::NotFound)
}

/// A version in the one spelling a URL carries: the normalised lower-case form.
fn valid_version(version: &str) -> Result<&str, ApiError> {
    (version.len() <= MAX_VERSION && nuget_version(version).as_deref() == Some(version))
        .then_some(version)
        .ok_or(ApiError::NotFound)
}

// ------------------------------------------------------------------ references

type Refs = [(File, ReferenceId, ArtifactReference); FILES_PER_VERSION];

/// One file's reference of one version, its URL built below the registry's own flat container.
fn reference(
    flat: &Url,
    origins: &Origins,
    id: &str,
    version: &str,
    registry_id: u64,
    file: File,
) -> Option<(File, ReferenceId, ArtifactReference)> {
    let filename = file.name(id, version);
    let url = origins
        .set
        .url_below(origins.index, flat, &[id, version, &filename])
        .ok()?;
    let reference = ArtifactReference {
        ecosystem: Ecosystem::NuGet,
        name: id.to_owned(),
        version: version.to_owned(),
        filename,
        upstream_url: url,
        // Neither the flat container nor registration advertises a digest; the first verified download
        // pins one (SPEC §9, STATE-01) and the client verifies the package signature itself.
        expected: Vec::new(),
    };
    Some((
        file,
        ReferenceId::compute_in_registry(registry_id, &reference),
        reference,
    ))
}

/// The references of one version.
fn references(
    flat: &Url,
    origins: &Origins,
    id: &str,
    version: &str,
    registry_id: u64,
) -> Option<Refs> {
    let build = |file: File| reference(flat, origins, id, version, registry_id, file);
    Some([
        build(File::Nupkg)?,
        build(File::Nuspec)?,
        build(File::Readme)?,
        build(File::Icon)?,
    ])
}

fn id_of(refs: &Refs, file: File) -> ReferenceId {
    refs.iter()
        .find(|(f, ..)| *f == file)
        .map(|(_, id, _)| *id)
        .expect("every file is built")
}

fn publication_of(entry: &Entry, id: &ReferenceId, cached: &CachedProject) -> PublicationTime {
    match entry.published {
        Some(micros) => PublicationTime::Upstream(micros),
        None => cached
            .first_seen
            .get(id)
            .copied()
            .or(entry.seen)
            .map_or(PublicationTime::Unknown, PublicationTime::FirstSeen),
    }
}

// ------------------------------------------------------------------ the project

/// One page of a registration: the registry's own bounds, the URL to fetch when the index only links it (`None`: its leaves
/// are inline in the index), and where its versions lie in `RegRaw::entries`.
struct PageInfo {
    bounds: Option<(String, String)>,
    link: Option<Url>,
    start: usize,
    end: usize,
}

/// A registration as fetched: the index document as the registry sent it and what every page says of its versions. The
/// leaves of a linked page are not kept (a page is fetched again when its own route is read), so a project of any size
/// costs a few dozen bytes per version here, shareable for a few seconds without a tree of values.
struct RegRaw {
    index: bytes::Bytes,
    pages: Vec<PageInfo>,
    entries: Vec<doc::RegEntry>,
    bytes: usize,
}

impl RegRaw {
    fn index_value(&self) -> Result<serde_json::Value, ApiError> {
        serde_json::from_slice(&self.index).map_err(|_| invalid("the registration index"))
    }
}

struct Fetched {
    flat: Vec<String>,
    registration: Option<Arc<RegRaw>>,
}

fn invalid(what: &'static str) -> ApiError {
    tracing::warn!(what, "the registry's NuGet document is unusable");
    ApiError::UpstreamInvalid
}

async fn fetch_flat(
    app: &App,
    principal: Option<&Principal>,
    origins: &Origins,
    resources: &Resources,
    id: &str,
) -> Result<Vec<String>, ApiError> {
    let base = resources.flat.as_ref().ok_or(ApiError::UpstreamInvalid)?;
    let url = origins
        .set
        .url_below(origins.index, base, &[id, "index.json"])
        .map_err(|_| ApiError::NotFound)?;
    let Some(body) = fetch(app, principal, url, JSON, index_cap(app)).await? else {
        return Err(ApiError::NotFound);
    };
    doc::parse_flat(&body, MAX_FLAT_VERSIONS).map_err(|_| invalid("the flat container index"))
}

/// The registration index of `id`: its bytes, its decoded document and its pages. `None` when the registry has none.
async fn fetch_registration_index(
    app: &App,
    principal: Option<&Principal>,
    origins: &Origins,
    resources: &Resources,
    id: &str,
) -> Result<Option<(bytes::Bytes, serde_json::Value, Vec<doc::PageDesc>)>, ApiError> {
    let Some(base) = resources.registration.as_ref() else {
        return Ok(None);
    };
    let url = origins
        .set
        .url_below(origins.index, base, &[id, "index.json"])
        .map_err(|_| ApiError::NotFound)?;
    let Some(index) = fetch(app, principal, url, JSON, index_cap(app)).await? else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_slice(&index).map_err(|_| invalid("the registration index"))?;
    let pages =
        doc::index_page_descs(&value, MAX_PAGES).map_err(|_| invalid("the registration pages"))?;
    Ok(Some((index, value, pages)))
}

/// A linked page lies under this registration's own directory of the registration base, nowhere else.
fn admit_page_link(origins: &Origins, base: &Url, id: &str, link: &str) -> Result<Url, ApiError> {
    let mut prefix = origins
        .set
        .url_below(origins.index, base, &[id])
        .map_err(|_| ApiError::NotFound)?;
    prefix.set_path(&format!("{}/", prefix.path().trim_end_matches('/')));
    let url = Url::parse(link).map_err(|_| invalid("a registration page link"))?;
    let inside = url.scheme() == prefix.scheme()
        && url.host_str() == prefix.host_str()
        && url.port_or_known_default() == prefix.port_or_known_default()
        && url.path().starts_with(prefix.path())
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().ends_with(".json");
    if !inside || origins.set.admit(&url, origins.index).is_err() {
        return Err(invalid("a registration page outside the registration"));
    }
    Ok(url)
}

/// The leaves of one linked page of the registration.
async fn fetch_page_leaves(
    app: &App,
    principal: Option<&Principal>,
    url: Url,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let Some(body) = fetch(app, principal, url, JSON, index_cap(app)).await? else {
        return Err(invalid("a missing registration page"));
    };
    let page: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| invalid("a registration page"))?;
    doc::page_leaves(&page).map_err(|_| invalid("a registration page"))
}

type PageFacts = Result<(Option<Url>, Vec<doc::RegEntry>), ApiError>;

/// What one page of a registration says of its versions (read from the index when inline, else fetched).
#[allow(clippy::too_many_arguments)]
async fn page_facts(
    app: &App,
    principal: Option<&Principal>,
    origins: &Origins,
    base: &Url,
    id: &str,
    index: &serde_json::Value,
    n: usize,
    desc: &doc::PageDesc,
) -> PageFacts {
    let facts =
        |leaves: &[serde_json::Value]| leaves.iter().filter_map(doc::entry_of).collect::<Vec<_>>();
    match &desc.link {
        None => Ok((
            None,
            facts(doc::inline_leaves(index, n).map_err(|_| invalid("a registration page"))?),
        )),
        Some(link) => {
            if desc.bounds.is_none() {
                return Err(invalid("a registration page without bounds"));
            }
            let url = admit_page_link(origins, base, id, link)?;
            let leaves = fetch_page_leaves(app, principal, url.clone()).await?;
            Ok((Some(url), facts(&leaves)))
        }
    }
}

/// The registration of `id`: the index, and what each page says of its versions (a page is read, its facts taken and its
/// bytes dropped, so the memory of a request does not grow with the number of versions beyond those facts). `None`
/// when the registry has no registration of it.
async fn fetch_registration(
    app: &App,
    principal: Option<&Principal>,
    origins: &Origins,
    resources: &Resources,
    id: &str,
) -> Result<Option<Arc<RegRaw>>, ApiError> {
    let Some(base) = resources.registration.as_ref() else {
        return Ok(None);
    };
    let Some((index, value, descs)) =
        fetch_registration_index(app, principal, origins, resources, id).await?
    else {
        return Ok(None);
    };
    type Fact<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = PageFacts> + Send + 'a>>;
    let work: Vec<Fact<'_>> = descs
        .iter()
        .enumerate()
        .map(|(n, desc)| -> Fact<'_> {
            Box::pin(page_facts(
                app, principal, origins, base, id, &value, n, desc,
            ))
        })
        .collect();
    let fetched: Vec<PageFacts> = futures_util::stream::iter(work)
        .buffered(PAGE_PARALLEL)
        .collect()
        .await;
    let mut pages = Vec::with_capacity(descs.len());
    let mut entries: Vec<doc::RegEntry> = Vec::new();
    for (desc, page) in descs.into_iter().zip(fetched) {
        let (link, facts) = page?;
        let start = entries.len();
        entries.extend(facts);
        if entries.len() > MAX_FLAT_VERSIONS * 2 {
            return Err(invalid("a registration over the version bound"));
        }
        pages.push(PageInfo {
            bounds: desc.bounds,
            link,
            start,
            end: entries.len(),
        });
    }
    let bytes = index.len() + entries.len() * 64 + pages.len() * 128;
    Ok(Some(Arc::new(RegRaw {
        index,
        pages,
        entries,
        bytes,
    })))
}

async fn fetch_upstream(
    app: &App,
    principal: Option<&Principal>,
    origins: &Origins,
    resources: &Resources,
    id: &str,
) -> Result<Fetched, ApiError> {
    let (flat, registration) = tokio::join!(
        fetch_flat(app, principal, origins, resources, id),
        fetch_registration(app, principal, origins, resources, id)
    );
    Ok(Fetched {
        flat: flat?,
        registration: registration?,
    })
}

/// The versions of a fetched project: the flat container's (downloadable) with their registration dates, then any
/// version only registration names. A version registration lists twice keeps its later date. Every version is kept.
fn entries_of(fetched: &Fetched) -> Result<Vec<Entry>, ApiError> {
    let mut by_version: HashMap<&str, doc::RegEntry> = HashMap::new();
    let facts: &[doc::RegEntry] = fetched
        .registration
        .as_ref()
        .map_or(&[], |raw| raw.entries.as_slice());
    for entry in facts {
        match by_version.get_mut(entry.version.as_str()) {
            Some(have) => {
                have.published = have.published.max(entry.published);
                have.listed &= entry.listed;
            }
            None => {
                by_version.insert(entry.version.as_str(), entry.clone());
            }
        }
    }
    let mut out: Vec<Entry> = Vec::with_capacity(fetched.flat.len());
    let mut seen = std::collections::HashSet::new();
    for version in &fetched.flat {
        let known = by_version.get(version.as_str());
        out.push(Entry {
            version: version.clone(),
            published: known.and_then(|k| k.published),
            listed: known.is_none_or(|k| k.listed),
            in_flat: true,
            seen: None,
        });
        seen.insert(version.as_str());
    }
    for entry in facts {
        if seen.insert(entry.version.as_str()) {
            let known = &by_version[entry.version.as_str()];
            out.push(Entry {
                version: entry.version.clone(),
                published: known.published,
                listed: known.listed,
                in_flat: false,
                seen: None,
            });
        }
    }
    if out.len() > MAX_FLAT_VERSIONS {
        return Err(invalid("a project over the version bound"));
    }
    Ok(out)
}

fn upserts_of(entry: &Entry, refs: Refs, now: i64) -> impl Iterator<Item = ReferenceUpsert> {
    let first_seen = entry.published.is_none().then(|| entry.seen.unwrap_or(now));
    let published = entry.published;
    refs.into_iter()
        .map(move |(_, id, reference)| ReferenceUpsert {
            id,
            reference,
            publication_micros: published,
            first_seen_micros: first_seen,
        })
}

/// A version with no date waits on when this firewall first saw it: the time a previous refresh stamped it with, or the
/// committed first-seen time of its rows, else now. Done for every such version, with or without rows.
async fn stamp_first_seen(
    app: &App,
    key: &ProjectKey,
    id: &str,
    entries: &mut [Entry],
    flat: &Url,
    origins: &Origins,
    now: i64,
) -> Result<(), ApiError> {
    if entries.iter().all(|entry| entry.published.is_some()) {
        return Ok(());
    }
    let previous: HashMap<String, i64> = match app
        .store()
        .get_project_in(key.registry_id, Ecosystem::NuGet, id)
        .await
        .map_err(storage_error)?
    {
        Some(row) => parse_payload(&row.payload, MAX_FLAT_VERSIONS)
            .map(|payload| {
                payload
                    .versions
                    .into_iter()
                    .filter_map(|entry| entry.seen.map(|seen| (entry.version, seen)))
                    .collect()
            })
            .unwrap_or_default(),
        None => HashMap::new(),
    };
    let rows = app
        .store()
        .list_project_first_seen_in(key.registry_id, Ecosystem::NuGet, id)
        .await
        .map_err(storage_error)?;
    for entry in entries.iter_mut().filter(|entry| entry.published.is_none()) {
        let committed = reference(
            flat,
            origins,
            id,
            &entry.version,
            key.registry_id,
            File::Nupkg,
        )
        .and_then(|(_, reference, _)| rows.get(&reference).copied());
        entry.seen = Some(
            previous
                .get(&entry.version)
                .copied()
                .or(committed)
                .unwrap_or(now),
        );
    }
    Ok(())
}

/// A registry's own share of the refresh places first, then one of the process-wide ones, both inside one wait.
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
                let mut map = lock(&app.nuget.per_registry);
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
            .nuget
            .refresh
            .acquire()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        Ok::<_, ApiError>((own, place))
    })
    .await
    .map_err(|_| ApiError::UpstreamTimeout)?
}

/// Fetch, derive and commit the project of `id` (and give back the registration documents the fetch carried).
#[allow(clippy::too_many_arguments)]
async fn refresh_with_docs(
    app: &App,
    id: &str,
    key: &ProjectKey,
    absent_key: &ProjectKey,
    now: i64,
    principal: Option<&Principal>,
    resources: &Resources,
) -> Result<(Arc<CachedProject>, Option<Arc<RegRaw>>), ApiError> {
    let _places = refresh_places(app, key.registry_id).await?;
    let origins = origins_for(app, principal)?;
    let fetched = match fetch_upstream(app, principal, &origins, resources, id).await {
        Ok(fetched) => fetched,
        Err(ApiError::NotFound) => {
            if let Some(token) = crate::http::credential_read::cache_token(app)
                .filter(|_| app.service_policy().is_none())
            {
                app.store().caches().absent.insert(
                    &token,
                    absent_key.clone(),
                    Arc::new(crate::store::cache::AbsentMark {
                        observed_monotonic: app.clock.now_monotonic(),
                    }),
                    128,
                );
            }
            return Err(ApiError::NotFound);
        }
        Err(error) => return Err(error),
    };
    let mut entries = entries_of(&fetched)?;
    let flat_base = resources.flat.as_ref().ok_or(ApiError::UpstreamInvalid)?;
    stamp_first_seen(app, key, id, &mut entries, flat_base, &origins, now).await?;
    // The newest versions (the flat container lists oldest first) have their four rows now; any other version gets its
    // rows when a file of it is first asked for, so the stored project and the lists keep every version.
    let window = entries.len().saturating_sub(max_versions(app));
    let mut upserts = Vec::with_capacity((entries.len() - window) * FILES_PER_VERSION);
    for entry in &entries[window..] {
        let Some(refs) = references(flat_base, &origins, id, &entry.version, key.registry_id)
        else {
            tracing::warn!(package = %id, "the flat container URL of a version is outside the registry's own origin");
            return Err(ApiError::UpstreamInvalid);
        };
        upserts.extend(upserts_of(entry, refs, now));
    }
    let payload: Arc<[u8]> = Arc::from(
        serde_json::to_vec(&Payload {
            id: id.to_owned(),
            versions: entries,
        })
        .map_err(|_| ApiError::InternalFailure)?,
    );
    let refresh = ProjectRefresh {
        ecosystem: Ecosystem::NuGet,
        name: id.to_owned(),
        payload: Arc::clone(&payload),
        validators: Default::default(),
        validated_at_micros: now,
        fetched_at_micros: now,
        references: upserts,
    };
    let committed = if app.service_policy().is_some() {
        app.store()
            .commit_request_references_in(key.registry_id, refresh)
            .await
    } else {
        app.store()
            .commit_project_refresh_in(key.registry_id, refresh)
            .await
    }
    .map_err(storage_error)?;
    let pins = app
        .store()
        .list_project_pins_in(key.registry_id, Ecosystem::NuGet, id)
        .await
        .map_err(storage_error)?;
    Ok((
        Arc::new(CachedProject {
            row: ProjectRow {
                ecosystem: Ecosystem::NuGet,
                name: id.to_owned(),
                payload,
                validators: Default::default(),
                validated_at_micros: now,
                fetched_at_micros: now,
                generation: committed.generation as Generation,
                digest_generation: committed.digest_generation,
            },
            first_seen: committed.first_seen,
            pins,
            advertised: OnceLock::new(),
        }),
        fetched.registration,
    ))
}

async fn load_project(
    app: &App,
    id: &str,
    registry_id: u64,
) -> Result<Option<CachedProject>, ApiError> {
    let Some(row) = app
        .store()
        .get_project_in(registry_id, Ecosystem::NuGet, id)
        .await
        .map_err(storage_error)?
    else {
        return Ok(None);
    };
    let first_seen = app
        .store()
        .list_project_first_seen_in(registry_id, Ecosystem::NuGet, id)
        .await
        .map_err(storage_error)?;
    let pins = app
        .store()
        .list_project_pins_in(registry_id, Ecosystem::NuGet, id)
        .await
        .map_err(storage_error)?;
    Ok(Some(CachedProject {
        row,
        first_seen,
        pins,
        advertised: OnceLock::new(),
    }))
}

/// Shared-service mode: keeps a project a credential-free read just fetched for `SERVICE_SHARE_TTL` (bounded).
fn remember_project(app: &App, key: ShareKey, at: Instant, project: &Arc<CachedProject>) {
    let mut shared = lock(&app.nuget.shared);
    if shared.len() >= MAX_SHARED_PROJECTS {
        shared.clear();
    }
    shared.insert(key, (at, Arc::clone(project)));
}

/// One request at a time refreshes one project (credential-free reads): the others wait for it and then find what it
/// stored. A read that carries the caller's credential shares nothing, so it takes no gate (it still takes one of the
/// process-wide refresh places). The gate table is bounded.
async fn single_flight(
    app: &App,
    key: &ShareKey,
    shareable: bool,
) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, ApiError> {
    if !shareable {
        return Ok(None);
    }
    let gate = {
        let mut gates = lock(&app.nuget.gates);
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

fn share_key(registry_id: u64, principal: Option<&Principal>, id: &str) -> ShareKey {
    (
        registry_id,
        principal
            .and_then(|p| p.registry_origin.as_ref())
            .map(Url::to_string),
        id.to_owned(),
    )
}

/// The project snapshot a decision is made from (SPEC §10): the cached one within its TTL, else a refreshed one.
async fn current_project(
    app: &App,
    id: &str,
    registry_id: u64,
    principal: Option<&Principal>,
    resources: &Resources,
) -> Result<Arc<CachedProject>, ApiError> {
    if let Some(project) = project_inner(app, id, registry_id, principal, resources, false).await? {
        return Ok(project);
    }
    let shareable = crate::http::credential_read::cache_token(app).is_some();
    let _gate = single_flight(app, &share_key(registry_id, principal, id), shareable).await?;
    project_inner(app, id, registry_id, principal, resources, true)
        .await?
        .ok_or(ApiError::InternalFailure)
}

/// The cached project when it is fresh, else (`may_refresh`) a refreshed one, else `None`.
async fn project_inner(
    app: &App,
    id: &str,
    registry_id: u64,
    principal: Option<&Principal>,
    resources: &Resources,
    may_refresh: bool,
) -> Result<Option<Arc<CachedProject>>, ApiError> {
    let now = app.clock.now_utc_micros();
    let monotonic = app.clock.now_monotonic();
    let key = ProjectKey::in_registry(registry_id, Ecosystem::NuGet, id);
    if app.service_policy().is_some() {
        let share_key = share_key(registry_id, principal, id);
        let shareable = crate::http::credential_read::cache_token(app).is_some();
        if shareable
            && let Some((at, project)) = lock(&app.nuget.shared).get(&share_key)
            && monotonic.saturating_duration_since(*at) < SERVICE_SHARE_TTL
        {
            return Ok(Some(Arc::clone(project)));
        }
        if !may_refresh {
            return Ok(None);
        }
        let (project, _) =
            refresh_with_docs(app, id, &key, &key, now, principal, resources).await?;
        if shareable {
            remember_project(app, share_key, monotonic, &project);
        }
        return Ok(Some(project));
    }
    let caches = app.store().caches();
    let ttl = Duration::from_secs(app.config.metadata_ttl_seconds);
    let ttl_micros = i64::try_from(ttl.as_micros()).unwrap_or(i64::MAX);
    if let Some(mark) = caches.absent.get(&key) {
        if monotonic.duration_since(mark.observed_monotonic) < ttl {
            return Err(ApiError::NotFound);
        }
        caches.absent.remove(&key);
    }
    let (seen, cached) = caches.projects.get_with_seen(&key);
    let cached = match cached {
        Some(cached) => Some(cached),
        None => load_project(app, id, registry_id).await?.map(Arc::new),
    };
    let over_age = cached.as_ref().is_some_and(|c| {
        crate::store::is_over_age(
            &key,
            app.config.metadata_max_age_seconds,
            c.row.fetched_at_micros,
            now,
        )
    });
    let cached = match cached {
        Some(cached)
            if !over_age && now < cached.row.validated_at_micros.saturating_add(ttl_micros) =>
        {
            cached
        }
        _ if !may_refresh => return Ok(None),
        _ => {
            refresh_with_docs(app, id, &key, &key, now, principal, resources)
                .await?
                .0
        }
    };
    if let Some(token) = crate::http::credential_read::cache_token(app) {
        caches.projects.insert_if_current(
            &token,
            key,
            Arc::clone(&cached),
            cached.approximate_bytes(),
            seen,
        );
    }
    Ok(Some(cached))
}

fn entries_in(_app: &App, id: &str, cached: &CachedProject) -> Result<Vec<Entry>, ApiError> {
    match parse_payload(&cached.row.payload, MAX_FLAT_VERSIONS) {
        Some(payload) if payload.id == id => Ok(payload.versions),
        _ => {
            tracing::warn!(package = %id, "a stored NuGet project is unusable");
            Err(ApiError::UpstreamInvalid)
        }
    }
}

// ------------------------------------------------------------------ judging

/// Decide every version of a project: the decision of the `nupkg` of each (digest pins and OSV follow the package).
async fn judge(
    app: &App,
    principal: Option<&Principal>,
    id: &str,
    entries: &[Entry],
    cached: &CachedProject,
    flat: &Url,
    registry_id: u64,
) -> Result<Vec<Decision>, ApiError> {
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
    let scope = app.osv_scope(registry_id);
    let judged = futures_util::future::join_all(entries.iter().map(|entry| {
        let (policy, origins) = (&policy, &origins);
        async move {
            let Some((_, nupkg, _)) =
                reference(flat, origins, id, &entry.version, registry_id, File::Nupkg)
            else {
                return Decision::Unavailable;
            };
            let candidate = Candidate {
                ecosystem: Ecosystem::NuGet,
                name: id,
                version: &entry.version,
                publication: publication_of(entry, &nupkg, cached),
                advertised_digests: &[],
                pinned_digests: cached.pins_of(&nupkg),
            };
            crate::osv::evaluate_scoped(&app.osv, policy, now, &candidate, scope).await
        }
    }))
    .await;
    logging::record_cache(logging::CacheStatus::Miss);
    // A request every version of which is refused leaves one decision record naming the first refusal.
    if let (Some(principal), Some(managed)) = (principal, app.managed())
        && !entries.is_empty()
        && !judged
            .iter()
            .any(|decision| matches!(decision, Decision::Allow))
    {
        let blocked = judged
            .iter()
            .position(|decision| matches!(decision, Decision::Deny(_)));
        let held = || {
            judged
                .iter()
                .enumerate()
                .filter_map(|(i, d)| match d {
                    Decision::Hold { eligible_at_micros } => Some((*eligible_at_micros, i)),
                    _ => None,
                })
                .min()
                .map(|(_, i)| i)
        };
        if let Some(index) = blocked.or_else(held)
            && let Some(refs) = references(flat, &origins, id, &entries[index].version, registry_id)
        {
            let nupkg = id_of(&refs, File::Nupkg);
            let candidate = Candidate {
                ecosystem: Ecosystem::NuGet,
                name: id,
                version: &entries[index].version,
                publication: publication_of(&entries[index], &nupkg, cached),
                advertised_digests: &[],
                pinned_digests: cached.pins_of(&nupkg),
            };
            let verdict = crate::managed::refused_verdict(&policy, now, &candidate, judged[index]);
            managed.record_decision(principal, Ecosystem::NuGet, id, None, &verdict);
        }
    }
    Ok(judged)
}

/// The allowed versions of a project, in flat container order (the registry's own).
fn allowed_versions(entries: &[Entry], judged: &[Decision], flat_only: bool) -> Vec<String> {
    entries
        .iter()
        .zip(judged)
        .filter(|(entry, decision)| {
            (entry.in_flat || !flat_only) && matches!(decision, Decision::Allow)
        })
        .map(|(entry, _)| entry.version.clone())
        .collect()
}

/// A name a policy blocks outright (no date is needed to know it).
fn name_is_blocked(policy: &crate::policy::CompiledPolicy, now: i64, id: &str) -> bool {
    let candidate = Candidate {
        ecosystem: Ecosystem::NuGet,
        name: &canonical_name(Ecosystem::NuGet, id),
        version: "",
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    matches!(
        crate::policy::decide(policy, &candidate, now, false).decision,
        Decision::Deny(DenyReason::BlockedPackage)
    )
}

/// A name or version a policy blocks outright is refused without asking upstream anything (PERF-01): the decision
/// with no date is conclusive for these two reasons only. A managed key's refusal is recorded.
fn locally_blocked(
    app: &App,
    principal: Option<&Principal>,
    id: &str,
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
        ecosystem: Ecosystem::NuGet,
        name: id,
        version: version.unwrap_or(""),
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    match crate::policy::decide(&policy, &candidate, now, false).decision {
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

fn rendered(body: Vec<u8>) -> Rendered {
    Rendered {
        body: bytes::Bytes::from(body),
        content_type: JSON,
    }
}

fn check_policy(app: &App, principal: Option<&Principal>) -> Result<(), ApiError> {
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
    Ok(())
}

fn flat_base(resources: &Resources) -> Result<&Url, ApiError> {
    resources.flat.as_ref().ok_or(ApiError::UpstreamInvalid)
}

// ------------------------------------------------------------------ the documents of the routes

/// `GET {root}v3/index.json`: the registry's own service index with every resource this firewall serves pointing
/// at it. `writes`: the shared service also advertises the publish endpoints.
pub async fn serve_service_index(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    root: &Url,
) -> Result<Rendered, ApiError> {
    check_policy(app, principal)?;
    let resources = resources(app, principal, registry_id).await?;
    let writes = app.service_policy().is_some() || (registry_id != 0 && app.managed().is_some());
    Ok(rendered(doc::render_service_index(
        &resources, root, writes,
    )))
}

/// `GET {root}v3-flatcontainer/{id}/index.json`: the versions the policy allows, in the registry's order.
pub async fn serve_flat_index(
    app: &App,
    principal: Option<&Principal>,
    id: &str,
    registry_id: u64,
) -> Result<Rendered, ApiError> {
    let id = valid_id(id)?;
    locally_blocked(app, principal, id, None)?;
    let resources = resources(app, principal, registry_id).await?;
    let cached = current_project(app, id, registry_id, principal, &resources).await?;
    let entries = entries_in(app, id, &cached)?;
    let judged = judge(
        app,
        principal,
        id,
        &entries,
        &cached,
        flat_base(&resources)?,
        registry_id,
    )
    .await?;
    let allowed = allowed_versions(&entries, &judged, true);
    Ok(rendered(doc::render_flat(
        allowed.iter().map(String::as_str),
    )))
}

fn route_urls(root: &Url) -> Result<(Url, Url), ApiError> {
    Ok((
        root.join("v3/registration/")
            .map_err(|_| ApiError::InternalFailure)?,
        root.join("v3-flatcontainer/")
            .map_err(|_| ApiError::InternalFailure)?,
    ))
}

/// The registration documents a credential-free read fetched within `RAW_TTL`.
fn fresh_raw(app: &App, key: &ShareKey) -> Option<Arc<RegRaw>> {
    lock(&app.nuget.raw)
        .get(key)
        .filter(|(at, _)| app.clock.now_monotonic().saturating_duration_since(*at) < RAW_TTL)
        .map(|(_, raw)| Arc::clone(raw))
}

/// `GET {root}v3/registration/{id}/index.json`: every page inline, only the versions the policy allows.
pub async fn serve_registration_index(
    app: &App,
    principal: Option<&Principal>,
    id: &str,
    registry_id: u64,
    root: &Url,
) -> Result<Rendered, ApiError> {
    let id = valid_id(id)?;
    locally_blocked(app, principal, id, None)?;
    let resources = resources(app, principal, registry_id).await?;
    if resources.registration.is_none() {
        return Err(ApiError::NotFound);
    }
    let now = app.clock.now_utc_micros();
    let key = ProjectKey::in_registry(registry_id, Ecosystem::NuGet, id);
    // A credential-free read shares the documents another one fetched a few seconds ago; a read that carries the
    // caller's credential reads and fills nothing shared (C1028).
    let share_key = (
        registry_id,
        principal
            .and_then(|p| p.registry_origin.as_ref())
            .map(Url::to_string),
        id.to_owned(),
    );
    let shareable = crate::http::credential_read::cache_token(app).is_some();
    let monotonic = app.clock.now_monotonic();
    let mut raw = if shareable {
        fresh_raw(app, &share_key)
    } else {
        None
    };
    let mut gate = None;
    if raw.is_none() {
        // One request refreshes the registration; the others wait for it and then use what it stored.
        gate = single_flight(app, &share_key, shareable).await?;
        raw = if shareable {
            fresh_raw(app, &share_key)
        } else {
            None
        };
    }
    let (cached, raw) = match raw {
        Some(raw) => {
            drop(gate);
            (
                current_project(app, id, registry_id, principal, &resources).await?,
                Some(raw),
            )
        }
        None => {
            let (cached, raw) =
                refresh_with_docs(app, id, &key, &key, now, principal, &resources).await?;
            drop(gate);
            if shareable && app.service_policy().is_some() {
                remember_project(app, share_key.clone(), monotonic, &cached);
            }
            if shareable
                && let Some(raw) = &raw
                && raw.bytes <= MAX_RAW_BYTES
            {
                let mut map = lock(&app.nuget.raw);
                if map.len() >= MAX_RAW {
                    map.clear();
                }
                map.insert(share_key, (monotonic, Arc::clone(raw)));
            }
            (cached, raw)
        }
    };
    let raw = raw.ok_or(ApiError::NotFound)?;
    let entries = entries_in(app, id, &cached)?;
    let judged = judge(
        app,
        principal,
        id,
        &entries,
        &cached,
        flat_base(&resources)?,
        registry_id,
    )
    .await?;
    let allowed: std::collections::HashSet<String> = allowed_versions(&entries, &judged, false)
        .into_iter()
        .collect();
    let (registration, flat) = route_urls(root)?;
    let origins = origins_for(app, principal)?;
    let upstream = resources
        .registration
        .clone()
        .unwrap_or_else(|| origins.service_index.clone());
    let links = Links {
        registration: &registration,
        flat: &flat,
        upstream: &upstream,
    };
    let index = raw.index_value()?;
    let versions: Vec<Vec<String>> = raw
        .pages
        .iter()
        .map(|page| {
            raw.entries[page.start..page.end]
                .iter()
                .map(|entry| entry.version.clone())
                .collect()
        })
        .collect();
    let mut views = Vec::with_capacity(raw.pages.len());
    for (n, page) in raw.pages.iter().enumerate() {
        let inline = if page.link.is_none() {
            Some(doc::inline_leaves(&index, n).map_err(|_| invalid("a registration page"))?)
        } else {
            None
        };
        views.push(doc::PageView {
            inline,
            bounds: page
                .bounds
                .as_ref()
                .map(|(lower, upper)| (lower.as_str(), upper.as_str())),
            versions: &versions[n],
        });
    }
    let value = doc::render_registration(&index, &views, &links, id, &|version| {
        allowed.contains(version)
    });
    Ok(rendered(
        serde_json::to_vec(&value).map_err(|_| ApiError::InternalFailure)?,
    ))
}

/// `GET {root}v3/registration/{id}/page/{lower}/{upper}.json`: one page of the registration the index links, named by the
/// registry page's own bounds; the registry's page is read now and only the versions the policy allows are in it.
pub async fn serve_registration_page(
    app: &App,
    principal: Option<&Principal>,
    id: &str,
    lower: &str,
    upper: &str,
    registry_id: u64,
    root: &Url,
) -> Result<Rendered, ApiError> {
    let id = valid_id(id)?;
    let (lower, upper) = (valid_version(lower)?, valid_version(upper)?);
    locally_blocked(app, principal, id, None)?;
    let resources = resources(app, principal, registry_id).await?;
    let base = resources.registration.as_ref().ok_or(ApiError::NotFound)?;
    let cached = current_project(app, id, registry_id, principal, &resources).await?;
    let origins = origins_for(app, principal)?;
    // Reads the registry like a refresh does: under one of its places, and the index of a credential-free read is the one
    // another read fetched a few seconds ago (the 5 s share), so a client walking the pages costs one index fetch, not one a page.
    let _places = refresh_places(app, registry_id).await?;
    let shared = if crate::http::credential_read::cache_token(app).is_some() {
        fresh_raw(app, &share_key(registry_id, principal, id))
    } else {
        None
    };
    let (value, descs) = match shared {
        Some(raw) => (
            raw.index_value()?,
            raw.pages
                .iter()
                .map(|page| doc::PageDesc {
                    bounds: page.bounds.clone(),
                    link: page.link.as_ref().map(Url::to_string),
                })
                .collect(),
        ),
        None => {
            let (_, value, descs) =
                fetch_registration_index(app, principal, &origins, &resources, id)
                    .await?
                    .ok_or(ApiError::NotFound)?;
            (value, descs)
        }
    };
    let (n, desc) = descs
        .iter()
        .enumerate()
        .find(|(_, desc)| {
            desc.bounds
                .as_ref()
                .is_some_and(|(a, b)| a == lower && b == upper)
        })
        .ok_or(ApiError::NotFound)?;
    let leaves = match &desc.link {
        None => doc::inline_leaves(&value, n)
            .map_err(|_| invalid("a registration page"))?
            .to_vec(),
        Some(link) => {
            fetch_page_leaves(app, principal, admit_page_link(&origins, base, id, link)?).await?
        }
    };
    // Only the versions this page names are judged; one the stored project does not know is not shown.
    let entries = entries_in(app, id, &cached)?;
    let named: std::collections::HashSet<String> = leaves
        .iter()
        .filter_map(doc::entry_of)
        .map(|entry| entry.version)
        .collect();
    let subset: Vec<Entry> = entries
        .into_iter()
        .filter(|entry| named.contains(&entry.version))
        .collect();
    let judged = judge(
        app,
        principal,
        id,
        &subset,
        &cached,
        flat_base(&resources)?,
        registry_id,
    )
    .await?;
    let allowed: std::collections::HashSet<String> = allowed_versions(&subset, &judged, false)
        .into_iter()
        .collect();
    let (registration, flat) = route_urls(root)?;
    let links = Links {
        registration: &registration,
        flat: &flat,
        upstream: base,
    };
    let page = doc::render_page(&leaves, &links, id, (lower, upper), &|version| {
        allowed.contains(version)
    })
    .ok_or(ApiError::NotFound)?;
    Ok(rendered(
        serde_json::to_vec(&page).map_err(|_| ApiError::InternalFailure)?,
    ))
}

/// `GET {root}v3/registration/{id}/{version}.json`: the registry's leaf document, when the policy allows the version.
pub async fn serve_registration_leaf(
    app: &App,
    principal: Option<&Principal>,
    id: &str,
    version: &str,
    registry_id: u64,
    root: &Url,
) -> Result<Rendered, ApiError> {
    let id = valid_id(id)?;
    let version = valid_version(version)?;
    locally_blocked(app, principal, id, Some(version))?;
    let resources = resources(app, principal, registry_id).await?;
    let base = resources.registration.as_ref().ok_or(ApiError::NotFound)?;
    let cached = current_project(app, id, registry_id, principal, &resources).await?;
    let entries = entries_in(app, id, &cached)?;
    let position = entries
        .iter()
        .position(|entry| entry.version == version)
        .ok_or(ApiError::NotFound)?;
    let judged = judge(
        app,
        principal,
        id,
        &entries,
        &cached,
        flat_base(&resources)?,
        registry_id,
    )
    .await?;
    if !matches!(judged[position], Decision::Allow) {
        return Err(crate::artifacts::decision_error(
            judged[position],
            app.clock.now_utc_micros(),
        ));
    }
    let origins = origins_for(app, principal)?;
    let url = origins
        .set
        .url_below(origins.index, base, &[id, &format!("{version}.json")])
        .map_err(|_| ApiError::NotFound)?;
    let body = fetch(app, principal, url, JSON, index_cap(app))
        .await?
        .ok_or(ApiError::NotFound)?;
    let leaf: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| invalid("a registration leaf"))?;
    if doc::entry_of(&leaf).is_some_and(|entry| entry.version != version) {
        return Err(invalid("a registration leaf of another version"));
    }
    let (registration, flat) = route_urls(root)?;
    let links = Links {
        registration: &registration,
        flat: &flat,
        upstream: base,
    };
    let value = doc::render_leaf(leaf, &links, id, version);
    Ok(rendered(
        serde_json::to_vec(&value).map_err(|_| ApiError::InternalFailure)?,
    ))
}

/// The query keys of the search service that are passed on; every other is dropped. `take` is passed on exactly (the
/// registry applies its own ceiling): every returned id is judged, and a request that runs out of its deadline is a 504.
const SEARCH_KEYS: &[&str] = &[
    "q",
    "skip",
    "take",
    "prerelease",
    "semVerLevel",
    "packageType",
    "supportedFramework",
];
const AUTOCOMPLETE_KEYS: &[&str] = &[
    "q",
    "id",
    "skip",
    "take",
    "prerelease",
    "semVerLevel",
    "packageType",
    "supportedFramework",
];
const DEFAULT_TAKE: usize = 20;

fn query_pairs(query: Option<&str>, keys: &[&str]) -> Result<Vec<(String, String)>, ApiError> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        if !keys.contains(&key.as_ref())
            || value.len() > 256
            || out.iter().any(|(have, _)| *have == key)
        {
            continue;
        }
        if key == "take" && value.parse::<usize>().is_err() {
            return Err(ApiError::InvalidInput("take is a number"));
        }
        out.push((key.into_owned(), value.into_owned()));
    }
    if !out.iter().any(|(key, _)| key == "take") {
        out.push(("take".to_owned(), DEFAULT_TAKE.to_string()));
    }
    Ok(out)
}

/// The versions a client may see of each of `ids`, judged against its project; `None` when it cannot be judged (a
/// blocked id is refused before any upstream call; the whole judgement shares the request's deadline).
/// The versions allowed of one search result: `None` for a blocked or unknown one.
type Allowed = Option<Vec<String>>;

async fn allowed_for(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    resources: &Resources,
    ids: Vec<String>,
) -> Result<HashMap<String, Option<Vec<String>>>, ApiError> {
    let policy = app.policy_for(principal);
    let now = app.clock.now_utc_micros();
    let judged: Vec<(String, Result<Allowed, ApiError>)> =
        futures_util::stream::iter(ids.into_iter().map(|id| {
            let blocked = policy
                .as_ref()
                .is_none_or(|policy| name_is_blocked(policy, now, &id));
            async move {
                if blocked {
                    return (id, Ok(None));
                }
                let result = async {
                    let cached =
                        current_project(app, &id, registry_id, principal, resources).await?;
                    let entries = entries_in(app, &id, &cached)?;
                    let judged = judge(
                        app,
                        principal,
                        &id,
                        &entries,
                        &cached,
                        flat_base(resources)?,
                        registry_id,
                    )
                    .await?;
                    Ok::<_, ApiError>(Some(allowed_versions(&entries, &judged, false)))
                }
                .await;
                // A package the registry does not have is not shown; any other failure fails the request (nothing is skipped).
                (
                    id,
                    match result {
                        Err(ApiError::NotFound) => Ok(None),
                        other => other,
                    },
                )
            }
        }))
        .buffer_unordered(SEARCH_PARALLEL)
        .collect()
        .await;
    judged
        .into_iter()
        .map(|(id, result)| result.map(|allowed| (id, allowed)))
        .collect()
}

fn upstream_url(base: &Url, pairs: &[(String, String)]) -> Url {
    let mut url = base.clone();
    if !pairs.is_empty() {
        url.query_pairs_mut().extend_pairs(pairs);
    }
    url
}

/// `GET {root}v3/query`: the registry's search results, only the versions the policy allows, each result's
/// registration, leaf and icon links pointing here.
pub async fn serve_search(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    query: Option<&str>,
    root: &Url,
) -> Result<Rendered, ApiError> {
    check_policy(app, principal)?;
    let pairs = query_pairs(query, SEARCH_KEYS)?;
    let resources = resources(app, principal, registry_id).await?;
    let base = resources.search.as_ref().ok_or(ApiError::NotFound)?;
    let body = fetch(
        app,
        principal,
        upstream_url(base, &pairs),
        JSON,
        index_cap(app),
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| invalid("a search result"))?;
    let ids = doc::search_ids(&value, SEARCH_TAKE_CAP).map_err(|_| invalid("a search result"))?;
    let allowed = allowed_for(app, principal, registry_id, &resources, ids).await?;
    let (registration, flat) = route_urls(root)?;
    let links = Links {
        registration: &registration,
        flat: &flat,
        upstream: resources.registration.as_ref().unwrap_or(base),
    };
    let out = doc::render_search(value, &links, &|id| allowed.get(id).cloned().flatten())
        .map_err(|_| invalid("a search result"))?;
    Ok(rendered(
        serde_json::to_vec(&out).map_err(|_| ApiError::InternalFailure)?,
    ))
}

/// `GET {root}v3/autocomplete`: ids (`?q=`) without the blocked names, or the allowed versions of one id (`?id=`).
pub async fn serve_autocomplete(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    query: Option<&str>,
) -> Result<Rendered, ApiError> {
    check_policy(app, principal)?;
    let pairs = query_pairs(query, AUTOCOMPLETE_KEYS)?;
    let wanted = pairs
        .iter()
        .find(|(key, _)| key == "id")
        .map(|(_, id)| id.to_ascii_lowercase());
    if let Some(id) = wanted.as_deref() {
        valid_id(id)?;
        // A blocked id is refused before the registry is asked anything.
        locally_blocked(app, principal, id, None)?;
    }
    let resources = resources(app, principal, registry_id).await?;
    let base = resources.autocomplete.as_ref().ok_or(ApiError::NotFound)?;
    let body = fetch(
        app,
        principal,
        upstream_url(base, &pairs),
        JSON,
        index_cap(app),
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| invalid("an autocomplete result"))?;
    let out = match wanted {
        Some(id) => {
            let allowed = allowed_for(app, principal, registry_id, &resources, vec![id.clone()])
                .await?
                .remove(&id)
                .flatten()
                .ok_or(ApiError::UpstreamFailure)?;
            doc::render_autocomplete_versions(value, &allowed)
        }
        None => {
            let policy = app
                .policy_for(principal)
                .ok_or(ApiError::PolicyUnavailable)?;
            let now = app.clock.now_utc_micros();
            let blocked = |id: &str| name_is_blocked(&policy, now, id);
            doc::render_autocomplete_ids(value, &blocked)
        }
    }
    .map_err(|_| invalid("an autocomplete result"))?;
    Ok(rendered(
        serde_json::to_vec(&out).map_err(|_| ApiError::InternalFailure)?,
    ))
}

/// A vulnerability or signature document: kept `DOC_TTL` for credential-free reads (bounded by entries and size), fetched
/// fresh by a read that carries the caller's credential, which also fills nothing (C1028). The bytes are shared, not copied.
async fn cached_document(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    url: Url,
    accept: &'static str,
    cap: u64,
) -> Result<Option<bytes::Bytes>, ApiError> {
    let shareable = crate::http::credential_read::cache_token(app).is_some();
    let key = (
        registry_id,
        principal
            .and_then(|p| p.registry_origin.as_ref())
            .map(Url::to_string),
        url.to_string(),
    );
    let now = app.clock.now_monotonic();
    if shareable
        && let Some((at, body)) = lock(&app.nuget.docs).get(&key)
        && now.saturating_duration_since(*at) < DOC_TTL
    {
        return Ok(Some(body.clone()));
    }
    let Some(body) = fetch(app, principal, url, accept, cap).await? else {
        return Ok(None);
    };
    if shareable && body.len() <= MAX_DOC_BYTES {
        let mut docs = lock(&app.nuget.docs);
        if docs.len() >= MAX_DOCS {
            docs.clear();
        }
        docs.insert(key, (now, body.clone()));
    }
    Ok(Some(body))
}

/// `GET {root}v3/vulnerabilities/index.json`.
pub async fn serve_vulnerability_index(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    root: &Url,
) -> Result<Rendered, ApiError> {
    check_policy(app, principal)?;
    let resources = resources(app, principal, registry_id).await?;
    let url = resources
        .vulnerabilities
        .clone()
        .ok_or(ApiError::NotFound)?;
    let body = cached_document(
        app,
        principal,
        registry_id,
        url,
        JSON,
        VULNERABILITY_INDEX_CAP,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    doc::render_vulnerability_index(&body, root)
        .map(rendered)
        .map_err(|_| invalid("the vulnerability index"))
}

/// `GET {root}v3/vulnerabilities/{base|update}.json`: the file the registry's current index names under that name.
pub async fn serve_vulnerability_file(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    name: &str,
) -> Result<Rendered, ApiError> {
    if !matches!(name, "base" | "update") {
        return Err(ApiError::NotFound);
    }
    check_policy(app, principal)?;
    let resources = resources(app, principal, registry_id).await?;
    let index = resources
        .vulnerabilities
        .clone()
        .ok_or(ApiError::NotFound)?;
    let origins = origins_for(app, principal)?;
    let listed = cached_document(
        app,
        principal,
        registry_id,
        index,
        JSON,
        VULNERABILITY_INDEX_CAP,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    let files =
        doc::parse_vulnerability_index(&listed).map_err(|_| invalid("the vulnerability index"))?;
    let (_, url) = files
        .into_iter()
        .find(|(have, _)| have == name)
        .ok_or(ApiError::NotFound)?;
    origins
        .set
        .admit(&url, origins.index)
        .ok()
        .filter(|()| origins.under_prefix(&url))
        .ok_or_else(|| invalid("a vulnerability file outside the registry's origin"))?;
    let body = cached_document(app, principal, registry_id, url, JSON, VULNERABILITY_CAP)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Rendered {
        body,
        content_type: JSON,
    })
}

/// `GET {root}v3/repository-signatures/{version}/index.json`.
pub async fn serve_signature_index(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    version: &str,
    root: &Url,
) -> Result<Rendered, ApiError> {
    check_policy(app, principal)?;
    let resources = resources(app, principal, registry_id).await?;
    let url = resources
        .signatures
        .iter()
        .find(|(have, _)| have == version)
        .map(|(_, url)| url.clone())
        .ok_or(ApiError::NotFound)?;
    let body = cached_document(
        app,
        principal,
        registry_id,
        url,
        JSON,
        VULNERABILITY_INDEX_CAP,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    doc::render_signature_index(&body, root)
        .map(rendered)
        .map_err(|_| invalid("the repository signature index"))
}

/// `GET {root}v3/repository-signatures/certificates/{fingerprint}.crt`: the certificate the registry's current
/// signature index names with that fingerprint, from the origin of that index, and only when its bytes hash to it.
pub async fn serve_signature_certificate(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    fingerprint: &str,
) -> Result<Rendered, ApiError> {
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ApiError::NotFound);
    }
    check_policy(app, principal)?;
    let resources = resources(app, principal, registry_id).await?;
    let origins = origins_for(app, principal)?;
    for (_, index) in &resources.signatures {
        let Some(listed) = cached_document(
            app,
            principal,
            registry_id,
            index.clone(),
            JSON,
            VULNERABILITY_INDEX_CAP,
        )
        .await?
        else {
            continue;
        };
        let certificates = doc::parse_signature_index(&listed)
            .map_err(|_| invalid("the repository signature index"))?;
        if let Some((_, url)) = certificates
            .into_iter()
            .find(|(have, _)| have == fingerprint)
        {
            origins
                .set
                .admit(&url, origins.index)
                .ok()
                .filter(|()| origins.under_prefix(&url))
                .ok_or_else(|| invalid("a certificate outside the registry's origin"))?;
            let body = cached_document(
                app,
                principal,
                registry_id,
                url,
                "application/octet-stream",
                CERT_CAP,
            )
            .await?
            .ok_or(ApiError::NotFound)?;
            // The index names a fingerprint: the bytes served under it must be the certificate that hashes to it.
            use sha2::Digest as _;
            if hex::encode(sha2::Sha256::digest(&body)) != fingerprint {
                return Err(invalid("a certificate that does not match its fingerprint"));
            }
            return Ok(Rendered {
                body,
                content_type: "application/x-x509-ca-cert",
            });
        }
    }
    Err(ApiError::NotFound)
}

// ------------------------------------------------------------------ files

/// The reference a `GET {root}v3-flatcontainer/{id}/{version}/{file}` names, against the current project: the id
/// and version are the one lower-case spelling, the file one of the four names, the version one the flat container
/// lists. One project is read at most, before anything else is asked of upstream.
pub async fn reference_for_file(
    app: &App,
    principal: Option<&Principal>,
    id: &str,
    version: &str,
    file: &str,
    registry_id: u64,
) -> Result<(ReferenceId, String), ApiError> {
    let id = valid_id(id)?;
    let version = valid_version(version)?;
    let kind = File::of_name(file, id, version).ok_or(ApiError::NotFound)?;
    locally_blocked(app, principal, id, Some(version))?;
    let resources = resources(app, principal, registry_id).await?;
    let cached = current_project(app, id, registry_id, principal, &resources).await?;
    let entries = entries_in(app, id, &cached)?;
    let position = entries
        .iter()
        .position(|entry| entry.version == version && entry.in_flat)
        .ok_or(ApiError::NotFound)?;
    let origins = origins_for(app, principal)?;
    let refs = references(flat_base(&resources)?, &origins, id, version, registry_id)
        .ok_or(ApiError::NotFound)?;
    let wanted = id_of(&refs, kind);
    // A version beyond the newest `max_references_per_project / 4` has no rows until a file of it is asked for: made here,
    // from the stored project (one version's four rows, idempotent, pins and first-seen times carried).
    if position + max_versions(app) < entries.len()
        && app
            .store()
            .get_reference(wanted)
            .await
            .map_err(storage_error)?
            .is_none()
    {
        let now = app.clock.now_utc_micros();
        // Rows are made only for a version the policy does not refuse (a Hold needs its row: the first-seen time runs from
        // it), and only while the project is within its row bound; a refused version is answered here with its reason.
        let judged = judge(
            app,
            principal,
            id,
            &entries[position..=position],
            &cached,
            flat_base(&resources)?,
            registry_id,
        )
        .await?;
        if matches!(judged[0], Decision::Deny(_)) {
            return Err(crate::artifacts::decision_error(judged[0], now));
        }
        let rows = app
            .store()
            .count_project_references_in(registry_id, Ecosystem::NuGet, id)
            .await
            .map_err(storage_error)?;
        if rows >= (1 + LAZY_ROWS_FACTOR) * u64::from(app.config.max_references_per_project.get()) {
            tracing::warn!(package = %id, rows, "a project is at its reference row bound: a file of one more old version is refused");
            return Err(ApiError::Overloaded);
        }
        let refresh = ProjectRefresh {
            ecosystem: Ecosystem::NuGet,
            name: id.to_owned(),
            payload: Arc::clone(&cached.row.payload),
            validators: Default::default(),
            validated_at_micros: cached.row.validated_at_micros,
            fetched_at_micros: cached.row.fetched_at_micros,
            references: upserts_of(&entries[position], refs, now).collect(),
        };
        app.store()
            .commit_request_references_in(registry_id, refresh)
            .await
            .map_err(storage_error)?;
    }
    Ok((wanted, file.to_owned()))
}

/// SPEC §9 membership: the ids the current snapshot advertises (artifact path).
pub async fn ensure_fresh_project_in(
    app: &App,
    reference: &ArtifactReference,
    registry_id: u64,
    principal: Option<&Principal>,
) -> Result<Arc<Advertised>, ApiError> {
    let id = valid_id(&reference.name)?;
    let resources = resources(app, principal, registry_id).await?;
    let cached = current_project(app, id, registry_id, principal, &resources).await?;
    let origins = origins_for(app, principal)?;
    // Membership is the stored project's list of versions (every one, whether its rows exist yet or not): the four files
    // of the version the reference names are advertised when the snapshot lists that version in the flat container.
    let entries = entries_in(app, id, &cached)?;
    let refs: Vec<(ReferenceId, String)> = entries
        .iter()
        .filter(|entry| entry.in_flat && entry.version == reference.version)
        .filter_map(|entry| {
            references(
                flat_base(&resources).ok()?,
                &origins,
                id,
                &entry.version,
                registry_id,
            )
        })
        .flat_map(|refs| {
            refs.into_iter()
                .map(|(_, id, reference)| (id, reference.filename))
        })
        .collect();
    Ok(Arc::new(Advertised::new(
        refs.iter().map(|(id, filename)| (*id, filename.as_str())),
    )))
}

// ------------------------------------------------------------------ writes

/// Where a publish, symbol publish, unlist or relist of the registry goes: the resource URL the registry's own
/// service index names for it (the registry's origin, or the configured public publish host), and the origin the
/// request is admitted against.
pub struct PublishTarget {
    pub url: Url,
    pub origin: Url,
}

pub async fn publish_target(
    app: &App,
    principal: &Principal,
    registry_id: u64,
    symbol: bool,
    tail: &[&str],
) -> Result<PublishTarget, ApiError> {
    let resources = resources(app, Some(principal), registry_id).await?;
    let base = if symbol {
        resources.symbol_publish.as_ref()
    } else {
        resources.publish.as_ref()
    }
    .ok_or(ApiError::NotFound)?;
    let origins = origins_for(app, Some(principal))?;
    let url = origins
        .set
        .url_below(origins.publish, base, tail)
        .map_err(|_| ApiError::UpstreamInvalid)?;
    let origin = match &origins.root {
        Some(root) => root.clone(),
        None => registry_root(base),
    };
    Ok(PublishTarget { url, origin })
}
