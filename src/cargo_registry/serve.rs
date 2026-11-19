//! Cargo sparse registry delivery on the shared firewall machinery. One index file per crate
//! (`/{prefix}/{name}`) is fetched, committed, judged version by version and rendered with the
//! kept lines unchanged; `config.json` is rewritten so `dl` and `api` name this firewall; an
//! archive is delivered only when its SHA-256 equals the `cksum` the same index line carries.
//!
//! Identities (the defects slice 17 taught): the index path and the archive file name keep the
//! registry's own spelling (`Inflector-0.11.4.crate`, lower-case path), while policy, blocklist
//! and OSV key by `canonical_name` (lower case, `_` folded to `-`; OSV answers either spelling,
//! checked against api.osv.dev). The project row and every reference row are stored under the
//! canonical name; the exact spelling is recovered from the archive file name.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use probation_policy::names::canonical_name;

use crate::App;
use crate::cargo_registry::index::{self, Entry, UpstreamConfig};
use crate::http::error::{ApiError, storage_error};
use crate::http::logging;
use crate::managed::Principal;
use crate::managed::report::Call;
use crate::policy::{Candidate, Decision, Ecosystem, PublicationTime};
use crate::store;
use crate::store::cache::{Advertised, CachedProject, ProjectKey};
use crate::store::rows::{ArtifactReference, Generation, ProjectRefresh, ProjectRow, ReferenceId, ReferenceUpsert};
use crate::upstream::{MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError};

pub struct Rendered {
    pub body: Arc<[u8]>,
    pub content_type: &'static str,
    /// A strong validator of the rendered body (the filtered index changes when policy does).
    pub etag: Option<String>,
}

const JSON: &str = "application/json";
const TEXT: &str = "text/plain; charset=utf-8";

/// LS-F7: no valid index is refused before this cap. The largest real index measured
/// (aws-sdk-ec2, 2026-11-19) is 1,484,079 bytes inflated, so 16 MiB is more than 4x that.
pub const INDEX_FLOOR_CAP: u64 = 16 << 20;
/// `config.json` is a few dozen bytes.
const CONFIG_CAP: u64 = 64 << 10;
/// Case/hyphen/underscore spellings of one crate committed per registry (as RubyGems' R1).
const MAX_SPELLINGS: usize = 4;
/// How long shareable service-mode reads share one fetched index: long enough for the two lookups of
/// one download and a burst of `cargo fetch`, short enough that membership stays current.
const SERVICE_SHARE_TTL: Duration = Duration::from_secs(5);
const CONFIG_TTL: Duration = Duration::from_secs(60);
const CONFIG_FAILURE_TTL: Duration = Duration::from_secs(15);
/// A published version longer than this is not a SemVer string a registry could hold.
pub const MAX_VERSION: usize = 256;

#[derive(Default)]
pub struct Shared {
    configs: std::sync::Mutex<std::collections::HashMap<(u64, Option<String>), ConfigCell>>,
    /// (registry, canonical name) -> exact lower-case spellings this process has committed.
    spellings: std::sync::Mutex<std::collections::HashMap<(u64, String), Vec<String>>>,
    /// Shared-service mode only: the project a shareable (credential-free) read just fetched, kept
    /// for `SERVICE_SHARE_TTL` per (registry, origin, crate). A request-scoped read never reads or fills it.
    shared: std::sync::Mutex<std::collections::HashMap<ShareKey, (Instant, Arc<CachedProject>)>>,
}

/// (registry, selected origin, exact lower-case crate name).
type ShareKey = (u64, Option<String>, String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigFailure {
    Unauthenticated,
    Denied,
    Timeout,
    Failed,
    Invalid,
}

impl From<ConfigFailure> for ApiError {
    fn from(failure: ConfigFailure) -> ApiError {
        match failure {
            ConfigFailure::Unauthenticated => ApiError::UpstreamUnauthenticated,
            ConfigFailure::Denied => ApiError::UpstreamDenied,
            ConfigFailure::Timeout => ApiError::UpstreamTimeout,
            ConfigFailure::Failed => ApiError::UpstreamFailure,
            ConfigFailure::Invalid => ApiError::UpstreamInvalid,
        }
    }
}

type ConfigCell = Arc<tokio::sync::Mutex<Option<(Instant, Result<Arc<UpstreamConfig>, ConfigFailure>)>>>;

/// The origin set a request reads through, and the kinds of the index and of the archives.
struct Origins {
    set: OriginSet,
    index: OriginKind,
    archives: OriginKind,
    /// The set archives are admitted against when the registry declares an archive origin of its own.
    archive_set: Option<OriginSet>,
}

fn origins_for(app: &App, principal: Option<&Principal>) -> Result<Origins, ApiError> {
    match principal.and_then(|p| p.registry_origin.as_ref()) {
        // A selected registry's origin travels in the slot `selected_npm_with_private` fills; its
        // archives must live under the same origin and path.
        Some(origin) => Ok(Origins {
            set: OriginSet::selected_npm_with_private(origin.clone(), principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone())).map_err(|_| ApiError::NotFound)?,
            index: OriginKind::NpmMetadata,
            archives: OriginKind::NpmMetadata,
            archive_set: principal
                .and_then(|p| p.registry_archive_origin.clone())
                .map(|archive| OriginSet::selected_npm_with_private(archive, principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone())))
                .transpose()
                .map_err(|_| ApiError::NotFound)?,
        }),
        None => Ok(Origins { set: app.origins.clone(), index: OriginKind::CargoIndex, archives: OriginKind::CargoArtifacts, archive_set: None }),
    }
}

fn crate_name(raw: &str) -> Result<&str, ApiError> {
    index::valid_crate_name(raw).then_some(raw).ok_or(ApiError::NotFound)
}

fn index_cap(app: &App) -> u64 {
    app.config.max_metadata_bytes.get().max(INDEX_FLOOR_CAP)
}

/// `config.json` of the registry the request reads through: cached 60 s per (registry, origin)
/// with one fetch at a time, and never read from or written to the cache by a credential-bearing
/// read (C1028).
async fn upstream_config(app: &App, principal: Option<&Principal>, registry_id: u64) -> Result<Arc<UpstreamConfig>, ApiError> {
    let origins = origins_for(app, principal)?;
    let url = origins.set.url_for(origins.index, &["config.json"]).map_err(|_| ApiError::NotFound)?;
    let cacheable = crate::http::credential_read::cache_token(app).is_some();
    let key = (registry_id, principal.and_then(|p| p.registry_origin.as_ref()).map(|origin| origin.to_string()));
    let cell = if cacheable {
        let Ok(mut map) = app.cargo.configs.lock() else { return Err(ApiError::InternalFailure) };
        if map.len() >= 64 {
            map.retain(|_, cell| Arc::strong_count(cell) > 1);
        }
        Some(Arc::clone(map.entry(key).or_default()))
    } else {
        None
    };
    let mut guard = match &cell {
        Some(cell) => Some(cell.lock().await),
        None => None,
    };
    if let Some(Some((at, result))) = guard.as_deref() {
        let ttl = if result.is_ok() { CONFIG_TTL } else { CONFIG_FAILURE_TTL };
        if app.clock.now_monotonic().saturating_duration_since(*at) < ttl {
            return result.clone().map_err(ApiError::from);
        }
    }
    let result = fetch_config(app, principal, url).await;
    if let Some(guard) = guard.as_mut() {
        **guard = Some((app.clock.now_monotonic(), result.clone()));
    }
    result.map_err(ApiError::from)
}

async fn fetch_config(app: &App, principal: Option<&Principal>, url: url::Url) -> Result<Arc<UpstreamConfig>, ConfigFailure> {
    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            origin: principal.and_then(|p| p.registry_origin.clone()),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept: "application/json",
            validators: None,
            max_bytes: CONFIG_CAP.min(app.config.max_metadata_bytes.get()),
        })
        .await;
    app.upstreams.record_upstream(Call::Cargo, &fetched);
    match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => index::parse_config(&body).map(Arc::new).ok_or_else(|| {
            tracing::warn!("the registry's config.json is not a Cargo config");
            ConfigFailure::Invalid
        }),
        Ok(_) | Err(UpstreamError::Status(404)) => Err(ConfigFailure::Invalid),
        Err(UpstreamError::Status(401)) if app.service_policy().is_some() => Err(ConfigFailure::Unauthenticated),
        Err(UpstreamError::Status(403)) if app.service_policy().is_some() => Err(ConfigFailure::Denied),
        Err(UpstreamError::Timeout) => Err(ConfigFailure::Timeout),
        Err(_) => Err(ConfigFailure::Failed),
    }
}

/// The reference of one index line: the archive URL its registry's `dl` names, admitted against
/// the archive origin (a `dl` on another host, port or path is not an origin this registry owns).
fn reference_of(entry: &Entry, canonical: &str, config: &UpstreamConfig, origins: &Origins, registry_id: u64) -> Option<(ReferenceId, ArtifactReference)> {
    let url = index::archive_url(&config.dl, &entry.name, &entry.vers, &hex::encode(entry.cksum))?;
    origins.archive_set.as_ref().unwrap_or(&origins.set).admit(&url, origins.archives).ok()?;
    let reference = ArtifactReference {
        ecosystem: Ecosystem::Cargo,
        name: canonical.to_owned(),
        version: entry.policy_version(),
        filename: entry.filename(),
        upstream_url: url,
        expected: entry.expected(),
    };
    Some((ReferenceId::compute_in_registry(registry_id, &reference), reference))
}

fn publication_of(entry: &Entry, id: &ReferenceId, cached: &CachedProject) -> PublicationTime {
    match entry.published_micros {
        Some(micros) => PublicationTime::Upstream(micros),
        None => cached.first_seen.get(id).map_or(PublicationTime::Unknown, |micros| PublicationTime::FirstSeen(*micros)),
    }
}

/// The crate a stored payload belongs to: the `name` of its first line.
fn payload_name(payload: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct First {
        name: String,
    }
    let text = std::str::from_utf8(payload).ok()?;
    let line = text.lines().find(|line| !line.trim().is_empty())?;
    serde_json::from_str::<First>(line).ok().map(|first| first.name.to_ascii_lowercase())
}

fn parse_entries(app: &App, lower: &str, payload: &[u8]) -> Result<Vec<Entry>, ApiError> {
    index::parse_index(payload, lower, app.config.max_references_per_project.get() as usize).map_err(|error| {
        tracing::warn!(crate_name = %lower, ?error, "the sparse index file is unusable");
        ApiError::UpstreamInvalid
    })
}

/// The project snapshot a decision is made from (SPEC §10) for the crate whose exact lower-case
/// spelling is `lower`: the cached one within its TTL, else a refreshed one.
async fn current_project(app: &App, lower: &str, registry_id: u64, principal: Option<&Principal>) -> Result<Arc<CachedProject>, ApiError> {
    let now = app.clock.now_utc_micros();
    let monotonic = app.clock.now_monotonic();
    let canonical = canonical_name(Ecosystem::Cargo, lower);
    let key = ProjectKey::in_registry(registry_id, Ecosystem::Cargo, &canonical);
    // A 404 is remembered under the exact spelling asked for, so `foo-bar` missing never hides `foo_bar`.
    let absent_key = ProjectKey::in_registry(registry_id, Ecosystem::Cargo, lower);
    // At most MAX_SPELLINGS case spellings of one crate are ever committed per registry: every
    // spelling is its own set of reference rows, never reclaimed.
    let spelled = {
        let known = app.cargo.spellings.lock().map_err(|_| ApiError::InternalFailure)?;
        let committed = known.get(&(registry_id, canonical.clone())).map_or(&[][..], Vec::as_slice);
        if !committed.iter().any(|spelling| spelling == lower) && committed.len() >= MAX_SPELLINGS {
            tracing::warn!(crate_name = %canonical, registry_id, "refusing a further spelling of a crate name");
            return Err(ApiError::NotFound);
        }
        committed.iter().any(|spelling| spelling == lower)
    };
    if app.service_policy().is_some() {
        let share_key = (registry_id, principal.and_then(|p| p.registry_origin.as_ref()).map(|origin| origin.to_string()), lower.to_owned());
        let shareable = crate::http::credential_read::cache_token(app).is_some();
        if shareable
            && let Ok(shared) = app.cargo.shared.lock()
            && let Some((at, project)) = shared.get(&share_key)
            && monotonic.saturating_duration_since(*at) < SERVICE_SHARE_TTL
        {
            return Ok(Arc::clone(project));
        }
        let project = refresh(app, lower, &key, &absent_key, now, true, None, principal).await?;
        if shareable && let Ok(mut shared) = app.cargo.shared.lock() {
            if shared.len() >= 256 {
                shared.clear();
            }
            shared.insert(share_key, (monotonic, Arc::clone(&project)));
        }
        return Ok(project);
    }
    let caches = app.store().caches();
    let ttl = Duration::from_secs(app.config.metadata_ttl_seconds);
    let ttl_micros = i64::try_from(ttl.as_micros()).unwrap_or(i64::MAX);
    if let Some(mark) = caches.absent.get(&absent_key) {
        if monotonic.duration_since(mark.observed_monotonic) < ttl {
            return Err(ApiError::NotFound);
        }
        caches.absent.remove(&absent_key);
    }
    let (seen, cached) = caches.projects.get_with_seen(&key);
    let cached = match cached {
        Some(cached) => Some(cached),
        None => load_project(app, &canonical, registry_id).await?.map(Arc::new),
    };
    // The stored row is shared by every spelling that folds to one canonical name; a row that
    // belongs to another spelling is not this crate's index.
    let cached = cached.filter(|cached| payload_name(&cached.row.payload).as_deref() == Some(lower));
    let over_age = cached.as_ref().is_some_and(|c| store::is_over_age(&key, app.config.metadata_max_age_seconds, c.row.fetched_at_micros, now));
    let cached = match cached {
        Some(cached) if !over_age && spelled && now < cached.row.validated_at_micros.saturating_add(ttl_micros) => cached,
        stale => refresh(app, lower, &key, &absent_key, now, over_age, stale, principal).await?,
    };
    if let Some(token) = crate::http::credential_read::cache_token(app) {
        caches.projects.insert_if_current(&token, key, Arc::clone(&cached), cached.approximate_bytes(), seen);
    }
    Ok(cached)
}

async fn load_project(app: &App, canonical: &str, registry_id: u64) -> Result<Option<CachedProject>, ApiError> {
    let Some(row) = app.store().get_project_in(registry_id, Ecosystem::Cargo, canonical).await.map_err(storage_error)? else {
        return Ok(None);
    };
    let first_seen = app.store().list_project_first_seen_in(registry_id, Ecosystem::Cargo, canonical).await.map_err(storage_error)?;
    let pins = app.store().list_project_pins_in(registry_id, Ecosystem::Cargo, canonical).await.map_err(storage_error)?;
    Ok(Some(CachedProject { row, first_seen, pins, advertised: OnceLock::new() }))
}

#[allow(clippy::too_many_arguments)]
async fn refresh(
    app: &App,
    lower: &str,
    key: &ProjectKey,
    absent_key: &ProjectKey,
    now: i64,
    over_age: bool,
    stale: Option<Arc<CachedProject>>,
    principal: Option<&Principal>,
) -> Result<Arc<CachedProject>, ApiError> {
    let origins = origins_for(app, principal)?;
    let segments = index::index_segments(lower);
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
    let url = origins.set.url_for(origins.index, &segments).map_err(|rejection| {
        tracing::warn!(crate_name = %lower, %rejection, "refused to build an upstream URL");
        ApiError::NotFound
    })?;
    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            origin: principal.and_then(|p| p.registry_origin.clone()),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept: "text/plain",
            validators: (!over_age)
                .then(|| stale.as_ref().map(|c| c.row.validators.clone()).filter(|v| !v.is_empty()))
                .flatten(),
            max_bytes: index_cap(app),
        })
        .await;
    app.upstreams.record_upstream(Call::Cargo, &fetched);
    let (payload, validators, fetched_at_micros): (Arc<[u8]>, _, i64) = match fetched {
        Ok(MetadataResponse::Fresh { body, validators }) => (Arc::from(body.as_ref()), validators, now),
        Ok(MetadataResponse::NotModified { validators }) => match &stale {
            Some(cached) if !over_age => {
                let validators = if validators.is_empty() { cached.row.validators.clone() } else { validators };
                (Arc::clone(&cached.row.payload), validators, cached.row.fetched_at_micros)
            }
            _ => return Err(ApiError::UpstreamInvalid),
        },
        Ok(MetadataResponse::Missing) => {
            if let Some(token) = crate::http::credential_read::cache_token(app).filter(|_| app.service_policy().is_none()) {
                app.store().caches().absent.insert(&token, absent_key.clone(), Arc::new(store::cache::AbsentMark { observed_monotonic: app.clock.now_monotonic() }), 128);
            }
            return Err(ApiError::NotFound);
        }
        Err(UpstreamError::Status(401)) if app.service_policy().is_some() => return Err(ApiError::UpstreamUnauthenticated),
        Err(UpstreamError::Status(403)) if app.service_policy().is_some() => return Err(ApiError::UpstreamDenied),
        Err(UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
        Err(err) => {
            tracing::warn!(crate_name = %lower, error = %err, "the upstream fetch failed");
            return Err(ApiError::UpstreamFailure);
        }
    };
    let entries = parse_entries(app, lower, &payload)?;
    let canonical = canonical_name(Ecosystem::Cargo, lower);
    let config = upstream_config(app, principal, key.registry_id).await?;
    let mut references = Vec::with_capacity(entries.len());
    for entry in &entries {
        let Some((id, reference)) = reference_of(entry, &canonical, &config, &origins, key.registry_id) else {
            tracing::warn!(crate_name = %lower, "the registry's dl names an archive outside the registry's own origin");
            return Err(ApiError::UpstreamInvalid);
        };
        references.push(ReferenceUpsert {
            id,
            reference,
            publication_micros: entry.published_micros,
            first_seen_micros: entry.published_micros.is_none().then_some(now),
        });
    }
    let refresh = ProjectRefresh {
        ecosystem: Ecosystem::Cargo,
        name: canonical.clone(),
        payload: Arc::clone(&payload),
        validators: validators.clone(),
        validated_at_micros: now,
        fetched_at_micros,
        references,
    };
    let committed = if app.service_policy().is_some() {
        app.store().commit_request_references_in(key.registry_id, refresh).await
    } else {
        app.store().commit_project_refresh_in(key.registry_id, refresh).await
    }
    .map_err(storage_error)?;
    let pins = app.store().list_project_pins_in(key.registry_id, Ecosystem::Cargo, &canonical).await.map_err(storage_error)?;
    if let Ok(mut known) = app.cargo.spellings.lock() {
        // ponytail: forgotten when 4096 crates are tracked and after a restart, and not shared
        // between instances; a persisted per-crate count if that matters.
        if known.len() >= 4096 {
            known.clear();
        }
        let committed = known.entry((key.registry_id, canonical.clone())).or_default();
        if !committed.iter().any(|spelling| spelling == lower) {
            committed.push(lower.to_owned());
        }
    }
    Ok(Arc::new(CachedProject {
        row: ProjectRow {
            ecosystem: Ecosystem::Cargo,
            name: canonical,
            payload,
            validators,
            validated_at_micros: now,
            fetched_at_micros,
            generation: committed.generation as Generation,
            digest_generation: committed.digest_generation,
        },
        first_seen: committed.first_seen,
        pins,
        advertised: OnceLock::new(),
    }))
}

fn etag_of(body: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    format!("\"{}\"", hex::encode(&Sha256::digest(body)[..16]))
}

/// `GET {root}/config.json`: the registry's own `config.json` with `dl` and `api` pointing at
/// this firewall (`root` is its public base for the registry the request selects).
pub async fn serve_config(app: &App, principal: Option<&Principal>, registry_id: u64, root: &url::Url) -> Result<Rendered, ApiError> {
    let config = upstream_config(app, principal, registry_id).await?;
    let join = |tail: &str| root.join(tail).map_err(|_| ApiError::InternalFailure);
    let mut document = serde_json::Map::new();
    // Cargo appends `/{crate}/{version}/download` to a `dl` that has no markers.
    document.insert("dl".to_owned(), join("crates")?.to_string().trim_end_matches('/').to_owned().into());
    if config.api.is_some() {
        document.insert("api".to_owned(), root.to_string().trim_end_matches('/').to_owned().into());
    }
    // A managed firewall on the key route authenticates every read, so Cargo must be told to send
    // its token (it sends one only to a registry whose `config.json` says `auth-required`).
    if config.auth_required || (registry_id == 0 && principal.is_some()) {
        document.insert("auth-required".to_owned(), true.into());
    }
    let body = serde_json::to_vec(&document).map_err(|_| ApiError::InternalFailure)?;
    Ok(Rendered { etag: Some(etag_of(&body)), body: Arc::from(body), content_type: JSON })
}

/// `GET {root}/{prefix}/{name}`: the index file of one crate with every version the policy
/// refuses removed and every other line unchanged.
pub async fn serve_index(app: &App, principal: Option<&Principal>, lower: &str, registry_id: u64) -> Result<Rendered, ApiError> {
    let lower = crate_name(lower)?;
    let now = app.clock.now_utc_micros();
    let policy = app.policy_for(principal).ok_or(ApiError::PolicyUnavailable)?;
    if !policy.snapshot.as_deref().is_some_and(|snapshot| snapshot.is_valid_at(now)) {
        return Err(ApiError::PolicyUnavailable);
    }
    let cached = current_project(app, lower, registry_id, principal).await?;
    let origins = origins_for(app, principal)?;
    let config = upstream_config(app, principal, registry_id).await?;
    let entries = parse_entries(app, lower, &cached.row.payload)?;
    let canonical = canonical_name(Ecosystem::Cargo, lower);
    let scope = app.osv_scope(registry_id);
    let judged = futures_util::future::join_all(entries.iter().map(|entry| {
        let (cached, policy, origins, config, canonical) = (Arc::clone(&cached), &policy, &origins, &config, &canonical);
        async move {
            let Some((id, reference)) = reference_of(entry, canonical, config, origins, registry_id) else { return Decision::Allow };
            let version = entry.policy_version();
            let candidate = Candidate {
                ecosystem: Ecosystem::Cargo,
                name: canonical,
                version: &version,
                publication: publication_of(entry, &id, &cached),
                advertised_digests: &reference.expected,
                pinned_digests: cached.pins_of(&id),
            };
            crate::osv::evaluate_scoped(&app.osv, policy, now, &candidate, scope).await
        }
    }))
    .await;
    logging::record_cache(logging::CacheStatus::Miss);
    // A reference this firewall cannot build (a `dl` outside the registry's origin) is never
    // listed: the `Allow` above is only a placeholder for the id-less case, so it is dropped here.
    let buildable: Vec<bool> = entries.iter().map(|entry| reference_of(entry, &canonical, &config, &origins, registry_id).is_some()).collect();
    if let (Some(principal), Some(managed)) = (principal, app.managed())
        && !entries.is_empty()
        && !judged.iter().zip(&buildable).any(|(decision, ok)| *ok && matches!(decision, Decision::Allow))
    {
        let blocked = judged.iter().position(|decision| matches!(decision, Decision::Deny(_)));
        let held = || {
            judged.iter().enumerate().filter_map(|(i, d)| match d {
                Decision::Hold { eligible_at_micros } => Some((*eligible_at_micros, i)),
                _ => None,
            }).min().map(|(_, i)| i)
        };
        if let Some(index) = blocked.or_else(held)
            && let Some((id, reference)) = reference_of(&entries[index], &canonical, &config, &origins, registry_id)
        {
            let version = entries[index].policy_version();
            let candidate = Candidate {
                ecosystem: Ecosystem::Cargo,
                name: &canonical,
                version: &version,
                publication: publication_of(&entries[index], &id, &cached),
                advertised_digests: &reference.expected,
                pinned_digests: cached.pins_of(&id),
            };
            let verdict = crate::managed::refused_verdict(&policy, now, &candidate, judged[index]);
            managed.record_decision(principal, Ecosystem::Cargo, &canonical, None, &verdict);
        }
    }
    let kept = entries.iter().zip(&judged).zip(&buildable).filter(|((_, decision), ok)| **ok && matches!(decision, Decision::Allow)).map(|((entry, _), _)| entry);
    let body = index::render_index(kept);
    Ok(Rendered { etag: Some(etag_of(&body)), body: Arc::from(body), content_type: TEXT })
}

/// The reference a `GET /crates/{crate}/{version}/download` names, against the current index.
/// The crate name and version are the line's exact spellings (the archive's file name is exact
/// upstream), so a different case or a version the index does not list is not found; one index
/// is fetched at most, and that before anything else is asked of upstream.
pub async fn reference_for_download(app: &App, principal: Option<&Principal>, name: &str, version: &str, registry_id: u64) -> Result<ReferenceId, ApiError> {
    let name = crate_name(name)?;
    if version.len() > MAX_VERSION || semver::Version::parse(version).is_err() {
        return Err(ApiError::NotFound);
    }
    let lower = name.to_ascii_lowercase();
    let cached = current_project(app, &lower, registry_id, principal).await?;
    let origins = origins_for(app, principal)?;
    let config = upstream_config(app, principal, registry_id).await?;
    let entries = parse_entries(app, &lower, &cached.row.payload)?;
    let canonical = canonical_name(Ecosystem::Cargo, &lower);
    entries
        .iter()
        .find(|entry| entry.name == name && entry.vers == version)
        .and_then(|entry| reference_of(entry, &canonical, &config, &origins, registry_id))
        .map(|(id, _)| id)
        .ok_or(ApiError::NotFound)
}

/// The crate name of an archive reference, spelled exactly: `{name}-{vers}.crate` with `vers` the
/// reference's version, build metadata included.
fn exact_name_of(reference: &ArtifactReference) -> Option<&str> {
    let stem = reference.filename.strip_suffix(".crate")?;
    stem.match_indices('-').rev().find_map(|(at, _)| {
        let rest = &stem[at + 1..];
        (index::strip_build(rest) == reference.version).then(|| &stem[..at])
    })
}

/// SPEC §9 membership: the ids the current snapshot advertises (artifact path).
pub async fn ensure_fresh_project_in(app: &App, reference: &ArtifactReference, registry_id: u64, principal: Option<&Principal>) -> Result<Arc<Advertised>, ApiError> {
    let name = exact_name_of(reference).filter(|name| index::valid_crate_name(name)).ok_or(ApiError::NotFound)?;
    let lower = name.to_ascii_lowercase();
    let cached = current_project(app, &lower, registry_id, principal).await?;
    if let Some(advertised) = cached.advertised.get() {
        return Ok(Arc::clone(advertised));
    }
    let origins = origins_for(app, principal)?;
    let config = upstream_config(app, principal, registry_id).await?;
    let entries = parse_entries(app, &lower, &cached.row.payload)?;
    let canonical = canonical_name(Ecosystem::Cargo, &lower);
    let refs: Vec<(ReferenceId, String)> = entries
        .iter()
        .filter_map(|entry| reference_of(entry, &canonical, &config, &origins, registry_id).map(|(id, r)| (id, r.filename)))
        .collect();
    let advertised = Arc::new(Advertised::new(refs.iter().map(|(id, filename)| (*id, filename.as_str()))));
    let _ = cached.advertised.set(Arc::clone(&advertised));
    Ok(advertised)
}
