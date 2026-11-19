//! RubyGems metadata and gem delivery on the shared firewall machinery: one compact-index
//! document per gem (`/info/{gem}`) is fetched, committed, judged version by version and
//! platform by platform, and rendered with the kept lines unchanged.
//!
//! What differs from `pypi` (and why it is its own module):
//! * the unit of judgement is a (version, platform) line, and `created_at:` in the line is
//!   the authoritative date of exactly that platform build; a registry without it falls
//!   back to the committed first-seen time of that reference (never a cache age);
//! * the file the client asks for (`/gems/{name}-{version}[-{platform}].gem`) names no
//!   reference id, so the reference is looked up from the current index by the file name,
//!   and a name that fits two index entries refuses;
//! * `/versions` and `/names` are passed through bounded and unchanged. Upstream's third
//!   column of `/versions` is the MD5 of the unfiltered info file; Bundler (which fails
//!   without the column) uses it only to decide whether its cached info is current, so a
//!   filtered info file costs a re-download, never a failure (witness: the native Bundler test).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::App;
use crate::http::error::{ApiError, storage_error};
use crate::http::logging;
use crate::managed::Principal;
use crate::managed::report::Call;
use crate::policy::{Candidate, Decision, Ecosystem, PublicationTime};
use crate::rubygems::info::{self, Entry};
use crate::store;
use crate::store::cache::{Advertised, CachedProject, ProjectKey};
use crate::store::rows::{ArtifactReference, Generation, ProjectRefresh, ProjectRow, ReferenceId, ReferenceUpsert};
use crate::upstream::{MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError};

pub struct Rendered {
    pub body: Arc<[u8]>,
    pub content_type: &'static str,
}

/// The most ways a gem file name may split into a name and a version before it is refused unasked.
const MAX_NAME_SPLITS: usize = 3;

const TEXT: &str = "text/plain; charset=utf-8";
const BINARY: &str = "application/octet-stream";

fn origins_for(app: &App, principal: Option<&Principal>) -> Result<(OriginSet, OriginKind), ApiError> {
    match principal.and_then(|p| p.registry_origin.as_ref()) {
        // A selected registry's origin travels in the slot `selected_npm_with_private` fills.
        Some(origin) => Ok((
            OriginSet::selected_npm_with_private(origin.clone(), principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()))
                .map_err(|_| ApiError::NotFound)?,
            OriginKind::NpmMetadata,
        )),
        None => Ok((app.origins.clone(), OriginKind::RubygemsMetadata)),
    }
}

fn gem_name(raw: &str) -> Result<&str, ApiError> {
    info::valid_gem_name(raw).then_some(raw).ok_or(ApiError::NotFound)
}

/// The reference of one index entry: `{origin}/gems/{file}` with the entry's sha256.
fn reference_of(name: &str, entry: &Entry, origins: &OriginSet, kind: OriginKind, registry_id: u64) -> Option<(ReferenceId, ArtifactReference)> {
    let filename = entry.gem_filename(name);
    let upstream_url = info::gem_url(origins.origin(kind), &filename)?;
    let reference = ArtifactReference {
        ecosystem: Ecosystem::RubyGems,
        name: name.to_ascii_lowercase(),
        version: entry.version.clone(),
        filename,
        upstream_url,
        expected: entry.expected(),
    };
    Some((ReferenceId::compute_in_registry(registry_id, &reference), reference))
}

fn publication_of(entry: &Entry, id: &ReferenceId, cached: &CachedProject) -> PublicationTime {
    match entry.created_micros {
        Some(micros) => PublicationTime::Upstream(micros),
        None => cached.first_seen.get(id).map_or(PublicationTime::Unknown, |micros| PublicationTime::FirstSeen(*micros)),
    }
}

/// The project snapshot a decision is made from (SPEC §10): the cached one within its TTL,
/// else a refreshed one.
async fn current_project(
    app: &App,
    name: &str,
    registry_id: u64,
    principal: Option<&Principal>,
) -> Result<Arc<CachedProject>, ApiError> {
    let now = app.clock.now_utc_micros();
    let monotonic = app.clock.now_monotonic();
    // One stored project per gem whatever the spelling (the compact index is case-insensitive);
    // the client's spelling still names the upstream info URL and the file names (those are
    // case-exact on rubygems.org), so a spelling this process has not committed references for
    // is revalidated once.
    let lower = name.to_ascii_lowercase();
    let key = ProjectKey::in_registry(registry_id, Ecosystem::RubyGems, &lower);
    if app.service_policy().is_some() {
        return refresh(app, name, &key, now, true, None, principal).await;
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
        None => load_project(app, &lower, registry_id).await?.map(Arc::new),
    };
    // At most MAX_SPELLINGS case spellings of one gem are ever committed per registry: every
    // spelling is its own set of reference rows (their ids include the file name), never reclaimed.
    let spelled = {
        let known = app.rubygems.spellings.lock().map_err(|_| ApiError::InternalFailure)?;
        let committed = known.get(&(registry_id, lower.clone())).map_or(&[][..], Vec::as_slice);
        if !committed.iter().any(|spelling| spelling == name) && committed.len() >= MAX_SPELLINGS {
            tracing::warn!(gem = %lower, registry_id, "refusing a further case spelling of a gem");
            return Err(ApiError::NotFound);
        }
        committed.iter().any(|spelling| spelling == name)
    };
    let over_age = cached.as_ref().is_some_and(|c| store::is_over_age(&key, app.config.metadata_max_age_seconds, c.row.fetched_at_micros, now));
    let cached = match cached {
        Some(cached) if !over_age && spelled && now < cached.row.validated_at_micros.saturating_add(ttl_micros) => cached,
        stale => refresh(app, name, &key, now, over_age, stale, principal).await?,
    };
    if let Some(token) = crate::http::credential_read::cache_token(app) {
        caches.projects.insert_if_current(&token, key, Arc::clone(&cached), cached.approximate_bytes(), seen);
    }
    Ok(cached)
}

async fn load_project(app: &App, name: &str, registry_id: u64) -> Result<Option<CachedProject>, ApiError> {
    let name = &name.to_ascii_lowercase();
    let Some(row) = app.store().get_project_in(registry_id, Ecosystem::RubyGems, name).await.map_err(storage_error)? else {
        return Ok(None);
    };
    let first_seen = app.store().list_project_first_seen_in(registry_id, Ecosystem::RubyGems, name).await.map_err(storage_error)?;
    let pins = app.store().list_project_pins_in(registry_id, Ecosystem::RubyGems, name).await.map_err(storage_error)?;
    Ok(Some(CachedProject { row, first_seen, pins, advertised: OnceLock::new() }))
}

fn parse_entries(app: &App, name: &str, payload: &[u8]) -> Result<Vec<Entry>, ApiError> {
    info::parse_info(payload, app.config.max_references_per_project.get() as usize).map_err(|error| {
        tracing::warn!(gem = %name, ?error, "the compact index document is unusable");
        ApiError::UpstreamInvalid
    })
}

async fn refresh(
    app: &App,
    name: &str,
    key: &ProjectKey,
    now: i64,
    over_age: bool,
    stale: Option<Arc<CachedProject>>,
    principal: Option<&Principal>,
) -> Result<Arc<CachedProject>, ApiError> {
    let (origins, kind) = origins_for(app, principal)?;
    let url = origins.url_for(kind, &["info", name]).map_err(|rejection| {
        tracing::warn!(gem = %name, %rejection, "refused to build an upstream URL");
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
            max_bytes: app.config.max_metadata_bytes.get(),
        })
        .await;
    app.upstreams.record_upstream(Call::Rubygems, &fetched);
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
                app.store().caches().absent.insert(&token, key.clone(), Arc::new(store::cache::AbsentMark { observed_monotonic: app.clock.now_monotonic() }), 128);
            }
            return Err(ApiError::NotFound);
        }
        Err(UpstreamError::Status(401)) if app.service_policy().is_some() => return Err(ApiError::UpstreamUnauthenticated),
        Err(UpstreamError::Status(403)) if app.service_policy().is_some() => return Err(ApiError::UpstreamDenied),
        Err(UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
        Err(err) => {
            tracing::warn!(gem = %name, error = %err, "the upstream fetch failed");
            return Err(ApiError::UpstreamFailure);
        }
    };
    let entries = parse_entries(app, name, &payload)?;
    let mut references = Vec::with_capacity(entries.len());
    for entry in &entries {
        let Some((id, reference)) = reference_of(name, entry, &origins, kind, key.registry_id) else {
            return Err(ApiError::UpstreamInvalid);
        };
        references.push(ReferenceUpsert {
            id,
            reference,
            publication_micros: entry.created_micros,
            first_seen_micros: entry.created_micros.is_none().then_some(now),
        });
    }
    let lower = name.to_ascii_lowercase();
    let refresh = ProjectRefresh {
        ecosystem: Ecosystem::RubyGems,
        name: lower.clone(),
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
    let pins = app.store().list_project_pins_in(key.registry_id, Ecosystem::RubyGems, &lower).await.map_err(storage_error)?;
    if let Ok(mut known) = app.rubygems.spellings.lock() {
        // ponytail: forgotten when 4096 gems are tracked (each then re-earns its spellings), after a
        // restart, and not coordinated across instances; a persisted per-gem count if that matters.
        if known.len() >= 4096 {
            known.clear();
        }
        let committed = known.entry((key.registry_id, lower.clone())).or_default();
        if !committed.iter().any(|spelling| spelling == name) {
            committed.push(name.to_owned());
        }
    }
    Ok(Arc::new(CachedProject {
        row: ProjectRow {
            ecosystem: Ecosystem::RubyGems,
            name: lower,
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

/// `GET {root}/info/{gem}`: the compact index of one gem with every line the policy
/// refuses removed and every other line unchanged.
pub async fn serve_info(app: &App, principal: Option<&Principal>, name: &str, registry_id: u64) -> Result<Rendered, ApiError> {
    let name = gem_name(name)?;
    let now = app.clock.now_utc_micros();
    let policy = app.policy_for(principal).ok_or(ApiError::PolicyUnavailable)?;
    if !policy.snapshot.as_deref().is_some_and(|snapshot| snapshot.is_valid_at(now)) {
        return Err(ApiError::PolicyUnavailable);
    }
    let cached = current_project(app, name, registry_id, principal).await?;
    let (origins, kind) = origins_for(app, principal)?;
    let entries = parse_entries(app, name, &cached.row.payload)?;
    let scope = app.osv_scope(registry_id);
    let lower = name.to_ascii_lowercase();
    let judged = futures_util::future::join_all(entries.iter().map(|entry| {
        let cached = Arc::clone(&cached);
        let policy = &policy;
        let origins = &origins;
        let lower = &lower;
        async move {
            let Some((id, reference)) = reference_of(name, entry, origins, kind, registry_id) else { return Decision::Allow };
            let candidate = Candidate {
                ecosystem: Ecosystem::RubyGems,
                name: lower,
                version: &entry.version,
                publication: publication_of(entry, &id, &cached),
                advertised_digests: &reference.expected,
                pinned_digests: cached.pins_of(&id),
            };
            crate::osv::evaluate_scoped(&app.osv, policy, now, &candidate, scope).await
        }
    }))
    .await;
    logging::record_cache(logging::CacheStatus::Miss);
    // Managed mode: a listing with nothing left is this family's refusal; its verdict is the
    // block of the first refused line, else the earliest hold (as `pypi::refused_listing`).
    if let (Some(principal), Some(managed)) = (principal, app.managed())
        && !entries.is_empty()
        && !judged.iter().any(|decision| matches!(decision, Decision::Allow))
    {
        let blocked = judged.iter().position(|decision| matches!(decision, Decision::Deny(_)));
        let held = || {
            judged.iter().enumerate().filter_map(|(i, d)| match d {
                Decision::Hold { eligible_at_micros } => Some((*eligible_at_micros, i)),
                _ => None,
            }).min().map(|(_, i)| i)
        };
        if let Some(index) = blocked.or_else(held)
            && let Some((id, reference)) = reference_of(name, &entries[index], &origins, kind, registry_id)
        {
            let candidate = Candidate {
                ecosystem: Ecosystem::RubyGems,
                name: &lower,
                version: &entries[index].version,
                publication: publication_of(&entries[index], &id, &cached),
                advertised_digests: &reference.expected,
                pinned_digests: cached.pins_of(&id),
            };
            let verdict = crate::managed::refused_verdict(&policy, now, &candidate, judged[index]);
            managed.record_decision(principal, Ecosystem::RubyGems, &lower, None, &verdict);
        }
    }
    let kept = entries.iter().zip(&judged).filter(|(_, decision)| matches!(decision, Decision::Allow)).map(|(entry, _)| entry);
    Ok(Rendered { body: Arc::from(info::render_info(kept)), content_type: TEXT })
}

/// The reference a gem file name resolves to, against the current index. A name that fits
/// no entry is not found; one that fits two (`foo-1-2.0.gem` as two gems) refuses.
pub async fn reference_for_file(app: &App, principal: Option<&Principal>, filename: &str, registry_id: u64) -> Result<(ReferenceId, String), ApiError> {
    let mut found = Vec::new();
    let candidates = info::filename_candidates(filename);
    // SR17-1: the name picks which gems are asked about upstream, so it is bounded before any
    // fetch: a file name with more digit-led hyphens than a real gem name has is not a gem file.
    if candidates.len() > MAX_NAME_SPLITS {
        return Err(ApiError::NotFound);
    }
    for (name, suffix) in candidates {
        if found.len() > 1 {
            break;
        }
        let cached = match current_project(app, &name, registry_id, principal).await {
            Ok(cached) => cached,
            Err(ApiError::NotFound) => continue,
            Err(other) => return Err(other),
        };
        let (origins, kind) = origins_for(app, principal)?;
        let entries = parse_entries(app, &name, &cached.row.payload)?;
        if let Some(entry) = entries.iter().find(|entry| entry.suffix() == suffix)
            && let Some((id, _)) = reference_of(&name, entry, &origins, kind, registry_id)
        {
            found.push((id, name));
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(ApiError::NotFound),
        _ => {
            tracing::warn!(%filename, "refusing a gem file name that fits two index entries");
            Err(ApiError::NotFound)
        }
    }
}

/// SPEC §9 membership: the ids the current snapshot advertises (artifact path).
///
/// `name` is the stored (lower-case) name; the ids are the ones of the spelling the file was
/// named with (`filename` starts with it), because file names are case-exact upstream.
pub async fn ensure_fresh_project_in(app: &App, name: &str, filename: &str, registry_id: u64, principal: Option<&Principal>) -> Result<Arc<Advertised>, ApiError> {
    let name = gem_name(name)?;
    let name = filename.get(..name.len()).filter(|prefix| prefix.eq_ignore_ascii_case(name)).unwrap_or(name);
    let cached = current_project(app, name, registry_id, principal).await?;
    if let Some(advertised) = cached.advertised.get()
        && advertised.by_filename(filename).is_some()
    {
        return Ok(Arc::clone(advertised));
    }
    let (origins, kind) = origins_for(app, principal)?;
    let entries = parse_entries(app, name, &cached.row.payload)?;
    let refs: Vec<(ReferenceId, String)> = entries
        .iter()
        .filter_map(|entry| reference_of(name, entry, &origins, kind, registry_id).map(|(id, r)| (id, r.filename)))
        .collect();
    // ponytail: the snapshot keeps the first spelling's set; another spelling rebuilds per call.
    let advertised = Arc::new(Advertised::new(refs.iter().map(|(id, filename)| (*id, filename.as_str()))));
    let _ = cached.advertised.set(Arc::clone(&advertised));
    Ok(advertised)
}

/// `GET {root}/versions` and `GET {root}/names`: upstream's list, bounded and unchanged.
pub async fn serve_list(app: &App, principal: Option<&Principal>, which: &str) -> Result<Rendered, ApiError> {
    let (origins, kind) = origins_for(app, principal)?;
    let url = origins.url_for(kind, &[which]).map_err(|_| ApiError::NotFound)?;
    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            origin: principal.and_then(|p| p.registry_origin.clone()),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept: "text/plain",
            validators: None,
            max_bytes: app.config.max_metadata_bytes.get(),
        })
        .await;
    app.upstreams.record_upstream(Call::Rubygems, &fetched);
    let body = match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => body,
        Ok(_) => return Err(ApiError::UpstreamInvalid),
        Err(UpstreamError::Status(401)) if app.service_policy().is_some() => return Err(ApiError::UpstreamUnauthenticated),
        Err(UpstreamError::Status(403)) if app.service_policy().is_some() => return Err(ApiError::UpstreamDenied),
        Err(UpstreamError::Status(404)) => return Err(ApiError::NotFound),
        Err(UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
        Err(_) => return Err(ApiError::UpstreamFailure),
    };
    let text = std::str::from_utf8(&body).map_err(|_| ApiError::UpstreamInvalid)?;
    if which == "versions" {
        check_versions(text)?;
    } else {
        check_names(text)?;
    }
    Ok(Rendered { body: Arc::from(body.as_ref()), content_type: TEXT })
}

/// `names`: the `---` header, then one gem name per line.
fn check_names(text: &str) -> Result<(), ApiError> {
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        return Err(ApiError::UpstreamInvalid);
    }
    lines.all(|line| line.is_empty() || info::valid_gem_name(line)).then_some(()).ok_or(ApiError::UpstreamInvalid)
}

/// A `versions` file has a header and a `---` line before its entries; anything else is not
/// the compact index and refuses.
fn check_versions(text: &str) -> Result<(), ApiError> {
    text.lines().any(|line| line == "---").then_some(()).ok_or(ApiError::UpstreamInvalid)
}

/// `GET {root}/quick/Marshal.4.8/{name}-{version}[-{platform}].gemspec.rz`: identity-gated.
/// The gem identity must resolve against the index and be allowed; upstream's zlib is
/// inflated within the 4 MiB cap, validated (LS-F13 B) and the ORIGINAL bytes are served.
pub async fn serve_quick_gemspec(app: &Arc<App>, principal: Option<&Principal>, file: &str, registry_id: u64) -> Result<Rendered, ApiError> {
    let gem_file = file.strip_suffix(".gemspec.rz").map(|stem| format!("{stem}.gem")).ok_or(ApiError::NotFound)?;
    let (id, name) = reference_for_file(app, principal, &gem_file, registry_id).await?;
    let now = app.clock.now_utc_micros();
    let policy = app.policy_for(principal).ok_or(ApiError::PolicyUnavailable)?;
    if !policy.snapshot.as_deref().is_some_and(|snapshot| snapshot.is_valid_at(now)) {
        return Err(ApiError::PolicyUnavailable);
    }
    let cached = current_project(app, &name, registry_id, principal).await?;
    let (origins, kind) = origins_for(app, principal)?;
    let entries = parse_entries(app, &name, &cached.row.payload)?;
    let entry = entries
        .iter()
        .find(|entry| reference_of(&name, entry, &origins, kind, registry_id).is_some_and(|(candidate, _)| candidate == id))
        .ok_or(ApiError::NotFound)?;
    let (_, reference) = reference_of(&name, entry, &origins, kind, registry_id).ok_or(ApiError::NotFound)?;
    let candidate = Candidate {
        ecosystem: Ecosystem::RubyGems,
        name: &name.to_ascii_lowercase(),
        version: &entry.version,
        publication: publication_of(entry, &id, &cached),
        advertised_digests: &reference.expected,
        pinned_digests: cached.pins_of(&id),
    };
    if !matches!(crate::osv::evaluate_scoped(&app.osv, &policy, now, &candidate, app.osv_scope(registry_id)).await, Decision::Allow) {
        return Err(ApiError::NotFound);
    }
    let url = origins.url_for(kind, &["quick", "Marshal.4.8", file]).map_err(|_| ApiError::NotFound)?;
    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            origin: principal.and_then(|p| p.registry_origin.clone()),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept: "application/octet-stream",
            validators: None,
            max_bytes: crate::rubygems::inflate::GEMSPEC_CAP.min(app.config.max_metadata_bytes.get()),
        })
        .await;
    app.upstreams.record_upstream(Call::Rubygems, &fetched);
    let body = match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => body,
        Ok(MetadataResponse::Missing) | Err(UpstreamError::Status(404)) => return Err(ApiError::NotFound),
        Ok(_) => return Err(ApiError::UpstreamInvalid),
        Err(UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
        Err(_) => return Err(ApiError::UpstreamFailure),
    };
    // The validating pass is synchronous and holds non-Send values, so it runs to completion here.
    let bytes = body.clone();
    let verdict = tokio::task::spawn_blocking(move || {
        crate::rubygems::inflate::inflate(&bytes, true, crate::rubygems::inflate::GEMSPEC_CAP)
            .map_err(|_| ())
            .and_then(|raw| crate::rubygems::marshal::validate_gemspec(&raw, crate::rubygems::marshal::Limits::GEMSPEC).map_err(|_| ()))
    })
    .await
    .map_err(|_| ApiError::InternalFailure)?;
    if verdict.is_err() {
        tracing::warn!(gemspec = %file, "refusing a quick gemspec that fails the Marshal contract");
        return Err(ApiError::UpstreamInvalid);
    }
    Ok(Rendered { body: Arc::from(body.as_ref()), content_type: BINARY })
}

/// State shared by every request of this process: the filtered tuple indexes (a request-scoped
/// read never reads or writes them), the recent-versions dates, and the limiter of the heavy
/// path (SR17-2, CR F6).
pub struct Shared {
    indexes: std::sync::Mutex<std::collections::HashMap<IndexKey, CachedIndex>>,
    /// One build at a time per filtered index (N6): later requests find it cached.
    flights: std::sync::Mutex<std::collections::HashMap<IndexKey, Flight>>,
    /// The recent-versions list per (registry, window, origin), one fetch at a time per key (N3).
    recent: std::sync::Mutex<std::collections::HashMap<RecentKey, RecentCell>>,
    /// (registry, spelling) pairs whose references this process has committed (N2/N7).
    spellings: std::sync::Mutex<std::collections::HashMap<(u64, String), Vec<String>>>,
    /// Credential-bearing index builds per (registry, origin): at most two crawl and build at once (R3).
    private_gates: std::sync::Mutex<std::collections::HashMap<RecentKey, Arc<PrivateGate>>>,
    heavy: tokio::sync::Semaphore,
    /// The total time one recent-versions crawl may take, in milliseconds (a test shortens it).
    recent_deadline_millis: std::sync::atomic::AtomicU64,
}

impl Shared {
    /// **Compiled only under `test-support`.**
    #[cfg(feature = "test-support")]
    pub fn set_recent_deadline(&self, deadline: Duration) {
        self.recent_deadline_millis.store(deadline.as_millis() as u64, std::sync::atomic::Ordering::SeqCst);
    }
}

struct PrivateGate(tokio::sync::Semaphore);

impl Default for PrivateGate {
    fn default() -> Self {
        PrivateGate(tokio::sync::Semaphore::new(2))
    }
}

type Flight = Arc<tokio::sync::Mutex<()>>;
/// Fetch time and the list; `None` is a remembered failure.
type RecentCell = Arc<tokio::sync::Mutex<Option<(std::time::Instant, Option<Arc<Recent>>)>>>;

/// The cell of `key`, dropping unused ones when the map is large.
fn cell_of<K: Eq + std::hash::Hash + Clone, V: Default>(map: &std::sync::Mutex<std::collections::HashMap<K, Arc<V>>>, key: &K) -> Arc<V> {
    let Ok(mut map) = map.lock() else { return Arc::default() };
    if map.len() >= 64 {
        map.retain(|_, cell| Arc::strong_count(cell) > 1);
    }
    Arc::clone(map.entry(key.clone()).or_default())
}

type IndexKey = (u64, &'static str, [u8; 32], Option<String>);
type CachedIndex = (std::time::Instant, Arc<[u8]>);
type RecentKey = (u64, u64, Option<String>);

impl Default for Shared {
    fn default() -> Shared {
        Shared { indexes: Default::default(), flights: Default::default(), recent: Default::default(), spellings: Default::default(), private_gates: Default::default(), heavy: tokio::sync::Semaphore::new(2), recent_deadline_millis: std::sync::atomic::AtomicU64::new(RECENT_DEADLINE.as_millis() as u64) }
    }
}

/// How long a filtered index or the recent-versions list is reused.
const INDEX_TTL: Duration = Duration::from_secs(60);
/// The recent-versions API reaches back at most this many seven-day windows (42 days).
const MAX_WINDOWS: u64 = 6;
const WEEK_SECONDS: u64 = 7 * 86_400;
/// A failed recent-versions fetch is remembered this long (a registry without the API is not
/// probed on every index build).
/// Case spellings of one gem committed per registry (R1).
const MAX_SPELLINGS: usize = 4;
const RECENT_FAILURE_TTL: Duration = Duration::from_secs(15);
/// rubygems.org answers 30 rows per page. At most this many page requests, this many rows and
/// this many bytes per page, and this long in all, are spent on one list; past any of them the
/// list is refused and every unindexed tuple stays unlisted (N1, N4). One seven-day window of
/// rubygems.org is roughly a thousand pages.
const MAX_RECENT_PAGES: u32 = 2_000;
const MAX_RECENT_ROWS: usize = 60_000;
const MAX_RECENT_PAGE_BYTES: u64 = 2 << 20;
const RECENT_DEADLINE: Duration = Duration::from_secs(300);

/// Versions published inside the cooldown window, each with its real publication time: the
/// authoritative date source for tuples of gems this instance has no compact index for.
struct Recent {
    dated: std::collections::HashMap<(String, String, String), i64>,
}

fn freeze_window(policy: &crate::policy::CompiledPolicy) -> u64 {
    if policy.skip_freeze {
        return 0;
    }
    policy.policy.chain.iter().filter_map(|layer| layer.freeze_seconds).max().unwrap_or(0)
}

/// `GET /api/v1/timeframe_versions.json?from=..&to=..&page=N` (rubygems.org: at most seven days
/// and 30 rows per call, pages until an empty one), once per window of the cooldown. Shareable
/// reads cache the result for a minute (a failure for 15 s), one fetch per (registry, window,
/// origin) at a time; a credential-bearing read neither reads nor fills the cache (C1028).
/// `None` when the registry has no such source or the list exceeds a cap: tuples of unindexed
/// gems then have no date at all, and none is invented for them.
async fn recent_versions(
    app: &Arc<App>,
    principal: Option<&Principal>,
    registry_id: u64,
    window: u64,
    now: i64,
    shareable: bool,
) -> Option<Arc<Recent>> {
    let key: RecentKey = (registry_id, window, principal.and_then(|p| p.registry_origin.as_ref()).map(ToString::to_string));
    let deadline = Duration::from_millis(app.rubygems.recent_deadline_millis.load(std::sync::atomic::Ordering::SeqCst));
    let crawl = {
        let (app, principal) = (Arc::clone(app), principal.cloned());
        move || async move { tokio::time::timeout(deadline, fetch_recent(&app, principal.as_ref(), registry_id, window, now)).await.ok().flatten() }
    };
    let Some(cell) = shareable.then(|| cell_of(&app.rubygems.recent, &key)) else {
        // A credential-bearing read never reads or fills the cache; it still queues behind a small
        // per-registry limit (R3). The caller already holds the index flight/limiter of its own.
        return crawl().await;
    };
    let mut guard = cell.lock_owned().await;
    if let Some((fetched, recent)) = guard.as_ref()
        && app.clock.now_monotonic().duration_since(*fetched) < if recent.is_some() { INDEX_TTL } else { RECENT_FAILURE_TTL }
    {
        return recent.clone();
    }
    // The crawl runs in a task that owns the cell's lock: a caller that goes away (a client
    // timeout) does not abandon it, and the next request finds the finished list. It is stamped
    // when it ends, not when it began.
    let (app, task) = (Arc::clone(app), crawl());
    tokio::spawn(async move {
        let recent = task.await;
        *guard = Some((app.clock.now_monotonic(), recent.clone()));
        recent
    })
    .await
    .ok()
    .flatten()
}

/// One row of a `timeframe_versions` page; every other field is skipped unparsed.
#[derive(serde::Deserialize)]
struct RecentRow {
    name: String,
    version: Option<String>,
    number: Option<String>,
    platform: Option<String>,
    version_created_at: Option<String>,
    created_at: Option<String>,
}

async fn fetch_recent(app: &App, principal: Option<&Principal>, registry_id: u64, window: u64, now: i64) -> Option<Arc<Recent>> {
    let windows = window.div_ceil(WEEK_SECONDS);
    if windows == 0 || windows > MAX_WINDOWS {
        // A freeze beyond 42 days cannot be dated from this API: fail closed, say so.
        tracing::warn!(window_seconds = window, registry_id, "the cooldown is longer than the recent-versions horizon; unindexed gem tuples are not listed");
        return None;
    }
    let (origins, kind) = origins_for(app, principal).ok()?;
    let mut dated = std::collections::HashMap::new();
    let (mut pages, mut rows) = (0u32, 0usize);
    let micros = |t: i64| jiff::Timestamp::from_microsecond(t).ok().map(|t| t.to_string());
    for n in 0..windows {
        let to = now - (n * WEEK_SECONDS * 1_000_000) as i64;
        let from = (to - (WEEK_SECONDS * 1_000_000) as i64).max(now - (window * 1_000_000) as i64 - 1_000_000);
        for page in 1u32.. {
            pages += 1;
            if pages > MAX_RECENT_PAGES {
                tracing::warn!(registry_id, "the recent-versions list has more pages than the cap; unindexed gem tuples are not listed");
                return None;
            }
            let mut url = origins.url_for(kind, &["api", "v1", "timeframe_versions.json"]).ok()?;
            url.query_pairs_mut().append_pair("from", &micros(from)?).append_pair("to", &micros(to)?).append_pair("page", &page.to_string());
            let fetched = app
                .transport
                .fetch_metadata(MetadataRequest {
                    url,
                    origin: principal.and_then(|p| p.registry_origin.clone()),
                    private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
                    read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
                    accept: "application/json",
                    validators: None,
                    max_bytes: MAX_RECENT_PAGE_BYTES.min(app.config.max_metadata_bytes.get()),
                })
                .await;
            app.upstreams.record_upstream(Call::Rubygems, &fetched);
            let Ok(MetadataResponse::Fresh { body, .. }) = fetched else { return None };
            let list: Vec<RecentRow> = serde_json::from_slice(&body).ok()?;
            if list.is_empty() {
                break;
            }
            rows += list.len();
            if rows > MAX_RECENT_ROWS {
                tracing::warn!(registry_id, "the recent-versions list has more rows than the cap; unindexed gem tuples are not listed");
                return None;
            }
            for item in list {
                let version = item.version.or(item.number)?;
                let created = item.version_created_at.or(item.created_at)?.parse::<jiff::Timestamp>().ok()?.as_microsecond();
                dated.insert((item.name.to_ascii_lowercase(), version, item.platform.unwrap_or_else(|| "ruby".to_owned())), created);
            }
        }
    }
    Some(Arc::new(Recent { dated }))
}

/// `GET {root}/specs.4.8.gz`, `latest_specs.4.8.gz`, `prerelease_specs.4.8.gz`: upstream's
/// tuple index inflated within the 128 MiB cap, filtered by the typed Marshal filter (LS-F13
/// A), re-rendered and gzip-encoded here.
///
/// Every tuple is judged by age and blocks with a real date:
/// * a tuple of a gem whose compact index this instance holds (standalone only; a shared
///   service never stores another caller's payload) is judged with everything the policy knows,
///   OSV included, so the listing agrees with `/info/{gem}`;
/// * any other tuple takes the registry's own publication time from the recent-versions list
///   (versions published inside the cooldown window), and a tuple absent from that list was
///   published before the window began, which is a date bound the cooldown cannot refuse;
/// * a registry with no recent-versions source gives such tuples no date, so they are NOT
///   listed (nothing is invented); Bundler's compact index is unaffected.
///
/// OSV is asked for the indexed gems only: a query per tuple of the whole index is not
/// possible, and the gemspec and gem file stay identity-gated, OSV included.
pub async fn serve_index(app: &Arc<App>, principal: Option<&Principal>, file: &str, registry_id: u64) -> Result<Rendered, ApiError> {
    if !matches!(file, "specs.4.8.gz" | "latest_specs.4.8.gz" | "prerelease_specs.4.8.gz") {
        return Err(ApiError::NotFound);
    }
    let now = app.clock.now_utc_micros();
    let policy = app.policy_for(principal).ok_or(ApiError::PolicyUnavailable)?;
    if !policy.snapshot.as_deref().is_some_and(|snapshot| snapshot.is_valid_at(now)) {
        return Err(ApiError::PolicyUnavailable);
    }
    let shareable = crate::http::credential_read::cache_token(app).is_some();
    let key: IndexKey = (
        registry_id,
        match file {
            "specs.4.8.gz" => "specs.4.8.gz",
            "latest_specs.4.8.gz" => "latest_specs.4.8.gz",
            _ => "prerelease_specs.4.8.gz",
        },
        policy.policy.fingerprint.0,
        principal.and_then(|p| p.registry_origin.as_ref()).map(ToString::to_string),
    );
    let cached_index = || {
        let (at, body) = app.rubygems.indexes.lock().ok().and_then(|cache| cache.get(&key).cloned())?;
        (app.clock.now_monotonic().duration_since(at) < INDEX_TTL).then_some(body)
    };
    if shareable && let Some(body) = cached_index() {
        return Ok(Rendered { body, content_type: BINARY });
    }
    // One build per index at a time (N6): the others wait here, then find it cached.
    let flight = shareable.then(|| cell_of(&app.rubygems.flights, &key));
    let _flight = match &flight {
        Some(flight) => Some(flight.lock().await),
        None => None,
    };
    if shareable && let Some(body) = cached_index() {
        return Ok(Rendered { body, content_type: BINARY });
    }
    // The dates come first and without a heavy permit: a slow registry holds only its own key.
    let private_gate = (!shareable).then(|| cell_of(&app.rubygems.private_gates, &(registry_id, 0, principal.and_then(|p| p.registry_origin.as_ref()).map(ToString::to_string))));
    let _private = match &private_gate {
        Some(gate) => Some(gate.0.acquire().await.map_err(|_| ApiError::InternalFailure)?),
        None => None,
    };
    let window = freeze_window(&policy);
    let recent = if window == 0 { None } else { recent_versions(app, principal, registry_id, window, now, shareable).await };
    // One or two index passes at a time: each holds up to the codec's memory budget.
    let _permit = app.rubygems.heavy.acquire().await.map_err(|_| ApiError::InternalFailure)?;
    let (origins, kind) = origins_for(app, principal)?;
    let url = origins.url_for(kind, &[file]).map_err(|_| ApiError::NotFound)?;
    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            origin: principal.and_then(|p| p.registry_origin.clone()),
            private_cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            read_authorization: principal.and_then(|p| p.registry_read_authorization.clone()),
            accept: "application/octet-stream",
            validators: None,
            max_bytes: app.config.max_metadata_bytes.get(),
        })
        .await;
    app.upstreams.record_upstream(Call::Rubygems, &fetched);
    let compressed = match fetched {
        Ok(MetadataResponse::Fresh { body, .. }) => body,
        Ok(_) => return Err(ApiError::UpstreamInvalid),
        Err(UpstreamError::Status(401)) if app.service_policy().is_some() => return Err(ApiError::UpstreamUnauthenticated),
        Err(UpstreamError::Status(403)) if app.service_policy().is_some() => return Err(ApiError::UpstreamDenied),
        Err(UpstreamError::Status(404)) => return Err(ApiError::NotFound),
        Err(UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
        Err(_) => return Err(ApiError::UpstreamFailure),
    };
    // The gems this instance holds a compact index for: judged completely, once, before the pass.
    type Tuple = (String, String);
    struct Held {
        present: std::collections::HashSet<Tuple>,
        refused: std::collections::HashSet<Tuple>,
    }
    let scope = app.osv_scope(registry_id);
    let mut judged: std::collections::HashMap<String, Held> = std::collections::HashMap::new();
    for name in app.store().list_known_projects_in(registry_id, Ecosystem::RubyGems).await.map_err(storage_error)? {
        let Some(cached) = load_project(app, &name, registry_id).await? else { continue };
        let Ok(entries) = info::parse_info(&cached.row.payload, app.config.max_references_per_project.get() as usize) else { continue };
        let lower = name.to_ascii_lowercase();
        let (origins, kind) = origins_for(app, principal)?;
        let mut held = Held { present: Default::default(), refused: Default::default() };
        for entry in &entries {
            let Some((id, reference)) = reference_of(&name, entry, &origins, kind, registry_id) else { continue };
            let tuple = (entry.version.clone(), entry.platform.clone().unwrap_or_else(|| "ruby".to_owned()));
            let candidate = Candidate {
                ecosystem: Ecosystem::RubyGems,
                name: &lower,
                version: &entry.version,
                publication: publication_of(entry, &id, &cached),
                advertised_digests: &reference.expected,
                pinned_digests: cached.pins_of(&id),
            };
            if !matches!(crate::osv::evaluate_scoped(&app.osv, &policy, now, &candidate, scope).await, Decision::Allow) {
                held.refused.insert(tuple.clone());
            }
            held.present.insert(tuple);
        }
        judged.insert(lower, held);
    }
    let task_policy = Arc::clone(&policy);
    let rendered = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, ()> {
        let raw = crate::rubygems::inflate::inflate(&compressed, false, crate::rubygems::inflate::TUPLE_INDEX_CAP).map_err(|_| ())?;
        let bound = now - (window * 1_000_000) as i64 - 1_000_000;
        let (out, _) = crate::rubygems::marshal::filter_tuple_index(&raw, crate::rubygems::marshal::Limits::TUPLE_INDEX, |name, version, platform| {
            let lower = name.to_ascii_lowercase();
            let tuple = (version.to_owned(), platform.to_owned());
            if let Some(held) = judged.get(&lower)
                && held.present.contains(&tuple)
            {
                return !held.refused.contains(&tuple);
            }
            let publication = if window == 0 {
                PublicationTime::Upstream(now)
            } else {
                match &recent {
                    Some(recent) => PublicationTime::Upstream(recent.dated.get(&(lower.clone(), tuple.0.clone(), tuple.1.clone())).copied().unwrap_or(bound)),
                    // No date source: no date is invented, the tuple is not listed.
                    None => return false,
                }
            };
            let candidate = Candidate {
                ecosystem: Ecosystem::RubyGems,
                name: &lower,
                version,
                publication,
                advertised_digests: &[],
                pinned_digests: &[],
            };
            matches!(crate::policy::decide(&task_policy, &candidate, now, false).decision, Decision::Allow)
        })
        .map_err(|_| ())?;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &out).map_err(|_| ())?;
        gz.finish().map_err(|_| ())
    })
    .await
    .map_err(|_| ApiError::InternalFailure)?;
    match rendered {
        Ok(body) => {
            let body: Arc<[u8]> = Arc::from(body);
            if shareable && let Ok(mut cache) = app.rubygems.indexes.lock() {
                if cache.len() >= 16 {
                    cache.clear();
                }
                cache.insert(key, (app.clock.now_monotonic(), Arc::clone(&body)));
            }
            Ok(Rendered { body, content_type: BINARY })
        }
        Err(()) => {
            tracing::warn!(%file, "refusing a tuple index that fails the Marshal or compression contract");
            Err(ApiError::UpstreamInvalid)
        }
    }
}
