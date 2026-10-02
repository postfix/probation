//! PyPI metadata, end to end: fetch or reuse one Simple API document, judge every
//! *file* against one blocklist snapshot and one `now`, and render the survivors as
//! HTML or JSON.
//!
//! Three things differ from `npm` (SPEC §7), and each of them is why this module
//! exists rather than being a parameter of that one:
//!
//! * **A name is rewritten.** PEP 503 normalisation decides the store key, the
//!   upstream segment and the name the blocklist is asked about; a request that used
//!   another spelling gets a local `301` rather than a second URL for one project.
//! * **The unit of judgement is a file, not a release.** Every file carries its own
//!   upload time, so a wheel added to a year-old release serves its own wait instead
//!   of inheriting the sdist's age.
//! * **An empty listing is a valid answer.** npm returns a policy denial when nothing
//!   survives; pip's own "no matching distribution" message is better than a `403`,
//!   so a known project with no eligible files gets a well-formed empty listing.

pub mod filename;
pub mod name;
pub mod render;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;
use url::Url;

use crate::App;
use crate::concurrency::Resolution;
use crate::http::error::ApiError;
use crate::http::logging;
use crate::policy::{
    BlocklistSnapshot, Candidate, Decision, Digest, Ecosystem, HashAlgorithm, PublicationTime,
};
use crate::pypi::filename::{FileIdentity, UnsupportedFilename, file_identity};
use crate::pypi::render::ListedFile;
use crate::store::cache::{
    AbsentMark, CachedProject, ProjectKey, RenderKey, RenderedResponse, Representation,
};
use crate::store::rows::{
    ArtifactReference, Generation, ProjectRefresh, ProjectRow, ReferenceId, ReferenceUpsert,
};
use crate::store::{self, StoreError};
use crate::upstream::{MetadataRequest, MetadataResponse, OriginKind, UpstreamError};

pub use name::{InvalidProjectName, ProjectName};

/// PEP 691's JSON serialisation, which is the only form that carries PEP 700's
/// per-file `upload-time` — and therefore the only form this proxy can judge a file's
/// own age from.
const PYPI_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

/// The hash names SPEC §8 can block on, plus npm's legacy SHA-1 for symmetry. Any
/// other name upstream advertises is carried through to the client untouched but is
/// never turned into a [`Digest`], because nothing could block on it.
const BLOCKABLE_HASHES: [(&str, HashAlgorithm); 3] = [
    ("sha256", HashAlgorithm::Sha256),
    ("sha512", HashAlgorithm::Sha512),
    ("sha1", HashAlgorithm::Sha1),
];

/// A serialised response and the type it is served as.
pub struct Rendered {
    pub body: Arc<[u8]>,
    pub content_type: &'static str,
}

/// `GET /pypi/simple/{project}/`.
pub async fn serve(
    app: &App,
    name: &ProjectName,
    representation: Representation,
) -> Result<Rendered, ApiError> {
    let now = app.clock.now_utc_micros();
    let monotonic = app.clock.now_monotonic();

    // SPEC §9's ordering point, read exactly once for this request.
    let snapshot = app.blocklist().ok_or(ApiError::PolicyUnavailable)?;
    if !snapshot.is_valid_at(now) {
        return Err(ApiError::PolicyUnavailable);
    }

    let project = ProjectKey::new(Ecosystem::PyPi, name.as_str());
    let render_key = RenderKey {
        project: project.clone(),
        representation: representation.clone(),
    };
    let caches = app.store().caches();

    // The warm path: two memory lookups and nothing else (SPEC §10).
    if let Some(rendered) = caches.rendered.get(&render_key)
        && let Some(cached) = caches.projects.get(&project)
        && rendered.is_reusable(
            cached.row.generation,
            snapshot.revision,
            cached.row.digest_generation,
            now,
            monotonic,
        )
    {
        // SPEC §11 asks the decision line to carry a cache status, and this branch is
        // the one that defines "warm" for metadata (SPEC §10).
        logging::record_cache(logging::CacheStatus::Hit);
        return Ok(Rendered {
            body: Arc::clone(&rendered.body),
            content_type: rendered.content_type,
        });
    }
    logging::record_cache(logging::CacheStatus::Miss);

    let resolved = resolve(app, name, &snapshot, now, monotonic).await?;
    let (body, content_type) = render(app, name, &resolved, &representation);
    let body: Arc<[u8]> = Arc::from(body);

    if resolved.deadline_utc_micros > now {
        caches.rendered.insert(
            render_key,
            Arc::new(RenderedResponse {
                body: Arc::clone(&body),
                content_type,
                project_generation: resolved.generation,
                blocklist_revision: snapshot.revision,
                digest_generation: resolved.digest_generation,
                deadline_utc_micros: resolved.deadline_utc_micros,
                deadline_monotonic: resolved.deadline_monotonic,
            }),
            body.len() as u64 + 256,
        );
    }

    Ok(Rendered { body, content_type })
}

/// `GET /pypi/simple/` — the projects *this instance* has already fetched, which
/// SPEC §7 is explicit is not a mirror of PyPI. Installing a project that is absent
/// from it still works through its own endpoint.
pub async fn index(app: &App, representation: &Representation) -> Result<Rendered, ApiError> {
    let now = app.clock.now_utc_micros();
    let snapshot = app.blocklist().ok_or(ApiError::PolicyUnavailable)?;
    if !snapshot.is_valid_at(now) {
        return Err(ApiError::PolicyUnavailable);
    }

    // Every known project is listed, including one the blocklist denies outright:
    // its own listing is what answers for it, and that listing is already empty.
    let projects = app
        .store()
        .list_known_projects(Ecosystem::PyPi)
        .await
        .map_err(storage_error)?;

    let (body, content_type) = match representation {
        Representation::PypiJson => (render::index_json(&projects), render::JSON_CONTENT_TYPE),
        _ => (render::index_html(&projects), render::HTML_CONTENT_TYPE),
    };

    Ok(Rendered {
        body: Arc::from(body),
        content_type,
    })
}

/// One project, judged. `decisions` is parallel to `files`.
struct Resolved {
    files: Vec<ProjectFile>,
    decisions: Vec<Decision>,
    generation: Generation,
    digest_generation: u64,
    deadline_utc_micros: i64,
    deadline_monotonic: Instant,
}

/// The project snapshot a decision must be made from: the cached one while it is
/// within its metadata TTL, a refreshed one when it is not (SPEC §10). The artifact
/// path needs exactly this, which is why it is not inline in [`resolve`].
async fn current_project(
    app: &App,
    name: &ProjectName,
    now: i64,
    monotonic: Instant,
) -> Result<Arc<CachedProject>, ApiError> {
    let key = ProjectKey::new(Ecosystem::PyPi, name.as_str());
    let caches = app.store().caches();
    let ttl = Duration::from_secs(app.config.metadata_ttl_seconds);
    let ttl_micros = i64::try_from(ttl.as_micros()).unwrap_or(i64::MAX);

    // TM-4: a name upstream has already denied is not asked about again until the
    // metadata TTL is up. Monotonic, so a wall-clock jump cannot extend it.
    if let Some(mark) = caches.absent.get(&key) {
        if monotonic.duration_since(mark.observed_monotonic) < ttl {
            return Err(ApiError::NotFound);
        }
        caches.absent.remove(&key);
    }

    // One read, returning the snapshot and the invalidation count it was read at.
    // Everything below may install that snapshot back into the cache, and a pin
    // committed in between contradicts it — so this count is what the insert at the
    // bottom is checked against (SPEC §9). Taking the two as one call is what makes
    // the ordering impossible to get wrong at this call site.
    let (seen, cached) = caches.projects.get_with_seen(&key);

    let cached = match cached {
        Some(cached) => Some(cached),
        None => load_project(app, name).await?.map(Arc::new),
    };

    // SPEC rev 3 §10: age since the last FULL fetch, which no `304` advances. Once
    // it reaches this project's effective ceiling the snapshot is over-age, and an
    // over-age snapshot is never served — so this is checked ahead of the TTL, which
    // repeated `304`s keep renewing.
    let over_age = cached.as_ref().is_some_and(|cached| {
        store::is_over_age(
            &key,
            app.config.metadata_max_age_seconds,
            cached.row.fetched_at_micros,
            now,
        )
    });

    let cached = match cached {
        Some(cached)
            if !over_age && now < cached.row.validated_at_micros.saturating_add(ttl_micros) =>
        {
            cached
        }
        // SPEC §10: revalidate upstream after the metadata TTL rather than serving
        // expired metadata. The expired snapshot travels with the refresh rather than
        // being dropped here: its validators are what make that revalidation
        // conditional — unless it is over-age, in which case the refresh sends none
        // at all.
        stale => refresh_coalesced(app, name, &key, now, monotonic, over_age, stale).await?,
    };

    caches
        .projects
        .insert_if_current(key, Arc::clone(&cached), cached.approximate_bytes(), seen);
    Ok(cached)
}

/// SPEC §9: "Every artifact request must confirm that the reference is still
/// advertised by a sufficiently fresh upstream project snapshot […] A removed
/// reference is unavailable even if its bytes remain cached."
///
/// The set is parsed once per project snapshot and kept with it
/// ([`CachedProject::advertised`]): a warm artifact request re-parses nothing, which
/// is what SPEC §12's warm-artifact target needs on a project carrying thousands of
/// files.
pub async fn ensure_fresh_project(
    app: &App,
    name: &str,
) -> Result<Arc<HashSet<ReferenceId>>, ApiError> {
    // Already normalised when it was stored; rebuilt rather than trusted, and a name
    // that is no longer a normal form is a reference nothing can be served for.
    let name = ProjectName::from_normalized(name).ok_or_else(|| {
        tracing::warn!(project = %name, "a stored reference names an unusable project");
        ApiError::NotFound
    })?;
    let cached = current_project(
        app,
        &name,
        app.clock.now_utc_micros(),
        app.clock.now_monotonic(),
    )
    .await?;

    if let Some(advertised) = cached.advertised.get() {
        return Ok(Arc::clone(advertised));
    }

    let files = parse_stored(app, &name, &cached.row.payload)?;
    let advertised: Arc<HashSet<ReferenceId>> =
        Arc::new(files.iter().map(|file| file.id).collect());
    // Through the `Arc` the cache handed out, so the next request for this same
    // snapshot finds it. A racing filler sets the same value from the same bytes.
    let _ = cached.advertised.set(Arc::clone(&advertised));
    Ok(advertised)
}

async fn resolve(
    app: &App,
    name: &ProjectName,
    snapshot: &BlocklistSnapshot,
    now: i64,
    monotonic: Instant,
) -> Result<Resolved, ApiError> {
    let cached = current_project(app, name, now, monotonic).await?;
    let ttl_micros =
        i64::try_from(Duration::from_secs(app.config.metadata_ttl_seconds).as_micros())
            .unwrap_or(i64::MAX);

    let files = parse_stored(app, name, &cached.row.payload)?;

    let mut decisions = Vec::with_capacity(files.len());
    let mut next_release: Option<i64> = None;
    for file in &files {
        let candidate = Candidate {
            ecosystem: Ecosystem::PyPi,
            name: name.as_str(),
            // The filename's own spelling. `blocks_version` compares parsed PEP 440
            // forms, so an equivalent spelling of a blocked version still matches.
            version: &file.identity.version,
            publication: publication_of(file, &cached.first_seen),
            advertised_digests: &file.reference.expected,
            // SPEC §9: a block on a digest this instance computed itself denies the
            // file here as well as at the artifact endpoint, so the next resolution
            // hides it. Unconditionally: the pin drops this project's cache entry,
            // and `current_project`'s guarded insert is what stops a reader putting
            // an older snapshot back — see `artifacts::download::fetch`.
            pinned_digests: cached.pins_of(&file.id),
        };
        let decision = crate::osv::evaluate(
            &app.osv,
            Some(snapshot),
            now,
            app.config.cooldown_seconds,
            &candidate,
        )
        .await;
        if let Decision::Hold { eligible_at_micros } = decision {
            next_release = Some(
                next_release.map_or(eligible_at_micros, |held: i64| held.min(eligible_at_micros)),
            );
        }
        decisions.push(decision);
    }

    // SPEC §10: the earliest of upstream metadata TTL, blocklist expiry, and the next
    // held file's eligibility time, so a released file appears without a scheduler.
    //
    // SPEC rev 3 §10 adds a fourth: this snapshot's maximum-age ceiling. Repeated
    // `304`s push the TTL deadline past it, and a projection outliving the ceiling
    // would serve an over-age snapshot from memory without ever reaching
    // [`current_project`] — which is the one thing "never served" forbids.
    let ceiling = store::effective_max_age_micros(
        &ProjectKey::new(Ecosystem::PyPi, name.as_str()),
        app.config.metadata_max_age_seconds,
    )
    .map_or(i64::MAX, |ceiling| {
        cached.row.fetched_at_micros.saturating_add(ceiling)
    });
    let deadline_utc_micros = cached
        .row
        .validated_at_micros
        .saturating_add(ttl_micros)
        .min(snapshot.expires_at_micros)
        .min(next_release.unwrap_or(i64::MAX))
        .min(ceiling);
    let deadline_monotonic =
        monotonic + Duration::from_micros(deadline_utc_micros.saturating_sub(now).max(0) as u64);

    Ok(Resolved {
        generation: cached.row.generation,
        digest_generation: cached.row.digest_generation,
        files,
        decisions,
        deadline_utc_micros,
        deadline_monotonic,
    })
}

/// SPEC §5: upstream's own time wins; otherwise the committed first-seen time for
/// that exact reference; otherwise `Unknown`, which never becomes eligible.
fn publication_of(file: &ProjectFile, first_seen: &HashMap<ReferenceId, i64>) -> PublicationTime {
    match file.publication {
        PublicationTime::Upstream(micros) => PublicationTime::Upstream(micros),
        PublicationTime::Malformed => PublicationTime::Malformed,
        PublicationTime::FirstSeen(_) | PublicationTime::Unknown => first_seen
            .get(&file.id)
            .map_or(PublicationTime::Unknown, |micros| {
                PublicationTime::FirstSeen(*micros)
            }),
    }
}

async fn load_project(app: &App, name: &ProjectName) -> Result<Option<CachedProject>, ApiError> {
    let row = app
        .store()
        .get_project(Ecosystem::PyPi, name.as_str())
        .await
        .map_err(storage_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let first_seen = app
        .store()
        .list_project_first_seen(Ecosystem::PyPi, name.as_str())
        .await
        .map_err(storage_error)?;
    let pins = app
        .store()
        .list_project_pins(Ecosystem::PyPi, name.as_str())
        .await
        .map_err(storage_error)?;
    Ok(Some(CachedProject {
        row,
        first_seen,
        pins,
        advertised: OnceLock::new(),
    }))
}

/// SPEC §10: "Coalesce concurrent metadata refreshes per project."
///
/// The mechanism is the same one, on the same table — `ProjectKey` carries the
/// ecosystem, so the two never collide.
///
/// `crate::npm::refresh_coalesced` carries the full note, including the one cost this
/// shares with it: the refresh runs inline in the leading request's own future rather
/// than in a task of its own, so a leader whose request is dropped hands every joiner a
/// `503` that a solo refresh would not have produced. Bounded and self-healing, not a
/// wedge; the upgrade path is the same `Arc<App>` change named there.
///
/// `stale` is the expired snapshot this request found, when there was one. Only the
/// leader's is used — a joiner is answered from the leader's result, which is the point
/// of the latch.
async fn refresh_coalesced(
    app: &App,
    name: &ProjectName,
    key: &ProjectKey,
    now: i64,
    monotonic: Instant,
    over_age: bool,
    stale: Option<Arc<CachedProject>>,
) -> Result<Arc<CachedProject>, ApiError> {
    let refreshes = app.downloads.metadata();
    let (slot, leader, _waiter) = refreshes.join(key.clone());
    if !leader {
        // A refresh for this project is already in flight; its result is this
        // request's answer.
        return slot.wait().await.unwrap_or(Err(ApiError::InternalFailure));
    }

    let mut resolution = Resolution::new(
        refreshes.clone(),
        key.clone(),
        Arc::clone(&slot),
        Err(ApiError::InternalFailure),
        name.as_str().to_owned(),
    );
    let refreshed = refresh(app, name, key, now, monotonic, over_age, stale).await;
    resolution.answer(refreshed.clone());
    refreshed
}

/// Revalidate or fetch, parse, and commit. The commit is SPEC §5's ordering point: a
/// first-seen time is written before it is used to make anything eligible.
///
/// A `304` and a `200` differ in one thing only — where the document comes from. Both
/// then run the same parse, the same reference upserts and the same commit, which is
/// what SPEC §10's second clause asks for: the caller re-judges *this* document against
/// the blocklist in force now, so a file blocked since the last full fetch is excluded
/// rather than carried along on a representation nobody rebuilt.
async fn refresh(
    app: &App,
    name: &ProjectName,
    key: &ProjectKey,
    now: i64,
    monotonic: Instant,
    over_age: bool,
    stale: Option<Arc<CachedProject>>,
) -> Result<Arc<CachedProject>, ApiError> {
    // `/simple/{project}/`, built by pushing segments onto the origin — never joined
    // and never formatted. The trailing empty segment is the canonical form upstream
    // would otherwise redirect to.
    let url = app
        .origins
        .url_for(OriginKind::PypiMetadata, &["simple", name.as_str(), ""])
        .map_err(|rejection| {
            tracing::warn!(project = %name, %rejection, "refused to build an upstream URL");
            ApiError::NotFound
        })?;

    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            accept: PYPI_ACCEPT,
            // SPEC §10: revalidate rather than refetch in full. These are *our* stored
            // validators going upstream, which is the only direction they travel — SPEC
            // §10 separately forbids forwarding any validator downstream to a client,
            // and no client header reaches this request in any case.
            //
            // SPEC rev 3 §10: an over-age snapshot sends NO validators, so upstream is
            // given no opportunity to answer `304`. Asking conditionally and rejecting
            // the `304` afterwards would leave this firewall dependent on upstream
            // choosing to send a body, which is the dependence the ceiling removes.
            validators: (!over_age)
                .then(|| {
                    stale
                        .as_ref()
                        .map(|cached| cached.row.validators.clone())
                        .filter(|validators| !validators.is_empty())
                })
                .flatten(),
            max_bytes: app.config.max_metadata_bytes.get(),
        })
        .await;

    let (payload, validators, fetched_at_micros): (Arc<[u8]>, _, i64) = match fetched {
        Ok(MetadataResponse::Fresh { body, validators }) => {
            (Arc::from(body.as_ref()), validators, now)
        }
        // SPEC §10: "An upstream `304` renews upstream freshness." The document is the
        // one already stored, re-committed at this `now`, so the snapshot is fresh
        // again and the rest of this function rebuilds everything derived from it.
        //
        // SPEC rev 3 §10: it renews validation time ONLY. `fetched_at_micros` is
        // carried forward exactly as stored — writing `now` here would delete the
        // ceiling while leaving every visible behaviour identical until a copy had
        // aged past it.
        Ok(MetadataResponse::NotModified { validators }) => match &stale {
            // An over-age refresh asked unconditionally, so a `304` to it is an
            // upstream protocol violation, and the over-age copy is never served.
            Some(cached) if !over_age => {
                // A `304` need not repeat the validators it matched; keeping the
                // stored ones means the next revalidation is still conditional.
                let validators = if validators.is_empty() {
                    cached.row.validators.clone()
                } else {
                    validators
                };
                (
                    Arc::clone(&cached.row.payload),
                    validators,
                    cached.row.fetched_at_micros,
                )
            }
            _ => {
                tracing::warn!(project = %name, "upstream answered 304 to an unconditional request");
                return Err(ApiError::UpstreamInvalid);
            }
        },
        Ok(MetadataResponse::Missing) => {
            app.store().caches().absent.insert(
                key.clone(),
                Arc::new(AbsentMark {
                    observed_monotonic: monotonic,
                }),
                128,
            );
            return Err(ApiError::NotFound);
        }
        Err(UpstreamError::Timeout) => {
            tracing::warn!(project = %name, "the upstream index did not answer in time");
            return Err(ApiError::UpstreamTimeout);
        }
        Err(err) => {
            tracing::warn!(project = %name, error = %err, "the upstream fetch failed");
            return Err(ApiError::UpstreamFailure);
        }
    };

    let files = parse_files(app, name, &payload)?;
    let references = files
        .iter()
        .map(|file| ReferenceUpsert {
            id: file.id,
            reference: file.reference.clone(),
            publication_micros: match file.publication {
                PublicationTime::Upstream(micros) => Some(micros),
                _ => None,
            },
            first_seen_micros: matches!(file.publication, PublicationTime::Unknown).then_some(now),
        })
        .collect();

    // A refresh carries existing pins forward rather than changing them, but it does
    // replace the cached project, so they are read back with it.
    let pins = app
        .store()
        .list_project_pins(Ecosystem::PyPi, name.as_str())
        .await
        .map_err(storage_error)?;

    let committed = app
        .store()
        .commit_project_refresh(ProjectRefresh {
            ecosystem: Ecosystem::PyPi,
            name: name.as_str().to_owned(),
            payload: Arc::clone(&payload),
            validators: validators.clone(),
            validated_at_micros: now,
            fetched_at_micros,
            references,
        })
        .await
        .map_err(storage_error)?;

    Ok(Arc::new(CachedProject {
        row: ProjectRow {
            ecosystem: Ecosystem::PyPi,
            name: name.as_str().to_owned(),
            payload,
            validators,
            validated_at_micros: now,
            fetched_at_micros,
            generation: committed.generation,
            digest_generation: committed.digest_generation,
        },
        first_seen: committed.first_seen,
        pins,
        advertised: OnceLock::new(),
    }))
}

fn render(
    app: &App,
    name: &ProjectName,
    resolved: &Resolved,
    representation: &Representation,
) -> (Vec<u8>, &'static str) {
    let mut listed = Vec::new();
    let mut versions = BTreeSet::new();
    for (file, decision) in resolved.files.iter().zip(&resolved.decisions) {
        if !matches!(decision, Decision::Allow) {
            continue;
        }
        versions.insert(file.identity.version.clone());
        listed.push(ListedFile {
            url: crate::npm::render::artifact_url(
                &app.config.public_url,
                file.reference.ecosystem,
                &file.id,
                &file.reference.filename,
            ),
            filename: file.reference.filename.clone(),
            hashes: file.hashes.clone(),
            requires_python: file.requires_python.clone(),
            yanked: file.yanked.clone(),
            size: file.size,
        });
    }

    // SPEC §7: "For an existing project with no eligible files, return an empty valid
    // project listing […] Log why the files were excluded." One line per listing, not
    // one per file: a large project could otherwise write thousands.
    if listed.is_empty() && !resolved.files.is_empty() {
        tracing::info!(
            project = %name,
            files = resolved.files.len(),
            reasons = ?resolved.decisions,
            "every file of this project was excluded; serving an empty listing"
        );
    }

    let versions: Vec<String> = versions.into_iter().collect();
    match representation {
        Representation::PypiJson => (
            render::project_json(name.as_str(), &listed, &versions),
            render::JSON_CONTENT_TYPE,
        ),
        _ => (
            render::project_html(name.as_str(), &listed),
            render::HTML_CONTENT_TYPE,
        ),
    }
}

/// One upstream file whose identity was established.
struct ProjectFile {
    id: ReferenceId,
    reference: ArtifactReference,
    identity: FileIdentity,
    publication: PublicationTime,
    hashes: BTreeMap<String, String>,
    requires_python: Option<String>,
    yanked: Option<String>,
    size: Option<u64>,
}

/// Parses a stored or freshly fetched Simple API document into the files this
/// instance can name.
///
/// A file whose identity cannot be established, or whose advertised digest does not
/// decode, is **excluded and logged** (SPEC §7). It is never guessed at and never
/// approximated to a near match: a misattributed file would be judged as some other
/// version and could escape a version-specific block (TM-2).
/// [`parse_files`] on the *stored* document, counted as a stored parse.
///
/// Stored rather than upstream: a refresh must always parse what upstream just sent,
/// but SPEC §10 says a warm request parses nothing, and `MemoryCaches::stored_parses`
/// is what a test asserts that on.
fn parse_stored(
    app: &App,
    name: &ProjectName,
    payload: &[u8],
) -> Result<Vec<ProjectFile>, ApiError> {
    app.store().caches().note_stored_parse();
    parse_files(app, name, payload)
}

fn parse_files(
    app: &App,
    name: &ProjectName,
    payload: &[u8],
) -> Result<Vec<ProjectFile>, ApiError> {
    let document: Value = serde_json::from_slice(payload).map_err(|err| {
        tracing::warn!(project = %name, error = %err, "the Simple API document is unusable");
        ApiError::UpstreamInvalid
    })?;
    let Some(raw_files) = document.get("files").and_then(Value::as_array) else {
        tracing::warn!(project = %name, "the Simple API document carries no `files` array");
        return Err(ApiError::UpstreamInvalid);
    };

    // TM-1: one pathological document would otherwise be committed in a single
    // transaction that delays every other store operation, including an urgent
    // blocklist commit.
    let limit = app.config.max_references_per_project.get();
    if raw_files.len() > limit as usize {
        tracing::error!(
            project = %name,
            references = raw_files.len(),
            limit = limit,
            "refusing a project whose file count exceeds max_references_per_project"
        );
        return Err(ApiError::UpstreamInvalid);
    }

    let mut files = Vec::with_capacity(raw_files.len());
    for raw in raw_files {
        match project_file(name, raw) {
            Ok(file) => files.push(file),
            Err(reason) => {
                let filename = raw
                    .get("filename")
                    .and_then(|value| value.as_str())
                    .unwrap_or("<absent>");
                tracing::warn!(
                    project = %name,
                    %filename,
                    %reason,
                    "excluding a file whose identity cannot be established"
                );
            }
        }
    }
    Ok(files)
}

fn project_file(name: &ProjectName, raw: &Value) -> Result<ProjectFile, UnusableFile> {
    let filename = raw
        .get("filename")
        .and_then(Value::as_str)
        .ok_or(UnusableFile::NoFilename)?;
    let url = raw
        .get("url")
        .and_then(Value::as_str)
        .ok_or(UnusableFile::NoUrl)?;
    let upstream_url = Url::parse(url).map_err(|_| UnusableFile::UrlNotAUrl)?;

    let identity = file_identity(filename, name.as_str()).map_err(UnusableFile::Identity)?;

    let mut hashes = BTreeMap::new();
    let mut expected = Vec::new();
    if let Some(object) = raw.get("hashes").and_then(Value::as_object) {
        for (algorithm, digest) in object {
            let digest = digest.as_str().ok_or(UnusableFile::MalformedHash)?;
            hashes.insert(algorithm.clone(), digest.to_owned());
            // An algorithm SPEC §8 cannot block on is still advertised to the client
            // — it just cannot produce a `Digest`, so there is nothing to compare.
            if let Some((_, known)) = BLOCKABLE_HASHES
                .iter()
                .find(|(named, _)| named.eq_ignore_ascii_case(algorithm))
            {
                expected.push(
                    Digest::parse_hex(*known, digest).map_err(|_| UnusableFile::MalformedHash)?,
                );
            }
        }
    }

    let reference = ArtifactReference {
        ecosystem: Ecosystem::PyPi,
        name: name.as_str().to_owned(),
        version: identity.version.clone(),
        filename: filename.to_owned(),
        upstream_url,
        expected,
    };

    Ok(ProjectFile {
        id: ReferenceId::compute(&reference),
        reference,
        identity,
        // PEP 700's per-file `upload-time`. Each file is judged on its own, so a
        // wheel added to an old release never inherits that release's age.
        publication: match raw.get("upload-time") {
            None | Some(Value::Null) => PublicationTime::Unknown,
            Some(Value::String(text)) => match text.parse::<jiff::Timestamp>() {
                Ok(timestamp) => PublicationTime::Upstream(timestamp.as_microsecond()),
                Err(_) => PublicationTime::Malformed,
            },
            Some(_) => PublicationTime::Malformed,
        },
        hashes,
        requires_python: raw
            .get("requires-python")
            .and_then(Value::as_str)
            .map(str::to_owned),
        yanked: match raw.get("yanked") {
            Some(Value::Bool(true)) => Some(String::new()),
            Some(Value::String(reason)) => Some(reason.clone()),
            _ => None,
        },
        size: raw.get("size").and_then(Value::as_u64),
    })
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum UnusableFile {
    NoFilename,
    NoUrl,
    UrlNotAUrl,
    MalformedHash,
    Identity(UnsupportedFilename),
}

impl std::fmt::Display for UnusableFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnusableFile::NoFilename => f.write_str("the entry carries no `filename`"),
            UnusableFile::NoUrl => f.write_str("the entry carries no `url`"),
            UnusableFile::UrlNotAUrl => f.write_str("`url` is not a URL"),
            UnusableFile::MalformedHash => f.write_str("an advertised hash does not decode"),
            UnusableFile::Identity(reason) => write!(f, "{reason}"),
        }
    }
}

fn storage_error(err: StoreError) -> ApiError {
    tracing::warn!(error = %err, "a storage command failed; refusing the request");
    match err {
        StoreError::Busy => ApiError::Overloaded,
        StoreError::Closed | StoreError::Database(_) | StoreError::Corrupt(_) => {
            ApiError::StorageUnusable
        }
    }
}
