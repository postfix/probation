//! npm metadata, end to end: fetch or reuse one project snapshot, judge every
//! version against one blocklist snapshot and one `now`, and render the result.
//!
//! Two properties hold across everything below, and both are structural rather than
//! remembered:
//!
//! * **one snapshot, one `now`.** Both are read once, at the top of [`serve`], and
//!   passed down. Nothing further in is able to read either again, so a decision
//!   cannot be made from two readings of the same thing (SPEC §5).
//! * **a warm request touches nothing.** A reusable rendered entry is answered from
//!   memory: no database command reaches a queue and no upstream call is made
//!   (SPEC §10). `StoreHandle::commands_issued` is what a test asserts that on.

pub mod document;
pub mod name;
pub mod render;
pub mod tags;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::App;
use crate::concurrency::Resolution;
use crate::http::error::ApiError;
use crate::http::logging;
use crate::npm::document::{PackageDocument, VersionEntry};
use crate::policy::{
    BlocklistSnapshot, Candidate, Decision, DenyReason, Ecosystem, PublicationTime,
};
use crate::store::cache::{
    AbsentMark, CachedProject, ProjectKey, RenderKey, RenderedResponse, Representation,
};
use crate::store::rows::{Generation, ProjectRefresh, ProjectRow, ReferenceId, ReferenceUpsert};
use crate::store::{self, StoreError};
use crate::upstream::{MetadataRequest, MetadataResponse, OriginKind, UpstreamError};

pub use name::{InvalidPackageName, PackageName};

/// What npm's registry answers a full-document request with.
const NPM_ACCEPT: &str = "application/json";

/// A serialised response and the type it is served as.
pub struct Rendered {
    pub body: Arc<[u8]>,
    pub content_type: &'static str,
}

/// `GET /npm/{package}` and `GET /npm/{package}/{version-or-tag}`, which differ only
/// in the representation they ask for.
pub async fn serve(
    app: &App,
    name: &PackageName,
    representation: Representation,
) -> Result<Rendered, ApiError> {
    let now = app.clock.now_utc_micros();
    let monotonic = app.clock.now_monotonic();

    // SPEC §9's ordering point, read exactly once for this request.
    let snapshot = app.blocklist().ok_or(ApiError::PolicyUnavailable)?;
    if !snapshot.is_valid_at(now) {
        return Err(ApiError::PolicyUnavailable);
    }

    let project = ProjectKey::new(Ecosystem::Npm, name.as_str());
    let render_key = RenderKey {
        project: project.clone(),
        representation: representation.clone(),
    };
    let caches = app.store().caches();

    // The warm path: two memory lookups and nothing else. `is_reusable` carries all
    // five conditions of SPEC §10, and the project generation it compares against
    // comes from the memory cache rather than from a query — a project whose record
    // has been evicted is not a warm request.
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
        // the one that defines "warm" for metadata (SPEC §10: no database query, no
        // upstream call, no repeated parse).
        logging::record_cache(logging::CacheStatus::Hit);
        return Ok(Rendered {
            body: Arc::clone(&rendered.body),
            content_type: rendered.content_type,
        });
    }
    logging::record_cache(logging::CacheStatus::Miss);

    let resolved = resolve(app, name, &snapshot, now, monotonic).await?;
    let (body, content_type) = render(app, &resolved, &representation, now)?;
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

/// One project, judged. Every field is derived from the same snapshot and the same
/// `now`; `decisions` is parallel to `entries`.
struct Resolved {
    document: PackageDocument,
    entries: Vec<VersionEntry>,
    decisions: Vec<Decision>,
    eligible: BTreeSet<String>,
    tags: serde_json::Map<String, Value>,
    generation: Generation,
    digest_generation: u64,
    deadline_utc_micros: i64,
    deadline_monotonic: Instant,
}

/// The project snapshot a decision must be made from: the cached one while it is
/// within its metadata TTL, a refreshed one when it is not (SPEC §10).
///
/// Separate from [`resolve`] because the artifact path needs exactly this and nothing
/// else — SPEC §9's "ensure current project metadata, refreshing if its TTL expired".
async fn current_project(
    app: &App,
    name: &PackageName,
    now: i64,
    monotonic: Instant,
) -> Result<Arc<CachedProject>, ApiError> {
    let key = ProjectKey::new(Ecosystem::Npm, name.as_str());
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
        // SPEC §10: "After metadata TTL, revalidate upstream before responding. […]
        // Do not serve expired metadata during an upstream outage in the MVP."
        //
        // The expired snapshot travels with the refresh rather than being dropped
        // here: its validators are what make that revalidation conditional — unless
        // it is over-age, in which case the refresh sends none at all.
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
/// Returns the references that snapshot advertises, so the caller can answer that
/// question for the one it holds.
///
/// The set is parsed once per project snapshot and kept with it
/// ([`CachedProject::advertised`]): a warm artifact request re-parses nothing, which
/// is what SPEC §12's warm-artifact target needs on a project carrying thousands of
/// versions.
pub async fn ensure_fresh_project(
    app: &App,
    name: &str,
) -> Result<Arc<HashSet<ReferenceId>>, ApiError> {
    // The stored name is a name this instance already accepted from upstream; it is
    // re-validated here rather than trusted, and a name that no longer parses is a
    // reference nothing can be served for.
    let name = PackageName::parse_route(name).map_err(|err| {
        tracing::warn!(error = %err, "a stored reference names an unusable package");
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

    let document = parse_stored(app, &name, &cached.row.payload)?;
    let entries = document
        .entries(app.config.max_references_per_project.get())
        .map_err(|err| reference_cap_error(&name, err))?;
    let advertised: Arc<HashSet<ReferenceId>> =
        Arc::new(entries.iter().map(|entry| entry.id).collect());
    // Through the `Arc` the cache handed out, so the next request for this same
    // snapshot finds it. A racing filler sets the same value from the same bytes.
    let _ = cached.advertised.set(Arc::clone(&advertised));
    Ok(advertised)
}

/// The stored project document, parsed, and counted as a stored parse.
///
/// Stored rather than upstream: a refresh must always parse what upstream just sent,
/// but SPEC §10 says a warm request parses nothing, and `MemoryCaches::stored_parses`
/// is what a test asserts that on.
fn parse_stored(
    app: &App,
    name: &PackageName,
    payload: &[u8],
) -> Result<PackageDocument, ApiError> {
    app.store().caches().note_stored_parse();
    PackageDocument::parse(payload).map_err(|err| {
        tracing::error!(package = %name, error = %err, "the stored project payload is unusable");
        ApiError::UpstreamInvalid
    })
}

async fn resolve(
    app: &App,
    name: &PackageName,
    snapshot: &BlocklistSnapshot,
    now: i64,
    monotonic: Instant,
) -> Result<Resolved, ApiError> {
    let cached = current_project(app, name, now, monotonic).await?;
    let ttl_micros =
        i64::try_from(Duration::from_secs(app.config.metadata_ttl_seconds).as_micros())
            .unwrap_or(i64::MAX);

    let document = parse_stored(app, name, &cached.row.payload)?;
    let entries = document
        .entries(app.config.max_references_per_project.get())
        .map_err(|err| reference_cap_error(name, err))?;

    let mut decisions = Vec::with_capacity(entries.len());
    let mut eligible = BTreeSet::new();
    let mut next_release: Option<i64> = None;

    for entry in &entries {
        let candidate = Candidate {
            ecosystem: Ecosystem::Npm,
            name: name.as_str(),
            version: entry.version(),
            publication: publication_of(entry, &cached.first_seen),
            advertised_digests: &entry.reference.expected,
            // SPEC §9: a block on a digest this instance computed itself denies the
            // version here as well as at the artifact endpoint, so the next
            // resolution hides it. Unconditionally: the pin drops this project's
            // cache entry, and `current_project`'s guarded insert is what stops a
            // reader putting an older snapshot back — see `artifacts::download::fetch`.
            pinned_digests: cached.pins_of(&entry.id),
        };
        let decision = crate::osv::evaluate(
            &app.osv,
            Some(snapshot),
            now,
            app.config.cooldown_seconds,
            &candidate,
        )
        .await;

        match decision {
            Decision::Allow => {
                eligible.insert(entry.version().to_owned());
            }
            Decision::Hold { eligible_at_micros } => {
                next_release = Some(
                    next_release
                        .map_or(eligible_at_micros, |held: i64| held.min(eligible_at_micros)),
                );
            }
            Decision::Deny(_) | Decision::Unavailable => {}
        }
        decisions.push(decision);
    }

    let tags = tags::resolve(&document.dist_tags, &eligible);

    // SPEC §10: the earliest of upstream metadata TTL, blocklist expiry, and the next
    // held version's eligibility time. A released version therefore appears without
    // waiting for a background scheduler.
    //
    // SPEC rev 3 §10 adds a fourth: this snapshot's maximum-age ceiling. Repeated
    // `304`s push the TTL deadline past it, and a projection outliving the ceiling
    // would serve an over-age snapshot from memory without ever reaching
    // [`current_project`] — which is the one thing "never served" forbids.
    let ceiling = store::effective_max_age_micros(
        &ProjectKey::new(Ecosystem::Npm, name.as_str()),
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
        document,
        entries,
        decisions,
        eligible,
        tags,
        deadline_utc_micros,
        deadline_monotonic,
    })
}

/// SPEC §5: upstream's own timestamp wins; otherwise the committed first-seen time
/// for that exact reference; otherwise `Unknown`, which never becomes eligible.
fn publication_of(entry: &VersionEntry, first_seen: &HashMap<ReferenceId, i64>) -> PublicationTime {
    match entry.publication {
        PublicationTime::Upstream(micros) => PublicationTime::Upstream(micros),
        PublicationTime::Malformed => PublicationTime::Malformed,
        PublicationTime::FirstSeen(_) | PublicationTime::Unknown => first_seen
            .get(&entry.id)
            .map_or(PublicationTime::Unknown, |micros| {
                PublicationTime::FirstSeen(*micros)
            }),
    }
}

async fn load_project(app: &App, name: &PackageName) -> Result<Option<CachedProject>, ApiError> {
    let row = app
        .store()
        .get_project(Ecosystem::Npm, name.as_str())
        .await
        .map_err(storage_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let first_seen = app
        .store()
        .list_project_first_seen(Ecosystem::Npm, name.as_str())
        .await
        .map_err(storage_error)?;
    let pins = app
        .store()
        .list_project_pins(Ecosystem::Npm, name.as_str())
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
/// The first request to find this project stale runs the refresh; every request that
/// arrives while it is in flight is answered from its result rather than making a
/// second upstream call. The latch is [`crate::concurrency::SingleFlight`] — the same
/// one an artifact transfer is shared on — and the [`Resolution`] guard is what makes a
/// refresh that panics fail its waiters instead of leaving them on a channel that can
/// never close, which would wedge this project for the life of the process.
///
/// # The leading request runs the refresh inline, and what that costs
///
/// `artifacts::download::fetch` spawns its transfer into a **task of its own**, so a
/// requester that disappears takes only itself. This does not: the refresh runs in the
/// leading request's own future, because spawning needs an `Arc<App>` and no metadata
/// entry point has one — `serve` and [`ensure_fresh_project`] are handed `&App`.
///
/// So when the leader's request is dropped mid-refresh — a client disconnect, a
/// response deadline — the refresh is abandoned where it stands, and every request
/// that joined it is answered with [`ApiError::InternalFailure`], a `503`. That is
/// worse than not coalescing at all for those joiners: alone, each would have run its
/// own refresh and most likely succeeded. It is bounded and self-healing rather than a
/// wedge — `Resolution` answers every joiner instead of leaving it on a channel that
/// can never close, retires the slot, and the next request refreshes normally — but it
/// is a real cost and it is accepted here rather than hidden.
/// `tests/slice11_adversarial_singleflight.rs` witnesses it on both ecosystems.
///
/// The upgrade path is to spawn the refresh the way `fetch` does, which means threading
/// `Arc<App>` through the npm and PyPI entry points and their call sites in
/// `src/http/npm_routes.rs` and `src/http/pypi_routes.rs`. That is a wider change than
/// this slice owns.
///
/// `stale` is the expired snapshot this request found, when there was one. Only the
/// leader's is used — a joiner is answered from the leader's result, which is the
/// point of the latch.
async fn refresh_coalesced(
    app: &App,
    name: &PackageName,
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

/// Revalidate or fetch, parse, and commit. The commit is the ordering point SPEC §5
/// requires: a first-seen time is written before it is used to make anything eligible,
/// so a storage failure refuses the request rather than quietly granting an age.
///
/// A `304` and a `200` differ in one thing only — where the document comes from. Both
/// then run the same parse, the same reference upserts and the same commit, which is
/// what SPEC §10's second clause asks for: the caller re-judges *this* document against
/// the blocklist in force now, so a version blocked since the last full fetch is
/// excluded rather than carried along on a representation nobody rebuilt.
async fn refresh(
    app: &App,
    name: &PackageName,
    key: &ProjectKey,
    now: i64,
    monotonic: Instant,
    over_age: bool,
    stale: Option<Arc<CachedProject>>,
) -> Result<Arc<CachedProject>, ApiError> {
    // Built by cloning the origin and pushing one segment, never joined or
    // formatted; `url_for` re-admits the finished URL before handing it back.
    let url = app
        .origins
        .url_for(OriginKind::NpmMetadata, &[name.upstream_segment()])
        .map_err(|rejection| {
            tracing::warn!(package = %name, %rejection, "refused to build an upstream URL");
            ApiError::NotFound
        })?;

    let fetched = app
        .transport
        .fetch_metadata(MetadataRequest {
            url,
            accept: NPM_ACCEPT,
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
                tracing::warn!(package = %name, "upstream answered 304 to an unconditional request");
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
            tracing::warn!(package = %name, "the upstream registry did not answer in time");
            return Err(ApiError::UpstreamTimeout);
        }
        Err(err) => {
            tracing::warn!(package = %name, error = %err, "the upstream fetch failed");
            return Err(ApiError::UpstreamFailure);
        }
    };

    let document = PackageDocument::parse(&payload).map_err(|err| {
        tracing::warn!(package = %name, error = %err, "the upstream document is unusable");
        ApiError::UpstreamInvalid
    })?;
    let entries = document
        .entries(app.config.max_references_per_project.get())
        .map_err(|err| reference_cap_error(name, err))?;

    let references = entries
        .iter()
        .map(|entry| ReferenceUpsert {
            id: entry.id,
            reference: entry.reference.clone(),
            publication_micros: match entry.publication {
                PublicationTime::Upstream(micros) => Some(micros),
                _ => None,
            },
            // Only for a reference with no upstream time: this is the value SPEC §5
            // says must be persisted before it grants eligibility.
            first_seen_micros: matches!(entry.publication, PublicationTime::Unknown).then_some(now),
        })
        .collect();

    // A refresh does not change a pin — `commit_project_refresh` carries them
    // forward — but it does replace the cached project, so they are read back with it.
    let pins = app
        .store()
        .list_project_pins(Ecosystem::Npm, name.as_str())
        .await
        .map_err(storage_error)?;

    let committed = app
        .store()
        .commit_project_refresh(ProjectRefresh {
            ecosystem: Ecosystem::Npm,
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
            ecosystem: Ecosystem::Npm,
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
    resolved: &Resolved,
    representation: &Representation,
    now: i64,
) -> Result<(Vec<u8>, &'static str), ApiError> {
    let public_url = &app.config.public_url;

    if let Representation::NpmVersion(spelling) = representation {
        return single_version(resolved, spelling, public_url, now);
    }

    // SPEC §6: "If some candidates remain, return the filtered document. If the
    // project exists but none remain, return a policy denial."
    if resolved.eligible.is_empty() {
        return Err(denial(resolved, now));
    }

    let kept: Vec<&VersionEntry> = resolved
        .entries
        .iter()
        .filter(|entry| resolved.eligible.contains(entry.version()))
        .collect();

    Ok(match representation {
        Representation::NpmAbbreviated => (
            render::abbreviated(&resolved.document, &kept, &resolved.tags, public_url),
            render::ABBREVIATED_CONTENT_TYPE,
        ),
        _ => (
            render::full(&resolved.document, &kept, &resolved.tags, public_url),
            render::FULL_CONTENT_TYPE,
        ),
    })
}

/// `GET /npm/{package}/{version-or-tag}`: the same checks, then one version.
fn single_version(
    resolved: &Resolved,
    spelling: &str,
    public_url: &url::Url,
    now: i64,
) -> Result<(Vec<u8>, &'static str), ApiError> {
    let target = if resolved.document.dist_tags.contains_key(spelling) {
        // A tag upstream really has. It is resolved through the *filtered* tags, so
        // `latest` gives its fallback and a tag the rules dropped is simply gone.
        match resolved.tags.get(spelling).and_then(Value::as_str) {
            Some(target) => target.to_owned(),
            None => return Err(ApiError::NotFound),
        }
    } else {
        spelling.to_owned()
    };

    let Some(index) = resolved
        .entries
        .iter()
        .position(|entry| entry.version() == target)
    else {
        return Err(ApiError::NotFound);
    };

    match resolved.decisions[index] {
        Decision::Allow => Ok((
            render::single_version(&resolved.entries[index], public_url),
            render::FULL_CONTENT_TYPE,
        )),
        Decision::Hold { eligible_at_micros } => Err(ApiError::held(eligible_at_micros, now)),
        Decision::Deny(reason) => Err(ApiError::Blocked {
            reason: deny_reason(reason),
        }),
        Decision::Unavailable => Err(ApiError::PolicyUnavailable),
    }
}

/// The denial for a project whose every version was excluded. A project held only by
/// age says when it will be back; one with anything blocked in it does not, because
/// a block has no deadline.
fn denial(resolved: &Resolved, now: i64) -> ApiError {
    // A block is reported ahead of a hold: it is the more specific answer, and it is
    // the one a client must not read as "try again later".
    for decision in &resolved.decisions {
        if let Decision::Deny(reason) = decision {
            return ApiError::Blocked {
                reason: deny_reason(*reason),
            };
        }
    }

    let earliest = resolved
        .decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::Hold { eligible_at_micros } => Some(*eligible_at_micros),
            _ => None,
        })
        .min();

    match earliest {
        Some(eligible_at_micros) => ApiError::held(eligible_at_micros, now),
        // Nothing here could even be identified, so there is nothing to serve and
        // nothing to wait for.
        None => ApiError::NotFound,
    }
}

const fn deny_reason(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::BlockedPackage => "the package is blocked",
        DenyReason::BlockedVersion => "the version is blocked",
        DenyReason::BlockedDigest => "the artifact digest is blocked",
        DenyReason::MalformedTimestamp => "the upstream publication time is malformed",
        DenyReason::FutureTimestamp => "the upstream publication time is in the future",
        DenyReason::NoTimestamp => "no publication time has been established",
        DenyReason::BlockedByOsv => {
            "the version is blocked by a known OSV malicious-package advisory"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exhaustive match compiles, and the new arm renders a real, non-empty
    /// reason string rather than the placeholder every other arm already has.
    /// Mirrors `artifacts::tests::deny_reason_maps_blocked_by_osv_in_artifacts_mod`;
    /// tests only this one-line match arm, not Slice 2's `osv::evaluate` wiring.
    #[test]
    fn deny_reason_maps_blocked_by_osv_in_npm_mod() {
        assert_eq!(
            deny_reason(DenyReason::BlockedByOsv),
            "the version is blocked by a known OSV malicious-package advisory"
        );
    }
}

/// TM-1: an outlier is rejected and logged with its name and reference count, rather
/// than held in one transaction that would delay every other store operation —
/// including an urgent blocklist commit.
fn reference_cap_error(name: &PackageName, err: document::DocumentError) -> ApiError {
    if let document::DocumentError::TooManyReferences { count, limit } = &err {
        tracing::error!(
            package = %name,
            references = count,
            limit = limit,
            "refusing a project whose reference count exceeds max_references_per_project"
        );
    }
    ApiError::UpstreamInvalid
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
