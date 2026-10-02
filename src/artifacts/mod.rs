//! Verified artifact delivery: SPEC §9's `serve(reference)`, in its order.
//!
//! ```text
//! reject expired policy or a locally known package/digest block
//! ensure current project metadata, refreshing if its TTL expired
//! require reference still belongs to that project snapshot
//! evaluate current policy using advertised and previously computed digests
//! if verified content is cached: open and pin the immutable file
//! else: download, hash, verify, pin, publish
//! revalidate project membership if metadata expired while downloading
//! perform the final policy check immediately before response creation
//! stream the already verified local file to the client
//! ```
//!
//! Three orderings in here are the point of the whole module.
//!
//! **PERF-01.** The blocklist snapshot is loaded and a locally conclusive denial is
//! answered *first*, before anything that could touch the network. A known-malware
//! block does not wait for upstream, which is what
//! `artifacts_verification::local_block_denies_with_upstream_unreachable` asserts by
//! making every upstream call fail.
//!
//! **Membership.** A reference is servable only while a sufficiently fresh upstream
//! snapshot still advertises it. Upstream removal is a different signal from this
//! firewall's blocklist — a version can be unpublished for being malicious without any
//! blocklist ever naming it — and cached bytes do not make a withdrawn release
//! available.
//!
//! **The revocation boundary.** The snapshot is loaded again immediately before the
//! response is created, and that second load is the ordering point SPEC §9 names: a
//! request loading it after a publication must see the publication. The result of
//! that check is the only way to obtain an [`stream::Authorized`], and an
//! [`stream::ArtifactResponse`] with a body cannot be built without one — so a path
//! that skipped it does not compile rather than failing a review.

pub mod content;
pub mod download;
pub mod reference;
pub mod stream;

use std::sync::Arc;

use axum::http::Method;

use crate::App;
use crate::artifacts::content::PinnedFile;
use crate::artifacts::stream::{ArtifactResponse, Authorized, RangeRequest};
use crate::http::error::ApiError;
use crate::http::logging;
use crate::policy::{BlocklistSnapshot, Candidate, Decision, DenyReason, Digest, Ecosystem};
use crate::store::StoreError;
use crate::store::rows::{ReferenceId, ReferenceRow};
use crate::{npm, osv, pypi};

pub use download::{DownloadError, VerifiedContent};
pub use reference::{ArtifactReference, InvalidReferenceId};

/// `GET|HEAD /{ecosystem}/artifacts/{reference_id}/{filename}`.
///
/// `ecosystem` is the root the request arrived under, which the route decided rather
/// than the client.
pub async fn serve_artifact(
    app: &Arc<App>,
    ecosystem: Ecosystem,
    id: ReferenceId,
    filename: &str,
    method: &Method,
    range_header: Option<&str>,
) -> Result<ArtifactResponse, ApiError> {
    // The ordering point, read before anything else about this request. PERF-01: a
    // locally conclusive answer is reached without a single upstream call.
    let snapshot = app.blocklist().ok_or(ApiError::PolicyUnavailable)?;
    let now = app.clock.now_utc_micros();
    if !snapshot.is_valid_at(now) {
        return Err(ApiError::PolicyUnavailable);
    }

    let row = load_reference(app, id).await?;
    // What this request is *about* is now known, and it is the row that says so. The
    // decision line takes its ecosystem from here rather than from the path, so a
    // request refused below is still logged under the ecosystem whose policy owns it.
    logging::record_ecosystem(row.reference.ecosystem);
    // The ecosystem is part of what the reference *is*, exactly as the filename is. A
    // reference id is a deterministic hash over public metadata and explicitly not an
    // authorization token (SPEC §9), so anyone can carry a valid npm id to the PyPI
    // root; serving it there would log the wrong ecosystem for a decision the other
    // ecosystem's policy made. Refusing here is one comparison, and it runs before
    // anything else this request could be measured by.
    if row.reference.ecosystem != ecosystem {
        return Err(ApiError::NotFound);
    }
    // The filename is part of what the reference *is*; a URL that names another one
    // is not this reference (SPEC §9: "The server looks up the record; it never
    // constructs an upstream URL from an arbitrary client URL parameter").
    if row.reference.filename != filename {
        return Err(ApiError::NotFound);
    }

    let pinned = row.pinned_digests();
    match evaluate(app, &snapshot, now, &row, &pinned).await {
        Decision::Allow => {}
        other => return Err(decision_error(other, now)),
    }

    // Only now, with every locally conclusive answer already given (PERF-01), does
    // this request touch upstream metadata.
    ensure_membership(app, &row).await?;
    match evaluate(app, &snapshot, now, &row, &pinned).await {
        Decision::Allow => {}
        other => return Err(decision_error(other, now)),
    }

    let (file, pinned, downloaded) = open_or_download(app, &row, pinned).await?;
    // SPEC §11 asks the decision line to carry a cache status. For an artifact that is
    // exactly this: were the bytes already verified on disk, or did this request pay
    // for the transfer?
    logging::record_cache(if downloaded {
        logging::CacheStatus::Miss
    } else {
        logging::CacheStatus::Hit
    });
    let total_length = file.size();

    // SPEC §9: "revalidate project membership if metadata expired while downloading".
    // A transfer can take fifteen minutes, so a snapshot that was fresh when it
    // started need not be when it ends. This re-checks after any transfer rather than
    // working out whether the TTL lapsed mid-flight: it is one comparison stricter,
    // and a great deal simpler to be sure of.
    if downloaded {
        ensure_membership(app, &row).await?;
    }

    // The final check. SPEC §9: "A request is authorized by its final successful
    // policy check immediately before response creation."
    let snapshot = app.blocklist().ok_or(ApiError::PolicyUnavailable)?;
    let now = app.clock.now_utc_micros();
    let decision = evaluate(app, &snapshot, now, &row, &pinned).await;
    let Some(auth) = Authorized::from_decision(decision, Some(snapshot.revision)) else {
        // No witness, no body — and not because a caller remembered to check.
        return Err(decision_error(decision, now));
    };

    if method == Method::HEAD {
        // SPEC §9: HEAD runs every check, including a cold verification, and returns
        // no body.
        return Ok(ArtifactResponse::head_only(auth, total_length));
    }

    Ok(match stream::parse_range(range_header, total_length) {
        RangeRequest::Whole => ArtifactResponse::with_body(auth, file, None, total_length),
        RangeRequest::One(range) => {
            ArtifactResponse::with_body(auth, file, Some(range), total_length)
        }
        RangeRequest::Unsatisfiable => ArtifactResponse::range_not_satisfiable(auth, total_length),
    })
}

/// SPEC §9: "Every artifact request must confirm that the reference is still
/// advertised by a sufficiently fresh upstream project snapshot […] A removed
/// reference is unavailable even if its bytes remain cached."
///
/// The reference id is a deterministic hash of public metadata and SPEC §9 is
/// explicit that it is "not an authorization token", so this is what stops a URL
/// anyone could compute from outliving the release it names.
///
/// Every artifact request reaches this, warm ones included, so the set it asks for is
/// parsed once per project snapshot and kept with it rather than recomputed per call
/// (SPEC §12's warm-artifact target).
async fn ensure_membership(app: &App, row: &ReferenceRow) -> Result<(), ApiError> {
    let advertised = match row.reference.ecosystem {
        Ecosystem::Npm => npm::ensure_fresh_project(app, &row.reference.name).await?,
        Ecosystem::PyPi => pypi::ensure_fresh_project(app, &row.reference.name).await?,
    };

    if advertised.contains(&row.id) {
        return Ok(());
    }

    tracing::info!(
        reference = %row.id.to_hex(),
        ecosystem = row.reference.ecosystem.as_tag(),
        package = %row.reference.name,
        version = %row.reference.version,
        "refusing a reference the current upstream snapshot no longer advertises"
    );
    // The bytes may still be cached and perfectly valid. They are not available.
    Err(ApiError::NotFound)
}

/// One `now`, one snapshot, and both kinds of digest knowledge: what upstream
/// advertised and what we computed ourselves (SPEC §9). Routes through
/// `osv::evaluate` (D2) rather than calling `policy::evaluate` directly, so OSV is
/// resolved for a candidate this checkpoint would otherwise allow.
async fn evaluate(
    app: &App,
    snapshot: &BlocklistSnapshot,
    now: i64,
    row: &ReferenceRow,
    pinned: &[Digest],
) -> Decision {
    osv::evaluate(
        &app.osv,
        Some(snapshot),
        now,
        app.config.cooldown_seconds,
        &Candidate {
            ecosystem: row.reference.ecosystem,
            name: &row.reference.name,
            version: &row.reference.version,
            publication: row.publication_time(),
            advertised_digests: &row.reference.expected,
            pinned_digests: pinned,
        },
    )
    .await
}

/// The reference record, from memory where possible. SPEC §9: the record is
/// persisted before its URL is advertised, so a reference this instance has never
/// committed is a `404` rather than something to go and find out about.
async fn load_reference(app: &App, id: ReferenceId) -> Result<ReferenceRow, ApiError> {
    let caches = app.store().caches();
    if let Some(row) = caches.references.get(&id) {
        return Ok((*row).clone());
    }

    let row = app
        .store()
        .get_reference(id)
        .await
        .map_err(|err| storage_error(&err))?
        .ok_or(ApiError::NotFound)?;
    caches
        .references
        .insert(id, Arc::new(row.clone()), approximate_bytes(&row));
    Ok(row)
}

fn approximate_bytes(row: &ReferenceRow) -> u64 {
    (row.reference.name.len()
        + row.reference.version.len()
        + row.reference.filename.len()
        + row.reference.upstream_url.as_str().len()) as u64
        + 512
}

/// The cached branch and the cold branch, with the same answer: an open file of
/// verified bytes, and the digests this instance has pinned for them.
async fn open_or_download(
    app: &Arc<App>,
    row: &ReferenceRow,
    pinned: Vec<Digest>,
) -> Result<(PinnedFile, Vec<Digest>, bool), ApiError> {
    if let (Some(key), Some(size)) = (row.content_key, row.pinned_size) {
        match app.content.open_verified(&key, size).await {
            Ok(file) => return Ok((file, pinned, false)),
            // SPEC §9: "Detect missing files and size mismatches and discard their
            // cache mappings." The pins are not discarded with them.
            Err(err) => {
                tracing::warn!(
                    reference = %row.id.to_hex(),
                    content = %key,
                    error = %err,
                    "the cached file is unusable; dropping the mapping and refetching"
                );
                if let Err(err) = app.store().clear_content_key(key).await {
                    tracing::warn!(error = %err, "the stale content mapping could not be cleared");
                }
                app.store().caches().references.remove(&row.id);
            }
        }
    }

    let verified = download::fetch(app, row)
        .await
        .map_err(|err| download_error(&err, app.clock.now_utc_micros()))?;
    // The row in hand predates the pins this download just established.
    app.store().caches().references.remove(&row.id);

    let file = app
        .content
        .open_verified(&verified.key, verified.size)
        .await
        .map_err(|err| {
            tracing::error!(
                reference = %row.id.to_hex(),
                error = %err,
                "the artifact was published and then could not be opened"
            );
            ApiError::CapacityExhausted
        })?;

    let mut pinned = pinned;
    if pinned.is_empty() {
        pinned = vec![
            Digest {
                algorithm: crate::policy::HashAlgorithm::Sha256,
                bytes: Box::from(verified.sha256.as_slice()),
            },
            Digest {
                algorithm: crate::policy::HashAlgorithm::Sha512,
                bytes: Box::from(verified.sha512.as_slice()),
            },
        ];
    }
    Ok((file, pinned, true))
}

fn decision_error(decision: Decision, now: i64) -> ApiError {
    match decision {
        // Not reachable: a caller only asks for the error of a non-`Allow` decision.
        // Refusing is still the right answer if one ever does.
        Decision::Allow => ApiError::Blocked {
            reason: "the artifact is not authorized",
        },
        Decision::Hold { eligible_at_micros } => ApiError::held(eligible_at_micros, now),
        Decision::Deny(reason) => ApiError::Blocked {
            reason: deny_reason(reason),
        },
        Decision::Unavailable => ApiError::PolicyUnavailable,
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
            "the artifact is blocked by a known OSV malicious-package advisory"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exhaustive match compiles, and the new arm renders a real, non-empty
    /// reason string rather than the placeholder every other arm already has.
    #[test]
    fn deny_reason_maps_blocked_by_osv_in_artifacts_mod() {
        assert_eq!(
            deny_reason(DenyReason::BlockedByOsv),
            "the artifact is blocked by a known OSV malicious-package advisory"
        );
    }
}

/// SPEC §11's rows, from the failure that produced them.
/// Taken by reference because one transfer's error is shared by every waiter on it
/// (SPEC §9: "returned consistently to waiters"), and `DownloadError` carries an
/// `io::Error` and a `turso::Error`, neither of which clones.
fn download_error(err: &DownloadError, now: i64) -> ApiError {
    match err {
        DownloadError::Refused(decision) => {
            tracing::info!(error = %err, "policy refused verified artifact bytes");
            return decision_error(*decision, now);
        }
        DownloadError::Capacity(_) => {
            // SPEC §10: "never relax policy to free space".
            tracing::error!(error = %err, "local storage could not take the artifact");
            return ApiError::CapacityExhausted;
        }
        _ => tracing::warn!(error = %err, "an artifact download failed"),
    }

    match err {
        DownloadError::Upstream(crate::upstream::UpstreamError::Timeout) => {
            ApiError::UpstreamTimeout
        }
        DownloadError::Upstream(_) => ApiError::UpstreamFailure,
        DownloadError::IntegrityMismatch { .. }
        | DownloadError::PinConflict
        | DownloadError::SizeMismatch { .. } => ApiError::IntegrityMismatch,
        DownloadError::TooLarge { .. } => ApiError::UpstreamInvalid,
        DownloadError::Storage(err) => storage_error(err),
        // SPEC §10: no download permit was free, so the request is refused rather
        // than queued behind the transfers that hold them.
        DownloadError::Overloaded => ApiError::Overloaded,
        // Not reachable: a transfer is cancelled only when no waiter is left to be
        // told. Refusing is still the right answer if one ever is.
        DownloadError::Cancelled => ApiError::Overloaded,
        // The transfer task died. Slice 9 ruled on the provisional mapping it
        // inherited: SPEC §11 needs no internal-failure row, because `503` already is
        // the instance-local row and this is an instance-local failure — `502` would
        // blame upstream for a fault that is ours. What did change is the reason: this
        // is no longer reported as `OVERLOADED`, because nothing was at capacity.
        DownloadError::Aborted => ApiError::InternalFailure,
        // Both handled above.
        DownloadError::Capacity(_) => ApiError::CapacityExhausted,
        DownloadError::Refused(_) => ApiError::Blocked {
            reason: "the artifact is blocked",
        },
    }
}

fn storage_error(err: &StoreError) -> ApiError {
    tracing::warn!(error = %err, "a storage command failed; refusing the request");
    match err {
        StoreError::Busy => ApiError::Overloaded,
        StoreError::Closed | StoreError::Database(_) | StoreError::Corrupt(_) => {
            ApiError::StorageUnusable
        }
    }
}
