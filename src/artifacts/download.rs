//! The cold path: fetch one artifact, verify it completely, pin what it taught us,
//! and only then publish it.
//!
//! The whole of SPEC §9's verification block is here, in its order:
//!
//! ```text
//! stream upstream bytes to a temporary file
//! compute SHA-256 and SHA-512 in the same pass
//! verify upstream integrity and expected size when available
//! require digests equal previously pinned digests for this reference, if any
//! persist computed digests, even when policy now blocks them
//! reevaluate the latest policy
//! atomically publish allowed bytes in the content cache
//! ```
//!
//! Three properties are structural rather than remembered. The bytes never exist as
//! one buffer — they go to a [`TempDownload`] chunk by chunk, so a 5 GiB artifact
//! costs one chunk of memory. The three hashers are fed from that same chunk, so
//! SHA-256, SHA-512 and SHA-1 cost one pass over the body and not three. And the
//! running total is checked against the cap inside that pass, so an artifact that
//! exceeds it is abandoned on the chunk that crosses it rather than after the body
//! has finished arriving.
//!
//! Content decoding is off for this transfer — the artifact client sets
//! `no_gzip`/`no_brotli`/`no_zstd` (SPEC §9) — so the bytes hashed here are the bytes
//! upstream served.
//!
//! # One transfer per reference (FLOW-01)
//!
//! SPEC §9: "Concurrent requests for one reference share one fetch and verification
//! result. […] A disconnected waiter releases its request resources without
//! cancelling other waiters. If the last waiter leaves before artifact publication,
//! cancel the fetch and remove its temporary file and reservation. Once the durable
//! publication transaction starts, finish that bounded operation."
//!
//! [`DownloadCoordinator`] is where that lives, and two decisions carry it:
//!
//! * the transfer runs in a **task of its own**, never in a requesting task. A
//!   request that disappears drops its own future and nothing else, so "one waiter
//!   cancelling leaves the others running" is structural rather than remembered.
//! * everything else — the waiter accounting, the publish-or-cancel latch and the
//!   guard that answers the waiters on every way out — is
//!   [`crate::concurrency::SingleFlight`], which is also what coalesces metadata
//!   refreshes (SPEC §10). One latch, two callers.

use std::fmt;
use std::sync::Arc;

use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};

use crate::App;
use crate::artifacts::content::{ContentError, ContentKey};
use crate::concurrency::{Resolution, SingleFlight, Slot};
use crate::http::error::ApiError;
use crate::policy::{Candidate, Decision, Digest, Ecosystem, HashAlgorithm};
use crate::store::cache::{CachedProject, ProjectKey};
use crate::store::rows::{ReferenceId, ReferenceRow};
use crate::store::{PinOutcome, StoreError};
use crate::upstream::{ArtifactRequest, UpstreamError};

/// What a complete, verified download produced.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedContent {
    pub key: ContentKey,
    pub sha256: [u8; 32],
    pub sha512: [u8; 64],
    pub size: u64,
}

/// The digests of one complete body, all three from one pass.
#[derive(Clone, Copy, Debug)]
struct Computed {
    sha256: [u8; 32],
    sha512: [u8; 64],
    sha1: [u8; 20],
    size: u64,
}

impl Computed {
    fn digest(&self, algorithm: HashAlgorithm) -> Digest {
        let bytes: Box<[u8]> = match algorithm {
            HashAlgorithm::Sha256 => Box::from(self.sha256.as_slice()),
            HashAlgorithm::Sha512 => Box::from(self.sha512.as_slice()),
            HashAlgorithm::Sha1 => Box::from(self.sha1.as_slice()),
        };
        Digest { algorithm, bytes }
    }

    /// The two SPEC §9 pins, as `policy::evaluate` takes them.
    fn pinned_digests(&self) -> Vec<Digest> {
        vec![
            self.digest(HashAlgorithm::Sha256),
            self.digest(HashAlgorithm::Sha512),
        ]
    }
}

/// What one transfer produced, shared by every waiter on it. The error is behind an
/// `Arc` because `DownloadError` carries an `io::Error` and a `turso::Error`, neither
/// of which can be cloned per waiter.
#[derive(Clone)]
enum SlotOutcome {
    Verified(VerifiedContent),
    Failed(Arc<DownloadError>),
}

/// What one coalesced metadata refresh produced, shared by every request that joined
/// it. `ApiError` is `Copy`, so unlike a transfer's error it needs no `Arc`; the
/// project itself is behind one, so joining costs an `Arc` clone rather than a copy of
/// the whole document and its per-reference maps.
pub type RefreshOutcome = Result<Arc<CachedProject>, ApiError>;

/// The in-flight upstream work this instance coalesces: one artifact transfer per
/// reference (SPEC §9, FLOW-01) and one metadata refresh per project (SPEC §10).
///
/// Two tables, one primitive, and neither knows anything about the other. They live
/// behind one `App` field because that is the field `App` has for in-flight upstream
/// work; the mechanism itself is [`crate::concurrency::SingleFlight`], which is where
/// the races are decided.
#[derive(Default)]
pub struct DownloadCoordinator {
    transfers: SingleFlight<ReferenceId, SlotOutcome>,
    metadata: SingleFlight<ProjectKey, RefreshOutcome>,
}

impl DownloadCoordinator {
    pub fn new() -> DownloadCoordinator {
        DownloadCoordinator::default()
    }

    /// One transfer per reference.
    fn transfers(&self) -> &SingleFlight<ReferenceId, SlotOutcome> {
        &self.transfers
    }

    /// One metadata refresh per project. npm and PyPI share this one table:
    /// `ProjectKey` carries the ecosystem, so two projects of the same name in the two
    /// ecosystems are still two pieces of work.
    pub fn metadata(&self) -> &SingleFlight<ProjectKey, RefreshOutcome> {
        &self.metadata
    }

    /// How many requests are currently sharing this reference's transfer. Zero when
    /// none is in flight.
    pub fn waiting_on(&self, id: &ReferenceId) -> usize {
        self.transfers.waiting_on(id)
    }

    /// Whether this reference's transfer has passed the point after which it always
    /// completes.
    pub fn publishing(&self, id: &ReferenceId) -> bool {
        self.transfers.publishing(id)
    }
}

/// One cold artifact, start to finish, shared with every other request for the same
/// reference. Returns only when the bytes are verified, durable, and their mapping is
/// committed.
pub async fn fetch(
    app: &Arc<App>,
    row: &ReferenceRow,
) -> Result<VerifiedContent, Arc<DownloadError>> {
    let (slot, leader, _waiter) = app.downloads.transfers().join(row.id);

    if leader {
        // Its own task: this request's future may be dropped at any moment, and SPEC
        // §9 says that must not cancel the transfer the other waiters are on.
        let app = Arc::clone(app);
        let row = row.clone();
        let started = Arc::clone(&slot);
        tokio::spawn(async move { run(app, row, started).await });
    }

    match slot.wait().await {
        Some(SlotOutcome::Verified(content)) => Ok(content),
        Some(SlotOutcome::Failed(err)) => Err(err),
        // The task went away without recording an outcome and without its `Resolution`
        // running, which happens only if the runtime itself is going away.
        None => Err(Arc::new(DownloadError::Cancelled)),
    }
}

/// The transfer task: one complete attempt, then one outcome for every waiter.
///
/// The [`Resolution`] is what makes that "every way out" rather than "every way out
/// this code thought of" — see `concurrency::single_flight` for why it is a `Drop`
/// guard and not a `catch_unwind` around `transfer`.
async fn run(app: Arc<App>, row: ReferenceRow, slot: Arc<Slot<SlotOutcome>>) {
    let mut resolution = Resolution::new(
        app.downloads.transfers().clone(),
        row.id,
        Arc::clone(&slot),
        SlotOutcome::Failed(Arc::new(DownloadError::Aborted)),
        row.id.to_hex(),
    );

    let outcome = match transfer(&app, &row, &slot).await {
        Ok(content) => SlotOutcome::Verified(content),
        Err(err) => SlotOutcome::Failed(Arc::new(err)),
    };
    resolution.answer(outcome);
}

async fn transfer(
    app: &App,
    row: &ReferenceRow,
    slot: &Slot<SlotOutcome>,
) -> Result<VerifiedContent, DownloadError> {
    // SPEC §9: "Bound active downloads globally." One permit per transfer, not per
    // waiter — the waiters above are sharing this one. SPEC §10 refuses overload
    // rather than queueing behind it.
    let _permit = app
        .limits
        .download_permit()
        .ok_or(DownloadError::Overloaded)?;

    let cap = app.config.max_artifact_bytes.get();
    let body = app
        .transport
        .open_artifact(ArtifactRequest {
            url: row.reference.upstream_url.clone(),
            max_bytes: cap,
        })
        .await
        .map_err(DownloadError::Upstream)?;

    // A declared length over the cap is refused before a byte is transferred. The
    // counted loop below is what refuses one that never declares a length at all.
    if body.declared_length.is_some_and(|declared| declared > cap) {
        return Err(DownloadError::TooLarge { limit: cap });
    }

    // SPEC §10: an unknown-length download counts against `max_artifact_bytes` until
    // its final size is known, and a reservation that cannot be taken refuses the
    // cold request rather than freeing space by force.
    let mut temp = app
        .content
        .create_temp(cap)
        .await
        .map_err(DownloadError::Capacity)?;

    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut sha1 = Sha1::new();
    let mut size = 0u64;

    let mut stream = body.stream;
    loop {
        // The one place a cancellation is observed. A transfer whose last waiter has
        // gone stops here rather than after the body has finished arriving, and
        // dropping `temp` on the way out is what removes the temporary file and
        // releases its reservation (SPEC §9).
        let next = tokio::select! {
            biased;
            () = slot.cancelled() => return Err(DownloadError::Cancelled),
            next = futures_util::StreamExt::next(&mut stream) => next,
        };
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(DownloadError::Upstream)?;
        size = size.saturating_add(chunk.len() as u64);
        if size > cap {
            return Err(DownloadError::TooLarge { limit: cap });
        }
        sha256.update(&chunk);
        sha512.update(&chunk);
        sha1.update(&chunk);
        temp.write_all(&chunk)
            .await
            .map_err(DownloadError::Capacity)?;
    }

    let computed = Computed {
        sha256: sha256.finalize().into(),
        sha512: sha512.finalize().into(),
        sha1: sha1.finalize().into(),
        size,
    };

    // A body that stopped early is a truncated download, not a short artifact.
    if let Some(declared) = body.declared_length
        && declared != computed.size
    {
        return Err(DownloadError::SizeMismatch {
            declared,
            actual: computed.size,
        });
    }

    verify_advertised(&row.reference.expected, &computed)?;

    // STATE-01. This runs before the policy re-check on purpose: SPEC §9 says
    // "persist computed digests, even when policy now blocks them", so a block
    // discovered from our own digest is remembered rather than re-learned on every
    // later attempt.
    match app
        .store()
        .pin_computed_digests(row.id, computed.sha256, computed.sha512, computed.size)
        .await
        .map_err(DownloadError::Storage)?
    {
        PinOutcome::Established => {
            // The cached project snapshot predates this pin, and a listing rendered
            // from it would judge the version without a digest we now hold. Dropping
            // it is what makes SPEC §9's "the next resolution hides the affected
            // artifact" true for a block that arrives later, too.
            //
            // Unconditional, and this is the one place that is written down. The
            // commit above and this removal are two steps, so a `current_project` that
            // read the entry before the commit reaches its own insert after the
            // removal, holding a pins snapshot that predates this digest. It cannot
            // install it: `ShardedCache::remove` counts this invalidation, and that
            // reader took the count *before* it read, so its guarded insert is refused
            // and the next resolution loads the project afresh. Reuse is
            // generation-checked, the way `RenderedResponse::is_reusable` already is,
            // rather than bounded by `metadata_ttl_seconds`.
            app.store().caches().projects.remove(&ProjectKey::new(
                row.reference.ecosystem,
                row.reference.name.as_str(),
            ));
        }
        PinOutcome::MatchedExisting => {}
        PinOutcome::Conflict => {
            tracing::error!(
                reference = %row.id.to_hex(),
                package = %row.reference.name,
                version = %row.reference.version,
                computed = %computed.digest(HashAlgorithm::Sha256),
                "the same reference now serves different bytes; keeping the original pins \
                 and discarding these"
            );
            return Err(DownloadError::PinConflict);
        }
    }

    // The latest policy, against digests upstream may never have advertised.
    let now = app.clock.now_utc_micros();
    let snapshot = app.blocklist();
    let pinned = computed.pinned_digests();
    let decision = crate::osv::evaluate(
        &app.osv,
        snapshot.as_deref(),
        now,
        app.config.cooldown_seconds,
        &Candidate {
            ecosystem: row.reference.ecosystem,
            name: &row.reference.name,
            version: &row.reference.version,
            publication: row.publication_time(),
            advertised_digests: &row.reference.expected,
            pinned_digests: &pinned,
        },
    )
    .await;
    if decision != Decision::Allow {
        // SPEC §9: "If a computed digest reveals a block not visible in upstream
        // metadata, invalidate that project's filtered metadata."
        if matches!(decision, Decision::Deny(_)) {
            bump_digest_generation(app, row.reference.ecosystem, &row.reference.name).await;
        }
        // The temporary file goes with `temp`; the pins stay.
        return Err(DownloadError::Refused(decision));
    }

    // The latch. SPEC §9: "Once the durable publication transaction starts, finish
    // that bounded operation and leave a valid cache entry." Nothing below this line
    // consults the cancellation token, and a waiter leaving from here on cannot take
    // `CANCELLED` because this exchange has already taken `PUBLISHING`.
    if !slot.begin_publishing() {
        return Err(DownloadError::Cancelled);
    }

    let key = ContentKey::from_sha256(computed.sha256);
    let published = app
        .content
        .publish(temp, &key)
        .await
        .map_err(DownloadError::Capacity)?;
    tracing::debug!(
        reference = %row.id.to_hex(),
        content = %key,
        size = computed.size,
        reused = published.reused,
        steps = ?published.steps,
        "published verified artifact bytes"
    );

    // Only now, with the bytes durable on disk (REL-01).
    app.store()
        .publish_content(key, computed.sha512, computed.size, row.id, now)
        .await
        .map_err(DownloadError::Storage)?;

    Ok(VerifiedContent {
        key,
        sha256: computed.sha256,
        sha512: computed.sha512,
        size: computed.size,
    })
}

/// A failed bump is logged and not fatal: the artifact is refused either way, and
/// the worst consequence is a rendered response that stays current one generation
/// too long.
async fn bump_digest_generation(app: &App, ecosystem: Ecosystem, name: &str) {
    if let Err(err) = app.store().bump_digest_generation(ecosystem, name).await {
        tracing::warn!(
            package = %name,
            error = %err,
            "could not invalidate the project's rendered metadata after a computed digest \
             revealed a block"
        );
    }
}

/// SRI verification semantics over digests we computed ourselves: the strongest
/// algorithm upstream advertised is the one that decides, and at least one entry of
/// that algorithm has to match.
///
/// A weaker entry alongside a stronger one is not a second chance — that is exactly
/// what "the strongest algorithm decides" exists to prevent — and a reference that
/// advertises nothing has nothing to check here, which is what makes the permanent
/// pins load-bearing for it (SPEC §15, STATE-01).
///
/// The comparison is over digest *bytes*, decoded strictly by `policy::digest`
/// when the metadata was parsed. The `ssri` crate is deliberately not used: its
/// `Integrity::to_hex` unwraps and its parser does not check digest length, and
/// checking with it would mean holding the whole artifact in memory, which the
/// streaming download above exists to avoid.
fn verify_advertised(expected: &[Digest], computed: &Computed) -> Result<(), DownloadError> {
    let strongest = [
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha1,
    ]
    .into_iter()
    .find(|algorithm| expected.iter().any(|digest| digest.algorithm == *algorithm));

    let Some(algorithm) = strongest else {
        return Ok(());
    };
    let ours = computed.digest(algorithm);
    if expected
        .iter()
        .filter(|digest| digest.algorithm == algorithm)
        .any(|digest| *digest == ours)
    {
        return Ok(());
    }

    Err(DownloadError::IntegrityMismatch {
        expected: expected
            .iter()
            .find(|digest| digest.algorithm == algorithm)
            .cloned()
            .unwrap_or_else(|| ours.clone()),
        computed: ours,
    })
}

#[derive(Debug)]
pub enum DownloadError {
    Upstream(UpstreamError),
    /// The bytes do not match what upstream said they would be.
    IntegrityMismatch {
        expected: Digest,
        computed: Digest,
    },
    /// The bytes do not match what this reference has always meant (STATE-01).
    PinConflict,
    SizeMismatch {
        declared: u64,
        actual: u64,
    },
    TooLarge {
        limit: u64,
    },
    /// The local filesystem could not take the bytes. SPEC §10: a `503`, never a
    /// relaxation of policy.
    Capacity(ContentError),
    /// Policy answered something other than `Allow` after the download completed.
    Refused(Decision),
    Storage(StoreError),
    /// No download permit was free. SPEC §10: refused, never queued.
    Overloaded,
    /// The last waiter left before publication began, so the transfer stopped and its
    /// temporary file and reservation went with it (FLOW-01). No request observes
    /// this: cancellation happens only when none is left to.
    Cancelled,
    /// The transfer task ended without an outcome — it panicked, or the runtime took
    /// it. The permit, the temporary file and its reservation are released by their
    /// own `Drop` during the unwind; this is what releases the *slot*, so one failure
    /// costs one request rather than the reference.
    Aborted,
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadError::Upstream(err) => write!(f, "{err}"),
            DownloadError::IntegrityMismatch { expected, computed } => write!(
                f,
                "the artifact hashes to {computed}, but upstream advertised {expected}"
            ),
            DownloadError::PinConflict => f.write_str(
                "the artifact no longer matches the digests permanently pinned for this reference",
            ),
            DownloadError::SizeMismatch { declared, actual } => write!(
                f,
                "upstream declared {declared} bytes and delivered {actual}"
            ),
            DownloadError::TooLarge { limit } => {
                write!(f, "the artifact exceeds the {limit}-byte cap")
            }
            DownloadError::Capacity(err) => write!(f, "{err}"),
            DownloadError::Refused(decision) => {
                write!(f, "policy refused the verified bytes: {decision:?}")
            }
            DownloadError::Storage(err) => write!(f, "{err}"),
            DownloadError::Overloaded => f.write_str("no artifact download permit was available"),
            DownloadError::Cancelled => {
                f.write_str("the last waiter left before the download was published")
            }
            DownloadError::Aborted => f.write_str("the artifact transfer ended without completing"),
        }
    }
}

impl std::error::Error for DownloadError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn computed() -> Computed {
        Computed {
            sha256: [1; 32],
            sha512: [2; 64],
            sha1: [3; 20],
            size: 10,
        }
    }

    fn digest(algorithm: HashAlgorithm, byte: u8) -> Digest {
        Digest {
            algorithm,
            bytes: vec![byte; algorithm.digest_len()].into_boxed_slice(),
        }
    }

    #[test]
    fn nothing_advertised_leaves_nothing_to_check() {
        assert!(verify_advertised(&[], &computed()).is_ok());
    }

    /// The case `pin_established_without_a_strong_advertised_digest` rests on: an old
    /// npm release carries only `dist.shasum`, and that is what gets verified.
    #[test]
    fn a_lone_legacy_sha1_is_what_decides() {
        assert!(verify_advertised(&[digest(HashAlgorithm::Sha1, 3)], &computed()).is_ok());
        assert!(matches!(
            verify_advertised(&[digest(HashAlgorithm::Sha1, 9)], &computed()),
            Err(DownloadError::IntegrityMismatch { .. })
        ));
    }

    /// A matching weak digest must not rescue a mismatching strong one, or an
    /// attacker who can forge SHA-1 could choose which check applies.
    #[test]
    fn the_strongest_advertised_algorithm_decides_alone() {
        let expected = vec![
            digest(HashAlgorithm::Sha1, 3),
            digest(HashAlgorithm::Sha512, 99),
        ];
        assert!(matches!(
            verify_advertised(&expected, &computed()),
            Err(DownloadError::IntegrityMismatch { .. })
        ));

        let expected = vec![
            digest(HashAlgorithm::Sha1, 9),
            digest(HashAlgorithm::Sha512, 2),
        ];
        assert!(
            verify_advertised(&expected, &computed()).is_ok(),
            "and a mismatching weak digest does not veto a matching strong one"
        );
    }

    fn fresh_slot() -> Slot<SlotOutcome> {
        Slot::new()
    }

    /// FLOW-01's whole race, in the one place it is decided: whichever of the two
    /// transitions happens first, the other is refused. A publication can never begin
    /// after a cancellation, and a cancellation can never abandon a publication.
    #[test]
    fn publishing_and_cancelling_cannot_both_win() {
        let slot = fresh_slot();
        assert!(slot.begin_publishing());
        assert!(
            !slot.begin_cancel(),
            "a waiter leaving after publication began does not cancel it"
        );
        assert!(!slot.begin_publishing(), "and publication begins once");

        let slot = fresh_slot();
        assert!(slot.begin_cancel());
        assert!(
            !slot.begin_publishing(),
            "a cancelled transfer never starts publishing"
        );
        assert!(!slot.begin_cancel(), "and is cancelled once");
    }

    /// The count a cancellation is decided on: joining twice and leaving twice
    /// returns to zero, and the slot is gone rather than left behind at zero.
    #[test]
    fn waiter_accounting_returns_to_zero_and_removes_the_slot() {
        let coordinator = DownloadCoordinator::new();
        let id = ReferenceId::from_bytes([9; 32]);

        let (_slot, leader, first) = coordinator.transfers().join(id);
        assert!(leader, "the first request starts the transfer");
        let (_slot, leader, second) = coordinator.transfers().join(id);
        assert!(!leader, "the second joins it");
        assert_eq!(coordinator.waiting_on(&id), 2);

        drop(second);
        assert_eq!(
            coordinator.waiting_on(&id),
            1,
            "one leaving leaves the other"
        );

        drop(first);
        assert_eq!(coordinator.waiting_on(&id), 0);
        let (_slot, leader, _third) = coordinator.transfers().join(id);
        assert!(
            leader,
            "and the next request starts a new transfer rather than joining a cancelled one"
        );
    }

    /// npm sometimes advertises several SRI entries of one algorithm; any of them
    /// matching is a match.
    #[test]
    fn one_of_several_entries_of_the_strongest_algorithm_is_enough() {
        let expected = vec![
            digest(HashAlgorithm::Sha512, 7),
            digest(HashAlgorithm::Sha512, 2),
        ];
        assert!(verify_advertised(&expected, &computed()).is_ok());
    }
}
