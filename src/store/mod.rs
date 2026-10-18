//! The storage module: one task, one connection, and every SQL statement in the
//! crate (Gate 2 constraint 2).
//!
//! Nothing outside `src/store/` names `turso`, writes SQL, or issues a pragma. The
//! rest of the application talks to a [`StoreHandle`], which is a pair of bounded
//! queues in front of a single task that owns the one connection.
//!
//! Two queues, one task. The task drains `critical` before it looks at
//! `maintenance`, which is how SPEC §10's "give pending blocklist commits priority
//! over ordinary queued cache maintenance, without interrupting an active
//! transaction" is implemented: the bias is checked between commands, never inside
//! one.

pub mod cache;
pub mod lock;
pub mod rows;
pub mod schema;
pub mod startup;

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use turso::Connection;
use turso::transaction::{DropBehavior, Transaction};

use crate::artifacts::content::ContentKey;
use crate::policy::{BlocklistSnapshot, Digest, Ecosystem, HashAlgorithm};
use crate::store::cache::{MemoryCaches, ProjectKey};
use crate::store::lock::DataDirLock;
use crate::store::rows::{
    BlocklistRow, Generation, ProjectRefresh, ProjectRow, ReferenceId, ReferenceRow,
    ReferenceUpsert, digest, encode_digests, integer, optional_digest, optional_integer,
    optional_unsigned, text, unsigned,
};

/// How many commands may wait on each queue before the store refuses more. SPEC
/// §10: "Use semaphores and bounded queues; reject overload instead of allowing
/// unbounded waiters or tasks."
const QUEUE_DEPTH: usize = 64;

const UPSERT_BLOCKLIST: &str = "INSERT OR REPLACE INTO blocklist \
     (id, revision, generated_at_micros, expires_at_micros, snapshot) \
     VALUES (1, ?1, ?2, ?3, ?4)";

const SELECT_BLOCKLIST: &str =
    "SELECT revision, generated_at_micros, expires_at_micros, snapshot FROM blocklist WHERE id = 1";

const SELECT_PROJECT: &str = "SELECT ecosystem, name, payload, etag, last_modified, \
     validated_at_micros, fetched_at_micros, generation, digest_generation \
     FROM projects WHERE ecosystem = ?1 AND name = ?2";

/// SPEC §7's known-project index: the projects *this instance* has fetched, in a
/// stable order so two renderings of one index are byte-identical.
const SELECT_KNOWN_PROJECTS: &str = "SELECT name FROM projects WHERE ecosystem = ?1 ORDER BY name";

const SELECT_PROJECT_GENERATIONS: &str =
    "SELECT generation, digest_generation FROM projects WHERE ecosystem = ?1 AND name = ?2";

/// The only statement that writes `fetched_at_micros`. It is a full-row upsert, so
/// the value has to be threaded through the caller's per-branch choice of payload
/// and validators: a `304` supplies the stored value, a `200` supplies `now`.
const REPLACE_PROJECT: &str = "INSERT OR REPLACE INTO projects \
     (ecosystem, name, payload, etag, last_modified, validated_at_micros, \
      fetched_at_micros, generation, digest_generation) \
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

const SELECT_REFERENCE: &str = "SELECT id, ecosystem, name, version, filename, upstream_url, \
     expected, publication_micros, first_seen_micros, pinned_sha256, pinned_sha512, pinned_size, \
     content_key FROM artifact_references WHERE id = ?1";

/// Everything a refresh must carry forward rather than overwrite: the committed
/// first-seen time (SPEC §5) and the permanent pins and content mapping (STATE-01).
const SELECT_REFERENCE_CARRIED: &str = "SELECT first_seen_micros, pinned_sha256, pinned_sha512, \
     pinned_size, content_key FROM artifact_references WHERE id = ?1";

const SELECT_PROJECT_FIRST_SEEN: &str = "SELECT id, first_seen_micros FROM artifact_references \
     WHERE ecosystem = ?1 AND name = ?2 AND first_seen_micros IS NOT NULL";

const REPLACE_REFERENCE: &str = "INSERT OR REPLACE INTO artifact_references \
     (id, ecosystem, name, version, filename, upstream_url, expected, publication_micros, \
      first_seen_micros, pinned_sha256, pinned_sha512, pinned_size, content_key) \
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

/// Every pin this instance holds for one project, for the metadata path: a block on
/// a digest we computed ourselves has to deny the version in the listing too
/// (SPEC §9), and a listing must not ask per version.
const SELECT_PROJECT_PINS: &str = "SELECT id, pinned_sha256, pinned_sha512 FROM \
     artifact_references WHERE ecosystem = ?1 AND name = ?2 AND pinned_sha256 IS NOT NULL";

const SELECT_REFERENCE_PINS: &str =
    "SELECT pinned_sha256, pinned_sha512, pinned_size FROM artifact_references WHERE id = ?1";

const UPDATE_REFERENCE_PINS: &str = "UPDATE artifact_references \
     SET pinned_sha256 = ?1, pinned_sha512 = ?2, pinned_size = ?3 WHERE id = ?4";

const UPSERT_CONTENT: &str = "INSERT OR REPLACE INTO content \
     (key, sha512, size, created_micros, accessed_micros) VALUES (?1, ?2, ?3, ?4, ?4)";

const UPDATE_REFERENCE_CONTENT: &str =
    "UPDATE artifact_references SET content_key = ?1 WHERE id = ?2";

const CLEAR_REFERENCE_CONTENT: &str =
    "UPDATE artifact_references SET content_key = NULL WHERE content_key = ?1";

const DELETE_CONTENT: &str = "DELETE FROM content WHERE key = ?1";

/// SPEC §10: "Disk eviction uses approximate least-recently-used order". The order
/// is the access time the maintenance pass last wrote, and `key` breaks ties so two
/// passes over the same cache choose the same victims.
const SELECT_CONTENT_BY_ACCESS: &str =
    "SELECT key, size FROM content ORDER BY accessed_micros ASC, key ASC";

/// A row written and deleted again in one transaction: a real commit, through the
/// log and its `fsync`, that leaves every record as it was. Rewriting a value with
/// itself is not one — the engine commits it without writing a frame.
const PROBE_INSERT: &str = "INSERT INTO projects (ecosystem, name, payload, validated_at_micros, \
     fetched_at_micros, generation, digest_generation) VALUES ('probe', '', x'', 0, 0, 0, 0)";
const PROBE_DELETE: &str = "DELETE FROM projects WHERE ecosystem = 'probe'";

/// SPEC §10: "access updates batched off the request path".
const TOUCH_CONTENT: &str = "UPDATE content SET accessed_micros = ?2 WHERE key = ?1";

/// SPEC §9: a computed digest that reveals what upstream metadata never advertised
/// invalidates every response rendered from that project.
const BUMP_DIGEST_GENERATION: &str = "UPDATE projects \
     SET digest_generation = digest_generation + 1 WHERE ecosystem = ?1 AND name = ?2";

/// How old one project's snapshot may become since its last FULL fetch, in
/// microseconds, or `None` when the ceiling is disabled (SPEC rev 3 §10).
///
/// The configured maximum is reduced by a deterministic offset of up to one tenth of
/// it, derived from the project's own identity. Snapshots fetched together otherwise
/// share one expiry instant, and because an over-age snapshot fails closed, a bulk
/// seed or a restore would turn an upstream outage that crosses the ceiling into one
/// simultaneous fleet-wide refusal rather than a gradual lapse.
///
/// The offset only ever SHORTENS, so `metadata_max_age_seconds` stays a true
/// maximum: no snapshot is ever served beyond it.
///
/// SHA-256 rather than `DefaultHasher` because SPEC rev 3 §10 requires the offset to
/// be stable across restarts *and identical on every instance*: the standard
/// hasher's output is explicitly not guaranteed stable across Rust releases, so two
/// instances built from different toolchains would spread the same project
/// differently.
pub fn effective_max_age_micros(key: &ProjectKey, max_age_seconds: u64) -> Option<i64> {
    if max_age_seconds == 0 {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(key.ecosystem.as_tag().as_bytes());
    hasher.update([0u8]);
    hasher.update(key.name.as_bytes());
    let spread = u64::from_be_bytes(
        hasher.finalize()[..8]
            .try_into()
            .expect("a SHA-256 digest has eight leading bytes"),
    );

    // `max(1)` keeps the remainder defined for a ceiling below ten seconds, where a
    // tenth of it rounds away; the offset is then always zero.
    let offset = spread % (max_age_seconds / 10).max(1);
    let effective = max_age_seconds - offset;
    Some(i64::try_from(effective.saturating_mul(1_000_000)).unwrap_or(i64::MAX))
}

/// Whether this snapshot has reached its effective ceiling, and so must be refetched
/// in full with no validators before anything is served from it (SPEC rev 3 §10).
///
/// A wall-clock comparison on purpose: the instant it measures from is persisted and
/// has to survive a restart, which no monotonic reading does (SPEC §5).
pub fn is_over_age(
    key: &ProjectKey,
    max_age_seconds: u64,
    fetched_at_micros: i64,
    now: i64,
) -> bool {
    effective_max_age_micros(key, max_age_seconds)
        .is_some_and(|ceiling| now.saturating_sub(fetched_at_micros) >= ceiling)
}

/// The handle every other module holds. Cheap to clone; all clones address the one
/// task.
///
/// It carries the bounded memory caches as well as the queues, because SPEC §3 puts
/// "embedded Turso records and bounded memory caches" in this one module and because
/// the caches exist precisely to keep callers from reaching the queues.
#[derive(Clone)]
pub struct StoreHandle {
    channels: Channels,
    caches: Arc<MemoryCaches>,
    /// Every command that reached a queue. The harness asserts a fully warm request
    /// leaves it unchanged (SPEC §10: "no database query"), and slice 9's periodic
    /// counter summary reads the same number.
    issued: Arc<AtomicU64>,
    /// What [`StoreHandle::is_healthy`] answers with, and therefore half of what
    /// `/health/ready` answers with. Written by the store task only.
    healthy: Arc<AtomicBool>,
    /// The content directory's half of the same answer: false from a refused content
    /// write until one succeeds again ([`StoreHandle::note_content_write`]).
    content_healthy: Arc<AtomicBool>,
}

#[derive(Clone)]
enum Channels {
    Live {
        critical: mpsc::Sender<StoreCommand>,
        maintenance: mpsc::Sender<StoreCommand>,
    },
    /// The database could not be opened or recovered. Every command fails with the
    /// reason, which is what keeps a snapshot from being published and therefore what
    /// keeps readiness false (SPEC §10).
    ///
    /// The lock travels with it: a data directory this instance could not open is
    /// still a data directory no second instance may take.
    Unusable {
        reason: Arc<str>,
        _lock: Arc<DataDirLock>,
    },
}

enum StoreCommand {
    /// The whole accepted snapshot in one transaction, before it is published.
    CommitBlocklist {
        snapshot: Arc<BlocklistSnapshot>,
        reply: oneshot::Sender<StoreResult<()>>,
    },
    LoadBlocklist {
        reply: oneshot::Sender<StoreResult<Option<BlocklistRow>>>,
    },
    GetProject {
        ecosystem: Ecosystem,
        name: String,
        reply: oneshot::Sender<StoreResult<Option<ProjectRow>>>,
    },
    /// Snapshot, reference upserts and new first-seen values in ONE transaction
    /// (SPEC §10, finding REL-01), before the new generation is published.
    CommitProjectRefresh {
        refresh: Box<ProjectRefresh>,
        reply: oneshot::Sender<StoreResult<CommittedProject>>,
    },
    GetReference {
        id: ReferenceId,
        reply: oneshot::Sender<StoreResult<Option<ReferenceRow>>>,
    },
    ListProjectFirstSeen {
        ecosystem: Ecosystem,
        name: String,
        reply: oneshot::Sender<StoreResult<HashMap<ReferenceId, i64>>>,
    },
    ListKnownProjects {
        ecosystem: Ecosystem,
        reply: oneshot::Sender<StoreResult<Vec<String>>>,
    },
    ListProjectPins {
        ecosystem: Ecosystem,
        name: String,
        reply: oneshot::Sender<StoreResult<HashMap<ReferenceId, Vec<Digest>>>>,
    },
    /// Permanent (SPEC §15, STATE-01): written even when policy now blocks the bytes,
    /// and never overwritten once established.
    PinComputedDigests {
        id: ReferenceId,
        sha256: [u8; 32],
        sha512: [u8; 64],
        size: u64,
        reply: oneshot::Sender<StoreResult<PinOutcome>>,
    },
    /// The mapping from a reference to bytes already durable on disk. Committed only
    /// after `ContentStore::publish` has returned (REL-01).
    PublishContent {
        key: ContentKey,
        sha512: [u8; 64],
        size: u64,
        id: ReferenceId,
        now_micros: i64,
        reply: oneshot::Sender<StoreResult<()>>,
    },
    /// The bytes are gone or are the wrong size. The mapping goes; the pins stay.
    ClearContentKey {
        key: ContentKey,
        reply: oneshot::Sender<StoreResult<()>>,
    },
    BumpDigestGeneration {
        ecosystem: Ecosystem,
        name: String,
        reply: oneshot::Sender<StoreResult<()>>,
    },
    // maintenance queue only:
    /// Batched access times. No reply: SPEC §10 keeps these off the request path, and
    /// a handler that awaited one would have put them back on it.
    TouchContent { keys: Vec<(ContentKey, i64)> },
    /// Every cached object in access order, with what they come to in total.
    EvictionPlan {
        reply: oneshot::Sender<StoreResult<EvictionPlan>>,
    },
    Checkpoint {
        reply: oneshot::Sender<StoreResult<()>>,
    },
    /// See [`StoreHandle::probe`].
    Probe {
        reply: oneshot::Sender<StoreResult<()>>,
    },
}

impl StoreHandle {
    /// A handle whose database never opened. Named rather than defaulted so a
    /// caller cannot produce one by accident.
    pub fn unusable(
        reason: impl Into<String>,
        lock: DataDirLock,
        caches: Arc<MemoryCaches>,
    ) -> StoreHandle {
        StoreHandle {
            channels: Channels::Unusable {
                reason: Arc::from(reason.into()),
                _lock: Arc::new(lock),
            },
            caches,
            issued: Arc::new(AtomicU64::new(0)),
            healthy: Arc::new(AtomicBool::new(false)),
            content_healthy: Arc::new(AtomicBool::new(true)),
        }
    }

    /// The bounded memory caches. A warm request answers from here and never reaches
    /// a queue (SPEC §10).
    pub fn caches(&self) -> &MemoryCaches {
        &self.caches
    }

    /// How many commands this handle has put on a queue since it was created.
    pub fn commands_issued(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }

    /// The stored snapshot for one project, or `None` when this instance has never
    /// fetched it.
    pub async fn get_project(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> StoreResult<Option<ProjectRow>> {
        let name = name.to_owned();
        self.critical(|reply| StoreCommand::GetProject {
            ecosystem,
            name,
            reply,
        })
        .await
    }

    /// SPEC §10: "Commit a project snapshot, its reference upserts, and new
    /// first-seen values together before publishing the new in-memory generation."
    /// The returned generation is the one the caller may then publish; on an error
    /// nothing was written and there is no generation to publish.
    pub async fn commit_project_refresh(
        &self,
        refresh: ProjectRefresh,
    ) -> StoreResult<CommittedProject> {
        let refresh = Box::new(refresh);
        self.critical(|reply| StoreCommand::CommitProjectRefresh { refresh, reply })
            .await
    }

    pub async fn get_reference(&self, id: ReferenceId) -> StoreResult<Option<ReferenceRow>> {
        self.critical(|reply| StoreCommand::GetReference { id, reply })
            .await
    }

    /// The committed first-seen time of every reference of one project, in one
    /// query. A metadata request needs all of them at once and must never ask per
    /// version.
    pub async fn list_project_first_seen(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> StoreResult<HashMap<ReferenceId, i64>> {
        let name = name.to_owned();
        self.critical(|reply| StoreCommand::ListProjectFirstSeen {
            ecosystem,
            name,
            reply,
        })
        .await
    }

    /// The permanently pinned digests of every reference of one project, in one
    /// query. SPEC §9's "the next resolution hides the affected artifact" needs them
    /// at listing time, and a listing must never ask per version. That guarantee holds
    /// under a concurrent project read too; why is recorded in
    /// `artifacts::download::fetch`.
    pub async fn list_project_pins(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> StoreResult<HashMap<ReferenceId, Vec<Digest>>> {
        let name = name.to_owned();
        self.critical(|reply| StoreCommand::ListProjectPins {
            ecosystem,
            name,
            reply,
        })
        .await
    }

    /// Every project this instance has fetched, in name order. SPEC §7 serves this
    /// as PyPI's index and is explicit that it is not a mirror of the upstream one.
    pub async fn list_known_projects(&self, ecosystem: Ecosystem) -> StoreResult<Vec<String>> {
        self.critical(|reply| StoreCommand::ListKnownProjects { ecosystem, reply })
            .await
    }

    /// Persists the accepted snapshot. SPEC §10: "Persist a new blocklist before
    /// publishing its memory snapshot" — the caller publishes only after this
    /// returns `Ok`.
    pub async fn commit_blocklist(&self, snapshot: Arc<BlocklistSnapshot>) -> StoreResult<()> {
        self.critical(|reply| StoreCommand::CommitBlocklist { snapshot, reply })
            .await
    }

    /// The last accepted snapshot, whether or not it is still valid. Validity is the
    /// caller's decision, made against the same `now` it decides with.
    pub async fn load_blocklist(&self) -> StoreResult<Option<BlocklistRow>> {
        self.critical(|reply| StoreCommand::LoadBlocklist { reply })
            .await
    }

    /// SPEC §9: "The first complete, upstream-integrity-verified download pins the
    /// reference's computed SHA-256 and SHA-512 permanently, including when those
    /// bytes are subsequently denied by policy."
    ///
    /// [`PinOutcome::Conflict`] writes nothing: the established pins are what the
    /// reference means, and new bytes that disagree with them are the thing being
    /// refused.
    pub async fn pin_computed_digests(
        &self,
        id: ReferenceId,
        sha256: [u8; 32],
        sha512: [u8; 64],
        size: u64,
    ) -> StoreResult<PinOutcome> {
        self.critical(|reply| StoreCommand::PinComputedDigests {
            id,
            sha256,
            sha512,
            size,
            reply,
        })
        .await
    }

    /// Commits the content mapping. SPEC §10 orders this after the file is durable,
    /// so the caller has already published the bytes when it calls this.
    pub async fn publish_content(
        &self,
        key: ContentKey,
        sha512: [u8; 64],
        size: u64,
        id: ReferenceId,
        now_micros: i64,
    ) -> StoreResult<()> {
        self.critical(|reply| StoreCommand::PublishContent {
            key,
            sha512,
            size,
            id,
            now_micros,
            reply,
        })
        .await
    }

    /// SPEC §9: "Detect missing files and size mismatches and discard their cache
    /// mappings." The permanent pins are untouched.
    pub async fn clear_content_key(&self, key: ContentKey) -> StoreResult<()> {
        self.critical(|reply| StoreCommand::ClearContentKey { key, reply })
            .await
    }

    /// [`StoreHandle::clear_content_key`] for an object the maintenance pass evicted,
    /// on the maintenance queue: a pass that evicts a thousand objects must not put a
    /// thousand commands ahead of a blocklist commit (SPEC §10).
    pub async fn clear_evicted_content(&self, key: ContentKey) -> StoreResult<()> {
        self.maintenance(|reply| StoreCommand::ClearContentKey { key, reply })
            .await
    }

    /// SPEC §9: "If a computed digest reveals a block not visible in upstream
    /// metadata, invalidate that project's filtered metadata."
    pub async fn bump_digest_generation(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> StoreResult<()> {
        let name = name.to_owned();
        self.critical(|reply| StoreCommand::BumpDigestGeneration {
            ecosystem,
            name,
            reply,
        })
        .await
    }

    /// SPEC §10: "access updates batched off the request path". Best effort and never
    /// awaited by a handler: a full maintenance queue drops the batch, which costs
    /// eviction some accuracy and a request nothing. SPEC §10 already calls the
    /// resulting order approximate.
    pub fn touch_content(&self, keys: Vec<(ContentKey, i64)>) {
        if keys.is_empty() {
            return;
        }
        self.issued.fetch_add(1, Ordering::Relaxed);
        if let Channels::Live { maintenance, .. } = &self.channels
            && maintenance
                .try_send(StoreCommand::TouchContent { keys })
                .is_err()
        {
            tracing::debug!("the maintenance queue is full; dropping a batch of access times");
        }
    }

    /// What the cache holds, oldest access first, for the maintenance pass to work
    /// down. Where to stop is the caller's, because only the content cache knows
    /// which files are open and SPEC §10 says an open one is never evicted — so the
    /// pass keeps going past a held key rather than giving up on the budget.
    pub async fn eviction_plan(&self) -> StoreResult<EvictionPlan> {
        self.maintenance(|reply| StoreCommand::EvictionPlan { reply })
            .await
    }

    /// SPEC §10: "Checkpoint with the pinned engine's supported API outside HTTP
    /// handling." It runs on the low-priority queue, behind any pending commit.
    pub async fn checkpoint(&self) -> StoreResult<()> {
        self.maintenance(|reply| StoreCommand::Checkpoint { reply })
            .await
    }

    /// Whether storage is usable right now. False when the database never opened,
    /// and false from the moment a command fails with a database or corruption
    /// error until a *write* succeeds again — SPEC §10: "Storage write failures make
    /// readiness false […] until storage is usable again." A read that succeeds is
    /// not evidence that the next commit will.
    ///
    /// The store task records each outcome as it executes the command, so the flag
    /// follows the order commands ran in rather than the order their callers woke.
    pub fn is_healthy(&self) -> bool {
        match &self.channels {
            Channels::Live { .. } => {
                self.healthy.load(Ordering::Relaxed) && self.content_healthy.load(Ordering::Relaxed)
            }
            Channels::Unusable { .. } => false,
        }
    }

    /// What a write to the content directory showed. SPEC §10 makes a storage write
    /// failure a readiness failure, and the artifact bytes are storage as much as the
    /// database is: a refused write turns readiness false, and only a write that
    /// succeeds turns it back.
    pub fn note_content_write(&self, succeeded: bool) {
        self.content_healthy.store(succeeded, Ordering::Relaxed);
    }

    /// A write that changes nothing, for the maintenance pass to find out whether a
    /// database that refused a write takes one again. Without it an instance that a
    /// readiness probe took out of rotation would receive no request whose write
    /// could ever bring it back.
    pub async fn probe(&self) -> StoreResult<()> {
        self.maintenance(|reply| StoreCommand::Probe { reply })
            .await
    }

    async fn critical<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<StoreResult<T>>) -> StoreCommand,
    ) -> StoreResult<T> {
        self.issued.fetch_add(1, Ordering::Relaxed);
        match &self.channels {
            Channels::Live { critical, .. } => send(critical, command).await,
            Channels::Unusable { reason, .. } => Err(StoreError::Corrupt(reason.to_string())),
        }
    }

    async fn maintenance<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<StoreResult<T>>) -> StoreCommand,
    ) -> StoreResult<T> {
        self.issued.fetch_add(1, Ordering::Relaxed);
        match &self.channels {
            Channels::Live { maintenance, .. } => send(maintenance, command).await,
            Channels::Unusable { reason, .. } => Err(StoreError::Corrupt(reason.to_string())),
        }
    }
}

async fn send<T>(
    queue: &mpsc::Sender<StoreCommand>,
    command: impl FnOnce(oneshot::Sender<StoreResult<T>>) -> StoreCommand,
) -> StoreResult<T> {
    let (reply, answer) = oneshot::channel();
    // `try_send`, not `send`: a full queue is overload, and SPEC §10 refuses overload
    // rather than queueing behind it.
    queue.try_send(command(reply)).map_err(|err| match err {
        mpsc::error::TrySendError::Full(_) => StoreError::Busy,
        mpsc::error::TrySendError::Closed(_) => StoreError::Closed,
    })?;
    answer.await.map_err(|_| StoreError::Closed)?
}

/// Starts the storage task. The returned handle is the only way to reach the
/// connection; the join handle lets a clean shutdown wait for the task to finish
/// whatever it was doing.
///
/// The task runs on an OS thread of its own, on a single-threaded runtime of its
/// own. The engine's file I/O blocks inside `poll` — `synchronous=FULL` is an
/// `fsync` per commit — so on a worker of the serving runtime every commit would
/// stall whatever else that worker had to do. The queues are unchanged: callers
/// still send a command and await a reply.
///
/// The task owns the data-directory lock as well as the connection, so the lock is
/// released after the connection is closed rather than before it, and the join
/// handle completes only after both.
pub fn spawn(
    connection: Connection,
    lock: DataDirLock,
    caches: Arc<MemoryCaches>,
) -> (StoreHandle, JoinHandle<()>) {
    let (critical_tx, critical_rx) = mpsc::channel(QUEUE_DEPTH);
    let (maintenance_tx, maintenance_rx) = mpsc::channel(QUEUE_DEPTH);
    let healthy = Arc::new(AtomicBool::new(true));

    let (stopped_tx, stopped_rx) = oneshot::channel::<()>();
    let task_health = Arc::clone(&healthy);
    std::thread::Builder::new()
        .name("probation-store".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the storage runtime builds");
            runtime.block_on(run(
                connection,
                lock,
                critical_rx,
                maintenance_rx,
                task_health,
            ));
            let _ = stopped_tx.send(());
        })
        .expect("the storage thread starts");
    // A panic on the storage thread drops the sender, which ends this as well.
    let task = tokio::spawn(async move {
        let _ = stopped_rx.await;
    });

    (
        StoreHandle {
            channels: Channels::Live {
                critical: critical_tx,
                maintenance: maintenance_tx,
            },
            caches,
            issued: Arc::new(AtomicU64::new(0)),
            healthy,
            content_healthy: Arc::new(AtomicBool::new(true)),
        },
        task,
    )
}

async fn run(
    mut connection: Connection,
    lock: DataDirLock,
    mut critical: mpsc::Receiver<StoreCommand>,
    mut maintenance: mpsc::Receiver<StoreCommand>,
    healthy: Arc<AtomicBool>,
) {
    loop {
        let command = tokio::select! {
            // `biased` is the priority rule: while anything is waiting on the
            // critical queue, the maintenance queue is not even looked at. The choice
            // happens here, between commands, so it can never interrupt a transaction.
            biased;
            Some(command) = critical.recv() => command,
            Some(command) = maintenance.recv() => command,
            else => break,
        };

        execute(&mut connection, command, &healthy).await;
    }

    // Explicit, and in this order: the connection closes, and only then is the data
    // directory free for another instance to take.
    drop(connection);
    drop(lock);
}

/// Runs one command and records what it showed about storage health before the
/// caller hears the answer.
async fn execute(connection: &mut Connection, command: StoreCommand, healthy: &AtomicBool) {
    match command {
        StoreCommand::CommitBlocklist { snapshot, reply } => {
            let result = commit_blocklist(connection, &snapshot).await;
            answer(healthy, WRITE, reply, result);
        }
        StoreCommand::LoadBlocklist { reply } => {
            answer(healthy, READ, reply, load_blocklist(connection).await);
        }
        StoreCommand::GetProject {
            ecosystem,
            name,
            reply,
        } => {
            let result = get_project(connection, ecosystem, &name).await;
            answer(healthy, READ, reply, result);
        }
        StoreCommand::CommitProjectRefresh { refresh, reply } => {
            let result = commit_project_refresh(connection, &refresh).await;
            answer(healthy, WRITE, reply, result);
        }
        StoreCommand::GetReference { id, reply } => {
            answer(healthy, READ, reply, get_reference(connection, id).await);
        }
        StoreCommand::ListProjectFirstSeen {
            ecosystem,
            name,
            reply,
        } => {
            let result = list_project_first_seen(connection, ecosystem, &name).await;
            answer(healthy, READ, reply, result);
        }
        StoreCommand::ListKnownProjects { ecosystem, reply } => {
            let result = list_known_projects(connection, ecosystem).await;
            answer(healthy, READ, reply, result);
        }
        StoreCommand::ListProjectPins {
            ecosystem,
            name,
            reply,
        } => {
            let result = list_project_pins(connection, ecosystem, &name).await;
            answer(healthy, READ, reply, result);
        }
        StoreCommand::PinComputedDigests {
            id,
            sha256,
            sha512,
            size,
            reply,
        } => {
            let result = pin_computed_digests(connection, id, sha256, sha512, size).await;
            // Only an established pin wrote anything; a match or a conflict read.
            let wrote = matches!(result, Ok(PinOutcome::Established));
            answer(healthy, wrote, reply, result);
        }
        StoreCommand::PublishContent {
            key,
            sha512,
            size,
            id,
            now_micros,
            reply,
        } => {
            let result = publish_content(connection, key, sha512, size, id, now_micros).await;
            answer(healthy, WRITE, reply, result);
        }
        StoreCommand::ClearContentKey { key, reply } => {
            let result = clear_content_key(connection, key).await;
            answer(healthy, WRITE, reply, result);
        }
        StoreCommand::BumpDigestGeneration {
            ecosystem,
            name,
            reply,
        } => {
            let result = bump_digest_generation(connection, ecosystem, &name).await;
            answer(healthy, WRITE, reply, result);
        }
        StoreCommand::TouchContent { keys } => {
            let result = touch_content(connection, &keys).await;
            record(healthy, WRITE, &result);
            if let Err(err) = result {
                tracing::debug!(error = %err, "a batch of access times could not be written");
            }
        }
        StoreCommand::EvictionPlan { reply } => {
            answer(healthy, READ, reply, eviction_plan(connection).await);
        }
        StoreCommand::Checkpoint { reply } => {
            answer(healthy, READ, reply, checkpoint(connection).await);
        }
        StoreCommand::Probe { reply } => {
            answer(healthy, WRITE, reply, probe(connection).await);
        }
    }
}

const WRITE: bool = true;
const READ: bool = false;

fn answer<T>(
    healthy: &AtomicBool,
    wrote: bool,
    reply: oneshot::Sender<StoreResult<T>>,
    result: StoreResult<T>,
) {
    record(healthy, wrote, &result);
    let _ = reply.send(result);
}

/// What one executed command showed about storage health. Any database or
/// corruption error marks it unhealthy; only a write that succeeded marks it healthy
/// again.
fn record<T>(healthy: &AtomicBool, wrote: bool, result: &StoreResult<T>) {
    match result {
        Ok(_) if wrote => healthy.store(true, Ordering::Relaxed),
        Ok(_) => {}
        Err(StoreError::Database(_) | StoreError::Corrupt(_)) => {
            healthy.store(false, Ordering::Relaxed);
        }
        // Neither is produced by a command the task executed.
        Err(StoreError::Busy | StoreError::Closed) => {}
    }
}

async fn get_project(
    connection: &mut Connection,
    ecosystem: Ecosystem,
    name: &str,
) -> StoreResult<Option<ProjectRow>> {
    let mut rows = connection
        .query(SELECT_PROJECT, (ecosystem.as_tag(), name))
        .await?;
    match rows.next().await? {
        Some(row) => ProjectRow::from_row(&row).map(Some),
        None => Ok(None),
    }
}

async fn get_reference(
    connection: &mut Connection,
    id: ReferenceId,
) -> StoreResult<Option<ReferenceRow>> {
    let mut rows = connection
        .query(SELECT_REFERENCE, (id.as_bytes().to_vec(),))
        .await?;
    match rows.next().await? {
        Some(row) => ReferenceRow::from_row(&row).map(Some),
        None => Ok(None),
    }
}

async fn list_project_first_seen(
    connection: &mut Connection,
    ecosystem: Ecosystem,
    name: &str,
) -> StoreResult<HashMap<ReferenceId, i64>> {
    let mut rows = connection
        .query(SELECT_PROJECT_FIRST_SEEN, (ecosystem.as_tag(), name))
        .await?;
    let mut first_seen = HashMap::new();
    while let Some(row) = rows.next().await? {
        let id = digest(&row, 0, "artifact_references.id")?;
        let micros = integer(&row, 1, "artifact_references.first_seen_micros")?;
        first_seen.insert(ReferenceId::from_bytes(id), micros);
    }
    Ok(first_seen)
}

async fn list_project_pins(
    connection: &mut Connection,
    ecosystem: Ecosystem,
    name: &str,
) -> StoreResult<HashMap<ReferenceId, Vec<Digest>>> {
    let mut rows = connection
        .query(SELECT_PROJECT_PINS, (ecosystem.as_tag(), name))
        .await?;
    let mut pins = HashMap::new();
    while let Some(row) = rows.next().await? {
        let id = digest(&row, 0, "artifact_references.id")?;
        let sha256 = optional_digest::<32>(&row, 1, "artifact_references.pinned_sha256")?;
        let sha512 = optional_digest::<64>(&row, 2, "artifact_references.pinned_sha512")?;
        let digests = [
            sha256.map(|bytes| (HashAlgorithm::Sha256, Box::from(bytes.as_slice()))),
            sha512.map(|bytes| (HashAlgorithm::Sha512, Box::from(bytes.as_slice()))),
        ]
        .into_iter()
        .flatten()
        .map(|(algorithm, bytes)| Digest { algorithm, bytes })
        .collect();
        pins.insert(ReferenceId::from_bytes(id), digests);
    }
    Ok(pins)
}

async fn list_known_projects(
    connection: &mut Connection,
    ecosystem: Ecosystem,
) -> StoreResult<Vec<String>> {
    let mut rows = connection
        .query(SELECT_KNOWN_PROJECTS, (ecosystem.as_tag(),))
        .await?;
    let mut names = Vec::new();
    while let Some(row) = rows.next().await? {
        names.push(text(&row, 0, "projects.name")?);
    }
    Ok(names)
}

/// Ends a transaction the way its body ended: committed on `Ok`, rolled back on
/// `Err`. Explicitly, both ways, so a failed command never leaves its transaction
/// open for the engine to roll back at the start of the next, unrelated command —
/// which would then be the one to fail if that rollback did.
async fn settle<T, E: From<turso::Error>>(
    mut transaction: Transaction<'_>,
    result: Result<T, E>,
) -> Result<T, E> {
    // Whichever way this goes, nothing is left for the next command to finish.
    transaction.set_drop_behavior(DropBehavior::Ignore);
    let result = match result {
        Ok(value) => transaction
            .execute("COMMIT", ())
            .await
            .map(|_| value)
            .map_err(E::from),
        Err(err) => Err(err),
    };
    if result.is_err() {
        // Fails only when the engine already ended the transaction itself, which
        // leaves nothing to undo.
        let _ = transaction.rollback().await;
    }
    result
}

/// What a committed refresh hands back: the generation the caller may now publish,
/// the project's computed-digest generation, and the first-seen time in force for
/// every reference — the value already on disk where there was one, so a caller
/// never has to re-read them to find out which of its proposals were kept.
#[derive(Clone, Debug)]
pub struct CommittedProject {
    pub generation: Generation,
    pub digest_generation: u64,
    pub first_seen: HashMap<ReferenceId, i64>,
}

/// One transaction for the snapshot, every reference it advertises, and the
/// first-seen times of the references that have no upstream timestamp (REL-01).
///
/// Nothing here overwrites an existing first-seen value: SPEC §5 requires that a
/// restart must not reset it, and a refresh is a restart's daytime equivalent. An
/// error anywhere rolls the transaction back and no generation is returned — so the
/// caller has nothing to publish. A stored value that does not decode is such an
/// error: a generation read as zero would hand out a generation already used.
async fn commit_project_refresh(
    connection: &mut Connection,
    refresh: &ProjectRefresh,
) -> StoreResult<CommittedProject> {
    let transaction = connection.transaction().await?;
    let result = refresh_in(&transaction, refresh).await;
    settle(transaction, result).await
}

async fn refresh_in(
    transaction: &Transaction<'_>,
    refresh: &ProjectRefresh,
) -> StoreResult<CommittedProject> {
    let (generation, digest_generation) = {
        let mut rows = transaction
            .query(
                SELECT_PROJECT_GENERATIONS,
                (refresh.ecosystem.as_tag(), refresh.name.as_str()),
            )
            .await?;
        match rows.next().await? {
            Some(row) => (
                Generation(unsigned(&row, 0, "projects.generation")?.saturating_add(1)),
                unsigned(&row, 1, "projects.digest_generation")?,
            ),
            None => (Generation(1), 0),
        }
    };

    let generation_column = i64::try_from(generation.0).map_err(|_| {
        StoreError::Corrupt(format!("generation {} cannot be stored", generation.0))
    })?;
    // Read back from an `INTEGER` column and never incremented here, so it fits.
    let digest_generation_column = digest_generation.cast_signed();

    transaction
        .execute(
            REPLACE_PROJECT,
            (
                refresh.ecosystem.as_tag(),
                refresh.name.as_str(),
                refresh.payload.to_vec(),
                refresh.validators.etag.clone(),
                refresh.validators.last_modified.clone(),
                refresh.validated_at_micros,
                refresh.fetched_at_micros,
                generation_column,
                digest_generation_column,
            ),
        )
        .await?;

    let mut committed_first_seen = HashMap::new();
    for upsert in &refresh.references {
        let carried = carried_forward(transaction, upsert).await?;
        transaction
            .execute(
                REPLACE_REFERENCE,
                (
                    upsert.id.as_bytes().to_vec(),
                    upsert.reference.ecosystem.as_tag(),
                    upsert.reference.name.as_str(),
                    upsert.reference.version.as_str(),
                    upsert.reference.filename.as_str(),
                    upsert.reference.upstream_url.as_str(),
                    encode_digests(&upsert.reference.expected),
                    upsert.publication_micros,
                    carried.first_seen_micros,
                    carried.pinned_sha256.map(|bytes| bytes.to_vec()),
                    carried.pinned_sha512.map(|bytes| bytes.to_vec()),
                    carried.pinned_size,
                    carried.content_key.map(|bytes| bytes.to_vec()),
                ),
            )
            .await?;
        if let Some(micros) = carried.first_seen_micros {
            committed_first_seen.insert(upsert.id, micros);
        }
    }

    Ok(CommittedProject {
        generation,
        digest_generation,
        first_seen: committed_first_seen,
    })
}

/// What a refresh must keep rather than write over.
///
/// A committed first-seen time is never replaced (SPEC §5): a reference this
/// instance has not seen before takes the `now` the refresh carries. Neither are the
/// permanent pins or the content mapping (STATE-01) — `INSERT OR REPLACE` deletes
/// the whole row before inserting the new one, so a column left off this list would
/// be silently erased by the next metadata refresh, which is precisely the "pins
/// survive" property.
#[derive(Default)]
struct Carried {
    first_seen_micros: Option<i64>,
    pinned_sha256: Option<[u8; 32]>,
    pinned_sha512: Option<[u8; 64]>,
    pinned_size: Option<i64>,
    content_key: Option<[u8; 32]>,
}

async fn carried_forward(
    transaction: &Transaction<'_>,
    upsert: &ReferenceUpsert,
) -> StoreResult<Carried> {
    let mut rows = transaction
        .query(SELECT_REFERENCE_CARRIED, (upsert.id.as_bytes().to_vec(),))
        .await?;
    let Some(row) = rows.next().await? else {
        return Ok(Carried {
            first_seen_micros: upsert.first_seen_micros,
            ..Carried::default()
        });
    };

    // Strict, every one: a damaged first-seen time read as absent would be replaced
    // by this refresh's `now`, and a damaged pin carried forward would be written
    // back as though it were one.
    Ok(Carried {
        first_seen_micros: optional_integer(&row, 0, "artifact_references.first_seen_micros")?
            .or(upsert.first_seen_micros),
        pinned_sha256: optional_digest(&row, 1, "artifact_references.pinned_sha256")?,
        pinned_sha512: optional_digest(&row, 2, "artifact_references.pinned_sha512")?,
        pinned_size: optional_unsigned(&row, 3, "artifact_references.pinned_size")?
            .map(|size| size as i64),
        content_key: optional_digest(&row, 4, "artifact_references.content_key")?,
    })
}

/// STATE-01, in one place: the first complete verified download establishes the
/// pins, a later download must equal them, and a disagreement writes nothing at all.
///
/// The comparison and the write are in one transaction so two downloads of the same
/// reference cannot both read "no pins yet" and then both write.
async fn pin_computed_digests(
    connection: &mut Connection,
    id: ReferenceId,
    sha256: [u8; 32],
    sha512: [u8; 64],
    size: u64,
) -> StoreResult<PinOutcome> {
    let transaction = connection.transaction().await?;
    let result = pin_in(&transaction, id, sha256, sha512, size).await;
    settle(transaction, result).await
}

async fn pin_in(
    transaction: &Transaction<'_>,
    id: ReferenceId,
    sha256: [u8; 32],
    sha512: [u8; 64],
    size: u64,
) -> StoreResult<PinOutcome> {
    let mut rows = transaction
        .query(SELECT_REFERENCE_PINS, (id.as_bytes().to_vec(),))
        .await?;
    let Some(row) = rows.next().await? else {
        return Err(StoreError::Corrupt(format!(
            "no artifact reference {} to pin digests on",
            id.to_hex()
        )));
    };
    let pinned_sha256 = optional_digest::<32>(&row, 0, "artifact_references.pinned_sha256")?;
    let pinned_sha512 = optional_digest::<64>(&row, 1, "artifact_references.pinned_sha512")?;
    let pinned_size = optional_unsigned(&row, 2, "artifact_references.pinned_size")?;
    drop(rows);

    if let Some(pinned_sha256) = pinned_sha256 {
        // A pin is permanent. Nothing is written either way.
        let matches = pinned_sha256 == sha256
            && pinned_sha512.is_none_or(|stored| stored == sha512)
            && pinned_size.is_none_or(|stored| stored == size);
        return Ok(if matches {
            PinOutcome::MatchedExisting
        } else {
            PinOutcome::Conflict
        });
    }

    let size_column = i64::try_from(size)
        .map_err(|_| StoreError::Corrupt(format!("a size of {size} cannot be stored")))?;
    transaction
        .execute(
            UPDATE_REFERENCE_PINS,
            (
                sha256.to_vec(),
                sha512.to_vec(),
                size_column,
                id.as_bytes().to_vec(),
            ),
        )
        .await?;
    Ok(PinOutcome::Established)
}

/// The content row and the reference's mapping in one transaction, so a reference
/// never points at a content row that is not there.
async fn publish_content(
    connection: &mut Connection,
    key: ContentKey,
    sha512: [u8; 64],
    size: u64,
    id: ReferenceId,
    now_micros: i64,
) -> StoreResult<()> {
    let size_column = i64::try_from(size)
        .map_err(|_| StoreError::Corrupt(format!("a size of {size} cannot be stored")))?;

    let transaction = connection.transaction().await?;
    let result = async {
        transaction
            .execute(
                UPSERT_CONTENT,
                (
                    key.as_bytes().to_vec(),
                    sha512.to_vec(),
                    size_column,
                    now_micros,
                ),
            )
            .await?;
        transaction
            .execute(
                UPDATE_REFERENCE_CONTENT,
                (key.as_bytes().to_vec(), id.as_bytes().to_vec()),
            )
            .await
    }
    .await;
    settle(transaction, result.map(drop).map_err(StoreError::from)).await
}

async fn clear_content_key(connection: &mut Connection, key: ContentKey) -> StoreResult<()> {
    let transaction = connection.transaction().await?;
    let result = async {
        transaction
            .execute(CLEAR_REFERENCE_CONTENT, (key.as_bytes().to_vec(),))
            .await?;
        transaction
            .execute(DELETE_CONTENT, (key.as_bytes().to_vec(),))
            .await
    }
    .await;
    settle(transaction, result.map(drop).map_err(StoreError::from)).await
}

async fn bump_digest_generation(
    connection: &mut Connection,
    ecosystem: Ecosystem,
    name: &str,
) -> StoreResult<()> {
    connection
        .execute(BUMP_DIGEST_GENERATION, (ecosystem.as_tag(), name))
        .await?;
    Ok(())
}

async fn commit_blocklist(
    connection: &mut Connection,
    snapshot: &BlocklistSnapshot,
) -> StoreResult<()> {
    let revision = i64::try_from(snapshot.revision).map_err(|_| {
        StoreError::Corrupt(format!(
            "revision {} cannot be represented on disk",
            snapshot.revision
        ))
    })?;

    let transaction = connection.transaction().await?;
    let result = transaction
        .execute(
            UPSERT_BLOCKLIST,
            (
                revision,
                snapshot.generated_at_micros,
                snapshot.expires_at_micros,
                snapshot.raw.to_vec(),
            ),
        )
        .await;
    settle(transaction, result.map(drop).map_err(StoreError::from)).await
}

async fn load_blocklist(connection: &mut Connection) -> StoreResult<Option<BlocklistRow>> {
    let mut rows = connection.query(SELECT_BLOCKLIST, ()).await?;
    match rows.next().await? {
        Some(row) => BlocklistRow::from_row(&row).map(Some),
        None => Ok(None),
    }
}

async fn probe(connection: &mut Connection) -> StoreResult<()> {
    let transaction = connection.transaction().await?;
    let result = async {
        transaction.execute(PROBE_INSERT, ()).await?;
        transaction.execute(PROBE_DELETE, ()).await
    }
    .await;
    settle(transaction, result.map(drop).map_err(StoreError::from)).await
}

async fn touch_content(connection: &mut Connection, keys: &[(ContentKey, i64)]) -> StoreResult<()> {
    let transaction = connection.transaction().await?;
    let result = async {
        for (key, micros) in keys {
            transaction
                .execute(TOUCH_CONTENT, (key.as_bytes().to_vec(), *micros))
                .await?;
        }
        Ok::<(), StoreError>(())
    }
    .await;
    settle(transaction, result).await
}

/// What the cache holds right now: every object in approximate least-recently-used
/// order (SPEC §10), and their total size.
#[derive(Clone, Debug, Default)]
pub struct EvictionPlan {
    pub total_bytes: u64,
    /// Oldest access first — the order they should be reclaimed in.
    pub oldest_first: Vec<(ContentKey, u64)>,
}

async fn eviction_plan(connection: &mut Connection) -> StoreResult<EvictionPlan> {
    let mut rows = connection.query(SELECT_CONTENT_BY_ACCESS, ()).await?;
    let mut plan = EvictionPlan::default();
    while let Some(row) = rows.next().await? {
        let key = digest(&row, 0, "content.key")?;
        let size = unsigned(&row, 1, "content.size")?;
        plan.total_bytes = plan.total_bytes.saturating_add(size);
        plan.oldest_first.push((ContentKey::from_sha256(key), size));
    }
    Ok(plan)
}

async fn checkpoint(connection: &mut Connection) -> StoreResult<()> {
    // The pinned engine's supported API: `PRAGMA wal_checkpoint` answers
    // (busy, log, checkpointed). A busy log is reported as `Busy` rather than as a
    // success, so a pass that moved nothing says so; the next pass retries.
    let mut rows = connection.query("PRAGMA wal_checkpoint", ()).await?;
    if let Some(row) = rows.next().await?
        && integer(&row, 0, "wal_checkpoint.busy")? != 0
    {
        return Err(StoreError::Busy);
    }
    Ok(())
}

/// What [`StoreHandle::pin_computed_digests`] did. `Conflict` is the STATE-01 answer:
/// this reference already means other bytes, and the new ones are refused with
/// `502 INTEGRITY_MISMATCH` rather than taking its place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinOutcome {
    Established,
    MatchedExisting,
    Conflict,
}

#[derive(Debug)]
pub enum StoreError {
    /// The queue is full, or — for a checkpoint only — the log was in use. SPEC §11
    /// maps this to `503`.
    Busy,
    /// The storage task is gone.
    Closed,
    Database(turso::Error),
    /// The database opened but does not hold what this build wrote, or never opened
    /// at all. Either way no state change depending on it may be published.
    Corrupt(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

impl From<turso::Error> for StoreError {
    fn from(err: turso::Error) -> StoreError {
        StoreError::Database(err)
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Busy => write!(f, "the storage queue is full"),
            StoreError::Closed => write!(f, "the storage task has stopped"),
            StoreError::Database(err) => write!(f, "database error: {err}"),
            StoreError::Corrupt(reason) => write!(f, "the store is unusable: {reason}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Database(err) => Some(err),
            StoreError::Busy | StoreError::Closed | StoreError::Corrupt(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::startup;

    fn document(revision: u64) -> String {
        format!(
            r#"{{"schema_version":1,"revision":{revision},"generated_at":"2026-09-16T00:00:00Z",
                 "expires_at":"2099-01-01T00:00:00Z","blocked_packages":[],"blocked_hashes":[]}}"#
        )
    }

    fn snapshot(revision: u64) -> Arc<BlocklistSnapshot> {
        let now = "2026-09-17T00:00:00Z"
            .parse::<jiff::Timestamp>()
            .expect("a test timestamp")
            .as_microsecond();
        Arc::new(
            BlocklistSnapshot::parse_and_validate(document(revision).as_bytes(), now)
                .expect("the test snapshot is valid"),
        )
    }

    /// The round trip the poller and startup depend on, and with it the answer to
    /// whether the pinned engine has the checkpoint API SPEC §10 asks for: commit,
    /// read back the exact accepted bytes, replace, and checkpoint the write-ahead log
    /// without losing any of it.
    #[tokio::test]
    async fn a_committed_blocklist_reads_back_and_survives_a_checkpoint() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let opened = startup::open_and_recover(dir.path())
            .await
            .expect("the data directory opens");
        let connection = opened.connection.expect("a fresh database recovers");
        let (store, task) = spawn(
            connection,
            opened.lock,
            Arc::new(MemoryCaches::new(1 << 20)),
        );

        assert!(
            store.load_blocklist().await.expect("a query").is_none(),
            "a fresh database has no accepted blocklist"
        );

        let first = snapshot(3);
        store
            .commit_blocklist(Arc::clone(&first))
            .await
            .expect("the commit");
        let row = store
            .load_blocklist()
            .await
            .expect("a query")
            .expect("the committed row");
        assert_eq!(row.revision, 3);
        assert_eq!(row.generated_at_micros, first.generated_at_micros);
        assert_eq!(row.expires_at_micros, first.expires_at_micros);
        assert_eq!(
            row.snapshot.as_ref(),
            first.raw.as_ref(),
            "the exact validated bytes come back, not a re-serialisation of them"
        );

        store
            .commit_blocklist(snapshot(4))
            .await
            .expect("the replacement commit");
        store.checkpoint().await.expect("the checkpoint");

        let row = store
            .load_blocklist()
            .await
            .expect("a query")
            .expect("the committed row");
        assert_eq!(
            row.revision, 4,
            "one row, replaced in place, and the checkpoint did not lose it"
        );

        // Read back through the same connection, the row is there whether or not
        // the checkpoint moved anything. The database file alone, without its log,
        // has it only if the checkpoint really did.
        let without_log = tempfile::tempdir().expect("a second data directory");
        std::fs::create_dir_all(without_log.path().join("state")).expect("a state directory");
        std::fs::copy(
            dir.path().join("state").join("firewall.db"),
            without_log.path().join("state").join("firewall.db"),
        )
        .expect("the database file alone");
        drop(store);
        task.await.expect("the storage task stops with its queues");

        let opened = startup::open_and_recover(without_log.path())
            .await
            .expect("the copy opens");
        let (copy, task) = spawn(
            opened.connection.expect("the copy recovers"),
            opened.lock,
            Arc::new(MemoryCaches::new(1 << 20)),
        );
        let row = copy
            .load_blocklist()
            .await
            .expect("a query")
            .expect("the checkpoint wrote the commit into the database file");
        assert_eq!(row.revision, 4);
        drop(copy);
        task.await.expect("the copy's storage task stops");
    }

    fn upsert() -> ReferenceUpsert {
        let reference = crate::store::rows::ArtifactReference {
            ecosystem: Ecosystem::Npm,
            name: "widget".to_owned(),
            version: "1.0.0".to_owned(),
            filename: "widget-1.0.0.tgz".to_owned(),
            upstream_url: url::Url::parse("https://npm.invalid/widget/-/widget-1.0.0.tgz")
                .expect("a test URL"),
            expected: Vec::new(),
        };
        ReferenceUpsert {
            id: ReferenceId::compute(&reference),
            reference,
            publication_micros: None,
            first_seen_micros: Some(1_000),
        }
    }

    fn refresh() -> ProjectRefresh {
        ProjectRefresh {
            ecosystem: Ecosystem::Npm,
            name: "widget".to_owned(),
            payload: Arc::from(b"{}".as_slice()),
            validators: crate::upstream::UpstreamValidators::default(),
            validated_at_micros: 1,
            fetched_at_micros: 1,
            references: vec![upsert()],
        }
    }

    /// A store over a database holding one committed, pinned reference, damaged by
    /// `corruption` while no store had it open.
    async fn damaged(dir: &std::path::Path, corruption: &str) -> (StoreHandle, JoinHandle<()>) {
        let opened = startup::open_and_recover(dir)
            .await
            .expect("the data directory");
        let (store, task) = spawn(
            opened.connection.expect("a fresh database"),
            opened.lock,
            Arc::new(MemoryCaches::new(1 << 20)),
        );
        store
            .commit_project_refresh(refresh())
            .await
            .expect("the seed");
        store
            .pin_computed_digests(upsert().id, [1; 32], [2; 64], 10)
            .await
            .expect("the pins");
        drop(store);
        task.await.expect("the first store stops");

        let opened = startup::open_and_recover(dir)
            .await
            .expect("the data directory");
        let connection = opened.connection.expect("the database reopens");
        connection
            .execute(corruption, ())
            .await
            .expect("the damage");
        spawn(
            connection,
            opened.lock,
            Arc::new(MemoryCaches::new(1 << 20)),
        )
    }

    /// A column that does not hold what this build wrote is corruption, and it is
    /// reported — never decoded as zero or as absent, which would silently reset a
    /// generation, re-grant a first-seen time, or let a pin compare equal.
    #[tokio::test]
    async fn a_damaged_column_is_reported_rather_than_reset() {
        let refreshes = [
            "UPDATE projects SET generation = 'seven'",
            "UPDATE projects SET digest_generation = -1",
            "UPDATE artifact_references SET first_seen_micros = 'yesterday'",
            "UPDATE artifact_references SET pinned_sha256 = x'0102'",
            "UPDATE artifact_references SET pinned_size = 'ten'",
            "UPDATE artifact_references SET content_key = 'not a key'",
        ];
        for corruption in refreshes {
            let dir = tempfile::tempdir().expect("a temporary data directory");
            let (store, task) = damaged(dir.path(), corruption).await;
            let outcome = store.commit_project_refresh(refresh()).await;
            assert!(
                matches!(outcome, Err(StoreError::Corrupt(_))),
                "a refresh over `{corruption}` is refused: {outcome:?}"
            );
            drop(store);
            task.await.expect("the store stops");
        }

        for corruption in [
            "UPDATE artifact_references SET pinned_size = 'ten'",
            "UPDATE artifact_references SET pinned_sha512 = x'0102'",
        ] {
            let dir = tempfile::tempdir().expect("a temporary data directory");
            let (store, task) = damaged(dir.path(), corruption).await;
            let outcome = store
                .pin_computed_digests(upsert().id, [1; 32], [2; 64], 10)
                .await;
            assert!(
                matches!(outcome, Err(StoreError::Corrupt(_))),
                "a pin check over `{corruption}` is refused: {outcome:?}"
            );
            drop(store);
            task.await.expect("the store stops");
        }
    }

    async fn fresh(dir: &std::path::Path) -> (StoreHandle, JoinHandle<()>) {
        let opened = startup::open_and_recover(dir)
            .await
            .expect("the data directory");
        spawn(
            opened.connection.expect("a fresh database"),
            opened.lock,
            Arc::new(MemoryCaches::new(1 << 20)),
        )
    }

    /// The read side of the same rule: a stored record that does not decode is
    /// reported, not reconstructed.
    #[tokio::test]
    async fn a_damaged_record_is_reported_when_it_is_read() {
        for corruption in [
            "UPDATE artifact_references SET upstream_url = 'not a url'",
            "UPDATE artifact_references SET expected = 'garbage'",
            "UPDATE artifact_references SET expected = 'md5-00'",
        ] {
            let dir = tempfile::tempdir().expect("a temporary data directory");
            let (store, task) = damaged(dir.path(), corruption).await;
            let read = store.get_reference(upsert().id).await;
            assert!(
                matches!(read, Err(StoreError::Corrupt(_))),
                "a reference read over `{corruption}` is refused: {read:?}"
            );
            drop(store);
            task.await.expect("the store stops");
        }

        let dir = tempfile::tempdir().expect("a temporary data directory");
        let (store, task) = fresh(dir.path()).await;
        store
            .commit_blocklist(snapshot(3))
            .await
            .expect("a blocklist");
        drop(store);
        task.await.expect("the store stops");
        let (store, task) = damaged(dir.path(), "UPDATE blocklist SET revision = -1").await;
        let read = store.load_blocklist().await;
        assert!(
            matches!(&read, Err(StoreError::Corrupt(reason)) if reason.contains("negative")),
            "{read:?}"
        );
        drop(store);
        task.await.expect("the store stops");
    }

    /// Values this build cannot write are refused before anything is written, and a
    /// pin for a reference that was never committed is not invented.
    #[tokio::test]
    async fn what_cannot_be_stored_is_refused() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let (store, task) = damaged(
            dir.path(),
            "UPDATE projects SET generation = 9223372036854775807",
        )
        .await;
        let refused = store.commit_project_refresh(refresh()).await;
        assert!(
            matches!(&refused, Err(StoreError::Corrupt(reason)) if reason.contains("cannot be stored")),
            "{refused:?}"
        );

        let unknown = ReferenceId::from_bytes([9; 32]);
        let refused = store
            .pin_computed_digests(unknown, [1; 32], [2; 64], 1)
            .await;
        assert!(
            matches!(refused, Err(StoreError::Corrupt(_))),
            "{refused:?}"
        );

        let refused = store.commit_blocklist(snapshot(u64::MAX)).await;
        assert!(
            matches!(&refused, Err(StoreError::Corrupt(reason)) if reason.contains("revision")),
            "{refused:?}"
        );
        drop(store);
        task.await.expect("the store stops");
    }

    /// What every store failure says, and which ones carry the engine's own error.
    #[tokio::test]
    async fn store_errors_say_what_failed() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let (store, task) = fresh(dir.path()).await;
        let mut bad = refresh();
        bad.references[0].reference.filename.clear();
        let failed = store
            .commit_project_refresh(bad)
            .await
            .expect_err("the CHECK refuses an empty filename");
        assert!(
            failed.to_string().starts_with("database error: "),
            "{failed}"
        );
        assert!(std::error::Error::source(&failed).is_some());
        drop(store);
        task.await.expect("the store stops");

        for (err, text) in [
            (StoreError::Busy, "the storage queue is full"),
            (StoreError::Closed, "the storage task has stopped"),
            (
                StoreError::Corrupt("x".to_owned()),
                "the store is unusable: x",
            ),
        ] {
            assert_eq!(err.to_string(), text);
            assert!(std::error::Error::source(&err).is_none());
        }
    }

    /// A store that never opened answers every command with its reason, on either
    /// queue, and is never healthy.
    #[tokio::test]
    async fn an_unusable_store_refuses_both_queues() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let lock = crate::store::lock::acquire(dir.path()).expect("the lock");
        let store = StoreHandle::unusable(
            "it never opened",
            lock,
            Arc::new(MemoryCaches::new(1 << 20)),
        );
        assert!(!store.is_healthy());
        assert!(matches!(
            store.load_blocklist().await,
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            store.eviction_plan().await,
            Err(StoreError::Corrupt(_))
        ));
        store.touch_content(vec![(ContentKey::from_sha256([1; 32]), 1)]);
        store.touch_content(Vec::new());
        assert_eq!(
            store.commands_issued(),
            3,
            "an empty batch of access times is not a command"
        );
    }

    /// SPEC §10: "reject overload instead of allowing unbounded waiters". With the
    /// store inside one long transaction, a burst beyond the queue depth is refused
    /// with `Busy` on the critical queue and dropped on the maintenance one — and the
    /// store answers again once the transaction ends.
    #[tokio::test]
    async fn a_full_queue_is_refused_not_waited_on() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let (store, task) = fresh(dir.path()).await;

        let mut large = refresh();
        large.references = (0..5_000)
            .map(|index| {
                let mut upsert = upsert();
                upsert.reference.version = format!("1.0.{index}");
                upsert.id = ReferenceId::compute(&upsert.reference);
                upsert
            })
            .collect();
        let busy = tokio::spawn({
            let store = store.clone();
            async move { store.commit_project_refresh(large).await }
        });
        tokio::task::yield_now().await;

        for _ in 0..(QUEUE_DEPTH * 2) {
            store.touch_content(vec![(ContentKey::from_sha256([1; 32]), 1)]);
        }
        let burst = futures_util::future::join_all(
            (0..QUEUE_DEPTH * 2).map(|_| store.get_reference(upsert().id)),
        )
        .await;
        assert!(
            burst
                .iter()
                .any(|answer| matches!(answer, Err(StoreError::Busy))),
            "some of the burst was refused rather than queued"
        );

        busy.await
            .expect("the refresh task")
            .expect("the long transaction commits");
        assert!(store.get_reference(upsert().id).await.is_ok());
        drop(store);
        task.await.expect("the store stops");
    }
}
