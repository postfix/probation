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

use crate::artifacts::content::ContentKey;
use crate::policy::{BlocklistSnapshot, Digest, Ecosystem, HashAlgorithm};
use crate::store::cache::{MemoryCaches, ProjectKey};
use crate::store::lock::DataDirLock;
use crate::store::rows::{
    BlocklistRow, Generation, ProjectRefresh, ProjectRow, ReferenceId, ReferenceRow,
    ReferenceUpsert, encode_digests,
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
    /// `/health/ready` answers with.
    healthy: Arc<AtomicBool>,
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
    /// error until one succeeds again — SPEC §10: "Storage write failures make
    /// readiness false […] until storage is usable again."
    pub fn is_healthy(&self) -> bool {
        match &self.channels {
            Channels::Live { .. } => self.healthy.load(Ordering::Relaxed),
            Channels::Unusable { .. } => false,
        }
    }

    /// One place both queues record what a command did to storage health, so a new
    /// command cannot forget to.
    fn observe<T>(&self, result: StoreResult<T>) -> StoreResult<T> {
        match &result {
            Ok(_) => self.healthy.store(true, Ordering::Relaxed),
            Err(StoreError::Database(_) | StoreError::Corrupt(_)) => {
                self.healthy.store(false, Ordering::Relaxed)
            }
            // A full queue or a stopped task is not damage to the database.
            Err(StoreError::Busy | StoreError::Closed) => {}
        }
        result
    }

    async fn critical<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<StoreResult<T>>) -> StoreCommand,
    ) -> StoreResult<T> {
        self.issued.fetch_add(1, Ordering::Relaxed);
        let result = match &self.channels {
            Channels::Live { critical, .. } => send(critical, command).await,
            Channels::Unusable { reason, .. } => Err(StoreError::Corrupt(reason.to_string())),
        };
        self.observe(result)
    }

    async fn maintenance<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<StoreResult<T>>) -> StoreCommand,
    ) -> StoreResult<T> {
        self.issued.fetch_add(1, Ordering::Relaxed);
        let result = match &self.channels {
            Channels::Live { maintenance, .. } => send(maintenance, command).await,
            Channels::Unusable { reason, .. } => Err(StoreError::Corrupt(reason.to_string())),
        };
        self.observe(result)
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
/// The task owns the data-directory lock as well as the connection, so the lock is
/// released after the connection is closed rather than before it.
pub fn spawn(
    connection: Connection,
    lock: DataDirLock,
    caches: Arc<MemoryCaches>,
) -> (StoreHandle, JoinHandle<()>) {
    let (critical_tx, critical_rx) = mpsc::channel(QUEUE_DEPTH);
    let (maintenance_tx, maintenance_rx) = mpsc::channel(QUEUE_DEPTH);

    let task = tokio::spawn(run(connection, lock, critical_rx, maintenance_rx));

    (
        StoreHandle {
            channels: Channels::Live {
                critical: critical_tx,
                maintenance: maintenance_tx,
            },
            caches,
            issued: Arc::new(AtomicU64::new(0)),
            healthy: Arc::new(AtomicBool::new(true)),
        },
        task,
    )
}

async fn run(
    mut connection: Connection,
    lock: DataDirLock,
    mut critical: mpsc::Receiver<StoreCommand>,
    mut maintenance: mpsc::Receiver<StoreCommand>,
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

        execute(&mut connection, command).await;
    }

    // Explicit, and in this order: the connection closes, and only then is the data
    // directory free for another instance to take.
    drop(connection);
    drop(lock);
}

async fn execute(connection: &mut Connection, command: StoreCommand) {
    match command {
        StoreCommand::CommitBlocklist { snapshot, reply } => {
            let _ = reply.send(commit_blocklist(connection, &snapshot).await);
        }
        StoreCommand::LoadBlocklist { reply } => {
            let _ = reply.send(load_blocklist(connection).await);
        }
        StoreCommand::GetProject {
            ecosystem,
            name,
            reply,
        } => {
            let _ = reply.send(get_project(connection, ecosystem, &name).await);
        }
        StoreCommand::CommitProjectRefresh { refresh, reply } => {
            let _ = reply.send(commit_project_refresh(connection, &refresh).await);
        }
        StoreCommand::GetReference { id, reply } => {
            let _ = reply.send(get_reference(connection, id).await);
        }
        StoreCommand::ListProjectFirstSeen {
            ecosystem,
            name,
            reply,
        } => {
            let _ = reply.send(list_project_first_seen(connection, ecosystem, &name).await);
        }
        StoreCommand::ListKnownProjects { ecosystem, reply } => {
            let _ = reply.send(list_known_projects(connection, ecosystem).await);
        }
        StoreCommand::ListProjectPins {
            ecosystem,
            name,
            reply,
        } => {
            let _ = reply.send(list_project_pins(connection, ecosystem, &name).await);
        }
        StoreCommand::PinComputedDigests {
            id,
            sha256,
            sha512,
            size,
            reply,
        } => {
            let _ = reply.send(pin_computed_digests(connection, id, sha256, sha512, size).await);
        }
        StoreCommand::PublishContent {
            key,
            sha512,
            size,
            id,
            now_micros,
            reply,
        } => {
            let _ =
                reply.send(publish_content(connection, key, sha512, size, id, now_micros).await);
        }
        StoreCommand::ClearContentKey { key, reply } => {
            let _ = reply.send(clear_content_key(connection, key).await);
        }
        StoreCommand::BumpDigestGeneration {
            ecosystem,
            name,
            reply,
        } => {
            let _ = reply.send(bump_digest_generation(connection, ecosystem, &name).await);
        }
        StoreCommand::TouchContent { keys } => {
            if let Err(err) = touch_content(connection, &keys).await {
                tracing::debug!(error = %err, "a batch of access times could not be written");
            }
        }
        StoreCommand::EvictionPlan { reply } => {
            let _ = reply.send(eviction_plan(connection).await);
        }
        StoreCommand::Checkpoint { reply } => {
            let _ = reply.send(checkpoint(connection).await);
        }
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
        let id = row
            .get_value(0)
            .ok()
            .and_then(|value| value.as_blob().cloned())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| {
                StoreError::Corrupt("artifact_references.id is not 32 bytes".to_owned())
            })?;
        let micros = row
            .get_value(1)
            .ok()
            .and_then(|value| value.as_integer().copied())
            .ok_or_else(|| {
                StoreError::Corrupt(
                    "artifact_references.first_seen_micros is not an integer".to_owned(),
                )
            })?;
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
        let blob = |index: usize| {
            row.get_value(index)
                .ok()
                .and_then(|value| value.as_blob().cloned())
        };
        let id = blob(0)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| {
                StoreError::Corrupt("artifact_references.id is not 32 bytes".to_owned())
            })?;

        let mut digests = Vec::with_capacity(2);
        for (index, algorithm) in [(1, HashAlgorithm::Sha256), (2, HashAlgorithm::Sha512)] {
            if let Some(bytes) = blob(index) {
                if bytes.len() != algorithm.digest_len() {
                    return Err(StoreError::Corrupt(format!(
                        "a pinned {algorithm} digest is {} bytes",
                        bytes.len()
                    )));
                }
                digests.push(Digest {
                    algorithm,
                    bytes: bytes.into_boxed_slice(),
                });
            }
        }
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
        let name = row
            .get_value(0)
            .ok()
            .and_then(|value| value.as_text().cloned())
            .ok_or_else(|| StoreError::Corrupt("projects.name is not text".to_owned()))?;
        names.push(name);
    }
    Ok(names)
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
/// error anywhere drops the transaction, which rolls it back, and no generation is
/// returned — so the caller has nothing to publish.
async fn commit_project_refresh(
    connection: &mut Connection,
    refresh: &ProjectRefresh,
) -> StoreResult<CommittedProject> {
    let transaction = connection.transaction().await?;

    let mut generation = Generation(1);
    let mut digest_generation = 0u64;
    {
        let mut rows = transaction
            .query(
                SELECT_PROJECT_GENERATIONS,
                (refresh.ecosystem.as_tag(), refresh.name.as_str()),
            )
            .await?;
        if let Some(row) = rows.next().await? {
            let previous = row
                .get_value(0)
                .ok()
                .and_then(|value| value.as_integer().copied())
                .unwrap_or(0);
            generation = Generation(u64::try_from(previous).unwrap_or(0).saturating_add(1));
            digest_generation = row
                .get_value(1)
                .ok()
                .and_then(|value| value.as_integer().copied())
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0);
        }
    }

    let generation_column = i64::try_from(generation.0).map_err(|_| {
        StoreError::Corrupt(format!("generation {} cannot be stored", generation.0))
    })?;
    let digest_generation_column = i64::try_from(digest_generation).map_err(|_| {
        StoreError::Corrupt(format!(
            "digest generation {digest_generation} cannot be stored"
        ))
    })?;

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
        let carried = carried_forward(&transaction, upsert).await?;
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
                    carried.pinned_sha256,
                    carried.pinned_sha512,
                    carried.pinned_size,
                    carried.content_key,
                ),
            )
            .await?;
        if let Some(micros) = carried.first_seen_micros {
            committed_first_seen.insert(upsert.id, micros);
        }
    }

    transaction.commit().await?;
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
    pinned_sha256: Option<Vec<u8>>,
    pinned_sha512: Option<Vec<u8>>,
    pinned_size: Option<i64>,
    content_key: Option<Vec<u8>>,
}

async fn carried_forward(
    transaction: &turso::transaction::Transaction<'_>,
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

    let integer = |index: usize| {
        row.get_value(index)
            .ok()
            .and_then(|value| value.as_integer().copied())
    };
    let blob = |index: usize| {
        row.get_value(index)
            .ok()
            .and_then(|value| value.as_blob().cloned())
    };

    Ok(Carried {
        first_seen_micros: integer(0).or(upsert.first_seen_micros),
        pinned_sha256: blob(1),
        pinned_sha512: blob(2),
        pinned_size: integer(3),
        content_key: blob(4),
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

    let established = {
        let mut rows = transaction
            .query(SELECT_REFERENCE_PINS, (id.as_bytes().to_vec(),))
            .await?;
        match rows.next().await? {
            Some(row) => {
                let pinned_sha256 = row
                    .get_value(0)
                    .ok()
                    .and_then(|value| value.as_blob().cloned());
                let pinned_sha512 = row
                    .get_value(1)
                    .ok()
                    .and_then(|value| value.as_blob().cloned());
                let pinned_size = row
                    .get_value(2)
                    .ok()
                    .and_then(|value| value.as_integer().copied());
                pinned_sha256.map(|first| (first, pinned_sha512, pinned_size))
            }
            None => {
                return Err(StoreError::Corrupt(format!(
                    "no artifact reference {} to pin digests on",
                    id.to_hex()
                )));
            }
        }
    };

    if let Some((pinned_sha256, pinned_sha512, pinned_size)) = established {
        // A pin is permanent. Nothing below writes; the transaction is dropped and
        // rolled back either way.
        let matches = pinned_sha256.as_slice() == sha256.as_slice()
            && pinned_sha512.is_none_or(|stored| stored.as_slice() == sha512.as_slice())
            && pinned_size.is_none_or(|stored| u64::try_from(stored).is_ok_and(|s| s == size));
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
    transaction.commit().await?;
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
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn clear_content_key(connection: &mut Connection, key: ContentKey) -> StoreResult<()> {
    let transaction = connection.transaction().await?;
    transaction
        .execute(CLEAR_REFERENCE_CONTENT, (key.as_bytes().to_vec(),))
        .await?;
    transaction
        .execute(DELETE_CONTENT, (key.as_bytes().to_vec(),))
        .await?;
    transaction.commit().await?;
    Ok(())
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
    transaction
        .execute(
            UPSERT_BLOCKLIST,
            (
                revision,
                snapshot.generated_at_micros,
                snapshot.expires_at_micros,
                snapshot.raw.to_vec(),
            ),
        )
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn load_blocklist(connection: &mut Connection) -> StoreResult<Option<BlocklistRow>> {
    let mut rows = connection.query(SELECT_BLOCKLIST, ()).await?;
    match rows.next().await? {
        Some(row) => BlocklistRow::from_row(&row).map(Some),
        None => Ok(None),
    }
}

async fn touch_content(connection: &mut Connection, keys: &[(ContentKey, i64)]) -> StoreResult<()> {
    let transaction = connection.transaction().await?;
    for (key, micros) in keys {
        transaction
            .execute(TOUCH_CONTENT, (key.as_bytes().to_vec(), *micros))
            .await?;
    }
    transaction.commit().await?;
    Ok(())
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
        let key = row
            .get_value(0)
            .ok()
            .and_then(|value| value.as_blob().cloned())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| StoreError::Corrupt("content.key is not 32 bytes".to_owned()))?;
        let size = row
            .get_value(1)
            .ok()
            .and_then(|value| value.as_integer().copied())
            .and_then(|size| u64::try_from(size).ok())
            .ok_or_else(|| StoreError::Corrupt("content.size is not a size".to_owned()))?;
        plan.total_bytes = plan.total_bytes.saturating_add(size);
        plan.oldest_first.push((ContentKey::from_sha256(key), size));
    }
    Ok(plan)
}

async fn checkpoint(connection: &mut Connection) -> StoreResult<()> {
    // The pinned engine's supported API: `PRAGMA wal_checkpoint` answers
    // (busy, log, checkpointed). A busy checkpoint is not an error — it means a
    // reader held the log and the next pass will take it.
    let mut rows = connection.query("PRAGMA wal_checkpoint", ()).await?;
    if let Some(row) = rows.next().await?
        && let Ok(busy) = row.get_value(0)
        && busy.as_integer().copied() != Some(0)
    {
        tracing::debug!("the write-ahead log was busy; the checkpoint will be retried");
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
    /// The queue is full. SPEC §11 maps this to `503`.
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

        drop(store);
        task.await.expect("the storage task stops with its queues");
    }
}
