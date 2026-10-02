//! The injectable application.
//!
//! `App::start` is the single constructor seam: tests build an `AppDeps` with their
//! own implementations and never spawn the binary, and the binary is the only place
//! the production implementations are named.

pub mod artifacts;
pub mod clock;
pub mod concurrency;
pub mod config;
/// Where a decision record goes once it exists. Crate-internal: this feature adds no
/// public Rust surface.
pub(crate) mod delivery;
pub mod http;
pub mod npm;
pub mod osv;
pub mod policy;
pub mod pypi;
pub mod store;
pub mod tasks;
pub mod upstream;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::artifacts::content::ContentStore;
use crate::artifacts::download::DownloadCoordinator;
use crate::clock::Clock;
use crate::config::Config;
use crate::http::limits::Limits;
use crate::policy::BlocklistSnapshot;
use crate::store::StoreHandle;
use crate::store::cache::MemoryCaches;
use crate::tasks::Tasks;
use crate::tasks::blocklist_poller::{self, Watcher};
use crate::upstream::{OriginSet, Transport};

/// Everything the application is handed from outside. The transport and the origin
/// set are constructor-injected for the same reason the clock is (SPEC §13, finding
/// TEST-01): a test supplies its own, and there is no other way in — no
/// configuration key, flag or environment variable reaches either one.
pub struct AppDeps {
    pub config: Config,
    pub clock: Arc<dyn Clock>,
    pub transport: Arc<dyn Transport>,
    pub origins: OriginSet,
    /// The HTTP client `App::start` builds `osv::OsvClient` from (D3): production
    /// hands in a real `reqwest::Client`, and a test hands in one built with
    /// `.resolve("api.osv.dev", <address nothing listens on>)`, so the fixed OSV
    /// endpoint address OSV's batcher always targets resolves to an immediate,
    /// local, deterministic connection refusal instead of a real socket — see
    /// `osv::tests::offline_osv_client` for the exact construction. `App::start`,
    /// not `AppDeps`'s caller, is the one and only place `osv::OsvClient::new` is
    /// called: it needs `drain`, the `CancellationToken` `App::start` creates for
    /// exactly this purpose (mirroring `delivery::build`'s own use of it), which
    /// does not exist yet at the point an `AppDeps` is built.
    pub osv_client: reqwest::Client,
    /// Where the OSV batcher sends its `POST /v1/querybatch` calls. `None` in
    /// production and in every test that only needs OSV out of the way
    /// (`osv::unreachable_client()`'s fail-open path): `App::start` then pins it to
    /// the real, fixed endpoint (D4). A test that needs OSV to actually answer
    /// something — a match, not just a refusal — sets this to a local server's URL
    /// instead, alongside a plain `osv_client`.
    pub osv_base_url: Option<url::Url>,
}

/// The shared state every handler sees.
pub struct App {
    pub config: Config,
    pub clock: Arc<dyn Clock>,
    /// The only way this process reaches a registry.
    pub transport: Arc<dyn Transport>,
    /// The origins that transport is allowed to reach, and the URL builder for them.
    pub origins: OriginSet,
    /// The publication point (SPEC §10: "Immutable policy snapshots can use
    /// `ArcSwap`"). SPEC §9 names `blocklist()` as the ordering point of the
    /// revocation boundary: a request that loads after a publish must see it.
    ///
    /// Gate 3 gives these three operations their own `PolicyHandle` type in
    /// `src/policy/blocklist.rs`. They live here until the slice that owns that file
    /// again can lift them out; the seam is the same either way, because every
    /// reader and the one writer already go through these methods.
    policy: ArcSwapOption<BlocklistSnapshot>,
    store: StoreHandle,
    /// Verified artifact bytes on disk (SPEC §9, §10).
    pub content: ContentStore,
    /// One upstream transfer per reference, however many requests want it
    /// (SPEC §9, FLOW-01).
    pub downloads: DownloadCoordinator,
    /// The bounded work SPEC §10 requires: active requests, artifact downloads, and
    /// the two response deadlines.
    pub limits: Limits,
    /// The destinations a copy of each decision record is offered to. Empty unless
    /// an operator configured one.
    pub(crate) delivery: delivery::Sinks,
    /// OSV vulnerability intelligence (D3). Private, matching `policy`/`store`'s
    /// privacy: reached only through `osv::evaluate` call sites that already hold
    /// `&App`.
    osv: osv::OsvClient,
}

impl App {
    /// The blocklist currently in force, whether or not it is still valid. Callers
    /// that judge a package go through `policy::evaluate`, which checks the window
    /// against the same `now` it decides with.
    pub fn blocklist(&self) -> Option<Arc<BlocklistSnapshot>> {
        self.policy.load_full()
    }

    /// Makes `snapshot` the one in force for every request that loads it from here
    /// on. Called only after the snapshot has been committed (SPEC §10).
    pub fn publish_blocklist(&self, snapshot: Arc<BlocklistSnapshot>) {
        self.policy.store(Some(snapshot));
    }

    pub fn blocklist_revision(&self) -> Option<u64> {
        self.policy
            .load()
            .as_ref()
            .map(|snapshot| snapshot.revision)
    }

    pub fn store(&self) -> &StoreHandle {
        &self.store
    }

    /// Whether decision-log delivery has any sink at all. **Compiled only under
    /// `test-support`.**
    ///
    /// Same reasoning as `Limits::set_response_timeouts`: the "an operator who
    /// configures nothing opens nothing" promise has to be readable by a witness,
    /// and `Sinks` is crate-internal precisely so that a consumer of this crate
    /// cannot reach the delivery path.
    #[cfg(feature = "test-support")]
    pub fn delivery_is_empty(&self) -> bool {
        self.delivery.is_empty()
    }

    /// Every decision record a sink has lost since the process started. Unlike the
    /// summary's per-window counts, nothing resets it.
    #[cfg(feature = "test-support")]
    pub fn delivery_lost_total(&self) -> u64 {
        self.delivery.lost_total()
    }

    /// Binds the configured address and starts serving. Returns once the listener
    /// is bound, so a caller can read the bound port before the first request.
    ///
    /// The order is SPEC §10's: take the exclusive data-directory lock and recover
    /// the database, publish a persisted blocklist that is still valid, read the
    /// blocklist file once, and only then accept a request. A database that cannot
    /// be recovered is not a reason to refuse to start — it is a reason to start with
    /// readiness false, which is the only way to say so.
    pub async fn start(deps: AppDeps) -> Result<Running, StartupError> {
        let opened = store::startup::open_and_recover(&deps.config.data_dir)
            .await
            .map_err(StartupError::DataDir)?;

        // SPEC §4's `memory_cache_max_bytes`. The caches travel with the store
        // handle, because they exist to keep callers from reaching its queues.
        let caches = Arc::new(MemoryCaches::new(deps.config.memory_cache_max_bytes.get()));

        let (store, store_task) = match opened.connection {
            Ok(connection) => {
                let (store, task) = store::spawn(connection, opened.lock, Arc::clone(&caches));
                (store, Some(task))
            }
            Err(err) => (
                StoreHandle::unusable(err.to_string(), opened.lock, caches),
                None,
            ),
        };

        // SPEC §10: "On startup […] remove incomplete artifact temporary files." A
        // crash must never leave one where a later request could find it.
        let content = ContentStore::new(&deps.config.data_dir, deps.config.cache_max_bytes.get());
        content.remove_temp_files();
        let limits = Limits::new(&deps.config);

        // The drain token is not the shutdown token: the sinks must outlive the
        // requests that are still being answered when shutdown begins. The osv
        // batcher is spawned with this same token, following the delivery sinks'
        // own pattern exactly (D3) — it is available here, well before `shutdown`
        // exists below, which is why this (and not `AppDeps`'s caller) is the one
        // place `osv::OsvClient::new` is called.
        let drain = CancellationToken::new();
        let (delivery, mut delivery_tasks) = delivery::build(&deps.config, drain.clone())?;
        let osv_cache_ttl = std::time::Duration::from_secs(deps.config.osv_cache_ttl_seconds.get());
        let osv_request_timeout =
            std::time::Duration::from_millis(deps.config.osv_request_timeout_ms.get());
        let (osv, osv_task) = match deps.osv_base_url {
            Some(url) => osv::OsvClient::spawn_with(
                deps.osv_client,
                url,
                osv_cache_ttl,
                osv_request_timeout,
                deps.config.osv_mode,
                drain.clone(),
            ),
            None => osv::OsvClient::new(
                deps.osv_client,
                osv_cache_ttl,
                osv_request_timeout,
                deps.config.osv_mode,
                drain.clone(),
            ),
        };
        delivery_tasks.push(osv_task);

        let app = Arc::new(App {
            config: deps.config,
            clock: deps.clock,
            transport: deps.transport,
            origins: deps.origins,
            policy: ArcSwapOption::empty(),
            store,
            content,
            downloads: DownloadCoordinator::new(),
            limits,
            delivery,
            osv,
        });

        restore_blocklist(&app).await;

        // One pass before the listener accepts anything, so an instance with a valid
        // blocklist file is ready on its first request rather than one poll interval
        // later. The poll loop continues from the state this pass leaves behind.
        let mut watcher = Watcher::new();
        blocklist_poller::poll_once(&app, &mut watcher).await;

        let addr = app.config.listen;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| StartupError::Bind { addr, source })?;
        let local_addr = listener.local_addr().map_err(StartupError::Serve)?;

        let shutdown = CancellationToken::new();
        let tasks = tasks::spawn(Arc::clone(&app), shutdown.clone(), watcher, delivery_tasks);

        let signal = shutdown.clone();
        let server = tokio::spawn({
            let app = Arc::clone(&app);
            async move {
                // `into_make_service_with_connect_info` changes the service type, so
                // each arm owns its whole expression rather than assigning to one
                // variable. The peer address is offered to the router only when an
                // operator has asked for it to be recorded.
                let consumer_identification = app.config.log_consumer_identification;
                let router = http::router(app);
                if consumer_identification {
                    axum::serve(
                        listener,
                        router.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(async move { signal.cancelled().await })
                    .await
                } else {
                    axum::serve(listener, router)
                        .with_graceful_shutdown(async move { signal.cancelled().await })
                        .await
                }
            }
        });

        Ok(Running {
            local_addr,
            app,
            shutdown,
            drain,
            server,
            tasks,
            store_task,
        })
    }
}

/// Publishes the last accepted snapshot when it is still valid (SPEC §8: "Persist
/// the last accepted snapshot so restart can use it while still valid").
///
/// The stored bytes are re-validated rather than trusted: they are validated against
/// *this* `now`, which is what decides that a snapshot persisted yesterday has since
/// expired, and against this build's rules, which is what a schema or rule change
/// between releases would otherwise walk straight past.
async fn restore_blocklist(app: &App) {
    let row = match app.store().load_blocklist().await {
        Ok(Some(row)) => row,
        Ok(None) => return,
        Err(err) => {
            tracing::error!(
                error = %err,
                "the persisted blocklist could not be read; readiness stays false until a \
                 current blocklist is loaded"
            );
            return;
        }
    };

    let now = app.clock.now_utc_micros();
    match BlocklistSnapshot::parse_and_validate(&row.snapshot, now) {
        Ok(snapshot) => {
            tracing::info!(
                revision = snapshot.revision,
                entries = snapshot.entry_count(),
                "the persisted blocklist is still valid and is back in force"
            );
            app.publish_blocklist(Arc::new(snapshot));
        }
        Err(err) => tracing::warn!(
            revision = row.revision,
            error = %err,
            "the persisted blocklist is no longer usable; readiness stays false until a \
             current blocklist is loaded"
        ),
    }
}

/// A started server.
pub struct Running {
    pub local_addr: SocketAddr,
    app: Arc<App>,
    shutdown: CancellationToken,
    /// Cancelled only after the HTTP server has joined, so a sink still delivers the
    /// records of the requests that were in flight when shutdown began.
    drain: CancellationToken,
    server: JoinHandle<std::io::Result<()>>,
    tasks: Tasks,
    /// `None` when the database could not be recovered, so there is no task to wait
    /// for and every store command answers with the reason instead.
    store_task: Option<JoinHandle<()>>,
}

impl Running {
    /// The application this server is running. Tests that assert on state the HTTP
    /// surface does not expose — how many storage commands a request issued, say —
    /// read it from here rather than from a back door in the application itself.
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    /// How many background loops this server is running. **Compiled only under
    /// `test-support`.**
    #[cfg(feature = "test-support")]
    pub fn background_task_count(&self) -> usize {
        self.tasks.count()
    }

    /// Asks the server to stop accepting and waits for in-flight requests to finish.
    ///
    /// Then, in order: the background loops leave the pass they are in, the last
    /// `App` is dropped so the storage queues close, and the storage task finishes
    /// its current command before it closes the connection and releases the lock.
    pub async fn shutdown(self) -> Result<(), StartupError> {
        self.shutdown.cancel();
        let served = match self.server.await {
            Ok(result) => result.map_err(StartupError::Serve),
            // The task is only ever cancelled by the runtime shutting down, which
            // means the process is going away anyway.
            Err(_) => Ok(()),
        };

        // No further records can be produced now that the server has joined, so the
        // window is closed and queued before the sinks are told to finish.
        http::logging::flush_summary(&self.app.delivery, self.app.clock.as_ref());
        self.drain.cancel();

        self.tasks.join().await;
        // The only window in which every sink has finished and `App` still exists.
        http::logging::flush_drop_tail(&self.app.delivery);
        drop(self.app);
        if let Some(task) = self.store_task {
            let _ = task.await;
        }

        served
    }
}

#[derive(Debug)]
pub enum StartupError {
    /// The data directory cannot be created, or another instance holds its lock.
    /// Unlike a database that will not recover, there is nothing left to run.
    DataDir(store::startup::StartupError),
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    Serve(std::io::Error),
    /// Decision-log delivery could not be set up. The text is a fixed `&'static str`
    /// on purpose: it is printed by `check_config` (`src/main.rs`) and by the startup
    /// log, and the rejection it most often reports is a malformed `PROBATION_SIEM_AUTH`.
    /// Nothing that could carry part of that value can be put here.
    Delivery(&'static str),
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::DataDir(err) => write!(f, "{err}"),
            StartupError::Bind { addr, source } => write!(f, "cannot bind {addr}: {source}"),
            StartupError::Serve(source) => write!(f, "server stopped: {source}"),
            StartupError::Delivery(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartupError::DataDir(err) => Some(err),
            StartupError::Bind { source, .. } | StartupError::Serve(source) => Some(source),
            StartupError::Delivery(_) => None,
        }
    }
}
