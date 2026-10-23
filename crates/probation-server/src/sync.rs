//! What firewalls fetch: `lookup`, `layers` and `changes` under a firewall token
//! (02-architecture.md § Endpoints), and the change log every state change a firewall
//! caches is written to (02 § Change propagation).

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use ipnet::IpNet;
use probation_policy::api::{
    ChainLink, ChangesRequest, ChangesResponse, KeyHash, KeyId, KeyLookup, KeyLookupRequest,
    LayersRequest, LayersResponse, LimitChange, LimitSource, LockRange, OrgId, PlaceLayer,
    SettingsPush,
};
use probation_policy::{LayerKind, PlaceRef};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::policy::{StoreError, load_layer};
use crate::tenancy::{Actor, PLATFORM, kind_of, kind_str};

/// Requests a second one firewall token may make to this server copy (T31): above the
/// firewall's lookup budget of 50.
pub const FIREWALL_TOKEN_RATE_PER_SECOND: usize = 200;

/// The biggest sync body (02 § Endpoints).
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// The most places one `layers` call may name.
pub const MAX_LAYER_PLACES: usize = 1_000;

/// The most activity events, and `activity_dropped` entries, one `changes` call may
/// carry: the firewall's `ACTIVITY_BATCH_MAX` (02 § Endpoints).
pub const MAX_ACTIVITY_ENTRIES: usize = 1_000;

/// The longest `last_apply_error` a report may carry.
pub const MAX_APPLY_ERROR_BYTES: usize = 2 * 1024;

/// The kinds of `change_log` row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChangeKind {
    Key,
    Layer,
    Place,
    Limits,
    Ranges,
    Settings,
    Firewall,
}

impl ChangeKind {
    const fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Key => "key",
            ChangeKind::Layer => "layer",
            ChangeKind::Place => "place",
            ChangeKind::Limits => "limits",
            ChangeKind::Ranges => "ranges",
            ChangeKind::Settings => "settings",
            ChangeKind::Firewall => "firewall",
        }
    }
}

/// Appends one `change_log` row in the caller's transaction and returns its revision.
/// The revision comes from the locked counter row, so a second writer waits for the
/// first to commit and revisions become visible in commit order (T7).
pub async fn record_change(
    conn: &mut PgConnection,
    kind: ChangeKind,
    subject: &impl Serialize,
) -> Result<i64, sqlx::Error> {
    let revision: i64 = sqlx::query_scalar(
        "UPDATE change_counter SET value = value + 1 WHERE id = 1 RETURNING value",
    )
    .fetch_one(&mut *conn)
    .await?;
    sqlx::query("INSERT INTO change_log (revision, kind, subject) VALUES ($1, $2, $3)")
        .bind(revision)
        .bind(kind.as_str())
        .bind(serde_json::to_value(subject).expect("a change subject encodes"))
        .execute(&mut *conn)
        .await?;
    Ok(revision)
}

/// Deletes `change_log` rows older than `retention_days` and raises `pruned_through` to
/// the highest deleted revision in the same transaction, so `changes` resets a firewall
/// whose cursor is below it even once the log is empty.
pub async fn prune_change_log(pool: &PgPool, retention_days: u32) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let pruned: Option<i64> = sqlx::query_scalar(
        "WITH gone AS (
             DELETE FROM change_log WHERE at < now() - make_interval(days => $1) RETURNING revision
         )
         SELECT max(revision) FROM gone",
    )
    .bind(retention_days as i32)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(pruned) = pruned {
        sqlx::query(
            "UPDATE change_counter SET pruned_through = GREATEST(pruned_through, $1) WHERE id = 1",
        )
        .bind(pruned)
        .execute(&mut *tx)
        .await?;
    }
    let () = tx.commit().await?;
    Ok(())
}

/// `change_counter` before and after `after_restore`: (value, pruned_through).
#[derive(Debug)]
pub struct Raised {
    pub before: (i64, i64),
    pub after: i64,
}

/// `admin after-restore` (C129): after the database was restored from a backup, sets
/// `value := greatest(value, now in microseconds since the Unix epoch) + 1`, then
/// `pruned_through := value`, in one transaction with an audit row. Both then lie above
/// every revision issued before the restore, so every firewall's cursor is below
/// `pruned_through` (or above `value`) and it resets at its next sync, missing nothing.
/// The clock is the database's (`clock_timestamp()`); it must never step backwards
/// across runs, and fewer than one change a microsecond keeps the counter from running
/// ahead of it. Neither number ever goes down. It also moves the settings rollouts' id
/// sequence a million past the highest id it or the table holds, so a rollout created
/// after the restore never reuses an id a firewall still reports as applied.
pub async fn after_restore(pool: &PgPool) -> Result<Raised, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let before: (i64, i64) =
        sqlx::query_as("SELECT value, pruned_through FROM change_counter WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    let after: i64 = sqlx::query_scalar(
        "UPDATE change_counter
         SET value = greatest(value, floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint) + 1
         WHERE id = 1 RETURNING value",
    )
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE change_counter SET pruned_through = value WHERE id = 1")
        .execute(&mut *tx)
        .await?;
    // A firewall reports the id of the last settings rollout it applied, which may be one
    // the restore lost; new rollouts start a million ids further, so none takes it.
    let rollouts_from: i64 = sqlx::query_scalar(
        "SELECT setval('settings_rollouts_id_seq',
                       greatest((SELECT last_value FROM settings_rollouts_id_seq),
                                (SELECT coalesce(max(id), 0) FROM settings_rollouts)) + 1000000)",
    )
    .fetch_one(&mut *tx)
    .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &Actor::Operator,
            org_id: None,
            action: "admin.after_restore",
            subject: "change_counter".to_owned(),
            before: Some(serde_json::json!({"value": before.0, "pruned_through": before.1})),
            after: Some(serde_json::json!({
                "value": after,
                "pruned_through": after,
                "settings_rollouts_id_after": rollouts_from,
            })),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(Raised { before, after })
}

pub struct SyncState {
    pool: PgPool,
    trusted_proxies: Vec<IpNet>,
    /// Each firewall's requests in the last second.
    recent: Mutex<HashMap<i32, VecDeque<Instant>>>,
}

impl SyncState {
    pub fn new(pool: PgPool, trusted_proxies: Vec<IpNet>) -> SyncState {
        SyncState {
            pool,
            trusted_proxies,
            recent: Mutex::new(HashMap::new()),
        }
    }

    /// The firewall a sync request comes from: a live `fwt_` token (401 otherwise),
    /// from one of its `allowed_source_cidrs` (403 `FIREWALL_SOURCE_REFUSED`), within its
    /// rate (429).
    async fn firewall(&self, headers: &HeaderMap, peer: IpAddr) -> Result<i32, SyncError> {
        let token = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| token.starts_with("fwt_"))
            .ok_or(SyncError::Unauthenticated)?;
        let found: Option<(i32, Vec<IpNet>)> = sqlx::query_as(
            "SELECT f.id, f.allowed_source_cidrs::inet[] FROM keys AS k
             JOIN firewalls AS f ON f.token_key_id = k.id
             WHERE k.hash = $1 AND k.kind = 'firewall' AND k.revoked_at IS NULL
               AND f.retired_at IS NULL",
        )
        .bind(KeyHash::of(token).0.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        let (firewall, allowed) = found.ok_or(SyncError::Unauthenticated)?;
        let source = source_address(peer, headers, &self.trusted_proxies);
        if !source.is_some_and(|source| allowed.iter().any(|range| range.contains(&source))) {
            return Err(SyncError::SourceRefused);
        }
        if !self.within_rate(firewall) {
            return Err(SyncError::TooManyRequests);
        }
        Ok(firewall)
    }

    /// The app role's pool, for the routes served beside the sync API.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn within_rate(&self, firewall: i32) -> bool {
        let now = Instant::now();
        let mut recent = self
            .recent
            .lock()
            .expect("the rate table is never poisoned");
        let window = recent.entry(firewall).or_default();
        while window
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(1))
        {
            window.pop_front();
        }
        if window.len() >= FIREWALL_TOKEN_RATE_PER_SECOND {
            return false;
        }
        window.push_back(now);
        true
    }
}

/// The firewall's address: the peer, or behind a load balancer in `trusted_proxies` the
/// rightmost `X-Forwarded-For` entry not in it, every header line read in order and
/// joined, as the firewall does for clients (C113). `None` when that entry is not an
/// address.
fn source_address(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> Option<IpAddr> {
    let peer = peer.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|range| range.contains(ip));
    if !is_trusted(&peer) {
        return Some(peer);
    }
    let mut lines = Vec::new();
    for line in headers.get_all("x-forwarded-for") {
        lines.push(line.to_str().ok()?);
    }
    let joined = lines.join(",");
    for entry in joined
        .rsplit(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let ip = forwarded_ip(entry)?.to_canonical();
        if !is_trusted(&ip) {
            return Some(ip);
        }
    }
    Some(peer)
}

/// The address of one `X-Forwarded-For` entry: a bare address, `ip:port`, `[v6]` or
/// `[v6]:port`, as proxies write them. `None` for anything else, `unknown` included.
pub(crate) fn forwarded_ip(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    let bracketed = entry.strip_prefix('[')?.strip_suffix(']')?;
    bracketed.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
}

#[derive(Debug)]
pub enum SyncError {
    Unauthenticated,
    SourceRefused,
    TooManyRequests,
    TooLarge,
    Unprocessable,
    Store(sqlx::Error),
}

impl From<sqlx::Error> for SyncError {
    fn from(err: sqlx::Error) -> Self {
        // Class 22, a data exception: a value the firewall sent that Postgres cannot
        // take, such as an `eligible_at` that is no timestamp.
        let data = err
            .as_database_error()
            .and_then(|err| err.code())
            .is_some_and(|code| code.starts_with("22"));
        if data {
            SyncError::Unprocessable
        } else {
            SyncError::Store(err)
        }
    }
}

impl From<StoreError> for SyncError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::Db(err) => SyncError::Store(err),
            StoreError::MissingLayer(place) => {
                tracing::error!(?place, "a place in the store has no layer row");
                SyncError::Store(sqlx::Error::RowNotFound)
            }
        }
    }
}

impl IntoResponse for SyncError {
    fn into_response(self) -> Response {
        match self {
            SyncError::Unauthenticated => StatusCode::UNAUTHORIZED.into_response(),
            SyncError::SourceRefused => (
                StatusCode::FORBIDDEN,
                [(
                    "x-probation-error",
                    HeaderValue::from_static("FIREWALL_SOURCE_REFUSED"),
                )],
            )
                .into_response(),
            SyncError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS.into_response(),
            SyncError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            SyncError::Unprocessable => StatusCode::UNPROCESSABLE_ENTITY.into_response(),
            SyncError::Store(err) => {
                tracing::error!(error = %err, "sync request failed in the store");
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        }
    }
}

pub fn router(state: Arc<SyncState>) -> Router {
    Router::new()
        .route("/api/v1/sync/lookup", post(lookup))
        .route("/api/v1/sync/layers", post(layers))
        .route("/api/v1/sync/changes", post(changes))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, SyncError> {
    serde_json::from_slice(body).map_err(|_| SyncError::Unprocessable)
}

/// One read-only `REPEATABLE READ` snapshot, its change-log revision read first, so an
/// answer's revision and its data agree (02 § Endpoints).
async fn snapshot(
    pool: &PgPool,
) -> Result<(sqlx::Transaction<'static, sqlx::Postgres>, u64), sqlx::Error> {
    let mut tx = pool
        .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await?;
    let revision: i64 = sqlx::query_scalar("SELECT value FROM change_counter WHERE id = 1")
        .fetch_one(&mut *tx)
        .await?;
    Ok((tx, revision as u64))
}

async fn lookup(
    State(state): State<Arc<SyncState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<KeyLookup>, SyncError> {
    state.firewall(&headers, peer.ip()).await?;
    let asked: KeyLookupRequest = parse(&body)?;
    let (mut tx, revision) = snapshot(&state.pool).await?;
    let answer = look_up(&mut tx, asked.key_hash, revision).await?;
    let () = tx.commit().await?;
    Ok(Json(answer))
}

async fn layers(
    State(state): State<Arc<SyncState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<LayersResponse>, SyncError> {
    state.firewall(&headers, peer.ip()).await?;
    let asked: LayersRequest = parse(&body)?;
    if asked.places.len() > MAX_LAYER_PLACES {
        return Err(SyncError::TooLarge);
    }
    let (mut tx, revision) = snapshot(&state.pool).await?;
    let mut layers = Vec::with_capacity(asked.places.len());
    for place in asked.places {
        if let Some((layer, revision)) = load_layer(&mut tx, place).await? {
            layers.push(PlaceLayer {
                place,
                layer,
                revision,
            });
        }
    }
    let () = tx.commit().await?;
    Ok(Json(LayersResponse { layers, revision }))
}

async fn changes(
    State(state): State<Arc<SyncState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ChangesResponse>, SyncError> {
    let firewall = state.firewall(&headers, peer.ip()).await?;
    let asked: ChangesRequest = parse(&body)?;
    let too_long = |error: &String| error.len() > MAX_APPLY_ERROR_BYTES;
    if asked.activity.len() > MAX_ACTIVITY_ENTRIES
        || asked.activity_dropped.len() > MAX_ACTIVITY_ENTRIES
        || asked.report.last_apply_error.as_ref().is_some_and(too_long)
    {
        return Err(SyncError::TooLarge);
    }
    // Every revision the server hands out is a Postgres bigint; only a cursor that
    // cannot be one is refused (C126).
    if asked.since > i64::MAX as u64 {
        return Err(SyncError::Unprocessable);
    }
    let () = record_report(&state.pool, firewall, &asked).await?;
    let (mut tx, revision) = snapshot(&state.pool).await?;
    let answer = delta(&mut tx, firewall, &asked, revision).await?;
    let () = tx.commit().await?;
    Ok(Json(answer))
}

/// The firewall's check-in and its activity, in one transaction. Each event is stored
/// under its key's place, whatever place the firewall named (T9, T18); an event for no
/// known API key is not stored, and a batch sent again is not duplicated. It never
/// touches the change counter (C126).
async fn record_report(
    pool: &PgPool,
    firewall: i32,
    asked: &ChangesRequest,
) -> Result<(), SyncError> {
    let mut tx = pool.begin().await?;
    crate::fleet::settle(&mut tx, firewall, &asked.report).await?;
    let report = serde_json::json!({
        "report": asked.report,
        "activity_dropped": asked.activity_dropped,
    });
    sqlx::query("UPDATE firewalls SET last_seen_at = now(), last_report = $2 WHERE id = $1")
        .bind(firewall)
        .bind(report)
        .execute(&mut *tx)
        .await?;
    let word = |value: serde_json::Value| value.as_str().map(str::to_owned);
    let events = &asked.activity;
    sqlx::query(
        "INSERT INTO activity (event_id, at, firewall_id, place_kind, place_id, key_id, layer,
                               ecosystem, package, version, result, rule, client_ip, eligible_at)
         SELECT e.event_id,
                -- The firewall's time, within [now - activity retention, now] (S4-11).
                LEAST(now(), GREATEST(COALESCE(e.at::timestamptz, now()),
                    now() - make_interval(days => COALESCE(
                        (SELECT o.activity_retention_days FROM orgs AS o
                         WHERE o.id = place_org(k.place_kind, k.place_id)),
                        (SELECT p.activity_retention_days FROM platform_settings AS p
                         WHERE p.id = 1))))),
                $1, k.place_kind, k.place_id, k.id, e.layer,
                e.ecosystem, e.package, e.version, e.result, e.rule,
                CASE WHEN e.result = 'refused_network' THEN e.client_ip END,
                e.eligible_at::timestamptz
         FROM unnest($2::text[], $3::bigint[], $4::text[], $5::text[], $6::text[], $7::text[],
                     $8::text[], $9::text[], $10::inet[], $11::text[], $12::text[])
              AS e(event_id, key_id, layer, ecosystem, package, version, result, rule, client_ip,
                   eligible_at, at)
         JOIN keys AS k ON k.id = e.key_id AND k.kind IN ('user', 'service')
         ON CONFLICT (firewall_id, event_id) DO NOTHING",
    )
    .bind(firewall)
    .bind(
        events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| event.key_id.0 as i64)
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| word(serde_json::to_value(event.layer).expect("a layer encodes")))
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| event.ecosystem.map(|ecosystem| ecosystem.as_tag()))
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| event.package.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| event.version.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| word(serde_json::to_value(event.result).expect("a result encodes")))
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| event.rule.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| event.client_ip)
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|event| event.eligible_at.clone())
            .collect::<Vec<_>>(),
    )
    // Parsed here, so a time that is no RFC 3339 falls back to now instead of failing
    // the batch; what goes to Postgres is jiff's own rendering.
    .bind(
        events
            .iter()
            .map(|event| {
                let at = event.at.as_deref()?.parse::<jiff::Timestamp>().ok()?;
                Some(at.to_string())
            })
            .collect::<Vec<_>>(),
    )
    .execute(&mut *tx)
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// What changed after `asked.since`, read at `revision`. A cursor below
/// `pruned_through`, or above the log (a database restored from a backup), is answered
/// with a reset at the server's current revision: only that firewall resets (C126).
async fn delta(
    conn: &mut PgConnection,
    firewall: i32,
    asked: &ChangesRequest,
    revision: u64,
) -> Result<ChangesResponse, SyncError> {
    let pruned_through: i64 =
        sqlx::query_scalar("SELECT pruned_through FROM change_counter WHERE id = 1")
            .fetch_one(&mut *conn)
            .await?;
    let settings: (i64, String) =
        sqlx::query_as("SELECT settings_revision, settings_toml FROM firewalls WHERE id = $1")
            .bind(firewall)
            .fetch_one(&mut *conn)
            .await?;
    let settings = (settings.0 != 0 && settings.0 as u64 != asked.report.settings_revision)
        .then_some(SettingsPush {
            revision: settings.0 as u64,
            toml: settings.1,
        });
    let since = asked.since;
    if since < pruned_through as u64 || since > revision {
        return Ok(ChangesResponse {
            revision,
            network_lock: Some(network_lock(conn).await?),
            settings,
            reset: true,
            ..ChangesResponse::default()
        });
    }
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT kind, subject FROM change_log WHERE revision > $1 AND revision <= $2 ORDER BY revision",
    )
    .bind(since as i64)
    .bind(revision as i64)
    .fetch_all(&mut *conn)
    .await?;
    let mut answer = ChangesResponse {
        revision,
        settings,
        ..ChangesResponse::default()
    };
    let mut ranges = since == 0;
    // A long delta repeats subjects; each list names one once, in first-seen order.
    let (mut keys, mut layers, mut places) = (HashSet::new(), HashSet::new(), HashSet::new());
    for (kind, subject) in rows {
        match kind.as_str() {
            "key" => push_new(
                &mut answer.changed_keys,
                &mut keys,
                serde_json::from_value::<KeyId>(subject).map_err(subject_error("key"))?,
            ),
            "layer" => push_new(
                &mut answer.changed_layers,
                &mut layers,
                serde_json::from_value::<PlaceRef>(subject).map_err(subject_error("layer"))?,
            ),
            "place" => push_new(
                &mut answer.changed_places,
                &mut places,
                serde_json::from_value::<PlaceRef>(subject).map_err(subject_error("place"))?,
            ),
            "limits" => answer.changed_limits.push(
                serde_json::from_value::<LimitChange>(subject).map_err(subject_error("limits"))?,
            ),
            "ranges" => ranges = true,
            // `settings` travels by revision above; a `firewall` row (retirement) is
            // answered by the 401 its token now gets.
            _ => {}
        }
    }
    if ranges {
        answer.network_lock = Some(network_lock(conn).await?);
    }
    Ok(answer)
}

fn subject_error(what: &'static str) -> impl Fn(serde_json::Error) -> SyncError {
    move |err| {
        tracing::error!(error = %err, what, "a change_log subject does not decode");
        SyncError::Store(sqlx::Error::Decode(Box::new(err)))
    }
}

fn push_new<T: Copy + Eq + Hash>(list: &mut Vec<T>, seen: &mut HashSet<T>, item: T) {
    if seen.insert(item) {
        list.push(item);
    }
}

/// Every approved network-lock range, fleet-wide (C30, C77).
async fn network_lock(conn: &mut PgConnection) -> Result<Vec<LockRange>, sqlx::Error> {
    let rows: Vec<(String, i32)> = sqlx::query_as(
        "SELECT r.cidr::text, r.org_id FROM org_ip_ranges AS r JOIN orgs AS o ON o.id = r.org_id
         WHERE r.approved_by IS NOT NULL AND o.deleted_at IS NULL ORDER BY r.id",
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(cidr, org)| LockRange {
            cidr,
            org: OrgId(org as u32),
        })
        .collect())
}

/// Where a key's place sits now, derived at read time (CO1).
struct Standing {
    chain: Vec<PlaceRef>,
    /// The organisation or personal account the key counts against.
    account: Option<PlaceRef>,
    /// The place, its organisation or personal account, or its owner's membership is
    /// gone or deleted.
    gone: bool,
    suspended: bool,
}

/// The lookup answer for `hash`, read at `revision`. Only user and service keys are
/// looked up: a firewall or automation token answers `Unknown` (T9).
async fn look_up(
    conn: &mut PgConnection,
    hash: KeyHash,
    revision: u64,
) -> Result<KeyLookup, sqlx::Error> {
    let row: Option<(i64, String, i32, Option<i32>, bool, bool)> = sqlx::query_as(
        "SELECT k.id, k.place_kind, k.place_id, k.owner_login, k.revoked_at IS NOT NULL,
                COALESCE((SELECT l.deleted_at IS NOT NULL FROM logins AS l WHERE l.id = k.owner_login), false)
         FROM keys AS k WHERE k.hash = $1 AND k.kind IN ('user', 'service')",
    )
    .bind(hash.0.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((key_id, kind, place_id, owner, revoked, owner_deleted)) = row else {
        return Ok(KeyLookup::Unknown { revision });
    };
    let key_id = KeyId(key_id as u64);
    let Some(kind) = kind_of(&kind) else {
        return Ok(KeyLookup::Unknown { revision });
    };
    let place = PlaceRef {
        kind,
        id: place_id as u32,
    };
    let standing = standing(conn, place, owner).await?;
    let place_chain = links(conn, &standing.chain).await?;
    if revoked || owner_deleted || standing.gone {
        return Ok(KeyLookup::Revoked {
            key_id,
            place,
            place_chain,
            revision,
        });
    }
    if standing.suspended {
        return Ok(KeyLookup::Suspended {
            key_id,
            place,
            place_chain,
            revision,
        });
    }
    let account = standing
        .account
        .expect("a place that is not gone belongs to an account");
    let (scope_kind, org) = match account.kind {
        LayerKind::Org => ("org", Some(OrgId(account.id))),
        _ => ("personal", None),
    };
    let (rate, overridden): (i32, bool) = sqlx::query_as(
        "SELECT rate_per_min, scope_id IS NOT NULL FROM limits
         WHERE scope_kind = $1 AND (scope_id = $2 OR scope_id IS NULL)
         ORDER BY scope_id NULLS LAST LIMIT 1",
    )
    .bind(scope_kind)
    .bind(account.id as i32)
    .fetch_one(&mut *conn)
    .await?;
    Ok(KeyLookup::Known {
        key_id,
        org,
        account,
        place_chain,
        rate_limit: NonZeroU32::new(rate as u32),
        rate_limit_source: if overridden {
            LimitSource::Override
        } else {
            LimitSource::Default
        },
        revision,
    })
}

async fn standing(
    conn: &mut PgConnection,
    place: PlaceRef,
    owner: Option<i32>,
) -> Result<Standing, sqlx::Error> {
    let id = place.id as i32;
    let org_place = |org: i32| PlaceRef {
        kind: LayerKind::Org,
        id: org as u32,
    };
    let group_place = |group: i32| PlaceRef {
        kind: LayerKind::Group,
        id: group as u32,
    };
    // Only the platform and the place itself when nothing above it can be found.
    let lost = Standing {
        chain: vec![PLATFORM, place],
        account: None,
        gone: true,
        suspended: false,
    };
    let in_org = |org: i32, group: Option<i32>, tail: Option<PlaceRef>| {
        let mut chain = vec![PLATFORM, org_place(org)];
        chain.extend(group.map(group_place));
        chain.extend(tail);
        chain
    };
    Ok(match place.kind {
        LayerKind::Org => match org_state(conn, id).await? {
            Some((suspended, deleted)) => Standing {
                chain: in_org(id, None, None),
                account: Some(place),
                gone: deleted,
                suspended,
            },
            None => lost,
        },
        LayerKind::Group => {
            let org: Option<i32> = sqlx::query_scalar("SELECT org_id FROM groups WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?;
            match org {
                Some(org) => {
                    let (suspended, deleted) = org_state(conn, org).await?.unwrap_or((false, true));
                    Standing {
                        chain: in_org(org, Some(id), None),
                        account: Some(org_place(org)),
                        gone: deleted,
                        suspended,
                    }
                }
                None => lost,
            }
        }
        LayerKind::User => {
            let member: Option<(i32, Option<i32>, i32)> = sqlx::query_as(
                "SELECT org_id, group_id, login_id FROM memberships WHERE id = $1 AND org_id IS NOT NULL",
            )
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
            match member {
                Some((org, group, login)) => {
                    let (suspended, deleted) = org_state(conn, org).await?.unwrap_or((false, true));
                    Standing {
                        chain: in_org(org, group, Some(place)),
                        account: Some(org_place(org)),
                        // The key's owner is no longer this member (C52).
                        gone: deleted || owner != Some(login),
                        suspended,
                    }
                }
                None => lost,
            }
        }
        LayerKind::Personal => {
            let account: Option<(i32, bool, bool)> = sqlx::query_as(
                "SELECT login_id, status = 'suspended', deleted_at IS NOT NULL
                 FROM personal_accounts WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
            match account {
                Some((login, suspended, deleted)) => Standing {
                    chain: vec![PLATFORM, place],
                    account: Some(place),
                    gone: deleted || owner != Some(login),
                    suspended,
                },
                None => lost,
            }
        }
        LayerKind::Platform => lost,
    })
}

/// `(suspended, deleted)` of an organisation, or `None` when it no longer exists.
async fn org_state(conn: &mut PgConnection, org: i32) -> Result<Option<(bool, bool)>, sqlx::Error> {
    sqlx::query_as("SELECT status = 'suspended', deleted_at IS NOT NULL FROM orgs WHERE id = $1")
        .bind(org)
        .fetch_optional(conn)
        .await
}

/// Each place with its layer's revision (0 when it has no layer row).
async fn links(conn: &mut PgConnection, chain: &[PlaceRef]) -> Result<Vec<ChainLink>, sqlx::Error> {
    let mut links = Vec::with_capacity(chain.len());
    for place in chain {
        let revision: Option<i64> = sqlx::query_scalar(
            "SELECT revision FROM policy_layers WHERE place_kind = $1 AND place_id = $2",
        )
        .bind(kind_str(place.kind))
        .bind(place.id as i32)
        .fetch_optional(&mut *conn)
        .await?;
        links.push(ChainLink {
            place: *place,
            layer_revision: revision.unwrap_or(0) as u64,
        });
    }
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F1: behind a trusted proxy, an `X-Forwarded-For` entry with a port or brackets
    /// names its address; anything else that is not an address still refuses (C113).
    #[test]
    fn forwarded_entries_with_ports_and_brackets() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let from = |entry: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", entry.parse().unwrap());
            source_address(peer, &headers, &trusted)
        };
        for (entry, ip) in [
            ("192.0.2.7", "192.0.2.7"),
            ("192.0.2.7:4711", "192.0.2.7"),
            ("[2001:db8::7]", "2001:db8::7"),
            ("[2001:db8::7]:4711", "2001:db8::7"),
            ("2001:db8::7", "2001:db8::7"),
            ("[::ffff:192.0.2.7]:80", "192.0.2.7"),
            ("192.0.2.7:4711, 10.0.0.2:80", "192.0.2.7"),
        ] {
            assert_eq!(from(entry), Some(ip.parse().unwrap()), "{entry}");
        }
        for entry in [
            "unknown",
            "192.0.2.7:port",
            "[192.0.2.7]",
            "[2001:db8::7",
            "2001:db8::7]:80",
            "_hidden",
        ] {
            assert_eq!(from(entry), None, "{entry}");
        }
    }
    #[test]
    fn forwarded_ip_forms() {
        for (entry, ip) in [
            ("192.0.2.7", "192.0.2.7"),
            ("192.0.2.7:4711", "192.0.2.7"),
            ("2001:db8::7", "2001:db8::7"),
            ("[2001:db8::7]", "2001:db8::7"),
            ("[2001:db8::7]:4711", "2001:db8::7"),
        ] {
            assert_eq!(forwarded_ip(entry), Some(ip.parse().unwrap()), "{entry}");
        }
        for entry in [
            "",
            "unknown",
            "[]",
            "[192.0.2.7]",
            "[192.0.2.7]:80",
            "192.0.2.7:",
            "::1]:80",
        ] {
            assert_eq!(forwarded_ip(entry), None, "{entry}");
        }
    }
}
