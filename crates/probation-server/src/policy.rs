//! Edit and store layer policies. An edit runs `authorized_place` -> `check_edit`
//! (against `parent_policy`) -> `authorize` -> `save_edit` (03 § Program behavior
//! step 4); `save_edit` writes the layer, its `change_log` row and its audit row in one
//! transaction. Blocklist import, export and the automation push (C80, C86) take the
//! same path.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use probation_policy::{
    Block, CheckedEdit, DigestAlgorithm, Ecosystem, EditRefusal, EditTarget, EffectivePolicy,
    Exception, Layer, Lifts, OsvSetting, PlaceRef, Switches, blocklist_json, check_edit, resolve,
};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::sync::{ChangeKind, record_change};
use crate::tenancy::{Actor, Authorized, EditPermit, Place, Tenancy, authorize, kind_of, kind_str};

#[derive(Debug)]
pub enum StoreError {
    /// A place of the chain has no layer row: the store is inconsistent.
    MissingLayer(PlaceRef),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        StoreError::Db(err)
    }
}

#[derive(Debug)]
pub enum SaveError {
    /// The layer's revision is no longer the one the form was loaded at.
    Conflict,
    /// The permit was granted for another place than the edit's.
    WrongPlace,
    /// The permit was granted to another actor than the one saving, or it covers the
    /// layer's blocks only (an automation token's, C86) and the save changes more.
    WrongActor,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for SaveError {
    fn from(err: sqlx::Error) -> Self {
        SaveError::Db(err)
    }
}

pub struct PolicyStore {
    pool: PgPool,
}

impl PolicyStore {
    pub fn new(pool: PgPool) -> PolicyStore {
        PolicyStore { pool }
    }

    /// The place's stored layer and its revision: what an edit form is loaded from.
    pub async fn layer(&self, place: &Authorized<Place>) -> Result<(Layer, u64), StoreError> {
        let mut conn = self.pool.acquire().await?;
        load_layer(&mut conn, place.place())
            .await?
            .ok_or(StoreError::MissingLayer(place.place()))
    }

    /// `check_edit`'s inputs: `resolve` of the layers above the place along its own
    /// chain (C9, C10; `EffectivePolicy::root()` for the platform), and the place's own
    /// stored layer.
    pub async fn parent_policy(
        &self,
        place: &Authorized<Place>,
    ) -> Result<(EffectivePolicy, Layer), StoreError> {
        let mut conn = self.pool.acquire().await?;
        let mut layers = Vec::with_capacity(place.chain().len());
        for link in place.chain() {
            let (layer, _) = load_layer(&mut conn, *link)
                .await?
                .ok_or(StoreError::MissingLayer(*link))?;
            layers.push(layer);
        }
        let current = layers.pop().expect("a chain ends with its place");
        let parent = if layers.is_empty() {
            EffectivePolicy::root()
        } else {
            resolve(&layers)
        };
        Ok((parent, current))
    }

    /// Write the layer, its change_log row and its audit_log row in one transaction.
    pub async fn save_edit(
        &self,
        actor: &Actor,
        permit: EditPermit,
        checked: CheckedEdit,
    ) -> Result<i64, SaveError> {
        // A permit allows one place and one actor: a member's permit for their own layer
        // never saves the organisation's, nor another login's save.
        if permit.place() != checked.place() {
            return Err(SaveError::WrongPlace);
        }
        if permit.login_id() != actor.login_id() {
            return Err(SaveError::WrongActor);
        }
        let mut tx = self.pool.begin().await?;
        let revision = update_layer(&mut tx, &checked, permit.blocks_only()).await?;
        let () = insert_change(&mut tx, checked.place(), revision).await?;
        let () = insert_audit(&mut tx, actor, &permit, &checked).await?;
        let () = tx.commit().await?;
        Ok(revision)
    }
}

/// Compare-and-set on the revision the form was loaded at, then replace the layer's
/// values, blocks and exceptions; with `blocks_only`, refused unless the blocks are all
/// that change. Keeps the old layer for the audit row in a transaction-local setting.
async fn update_layer(
    conn: &mut PgConnection,
    checked: &CheckedEdit,
    blocks_only: bool,
) -> Result<i64, SaveError> {
    let place = checked.place();
    let locked: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM policy_layers
         WHERE place_kind = $1 AND place_id = $2 AND revision = $3 FOR UPDATE",
    )
    .bind(kind_str(place.kind))
    .bind(place.id as i32)
    .bind(checked.expected_revision() as i64)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(layer_id) = locked else {
        return Err(SaveError::Conflict);
    };
    let (before, _) = load_layer(conn, place)
        .await
        .map_err(|err| match err {
            StoreError::Db(err) => SaveError::Db(err),
            StoreError::MissingLayer(_) => SaveError::Conflict,
        })?
        .ok_or(SaveError::Conflict)?;
    let without_blocks = |layer: &Layer| Layer {
        blocks: Vec::new(),
        ..layer.clone()
    };
    if blocks_only && without_blocks(&before) != without_blocks(checked.layer()) {
        return Err(SaveError::WrongActor);
    }
    sqlx::query("SELECT set_config('probation.layer_before', $1, true)")
        .bind(serde_json::to_string(&before).expect("a layer encodes"))
        .execute(&mut *conn)
        .await?;

    let layer = checked.layer();
    let revision: i64 = sqlx::query_scalar(
        "UPDATE policy_layers SET revision = revision + 1, freeze_seconds = $2, osv_mode = $3,
             allow_exceptions = $4, allow_osv_off = $5, allow_shorter_freeze = $6
         WHERE id = $1 RETURNING revision",
    )
    .bind(layer_id)
    .bind(layer.freeze_seconds.map(|seconds| seconds as i64))
    .bind(layer.osv.map(osv_str))
    .bind(layer.allow.exceptions)
    .bind(layer.allow.osv_off)
    .bind(layer.allow.shorter_freeze)
    .fetch_one(&mut *conn)
    .await?;

    sqlx::query("DELETE FROM policy_blocks WHERE layer = $1")
        .bind(layer_id)
        .execute(&mut *conn)
        .await?;
    for block in &layer.blocks {
        let (ecosystem, name, version, algorithm, digest, reason) = match block {
            Block::Package {
                ecosystem,
                name,
                reason,
            } => (
                Some(ecosystem.as_tag()),
                Some(name),
                None,
                None,
                None,
                reason,
            ),
            Block::Version {
                ecosystem,
                name,
                version,
                reason,
            } => (
                Some(ecosystem.as_tag()),
                Some(name),
                Some(version),
                None,
                None,
                reason,
            ),
            Block::File {
                algorithm,
                digest,
                reason,
            } => (
                None,
                None,
                None,
                Some(algorithm_str(*algorithm)),
                Some(digest),
                reason,
            ),
        };
        sqlx::query(
            "INSERT INTO policy_blocks (layer, ecosystem, name, version, digest_algorithm, digest, reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(layer_id)
        .bind(ecosystem)
        .bind(name)
        .bind(version)
        .bind(algorithm)
        .bind(digest)
        .bind(reason)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("DELETE FROM policy_exceptions WHERE layer = $1")
        .bind(layer_id)
        .execute(&mut *conn)
        .await?;
    for exception in &layer.exceptions {
        sqlx::query(
            "INSERT INTO policy_exceptions (layer, ecosystem, name, version, lifts_block, lifts_freeze, lifts_osv)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(layer_id)
        .bind(exception.ecosystem.as_tag())
        .bind(&exception.name)
        .bind(&exception.version)
        .bind(exception.lifts.block)
        .bind(exception.lifts.freeze)
        .bind(exception.lifts.osv)
        .execute(&mut *conn)
        .await?;
    }
    Ok(revision)
}

/// The `layer` row that sends the edit to every firewall (C20, C111).
async fn insert_change(
    conn: &mut PgConnection,
    place: PlaceRef,
    _layer_revision: i64,
) -> Result<(), sqlx::Error> {
    record_change(conn, ChangeKind::Layer, &place)
        .await
        .map(drop)
}

/// The edit's audit row: actor, global-admin flag (C79), the layer before and after,
/// under the edited place (`save_edit` checked the permit is for it).
async fn insert_audit(
    conn: &mut PgConnection,
    actor: &Actor,
    _permit: &EditPermit,
    checked: &CheckedEdit,
) -> Result<(), sqlx::Error> {
    let place = checked.place();
    let before: Option<String> =
        sqlx::query_scalar("SELECT current_setting('probation.layer_before', true)")
            .fetch_one(&mut *conn)
            .await?;
    let org_id: Option<i32> = sqlx::query_scalar("SELECT place_org($1, $2)")
        .bind(kind_str(place.kind))
        .bind(place.id as i32)
        .fetch_one(&mut *conn)
        .await?;
    audit::record(
        conn,
        audit::Entry {
            actor,
            org_id,
            action: "layer.edit",
            subject: format!("{}:{}", kind_str(place.kind), place.id),
            before: before
                .filter(|text| !text.is_empty())
                .and_then(|text| serde_json::from_str(&text).ok()),
            after: Some(serde_json::to_value(checked.layer()).expect("a layer encodes")),
        },
    )
    .await
}

/// `place`'s stored layer and revision, or `None` when it has no layer row.
pub(crate) async fn load_layer(
    conn: &mut PgConnection,
    place: PlaceRef,
) -> Result<Option<(Layer, u64)>, StoreError> {
    type Row = (i32, i64, Option<i64>, Option<String>, bool, bool, bool);
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, revision, freeze_seconds, osv_mode, allow_exceptions, allow_osv_off, allow_shorter_freeze
         FROM policy_layers WHERE place_kind = $1 AND place_id = $2",
    )
    .bind(kind_str(place.kind))
    .bind(place.id as i32)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((id, revision, freeze, osv, exceptions, osv_off, shorter_freeze)) = row else {
        return Ok(None);
    };
    let blocks: Vec<BlockRow> = sqlx::query_as(
        "SELECT ecosystem, name, version, digest_algorithm, digest, reason FROM policy_blocks
         WHERE layer = $1 ORDER BY id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    type ExceptionRow = (String, String, Option<String>, bool, bool, bool);
    let lifted: Vec<ExceptionRow> = sqlx::query_as(
        "SELECT ecosystem, name, version, lifts_block, lifts_freeze, lifts_osv FROM policy_exceptions
         WHERE layer = $1 ORDER BY id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    let layer = Layer {
        kind: place.kind,
        freeze_seconds: freeze.map(|seconds| seconds as u64),
        osv: osv.as_deref().map(osv_of),
        blocks: blocks.into_iter().map(block_of).collect(),
        exceptions: lifted
            .into_iter()
            .map(|(ecosystem, name, version, block, freeze, osv)| Exception {
                ecosystem: ecosystem_of(&ecosystem),
                name,
                version,
                lifts: Lifts { block, freeze, osv },
            })
            .collect(),
        allow: Switches {
            exceptions,
            osv_off,
            shorter_freeze,
        },
    };
    Ok(Some((layer, revision as u64)))
}

/// `policy_blocks`' ecosystem, name, version, digest algorithm, digest and reason.
type BlockRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

// The column CHECK constraints admit only the spellings these match.

fn osv_str(osv: OsvSetting) -> &'static str {
    match osv {
        OsvSetting::Off => "off",
        OsvSetting::LogOnly => "log_only",
        OsvSetting::On => "on",
    }
}

fn osv_of(text: &str) -> OsvSetting {
    match text {
        "off" => OsvSetting::Off,
        "log_only" => OsvSetting::LogOnly,
        _ => OsvSetting::On,
    }
}

fn ecosystem_of(text: &str) -> Ecosystem {
    Ecosystem::from_tag(text).unwrap_or(Ecosystem::Npm)
}

fn algorithm_str(algorithm: DigestAlgorithm) -> &'static str {
    match algorithm {
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha512 => "sha512",
    }
}

fn block_of((ecosystem, name, version, algorithm, digest, reason): BlockRow) -> Block {
    match (ecosystem, name, digest) {
        (Some(ecosystem), Some(name), None) => match version {
            Some(version) => Block::Version {
                ecosystem: ecosystem_of(&ecosystem),
                name,
                version,
                reason,
            },
            None => Block::Package {
                ecosystem: ecosystem_of(&ecosystem),
                name,
                reason,
            },
        },
        (_, _, digest) => Block::File {
            algorithm: if algorithm.as_deref() == Some("sha512") {
                DigestAlgorithm::Sha512
            } else {
                DigestAlgorithm::Sha256
            },
            digest: digest.unwrap_or_default(),
            reason,
        },
    }
}

// ---- Blocklist import, export and the automation push (C80, C86) ----------------------

/// The biggest blocklist an automation push may send (T24): checked before parsing.
pub const MAX_BLOCKLIST_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum PushError {
    /// The actor's role or token does not cover the layer (403).
    Denied,
    /// The file or a block in it is refused, for the reason given (422).
    Refused(String),
    /// The layer changed while the push was checked; send it again (409).
    Conflict,
    Store(StoreError),
}

impl From<StoreError> for PushError {
    fn from(err: StoreError) -> Self {
        PushError::Store(err)
    }
}

impl From<sqlx::Error> for PushError {
    fn from(err: sqlx::Error) -> Self {
        PushError::Store(StoreError::Db(err))
    }
}

/// A block's target, without its reason.
fn target(block: &Block) -> Block {
    let mut block = block.clone();
    let (Block::Package { reason, .. }
    | Block::Version { reason, .. }
    | Block::File { reason, .. }) = &mut block;
    *reason = None;
    block
}

/// Writes `blocks` into `place`'s layer through the edit path (`check_edit` ->
/// `authorize` -> `save_edit`): replacing its blocks, or adding those it lacks. Every
/// other setting of the layer is saved as stored, so one kept under C47 stays.
pub async fn push_blocks(
    pool: &PgPool,
    actor: &Actor,
    place: &Authorized<Place>,
    blocks: Vec<Block>,
    replace: bool,
) -> Result<i64, PushError> {
    let store = PolicyStore::new(pool.clone());
    let (parent, _) = store.parent_policy(place).await?;
    let (current, revision) = store.layer(place).await?;
    let mut proposed = current.clone();
    if replace {
        proposed.blocks = blocks;
    } else {
        for block in blocks {
            if !proposed
                .blocks
                .iter()
                .any(|held| target(held) == target(&block))
            {
                proposed.blocks.push(block);
            }
        }
    }
    let target = EditTarget {
        place: place.place(),
        expected_revision: revision,
    };
    let checked = check_edit(&parent, &current, target, proposed).map_err(|refusal| {
        PushError::Refused(match refusal {
            EditRefusal::Invalid(problem) => problem,
            other => format!("{other:?}"),
        })
    })?;
    let permit = authorize(actor, &checked).map_err(|_| PushError::Denied)?;
    match store.save_edit(actor, permit, checked).await {
        Ok(revision) => Ok(revision),
        Err(SaveError::Conflict) => Err(PushError::Conflict),
        Err(SaveError::WrongPlace | SaveError::WrongActor) => Err(PushError::Denied),
        Err(SaveError::Db(err)) => Err(err.into()),
    }
}

/// `place`'s blocks as today's blocklist file (C86), valid for a year from now.
pub async fn export_blocks(pool: &PgPool, place: &Authorized<Place>) -> Result<String, StoreError> {
    let (layer, revision) = PolicyStore::new(pool.clone()).layer(place).await?;
    let now = jiff::Timestamp::now();
    let expires = now
        .checked_add(jiff::SignedDuration::from_hours(365 * 24))
        .unwrap_or(now);
    Ok(blocklist_json::export(
        &layer.blocks,
        revision,
        &now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
        &expires.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
    ))
}

/// `org-3`, `platform-1` and the like, as the policy pages name a layer.
pub(crate) fn layer_ref(id: &str) -> Option<PlaceRef> {
    let (kind, id) = id.split_once('-')?;
    Some(PlaceRef {
        kind: kind_of(kind)?,
        id: id.parse().ok()?,
    })
}

/// The automation blocklist API (C86): `GET` exports, `PUT` replaces and `POST` adds to
/// the blocks of the one layer its `aut_` token was created for. A body over
/// `MAX_BLOCKLIST_BYTES` answers 413 before it is parsed (T24).
pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route(
            "/api/v1/blocklist/{layer}",
            get(export_route).put(replace_route).post(add_route),
        )
        .layer(DefaultBodyLimit::max(MAX_BLOCKLIST_BYTES))
        .with_state(pool)
}

/// The token's actor and layer when the request names that layer: 401 for no live
/// token, 403 for another layer (T9).
async fn token_layer(
    pool: &PgPool,
    headers: &HeaderMap,
    layer: &str,
) -> Result<(Actor, Authorized<Place>), Response> {
    let secret = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let found = match secret {
        Some(secret) => Tenancy::new(pool.clone()).automation(secret).await,
        None => None,
    };
    let Some((actor, place)) = found else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    if layer_ref(layer) != Some(place.place()) {
        return Err((StatusCode::FORBIDDEN, "This token writes one other layer.").into_response());
    }
    Ok((actor, place))
}

async fn export_route(
    State(pool): State<PgPool>,
    Path(layer): Path<String>,
    headers: HeaderMap,
) -> Response {
    let place = match token_layer(&pool, &headers, &layer).await {
        Ok((_, place)) => place,
        Err(answer) => return answer,
    };
    match export_blocks(&pool, &place).await {
        Ok(file) => (
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            file,
        )
            .into_response(),
        Err(err) => store_failure(err),
    }
}

async fn replace_route(
    State(pool): State<PgPool>,
    Path(layer): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    push_route(&pool, &layer, &headers, &body, true).await
}

async fn add_route(
    State(pool): State<PgPool>,
    Path(layer): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    push_route(&pool, &layer, &headers, &body, false).await
}

async fn push_route(
    pool: &PgPool,
    layer: &str,
    headers: &HeaderMap,
    body: &[u8],
    replace: bool,
) -> Response {
    let (actor, place) = match token_layer(pool, headers, layer).await {
        Ok(found) => found,
        Err(answer) => return answer,
    };
    let blocks = match std::str::from_utf8(body)
        .map_err(|_| "the body is not UTF-8".to_owned())
        .and_then(blocklist_json::import)
    {
        Ok(blocks) => blocks,
        Err(problem) => return (StatusCode::UNPROCESSABLE_ENTITY, problem).into_response(),
    };
    match push_blocks(pool, &actor, &place, blocks, replace).await {
        Ok(revision) => (
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            serde_json::json!({"revision": revision}).to_string(),
        )
            .into_response(),
        Err(PushError::Denied) => StatusCode::FORBIDDEN.into_response(),
        Err(PushError::Refused(problem)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, problem).into_response()
        }
        Err(PushError::Conflict) => (
            StatusCode::CONFLICT,
            "The layer changed meanwhile; send the push again.",
        )
            .into_response(),
        Err(PushError::Store(err)) => store_failure(err),
    }
}

fn store_failure(err: StoreError) -> Response {
    tracing::error!(?err, "a blocklist request failed in the store");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}
