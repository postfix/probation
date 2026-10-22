//! Edit and store layer policies. An edit runs `authorized_place` -> `check_edit`
//! (against `parent_policy`) -> `authorize` -> `save_edit` (03 § Program behavior
//! step 4); `save_edit` writes the layer, its `change_log` row and its audit row in one
//! transaction.

use probation_policy::{
    Block, CheckedEdit, DigestAlgorithm, Ecosystem, EffectivePolicy, Exception, Layer, Lifts,
    OsvSetting, PlaceRef, Switches, resolve,
};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::sync::{ChangeKind, record_change};
use crate::tenancy::{Actor, Authorized, EditPermit, Place, kind_str};

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
        let mut tx = self.pool.begin().await?;
        let revision = update_layer(&mut tx, &checked).await?;
        let () = insert_change(&mut tx, checked.place(), revision).await?;
        let () = insert_audit(&mut tx, actor, &permit, &checked).await?;
        let () = tx.commit().await?;
        Ok(revision)
    }
}

/// Compare-and-set on the revision the form was loaded at, then replace the layer's
/// values, blocks and exceptions. Keeps the old layer for the audit row in a
/// transaction-local setting.
async fn update_layer(conn: &mut PgConnection, checked: &CheckedEdit) -> Result<i64, SaveError> {
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
        let (ecosystem, name, version, algorithm, digest) = match block {
            Block::Package { ecosystem, name } => {
                (Some(ecosystem.as_tag()), Some(name), None, None, None)
            }
            Block::Version {
                ecosystem,
                name,
                version,
            } => (
                Some(ecosystem.as_tag()),
                Some(name),
                Some(version),
                None,
                None,
            ),
            Block::File { algorithm, digest } => (
                None,
                None,
                None,
                Some(algorithm_str(*algorithm)),
                Some(digest),
            ),
        };
        sqlx::query(
            "INSERT INTO policy_blocks (layer, ecosystem, name, version, digest_algorithm, digest)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(layer_id)
        .bind(ecosystem)
        .bind(name)
        .bind(version)
        .bind(algorithm)
        .bind(digest)
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

/// The edit's audit row: actor, global-admin flag (C79), the layer before and after.
async fn insert_audit(
    conn: &mut PgConnection,
    actor: &Actor,
    permit: &EditPermit,
    checked: &CheckedEdit,
) -> Result<(), sqlx::Error> {
    let place = permit.place();
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
        "SELECT ecosystem, name, version, digest_algorithm, digest FROM policy_blocks
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

/// `policy_blocks`' ecosystem, name, version, digest algorithm and digest.
type BlockRow = (
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

fn block_of((ecosystem, name, version, algorithm, digest): BlockRow) -> Block {
    match (ecosystem, name, digest) {
        (Some(ecosystem), Some(name), None) => match version {
            Some(version) => Block::Version {
                ecosystem: ecosystem_of(&ecosystem),
                name,
                version,
            },
            None => Block::Package {
                ecosystem: ecosystem_of(&ecosystem),
                name,
            },
        },
        (_, _, digest) => Block::File {
            algorithm: if algorithm.as_deref() == Some("sha512") {
                DigestAlgorithm::Sha512
            } else {
                DigestAlgorithm::Sha256
            },
            digest: digest.unwrap_or_default(),
        },
    }
}
