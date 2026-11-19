//! A service key selects its own organisation and complete policy in one snapshot.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use probation_policy::{
    Ecosystem,
    api::{
        KeyHash, KeyLookup, OsvScope, PlaceLayer, RegistryDeletionScope, RegistryDescriptor, RegistryId,
        ServicePolicySnapshot,
    },
};
use sqlx::{PgPool, Postgres, Transaction};

use crate::{policy::load_layer, sync};

struct SnapshotState {
    pool: PgPool,
    recent: Mutex<HashMap<u64, VecDeque<Instant>>>,
}

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route("/api/v1/policy/snapshot", get(snapshot))
        .with_state(Arc::new(SnapshotState {
            pool,
            recent: Mutex::new(HashMap::new()),
        }))
}

struct ServiceScope(ServicePolicySnapshot);

async fn snapshot(
    State(state): State<Arc<SnapshotState>>,
    headers: HeaderMap,
) -> Result<Json<ServicePolicySnapshot>, StatusCode> {
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|key| {
            key.len() == 36
                && key.starts_with("prb_")
                && key[4..].bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let (mut tx, _) = sync::snapshot(&state.pool).await.map_err(unavailable)?;
    let scope = match require_live_service_scope(&mut tx, key).await? {
        Ok(scope) => scope,
        // Only a live key passes the guard, so this is always the refusal.
        Err(standing) => return Err(crate::order_guards::snapshot_order(standing, true).expect_err("a live key is not a refusal")),
    };
    {
        let now = Instant::now();
        let mut recent = state
            .recent
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        recent.retain(|_, window| {
            window
                .back()
                .is_some_and(|at| now.duration_since(*at) < Duration::from_secs(1))
        });
        let window = recent.entry(scope.0.key_id.0).or_default();
        while window
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(1))
        {
            window.pop_front();
        }
        // The scope above is live (a missing or suspended one already returned), so this is
        // the only standing the guard can see here.
        crate::order_guards::snapshot_order(
            crate::order_guards::Standing::Live,
            window.len() < sync::FIREWALL_TOKEN_RATE_PER_SECOND,
        )?;
        window.push_back(now);
    }
    let answer = load_policy_snapshot(scope, &mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(answer))
}

async fn require_live_service_scope(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<Result<ServiceScope, crate::order_guards::Standing>, StatusCode> {
    use crate::order_guards::Standing;
    let hash = KeyHash::of(key);
    let service: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM keys WHERE hash = $1 AND kind = 'service' AND revoked_at IS NULL)")
        .bind(hash.0.as_slice()).fetch_one(&mut **tx).await.map_err(unavailable)?;
    if !service {
        return Ok(Err(Standing::Unknown));
    }
    let revision: i64 = sqlx::query_scalar("SELECT value FROM change_counter WHERE id = 1")
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)?;
    match sync::look_up(tx, hash, revision as u64)
        .await
        .map_err(unavailable)?
    {
        KeyLookup::Known {
            key_id,
            org: Some(org),
            account,
            place_chain,
            rate_limit,
            rate_limit_source,
            revision,
        } => Ok(Ok(ServiceScope(ServicePolicySnapshot {
            version: 1,
            key_id,
            org,
            account,
            place_chain,
            rate_limit,
            rate_limit_source,
            revision,
            layers: Vec::new(),
            registries: Vec::new(),
        }))),
        KeyLookup::Suspended { .. } => Ok(Err(Standing::Suspended)),
        _ => Ok(Err(Standing::Unknown)),
    }
}

async fn load_policy_snapshot(
    scope: ServiceScope,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<ServicePolicySnapshot, StatusCode> {
    let mut snapshot = scope.0;
    for link in &snapshot.place_chain {
        let (layer, revision) = load_layer(tx, link.place)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        snapshot.layers.push(PlaceLayer {
            place: link.place,
            layer,
            revision,
        });
    }
    type Row = (i64, String, Option<String>, bool, Option<String>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, ecosystem, target_url, trusted, osv_scope, archive_origin FROM registries WHERE org_id = $1 AND removed_at IS NULL ORDER BY id LIMIT 257"
    ).bind(snapshot.org.0 as i32).fetch_all(&mut **tx).await.map_err(unavailable)?;
    if rows.len() > 256 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    for (id, tag, target_url, trusted, osv_scope, archive_origin) in rows {
        let ecosystem = match tag.as_str() {
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPi,
            "rubygems" => Ecosystem::RubyGems,
            "cargo" => Ecosystem::Cargo,
            _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
        };
        let registry_private_cidrs = match &target_url {
            Some(url) => sync::approved_private_cidrs(tx, snapshot.org.0 as i32, "registry", url)
                .await
                .map_err(unavailable)?,
            None => Vec::new(),
        };
        let deletion_scopes = sqlx::query_as::<_, (String, String, bool)>(
            "SELECT origin, path_prefix, forward_bearer FROM registry_delete_origins WHERE registry_id = $1 ORDER BY origin, path_prefix"
        ).bind(id).fetch_all(&mut **tx).await.map_err(unavailable)?.into_iter()
            .map(|(origin, path_prefix, forward_bearer)| RegistryDeletionScope { origin, path_prefix, forward_bearer }).collect();
        snapshot.registries.push(RegistryDescriptor {
            registry: RegistryId(id as u64),
            ecosystem,
            target_url,
            trusted,
            registry_private_cidrs,
            deletion_scopes,
            osv_scope: match osv_scope.as_deref() {
                Some("public") => Some(OsvScope::Public),
                Some("private") => Some(OsvScope::Private),
                _ => None,
            },
            archive_origin,
        });
    }
    Ok(snapshot)
}

fn unavailable(error: sqlx::Error) -> StatusCode {
    tracing::error!(%error, "service policy snapshot unavailable");
    StatusCode::SERVICE_UNAVAILABLE
}

/// Sets (`Some`) or clears (`None`) a registry's OSV scope (LS-F12). False when the
/// registry is not this organisation's live registry.
pub async fn set_osv_scope(
    pool: &sqlx::PgPool,
    org: i32,
    registry: i64,
    scope: Option<OsvScope>,
) -> Result<bool, sqlx::Error> {
    let column = scope.map(|scope| match scope {
        OsvScope::Public => "public",
        OsvScope::Private => "private",
    });
    let done = sqlx::query("UPDATE registries SET osv_scope = $1 WHERE id = $2 AND org_id = $3 AND removed_at IS NULL")
        .bind(column)
        .bind(registry)
        .bind(org)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// Why an archive origin is refused: it is checked with the rules of a registry target.
pub fn valid_archive_origin(text: &str) -> Option<url::Url> {
    let url = url::Url::parse(text).ok()?;
    (text.len() <= 2048
        && url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

/// Sets (`Some`) or clears (`None`) a Cargo registry's archive origin. False when the registry is not
/// this organisation's live Cargo registry (the column only exists for one).
pub async fn set_archive_origin(
    pool: &sqlx::PgPool,
    org: i32,
    registry: i64,
    origin: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("UPDATE registries SET archive_origin = $1 WHERE id = $2 AND org_id = $3 AND ecosystem = 'cargo' AND target_url IS NOT NULL AND removed_at IS NULL")
        .bind(origin)
        .bind(registry)
        .bind(org)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// The id of a live service-kind key (`prb_`, not revoked), for the OSV route's closed
/// credential set. User-kind, firewall-kind, revoked and unknown keys are `None`.
pub(crate) async fn live_service_key_id(pool: &PgPool, key: &str) -> Result<Option<(i64, String, Option<i32>)>, sqlx::Error> {
    if key.len() != 36 || !key.starts_with("prb_") || !key[4..].bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Ok(None);
    }
    sqlx::query_as("SELECT id::bigint, place_kind,
            (CASE place_kind
                WHEN 'org' THEN place_id
                WHEN 'group' THEN (SELECT org_id FROM groups WHERE groups.id = keys.place_id)
                WHEN 'user' THEN (SELECT org_id FROM memberships WHERE memberships.id = keys.place_id)
                ELSE place_id END)::int FROM keys WHERE hash = $1 AND kind = 'service' AND revoked_at IS NULL")
        .bind(KeyHash::of(key).0.as_slice())
        .fetch_optional(pool)
        .await
}
