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
        KeyHash, KeyLookup, PlaceLayer, RegistryDeletionScope, RegistryDescriptor, RegistryId,
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
    let scope = require_live_service_scope(&mut tx, &key).await?;
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
        if window.len() >= sync::FIREWALL_TOKEN_RATE_PER_SECOND {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        window.push_back(now);
    }
    let answer = load_policy_snapshot(scope, &mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(answer))
}

async fn require_live_service_scope(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<ServiceScope, StatusCode> {
    let hash = KeyHash::of(key);
    let service: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM keys WHERE hash = $1 AND kind = 'service' AND revoked_at IS NULL)")
        .bind(hash.0.as_slice()).fetch_one(&mut **tx).await.map_err(unavailable)?;
    if !service {
        return Err(StatusCode::UNAUTHORIZED);
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
        } => Ok(ServiceScope(ServicePolicySnapshot {
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
        })),
        KeyLookup::Suspended { .. } => Err(StatusCode::FORBIDDEN),
        _ => Err(StatusCode::UNAUTHORIZED),
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
    let rows: Vec<(i64, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, ecosystem, target_url, trusted FROM registries WHERE org_id = $1 AND removed_at IS NULL ORDER BY id LIMIT 1001"
    ).bind(snapshot.org.0 as i32).fetch_all(&mut **tx).await.map_err(unavailable)?;
    if rows.len() > 1000 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    for (id, tag, target_url, trusted) in rows {
        let ecosystem = match tag.as_str() {
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPi,
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
        });
    }
    Ok(snapshot)
}

fn unavailable(error: sqlx::Error) -> StatusCode {
    tracing::error!(%error, "service policy snapshot unavailable");
    StatusCode::SERVICE_UNAVAILABLE
}
