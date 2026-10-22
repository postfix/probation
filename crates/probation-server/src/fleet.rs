//! Firewall registration: each firewall gets one `fwt_` token, usable only from its
//! `allowed_source_cidrs` (T31). Settings, retirement and status arrive with the fleet
//! pages (slice 7).

use ipnet::IpNet;
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::keys::{self, KeyKind};
use crate::tenancy::{Actor, PLATFORM};

/// A registered firewall. The token is shown once.
pub struct Registered {
    pub id: i32,
    pub token: String,
}

#[derive(Debug)]
pub enum RegisterError {
    /// Only a global admin registers firewalls (C4).
    Denied,
    Store(sqlx::Error),
}

impl From<sqlx::Error> for RegisterError {
    fn from(err: sqlx::Error) -> Self {
        RegisterError::Store(err)
    }
}

/// Registers a firewall with its audit row, in one transaction.
pub async fn register(
    pool: &PgPool,
    actor: &Actor,
    name: &str,
    allowed_source_cidrs: &[IpNet],
) -> Result<Registered, RegisterError> {
    if !actor.is_global_admin() {
        return Err(RegisterError::Denied);
    }
    let mut tx = pool.begin().await?;
    let firewall = insert(&mut tx, name, allowed_source_cidrs).await?;
    let sources: Vec<String> = allowed_source_cidrs.iter().map(IpNet::to_string).collect();
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "firewall.register",
            subject: format!("firewall:{}", firewall.id),
            before: None,
            after: Some(serde_json::json!({"name": name, "allowed_source_cidrs": sources})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(firewall)
}

/// The firewall row and its token, without an audit row: the caller writes one.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    name: &str,
    allowed_source_cidrs: &[IpNet],
) -> Result<Registered, sqlx::Error> {
    let token = keys::insert(conn, KeyKind::Firewall, PLATFORM, None, name).await?;
    let id = sqlx::query_scalar(
        "INSERT INTO firewalls (name, token_key_id, allowed_source_cidrs) VALUES ($1, $2, $3::inet[]::cidr[]) RETURNING id",
    )
    .bind(name)
    .bind(token.id.0 as i64)
    .bind(allowed_source_cidrs)
    .fetch_one(conn)
    .await?;
    Ok(Registered {
        id,
        token: token.secret,
    })
}
