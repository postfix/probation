//! The append-only audit log (C25, C79, T17) and the retention jobs (C26, C68). Every
//! writer records its row inside its own transaction, so a change and its audit row
//! commit together or not at all.

use serde_json::Value;
use sqlx::{PgConnection, PgPool};

use crate::tenancy::{Actor, ChangeError};

pub struct Entry<'a> {
    pub actor: &'a Actor,
    /// The organisation whose log lists the row; `None` for the platform and personal
    /// accounts.
    pub org_id: Option<i32>,
    pub action: &'a str,
    pub subject: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

/// Inserts one `audit_log` row. A global admin acting inside an organisation is flagged
/// in that organisation's log (C79); an automation push names its token and the token's
/// creator (C86).
pub async fn record(conn: &mut PgConnection, entry: Entry<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (actor_login, actor_is_global_admin, org_id, action, subject, before, after, actor_token)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(entry.actor.login_id())
    .bind(entry.actor.is_global_admin())
    .bind(entry.org_id)
    .bind(entry.action)
    .bind(entry.subject)
    .bind(entry.before)
    .bind(entry.after)
    .bind(entry.actor.token().map(|token| token.0 as i64))
    .execute(conn)
    .await
    .map(drop)
}

/// The shortest retention either log may have (C68).
pub const MIN_RETENTION_DAYS: i32 = 7;

/// The platform's retention: (activity days, audit days) (C26).
pub async fn retention(pool: &PgPool) -> Result<(i32, i32), sqlx::Error> {
    sqlx::query_as(
        "SELECT activity_retention_days, audit_retention_days FROM platform_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await
}

/// Sets the platform's retention, as only a global admin may; each at least 7 days
/// (C68). Audited, because cutting it is the risk the operator accepted (A6).
pub async fn set_retention(
    pool: &PgPool,
    actor: &Actor,
    activity_days: i32,
    audit_days: i32,
) -> Result<(), ChangeError> {
    if !actor.is_global_admin() {
        return Err(ChangeError::Denied);
    }
    if activity_days < MIN_RETENTION_DAYS || audit_days < MIN_RETENTION_DAYS {
        return Err(ChangeError::Refused(
            "Not saved. Each must be at least 7 days.".to_owned(),
        ));
    }
    let mut tx = pool.begin().await?;
    let (old_activity, old_audit): (i32, i32) = sqlx::query_as(
        "SELECT activity_retention_days, audit_retention_days FROM platform_settings
         WHERE id = 1 FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    if (old_activity, old_audit) == (activity_days, audit_days) {
        return Ok(());
    }
    sqlx::query(
        "UPDATE platform_settings SET activity_retention_days = $1, audit_retention_days = $2
         WHERE id = 1",
    )
    .bind(activity_days)
    .bind(audit_days)
    .execute(&mut *tx)
    .await?;
    let () = record(
        &mut tx,
        Entry {
            actor,
            org_id: None,
            action: "retention.set",
            subject: "platform".to_owned(),
            before: Some(
                serde_json::json!({"activity_days": old_activity, "audit_days": old_audit}),
            ),
            after: Some(
                serde_json::json!({"activity_days": activity_days, "audit_days": audit_days}),
            ),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// The retention job (C26): deletes activity rows older than their organisation's
/// retention (the platform's for the platform and personal accounts), then audit rows
/// through `prune_audit()`, the only way the app role can (T17). Returns how many rows
/// of each went.
pub async fn prune(pool: &PgPool) -> Result<(u64, i64), sqlx::Error> {
    let activity = sqlx::query(
        "DELETE FROM activity AS a
         WHERE a.at < now() - make_interval(days => GREATEST(7, COALESCE(
             (SELECT o.activity_retention_days FROM orgs AS o WHERE o.id = place_org(a.place_kind, a.place_id)),
             (SELECT p.activity_retention_days FROM platform_settings AS p WHERE p.id = 1))))",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let audit: i64 = sqlx::query_scalar("SELECT prune_audit()")
        .fetch_one(pool)
        .await?;
    Ok((activity, audit))
}
