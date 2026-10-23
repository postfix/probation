//! The append-only audit log (C25, C79, T17). Every writer records its row inside its
//! own transaction, so a change and its audit row commit together or not at all.

use serde_json::Value;
use sqlx::PgConnection;

use crate::tenancy::Actor;

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
/// in that organisation's log (C79); an automation push names its token's creator.
pub async fn record(conn: &mut PgConnection, entry: Entry<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (actor_login, actor_is_global_admin, org_id, action, subject, before, after)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(entry.actor.login_id())
    .bind(entry.actor.is_global_admin())
    .bind(entry.org_id)
    .bind(entry.action)
    .bind(entry.subject)
    .bind(entry.before)
    .bind(entry.after)
    .execute(conn)
    .await
    .map(drop)
}
