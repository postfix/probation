//! Credentials: API keys (`prb_`, C99), automation tokens (`aut_`) and firewall tokens
//! (`fwt_`). A credential is shown once at creation; only its SHA-256 is stored, and
//! every query filters its kind, so one kind never passes for another (T9).

use probation_policy::api::{KeyHash, KeyId};
use probation_policy::{LayerKind, PlaceRef};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::sync::{ChangeKind, record_change};
use crate::tenancy::{Actor, Authorized, Place};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    /// A person's key, on their user layer or personal account.
    User,
    /// An organisation's key, attached to the organisation or one of its groups (C15).
    Service,
    Automation,
    Firewall,
}

impl KeyKind {
    pub const fn prefix(self) -> &'static str {
        match self {
            KeyKind::User | KeyKind::Service => "prb_",
            KeyKind::Automation => "aut_",
            KeyKind::Firewall => "fwt_",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            KeyKind::User => "user",
            KeyKind::Service => "service",
            KeyKind::Automation => "automation",
            KeyKind::Firewall => "firewall",
        }
    }
}

/// A credential just created. `secret` is never stored and never shown again.
pub struct NewKey {
    pub id: KeyId,
    pub secret: String,
}

/// The kind's prefix and 32 random characters from `[A-Za-z0-9]` (C99).
pub fn generate(kind: KeyKind) -> String {
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut secret = String::from(kind.prefix());
    while secret.len() < kind.prefix().len() + 32 {
        let mut bytes = [0u8; 64];
        getrandom::fill(&mut bytes).expect("the operating system's random source");
        // 248 = 4 × 62: rejecting the bytes above it keeps every character equally likely.
        for byte in bytes.into_iter().filter(|byte| *byte < 248) {
            if secret.len() == kind.prefix().len() + 32 {
                break;
            }
            secret.push(char::from(ALPHABET[usize::from(byte) % 62]));
        }
    }
    secret
}

/// The credential's row, without an audit row: the caller writes one.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    kind: KeyKind,
    place: PlaceRef,
    owner_login: Option<i32>,
    name: &str,
) -> Result<NewKey, sqlx::Error> {
    let secret = generate(kind);
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO keys (hash, last4, kind, place_kind, place_id, owner_login, name)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(KeyHash::of(&secret).0.as_slice())
    .bind(&secret[secret.len() - 4..])
    .bind(kind.as_str())
    .bind(crate::tenancy::kind_str(place.kind))
    .bind(place.id as i32)
    .bind(owner_login)
    .bind(name)
    .fetch_one(conn)
    .await?;
    Ok(NewKey {
        id: KeyId(id as u64),
        secret,
    })
}

#[derive(Debug)]
pub enum KeyError {
    /// The actor's role on the place does not manage its keys.
    Denied,
    /// The account already holds this many keys of the kind, its limit (C51, C53).
    Limit(i64),
    Store(sqlx::Error),
}

impl From<sqlx::Error> for KeyError {
    fn from(err: sqlx::Error) -> Self {
        KeyError::Store(err)
    }
}

/// Creates a key on `place` with its audit row: a user key on a user layer or personal
/// account (owned by that place's login), a service key on an organisation or group.
pub async fn create(
    pool: &PgPool,
    actor: &Actor,
    place: &Authorized<Place>,
    name: &str,
) -> Result<NewKey, KeyError> {
    let kind = match place.place().kind {
        LayerKind::User | LayerKind::Personal => KeyKind::User,
        LayerKind::Org | LayerKind::Group => KeyKind::Service,
        LayerKind::Platform => return Err(KeyError::Denied),
    };
    if !actor.may_manage_keys(place.place()) {
        return Err(KeyError::Denied);
    }
    let mut tx = pool.begin().await?;
    if let Some(limit) = at_limit(&mut tx, kind, place).await? {
        return Err(KeyError::Limit(limit));
    }
    let key = insert(&mut tx, kind, place.place(), place.owner_login(), name).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: place.org(),
            action: "key.create",
            subject: format!("key:{}", key.id.0),
            before: None,
            after: Some(serde_json::json!({
                "name": name,
                "kind": kind.as_str(),
                "place": place.place(),
                "last4": &key.secret[key.secret.len() - 4..],
            })),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(key)
}

/// One API key as the keys page lists it: its name and last 4 characters, never the
/// key (C99).
pub struct KeyRow {
    pub id: i64,
    pub name: String,
    pub last4: String,
    pub created: String,
}

/// The live user keys of `place` (a user place or a personal account), oldest first.
pub async fn own(pool: &PgPool, place: &Authorized<Place>) -> Result<Vec<KeyRow>, sqlx::Error> {
    let rows: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, name, last4, to_char(created_at, 'DD Mon YYYY') FROM keys
         WHERE kind = 'user' AND place_kind = $1 AND place_id = $2 AND revoked_at IS NULL
         ORDER BY id",
    )
    .bind(crate::tenancy::kind_str(place.place().kind))
    .bind(place.place().id as i32)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, last4, created)| KeyRow {
            id,
            name,
            last4,
            created,
        })
        .collect())
}

/// One live service key as the keys page lists it: where it is attached and who
/// created it (from its audit row: a service key has no owner, so it survives staff
/// changes, C14).
pub struct ServiceKeyRow {
    pub id: i64,
    pub name: String,
    pub last4: String,
    pub created: String,
    /// "Frontend group" or "Acme organisation".
    pub attached: String,
    pub created_by: String,
}

/// The live service keys of organisation `org`, or of one of its groups.
pub async fn service(
    pool: &PgPool,
    org: i32,
    group: Option<i32>,
) -> Result<Vec<ServiceKeyRow>, sqlx::Error> {
    type Row = (i64, String, String, String, String, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT k.id, k.name, k.last4, to_char(k.created_at, 'DD Mon YYYY'),
                CASE k.place_kind WHEN 'org' THEN o.name || ' organisation' ELSE g.name || ' group' END,
                (SELECT m.email FROM audit_log AS a JOIN sign_in_methods AS m ON m.login_id = a.actor_login
                 WHERE a.action = 'key.create' AND a.subject = 'key:' || k.id AND m.email IS NOT NULL
                 ORDER BY m.id LIMIT 1)
         FROM keys AS k
         JOIN orgs AS o ON o.id = $1
         LEFT JOIN groups AS g ON k.place_kind = 'group' AND g.id = k.place_id
         WHERE k.kind = 'service' AND k.revoked_at IS NULL
           AND ((k.place_kind = 'org' AND k.place_id = $1 AND $2::integer IS NULL)
                OR (k.place_kind = 'group' AND g.org_id = $1 AND ($2::integer IS NULL OR g.id = $2)))
         ORDER BY k.id",
    )
    .bind(org)
    .bind(group)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, name, last4, created, attached, created_by)| ServiceKeyRow {
                id,
                name,
                last4,
                created,
                attached,
                created_by: created_by.unwrap_or_default(),
            },
        )
        .collect())
}

/// The limit a new key of `kind` on `place` would pass, if any: a member's own keys in
/// an organisation and a personal account's keys count against `max_keys`, an
/// organisation's service keys against `max_service_keys` (C28, C51). Lowering a limit
/// below the count stops nothing that exists (C53). The account row is locked first, so
/// two creations cannot both see room.
async fn at_limit(
    conn: &mut PgConnection,
    kind: KeyKind,
    place: &Authorized<Place>,
) -> Result<Option<i64>, sqlx::Error> {
    let (scope, account) = match place.org() {
        Some(org) => ("org", org),
        None => ("personal", place.place().id as i32),
    };
    let lock = if scope == "org" {
        "SELECT 1 FROM orgs WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT 1 FROM personal_accounts WHERE id = $1 FOR UPDATE"
    };
    sqlx::query(lock).bind(account).execute(&mut *conn).await?;
    let (max_keys, max_service_keys): (i32, Option<i32>) = sqlx::query_as(
        "SELECT max_keys, max_service_keys FROM limits
         WHERE scope_kind = $1 AND (scope_id = $2 OR scope_id IS NULL)
         ORDER BY scope_id NULLS LAST LIMIT 1",
    )
    .bind(scope)
    .bind(account)
    .fetch_one(&mut *conn)
    .await?;
    let (count, limit): (i64, Option<i32>) = if kind == KeyKind::Service {
        let count = sqlx::query_scalar(
            "SELECT count(*) FROM keys
             WHERE kind = 'service' AND revoked_at IS NULL
               AND ((place_kind = 'org' AND place_id = $1)
                    OR (place_kind = 'group' AND place_id IN (SELECT id FROM groups WHERE org_id = $1)))",
        )
        .bind(account)
        .fetch_one(&mut *conn)
        .await?;
        (count, max_service_keys)
    } else {
        let count = sqlx::query_scalar(
            "SELECT count(*) FROM keys
             WHERE kind = 'user' AND revoked_at IS NULL AND place_kind = $1 AND place_id = $2",
        )
        .bind(crate::tenancy::kind_str(place.place().kind))
        .bind(place.place().id as i32)
        .fetch_one(&mut *conn)
        .await?;
        (count, Some(max_keys))
    };
    Ok(limit.map(i64::from).filter(|limit| count >= *limit))
}

#[derive(Debug)]
pub enum RevokeError {
    /// No live API key with that id on that place: the same answer for another
    /// tenant's key and for none (C1).
    NotFound,
    Denied,
    Store(sqlx::Error),
}

impl From<sqlx::Error> for RevokeError {
    fn from(err: sqlx::Error) -> Self {
        RevokeError::Store(err)
    }
}

/// Revokes one API key of `place` (flow F-key).
pub async fn revoke(
    pool: &PgPool,
    actor: &Actor,
    place: &Authorized<Place>,
    key_id: KeyId,
) -> Result<(), RevokeError> {
    if !actor.may_manage_keys(place.place()) {
        return Err(RevokeError::Denied);
    }
    revoke_where(pool, actor, key_id, Some(place.place())).await
}

/// `admin revoke-key`: the host operator holds the database credentials, so the key is
/// found by id alone.
pub async fn revoke_as_operator(pool: &PgPool, key_id: KeyId) -> Result<(), RevokeError> {
    revoke_where(pool, &Actor::Operator, key_id, None).await
}

/// `revoked_at`, the `change_log(key)` row and the audit row in one transaction, so a
/// firewall learns of every revocation within one interval (C13, C20).
async fn revoke_where(
    pool: &PgPool,
    actor: &Actor,
    key_id: KeyId,
    place: Option<PlaceRef>,
) -> Result<(), RevokeError> {
    let mut tx = pool.begin().await?;
    let revoked: Option<Option<i32>> = sqlx::query_scalar(
        "UPDATE keys SET revoked_at = now()
         WHERE id = $1 AND kind IN ('user', 'service') AND revoked_at IS NULL
           AND ($2::text IS NULL OR (place_kind = $2 AND place_id = $3))
         RETURNING place_org(place_kind, place_id)",
    )
    .bind(key_id.0 as i64)
    .bind(place.map(|place| crate::tenancy::kind_str(place.kind)))
    .bind(place.map(|place| place.id as i32))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(org_id) = revoked else {
        return Err(RevokeError::NotFound);
    };
    let _revision = record_change(&mut tx, ChangeKind::Key, &key_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id,
            action: "key.revoke",
            subject: format!("key:{}", key_id.0),
            before: Some(serde_json::json!({"revoked": false})),
            after: Some(serde_json::json!({"revoked": true})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_its_prefix_and_32_alphanumerics() {
        for kind in [KeyKind::User, KeyKind::Automation, KeyKind::Firewall] {
            let secret = generate(kind);
            assert_eq!(secret.len(), 36, "{secret}");
            assert!(secret.starts_with(kind.prefix()));
            assert!(secret[4..].bytes().all(|byte| byte.is_ascii_alphanumeric()));
        }
        assert_ne!(generate(KeyKind::User), generate(KeyKind::User));
    }
}
