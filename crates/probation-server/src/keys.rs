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
