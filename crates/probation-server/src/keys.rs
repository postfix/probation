//! Credentials: API keys (`prb_`, C99), automation tokens (`aut_`) and firewall tokens
//! (`fwt_`). A credential is shown once at creation; only its SHA-256 is stored, and
//! every query filters its kind, so one kind never passes for another (T9).

use std::num::NonZeroU32;

use probation_policy::api::{AccountKind, KeyHash, KeyId, LimitChange, LimitSource};
use probation_policy::{LayerKind, PlaceRef};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::sync::{ChangeKind, record_change};
use crate::tenancy::{Actor, Authorized, ChangeError, Place, Role};

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

    pub(crate) const fn as_str(self) -> &'static str {
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

// ---- Automation tokens (C80, C86) ------------------------------------------------------

/// One live automation token as its page lists it.
pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub last4: String,
    pub created: String,
    /// "Acme organisation", "Frontend group" or "Platform".
    pub layer: String,
    pub created_by: String,
}

/// Creates an automation token for `place`'s layer, shown once: an organisation's or
/// one of its groups' layers by its org admin, the platform layer by a global admin
/// (C80, C86). Its creator is its `owner_login`, so the token goes when they lose the
/// role that let them create it.
pub async fn create_token(
    pool: &PgPool,
    actor: &Actor,
    place: &Authorized<Place>,
    name: &str,
) -> Result<NewKey, KeyError> {
    let allowed = match place.place().kind {
        LayerKind::Platform => actor.role(place.place()) == Some(Role::GlobalAdmin),
        LayerKind::Org | LayerKind::Group => matches!(
            actor.role(place.place()),
            Some(Role::OrgAdmin | Role::GlobalAdmin)
        ),
        LayerKind::User | LayerKind::Personal => false,
    };
    let Some(login) = actor.login_id().filter(|_| allowed) else {
        return Err(KeyError::Denied);
    };
    let mut tx = pool.begin().await?;
    // The role again under the lock every path that ends it takes (the organisation's
    // row, or the platform's), so a token is never created by a role just lost (C86).
    let org = place.org();
    let lock = if org.is_some() {
        "SELECT 1 FROM orgs WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT 1 FROM platform_settings WHERE id = 1 AND $1::integer IS NULL FOR UPDATE"
    };
    sqlx::query(lock).bind(org).execute(&mut *tx).await?;
    let holds: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships AS m JOIN logins AS l ON l.id = m.login_id
                        WHERE m.login_id = $1 AND l.deleted_at IS NULL
                          AND (m.org_id IS NULL OR (m.role = 'org_admin' AND m.org_id = $2)))",
    )
    .bind(login)
    .bind(org)
    .fetch_one(&mut *tx)
    .await?;
    if !holds {
        return Err(KeyError::Denied);
    }
    let token = insert(
        &mut tx,
        KeyKind::Automation,
        place.place(),
        Some(login),
        name,
    )
    .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: place.org(),
            action: "automation.create",
            subject: format!("key:{}", token.id.0),
            before: None,
            after: Some(serde_json::json!({
                "name": name,
                "place": place.place(),
                "last4": &token.secret[token.secret.len() - 4..],
            })),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(token)
}

/// Revokes the automation token `id` of `place`'s layer (its organisation's layers for
/// an org place).
pub async fn revoke_token(
    pool: &PgPool,
    actor: &Actor,
    place: &Authorized<Place>,
    id: i64,
) -> Result<(), RevokeError> {
    if !matches!(
        actor.role(place.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    ) {
        return Err(RevokeError::Denied);
    }
    let mut tx = pool.begin().await?;
    let revoked = sqlx::query(
        "UPDATE keys SET revoked_at = now()
         WHERE id = $1 AND kind = 'automation' AND revoked_at IS NULL
           AND ((place_kind = $2 AND place_id = $3)
                OR ($2 = 'org' AND place_kind = 'group'
                    AND place_id IN (SELECT id FROM groups WHERE org_id = $3)))",
    )
    .bind(id)
    .bind(crate::tenancy::kind_str(place.place().kind))
    .bind(place.place().id as i32)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if revoked == 0 {
        return Err(RevokeError::NotFound);
    }
    let () = audit_token_revoked(&mut tx, actor, place.org(), id).await?;
    let () = tx.commit().await?;
    Ok(())
}

async fn audit_token_revoked(
    conn: &mut PgConnection,
    actor: &Actor,
    org_id: Option<i32>,
    id: i64,
) -> Result<(), sqlx::Error> {
    audit::record(
        conn,
        audit::Entry {
            actor,
            org_id,
            action: "automation.revoke",
            subject: format!("key:{id}"),
            before: Some(serde_json::json!({"revoked": false})),
            after: Some(serde_json::json!({"revoked": true})),
        },
    )
    .await
}

/// Revokes, each with its audit row and in the caller's transaction, the automation
/// tokens `login` created that its roles no longer cover: a platform token needs a
/// global admin, an organisation's one its org admin or a global admin (C86). `all`
/// revokes every one, for a login that is deleted.
pub(crate) async fn revoke_tokens_of(
    conn: &mut PgConnection,
    actor: &Actor,
    login: i32,
    all: bool,
) -> Result<(), sqlx::Error> {
    let revoked: Vec<(i64, Option<i32>)> = sqlx::query_as(
        "UPDATE keys AS k SET revoked_at = now()
         WHERE k.kind = 'automation' AND k.owner_login = $1 AND k.revoked_at IS NULL
           AND ($2 OR NOT EXISTS (
               SELECT 1 FROM memberships AS m
               WHERE m.login_id = $1
                 AND (m.org_id IS NULL
                      OR (m.role = 'org_admin' AND m.org_id = place_org(k.place_kind, k.place_id)))))
         RETURNING k.id, place_org(k.place_kind, k.place_id)",
    )
    .bind(login)
    .bind(all)
    .fetch_all(&mut *conn)
    .await?;
    for (id, org) in revoked {
        audit_token_revoked(conn, actor, org, id).await?;
    }
    Ok(())
}

/// The live automation tokens of `place`'s layer, and of its groups' for an
/// organisation.
pub async fn tokens(
    pool: &PgPool,
    place: &Authorized<Place>,
) -> Result<Vec<TokenRow>, sqlx::Error> {
    type Row = (i64, String, String, String, String, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT k.id, k.name, k.last4, to_char(k.created_at, 'DD Mon YYYY'),
                CASE k.place_kind WHEN 'platform' THEN 'Platform'
                                  WHEN 'org' THEN o.name || ' organisation'
                                  ELSE g.name || ' group' END,
                (SELECT m.email FROM sign_in_methods AS m WHERE m.login_id = k.owner_login
                 AND m.email IS NOT NULL ORDER BY m.id LIMIT 1)
         FROM keys AS k
         LEFT JOIN orgs AS o ON k.place_kind = 'org' AND o.id = k.place_id
         LEFT JOIN groups AS g ON k.place_kind = 'group' AND g.id = k.place_id
         WHERE k.kind = 'automation' AND k.revoked_at IS NULL
           AND ((k.place_kind = $1 AND k.place_id = $2)
                OR ($1 = 'org' AND k.place_kind = 'group' AND g.org_id = $2))
         ORDER BY k.id",
    )
    .bind(crate::tenancy::kind_str(place.place().kind))
    .bind(place.place().id as i32)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, last4, created, layer, created_by)| TokenRow {
            id,
            name,
            last4,
            created,
            layer,
            created_by: created_by.unwrap_or_default(),
        })
        .collect())
}

// ---- Revoking every key of a personal account, and limits (C28, C51, C65, C67) --------

/// "Revoke keys" on a personal account: every live key of it, each with its `key` row,
/// and one audit row (C65).
pub async fn revoke_all(
    pool: &PgPool,
    actor: &Actor,
    place: &Authorized<Place>,
) -> Result<(), RevokeError> {
    if actor.role(place.place()) != Some(Role::GlobalAdmin)
        || place.place().kind != LayerKind::Personal
    {
        return Err(RevokeError::Denied);
    }
    let mut tx = pool.begin().await?;
    let revoked: Vec<i64> = sqlx::query_scalar(
        "UPDATE keys SET revoked_at = now()
         WHERE place_kind = 'personal' AND place_id = $1 AND kind = 'user' AND revoked_at IS NULL
         RETURNING id",
    )
    .bind(place.place().id as i32)
    .fetch_all(&mut *tx)
    .await?;
    for key in &revoked {
        record_change(&mut tx, ChangeKind::Key, &KeyId(*key as u64)).await?;
    }
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "keys.revoke_all",
            subject: format!("personal:{}", place.place().id),
            before: Some(serde_json::json!({"live": revoked})),
            after: Some(serde_json::json!({"live": []})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// One `limits` row: requests a minute, keys (per member in an organisation) and, for
/// organisations, service keys (C28, C51).
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
pub struct Limits {
    pub rate_per_min: i32,
    pub max_keys: i32,
    pub max_service_keys: Option<i32>,
}

impl Limits {
    fn problem(&self) -> Option<&'static str> {
        if self.rate_per_min < 1 {
            Some("Not saved. The most requests per minute must be at least 1.")
        } else if self.max_keys < 1 {
            Some("Not saved. The most keys must be at least 1.")
        } else if self.max_service_keys.is_some_and(|keys| keys < 0) {
            Some("Not saved. The most service keys cannot be below 0.")
        } else {
            None
        }
    }
}

/// Saves the default limits of an account kind (`org` `None`), or one organisation's
/// own (C67), as only a global admin may. A `limits` row updates the rate of every
/// cached key it covers in place (K2).
pub async fn set_limits(
    pool: &PgPool,
    actor: &Actor,
    kind: AccountKind,
    org: Option<&Authorized<Place>>,
    limits: Limits,
) -> Result<(), ChangeError> {
    if !actor.is_global_admin()
        || org.is_some_and(|org| {
            actor.role(org.place()) != Some(Role::GlobalAdmin) || kind != AccountKind::Org
        })
    {
        return Err(ChangeError::Denied);
    }
    if let Some(problem) = limits.problem() {
        return Err(ChangeError::Refused(problem.to_owned()));
    }
    let scope_id = org.and_then(|org| org.org());
    let scope = kind_tag(kind);
    let service = match kind {
        AccountKind::Org => limits.max_service_keys,
        AccountKind::Personal => None,
    };
    let mut tx = pool.begin().await?;
    let before: Option<(i32, i32, Option<i32>)> = sqlx::query_as(
        "SELECT rate_per_min, max_keys, max_service_keys FROM limits
         WHERE scope_kind = $1 AND scope_id IS NOT DISTINCT FROM $2 FOR UPDATE",
    )
    .bind(scope)
    .bind(scope_id)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO limits (scope_kind, scope_id, rate_per_min, max_keys, max_service_keys)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (scope_kind, scope_id) DO UPDATE
         SET rate_per_min = $3, max_keys = $4, max_service_keys = $5",
    )
    .bind(scope)
    .bind(scope_id)
    .bind(limits.rate_per_min)
    .bind(limits.max_keys)
    .bind(service)
    .execute(&mut *tx)
    .await?;
    let source = if scope_id.is_some() {
        LimitSource::Override
    } else {
        LimitSource::Default
    };
    record_change(
        &mut tx,
        ChangeKind::Limits,
        &LimitChange {
            scope_kind: kind,
            scope_id: scope_id.map(|id| id as u32),
            rate_per_min: NonZeroU32::new(limits.rate_per_min as u32),
            source,
        },
    )
    .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: scope_id,
            action: "limits.set",
            subject: match scope_id {
                Some(org) => format!("org:{org}"),
                None => format!("{scope}:default"),
            },
            before: before.map(|(rate, keys, service)| {
                serde_json::json!({"rate_per_min": rate, "max_keys": keys, "max_service_keys": service})
            }),
            after: Some(serde_json::json!({
                "rate_per_min": limits.rate_per_min,
                "max_keys": limits.max_keys,
                "max_service_keys": service,
            })),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// "Back to default" for organisation `org`: its row goes, and a `limits` row for it
/// carries the default's rate with source `default` (02 § Change propagation).
pub async fn reset_limits(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
) -> Result<(), ChangeError> {
    if actor.role(org.place()) != Some(Role::GlobalAdmin) {
        return Err(ChangeError::Denied);
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    let removed: Option<(i32, i32, Option<i32>)> = sqlx::query_as(
        "DELETE FROM limits WHERE scope_kind = 'org' AND scope_id = $1
         RETURNING rate_per_min, max_keys, max_service_keys",
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((rate, keys, service)) = removed else {
        return Ok(());
    };
    let default: i32 = sqlx::query_scalar(
        "SELECT rate_per_min FROM limits WHERE scope_kind = 'org' AND scope_id IS NULL",
    )
    .fetch_one(&mut *tx)
    .await?;
    record_change(
        &mut tx,
        ChangeKind::Limits,
        &LimitChange {
            scope_kind: AccountKind::Org,
            scope_id: Some(org_id as u32),
            rate_per_min: NonZeroU32::new(default as u32),
            source: LimitSource::Default,
        },
    )
    .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "limits.reset",
            subject: format!("org:{org_id}"),
            before: Some(
                serde_json::json!({"rate_per_min": rate, "max_keys": keys, "max_service_keys": service}),
            ),
            after: Some(serde_json::json!({"default": true})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

fn kind_tag(kind: AccountKind) -> &'static str {
    match kind {
        AccountKind::Org => "org",
        AccountKind::Personal => "personal",
    }
}

/// One `limits` row as `/admin` shows it: the kind's default (`org` `None`) or one
/// organisation's own, with its name.
pub struct LimitsRow {
    pub kind: AccountKind,
    pub org: Option<(i32, String)>,
    pub limits: Limits,
}

/// Every `limits` row: the two defaults first, then the organisations' own by name.
pub async fn limits(pool: &PgPool) -> Result<Vec<LimitsRow>, sqlx::Error> {
    type Row = (String, Option<i32>, Option<String>, i32, i32, Option<i32>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT l.scope_kind, l.scope_id, o.name, l.rate_per_min, l.max_keys, l.max_service_keys
         FROM limits AS l LEFT JOIN orgs AS o ON l.scope_kind = 'org' AND o.id = l.scope_id
         ORDER BY l.scope_id IS NOT NULL, l.scope_kind DESC, o.name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(kind, id, name, rate, keys, service)| LimitsRow {
            kind: if kind == "org" {
                AccountKind::Org
            } else {
                AccountKind::Personal
            },
            org: id.map(|id| (id, name.unwrap_or_default())),
            limits: Limits {
                rate_per_min: rate,
                max_keys: keys,
                max_service_keys: service,
            },
        })
        .collect())
}
