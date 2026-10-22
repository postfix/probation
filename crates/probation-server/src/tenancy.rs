//! Where someone belongs and what they may do. Every route first turns a place id into
//! an `Authorized<Place>` here (404 outside the actor's places, C1, T9), and repository
//! functions take only that; an edit is then allowed by `authorize`.

use probation_policy::api::{KeyId, OrgId};
use probation_policy::{CheckedEdit, LayerKind, PlaceRef};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::sync::{ChangeKind, record_change};

pub const PLATFORM: PlaceRef = PlaceRef {
    kind: LayerKind::Platform,
    id: 1,
};

pub fn org_place(org: OrgId) -> PlaceRef {
    PlaceRef {
        kind: LayerKind::Org,
        id: org.0,
    }
}

/// A place kind as the `place_kind` columns spell it.
pub(crate) fn kind_str(kind: LayerKind) -> &'static str {
    match kind {
        LayerKind::Platform => "platform",
        LayerKind::Org => "org",
        LayerKind::Group => "group",
        LayerKind::User => "user",
        LayerKind::Personal => "personal",
    }
}

pub(crate) fn kind_of(text: &str) -> Option<LayerKind> {
    Some(match text {
        "platform" => LayerKind::Platform,
        "org" => LayerKind::Org,
        "group" => LayerKind::Group,
        "user" => LayerKind::User,
        "personal" => LayerKind::Personal,
        _ => return None,
    })
}

/// A new organisation; its layer comes from the `org_layer` trigger.
pub(crate) async fn create_org(conn: &mut PgConnection, name: &str) -> Result<OrgId, sqlx::Error> {
    let id: i32 = sqlx::query_scalar("INSERT INTO orgs (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(conn)
        .await?;
    Ok(OrgId(id as u32))
}

/// A signed-in login, and the organisation its session is confined to when it was
/// opened through that organisation's SSO (T2). Loaded from `sessions` by the portal.
#[derive(Clone, Copy, Debug)]
pub struct Session {
    login_id: i32,
    scope_org_id: Option<i32>,
}

impl Session {
    pub fn new(login_id: i32, scope_org_id: Option<i32>) -> Session {
        Session {
            login_id,
            scope_org_id,
        }
    }
}

/// A place and what tenancy knows about it.
#[derive(Clone, Debug)]
pub struct Place {
    place: PlaceRef,
    org: Option<i32>,
    group: Option<i32>,
    /// The login of a user place or personal account.
    owner_login: Option<i32>,
    /// Its organisation or personal account is suspended (C78).
    suspended: bool,
    /// Platform first, the place last (C9).
    chain: Vec<PlaceRef>,
    /// Its organisation's name, and its group's for a group or a user in one.
    org_name: Option<String>,
    group_name: Option<String>,
}

/// A value only `tenancy` hands out: proof that the session may see it.
#[derive(Clone, Debug)]
pub struct Authorized<T>(T);

impl Authorized<Place> {
    pub fn place(&self) -> PlaceRef {
        self.0.place
    }

    pub fn org(&self) -> Option<i32> {
        self.0.org
    }

    pub fn owner_login(&self) -> Option<i32> {
        self.0.owner_login
    }

    pub fn chain(&self) -> &[PlaceRef] {
        &self.0.chain
    }

    pub fn group(&self) -> Option<i32> {
        self.0.group
    }

    pub fn org_name(&self) -> Option<&str> {
        self.0.org_name.as_deref()
    }

    pub fn group_name(&self) -> Option<&str> {
        self.0.group_name.as_deref()
    }
}

/// The same answer for a foreign place and an unknown one (C1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotFound;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Denied;

/// One role on one place (C4, C27).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    GlobalAdmin,
    OrgAdmin,
    /// Admin of the group the place is.
    GroupAdmin,
    /// The login of a user place or personal account.
    Owner,
    Member,
    /// An automation token on its own layer (C86).
    BlocklistEditor,
}

impl Role {
    pub fn may_edit(self, layer: LayerKind) -> bool {
        match self {
            Role::GlobalAdmin | Role::BlocklistEditor => true,
            Role::OrgAdmin => matches!(layer, LayerKind::Org | LayerKind::Group | LayerKind::User),
            Role::GroupAdmin => layer == LayerKind::Group,
            Role::Owner => matches!(layer, LayerKind::User | LayerKind::Personal),
            Role::Member => false,
        }
    }
}

/// Who is acting, with the roles loaded with the session in the request's transaction.
/// A login's and an automation token's fields are private, so only `tenancy` builds an
/// actor that holds a role (T9).
#[derive(Clone, Debug)]
pub enum Actor {
    Login(LoginActor),
    /// An automation token; its only role is blocklist editor on its own layer, and its
    /// audit rows name its creator (C86).
    Automation(AutomationActor),
    /// The host operator running `probation-server admin`: it holds the database
    /// credentials, so it acts as a global admin, audited with no login.
    Operator,
}

#[derive(Clone, Debug)]
pub struct LoginActor {
    login_id: i32,
    global_admin: bool,
    /// Its role on the one place `Tenancy::actor` loaded it for, so a permit or a key
    /// action is bound to that `Authorized<Place>`.
    roles: Vec<(PlaceRef, Role)>,
}

#[derive(Clone, Debug)]
pub struct AutomationActor {
    token_id: KeyId,
    place: PlaceRef,
    created_by: i32,
}

impl Actor {
    /// A login acting on its own account, with no role on any place: its audit rows
    /// carry the global-admin flag it has.
    pub(crate) fn own_account(login_id: i32, global_admin: bool) -> Actor {
        Actor::Login(LoginActor {
            login_id,
            global_admin,
            roles: Vec::new(),
        })
    }

    /// The login an audit row names.
    pub fn login_id(&self) -> Option<i32> {
        match self {
            Actor::Login(login) => Some(login.login_id),
            Actor::Automation(token) => Some(token.created_by),
            Actor::Operator => None,
        }
    }

    pub fn is_global_admin(&self) -> bool {
        match self {
            Actor::Login(login) => login.global_admin,
            Actor::Automation(_) => false,
            Actor::Operator => true,
        }
    }

    /// The automation token acting, if it is one.
    pub fn token(&self) -> Option<KeyId> {
        match self {
            Actor::Automation(token) => Some(token.token_id),
            _ => None,
        }
    }

    /// The actor's role on `place`: on the place it was loaded for only.
    pub fn role(&self, place: PlaceRef) -> Option<Role> {
        role_on(self, place)
    }

    /// Creating and revoking keys: the place's owner, its organisation's or group's
    /// admin, or a global admin.
    pub fn may_manage_keys(&self, place: PlaceRef) -> bool {
        matches!(
            role_on(self, place),
            Some(Role::GlobalAdmin | Role::OrgAdmin | Role::GroupAdmin | Role::Owner)
        )
    }
}

/// One membership row of the session's login.
struct Membership {
    id: i32,
    org: Option<i32>,
    group: Option<i32>,
    role: String,
}

/// An id a portal route takes, by what it names.
#[derive(Clone, Copy, Debug)]
pub enum Owned {
    Key(i64),
    Group(i32),
    Invitation(i32),
    Range(i32),
    Leave(i32),
}

pub struct Tenancy {
    pool: PgPool,
}

impl Tenancy {
    pub fn new(pool: PgPool) -> Tenancy {
        Tenancy { pool }
    }

    /// `place` when it is the session's personal account, inside one of its
    /// organisations, or the session is a global admin's; an SSO session sees only its
    /// organisation's places (T2). Anything else, unknown places included, is
    /// `NotFound` before any policy or row of the place is read beyond where it sits.
    pub async fn authorized_place(
        &self,
        session: &Session,
        place: PlaceRef,
    ) -> Result<Authorized<Place>, NotFound> {
        let found = async {
            let mut conn = self.pool.acquire().await?;
            let memberships = memberships(&mut conn, session).await?;
            let place = load_place(&mut conn, place).await?;
            Ok::<_, sqlx::Error>((memberships, place))
        }
        .await;
        // A store error answers like a missing place: fail closed.
        let (memberships, place) = match found {
            Ok((memberships, Some(place))) => (memberships, place),
            Ok((_, None)) => return Err(NotFound),
            Err(err) => {
                tracing::error!(error = %err, "authorized_place could not read the store");
                return Err(NotFound);
            }
        };
        let in_scope = session
            .scope_org_id
            .is_none_or(|scope| place.org == Some(scope));
        let global_admin = memberships.iter().any(|m| m.org.is_none());
        let admitted = match place.place.kind {
            LayerKind::Personal => place.owner_login == Some(session.login_id),
            _ => place
                .org
                .is_some_and(|org| memberships.iter().any(|m| m.org == Some(org))),
        };
        if in_scope && (admitted || global_admin) {
            Ok(Authorized(place))
        } else {
            Err(NotFound)
        }
    }

    /// The place a route's id belongs to, through `authorized_place`: a key's place, a
    /// group itself, or the organisation of an invitation, a range or a leave request.
    /// An unknown id and another tenant's are the same `NotFound` (C1, T9).
    pub async fn authorized_owner(
        &self,
        session: &Session,
        owned: Owned,
    ) -> Result<Authorized<Place>, NotFound> {
        let (sql, id) = match owned {
            Owned::Key(id) => (
                "SELECT place_kind, place_id FROM keys WHERE id = $1 AND kind IN ('user', 'service')",
                id,
            ),
            Owned::Group(id) => (
                "SELECT 'group', id FROM groups WHERE id = $1",
                i64::from(id),
            ),
            Owned::Invitation(id) => (
                "SELECT 'org', org_id FROM invitations WHERE id = $1 AND org_id IS NOT NULL",
                i64::from(id),
            ),
            Owned::Range(id) => (
                "SELECT 'org', org_id FROM org_ip_ranges WHERE id = $1",
                i64::from(id),
            ),
            Owned::Leave(id) => (
                "SELECT 'org', org_id FROM leave_requests WHERE id = $1",
                i64::from(id),
            ),
        };
        let found: Result<Option<(String, i32)>, sqlx::Error> = sqlx::query_as(sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await;
        let place = match found {
            Ok(Some((kind, id))) => kind_of(&kind).map(|kind| PlaceRef {
                kind,
                id: id as u32,
            }),
            Ok(None) => None,
            Err(err) => {
                tracing::error!(error = %err, "authorized_owner could not read the store");
                None
            }
        };
        match place {
            Some(place) => self.authorized_place(session, place).await,
            None => Err(NotFound),
        }
    }

    /// Whether the session acts as a global admin: never one opened through an
    /// organisation's SSO (T2). A store error answers no (fail closed).
    pub async fn global_admin(&self, session: &Session) -> bool {
        let found = async {
            let mut conn = self.pool.acquire().await?;
            memberships(&mut conn, session).await
        };
        match found.await {
            Ok(memberships) => memberships.iter().any(|m| m.org.is_none()),
            Err(err) => {
                tracing::error!(error = %err, "global_admin could not read the store");
                false
            }
        }
    }

    /// The session's own place in `account`: its user place in an organisation (its
    /// membership there), or the personal account itself.
    pub async fn own_place(
        &self,
        session: &Session,
        account: &Authorized<Place>,
    ) -> Result<Authorized<Place>, NotFound> {
        let Some(org) = account.org() else {
            return Ok(account.clone());
        };
        let membership: Result<Option<i32>, sqlx::Error> =
            sqlx::query_scalar("SELECT id FROM memberships WHERE login_id = $1 AND org_id = $2")
                .bind(session.login_id)
                .bind(org)
                .fetch_optional(&self.pool)
                .await;
        match membership {
            Ok(Some(id)) => {
                let user = PlaceRef {
                    kind: LayerKind::User,
                    id: id as u32,
                };
                self.authorized_place(session, user).await
            }
            Ok(None) => Err(NotFound),
            Err(err) => {
                tracing::error!(error = %err, "own_place could not read the store");
                Err(NotFound)
            }
        }
    }

    /// The session's login with its role on `place`.
    pub async fn actor(
        &self,
        session: &Session,
        place: &Authorized<Place>,
    ) -> Result<Actor, sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        let memberships = memberships(&mut conn, session).await?;
        let global_admin = memberships.iter().any(|m| m.org.is_none());
        let role = role_for(session.login_id, &memberships, &place.0);
        Ok(Actor::Login(LoginActor {
            login_id: session.login_id,
            global_admin,
            roles: role.map(|role| (place.0.place, role)).into_iter().collect(),
        }))
    }
}

/// One member of an organisation, as its page lists them.
pub struct MemberRow {
    /// The membership's id: the member's user place.
    pub id: i32,
    pub login_id: i32,
    pub email: String,
    pub role: String,
    pub group: Option<i32>,
    /// Joined through the organisation's SSO.
    pub via_sso: bool,
    /// The login belongs to this organisation alone: no personal account, no other
    /// membership (C76).
    pub org_only: bool,
}

/// The members of `org`'s organisation whose logins are live, by email.
pub async fn members(
    pool: &PgPool,
    org: &Authorized<Place>,
) -> Result<Vec<MemberRow>, sqlx::Error> {
    type Row = (i32, i32, String, String, Option<i32>, bool, bool);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT m.id, m.login_id,
                coalesce((SELECT s.email FROM sign_in_methods AS s
                          WHERE s.login_id = m.login_id AND s.email IS NOT NULL ORDER BY s.id LIMIT 1),
                         'Login ' || m.login_id) AS email,
                m.role, m.group_id,
                EXISTS (SELECT 1 FROM sign_in_methods AS s WHERE s.login_id = m.login_id AND s.org_id = m.org_id),
                NOT EXISTS (SELECT 1 FROM personal_accounts AS p WHERE p.login_id = m.login_id)
                    AND NOT EXISTS (SELECT 1 FROM memberships AS o WHERE o.login_id = m.login_id AND o.id <> m.id)
         FROM memberships AS m JOIN logins AS l ON l.id = m.login_id
         WHERE m.org_id = $1 AND l.deleted_at IS NULL
         ORDER BY email, m.id",
    )
    .bind(org.org())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, login_id, email, role, group, via_sso, org_only)| MemberRow {
                id,
                login_id,
                email,
                role,
                group,
                via_sso,
                org_only,
            },
        )
        .collect())
}

/// One group of an organisation, as the organisation and keys pages list it.
pub struct GroupRow {
    pub id: i32,
    pub name: String,
    pub members: i64,
    pub service_keys: i64,
}

/// The groups of `org`'s organisation, by name.
pub async fn groups(pool: &PgPool, org: &Authorized<Place>) -> Result<Vec<GroupRow>, sqlx::Error> {
    let rows: Vec<(i32, String, i64, i64)> = sqlx::query_as(
        "SELECT g.id, g.name,
                (SELECT count(*) FROM memberships AS m WHERE m.group_id = g.id),
                (SELECT count(*) FROM keys AS k WHERE k.kind = 'service' AND k.place_kind = 'group'
                   AND k.place_id = g.id AND k.revoked_at IS NULL)
         FROM groups AS g WHERE g.org_id = $1 ORDER BY g.name, g.id",
    )
    .bind(org.org())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, members, service_keys)| GroupRow {
            id,
            name,
            members,
            service_keys,
        })
        .collect())
}

/// The session's memberships; none for a deleted login. A session opened through an
/// organisation's SSO holds only that organisation's, so it is no global admin there
/// and no admin anywhere else (T2).
async fn memberships(
    conn: &mut PgConnection,
    session: &Session,
) -> Result<Vec<Membership>, sqlx::Error> {
    let rows: Vec<(i32, Option<i32>, Option<i32>, String)> = sqlx::query_as(
        "SELECT m.id, m.org_id, m.group_id, m.role FROM memberships AS m
         JOIN logins AS l ON l.id = m.login_id
         WHERE m.login_id = $1 AND l.deleted_at IS NULL
           AND ($2::integer IS NULL OR m.org_id = $2)",
    )
    .bind(session.login_id)
    .bind(session.scope_org_id)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, org, group, role)| Membership {
            id,
            org,
            group,
            role,
        })
        .collect())
}

/// Where `place` sits, or `None` when it does not exist (or its organisation or personal
/// account is deleted).
async fn load_place(
    conn: &mut PgConnection,
    place: PlaceRef,
) -> Result<Option<Place>, sqlx::Error> {
    let id = place.id as i32;
    let sql = match place.kind {
        LayerKind::Platform => {
            return Ok((place == PLATFORM)
                .then(|| at(place, (None, None, None, "active".to_owned(), None, None))));
        }
        LayerKind::Org => {
            "SELECT o.id, NULL::integer, NULL::integer, o.status, o.name, NULL::text FROM orgs AS o
             WHERE o.id = $1 AND o.deleted_at IS NULL"
        }
        LayerKind::Group => {
            "SELECT g.org_id, g.id, NULL::integer, o.status, o.name, g.name
             FROM groups AS g JOIN orgs AS o ON o.id = g.org_id
             WHERE g.id = $1 AND o.deleted_at IS NULL"
        }
        LayerKind::User => {
            "SELECT m.org_id, m.group_id, m.login_id, o.status, o.name, g.name
             FROM memberships AS m JOIN orgs AS o ON o.id = m.org_id
             LEFT JOIN groups AS g ON g.id = m.group_id
             WHERE m.id = $1 AND o.deleted_at IS NULL"
        }
        LayerKind::Personal => {
            "SELECT NULL::integer, NULL::integer, login_id, status, NULL::text, NULL::text
             FROM personal_accounts WHERE id = $1 AND deleted_at IS NULL"
        }
    };
    let row: Option<PlaceRow> = sqlx::query_as(sql).bind(id).fetch_optional(conn).await?;
    Ok(row.map(|row| at(place, row)))
}

/// Where a place sits: (organisation, group, owner login, status, organisation name,
/// group name).
type PlaceRow = (
    Option<i32>,
    Option<i32>,
    Option<i32>,
    String,
    Option<String>,
    Option<String>,
);

/// `place` as it sits: in its organisation and group, or owned by a login.
fn at(place: PlaceRef, (org, group, owner_login, status, org_name, group_name): PlaceRow) -> Place {
    let chain = [
        Some(PLATFORM),
        org.map(|org| PlaceRef {
            kind: LayerKind::Org,
            id: org as u32,
        }),
        group.map(|group| PlaceRef {
            kind: LayerKind::Group,
            id: group as u32,
        }),
        (!matches!(
            place.kind,
            LayerKind::Platform | LayerKind::Org | LayerKind::Group
        ))
        .then_some(place),
    ]
    .into_iter()
    .flatten()
    .collect();
    Place {
        place,
        org,
        group,
        owner_login,
        suspended: status == "suspended",
        chain,
        org_name,
        group_name,
    }
}

/// The login's role on `place` (C4, C27); none in a suspended organisation or personal
/// account except for a global admin (C78).
fn role_for(login_id: i32, memberships: &[Membership], place: &Place) -> Option<Role> {
    if memberships.iter().any(|m| m.org.is_none()) {
        return Some(Role::GlobalAdmin);
    }
    if place.suspended {
        return None;
    }
    if place.place.kind == LayerKind::Personal {
        return (place.owner_login == Some(login_id)).then_some(Role::Owner);
    }
    let membership = memberships
        .iter()
        .find(|m| m.org.is_some() && m.org == place.org)?;
    Some(match place.place.kind {
        _ if membership.role == "org_admin" => Role::OrgAdmin,
        LayerKind::Group if membership.role == "group_admin" && membership.group == place.group => {
            Role::GroupAdmin
        }
        LayerKind::User if place.place.id as i32 == membership.id => Role::Owner,
        _ => Role::Member,
    })
}

fn role_on(actor: &Actor, place: PlaceRef) -> Option<Role> {
    match actor {
        Actor::Operator => Some(Role::GlobalAdmin),
        Actor::Login(login) => login
            .roles
            .iter()
            .find(|(on, _)| *on == place)
            .map(|(_, role)| *role),
        Actor::Automation(token) => (token.place == place).then_some(Role::BlocklistEditor),
    }
}

/// Permission to save one checked edit, for one place. Its fields are private and so is
/// its constructor, so only `authorize` builds one:
///
/// ```compile_fail,E0624
/// use probation_policy::{LayerKind, PlaceRef};
/// use probation_server::tenancy::EditPermit;
///
/// let forged = EditPermit::granted(Some(1), PlaceRef { kind: LayerKind::Org, id: 1 });
/// ```
#[derive(Debug)]
pub struct EditPermit {
    login_id: Option<i32>,
    place: PlaceRef,
}

impl EditPermit {
    fn granted(login_id: Option<i32>, place: PlaceRef) -> Self {
        Self { login_id, place }
    }

    pub fn login_id(&self) -> Option<i32> {
        self.login_id
    }

    pub fn place(&self) -> PlaceRef {
        self.place
    }
}

/// Permit `actor` to save `checked` only if their role on its place may edit that layer.
pub fn authorize(actor: &Actor, checked: &CheckedEdit) -> Result<EditPermit, Denied> {
    let role = role_on(actor, checked.place()).ok_or(Denied)?;
    if !role.may_edit(checked.layer_kind()) {
        return Err(Denied);
    }
    Ok(EditPermit::granted(actor.login_id(), checked.place()))
}

// ---- Members, groups, invitations, leave requests, ranges, organisations ---------------
//
// Each change writes its `change_log` rows and its audit row in the transaction that
// makes it (02 § Change propagation, C25), and every path that ends or demotes an org
// admin locks the organisation row and recounts first (C60, T21).

#[derive(Debug)]
pub enum ChangeError {
    /// The actor's role does not allow it (403).
    Denied,
    /// The row is gone (404).
    NotFound,
    /// Refused for the reason given, shown on the page.
    Refused(String),
    Store(sqlx::Error),
}

impl From<sqlx::Error> for ChangeError {
    fn from(err: sqlx::Error) -> Self {
        ChangeError::Store(err)
    }
}

/// Whether `actor` runs `place`'s organisation: its org admin or a global admin.
fn runs_org(actor: &Actor, place: &Authorized<Place>) -> bool {
    matches!(
        role_on(actor, place.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    )
}

async fn lock_org(conn: &mut PgConnection, org: i32) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1 FROM orgs WHERE id = $1 FOR UPDATE")
        .bind(org)
        .execute(conn)
        .await
        .map(drop)
}

/// Writes `key` for each live user key on the user place `member`, so firewalls drop
/// them and look them up again (02 § Change propagation).
async fn change_member_keys(conn: &mut PgConnection, member: i32) -> Result<(), sqlx::Error> {
    let keys: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM keys WHERE place_kind = 'user' AND place_id = $1 AND revoked_at IS NULL ORDER BY id",
    )
    .bind(member)
    .fetch_all(&mut *conn)
    .await?;
    for key in keys {
        record_change(conn, ChangeKind::Key, &KeyId(key as u64)).await?;
    }
    Ok(())
}

/// Moves the member at user place `member` into `group` (or into no group), as only an
/// org admin may (C10, C27). A group admin runs the group they are in (C59), so a moved
/// group admin becomes a member. `key` rows for the member's keys make firewalls serve
/// them under the new group's policy within one interval.
pub async fn move_member(
    pool: &PgPool,
    actor: &Actor,
    member: &Authorized<Place>,
    group: Option<&Authorized<Place>>,
) -> Result<(), ChangeError> {
    if !runs_org(actor, member) || member.place().kind != LayerKind::User {
        return Err(ChangeError::Denied);
    }
    if group
        .is_some_and(|group| group.place().kind != LayerKind::Group || group.org() != member.org())
    {
        return Err(ChangeError::NotFound);
    }
    let org = member.org().ok_or(ChangeError::NotFound)?;
    let id = member.place().id as i32;
    let group = group.map(|group| group.place().id as i32);
    let mut tx = pool.begin().await?;
    lock_org(&mut tx, org).await?;
    let before: Option<(Option<i32>, String)> = sqlx::query_as(
        "SELECT group_id, role FROM memberships WHERE id = $1 AND org_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(org)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((old_group, old_role)) = before else {
        return Err(ChangeError::NotFound);
    };
    if old_group == group {
        return Ok(());
    }
    let role: String = sqlx::query_scalar(
        "UPDATE memberships SET group_id = $2,
             role = CASE WHEN role = 'group_admin' THEN 'member' ELSE role END
         WHERE id = $1 RETURNING role",
    )
    .bind(id)
    .bind(group)
    .fetch_one(&mut *tx)
    .await?;
    change_member_keys(&mut tx, id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org),
            action: "member.move",
            subject: format!("member:{id}"),
            before: Some(serde_json::json!({"group": old_group, "role": old_role})),
            after: Some(serde_json::json!({"group": group, "role": role})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// The roles an organisation page grants; a global admin is appointed only from
/// `/admin` (C27, T3).
const ORG_ROLES: [&str; 3] = ["member", "group_admin", "org_admin"];

/// Gives the member at user place `member` `role`, as only an org admin may: an explicit
/// login picked from the member list (T3). A group admin must be in the group they run
/// (C59).
pub async fn set_role(
    pool: &PgPool,
    actor: &Actor,
    member: &Authorized<Place>,
    role: &str,
) -> Result<(), ChangeError> {
    if !runs_org(actor, member) || member.place().kind != LayerKind::User {
        return Err(ChangeError::Denied);
    }
    if !ORG_ROLES.contains(&role) {
        return Err(ChangeError::Refused(
            "Choose member, group admin or org admin.".to_owned(),
        ));
    }
    let org = member.org().ok_or(ChangeError::NotFound)?;
    let id = member.place().id as i32;
    let mut tx = pool.begin().await?;
    lock_org(&mut tx, org).await?;
    let before: Option<(String, Option<i32>)> = sqlx::query_as(
        "SELECT role, group_id FROM memberships WHERE id = $1 AND org_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(org)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((old, group)) = before else {
        return Err(ChangeError::NotFound);
    };
    if old == role {
        return Ok(());
    }
    if old == "org_admin" && last_org_admin(&mut tx, org, id).await? {
        return Err(last_admin_refusal());
    }
    if role == "group_admin" && group.is_none() {
        return Err(ChangeError::Refused(
            "That person is in no group. Put them in a group first: a group admin runs the group they are in.".to_owned(),
        ));
    }
    sqlx::query("UPDATE memberships SET role = $2 WHERE id = $1")
        .bind(id)
        .bind(role)
        .execute(&mut *tx)
        .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org),
            action: "member.role",
            subject: format!("member:{id}"),
            before: Some(serde_json::json!({"role": old, "group": group})),
            after: Some(serde_json::json!({"role": role, "group": group})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Whether the membership `id` is an org admin of `org` with no other live one left.
/// The caller holds the organisation row's lock (C60, T21).
async fn last_org_admin(conn: &mut PgConnection, org: i32, id: i32) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships WHERE id = $2 AND org_id = $1 AND role = 'org_admin')
            AND NOT EXISTS (SELECT 1 FROM memberships AS m JOIN logins AS l ON l.id = m.login_id
                            WHERE m.org_id = $1 AND m.id <> $2 AND m.role = 'org_admin'
                              AND l.deleted_at IS NULL)",
    )
    .bind(org)
    .bind(id)
    .fetch_one(conn)
    .await
}

fn last_admin_refusal() -> ChangeError {
    ChangeError::Refused(
        "Not done: the organisation must always have at least one org admin. Make someone else an org admin first.".to_owned(),
    )
}

/// Ends the membership `id` in `org` under the organisation row's lock: refused for the
/// last org admin; the member's keys are revoked with a `key` row each (C52), and their
/// own layer and any leave request go with the membership. Writes no audit row.
async fn end_membership(conn: &mut PgConnection, org: i32, id: i32) -> Result<(), ChangeError> {
    lock_org(conn, org).await?;
    let exists: Option<i32> = sqlx::query_scalar(
        "SELECT login_id FROM memberships WHERE id = $1 AND org_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(org)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(login) = exists else {
        return Err(ChangeError::NotFound);
    };
    if last_org_admin(conn, org, id).await? {
        return Err(last_admin_refusal());
    }
    let revoked: Vec<i64> = sqlx::query_scalar(
        "UPDATE keys SET revoked_at = now()
         WHERE place_kind = 'user' AND place_id = $1 AND revoked_at IS NULL RETURNING id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    for key in revoked {
        record_change(conn, ChangeKind::Key, &KeyId(key as u64)).await?;
    }
    sqlx::query("DELETE FROM leave_requests WHERE login_id = $1 AND org_id = $2")
        .bind(login)
        .bind(org)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM memberships WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM policy_layers WHERE place_kind = 'user' AND place_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Removes the member at user place `member` from its organisation, as only an org admin
/// may (C52, C60).
pub async fn remove_member(
    pool: &PgPool,
    actor: &Actor,
    member: &Authorized<Place>,
) -> Result<(), ChangeError> {
    if !runs_org(actor, member) || member.place().kind != LayerKind::User {
        return Err(ChangeError::Denied);
    }
    let org = member.org().ok_or(ChangeError::NotFound)?;
    let id = member.place().id as i32;
    let mut tx = pool.begin().await?;
    end_membership(&mut tx, org, id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org),
            action: "member.remove",
            subject: format!("member:{id}"),
            before: Some(serde_json::json!({"member": member.owner_login()})),
            after: None,
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// A member asks to leave `org`'s organisation; an org admin decides (C85).
pub async fn ask_to_leave(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
) -> Result<(), ChangeError> {
    let (Some(login), Some(org_id)) = (actor.login_id(), org.org()) else {
        return Err(ChangeError::Denied);
    };
    let mut tx = pool.begin().await?;
    let asked = sqlx::query(
        "INSERT INTO leave_requests (login_id, org_id)
         SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM memberships WHERE login_id = $1 AND org_id = $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(login)
    .bind(org_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if asked == 0 {
        return Ok(());
    }
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "leave.ask",
            subject: format!("login:{login}"),
            before: None,
            after: Some(serde_json::json!({"asked": true})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Approves the leave request `leave` of `org`'s organisation: the membership ends as a
/// removal does, under the same lock and last-admin recount (C60, C85, T21).
pub async fn approve_leave(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    leave: i32,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) {
        return Err(ChangeError::Denied);
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    lock_org(&mut tx, org_id).await?;
    let member: Option<(i32, i32)> = sqlx::query_as(
        "SELECT m.id, m.login_id FROM leave_requests AS r
         JOIN memberships AS m ON m.login_id = r.login_id AND m.org_id = r.org_id
         WHERE r.id = $1 AND r.org_id = $2",
    )
    .bind(leave)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, login)) = member else {
        return Err(ChangeError::NotFound);
    };
    end_membership(&mut tx, org_id, id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "leave.approve",
            subject: format!("login:{login}"),
            before: Some(serde_json::json!({"member": id})),
            after: None,
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// The member cancels their own leave request while it waits (C88).
pub async fn cancel_leave(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
) -> Result<(), ChangeError> {
    let (Some(login), Some(org_id)) = (actor.login_id(), org.org()) else {
        return Err(ChangeError::Denied);
    };
    let mut tx = pool.begin().await?;
    let cancelled = sqlx::query("DELETE FROM leave_requests WHERE login_id = $1 AND org_id = $2")
        .bind(login)
        .bind(org_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if cancelled == 0 {
        return Ok(());
    }
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "leave.cancel",
            subject: format!("login:{login}"),
            before: Some(serde_json::json!({"asked": true})),
            after: Some(serde_json::json!({"asked": false})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Refuses the leave request `leave`: the person stays a member (C85).
pub async fn refuse_leave(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    leave: i32,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) {
        return Err(ChangeError::Denied);
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    let login: Option<i32> = sqlx::query_scalar(
        "DELETE FROM leave_requests WHERE id = $1 AND org_id = $2 RETURNING login_id",
    )
    .bind(leave)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(login) = login else {
        return Err(ChangeError::NotFound);
    };
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "leave.refuse",
            subject: format!("login:{login}"),
            before: Some(serde_json::json!({"asked": true})),
            after: Some(serde_json::json!({"asked": false})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// One waiting leave request: (id, email, asked on).
pub async fn leave_requests(
    pool: &PgPool,
    org: &Authorized<Place>,
) -> Result<Vec<(i32, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.id,
                coalesce((SELECT s.email FROM sign_in_methods AS s
                          WHERE s.login_id = r.login_id AND s.email IS NOT NULL ORDER BY s.id LIMIT 1),
                         'Login ' || r.login_id),
                to_char(r.created_at, 'DD Mon YYYY')
         FROM leave_requests AS r WHERE r.org_id = $1 ORDER BY r.id",
    )
    .bind(org.org())
    .fetch_all(pool)
    .await
}

/// When the login asked to leave `org`'s organisation, if it is waiting.
pub async fn own_leave_request(
    pool: &PgPool,
    login: i32,
    org: &Authorized<Place>,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT to_char(created_at, 'DD Mon YYYY') FROM leave_requests WHERE login_id = $1 AND org_id = $2",
    )
    .bind(login)
    .bind(org.org())
    .fetch_optional(pool)
    .await
}

/// What deleting group `group` does, for its confirmation (C61): its members and the
/// names of its live service keys.
pub async fn group_effects(
    pool: &PgPool,
    group: &Authorized<Place>,
) -> Result<(i64, Vec<String>), sqlx::Error> {
    let id = group.place().id as i32;
    let members: i64 = sqlx::query_scalar("SELECT count(*) FROM memberships WHERE group_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM keys WHERE kind = 'service' AND place_kind = 'group' AND place_id = $1
           AND revoked_at IS NULL ORDER BY id",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok((members, keys))
}

/// Deletes group `group`, as only an org admin may (C61): its policy goes, its service
/// keys are revoked and its members fall back to the organisation policy, with a `key`
/// row for each of those keys (02 § Change propagation). Its group admins become
/// members (C59).
pub async fn delete_group(
    pool: &PgPool,
    actor: &Actor,
    group: &Authorized<Place>,
) -> Result<(), ChangeError> {
    if !runs_org(actor, group) || group.place().kind != LayerKind::Group {
        return Err(ChangeError::Denied);
    }
    let org = group.org().ok_or(ChangeError::NotFound)?;
    let id = group.place().id as i32;
    let mut tx = pool.begin().await?;
    lock_org(&mut tx, org).await?;
    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM groups WHERE id = $1 AND org_id = $2 FOR UPDATE")
            .bind(id)
            .bind(org)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(name) = name else {
        return Err(ChangeError::NotFound);
    };
    let members: Vec<i32> = sqlx::query_scalar(
        "UPDATE memberships SET role = CASE WHEN role = 'group_admin' THEN 'member' ELSE role END
                            WHERE group_id = $1 RETURNING id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let revoked: Vec<i64> = sqlx::query_scalar(
        "UPDATE keys SET revoked_at = now()
         WHERE kind = 'service' AND place_kind = 'group' AND place_id = $1 AND revoked_at IS NULL
         RETURNING id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    for key in &revoked {
        record_change(&mut tx, ChangeKind::Key, &KeyId(*key as u64)).await?;
    }
    for member in &members {
        change_member_keys(&mut tx, *member).await?;
    }
    sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM policy_layers WHERE place_kind = 'group' AND place_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org),
            action: "group.delete",
            subject: format!("group:{id}"),
            before: Some(serde_json::json!({
                "group": id,
                "name": name,
                "members": members,
                "service_keys_revoked": revoked,
            })),
            after: None,
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// An invitation link lives 7 days (C43).
const INVITATION_DAYS: i32 = 7;

/// Invites `email` to `org`'s organisation as `role` (in `group`), as only an org admin
/// may, and mails the single-use link (C43). The grant ceiling (T3): an org admin
/// invites a member, group admin or org admin of their own organisation only, with a
/// group of it; a group admin runs a group, so they are invited into one (C59). The
/// address is only where the link goes: whoever signs in and opens it accepts it.
pub async fn invite(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    email: &str,
    role: &str,
    group: Option<&Authorized<Place>>,
    base: &url::Url,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) || org.place().kind != LayerKind::Org || !ORG_ROLES.contains(&role) {
        return Err(ChangeError::Denied);
    }
    if group.is_some_and(|group| group.place().kind != LayerKind::Group || group.org() != org.org())
    {
        return Err(ChangeError::NotFound);
    }
    let Some(email) = crate::accounts::normal_email(email) else {
        return Err(ChangeError::Refused(
            "Enter the email address to send the invitation to.".to_owned(),
        ));
    };
    if role == "group_admin" && group.is_none() {
        return Err(ChangeError::Refused(
            "Choose the group a new group admin will run: a group admin runs the group they are in.".to_owned(),
        ));
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let group = group.map(|group| group.place().id as i32);
    let token = crate::accounts::random_token();
    let mut tx = pool.begin().await?;
    let id: i32 = sqlx::query_scalar(
        "INSERT INTO invitations (token_hash, org_id, group_id, role, created_by, expires_at, email)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6), $7) RETURNING id",
    )
    .bind(crate::accounts::token_hash(&token))
    .bind(org_id)
    .bind(group)
    .bind(role)
    .bind(actor.login_id())
    .bind(INVITATION_DAYS)
    .bind(&email)
    .fetch_one(&mut *tx)
    .await?;
    let body = format!(
        "You are invited to join {} on Probation.\n\nSign in (or create a login), then open this link to accept:\n\n{}invite?token={token}\n\nThe link works once and expires in {INVITATION_DAYS} days.\n",
        org.org_name().unwrap_or_default(),
        crate::accounts::base_path(base)
    );
    crate::accounts::enqueue(
        &mut tx,
        &email,
        "invitation",
        "Your Probation invitation",
        &body,
    )
    .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "invitation.create",
            subject: format!("invitation:{id}"),
            before: None,
            after: Some(serde_json::json!({"email": email, "role": role, "group": group})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// What a live invitation link grants: (organisation, role, group).
pub async fn invitation(
    pool: &PgPool,
    token: &str,
) -> Result<Option<(String, String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT o.name, i.role, g.name FROM invitations AS i
         JOIN orgs AS o ON o.id = i.org_id AND o.deleted_at IS NULL
         LEFT JOIN groups AS g ON g.id = i.group_id
         WHERE i.token_hash = $1 AND i.accepted_by IS NULL AND i.expires_at > now()",
    )
    .bind(crate::accounts::token_hash(token))
    .fetch_optional(pool)
    .await
}

/// Accepts an invitation link for the signed-in `login`: the conditional update takes
/// the link once, so under concurrent accepts exactly one login gets the grant (T3).
/// `None` when the link is unknown, used or expired; refused, with the link left unused,
/// when the login is a member already.
pub async fn accept_invitation(
    pool: &PgPool,
    login: i32,
    token: &str,
) -> Result<Option<i32>, ChangeError> {
    let mut tx = pool.begin().await?;
    let taken: Option<(i32, i32, Option<i32>, String)> = sqlx::query_as(
        "UPDATE invitations SET accepted_by = $2
         WHERE token_hash = $1 AND accepted_by IS NULL AND expires_at > now()
           AND org_id IN (SELECT id FROM orgs WHERE deleted_at IS NULL)
         RETURNING id, org_id, group_id, role",
    )
    .bind(crate::accounts::token_hash(token))
    .bind(login)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, org, group, role)) = taken else {
        return Ok(None);
    };
    let member: Option<i32> = sqlx::query_scalar(
        "INSERT INTO memberships (login_id, org_id, group_id, role) VALUES ($1, $2, $3, $4)
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(login)
    .bind(org)
    .bind(group)
    .bind(&role)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(member) = member else {
        return Err(ChangeError::Refused(
            "You are a member of this organisation already. The link stays unused.".to_owned(),
        ));
    };
    let actor = crate::accounts::login_actor(&mut tx, login).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: Some(org),
            action: "invitation.accept",
            subject: format!("invitation:{id}"),
            before: None,
            after: Some(
                serde_json::json!({"member": member, "login": login, "role": role, "group": group}),
            ),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(Some(org))
}

/// Cancels a waiting invitation of `org`'s organisation.
pub async fn cancel_invitation(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    id: i32,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) {
        return Err(ChangeError::Denied);
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    let email: Option<String> = sqlx::query_scalar(
        "DELETE FROM invitations WHERE id = $1 AND org_id = $2 AND accepted_by IS NULL RETURNING email",
    )
    .bind(id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(email) = email else {
        return Err(ChangeError::NotFound);
    };
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "invitation.cancel",
            subject: format!("invitation:{id}"),
            before: Some(serde_json::json!({"email": email})),
            after: None,
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// The waiting invitations of `org`'s organisation: (id, email, role, expires on).
pub async fn invitations(
    pool: &PgPool,
    org: &Authorized<Place>,
) -> Result<Vec<(i32, String, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, email, role, to_char(expires_at, 'DD Mon YYYY') FROM invitations
         WHERE org_id = $1 AND accepted_by IS NULL AND expires_at > now() ORDER BY id",
    )
    .bind(org.org())
    .fetch_all(pool)
    .await
}

/// Registers `cidr` for `org`'s network lock. It does nothing until the operator
/// approves it (C30, C77).
pub async fn add_range(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    cidr: &str,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) {
        return Err(ChangeError::Denied);
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let cidr = cidr.trim();
    let Ok(range) = cidr.parse::<ipnet::IpNet>() else {
        return Err(ChangeError::Refused(format!(
            "\"{cidr}\" is not a valid IP range. Write it like 192.0.2.0/24."
        )));
    };
    let range = range.trunc();
    let mut tx = pool.begin().await?;
    let id: i32 = sqlx::query_scalar(
        "INSERT INTO org_ip_ranges (org_id, cidr) VALUES ($1, $2::cidr) RETURNING id",
    )
    .bind(org_id)
    .bind(range.to_string())
    .fetch_one(&mut *tx)
    .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "range.add",
            subject: format!("range:{id}"),
            before: None,
            after: Some(serde_json::json!({"cidr": range.to_string(), "status": "waiting"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Deletes range `id` of `org`'s organisation; an approved one writes `ranges`, so every
/// firewall drops it within one interval (C87).
pub async fn delete_range(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    id: i32,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) {
        return Err(ChangeError::Denied);
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    let deleted: Option<(String, bool)> = sqlx::query_as(
        "DELETE FROM org_ip_ranges WHERE id = $1 AND org_id = $2
         RETURNING cidr::text, approved_by IS NOT NULL",
    )
    .bind(id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((cidr, approved)) = deleted else {
        return Err(ChangeError::NotFound);
    };
    if approved {
        record_change(&mut tx, ChangeKind::Ranges, &org_id).await?;
    }
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "range.delete",
            subject: format!("range:{id}"),
            before: Some(serde_json::json!({"cidr": cidr, "approved": approved})),
            after: None,
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Sends a refused range back to the operator (C87).
pub async fn resubmit_range(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    id: i32,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) {
        return Err(ChangeError::Denied);
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    let refused: Option<(String, String)> = sqlx::query_as(
        "UPDATE org_ip_ranges AS r SET refused_reason = NULL
         FROM (SELECT refused_reason FROM org_ip_ranges WHERE id = $1) AS old
         WHERE r.id = $1 AND r.org_id = $2 AND r.refused_reason IS NOT NULL
         RETURNING r.cidr::text, old.refused_reason",
    )
    .bind(id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((cidr, reason)) = refused else {
        return Err(ChangeError::NotFound);
    };
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "range.resubmit",
            subject: format!("range:{id}"),
            before: Some(serde_json::json!({"cidr": cidr, "status": "refused", "reason": reason})),
            after: Some(serde_json::json!({"cidr": cidr, "status": "waiting"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// One network-lock range of an organisation, as its page lists it.
pub struct RangeRow {
    pub id: i32,
    pub cidr: String,
    pub approved: bool,
    /// The operator's reason when refused.
    pub refused: Option<String>,
}

pub async fn ranges(pool: &PgPool, org: &Authorized<Place>) -> Result<Vec<RangeRow>, sqlx::Error> {
    let rows: Vec<(i32, String, bool, Option<String>)> = sqlx::query_as(
        "SELECT id, cidr::text, approved_by IS NOT NULL, refused_reason FROM org_ip_ranges
         WHERE org_id = $1 ORDER BY id",
    )
    .bind(org.org())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, cidr, approved, refused)| RangeRow {
            id,
            cidr,
            approved,
            refused,
        })
        .collect())
}

/// An organisation stays restorable for 30 days after its deletion (C33).
const RESTORE_DAYS: i32 = 30;

/// Deletes `org`'s organisation once its name is typed, as only an org admin may (C33):
/// a `place` row makes every firewall refuse its keys within one interval; everything
/// else stays restorable for 30 days.
pub async fn delete_org(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    confirm: &str,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) || org.place().kind != LayerKind::Org {
        return Err(ChangeError::Denied);
    }
    let name = org.org_name().unwrap_or_default();
    if confirm.trim() != name {
        return Err(ChangeError::Refused(format!(
            "Not deleted. Type {name} to confirm."
        )));
    }
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    let deleted = sqlx::query(
        "UPDATE orgs SET deleted_at = now(), restore_until = now() + make_interval(days => $2)
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(org_id)
    .bind(RESTORE_DAYS)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if deleted == 0 {
        return Err(ChangeError::NotFound);
    }
    record_change(&mut tx, ChangeKind::Place, &org.place()).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "org.delete",
            subject: format!("org:{org_id}"),
            before: Some(serde_json::json!({"name": name, "deleted": false})),
            after: Some(serde_json::json!({"name": name, "deleted": true})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// The deleted organisations the session may restore: those it is an org admin of,
/// still within their 30 days, as (id, name, deleted on, erased on) (C63).
pub async fn restorable_orgs(
    pool: &PgPool,
    session: &Session,
) -> Result<Vec<(i32, String, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT o.id, o.name, to_char(o.deleted_at, 'DD Mon YYYY'), to_char(o.restore_until, 'DD Mon YYYY')
         FROM orgs AS o JOIN memberships AS m ON m.org_id = o.id AND m.role = 'org_admin'
         JOIN logins AS l ON l.id = m.login_id AND l.deleted_at IS NULL
         WHERE m.login_id = $1 AND o.deleted_at IS NOT NULL AND o.restore_until > now()
           AND ($2::integer IS NULL OR o.id = $2)
         ORDER BY o.name",
    )
    .bind(session.login_id)
    .bind(session.scope_org_id)
    .fetch_all(pool)
    .await
}

/// Restores deleted organisation `org` within its 30 days; any of its org admins may
/// (C63). A deleted organisation is no `Authorized<Place>`, so the session's admin role
/// there is checked here, under the row's lock; another tenant's, an unknown and an
/// expired one are all `NotFound` (C1). Its keys work again within one interval.
pub async fn restore_org(pool: &PgPool, session: &Session, org: i32) -> Result<(), ChangeError> {
    let mut tx = pool.begin().await?;
    let restorable: Option<String> = sqlx::query_scalar(
        "SELECT o.name FROM orgs AS o
         WHERE o.id = $1 AND o.deleted_at IS NOT NULL AND o.restore_until > now()
           AND ($3::integer IS NULL OR o.id = $3)
           AND EXISTS (SELECT 1 FROM memberships AS m JOIN logins AS l ON l.id = m.login_id
                       WHERE m.org_id = o.id AND m.login_id = $2 AND m.role = 'org_admin'
                         AND l.deleted_at IS NULL)
         FOR UPDATE OF o",
    )
    .bind(org)
    .bind(session.login_id)
    .bind(session.scope_org_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(name) = restorable else {
        return Err(ChangeError::NotFound);
    };
    sqlx::query("UPDATE orgs SET deleted_at = NULL, restore_until = NULL WHERE id = $1")
        .bind(org)
        .execute(&mut *tx)
        .await?;
    let place = PlaceRef {
        kind: LayerKind::Org,
        id: org as u32,
    };
    record_change(&mut tx, ChangeKind::Place, &place).await?;
    let actor = crate::accounts::login_actor(&mut tx, session.login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: Some(org),
            action: "org.restore",
            subject: format!("org:{org}"),
            before: Some(serde_json::json!({"name": name, "deleted": true})),
            after: Some(serde_json::json!({"name": name, "deleted": false})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Erases a deleted organisation whose 30 days have passed (C33): the keys of its places
/// with their activity, its layers, and the organisation with everything that hangs off
/// it. When it held an approved range, `ranges` sends every firewall the smaller table
/// in the same transaction (C63, C87). The audit log keeps its rows.
pub(crate) async fn erase_org(conn: &mut PgConnection, org: i32) -> Result<(), sqlx::Error> {
    let held_range: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM org_ip_ranges WHERE org_id = $1 AND approved_by IS NOT NULL)",
    )
    .bind(org)
    .fetch_one(&mut *conn)
    .await?;
    // Every place of the organisation, as (kind, id).
    let places = "SELECT 'org'::text, $1::integer
                  UNION ALL SELECT 'group', id FROM groups WHERE org_id = $1
                  UNION ALL SELECT 'user', id FROM memberships WHERE org_id = $1";
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM activity WHERE (place_kind, place_id) IN ({places})
            OR key_id IN (SELECT id FROM keys WHERE (place_kind, place_id) IN ({places}))"
    )))
    .bind(org)
    .execute(&mut *conn)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM keys WHERE (place_kind, place_id) IN ({places})"
    )))
    .bind(org)
    .execute(&mut *conn)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM policy_layers WHERE (place_kind, place_id) IN ({places})"
    )))
    .bind(org)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM orgs WHERE id = $1")
        .bind(org)
        .execute(&mut *conn)
        .await?;
    if held_range {
        record_change(conn, ChangeKind::Ranges, &org).await?;
    }
    Ok(())
}

/// A group's name: 1 to 100 characters.
fn group_name(name: &str) -> Result<&str, ChangeError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ChangeError::Refused(
            "Give the group a name of at most 100 characters.".to_owned(),
        ));
    }
    Ok(name)
}

/// Creates a group in `org`'s organisation, as only an org admin may; its layer comes
/// from the `group_layer` trigger.
pub async fn create_group(
    pool: &PgPool,
    actor: &Actor,
    org: &Authorized<Place>,
    name: &str,
) -> Result<(), ChangeError> {
    if !runs_org(actor, org) || org.place().kind != LayerKind::Org {
        return Err(ChangeError::Denied);
    }
    let name = group_name(name)?;
    let org_id = org.org().ok_or(ChangeError::NotFound)?;
    let mut tx = pool.begin().await?;
    let id: i32 =
        sqlx::query_scalar("INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id")
            .bind(org_id)
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "group.create",
            subject: format!("group:{id}"),
            before: None,
            after: Some(serde_json::json!({"group": id, "name": name})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Renames group `group`, as only an org admin may.
pub async fn rename_group(
    pool: &PgPool,
    actor: &Actor,
    group: &Authorized<Place>,
    name: &str,
) -> Result<(), ChangeError> {
    if !runs_org(actor, group) || group.place().kind != LayerKind::Group {
        return Err(ChangeError::Denied);
    }
    let name = group_name(name)?;
    let org = group.org().ok_or(ChangeError::NotFound)?;
    let id = group.place().id as i32;
    let mut tx = pool.begin().await?;
    let old: Option<String> = sqlx::query_scalar(
        "UPDATE groups AS g SET name = $3 FROM (SELECT name FROM groups WHERE id = $1) AS old
         WHERE g.id = $1 AND g.org_id = $2 RETURNING old.name",
    )
    .bind(id)
    .bind(org)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(old) = old else {
        return Err(ChangeError::NotFound);
    };
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org),
            action: "group.rename",
            subject: format!("group:{id}"),
            before: Some(serde_json::json!({"group": id, "name": old})),
            after: Some(serde_json::json!({"group": id, "name": name})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}
