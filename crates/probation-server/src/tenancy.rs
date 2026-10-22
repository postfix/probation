//! Where someone belongs and what they may do. Every route first turns a place id into
//! an `Authorized<Place>` here (404 outside the actor's places, C1, T9), and repository
//! functions take only that; an edit is then allowed by `authorize`.

use probation_policy::api::{KeyId, OrgId};
use probation_policy::{CheckedEdit, LayerKind, PlaceRef};
use sqlx::{PgConnection, PgPool};

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
#[derive(Clone, Debug)]
pub enum Actor {
    Login {
        login_id: i32,
        global_admin: bool,
        roles: Vec<(PlaceRef, Role)>,
    },
    /// An automation token; its only role is blocklist editor on its own layer, and its
    /// audit rows name its creator (C86).
    Automation {
        token_id: KeyId,
        place: PlaceRef,
        created_by: i32,
    },
    /// The host operator running `probation-server admin`: it holds the database
    /// credentials, so it acts as a global admin, audited with no login.
    Operator,
}

impl Actor {
    /// The login an audit row names.
    pub fn login_id(&self) -> Option<i32> {
        match self {
            Actor::Login { login_id, .. } => Some(*login_id),
            Actor::Automation { created_by, .. } => Some(*created_by),
            Actor::Operator => None,
        }
    }

    pub fn is_global_admin(&self) -> bool {
        match self {
            Actor::Login { global_admin, .. } => *global_admin,
            Actor::Automation { .. } => false,
            Actor::Operator => true,
        }
    }

    /// The global admin `admin bootstrap` has just created.
    pub(crate) fn bootstrap(login_id: i32) -> Actor {
        Actor::Login {
            login_id,
            global_admin: true,
            roles: Vec::new(),
        }
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
            let memberships = memberships(&mut conn, session.login_id).await?;
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

    /// The session's login with its role on `place`.
    pub async fn actor(
        &self,
        session: &Session,
        place: &Authorized<Place>,
    ) -> Result<Actor, sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        let memberships = memberships(&mut conn, session.login_id).await?;
        let global_admin = memberships.iter().any(|m| m.org.is_none());
        let role = role_for(session.login_id, &memberships, &place.0);
        Ok(Actor::Login {
            login_id: session.login_id,
            global_admin,
            roles: role.map(|role| (place.0.place, role)).into_iter().collect(),
        })
    }
}

/// The login's memberships; none for a deleted login.
async fn memberships(
    conn: &mut PgConnection,
    login_id: i32,
) -> Result<Vec<Membership>, sqlx::Error> {
    let rows: Vec<(i32, Option<i32>, Option<i32>, String)> = sqlx::query_as(
        "SELECT m.id, m.org_id, m.group_id, m.role FROM memberships AS m
         JOIN logins AS l ON l.id = m.login_id
         WHERE m.login_id = $1 AND l.deleted_at IS NULL",
    )
    .bind(login_id)
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
    let at = |org: Option<i32>, group: Option<i32>, owner: Option<i32>, status: &str| Place {
        place,
        org,
        group,
        owner_login: owner,
        suspended: status == "suspended",
        chain: [
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
        .collect(),
    };
    Ok(match place.kind {
        LayerKind::Platform => (place == PLATFORM).then(|| at(None, None, None, "active")),
        LayerKind::Org => sqlx::query_scalar::<_, String>(
            "SELECT status FROM orgs WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(|status| at(Some(id), None, None, &status)),
        LayerKind::Group => sqlx::query_as::<_, (i32, String)>(
            "SELECT g.org_id, o.status FROM groups AS g JOIN orgs AS o ON o.id = g.org_id
             WHERE g.id = $1 AND o.deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(|(org, status)| at(Some(org), Some(id), None, &status)),
        LayerKind::User => sqlx::query_as::<_, (i32, Option<i32>, i32, String)>(
            "SELECT m.org_id, m.group_id, m.login_id, o.status
             FROM memberships AS m JOIN orgs AS o ON o.id = m.org_id
             WHERE m.id = $1 AND o.deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(|(org, group, login, status)| at(Some(org), group, Some(login), &status)),
        LayerKind::Personal => sqlx::query_as::<_, (i32, String)>(
            "SELECT login_id, status FROM personal_accounts WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(|(login, status)| at(None, None, Some(login), &status)),
    })
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
        Actor::Login {
            global_admin: true, ..
        }
        | Actor::Operator => Some(Role::GlobalAdmin),
        Actor::Login { roles, .. } => roles
            .iter()
            .find(|(on, _)| *on == place)
            .map(|(_, role)| *role),
        Actor::Automation { place: own, .. } => (*own == place).then_some(Role::BlocklistEditor),
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
