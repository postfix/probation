//! Slice 4: who may see and edit which place (C1, C4, C27, C78), and the bootstrap
//! grant (T3) (03-program-design.md § Test plan). Needs the Postgres of
//! docker-compose.test.yml.

mod common;

use std::process::Command;

use common::{Db, EditFailure};
use probation_policy::api::KeyId;
use probation_policy::{Block, Ecosystem, Layer, LayerKind, PlaceRef};
use probation_server::fleet;
use probation_server::keys::{self, RevokeError};
use probation_server::tenancy::{NotFound, PLATFORM, Session, authorize};

fn stricter(layer: &mut Layer) {
    layer.blocks.push(Block::Package {
        ecosystem: Ecosystem::Npm,
        name: "left-pad".to_owned(),
    });
}

/// What the matrix expects of one login on one place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum May {
    Nothing,
    Read,
    Edit,
}

/// Whether `login` may create a key on `place` and revoke one there (created by the
/// global admin `admin`); both answers must agree.
async fn may_manage_keys(db: &Db, admin: i32, login: i32, place: PlaceRef) -> bool {
    let (admin_actor, admin_place) = db.as_admin(admin, place).await;
    let target = keys::create(&db.app, &admin_actor, &admin_place, "target")
        .await
        .unwrap();
    let session = Session::new(login, None);
    let authorized = db
        .tenancy()
        .authorized_place(&session, place)
        .await
        .unwrap();
    let actor = db.tenancy().actor(&session, &authorized).await.unwrap();
    let created = match keys::create(&db.app, &actor, &authorized, "own").await {
        Ok(_) => true,
        Err(keys::KeyError::Denied) => false,
        Err(other) => panic!("create: {other:?}"),
    };
    let revoked = match keys::revoke(&db.app, &actor, &authorized, target.id).await {
        Ok(()) => true,
        Err(RevokeError::Denied) => false,
        Err(other) => panic!("revoke: {other:?}"),
    };
    assert_eq!(
        created, revoked,
        "login {login} on {place:?}: create and revoke disagree"
    );
    created
}

async fn may(db: &Db, login: i32, place: PlaceRef) -> May {
    let session = Session::new(login, None);
    if db
        .tenancy()
        .authorized_place(&session, place)
        .await
        .is_err()
    {
        return May::Nothing;
    }
    match db.edit(login, place, stricter).await {
        Ok(_) => May::Edit,
        Err(EditFailure::Denied) => May::Read,
        Err(other) => panic!("{login} on {place:?}: {other:?}"),
    }
}

/// T-authz-matrix: every role on every layer kind, read and edit, as C4, C9, C27 say;
/// a suspended organisation denies all but global admins (C78).
#[tokio::test]
async fn t_authz_matrix() {
    let db = Db::fresh().await;
    let global = db.global_admin().await;
    let acme = db.org("Acme").await;
    let g1 = db.group(acme, "G1").await;
    let g2 = db.group(acme, "G2").await;
    let org_admin = db.login().await;
    let org_admin_place = db.member(org_admin, acme, None, "org_admin").await;
    let group_admin = db.login().await;
    let group_admin_place = db.member(group_admin, acme, Some(g1), "group_admin").await;
    let m1 = db.login().await;
    let m1_place = db.member(m1, acme, Some(g1), "member").await;
    let m2 = db.login().await;
    let m2_place = db.member(m2, acme, Some(g2), "member").await;
    let solo = db.login().await;
    let personal = db.personal(solo).await;

    use May::{Edit as E, Nothing as N, Read as R};
    let places = [
        PLATFORM,
        acme,
        g1,
        g2,
        org_admin_place,
        group_admin_place,
        m1_place,
        m2_place,
        personal,
    ];
    #[rustfmt::skip]
    let expected = [
        // platform, acme, g1, g2, user(org admin), user(group admin), user(m1), user(m2), personal
        (global,      [E, E, E, E, E, E, E, E, E]),
        (org_admin,   [N, E, E, E, E, E, E, E, N]),
        (group_admin, [N, R, E, R, R, E, R, R, N]),
        (m1,          [N, R, R, R, R, R, E, R, N]),
        (m2,          [N, R, R, R, R, R, R, E, N]),
        (solo,        [N, N, N, N, N, N, N, N, E]),
    ];
    for (login, row) in expected {
        for (place, want) in places.iter().zip(row) {
            assert_eq!(
                may(&db, login, *place).await,
                want,
                "login {login} on {place:?}"
            );
        }
    }

    // Keys: create and revoke, each role on the organisation, a group, the login's own
    // user place and another member's (C14, C27, C50). A global admin has no user place.
    let (yes, no, absent) = (Some(true), Some(false), None);
    #[rustfmt::skip]
    let key_matrix = [
        // org, g1, own user, other user (m2's)
        (global,      [yes, yes, absent, yes]),
        (org_admin,   [yes, yes, yes,    yes]),
        (group_admin, [no,  yes, yes,    no ]),
        (m1,          [no,  no,  yes,    no ]),
    ];
    let own_place = |login| match login {
        l if l == org_admin => Some(org_admin_place),
        l if l == group_admin => Some(group_admin_place),
        l if l == m1 => Some(m1_place),
        _ => None,
    };
    for (login, row) in key_matrix {
        let targets = [Some(acme), Some(g1), own_place(login), Some(m2_place)];
        for (target, want) in targets.into_iter().zip(row) {
            let (Some(target), Some(want)) = (target, want) else {
                continue;
            };
            assert_eq!(
                may_manage_keys(&db, global, login, target).await,
                want,
                "keys: login {login} on {target:?}"
            );
        }
    }
    // Firewalls: only a global admin registers one.
    let sources = ["192.0.2.0/24".parse().unwrap()];
    for (login, at, want) in [
        (global, acme, true),
        (org_admin, acme, false),
        (m1, m1_place, false),
    ] {
        let session = Session::new(login, None);
        let authorized = db.tenancy().authorized_place(&session, at).await.unwrap();
        let actor = db.tenancy().actor(&session, &authorized).await.unwrap();
        let registered = fleet::register(&db.app, &actor, "fw", &sources).await;
        match (want, registered) {
            (true, Ok(_)) | (false, Err(fleet::RegisterError::Denied)) => {}
            (_, other) => panic!("fleet::register by login {login}: {:?}", other.err()),
        }
    }

    // A permit is for one place: m1's permit for its own user layer, paired with a
    // checked edit of the organisation layer, writes nothing (R1).
    let session = Session::new(m1, None);
    let own = db
        .tenancy()
        .authorized_place(&session, m1_place)
        .await
        .unwrap();
    let actor = db.tenancy().actor(&session, &own).await.unwrap();
    let own_edit = db.check(&own, stricter).await.unwrap();
    let permit = authorize(&actor, &own_edit).unwrap();
    let org = db.tenancy().authorized_place(&session, acme).await.unwrap();
    let org_edit = db.check(&org, stricter).await.unwrap();
    let before = db.store().layer(&org).await.unwrap();
    let audits = db.count("SELECT count(*) FROM audit_log").await;
    let changes = db.count("SELECT count(*) FROM change_log").await;
    let saved = db.store().save_edit(&actor, permit, org_edit).await;
    assert!(
        saved.is_err(),
        "a permit for {m1_place:?} saved {acme:?}: {saved:?}"
    );
    assert_eq!(db.store().layer(&org).await.unwrap(), before);
    assert_eq!(db.count("SELECT count(*) FROM audit_log").await, audits);
    assert_eq!(db.count("SELECT count(*) FROM change_log").await, changes);

    db.suspend_org(acme).await;
    for (login, want) in [(global, E), (org_admin, R), (group_admin, R), (m1, R)] {
        assert_eq!(
            may(&db, login, g1).await,
            want,
            "suspended Acme, login {login}"
        );
    }
}

/// T-tenant-isolation (C1): an Acme admin gets `NotFound` for every Globex place, the
/// same as for an unknown one, and no repository function reaches a Globex row by id;
/// a session opened through Acme's SSO sees only Acme (T2).
#[tokio::test]
async fn t_tenant_isolation() {
    let db = Db::fresh().await;
    let acme = db.org("Acme").await;
    let globex = db.org("Globex").await;
    let acme_admin = db.login().await;
    let acme_admin_place = db.member(acme_admin, acme, None, "org_admin").await;
    let globex_group = db.group(globex, "Ops").await;
    let globex_member = db.login().await;
    let globex_user = db
        .member(globex_member, globex, Some(globex_group), "member")
        .await;
    let globex_personal = db.personal(globex_member).await;

    let session = Session::new(acme_admin, None);
    let tenancy = db.tenancy();
    for place in [
        globex,
        globex_group,
        globex_user,
        globex_personal,
        PLATFORM,
        common::place(LayerKind::Org, 9_999),
        common::place(LayerKind::User, 9_999),
    ] {
        assert_eq!(
            tenancy.authorized_place(&session, place).await.err(),
            Some(NotFound),
            "{place:?}"
        );
    }

    // A Globex key, reached through an Acme place by its id.
    let globex_session = Session::new(globex_member, None);
    let globex_place = tenancy
        .authorized_place(&globex_session, globex_user)
        .await
        .unwrap();
    let globex_actor = tenancy.actor(&globex_session, &globex_place).await.unwrap();
    let globex_key = keys::create(&db.app, &globex_actor, &globex_place, "laptop")
        .await
        .unwrap();
    for (place, key) in [
        (acme, globex_key.id),
        (acme_admin_place, globex_key.id),
        (acme, KeyId(9_999)),
    ] {
        let authorized = tenancy.authorized_place(&session, place).await.unwrap();
        let acme_actor = tenancy.actor(&session, &authorized).await.unwrap();
        assert!(matches!(
            keys::revoke(&db.app, &acme_actor, &authorized, key).await,
            Err(RevokeError::NotFound)
        ));
    }
    assert_eq!(
        db.count("SELECT count(*) FROM keys WHERE revoked_at IS NOT NULL")
            .await,
        0
    );
    assert!(matches!(
        db.edit(acme_admin, globex, |_| {}).await,
        Err(EditFailure::NotFound)
    ));
    let (layer, revision) = db.store().layer(&globex_place).await.unwrap();
    assert_eq!((layer, revision), (Layer::empty(LayerKind::User), 1));

    // A login in both organisations, signed in through Acme's SSO.
    db.member(acme_admin, globex, None, "member").await;
    let unscoped = Session::new(acme_admin, None);
    assert!(tenancy.authorized_place(&unscoped, globex).await.is_ok());
    let scoped = Session::new(acme_admin, Some(acme.id as i32));
    assert!(tenancy.authorized_place(&scoped, acme).await.is_ok());
    assert_eq!(
        tenancy.authorized_place(&scoped, globex).await.err(),
        Some(NotFound)
    );
}

fn bootstrap(db: &Db) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_probation-server"))
        .args([
            "admin",
            "bootstrap",
            "--org",
            "Acme",
            "--firewall",
            "fw-1",
            "--firewall-source",
            "10.0.0.0/8",
        ])
        .env("PROBATION_SERVER_DATABASE_URL", &db.app_url)
        .output()
        .expect("the binary runs")
}

/// T-grant-bootstrap (T3): `probation-server admin bootstrap` creates exactly one global
/// admin and one audit row; run again it refuses and changes nothing.
#[tokio::test]
async fn t_grant_bootstrap() {
    let db = Db::fresh().await;
    let first = bootstrap(&db);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let printed = String::from_utf8(first.stdout).unwrap();
    assert!(
        printed.lines().any(|line| line.starts_with("key=prb_")),
        "{printed}"
    );
    assert!(
        printed
            .lines()
            .any(|line| line.starts_with("firewall_token=fwt_")),
        "{printed}"
    );

    let tables = [
        "SELECT count(*) FROM memberships WHERE role = 'global_admin'",
        "SELECT count(*) FROM audit_log",
        "SELECT count(*) FROM logins",
        "SELECT count(*) FROM orgs",
        "SELECT count(*) FROM keys",
        "SELECT count(*) FROM firewalls",
        "SELECT count(*) FROM memberships",
    ];
    let mut after_first = Vec::new();
    for sql in tables {
        after_first.push(db.count(sql).await);
    }
    assert_eq!(after_first, [1, 1, 1, 1, 2, 1, 1]);

    let second = bootstrap(&db);
    assert!(!second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("refused"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let mut after_second = Vec::new();
    for sql in tables {
        after_second.push(db.count(sql).await);
    }
    assert_eq!(after_second, after_first);
}
