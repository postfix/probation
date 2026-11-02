//! Slice 4: layer edits and key revocations are atomic, audited and change-logged in
//! commit order, and an edit is checked against its place's own chain
//! (03-program-design.md § Test plan). Needs the Postgres of docker-compose.test.yml.

mod common;

use std::time::Duration;

use common::{Db, EditFailure};
use ipnet::IpNet;
use probation_policy::api::KeyHash;
use probation_policy::{
    Block, Ecosystem, EditRefusal, EditTarget, EffectivePolicy, Layer, LayerKind, Loosening,
    OsvSetting, SwitchName, Switches, check_edit, resolve,
};
use probation_server::policy::SaveError;
use probation_server::sync::{ChangeKind, record_change};
use probation_server::tenancy::{Actor, authorize};
use probation_server::{fleet, keys};

const DAY: u64 = 86_400;

fn block(name: &str) -> Block {
    Block::Package {
        ecosystem: Ecosystem::Npm,
        name: name.to_owned(),
        reason: None,
    }
}

/// T-edit-parent-chain (slice-1 S1-1): the parent an edit is checked against is the
/// resolve of the place's own ancestors, and the stored layer returned is its own.
#[tokio::test]
async fn t_edit_parent_chain() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let platform = probation_server::tenancy::PLATFORM;
    let acme = db.org("Acme").await;
    let g = db.group(acme, "G").await;
    let g2 = db.group(acme, "G2").await;
    let u = db.member(db.login().await, acme, Some(g), "member").await;
    let u2 = db.member(db.login().await, acme, Some(g2), "member").await;
    let ungrouped = db.member(db.login().await, acme, None, "member").await;
    let personal = db.personal(db.login().await).await;

    let platform_layer = Layer {
        freeze_seconds: Some(2 * DAY),
        osv: Some(OsvSetting::On),
        allow: Switches::ALL,
        ..Layer::empty(LayerKind::Platform)
    };
    let org_layer = Layer {
        blocks: vec![block("left-pad")],
        allow: Switches::ALL,
        ..Layer::empty(LayerKind::Org)
    };
    let g2_layer = Layer {
        allow: Switches::ALL,
        ..Layer::empty(LayerKind::Group)
    };
    db.edit(admin, platform, |layer| *layer = platform_layer.clone())
        .await
        .unwrap();
    db.edit(admin, acme, |layer| *layer = org_layer.clone())
        .await
        .unwrap();
    db.edit(admin, g2, |layer| *layer = g2_layer.clone())
        .await
        .unwrap();
    // U's 1-day freeze is saved while G lets its users shorten, then G turns that off:
    // the value is kept, not in effect (C47).
    db.edit(admin, g, |layer| layer.allow.shorter_freeze = true)
        .await
        .unwrap();
    db.edit(admin, u, |layer| layer.freeze_seconds = Some(DAY))
        .await
        .unwrap();
    db.edit(admin, g, |layer| layer.allow.shorter_freeze = false)
        .await
        .unwrap();
    let g_layer = Layer::empty(LayerKind::Group);
    let u_layer = Layer {
        freeze_seconds: Some(DAY),
        ..Layer::empty(LayerKind::User)
    };

    let store = db.store();
    for (at, ancestors, own) in [
        (
            personal,
            vec![platform_layer.clone()],
            Layer::empty(LayerKind::Personal),
        ),
        (
            ungrouped,
            vec![platform_layer.clone(), org_layer.clone()],
            Layer::empty(LayerKind::User),
        ),
        (
            u,
            vec![platform_layer.clone(), org_layer.clone(), g_layer.clone()],
            u_layer.clone(),
        ),
    ] {
        let (_, authorized) = db.as_admin(admin, at).await;
        let (parent, current) = store.parent_policy(&authorized).await.unwrap();
        assert_eq!(parent, resolve(&ancestors), "{at:?}");
        assert_eq!(current, own, "{at:?}");
    }
    let (_, platform_place) = db.as_admin(admin, platform).await;
    let (parent, current) = store.parent_policy(&platform_place).await.unwrap();
    assert_eq!(parent, EffectivePolicy::root());
    assert_eq!(current, platform_layer);

    // A newly proposed shorter freeze for U is refused by G's switch…
    let (_, u_place) = db.as_admin(admin, u).await;
    let (parent, current) = store.parent_policy(&u_place).await.unwrap();
    let (_, revision) = store.layer(&u_place).await.unwrap();
    let target = EditTarget {
        place: u,
        expected_revision: revision,
    };
    let shorter = Layer {
        freeze_seconds: Some(DAY / 2),
        ..u_layer.clone()
    };
    assert!(matches!(
        check_edit(&parent, &current, target, shorter.clone()),
        Err(EditRefusal::NotAllowedByParent {
            what: Loosening::ShorterFreeze { .. },
            switch: SwitchName::ShorterFreeze
        })
    ));
    // …although G2's users may shorten theirs…
    let (_, u2_place) = db.as_admin(admin, u2).await;
    let (parent2, current2) = store.parent_policy(&u2_place).await.unwrap();
    let target2 = EditTarget {
        place: u2,
        expected_revision: store.layer(&u2_place).await.unwrap().1,
    };
    let shorter2 = Layer {
        freeze_seconds: Some(DAY / 2),
        ..Layer::empty(LayerKind::User)
    };
    assert!(check_edit(&parent2, &current2, target2, shorter2).is_ok());
    // …and U's re-save of its kept value is accepted (C47).
    assert!(check_edit(&parent, &current, target, u_layer).is_ok());
}

/// T-edit-atomic: a failed audit insert leaves the layer and the change log unchanged.
#[tokio::test]
async fn t_edit_atomic() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    db.break_audit_inserts().await;
    let changes = db.count("SELECT count(*) FROM change_log").await;

    let failed = db
        .edit(admin, acme, |layer| layer.blocks.push(block("left-pad")))
        .await;
    assert!(
        matches!(failed, Err(EditFailure::Save(SaveError::Db(_)))),
        "{failed:?}"
    );

    let (_, authorized) = db.as_admin(admin, acme).await;
    assert_eq!(
        db.store().layer(&authorized).await.unwrap(),
        (Layer::empty(LayerKind::Org), 1)
    );
    assert_eq!(db.count("SELECT count(*) FROM change_log").await, changes);
}

/// T-edit-conflict: of two saves loaded at the same revision only the first is kept.
#[tokio::test]
async fn t_edit_conflict() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    let (actor, authorized) = db.as_admin(admin, acme).await;
    let first = db
        .check(&authorized, |layer| layer.blocks.push(block("first")))
        .await
        .unwrap();
    let second = db
        .check(&authorized, |layer| layer.blocks.push(block("second")))
        .await
        .unwrap();
    let store = db.store();
    let (one, two) = tokio::join!(
        store.save_edit(&actor, authorize(&actor, &first).unwrap(), first),
        store.save_edit(&actor, authorize(&actor, &second).unwrap(), second),
    );
    let (kept, lost) = match (one, two) {
        (Ok(_), Err(SaveError::Conflict)) => ("first", "second"),
        (Err(SaveError::Conflict), Ok(_)) => ("second", "first"),
        other => panic!("exactly one save must win: {other:?}"),
    };
    let (layer, revision) = store.layer(&authorized).await.unwrap();
    assert_eq!(revision, 2);
    assert_eq!(layer.blocks, vec![block(kept)], "{lost} must not be stored");
    assert_eq!(db.count("SELECT count(*) FROM change_log").await, 1);
    assert_eq!(db.count("SELECT count(*) FROM audit_log").await, 1);
}

/// T-edit-audited-global-admin (C79): a global admin's edit in Acme is in Acme's log,
/// flagged, with the layer before and after.
#[tokio::test]
async fn t_edit_audited_global_admin() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    db.edit(admin, acme, |layer| layer.freeze_seconds = Some(DAY))
        .await
        .unwrap();

    let row: (Option<i32>, bool, Option<i32>, String, String, serde_json::Value, serde_json::Value) =
        sqlx::query_as(
            "SELECT actor_login, actor_is_global_admin, org_id, action, subject, before, after FROM audit_log",
        )
        .fetch_one(&db.owner)
        .await
        .unwrap();
    let expected_after = Layer {
        freeze_seconds: Some(DAY),
        ..Layer::empty(LayerKind::Org)
    };
    assert_eq!(row.0, Some(admin));
    assert!(row.1, "flagged global admin");
    assert_eq!(row.2, Some(acme.id as i32), "listed in Acme's log");
    assert_eq!(
        (row.3.as_str(), row.4.as_str()),
        ("layer.edit", &*format!("org:{}", acme.id))
    );
    assert_eq!(
        serde_json::from_value::<Layer>(row.5).unwrap(),
        Layer::empty(LayerKind::Org)
    );
    assert_eq!(
        serde_json::from_value::<Layer>(row.6).unwrap(),
        expected_after
    );
}

/// T-changelog-commit-order (T7): a second writer cannot take a revision until the
/// first commits, so a cursor reading the log at any moment never sees a later
/// revision without every earlier one.
#[tokio::test]
async fn t_changelog_commit_order() {
    let db = Db::fresh().await;
    let place = probation_server::tenancy::PLATFORM;
    let mut first = db.app.begin().await.unwrap();
    let a = record_change(&mut first, ChangeKind::Layer, &place)
        .await
        .unwrap();

    let app = db.app.clone();
    let second = tokio::spawn(async move {
        let mut tx = app.begin().await.unwrap();
        let b = record_change(&mut tx, ChangeKind::Layer, &place)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        b
    });
    let owner = db.owner.clone();
    let reader = tokio::spawn(async move {
        let mut seen = Vec::new();
        for _ in 0..60 {
            let visible: Vec<i64> =
                sqlx::query_scalar("SELECT revision FROM change_log ORDER BY revision")
                    .fetch_all(&owner)
                    .await
                    .unwrap();
            seen.push(visible);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        seen
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !second.is_finished(),
        "the second writer waits for the first"
    );
    first.commit().await.unwrap();
    let b = second.await.unwrap();
    assert_eq!(b, a + 1);
    for visible in reader.await.unwrap() {
        assert!(
            visible.is_empty() || visible == [a] || visible == [a, b],
            "a cursor saw {visible:?}"
        );
    }
}

/// T-audit-append-only (T17): the app role can only add and read audit rows; pruning
/// goes through `prune_audit()`, which picks each organisation's cutoff itself.
#[tokio::test]
async fn t_audit_append_only() {
    let db = Db::fresh().await;
    let acme = db.org("Acme").await;
    let globex = db.org("Globex").await;
    let weekly = db.org("Weekly").await;
    sqlx::query("UPDATE orgs SET audit_retention_days = 500 WHERE id = $1")
        .bind(globex.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    sqlx::query("UPDATE orgs SET audit_retention_days = 7 WHERE id = $1")
        .bind(weekly.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    // (org, age in days, kept by prune_audit): platform default 365.
    let rows = [
        (Some(acme), 400, false),
        (Some(acme), 100, true),
        (None, 400, false),
        (Some(globex), 400, true),
        (Some(weekly), 8, false),
        (Some(weekly), 6, true),
    ];
    for (org, age, _) in rows {
        sqlx::query(
            "INSERT INTO audit_log (at, actor_is_global_admin, org_id, action, subject)
             VALUES (now() - make_interval(days => $1), false, $2, 'test', $3)",
        )
        .bind(age)
        .bind(org.map(|org| org.id as i32))
        .bind(format!("{org:?}/{age}"))
        .execute(&db.owner)
        .await
        .unwrap();
    }

    for statement in [
        "UPDATE audit_log SET action = 'forged'",
        "DELETE FROM audit_log",
    ] {
        let err = sqlx::query(statement).execute(&db.app).await.unwrap_err();
        assert_eq!(
            err.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501"),
            "{statement}: {err}"
        );
    }
    sqlx::query(
        "INSERT INTO audit_log (actor_is_global_admin, action, subject) VALUES (false, 'app', 'x')",
    )
    .execute(&db.app)
    .await
    .expect("the app role inserts");
    let err = sqlx::query("SELECT prune_audit(now())")
        .execute(&db.app)
        .await
        .unwrap_err();
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42883"),
        "no cutoff argument: {err}"
    );
    let pruned: i64 = sqlx::query_scalar("SELECT prune_audit()")
        .fetch_one(&db.app)
        .await
        .unwrap();
    assert_eq!(pruned, 3);
    let left: Vec<String> = sqlx::query_scalar("SELECT subject FROM audit_log ORDER BY id")
        .fetch_all(&db.app)
        .await
        .unwrap();
    let mut expected: Vec<String> = rows
        .iter()
        .filter(|(_, _, kept)| *kept)
        .map(|(org, age, _)| format!("{org:?}/{age}"))
        .collect();
    expected.push("x".to_owned());
    assert_eq!(left, expected);
}

/// T-audit-coverage-keys-policy: key create and revoke, a layer edit and a firewall
/// registration each write exactly one audit row naming actor, flag, subject and state.
#[tokio::test]
async fn t_audit_coverage_keys_policy() {
    let db = Db::fresh().await;
    let owner_login = db.login().await;
    let acme = db.org("Acme").await;
    let user = db.member(owner_login, acme, None, "member").await;
    let session = probation_server::tenancy::Session::new(owner_login, None);
    let authorized = db.tenancy().authorized_place(&session, user).await.unwrap();
    let actor = db.tenancy().actor(&session, &authorized).await.unwrap();

    let key = keys::create(&db.app, &actor, &authorized, "laptop")
        .await
        .unwrap();
    keys::revoke(&db.app, &actor, &authorized, key.id)
        .await
        .unwrap();
    db.edit(owner_login, user, |layer| {
        layer.blocks.push(block("left-pad"))
    })
    .await
    .unwrap();
    let sources: Vec<IpNet> = vec!["192.0.2.0/24".parse().unwrap()];
    let firewall = fleet::register(&db.app, &Actor::Operator, "fw-1", &sources)
        .await
        .unwrap();

    type Row = (String, Option<i32>, bool, Option<i32>, String, bool, bool);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT action, actor_login, actor_is_global_admin, org_id, subject,
                before IS NOT NULL, after IS NOT NULL
         FROM audit_log ORDER BY id",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    let org = Some(acme.id as i32);
    assert_eq!(
        rows,
        vec![
            (
                "key.create".into(),
                Some(owner_login),
                false,
                org,
                format!("key:{}", key.id.0),
                false,
                true
            ),
            (
                "key.revoke".into(),
                Some(owner_login),
                false,
                org,
                format!("key:{}", key.id.0),
                true,
                true
            ),
            (
                "layer.edit".into(),
                Some(owner_login),
                false,
                org,
                format!("user:{}", user.id),
                true,
                true
            ),
            (
                "firewall.register".into(),
                None,
                true,
                None,
                format!("firewall:{}", firewall.id),
                false,
                true
            ),
        ]
    );
}

/// T-revoke-atomic: with the audit insert failing, the key stays live and no
/// `change_log` row is written.
#[tokio::test]
async fn t_revoke_atomic() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    let (actor, authorized) = db.as_admin(admin, acme).await;
    let key = keys::create(&db.app, &actor, &authorized, "ci")
        .await
        .unwrap();
    db.break_audit_inserts().await;

    let failed = keys::revoke(&db.app, &actor, &authorized, key.id).await;
    assert!(
        matches!(failed, Err(keys::RevokeError::Store(_))),
        "{failed:?}"
    );
    let live: bool = sqlx::query_scalar("SELECT revoked_at IS NULL FROM keys WHERE hash = $1")
        .bind(KeyHash::of(&key.secret).0.as_slice())
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert!(live, "the key stays live");
    assert_eq!(db.count("SELECT count(*) FROM change_log").await, 0);
}
