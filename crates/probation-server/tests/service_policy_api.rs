mod common;

use common::{Db, client};
use probation_server::keys;
use reqwest::StatusCode;

#[tokio::test]
async fn service_snapshot_requires_live_service_scope() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Shared service").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    // The foreign registry must exist before the snapshot under test is read.
    let other_org = db.org("Other service").await;
    let other_registry: i64 = sqlx::query_scalar("SELECT id FROM registries WHERE org_id=$1")
        .bind(other_org.id as i32)
        .fetch_one(&db.owner)
        .await
        .unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let http = client();
    assert_eq!(
        http.get(url.clone()).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let response = http
        .get(url.clone())
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(snapshot["version"], 1);
    assert_eq!(snapshot["org"], org.id);
    assert_eq!(snapshot["key_id"], key.id.0);
    assert_eq!(snapshot["layers"].as_array().unwrap().len(), 2);
    assert!(!snapshot.to_string().contains(&key.secret));
    assert!(!snapshot.to_string().contains("read_authorization"));
    assert!(
        !snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["registry"] == other_registry)
    );
    let registry = snapshot["registries"][0]["registry"].as_i64().unwrap();
    sqlx::query("UPDATE registries SET trusted=true, target_url='https://packages.example.test/npm/' WHERE id=$1").bind(registry).execute(&db.owner).await.unwrap();
    let response = http
        .get(url.clone())
        .header("if-none-match", snapshot["revision"].to_string())
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "descriptor edits always return a complete snapshot"
    );
    let edited: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(edited["registries"][0]["trusted"], true);
    assert_eq!(
        edited["registries"][0]["target_url"],
        "https://packages.example.test/npm/"
    );
    sqlx::query("UPDATE registries SET removed_at=now() WHERE id=$1")
        .bind(registry)
        .execute(&db.owner)
        .await
        .unwrap();
    let removed: serde_json::Value = serde_json::from_slice(
        &http
            .get(url.clone())
            .bearer_auth(&key.secret)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(removed["registries"].as_array().unwrap().is_empty());
    let wrong_kind = keys::create(&db.app, &actor, &place, "wrong kind")
        .await
        .unwrap();
    sqlx::query("UPDATE keys SET kind='user' WHERE id=$1")
        .bind(wrong_kind.id.0 as i64)
        .execute(&db.owner)
        .await
        .unwrap();
    assert_eq!(
        http.get(url.clone())
            .bearer_auth(&wrong_kind.secret)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    db.suspend_org(org).await;
    assert_eq!(
        http.get(url.clone())
            .bearer_auth(&key.secret)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    keys::revoke_as_operator(&db.app, key.id).await.unwrap();
    assert_eq!(
        http.get(url)
            .bearer_auth(&key.secret)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

// ---- Slice 28, LS-F8: the snapshot revision moves with every digest field ----

async fn snapshot_of(http: &reqwest::Client, url: &url::Url, key: &str) -> serde_json::Value {
    serde_json::from_slice(&http.get(url.clone()).bearer_auth(key).send().await.unwrap().bytes().await.unwrap()).unwrap()
}

#[tokio::test]
async fn revision_moves_with_every_digest_field() {
    use probation_policy::{Block, Ecosystem, Exception, Layer, LayerKind, Lifts, OsvSetting, PlaceRef, Switches};
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Shared service").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service").await.unwrap();
    let url = common::serve(db.app.clone(), vec![]).await.join("api/v1/policy/snapshot").unwrap();
    let http = client();
    let platform = PlaceRef { kind: LayerKind::Platform, id: 1 };
    // Each edit changes one layer field that is part of the client's policy digest.
    type Edit = Box<dyn Fn(&mut Layer)>;
    let edits: Vec<(&str, PlaceRef, Edit)> = vec![
        ("platform block of a package", platform, Box::new(|l| l.blocks.push(Block::Package { ecosystem: Ecosystem::Npm, name: "bad-pkg".into(), reason: None }))),
        ("platform block of a version", platform, Box::new(|l| l.blocks.push(Block::Version { ecosystem: Ecosystem::PyPi, name: "bad".into(), version: "1.0.0".into(), reason: None }))),
        ("platform freeze", platform, Box::new(|l| l.freeze_seconds = Some(86_400))),
        ("platform osv", platform, Box::new(|l| l.osv = Some(OsvSetting::On))),
        ("platform allow switches", platform, Box::new(|l| l.allow = Switches::ALL)),
        ("org exception", org, Box::new(|l| l.exceptions.push(Exception { ecosystem: Ecosystem::Npm, name: "ok-pkg".into(), version: None, lifts: Lifts { block: true, freeze: false, osv: false } }))),
        ("org freeze", org, Box::new(|l| l.freeze_seconds = Some(172_800))),
    ];
    let mut last = snapshot_of(&http, &url, &key.secret).await["revision"].as_u64().unwrap();
    for (name, at, edit) in edits {
        db.edit(admin, at, |layer| edit(layer)).await.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let now = snapshot_of(&http, &url, &key.secret).await["revision"].as_u64().unwrap();
        assert!(now > last, "{name}: revision {now} must exceed {last}");
        last = now;
    }
    // The chain: a service key placed in a group sees the group layer, and a group-layer
    // edit (layer revision in the chain, rules in the digest) moves its revision too.
    let group = db.group(org, "builders").await;
    let (gactor, gplace) = db.as_admin(admin, group).await;
    let gkey = keys::create(&db.app, &gactor, &gplace, "group service").await.unwrap();
    let chain = snapshot_of(&http, &url, &gkey.secret).await;
    assert_eq!(chain["place_chain"].as_array().unwrap().len(), 3, "platform, org, group");
    let before = chain["revision"].as_u64().unwrap();
    db.edit(admin, group, |l| l.blocks.push(Block::Package { ecosystem: Ecosystem::Npm, name: "group-bad".into(), reason: None })).await.unwrap();
    let after = snapshot_of(&http, &url, &gkey.secret).await;
    assert!(after["revision"].as_u64().unwrap() > before, "a group-layer edit must move the revision of a key in that group");
    assert_eq!(after["layers"][2]["layer"]["blocks"].as_array().unwrap().len(), 1);
    // account, org and key id are fixed for a live service key (no production path moves
    // them: a deleted group revokes its keys, a new binding is a new key), so they cannot
    // change within a binding and need no bump.
}

// ---- Slice 28, LS-F12: server-side osv_scope field, migration 0015, setter ----

#[tokio::test]
async fn osv_scope_migration_additive_and_reopens_old_rows() {
    let db = Db::fresh().await;
    let column: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT is_nullable, column_default FROM information_schema.columns WHERE table_name = 'registries' AND column_name = 'osv_scope'",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    assert_eq!(column, vec![("YES".to_owned(), None)], "a nullable column with no default: additive");
    // A row written before the migration has NULL and reads as the default rule: the
    // descriptor carries no osv_scope at all.
    let admin = db.global_admin().await;
    let org = db.org("Shared service").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service").await.unwrap();
    let url = common::serve(db.app.clone(), vec![]).await.join("api/v1/policy/snapshot").unwrap();
    let snapshot = snapshot_of(&client(), &url, &key.secret).await;
    let registries = snapshot["registries"].as_array().unwrap();
    assert!(!registries.is_empty());
    assert!(registries.iter().all(|r| r.get("osv_scope").is_none()), "old rows reopen unchanged");
}

#[tokio::test]
async fn osv_scope_api_sets_and_clears() {
    use probation_policy::api::OsvScope;
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Shared service").await;
    let other = db.org("Other service").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service").await.unwrap();
    let url = common::serve(db.app.clone(), vec![]).await.join("api/v1/policy/snapshot").unwrap();
    let http = client();
    let registry: i64 = snapshot_of(&http, &url, &key.secret).await["registries"][0]["registry"].as_i64().unwrap();
    let scope = |value: serde_json::Value| value["registries"][0]["osv_scope"].clone();
    assert!(probation_server::service_policy::set_osv_scope(&db.app, org.id as i32, registry, Some(OsvScope::Private)).await.unwrap());
    assert_eq!(scope(snapshot_of(&http, &url, &key.secret).await), "Private");
    assert!(probation_server::service_policy::set_osv_scope(&db.app, org.id as i32, registry, Some(OsvScope::Public)).await.unwrap());
    assert_eq!(scope(snapshot_of(&http, &url, &key.secret).await), "Public");
    assert!(probation_server::service_policy::set_osv_scope(&db.app, org.id as i32, registry, None).await.unwrap());
    assert!(scope(snapshot_of(&http, &url, &key.secret).await).is_null(), "cleared: back to the default rule");
    assert!(
        !probation_server::service_policy::set_osv_scope(&db.app, other.id as i32, registry, Some(OsvScope::Private)).await.unwrap(),
        "another organisation cannot set it"
    );
}

#[tokio::test]
async fn osv_scope_migration_refuses_unknown_values_and_rolls_back() {
    let db = Db::fresh().await;
    let _org = db.org("Shared service").await;
    let registry: i64 = sqlx::query_scalar("SELECT id FROM registries LIMIT 1").fetch_one(&db.owner).await.unwrap();
    // The column accepts only the two spellings (or NULL): anything else is refused.
    for bad in ["weird", "PUBLIC", ""] {
        let refused = sqlx::query("UPDATE registries SET osv_scope = $1 WHERE id = $2").bind(bad).bind(registry).execute(&db.owner).await;
        assert!(refused.is_err(), "{bad:?} must be refused by the CHECK constraint");
    }
    // A transaction that sets a value and rolls back leaves the old-row reading (NULL).
    let mut tx = db.owner.begin().await.unwrap();
    sqlx::query("UPDATE registries SET osv_scope = 'private' WHERE id = $1").bind(registry).execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    let value: Option<String> = sqlx::query_scalar("SELECT osv_scope FROM registries WHERE id = $1").bind(registry).fetch_one(&db.owner).await.unwrap();
    assert_eq!(value, None);
}
