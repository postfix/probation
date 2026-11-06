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
