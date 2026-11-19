//! Row 17: the shared nine-family identities on the server. Migration 0014 widens every
//! ecosystem CHECK to the nine selected tags, and a tag this binary has no variant for is
//! an explicit decode refusal, never `Npm` (the old fallback in `policy::ecosystem_of`).

mod common;

use common::{Db, client};
use probation_server::keys;
use reqwest::StatusCode;

const NINE: [&str; 9] = ["npm", "pypi", "maven", "go", "cargo", "nuget", "rubygems", "conan", "oci"];

#[tokio::test]
async fn migration_0014_accepts_the_nine_selected_tags_and_no_others() {
    let db = Db::fresh().await;
    let org = db.org("Tags").await;
    for tag in NINE {
        sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, $2, $3)")
            .bind(org.id as i32)
            .bind(tag)
            .bind(format!("registry {tag}"))
            .execute(&db.owner)
            .await
            .unwrap_or_else(|e| panic!("registries must accept `{tag}`: {e}"));
    }
    for tag in ["maven2", "RubyGems", "rubygem", ""] {
        let refused = sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, $2, 'x')")
            .bind(org.id as i32)
            .bind(tag)
            .execute(&db.owner)
            .await;
        assert!(refused.is_err(), "`{tag}` must stay refused");
    }
    // The other two tables that carry the tag take the same nine.
    let layer: i32 = sqlx::query_scalar("SELECT id FROM policy_layers LIMIT 1").fetch_one(&db.owner).await.unwrap();
    for tag in NINE {
        sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name) VALUES ($1, $2, 'pkg')")
            .bind(layer).bind(tag).execute(&db.owner).await
            .unwrap_or_else(|e| panic!("policy_blocks must accept `{tag}`: {e}"));
        sqlx::query("INSERT INTO policy_exceptions (layer, ecosystem, name, lifts_block, lifts_freeze, lifts_osv) VALUES ($1, $2, 'pkg', true, false, false)")
            .bind(layer).bind(tag).execute(&db.owner).await
            .unwrap_or_else(|e| panic!("policy_exceptions must accept `{tag}`: {e}"));
    }
    // Old rows reopen unchanged: the default npm registry is still there.
    let old: i64 = sqlx::query_scalar("SELECT count(*) FROM registries WHERE org_id = $1 AND ecosystem = 'npm' AND name = 'Default npm'")
        .bind(org.id as i32).fetch_one(&db.owner).await.unwrap();
    assert_eq!(old, 1);
}

#[tokio::test]
async fn snapshot_names_a_rubygems_registry() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Gems").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service").await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'rubygems', 'Gems')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    let url = common::serve(db.app.clone(), vec![]).await.join("api/v1/policy/snapshot").unwrap();
    let response = client().get(url).bearer_auth(&key.secret).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"].as_array().unwrap().iter().any(|r| r["ecosystem"] == "RubyGems"),
        "{snapshot}"
    );
}

/// An old server binary decodes only the tags it knows. A row of a selected tag that this
/// binary has no variant for (here `maven`) is refused with 503, never read as an npm
/// registry or an npm block.
#[tokio::test]
async fn unknown_tag_rows_are_an_explicit_decode_refusal_never_npm() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Mixed").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service").await.unwrap();
    let url = common::serve(db.app.clone(), vec![]).await.join("api/v1/policy/snapshot").unwrap();
    let http = client();
    let layer: i32 = sqlx::query_scalar("SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1")
        .bind(org.id as i32).fetch_one(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name) VALUES ($1, 'maven', 'org.example:evil')")
        .bind(layer).execute(&db.owner).await.unwrap();
    let response = http.get(url).bearer_auth(&key.secret).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "a maven block must not decode as an npm block");
}
