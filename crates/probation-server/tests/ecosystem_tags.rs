//! Row 17: the shared nine-family identities on the server. Migration 0014 widens every
//! ecosystem CHECK to the nine selected tags, and a tag this binary has no variant for is
//! an explicit decode refusal, never `Npm` (the old fallback in `policy::ecosystem_of`).

mod common;

use common::{Db, client};
use probation_server::keys;
use reqwest::StatusCode;

const NINE: [&str; 9] = [
    "npm", "pypi", "maven", "go", "cargo", "nuget", "rubygems", "conan", "oci",
];

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
        let refused =
            sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, $2, 'x')")
                .bind(org.id as i32)
                .bind(tag)
                .execute(&db.owner)
                .await;
        assert!(refused.is_err(), "`{tag}` must stay refused");
    }
    // The other two tables that carry the tag take the same nine.
    let layer: i32 = sqlx::query_scalar("SELECT id FROM policy_layers LIMIT 1")
        .fetch_one(&db.owner)
        .await
        .unwrap();
    for tag in NINE {
        sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name) VALUES ($1, $2, 'pkg')")
            .bind(layer)
            .bind(tag)
            .execute(&db.owner)
            .await
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
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'rubygems', 'Gems')")
        .bind(org.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ecosystem"] == "RubyGems"),
        "{snapshot}"
    );
}

/// An old server binary decodes only the tags it knows. A row of a selected tag that this
/// binary has no variant for (here `swift`, which no family will ever be: the CHECK is dropped inside the test so such a row can exist) is refused with 503, never read as an npm
/// registry or an npm block.
#[tokio::test]
async fn unknown_tag_rows_are_an_explicit_decode_refusal_never_npm() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Mixed").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let http = client();
    let layer: i32 = sqlx::query_scalar(
        "SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1",
    )
    .bind(org.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    // The CHECK of migration 0014 admits only the selected tags; a row of a tag the binary does not know is what an older or newer database
    // could hold, so the constraint is dropped here (the database is this test's own).
    sqlx::query("DO $$ DECLARE found text; BEGIN FOR found IN SELECT conname::text FROM pg_constraint WHERE conrelid = 'policy_blocks'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%ecosystem%' LOOP EXECUTE format('ALTER TABLE policy_blocks DROP CONSTRAINT %I', found); END LOOP; END $$")
        .execute(&db.owner).await.unwrap();
    sqlx::query(
        "INSERT INTO policy_blocks (layer, ecosystem, name) VALUES ($1, 'swift', 'evil/1.0')",
    )
    .bind(layer)
    .execute(&db.owner)
    .await
    .unwrap();
    let response = http.get(url).bearer_auth(&key.secret).send().await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a swift block must not decode as an npm block"
    );
}

/// Row 18: a Cargo registry and a Cargo block travel in the snapshot under the wire spelling
/// `Cargo` (the tag in the database is `cargo`); migration 0014 already carries the tag, so row
/// 18 needs no migration of its own.
#[tokio::test]
async fn snapshot_names_a_cargo_registry_and_a_cargo_block() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Crates").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'cargo', 'Crates')")
        .bind(org.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    let layer: i32 = sqlx::query_scalar(
        "SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1",
    )
    .bind(org.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name, version) VALUES ($1, 'cargo', 'serde-json', '1.0.0')")
        .bind(layer).execute(&db.owner).await.unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ecosystem"] == "Cargo"),
        "{snapshot}"
    );
    assert!(
        snapshot.to_string().contains(r#""name":"serde-json""#)
            && snapshot.to_string().contains("Cargo"),
        "the block decodes as a Cargo block: {snapshot}"
    );
}

/// Row 18: a settings push may set the two Cargo origins, and only to an https address (the same
/// rule as every other upstream origin key); a local-only key still cannot be pushed.
#[test]
fn settings_push_accepts_https_cargo_origins_and_refuses_the_rest() {
    use probation_server::fleet::check_settings;
    for key in ["cargo_upstream_url", "cargo_artifacts_url"] {
        assert!(
            check_settings(&format!("{key} = \"https://crates.mirror.example\"\n")).is_ok(),
            "{key}"
        );
        for refused in ["http://crates.mirror.example", "ftp://x", "mirror"] {
            assert!(
                check_settings(&format!("{key} = \"{refused}\"\n")).is_err(),
                "{key} = {refused}"
            );
        }
        assert!(
            check_settings(&format!("{key} = 7\n")).is_err(),
            "{key} must be a string"
        );
    }
    assert!(check_settings("listen = \"0.0.0.0:1\"\n").is_err());
}

/// Row 18: the archive origin travels in the snapshot for a Cargo registry that has one, is omitted for
/// every other, and the database refuses one on any other kind of registry.
#[tokio::test]
async fn snapshot_carries_the_archive_origin_of_a_cargo_registry_only() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Archives").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'cargo', 'With', 'https://reg.example/index/', 'https://reg.example/crates')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'cargo', 'Without', 'https://reg2.example/index/')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'npm', 'Npm', 'https://n.example/', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, archive_origin) VALUES ($1, 'cargo', 'NoTarget', 'https://x.example/')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let cargo: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "Cargo")
        .collect();
    assert_eq!(cargo.len(), 2);
    let with = cargo
        .iter()
        .find(|r| r["target_url"] == "https://reg.example/index/")
        .unwrap();
    let without = cargo
        .iter()
        .find(|r| r["target_url"] == "https://reg2.example/index/")
        .unwrap();
    assert_eq!(with["archive_origin"], "https://reg.example/crates");
    assert!(
        without.get("archive_origin").is_none(),
        "absent, never null: {without}"
    );
}

/// Row 19: a Go registry and a Go block travel in the snapshot under the wire spelling `Go` (the tag in
/// the database is `go`, already carried by migration 0014, so row 19 needs no migration of its own),
/// and a block on a case-sensitive module path keeps its capitals.
#[tokio::test]
async fn snapshot_names_a_go_registry_and_a_go_block() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Gophers").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'go', 'Modules')")
        .bind(org.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    let layer: i32 = sqlx::query_scalar(
        "SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1",
    )
    .bind(org.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name, version) VALUES ($1, 'go', 'github.com/Azure/azure-sdk-for-go', '1.0.0+incompatible')")
        .bind(layer).execute(&db.owner).await.unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ecosystem"] == "Go"),
        "{snapshot}"
    );
    let text = snapshot.to_string();
    assert!(
        text.contains(r#""name":"github.com/Azure/azure-sdk-for-go""#)
            && text.contains(r#""version":"1.0.0+incompatible""#)
            && text.contains("Go"),
        "the block decodes as a Go block: {snapshot}"
    );
}

/// Row 19: a settings push may set the two Go origins, and only to an https address.
#[test]
fn settings_push_accepts_https_go_origins_and_refuses_the_rest() {
    use probation_server::fleet::check_settings;
    for key in ["go_upstream_url", "go_sumdb_url", "go_artifacts_url"] {
        assert!(
            check_settings(&format!("{key} = \"https://goproxy.mirror.example\"\n")).is_ok(),
            "{key}"
        );
        for refused in ["http://goproxy.mirror.example", "ftp://x", "mirror"] {
            assert!(
                check_settings(&format!("{key} = \"{refused}\"\n")).is_err(),
                "{key} = {refused}"
            );
        }
        assert!(
            check_settings(&format!("{key} = 7\n")).is_err(),
            "{key} must be a string"
        );
    }
}

/// Row 19 (migration 0017): the database lets a Go registry with a target hold an archive origin and
/// still refuses one on any other kind of registry, or without a target; the snapshot carries it for
/// the Go registry that has one and omits it for the one that has none.
#[tokio::test]
async fn snapshot_carries_the_archive_origin_of_a_go_registry_and_the_constraint_still_refuses_the_rest()
 {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Goarchives").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'go', 'With', 'https://goproxy.example/repo/', 'https://zips.example/bucket')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'go', 'Without', 'https://goproxy2.example/repo/')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'npm', 'Npm', 'https://n.example/', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, archive_origin) VALUES ($1, 'go', 'NoTarget', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'pypi', 'Pypi', 'https://n.example/', 'https://x.example/')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let go: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "Go")
        .collect();
    assert_eq!(go.len(), 2);
    let with = go
        .iter()
        .find(|r| r["target_url"] == "https://goproxy.example/repo/")
        .unwrap();
    let without = go
        .iter()
        .find(|r| r["target_url"] == "https://goproxy2.example/repo/")
        .unwrap();
    assert_eq!(with["archive_origin"], "https://zips.example/bucket");
    assert!(
        without.get("archive_origin").is_none(),
        "absent, never null: {without}"
    );
}

/// Row 20: a NuGet registry and a NuGet block travel in the snapshot under the wire spelling `NuGet` (the tag in the
/// database is `nuget`, already carried by migration 0014), and a block is keyed by the lower-cased id the firewall
/// looks up.
#[tokio::test]
async fn snapshot_names_a_nuget_registry_and_a_nuget_block() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Dotnetters").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'nuget', 'Packages')",
    )
    .bind(org.id as i32)
    .execute(&db.owner)
    .await
    .unwrap();
    let layer: i32 = sqlx::query_scalar(
        "SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1",
    )
    .bind(org.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name, version) VALUES ($1, 'nuget', 'Newtonsoft.Json', '12.0.3')")
        .bind(layer).execute(&db.owner).await.unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ecosystem"] == "NuGet"),
        "{snapshot}"
    );
    let text = snapshot.to_string();
    assert!(
        text.contains(r#""ecosystem":"NuGet""#) && text.contains(r#""version":"12.0.3""#),
        "the block decodes as a NuGet block: {snapshot}"
    );
}

/// Row 20: a settings push may set the three NuGet origins, and only to an https address.
#[test]
fn settings_push_accepts_https_nuget_origins_and_refuses_the_rest() {
    use probation_server::fleet::check_settings;
    for key in [
        "nuget_upstream_url",
        "nuget_search_url",
        "nuget_publish_url",
    ] {
        assert!(
            check_settings(&format!("{key} = \"https://nuget.mirror.example\"\n")).is_ok(),
            "{key}"
        );
        for refused in ["http://nuget.mirror.example", "ftp://x", "mirror"] {
            assert!(
                check_settings(&format!("{key} = \"{refused}\"\n")).is_err(),
                "{key} = {refused}"
            );
        }
        assert!(
            check_settings(&format!("{key} = 7\n")).is_err(),
            "{key} must be a string"
        );
    }
}

/// Row 20 (migration 0018): the database lets a NuGet registry with a target hold an archive origin (a feed that
/// redirects a package to its storage) and still refuses one on any other kind of registry, or without a target;
/// the snapshot carries it for the NuGet registry that has one and omits it for the one that has none.
#[tokio::test]
async fn snapshot_carries_the_archive_origin_of_a_nuget_registry_and_the_constraint_still_refuses_the_rest()
 {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Nugetarchives").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'nuget', 'With', 'https://pkgs.example/nuget/v3/index.json', 'https://blobs.example/store')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'nuget', 'Without', 'https://pkgs2.example/nuget/v3/index.json')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'rubygems', 'Gems', 'https://n.example/', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, archive_origin) VALUES ($1, 'nuget', 'NoTarget', 'https://x.example/')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let nuget: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "NuGet")
        .collect();
    assert_eq!(nuget.len(), 2);
    let with = nuget
        .iter()
        .find(|r| r["target_url"] == "https://pkgs.example/nuget/v3/index.json")
        .unwrap();
    let without = nuget
        .iter()
        .find(|r| r["target_url"] == "https://pkgs2.example/nuget/v3/index.json")
        .unwrap();
    assert_eq!(with["archive_origin"], "https://blobs.example/store");
    assert!(
        without.get("archive_origin").is_none(),
        "absent, never null: {without}"
    );
}

/// Row 20 (migration 0019, security review F3): only a NuGet registry with a target may hold a resource path prefix, and
/// the snapshot carries it for the registry that has one and omits it for the one that has none.
#[tokio::test]
async fn snapshot_carries_the_resource_path_prefix_of_a_nuget_registry_and_the_constraint_refuses_the_rest()
 {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Prefixed").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, resource_path_prefix) VALUES ($1, 'nuget', 'With', 'https://pkgs.example/org-a/v3/index.json', '/org-a')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'nuget', 'Without', 'https://pkgs2.example/v3/index.json')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, resource_path_prefix) VALUES ($1, 'go', 'Go', 'https://g.example/', '/x')",
        "INSERT INTO registries (org_id, ecosystem, name, resource_path_prefix) VALUES ($1, 'nuget', 'NoTarget', '/x')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let nuget: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "NuGet")
        .collect();
    let with = nuget
        .iter()
        .find(|r| r["target_url"] == "https://pkgs.example/org-a/v3/index.json")
        .unwrap();
    let without = nuget
        .iter()
        .find(|r| r["target_url"] == "https://pkgs2.example/v3/index.json")
        .unwrap();
    assert_eq!(with["resource_path_prefix"], "/org-a");
    assert!(
        without.get("resource_path_prefix").is_none(),
        "absent, never null: {without}"
    );
}

/// Row 21: a Maven registry and a Maven block travel in the snapshot under the wire spelling `Maven` (the tag in the database is
/// `maven`, already carried by migration 0014), and the block keeps the coordinate's case (`groupId:artifactId` is case-exact).
#[tokio::test]
async fn snapshot_names_a_maven_registry_and_a_maven_block() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Javaers").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'maven', 'Central')")
        .bind(org.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    let layer: i32 = sqlx::query_scalar(
        "SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1",
    )
    .bind(org.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name, version) VALUES ($1, 'maven', 'org.Example:Lib', '1.0-SNAPSHOT')")
        .bind(layer).execute(&db.owner).await.unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ecosystem"] == "Maven"),
        "{snapshot}"
    );
    let text = snapshot.to_string();
    assert!(
        text.contains(r#""ecosystem":"Maven""#)
            && text.contains("org.Example:Lib")
            && text.contains("1.0-SNAPSHOT"),
        "the block decodes as a Maven block: {snapshot}"
    );
}

/// Row 21: a settings push may set the two Maven origins (an origin and a path prefix), and only to an https address.
#[test]
fn settings_push_accepts_https_maven_origins_and_refuses_the_rest() {
    use probation_server::fleet::check_settings;
    for key in ["maven_upstream_url", "maven_publish_url"] {
        assert!(
            check_settings(&format!(
                "{key} = \"https://maven.mirror.example/maven2\"\n"
            ))
            .is_ok(),
            "{key}"
        );
        for refused in ["http://maven.mirror.example", "ftp://x", "mirror"] {
            assert!(
                check_settings(&format!("{key} = \"{refused}\"\n")).is_err(),
                "{key} = {refused}"
            );
        }
        assert!(
            check_settings(&format!("{key} = 7\n")).is_err(),
            "{key} must be a string"
        );
    }
}

/// Row 21 (migration 0020): the database lets a Maven registry with a target hold an archive origin (a repository that redirects an
/// artifact to its storage) and still refuses one on any other kind of registry, or without a target; the snapshot carries it for
/// the Maven registry that has one and omits it for the one that has none.
#[tokio::test]
async fn snapshot_carries_the_archive_origin_of_a_maven_registry_and_the_constraint_still_refuses_the_rest()
 {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Mavenarchives").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'maven', 'With', 'https://nexus.example/repository/releases/', 'https://blobs.example/store')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'maven', 'Without', 'https://nexus2.example/repository/releases/')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'rubygems', 'Gems', 'https://n.example/', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, archive_origin) VALUES ($1, 'maven', 'NoTarget', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, target_url, resource_path_prefix) VALUES ($1, 'maven', 'Prefix', 'https://m.example/', '/x')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let maven: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "Maven")
        .collect();
    assert_eq!(maven.len(), 2);
    let with = maven
        .iter()
        .find(|r| r["target_url"] == "https://nexus.example/repository/releases/")
        .unwrap();
    let without = maven
        .iter()
        .find(|r| r["target_url"] == "https://nexus2.example/repository/releases/")
        .unwrap();
    assert_eq!(with["archive_origin"], "https://blobs.example/store");
    assert!(
        without.get("archive_origin").is_none(),
        "absent, never null: {without}"
    );
}

/// Row 23: a Conan registry and a Conan block travel in the snapshot under the wire spelling `Conan` (the tag in the database is
/// `conan`, already carried by migration 0014), and the block keeps the package name's case.
#[tokio::test]
async fn snapshot_names_a_conan_registry_and_a_conan_block() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Cpp").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'conan', 'Center')")
        .bind(org.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    let layer: i32 = sqlx::query_scalar(
        "SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1",
    )
    .bind(org.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name, version) VALUES ($1, 'conan', 'Evil_Pkg', '1.0')")
        .bind(layer).execute(&db.owner).await.unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ecosystem"] == "Conan"),
        "{snapshot}"
    );
    let text = snapshot.to_string();
    assert!(
        text.contains(r#""ecosystem":"Conan""#) && text.contains("Evil_Pkg"),
        "the block decodes as a Conan block: {snapshot}"
    );
}

/// Row 23: a settings push may set the two Conan origins (an origin and a path prefix), and only to an https address.
#[test]
fn settings_push_accepts_https_conan_origins_and_refuses_the_rest() {
    use probation_server::fleet::check_settings;
    for key in ["conan_upstream_url", "conan_publish_url"] {
        assert!(
            check_settings(&format!(
                "{key} = \"https://conan.mirror.example/artifactory/api/conan/conan\"\n"
            ))
            .is_ok(),
            "{key}"
        );
        for refused in ["http://conan.mirror.example", "ftp://x", "mirror"] {
            assert!(
                check_settings(&format!("{key} = \"{refused}\"\n")).is_err(),
                "{key} = {refused}"
            );
        }
        assert!(
            check_settings(&format!("{key} = 7\n")).is_err(),
            "{key} must be a string"
        );
    }
}

/// Row 23 (migration 0021): the database lets a Conan registry with a target hold an archive origin and still refuses one on any
/// other kind of registry, or without a target; the snapshot carries it for the Conan registry that has one and omits it for the one
/// that has none.
#[tokio::test]
async fn snapshot_carries_the_archive_origin_of_a_conan_registry_and_the_constraint_still_refuses_the_rest()
 {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Conanarchives").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'conan', 'With', 'https://art.example/artifactory/api/conan/c/', 'https://blobs.example/store')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'conan', 'Without', 'https://art2.example/artifactory/api/conan/c/')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'rubygems', 'Gems', 'https://n.example/', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, archive_origin) VALUES ($1, 'conan', 'NoTarget', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, target_url, resource_path_prefix) VALUES ($1, 'conan', 'Prefix', 'https://m.example/', '/x')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let conan: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "Conan")
        .collect();
    assert_eq!(conan.len(), 2);
    let with = conan
        .iter()
        .find(|r| r["target_url"] == "https://art.example/artifactory/api/conan/c/")
        .unwrap();
    let without = conan
        .iter()
        .find(|r| r["target_url"] == "https://art2.example/artifactory/api/conan/c/")
        .unwrap();
    assert_eq!(with["archive_origin"], "https://blobs.example/store");
    assert!(
        without.get("archive_origin").is_none(),
        "absent, never null: {without}"
    );
}

/// Row 24: an OCI registry and an OCI block travel in the snapshot under the wire spelling `Oci` (the tag in the database is
/// `oci`, already carried by migration 0014), and the block keeps the repository name.
#[tokio::test]
async fn snapshot_names_a_oci_registry_and_a_oci_block() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Images").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name) VALUES ($1, 'oci', 'Hub')")
        .bind(org.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
    let layer: i32 = sqlx::query_scalar(
        "SELECT l.id FROM policy_layers l WHERE l.place_kind = 'org' AND l.place_id = $1",
    )
    .bind(org.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO policy_blocks (layer, ecosystem, name, version) VALUES ($1, 'oci', 'evil/pkg', '1.0')")
        .bind(layer).execute(&db.owner).await.unwrap();
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(
        snapshot["registries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ecosystem"] == "Oci"),
        "{snapshot}"
    );
    let text = snapshot.to_string();
    assert!(
        text.contains(r#""ecosystem":"Oci""#) && text.contains("evil/pkg"),
        "the block decodes as an OCI block: {snapshot}"
    );
}

/// Row 24: a settings push may set the two OCI origins (the default registry, with a path prefix if it has one, and the storage its blob redirects land on), and only to an https address.
#[test]
fn settings_push_accepts_https_oci_origins_and_refuses_the_rest() {
    use probation_server::fleet::check_settings;
    for key in ["oci_upstream_url", "oci_artifacts_url"] {
        assert!(
            check_settings(&format!(
                "{key} = \"https://oci.mirror.example/artifactory/api/oci/oci\"\n"
            ))
            .is_ok(),
            "{key}"
        );
        for refused in ["http://oci.mirror.example", "ftp://x", "mirror"] {
            assert!(
                check_settings(&format!("{key} = \"{refused}\"\n")).is_err(),
                "{key} = {refused}"
            );
        }
        assert!(
            check_settings(&format!("{key} = 7\n")).is_err(),
            "{key} must be a string"
        );
    }
}

/// Row 24 (migration 0022): the database lets an OCI registry with a target hold an archive origin and still refuses one on any
/// other kind of registry, or without a target; the snapshot carries it for the OCI registry that has one and omits it for the one
/// that has none.
#[tokio::test]
async fn snapshot_carries_the_archive_origin_of_a_oci_registry_and_the_constraint_still_refuses_the_rest()
 {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Ociarchives").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'oci', 'With', 'https://reg.example/', 'https://blobs.example/store')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'oci', 'Without', 'https://reg2.example/')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, archive_origin) VALUES ($1, 'rubygems', 'Gems', 'https://n.example/', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, archive_origin) VALUES ($1, 'oci', 'NoTarget', 'https://x.example/')",
        "INSERT INTO registries (org_id, ecosystem, name, target_url, resource_path_prefix) VALUES ($1, 'oci', 'Prefix', 'https://m.example/', '/x')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let oci: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "Oci")
        .collect();
    assert_eq!(oci.len(), 2);
    let with = oci
        .iter()
        .find(|r| r["target_url"] == "https://reg.example/")
        .unwrap();
    let without = oci
        .iter()
        .find(|r| r["target_url"] == "https://reg2.example/")
        .unwrap();
    assert_eq!(with["archive_origin"], "https://blobs.example/store");
    assert!(
        without.get("archive_origin").is_none(),
        "absent, never null: {without}"
    );
}

/// Row 24 (migration 0023, code review F5): an OCI registry with a target may declare a token origin and the snapshot carries it; the database
/// refuses one on any other kind of registry or without a target.
#[tokio::test]
async fn snapshot_carries_the_token_origin_of_an_oci_registry_and_the_constraint_refuses_the_rest()
{
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Ocitokens").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let key = keys::create(&db.app, &actor, &place, "service")
        .await
        .unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url, token_origin) VALUES ($1, 'oci', 'With', 'https://reg.example/', 'https://gitlab.example')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    sqlx::query("INSERT INTO registries (org_id, ecosystem, name, target_url) VALUES ($1, 'oci', 'Without', 'https://reg2.example/')")
        .bind(org.id as i32).execute(&db.owner).await.unwrap();
    for bad in [
        "INSERT INTO registries (org_id, ecosystem, name, target_url, token_origin) VALUES ($1, 'conan', 'C', 'https://n.example/', 'https://x.example')",
        "INSERT INTO registries (org_id, ecosystem, name, token_origin) VALUES ($1, 'oci', 'NoTarget', 'https://x.example')",
    ] {
        assert!(
            sqlx::query(bad)
                .bind(org.id as i32)
                .execute(&db.owner)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let url = common::serve(db.app.clone(), vec![])
        .await
        .join("api/v1/policy/snapshot")
        .unwrap();
    let response = client()
        .get(url)
        .bearer_auth(&key.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let oci: Vec<&serde_json::Value> = snapshot["registries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ecosystem"] == "Oci")
        .collect();
    assert_eq!(oci.len(), 2);
    let with = oci
        .iter()
        .find(|r| r["target_url"] == "https://reg.example/")
        .unwrap();
    let without = oci
        .iter()
        .find(|r| r["target_url"] == "https://reg2.example/")
        .unwrap();
    assert_eq!(with["token_origin"], "https://gitlab.example");
    assert!(
        without.get("token_origin").is_none(),
        "absent, never null: {without}"
    );
    // R2: the certificate admission reads the same column as the application role does (the query it runs after the grant).
    for (target, expected) in [
        ("https://reg.example/", Some("https://gitlab.example")),
        ("https://reg2.example/", None),
    ] {
        let found: Option<String> =
            sqlx::query_scalar("SELECT token_origin FROM registries WHERE target_url = $1")
                .bind(target)
                .fetch_one(&db.app)
                .await
                .unwrap();
        assert_eq!(found.as_deref(), expected, "{target}");
    }
}
