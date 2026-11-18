//! Row 30, LS-F7: the degraded-ratio warning and refused keys a managed firewall reports are
//! shown in the fleet health the portal lists.

mod common;

use common::Db;
use probation_server::{fleet, tenancy::Actor};

async fn health_with(osv: serde_json::Value) -> String {
    let db = Db::fresh().await;
    let registered = fleet::register(&db.app, &Actor::Operator, "fw", &["127.0.0.0/8".parse().unwrap()]).await.unwrap();
    let report = serde_json::json!({
        "settings_revision": 0, "last_apply_error": null,
        "status": {"upstreams": {"npm": "ok", "pypi": "ok", "osv": "ok"}},
        "effective_period_seconds": 55, "version": "0.2.2", "osv": osv,
    });
    sqlx::query("UPDATE firewalls SET last_seen_at = now(), last_report = $2 WHERE id = $1")
        .bind(registered.id)
        .bind(serde_json::json!({"report": report}))
        .execute(&db.owner)
        .await
        .unwrap();
    let rows = fleet::firewalls(&db.app).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].healthy, "a warning never makes a firewall unhealthy: readiness is unchanged");
    rows[0].health.clone()
}

#[tokio::test]
async fn osv_degraded_warning_and_refused_keys_show_in_fleet_health() {
    let quiet = health_with(serde_json::json!({"degraded_warning": false, "results_total": 5, "results_degraded": 0, "server_unreached": 0, "matches_file_degraded": 0, "stale_matches_expired": 0, "matches_records_skipped": 0})).await;
    assert_eq!(quiet, "Healthy");
    let degraded = health_with(serde_json::json!({"degraded_warning": true, "results_total": 100, "results_degraded": 40, "server_unreached": 1, "matches_file_degraded": 0, "stale_matches_expired": 0, "matches_records_skipped": 0})).await;
    assert!(degraded.starts_with("Healthy") && degraded.contains("OSV warning") && degraded.contains("degraded"), "{degraded}");
    let refused = health_with(serde_json::json!({"degraded_warning": false, "results_total": 1, "results_degraded": 1, "server_unreached": 0, "matches_file_degraded": 0, "stale_matches_expired": 0, "matches_records_skipped": 0, "keys_refused": 3})).await;
    assert!(refused.contains("OSV warning") && refused.contains("3 keys refused"), "{refused}");
    let stale = health_with(serde_json::json!({"degraded_warning": false, "results_total": 1, "results_degraded": 0, "server_unreached": 0, "matches_file_degraded": 2, "stale_matches_expired": 1, "matches_records_skipped": 0})).await;
    assert!(stale.contains("OSV warning") && stale.contains("matches file"), "{stale}");
}
