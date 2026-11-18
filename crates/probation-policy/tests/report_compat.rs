//! The sync report is read by firewalls and servers of different versions (S7-14): a report in
//! the shape written before row 30 still parses, and the `osv` object is additive.

use probation_policy::api::FirewallReport;

/// Verbatim shape of a pre-row-30 report (no `osv` key, no `failed_revision`).
const OLD: &str = r#"{"settings_revision":3,"last_apply_error":null,"status":{"upstreams":{"npm":"ok","pypi":"ok","osv":"unreachable"}},"effective_period_seconds":55,"version":"0.2.2"}"#;

#[test]
fn an_old_shape_report_parses_and_has_no_osv() {
    let report: FirewallReport = serde_json::from_str(OLD).unwrap();
    assert_eq!(report.osv, None);
    assert_eq!(report.settings_revision, 3);
    let again = serde_json::to_string(&report).unwrap();
    assert!(!again.contains("\"osv\":{"), "an absent osv is left out: {again}");
}

#[test]
fn a_new_report_with_an_older_osv_object_and_unknown_fields_parses() {
    let text = OLD.replace(r#""version":"0.2.2""#, r#""version":"0.2.2","osv":{"degraded_warning":true,"results_total":10,"results_degraded":2,"server_unreached":0,"matches_file_degraded":0,"stale_matches_expired":0,"matches_records_skipped":0,"from_the_future":1}"#);
    let report: FirewallReport = serde_json::from_str(&text).unwrap();
    let osv = report.osv.unwrap();
    assert!(osv.degraded_warning);
    assert_eq!(osv.keys_refused, 0, "a field added later defaults");
}
