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

/// Row 17: the RubyGems upstream state is additive. A report without it parses (an old firewall),
/// a firewall that never calls RubyGems leaves the key out, and an older server's struct, which
/// has no such field, still reads a report that carries it.
#[test]
fn rubygems_reachability_is_additive_in_both_directions() {
    use probation_policy::api::{Reachability, Upstreams};
    let old: Upstreams = serde_json::from_str(r#"{"npm":"ok","pypi":"ok","osv":"ok"}"#).unwrap();
    assert_eq!(old.rubygems, None);
    assert!(!serde_json::to_string(&old).unwrap().contains("rubygems"), "an unknown state is not written");
    let new = Upstreams { rubygems: Some(Reachability::Unreachable), ..old };
    let text = serde_json::to_string(&new).unwrap();
    assert!(text.contains(r#""rubygems":"unreachable""#), "{text}");
    #[derive(serde::Deserialize)]
    struct OlderServer {
        npm: Reachability,
        pypi: Reachability,
        osv: Reachability,
    }
    let older: OlderServer = serde_json::from_str(&text).unwrap();
    assert_eq!((older.npm, older.pypi, older.osv), (Reachability::Ok, Reachability::Ok, Reachability::Ok));
}

/// Row 18: the Cargo upstream state is additive in the same way (absent from an older report,
/// never written when unknown, ignored by an older reader).
#[test]
fn cargo_reachability_is_additive_in_both_directions() {
    use probation_policy::api::{Reachability, Upstreams};
    let old: Upstreams = serde_json::from_str(r#"{"npm":"ok","pypi":"ok","osv":"ok","rubygems":"ok"}"#).unwrap();
    assert_eq!(old.cargo, None);
    assert!(!serde_json::to_string(&old).unwrap().contains("cargo"));
    let new = Upstreams { cargo: Some(Reachability::Unreachable), ..old };
    let text = serde_json::to_string(&new).unwrap();
    assert!(text.contains(r#""cargo":"unreachable""#), "{text}");
    #[derive(serde::Deserialize)]
    struct OlderServer {
        npm: Reachability,
        rubygems: Option<Reachability>,
    }
    let older: OlderServer = serde_json::from_str(&text).unwrap();
    assert_eq!((older.npm, older.rubygems), (Reachability::Ok, Some(Reachability::Ok)));
}

/// Row 19: the Go upstream state is additive in the same way as RubyGems and Cargo.
#[test]
fn go_reachability_is_additive_in_both_directions() {
    use probation_policy::api::{Reachability, Upstreams};
    let old: Upstreams = serde_json::from_str(r#"{"npm":"ok","pypi":"ok","osv":"ok","cargo":"ok"}"#).unwrap();
    assert_eq!(old.go, None);
    assert!(!serde_json::to_string(&old).unwrap().contains("\"go\""));
    let new = Upstreams { go: Some(Reachability::Unreachable), ..old };
    let text = serde_json::to_string(&new).unwrap();
    assert!(text.contains(r#""go":"unreachable""#), "{text}");
    #[derive(serde::Deserialize)]
    struct OlderServer {
        npm: Reachability,
        cargo: Option<Reachability>,
    }
    let older: OlderServer = serde_json::from_str(&text).unwrap();
    assert_eq!((older.npm, older.cargo), (Reachability::Ok, Some(Reachability::Ok)));
}

/// Row 20: the NuGet upstream state is additive in the same way as the families before it.
#[test]
fn nuget_reachability_is_additive_in_both_directions() {
    use probation_policy::api::{Reachability, Upstreams};
    let old: Upstreams = serde_json::from_str(r#"{"npm":"ok","pypi":"ok","osv":"ok","go":"ok"}"#).unwrap();
    assert_eq!(old.nuget, None);
    assert!(!serde_json::to_string(&old).unwrap().contains("nuget"));
    let new = Upstreams { nuget: Some(Reachability::Unreachable), ..old };
    let text = serde_json::to_string(&new).unwrap();
    assert!(text.contains(r#""nuget":"unreachable""#), "{text}");
    #[derive(serde::Deserialize)]
    struct OlderServer {
        npm: Reachability,
        go: Option<Reachability>,
    }
    let older: OlderServer = serde_json::from_str(&text).unwrap();
    assert_eq!((older.npm, older.go), (Reachability::Ok, Some(Reachability::Ok)));
}
