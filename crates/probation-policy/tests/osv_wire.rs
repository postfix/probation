//! LS-F2 and LS-F5: the central answer and request wire, shared by client and server.

use probation_policy::osv_wire::{
    AnswerError, OsvOutcome, parse_central_answer, parse_request, render_answer,
    RenderedResult,
};

fn answer(results: &str, meta: &str) -> Vec<u8> {
    format!(r#"{{"results":{results}{meta}}}"#).into_bytes()
}
const META_OK: &str = r#","probation_osv":{"v":1,"upstream_ok":true}"#;

#[test]
fn osv_central_answer_without_meta_is_unreached() {
    let body = answer("[{}]", "");
    assert_eq!(parse_central_answer(&body, 1), Err(AnswerError::MissingEnvelopeMeta));
}

#[test]
fn central_answer_outcomes_follow_ls_f2() {
    let body = answer(r#"[{},{"vulns":[{"id":"MAL-1"}]},{"probation_degraded":true}]"#, META_OK);
    assert_eq!(
        parse_central_answer(&body, 3).unwrap(),
        vec![OsvOutcome::NoMatch, OsvOutcome::Matched, OsvOutcome::Degraded]
    );
}

#[test]
fn osv_result_with_vulns_and_degraded_is_degraded() {
    let body = answer(r#"[{"vulns":[{"id":"MAL-1"}],"probation_degraded":true}]"#, META_OK);
    assert_eq!(parse_central_answer(&body, 1).unwrap(), vec![OsvOutcome::Degraded]);
}

#[test]
fn upstream_not_ok_makes_no_match_degraded_but_a_match_stands() {
    let meta = r#","probation_osv":{"v":1,"upstream_ok":false}"#;
    let body = answer(r#"[{},{"vulns":[{"id":"MAL-1"}]}]"#, meta);
    assert_eq!(
        parse_central_answer(&body, 2).unwrap(),
        vec![OsvOutcome::Degraded, OsvOutcome::Matched],
        "only an upstream_ok no-match may be stored as a no-match; a match is always honoured"
    );
}

#[test]
fn osv_answer_duplicate_keys_unreached() {
    let body = br#"{"results":[{}],"results":[{}],"probation_osv":{"v":1,"upstream_ok":true}}"#;
    assert_eq!(parse_central_answer(body, 1), Err(AnswerError::DuplicateKey));
}

#[test]
fn answer_errors_length_version_notjson_oversize() {
    assert_eq!(parse_central_answer(&answer("[{}]", META_OK), 2), Err(AnswerError::LengthMismatch));
    assert_eq!(
        parse_central_answer(&answer("[{}]", r#","probation_osv":{"v":2,"upstream_ok":true}"#), 1),
        Err(AnswerError::UnsupportedVersion)
    );
    assert_eq!(parse_central_answer(b"<html>", 1), Err(AnswerError::NotJson));
    let big = vec![b' '; 8192 + 4096 + 1];
    assert_eq!(parse_central_answer(&big, 1), Err(AnswerError::Oversize));
}

#[test]
fn answer_ignores_unknown_fields_for_forward_compatibility() {
    let body = answer(r#"[{"extra":1,"vulns":[{"id":"MAL-1","modified":"x","z":0}]}]"#, r#","probation_osv":{"v":1,"upstream_ok":true,"later":true}"#);
    assert_eq!(parse_central_answer(&body, 1).unwrap(), vec![OsvOutcome::Matched]);
}

#[test]
fn osv_empty_queries_answers_upstream_ok() {
    let body = render_answer(&[], true);
    assert_eq!(parse_central_answer(&body, 0).unwrap(), vec![]);
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains(r#""results":[]"#) && text.contains(r#""upstream_ok":true"#), "{text}");
}

#[test]
fn response_shape_matches_osv_dev_golden() {
    let body = render_answer(
        &[
            RenderedResult::NoMatch,
            RenderedResult::Matched(vec![("MAL-2026-1".into(), Some("2026-01-01T00:00:00Z".into()))]),
            RenderedResult::Degraded,
        ],
        true,
    );
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "results": [
                {},
                {"vulns": [{"id": "MAL-2026-1", "modified": "2026-01-01T00:00:00Z"}]},
                {"probation_degraded": true}
            ],
            "probation_osv": {"v": 1, "upstream_ok": true}
        }),
        "the osv.dev shape plus exactly the two additive fields"
    );
}

fn request(body: &str) -> Result<Vec<probation_policy::osv_wire::ParsedQuery>, probation_policy::osv_wire::EnvelopeError> {
    parse_request(body.as_bytes())
}

#[test]
fn osv_envelope_defects_return_4xx() {
    for body in ["not json", "[]", "{}", r#"{"queries":5}"#, r#"{"queries":[],"queries":[]}"#] {
        assert!(request(body).is_err(), "{body}");
    }
    assert!(request(r#"{"queries":[]}"#).unwrap().is_empty());
}

#[test]
fn osv_route_degrades_unknown_field_commit_purl_page_token_and_versionless_per_query() {
    let good = r#"{"package":{"name":"left-pad","ecosystem":"npm"},"version":"1.3.0"}"#;
    let bad = [
        r#"{"package":{"name":"a","ecosystem":"npm"},"version":"1","extra":1}"#,
        r#"{"package":{"name":"a","ecosystem":"npm"},"version":"1","commit":"abc"}"#,
        r#"{"package":{"purl":"pkg:npm/a"},"version":"1"}"#,
        r#"{"package":{"name":"a","ecosystem":"npm"},"version":"1","page_token":"t"}"#,
        r#"{"package":{"name":"a","ecosystem":"npm"}}"#,
        r#"{"package":{"name":"a","ecosystem":"npm"},"version":""}"#,
        r#"{"package":{"name":"a","ecosystem":"npm"},"version":5}"#,
        r#"7"#,
        r#"{"package":{"name":"a","ecosystem":"npm"},"version":"1","version":"2"}"#,
    ];
    let body = format!(r#"{{"queries":[{good},{}]}}"#, bad.join(&format!(",{good},")));
    let parsed = request(&body).unwrap();
    assert_eq!(parsed.len(), bad.len() * 2);
    for (i, item) in parsed.iter().enumerate() {
        if i % 2 == 0 {
            assert_eq!(item.as_ref().unwrap(), &("npm".to_owned(), "left-pad".to_owned(), "1.3.0".to_owned()));
        } else {
            assert!(item.is_err(), "query {i} must degrade");
        }
    }
}

#[test]
fn osv_result_vuln_refs_truncated_still_matched() {
    let refs: Vec<(String, Option<String>)> = (0..40).map(|i| (format!("MAL-{i}"), Some("m".repeat(60)))).collect();
    let body = render_answer(&[RenderedResult::Matched(refs)], true);
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vulns = value["results"][0]["vulns"].as_array().unwrap();
    assert_eq!(vulns.len(), 32, "at most 32 refs");
    assert_eq!(vulns[0]["modified"].as_str().unwrap().len(), 40, "modified at most 40 bytes");
    assert_eq!(parse_central_answer(&body, 1).unwrap(), vec![OsvOutcome::Matched]);
    let long_id = render_answer(&[RenderedResult::Matched(vec![("MAL-".to_owned() + &"x".repeat(200), None)])], true);
    let value: serde_json::Value = serde_json::from_slice(&long_id).unwrap();
    assert_eq!(value["results"][0]["vulns"][0]["id"].as_str().unwrap().len(), 128);
    assert!(long_id.len() <= 8192 + 4096);
}

/// A result is `{}` for no match; anything else that is not an object is not a
/// confirmation of anything, so it can never erase a retained match.
#[test]
fn osv_non_object_result_is_degraded() {
    let body = answer(r#"[null,5,"x",[],{}]"#, META_OK);
    assert_eq!(
        parse_central_answer(&body, 5).unwrap(),
        vec![OsvOutcome::Degraded, OsvOutcome::Degraded, OsvOutcome::Degraded, OsvOutcome::Degraded, OsvOutcome::NoMatch]
    );
}
