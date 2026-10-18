//! PyPI content negotiation (SPEC §7, RFC 9110 §12.5.1): the most specific media
//! range that matches a representation decides its quality, and `q=0` means "not
//! acceptable" however broad a wildcard elsewhere in the header is.

mod common;

use std::sync::OnceLock;

use common::{TestClock, TestServer, config_with_open_blocklist};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// One server for every generated case: starting one per case would make the
/// property minutes long for no extra coverage.
struct Shared {
    runtime: tokio::runtime::Runtime,
    server: TestServer,
    _dir: tempfile::TempDir,
}

fn shared() -> &'static Shared {
    static SHARED: OnceLock<Shared> = OnceLock::new();
    SHARED.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a test runtime");
        let dir = tempfile::tempdir().expect("a temporary directory");
        let config = config_with_open_blocklist(dir.path());
        let server = runtime.block_on(TestServer::start_with(
            config,
            TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        ));
        Shared {
            runtime,
            server,
            _dir: dir,
        }
    })
}

/// The status and the media type served, for one `Accept` header.
fn negotiate(accept: &str) -> (u16, String) {
    let shared = shared();
    shared.runtime.block_on(async {
        let response = shared
            .server
            .get_with_headers("/pypi/simple/", &[("accept", accept)])
            .await;
        let media = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        (response.status().as_u16(), media)
    })
}

const RANGES: &[&str] = &[
    "application/vnd.pypi.simple.v1+json",
    "application/vnd.pypi.simple.v1+html",
    "application/json",
    "text/html",
    "TEXT/HTML",
    "text/*",
    "application/*",
    "*/*",
    "application/xml",
];

/// Spellings of a quality, each with whether it is zero.
const QUALITIES: &[(&str, bool)] = &[
    ("", false),
    (";q=0", true),
    (";Q=0", true),
    (";q=0.000", true),
    (" ; q=0.0", true),
    (";q=0.001", false),
    (";q=0.5", false),
    (";q=1", false),
];

fn accept_header() -> impl Strategy<Value = (String, Vec<(String, bool)>)> {
    proptest::collection::vec((0..RANGES.len(), 0..QUALITIES.len()), 1..5).prop_map(|entries| {
        let parsed: Vec<(String, bool)> = entries
            .iter()
            .map(|&(range, quality)| (RANGES[range].to_ascii_lowercase(), QUALITIES[quality].1))
            .collect();
        let header = entries
            .iter()
            .map(|&(range, quality)| format!("{}{}", RANGES[range], QUALITIES[quality].0))
            .collect::<Vec<_>>()
            .join(", ");
        (header, parsed)
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "proptest-regressions/pypi_accept.txt",
        ))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_media_type_given_q_zero_is_never_served((header, entries) in accept_header()) {
        let (status, served) = negotiate(&header);
        prop_assert!(status == 200 || status == 406, "Accept: {header} answered {status}");
        if status == 200 {
            prop_assert!(
                !entries.iter().any(|(range, zero)| *zero && *range == served),
                "Accept: {header} was served {served}, which it refused with q=0"
            );
        }
    }
}

#[test]
fn a_type_wildcard_matches_its_own_types() {
    assert_eq!(negotiate("text/*"), (200, "text/html".to_owned()));
    assert_eq!(
        negotiate("*/*;q=0.1, text/html;q=0"),
        (200, "application/vnd.pypi.simple.v1+json".to_owned()),
        "the more specific range refuses HTML, and the wildcard still admits JSON"
    );
    assert_eq!(negotiate("text/*;q=0, application/xml").0, 406);
}
