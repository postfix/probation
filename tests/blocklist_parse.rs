//! The blocklist snapshot's public parse and lookup API (SPEC §7, §8), without a
//! server: how names, versions and digests are read, and how a refusal is reported.

use std::error::Error as _;

use probation::policy::blocklist::{self, BlocklistError};
use probation::policy::{BlocklistSnapshot, Digest, Ecosystem, HashAlgorithm};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

const NOW: i64 = 1_790_000_000_000_000;

fn document(packages: &str, hashes: &str) -> String {
    format!(
        r#"{{"schema_version":1,"revision":1,
             "generated_at":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
             "blocked_packages":[{packages}],"blocked_hashes":[{hashes}]}}"#
    )
}

fn parse(packages: &str, hashes: &str) -> Result<BlocklistSnapshot, BlocklistError> {
    BlocklistSnapshot::parse_and_validate(document(packages, hashes).as_bytes(), NOW)
}

fn snapshot(packages: &str) -> BlocklistSnapshot {
    parse(packages, "").expect("a valid snapshot")
}

/// An empty or padded version, and a digest with no reason, are malformed records:
/// the whole candidate is refused rather than applied without them.
#[test]
fn a_record_missing_what_it_needs_is_refused_by_index() {
    for version in ["\"\"", "\" 1.0\""] {
        let err = parse(
            &format!(r#"{{"ecosystem":"npm","name":"a","version":{version},"reason":"x"}}"#),
            "",
        )
        .expect_err("a malformed version");
        assert!(
            matches!(err, BlocklistError::MalformedRecord { index: 0, .. }),
            "{err}"
        );
    }
    let err = parse(
        "",
        &format!(
            r#"{{"algorithm":"sha256","digest":"{}","reason":" "}}"#,
            "aa".repeat(32)
        ),
    )
    .expect_err("a digest with no reason");
    assert!(
        matches!(err, BlocklistError::MalformedRecord { index: 0, .. }),
        "{err}"
    );
    assert!(err.to_string().contains("blocked_hashes[0]"), "{err}");
}

/// A version npm's parser rejects keeps only its exact spelling: it narrows a block,
/// it never widens one onto a real release.
#[test]
fn an_unparseable_npm_version_matches_only_itself() {
    let blocked = snapshot(r#"{"ecosystem":"npm","name":"a","version":"v-odd","reason":"x"}"#);
    assert!(blocked.blocks_version(Ecosystem::Npm, "a", "v-odd"));
    assert!(!blocked.blocks_version(Ecosystem::Npm, "a", "1.0.0"));
}

/// `load_file` caps the read itself, and every refusal is reported by what went
/// wrong, keeping the underlying error where there is one.
#[test]
fn load_file_refusals_name_their_cause() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("blocklist.json");
    let text = document("", "");
    std::fs::write(&path, &text).expect("the blocklist is written");

    let err = blocklist::load_file(&path, text.len() as u64 - 1, NOW).expect_err("too large");
    assert!(matches!(err, BlocklistError::TooLarge { .. }), "{err}");
    assert!(err.to_string().contains("byte limit"), "{err}");
    assert!(err.source().is_none());
    blocklist::load_file(&path, text.len() as u64, NOW).expect("exactly the limit is accepted");

    let err = blocklist::load_file(&dir.path().join("absent.json"), 1024, NOW)
        .expect_err("an absent file");
    assert!(err.to_string().starts_with("cannot read"), "{err}");
    assert!(err.source().is_some());

    let err = BlocklistSnapshot::parse_and_validate(b"{", NOW).expect_err("not JSON");
    assert!(err.source().is_some(), "{err}");
}

/// Every digest refusal says which algorithm and what was wrong with it.
#[test]
fn digest_refusals_name_their_cause() {
    for (entry, needle) in [
        ("md5-AAAA", "unsupported hash algorithm `md5`"),
        ("no-separator", "unsupported hash algorithm `no`"),
        ("nodash", "is not an `<algorithm>-<base64>` SRI entry"),
        (
            "sha256-AAAA",
            "a sha256 digest is 32 bytes, but this one decodes to 3",
        ),
        ("sha256-QQ=A", "the sha256 digest is not valid base64"),
        ("sha256-not!base64", "the sha256 digest is not valid base64"),
    ] {
        let err = Digest::parse_sri_entry(entry).expect_err("refused");
        assert!(err.to_string().contains(needle), "{entry}: {err}");
    }
    let err = Digest::parse_hex(HashAlgorithm::Sha512, "zz").expect_err("not hexadecimal");
    assert_eq!(
        err.to_string(),
        "the sha512 digest is not valid hexadecimal"
    );
    assert_eq!(HashAlgorithm::Sha1.to_string(), "sha1");
}

/// A canonical name, `[a-z0-9]+` segments joined by `-`, and a PEP 503 spelling of
/// it: any letter's case flipped and each `-` replaced by a run of `-`, `_` and `.`.
fn canonical_and_variant() -> impl Strategy<Value = (String, String)> {
    let part = ("[a-z0-9]{1,8}", "[-_.]{1,3}", any::<u64>());
    proptest::collection::vec(part, 1..5).prop_map(|parts| {
        let canonical = parts
            .iter()
            .map(|(segment, ..)| segment.as_str())
            .collect::<Vec<_>>()
            .join("-");
        let mut variant = String::new();
        for (index, (segment, separator, case_bits)) in parts.iter().enumerate() {
            if index > 0 {
                variant.push_str(separator);
            }
            for (bit, c) in segment.chars().enumerate() {
                if (case_bits >> bit) & 1 == 1 {
                    variant.push(c.to_ascii_uppercase());
                } else {
                    variant.push(c);
                }
            }
        }
        (canonical, variant)
    })
}

proptest! {
    // Integration tests have no `src/` sibling for proptest to place seeds beside, so
    // they go where the crate's other regressions are committed.
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "proptest-regressions/blocklist_parse.txt",
        ))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_pypi_block_in_any_pep503_spelling_blocks_the_normalised_name(
        (canonical, variant) in canonical_and_variant()
    ) {
        let blocked = snapshot(&format!(
            r#"{{"ecosystem":"pypi","name":"{variant}","version":null,"reason":"malware"}},
               {{"ecosystem":"pypi","name":"{variant}","version":"1.0","reason":"malware"}}"#
        ));
        let versioned = snapshot(&format!(
            r#"{{"ecosystem":"pypi","name":"{variant}","version":"1.0","reason":"malware"}}"#
        ));

        prop_assert!(blocked.blocks_package(Ecosystem::PyPi, &canonical));
        prop_assert!(versioned.blocks_version(Ecosystem::PyPi, &canonical, "1.0"));
        let unrelated = format!("{canonical}-unrelated");
        prop_assert!(!blocked.blocks_package(Ecosystem::PyPi, &unrelated));
        prop_assert!(!versioned.blocks_version(Ecosystem::PyPi, &unrelated, "1.0"));
    }
}

/// npm names are case-sensitive identifiers and are never rewritten.
#[test]
fn an_npm_block_is_not_normalised() {
    let blocked =
        snapshot(r#"{"ecosystem":"npm","name":"Evil_Pkg","version":null,"reason":"malware"}"#);
    assert!(blocked.blocks_package(Ecosystem::Npm, "Evil_Pkg"));
    assert!(!blocked.blocks_package(Ecosystem::Npm, "evil-pkg"));
}
