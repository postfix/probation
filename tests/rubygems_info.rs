//! Row 17: compact-index parsing and the gem file name rules, against a real slice of
//! rubygems.org's `info/nokogiri` (platform lines, `created_at:` and `checksum:`).

use probation::rubygems::info::{InfoError, filename_candidates, parse_info, render_info, valid_gem_name};

fn real() -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/rubygems/info-nokogiri.txt", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn info_real_slice_parses_with_platforms_checksums_and_dates() {
    let entries = parse_info(&real(), 10_000).unwrap();
    assert!(entries.len() >= 20);
    let mac = entries.iter().find(|e| e.version == "1.16.6" && e.platform.as_deref() == Some("x86_64-darwin")).unwrap();
    assert_eq!(hex::encode(mac.sha256.unwrap()), "92fa413d866baf9b609f17558ecfbcf950d5373213babcf4ce11d7eaed4b21cf");
    assert_eq!(mac.gem_filename("nokogiri"), "nokogiri-1.16.6-x86_64-darwin.gem");
    assert!(mac.created_micros.is_some_and(|m| m > 1_700_000_000_000_000));
    let plain = entries.iter().find(|e| e.version == "1.16.6" && e.platform.is_none()).unwrap();
    assert_eq!(plain.gem_filename("nokogiri"), "nokogiri-1.16.6.gem");
    assert_eq!(plain.expected().len(), 1);
}

#[test]
fn info_filter_keeps_every_kept_line_byte_for_byte() {
    let raw = real();
    let entries = parse_info(&raw, 10_000).unwrap();
    assert_eq!(render_info(entries.iter()), raw, "keeping everything reproduces the file");
    let kept: Vec<_> = entries.iter().filter(|e| e.version != "1.16.6").collect();
    let out = String::from_utf8(render_info(kept.iter().copied())).unwrap();
    assert!(out.starts_with("---\n") && !out.contains("\n1.16.6 ") && !out.contains("\n1.16.6-"));
    assert_eq!(out.lines().count(), kept.len() + 1);
    // The surviving lines are upstream's own text.
    assert!(kept.iter().all(|e| out.contains(&e.line)));
}

#[test]
fn info_refuses_what_is_not_an_index_instead_of_passing_it_through() {
    assert_eq!(parse_info(b"1.0.0 |checksum:aa\n", 10).unwrap_err(), InfoError::Header);
    assert_eq!(parse_info(&[0xff, 0xfe], 10).unwrap_err(), InfoError::NotUtf8);
    for bad in ["../x |checksum:aa", "1.0.0-a/b |x:y", "v1 |x:y", "1..0 |x:y", "1.0.0", "1.0.0-java extra |x:y\n1.0.0-java |x:y"] {
        assert!(parse_info(format!("---\n{bad}\n").as_bytes(), 10).is_err(), "{bad}");
    }
    assert_eq!(parse_info(b"---\n1.0.0 |a:b\n1.0.0 |a:b\n", 10).unwrap_err(), InfoError::Duplicate);
    assert_eq!(parse_info(b"---\n1.0.0 |a:b\n1.0.1 |a:b\n", 1).unwrap_err(), InfoError::TooMany);
    // A registry without created_at or checksum still parses: the lines carry no date.
    let plain = parse_info(b"---\n2.0.0 dep:>= 1|ruby:>= 2\n", 10).unwrap();
    assert_eq!((plain[0].created_micros, plain[0].sha256), (None, None));
}

#[test]
fn gem_file_names_split_at_every_digit_led_hyphen() {
    assert_eq!(filename_candidates("rack-3.0.0.gem"), vec![("rack".to_owned(), "3.0.0".to_owned())]);
    let platform = filename_candidates("nokogiri-1.16.6-x86_64-linux.gem");
    assert_eq!(platform, vec![("nokogiri".to_owned(), "1.16.6-x86_64-linux".to_owned())]);
    // `foo-1-2.gem` could be foo 1-2 (platform `2`) or foo-1 version 2: both are candidates, the index decides.
    let ambiguous = filename_candidates("foo-1-2.0.gem");
    assert_eq!(ambiguous.len(), 2);
    assert!(filename_candidates("rack-3.0.0.tgz").is_empty());
    assert!(filename_candidates("-1.0.gem").is_empty());
    assert!(filename_candidates("../etc-1.0.gem").is_empty(), "a path never becomes a name");
    assert!(valid_gem_name("Rack_Test-2.rb") && !valid_gem_name("a/b") && !valid_gem_name("") && !valid_gem_name("-x"));
}
