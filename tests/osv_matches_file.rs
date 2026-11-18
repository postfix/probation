//! Row 30, LS-F11 and C1031: the persisted matched entries of a managed endpoint.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use probation::osv::matches::{self, HEADER, MAX_ENTRIES, MAX_RECORD, crc32, load_matches, render_matches};
use probation_policy::Ecosystem;

const WINDOW: Duration = Duration::from_secs(86_400);

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn at(offset: u64) -> u64 {
    1_800_000_000 + offset
}

/// One record line as the writer spells it.
fn record(eco: &str, name: &str, version: &str, x: u64) -> String {
    let c = crc32(format!("{eco}|{name}|{version}|{x}").as_bytes());
    format!(r#"{{"e":"{eco}","n":"{name}","v":"{version}","x":{x},"c":"{c:08x}"}}"#) + "\n"
}

fn file(lines: &[String]) -> Vec<u8> {
    let mut out = format!("{HEADER}\n").into_bytes();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
    }
    out
}

#[test]
fn osv_matches_file_one_bad_record_keeps_the_rest() {
    let bytes = file(&[
        record("npm", "a", "1.0.0", at(100)),
        "this is not json\n".to_owned(),
        record("npm", "b", "1.0.0", at(100)),
    ]);
    let loaded = load_matches(&bytes, now(), WINDOW);
    assert_eq!(loaded.entries.len(), 2);
    assert_eq!(loaded.skipped, 1, "counted in osv_matches_records_skipped");
}

#[test]
fn osv_matches_file_torn_last_line_skipped() {
    let mut bytes = file(&[record("npm", "a", "1.0.0", at(100))]);
    let torn = record("npm", "b", "1.0.0", at(100));
    bytes.extend_from_slice(&torn.as_bytes()[..torn.len() - 1]);
    let loaded = load_matches(&bytes, now(), WINDOW);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.skipped, 1);
}

#[test]
fn osv_matches_file_expiry_clamped_to_stale_window() {
    let far = at(10 * 86_400);
    let loaded = load_matches(&file(&[record("npm", "a", "1.0.0", far)]), now(), WINDOW);
    assert_eq!(loaded.entries[0].expiry_unix, at(86_400), "a clock set back cannot extend protection");
}

#[test]
fn osv_matches_file_expired_records_pruned() {
    let bytes = file(&[
        record("npm", "gone", "1.0.0", at(0)),
        record("npm", "older", "1.0.0", 5),
        record("npm", "live", "1.0.0", at(1)),
    ]);
    let loaded = load_matches(&bytes, now(), WINDOW);
    let names: Vec<&str> = loaded.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["live"], "x at or before the wall clock is pruned");
    assert_eq!(loaded.skipped, 0, "expiry is not corruption");
}

#[test]
fn osv_matches_file_record_revalidated_with_wire_bounds() {
    let bad_checksum = record("npm", "a", "1.0.0", at(100)).replace("\"c\":\"", "\"c\":\"0");
    let charset = record("npm", "bad name", "1.0.0", at(100));
    let negative = r#"{"e":"npm","n":"a","v":"1","x":-5,"c":"00000000"}"#.to_owned() + "\n";
    let float = r#"{"e":"npm","n":"a","v":"1","x":1.5e9,"c":"00000000"}"#.to_owned() + "\n";
    let unknown_eco = record("maven", "a", "1", at(100));
    let extra = r#"{"e":"npm","n":"a","v":"1","x":1900000000,"c":"00000000","z":1}"#.to_owned() + "\n";
    let bytes = file(&[bad_checksum, charset, negative, float, unknown_eco, extra]);
    let loaded = load_matches(&bytes, now(), WINDOW);
    assert!(loaded.entries.is_empty());
    assert_eq!(loaded.skipped, 6);
}

/// If a later release tightens `osv_key`, an old record that no longer validates is
/// skipped and counted: modelled here by a record the current charset already refuses.
#[test]
fn osv_matches_file_older_records_skipped_after_charset_change() {
    let loaded = load_matches(&file(&[record("pypi", "Mixed_Case", "1.0", at(100))]), now(), WINDOW);
    assert!(loaded.entries.is_empty());
    assert_eq!(loaded.skipped, 1);
}

#[test]
fn osv_matches_file_unknown_header_loads_empty() {
    for bytes in [b"".to_vec(), b"probation-osv-matches v2\n".to_vec(), b"garbage".to_vec(), vec![0xff, 0xfe, 0x00]] {
        let loaded = load_matches(&bytes, now(), WINDOW);
        assert!(loaded.entries.is_empty() && !loaded.header_ok, "{bytes:?}");
    }
    let mut with_record = b"probation-osv-matches v2\n".to_vec();
    with_record.extend_from_slice(record("npm", "a", "1.0.0", at(100)).as_bytes());
    assert!(load_matches(&with_record, now(), WINDOW).entries.is_empty());
}

#[test]
fn osv_matches_file_record_over_the_bound_skipped() {
    let long = "a".repeat(1000);
    let c = crc32(format!("npm|{long}|{}|{}", "1".repeat(1000), at(100)).as_bytes());
    let line = format!(r#"{{"e":"npm","n":"{long}","v":"{}","x":{},"c":"{c:08x}","pad":"{}"}}"#, "1".repeat(1000), at(100), "p".repeat(400)) + "\n";
    assert!(line.len() > MAX_RECORD);
    let ok = record("npm", "fine", "1.0.0", at(100));
    let loaded = load_matches(&file(&[line, ok]), now(), WINDOW);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.skipped, 1);
}

#[test]
fn osv_matches_file_duplicate_keys_later_line_wins() {
    let bytes = file(&[record("npm", "a", "1.0.0", at(100)), record("npm", "a", "1.0.0", at(500))]);
    let loaded = load_matches(&bytes, now(), WINDOW);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].expiry_unix, at(500));
}

#[test]
fn osv_matches_file_bounds_on_load_and_write() {
    // Load: valid records beyond the cap are dropped, keeping the furthest expiry.
    let mut lines = Vec::new();
    for i in 0..(MAX_ENTRIES + 5) {
        lines.push(record("npm", &format!("p{i}"), "1.0.0", at(10 + i as u64)));
    }
    let loaded = load_matches(&file(&lines), now(), Duration::from_secs(10_000_000));
    assert_eq!(loaded.entries.len(), MAX_ENTRIES);
    assert!(loaded.entries.iter().all(|e| e.expiry_unix >= at(15)), "the nearest expiries went");
    // At the cap is accepted untouched.
    let at_cap = load_matches(&file(&lines[..MAX_ENTRIES]), now(), Duration::from_secs(10_000_000));
    assert_eq!(at_cap.entries.len(), MAX_ENTRIES);

    // Write: over the entry cap drops the nearest expiry, never the newest.
    let entries: Vec<_> = (0..(MAX_ENTRIES + 3))
        .map(|i| (Ecosystem::Npm, format!("p{i}"), "1.0.0".to_owned(), at(10 + i as u64)))
        .collect();
    let rendered = render_matches(&entries);
    assert_eq!(rendered.dropped, 3);
    let reloaded = load_matches(&rendered.bytes, now(), Duration::from_secs(10_000_000));
    assert_eq!(reloaded.entries.len(), MAX_ENTRIES);
    assert!(reloaded.entries.iter().any(|e| e.name == format!("p{}", MAX_ENTRIES + 2)), "the newest survives");
    assert!(rendered.bytes.len() <= 16 << 20);
}

#[test]
fn osv_matches_file_mode_owner_only_and_atomic_replace() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("osv-matches");
    matches::write_atomic(&path, &render_matches(&[(Ecosystem::Npm, "a".into(), "1.0.0".into(), at(100))]).bytes).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    // A replace leaves no temp file behind and the old content only until the rename.
    matches::write_atomic(&path, &render_matches(&[(Ecosystem::Npm, "b".into(), "2.0.0".into(), at(100))]).bytes).unwrap();
    let names: Vec<String> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(names, ["osv-matches"], "{names:?}");
    let loaded = load_matches(&std::fs::read(&path).unwrap(), now(), WINDOW);
    assert_eq!(loaded.entries[0].name, "b");
}

/// A match for the longest key `osv_key` accepts must persist and load (SEC-1 widened the key).
#[test]
fn osv_matches_file_longest_key_roundtrips() {
    let entries = [(Ecosystem::Npm, "n".repeat(1024), "1".repeat(1024), at(100))];
    let rendered = render_matches(&entries);
    assert_eq!(rendered.dropped, 0);
    let loaded = load_matches(&rendered.bytes, now(), WINDOW);
    assert_eq!((loaded.entries.len(), loaded.skipped), (1, 0));
}
