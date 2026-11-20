//! The service-mode operational log (row 25 fix round): under the Windows service control manager stdout goes nowhere, so the
//! JSON events go to a size-bounded, self-rotating file in the installer's access-controlled log directory. The module is not
//! platform specific; this proves the bound and that no event is lost across a rotation.

use std::io::Write;

use probation::service_log::RotatingFile;

#[test]
fn the_log_stays_within_its_bound_and_keeps_the_newest_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probation.log");
    let mut log = RotatingFile::open(&path, 1000, 2).expect("opens");
    for n in 0..200 {
        // One `write_all` per event, as the tracing formatter does (it renders the line into a buffer first).
        log.write_all(format!("{{\"event\":{n:04}}}\n").as_bytes()).unwrap();
    }
    log.flush().unwrap();
    let mut total = 0;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let len = entry.metadata().unwrap().len();
        assert!(len <= 1000, "{:?} is {len} bytes, over the 1000 byte bound", entry.file_name());
        total += len;
    }
    assert!(total <= 3000, "live file plus two backups: {total}");
    let newest = std::fs::read_to_string(&path).unwrap();
    assert!(newest.contains("\"event\":0199"), "the newest event is in the live file: {newest}");
    assert!(dir.path().join("probation.log.2").exists() && !dir.path().join("probation.log.3").exists(), "two backups, no more");
}

#[test]
fn a_single_event_larger_than_the_bound_is_cut_not_dropped_silently() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probation.log");
    let mut log = RotatingFile::open(&path, 100, 1).unwrap();
    log.write_all(&[b'x'; 500]).unwrap();
    log.flush().unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() <= 100);
}

#[test]
fn reopening_appends_to_the_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probation.log");
    writeln!(RotatingFile::open(&path, 1000, 1).unwrap(), "first").unwrap();
    writeln!(RotatingFile::open(&path, 1000, 1).unwrap(), "second").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\nsecond\n");
}
