//! Slice 2's witness for the two validation commands (SPEC §4) and for the
//! configuration rules behind them.
//!
//! Three things are asserted here that no unit test can: that the rules reach the
//! command an operator actually runs, that a refusal names a reason rather than
//! "invalid TOML", and that neither command writes anything. The readiness tests at
//! the end cover the other half of the slice — a snapshot loaded at startup, and
//! `/health/ready` following its validity while `/health/live` does not. The named
//! `readiness_false_at_expiry_liveness_true` belongs to the poller slice, which is
//! where the reload path that test also exercises is built.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{TestClock, TestServer, sample_config};
use probation::config::{Config, ConfigError};
use probation::policy::{Ecosystem, blocklist};
use probation::store::cache::ProjectKey;
use url::Url;

/// Cargo builds the binary for this test and hands us its path; the exit codes SPEC
/// §4 specifies belong to the command, not to a library call.
const BINARY: &str = env!("CARGO_BIN_EXE_probation");

/// Each fixture with the reason its refusal must name. The same table drives the
/// library check and the command check, so the two cannot report different things.
const INVALID_CONFIGS: &[(&str, &str)] = &[
    ("unknown_key.toml", "unknown key `cooldown_second`"),
    ("missing_key.toml", "missing key `data_dir`"),
    ("syntax.toml", "invalid TOML"),
    ("listen_not_an_address.toml", "invalid `listen`"),
    ("public_url_not_https.toml", "invalid `public_url`"),
    ("public_url_with_path.toml", "invalid `public_url`"),
    ("public_url_with_query.toml", "invalid `public_url`"),
    ("relative_data_dir.toml", "invalid `data_dir`"),
    ("relative_blocklist_file.toml", "invalid `blocklist_file`"),
    (
        "zero_blocklist_poll_seconds.toml",
        "invalid `blocklist_poll_seconds`",
    ),
    ("zero_cache_max_bytes.toml", "invalid `cache_max_bytes`"),
    (
        "zero_memory_cache_max_bytes.toml",
        "invalid `memory_cache_max_bytes`",
    ),
    (
        "zero_max_metadata_bytes.toml",
        "invalid `max_metadata_bytes`",
    ),
    (
        "zero_max_blocklist_bytes.toml",
        "invalid `max_blocklist_bytes`",
    ),
    (
        "zero_max_upstream_requests.toml",
        "invalid `max_upstream_requests`",
    ),
    (
        "zero_max_artifact_downloads.toml",
        "invalid `max_artifact_downloads`",
    ),
    (
        "zero_max_active_requests.toml",
        "invalid `max_active_requests`",
    ),
    (
        "zero_max_references_per_project.toml",
        "invalid `max_references_per_project`",
    ),
    (
        "artifact_larger_than_cache.toml",
        "invalid `max_artifact_bytes`",
    ),
    (
        "zero_osv_cache_ttl_seconds.toml",
        "invalid `osv_cache_ttl_seconds`",
    ),
    (
        "zero_osv_request_timeout_ms.toml",
        "invalid `osv_request_timeout_ms`",
    ),
    ("invalid_osv_mode.toml", "invalid `osv_mode`"),
];

const INVALID_BLOCKLISTS: &[(&str, &str)] = &[
    ("syntax.json", "invalid JSON"),
    (
        "unsupported_schema_version.json",
        "unsupported schema_version 2",
    ),
    (
        "unsupported_algorithm.json",
        "unsupported hash algorithm `sha1`",
    ),
    ("malformed_digest.json", "malformed sha256 digest"),
    ("malformed_record.json", "malformed record"),
    ("unknown_record_field.json", "invalid JSON"),
    ("missing_field.json", "invalid JSON"),
    ("expired.json", "the snapshot has expired"),
    (
        "generated_in_the_future.json",
        "generated_at is in the future",
    ),
    (
        "inverted_window.json",
        "generated_at is not before expires_at",
    ),
];

fn config_fixture(name: &str) -> PathBuf {
    Path::new("tests/fixtures/config").join(name)
}

fn blocklist_fixture(name: &str) -> PathBuf {
    Path::new("tests/fixtures/blocklist").join(name)
}

fn now_micros() -> i64 {
    jiff::Timestamp::now().as_microsecond()
}

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("the binary runs")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_shipped_samples_are_valid() {
    Config::load(Path::new("config.sample.toml")).expect("the sample configuration is valid");
    let snapshot = blocklist::load_file(
        Path::new("blocklist.sample.json"),
        blocklist::DEFAULT_MAX_BLOCKLIST_BYTES,
        now_micros(),
    )
    .expect("the sample blocklist is valid");
    assert_eq!(snapshot.entry_count(), 3);
}

#[test]
fn an_unknown_key_is_named_rather_than_reported_as_invalid_toml() {
    match Config::load(&config_fixture("unknown_key.toml")) {
        Err(ConfigError::UnknownKey(key)) => assert_eq!(key, "cooldown_second"),
        other => panic!("expected the misspelled key to be named, got {other:?}"),
    }
}

#[test]
fn a_missing_key_is_named_rather_than_reported_as_invalid_toml() {
    match Config::load(&config_fixture("missing_key.toml")) {
        Err(ConfigError::MissingKey(key)) => assert_eq!(key, "data_dir"),
        other => panic!("expected the absent key to be named, got {other:?}"),
    }
}

/// Deletes each key of the shipped sample in turn. Every key is either required and
/// named when it goes missing, or documented here as one with a default — so the
/// required-key list in `src/config.rs` cannot drift from the file an operator
/// copies.
#[test]
fn deleting_any_sample_key_is_reported_as_that_key_missing() {
    let text = fs::read_to_string("config.sample.toml").expect("the sample is readable");
    let key_of = |line: &str| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        line.split('=').next().map(|key| key.trim().to_owned())
    };

    let keys: Vec<String> = text.lines().filter_map(key_of).collect();
    assert_eq!(keys.len(), 20, "the sample carries every documented key");

    /// The keys `src/config.rs` gives a default, which a file may leave out.
    const WITH_DEFAULTS: &[&str] = &[
        "max_references_per_project",
        "metadata_max_age_seconds",
        "osv_cache_ttl_seconds",
        "osv_request_timeout_ms",
        "osv_mode",
    ];

    for key in &keys {
        let without: Vec<&str> = text
            .lines()
            .filter(|line| key_of(line).as_ref() != Some(key))
            .collect();
        let without = without.join("\n");

        match Config::from_toml_str(&without) {
            Err(ConfigError::MissingKey(missing)) => assert_eq!(&missing, key),
            Ok(_) => assert!(
                WITH_DEFAULTS.contains(&key.as_str()),
                "only a key with a documented default may be left out, and `{key}` has none"
            ),
            other => panic!("deleting `{key}` should name it as missing, got {other:?}"),
        }
    }
}

#[test]
fn every_invalid_config_fixture_is_refused_with_its_reason() {
    for (fixture, reason) in INVALID_CONFIGS {
        let err = Config::load(&config_fixture(fixture))
            .expect_err(&format!("{fixture} must be refused"))
            .to_string();
        assert!(
            err.contains(reason),
            "{fixture}: expected a refusal naming `{reason}`, got `{err}`"
        );
    }
}

#[test]
fn osv_mode_defaults_to_enforce_when_absent() {
    let config =
        Config::load(Path::new("config.sample.toml")).expect("the sample configuration is valid");
    assert_eq!(config.osv_mode, probation::osv::OsvMode::Enforce);

    let text = fs::read_to_string("config.sample.toml").expect("the sample is readable");
    let without: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("osv_mode"))
        .collect::<Vec<_>>()
        .join("\n");
    let config = Config::from_toml_str(&without).expect("osv_mode is optional");
    assert_eq!(config.osv_mode, probation::osv::OsvMode::Enforce);
}

#[test]
fn every_invalid_blocklist_fixture_is_refused_with_its_reason() {
    for (fixture, reason) in INVALID_BLOCKLISTS {
        let err = blocklist::load_file(
            &blocklist_fixture(fixture),
            blocklist::DEFAULT_MAX_BLOCKLIST_BYTES,
            now_micros(),
        )
        .expect_err(&format!("{fixture} must be refused"))
        .to_string();
        assert!(
            err.contains(reason),
            "{fixture}: expected a refusal naming `{reason}`, got `{err}`"
        );
    }

    // SPEC §8: an intentionally empty, valid snapshot is allowed and means only
    // cooldown protection is active. It is not a malformed file.
    let empty = blocklist::load_file(
        &blocklist_fixture("empty_but_valid.json"),
        blocklist::DEFAULT_MAX_BLOCKLIST_BYTES,
        now_micros(),
    )
    .expect("an empty snapshot is valid");
    assert_eq!(empty.entry_count(), 0);
}

#[test]
fn check_config_exits_zero_on_the_sample_and_names_a_reason_otherwise() {
    let ok = run(&["check-config", "config.sample.toml"]);
    assert!(
        ok.status.success(),
        "check-config on the sample must exit 0: {}",
        stderr_of(&ok)
    );

    // SPEC §4 spells the command with `--config`; the slice's witness uses the
    // positional form. Both reach the same validation.
    let with_flag = run(&["check-config", "--config", "config.sample.toml"]);
    assert!(with_flag.status.success());

    for (fixture, reason) in INVALID_CONFIGS {
        let path = config_fixture(fixture);
        let output = run(&["check-config", path.to_str().expect("a UTF-8 path")]);
        assert!(
            !output.status.success(),
            "{fixture}: check-config must exit non-zero"
        );
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains(reason),
            "{fixture}: expected stderr to name `{reason}`, got `{stderr}`"
        );
    }

    let absent = run(&["check-config", "tests/fixtures/config/not-here.toml"]);
    assert!(!absent.status.success());
    assert!(stderr_of(&absent).contains("cannot read"));
}

#[test]
fn check_blocklist_exits_zero_on_a_valid_snapshot_and_names_a_reason_otherwise() {
    let ok = run(&["check-blocklist", "blocklist.sample.json"]);
    assert!(
        ok.status.success(),
        "check-blocklist on the sample must exit 0: {}",
        stderr_of(&ok)
    );

    let empty = blocklist_fixture("empty_but_valid.json");
    let empty = run(&["check-blocklist", empty.to_str().expect("a UTF-8 path")]);
    assert!(
        empty.status.success(),
        "a valid empty snapshot is accepted, never treated as malformed"
    );

    for (fixture, reason) in INVALID_BLOCKLISTS {
        let path = blocklist_fixture(fixture);
        let output = run(&["check-blocklist", path.to_str().expect("a UTF-8 path")]);
        assert!(
            !output.status.success(),
            "{fixture}: check-blocklist must exit non-zero"
        );
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains(reason),
            "{fixture}: expected stderr to name `{reason}`, got `{stderr}`"
        );
    }

    let absent = run(&["check-blocklist", "tests/fixtures/blocklist/not-here.json"]);
    assert!(!absent.status.success());
    assert!(stderr_of(&absent).contains("cannot read"));
}

/// SPEC §4: the validation commands do not modify state. The configuration under
/// test points its `data_dir` and `blocklist_file` inside the temporary directory,
/// so a command that created either would be caught here.
#[test]
fn the_check_commands_write_nothing() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let root = dir.path();
    let config_path = root.join("config.toml");
    let sample = fs::read_to_string("config.sample.toml").expect("the sample is readable");
    let config = sample
        .replace(
            "/var/lib/probation",
            &root.join("data").display().to_string(),
        )
        .replace(
            "/etc/probation/blocklist.json",
            &root.join("blocklist.json").display().to_string(),
        );
    fs::write(&config_path, config).expect("the test configuration is written");

    let entries_before = listing(root);

    for args in [
        vec!["check-config".to_owned(), path_arg(&config_path)],
        vec![
            "check-blocklist".to_owned(),
            path_arg(&root.join("blocklist.json")),
        ],
        vec![
            "check-config".to_owned(),
            path_arg(&absolute(&config_fixture("syntax.toml"))),
        ],
    ] {
        let output = Command::new(BINARY)
            .args(&args)
            .current_dir(root)
            .output()
            .expect("the binary runs");
        // check-config on a valid file succeeds; the other two refuse. Either way
        // nothing may appear on disk.
        assert!(output.status.code().is_some(), "{args:?} exits normally");
        assert_eq!(
            listing(root),
            entries_before,
            "{args:?} changed the directory contents"
        );
    }

    assert!(
        !root.join("data").exists(),
        "check-config must not create data_dir"
    );
    assert!(
        !root.join("blocklist.json").exists(),
        "check-blocklist must not create the file it was asked about"
    );
}

fn listing(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root)
        .expect("the directory is readable")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn absolute(path: &Path) -> PathBuf {
    std::env::current_dir()
        .expect("a working directory")
        .join(path)
}

fn path_arg(path: &Path) -> String {
    path.to_str().expect("a UTF-8 path").to_owned()
}

/// The blocklist `serve` loads at startup, with a window the test controls.
fn windowed_snapshot(generated_at: &str, expires_at: &str) -> String {
    format!(
        r#"{{"schema_version":1,"revision":11,"generated_at":"{generated_at}",
             "expires_at":"{expires_at}","blocked_packages":[],"blocked_hashes":[]}}"#
    )
}

#[tokio::test]
async fn a_valid_snapshot_at_startup_makes_the_service_ready() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("blocklist.json");
    fs::write(
        &path,
        windowed_snapshot("2026-09-17T00:00:00Z", "2026-09-18T00:00:00Z"),
    )
    .expect("the snapshot is written");

    let mut config = sample_config();
    config.blocklist_file = path;
    let clock = TestClock::at_rfc3339("2026-09-17T12:00:00Z");
    let server = TestServer::start_with(config, clock).await;

    assert_eq!(server.status("/health/live").await, 200);
    assert_eq!(
        server.status("/health/ready").await,
        200,
        "a valid snapshot is in force, so the service is ready"
    );
    assert_eq!(
        server.status("/npm/left-pad").await,
        404,
        "with a policy in force the npm route answers from the decision, not with \
         POLICY_UNAVAILABLE"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn readiness_turns_false_at_expiry_while_liveness_stays_true() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("blocklist.json");
    fs::write(
        &path,
        windowed_snapshot("2026-09-17T00:00:00Z", "2026-09-18T00:00:00Z"),
    )
    .expect("the snapshot is written");

    let mut config = sample_config();
    config.blocklist_file = path;
    let clock = TestClock::at_rfc3339("2026-09-17T23:59:59Z");
    let server = TestServer::start_with(config, clock.clone()).await;

    assert_eq!(server.status("/health/ready").await, 200);

    // Expiry is exclusive: at exactly `expires_at` the snapshot is no longer in
    // force. No poll and no restart is involved — the window is compared against the
    // clock on the request itself.
    clock.set_rfc3339("2026-09-18T00:00:00Z");

    assert_eq!(
        server.status("/health/ready").await,
        503,
        "an expired snapshot is not a policy"
    );
    assert_eq!(
        server.status("/health/live").await,
        200,
        "SPEC §8: liveness remains healthy at expiry"
    );
    assert_eq!(
        server.status("/npm/left-pad").await,
        503,
        "delivery stops at expiry as well"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn a_missing_blocklist_file_leaves_the_service_running_and_unready() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = sample_config();
    config.blocklist_file = dir.path().join("absent.json");

    let server =
        TestServer::start_with(config, TestClock::at_rfc3339("2026-09-17T12:00:00Z")).await;

    assert_eq!(
        server.status("/health/live").await,
        200,
        "an unreadable blocklist is not a reason to refuse to start"
    );
    assert_eq!(server.status("/health/ready").await, 503);
    assert_eq!(server.status("/npm/left-pad").await, 503);

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 15: the maximum-age ceiling (SPEC rev 3 §4)
// ---------------------------------------------------------------------------

/// The shipped sample with its `metadata_max_age_seconds` line removed, and
/// optionally replaced. Written against the real sample rather than a fixture of its
/// own so these three cannot drift from the file an operator copies.
fn sample_with_ceiling(replacement: Option<&str>) -> String {
    let text = fs::read_to_string("config.sample.toml").expect("the sample is readable");
    let mut kept: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("metadata_max_age_seconds"))
        .collect();
    assert_eq!(
        kept.len(),
        text.lines().count() - 1,
        "the sample states the ceiling exactly once"
    );
    if let Some(line) = replacement {
        kept.push(line);
    }
    kept.join("\n")
}

/// SPEC rev 3 §4: a ceiling beneath the revalidation interval would expire every copy
/// before it could ever be revalidated — a configuration that looks stricter and is
/// in fact a self-inflicted outage.
#[test]
fn a_ceiling_below_the_ttl_is_rejected() {
    // The sample's `metadata_ttl_seconds` is 300.
    let err = Config::from_toml_str(&sample_with_ceiling(Some("metadata_max_age_seconds = 299")))
        .expect_err("a ceiling one second beneath the TTL is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "metadata_max_age_seconds",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
    assert!(
        err.to_string().contains("metadata_ttl_seconds"),
        "and the key it is measured against, got `{err}`"
    );

    // The rule is "below", not "at or below": equal is a legitimate choice.
    let equal = Config::from_toml_str(&sample_with_ceiling(Some("metadata_max_age_seconds = 300")))
        .expect("a ceiling equal to the TTL is valid");
    assert_eq!(equal.metadata_max_age_seconds, 300);
}

/// Zero is the off switch, so it is exempt from the rule above rather than caught by
/// it — every TTL is above zero.
#[test]
fn a_zero_ceiling_is_accepted_and_disables_the_rule() {
    let config = Config::from_toml_str(&sample_with_ceiling(Some("metadata_max_age_seconds = 0")))
        .expect("zero disables the ceiling rather than failing the below-the-TTL check");
    assert_eq!(config.metadata_max_age_seconds, 0);
    assert_eq!(
        probation::store::effective_max_age_micros(
            &ProjectKey::new(Ecosystem::Npm, "anything"),
            config.metadata_max_age_seconds
        ),
        None,
        "and no project then has a ceiling at all"
    );
}

/// The key is optional, because files written against SPEC revision 2 do not carry
/// it. They inherit a bound rather than the unbounded staleness the ceiling closes.
#[test]
fn an_absent_ceiling_key_takes_the_default() {
    let config = Config::from_toml_str(&sample_with_ceiling(None))
        .expect("a configuration with no opinion about the ceiling is still valid");
    assert_eq!(
        config.metadata_max_age_seconds, 86_400,
        "an absent key is one day, not zero: a file that predates the key must not \
         silently opt out of the control"
    );
    assert_eq!(
        sample_config().metadata_max_age_seconds,
        86_400,
        "and the shipped sample states the same value explicitly"
    );
}

// ---------------------------------------------------------------------------
// Decision log delivery, slice 1: the two `log_file_*` keys (TP-5a)
// ---------------------------------------------------------------------------

/// The shipped sample with `lines` appended, so these cannot drift from the file an
/// operator copies.
fn sample_with(lines: &[&str]) -> String {
    let mut text = fs::read_to_string("config.sample.toml").expect("the sample is readable");
    for line in lines {
        text.push('\n');
        text.push_str(line);
    }
    text
}

/// A size with nowhere to write it is an operator who believes delivery is on and is
/// getting nothing. Refused by name rather than ignored.
#[test]
fn tp5a_log_file_max_bytes_requires_path() {
    let err = Config::from_toml_str(&sample_with(&["log_file_max_bytes = 1048576"]))
        .expect_err("a size without a path is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "log_file_max_bytes",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
    assert!(
        err.to_string().contains("log_file_path"),
        "and the key it depends on, got `{err}`"
    );

    // The same size *with* a path is the ordinary configuration, so the rule is the
    // pairing and not the key itself.
    let config = Config::from_toml_str(&sample_with(&[
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
        "log_file_max_bytes = 1048576",
    ]))
    .expect("a size alongside a path is valid");
    assert_eq!(config.log_file_max_bytes.get(), 1_048_576);
}

/// Zero is not "unbounded": it is a file that can never hold a record.
#[test]
fn tp5a_log_file_max_bytes_rejects_zero() {
    let err = Config::from_toml_str(&sample_with(&[
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
        "log_file_max_bytes = 0",
    ]))
    .expect_err("a zero size is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "log_file_max_bytes",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
}

/// Absent means off, and the size an absent-but-configured file inherits is the one
/// `config.sample.toml` documents.
#[test]
fn both_log_file_keys_are_optional_and_the_size_has_a_default() {
    let bare = sample_config();
    assert_eq!(bare.log_file_path, None, "delivery is off by default");

    let configured = Config::from_toml_str(&sample_with(&[
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
    ]))
    .expect("a path on its own is valid");
    assert_eq!(
        configured.log_file_max_bytes.get(),
        100 * 1024 * 1024,
        "a path with no stated size inherits 100 MiB, so the pair costs at most 200 MiB"
    );
}

// ---------------------------------------------------------------------------
// Decision log delivery, slice 2: the two `siem_*` keys (TP-5b, TP-6)
// ---------------------------------------------------------------------------

/// A credential header with no collector to send it to is the same mistake as a size
/// with no file: the operator believes delivery is on and is getting nothing.
#[test]
fn tp5b_siem_auth_header_requires_siem_url() {
    let err = Config::from_toml_str(&sample_with(&["siem_auth_header = \"X-Collector-Token\""]))
        .expect_err("a credential header without a collector is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "siem_auth_header",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
    assert!(
        err.to_string().contains("siem_url"),
        "and the key it depends on, got `{err}`"
    );

    // The same header *with* a collector is the ordinary configuration, so the rule is
    // the pairing and not the key itself.
    let config = Config::from_toml_str(&sample_with(&[
        "siem_url = \"https://siem.example.org/ingest\"",
        "siem_auth_header = \"X-Collector-Token\"",
    ]))
    .expect("a credential header alongside a collector is valid");
    assert_eq!(config.siem_auth_header.as_str(), "x-collector-token");

    // And a collector on its own sends the credential under the documented default.
    let defaulted = Config::from_toml_str(&sample_with(&[
        "siem_url = \"https://siem.example.org/ingest\"",
    ]))
    .expect("a collector on its own is valid");
    assert_eq!(
        defaulted.siem_auth_header.as_str(),
        "authorization",
        "a collector with no stated header inherits Authorization"
    );

    // A name no HTTP message could carry is refused by name too.
    let err = Config::from_toml_str(&sample_with(&[
        "siem_url = \"https://siem.example.org/ingest\"",
        "siem_auth_header = \"not a header name\"",
    ]))
    .expect_err("a header name with spaces in it is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "siem_auth_header",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
}

/// The credential and every decision record travel this URL. Plaintext is allowed only
/// where the traffic cannot leave the machine.
#[test]
fn tp6_siem_url_scheme_rule() {
    for accepted in [
        "https://siem.example.org/ingest",
        "http://127.0.0.1:8088/ingest",
        "http://localhost:8088/ingest",
    ] {
        let line = format!("siem_url = \"{accepted}\"");
        let config = Config::from_toml_str(&sample_with(&[&line]))
            .unwrap_or_else(|err| panic!("{accepted} is a valid collector: {err}"));
        assert_eq!(
            config.siem_url.as_ref().map(Url::as_str),
            Some(accepted),
            "and it is kept as written"
        );
    }

    let err = Config::from_toml_str(&sample_with(&[
        "siem_url = \"http://collector.example/ingest\"",
    ]))
    .expect_err("plaintext to a host that is not this machine is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "siem_url",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );

    let err = Config::from_toml_str(&sample_with(&["siem_url = \"not a url\""]))
        .expect_err("a collector that is not a URL is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "siem_url",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
}

// ---------------------------------------------------------------------------
// Decision log delivery, slice 3: `log_consumer_identification` (TP-5c)
// ---------------------------------------------------------------------------

/// Peer addresses acquired for a console the product calls non-durable are data
/// collected for no stated purpose. The opt-in is refused unless something durable is
/// configured to receive them.
#[test]
fn tp5c_consumer_identification_requires_a_sink() {
    let err = Config::from_toml_str(&sample_with(&["log_consumer_identification = true"]))
        .expect_err("recording peer addresses with nowhere to put them is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "log_consumer_identification",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
    // The whole reason, not only the key: the console already receives every peer
    // address, so what the refusal buys is a second destination the operator chose,
    // and a reason claiming otherwise must not come back.
    let ConfigError::Invalid { reason, .. } = &err else {
        unreachable!("matched above");
    };
    assert_eq!(
        reason,
        "requires log_file_path or siem_url, so recorded peer addresses reach a durable \
         destination the operator chose",
        "the refusal says what it actually protects"
    );

    // Either sink on its own is a destination, so the rule is the pairing and not the
    // key itself.
    for sink in [
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
        "siem_url = \"https://siem.example.org/ingest\"",
    ] {
        Config::from_toml_str(&sample_with(&[sink, "log_consumer_identification = true"]))
            .unwrap_or_else(|err| panic!("`{sink}` is a destination for them: {err}"));
    }
}

// ---------------------------------------------------------------------------
// Rated load guard, slice 1: the two delivery queue budget keys
// ---------------------------------------------------------------------------

/// `delivery::DEFAULT_QUEUE_MAX_BYTES`, restated. `mod delivery` is `pub(crate)`, so
/// this external test crate cannot name the constant; pinning its value is the only
/// form the claim has here, and it is a real one — an accidental change to the
/// shipped default fails this line. `ceil(5 min x 200 req/s x BYTES_PER_RECORD)`: the
/// stated 200 req/s reference load, not the rated-load bench's measured ceiling,
/// which the formula could not fit under. Documented in `docs/operations.md` §8
/// (C13 as amended, C39).
const DEFAULT_QUEUE_MAX_BYTES: u64 = 1875 * 1024 * 1024;

/// An operator who writes neither key gets a memory budget all the same, and the same
/// one for both sinks. The default is not conditional on a sink being configured: the
/// shipped sample has both sinks commented out and still carries both budgets.
#[test]
fn rl5_absent_budgets_take_the_default() {
    let config = sample_config();
    assert_eq!(
        config.log_queue_max_bytes, config.siem_queue_max_bytes,
        "one default, not one per sink: the two keys mean the same thing"
    );
    assert_eq!(
        config.log_queue_max_bytes.get(),
        DEFAULT_QUEUE_MAX_BYTES,
        "the shipped default is a memory budget, the same shape as cache_max_bytes"
    );
}

/// A budget too small to hold one whole record is a queue of zero records, which is
/// exactly the buffer `mpsc::channel` panics on. Refused by name at load, so that
/// panic is unreachable rather than merely unlikely — and the refusal states the real
/// minimum, because "1 is too small" leaves the operator guessing what is not.
#[test]
fn rl2_budget_below_one_record_is_refused() {
    let err = Config::from_toml_str(&sample_with(&[
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
        "log_queue_max_bytes = 1",
    ]))
    .expect_err("a budget that cannot hold one record is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "log_queue_max_bytes",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
    assert!(
        err.to_string().contains("32768"),
        "and the smallest budget that would work, got `{err}`"
    );

    // One whole record is the boundary, and it is accepted: the rule is the quotient
    // reaching zero, not a round number someone picked.
    let config = Config::from_toml_str(&sample_with(&[
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
        "log_queue_max_bytes = 32768",
    ]))
    .expect("a budget holding exactly one record is valid");
    assert_eq!(config.log_queue_max_bytes.get(), 32_768);
}

/// The ceiling is a byte ceiling, not a record count: two sinks at the maximum is
/// 8 GiB of resident queue once slice 2 bounds `method` and a record has an upper
/// bound at all, which is already the operator's call to make. Beyond it a
/// figure is far more likely a typo than an intention, and a typo that only shows up
/// as an out-of-memory kill hours later is worth refusing at load.
#[test]
fn rl3_budget_above_the_ceiling_is_refused() {
    let err = Config::from_toml_str(&sample_with(&[
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
        "log_queue_max_bytes = 5368709120",
    ]))
    .expect_err("five gibibytes of queue for one sink is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "log_queue_max_bytes",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
    assert!(
        err.to_string().contains("4294967296"),
        "and the ceiling it exceeded, got `{err}`"
    );

    // The ceiling itself is accepted, so the rule is "above", not "at".
    let config = Config::from_toml_str(&sample_with(&[
        "log_file_path = \"/var/log/probation/decisions.ndjson\"",
        "log_queue_max_bytes = 4294967296",
    ]))
    .expect("a budget at the ceiling is valid");
    assert_eq!(config.log_queue_max_bytes.get(), 4_294_967_296);
}

/// A budget with no sink to size is an operator who believes delivery is on and is
/// getting nothing — the same mistake, and the same refusal, as `log_file_max_bytes`
/// without `log_file_path`.
#[test]
fn rl4_budget_without_its_sink_is_refused() {
    let err = Config::from_toml_str(&sample_with(&["siem_queue_max_bytes = 1048576"]))
        .expect_err("a queue budget with no collector to feed is refused");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                key: "siem_queue_max_bytes",
                ..
            }
        ),
        "the refusal names the key an operator can fix, got `{err}`"
    );
    assert!(
        err.to_string().contains("siem_url"),
        "and the key it depends on, got `{err}`"
    );

    // The same budget *with* its sink is the ordinary configuration, so the rule is
    // the pairing and not the key itself.
    let config = Config::from_toml_str(&sample_with(&[
        "siem_url = \"https://siem.example.org/ingest\"",
        "siem_queue_max_bytes = 1048576",
    ]))
    .expect("a budget alongside its collector is valid");
    assert_eq!(config.siem_queue_max_bytes.get(), 1_048_576);
}
