//! Slice 5's half of the blocklist behaviour group (SPEC §13 items 4 and 8): what a
//! snapshot actually removes from a rendered listing, and what its expiry does to
//! one that is already warm.
//!
//! The reload mechanics — change detection, rollback, malformed replacement, restart
//! — are slice 3's and live in `blocklist_reload.rs`. Everything here needs a
//! rendered document to look at, which is why it waits for the metadata slice.

mod common;

use std::sync::Arc;

use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, fake_origins, npm_upstream_path, sample_config,
};
use probation::policy::Digest;
use serde_json::Value;
use tempfile::TempDir;

const NAME: &str = "fixture-hashes";
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;

/// `1.0.0` advertises a SHA-512 SRI entry and `2.0.0` a SHA-256 one, which is what
/// lets one document exercise both digest-block rows. Both were published long
/// enough ago that only the blocklist can exclude them.
const SHA512_INTEGRITY: &str = "sha512-Sd9kOvynHCBatc6w4huUyC3/7x7HCRuD4f4zsULZDRfuwTcK+Fcwk3dj0bGoYQCYWpj1JTQK4tE4pN2el9Mi6Q==";
const SHA256_INTEGRITY: &str = "sha256-qNluRQ2G+9oG/QJagz5Buu7G6KX3R9h6j0M2sML1nhc=";

fn document() -> String {
    format!(
        r#"{{
            "name": "{NAME}",
            "dist-tags": {{"latest": "2.0.0"}},
            "versions": {{
                "1.0.0": {{"name": "{NAME}", "version": "1.0.0",
                    "dist": {{"tarball": "https://npm.invalid/{NAME}/-/{NAME}-1.0.0.tgz",
                              "integrity": "{SHA512_INTEGRITY}"}}}},
                "2.0.0": {{"name": "{NAME}", "version": "2.0.0",
                    "dist": {{"tarball": "https://npm.invalid/{NAME}/-/{NAME}-2.0.0.tgz",
                              "integrity": "{SHA256_INTEGRITY}"}}}}
            }},
            "time": {{
                "1.0.0": "2026-01-01T00:00:00.000Z",
                "2.0.0": "2026-02-01T00:00:00.000Z"
            }}
        }}"#
    )
}

/// The hexadecimal spelling of an SRI entry — the form a blocklist is written in.
/// Computed rather than pasted, so the block and the metadata cannot drift apart.
fn hex_of(sri: &str) -> String {
    Digest::parse_sri_entry(sri)
        .expect("the fixture's integrity entry decodes")
        .to_hex_lowercase()
}

fn blocklist(expires_at: &str, packages: &str, hashes: &str) -> String {
    format!(
        r#"{{"schema_version":1,"revision":1,"generated_at":"2020-01-01T00:00:00Z",
            "expires_at":"{expires_at}","blocked_packages":[{packages}],
            "blocked_hashes":[{hashes}]}}"#
    )
}

struct Harness {
    server: TestServer,
    clock: Arc<TestClock>,
    _dir: TempDir,
}

async fn harness(blocklist_document: &str) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let blocklist_file = dir.path().join("blocklist.json");
    std::fs::write(&blocklist_file, blocklist_document).expect("the blocklist is written");

    let mut config = sample_config();
    config.blocklist_file = blocklist_file;
    config.cooldown_seconds = ONE_DAY;

    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(NAME), FakeAnswer::Body(document()));

    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        registry as Arc<dyn probation::upstream::Transport>,
        fake_origins(),
    )
    .await;

    Harness {
        server,
        clock,
        _dir: dir,
    }
}

async fn versions(harness: &Harness) -> Vec<String> {
    let document: Value = harness.server.json(&format!("/npm/{NAME}")).await;
    document["versions"]
        .as_object()
        .expect("versions is an object")
        .keys()
        .cloned()
        .collect()
}

const FOREVER: &str = "2099-01-01T00:00:00Z";

#[tokio::test]
async fn package_wide_block() {
    let harness = harness(&blocklist(
        FOREVER,
        &format!(r#"{{"ecosystem":"npm","name":"{NAME}","version":null,"reason":"malware"}}"#),
        "",
    ))
    .await;

    assert_eq!(
        harness.server.status(&format!("/npm/{NAME}")).await,
        403,
        "a package-wide block removes every release, so nothing survives filtering"
    );
    assert_eq!(
        harness.server.status(&format!("/npm/{NAME}/1.0.0")).await,
        403
    );

    harness.server.shutdown().await;
}

#[tokio::test]
async fn version_specific_block() {
    let harness = harness(&blocklist(
        FOREVER,
        &format!(r#"{{"ecosystem":"npm","name":"{NAME}","version":"2.0.0","reason":"malware"}}"#),
        "",
    ))
    .await;

    assert_eq!(versions(&harness).await, vec!["1.0.0".to_owned()]);
    assert_eq!(
        harness.server.status(&format!("/npm/{NAME}/2.0.0")).await,
        403
    );
    assert_eq!(
        harness.server.status(&format!("/npm/{NAME}/1.0.0")).await,
        200,
        "a version block is exactly one version, not the package"
    );

    harness.server.shutdown().await;
}

#[tokio::test]
async fn sha256_block() {
    let harness = harness(&blocklist(
        FOREVER,
        "",
        &format!(
            r#"{{"algorithm":"sha256","digest":"{}","reason":"malware"}}"#,
            hex_of(SHA256_INTEGRITY)
        ),
    ))
    .await;

    assert_eq!(
        versions(&harness).await,
        vec!["1.0.0".to_owned()],
        "the release whose advertised SHA-256 is blocked is gone, and only that one"
    );

    harness.server.shutdown().await;
}

#[tokio::test]
async fn sha512_block() {
    let harness = harness(&blocklist(
        FOREVER,
        "",
        &format!(
            r#"{{"algorithm":"sha512","digest":"{}","reason":"malware"}}"#,
            hex_of(SHA512_INTEGRITY)
        ),
    ))
    .await;

    assert_eq!(
        versions(&harness).await,
        vec!["2.0.0".to_owned()],
        "a block written in hex matches metadata that only ever advertised base64"
    );

    harness.server.shutdown().await;
}

/// SPEC §8: "At expiry, both new resolutions and artifact downloads fail with `503`,
/// including cache hits. Liveness remains healthy; readiness becomes unhealthy."
///
/// The warm hit is the point. A rendered response is held in memory with no further
/// check needed to send it, so expiry has to be enforced *before* that entry is
/// consulted, not by letting it age out.
#[tokio::test]
async fn expiry_stops_delivery_including_warm_hits() {
    let harness = harness(&blocklist("2026-04-07T00:00:00Z", "", "")).await;

    assert_eq!(versions(&harness).await.len(), 2);
    let commands = harness.server.store_commands();
    assert_eq!(
        harness.server.status(&format!("/npm/{NAME}")).await,
        200,
        "the second request is the warm one"
    );
    assert_eq!(
        harness.server.store_commands(),
        commands,
        "and it is genuinely warm: it issued no storage command"
    );
    assert_eq!(harness.server.status("/health/ready").await, 200);

    // Twelve hours later the snapshot has expired. Nothing was replaced, nothing was
    // evicted, and the rendered response is still sitting in memory.
    harness.clock.advance_seconds(12 * 3600 + 1);

    assert_eq!(
        harness.server.status(&format!("/npm/{NAME}")).await,
        503,
        "a warm hit is not a way past an expired blocklist"
    );
    assert_eq!(
        harness.server.status(&format!("/npm/{NAME}/1.0.0")).await,
        503
    );
    assert_eq!(harness.server.status("/health/live").await, 200);
    harness
        .server
        .wait_for_status("/health/ready", 503, std::time::Duration::from_secs(5))
        .await;

    harness.server.shutdown().await;
}
