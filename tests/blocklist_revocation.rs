//! Slice 7's second witness: the revocation boundary.
//!
//! SPEC §9: "A request is authorized by its final successful policy check
//! immediately before response creation. Loading the immutable policy snapshot for
//! that check is the ordering point: a request loading it after publication of an
//! update must see the update."
//!
//! Two of these tests land a blocklist update *inside* one request rather than
//! between two, and neither uses a sleep to do it. The download case parks the
//! transport half way through the transfer; the cached case uses a clock that
//! publishes on its first reading, which `artifacts::serve_artifact` takes after it
//! has already loaded the snapshot its first check uses. In both cases the first
//! check provably ran against the old snapshot and the final check is the only thing
//! that can refuse.

mod common;

use std::sync::Arc;

use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, TriggerClock, artifact_path,
    config_with_open_blocklist, npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
    publish_blocklist, snapshot_with,
};
use probation::clock::Clock;
use probation::policy::Ecosystem;
use probation::store::rows::ReferenceId;
use serde_json::{Map, Value, json};
use tempfile::TempDir;

const WIDGET: &str = "fixture-widget";
const FILENAME: &str = "fixture-widget-1.0.0.tgz";
const VERSION: &str = "1.0.0";
const PUBLISHED: &str = "2026-04-01T00:00:00Z";
const NOW: &str = "2026-04-06T12:00:00Z";

/// `tests/fixtures/artifacts/harmless-widget-1.0.0.tgz`, as `sha256sum` and
/// `openssl dgst -sha512 -binary | base64` report it.
const BODY_SHA256: &str = "029830248baf17af5d9a9e23d3e7054a8860882d1cdc06bbbb1549056d347acb";
const BODY_SRI: &str = "sha512-cuZOnpQDIYuoiW0VpldsZLmUaQ/eZwGjVHeTZQoXRdTeBMh5mj1XyHMlEqTzPjYFW3AxzuKZi8cb4GZ2QP4G7g==";

/// A second, different artifact — `tests/fixtures/artifacts/tampered-widget-1.0.0.tgz`
/// under another version — so a listing can lose one version and keep another.
const OTHER_VERSION: &str = "2.0.0";
const OTHER_FILENAME: &str = "fixture-widget-2.0.0.tgz";
const OTHER_SRI: &str = "sha512-hl/BywthAR9bBzuAS/JOKoCECO9fgaHl2bce2C43qs4r89tbyU9hMv02qnBf4Vn5193+NTmwCSt1RBlrihU54Q==";

/// `metadata_ttl_seconds` in `config.sample.toml`, which every harness here uses.
const METADATA_TTL_SECONDS: i64 = 300;

fn body() -> String {
    common::fixture("artifacts/harmless-widget-1.0.0.tgz")
}

/// One version, advertising SHA-512 only — which is what npm publishes.
fn document() -> String {
    document_of(&[(VERSION, FILENAME, BODY_SRI)])
}

/// A document advertising exactly the versions given, so a test can take one away the
/// way an unpublish or a yank does.
fn document_of(entries: &[(&str, &str, &str)]) -> String {
    let mut versions = Map::new();
    let mut time = Map::new();
    for (version, filename, integrity) in entries {
        versions.insert(
            (*version).to_owned(),
            json!({
                "name": WIDGET,
                "version": version,
                "dist": {"tarball": npm_tarball_url(WIDGET, filename), "integrity": integrity},
            }),
        );
        time.insert((*version).to_owned(), json!(PUBLISHED));
    }

    let latest = entries.last().map_or(VERSION, |(version, _, _)| version);
    json!({
        "name": WIDGET,
        "dist-tags": {"latest": latest},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

fn blocklist(revision: u64, packages: &str, hashes: &str) -> String {
    snapshot_with(
        revision,
        "2026-04-05T00:00:00Z",
        "2099-01-01T00:00:00Z",
        packages,
        hashes,
    )
}

fn blocked_package() -> String {
    format!(r#"{{"ecosystem":"npm","name":"{WIDGET}","version":null,"reason":"known malware"}}"#)
}

fn blocked_sha256(digest: &str) -> String {
    format!(r#"{{"algorithm":"sha256","digest":"{digest}","reason":"known malicious artifact"}}"#)
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    data_dir: std::path::PathBuf,
    _dir: TempDir,
}

impl Harness {
    async fn artifact_path(&self) -> String {
        let document = self.server.json(&format!("/npm/{WIDGET}")).await;
        artifact_path(&document, VERSION)
    }

    async fn reference(&self, path: &str) -> probation::store::rows::ReferenceRow {
        let hex = path.split('/').nth(3).expect("a reference id");
        self.server
            .running()
            .app()
            .store()
            .get_reference(ReferenceId::parse_hex(hex).expect("hexadecimal"))
            .await
            .expect("the reference query")
            .expect("the reference is committed")
    }

    fn content_files(&self) -> usize {
        let objects = self.data_dir.join("content").join("objects");
        std::fs::read_dir(&objects)
            .map(|fan_out| {
                fan_out
                    .flatten()
                    .filter_map(|directory| std::fs::read_dir(directory.path()).ok())
                    .map(|entries| entries.count())
                    .sum()
            })
            .unwrap_or(0)
    }

    fn artifact_calls(&self) -> usize {
        self.registry
            .calls()
            .iter()
            .filter(|url| url.path() == npm_artifact_upstream_path(WIDGET, FILENAME))
            .count()
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

async fn harness(clock: Arc<dyn Clock>, artifact: FakeAnswer) -> Harness {
    harness_with_artifacts(clock, document(), &[(FILENAME, artifact)]).await
}

async fn harness_with_artifacts(
    clock: Arc<dyn Clock>,
    document: String,
    artifacts: &[(&str, FakeAnswer)],
) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = config_with_open_blocklist(dir.path());
    let data_dir = dir.path().join("data");

    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(WIDGET), FakeAnswer::Body(document));
    for (filename, answer) in artifacts {
        registry.answer(
            &npm_artifact_upstream_path(WIDGET, filename),
            answer.clone(),
        );
    }

    let server =
        TestServer::start_in_with_registry(&data_dir, config, clock, Arc::clone(&registry)).await;

    Harness {
        server,
        registry,
        data_dir,
        _dir: dir,
    }
}

/// The update arrives while the bytes are still being transferred. The download runs
/// to completion — SPEC §9 wants its digests pinned either way — and the final check
/// is what refuses to hand any of it over.
#[tokio::test]
async fn blocklist_update_during_download_denies_at_the_final_check() {
    let gate = Gate::new();
    let whole = body();
    let (head, tail) = whole.split_at(whole.len() / 2);
    let harness = harness(
        TestClock::at_rfc3339(NOW).shared(),
        FakeAnswer::Gated {
            head: head.to_owned(),
            tail: tail.to_owned(),
            gate: Arc::clone(&gate),
        },
    )
    .await;
    let path = harness.artifact_path().await;

    let url = harness.server.url(&path);
    let request = tokio::spawn(async move {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("a test client")
            .get(url)
            .send()
            .await
            .expect("the request completes")
    });

    // The transfer is in flight and half arrived. Only now does the block appear.
    gate.wait_until_reached().await;
    publish_blocklist(
        &harness.server,
        &blocklist(2, &blocked_package(), ""),
        common::parse_rfc3339(NOW),
    );
    gate.release();

    let response = request.await.expect("the request task");
    assert_eq!(
        response.status().as_u16(),
        403,
        "the request started under a policy that allowed it and ends under one that \
         does not; the final check is what decides"
    );
    assert_eq!(common::body_error(response).await, "BLOCKED");

    let row = harness.reference(&path).await;
    assert_eq!(
        row.pinned_sha256.map(hex::encode).as_deref(),
        Some(BODY_SHA256),
        "the completed download still pinned what it computed (SPEC §9)"
    );
    assert_eq!(row.content_key, None, "and published nothing");
    assert_eq!(harness.content_files(), 0);
    harness.shutdown().await;
}

/// The same window exists with no download in flight at all: a warm request checks
/// policy, opens the cached file, and checks again. An update landing in between is
/// refused by the second check.
///
/// This is the test that isolates the final check. Two falsification probes — one
/// making the final check reuse the snapshot the first check loaded, one making it
/// ignore the pinned digests — leave every other test in this file green and fail
/// this one.
#[tokio::test]
async fn blocklist_update_during_revalidation_of_cached_content_denies() {
    let clock = TriggerClock::at_rfc3339(NOW);
    let harness = harness(clock.shared(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    assert_eq!(
        harness.server.status(&path).await,
        200,
        "the content is now cached"
    );
    assert_eq!(harness.artifact_calls(), 1);

    // Fires on the next clock reading, which `serve_artifact` takes *after* loading
    // the snapshot its first check uses. The block names the artifact's SHA-256,
    // which upstream never advertised, so the final check has to consult the digests
    // this instance pinned as well as reload the snapshot.
    clock.arm(
        &harness.server,
        &blocklist(2, "", &blocked_sha256(BODY_SHA256)),
    );

    let response = harness.server.get(&path).await;
    assert!(
        clock.fired(),
        "the update really was published inside the request"
    );
    assert_eq!(
        response.status().as_u16(),
        403,
        "cached, verified, previously allowed bytes are still refused"
    );
    assert_eq!(common::body_error(response).await, "BLOCKED");
    assert_eq!(
        harness.artifact_calls(),
        1,
        "and this ran on the cached branch: no second upstream transfer"
    );
    assert_eq!(
        harness.content_files(),
        1,
        "the bytes are still on disk; the refusal is policy, not absence"
    );
    harness.shutdown().await;
}

/// SPEC §2: "A cached artifact becomes blocked: refuse subsequent downloads,
/// including requests using previously issued URLs."
///
/// The block names the artifact's SHA-256, which upstream metadata never advertised —
/// so the only thing that can connect it to this reference is the digest pinned by
/// the download that already happened. The refusal here is reached by the first,
/// locally conclusive check; `blocklist_update_during_revalidation_of_cached_content_denies`
/// is what isolates the final one.
#[tokio::test]
async fn previously_issued_url_is_refused_after_a_block() {
    let harness = harness(
        TestClock::at_rfc3339(NOW).shared(),
        FakeAnswer::Body(body()),
    )
    .await;
    // The URL a client was given while the package was still eligible.
    let issued = harness.artifact_path().await;
    assert_eq!(harness.server.status(&issued).await, 200);
    assert_eq!(
        harness.content_files(),
        1,
        "the bytes are cached, so what follows is not an absence"
    );

    publish_blocklist(
        &harness.server,
        &blocklist(2, "", &blocked_sha256(BODY_SHA256)),
        common::parse_rfc3339(NOW),
    );

    let response = harness.server.get(&issued).await;
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(common::body_error(response).await, "BLOCKED");
    assert_eq!(
        harness.server.status(&issued).await,
        403,
        "and it stays refused: the URL is a lookup key, never an authorization token"
    );
    assert_eq!(
        harness.artifact_calls(),
        1,
        "both refusals were decided on the cached branch, with no second transfer"
    );
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// SPEC.md:230 — membership in a sufficiently fresh project snapshot
// ---------------------------------------------------------------------------

/// SPEC §9: "A removed reference is unavailable even if its bytes remain cached."
///
/// Upstream removal is a different signal from this firewall's blocklist, and the
/// reference id is a deterministic hash of public metadata rather than an
/// authorization token — so anyone who saw the metadata before the removal can
/// compute the URL. Membership in a fresh snapshot is the only thing that refuses
/// them.
#[tokio::test]
async fn a_reference_removed_upstream_is_unavailable_even_though_its_bytes_are_cached() {
    let clock = TestClock::at_rfc3339(NOW);
    let harness = harness(clock.shared(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    assert_eq!(harness.server.status(&path).await, 200);
    assert_eq!(harness.content_files(), 1, "the bytes are cached");

    // Upstream unpublishes the version; the project itself stays.
    harness.registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(document_of(&[(OTHER_VERSION, OTHER_FILENAME, OTHER_SRI)])),
    );
    clock.advance_seconds(METADATA_TTL_SECONDS + 1);

    assert_eq!(
        harness.server.status(&path).await,
        404,
        "a reference no upstream snapshot advertises any more is unavailable"
    );
    assert_eq!(
        harness.content_files(),
        1,
        "and its bytes are still on disk, so this is a membership refusal rather than \
         an absence"
    );
    harness.shutdown().await;
}

/// SPEC §9's last revalidation line: "revalidate project membership if metadata
/// expired while downloading". The removal lands while the transfer is in flight, so
/// only a check made *after* it can see it.
#[tokio::test]
async fn membership_is_revalidated_when_metadata_expired_during_the_download() {
    let gate = Gate::new();
    let whole = body();
    let (head, tail) = whole.split_at(whole.len() / 2);
    let clock = TestClock::at_rfc3339(NOW);
    let harness = harness(
        clock.shared(),
        FakeAnswer::Gated {
            head: head.to_owned(),
            tail: tail.to_owned(),
            gate: Arc::clone(&gate),
        },
    )
    .await;
    let path = harness.artifact_path().await;

    let url = harness.server.url(&path);
    let request = tokio::spawn(async move {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("a test client")
            .get(url)
            .send()
            .await
            .expect("the request completes")
    });

    // Mid-transfer: the version is withdrawn and the snapshot this request checked
    // membership against goes stale.
    gate.wait_until_reached().await;
    harness.registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(document_of(&[(OTHER_VERSION, OTHER_FILENAME, OTHER_SRI)])),
    );
    clock.advance_seconds(METADATA_TTL_SECONDS + 1);
    gate.release();

    let response = request.await.expect("the request task");
    assert_eq!(
        response.status().as_u16(),
        404,
        "membership is confirmed again after the download, not only before it"
    );
    harness.shutdown().await;
}

/// SPEC §9: "If a computed digest reveals a block not visible in upstream metadata,
/// invalidate that project's filtered metadata. The next resolution hides the
/// affected artifact."
///
/// The listing is what this asserts on, so it belongs beside the other revocation
/// tests rather than in slice 5's `npm_metadata.rs`: its subject is a block reachable
/// only through a digest this instance computed, which is this slice's.
#[tokio::test]
async fn a_computed_digest_block_hides_the_version_from_the_next_metadata_listing() {
    let harness = harness_with_artifacts(
        TestClock::at_rfc3339(NOW).shared(),
        document_of(&[
            (VERSION, FILENAME, BODY_SRI),
            (OTHER_VERSION, OTHER_FILENAME, OTHER_SRI),
        ]),
        &[
            (FILENAME, FakeAnswer::Body(body())),
            (
                OTHER_FILENAME,
                FakeAnswer::Body(common::fixture("artifacts/tampered-widget-1.0.0.tgz")),
            ),
        ],
    )
    .await;

    let listing = harness.server.json(&format!("/npm/{WIDGET}")).await;
    assert!(listing["versions"][VERSION].is_object());
    assert!(listing["versions"][OTHER_VERSION].is_object());

    // One download, which is what teaches this instance the artifact's SHA-256.
    let path = artifact_path(&listing, VERSION);
    assert_eq!(harness.server.status(&path).await, 200);

    publish_blocklist(
        &harness.server,
        &blocklist(2, "", &blocked_sha256(BODY_SHA256)),
        common::parse_rfc3339(NOW),
    );

    let listing = harness.server.json(&format!("/npm/{WIDGET}")).await;
    assert!(
        listing["versions"][VERSION].is_null(),
        "the next resolution hides the version its computed digest revealed a block \
         for: {listing}"
    );
    assert!(
        listing["versions"][OTHER_VERSION].is_object(),
        "and hides nothing else"
    );
    harness.shutdown().await;
}

/// SPEC §9: "Support `GET`, `HEAD`, and a single byte range on a fully verified
/// artifact", and SPEC §13 item 7's "HEAD/range requests obey the same policy".
///
/// Not named in the slice witness, but named in the Gate 3 test plan and required by
/// the slice outcome, so it lands here rather than becoming an unowned obligation.
#[tokio::test]
async fn head_and_range_obey_the_same_policy() {
    let harness = harness(
        TestClock::at_rfc3339(NOW).shared(),
        FakeAnswer::Body(body()),
    )
    .await;
    let path = harness.artifact_path().await;
    let whole = body();

    let head = harness.server.head(&path).await;
    assert_eq!(head.status().as_u16(), 200);
    assert_eq!(
        head.headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some(whole.len().to_string().as_str()),
        "HEAD reports the length of the entity it would have sent"
    );
    assert!(head.text().await.expect("a body").is_empty());
    assert_eq!(
        harness.artifact_calls(),
        1,
        "and a cold HEAD really did verify the bytes rather than guess at them"
    );

    let ranged = harness
        .server
        .get_with_headers(&path, &[("range", "bytes=0-9")])
        .await;
    assert_eq!(ranged.status().as_u16(), 206);
    assert_eq!(
        ranged
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some(format!("bytes 0-9/{}", whole.len()).as_str())
    );
    assert_eq!(ranged.text().await.expect("a body"), whole[..10]);

    let unsatisfiable = harness
        .server
        .get_with_headers(&path, &[("range", "bytes=99999-100000")])
        .await;
    assert_eq!(unsatisfiable.status().as_u16(), 416);

    // Several ranges are ignored and the complete verified body is returned (SPEC §9).
    let several = harness
        .server
        .get_with_headers(&path, &[("range", "bytes=0-1,4-5")])
        .await;
    assert_eq!(several.status().as_u16(), 200);
    assert_eq!(several.text().await.expect("a body"), whole);

    publish_blocklist(
        &harness.server,
        &blocklist(2, &blocked_package(), ""),
        common::parse_rfc3339(NOW),
    );

    assert_eq!(
        harness.server.head(&path).await.status().as_u16(),
        403,
        "HEAD obeys the same policy as GET"
    );
    assert_eq!(
        harness
            .server
            .get_with_headers(&path, &[("range", "bytes=0-9")])
            .await
            .status()
            .as_u16(),
        403,
        "and so does a range request, on bytes that are still cached"
    );
    harness.shutdown().await;
}

/// SPEC §13 item 4: "newly computed SHA-256 detecting a block absent from npm's
/// advertised SHA-512".
///
/// Upstream advertises SHA-512 and nothing else, and the blocklist names a SHA-256 —
/// so until these bytes are downloaded and hashed, nothing in the system can connect
/// the two.
#[tokio::test]
async fn computed_sha256_block_absent_from_npm_sha512_metadata() {
    let harness = harness(
        TestClock::at_rfc3339(NOW).shared(),
        FakeAnswer::Body(body()),
    )
    .await;
    let path = harness.artifact_path().await;

    let row = harness.reference(&path).await;
    assert!(
        row.reference
            .expected
            .iter()
            .all(|digest| digest.algorithm != probation::policy::HashAlgorithm::Sha256),
        "upstream metadata advertises no SHA-256 at all: {:?}",
        row.reference.expected
    );

    publish_blocklist(
        &harness.server,
        &blocklist(2, "", &blocked_sha256(BODY_SHA256)),
        common::parse_rfc3339(NOW),
    );

    let before = harness
        .server
        .running()
        .app()
        .store()
        .get_project(Ecosystem::Npm, WIDGET)
        .await
        .expect("the project query")
        .expect("the project is stored")
        .digest_generation;

    let response = harness.server.get(&path).await;
    assert_eq!(
        response.status().as_u16(),
        403,
        "the block is only reachable through a digest this instance computed itself"
    );
    assert_eq!(common::body_error(response).await, "BLOCKED");

    let row = harness.reference(&path).await;
    assert_eq!(
        row.pinned_sha256.map(hex::encode).as_deref(),
        Some(BODY_SHA256)
    );
    assert_eq!(
        harness.content_files(),
        0,
        "the blocked bytes are discarded"
    );

    let after = harness
        .server
        .running()
        .app()
        .store()
        .get_project(Ecosystem::Npm, WIDGET)
        .await
        .expect("the project query")
        .expect("the project is stored")
        .digest_generation;
    assert!(
        after > before,
        "SPEC §9: a computed digest revealing a block invalidates that project's \
         filtered metadata ({before} to {after})"
    );
    harness.shutdown().await;
}
