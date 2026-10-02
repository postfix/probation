//! Slice 7's witness: an artifact is delivered only after a complete verified
//! download, and nothing that failed verification ever becomes a cache hit.
//!
//! Everything here runs against an in-process `FakeRegistry` and a clock the test
//! moves by hand, so a run reaches no socket and depends on no wall clock.
//!
//! The digest constants below were taken from the fixture files themselves with
//! `sha256sum`, `sha512sum`, `sha1sum` and `openssl dgst -sha512 -binary | base64`.
//! They are not an independent restatement of what the code computes: the download
//! path computes them, and `pin_established_without_a_strong_advertised_digest`
//! asserts the pinned value equals the constant, so a fixture edited without
//! updating these fails loudly rather than quietly agreeing with itself.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, artifact_path,
    config_with_open_blocklist, npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
    publish_blocklist, snapshot_with,
};
use probation::store::rows::ReferenceId;
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WIDGET: &str = "fixture-widget";
const FILENAME: &str = "fixture-widget-1.0.0.tgz";
const VERSION: &str = "1.0.0";

/// Five days before [`NOW`], so the one-day cooldown is spent.
const PUBLISHED: &str = "2026-04-01T00:00:00Z";
const NOW: &str = "2026-04-06T12:00:00Z";

/// `tests/fixtures/artifacts/harmless-widget-1.0.0.tgz`.
const BODY_SHA256: &str = "029830248baf17af5d9a9e23d3e7054a8860882d1cdc06bbbb1549056d347acb";
const BODY_SHA512: &str = "72e64e9e9403218ba8896d15a6576c64b994690fde6701a3547793650a1745d4de04c8799a3d57c8732512a4f33e36055b7031cee2998bc71be0667640fe06ee";
const BODY_SHA1: &str = "06e87889ae32c865ca8a744b780e57253f0b0a47";
const BODY_SRI: &str = "sha512-cuZOnpQDIYuoiW0VpldsZLmUaQ/eZwGjVHeTZQoXRdTeBMh5mj1XyHMlEqTzPjYFW3AxzuKZi8cb4GZ2QP4G7g==";

/// `tests/fixtures/artifacts/tampered-widget-1.0.0.tgz` — the same reference, other
/// bytes.
const TAMPERED_SHA256: &str = "f753ce595d22fe1a96c17aa0d93e1fc1bfcb1d7bfa756b23d96f67ff31ffdc3b";
const TAMPERED_SRI: &str = "sha512-hl/BywthAR9bBzuAS/JOKoCECO9fgaHl2bce2C43qs4r89tbyU9hMv02qnBf4Vn5193+NTmwCSt1RBlrihU54Q==";

fn body() -> String {
    common::fixture("artifacts/harmless-widget-1.0.0.tgz")
}

fn tampered() -> String {
    common::fixture("artifacts/tampered-widget-1.0.0.tgz")
}

/// One npm document advertising one version, with whatever integrity the test wants
/// behind it.
fn document(dist: Value) -> String {
    let mut versions = Map::new();
    versions.insert(
        VERSION.to_owned(),
        json!({"name": WIDGET, "version": VERSION, "dist": dist}),
    );
    let mut time = Map::new();
    time.insert(VERSION.to_owned(), json!(PUBLISHED));

    json!({
        "name": WIDGET,
        "dist-tags": {"latest": VERSION},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

fn strong_integrity() -> Value {
    json!({"tarball": npm_tarball_url(WIDGET, FILENAME), "integrity": BODY_SRI})
}

/// An old release carrying only npm's legacy hexadecimal SHA-1.
fn legacy_shasum_only() -> Value {
    json!({"tarball": npm_tarball_url(WIDGET, FILENAME), "shasum": BODY_SHA1})
}

/// No integrity at all, which is what makes the permanent pins the only thing
/// standing between this reference and different bytes.
fn no_advertised_digest() -> Value {
    json!({"tarball": npm_tarball_url(WIDGET, FILENAME)})
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    data_dir: std::path::PathBuf,
    _dir: TempDir,
}

impl Harness {
    /// The rendered document's own artifact URL. Going through the metadata route is
    /// the point: this is the URL a client is actually given.
    async fn artifact_path(&self) -> String {
        let document = self.server.json(&format!("/npm/{WIDGET}")).await;
        artifact_path(&document, VERSION)
    }

    fn reference_id(&self, path: &str) -> ReferenceId {
        let hex = path
            .split('/')
            .nth(3)
            .unwrap_or_else(|| panic!("an artifact path has a reference id: {path}"));
        ReferenceId::parse_hex(hex).expect("the reference id is hexadecimal")
    }

    async fn reference(&self, path: &str) -> probation::store::rows::ReferenceRow {
        self.server
            .running()
            .app()
            .store()
            .get_reference(self.reference_id(path))
            .await
            .expect("the reference query")
            .expect("the reference was committed before its URL was advertised")
    }

    fn content_files(&self) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let objects = self.data_dir.join("content").join("objects");
        let Ok(fan_out) = std::fs::read_dir(&objects) else {
            return found;
        };
        for directory in fan_out.flatten() {
            if let Ok(entries) = std::fs::read_dir(directory.path()) {
                found.extend(entries.flatten().map(|entry| entry.path()));
            }
        }
        found
    }

    fn temp_files(&self) -> usize {
        std::fs::read_dir(self.data_dir.join("content").join("tmp"))
            .map(|entries| entries.count())
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

async fn harness(dist: Value, artifact: FakeAnswer) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = config_with_open_blocklist(dir.path());
    let data_dir = dir.path().join("data");

    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path(WIDGET), FakeAnswer::Body(document(dist)));
    registry.answer(&npm_artifact_upstream_path(WIDGET, FILENAME), artifact);

    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_in_with_registry(
        &data_dir,
        config,
        clock.shared(),
        Arc::clone(&registry),
    )
    .await;

    Harness {
        server,
        registry,
        clock,
        data_dir,
        _dir: dir,
    }
}

/// A blocklist naming `hashes`, valid at [`NOW`].
fn blocklist(revision: u64, packages: &str, hashes: &str) -> String {
    snapshot_with(
        revision,
        "2026-04-05T00:00:00Z",
        "2099-01-01T00:00:00Z",
        packages,
        hashes,
    )
}

fn blocked_digest(algorithm: &str, digest: &str) -> String {
    format!(
        r#"{{"algorithm":"{algorithm}","digest":"{digest}","reason":"known malicious artifact"}}"#
    )
}

// ---------------------------------------------------------------------------
// SPEC §13 item 6: nothing unverified reaches a client, and nothing unverified is
// cached
// ---------------------------------------------------------------------------

/// The failure this slice exists to prevent: forwarding bytes as they arrive.
///
/// The transport delivers the first half of the artifact and then parks. At that
/// moment the request is genuinely in flight with real upstream bytes in hand — and
/// the client socket must have received **nothing at all**, not merely no body. The
/// request is written to a raw `TcpStream` so this asserts on what crossed the
/// socket rather than on what a client library chose to surface.
#[tokio::test]
async fn zero_body_bytes_before_cold_verification_completes() {
    let gate = Gate::new();
    let whole = body();
    let (head, tail) = whole.split_at(whole.len() / 2);
    let harness = harness(
        strong_integrity(),
        FakeAnswer::Gated {
            head: head.to_owned(),
            tail: tail.to_owned(),
            gate: Arc::clone(&gate),
        },
    )
    .await;
    let path = harness.artifact_path().await;

    let addr = harness.server.running().local_addr;
    let mut socket = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the server accepts a connection");
    socket
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("the request is written");

    gate.wait_until_reached().await;
    let mut early = [0u8; 1];
    let peeked = tokio::time::timeout(Duration::from_millis(300), socket.read(&mut early)).await;
    assert!(
        peeked.is_err(),
        "half the artifact has arrived from upstream and the client already received \
         {peeked:?}; nothing may cross the socket before verification completes"
    );
    assert!(
        harness.content_files().is_empty(),
        "and nothing is in the content cache yet either"
    );

    gate.release();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response))
        .await
        .expect("the response arrives once verification completes")
        .expect("the response is read");
    let response = String::from_utf8_lossy(&response).into_owned();

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the verified artifact is served once, whole: {response}"
    );
    assert!(
        response.ends_with(&whole),
        "and the body is the artifact itself"
    );
    harness.shutdown().await;
}

/// A body that stops early is a truncated download. Upstream declared a length; the
/// stream ended before it.
///
/// The reference advertises **no** digest, deliberately. With a strong SRI in the
/// document this test passes whether or not the declared length is ever checked — the
/// digest of half a file does not match either — and a falsification probe that
/// disabled the length check left it green. With nothing advertised, the declared
/// length is the only thing that can notice.
#[tokio::test]
async fn truncated_download_never_becomes_a_cache_hit() {
    let whole = body();
    let harness = harness(
        no_advertised_digest(),
        FakeAnswer::Truncated {
            declared_length: whole.len() as u64,
            body: whole[..whole.len() / 2].to_owned(),
        },
    )
    .await;
    let path = harness.artifact_path().await;

    assert_eq!(harness.server.status(&path).await, 502);

    let row = harness.reference(&path).await;
    assert_eq!(row.content_key, None, "no mapping was committed");
    assert_eq!(
        row.pinned_sha256, None,
        "SPEC §9: an incomplete download never establishes a pin"
    );
    assert!(harness.content_files().is_empty());
    assert_eq!(harness.temp_files(), 0, "and its temporary file is gone");

    assert_eq!(
        harness.server.status(&path).await,
        502,
        "a second request is refused too, rather than finding the first attempt cached"
    );
    assert_eq!(
        harness.artifact_calls(),
        2,
        "both attempts really went upstream; neither was served from a cache"
    );
    harness.shutdown().await;
}

/// The bytes do not hash to what upstream advertised.
#[tokio::test]
async fn integrity_failure_never_becomes_a_cache_hit() {
    // The document advertises the *tampered* fixture's SRI; the registry serves the
    // harmless one.
    let harness = harness(
        json!({"tarball": npm_tarball_url(WIDGET, FILENAME), "integrity": TAMPERED_SRI}),
        FakeAnswer::Body(body()),
    )
    .await;
    let path = harness.artifact_path().await;

    assert_eq!(harness.server.status(&path).await, 502);
    let error = common::body_error(harness.server.get(&path).await).await;
    assert_eq!(error, "INTEGRITY_MISMATCH");

    let row = harness.reference(&path).await;
    assert_eq!(row.content_key, None);
    assert_eq!(
        row.pinned_sha256, None,
        "SPEC §9: an upstream-integrity-failing download never establishes a pin"
    );
    assert!(harness.content_files().is_empty());
    assert_eq!(harness.temp_files(), 0);
    harness.shutdown().await;
}

/// The bytes verify against upstream and are then denied by policy. SPEC §9 is
/// explicit that both halves hold at once: the computed digests are persisted, and
/// the bytes are not.
#[tokio::test]
async fn blocked_bytes_never_become_a_cache_hit() {
    let harness = harness(strong_integrity(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    publish_blocklist(
        &harness.server,
        &blocklist(2, "", &blocked_digest("sha256", BODY_SHA256)),
        common::parse_rfc3339(NOW),
    );

    assert_eq!(harness.server.status(&path).await, 403);

    let row = harness.reference(&path).await;
    assert_eq!(
        row.pinned_sha256.map(hex::encode).as_deref(),
        Some(BODY_SHA256),
        "SPEC §9: persist computed digests, even when policy now blocks them"
    );
    assert_eq!(row.content_key, None, "but the bytes are not published");
    assert!(harness.content_files().is_empty());
    assert_eq!(harness.temp_files(), 0);

    assert_eq!(
        harness.server.status(&path).await,
        403,
        "and the next request is refused from the pins, not served from a cache"
    );
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// SPEC §13 item 11: pins are permanent (STATE-01)
// ---------------------------------------------------------------------------

/// Eviction removes bytes and their mapping. It does not remove what this reference
/// has been proven to mean, and a refetch has to agree with it.
#[tokio::test]
async fn eviction_and_refetch_preserve_pins() {
    let harness = harness(strong_integrity(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    assert_eq!(harness.server.status(&path).await, 200);
    let pinned = harness.reference(&path).await;
    assert_eq!(
        pinned.pinned_sha256.map(hex::encode).as_deref(),
        Some(BODY_SHA256)
    );
    assert_eq!(
        pinned.pinned_sha512.map(hex::encode).as_deref(),
        Some(BODY_SHA512)
    );
    assert!(pinned.content_key.is_some());

    // A metadata refresh rewrites the whole reference row. SPEC §9 keeps the pins
    // across eviction, which means they have to survive being rewritten too.
    harness.clock.advance_seconds(600);
    let _ = harness.server.json(&format!("/npm/{WIDGET}")).await;
    let refreshed = harness.reference(&path).await;
    assert_eq!(
        refreshed.pinned_sha256, pinned.pinned_sha256,
        "an upstream metadata refresh must not erase what this reference was proven \
         to mean"
    );
    assert_eq!(refreshed.content_key, pinned.content_key);

    // Eviction, as the cache performs it: the bytes go.
    for file in harness.content_files() {
        std::fs::remove_file(&file).expect("the evicted file is removed");
    }

    let response = harness.server.get(&path).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.text().await.expect("a body"),
        body(),
        "the refetched bytes are served"
    );
    assert_eq!(
        harness.artifact_calls(),
        2,
        "the eviction really did force a second transfer"
    );

    let refetched = harness.reference(&path).await;
    assert_eq!(
        refetched.pinned_sha256, pinned.pinned_sha256,
        "the pin survived the eviction of the bytes it describes"
    );
    assert_eq!(refetched.pinned_sha512, pinned.pinned_sha512);
    assert_eq!(refetched.pinned_size, pinned.pinned_size);
    harness.shutdown().await;
}

/// STATE-01's whole point: a reference without a strong upstream digest could
/// otherwise acquire different bytes after an eviction. The pins are what refuse
/// them, and the original pins are what stay.
#[tokio::test]
async fn changed_bytes_for_the_same_reference_are_refused_with_502() {
    let harness = harness(no_advertised_digest(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    assert_eq!(harness.server.status(&path).await, 200);
    let pinned = harness.reference(&path).await;
    assert_eq!(
        pinned.pinned_sha256.map(hex::encode).as_deref(),
        Some(BODY_SHA256)
    );
    assert!(
        pinned.reference.expected.is_empty(),
        "upstream advertised nothing, so only the pins can refuse the new bytes"
    );

    for file in harness.content_files() {
        std::fs::remove_file(&file).expect("the evicted file is removed");
    }
    // The same reference, the same URL, other bytes behind it.
    harness.registry.answer(
        &npm_artifact_upstream_path(WIDGET, FILENAME),
        FakeAnswer::Body(tampered()),
    );

    let response = harness.server.get(&path).await;
    assert_eq!(response.status().as_u16(), 502);
    assert_eq!(
        common::body_error(response).await,
        "INTEGRITY_MISMATCH",
        "SPEC §9: a mismatch is 502 INTEGRITY_MISMATCH"
    );

    let after = harness.reference(&path).await;
    assert_eq!(
        after.pinned_sha256, pinned.pinned_sha256,
        "the original pins are retained, never replaced by the new bytes"
    );
    assert_ne!(
        after.pinned_sha256.map(hex::encode).as_deref(),
        Some(TAMPERED_SHA256)
    );
    assert_eq!(after.content_key, None);
    assert!(
        harness.content_files().is_empty(),
        "and the refused bytes were discarded"
    );
    assert_eq!(harness.temp_files(), 0);
    harness.shutdown().await;
}

/// SPEC §9: "Compute the archive SHA-256 even when npm supplies only SHA-512 or
/// legacy SHA-1." The fixture advertises only `dist.shasum`.
#[tokio::test]
async fn pin_established_without_a_strong_advertised_digest() {
    let harness = harness(legacy_shasum_only(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    assert_eq!(harness.server.status(&path).await, 200);

    let row = harness.reference(&path).await;
    assert_eq!(
        row.reference.expected.len(),
        1,
        "upstream advertised exactly one digest, and it is the legacy SHA-1"
    );
    assert_eq!(row.reference.expected[0].to_hex_lowercase(), BODY_SHA1);
    assert_eq!(
        row.pinned_sha256.map(hex::encode).as_deref(),
        Some(BODY_SHA256),
        "a SHA-256 was computed and pinned although upstream never advertised one"
    );
    assert_eq!(
        row.pinned_sha512.map(hex::encode).as_deref(),
        Some(BODY_SHA512)
    );
    assert_eq!(row.pinned_size, Some(body().len() as u64));
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// PERF-01: a locally conclusive denial never waits on upstream
// ---------------------------------------------------------------------------

/// The reference is known and its bytes are not cached, so a denial that needed
/// upstream would have to fail. With every upstream call failing, the block still
/// answers `403` — and the transport records that nothing even tried.
#[tokio::test]
async fn local_block_denies_with_upstream_unreachable() {
    let harness = harness(strong_integrity(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    publish_blocklist(
        &harness.server,
        &blocklist(
            2,
            &format!(
                r#"{{"ecosystem":"npm","name":"{WIDGET}","version":null,"reason":"malware"}}"#
            ),
            "",
        ),
        common::parse_rfc3339(NOW),
    );
    harness.registry.go_offline();
    let calls_before = harness.registry.calls().len();

    let response = harness.server.get(&path).await;
    assert_eq!(
        response.status().as_u16(),
        403,
        "a locally conclusive block answers without upstream"
    );
    assert_eq!(common::body_error(response).await, "BLOCKED");
    assert_eq!(
        harness.registry.calls().len(),
        calls_before,
        "and it reached upstream not once — an unreachable registry cannot even be \
         observed from this path"
    );
    harness.shutdown().await;
}

/// The slice 4 carry-forward: an assertion about a hostile path must bypass
/// `reqwest`, which decodes `%2E` client-side and would silently test nothing.
///
/// A filename is part of what a reference *is*, so a request naming a different one —
/// however it is spelled — is not that reference.
#[tokio::test]
async fn a_dot_dot_filename_never_serves_another_reference() {
    let harness = harness(strong_integrity(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;
    assert_eq!(harness.server.status(&path).await, 200);

    let id = path.split('/').nth(3).expect("a reference id").to_owned();
    for hostile in [
        format!("/npm/artifacts/{id}/%2E%2E"),
        format!("/npm/artifacts/{id}/..%2F{FILENAME}"),
        format!("/npm/artifacts/{id}/other-name.tgz"),
    ] {
        let status = harness.server.raw_get_status(&hostile).await;
        assert_eq!(
            status, 404,
            "{hostile} names no reference this instance has committed"
        );
    }
    harness.shutdown().await;
}

/// SPEC §9 makes *every* artifact request confirm that its reference is still
/// advertised, warm ones included, and SPEC §12 gives a warm artifact a 5 ms budget
/// over an unfiltered local-file server. Before slice 13 those two were in direct
/// conflict: the membership check re-parsed the whole stored project document on
/// every call, so the budget was spent on JSON a previous request had already read.
///
/// The advertised set is now parsed once per project snapshot and kept with it, so a
/// warm request parses nothing at all — the third clause of SPEC §10's warm path,
/// beside the no-query and no-upstream-call clauses `store_commands` witnesses.
#[tokio::test]
async fn a_warm_artifact_request_does_not_reparse_the_project_document() {
    let harness = harness(strong_integrity(), FakeAnswer::Body(body())).await;
    let path = harness.artifact_path().await;

    // Cold: the transfer, the hashing, and whatever parsing a first look costs.
    assert_eq!(harness.server.status(&path).await, 200);

    // `app` is scoped: a live `StoreHandle` outside this block would keep the store
    // task from ending and `shutdown` below would wait for it forever.
    let before = harness.server.app().store().caches().stored_parses();
    assert_eq!(harness.server.status(&path).await, 200);
    let warm = harness.server.app().store().caches().stored_parses() - before;

    assert_eq!(
        warm, 0,
        "a warm artifact request parsed the stored project document {warm} time(s); \
         the advertised reference-id set is supposed to be kept with the snapshot it \
         was parsed from"
    );
    harness.shutdown().await;
}
