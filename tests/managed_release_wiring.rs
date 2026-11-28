//! FIX-16-A / C1029 wiring: the OSV generation is read before evaluation, and a managed
//! artifact release is refused after a new OSV match, a publication, or a poisoned gate.
mod common;

use axum::http::{HeaderMap, Method};
use axum::response::IntoResponse;
use common::sync::{FakeSyncServer, PLATFORM, base64, key, org};
use common::{
    FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins,
    npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path, osv_flagging,
};
use probation::upstream::Transport;
use probation_policy::{Layer, LayerKind, OsvSetting};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const BYTES: &str = "verified package bytes";
const FILE: &str = "authority-check-1.0.0.tgz";

fn doc(name: &str) -> String {
    serde_json::json!({"name":name,"versions":{"1.0.0":{"name":name,"version":"1.0.0","dist":{
        "tarball":npm_tarball_url(name, &format!("{name}-1.0.0.tgz")),
        "integrity":format!("sha256-{}", base64(Sha256::digest(BYTES.as_bytes())))}}},
        "time":{"1.0.0":"2026-01-01T00:00:00Z"}})
    .to_string()
}

struct Fx {
    server: TestServer,
    bearer: String,
    id: probation::store::rows::ReferenceId,
    _osv: wiremock::MockServer,
    _dir: tempfile::TempDir,
}

async fn fixture(warm: bool) -> Fx {
    let management = FakeSyncServer::start().await;
    management.layer(
        PLATFORM,
        Layer {
            freeze_seconds: Some(0),
            osv: Some(OsvSetting::On),
            ..Layer::empty(LayerKind::Platform)
        },
    );
    management.layer(org(10), Layer::empty(LayerKind::Org));
    let key = key(1);
    management.known_key(&key, &[PLATFORM, org(10)]);
    let registry = FakeRegistry::new();
    for name in ["authority-check", "flagged-pkg"] {
        registry.answer(&npm_upstream_path(name), FakeAnswer::Body(doc(name)));
        registry.answer(
            &npm_artifact_upstream_path(name, &format!("{name}-1.0.0.tgz")),
            FakeAnswer::Body(BYTES.into()),
        );
    }
    let (osv_url, osv) = osv_flagging(&[("flagged-pkg", "1.0.0")]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = management.managed(config_with_open_blocklist(dir.path()));
    config.metadata_ttl_seconds = 0;
    let server = TestServer::start_with_upstream_and_osv(
        config,
        TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        registry as Arc<dyn Transport>,
        fake_origins(),
        reqwest::Client::new(),
        osv_url,
    )
    .await;
    let app = server.app();
    let managed = app.managed().unwrap();
    let request = probation_policy::api::ChangesRequest {
        since: managed.sync().cursor(),
        report: managed.report(probation_policy::api::Upstreams {
            npm: probation_policy::api::Reachability::Ok,
            pypi: probation_policy::api::Reachability::Ok,
            osv: probation_policy::api::Reachability::Ok,
            rubygems: None,
            cargo: None,
            go: None,
            nuget: None,
            maven: None,
            conan: None,
            oci: None,
        }),
        activity: vec![],
        activity_dropped: vec![],
    };
    managed.sync().fetch_changes(&request).await.unwrap();
    managed.after_answer().await;
    let bearer = format!("Bearer {key}");
    let listing = server
        .get_with_headers("/npm/authority-check", &[("authorization", &bearer)])
        .await;
    assert!(listing.status().is_success());
    let listing: serde_json::Value =
        serde_json::from_slice(&listing.bytes().await.unwrap()).unwrap();
    let url: reqwest::Url = listing["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let id =
        probation::store::rows::ReferenceId::parse_hex(url.path().split('/').rev().nth(1).unwrap())
            .unwrap();
    if warm {
        let r = server
            .get_with_headers(url.path(), &[("authorization", &bearer)])
            .await;
        assert_eq!(r.status().as_u16(), 200);
        r.bytes().await.unwrap();
    }
    Fx {
        server,
        bearer,
        id,
        _osv: osv,
        _dir: dir,
    }
}

impl Fx {
    async fn principal(&self) -> probation::managed::Principal {
        let mut h = HeaderMap::new();
        h.insert("authorization", self.bearer.parse().unwrap());
        self.server
            .app()
            .managed()
            .unwrap()
            .authenticate(&h, "127.0.0.1".parse().unwrap())
            .await
            .unwrap()
    }

    async fn prepare(
        &self,
        p: &probation::managed::Principal,
        m: &Method,
        range: Option<&str>,
    ) -> probation::artifacts::stream::ArtifactResponse {
        probation::artifacts::serve_artifact(
            &self.server.app(),
            Some(p),
            probation_policy::Ecosystem::Npm,
            self.id,
            FILE,
            m,
            range,
        )
        .await
        .unwrap()
    }

    /// Drives the real OSV batcher: a previously unseen MAL match advances the generation.
    async fn flip_osv(&self) {
        let r = self
            .server
            .get_with_headers("/npm/flagged-pkg", &[("authorization", &self.bearer)])
            .await;
        let _ = r.bytes().await;
    }
}

async fn released(r: axum::response::Response) -> (bool, Vec<u8>) {
    let ok = r.status().is_success();
    (
        ok,
        axum::body::to_bytes(r.into_body(), 4096)
            .await
            .unwrap()
            .to_vec(),
    )
}

const CASES: [(Method, Option<&str>); 3] = [
    (Method::GET, None),
    (Method::HEAD, None),
    (Method::GET, Some("bytes=0-7")),
];

#[tokio::test]
async fn osv_flip_after_prepare_refuses_cold_and_warm_all_methods() {
    for warm in [false, true] {
        for (m, range) in CASES.iter() {
            let fx = fixture(warm).await;
            let p = fx.principal().await;
            let prepared = fx.prepare(&p, m, *range).await;
            fx.flip_osv().await;
            let (ok, body) = released(prepared.into_response()).await;
            assert!(!ok, "warm={warm} {m} {range:?} must refuse");
            assert!(
                !body.windows(8).any(|w| w == b"verified"),
                "no payload bytes"
            );
        }
    }
}

#[tokio::test]
async fn osv_flip_before_prepare_and_no_flip_deliver() {
    for warm in [false, true] {
        let fx = fixture(warm).await;
        let p = fx.principal().await;
        let (ok, body) = released(fx.prepare(&p, &Method::GET, None).await.into_response()).await;
        assert!(ok && body == BYTES.as_bytes());
        fx.flip_osv().await;
        let (ok, body) = released(fx.prepare(&p, &Method::GET, None).await.into_response()).await;
        assert!(
            ok && body == BYTES.as_bytes(),
            "a flip before the generation read must not refuse"
        );
    }
}

#[tokio::test]
async fn repeated_live_match_does_not_refuse_inflight() {
    let fx = fixture(true).await;
    let p = fx.principal().await;
    fx.flip_osv().await;
    let prepared = fx.prepare(&p, &Method::GET, None).await;
    fx.flip_osv().await;
    let (ok, _) = released(prepared.into_response()).await;
    assert!(ok, "a second observation of a live match is not a new deny");
}

#[tokio::test]
async fn poisoned_gate_refuses_release() {
    for warm in [false, true] {
        let fx = fixture(warm).await;
        let p = fx.principal().await;
        let prepared = fx.prepare(&p, &Method::GET, None).await;
        let gate = Arc::clone(fx.server.app().managed().unwrap().publication_gate());
        assert!(
            std::thread::spawn(move || {
                let _ = gate.publish(|| panic!("boom"));
            })
            .join()
            .is_err()
        );
        let (ok, body) = released(prepared.into_response()).await;
        assert!(!ok && !body.windows(8).any(|w| w == b"verified"));
    }
}

#[tokio::test]
async fn barrier_publication_governs_release() {
    for publish in [false, true] {
        let fx = fixture(true).await;
        let p = fx.principal().await;
        let prepared = fx.prepare(&p, &Method::GET, None).await;
        let gate = Arc::clone(fx.server.app().managed().unwrap().publication_gate());
        let g2 = Arc::clone(&gate);
        gate.set_barrier(Arc::new(move || {
            if publish {
                let g3 = Arc::clone(&g2);
                std::thread::spawn(move || g3.publish(|| ()).unwrap())
                    .join()
                    .unwrap();
            }
        }));
        let (ok, _) = released(prepared.into_response()).await;
        assert_eq!(ok, !publish);
    }
}

#[tokio::test]
async fn publish_after_prepare_refuses_even_if_unchanged() {
    let fx = fixture(true).await;
    let p = fx.principal().await;
    let prepared = fx.prepare(&p, &Method::GET, None).await;
    fx.server
        .app()
        .managed()
        .unwrap()
        .publication_gate()
        .publish(|| ())
        .unwrap();
    let (ok, _) = released(prepared.into_response()).await;
    assert!(!ok);
}
