//! Slice 4: changes made on the real server reach real managed firewalls within one
//! sync interval (C13, C20, C32 metric 2, H3) (03-program-design.md § Test plan). Needs
//! the Postgres of docker-compose.test.yml. Run with `-- --nocapture` to see the
//! M-propagation lines.

mod common;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Db, Firewall, client};
use probation_policy::api::KeyId;
use probation_policy::{Block, Ecosystem, PlaceRef};
use probation_server::fleet::{self, Registered};
use probation_server::keys::{self, NewKey};
use probation_server::tenancy::Actor;
use reqwest::StatusCode;
use tokio::sync::Mutex;

/// A server, an organisation with an admin, and a firewall registration.
struct World {
    db: Db,
    admin: i32,
    acme: PlaceRef,
    url: url::Url,
}

impl World {
    async fn new() -> World {
        let db = Db::fresh().await;
        let admin = db.global_admin().await;
        let acme = db.org("Acme").await;
        // Every key here is Acme's, and the pollers below send far more than the
        // default 6 000 a minute an organisation's keys share on one firewall (C114).
        sqlx::query(
            "INSERT INTO limits (scope_kind, scope_id, rate_per_min, max_keys, max_service_keys)
             VALUES ('org', $1, 10000000, 1000, 1000)",
        )
        .bind(acme.id as i32)
        .execute(&db.owner)
        .await
        .unwrap();
        let url = common::serve(db.app.clone(), Vec::new()).await;
        World {
            db,
            admin,
            acme,
            url,
        }
    }

    async fn firewall(&self) -> Registered {
        fleet::register(
            &self.db.app,
            &Actor::Operator,
            "fw",
            &["127.0.0.0/8".parse().unwrap()],
        )
        .await
        .unwrap()
    }

    async fn keys(&self, count: usize) -> Vec<NewKey> {
        let (actor, place) = self.db.as_admin(self.admin, self.acme).await;
        let mut created = Vec::with_capacity(count);
        for n in 0..count {
            created.push(
                keys::create(&self.db.app, &actor, &place, &format!("key {n}"))
                    .await
                    .unwrap(),
            );
        }
        created
    }

    async fn block(&self, name: &str) {
        self.db
            .edit(self.admin, self.acme, |layer| {
                layer.blocks.push(Block::Package {
                    ecosystem: Ecosystem::Npm,
                    name: name.to_owned(),
                })
            })
            .await
            .unwrap();
    }

    async fn revoke(&self, key: KeyId) {
        let (actor, place) = self.db.as_admin(self.admin, self.acme).await;
        keys::revoke(&self.db.app, &actor, &place, key)
            .await
            .unwrap();
    }
}

/// T-revoke-end-to-end (C13, C20): `probation-server admin revoke-key` on a key a real
/// firewall has cached answers 401 within one interval, and its refusal is recorded.
#[tokio::test]
async fn t_revoke_end_to_end() {
    let world = World::new().await;
    let registered = world.firewall().await;
    let key = world.keys(1).await.remove(0);
    let firewall = Firewall::start(world.url.clone(), &registered.token, 2, 1).await;
    firewall.ready(Duration::from_secs(10)).await;
    let http = client();
    assert_eq!(
        firewall
            .get(&http, "/npm/left-pad", &key.secret)
            .await
            .status(),
        StatusCode::OK
    );

    let revoked = Command::new(env!("CARGO_BIN_EXE_probation-server"))
        .args(["admin", "revoke-key", "--key-id", &key.id.0.to_string()])
        .env("PROBATION_SERVER_DATABASE_URL", &world.db.app_url)
        .output()
        .unwrap();
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let committed = Instant::now();
    loop {
        let status = firewall
            .get(&http, "/npm/left-pad", &key.secret)
            .await
            .status();
        if status == StatusCode::UNAUTHORIZED {
            break;
        }
        assert_eq!(status, StatusCode::OK);
        assert!(
            committed.elapsed() <= Duration::from_secs(2),
            "401 within one interval"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The refusal reaches the server with the next `changes` call.
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let rows: Vec<(String, String, String, i32)> = sqlx::query_as(
            "SELECT result, layer, place_kind, place_id FROM activity WHERE key_id = $1",
        )
        .bind(key.id.0 as i64)
        .fetch_all(&world.db.owner)
        .await
        .unwrap();
        if !rows.is_empty() {
            assert_eq!(
                rows[0],
                (
                    "refused_revoked".into(),
                    "none".into(),
                    "org".into(),
                    world.acme.id as i32
                )
            );
            break;
        }
        assert!(Instant::now() < deadline, "no refused_revoked activity row");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// T-lookup-burst (H3): a cold firewall and 60 new valid keys in one second from 12
/// client addresses (5 each, within the C120 allowance) against the real server: each
/// answers 200 within two seconds, retried once after `Retry-After`, and none 401.
#[tokio::test]
async fn t_lookup_burst() {
    let world = World::new().await;
    let registered = world.firewall().await;
    let keys = world.keys(60).await;
    let firewall = Arc::new(Firewall::start(world.url.clone(), &registered.token, 2, 1).await);
    firewall.ready(Duration::from_secs(10)).await;

    // One client per address, built before the clock starts: building one loads the
    // TLS roots, which is slow enough to skew the two-second bound.
    let clients: Vec<reqwest::Client> = (0..12u8)
        .map(|n| {
            reqwest::Client::builder()
                .no_proxy()
                .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1 + n)))
                .build()
                .unwrap()
        })
        .collect();
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (n, key) in keys.into_iter().enumerate() {
        let http = clients[n / 5].clone();
        let firewall = Arc::clone(&firewall);
        tasks.push(tokio::spawn(async move {
            let mut answers = Vec::new();
            for _ in 0..2 {
                let answer = firewall.get(&http, "/npm/left-pad", &key.secret).await;
                let status = answer.status();
                answers.push(status);
                if status != StatusCode::SERVICE_UNAVAILABLE {
                    break;
                }
                let retry = answer
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .expect("a 503 says when to retry");
                tokio::time::sleep(Duration::from_secs(retry)).await;
            }
            (answers, started.elapsed())
        }));
    }
    for (n, task) in tasks.into_iter().enumerate() {
        let (answers, at) = task.await.unwrap();
        assert!(
            !answers.contains(&StatusCode::UNAUTHORIZED),
            "key {n}: {answers:?}"
        );
        assert_eq!(
            answers.last(),
            Some(&StatusCode::OK),
            "key {n}: {answers:?}"
        );
        assert!(
            at <= Duration::from_secs(2),
            "key {n} answered 200 after {at:?}"
        );
    }
}

/// `GET path` until it answers 200, waiting out each `503 LOOKUP_BUSY`.
async fn warm(firewall: &Firewall, http: &reqwest::Client, path: &str, key: &str) {
    for _ in 0..10 {
        let answer = firewall.get(http, path, key).await;
        match answer.status() {
            StatusCode::OK => return,
            StatusCode::SERVICE_UNAVAILABLE => tokio::time::sleep(Duration::from_secs(1)).await,
            other => panic!("{path}: {other}"),
        }
    }
    panic!("{path} never answered 200");
}

/// When each firewall first showed each change.
type Applied = Mutex<BTreeMap<(usize, usize), Instant>>;

/// p99 of (last firewall apply − commit), over the changes in `committed`.
fn p99(
    committed: &BTreeMap<usize, Instant>,
    applied: &BTreeMap<(usize, usize), Instant>,
    firewalls: usize,
) -> Duration {
    let mut latencies: Vec<Duration> = committed
        .iter()
        .map(|(change, at)| {
            (0..firewalls)
                .map(|f| applied[&(f, *change)].duration_since(*at))
                .max()
                .unwrap()
        })
        .collect();
    latencies.sort();
    let index = (latencies.len() * 99).div_ceil(100) - 1;
    latencies[index]
}

/// M-propagation (C32 metric 2): two firewalls, 50 policy edits and 50 key revocations
/// at a 10 s interval; the p99 of (last firewall apply − commit) is at most the
/// interval, for edits and revocations each.
#[tokio::test]
async fn m_propagation() {
    const INTERVAL: u64 = 10;
    const CHANGES: usize = 50;
    let world = Arc::new(World::new().await);
    let mut keys = world.keys(CHANGES + 1).await;
    let probe = keys.pop().unwrap();
    let mut firewalls = Vec::new();
    for _ in 0..2 {
        let registered = world.firewall().await;
        let firewall =
            Firewall::start(world.url.clone(), &registered.token, INTERVAL, INTERVAL / 2).await;
        firewall.ready(Duration::from_secs(3 * INTERVAL)).await;
        firewalls.push(Arc::new(firewall));
    }
    let package = |n: usize| format!("pkg-{n:02}");
    // Warm: every key cached and every package fetched, on both firewalls. New keys
    // share the firewall's lookup budget, so a 503 is retried after `Retry-After`.
    let http = client();
    for firewall in &firewalls {
        for key in &keys {
            warm(firewall, &http, "/npm/probe", &key.secret).await;
        }
        for n in 0..CHANGES {
            warm(
                firewall,
                &http,
                &format!("/npm/{}", package(n)),
                &probe.secret,
            )
            .await;
        }
    }

    let edits: Arc<Mutex<BTreeMap<usize, Instant>>> = Arc::default();
    let revocations: Arc<Mutex<BTreeMap<usize, Instant>>> = Arc::default();
    let edits_applied: Arc<Applied> = Arc::default();
    let revocations_applied: Arc<Applied> = Arc::default();
    let key_ids: Vec<KeyId> = keys.iter().map(|key| key.id).collect();
    let writer = {
        let (world, edits, revocations) = (
            Arc::clone(&world),
            Arc::clone(&edits),
            Arc::clone(&revocations),
        );
        tokio::spawn(async move {
            // One change every 100 ms, edits and revocations alternating, over 10 s.
            for (n, key_id) in key_ids.into_iter().enumerate() {
                edits.lock().await.insert(n, Instant::now());
                world.block(&package(n)).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                revocations.lock().await.insert(n, Instant::now());
                world.revoke(key_id).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
    };
    // A revoked key is looked up again on its next request, and one client address gets
    // 5 such lookups a second (C120): each key polls from its own address, so the
    // pollers measure propagation, not that allowance.
    let per_key: Vec<reqwest::Client> = (0..CHANGES)
        .map(|n| {
            reqwest::Client::builder()
                .no_proxy()
                .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 2, 1 + n as u8)))
                .build()
                .unwrap()
        })
        .collect();
    let mut pollers = Vec::new();
    for (f, firewall) in firewalls.iter().enumerate() {
        let firewall = Arc::clone(firewall);
        let (edits, revocations) = (Arc::clone(&edits), Arc::clone(&revocations));
        let (edits_applied, revocations_applied) =
            (Arc::clone(&edits_applied), Arc::clone(&revocations_applied));
        let secrets: Vec<String> = keys.iter().map(|key| key.secret.clone()).collect();
        let per_key = per_key.clone();
        let probe = probe.secret.clone();
        pollers.push(tokio::spawn(async move {
            let http = client();
            let deadline = Instant::now() + Duration::from_secs(CHANGES as u64 / 10 + 4 * INTERVAL);
            loop {
                let pending_edits: Vec<usize> = {
                    let applied = edits_applied.lock().await;
                    edits
                        .lock()
                        .await
                        .keys()
                        .copied()
                        .filter(|n| !applied.contains_key(&(f, *n)))
                        .collect()
                };
                for n in pending_edits {
                    let status = firewall
                        .get(&http, &format!("/npm/{}", package(n)), &probe)
                        .await
                        .status();
                    if status == StatusCode::FORBIDDEN {
                        edits_applied.lock().await.insert((f, n), Instant::now());
                    }
                }
                let pending_revocations: Vec<usize> = {
                    let applied = revocations_applied.lock().await;
                    revocations
                        .lock()
                        .await
                        .keys()
                        .copied()
                        .filter(|n| !applied.contains_key(&(f, *n)))
                        .collect()
                };
                for n in pending_revocations {
                    let status = firewall
                        .get(&per_key[n], "/npm/probe", &secrets[n])
                        .await
                        .status();
                    if status == StatusCode::UNAUTHORIZED {
                        revocations_applied
                            .lock()
                            .await
                            .insert((f, n), Instant::now());
                    }
                }
                let done = edits_applied.lock().await.len() == 2 * CHANGES
                    && revocations_applied.lock().await.len() == 2 * CHANGES;
                if done {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "firewall {f} never applied every change"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }));
    }
    writer.await.unwrap();
    for poller in pollers {
        poller.await.unwrap();
    }

    let interval = Duration::from_secs(INTERVAL);
    let edits_p99 = p99(&*edits.lock().await, &*edits_applied.lock().await, 2);
    let revocations_p99 = p99(
        &*revocations.lock().await,
        &*revocations_applied.lock().await,
        2,
    );
    let compared = |p99: Duration| if p99 <= interval { "<=" } else { ">" };
    println!(
        "propagation edits p99 {} interval ({:.3} s, interval {INTERVAL} s)",
        compared(edits_p99),
        edits_p99.as_secs_f64()
    );
    println!(
        "propagation revocations p99 {} interval ({:.3} s, interval {INTERVAL} s)",
        compared(revocations_p99),
        revocations_p99.as_secs_f64()
    );
    assert!(
        edits_p99 <= interval,
        "edits p99 {edits_p99:?} exceeds the interval"
    );
    assert!(
        revocations_p99 <= interval,
        "revocations p99 {revocations_p99:?} exceeds the interval"
    );
}
