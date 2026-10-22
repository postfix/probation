//! Slice 4: the firewall sync API on the real server — the wire contract the firewall's
//! own client reads, the firewall token's kind, source and rate, and the body caps
//! (03-program-design.md § Test plan). Needs the Postgres of docker-compose.test.yml.

mod common;

use std::num::NonZeroU32;
use std::time::Instant;

use common::{Db, client, post};
use ipnet::IpNet;
use probation::managed::client::{CallError, SyncClient};
use probation_policy::api::{
    ActivityEvent, ActivityLayer, ActivityResult, ChainLink, ChangesRequest, ChangesResponse,
    DroppedCount, FirewallReport, KeyHash, KeyId, KeyLookup, LayersResponse, LimitSource,
    LockRange, OrgId, PlaceLayer, Reachability, ReportStatus, Upstreams,
};
use probation_policy::{Block, Ecosystem, Layer, LayerKind, OsvSetting, PlaceRef};
use probation_server::fleet::{self, Registered};
use probation_server::keys;
use probation_server::sync::{ChangeKind, prune_change_log, record_change};
use probation_server::tenancy::{Actor, PLATFORM};
use reqwest::StatusCode;

async fn register(db: &Db, sources: &[&str]) -> Registered {
    let sources: Vec<IpNet> = sources
        .iter()
        .map(|source| source.parse().unwrap())
        .collect();
    fleet::register(&db.app, &Actor::Operator, "fw", &sources)
        .await
        .unwrap()
}

fn changes_body(since: u64, activity: Vec<ActivityEvent>, dropped: Vec<DroppedCount>) -> Vec<u8> {
    let report = FirewallReport {
        settings_revision: 0,
        last_apply_error: None,
        status: ReportStatus {
            upstreams: Upstreams {
                npm: Reachability::Ok,
                pypi: Reachability::Ok,
                osv: Reachability::Ok,
            },
        },
        effective_period_seconds: 55,
        version: "0.2.2".to_owned(),
    };
    serde_json::to_vec(&ChangesRequest {
        since,
        report,
        activity,
        activity_dropped: dropped,
    })
    .unwrap()
}

/// `changes` since `since` with no activity, as the firewall with `token` sends it.
async fn changes(url: &url::Url, token: &str, since: u64) -> ChangesResponse {
    let answer = post(
        &client(),
        url.join("api/v1/sync/changes").unwrap(),
        Some(token),
        &[],
        changes_body(since, Vec::new(), Vec::new()),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    serde_json::from_slice(&answer.bytes().await.unwrap()).expect("a ChangesResponse")
}

fn event(n: usize, key_id: KeyId, place: PlaceRef) -> ActivityEvent {
    ActivityEvent {
        event_id: format!("event-{n}"),
        key_id,
        place,
        ecosystem: Some(Ecosystem::Npm),
        package: Some("left-pad".to_owned()),
        version: Some("1.0.0".to_owned()),
        result: ActivityResult::Blocked,
        rule: "blocked package".to_owned(),
        layer: ActivityLayer::Layer(LayerKind::Org),
        client_ip: None,
        eligible_at: None,
        at: None,
    }
}

fn lookup_body(key: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"key_hash": KeyHash::of(key)})).unwrap()
}

/// T-sync-api-contract: what the firewall's own `SyncClient` reads from the real
/// handlers is the answer the store holds, for every lookup outcome and for layers.
#[tokio::test]
async fn t_sync_api_contract() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    let globex = db.org("Globex").await;
    let platform_layer = Layer {
        freeze_seconds: Some(86_400),
        osv: Some(OsvSetting::On),
        ..Layer::empty(LayerKind::Platform)
    };
    let acme_layer = Layer {
        blocks: vec![Block::Package {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".to_owned(),
        }],
        ..Layer::empty(LayerKind::Org)
    };
    db.edit(admin, PLATFORM, |layer| *layer = platform_layer.clone())
        .await
        .unwrap();
    db.edit(admin, acme, |layer| *layer = acme_layer.clone())
        .await
        .unwrap();
    let (actor, acme_place) = db.as_admin(admin, acme).await;
    let live = keys::create(&db.app, &actor, &acme_place, "live")
        .await
        .unwrap();
    let revoked = keys::create(&db.app, &actor, &acme_place, "revoked")
        .await
        .unwrap();
    keys::revoke(&db.app, &actor, &acme_place, revoked.id)
        .await
        .unwrap();
    let (actor, globex_place) = db.as_admin(admin, globex).await;
    let suspended = keys::create(&db.app, &actor, &globex_place, "suspended")
        .await
        .unwrap();
    db.suspend_org(globex).await;
    let firewall = register(&db, &["127.0.0.0/8"]).await;
    let url = common::serve(db.app.clone(), Vec::new()).await;
    let sync_url = url.clone();
    let sync = SyncClient::new(&common::management(url, &firewall.token));
    // Two layer edits and one revocation so far.
    let revision = 3;
    let acme_chain = vec![
        ChainLink {
            place: PLATFORM,
            layer_revision: 2,
        },
        ChainLink {
            place: acme,
            layer_revision: 2,
        },
    ];

    assert_eq!(
        sync.lookup(KeyHash::of(&live.secret)).await.unwrap(),
        KeyLookup::Known {
            key_id: live.id,
            org: Some(OrgId(acme.id)),
            account: acme,
            place_chain: acme_chain.clone(),
            rate_limit: NonZeroU32::new(6_000),
            rate_limit_source: LimitSource::Default,
            revision,
        }
    );
    assert_eq!(
        sync.lookup(KeyHash::of(&revoked.secret)).await.unwrap(),
        KeyLookup::Revoked {
            key_id: revoked.id,
            place: acme,
            place_chain: acme_chain,
            revision,
        }
    );
    assert_eq!(
        sync.lookup(KeyHash::of(&suspended.secret)).await.unwrap(),
        KeyLookup::Suspended {
            key_id: suspended.id,
            place: globex,
            place_chain: vec![
                ChainLink {
                    place: PLATFORM,
                    layer_revision: 2
                },
                ChainLink {
                    place: globex,
                    layer_revision: 1
                },
            ],
            revision,
        }
    );
    assert_eq!(
        sync.lookup(KeyHash::of("prb_00000000000000000000000000000000"))
            .await
            .unwrap(),
        KeyLookup::Unknown { revision }
    );
    let unknown_place = PlaceRef {
        kind: LayerKind::Org,
        id: 9_999,
    };
    assert_eq!(
        sync.layers(vec![PLATFORM, acme, unknown_place])
            .await
            .unwrap(),
        LayersResponse {
            layers: vec![
                PlaceLayer {
                    place: PLATFORM,
                    layer: platform_layer,
                    revision: 2
                },
                PlaceLayer {
                    place: acme,
                    layer: acme_layer,
                    revision: 2
                },
            ],
            revision,
        }
    );

    // `changes`: the rows after the cursor, the whole network lock on `since = 0`.
    let url = sync_url;
    let token = &firewall.token;
    let full = ChangesResponse {
        revision,
        changed_keys: vec![revoked.id],
        changed_layers: vec![PLATFORM, acme],
        network_lock: Some(Vec::new()),
        ..ChangesResponse::default()
    };
    assert_eq!(changes(&url, token, 0).await, full);
    assert_eq!(
        changes(&url, token, 2).await,
        ChangesResponse {
            revision,
            changed_keys: vec![revoked.id],
            ..ChangesResponse::default()
        }
    );
    assert_eq!(
        changes(&url, token, revision).await,
        ChangesResponse {
            revision,
            ..ChangesResponse::default()
        }
    );
    // A `ranges` row sends the whole table.
    sqlx::query(
        "INSERT INTO org_ip_ranges (org_id, cidr, approved_by) VALUES ($1, '192.0.2.0/24', $2)",
    )
    .bind(acme.id as i32)
    .bind(admin)
    .execute(&db.owner)
    .await
    .unwrap();
    let mut tx = db.app.begin().await.unwrap();
    record_change(&mut tx, ChangeKind::Ranges, &acme)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let lock = vec![LockRange {
        cidr: "192.0.2.0/24".to_owned(),
        org: OrgId(acme.id),
    }];
    assert_eq!(
        changes(&url, token, revision).await,
        ChangesResponse {
            revision: revision + 1,
            network_lock: Some(lock.clone()),
            ..ChangesResponse::default()
        }
    );
    let revision = revision + 1;

    // A cursor below `pruned_through` is reset, with the whole lock.
    let reset = ChangesResponse {
        revision,
        network_lock: Some(lock),
        reset: true,
        ..ChangesResponse::default()
    };
    sqlx::query("UPDATE change_counter SET pruned_through = 2")
        .execute(&db.owner)
        .await
        .unwrap();
    assert_eq!(changes(&url, token, 1).await, reset);
    assert!(!changes(&url, token, 2).await.reset);

    // The prune job: rows older than the retention go, and `pruned_through` follows.
    sqlx::query("UPDATE change_log SET at = now() - interval '8 days' WHERE revision <= 3")
        .execute(&db.owner)
        .await
        .unwrap();
    prune_change_log(&db.app, 7).await.unwrap();
    let left: Vec<i64> = sqlx::query_scalar("SELECT revision FROM change_log ORDER BY revision")
        .fetch_all(&db.owner)
        .await
        .unwrap();
    assert_eq!(left, vec![4]);
    let pruned: i64 = sqlx::query_scalar("SELECT pruned_through FROM change_counter")
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert_eq!(pruned, 3);
    assert_eq!(changes(&url, token, 2).await, reset);
    assert!(!changes(&url, token, 3).await.reset);

    // A cursor above the log, as after the database was restored from a backup: the
    // reset is answered at or above the cursor, so the firewall's invalidation floor
    // never outruns the server and the next lookup is still served (R3).
    // Every firewall from the lost history is reset, not only the first to report (N1).
    let ahead = revision + 100;
    let others = [
        register(&db, &["127.0.0.0/8"]).await,
        register(&db, &["127.0.0.0/8"]).await,
    ];
    for (token, cursor) in [
        (token.as_str(), ahead),
        (others[0].token.as_str(), revision + 50),
        (others[1].token.as_str(), ahead),
    ] {
        let restored = changes(&url, token, cursor).await;
        assert!(restored.reset, "cursor {cursor}: {restored:?}");
        assert!(restored.revision >= cursor, "cursor {cursor}: {restored:?}");
    }
    let restored = changes(&url, token, ahead).await;
    match sync.lookup(KeyHash::of(&live.secret)).await.unwrap() {
        KeyLookup::Known { revision, .. } => assert!(revision >= ahead, "read at {revision}"),
        other => panic!("{other:?}"),
    }
    assert!(!changes(&url, token, restored.revision).await.reset);

    // A revision the server handed out is always accepted, however high (N2): a cursor
    // at the raise bound, then a change past it.
    let bound = probation_server::sync::MAX_CURSOR;
    let raised = changes(&url, token, bound).await;
    assert!(raised.reset && raised.revision >= bound, "{raised:?}");
    let mut tx = db.app.begin().await.unwrap();
    record_change(&mut tx, ChangeKind::Ranges, &acme)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let past = changes(&url, token, raised.revision).await;
    assert!(!past.reset && past.revision > bound, "{past:?}");
    assert!(!changes(&url, token, past.revision).await.reset);
    // A cursor above the raise bound is answered but raises nothing, so the revisions
    // after it still fit in a bigint.
    let forged = changes(&url, token, i64::MAX as u64 - 1).await;
    assert!(
        forged.reset && forged.revision < i64::MAX as u64 - 1,
        "{forged:?}"
    );
    let mut tx = db.app.begin().await.unwrap();
    record_change(&mut tx, ChangeKind::Ranges, &acme)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Only a cursor that is no Postgres bigint is refused.
    let answer = post(
        &client(),
        url.join("api/v1/sync/changes").unwrap(),
        Some(token),
        &[],
        changes_body(u64::MAX, Vec::new(), Vec::new()),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// T-firewall-token-required: no token, an unknown token and a retired firewall's
/// token are each refused with 401 on every sync route.
#[tokio::test]
async fn t_firewall_token_required() {
    let db = Db::fresh().await;
    let firewall = register(&db, &["127.0.0.0/8"]).await;
    let retired = register(&db, &["127.0.0.0/8"]).await;
    sqlx::query("UPDATE firewalls SET retired_at = now() WHERE id = $1")
        .bind(retired.id)
        .execute(&db.owner)
        .await
        .unwrap();
    let url = common::serve(db.app.clone(), Vec::new()).await;
    let http = client();
    let unknown = keys::generate(keys::KeyKind::Firewall);
    for (path, body) in [
        ("api/v1/sync/lookup", lookup_body("prb_x")),
        ("api/v1/sync/layers", br#"{"places":[]}"#.to_vec()),
        (
            "api/v1/sync/changes",
            changes_body(0, Vec::new(), Vec::new()),
        ),
    ] {
        for token in [None, Some(unknown.as_str()), Some(retired.token.as_str())] {
            let answer = post(&http, url.join(path).unwrap(), token, &[], body.clone()).await;
            assert_eq!(
                answer.status(),
                StatusCode::UNAUTHORIZED,
                "{path} with {token:?}"
            );
        }
        let answer = post(
            &http,
            url.join(path).unwrap(),
            Some(&firewall.token),
            &[],
            body,
        )
        .await;
        assert_eq!(answer.status(), StatusCode::OK, "{path}");
    }
}

/// T-credential-kind (T9): an API key is no firewall token, and a firewall or
/// automation token is no API key.
#[tokio::test]
async fn t_credential_kind() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    let (actor, acme_place) = db.as_admin(admin, acme).await;
    let key = keys::create(&db.app, &actor, &acme_place, "ci")
        .await
        .unwrap();
    let firewall = register(&db, &["127.0.0.0/8"]).await;
    let automation = keys::generate(keys::KeyKind::Automation);
    sqlx::query(
        "INSERT INTO keys (hash, last4, kind, place_kind, place_id, owner_login, name)
         VALUES ($1, 'xxxx', 'automation', 'org', $2, $3, 'push')",
    )
    .bind(KeyHash::of(&automation).0.as_slice())
    .bind(acme.id as i32)
    .bind(admin)
    .execute(&db.owner)
    .await
    .unwrap();
    let url = common::serve(db.app.clone(), Vec::new()).await;

    // A `prb_` key as the firewall token, and its `fwt_` text spelled as a key would be.
    let http = client();
    let lookup = url.join("api/v1/sync/lookup").unwrap();
    for token in [key.secret.clone(), format!("fwt_{}", &key.secret[4..])] {
        let answer = post(
            &http,
            lookup.clone(),
            Some(&token),
            &[],
            lookup_body(&key.secret),
        )
        .await;
        assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
    }
    // A firewall token and an automation token looked up as keys.
    let sync = SyncClient::new(&common::management(url.clone(), &firewall.token));
    for token in [&firewall.token, &automation] {
        assert!(matches!(
            sync.lookup(KeyHash::of(token)).await.unwrap(),
            KeyLookup::Unknown { .. }
        ));
    }
    // The real key still answers, so the refusals above are about kind alone.
    assert!(matches!(
        sync.lookup(KeyHash::of(&key.secret)).await.unwrap(),
        KeyLookup::Known { .. }
    ));
    let wrong = SyncClient::new(&common::management(url, &key.secret));
    assert_eq!(
        wrong.lookup(KeyHash::of(&key.secret)).await,
        Err(CallError::TokenRefused)
    );
}

fn refused_source(answer: &reqwest::Response) -> bool {
    answer.status() == StatusCode::FORBIDDEN
        && answer
            .headers()
            .get("x-probation-error")
            .is_some_and(|value| value == "FIREWALL_SOURCE_REFUSED")
}

/// T-firewall-token-source (T31): a valid token is accepted only from its
/// `allowed_source_cidrs` (behind a listed load balancer, from `X-Forwarded-For` read
/// as the firewall reads it) and at most 200 times a second.
#[tokio::test]
async fn t_firewall_token_source() {
    let db = Db::fresh().await;
    let remote = register(&db, &["192.0.2.0/24"]).await;
    let local = register(&db, &["127.0.0.0/8"]).await;
    let direct = common::serve(db.app.clone(), Vec::new()).await;
    let balanced = common::serve(db.app.clone(), vec!["127.0.0.1/32".parse().unwrap()]).await;
    let http = client();
    let layers = |url: &url::Url| url.join("api/v1/sync/layers").unwrap();
    let empty = || br#"{"places":[]}"#.to_vec();

    // From outside its ranges, directly or through an unlisted balancer.
    for extra in [&[][..], &[("x-forwarded-for", "192.0.2.7")][..]] {
        let answer = post(&http, layers(&direct), Some(&remote.token), extra, empty()).await;
        assert!(refused_source(&answer), "{extra:?}: {}", answer.status());
    }
    // Through a listed balancer: the forwarded address counts, not the balancer's.
    let answer = post(
        &http,
        layers(&balanced),
        Some(&remote.token),
        &[("x-forwarded-for", "192.0.2.7")],
        empty(),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    let answer = post(&http, layers(&balanced), Some(&remote.token), &[], empty()).await;
    assert!(
        refused_source(&answer),
        "no header: the balancer's own address"
    );
    // Two header lines are joined in order; the rightmost untrusted entry wins.
    let answer = post(
        &http,
        layers(&balanced),
        Some(&remote.token),
        &[
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-for", "192.0.2.7"),
        ],
        empty(),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    let answer = post(
        &http,
        layers(&balanced),
        Some(&remote.token),
        &[
            ("x-forwarded-for", "192.0.2.7"),
            ("x-forwarded-for", "203.0.113.9"),
        ],
        empty(),
    )
    .await;
    assert!(refused_source(&answer), "{}", answer.status());

    // 201 requests within one second from an allowed address: the 201st is refused.
    let started = Instant::now();
    let mut statuses = Vec::new();
    for _ in 0..201 {
        statuses.push(
            post(&http, layers(&direct), Some(&local.token), &[], empty())
                .await
                .status(),
        );
    }
    assert!(
        started.elapsed().as_secs_f64() < 1.0,
        "the burst fits in one second"
    );
    assert!(
        statuses[..200]
            .iter()
            .all(|status| *status == StatusCode::OK)
    );
    assert_eq!(statuses[200], StatusCode::TOO_MANY_REQUESTS);
}

/// T-body-limits (T24): a `changes` call one entry over a cap, or one byte over 2 MiB,
/// answers 413 and writes nothing; one at the caps is taken whole.
#[tokio::test]
async fn t_body_limits() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    let (actor, acme_place) = db.as_admin(admin, acme).await;
    let key = keys::create(&db.app, &actor, &acme_place, "ci")
        .await
        .unwrap();
    let firewall = register(&db, &["127.0.0.0/8"]).await;
    let url = common::serve(db.app.clone(), Vec::new()).await;
    let http = client();
    let endpoint = url.join("api/v1/sync/changes").unwrap();
    let events = |count: usize| {
        (0..count)
            .map(|n| event(n, key.id, acme))
            .collect::<Vec<_>>()
    };
    let drops = |count: usize| {
        (0..count)
            .map(|n| DroppedCount {
                account: PlaceRef {
                    kind: LayerKind::Org,
                    id: n as u32 + 1,
                },
                count: 1,
            })
            .collect::<Vec<_>>()
    };
    let mut padded: serde_json::Value =
        serde_json::from_slice(&changes_body(0, Vec::new(), Vec::new())).unwrap();
    padded["report"]["version"] = serde_json::Value::String("x".repeat(2 * 1024 * 1024));

    for (what, body) in [
        ("1 001 events", changes_body(0, events(1_001), Vec::new())),
        (
            "1 001 dropped counts",
            changes_body(0, Vec::new(), drops(1_001)),
        ),
        ("over 2 MiB", serde_json::to_vec(&padded).unwrap()),
    ] {
        let answer = post(&http, endpoint.clone(), Some(&firewall.token), &[], body).await;
        assert_eq!(answer.status(), StatusCode::PAYLOAD_TOO_LARGE, "{what}");
    }
    assert_eq!(db.count("SELECT count(*) FROM activity").await, 0);
    assert_eq!(
        db.count("SELECT count(*) FROM firewalls WHERE last_seen_at IS NOT NULL")
            .await,
        0
    );

    let answer = post(
        &http,
        endpoint,
        Some(&firewall.token),
        &[],
        changes_body(0, events(1_000), drops(1_000)),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    assert_eq!(db.count("SELECT count(*) FROM activity").await, 1_000);
}

/// T-activity-place-from-key (T9, T18): an event's place comes from its key, never from
/// the firewall's report; an unknown key's event is not stored, and a batch sent twice
/// is stored once.
#[tokio::test]
async fn t_activity_place_from_key() {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let acme = db.org("Acme").await;
    let globex = db.org("Globex").await;
    let (actor, acme_place) = db.as_admin(admin, acme).await;
    let key = keys::create(&db.app, &actor, &acme_place, "ci")
        .await
        .unwrap();
    let firewall = register(&db, &["127.0.0.0/8"]).await;
    let url = common::serve(db.app.clone(), Vec::new()).await;

    let forged = event(1, key.id, globex);
    let refused = ActivityEvent {
        result: ActivityResult::RefusedNetwork,
        layer: ActivityLayer::Network,
        client_ip: Some("192.0.2.7".parse().unwrap()),
        ecosystem: None,
        package: None,
        version: None,
        ..event(2, key.id, globex)
    };
    let unknown = event(3, KeyId(9_999), acme);
    let batch = changes_body(0, vec![forged, refused, unknown], Vec::new());
    for _ in 0..2 {
        let answer = post(
            &client(),
            url.join("api/v1/sync/changes").unwrap(),
            Some(&firewall.token),
            &[],
            batch.clone(),
        )
        .await;
        assert_eq!(answer.status(), StatusCode::OK);
    }

    type Row = (String, String, i32, i64, String, String, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT event_id, place_kind, place_id, key_id, result, layer, host(client_ip)
         FROM activity ORDER BY event_id",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    let acme_id = acme.id as i32;
    let key_id = key.id.0 as i64;
    assert_eq!(
        rows,
        vec![
            (
                "event-1".into(),
                "org".into(),
                acme_id,
                key_id,
                "blocked".into(),
                "org".into(),
                None
            ),
            (
                "event-2".into(),
                "org".into(),
                acme_id,
                key_id,
                "refused_network".into(),
                "network".into(),
                Some("192.0.2.7".into())
            ),
        ]
    );

    // The firewall's time of each event (S4-11): kept when it is within the activity
    // retention (Acme: the platform's 90 days), clamped to it when older, and now when
    // it is in the future, missing or no RFC 3339 time.
    let rfc3339 = |interval: &'static str| {
        let db = &db;
        async move {
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
                "SELECT to_char((now() + interval '{interval}') AT TIME ZONE 'UTC',
                                'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
            )))
            .fetch_one(&db.owner)
            .await
            .unwrap()
        }
    };
    let ten_minutes_ago = rfc3339("-10 minutes").await;
    let timed = |n: usize, at: Option<String>| ActivityEvent {
        at,
        ..event(n, key.id, acme)
    };
    let batch = changes_body(
        0,
        vec![
            timed(4, Some(ten_minutes_ago.clone())),
            timed(5, Some(rfc3339("1 hour").await)),
            timed(6, None),
            timed(7, Some("yesterday".to_owned())),
            timed(8, Some(rfc3339("-200 days").await)),
        ],
        Vec::new(),
    );
    let clock = || async {
        sqlx::query_scalar::<_, String>("SELECT clock_timestamp()::text")
            .fetch_one(&db.owner)
            .await
            .unwrap()
    };
    let before = clock().await;
    let answer = post(
        &client(),
        url.join("api/v1/sync/changes").unwrap(),
        Some(&firewall.token),
        &[],
        batch,
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    let after = clock().await;
    let stored: Vec<(String, bool, bool, bool)> = sqlx::query_as(
        "SELECT event_id,
                at = $1::timestamptz,
                at BETWEEN $2::timestamptz AND $3::timestamptz,
                at BETWEEN $2::timestamptz - interval '90 days' AND $3::timestamptz - interval '90 days'
         FROM activity WHERE event_id IN ('event-4', 'event-5', 'event-6', 'event-7', 'event-8')
         ORDER BY event_id",
    )
    .bind(&ten_minutes_ago)
    .bind(&before)
    .bind(&after)
    .fetch_all(&db.owner)
    .await
    .unwrap();
    assert_eq!(
        stored,
        vec![
            ("event-4".into(), true, false, false),
            ("event-5".into(), false, true, false),
            ("event-6".into(), false, true, false),
            ("event-7".into(), false, true, false),
            ("event-8".into(), false, false, true),
        ],
        "(event, at the firewall's time, at now, at the retention bound)"
    );
}
