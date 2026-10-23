//! Slice 8: `probation-server admin after-restore` (C129). After the database is restored
//! from a backup, revisions issued after the restore reuse numbers a firewall has
//! already applied; the command raises the counter and `pruned_through` above every
//! revision issued before, so every firewall resets once and misses nothing
//! (03-program-design.md § Test plan, "restore from a backup"). Needs the Postgres of
//! docker-compose.test.yml.
//!
//! A backup is `CREATE DATABASE … TEMPLATE` of the test's database, a restore drops the
//! database and creates it again from that copy. While it happens the server is down:
//! its own login role cannot log in, so the firewalls see 503 and keep their cursors,
//! as firewalls do while an operator restores.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use common::{Db, Firewall, client, post};
use probation_policy::PlaceRef;
use probation_policy::api::{
    ChangesRequest, ChangesResponse, FirewallReport, KeyId, Reachability, ReportStatus, Upstreams,
};
use probation_server::fleet::{self, Registered};
use probation_server::keys::{self, NewKey};
use probation_server::sync::{self, ChangeKind};
use probation_server::tenancy::{Actor, PLATFORM};
use reqwest::StatusCode;
use sqlx::{Connection, PgConnection};

struct World {
    db: Db,
    admin: i32,
    acme: PlaceRef,
    /// The login role the server connects as, of its own so it can be turned off.
    server_role: String,
    url: url::Url,
    backups: u32,
}

impl World {
    async fn new() -> World {
        let db = Db::fresh().await;
        let admin = db.global_admin().await;
        let acme = db.org("Acme").await;
        let server_role = format!("srv_{}", db.name);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {server_role} LOGIN PASSWORD 'probation' IN ROLE probation_app"
        )))
        .execute(&db.owner)
        .await
        .unwrap();
        let mut server_url = url::Url::parse(&db.app_url).unwrap();
        server_url.set_username(&server_role).unwrap();
        let pool = probation_server::connect(server_url.as_str())
            .await
            .unwrap();
        let url = common::serve(pool, Vec::new()).await;
        World {
            db,
            admin,
            acme,
            server_role,
            url,
            backups: 0,
        }
    }

    async fn cluster(&self) -> PgConnection {
        PgConnection::connect(&common::admin_url()).await.unwrap()
    }

    /// The server cannot reach its database: every sync answers 503.
    async fn server_down(&self, cluster: &mut PgConnection) {
        let role = &self.server_role;
        for statement in [
            format!("ALTER ROLE {role} NOLOGIN"),
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{role}'"
            ),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(&mut *cluster)
                .await
                .unwrap();
        }
    }

    async fn server_up(&self) {
        let role = &self.server_role;
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER ROLE {role} LOGIN")))
            .execute(&mut self.cluster().await)
            .await
            .unwrap();
    }

    /// A copy of the database as it is now; the server is up again afterwards.
    async fn backup(&mut self) -> String {
        self.backups += 1;
        let copy = format!("{}_bak{}", self.db.name, self.backups);
        let mut cluster = self.cluster().await;
        self.server_down(&mut cluster).await;
        let live = &self.db.name;
        for statement in [
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{live}'"
            ),
            format!("CREATE DATABASE {copy} TEMPLATE {live}"),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(&mut cluster)
                .await
                .unwrap();
        }
        self.server_up().await;
        copy
    }

    /// Replaces the database with `backup`; the server stays down.
    async fn restore(&self, backup: &str) {
        let mut cluster = self.cluster().await;
        self.server_down(&mut cluster).await;
        let live = &self.db.name;
        for statement in [
            format!("DROP DATABASE {live} WITH (FORCE)"),
            format!("CREATE DATABASE {live} TEMPLATE {backup}"),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(&mut cluster)
                .await
                .unwrap();
        }
    }

    /// `probation-server admin after-restore`, as the operator runs it.
    fn after_restore(&self) -> String {
        let ran = Command::new(env!("CARGO_BIN_EXE_probation-server"))
            .args(["admin", "after-restore"])
            .env("PROBATION_SERVER_DATABASE_URL", &self.db.app_url)
            .output()
            .unwrap();
        assert!(
            ran.status.success(),
            "after-restore failed: {}",
            String::from_utf8_lossy(&ran.stderr)
        );
        String::from_utf8(ran.stdout).unwrap()
    }

    async fn counter(&self) -> (i64, i64) {
        sqlx::query_as("SELECT value, pruned_through FROM change_counter")
            .fetch_one(&self.db.owner)
            .await
            .unwrap()
    }

    async fn firewall(&self, name: &str) -> Registered {
        fleet::register(
            &self.db.app,
            &Actor::Operator,
            name,
            &["127.0.0.0/8".parse().unwrap()],
        )
        .await
        .unwrap()
    }

    async fn key(&self, name: &str) -> NewKey {
        let (actor, place) = self.db.as_admin(self.admin, self.acme).await;
        keys::create(&self.db.app, &actor, &place, name)
            .await
            .unwrap()
    }

    async fn revoke(&self, key: KeyId) {
        let (actor, place) = self.db.as_admin(self.admin, self.acme).await;
        keys::revoke(&self.db.app, &actor, &place, key)
            .await
            .unwrap();
    }

    /// One `change_log` row that changes nothing a firewall serves.
    async fn filler(&self) {
        let mut tx = self.db.app.begin().await.unwrap();
        sync::record_change(&mut tx, ChangeKind::Ranges, &self.acme)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// Keeps the firewall registered as `id` from syncing (403 `FIREWALL_SOURCE_REFUSED`).
    async fn refuse_source(&self, id: i32) {
        sqlx::query("UPDATE firewalls SET allowed_source_cidrs = '{192.0.2.1/32}' WHERE id = $1")
            .bind(id)
            .execute(&self.db.owner)
            .await
            .unwrap();
    }

    /// A settings push to the firewall registered as `id`; the rollout's id.
    async fn push(&self, id: i32) -> i32 {
        let (actor, _) = self.db.as_admin(self.admin, PLATFORM).await;
        fleet::push_settings(&self.db.app, &actor, &[id], "sync_interval_seconds = 30")
            .await
            .unwrap()
    }

    async fn step(&self, rollout: i32, firewall: i32) -> String {
        sqlx::query_scalar(
            "SELECT state FROM settings_rollout_steps WHERE rollout_id = $1 AND firewall_id = $2",
        )
        .bind(rollout)
        .bind(firewall)
        .fetch_one(&self.db.owner)
        .await
        .unwrap()
    }

    async fn audit_rows(&self) -> i64 {
        self.db
            .count("SELECT count(*) FROM audit_log WHERE action = 'admin.after_restore'")
            .await
    }
}

/// `changes` since `since`, as the firewall with `token` sends it.
async fn changes(url: &url::Url, token: &str, since: u64) -> ChangesResponse {
    changes_reporting(url, token, since, 0).await
}

/// `changes`, reporting `settings_revision` as the settings the firewall runs.
async fn changes_reporting(
    url: &url::Url,
    token: &str,
    since: u64,
    settings_revision: u64,
) -> ChangesResponse {
    let report = FirewallReport {
        settings_revision,
        last_apply_error: None,
        status: ReportStatus {
            upstreams: Upstreams {
                npm: Reachability::Ok,
                pypi: Reachability::Ok,
                osv: Reachability::Ok,
            },
        },
        effective_period_seconds: 2,
        version: "0.2.2".to_owned(),
    };
    let body = serde_json::to_vec(&ChangesRequest {
        since,
        report,
        activity: Vec::new(),
        activity_dropped: Vec::new(),
    })
    .unwrap();
    let answer = post(
        &client(),
        url.join("api/v1/sync/changes").unwrap(),
        Some(token),
        &[],
        body,
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    serde_json::from_slice(&answer.bytes().await.unwrap()).unwrap()
}

/// Waits until `key` answers `want` on `firewall`.
async fn answers(firewall: &Firewall, key: &NewKey, want: StatusCode, what: &str) {
    let http = client();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let got = firewall
            .get(&http, "/npm/left-pad", &key.secret)
            .await
            .status();
        if got == want {
            return;
        }
        assert!(Instant::now() < deadline, "{what}: {got}, not {want}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Lets every firewall finish a sync at the current revision.
async fn settle() {
    tokio::time::sleep(Duration::from_secs(3)).await;
}

/// T-ops-after-restore-resets-fleet (C129, amends C126).
#[tokio::test]
async fn t_ops_after_restore_resets_fleet() {
    let mut world = World::new().await;
    let a = world.firewall("a").await;
    let b = world.firewall("b").await;
    // Fakes that sync only when this test says so.
    let c = world.firewall("c").await;
    let d = world.firewall("d").await;
    // A fake that runs settings pushed before the restore.
    let e = world.firewall("e").await;
    let (k, k2) = (world.key("k").await, world.key("k2").await);
    let fa = Firewall::start(world.url.clone(), &a.token, 2, 1).await;
    let fb = Firewall::start(world.url.clone(), &b.token, 2, 1).await;
    fa.ready(Duration::from_secs(10)).await;
    fb.ready(Duration::from_secs(10)).await;
    for firewall in [&fa, &fb] {
        answers(firewall, &k, StatusCode::OK, "k is served").await;
        answers(firewall, &k2, StatusCode::OK, "k2 is served").await;
    }

    // The backup; then firewall B stops at cursor b_cursor while A goes further.
    let backup = world.backup().await;
    let (backed_up, _) = world.counter().await;
    // A push made after the backup, which E applies and keeps reporting.
    let lost_rollout = world.push(e.id).await;
    changes_reporting(&world.url, &e.token, 0, lost_rollout as u64).await;
    assert_eq!(world.step(lost_rollout, e.id).await, "applied");
    let c_cursor = backed_up as u64;
    world.filler().await;
    settle().await;
    world.refuse_source(b.id).await;
    let (b_cursor, _) = world.counter().await;
    for _ in 0..3 {
        world.filler().await;
    }
    settle().await;
    let (a_cursor, _) = world.counter().await;

    // Restored, and with the server still down, enough rows are written that B's
    // cursor is no longer ahead of the server's revision (A's still is); one of them
    // revokes k. Without the command B would apply only the rows above its cursor
    // and keep serving k.
    world.restore(&backup).await;
    world.revoke(k.id).await;
    while world.counter().await.0 <= b_cursor {
        world.filler().await;
    }
    let before = world.counter().await;
    assert!(before.0 > b_cursor && before.0 < a_cursor, "{before:?}");

    let printed = world.after_restore();
    let after = world.counter().await;
    assert!(
        after.0 > before.0 && after.0 > a_cursor,
        "{before:?} -> {after:?}"
    );
    assert_eq!(after.1, after.0, "pruned_through equals value");
    assert_eq!(world.audit_rows().await, 1, "one audit row");
    assert!(printed.contains(&after.0.to_string()), "{printed}");
    world.server_up().await;
    // A push made after the restore gets an id no firewall can still report, so E's
    // report of the lost push does not mark it applied.
    let new_rollout = world.push(e.id).await;
    assert!(
        new_rollout > lost_rollout,
        "{new_rollout} after {lost_rollout}"
    );
    changes_reporting(&world.url, &e.token, after.0 as u64, lost_rollout as u64).await;
    assert_eq!(world.step(new_rollout, e.id).await, "sent");
    for firewall in [&fa, &fb] {
        answers(
            firewall,
            &k,
            StatusCode::UNAUTHORIZED,
            "k is revoked everywhere",
        )
        .await;
        answers(firewall, &k2, StatusCode::OK, "k2 is served again").await;
    }

    // A new row reaches both firewalls, as a delta.
    world.revoke(k2.id).await;
    for firewall in [&fa, &fb] {
        answers(
            firewall,
            &k2,
            StatusCode::UNAUTHORIZED,
            "k2 is revoked everywhere",
        )
        .await;
    }
    let delta = changes(&world.url, &d.token, after.0 as u64).await;
    assert!(!delta.reset, "{delta:?}");
    assert_eq!(delta.changed_keys, vec![k2.id]);

    // A second run raises both again.
    world.after_restore();
    let again = world.counter().await;
    assert!(
        again.0 > after.0 + 1 && again.1 == again.0,
        "{after:?} -> {again:?}"
    );
    assert_eq!(world.audit_rows().await, 2);

    // The prune after the command never lowers pruned_through, and C, which has not
    // synced since the restore, still resets.
    sqlx::query("UPDATE change_log SET at = now() - interval '30 days'")
        .execute(&world.db.owner)
        .await
        .unwrap();
    sync::prune_change_log(&world.db.app, 7).await.unwrap();
    assert_eq!(
        world.counter().await,
        again,
        "the prune left the counter alone"
    );
    assert!(changes(&world.url, &c.token, c_cursor).await.reset);
    settle().await;

    // A backup taken right after an earlier after-restore, restored twice: a key the
    // firewalls looked up after it was taken answers as the restored database says.
    let backup = world.backup().await;
    let mut last = again.0;
    for round in 0..2 {
        let newer = world.key(&format!("newer {round}")).await;
        world.filler().await;
        settle().await;
        for firewall in [&fa, &fb] {
            answers(
                firewall,
                &newer,
                StatusCode::OK,
                "a key made after the backup",
            )
            .await;
        }
        world.restore(&backup).await;
        world.after_restore();
        let raised = world.counter().await;
        assert!(
            raised.0 > last && raised.1 == raised.0,
            "round {round}: {raised:?}"
        );
        last = raised.0;
        world.server_up().await;
        for firewall in [&fa, &fb] {
            answers(
                firewall,
                &newer,
                StatusCode::UNAUTHORIZED,
                "the restored database has no such key",
            )
            .await;
            answers(
                firewall,
                &k2,
                StatusCode::UNAUTHORIZED,
                "k2 was revoked before the backup",
            )
            .await;
        }
    }

    // The backups and the server's role are the cluster's, not the test database's.
    let mut cluster = world.cluster().await;
    world.server_down(&mut cluster).await;
    for n in 1..=world.backups {
        let copy = format!("{}_bak{n}", world.db.name);
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {copy}")))
            .execute(&mut cluster)
            .await
            .unwrap();
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP ROLE {}",
        world.server_role
    )))
    .execute(&mut cluster)
    .await
    .unwrap();
}
