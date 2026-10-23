//! `probation-server serve` as an orchestrator runs it: it stops cleanly on SIGTERM
//! (F8), and answers its health endpoints (F9). Needs the Postgres of
//! docker-compose.test.yml.

mod common;

use std::time::{Duration, Instant};

use common::{Db, client};
use reqwest::StatusCode;

/// `probation-server serve` on a free loopback port, once it listens. The portal and an
/// SMTP relay are set too, so the outbox and purge jobs run as well as the prune; nothing
/// is queued, so the relay is never called.
struct Server {
    process: std::process::Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Server {
    async fn start(db: &Db) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config = dir.path().join("server.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\nlisten = \"127.0.0.1:{port}\"\n\n[portal]\nbase_url = \"http://127.0.0.1:{port}/\"\n\n[portal.smtp]\nhost = \"127.0.0.1\"\nport = 1\nfrom = \"probation@example.org\"\n"
            ),
        )
        .unwrap();
        let mut process = std::process::Command::new(env!("CARGO_BIN_EXE_probation-server"))
            .args(["serve", "--config"])
            .arg(&config)
            .env("PROBATION_SERVER_DATABASE_URL", &db.app_url)
            .env("PROBATION_SERVER_SECRET_KEY", "07".repeat(32))
            .spawn()
            .unwrap();
        let started = Instant::now();
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            if let Some(status) = process.try_wait().unwrap() {
                panic!("serve exited before listening: {status}");
            }
            assert!(started.elapsed() < Duration::from_secs(20), "serve listens");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Server {
            process,
            port,
            _dir: dir,
        }
    }

    fn sigterm(&self) {
        let sent = std::process::Command::new("kill")
            .args(["-TERM", &self.process.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
    }

    /// Its exit status, which must come within `limit`.
    async fn exit_within(&mut self, limit: Duration) -> std::process::ExitStatus {
        let waiting = Instant::now();
        loop {
            if let Some(status) = self.process.try_wait().unwrap() {
                return status;
            }
            if waiting.elapsed() > limit {
                let _ = self.process.kill();
                panic!("serve still runs {limit:?} later");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// A connection whose request never finishes: a body of 1000 bytes announced, 10
    /// sent.
    async fn stalled_request(&self) -> tokio::net::TcpStream {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
            .await
            .unwrap();
        stream
            .write_all(
                b"PUT /api/v1/blocklist/org-1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer aut_x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"schema\":",
            )
            .await
            .unwrap();
        // Let the server take the request in before the signal.
        tokio::time::sleep(Duration::from_millis(300)).await;
        stream
    }
}

/// ND-2: `serve` refuses to start when `PROBATION_SERVER_SECRET_KEY` does not open the
/// secrets already sealed in the database (a restore with another key), and says so;
/// with the key they were sealed with it starts.
#[tokio::test]
async fn serve_refuses_a_secret_key_that_does_not_match() {
    use probation_server::accounts::{SecretBox, totp_aad};
    let db = Db::fresh().await;
    let login = db.login().await;
    let plant = |key: [u8; 32]| {
        sqlx::query(
            "INSERT INTO totp (login_id, secret_enc, enabled_at) VALUES ($1, $2, now())
             ON CONFLICT (login_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc",
        )
        .bind(login)
        .bind(SecretBox::new(key).seal(&totp_aad(login), b"a totp secret"))
        .execute(&db.owner)
    };
    plant([8; 32]).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        "[server]\nlisten = \"127.0.0.1:0\"\n\n[portal]\nbase_url = \"http://127.0.0.1/\"\n",
    )
    .unwrap();
    let mut refused = std::process::Command::new(env!("CARGO_BIN_EXE_probation-server"))
        .args(["serve", "--config"])
        .arg(&config)
        .env("PROBATION_SERVER_DATABASE_URL", &db.app_url)
        .env("PROBATION_SERVER_SECRET_KEY", "07".repeat(32))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while refused.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(20) {
            let _ = refused.kill();
            panic!("serve runs with a secret key that does not match");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let refused = refused.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("does not match the one these secrets were sealed with"),
        "{stderr}"
    );
    plant(common::SECRET_KEY).await.unwrap();
    let mut server = Server::start(&db).await;
    server.sigterm();
    assert!(server.exit_within(Duration::from_secs(5)).await.success());
}

/// F8: SIGTERM stops `serve`, its background jobs included, with exit code 0 within a
/// few seconds.
#[tokio::test]
async fn sigterm_stops_serve_with_success() {
    let db = Db::fresh().await;
    let mut server = Server::start(&db).await;
    server.sigterm();
    let status = server.exit_within(Duration::from_secs(5)).await;
    assert!(status.success(), "{status}");
}

/// F8: a request that never finishes holds `serve` up for the 20 s drain at most.
#[tokio::test]
async fn stalled_request_holds_shutdown_for_the_drain_only() {
    let db = Db::fresh().await;
    let mut server = Server::start(&db).await;
    let _stalled = server.stalled_request().await;
    server.sigterm();
    let status = server.exit_within(Duration::from_secs(25)).await;
    assert!(status.success(), "{status}");
}

/// F8: a second SIGTERM during the drain stops `serve` at once.
#[tokio::test]
async fn second_sigterm_ends_the_drain() {
    let db = Db::fresh().await;
    let mut server = Server::start(&db).await;
    let _stalled = server.stalled_request().await;
    server.sigterm();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        server.process.try_wait().unwrap().is_none(),
        "still draining"
    );
    server.sigterm();
    let status = server.exit_within(Duration::from_secs(3)).await;
    assert!(status.success(), "{status}");
}

/// F9: `/health/live` answers 200 while the process runs; `/health/ready` answers 200
/// while the database answers and 503 once it does not.
#[tokio::test]
async fn health_live_and_ready() {
    let db = Db::fresh().await;
    let url = common::serve(db.app.clone(), Vec::new()).await;
    let get = |path: &'static str| {
        let url = url.join(path).unwrap();
        async move {
            tokio::time::timeout(Duration::from_secs(5), client().get(url).send())
                .await
                .expect("answered in time")
                .expect("sent")
                .status()
        }
    };
    assert_eq!(get("health/live").await, StatusCode::OK);
    assert_eq!(get("health/ready").await, StatusCode::OK);
    db.app.close().await;
    assert_eq!(get("health/live").await, StatusCode::OK);
    assert_eq!(get("health/ready").await, StatusCode::SERVICE_UNAVAILABLE);
}

/// F9: `probation-server health`, the container's health check, exits 0 on a ready
/// server and 1 on one whose database is gone.
#[tokio::test]
async fn health_command_follows_ready() {
    let db = Db::fresh().await;
    let url = common::serve(db.app.clone(), Vec::new()).await;
    let ready = url.join("health/ready").unwrap();
    let check = || {
        let ready = ready.clone();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_probation-server"))
                .args(["health", "--url", ready.as_str()])
                .status()
                .unwrap()
        })
    };
    assert!(check().await.unwrap().success());
    db.app.close().await;
    assert_eq!(check().await.unwrap().code(), Some(1));
}
