//! `probation-server serve` as an orchestrator runs it: it stops cleanly on SIGTERM
//! (F8), and answers its health endpoints (F9). Needs the Postgres of
//! docker-compose.test.yml.

mod common;

use std::time::{Duration, Instant};

use common::{Db, client};
use reqwest::StatusCode;

/// F8: SIGTERM stops `serve`, its background jobs included, with exit code 0 within a
/// few seconds.
#[tokio::test]
async fn sigterm_stops_serve_with_success() {
    let db = Db::fresh().await;
    let dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = dir.path().join("server.toml");
    // The portal and an SMTP relay too, so the outbox and purge jobs run as well as the
    // prune; nothing is queued, so the relay is never called.
    std::fs::write(
        &config,
        format!(
            "[server]\nlisten = \"127.0.0.1:{port}\"\n\n[portal]\nbase_url = \"http://127.0.0.1:{port}/\"\n\n[portal.smtp]\nhost = \"127.0.0.1\"\nport = 1\nfrom = \"probation@example.org\"\n"
        ),
    )
    .unwrap();
    let mut server = std::process::Command::new(env!("CARGO_BIN_EXE_probation-server"))
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
        if let Some(status) = server.try_wait().unwrap() {
            panic!("serve exited before listening: {status}");
        }
        assert!(started.elapsed() < Duration::from_secs(20), "serve listens");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let sent = std::process::Command::new("kill")
        .args(["-TERM", &server.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let signalled = Instant::now();
    let status = loop {
        if let Some(status) = server.try_wait().unwrap() {
            break status;
        }
        if signalled.elapsed() > Duration::from_secs(5) {
            let _ = server.kill();
            panic!("serve still runs 5 s after SIGTERM");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
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
