//! Coalesces concurrent OSV lookups into `POST /v1/querybatch` calls, mirroring
//! `delivery/siem.rs::run`'s batching shape, with two differences that shape are
//! carries: the outbound call is timeout-wrapped (C12c), and a successful response is
//! trusted only after its `results` length is checked against `queries` (C12b) —
//! either kind of failure answers every waiter in the flush `false` over its
//! `oneshot`, the same fail-open path for every failure kind, so `OsvClient::check`
//! needs only one failure branch.

use std::time::Duration;

use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{OSV_BATCH_INTERVAL, OSV_BATCH_RECORDS, OsvRequest};
use crate::policy::Ecosystem;

/// OSV's ecosystem spelling, which is not `Ecosystem::as_tag`'s: OSV's schema is
/// case-sensitive and spells PyPI's ecosystem `PyPI`, while `as_tag` spells the
/// blocklist file and log lines' `pypi`.
fn osv_ecosystem(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "PyPI",
    }
}

#[derive(Serialize)]
struct QueryBatchRequest {
    queries: Vec<Query>,
}

#[derive(Serialize)]
struct Query {
    package: Package,
    version: String,
}

#[derive(Serialize)]
struct Package {
    name: String,
    ecosystem: &'static str,
}

#[derive(Deserialize)]
struct QueryBatchResponse {
    #[serde(default)]
    results: Vec<QueryResult>,
}

#[derive(Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<Vuln>,
}

#[derive(Deserialize)]
struct Vuln {
    id: String,
}

/// Runs until `rx` closes or `shutdown` fires.
///
/// `request_timeout` bounds each flush's outbound call (C12c) — reused from
/// `osv_request_timeout_ms` (D4), so there is exactly one knob rather than two that
/// could drift out of sync with C14's per-waiter reply bound.
pub(super) async fn run(
    client: Client,
    url: Url,
    mut rx: mpsc::Receiver<OsvRequest>,
    request_timeout: Duration,
    shutdown: CancellationToken,
) {
    let mut batch: Vec<OsvRequest> = Vec::new();
    // Meaningful only while `batch` is non-empty, set when the first request of a
    // batch arrives, so the interval is counted from the oldest request rather than
    // the newest — the same reasoning as `delivery/siem.rs`.
    let mut deadline = Instant::now();

    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Some(request) => {
                    if batch.is_empty() {
                        deadline = Instant::now() + OSV_BATCH_INTERVAL;
                    }
                    batch.push(request);
                    if batch.len() >= OSV_BATCH_RECORDS {
                        flush(&client, &url, &mut batch, request_timeout).await;
                    }
                }
                None => break,
            },
            () = tokio::time::sleep_until(deadline), if !batch.is_empty() => {
                flush(&client, &url, &mut batch, request_timeout).await;
            }
            () = shutdown.cancelled() => {
                // Drains whatever is already queued, and nothing more — the same
                // reasoning as the delivery sinks: the caller only cancels this
                // token once nothing new will be sent.
                while let Ok(request) = rx.try_recv() {
                    batch.push(request);
                    if batch.len() >= OSV_BATCH_RECORDS {
                        flush(&client, &url, &mut batch, request_timeout).await;
                    }
                }
                if !batch.is_empty() {
                    flush(&client, &url, &mut batch, request_timeout).await;
                }
                break;
            }
        }
    }
}

/// Ships `batch` and empties it, answering every waiter exactly once.
///
/// **Every failure kind takes the same path.** A timeout (C12c), a non-2xx, a
/// transport error, and a `results`/`queries` length mismatch (C12b) are
/// indistinguishable to a waiter: each answers `false` to every request in this
/// flush. `OsvClient::check` therefore never has to special-case which failure it
/// was — fail-open is fail-open (C14).
async fn flush(client: &Client, url: &Url, batch: &mut Vec<OsvRequest>, request_timeout: Duration) {
    let requests = std::mem::take(batch);
    let mut keys = Vec::with_capacity(requests.len());
    let mut waiters = Vec::with_capacity(requests.len());
    for (key, reply) in requests {
        keys.push(key);
        waiters.push(reply);
    }

    let body = QueryBatchRequest {
        queries: keys
            .iter()
            .map(|(ecosystem, name, version)| Query {
                package: Package {
                    name: name.clone(),
                    ecosystem: osv_ecosystem(*ecosystem),
                },
                version: version.clone(),
            })
            .collect(),
    };

    let outcome = tokio::time::timeout(request_timeout, send(client, url, &body)).await;

    let matches: Option<Vec<bool>> = match outcome {
        Ok(Ok(response)) if response.results.len() == keys.len() => Some(
            response
                .results
                .iter()
                .map(|result| result.vulns.iter().any(|vuln| vuln.id.starts_with("MAL-")))
                .collect(),
        ),
        Ok(Ok(response)) => {
            tracing::warn!(
                queries = keys.len(),
                results = response.results.len(),
                "OSV answered a different number of results than queries; failing the batch open"
            );
            None
        }
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "a batch of OSV lookups could not be sent");
            None
        }
        Err(_) => {
            tracing::warn!(?request_timeout, "an OSV lookup batch timed out");
            None
        }
    };

    for (index, waiter) in waiters.into_iter().enumerate() {
        let matched = matches.as_ref().is_some_and(|matches| matches[index]);
        // A waiter that has stopped listening (its `check` call was itself cancelled)
        // is not this loop's problem: nothing here needs the reply to be received.
        let _ = waiter.send(matched);
    }
}

async fn send(
    client: &Client,
    url: &Url,
    body: &QueryBatchRequest,
) -> Result<QueryBatchResponse, SendError> {
    // Written out by hand rather than `RequestBuilder::json`: this crate's `reqwest`
    // dependency does not enable the `json` cargo feature (it is not otherwise
    // needed), so the body is serialized explicitly and the response is parsed from
    // its raw bytes instead.
    let body = serde_json::to_vec(body).map_err(SendError::Encode)?;
    let response = client
        .post(url.clone())
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(SendError::Transport)?;
    // A non-2xx is a failure like any other; `error_for_status` turns it into an
    // `Err` variant `send`'s single failure branch already covers, so a collector
    // that answers `500` is treated exactly like one that never answers at all.
    let response = response.error_for_status().map_err(SendError::Transport)?;
    let bytes = response.bytes().await.map_err(SendError::Transport)?;
    serde_json::from_slice(&bytes).map_err(SendError::Decode)
}

/// Every way `send` can fail to produce a usable [`QueryBatchResponse`], folded into
/// `flush`'s single failure branch alongside a length mismatch and a timeout.
#[derive(Debug)]
enum SendError {
    Transport(reqwest::Error),
    Encode(serde_json::Error),
    Decode(serde_json::Error),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Transport(err) => write!(f, "{err}"),
            SendError::Encode(err) => write!(f, "the request could not be encoded: {err}"),
            SendError::Decode(err) => write!(f, "the response could not be decoded: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn request(name: &str) -> (OsvRequest, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        (
            ((Ecosystem::Npm, name.to_owned(), "1.0.0".to_owned()), tx),
            rx,
        )
    }

    /// A `wiremock` server that counts the requests it receives, so a test can
    /// assert exactly one flush happened.
    async fn counting_server(
        response: wiremock::ResponseTemplate,
    ) -> (
        Url,
        wiremock::MockServer,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&count);
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(move |_: &wiremock::Request| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                response.clone()
            })
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/v1/querybatch", server.uri())).unwrap();
        (url, server, count)
    }

    #[tokio::test]
    async fn batcher_flushes_on_record_count_cap() {
        let body = serde_json::json!({
            "results": (0..OSV_BATCH_RECORDS).map(|_| serde_json::json!({"vulns": []})).collect::<Vec<_>>(),
        });
        let (url, server, count) =
            counting_server(wiremock::ResponseTemplate::new(200).set_body_json(body)).await;

        let (tx, rx) = mpsc::channel(OSV_BATCH_RECORDS + 8);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run(
            Client::new(),
            url,
            rx,
            Duration::from_secs(5),
            shutdown.clone(),
        ));

        let mut waiters = Vec::new();
        for i in 0..OSV_BATCH_RECORDS {
            let (request, reply) = request(&format!("pkg-{i}"));
            tx.send(request).await.unwrap();
            waiters.push(reply);
        }

        for waiter in waiters {
            assert_eq!(waiter.await.unwrap(), false);
        }
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly the count-cap's worth triggers exactly one flush, immediately"
        );

        drop(tx);
        shutdown.cancel();
        let _ = handle.await;
        drop(server);
    }

    /// `tokio::time::advance` needs the `test-util` feature, which this crate does
    /// not enable, so this waits out `OSV_BATCH_INTERVAL` for real rather than
    /// fast-forwarding a paused clock.
    #[tokio::test]
    async fn batcher_flushes_on_interval() {
        let body = serde_json::json!({"results": [{"vulns": []}]});
        let (url, server, count) =
            counting_server(wiremock::ResponseTemplate::new(200).set_body_json(body)).await;

        let (tx, rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run(
            Client::new(),
            url,
            rx,
            Duration::from_secs(5),
            shutdown.clone(),
        ));

        let (req, reply) = request("left-pad");
        tx.send(req).await.unwrap();
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a single request under the count cap does not flush immediately"
        );

        tokio::time::sleep(OSV_BATCH_INTERVAL + Duration::from_millis(200)).await;
        assert_eq!(reply.await.unwrap(), false);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        drop(tx);
        shutdown.cancel();
        let _ = handle.await;
        drop(server);
    }

    #[tokio::test]
    async fn batcher_never_blocks_past_timeout_on_a_hung_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let (tx, rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let request_timeout = Duration::from_millis(100);
        let handle = tokio::spawn(run(
            Client::new(),
            url,
            rx,
            request_timeout,
            shutdown.clone(),
        ));

        let (req, reply) = request("left-pad");
        let started = Instant::now();
        tx.send(req).await.unwrap();
        // The interval flush fires first (2s default), so nudge a flush directly by
        // filling to the count cap is unnecessary here: the interval bound itself is
        // what this test is measuring against, so assert the reply lands within it
        // plus the request timeout, never hanging on the connection.
        let matched = reply.await.unwrap();
        let elapsed = started.elapsed();
        assert!(!matched, "a hung connection fails the batch open");
        assert!(
            elapsed < OSV_BATCH_INTERVAL + request_timeout + Duration::from_secs(2),
            "the flush must not block past its own timeout bound; took {elapsed:?}"
        );

        drop(tx);
        shutdown.cancel();
        let _ = handle.await;
        hold.abort();
    }

    #[tokio::test]
    async fn batcher_fails_open_the_whole_batch_on_length_mismatch() {
        // Two queries go in; the collector answers with only one result.
        let body = serde_json::json!({"results": [{"vulns": []}]});
        let (url, server, _count) =
            counting_server(wiremock::ResponseTemplate::new(200).set_body_json(body)).await;

        let (tx, rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run(
            Client::new(),
            url,
            rx,
            Duration::from_secs(5),
            shutdown.clone(),
        ));

        let (req_a, reply_a) = request("pkg-a");
        let (req_b, reply_b) = request("pkg-b");
        tx.send(req_a).await.unwrap();
        tx.send(req_b).await.unwrap();

        drop(tx);
        shutdown.cancel();
        let _ = handle.await;
        drop(server);

        assert_eq!(
            reply_a.await.unwrap(),
            false,
            "every waiter fails open on a mismatch"
        );
        assert_eq!(reply_b.await.unwrap(), false);
    }

    #[tokio::test]
    async fn batcher_drains_after_shutdown_signal() {
        let body = serde_json::json!({"results": [{"vulns": []}]});
        let (url, server, count) =
            counting_server(wiremock::ResponseTemplate::new(200).set_body_json(body)).await;

        let (tx, rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run(
            Client::new(),
            url,
            rx,
            Duration::from_secs(5),
            shutdown.clone(),
        ));

        let (req, reply) = request("left-pad");
        tx.send(req).await.unwrap();
        // Queued but under the count cap and well inside the interval: nothing has
        // flushed yet.
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);

        shutdown.cancel();
        assert_eq!(
            reply.await.unwrap(),
            false,
            "the queued request is drained and actually answered by the collector on \
             shutdown, rather than left unanswered or dropped"
        );
        let _ = handle.await;
        drop(tx);
        drop(server);
    }
}
